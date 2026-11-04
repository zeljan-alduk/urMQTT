//! virtio-gpu, 2D only (virtio 1.x §5.7): one resource in guest memory,
//! shown on scanout 0, for the kernel's text console (ADR-256).
//!
//! The framebuffer is ordinary RAM the kernel allocated for this purpose and
//! attached as the resource's backing; drawing changes only that RAM, and the
//! host sees it after `TRANSFER_TO_HOST_2D` and `RESOURCE_FLUSH`
//! ([`VirtioGpu::present`]). Only the control queue is used; no cursor, no
//! 3D, no EDID, no fences. Every response is parsed from a fixed-size buffer
//! by [`parse_response`]: the type, the length the device says it wrote and
//! the fence are checked, and nothing the device returns is used as a pointer
//! or an index without a bound.

use crate::queue::{Buf, DmaRegion, SplitQueue};
use crate::transport::Transport;
use crate::{Env, F_VERSION_1, VirtioError, wait_used};

// Command and response types (§5.7.6.7).
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// First and last error response types (`ERR_UNSPEC` .. `ERR_INVALID_PARAMETER`).
pub const RESP_ERR_FIRST: u32 = 0x1200;
pub const RESP_ERR_LAST: u32 = 0x12ff;
/// `VIRTIO_GPU_FLAG_FENCE` in the header's flags.
pub const FLAG_FENCE: u32 = 1;
/// `VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM`: bytes B, G, R, X in memory, which is
/// a little-endian `u32` with red at bit 16, green at 8, blue at 0.
pub const FORMAT_B8G8R8X8: u32 = 2;

/// `struct virtio_gpu_ctrl_hdr`: type, flags, fence_id, ctx_id, ring_idx, padding.
pub const HDR_LEN: usize = 24;
/// `VIRTIO_GPU_MAX_SCANOUTS`.
pub const MAX_SCANOUTS: usize = 16;
/// One `virtio_gpu_display_one`: rect (4 x u32), enabled, flags.
const DISPLAY_ONE: usize = 24;
/// `struct virtio_gpu_resp_display_info`.
pub const DISPLAY_INFO_LEN: usize = HDR_LEN + MAX_SCANOUTS * DISPLAY_ONE;

/// The one resource this driver creates.
pub const RESOURCE_ID: u32 = 1;

/// Mode bounds: anything the device prefers is clamped into them.
pub const MIN_WIDTH: u32 = 640;
pub const MIN_HEIGHT: u32 = 480;
pub const MAX_WIDTH: u32 = 1920;
pub const MAX_HEIGHT: u32 = 1080;
/// The mode used when the device prefers none.
pub const DEFAULT_MODE: (u32, u32) = (1280, 800);
/// Smaller modes tried, in order, when the preferred one is over the memory budget.
const FALLBACK_MODES: [(u32, u32); 4] = [(1280, 800), (1024, 768), (800, 600), (640, 480)];

const QUEUE_SIZE: u16 = 8;
/// Bytes per command slot in the I/O page: request at 0, response at `RESP_OFF`.
const SLOT: usize = 1024;
const RESP_OFF: usize = 512;
/// Slots: 0 for synchronous commands and the transfer, 1 for the flush.
const SLOTS: usize = 2;
const CMD_TIMEOUT_NS: u64 = 1_000_000_000;

/// A rectangle as the device describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// `GET_DISPLAY_INFO`: the rectangle of each enabled scanout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DisplayInfo {
    pub modes: [Option<Rect>; MAX_SCANOUTS],
}

/// A response that passed every check.
// 320 bytes on the stack for a moment; this crate has no allocator to box it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    NoData,
    DisplayInfo(DisplayInfo),
}

/// Why a response was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespError {
    /// Shorter than its type needs (as written by the device, or as a buffer).
    Short,
    /// The device reported an error (`VIRTIO_GPU_RESP_ERR_*`).
    Device(u32),
    /// A type that is neither the one expected nor an error.
    Unexpected(u32),
    /// The fence does not match the request's.
    Fence,
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at.checked_add(4)?)
        .and_then(|x| <[u8; 4]>::try_from(x).ok())
        .map(u32::from_le_bytes)
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at.checked_add(8)?)
        .and_then(|x| <[u8; 8]>::try_from(x).ok())
        .map(u64::from_le_bytes)
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    if let Some(d) = b.get_mut(at..at + 4) {
        d.copy_from_slice(&v.to_le_bytes());
    }
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    if let Some(d) = b.get_mut(at..at + 8) {
        d.copy_from_slice(&v.to_le_bytes());
    }
}

/// Parses a response. `buf` is the response buffer, `written` the length the
/// device reported in the used ring (it may claim anything; only the part
/// inside `buf` counts), `expect` the OK type of the command, `fence` the
/// fence id the request carried (none: the response's fence is ignored, as
/// the specification lets a device echo or zero it).
pub fn parse_response(
    buf: &[u8],
    written: u32,
    expect: u32,
    fence: Option<u64>,
) -> Result<Reply, RespError> {
    let n = (written as usize).min(buf.len());
    let resp = buf.get(..n).ok_or(RespError::Short)?;
    let ty = le32(resp, 0).ok_or(RespError::Short)?;
    let flags = le32(resp, 4).ok_or(RespError::Short)?;
    let fence_id = le64(resp, 8).ok_or(RespError::Short)?;
    if resp.len() < HDR_LEN {
        return Err(RespError::Short);
    }
    if (RESP_ERR_FIRST..=RESP_ERR_LAST).contains(&ty) {
        return Err(RespError::Device(ty));
    }
    if ty != expect {
        return Err(RespError::Unexpected(ty));
    }
    if let Some(f) = fence
        && (flags & FLAG_FENCE == 0 || fence_id != f)
    {
        return Err(RespError::Fence);
    }
    match ty {
        RESP_OK_DISPLAY_INFO => {
            // The whole structure, even the fields not read (the last
            // scanout's flags): a shorter answer is not a display info.
            if resp.len() < DISPLAY_INFO_LEN {
                return Err(RespError::Short);
            }
            let mut info = DisplayInfo::default();
            for (i, slot) in info.modes.iter_mut().enumerate() {
                let at = HDR_LEN + i * DISPLAY_ONE;
                let field = |k: usize| le32(resp, at + 4 * k).ok_or(RespError::Short);
                let rect = Rect {
                    x: field(0)?,
                    y: field(1)?,
                    width: field(2)?,
                    height: field(3)?,
                };
                if field(4)? != 0 {
                    *slot = Some(rect);
                }
            }
            Ok(Reply::DisplayInfo(info))
        }
        RESP_OK_NODATA => Ok(Reply::NoData),
        other => Err(RespError::Unexpected(other)),
    }
}

/// The mode to use: scanout 0's preferred size clamped to
/// [`MIN_WIDTH`]..[`MAX_WIDTH`] x [`MIN_HEIGHT`]..[`MAX_HEIGHT`], or
/// [`DEFAULT_MODE`] when the device prefers none; then the first of the
/// fallback modes that fits `max_bytes` at 4 bytes per pixel. `None` if not
/// even 640x480 fits.
pub fn choose_mode(info: Option<&DisplayInfo>, max_bytes: u64) -> Option<(u32, u32)> {
    let preferred = info
        .and_then(|i| i.modes.first().copied().flatten())
        .filter(|r| r.width > 0 && r.height > 0)
        .map_or(DEFAULT_MODE, |r| {
            (
                r.width.clamp(MIN_WIDTH, MAX_WIDTH),
                r.height.clamp(MIN_HEIGHT, MAX_HEIGHT),
            )
        });
    let fits = |(w, h): (u32, u32)| u64::from(w) * u64::from(h) * 4 <= max_bytes;
    core::iter::once(preferred)
        .chain(FALLBACK_MODES)
        .find(|&m| fits(m))
}

/// A request in a slot: its bytes and the OK type that answers it.
pub struct Request {
    pub bytes: [u8; 64],
    pub len: usize,
    pub expect: u32,
}

fn request(ty: u32, len: usize, expect: u32) -> Request {
    let mut bytes = [0u8; 64];
    put32(&mut bytes, 0, ty);
    Request { bytes, len, expect }
}

fn put_rect(b: &mut [u8], at: usize, r: Rect) {
    put32(b, at, r.x);
    put32(b, at + 4, r.y);
    put32(b, at + 8, r.width);
    put32(b, at + 12, r.height);
}

/// `GET_DISPLAY_INFO`: the header only.
pub fn cmd_get_display_info() -> Request {
    request(CMD_GET_DISPLAY_INFO, HDR_LEN, RESP_OK_DISPLAY_INFO)
}

/// `RESOURCE_CREATE_2D`: resource_id, format, width, height.
pub fn cmd_create_2d(id: u32, format: u32, width: u32, height: u32) -> Request {
    let mut r = request(CMD_RESOURCE_CREATE_2D, HDR_LEN + 16, RESP_OK_NODATA);
    put32(&mut r.bytes, HDR_LEN, id);
    put32(&mut r.bytes, HDR_LEN + 4, format);
    put32(&mut r.bytes, HDR_LEN + 8, width);
    put32(&mut r.bytes, HDR_LEN + 12, height);
    r
}

/// `RESOURCE_ATTACH_BACKING` with one memory entry (addr, length, padding).
pub fn cmd_attach_backing(id: u32, addr: u64, length: u32) -> Request {
    let mut r = request(
        CMD_RESOURCE_ATTACH_BACKING,
        HDR_LEN + 8 + 16,
        RESP_OK_NODATA,
    );
    put32(&mut r.bytes, HDR_LEN, id);
    put32(&mut r.bytes, HDR_LEN + 4, 1);
    put64(&mut r.bytes, HDR_LEN + 8, addr);
    put32(&mut r.bytes, HDR_LEN + 16, length);
    r
}

/// `SET_SCANOUT`: rect, scanout_id, resource_id.
pub fn cmd_set_scanout(scanout: u32, id: u32, rect: Rect) -> Request {
    let mut r = request(CMD_SET_SCANOUT, HDR_LEN + 24, RESP_OK_NODATA);
    put_rect(&mut r.bytes, HDR_LEN, rect);
    put32(&mut r.bytes, HDR_LEN + 16, scanout);
    put32(&mut r.bytes, HDR_LEN + 20, id);
    r
}

/// `TRANSFER_TO_HOST_2D`: rect, offset (u64), resource_id, padding.
pub fn cmd_transfer_2d(id: u32, rect: Rect, offset: u64) -> Request {
    let mut r = request(CMD_TRANSFER_TO_HOST_2D, HDR_LEN + 32, RESP_OK_NODATA);
    put_rect(&mut r.bytes, HDR_LEN, rect);
    put64(&mut r.bytes, HDR_LEN + 16, offset);
    put32(&mut r.bytes, HDR_LEN + 24, id);
    r
}

/// `RESOURCE_FLUSH`: rect, resource_id, padding.
pub fn cmd_flush(id: u32, rect: Rect) -> Request {
    let mut r = request(CMD_RESOURCE_FLUSH, HDR_LEN + 24, RESP_OK_NODATA);
    put_rect(&mut r.bytes, HDR_LEN, rect);
    put32(&mut r.bytes, HDR_LEN + 16, id);
    r
}

/// What [`VirtioGpu::present`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Present {
    /// A transfer and a flush were queued.
    Queued,
    /// The previous pair is still with the device: nothing queued.
    Busy,
}

/// The driver: the control queue, a page for requests and responses, and
/// the framebuffer.
pub struct VirtioGpu {
    t: Transport,
    q: SplitQueue,
    notify_off: usize,
    io: DmaRegion,
    fb: DmaRegion,
    pub width: u32,
    pub height: u32,
    /// What the device preferred (scanout 0), if it said.
    pub preferred: Option<Rect>,
    /// Scanouts the device has (its configuration, bounded by 16).
    pub scanouts: u32,
    /// Heads of the queued present pair (transfer, flush), or none.
    pending: [Option<u16>; SLOTS],
    /// Presents the device answered with an error or a malformed response.
    pub errors: u32,
    /// The last such answer.
    pub last_error: Option<RespError>,
}

impl VirtioGpu {
    /// Brings the device up and shows a black resource on scanout 0.
    /// `max_bytes` bounds the framebuffer.
    pub fn new<E: Env>(t: Transport, env: &E, max_bytes: u64) -> Result<Self, VirtioError> {
        t.init(env, 0, F_VERSION_1)?;
        // virtio_gpu_config: events_read, events_clear, num_scanouts, num_capsets.
        let scanouts = t.device.read32(8).min(MAX_SCANOUTS as u32);
        let size = QUEUE_SIZE.min(t.queue_max(0));
        if size == 0 {
            return Err(VirtioError::QueueUnavailable(0));
        }
        let mem = env
            .dma_alloc(crate::queue::Layout::new(size).total)
            .ok_or(VirtioError::NoDma)?;
        // SAFETY: fresh zeroed DMA memory of the right size, owned by the queue.
        #[allow(unsafe_code)]
        let q = unsafe { SplitQueue::new(mem, size) }?;
        let notify_off = t.setup_queue(0, &q, None)?;
        let io = env.dma_alloc(SLOT * SLOTS).ok_or(VirtioError::NoDma)?;
        t.driver_ok()?;
        let mut gpu = Self {
            t,
            q,
            notify_off,
            io,
            fb: DmaRegion {
                va: 0,
                pa: 0,
                len: 0,
            },
            width: 0,
            height: 0,
            preferred: None,
            scanouts,
            pending: [None; SLOTS],
            errors: 0,
            last_error: None,
        };
        // A device that does not answer GET_DISPLAY_INFO still gets the default mode.
        let info = match gpu.command(env, &cmd_get_display_info()) {
            Ok(Reply::DisplayInfo(i)) => Some(i),
            Ok(Reply::NoData) => None,
            Err(VirtioError::Timeout(w)) => return Err(VirtioError::Timeout(w)),
            Err(_) => None,
        };
        gpu.preferred = info.and_then(|i| i.modes.first().copied().flatten());
        let (w, h) = choose_mode(info.as_ref(), max_bytes).ok_or(VirtioError::NoDma)?;
        let bytes = w as usize * h as usize * 4;
        gpu.fb = env.dma_alloc(bytes).ok_or(VirtioError::NoDma)?;
        (gpu.width, gpu.height) = (w, h);
        gpu.command(env, &cmd_create_2d(RESOURCE_ID, FORMAT_B8G8R8X8, w, h))?;
        gpu.command(
            env,
            &cmd_attach_backing(RESOURCE_ID, gpu.fb.pa, bytes as u32),
        )?;
        gpu.command(env, &cmd_set_scanout(0, RESOURCE_ID, gpu.rect()))?;
        gpu.command(env, &cmd_transfer_2d(RESOURCE_ID, gpu.rect(), 0))?;
        gpu.command(env, &cmd_flush(RESOURCE_ID, gpu.rect()))?;
        Ok(gpu)
    }

    /// The whole screen.
    pub fn rect(&self) -> Rect {
        Rect {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        }
    }

    /// The framebuffer: `width * height * 4` bytes of B8G8R8X8 at `va`,
    /// pitch `width * 4` (the region may be longer, rounded to pages).
    pub fn framebuffer(&self) -> DmaRegion {
        self.fb
    }

    #[allow(unsafe_code)]
    fn slot_bytes(&mut self, slot: usize, off: usize, len: usize) -> &mut [u8] {
        let start = (slot * SLOT + off).min(self.io.len);
        let len = len.min(self.io.len - start);
        // SAFETY: inside our DMA page; the device only touches a slot while
        // its request is queued, and a slot is written only when it is not.
        unsafe { core::slice::from_raw_parts_mut((self.io.va + start) as *mut u8, len) }
    }

    /// Puts `req` into `slot` and queues it with its response buffer.
    fn queue(&mut self, slot: usize, req: &Request) -> Result<u16, VirtioError> {
        let len = req.len.min(req.bytes.len()).min(RESP_OFF);
        self.slot_bytes(slot, 0, len)
            .copy_from_slice(req.bytes.get(..len).unwrap_or(&[]));
        // A stale response must never be read as this one's.
        self.slot_bytes(slot, RESP_OFF, HDR_LEN).fill(0);
        let pa = self.io.pa + (slot * SLOT) as u64;
        let head = self.q.add(&[
            Buf {
                pa,
                len: len as u32,
                device_writes: false,
            },
            Buf {
                pa: pa + RESP_OFF as u64,
                len: (SLOT - RESP_OFF) as u32,
                device_writes: true,
            },
        ])?;
        Ok(head)
    }

    fn parse_slot(&mut self, slot: usize, written: u32, expect: u32) -> Result<Reply, RespError> {
        let mut resp = [0u8; DISPLAY_INFO_LEN];
        let src = self.slot_bytes(slot, RESP_OFF, DISPLAY_INFO_LEN);
        let n = src.len().min(resp.len());
        if let (Some(d), Some(s)) = (resp.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
        parse_response(resp.get(..n).unwrap_or(&[]), written, expect, None)
    }

    /// One command, synchronously (only while no present is queued).
    fn command<E: Env>(&mut self, env: &E, req: &Request) -> Result<Reply, VirtioError> {
        self.wait_idle(env, CMD_TIMEOUT_NS)?;
        let head = self.queue(0, req)?;
        self.t.notify(self.notify_off, 0);
        let (id, written) = wait_used(env, &mut self.q, CMD_TIMEOUT_NS, "gpu")?;
        if id != head {
            return Err(VirtioError::Queue(crate::QueueError::DeviceProtocol));
        }
        self.parse_slot(0, written, req.expect)
            .map_err(|e| match e {
                RespError::Device(t) => VirtioError::Io((t & 0xff) as u8),
                _ => VirtioError::Io(0xff),
            })
    }

    /// Takes the answers of a queued present pair that the device has
    /// finished. Never waits.
    pub fn reap(&mut self) {
        // At most one used entry per queued chain.
        for _ in 0..SLOTS {
            match self.q.pop_used() {
                Ok(Some((id, written))) => {
                    let Some(slot) = self.pending.iter().position(|p| *p == Some(id)) else {
                        self.note_error(RespError::Unexpected(0));
                        continue;
                    };
                    if let Some(p) = self.pending.get_mut(slot) {
                        *p = None;
                    }
                    if let Err(e) = self.parse_slot(slot, written, RESP_OK_NODATA) {
                        self.note_error(e);
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    // A used ring that cannot be ours: stop presenting rather
                    // than guess which chains are still out.
                    self.note_error(RespError::Unexpected(0));
                    break;
                }
            }
        }
    }

    fn note_error(&mut self, e: RespError) {
        self.errors = self.errors.saturating_add(1);
        self.last_error = Some(e);
    }

    /// Whether a present pair is still with the device.
    pub fn busy(&self) -> bool {
        self.pending.iter().any(Option::is_some)
    }

    /// Waits (bounded) until the queued present pair is answered.
    pub fn wait_idle<E: Env>(&mut self, env: &E, timeout_ns: u64) -> Result<(), VirtioError> {
        let deadline = env.now_ns().saturating_add(timeout_ns);
        loop {
            self.reap();
            if !self.busy() {
                return Ok(());
            }
            if env.now_ns() > deadline {
                return Err(VirtioError::Timeout("gpu present"));
            }
            core::hint::spin_loop();
        }
    }

    /// Queues `TRANSFER_TO_HOST_2D` and `RESOURCE_FLUSH` of the whole
    /// screen, without waiting: the device copies the framebuffer and shows
    /// it. If the previous pair is still out, nothing is queued.
    pub fn present(&mut self) -> Result<Present, VirtioError> {
        self.reap();
        if self.busy() {
            return Ok(Present::Busy);
        }
        let rect = self.rect();
        let t = self.queue(0, &cmd_transfer_2d(RESOURCE_ID, rect, 0))?;
        if let Some(p) = self.pending.get_mut(0) {
            *p = Some(t);
        }
        // The device takes the queue in order: the flush shows what the
        // transfer copied (as the Linux driver relies on, without fences).
        match self.queue(1, &cmd_flush(RESOURCE_ID, rect)) {
            Ok(f) => {
                if let Some(p) = self.pending.get_mut(1) {
                    *p = Some(f);
                }
            }
            Err(e) => {
                self.t.notify(self.notify_off, 0);
                return Err(e);
            }
        }
        self.t.notify(self.notify_off, 0);
        Ok(Present::Queued)
    }
}

/// Why the console takes (or leaves) a virtio-gpu device under
/// `console.virtio_gpu = "auto"` (ADR-256). What can be told apart at boot is
/// where the bootloader's framebuffer lives: inside a memory BAR of a PCI
/// display controller (a VGA-compatible device scanning out its own VRAM:
/// live), or in RAM (with a virtio-gpu, the shadow edk2's VirtioGpuDxe used
/// for its GOP; that driver resets the device at ExitBootServices, so nothing
/// shows that RAM any more).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoChoice {
    /// No usable boot framebuffer: the device is the only way to a screen.
    NoBootFramebuffer,
    /// The boot framebuffer is RAM that nothing presents.
    BootFramebufferInRam,
    /// The boot framebuffer is inside BAR `bar` of display function `index`
    /// (an index into the caller's list): it is live, the device is left alone.
    BootFramebufferInBar { index: usize, bar: u8 },
}

impl AutoChoice {
    /// Whether the console moves to the virtio-gpu device.
    pub fn takes_device(self) -> bool {
        !matches!(self, Self::BootFramebufferInBar { .. })
    }
}

/// [`AutoChoice`] from the boot framebuffer's physical range (`None`: no
/// usable one) and the memory BARs of the PCI display controllers, as lists
/// of (BAR index, base, size) per function.
pub fn auto_choice(boot_fb: Option<(u64, u64)>, displays: &[&[(u8, u64, u64)]]) -> AutoChoice {
    let Some((fb, fb_len)) = boot_fb else {
        return AutoChoice::NoBootFramebuffer;
    };
    let fb_end = fb.saturating_add(fb_len.max(1));
    for (index, bars) in displays.iter().enumerate() {
        for &(bar, base, size) in *bars {
            if size > 0 && fb >= base && fb_end <= base.saturating_add(size) {
                return AutoChoice::BootFramebufferInBar { index, bar };
            }
        }
    }
    AutoChoice::BootFramebufferInRam
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hdr(ty: u32, flags: u32, fence: u64) -> [u8; DISPLAY_INFO_LEN] {
        let mut b = [0u8; DISPLAY_INFO_LEN];
        b[0..4].copy_from_slice(&ty.to_le_bytes());
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        b[8..16].copy_from_slice(&fence.to_le_bytes());
        b
    }

    fn display(b: &mut [u8], i: usize, w: u32, h: u32, enabled: u32) {
        let at = HDR_LEN + i * DISPLAY_ONE;
        b[at + 8..at + 12].copy_from_slice(&w.to_le_bytes());
        b[at + 12..at + 16].copy_from_slice(&h.to_le_bytes());
        b[at + 16..at + 20].copy_from_slice(&enabled.to_le_bytes());
    }

    #[test]
    fn commands_are_encoded_as_the_specification_lays_them_out() {
        let r = cmd_get_display_info();
        assert_eq!((r.len, r.expect), (24, RESP_OK_DISPLAY_INFO));
        assert_eq!(&r.bytes[..4], &0x0100u32.to_le_bytes());
        assert!(r.bytes[4..24].iter().all(|b| *b == 0), "no flags, no fence");

        let r = cmd_create_2d(1, FORMAT_B8G8R8X8, 1280, 800);
        assert_eq!(r.len, 40);
        let w: Vec<u32> = (0..10).map(|i| le32(&r.bytes, 4 * i).unwrap()).collect();
        assert_eq!(w, [0x0101, 0, 0, 0, 0, 0, 1, 2, 1280, 800]);

        let r = cmd_attach_backing(1, 0x1234_5678_9abc_d000, 4096);
        assert_eq!(r.len, 48);
        assert_eq!(le32(&r.bytes, 0), Some(0x0106));
        assert_eq!((le32(&r.bytes, 24), le32(&r.bytes, 28)), (Some(1), Some(1)));
        assert_eq!(le64(&r.bytes, 32), Some(0x1234_5678_9abc_d000));
        assert_eq!(
            (le32(&r.bytes, 40), le32(&r.bytes, 44)),
            (Some(4096), Some(0))
        );

        let rect = Rect {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
        };
        let r = cmd_set_scanout(0, 1, rect);
        assert_eq!(r.len, 48);
        let w: Vec<u32> = (6..12).map(|i| le32(&r.bytes, 4 * i).unwrap()).collect();
        assert_eq!(w, [1, 2, 3, 4, 0, 1]);

        let r = cmd_transfer_2d(1, rect, 0x10);
        assert_eq!((r.len, le32(&r.bytes, 0)), (56, Some(0x0105)));
        assert_eq!(le64(&r.bytes, 40), Some(0x10));
        assert_eq!(le32(&r.bytes, 48), Some(1));

        let r = cmd_flush(1, rect);
        assert_eq!((r.len, le32(&r.bytes, 0)), (48, Some(0x0104)));
        assert_eq!(le32(&r.bytes, 40), Some(1));
    }

    #[test]
    fn display_info_is_parsed_and_only_enabled_scanouts_count() {
        let mut b = hdr(RESP_OK_DISPLAY_INFO, 0, 0);
        display(&mut b, 0, 1024, 768, 1);
        display(&mut b, 1, 800, 600, 0);
        display(&mut b, 15, 640, 480, 7);
        let Ok(Reply::DisplayInfo(i)) =
            parse_response(&b, DISPLAY_INFO_LEN as u32, RESP_OK_DISPLAY_INFO, None)
        else {
            panic!("not parsed");
        };
        assert_eq!(i.modes[0].map(|r| (r.width, r.height)), Some((1024, 768)));
        assert_eq!(i.modes[1], None);
        assert_eq!(i.modes[15].map(|r| r.width), Some(640));
    }

    #[test]
    fn responses_are_checked_fail_closed() {
        let ok = hdr(RESP_OK_NODATA, 0, 0);
        assert_eq!(
            parse_response(&ok, 24, RESP_OK_NODATA, None),
            Ok(Reply::NoData)
        );
        // The device says it wrote more than the buffer: only the buffer counts.
        assert_eq!(
            parse_response(&ok[..24], u32::MAX, RESP_OK_NODATA, None),
            Ok(Reply::NoData)
        );
        // Too short, as written or as a buffer.
        assert_eq!(
            parse_response(&ok, 23, RESP_OK_NODATA, None),
            Err(RespError::Short)
        );
        assert_eq!(
            parse_response(&ok, 0, RESP_OK_NODATA, None),
            Err(RespError::Short)
        );
        assert_eq!(
            parse_response(&ok[..10], 24, RESP_OK_NODATA, None),
            Err(RespError::Short)
        );
        // A display info cut short.
        let di = hdr(RESP_OK_DISPLAY_INFO, 0, 0);
        assert_eq!(
            parse_response(&di, 200, RESP_OK_DISPLAY_INFO, None),
            Err(RespError::Short)
        );
        // Found by the fuzz target: everything but the last scanout's flags.
        assert_eq!(
            parse_response(&di, DISPLAY_INFO_LEN as u32 - 4, RESP_OK_DISPLAY_INFO, None),
            Err(RespError::Short)
        );
        // Error types, unexpected types, the wrong OK type.
        let e = hdr(0x1203, 0, 0);
        assert_eq!(
            parse_response(&e, 24, RESP_OK_NODATA, None),
            Err(RespError::Device(0x1203))
        );
        let u = hdr(0x3000, 0, 0);
        assert_eq!(
            parse_response(&u, 24, RESP_OK_NODATA, None),
            Err(RespError::Unexpected(0x3000))
        );
        assert_eq!(
            parse_response(&ok, 24, RESP_OK_DISPLAY_INFO, None),
            Err(RespError::Unexpected(RESP_OK_NODATA))
        );
        // Fences: checked only when the request had one.
        let f = hdr(RESP_OK_NODATA, FLAG_FENCE, 7);
        assert_eq!(
            parse_response(&f, 24, RESP_OK_NODATA, Some(7)),
            Ok(Reply::NoData)
        );
        assert_eq!(
            parse_response(&f, 24, RESP_OK_NODATA, Some(8)),
            Err(RespError::Fence)
        );
        assert_eq!(
            parse_response(&ok, 24, RESP_OK_NODATA, Some(0)),
            Err(RespError::Fence)
        );
        assert_eq!(
            parse_response(&f, 24, RESP_OK_NODATA, None),
            Ok(Reply::NoData)
        );
    }

    #[test]
    fn modes_are_clamped_and_fit_the_budget() {
        let big = u64::MAX;
        assert_eq!(choose_mode(None, big), Some(DEFAULT_MODE));
        let mut i = DisplayInfo::default();
        assert_eq!(choose_mode(Some(&i), big), Some(DEFAULT_MODE));
        i.modes[0] = Some(Rect {
            width: 1024,
            height: 768,
            ..Rect::default()
        });
        assert_eq!(choose_mode(Some(&i), big), Some((1024, 768)));
        i.modes[0] = Some(Rect {
            width: u32::MAX,
            height: 1,
            ..Rect::default()
        });
        assert_eq!(choose_mode(Some(&i), big), Some((1920, 480)));
        i.modes[0] = Some(Rect {
            width: 0,
            height: 600,
            ..Rect::default()
        });
        assert_eq!(choose_mode(Some(&i), big), Some(DEFAULT_MODE));
        // Only another scanout enabled: the default.
        i.modes[0] = None;
        i.modes[3] = Some(Rect {
            width: 800,
            height: 600,
            ..Rect::default()
        });
        assert_eq!(choose_mode(Some(&i), big), Some(DEFAULT_MODE));
        // The budget picks a smaller mode, or none.
        assert_eq!(choose_mode(None, 1024 * 768 * 4), Some((1024, 768)));
        assert_eq!(choose_mode(None, 640 * 480 * 4), Some((640, 480)));
        assert_eq!(choose_mode(None, 640 * 480 * 4 - 1), None);
        // The largest mode is within 8 MiB.
        assert!(u64::from(MAX_WIDTH * MAX_HEIGHT * 4) <= 8 << 20);
    }

    #[test]
    fn auto_takes_the_device_unless_the_boot_framebuffer_is_live_in_a_bar() {
        assert_eq!(auto_choice(None, &[]), AutoChoice::NoBootFramebuffer);
        assert!(AutoChoice::NoBootFramebuffer.takes_device());
        // edk2 VirtioGpuDxe: the GOP framebuffer is RAM.
        let gpu: &[(u8, u64, u64)] = &[(4, 0x80_0000_0000, 0x4000)];
        assert_eq!(
            auto_choice(Some((0x4000_0000, 4 << 20)), &[gpu]),
            AutoChoice::BootFramebufferInRam
        );
        // virtio-vga / std VGA: the framebuffer is VRAM in BAR 0.
        let vga: &[(u8, u64, u64)] = &[(0, 0xc000_0000, 16 << 20), (2, 0xc100_0000, 0x1000)];
        let c = auto_choice(Some((0xc000_0000, 4 << 20)), &[gpu, vga]);
        assert_eq!(c, AutoChoice::BootFramebufferInBar { index: 1, bar: 0 });
        assert!(!c.takes_device());
        // Straddling the end of a BAR is not inside it; a zero-sized BAR never holds it.
        assert_eq!(
            auto_choice(Some((0xc0f0_0000, 2 << 20)), &[vga]),
            AutoChoice::BootFramebufferInRam
        );
        let empty: &[(u8, u64, u64)] = &[(0, 0x1000, 0)];
        assert_eq!(
            auto_choice(Some((0x1000, 0)), &[empty]),
            AutoChoice::BootFramebufferInRam
        );
        // No overflow at the top of the address space.
        let top: &[(u8, u64, u64)] = &[(0, u64::MAX - 0xfff, 0x1000)];
        assert!(matches!(
            auto_choice(Some((u64::MAX, u64::MAX)), &[top]),
            AutoChoice::BootFramebufferInBar { .. } | AutoChoice::BootFramebufferInRam
        ));
    }
}
