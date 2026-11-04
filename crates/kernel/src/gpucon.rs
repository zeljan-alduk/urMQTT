//! The console on a virtio-gpu scanout (ADR-256, `console.virtio_gpu`).
//!
//! On a VM whose firmware drove a virtio-gpu (edk2's VirtioGpuDxe) the
//! bootloader's framebuffer is a RAM shadow that nothing shows after boot:
//! the provider's console says "Display output is not active". Here the
//! device gets a resource of its own, backed by DMA memory allocated for it,
//! on scanout 0; the log's framebuffer console moves onto that memory (the
//! lines logged before are redrawn from the console ring), and every change
//! is sent to the host with `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH`:
//!
//! - lines mark the framebuffer drawn on; the log calls [`present`] after
//!   writing (rate-limited to one pair per [`PERIOD_NS`]), the boot CPU's
//!   tick calls it every 10 ms so the last lines of a burst follow;
//! - before the machine stops (fatal errors, panics, power-off, `flush`) and
//!   after a dashboard redraw it is called with `now`: the pair is queued and
//!   waited for (bounded).
//!
//! The device lock is only ever tried (bounded for `now`), never waited on:
//! a tick that interrupts a present on its own core, or a panic inside one,
//! skips the frame instead of hanging. Nothing here logs while it holds it.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use urmqtt_arch::time;
use urmqtt_log::fbcon::{FbConsole, PixelFormat};
use urmqtt_log::{info, warn};
use urmqtt_sync::sync::SpinLock;
use urmqtt_virtio::gpu::{Present, VirtioGpu};

use crate::devices::KernelEnv;

static GPU: SpinLock<Option<VirtioGpu>> = SpinLock::new(None);
/// The console is on the device (set once, after [`GPU`] is filled).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// When the last pair was queued (ns since boot).
static LAST_NS: AtomicU64 = AtomicU64::new(0);

/// Shortest time between two presents that are not forced: at most 20 a second.
pub const PERIOD_NS: u64 = 50_000_000;
/// How long a forced present tries for the device lock, and waits for the device.
const FORCE_LOCK_NS: u64 = 50_000_000;
const FORCE_WAIT_NS: u64 = 250_000_000;

/// B8G8R8X8: a little-endian `u32` with red at 16, green at 8, blue at 0.
const FORMAT: PixelFormat = PixelFormat {
    red_shift: 16,
    green_shift: 8,
    blue_shift: 0,
};

/// Moves the log's framebuffer console onto `gpu` (already showing its
/// resource on scanout 0). `bdf` and `why` are for the boot log.
pub fn install(gpu: VirtioGpu, bdf: &str, why: &str) {
    let (w, h) = (gpu.width as usize, gpu.height as usize);
    let fb = gpu.framebuffer();
    let bytes = w * h * 4;
    if fb.len < bytes {
        warn!("console: virtio-gpu at pci {bdf}: framebuffer smaller than its mode, not used");
        return;
    }
    // SAFETY: `fb` is zeroed DMA memory allocated for this framebuffer
    // alone, mapped read-write in the HHDM for the kernel's lifetime (the
    // driver is never dropped: it moves into `GPU`). Only the console writes
    // it; the device only reads it, when it is told to (TRANSFER_TO_HOST_2D).
    let buf: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(fb.va as *mut u8, bytes) };
    let Some(con) = FbConsole::new(buf, w, h, w * 4, FORMAT) else {
        warn!("console: virtio-gpu at pci {bdf}: no text fits {w}x{h}, not used");
        return;
    };
    let preferred = gpu
        .preferred
        .map(|r| (r.width, r.height))
        .unwrap_or((0, 0));
    let scanouts = gpu.scanouts;
    *GPU.lock() = Some(gpu);
    // Release: the driver in `GPU` is visible before a presenter sees the flag.
    ACTIVE.store(true, Ordering::Release);
    urmqtt_log::set_framebuffer_present(present);
    // Logged before the switch, so it is among the lines redrawn on the screen.
    info!(
        "console: virtio-gpu at pci {bdf} ({why}): {w}x{h} B8G8R8X8 on scanout 0 of {scanouts}, \
         device preferred {}x{}; the log moves to it",
        preferred.0, preferred.1
    );
    let n = urmqtt_log::replace_framebuffer(con);
    info!(
        "console: virtio-gpu active: {n} earlier line(s) redrawn, presented at most every {} ms and before a stop",
        PERIOD_NS / 1_000_000
    );
}

/// Whether the console is on a virtio-gpu.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// From the boot CPU's tick: sends what was drawn and held back by the rate limit.
pub fn tick() {
    if active() && crate::smp::current() == 0 {
        present(false);
    }
}

/// Tries the device lock for up to [`FORCE_LOCK_NS`] (the clock runs with
/// interrupts masked; the pass count bounds it if it does not).
fn lock_bounded() -> Option<urmqtt_sync::sync::SpinGuard<'static, Option<VirtioGpu>>> {
    let give_up = time::uptime_ns().saturating_add(FORCE_LOCK_NS);
    for _ in 0..10_000_000u32 {
        if let Some(g) = GPU.try_lock() {
            return Some(g);
        }
        if time::uptime_ns() >= give_up {
            break;
        }
        core::hint::spin_loop();
    }
    None
}

/// The log's presenter (`urmqtt_log::set_framebuffer_present`). `now`:
/// queue whatever was drawn and wait until the device has it.
fn present(now: bool) {
    if !active() {
        return;
    }
    let t = time::uptime_ns();
    // Relaxed: a rate limit; two cores racing here are serialised by the lock.
    if !now && t.saturating_sub(LAST_NS.load(Ordering::Relaxed)) < PERIOD_NS {
        return;
    }
    let guard = if now { lock_bounded() } else { GPU.try_lock() };
    let Some(mut g) = guard else { return };
    let Some(gpu) = g.as_mut() else { return };
    let env = KernelEnv;
    if now && gpu.busy() {
        let _ = gpu.wait_idle(&env, FORCE_WAIT_NS);
    }
    if urmqtt_log::take_framebuffer_dirty() {
        match gpu.present() {
            Ok(Present::Queued) => LAST_NS.store(t, Ordering::Relaxed),
            // Still with the device, or the queue refused: the next call sends it.
            Ok(Present::Busy) | Err(_) => urmqtt_log::mark_framebuffer_dirty(),
        }
    }
    if now {
        let _ = gpu.wait_idle(&env, FORCE_WAIT_NS);
    }
}

/// Logs how many presents the device answered with an error or a malformed
/// response (the presenter itself never logs), once the boot is complete.
pub fn report() {
    if !active() {
        return;
    }
    let Some((n, last)) = lock_bounded().and_then(|g| g.as_ref().map(|d| (d.errors, d.last_error)))
    else {
        return;
    };
    match last {
        None => info!("console: virtio-gpu: {n} device error(s)"),
        Some(e) => warn!("console: virtio-gpu: {n} device error(s), the last {e:?}"),
    }
}
