//! DMA remapping (H4b, ADR-305 to ADR-307): the kernel side of
//! `urmqtt-iommu`.
//!
//! `devices.iommu` decides: `off` (the default) leaves the IOMMU as the
//! firmware set it and only names it in the log; `auto` brings up every unit
//! the firmware describes and goes on without one that fails; `require`
//! refuses to boot unless every unit comes up and every device the kernel
//! drives is behind one. Bring-up ([`init`]) happens after the PCI scan and
//! before any driver runs, and blocks every device's DMA; a device the kernel
//! drives gets a domain of its own the first time it allocates DMA memory
//! ([`map`], from `devices::KernelEnv`), with exactly those pages mapped (and,
//! on a GIC, the MSI doorbell page). Faults are polled from core 0's tick,
//! a bounded number per unit per poll, counted and logged ([`poll`]).
//!
//! The unsafe parts: the units' register frames (volatile accesses inside the
//! mapping made here), the tables and queues the units read (through the
//! HHDM, memory allocated here), and the cache clean for a unit that does not
//! snoop. See docs/unsafe.md.

#![allow(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use urmqtt_config::Iommu as Mode;
use urmqtt_iommu::amdvi::{self, AmdVi};
use urmqtt_iommu::pt::{Access, Tables};
use urmqtt_iommu::smmuv3::{self, Smmu};
use urmqtt_iommu::vtd::{self, Vtd};
use urmqtt_iommu::{Env, Error, Fault, Regs};
use urmqtt_log::{error, info, warn};
use urmqtt_pci::Bdf;
use urmqtt_platform::PlatformInfo;
use urmqtt_platform::iommu::{IommuInfo, Kind};
use urmqtt_sync::sync::SpinLock;

use crate::owned_frames::OwnedFrames;
use crate::{memory, vm};

/// A unit's register frame, mapped as device memory by [`init`].
struct Mmio {
    va: usize,
    len: usize,
}

impl Mmio {
    fn at(&self, off: usize, width: usize) -> Option<usize> {
        (off.checked_add(width)? <= self.len && off.is_multiple_of(width)).then_some(self.va + off)
    }
}

impl Regs for Mmio {
    fn read32(&self, off: usize) -> u32 {
        match self.at(off, 4) {
            // SAFETY: inside the frame mapped for this unit, aligned.
            Some(a) => unsafe { (a as *const u32).read_volatile() },
            None => u32::MAX,
        }
    }

    fn write32(&mut self, off: usize, v: u32) {
        if let Some(a) = self.at(off, 4) {
            // SAFETY: as in `read32`.
            unsafe { (a as *mut u32).write_volatile(v) }
        }
    }

    fn read64(&self, off: usize) -> u64 {
        match self.at(off, 8) {
            // SAFETY: as in `read32`.
            Some(a) => unsafe { (a as *const u64).read_volatile() },
            None => u64::MAX,
        }
    }

    fn write64(&mut self, off: usize, v: u64) {
        if let Some(a) = self.at(off, 8) {
            // SAFETY: as in `read32`.
            unsafe { (a as *mut u64).write_volatile(v) }
        }
    }
}

/// Memory for the units: DMA frames reached through the HHDM.
struct KEnv {
    coherent: bool,
    /// The frames [`Env::alloc`] handed out: the only memory `read` and
    /// `write` reach (ADR-347).
    owned: OwnedFrames,
}

impl KEnv {
    fn new(coherent: bool) -> Self {
        Self {
            coherent,
            owned: OwnedFrames::default(),
        }
    }

    /// The HHDM address of `pa`, if `pa` is 8-byte aligned and its
    /// doubleword lies in a frame [`Env::alloc`] handed out. Anything else
    /// is refused, so a logic bug in the safe `urmqtt-iommu` cannot reach
    /// other kernel memory (ADR-347).
    fn va(&self, pa: u64) -> Option<usize> {
        (pa.is_multiple_of(8) && self.owned.contains(pa, 8)).then(|| (vm::hhdm() + pa) as usize)
    }
}

impl Env for KEnv {
    fn alloc(&mut self, pages: usize, align_pages: usize) -> Option<u64> {
        let bytes = pages.checked_mul(urmqtt_iommu::PAGE as usize)?;
        let align = align_pages
            .max(1)
            .checked_mul(urmqtt_iommu::PAGE as usize)?;
        let (_, pa, len) = vm::dma_alloc_aligned(bytes, align)?;
        // Frames for device tables are never freed; one the bookkeeping
        // cannot record is leaked rather than handed out unreachable.
        if !self.owned.add(pa, len as u64) {
            return None;
        }
        PAGES_TABLES.fetch_add(pages as u64, Ordering::Relaxed);
        Some(pa)
    }

    fn read(&self, pa: u64) -> u64 {
        match self.va(pa) {
            // SAFETY: `va` checked that the doubleword lies in a zeroed
            // frame this unit allocated with `vm::dma_alloc_aligned`, which
            // the HHDM maps read-write for the kernel's lifetime (frames for
            // device tables are never freed); 8-byte aligned.
            Some(va) => unsafe { (va as *const u64).read_volatile() },
            None => 0,
        }
    }

    fn write(&mut self, pa: u64, v: u64) {
        if let Some(va) = self.va(pa) {
            // SAFETY: as in `read`.
            unsafe { (va as *mut u64).write_volatile(v) }
        }
    }

    fn flush(&mut self, pa: u64, len: usize) {
        if !self.coherent {
            urmqtt_arch::cache::clean_to_device((vm::hhdm() + pa) as usize, len);
        }
    }

    fn now_ns(&self) -> u64 {
        urmqtt_arch::time::uptime_ns()
    }
}

enum Driver {
    /// Boxed: its per-bus context-table list is 2 KiB.
    Vtd(alloc::boxed::Box<Vtd<Mmio>>),
    Amd(AmdVi<Mmio>),
    Smmu(Smmu<Mmio>),
}

struct Unit {
    kind: Kind,
    base: u64,
    drv: Driver,
    env: KEnv,
}

impl Unit {
    /// A new domain for the ID `id` the unit sees: (tables, domain or ASID).
    fn attach(&mut self, id: u32) -> Result<(Tables, u16), Error> {
        let id16 = u16::try_from(id).map_err(|_| Error::IdOutOfRange)?;
        match &mut self.drv {
            Driver::Vtd(v) => v.attach(&mut self.env, id16).map(|t| (t, 0)),
            Driver::Amd(a) => a.attach(&mut self.env, id16),
            Driver::Smmu(s) => s.attach(&mut self.env, id),
        }
    }

    fn invalidate(&mut self, tag: u16) -> Result<(), Error> {
        match &mut self.drv {
            Driver::Vtd(v) => v.invalidate(&self.env),
            Driver::Amd(a) => a.invalidate(&mut self.env, tag),
            Driver::Smmu(s) => s.invalidate(&mut self.env, tag),
        }
    }

    fn poll(&mut self, max: u32, each: impl FnMut(Fault)) -> urmqtt_iommu::Poll {
        match &mut self.drv {
            Driver::Vtd(v) => v.poll_faults(max, each),
            Driver::Amd(a) => a.poll_faults(&self.env, max, each),
            Driver::Smmu(s) => s.poll_faults(&self.env, max, each),
        }
    }
}

struct Domain {
    bdf: Bdf,
    unit: usize,
    /// The ID the unit sees: two functions with the same one (an IVRS alias,
    /// a shared stream ID) are one domain to the unit, so they share it.
    id: u32,
    tables: Tables,
    tag: u16,
}

struct State {
    info: IommuInfo,
    segment: u16,
    /// One per described unit, `None` where it did not come up.
    units: Vec<Option<Unit>>,
    domains: Vec<Domain>,
    /// MSI doorbell pages every domain maps (aarch64: the ITS's
    /// translation frame, the GICv2m frame).
    doorbells: [Option<u64>; 2],
    /// Devices that DMA without translation (auto only), each counted once.
    uncovered: Vec<Bdf>,
    /// Functions that share another's domain (the same ID on the unit).
    shared: Vec<Bdf>,
}

static STATE: SpinLock<Option<State>> = SpinLock::new(None);

/// What `$SYS/broker/iommu/state` says.
const ST_OFF: u8 = 0;
const ST_NONE: u8 = 1;
const ST_FAILED: u8 = 2;
const ST_ACTIVE: u8 = 3;

// Relaxed throughout: statistics for `$SYS`, written under STATE's lock or by
// core 0's poll and read by the reporter; nothing else is ordered by them.
static STATE_WORD: AtomicU8 = AtomicU8::new(ST_OFF);
static UNITS: AtomicU64 = AtomicU64::new(0);
static DOMAINS: AtomicU64 = AtomicU64::new(0);
static PAGES: AtomicU64 = AtomicU64::new(0);
static PAGES_TABLES: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static OVERFLOWS: AtomicU64 = AtomicU64::new(0);
static WARNED_RUNTIME: AtomicBool = AtomicBool::new(false);

/// Faults read per unit per poll, and lines logged before thinning out.
const POLL_MAX: u32 = 16;
const LOG_FIRST: u64 = 16;

fn mode() -> Mode {
    urmqtt_config::CONFIG.devices.iommu
}

fn rid(bdf: Bdf) -> u16 {
    (u16::from(bdf.bus) << 8) | (u16::from(bdf.dev) << 3) | u16::from(bdf.func)
}

fn bdf_of(id: u32) -> Bdf {
    Bdf {
        bus: (id >> 8) as u8,
        dev: ((id >> 3) & 0x1f) as u8,
        func: (id & 7) as u8,
    }
}

/// A condition `require` refuses to boot with; `auto` goes on with a warning.
fn refuse(args: core::fmt::Arguments<'_>) {
    if mode() == Mode::Require {
        crate::boot::fatal_fmt(format_args!(
            "iommu: {args}; devices.iommu = \"require\" refuses to run without DMA isolation \
             (set \"auto\" to run anyway, or \"off\")"
        ));
    }
    warn!("iommu: {args}; going on without DMA isolation for it (devices.iommu = \"auto\")");
}

/// Brings up the units the firmware describes (after the PCI scan, before
/// any driver runs). `functions`: every PCI function found, for the SMMU's
/// stream table size.
pub fn init(platform: &PlatformInfo, functions: impl Iterator<Item = Bdf>) {
    let info = platform.iommu;
    let m = mode();
    if m == Mode::Off {
        if !info.is_empty() {
            info!("iommu: {info}: not used (devices.iommu = \"off\")");
        }
        return;
    }
    if info.is_empty() {
        STATE_WORD.store(ST_NONE, Ordering::Relaxed);
        refuse(format_args!(
            "the firmware describes no IOMMU (no DMAR, IVRS or IORT table, no arm,smmu-v3 node)"
        ));
        return;
    }
    info!("iommu: {info} (devices.iommu = \"{}\")", m.name());
    if info.reserved_regions > 0 {
        warn!(
            "iommu: the firmware lists {} reserved memory region(s) (RMRR/IVMD/RMR) for devices; they are not mapped (the kernel drives only virtio devices, which have none)",
            info.reserved_regions
        );
    }
    let segment = platform.pcie.map_or(0, |p| p.segment);
    let max_id = functions
        .filter_map(|b| info.unit_for(segment, rid(b)).map(|(_, id)| id))
        .max()
        .unwrap_or(0);
    let mut units = Vec::new();
    let mut up = 0u64;
    for u in info.units.as_slice() {
        match bring_up(u.kind, u.base, max_id) {
            Ok(unit) => {
                up += 1;
                units.push(Some(unit));
            }
            Err(e) => {
                units.push(None);
                refuse(format_args!(
                    "{} at {:#x} did not come up: {e}",
                    u.kind.name(),
                    u.base
                ));
            }
        }
    }
    let doorbells = doorbells(platform);
    UNITS.store(up, Ordering::Relaxed);
    STATE_WORD.store(
        if up > 0 { ST_ACTIVE } else { ST_FAILED },
        Ordering::Relaxed,
    );
    *STATE.lock() = Some(State {
        info,
        segment,
        units,
        domains: Vec::new(),
        doorbells,
        uncovered: Vec::new(),
        shared: Vec::new(),
    });
}

#[cfg(target_arch = "aarch64")]
fn doorbells(p: &PlatformInfo) -> [Option<u64>; 2] {
    let gic = p.interrupts.map(|i| i.gic);
    [
        gic.and_then(|g| g.its)
            .map(|its| (its + urmqtt_arch::its::TRANSLATER) & !0xfff),
        gic.and_then(|g| g.v2m),
    ]
}

/// x86: an MSI is an interrupt request, not a DMA, while interrupt
/// remapping is off.
#[cfg(target_arch = "x86_64")]
fn doorbells(_p: &PlatformInfo) -> [Option<u64>; 2] {
    [None, None]
}

fn map_frame(base: u64, len: usize) -> Result<Mmio, Error> {
    let va = memory::map_mmio(base, len as u64)
        .map_err(|_| Error::Unsupported("mapping the registers"))?;
    Ok(Mmio {
        va: va as usize,
        len,
    })
}

fn bring_up(kind: Kind, base: u64, max_id: u32) -> Result<Unit, Error> {
    match kind {
        Kind::VtD => {
            let probe = map_frame(base, 0x1000)?;
            let caps = vtd::Caps::decode(probe.read64(vtd::CAP), probe.read64(vtd::ECAP));
            let regs = if caps.frame_len() > 0x1000 {
                map_frame(base, caps.frame_len())?
            } else {
                probe
            };
            let mut env = KEnv::new(caps.coherent);
            let v = Vtd::init(regs, &mut env)?;
            info!(
                "iommu: VT-d at {base:#x}: {}-level tables, {} domains, caching mode {}, coherent {}, interrupt remapping {} (left off), translation on: every device blocked until it is given a domain",
                v.levels,
                caps.domains,
                caps.caching_mode,
                caps.coherent,
                if caps.interrupt_remapping {
                    "available"
                } else {
                    "absent"
                }
            );
            Ok(Unit {
                kind,
                base,
                drv: Driver::Vtd(alloc::boxed::Box::new(v)),
                env,
            })
        }
        Kind::AmdVi => {
            let regs = map_frame(base, amdvi::FRAME_LEN)?;
            let efr = regs.read64(amdvi::EXT_FEATURE);
            let mut env = KEnv::new(true);
            let a = AmdVi::init(regs, &mut env)?;
            info!(
                "iommu: AMD-Vi at {base:#x}: {}-level tables, device table for all 65536 IDs, extended features {efr:#x}, enabled: every device blocked until it is given a domain",
                a.levels
            );
            Ok(Unit {
                kind,
                base,
                drv: Driver::Amd(a),
                env,
            })
        }
        Kind::SmmuV3 => {
            let regs = map_frame(base, smmuv3::FRAME_LEN)?;
            let caps = smmuv3::Caps::decode(
                regs.read32(smmuv3::IDR0),
                regs.read32(smmuv3::IDR1),
                regs.read32(smmuv3::IDR5),
            );
            let mut env = KEnv::new(caps.coherent);
            let s = Smmu::init(regs, &mut env, max_id)?;
            info!(
                "iommu: SMMUv3 at {base:#x}: stage 1, {}-level tables, {}-bit output, stream table for IDs 0..{}, coherent {}, enabled: every stream aborted until it is given a domain",
                s.levels,
                caps.oas,
                1u32 << s.sid_log2,
                caps.coherent
            );
            Ok(Unit {
                kind,
                base,
                drv: Driver::Smmu(s),
                env,
            })
        }
    }
}

/// The domain of `bdf`, created on first use: its index in `s.domains`, or
/// `None` when the device is not translated (auto) or the unit refused.
fn domain_of(s: &mut State, bdf: Bdf) -> Option<usize> {
    if let Some(i) = s.domains.iter().position(|d| d.bdf == bdf) {
        return Some(i);
    }
    // Refused once already: counted and logged then, not on every allocation.
    if s.uncovered.contains(&bdf) {
        return None;
    }
    let Some((ui, id)) = s.info.unit_for(s.segment, rid(bdf)) else {
        s.uncovered.push(bdf);
        if s.info.unclear(s.segment, rid(bdf)) {
            refuse(format_args!(
                "pci {bdf} may be behind a unit whose scope the firmware tables do not let the kernel represent \
                 (a bridge's sub-hierarchy, an unknown entry, more units or ranges than it keeps), not the catch-all one"
            ));
        } else {
            refuse(format_args!(
                "pci {bdf} is not behind any IOMMU the firmware describes"
            ));
        }
        return None;
    };
    if let Some(i) = s.domains.iter().position(|d| d.unit == ui && d.id == id) {
        // The unit cannot tell the two apart: one domain, and the log says
        // they are not isolated from each other.
        let other = s.domains.get(i).map(|d| d.bdf);
        if let Some(o) = other {
            warn!(
                "iommu: pci {bdf} reaches its unit with the same ID ({id:#x}) as pci {o}: they share one domain and are not isolated from each other"
            );
        }
        s.shared.push(bdf);
        return Some(i);
    }
    let Some(unit) = s.units.get_mut(ui).and_then(Option::as_mut) else {
        s.uncovered.push(bdf);
        refuse(format_args!(
            "pci {bdf} is behind a unit that did not come up"
        ));
        return None;
    };
    let (mut tables, tag) = match unit.attach(id) {
        Ok(d) => d,
        Err(e) => {
            s.uncovered.push(bdf);
            refuse(format_args!("pci {bdf}: no domain: {e}"));
            return None;
        }
    };
    for db in s.doorbells.iter().flatten() {
        if let Err(e) = tables.map(&mut unit.env, *db, urmqtt_iommu::PAGE, Access::DOORBELL) {
            refuse(format_args!(
                "pci {bdf}: the MSI doorbell {db:#x} could not be mapped: {e}"
            ));
        }
    }
    info!(
        "iommu: pci {bdf}: own domain on {} {:#x} (ID {id:#x}{}){}",
        unit.kind.name(),
        unit.base,
        match unit.drv {
            Driver::Vtd(_) => alloc::format!(", domain {}", s.domains.len() + 1),
            Driver::Amd(_) => alloc::format!(", domain {tag}"),
            Driver::Smmu(_) => alloc::format!(", ASID {tag}"),
        },
        if s.doorbells.iter().any(Option::is_some) {
            ", MSI doorbell mapped"
        } else {
            ""
        }
    );
    s.domains.push(Domain {
        bdf,
        unit: ui,
        id,
        tables,
        tag,
    });
    DOMAINS.store(s.domains.len() as u64, Ordering::Relaxed);
    Some(s.domains.len() - 1)
}

/// A virtio device at `bdf` that does not offer VIRTIO_F_ACCESS_PLATFORM
/// reaches memory around the IOMMU (virtio 1.x §6): with translation active
/// that is a device without isolation.
pub fn bypass(bdf: Bdf) {
    if !active() {
        return;
    }
    if let Some(s) = STATE.lock().as_mut()
        && !s.uncovered.contains(&bdf)
    {
        s.uncovered.push(bdf);
    }
    refuse(format_args!(
        "pci {bdf}: the virtio device does not offer VIRTIO_F_ACCESS_PLATFORM, so it bypasses the IOMMU \
         (QEMU: iommu_platform=on)"
    ));
}

/// Gives `dev` (the device the memory is for) access to `[pa, pa + len)`.
/// Called for every DMA allocation of a driver (`devices::KernelEnv`).
pub fn map(dev: Option<Bdf>, pa: u64, len: usize) {
    if STATE_WORD.load(Ordering::Relaxed) != ST_ACTIVE {
        return;
    }
    let mut g = STATE.lock();
    let Some(s) = g.as_mut() else { return };
    let Some(bdf) = dev else {
        if !WARNED_RUNTIME.swap(true, Ordering::Relaxed) {
            warn!(
                "iommu: DMA memory allocated for no named device at {pa:#x}: no device can reach it"
            );
        }
        return;
    };
    let Some(i) = domain_of(s, bdf) else { return };
    let Some(d) = s.domains.get_mut(i) else {
        return;
    };
    let Some(unit) = s.units.get_mut(d.unit).and_then(Option::as_mut) else {
        return;
    };
    let before = d.tables.pages;
    let r = d
        .tables
        .map(&mut unit.env, pa, len as u64, Access::RW)
        .and_then(|()| unit.invalidate(d.tag));
    PAGES.fetch_add(u64::from(d.tables.pages - before), Ordering::Relaxed);
    if let Err(e) = r {
        match mode() {
            Mode::Require => crate::boot::fatal_fmt(format_args!(
                "iommu: pci {bdf}: mapping {len} bytes at {pa:#x} failed: {e}"
            )),
            _ => error!(
                "iommu: pci {bdf}: mapping {len} bytes at {pa:#x} failed: {e}: the device will fault"
            ),
        }
    }
}

/// Reads the units' fault logs: at most [`POLL_MAX`] per unit. Core 0's
/// tick calls it every 100 ms; it only tries the lock (a poll that finds
/// the bring-up or a mapping in progress is skipped).
pub fn poll() {
    if STATE_WORD.load(Ordering::Relaxed) != ST_ACTIVE {
        return;
    }
    let Some(mut g) = STATE.try_lock() else {
        return;
    };
    let Some(s) = g.as_mut() else { return };
    for unit in s.units.iter_mut().flatten() {
        let (kind, base) = (unit.kind, unit.base);
        let p = unit.poll(POLL_MAX, |f| {
            let n = FAULTS.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= LOG_FIRST || n.is_power_of_two() {
                warn!(
                    "iommu: fault {n}: {} {base:#x}: pci {} {} {:#x} blocked (reason {:#x}){}",
                    kind.name(),
                    bdf_of(f.source),
                    if f.write { "write to" } else { "access to" },
                    f.addr,
                    f.reason,
                    if n == LOG_FIRST {
                        "; from now on only every power of two is logged, $SYS/broker/iommu/faults counts all"
                    } else {
                        ""
                    }
                );
            }
        });
        if p.overflowed {
            let n = OVERFLOWS.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                "iommu: {} {base:#x}: its fault log overflowed (faults lost; {n} overflow(s))",
                kind.name()
            );
        }
    }
}

/// The figures of `$SYS/broker/iommu/...`.
pub fn sys() -> urmqtt_broker::sys::IommuSys<'static> {
    urmqtt_broker::sys::IommuSys {
        mode: mode().name(),
        state: match STATE_WORD.load(Ordering::Relaxed) {
            ST_NONE => "none",
            ST_FAILED => "failed",
            ST_ACTIVE => "active",
            _ => "off",
        },
        units: UNITS.load(Ordering::Relaxed),
        domains: DOMAINS.load(Ordering::Relaxed),
        pages: PAGES.load(Ordering::Relaxed),
        faults: FAULTS.load(Ordering::Relaxed),
        overflows: OVERFLOWS.load(Ordering::Relaxed),
    }
}

/// Whether translation is active (some unit up).
pub fn active() -> bool {
    STATE_WORD.load(Ordering::Relaxed) == ST_ACTIVE
}

/// The boot summary: one line once every driver has run.
pub fn summary() {
    if !active() {
        return;
    }
    let g = STATE.lock();
    let Some(s) = g.as_ref() else { return };
    info!(
        "iommu: active: {} unit(s), {} device domain(s), {} page(s) mapped for devices, {} KiB of tables, {} device(s) without isolation{}",
        UNITS.load(Ordering::Relaxed),
        s.domains.len(),
        PAGES.load(Ordering::Relaxed),
        PAGES_TABLES.load(Ordering::Relaxed) * 4,
        s.uncovered.len(),
        if s.shared.is_empty() {
            alloc::string::String::new()
        } else {
            alloc::format!(", {} sharing another's domain", s.shared.len())
        }
    );
}

/// Faults counted so far.
pub fn faults() -> u64 {
    FAULTS.load(Ordering::Relaxed)
}
