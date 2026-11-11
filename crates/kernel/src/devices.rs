//! PCIe and virtio bring-up (M6, X7): configuration access (ECAM, or the
//! 0xCF8/0xCFC ports on x86 without an MCFG table), device initialisation,
//! entropy seeding, MSI-X through an `arch::msi` frame (a GICv2m frame on
//! aarch64, the local APIC window on x86), and device self-tests.
//!
//! All MMIO mappings happen in [`probe`], before the page tables lock;
//! the self-tests afterwards only use DMA memory and registers.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;

use urmqtt_arch::{msi, time};
use urmqtt_log::{info, warn};
use urmqtt_pci::{self as pci, Bar, Bdf, ConfigSpace};
use urmqtt_platform::PlatformInfo;
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::gpt::{self, DataPartition, Guid};
use urmqtt_store::{BlockDevice, IoError};
use urmqtt_sync::sync::SpinLock;
use urmqtt_tls::rng::{Csprng, EntropyPool, Source};
use urmqtt_virtio::blk::VirtioBlk;
#[cfg(feature = "virtio-gpu")]
use urmqtt_virtio::gpu::{AutoChoice, VirtioGpu, auto_choice};
use urmqtt_virtio::net::{MAX_PAIRS, VirtioNet};
use urmqtt_virtio::registry::{self, State};
use urmqtt_virtio::rng::VirtioRng;
use urmqtt_virtio::scsi::{DiskInfo, ScsiDisk, VirtioScsi};
use urmqtt_virtio::transport::CapLoc;
use urmqtt_virtio::wake::{Mode, Why};
use urmqtt_virtio::{
    DeviceType, DmaRegion, Env, Region, Support, Transport, VirtioCaps, VirtioError, find_caps,
};

use crate::{irq, memory, vdev, vm};

/// ECAM configuration space mapped at `va`.
pub struct Ecam {
    va: usize,
    bus_start: u8,
    bus_end: u8,
}

impl Ecam {
    fn addr(&self, bdf: Bdf, off: u16) -> Option<usize> {
        if bdf.bus < self.bus_start || bdf.bus > self.bus_end || off >= 4096 {
            return None;
        }
        Some(self.va + bdf.ecam_offset(self.bus_start) as usize + usize::from(off & !3))
    }
}

impl ConfigSpace for Ecam {
    fn read32(&self, bdf: Bdf, off: u16) -> u32 {
        match self.addr(bdf, off) {
            // SAFETY: inside the mapped ECAM window for this bus range.
            Some(a) => unsafe { (a as *const u32).read_volatile() },
            None => u32::MAX,
        }
    }

    fn write32(&mut self, bdf: Bdf, off: u16, v: u32) {
        if let Some(a) = self.addr(bdf, off) {
            // SAFETY: as in `read32`.
            unsafe { (a as *mut u32).write_volatile(v) }
        }
    }
}

/// x86 port I/O, the transport of configuration mechanism #1.
#[cfg(target_arch = "x86_64")]
pub struct Ports;

#[cfg(target_arch = "x86_64")]
impl pci::PortIo for Ports {
    fn outl(&self, port: u16, value: u32) {
        urmqtt_arch::pio::outl(port, value);
    }

    fn inl(&self, port: u16) -> u32 {
        urmqtt_arch::pio::inl(port)
    }
}

/// The configuration-space backend in use.
pub enum Cfg {
    Ecam(Ecam),
    #[cfg(target_arch = "x86_64")]
    Ports(pci::PortConfig<Ports>),
}

impl ConfigSpace for Cfg {
    fn read32(&self, bdf: Bdf, off: u16) -> u32 {
        match self {
            Self::Ecam(e) => e.read32(bdf, off),
            #[cfg(target_arch = "x86_64")]
            Self::Ports(p) => p.read32(bdf, off),
        }
    }

    fn write32(&mut self, bdf: Bdf, off: u16, v: u32) {
        match self {
            Self::Ecam(e) => e.write32(bdf, off, v),
            #[cfg(target_arch = "x86_64")]
            Self::Ports(p) => p.write32(bdf, off, v),
        }
    }
}

/// The kernel side of the virtio `Env`: DMA memory for one device, which the
/// IOMMU (when one is in use, ADR-305) maps into that device's domain.
pub struct KernelEnv {
    dev: Option<Bdf>,
}

impl KernelEnv {
    /// For the work after bring-up, which allocates no DMA memory.
    pub const RUNTIME: Self = Self { dev: None };

    /// For the bring-up of the device at `bdf`.
    pub const fn device(bdf: Bdf) -> Self {
        Self { dev: Some(bdf) }
    }
}

impl Env for KernelEnv {
    fn dma_alloc(&self, bytes: usize) -> Option<DmaRegion> {
        let (va, pa, len) = vm::dma_alloc(bytes)?;
        crate::iommu::map(self.dev, pa, len);
        Some(DmaRegion { va, pa, len })
    }

    fn platform_access(&self, offered: bool) {
        if let (Some(bdf), false) = (self.dev, offered) {
            crate::iommu::bypass(bdf);
        }
    }

    fn now_ns(&self) -> u64 {
        time::uptime_ns()
    }
}

/// The data disk: a virtio-blk device, or one LUN behind virtio-scsi (the
/// way many clouds attach disks).
pub enum DataDisk {
    Blk(VirtioBlk),
    Scsi(ScsiDisk),
}

impl DataDisk {
    pub fn capacity_sectors(&self) -> u64 {
        match self {
            Self::Blk(b) => b.capacity_sectors,
            Self::Scsi(s) => s.capacity_sectors,
        }
    }

    /// Whether writes can be made durable (virtio-blk needs
    /// `VIRTIO_BLK_F_FLUSH`; SCSI disks take SYNCHRONIZE CACHE).
    pub fn has_flush(&self) -> bool {
        match self {
            Self::Blk(b) => b.has_flush,
            Self::Scsi(_) => true,
        }
    }

    /// Block sizes and I/O hints, as the store's topology (S2).
    pub fn topology(&self) -> urmqtt_store::layout::Topology {
        let t = match self {
            Self::Blk(b) => b.topology,
            Self::Scsi(s) => s.topology,
        };
        urmqtt_store::layout::Topology {
            logical: t.logical,
            physical: t.physical,
            align_offset: t.align_offset,
            min_io: t.min_io,
            opt_io: t.opt_io,
        }
    }

    /// The capacity after a configuration-change notification: `Some` if
    /// the disk got larger (virtio-blk only; a SCSI LUN is not notified).
    pub fn refresh_capacity(&mut self) -> Option<u64> {
        match self {
            Self::Blk(b) => b.refresh_capacity(),
            Self::Scsi(_) => None,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Blk(b) => b.read_only,
            // A write-protected LUN fails its writes (the self-test).
            Self::Scsi(_) => false,
        }
    }

    pub fn max_io(&self) -> usize {
        match self {
            Self::Blk(_) => urmqtt_virtio::blk::MAX_IO,
            Self::Scsi(s) => s.max_io(),
        }
    }

    /// What the device can discard and its limits (S4, ADR-150): DISCARD or
    /// UNMAP, else WRITE ZEROES that may unmap. `None` for a read-only disk
    /// or a device with neither.
    pub fn discard_caps(&self) -> Option<urmqtt_store::disk::DiscardCaps> {
        use urmqtt_store::disk::{DiscardCaps, DiscardKind};
        let (u, ro) = match self {
            Self::Blk(b) => (b.unmap, b.read_only),
            Self::Scsi(s) => (s.unmap, false),
        };
        if ro {
            return None;
        }
        if u.discard {
            Some(DiscardCaps {
                kind: DiscardKind::Discard,
                max_sectors: u64::from(u.max_discard_sectors),
                max_ranges: u.max_discard_ranges,
                granularity: u64::from(u.discard_align),
            })
        } else if u.zeroes {
            Some(DiscardCaps {
                kind: DiscardKind::WriteZeroes,
                max_sectors: u64::from(u.max_zeroes_sectors),
                max_ranges: u.max_zeroes_ranges,
                granularity: u64::from(u.discard_align),
            })
        } else {
            None
        }
    }

    /// Releases the (first sector, sectors) ranges, within the limits of
    /// [`discard_caps`](Self::discard_caps).
    pub fn discard(&mut self, ranges: &[(u64, u64)]) -> Result<(), urmqtt_virtio::VirtioError> {
        let mut v: alloc::vec::Vec<(u64, u32)> = alloc::vec::Vec::with_capacity(ranges.len());
        for &(s, n) in ranges {
            let n = u32::try_from(n).map_err(|_| urmqtt_virtio::VirtioError::OutOfRange)?;
            v.push((s, n));
        }
        let r = v.as_slice();
        match self {
            Self::Blk(b) if b.unmap.discard => b.discard(&KernelEnv::RUNTIME, r),
            Self::Blk(b) => b.write_zeroes(&KernelEnv::RUNTIME, r),
            Self::Scsi(s) if s.unmap.discard => s.discard(&KernelEnv::RUNTIME, r),
            Self::Scsi(s) => s.write_zeroes(&KernelEnv::RUNTIME, r),
        }
    }

    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.read(&KernelEnv::RUNTIME, sector, buf),
            Self::Scsi(s) => s.read(&KernelEnv::RUNTIME, sector, buf),
        }
    }

    pub fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.write(&KernelEnv::RUNTIME, sector, data),
            Self::Scsi(s) => s.write(&KernelEnv::RUNTIME, sector, data),
        }
    }

    pub fn flush(&mut self) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.flush(&KernelEnv::RUNTIME),
            Self::Scsi(s) => s.flush(&KernelEnv::RUNTIME),
        }
    }
}

/// The boot disk as a block device: the driver, and whether its flushes
/// are real (`storage.require_flush = false` allows none, dev only).
pub struct KernelBlk {
    pub blk: DataDisk,
    pub flush: bool,
}

// SAFETY: the wrapper owns the device exclusively; it is used by one core
// at a time (the boot CPU at boot, then the DB core).
unsafe impl Send for KernelBlk {}

impl BlockDevice for KernelBlk {
    fn sectors(&self) -> u64 {
        self.blk.capacity_sectors()
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), IoError> {
        self.blk.read(lba, buf).map_err(|_| IoError::Device)
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), IoError> {
        self.blk.write(lba, buf).map_err(|_| IoError::Device)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if !self.flush {
            // Only reachable with storage.require_flush = false (dev).
            return Ok(());
        }
        self.blk.flush().map_err(|_| IoError::Device)
    }

    fn max_io(&self) -> usize {
        self.blk.max_io()
    }

    fn topology(&self) -> urmqtt_store::layout::Topology {
        self.blk.topology()
    }

    fn refresh_size(&mut self) -> Option<u64> {
        self.blk.refresh_capacity()
    }

    fn discard_caps(&self) -> Option<urmqtt_store::disk::DiscardCaps> {
        self.blk.discard_caps()
    }

    fn discard(&mut self, ranges: &[(u64, u64)]) -> Result<(), IoError> {
        self.blk.discard(ranges).map_err(|e| match e {
            // The device said it does not implement the command.
            urmqtt_virtio::VirtioError::Io(urmqtt_virtio::blk::S_UNSUPP)
            | urmqtt_virtio::VirtioError::MissingFeatures(_) => IoError::Unsupported,
            _ => IoError::Device,
        })
    }
}

/// A device's block sizes and I/O hints, for the boot log (S2).
struct TopologyText(urmqtt_virtio::BlockTopology);

impl core::fmt::Display for TopologyText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let t = &self.0;
        write!(
            f,
            "logical {} B, physical {} B, alignment offset {} B, minimum I/O {} B, optimal I/O {} B",
            t.logical, t.physical, t.align_offset, t.min_io, t.opt_io
        )
    }
}

/// Where Limine loaded the kernel from (STORAGE-PLAN §2a).
#[derive(Debug, Clone, Copy, Default)]
pub struct BootMedium {
    /// A CD or DVD (an ISO): read-only, no data partition possible.
    pub optical: bool,
    /// The GPT disk GUID of the boot disk, if it has a GPT.
    pub disk_guid: Option<Guid>,
    /// The GPT unique GUID of the partition the kernel was loaded from: the
    /// ESP entry, or the standby boot slot if the firmware booted that
    /// (ADR-296).
    pub part_guid: Option<Guid>,
}

/// The boot disk with its data partition, ready for the store.
pub struct BootDisk {
    pub dev: Box<dyn BlockDevice>,
    pub partition: DataPartition,
    /// Fault injection is active (dev `test=disk-fault:`).
    pub faulty: bool,
}

/// Initialised devices, kept for later milestones (network stack, storage).
pub struct Devices {
    pub net: Option<VirtioNet>,
    /// The disk Limine booted from (the only disk ever written).
    pub blk: Option<DataDisk>,
    pub rng: Option<VirtioRng>,
    /// Where the entropy device is (the IOMMU test, ADR-307).
    pub rng_bdf: Option<Bdf>,
    pub blk_msix_spi: Option<u32>,
    /// The NIC's receive interrupt (ADR-270): its SPI or vector, and the
    /// dispatcher's wake-up mode.
    pub net_msix_spi: Option<u32>,
    pub net_wake: Mode,
    /// Disks driven but left alone (not the boot disk).
    pub other_disks: u32,
    /// The boot disk after [`prepare_boot_disk`].
    pub boot: Option<BootDisk>,
    /// Install mode (S1b): every disk, for the installer to choose from.
    pub install: alloc::vec::Vec<InstallDisk>,
    /// Install mode: the virtio-scsi HBAs whose LUNs are candidates.
    pub hbas: alloc::vec::Vec<Option<VirtioScsi>>,
}

/// A disk the installer may write (install mode only).
pub struct InstallDisk {
    pub name: alloc::string::String,
    pub sectors: u64,
    pub read_only: bool,
    /// The installer's own boot medium (a disk with the boot GPT GUID).
    pub boot_medium: bool,
    pub source: InstallSource,
}

pub enum InstallSource {
    Blk(Box<VirtioBlk>),
    /// A LUN behind HBA `hba` of [`Devices::hbas`].
    Scsi {
        hba: usize,
        info: DiskInfo,
    },
}

/// A PCI function the enumeration saw, kept for the diagnostic (O4).
pub struct PciSeen {
    pub bdf: alloc::string::String,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub driver: Option<&'static str>,
}

pub static PCI_SEEN: SpinLock<alloc::vec::Vec<PciSeen>> = SpinLock::new(alloc::vec::Vec::new());

/// A disk handed to the diagnostic; `disk` is `None` when the controller
/// was already given to another LUN (one LUN per virtio-scsi HBA).
pub struct DiagDisk {
    pub name: alloc::string::String,
    pub bus: &'static str,
    pub sectors: u64,
    pub read_only: bool,
    pub boot_medium: bool,
    pub disk: Option<DataDisk>,
}

/// Takes every candidate disk (install mode, which the diagnostic shares:
/// no disk is chosen or written by the probe).
pub fn take_diag_disks() -> alloc::vec::Vec<DiagDisk> {
    let mut devs = DEVICES.lock();
    let list = core::mem::take(&mut devs.install);
    let mut out = alloc::vec::Vec::new();
    for d in list {
        let (bus, disk) = match d.source {
            InstallSource::Blk(b) => ("virtio-blk", Some(DataDisk::Blk(*b))),
            InstallSource::Scsi { hba, info } => (
                "virtio-scsi",
                devs.hbas
                    .get_mut(hba)
                    .and_then(Option::take)
                    .map(|h| DataDisk::Scsi(h.into_disk(info))),
            ),
        };
        out.push(DiagDisk {
            name: d.name,
            bus,
            sectors: d.sectors,
            read_only: d.read_only,
            boot_medium: d.boot_medium,
            disk,
        });
    }
    out
}

static INSTALL_MODE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Install mode: [`probe`] keeps every disk as a candidate (written by
/// nothing but the installer) instead of choosing the boot disk.
pub fn set_install_mode(on: bool) {
    // Relaxed: set before probe, on the boot CPU.
    INSTALL_MODE.store(on, Ordering::Relaxed);
}

fn install_mode() -> bool {
    INSTALL_MODE.load(Ordering::Relaxed)
}

/// Takes candidate `i` out as a usable disk.
pub fn take_install_disk(i: usize) -> Option<DataDisk> {
    let mut devs = DEVICES.lock();
    if i >= devs.install.len() {
        return None;
    }
    let d = devs.install.swap_remove(i);
    match d.source {
        InstallSource::Blk(b) => Some(DataDisk::Blk(*b)),
        InstallSource::Scsi { hba, info } => devs
            .hbas
            .get_mut(hba)
            .and_then(Option::take)
            .map(|h| DataDisk::Scsi(h.into_disk(info))),
    }
}

pub static DEVICES: SpinLock<Devices> = SpinLock::new(Devices {
    net: None,
    blk: None,
    rng: None,
    rng_bdf: None,
    blk_msix_spi: None,
    net_msix_spi: None,
    net_wake: Mode::Polling(Why::NoMsix),
    other_disks: 0,
    boot: None,
    install: alloc::vec::Vec::new(),
    hbas: alloc::vec::Vec::new(),
});

static BOOT_MEDIUM: SpinLock<BootMedium> = SpinLock::new(BootMedium {
    optical: false,
    disk_guid: None,
    part_guid: None,
});

/// Records where the kernel was loaded from (before [`probe`]).
pub fn set_boot_medium(m: BootMedium) {
    *BOOT_MEDIUM.lock() = m;
}

pub fn boot_medium() -> BootMedium {
    *BOOT_MEDIUM.lock()
}

/// The disk GUID of a disk whose sectors 1..=33 are `head`.
fn guid_of(head: &[u8], sectors: u64) -> Option<Guid> {
    urmqtt_store::gpt::primary_guid(head, sectors)
}

/// Whether a disk with GPT GUID `g` is the boot disk.
fn is_boot_disk(g: Option<Guid>) -> bool {
    let m = boot_medium();
    !m.optical && g.is_some() && g == m.disk_guid
}

/// Network controllers found without a driver: (vendor, device).
pub static OTHER_NICS: SpinLock<alloc::vec::Vec<(u16, u16)>> =
    SpinLock::new(alloc::vec::Vec::new());

/// A name for a NIC vendor, for the missing-driver message.
pub fn nic_vendor(v: u16) -> &'static str {
    match v {
        0x15b3 => "Mellanox/NVIDIA (ConnectX, SR-IOV)",
        0x8086 => "Intel",
        0x14e4 => "Broadcom",
        0x1d0f => "Amazon (ENA)",
        0x1414 => "Microsoft (MANA)",
        0x1af4 => "virtio (transitional/unknown)",
        _ => "unknown vendor",
    }
}

/// What the boot did with each entropy source, for the Diagnostic entry.
#[derive(Clone, Default)]
pub struct EntropyFacts {
    /// How many of the bootloader's values were not zero.
    pub bootloader_values: u32,
    /// `None`: no virtio-rng device; `Some(Ok(n))`: n bytes; `Some(Err)`: failed.
    pub virtio_rng: Option<Result<usize, ()>>,
    /// The CPU's own instructions delivered 64 bytes.
    pub hw_rng: bool,
    /// The jitter fallback ran: clock, granularity shift, samples, steps per
    /// sample, bits per sample estimated, bits credited, health tests failed.
    pub jitter: Option<JitterFacts>,
    /// `entropy.jitter_fallback` of the configuration.
    pub fallback_allowed: bool,
    /// The sources that went into the pool (`EntropyPool::sources`).
    pub mask: u8,
    /// A hardware source alone seeded the generator.
    pub hardware_seed: bool,
}

#[derive(Clone)]
pub struct JitterFacts {
    pub clock: &'static str,
    pub shift: u32,
    pub samples: u32,
    pub iters: u32,
    pub bits_per_sample: u32,
    pub credited: u64,
    pub failed: bool,
}

pub static ENTROPY_FACTS: SpinLock<EntropyFacts> = SpinLock::new(EntropyFacts {
    bootloader_values: 0,
    virtio_rng: None,
    hw_rng: false,
    jitter: None,
    fallback_allowed: false,
    mask: 0,
    hardware_seed: false,
});

/// The name of what seeded the generator, for `$SYS/broker/entropy/source`
/// and the status (ADR-263); set once at boot, `unknown` before.
static ENTROPY_NAME: SpinLock<&'static str> = SpinLock::new("unknown");

/// What seeded the generator (`virtio-rng`, `rndr`, `virtio-rng+rndr`,
/// `jitter+firmware`, ...).
pub fn entropy_source_name() -> &'static str {
    *ENTROPY_NAME.lock()
}

/// Fresh bytes from the virtio-rng device, for the Diagnostic entry's sanity
/// test; returns how many it got (0 without the device).
pub fn sample_virtio_rng(out: &mut [u8]) -> usize {
    match DEVICES.lock().rng.as_mut() {
        Some(rng) => rng.fill(&KernelEnv::RUNTIME, out).unwrap_or(0),
        None => 0,
    }
}

/// Fresh bytes from the CPU's own random instructions (64 per call).
pub fn sample_hw_rng(out: &mut [u8]) -> usize {
    let mut n = 0;
    for chunk in out.chunks_mut(64) {
        match urmqtt_arch::entropy::hw_random() {
            Some(r) => {
                let k = chunk.len();
                chunk.copy_from_slice(&r[..k]);
                n += k;
            }
            None => break,
        }
    }
    n
}

/// The boot CPU's CSPRNG (per-core generators are forked from it).
pub static RNG: SpinLock<Option<Csprng>> = SpinLock::new(None);

static BLK_IRQS: AtomicU64 = AtomicU64::new(0);

/// Interrupts the boot disk's vector has raised: completions of its
/// requests, and the configuration-change notification of a resize (S3,
/// ADR-143), which has no request behind it.
pub fn blk_irqs() -> u64 {
    // Relaxed: a counter compared with an earlier reading.
    BLK_IRQS.load(Ordering::Relaxed)
}

/// The handler of a disk's vector until (unless) the disk becomes the boot
/// disk: its completions are polled, the interrupt only needs its EOI.
fn ignore_irq(_intid: u32) {}

static NET_IRQS: AtomicU64 = AtomicU64::new(0);

/// Receive interrupts of the NIC (ADR-270): the dispatcher compares the
/// counter across a sleep, the statistics show it per window.
pub fn net_irqs() -> u64 {
    // Relaxed: a counter compared with an earlier reading on the same core
    // that takes the interrupt.
    NET_IRQS.load(Ordering::Relaxed)
}

/// The NIC's receive interrupt: only counted. The interrupt itself ended the
/// dispatcher's `wfi`/`hlt`; the dispatcher reads the ring.
fn on_net_irq(_intid: u32) {
    // Relaxed: see `net_irqs`.
    NET_IRQS.fetch_add(1, Ordering::Relaxed);
}

fn on_blk_irq(_intid: u32) {
    // Relaxed: statistics read by the boot CPU after the self-test.
    BLK_IRQS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy)]
pub enum ProbeError {
    Map,
    NoEntropy,
    #[allow(dead_code)] // read through `Debug` in the fatal boot message
    Virtio(VirtioError),
}

impl From<VirtioError> for ProbeError {
    fn from(e: VirtioError) -> Self {
        Self::Virtio(e)
    }
}

fn map(pa: u64, len: u64) -> Result<usize, ProbeError> {
    memory::map_mmio(pa, len)
        .map(|va| va as usize)
        .map_err(|_| ProbeError::Map)
}

/// Maps one virtio structure. `loc == None` gives an empty region when
/// `optional` (virtio-rng has no device configuration), else an error. The
/// structure must lie inside its memory BAR (sized by probing).
fn region<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    loc: Option<CapLoc>,
    optional: bool,
) -> Result<Region, ProbeError> {
    let Some(loc) = loc else {
        if !optional {
            return Err(ProbeError::Map);
        }
        // SAFETY: a zero-length region is never dereferenced.
        return Ok(unsafe { Region::new(0, 0) });
    };
    let Some(Bar::Memory { base, .. }) = pci::bar(cfg, bdf, loc.bar) else {
        return Err(ProbeError::Map);
    };
    let end = u64::from(loc.offset) + u64::from(loc.length);
    if pci::bar_size(cfg, bdf, loc.bar).is_none_or(|size| end > size) {
        return Err(ProbeError::Map);
    }
    let va = map(base + u64::from(loc.offset), u64::from(loc.length.max(4)))?;
    // SAFETY: just mapped as device memory for the kernel's lifetime.
    Ok(unsafe { Region::new(va, loc.length as usize) })
}

pub(crate) fn transport<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    caps: &VirtioCaps,
    device_optional: bool,
) -> Result<Transport, ProbeError> {
    Ok(Transport {
        common: region(cfg, bdf, caps.common, false)?,
        notify: region(cfg, bdf, caps.notify, false)?,
        notify_multiplier: caps.notify_multiplier,
        device: region(cfg, bdf, caps.device, device_optional)?,
    })
}

/// Points MSI-X vector 0 of `bdf` at a fresh GICv2m SPI (aarch64) or CPU
/// vector (x86) and enables MSI-X. The error says why the device stays
/// polled (ADR-270's boot line).
fn setup_msix<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    frame: Option<&mut msi::Frame>,
) -> Result<u32, Why> {
    setup_msix_with(cfg, bdf, || {
        let frame = frame.ok_or(Why::NoMsiSource)?;
        let spi = frame.alloc().ok_or(Why::NoVector)?;
        let (address, data) = frame.compose(spi);
        Ok((spi, address, data))
    })
}

/// Points MSI-X vector 0 of `bdf` at the message `source` hands out (the
/// interrupt number, address and data) and enables MSI-X.
fn setup_msix_with<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    source: impl FnOnce() -> Result<(u32, u64, u32), Why>,
) -> Result<u32, Why> {
    setup_msix_queues(cfg, bdf, source, 1, |_| Err(Why::NoVector)).map(|(id, _)| id)
}

/// An MSI-X table: where it is mapped, and its entries.
#[derive(Clone, Copy)]
struct MsixTable {
    va: usize,
    entries: u16,
}

impl MsixTable {
    /// Writes entry `k` (bounds-checked against the table).
    fn write(&self, k: u16, address: u64, data: u32, masked: bool) {
        if k >= self.entries {
            return;
        }
        let at = self.va + usize::from(k) * 16;
        for (i, w) in pci::msix_entry(address, data, masked).iter().enumerate() {
            // SAFETY: entry `k` (< the table size read from the capability)
            // of the table mapped as device memory in `setup_msix_queues`.
            unsafe { ((at + 4 * i) as *mut u32).write_volatile(*w) };
        }
    }
}

/// [`setup_msix_with`] for a device with `want` queues (the NIC's pairs,
/// NEXT-6, ADR-311): entry 0 as before; entries 1.. get what `more(k)` hands
/// out, written **masked** (the core that will own the queue is not known
/// yet; [`route_net_queue`] aims and unmasks it), or the reason there is
/// none (also for entries beyond the table). Returns entry 0's interrupt
/// and the table with the others.
#[allow(clippy::type_complexity)]
fn setup_msix_queues<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    source: impl FnOnce() -> Result<(u32, u64, u32), Why>,
    want: usize,
    mut more: impl FnMut(u16) -> Result<(u32, u64, u32), Why>,
) -> Result<(u32, NetQueueVectors), Why> {
    let info = pci::msix(cfg, bdf).ok_or(Why::NoMsix)?;
    // The table must lie inside its BAR (ADR-345), as `region` requires of
    // the virtio structures: offset and size are the device's to choose.
    // Sizing the BAR turns decoding off briefly, so it precedes the enable.
    let (pa, len) = pci::msix_table(cfg, bdf, &info).ok_or(Why::TableUnmapped)?;
    let va = map(pa, len).map_err(|_| Why::TableUnmapped)?;
    let table = MsixTable {
        va,
        entries: info.table_size,
    };
    let (id, address, data) = source()?;
    table.write(0, address, data, false);
    let mut v = NetQueueVectors {
        table: Some(table),
        irq: [Err(Why::NoVector); MAX_PAIRS],
    };
    for k in 1..want.min(MAX_PAIRS) {
        let e = k as u16;
        let got = if e < table.entries {
            more(e)
        } else {
            Err(Why::NoVector)
        };
        if let Ok((_, address, data)) = got {
            table.write(e, address, data, true);
        }
        if let Some(slot) = v.irq.get_mut(k) {
            *slot = got;
        }
    }
    pci::msix_enable(cfg, bdf, &info, true);
    pci::enable(cfg, bdf, pci::CMD_INTX_DISABLE);
    Ok((id, v))
}

/// The NIC's receive interrupts of pairs 1.. (NEXT-6, ADR-311): the table
/// and, per pair, the interrupt and its message, or why the pair is polled.
pub struct NetQueueVectors {
    table: Option<MsixTable>,
    irq: [Result<(u32, u64, u32), Why>; MAX_PAIRS],
}

impl NetQueueVectors {
    const NONE: Self = Self {
        table: None,
        irq: [Err(Why::NoMsix); MAX_PAIRS],
    };

    fn all(why: Why) -> Self {
        Self {
            table: None,
            irq: [Err(why); MAX_PAIRS],
        }
    }

    /// Whether pair `k` has a vector (its MSI-X entry is `k`).
    fn has(&self, k: u16) -> bool {
        self.irq.get(usize::from(k)).is_some_and(Result::is_ok)
    }
}

static NET_QUEUE_VECTORS: SpinLock<NetQueueVectors> = SpinLock::new(NetQueueVectors::NONE);

/// Receive interrupts per pair (pair 0 is [`net_irqs`]), and the interrupt
/// number each pair's handler answers to (0: none).
static NET_QUEUE_IRQS: [AtomicU64; MAX_PAIRS] = [const { AtomicU64::new(0) }; MAX_PAIRS];
static NET_QUEUE_INTID: [AtomicU32; MAX_PAIRS] = [const { AtomicU32::new(0) }; MAX_PAIRS];

/// Receive interrupts of pair `k` so far (statistics, and the wake-up
/// machine of the core that owns the pair).
pub fn net_queue_irqs(k: usize) -> u64 {
    if k == 0 {
        return net_irqs();
    }
    // Relaxed: a counter compared with an earlier reading on the core that
    // takes the interrupt.
    NET_QUEUE_IRQS
        .get(k)
        .map_or(0, |c| c.load(Ordering::Relaxed))
}

/// Why pair `k` has no receive interrupt (for its boot line).
pub fn net_queue_why(k: usize) -> Why {
    match NET_QUEUE_VECTORS.lock().irq.get(k) {
        Some(Err(why)) => *why,
        _ => Why::NoVector,
    }
}

/// A receive interrupt of pair 1..: only counted, as [`on_net_irq`].
fn on_net_queue_irq(intid: u32) {
    for (k, id) in NET_QUEUE_INTID.iter().enumerate().skip(1) {
        // Relaxed: written before the vector was unmasked.
        if id.load(Ordering::Relaxed) == intid {
            if let Some(c) = NET_QUEUE_IRQS.get(k) {
                // Relaxed: see `net_queue_irqs`.
                c.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }
}

/// Aims pair `k`'s receive interrupt at logical CPU `cpu` (the core that
/// owns the pair, on that core when it starts) and unmasks it. Returns the
/// interrupt for the boot line, or why the pair stays polled.
pub fn route_net_queue(k: usize, cpu: usize) -> Result<u32, Why> {
    let v = NET_QUEUE_VECTORS.lock();
    let (id, address, data) = v.irq.get(k).copied().unwrap_or(Err(Why::NoVector))?;
    let table = v.table.ok_or(Why::TableUnmapped)?;
    #[cfg(target_arch = "aarch64")]
    let (address, data) = {
        // A GICv2m SPI: the distributor routes it; the message is the same.
        irq::enable_spi(id, cpu);
        (address, data)
    };
    #[cfg(target_arch = "x86_64")]
    let (address, data) = {
        let _ = (address, data);
        // Relaxed: written before the CPU was started.
        let apic = crate::smp::CPUS
            .get(cpu)
            .map_or(u64::MAX, |c| c.mpidr.load(Ordering::Relaxed));
        if apic > 0xfe {
            return Err(Why::CoreZeroOnly);
        }
        msi::message(apic, id)
    };
    if let Some(slot) = NET_QUEUE_INTID.get(k) {
        // Relaxed: the handler reads it only after the unmask below.
        slot.store(id, Ordering::Relaxed);
    }
    table.write(k as u16, address, data, false);
    Ok(id)
}

/// Queue pairs to ask the NIC for (ADR-313): one per CPU (the data cores
/// are not known before the store is opened; a DB core's pair is set up and
/// never used), at most [`MAX_PAIRS`], or one with
/// `devices.virtio_net_queues = "single"`.
static NET_WANT_PAIRS: AtomicUsize = AtomicUsize::new(1);

/// The GICv3 ITS for the NIC's MSI (ADR-270), set up on first use: when
/// the platform has an ITS and no GICv2m frame (QEMU TCG, KVM such as the
/// netcup ARM VPS). Only the NIC uses it: its fallback (polling after missed
/// wake-ups) covers a platform whose ITS maps devices differently, which the
/// boot disk's self-test, which requires its interrupts, would not.
#[cfg(target_arch = "aarch64")]
struct ItsSource {
    its: u64,
    gicr: u64,
    max_device: u32,
    state: Option<Result<urmqtt_arch::its::Its, ()>>,
}

#[cfg(target_arch = "aarch64")]
impl ItsSource {
    fn new(platform: &PlatformInfo, functions: &pci::Functions) -> Option<Self> {
        let i = platform.interrupts?;
        let urmqtt_platform::GicCpu::V3 { gicr } = i.gic.cpu else {
            return None;
        };
        let max_device = functions
            .iter()
            .map(|f| requester_id(f.bdf))
            .max()
            .unwrap_or(0);
        Some(Self {
            its: i.gic.its?,
            gicr: gicr.0,
            max_device,
            state: None,
        })
    }

    /// Maps `bdf`'s event 0 to an LPI: (LPI, address, data).
    fn map(&mut self, bdf: Bdf) -> Result<(u32, u64, u32), Why> {
        let (its, gicr, max) = (self.its, self.gicr, self.max_device);
        let state = self.state.get_or_insert_with(|| match irq::its_init(its, gicr, max) {
            Ok(i) => {
                info!("msi: GICv3 ITS at {its:#x}, device table for requester IDs 0..={max:#x}, LPIs to core 0");
                Ok(i)
            }
            Err(e) => {
                warn!("msi: the GICv3 ITS at {its:#x} could not be set up: {e}");
                Err(())
            }
        });
        let its = state.as_mut().map_err(|()| Why::ItsFailed)?;
        its.map_msi(requester_id(bdf), &mut irq::its_mem)
            .map_err(|e| {
                warn!("msi: the ITS refused {bdf}: {e:?}");
                Why::ItsFailed
            })
    }
}

/// The NIC's MSI-X vector: the GICv2m frame or the local APIC as for the
/// disks, else (aarch64) the GICv3 ITS.
/// Pairs 1.. get further SPIs of the GICv2m frame; the ITS serves core 0
/// only (one collection, ADR-270), so with it they are polled (ADR-311).
#[cfg(target_arch = "aarch64")]
fn net_msix<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    frame: &mut Option<msi::Frame>,
    its: &mut Option<ItsSource>,
    want: usize,
) -> Result<(u32, NetQueueVectors), Why> {
    match (frame.as_mut(), its.as_mut()) {
        (None, Some(its)) => {
            setup_msix_queues(cfg, bdf, || its.map(bdf), want, |_| Err(Why::CoreZeroOnly))
        }
        (Some(frame), _) => {
            let first = frame.alloc().ok_or(Why::NoVector);
            let f = *frame;
            setup_msix_queues(
                cfg,
                bdf,
                || {
                    let spi = first?;
                    let (a, d) = f.compose(spi);
                    Ok((spi, a, d))
                },
                want,
                |_| {
                    let spi = frame.alloc().ok_or(Why::NoVector)?;
                    let (a, d) = frame.compose(spi);
                    Ok((spi, a, d))
                },
            )
        }
        (None, None) => Err(Why::NoMsiSource),
    }
}

/// Pairs 1.. get further vectors of the local APIC; the destination is
/// written when the pair's core is known ([`route_net_queue`]).
#[cfg(target_arch = "x86_64")]
fn net_msix<C: ConfigSpace>(
    cfg: &mut C,
    bdf: Bdf,
    frame: &mut Option<msi::Frame>,
    _its: &mut Option<()>,
    want: usize,
) -> Result<(u32, NetQueueVectors), Why> {
    let Some(frame) = frame.as_mut() else {
        return Err(Why::NoMsiSource);
    };
    let first = frame.alloc().ok_or(Why::NoVector);
    let f = *frame;
    setup_msix_queues(
        cfg,
        bdf,
        || {
            let v = first?;
            let (a, d) = f.compose(v);
            Ok((v, a, d))
        },
        want,
        |_| {
            let v = frame.alloc().ok_or(Why::NoVector)?;
            let (a, d) = frame.compose(v);
            Ok((v, a, d))
        },
    )
}

/// A PCI function's requester ID: the ITS device ID on QEMU's `virt`.
#[cfg(target_arch = "aarch64")]
fn requester_id(bdf: Bdf) -> u32 {
    (u32::from(bdf.bus) << 8) | (u32::from(bdf.dev) << 3) | u32::from(bdf.func)
}

/// Enumerates PCIe, maps and initialises the virtio devices and seeds the
/// CSPRNG. Must run before the page tables are locked.
pub fn probe(
    platform: &PlatformInfo,
    bootloader_entropy: &[u64],
    cpus: u64,
) -> Result<(), ProbeError> {
    let want =
        if urmqtt_config::CONFIG.devices.virtio_net_queues == urmqtt_config::NetQueues::Single {
            1
        } else {
            (cpus as usize).clamp(1, MAX_PAIRS)
        };
    // Relaxed: read by this CPU in `probe_pci` below.
    NET_WANT_PAIRS.store(want, Ordering::Relaxed);
    let env = KernelEnv::RUNTIME;
    let mut pool = EntropyPool::new();
    let mut facts = EntropyFacts {
        bootloader_values: bootloader_entropy.iter().filter(|v| **v != 0).count() as u32,
        ..EntropyFacts::default()
    };
    for v in bootloader_entropy {
        pool.add(Source::Bootloader, &v.to_le_bytes());
    }
    let mut devs = Devices {
        net: None,
        blk: None,
        rng: None,
        rng_bdf: None,
        blk_msix_spi: None,
        net_msix_spi: None,
        net_wake: Mode::Polling(Why::NoMsix),
        other_disks: 0,
        boot: None,
        install: alloc::vec::Vec::new(),
        hbas: alloc::vec::Vec::new(),
    };

    probe_pci(platform, &env, &mut devs)?;

    // Entropy: virtio-rng and RNDR are hardware sources (PROMPT §6).
    let mut hw = [0u8; 64];
    if let Some(rng) = devs.rng.as_mut() {
        match rng.fill(&env, &mut hw) {
            Ok(n) => {
                pool.add(Source::VirtioRng, hw.get(..n).unwrap_or(&[]));
                facts.virtio_rng = Some(Ok(n));
                info!("entropy: {n} bytes from virtio-rng");
            }
            Err(e) => {
                facts.virtio_rng = Some(Err(()));
                warn!("entropy: virtio-rng failed: {e:?}");
            }
        }
    }
    if let Some(r) = urmqtt_arch::entropy::hw_random() {
        pool.add(Source::Rndr, &r);
        facts.hw_rng = true;
        info!("entropy: 64 bytes from {HW_RNG}");
    }
    pool.add(Source::Jitter, &time::now().to_le_bytes());
    let fallback = urmqtt_config::CONFIG.entropy.jitter_fallback;
    facts.fallback_allowed = fallback;
    facts.hardware_seed = pool.has_hardware();
    if !pool.has_hardware() && fallback {
        let t0 = time::uptime_ns();
        let r = crate::jitter::collect(&mut pool);
        warn!(
            "entropy: no hardware source (virtio-rng, {HW_RNG}): CPU jitter fallback via the {} (granularity 2^{}): \
             {} samples of {} steps, {} bit(s)/sample estimated, {} bit(s) credited (1/{}), health tests {}, {} ms; \
             weaker than a hardware source (entropy.fallback = \"none\" refuses such hosts)",
            r.clock,
            r.shift,
            r.samples,
            r.iters,
            r.bits_per_sample,
            r.credited,
            urmqtt_tls::rng::JITTER_SAFETY,
            if r.failed { "FAILED" } else { "passed" },
            (time::uptime_ns() - t0) / 1_000_000
        );
        facts.jitter = Some(JitterFacts {
            clock: r.clock,
            shift: r.shift,
            samples: r.samples,
            iters: r.iters,
            bits_per_sample: r.bits_per_sample,
            credited: r.credited,
            failed: r.failed,
        });
    }
    facts.mask = pool.sources();
    // Leaked once: a few bytes that live as long as the kernel.
    *ENTROPY_NAME.lock() = alloc::boxed::Box::leak(
        urmqtt_broker::sys::entropy_source(
            matches!(facts.virtio_rng, Some(Ok(_))),
            facts.hw_rng.then_some(HW_RNG_NAME),
            facts.jitter.is_some(),
            facts.bootloader_values > 0,
        )
        .into_boxed_str(),
    );
    *ENTROPY_FACTS.lock() = facts;
    let mut rng = pool
        .finish_with(fallback)
        .map_err(|_| ProbeError::NoEntropy)?;
    urmqtt_tls::rng::install(rng.fork());
    *RNG.lock() = Some(rng);
    info!("entropy: ChaCha20 CSPRNG seeded");
    *DEVICES.lock() = devs;
    Ok(())
}

/// The MSI source: the platform's GICv2m frame on aarch64.
#[cfg(target_arch = "aarch64")]
fn msi_frame(platform: &PlatformInfo) -> Option<msi::Frame> {
    platform.interrupts.and_then(|i| i.gic.v2m).and_then(|pa| {
        let va = map(pa, 0x1000).ok()?;
        // SAFETY: MSI_TYPER of the just-mapped v2m frame.
        let typer = unsafe { ((va + msi::TYPER) as *const u32).read_volatile() };
        let frame = msi::Frame::from_typer(pa, typer);
        let (start, end) = frame.spis();
        info!("msi: GICv2m frame at {pa:#x}, SPIs {start}..{end}");
        Some(frame)
    })
}

/// The MSI source on x86: vectors delivered to the boot CPU's local APIC.
#[cfg(target_arch = "x86_64")]
fn msi_frame(_platform: &PlatformInfo) -> Option<msi::Frame> {
    // MSI addresses carry an 8-bit destination.
    let apic_id = urmqtt_arch::pio::initial_apic_id();
    let frame = msi::Frame::from_typer(u64::from(apic_id), 0);
    let (start, end) = frame.spis();
    info!("msi: local APIC {apic_id}, vectors {start}..{end}");
    Some(frame)
}

/// A configuration backend, the bus range to scan and a log description.
type Opened = (Cfg, u8, u8, alloc::string::String);

/// Opens configuration space: ECAM as described by the platform, or (x86)
/// mechanism #1 when there is no usable MCFG region.
fn open_config(platform: &PlatformInfo) -> Result<Option<Opened>, ProbeError> {
    let mut ecam = None;
    if let Some(pcie) = platform.pcie {
        let va = map(pcie.ecam, pcie.ecam_size())?;
        let e = Ecam {
            va,
            bus_start: pcie.bus_start,
            bus_end: pcie.bus_end,
        };
        // Some firmware lists an MCFG whose window decodes nothing; the
        // host bridge at 00:00.0 must answer (x86 only: aarch64 trusts it).
        let host = e.read32(
            Bdf {
                bus: pcie.bus_start,
                dev: 0,
                func: 0,
            },
            0,
        );
        let alive = cfg!(target_arch = "aarch64") || !matches!(host as u16, 0xffff | 0);
        let desc = alloc::format!(
            "ECAM {:#x} buses {}-{}",
            pcie.ecam,
            pcie.bus_start,
            pcie.bus_end
        );
        if alive {
            return Ok(Some((Cfg::Ecam(e), pcie.bus_start, pcie.bus_end, desc)));
        }
        warn!("pci: {desc} does not decode (00:00.0 reads {host:#010x})");
        ecam = Some((e, pcie, desc));
    }
    #[cfg(target_arch = "x86_64")]
    if let Some(p) = pci::PortConfig::detect(Ports) {
        let desc = alloc::string::String::from("ports 0xcf8/0xcfc (mechanism #1) buses 0-255");
        return Ok(Some((Cfg::Ports(p), 0, 255, desc)));
    }
    // Nothing better: scan the (silent) ECAM anyway so the log shows it.
    Ok(ecam.map(|(e, p, d)| (Cfg::Ecam(e), p.bus_start, p.bus_end, d)))
}

fn probe_pci(
    platform: &PlatformInfo,
    env: &KernelEnv,
    devs: &mut Devices,
) -> Result<(), ProbeError> {
    let Some((mut ecam, bus_start, bus_end, how)) = open_config(platform)? else {
        warn!("pci: no ECAM described and no legacy config ports, no devices");
        return Ok(());
    };
    let mut v2m = msi_frame(platform);
    let functions = pci::enumerate(&ecam, bus_start, bus_end);
    // DMA remapping (ADR-305): up before any driver, every device blocked
    // until it is given a domain.
    crate::iommu::init(platform, functions.iter().map(|f| f.bdf));
    #[cfg(target_arch = "aarch64")]
    let mut its = ItsSource::new(platform, &functions);
    #[cfg(target_arch = "x86_64")]
    let mut its: Option<()> = None;
    info!("pci: {how}, {} function(s)", functions.len());
    info!(
        "virtio: drivers in this image: {}",
        vdev::drivers_in_image()
    );
    // The first virtio-gpu and the display controllers, for the console
    // (ADR-256), brought up after the enumeration.
    let mut gpu: Option<(Bdf, u16)> = None;
    let mut displays: alloc::vec::Vec<Bdf> = alloc::vec::Vec::new();
    for f in functions.iter() {
        let ty = registry::type_of(f.vendor, f.device, f.subsystem);
        let kind = ty.map(DeviceType::from_id);
        if f.class == 0x03 && displays.len() < 8 {
            displays.push(f.bdf);
        }
        // A network controller we have no driver for (e.g. an SR-IOV
        // virtual function): remembered for the error if no virtio-net exists.
        if f.class == 0x02 && kind.is_none() {
            let mut list = OTHER_NICS.lock();
            if list.len() < 4 {
                list.push((f.vendor, f.device));
            }
        }
        info!(
            "pci {} {:04x}:{:04x} class {:02x}.{:02x}{}{}",
            f.bdf,
            f.vendor,
            f.device,
            f.class,
            f.subclass,
            if ty.is_some() { " " } else { "" },
            ty.map_or("", registry::type_name)
        );
        PCI_SEEN.lock().push(PciSeen {
            bdf: alloc::format!("{}", f.bdf),
            vendor: f.vendor,
            device: f.device,
            class: f.class,
            subclass: f.subclass,
            driver: match kind {
                Some(DeviceType::Net) => Some("virtio-net"),
                Some(DeviceType::Block) => Some("virtio-blk"),
                Some(DeviceType::Entropy) => Some("virtio-rng"),
                Some(DeviceType::Scsi) => Some("virtio-scsi"),
                _ => None,
            },
        });
        let (Some(ty), Some(kind)) = (ty, kind) else {
            // Not a virtio function this kernel knows: an edition's driver
            // may bind it (ADR-336); the open edition has none.
            crate::ext::probe_pci(&mut ecam, f);
            continue;
        };
        // DMA memory of this device goes into its own IOMMU domain (ADR-305).
        let dev_env = KernelEnv::device(f.bdf);
        let env = &dev_env;
        // Every type without a path of its own (ADR-257): the table decides.
        if !matches!(vdev::driver(ty).map(|d| d.path), Some(vdev::Path::Builtin)) {
            vdev::probe_generic(&mut ecam, env, f.bdf, f.device, ty);
            continue;
        }
        // The virtio-gpu is left alone here: `virtio_gpu_console` decides.
        if kind == DeviceType::Gpu {
            if !registry::kind_of(ty).is_some_and(|k| k.compiled) {
                vdev::record(
                    f.bdf,
                    ty,
                    State::NotCompiled,
                    "built without the kernel feature virtio-gpu",
                );
            } else if gpu.is_none() {
                gpu = Some((f.bdf, f.device));
            } else {
                vdev::record(f.bdf, ty, State::Spare, "");
            }
            continue;
        }
        let caps = find_caps(&ecam, f.bdf);
        let rng = matches!(kind, DeviceType::Entropy);
        match caps.support(f.device, !rng) {
            Support::Modern => {}
            Support::LegacyOnly => {
                // Pre-1.0 register block in an I/O-port BAR: no legacy driver (X7).
                let io = match pci::bar(&ecam, f.bdf, 0) {
                    Some(Bar::Io { base }) => alloc::format!("I/O BAR0 at {base:#x}"),
                    _ => alloc::string::String::from("no I/O BAR0"),
                };
                warn!(
                    "pci {}: unsupported legacy virtio device {:04x}:{:04x} ({io}, no virtio 1.0 capabilities): ignored; \
                     attach it as a modern device (disable-legacy=on)",
                    f.bdf, f.vendor, f.device
                );
                vdev::record(f.bdf, ty, State::Legacy, &io);
                if matches!(kind, DeviceType::Net) {
                    let mut list = OTHER_NICS.lock();
                    if list.len() < 4 {
                        list.push((f.vendor, f.device));
                    }
                }
                continue;
            }
            Support::Incomplete => {
                warn!(
                    "pci {}: virtio {:04x}:{:04x} lacks the required virtio 1.0 capabilities, ignored",
                    f.bdf, f.vendor, f.device
                );
                vdev::record(f.bdf, ty, State::Incomplete, "");
                continue;
            }
        }
        pci::enable(&mut ecam, f.bdf, pci::CMD_MEMORY | pci::CMD_BUS_MASTER);
        match kind {
            DeviceType::Entropy if devs.rng.is_none() => {
                devs.rng = Some(VirtioRng::new(
                    transport(&mut ecam, f.bdf, &caps, true)?,
                    env,
                )?);
                devs.rng_bdf = Some(f.bdf);
                vdev::record(f.bdf, ty, State::Driven, "entropy");
            }
            DeviceType::Block => {
                // Sizing the BARs (in `transport`) briefly turns decoding
                // off, so it comes before MSI-X is enabled.
                let t = transport(&mut ecam, f.bdf, &caps, false)?;
                let spi = setup_msix(&mut ecam, f.bdf, v2m.as_mut()).ok();
                let mut blk = VirtioBlk::new_with_msix(t, env, spi.map(|_| 0))?;
                // Only the disk Limine booted from is used (single-disk
                // model, STORAGE-PLAN §2a); every other disk is only read
                // here, to compare its GPT disk GUID, and never written.
                let mut head = alloc::vec![0u8; (gpt::HEAD_SECTORS * 512) as usize];
                let g = if blk.capacity_sectors > gpt::HEAD_SECTORS {
                    blk.read(env, 1, &mut head)
                        .ok()
                        .and(guid_of(&head, blk.capacity_sectors))
                } else {
                    None
                };
                // Its completions arrive on the vector set up above whether or
                // not the disk is used: the boot disk's handler replaces this.
                if let Some(spi) = spi {
                    irq::register(spi, ignore_irq);
                }
                if install_mode() {
                    vdev::record(
                        f.bdf,
                        ty,
                        State::Driven,
                        "a disk candidate (install, diagnostic)",
                    );
                    devs.install.push(InstallDisk {
                        name: alloc::format!("virtio-blk {}", f.bdf),
                        sectors: blk.capacity_sectors,
                        read_only: blk.read_only,
                        boot_medium: is_boot_disk(g),
                        source: InstallSource::Blk(Box::new(blk)),
                    });
                    continue;
                }
                if devs.blk.is_some() || !is_boot_disk(g) {
                    info!(
                        "disk: virtio-blk {} ({} MiB) is not the boot disk, left untouched",
                        f.bdf,
                        (blk.capacity_sectors * 512) >> 20
                    );
                    vdev::record(f.bdf, ty, State::NotUsed, "not the boot disk");
                    devs.other_disks += 1;
                    continue;
                }
                if let Some(spi) = spi {
                    irq::register(spi, on_blk_irq);
                    // x86: routing is in the MSI address; X4's irq module
                    // decides what enabling a vector means there.
                    irq::enable_spi(spi, 0);
                }
                info!(
                    "blk: boot disk is virtio-blk {}: {} MiB, block size {}, flush={}, read-only={}, msi-x={}",
                    f.bdf,
                    (blk.capacity_sectors * 512) >> 20,
                    blk.block_size,
                    blk.has_flush,
                    blk.read_only,
                    spi.map_or("no (polling)", |_| "yes")
                );
                info!("blk: topology: {}", TopologyText(blk.topology));
                info!(
                    "blk: resize notification (configuration-change interrupt): {}",
                    if blk.config_irq {
                        "armed (online grow)"
                    } else {
                        "not available (a larger disk is taken up at the next boot)"
                    }
                );
                vdev::record(f.bdf, ty, State::Driven, "the boot disk");
                devs.blk_msix_spi = spi;
                devs.blk = Some(DataDisk::Blk(blk));
            }
            DeviceType::Scsi => {
                let mut hba = VirtioScsi::new(transport(&mut ecam, f.bdf, &caps, false)?, env)?;
                let (disks, n) = hba.scan(env);
                info!("scsi: {} {n} disk(s) with 512-byte blocks", f.bdf);
                vdev::record(f.bdf, ty, State::Driven, &alloc::format!("{n} disk(s)"));
                if install_mode() {
                    let idx = devs.hbas.len();
                    for d in disks.iter().take(n).flatten() {
                        let mut head = alloc::vec![0u8; (gpt::HEAD_SECTORS * 512) as usize];
                        let g = if d.sectors > gpt::HEAD_SECTORS {
                            hba.read(env, *d, 1, &mut head)
                                .ok()
                                .and(guid_of(&head, d.sectors))
                        } else {
                            None
                        };
                        devs.install.push(InstallDisk {
                            name: alloc::format!(
                                "virtio-scsi {} target {} lun {}",
                                f.bdf,
                                d.target,
                                d.lun
                            ),
                            sectors: d.sectors,
                            read_only: false,
                            boot_medium: is_boot_disk(g),
                            source: InstallSource::Scsi { hba: idx, info: *d },
                        });
                    }
                    devs.hbas.push(Some(hba));
                    continue;
                }
                let mut chosen = None;
                for d in disks.iter().take(n).flatten() {
                    let mut head = alloc::vec![0u8; (gpt::HEAD_SECTORS * 512) as usize];
                    let g = if d.sectors > gpt::HEAD_SECTORS {
                        hba.read(env, *d, 1, &mut head)
                            .ok()
                            .and(guid_of(&head, d.sectors))
                    } else {
                        None
                    };
                    let boot = devs.blk.is_none() && chosen.is_none() && is_boot_disk(g);
                    info!(
                        "scsi: target {} lun {}: {} MiB{}",
                        d.target,
                        d.lun,
                        (d.sectors * 512) >> 20,
                        if boot {
                            ", the boot disk"
                        } else {
                            ", not the boot disk, left untouched"
                        }
                    );
                    if boot {
                        chosen = Some(*d);
                    } else {
                        devs.other_disks += 1;
                    }
                }
                if let Some(d) = chosen {
                    info!(
                        "blk: boot disk is scsi target {} lun {} ({} MiB, polled)",
                        d.target,
                        d.lun,
                        (d.sectors * 512) >> 20
                    );
                    info!("blk: topology: {}", TopologyText(d.topology));
                    devs.blk = Some(DataDisk::Scsi(hba.into_disk(d)));
                }
            }
            DeviceType::Net if devs.net.is_none() => {
                // The receive interrupt (ADR-270): MSI-X vector 0 for the
                // receive queue, unless the configuration forces polling.
                // Sizing the BARs (in `transport`) comes first, as for blk.
                let t = transport(&mut ecam, f.bdf, &caps, false)?;
                // Relaxed: stored by this CPU in `probe`.
                let want = NET_WANT_PAIRS.load(Ordering::Relaxed);
                let (msix, vectors) = if urmqtt_config::CONFIG.devices.virtio_net_interrupt
                    == urmqtt_config::NetInterrupt::Off
                {
                    (Err(Why::Configured), NetQueueVectors::all(Why::Configured))
                } else {
                    match net_msix(&mut ecam, f.bdf, &mut v2m, &mut its, want) {
                        Ok((spi, v)) => (Ok(spi), v),
                        Err(why) => (Err(why), NetQueueVectors::all(why)),
                    }
                };
                // Pair k's receive queue signals MSI-X entry k (NEXT-6, ADR-311).
                let net = VirtioNet::new_multi(t, env, want, |k| {
                    let ok = if k == 0 { msix.is_ok() } else { vectors.has(k) };
                    ok.then_some(k)
                })?;
                for r in vectors.irq.iter().skip(1).flatten() {
                    // Counted from now on; aimed at the pair's core and
                    // unmasked when that core starts.
                    irq::register(r.0, on_net_queue_irq);
                }
                *NET_QUEUE_VECTORS.lock() = vectors;
                devs.net_wake = match msix {
                    Ok(spi) if net.rx_irq => {
                        // Counted, and acknowledged, from now on; routed to
                        // core 0 when its dispatcher starts.
                        irq::register(spi, on_net_irq);
                        devs.net_msix_spi = Some(spi);
                        Mode::Interrupt
                    }
                    Ok(spi) => {
                        irq::register(spi, ignore_irq);
                        Mode::Polling(Why::Rejected)
                    }
                    Err(why) => Mode::Polling(why),
                };
                let m = net.mac;
                info!(
                    "net: mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
                    m[0],
                    m[1],
                    m[2],
                    m[3],
                    m[4],
                    m[5],
                    if net.link_up() { "up" } else { "down" }
                );
                vdev::record(f.bdf, ty, State::Driven, "the network");
                devs.net = Some(net);
            }
            _ => vdev::record(f.bdf, ty, State::Spare, ""),
        }
    }
    #[cfg(feature = "virtio-gpu")]
    virtio_gpu_console(&mut ecam, env, gpu, &displays);
    #[cfg(not(feature = "virtio-gpu"))]
    let _ = (gpu, &displays, env);
    vdev::check_configuration();
    crate::iommu::summary();
    Ok(())
}

/// Largest framebuffer the virtio-gpu console allocates: 1920x1080 at 4
/// bytes per pixel fits.
#[cfg(feature = "virtio-gpu")]
const GPU_FB_BUDGET: u64 = 8 << 20;

/// The memory BARs of `bdf` as (index, base, size).
#[cfg(feature = "virtio-gpu")]
fn memory_bars<C: ConfigSpace>(cfg: &mut C, bdf: Bdf) -> alloc::vec::Vec<(u8, u64, u64)> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0u8;
    while i < 6 {
        let next = match pci::bar(cfg, bdf, i) {
            Some(Bar::Memory { base, is64, .. }) => {
                if let Some(size) = pci::bar_size(cfg, bdf, i) {
                    out.push((i, base, size));
                }
                if is64 { 2 } else { 1 }
            }
            _ => 1,
        };
        i += next;
    }
    out
}

/// `console.virtio_gpu` (ADR-256): whether the console moves to the first
/// virtio-gpu, and why. Every outcome is logged as `console: virtio-gpu ...`;
/// a device that fails to come up leaves the console where it was (a
/// display problem never stops the broker), loudly. The outcome is also
/// recorded for the Diagnostic report (`virtio: virtio-gpu at ...`).
#[cfg(feature = "virtio-gpu")]
fn virtio_gpu_console(
    cfg: &mut Cfg,
    _runtime: &KernelEnv,
    gpu: Option<(Bdf, u16)>,
    displays: &[Bdf],
) {
    use urmqtt_config::VirtioGpuMode;
    let mode = urmqtt_config::CONFIG.console.virtio_gpu;
    let Some((bdf, device)) = gpu else {
        if mode != VirtioGpuMode::Off {
            info!(
                "console: virtio-gpu: none found (console.virtio_gpu = \"{}\")",
                mode.name()
            );
        }
        return;
    };
    let why = match mode {
        VirtioGpuMode::Off => {
            info!("console: virtio-gpu at pci {bdf} not used (console.virtio_gpu = \"off\")");
            vdev::record(
                bdf,
                registry::GPU,
                State::Off,
                "console.virtio_gpu = \"off\"",
            );
            return;
        }
        VirtioGpuMode::On => "console.virtio_gpu = \"on\"",
        VirtioGpuMode::Auto => {
            let boot_fb = crate::console::boot_framebuffer_phys();
            let bars: alloc::vec::Vec<_> = displays.iter().map(|&d| memory_bars(cfg, d)).collect();
            let lists: alloc::vec::Vec<&[(u8, u64, u64)]> =
                bars.iter().map(|b| b.as_slice()).collect();
            match auto_choice(boot_fb, &lists) {
                AutoChoice::NoBootFramebuffer => "auto: no usable boot framebuffer",
                AutoChoice::BootFramebufferInRam => {
                    "auto: the boot framebuffer is RAM that nothing shows after boot (the firmware's virtio-gpu GOP)"
                }
                AutoChoice::BootFramebufferInBar { index, bar } => {
                    let owner = displays.get(index).map_or_else(
                        || alloc::string::String::from("?"),
                        |d| alloc::format!("{d}"),
                    );
                    info!(
                        "console: virtio-gpu at pci {bdf} not used (auto): the boot framebuffer is in BAR{bar} \
                         of display pci {owner}, which shows it"
                    );
                    vdev::record(
                        bdf,
                        registry::GPU,
                        State::NotUsed,
                        "auto: the boot framebuffer is shown",
                    );
                    return;
                }
            }
        }
    };
    // Its DMA memory goes into its own IOMMU domain (ADR-305).
    let gpu_env = KernelEnv::device(bdf);
    let env = &gpu_env;
    let caps = find_caps(cfg, bdf);
    if caps.support(device, true) != Support::Modern {
        warn!("console: virtio-gpu at pci {bdf}: no virtio 1.0 capabilities, not used ({why})");
        vdev::record(bdf, registry::GPU, State::Incomplete, why);
        return;
    }
    pci::enable(cfg, bdf, pci::CMD_MEMORY | pci::CMD_BUS_MASTER);
    let t = match transport(cfg, bdf, &caps, false) {
        Ok(t) => t,
        Err(e) => {
            warn!("console: virtio-gpu at pci {bdf}: mapping failed ({e:?}), not used ({why})");
            vdev::record(bdf, registry::GPU, State::Failed, "mapping failed");
            return;
        }
    };
    match VirtioGpu::new(t, env, GPU_FB_BUDGET) {
        Ok(dev) => {
            let name = alloc::format!("{bdf}");
            if let Some(seen) = PCI_SEEN.lock().iter_mut().find(|p| p.bdf == name) {
                seen.driver = Some("virtio-gpu");
            }
            vdev::record(bdf, registry::GPU, State::Driven, "the console");
            crate::gpucon::install(dev, &name, why);
        }
        Err(e) => {
            warn!(
                "console: virtio-gpu at pci {bdf}: {e:?}: not used, the console stays on the boot framebuffer ({why})"
            );
            vdev::record(bdf, registry::GPU, State::Failed, &alloc::format!("{e:?}"));
        }
    }
}

/// Why the boot disk cannot hold a data partition, if it cannot (for the
/// storage refusal message).
pub fn no_boot_disk_reason() -> &'static str {
    let m = boot_medium();
    if m.optical {
        "booted from read-only media (CD/ISO): write the image to the machine's disk (docs/DEPLOY.md)"
    } else if m.disk_guid.is_none() {
        "the bootloader did not report a GPT boot disk"
    } else {
        "the boot disk is not among the disks this kernel drives"
    }
}

/// Brings the boot disk to its single-disk form (STORAGE-PLAN §2a): the
/// GPT first-boot steps and the data partition. Runs before the self-test
/// and the store. `fault` (dev `test=disk-fault:`) wraps the disk so a
/// power cut can be injected at any write; when it fires, the VM powers
/// off as if the power went.
pub fn prepare_boot_disk(fault: Option<FaultSpec>) -> Result<(), &'static str> {
    let mut devs = DEVICES.lock();
    let Some(blk) = devs.blk.take() else {
        return Ok(());
    };
    let cfg = &urmqtt_config::CONFIG.storage;
    if !blk.has_flush() {
        if cfg.require_flush {
            return Err("the boot disk lacks VIRTIO_BLK_F_FLUSH (storage.require_flush)");
        }
        warn!("storage: boot disk lacks VIRTIO_BLK_F_FLUSH: writes are NOT durable (dev only)");
    }
    if blk.read_only() {
        warn!("storage: the boot disk is read-only: no data partition");
        return Ok(());
    }
    if blk.topology().logical != 512 {
        return Err(
            "the boot disk has a logical block size other than 512 bytes (4Kn): only 512-byte logical blocks are supported (docs/DISK-FORMAT.md)",
        );
    }
    let flush = blk.has_flush();
    let raw: Box<dyn BlockDevice> = Box::new(KernelBlk { blk, flush });
    let mut dev: Box<dyn BlockDevice> = match fault {
        Some(spec) => {
            warn!("disk-fault: injecting {spec:?} (dev test)");
            Box::new(FaultDevice::new(raw, spec))
        }
        None => raw,
    };
    let random = || {
        let mut b = [0u8; 16];
        if let Some(r) = RNG.lock().as_mut() {
            r.fill(&mut b);
        }
        b
    };
    let total = dev.sectors();
    // A/B boot slots (ADR-295): the first boot reserves the standby next to
    // the ESP, labelled with this kernel's version and store schema.
    let opts = gpt::Options {
        boot_slot: Some(urmqtt_store::slots::Init {
            label: crate::VERSION,
            schema: crate::bootslot::own_schema(),
        }),
    };
    match gpt::prepare_with(dev.as_mut(), random, opts) {
        Ok((part, steps)) => {
            if steps.repaired_primary {
                warn!("gpt: primary table was damaged, restored from the backup");
            }
            if steps.moved_backup {
                info!(
                    "gpt: backup table moved to the end of the {} MiB disk",
                    (total * 512) >> 20
                );
            }
            if steps.extended_partition {
                info!(
                    "gpt: data partition extended to the end of the {} MiB disk ({} MiB)",
                    (total * 512) >> 20,
                    (part.sectors() * 512) >> 20
                );
            }
            if steps.created_boot_slot {
                info!(
                    "gpt: standby boot slot reserved next to the EFI system partition (A/B updates: urmqtt-disk slots, docs/DEPLOY.md)"
                );
            }
            // The slot step (ADR-296): count a trial boot or go back, before
            // anything else runs from this kernel.
            if let Err(e) = crate::bootslot::at_boot(dev.as_mut(), boot_medium().part_guid) {
                if fault.is_some() {
                    warn!(
                        "disk-fault: power cut injected during the boot-slot step ({e:?}), powering off"
                    );
                    crate::power::off()
                }
                warn!("boot: the boot-slot step failed ({e:?}); booting without A/B");
            }
            let guid = gpt::disk_guid(dev.as_mut()).ok().flatten();
            info!(
                "gpt: data partition {} at LBA {}..{} ({} MiB){}",
                part.unique_guid,
                part.first_lba,
                part.last_lba,
                (part.sectors() * 512) >> 20,
                match (steps.created_partition, guid) {
                    (true, Some(g)) => alloc::format!(", created now, new disk GUID {g}"),
                    _ => alloc::string::String::new(),
                }
            );
            devs.boot = Some(BootDisk {
                dev,
                partition: part,
                faulty: fault.is_some(),
            });
            Ok(())
        }
        Err(e) if fault.is_some() => {
            warn!("disk-fault: power cut injected during the first boot ({e:?}), powering off");
            crate::power::off()
        }
        Err(gpt::GptError::NoGpt) => Err("the boot disk has no valid GPT"),
        Err(gpt::GptError::TooSmall) => Err(
            "the boot disk has no room for a data partition (at least 16 MiB after the EFI partition)",
        ),
        Err(gpt::GptError::Shrunk) => Err("the boot disk is smaller than its partition table"),
        Err(gpt::GptError::TableFull) => Err("the boot disk's partition table is full"),
        Err(gpt::GptError::Inconsistent) => Err("the boot disk's partition table is inconsistent"),
        Err(gpt::GptError::Io(_)) => Err("the boot disk failed during the first-boot steps"),
    }
}

/// Live mode (O3): the data partition is a RAM block device. Disks the
/// kernel found are dropped untouched: nothing is read from or written to
/// them.
pub fn prepare_ram_disk(bytes: u64) -> Result<(), &'static str> {
    let dev = crate::live::reserve(bytes)?;
    let mut devs = DEVICES.lock();
    if devs.blk.take().is_some() {
        info!("live: the boot disk is not used (the store is RAM; nothing is written to any disk)");
    }
    let sectors = dev.sectors();
    devs.boot = Some(BootDisk {
        dev,
        partition: DataPartition {
            first_lba: 0,
            last_lba: sectors - 1,
            unique_guid: Guid([0; 16]),
        },
        faulty: false,
    });
    info!("live: RAM store of {} MiB ready", (sectors * 512) >> 20);
    Ok(())
}

/// Sectors at the end of the data partition reserved for the self-test
/// (the M11 disk layout keeps them out of every region).
pub const BLK_SCRATCH_SECTORS: u64 = 8;

/// Writes a random pattern to the scratch sectors at the end of the data
/// partition, flushes, reads it back. Nothing outside the partition is
/// ever written.
pub fn blk_selftest() -> Result<(), &'static str> {
    let mut devs = DEVICES.lock();
    let msix = devs.blk_msix_spi.is_some();
    let Some(boot) = devs.boot.as_mut() else {
        warn!("blk: no data partition, self-test skipped");
        return Ok(());
    };
    let part = boot.partition;
    if part.sectors() < BLK_SCRATCH_SECTORS * 2 {
        return Err("data partition too small");
    }
    // Nothing is written to a data partition the store will refuse (an
    // older layout, or damaged): the self-test pattern goes to the scratch
    // sectors only of a partition that is blank or a v2 layout (S2).
    {
        use urmqtt_store::layout::{BLOCK, Layout, SB_SLOT_LBA};
        let mut a = [0u8; BLOCK];
        let mut b = [0u8; BLOCK];
        let ok = boot
            .dev
            .read(part.first_lba + SB_SLOT_LBA[0], &mut a)
            .is_ok()
            && boot
                .dev
                .read(part.first_lba + SB_SLOT_LBA[1], &mut b)
                .is_ok();
        match Layout::select(&a, &b, part.sectors()) {
            Ok(_) if ok => {}
            Err(e) if ok => {
                info!(
                    "blk: self-test skipped: the data partition is not a v2 layout ({e:?}); nothing is written"
                );
                return Ok(());
            }
            _ => return Err("blk read failed"),
        }
    }
    let sector = part.last_lba + 1 - BLK_SCRATCH_SECTORS;
    let mut pattern = [0u8; 4096];
    RNG.lock().as_mut().ok_or("no CSPRNG")?.fill(&mut pattern);
    let irqs_before = BLK_IRQS.load(Ordering::Relaxed);
    boot.dev
        .write(sector, &pattern)
        .map_err(|_| "blk write failed")?;
    boot.dev
        .flush()
        .map_err(|_| "blk flush failed (VIRTIO_BLK_F_FLUSH missing?)")?;
    let mut back = [0u8; 4096];
    boot.dev
        .read(sector, &mut back)
        .map_err(|_| "blk read failed")?;
    if back != pattern {
        return Err("blk read-back mismatch");
    }
    if crate::live::ephemeral() {
        info!(
            "blk: self-test ok on the RAM store (4 KiB random pattern written, read back at sector {sector})"
        );
        return Ok(());
    }
    info!(
        "blk: self-test ok (4 KiB random pattern written, flushed, read back at sector {sector}, inside the data partition)"
    );
    if msix {
        let irqs = BLK_IRQS.load(Ordering::Relaxed) - irqs_before;
        info!("msi-x: {irqs} blk completion interrupt(s) via {MSI_SOURCE}");
        if irqs == 0 {
            return Err("no MSI-X interrupt arrived for blk completions");
        }
    } else {
        info!("msi-x: boot disk polled (virtio-scsi, or no MSI-X frame)");
    }
    Ok(())
}

/// The CPU's own random number instruction as `$SYS` names it.
#[cfg(target_arch = "aarch64")]
const HW_RNG_NAME: &str = "rndr";
#[cfg(target_arch = "x86_64")]
const HW_RNG_NAME: &str = "rdrand";

/// The CPU's own random number instructions, for the boot log.
#[cfg(target_arch = "aarch64")]
pub(crate) const HW_RNG: &str = "RNDR";
#[cfg(target_arch = "x86_64")]
pub(crate) const HW_RNG: &str = "RDRAND/RDSEED";

#[cfg(target_arch = "aarch64")]
const MSI_SOURCE: &str = "GICv2m";
#[cfg(target_arch = "x86_64")]
const MSI_SOURCE: &str = "the local APIC";

const ETH_ARP: [u8; 2] = [0x08, 0x06];

fn arp_frame(mac: [u8; 6], op: u16, sender_ip: [u8; 4], target_ip: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&ETH_ARP);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, op as u8]); // Ethernet/IPv4, op
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&sender_ip);
    // target MAC stays zero
    f[38..42].copy_from_slice(&target_ip);
    f
}

/// `test=iommu-dma` (dev only, ADR-307): makes the entropy device write into
/// a page that is not in its IOMMU domain, then reports whether the page
/// stayed untouched and how many faults the units recorded meanwhile. With
/// the IOMMU off the same request reaches the page (the control run). The
/// entropy device is not used again afterwards (the CSPRNG is seeded).
pub fn iommu_dma_test() {
    let mut devs = DEVICES.lock();
    let bdf = devs.rng_bdf;
    let Some(rng) = devs.rng.as_mut() else {
        warn!("iommu: test: no virtio-rng device, the DMA test needs one");
        return;
    };
    // A page no device's domain holds: allocated outside `KernelEnv`.
    let Some((va, pa, len)) = vm::dma_alloc(4096) else {
        warn!("iommu: test: no memory");
        return;
    };
    let before = crate::iommu::faults();
    let r = rng.request_at(&KernelEnv::RUNTIME, pa, 64, 500_000_000);
    devs.rng = None;
    drop(devs);
    // First core 0's tick alone (it reads the logs every 100 ms): the test
    // runs on core 0 with interrupts on. Then, if it saw nothing within a
    // second, the logs read here, so a broken tick poll shows as such.
    let t0 = time::uptime_ns();
    while crate::iommu::faults() == before && time::uptime_ns() - t0 < 1_000_000_000 {
        core::hint::spin_loop();
    }
    let by_tick = crate::iommu::faults() != before;
    let t0 = time::uptime_ns();
    while crate::iommu::faults() == before && time::uptime_ns() - t0 < 1_000_000_000 {
        crate::iommu::poll();
        core::hint::spin_loop();
    }
    // SAFETY: the page was just allocated (zeroed, HHDM-mapped, `len`
    // bytes) and is owned here; only read.
    let page = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
    let written = page.iter().any(|b| *b != 0);
    let faults = crate::iommu::faults() - before;
    info!(
        "iommu: test: virtio-rng {} asked to write 64 bytes at {pa:#x} (outside its domain): {}; the page is {}; {faults} fault(s) recorded",
        bdf.map_or_else(
            || alloc::string::String::from("?"),
            |b| alloc::format!("{b}")
        ),
        match r {
            Ok(n) => alloc::format!("the device answered {n} byte(s)"),
            Err(e) => alloc::format!("no answer ({e:?})"),
        },
        if written { "WRITTEN" } else { "untouched" }
    );
    if crate::iommu::active() {
        info!(
            "iommu: test: the fault was {}",
            if by_tick {
                "read by core 0's tick"
            } else {
                "NOT read by core 0's tick within a second"
            }
        );
        if !written && faults > 0 {
            info!("iommu: test: DMA outside the domain blocked and counted");
        } else {
            warn!("iommu: test: DMA outside the domain NOT blocked or not counted");
        }
    }
}

/// Sends a gratuitous ARP announcement and an ARP request for the QEMU user
/// network gateway, then waits briefly for any reply (RX path check).
pub fn net_selftest() -> Result<(), &'static str> {
    let env = KernelEnv::RUNTIME;
    let mut devs = DEVICES.lock();
    let Some(net) = devs.net.as_mut() else {
        warn!("net: no virtio-net device, self-test skipped");
        return Ok(());
    };
    let mac = net.mac;
    // No address yet (DHCP is M7): announce with 0.0.0.0.
    net.send(&env, &arp_frame(mac, 1, [0; 4], [0; 4]))
        .map_err(|_| "net tx failed")?;
    info!("net: gratuitous ARP sent");
    net.send(&env, &arp_frame(mac, 1, [10, 0, 2, 15], [10, 0, 2, 2]))
        .map_err(|_| "net tx failed")?;
    let deadline = time::uptime_ns() + 500_000_000;
    let mut buf = [0u8; 1514];
    while time::uptime_ns() < deadline {
        net.flush();
        if let Ok(Some(n)) = net.recv(&mut buf)
            && n >= 42
            && buf.get(12..14) == Some(&ETH_ARP[..])
            && buf.get(20..22) == Some(&[0, 2][..])
        {
            let s = buf.get(22..28).unwrap_or(&[]);
            info!(
                "net: rx ok, ARP reply from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                s.first().copied().unwrap_or(0),
                s.get(1).copied().unwrap_or(0),
                s.get(2).copied().unwrap_or(0),
                s.get(3).copied().unwrap_or(0),
                s.get(4).copied().unwrap_or(0),
                s.get(5).copied().unwrap_or(0)
            );
            return Ok(());
        }
        core::hint::spin_loop();
    }
    warn!("net: no ARP reply within 500 ms (RX path not confirmed)");
    Ok(())
}
