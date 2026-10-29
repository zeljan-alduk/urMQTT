//! PCIe and virtio bring-up (M6): ECAM enumeration, device initialisation,
//! entropy seeding, MSI-X through a GICv2m frame, and device self-tests.
//!
//! All MMIO mappings happen in [`probe`], before the page tables lock;
//! the self-tests afterwards only use DMA memory and registers.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;

use urmqtt_arch::{msi, time};
use urmqtt_log::{info, warn};
use urmqtt_pci::{self as pci, Bar, Bdf, ConfigSpace};
use urmqtt_platform::{Pcie, PlatformInfo};
use urmqtt_store::fault::{FaultDevice, FaultSpec};
use urmqtt_store::gpt::{self, DataPartition, Guid};
use urmqtt_store::{BlockDevice, IoError};
use urmqtt_sync::sync::SpinLock;
use urmqtt_tls::rng::{Csprng, EntropyPool, Source};
use urmqtt_virtio::blk::VirtioBlk;
use urmqtt_virtio::net::VirtioNet;
use urmqtt_virtio::rng::VirtioRng;
use urmqtt_virtio::scsi::{ScsiDisk, VirtioScsi};
use urmqtt_virtio::transport::CapLoc;
use urmqtt_virtio::{DeviceType, DmaRegion, Env, Region, Transport, VirtioError, find_caps};

use crate::{irq, memory, vm};

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

/// The kernel side of the virtio `Env`.
pub struct KernelEnv;

impl Env for KernelEnv {
    fn dma_alloc(&self, bytes: usize) -> Option<DmaRegion> {
        vm::dma_alloc(bytes).map(|(va, pa, len)| DmaRegion { va, pa, len })
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

    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.read(&KernelEnv, sector, buf),
            Self::Scsi(s) => s.read(&KernelEnv, sector, buf),
        }
    }

    pub fn write(&mut self, sector: u64, data: &[u8]) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.write(&KernelEnv, sector, data),
            Self::Scsi(s) => s.write(&KernelEnv, sector, data),
        }
    }

    pub fn flush(&mut self) -> Result<(), urmqtt_virtio::VirtioError> {
        match self {
            Self::Blk(b) => b.flush(&KernelEnv),
            Self::Scsi(s) => s.flush(&KernelEnv),
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
}

/// Where Limine loaded the kernel from (STORAGE-PLAN §2a).
#[derive(Debug, Clone, Copy, Default)]
pub struct BootMedium {
    /// A CD or DVD (an ISO): read-only, no data partition possible.
    pub optical: bool,
    /// The GPT disk GUID of the boot disk, if it has a GPT.
    pub disk_guid: Option<Guid>,
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
    pub blk_msix_spi: Option<u32>,
    /// Disks driven but left alone (not the boot disk).
    pub other_disks: u32,
    /// The boot disk after [`prepare_boot_disk`].
    pub boot: Option<BootDisk>,
}

pub static DEVICES: SpinLock<Devices> = SpinLock::new(Devices {
    net: None,
    blk: None,
    rng: None,
    blk_msix_spi: None,
    other_disks: 0,
    boot: None,
});

static BOOT_MEDIUM: SpinLock<BootMedium> = SpinLock::new(BootMedium {
    optical: false,
    disk_guid: None,
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

/// The boot CPU's CSPRNG (per-core generators are forked from it).
pub static RNG: SpinLock<Option<Csprng>> = SpinLock::new(None);

static BLK_IRQS: AtomicU64 = AtomicU64::new(0);

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

fn region<C: ConfigSpace>(cfg: &C, bdf: Bdf, loc: Option<CapLoc>) -> Result<Region, ProbeError> {
    let loc = loc.ok_or(ProbeError::Map)?;
    let Some(Bar::Memory { base, .. }) = pci::bar(cfg, bdf, loc.bar) else {
        return Err(ProbeError::Map);
    };
    let va = map(base + u64::from(loc.offset), u64::from(loc.length.max(4)))?;
    // SAFETY: just mapped as device memory for the kernel's lifetime.
    Ok(unsafe { Region::new(va, loc.length as usize) })
}

fn transport<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> Result<Transport, ProbeError> {
    let caps = find_caps(cfg, bdf);
    Ok(Transport {
        common: region(cfg, bdf, caps.common)?,
        notify: region(cfg, bdf, caps.notify)?,
        notify_multiplier: caps.notify_multiplier,
        device: region(cfg, bdf, caps.device)?,
    })
}

/// Points MSI-X vector 0 of `bdf` at a fresh GICv2m SPI and enables MSI-X.
fn setup_msix<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, frame: &mut msi::Frame) -> Option<u32> {
    let info = pci::msix(cfg, bdf)?;
    let Some(Bar::Memory { base, .. }) = pci::bar(cfg, bdf, info.table_bar) else {
        return None;
    };
    let spi = frame.alloc()?;
    let table = map(
        base + u64::from(info.table_offset),
        u64::from(info.table_size) * 16,
    )
    .ok()?;
    let (address, data) = frame.compose(spi);
    let entry = pci::msix_entry(address, data, false);
    for (i, w) in entry.iter().enumerate() {
        // SAFETY: entry 0 of the just-mapped MSI-X table.
        unsafe { ((table + 4 * i) as *mut u32).write_volatile(*w) };
    }
    pci::msix_enable(cfg, bdf, &info, true);
    pci::enable(cfg, bdf, pci::CMD_INTX_DISABLE);
    Some(spi)
}

/// Enumerates PCIe, maps and initialises the virtio devices and seeds the
/// CSPRNG. Must run before the page tables are locked.
pub fn probe(platform: &PlatformInfo, bootloader_entropy: &[u64]) -> Result<(), ProbeError> {
    let env = KernelEnv;
    let mut pool = EntropyPool::new();
    for v in bootloader_entropy {
        pool.add(Source::Bootloader, &v.to_le_bytes());
    }
    let mut devs = Devices {
        net: None,
        blk: None,
        rng: None,
        blk_msix_spi: None,
        other_disks: 0,
        boot: None,
    };

    if let Some(pcie) = platform.pcie {
        probe_pci(&pcie, platform, &env, &mut devs)?;
    } else {
        warn!("pci: no ECAM described, no devices");
    }

    // Entropy: virtio-rng and RNDR are hardware sources (PROMPT §6).
    let mut hw = [0u8; 64];
    if let Some(rng) = devs.rng.as_mut() {
        match rng.fill(&env, &mut hw) {
            Ok(n) => {
                pool.add(Source::VirtioRng, hw.get(..n).unwrap_or(&[]));
                info!("entropy: {n} bytes from virtio-rng");
            }
            Err(e) => warn!("entropy: virtio-rng failed: {e:?}"),
        }
    }
    if let Some(r) = urmqtt_arch::entropy::hw_random() {
        pool.add(Source::Rndr, &r);
        info!("entropy: 64 bytes from RNDR");
    }
    pool.add(Source::Jitter, &time::now().to_le_bytes());
    let fallback = urmqtt_config::CONFIG.entropy.jitter_fallback;
    if !pool.has_hardware() && fallback {
        let t0 = time::uptime_ns();
        let r = crate::jitter::collect(&mut pool);
        warn!(
            "entropy: no hardware source (virtio-rng, RNDR): CPU jitter fallback via the {} (granularity 2^{}): \
             {} samples of {} steps, {} bit(s)/sample estimated, {} bit(s) credited (1/{}), health tests {}, {} ms",
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
    }
    let mut rng = pool
        .finish_with(fallback)
        .map_err(|_| ProbeError::NoEntropy)?;
    urmqtt_tls::rng::install(rng.fork());
    *RNG.lock() = Some(rng);
    info!("entropy: ChaCha20 CSPRNG seeded");
    *DEVICES.lock() = devs;
    Ok(())
}

fn probe_pci(
    pcie: &Pcie,
    platform: &PlatformInfo,
    env: &KernelEnv,
    devs: &mut Devices,
) -> Result<(), ProbeError> {
    let va = map(pcie.ecam, pcie.ecam_size())?;
    let mut ecam = Ecam {
        va,
        bus_start: pcie.bus_start,
        bus_end: pcie.bus_end,
    };
    let mut v2m = platform.interrupts.and_then(|i| i.gic.v2m).and_then(|pa| {
        let va = map(pa, 0x1000).ok()?;
        // SAFETY: MSI_TYPER of the just-mapped v2m frame.
        let typer = unsafe { ((va + msi::TYPER) as *const u32).read_volatile() };
        let frame = msi::Frame::from_typer(pa, typer);
        let (start, end) = frame.spis();
        info!("msi: GICv2m frame at {pa:#x}, SPIs {start}..{end}");
        Some(frame)
    });
    let functions = pci::enumerate(&ecam, pcie.bus_start, pcie.bus_end);
    info!(
        "pci: ECAM {:#x} buses {}-{}, {} function(s)",
        pcie.ecam,
        pcie.bus_start,
        pcie.bus_end,
        functions.len()
    );
    for f in functions.iter() {
        let kind = DeviceType::from_pci(f.vendor, f.device, f.subsystem);
        // A network controller we have no driver for (e.g. an SR-IOV
        // virtual function): remembered for the error if no virtio-net exists.
        if f.class == 0x02 && kind.is_none() {
            let mut list = OTHER_NICS.lock();
            if list.len() < 4 {
                list.push((f.vendor, f.device));
            }
        }
        info!(
            "pci {} {:04x}:{:04x} class {:02x}.{:02x}{}",
            f.bdf,
            f.vendor,
            f.device,
            f.class,
            f.subclass,
            match kind {
                Some(DeviceType::Net) => " virtio-net",
                Some(DeviceType::Block) => " virtio-blk",
                Some(DeviceType::Entropy) => " virtio-rng",
                Some(DeviceType::Scsi) => " virtio-scsi",
                Some(DeviceType::Other(_)) => " virtio (unused)",
                None => "",
            }
        );
        let Some(kind) = kind else { continue };
        if matches!(kind, DeviceType::Other(_)) {
            continue;
        }
        pci::enable(&mut ecam, f.bdf, pci::CMD_MEMORY | pci::CMD_BUS_MASTER);
        match kind {
            DeviceType::Entropy if devs.rng.is_none() => {
                devs.rng = Some(VirtioRng::new(transport(&ecam, f.bdf)?, env)?);
            }
            DeviceType::Block => {
                let spi = v2m.as_mut().and_then(|v| setup_msix(&mut ecam, f.bdf, v));
                let t = transport(&ecam, f.bdf)?;
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
                if devs.blk.is_some() || !is_boot_disk(g) {
                    info!(
                        "disk: virtio-blk {} ({} MiB) is not the boot disk, left untouched",
                        f.bdf,
                        (blk.capacity_sectors * 512) >> 20
                    );
                    devs.other_disks += 1;
                    continue;
                }
                if let Some(spi) = spi {
                    irq::register(spi, on_blk_irq);
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
                devs.blk_msix_spi = spi;
                devs.blk = Some(DataDisk::Blk(blk));
            }
            DeviceType::Scsi => {
                let mut hba = VirtioScsi::new(transport(&ecam, f.bdf)?, env)?;
                let (disks, n) = hba.scan(env);
                info!("scsi: {} {n} disk(s) with 512-byte blocks", f.bdf);
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
                    devs.blk = Some(DataDisk::Scsi(hba.into_disk(d)));
                }
            }
            DeviceType::Net if devs.net.is_none() => {
                let net = VirtioNet::new(transport(&ecam, f.bdf)?, env)?;
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
                devs.net = Some(net);
            }
            _ => {}
        }
    }
    Ok(())
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
    match gpt::prepare(dev.as_mut(), random) {
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
    info!(
        "blk: self-test ok (4 KiB random pattern written, flushed, read back at sector {sector}, inside the data partition)"
    );
    if msix {
        let irqs = BLK_IRQS.load(Ordering::Relaxed) - irqs_before;
        info!("msi-x: {irqs} blk completion interrupt(s) via GICv2m");
        if irqs == 0 {
            return Err("no MSI-X interrupt arrived for blk completions");
        }
    } else {
        info!("msi-x: boot disk polled (virtio-scsi, or no MSI-X frame)");
    }
    Ok(())
}

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

/// Sends a gratuitous ARP announcement and an ARP request for the QEMU user
/// network gateway, then waits briefly for any reply (RX path check).
pub fn net_selftest() -> Result<(), &'static str> {
    let env = KernelEnv;
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
