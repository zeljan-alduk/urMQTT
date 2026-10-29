//! PCIe and virtio bring-up (M6): ECAM enumeration, device initialisation,
//! entropy seeding, MSI-X through a GICv2m frame, and device self-tests.
//!
//! All MMIO mappings happen in [`probe`], before the page tables lock;
//! the self-tests afterwards only use DMA memory and registers.

#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_arch_aarch64::sync::SpinLock;
use urmqtt_arch_aarch64::timer;
use urmqtt_log::{info, warn};
use urmqtt_pci::{self as pci, Bar, Bdf, ConfigSpace};
use urmqtt_platform::{Pcie, PlatformInfo};
use urmqtt_tls::rng::{Csprng, EntropyPool, Source};
use urmqtt_virtio::blk::VirtioBlk;
use urmqtt_virtio::net::VirtioNet;
use urmqtt_virtio::rng::VirtioRng;
use urmqtt_virtio::transport::CapLoc;
use urmqtt_virtio::{DeviceType, DmaRegion, Env, Region, Transport, VirtioError, find_caps};

use crate::{irq, memory, smp, vm};

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
        timer::uptime_ns()
    }
}

/// Initialised devices, kept for later milestones (network stack, storage).
pub struct Devices {
    pub net: Option<VirtioNet>,
    pub blk: Option<VirtioBlk>,
    pub rng: Option<VirtioRng>,
    pub blk_msix_spi: Option<u32>,
}

pub static DEVICES: SpinLock<Devices> = SpinLock::new(Devices {
    net: None,
    blk: None,
    rng: None,
    blk_msix_spi: None,
});

/// The boot CPU's CSPRNG (per-core generators are forked from it).
pub static RNG: SpinLock<Option<Csprng>> = SpinLock::new(None);

static BLK_IRQS: AtomicU64 = AtomicU64::new(0);

fn on_blk_irq(_intid: u32) {
    // Relaxed: statistics read by the boot CPU after the self-test.
    BLK_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// A GICv2m MSI frame: MSIs are writes of an SPI number to SETSPI_NS.
struct V2m {
    pa: u64,
    next_spi: u32,
    end_spi: u32,
}

const V2M_TYPER: usize = 0x008;
const V2M_SETSPI_NS: u64 = 0x040;

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
fn setup_msix<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, v2m: &mut V2m) -> Option<u32> {
    let info = pci::msix(cfg, bdf)?;
    let Some(Bar::Memory { base, .. }) = pci::bar(cfg, bdf, info.table_bar) else {
        return None;
    };
    if v2m.next_spi >= v2m.end_spi {
        return None;
    }
    let spi = v2m.next_spi;
    v2m.next_spi += 1;
    let table = map(
        base + u64::from(info.table_offset),
        u64::from(info.table_size) * 16,
    )
    .ok()?;
    let entry = pci::msix_entry(v2m.pa + V2M_SETSPI_NS, spi, false);
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
    if let Some(r) = rndr_bytes() {
        pool.add(Source::Rndr, &r);
        info!("entropy: 64 bytes from RNDR");
    }
    pool.add(Source::Jitter, &timer::now().to_le_bytes());
    let rng = pool.finish().map_err(|_| ProbeError::NoEntropy)?;
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
        let typer = unsafe { ((va + V2M_TYPER) as *const u32).read_volatile() };
        let base = (typer >> 16) & 0x3ff;
        let count = typer & 0x3ff;
        info!(
            "msi: GICv2m frame at {pa:#x}, SPIs {base}..{}",
            base + count
        );
        Some(V2m {
            pa,
            next_spi: base,
            end_spi: base + count,
        })
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
            DeviceType::Block if devs.blk.is_none() => {
                let spi = v2m.as_mut().and_then(|v| setup_msix(&mut ecam, f.bdf, v));
                let t = transport(&ecam, f.bdf)?;
                let blk = VirtioBlk::new_with_msix(t, env, spi.map(|_| 0))?;
                if let Some(spi) = spi {
                    irq::register(spi, on_blk_irq);
                    irq::enable_spi(spi, smp::CPUS[0].mpidr.load(Ordering::Relaxed));
                }
                info!(
                    "blk: {} MiB, block size {}, flush={}, read-only={}, msi-x={}",
                    (blk.capacity_sectors * 512) >> 20,
                    blk.block_size,
                    blk.has_flush,
                    blk.read_only,
                    spi.map_or("no (polling)", |_| "yes")
                );
                devs.blk_msix_spi = spi;
                devs.blk = Some(blk);
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

/// 64 bytes from `RNDR` if the CPU implements FEAT_RNG and it succeeds.
fn rndr_bytes() -> Option<[u8; 64]> {
    let f = urmqtt_arch_aarch64::features::Features::decode(urmqtt_arch_aarch64::pac::id_regs());
    if !f.rndr {
        return None;
    }
    let mut out = [0u8; 64];
    for chunk in out.as_chunks_mut::<8>().0 {
        let (v, ok): (u64, u64);
        // SAFETY: RNDR (S3_3_C2_C4_0) exists (FEAT_RNG); it sets Z on failure.
        unsafe {
            core::arch::asm!(
                "mrs {v}, S3_3_C2_C4_0",
                "cset {ok}, ne",
                v = out(reg) v, ok = out(reg) ok,
                options(nomem, nostack)
            )
        };
        if ok == 0 {
            return None;
        }
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    Some(out)
}

/// Sectors at the end of the data disk reserved for the self-test
/// (the M11 disk layout keeps them out of every region).
pub const BLK_SCRATCH_SECTORS: u64 = 8;

/// Writes a random pattern to the scratch sectors, flushes, reads it back.
pub fn blk_selftest() -> Result<(), &'static str> {
    let env = KernelEnv;
    let mut devs = DEVICES.lock();
    let Some(blk) = devs.blk.as_mut() else {
        warn!("blk: no data disk attached, self-test skipped");
        return Ok(());
    };
    if blk.capacity_sectors < BLK_SCRATCH_SECTORS * 2 {
        return Err("data disk too small");
    }
    let sector = blk.capacity_sectors - BLK_SCRATCH_SECTORS;
    let mut pattern = [0u8; 4096];
    RNG.lock().as_mut().ok_or("no CSPRNG")?.fill(&mut pattern);
    let irqs_before = BLK_IRQS.load(Ordering::Relaxed);
    blk.write(&env, sector, &pattern)
        .map_err(|_| "blk write failed")?;
    blk.flush(&env)
        .map_err(|_| "blk flush failed (VIRTIO_BLK_F_FLUSH missing?)")?;
    let mut back = [0u8; 4096];
    blk.read(&env, sector, &mut back)
        .map_err(|_| "blk read failed")?;
    if back != pattern {
        return Err("blk read-back mismatch");
    }
    info!(
        "blk: self-test ok (4 KiB random pattern written, flushed, read back at sector {sector})"
    );
    if devs.blk_msix_spi.is_some() {
        let irqs = BLK_IRQS.load(Ordering::Relaxed) - irqs_before;
        info!("msi-x: {irqs} blk completion interrupt(s) via GICv2m");
        if irqs == 0 {
            return Err("no MSI-X interrupt arrived for blk completions");
        }
    } else {
        info!("msi-x: not available on this machine (ITS support arrives in M13), blk polled");
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
    let deadline = timer::uptime_ns() + 500_000_000;
    let mut buf = [0u8; 1514];
    while timer::uptime_ns() < deadline {
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
