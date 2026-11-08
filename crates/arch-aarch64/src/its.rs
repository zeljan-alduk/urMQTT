//! GICv3 Interrupt Translation Service (ITS): message-signalled interrupts
//! as LPIs (ADR-270). This is what QEMU's `virt` machine gives a guest
//! under TCG and, with an in-kernel vITS, under KVM (the netcup ARM VPS),
//! where there is no GICv2m frame.
//!
//! What it sets up, and no more: the boot CPU's redistributor gets an LPI
//! configuration table and a pending table (LPIs 8192..16383); the ITS gets
//! a flat device table sized for the highest PCI requester ID the scan saw,
//! a collection table, and a one-page command queue. One collection (0)
//! targets the boot CPU. [`Its::map_msi`] maps event 0 of one device to the
//! next LPI (`MAPD`, `MAPTI`, `INV`, `SYNC`) and returns the message the
//! device writes: `GITS_TRANSLATER` and the event. The device ID is the
//! requester ID (bus, device, function), which is QEMU's `msi-map` and IORT
//! mapping on `virt`; a platform that maps it differently delivers nothing,
//! and the caller's fallback (ADR-270: polling after missed wake-ups) covers
//! that.
//!
//! The command encodings and table arithmetic are pure and host-tested; the
//! register accesses and the command queue are the unsafe part.

/// Offset of `GITS_TRANSLATER` from the ITS base (the second 64 KiB frame).
pub const TRANSLATER: u64 = 0x1_0040;
/// The ITS's register frames: control (64 KiB) and translation (64 KiB).
pub const FRAME_LEN: u64 = 0x2_0000;
/// The first LPI.
pub const LPI_BASE: u32 = 8192;
/// INTID bits programmed into `GICR_PROPBASER`: LPIs 8192..16383.
pub const ID_BITS: u32 = 14;
/// LPI configuration table: one byte per LPI.
pub const PROP_BYTES: usize = (1 << ID_BITS) - LPI_BASE as usize;
/// LPI pending table: one bit per INTID (including the first 8192), 64 KiB
/// aligned.
pub const PEND_BYTES: usize = (1 << ID_BITS) / 8;
pub const PEND_ALIGN: usize = 0x1_0000;
/// The command queue: one 4 KiB page, 128 commands of 32 bytes.
pub const CMDQ_BYTES: usize = 4096;
/// Each device's interrupt translation table holds 2 events (the smallest
/// `MAPD` size), aligned to 256 bytes.
pub const ITT_EVENT_BITS: u32 = 1;
pub const ITT_ALIGN: usize = 256;

/// `GITS_BASER<n>.Type`.
pub const BASER_TYPE_DEVICE: u64 = 1;
pub const BASER_TYPE_COLLECTION: u64 = 4;

/// One ITS command: four little-endian doublewords.
pub type Cmd = [u64; 4];

/// What `GITS_TYPER` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Typer {
    /// Bytes per interrupt translation table entry.
    pub itt_entry: usize,
    /// Device ID bits.
    pub dev_bits: u32,
    /// Collections are targeted by redistributor physical address (else by
    /// processor number).
    pub pta: bool,
}

impl Typer {
    pub const fn decode(v: u64) -> Self {
        Self {
            itt_entry: (((v >> 4) & 0xf) + 1) as usize,
            dev_bits: (((v >> 13) & 0x1f) + 1) as u32,
            pta: (v >> 19) & 1 != 0,
        }
    }
}

/// Cacheability and shareability every table and the queue are declared
/// with: normal inner write-back read/write-allocate, inner shareable (as the
/// kernel maps RAM), so a coherent ITS needs no cache maintenance.
const INNER_WB: u64 = 0b111;
const INNER_SHAREABLE: u64 = 0b01;

/// The attribute bits of a `GITS_BASER`/`GITS_CBASER` value (InnerCache at
/// 61:59, Shareability at 11:10).
pub const fn attrs() -> u64 {
    (INNER_WB << 59) | (INNER_SHAREABLE << 10)
}

/// Shareability as read back from a table register (11:10): 0 means the
/// ITS asks for non-shareable memory, so the tables need cache cleaning.
pub const fn shareable(v: u64) -> bool {
    (v >> 10) & 0b11 != 0
}

/// Bytes of an ITS table page for `GITS_BASER.Page_Size` (9:8).
pub const fn page_bytes(field: u64) -> usize {
    match field & 0b11 {
        0 => 0x1000,
        1 => 0x4000,
        _ => 0x1_0000,
    }
}

/// Pages of `page` bytes a flat table of `entries` entries of `entry` bytes
/// needs, at least 1 and at most 256 (`Size` is 8 bits); `None` if 256 are
/// not enough.
pub const fn table_pages(entries: u64, entry: usize, page: usize) -> Option<u64> {
    let bytes = entries * entry as u64;
    let pages = bytes.div_ceil(page as u64);
    let pages = if pages == 0 { 1 } else { pages };
    if pages > 256 { None } else { Some(pages) }
}

/// A `GITS_BASER` value: valid, flat, the page size field, `pages` pages at
/// `pa` (Size is pages - 1), with [`attrs`]. Type and Entry_Size are
/// read-only and kept from `old`.
pub const fn baser(old: u64, pa: u64, page_field: u64, pages: u64) -> u64 {
    let ro = old & ((0b111 << 56) | (0x1f << 48));
    let addr = pa & 0x0000_ffff_ffff_f000;
    (1 << 63) | ro | attrs() | addr | ((page_field & 0b11) << 8) | ((pages - 1) & 0xff)
}

/// A `GITS_CBASER` value: valid, one 4 KiB page at `pa`.
pub const fn cbaser(pa: u64) -> u64 {
    (1 << 63) | attrs() | (pa & 0x000f_ffff_ffff_f000)
}

/// A `GICR_PROPBASER` value for [`ID_BITS`] at `pa`.
pub const fn propbaser(pa: u64) -> u64 {
    (INNER_WB << 7) | (INNER_SHAREABLE << 10) | (pa & 0x000f_ffff_ffff_f000) | (ID_BITS as u64 - 1)
}

/// A `GICR_PENDBASER` value at `pa` (64 KiB aligned), the table zeroed (PTZ).
pub const fn pendbaser(pa: u64) -> u64 {
    (1 << 62) | (INNER_WB << 7) | (INNER_SHAREABLE << 10) | (pa & 0x000f_ffff_ffff_0000)
}

/// An LPI configuration byte: `priority` (its top six bits), RES1 bit 1,
/// enabled.
pub const fn lpi_config(priority: u8) -> u8 {
    (priority & 0xfc) | 0b10 | 1
}

/// The target of a collection in `MAPC`/`SYNC` (`RDbase`, bits 51:16): the
/// redistributor's physical address (PTA) or its processor number.
pub const fn rdbase(pta: bool, rd_pa: u64, processor: u32) -> u64 {
    if pta {
        rd_pa & 0x000f_ffff_ffff_0000
    } else {
        (processor as u64) << 16
    }
}

/// `MAPD`: device `dev` gets the translation table at `itt` with 2^`bits`
/// events.
pub const fn mapd(dev: u32, itt: u64, bits: u32) -> Cmd {
    [
        0x08 | ((dev as u64) << 32),
        (bits.saturating_sub(1) & 0x1f) as u64,
        (1 << 63) | (itt & 0x000f_ffff_ffff_ff00),
        0,
    ]
}

/// `MAPC`: collection `icid` targets `rdbase` (see [`rdbase`]).
pub const fn mapc(icid: u16, rdbase: u64) -> Cmd {
    [0x09, 0, (1 << 63) | rdbase | icid as u64, 0]
}

/// `MAPTI`: event `event` of device `dev` raises LPI `lpi` through
/// collection `icid`.
pub const fn mapti(dev: u32, event: u32, lpi: u32, icid: u16) -> Cmd {
    [
        0x0a | ((dev as u64) << 32),
        event as u64 | ((lpi as u64) << 32),
        icid as u64,
        0,
    ]
}

/// `INV`: the redistributor re-reads the configuration of the LPI that event
/// `event` of device `dev` maps to.
pub const fn inv(dev: u32, event: u32) -> Cmd {
    [0x0c | ((dev as u64) << 32), event as u64, 0, 0]
}

/// `SYNC`: every earlier command's effect on `rdbase` is visible.
pub const fn sync(rdbase: u64) -> Cmd {
    [0x05, 0, rdbase, 0]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItsError {
    /// The distributor or the redistributor has no physical LPIs.
    NoLpis,
    /// The device IDs to cover need more than 256 table pages.
    DeviceTable,
    /// No device or collection table register.
    NoTable,
    /// Memory for a table could not be had.
    NoMemory,
    /// The ITS did not consume a command in time, or stalled on one.
    Command,
    /// A device ID beyond what the ITS or the device table covers.
    DeviceId,
    /// Every LPI is in use.
    NoLpi,
}

#[cfg(target_os = "none")]
pub use imp::*;

#[cfg(target_os = "none")]
mod imp {
    #![allow(unsafe_code)]

    use super::*;
    use crate::gic::{Gicv3, Redistributor};

    const GITS_CTLR: usize = 0x0000;
    const GITS_TYPER: usize = 0x0008;
    const GITS_CBASER: usize = 0x0080;
    const GITS_CWRITER: usize = 0x0088;
    const GITS_CREADR: usize = 0x0090;
    const GITS_BASER: usize = 0x0100;
    const GITS_CTLR_ENABLED: u32 = 1;
    const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
    const SPIN_LIMIT: u32 = 10_000_000;

    /// Physically contiguous, zeroed memory the caller hands over for good:
    /// kernel virtual address, physical address, bytes.
    #[derive(Debug, Clone, Copy)]
    pub struct Mem {
        pub va: usize,
        pub pa: u64,
        pub len: usize,
    }

    /// The source of [`Mem`]: `alloc(bytes, align)`.
    pub type Alloc<'a> = &'a mut dyn FnMut(usize, usize) -> Option<Mem>;

    /// A running ITS with one collection on the boot CPU.
    pub struct Its {
        base: usize,
        pa: u64,
        typer: Typer,
        /// Device IDs the device table covers.
        devices: u64,
        cmdq: Mem,
        /// Next command slot (bytes into the queue).
        wr: usize,
        rdbase: u64,
        prop: Mem,
        next_lpi: u32,
        /// The ITS and redistributor asked for non-shareable memory: clean
        /// the cache over what they read.
        clean: bool,
    }

    fn rd32(a: usize) -> u32 {
        // SAFETY: callers pass addresses inside the ITS frame mapped in `Its::init`.
        unsafe { (a as *const u32).read_volatile() }
    }
    fn wr32(a: usize, v: u32) {
        // SAFETY: as in `rd32`.
        unsafe { (a as *mut u32).write_volatile(v) }
    }
    fn rd64(a: usize) -> u64 {
        // SAFETY: as in `rd32`; the ITS's 64-bit registers.
        unsafe { (a as *const u64).read_volatile() }
    }
    fn wr64(a: usize, v: u64) {
        // SAFETY: as in `rd64`.
        unsafe { (a as *mut u64).write_volatile(v) }
    }

    /// Cleans the data cache over `len` bytes at `va` to the point of
    /// coherency, for an ITS that does not snoop.
    fn clean(va: usize, len: usize) {
        let mut a = va & !63;
        while a < va + len {
            // SAFETY: a cache clean of memory this module owns has no effect
            // besides writing dirty lines back.
            unsafe {
                core::arch::asm!("dc cvac, {}", in(reg) a, options(nostack, preserves_flags))
            };
            a += 64;
        }
        crate::cpu::dsb_sy();
    }

    impl Its {
        /// Enables LPIs on the boot CPU's redistributor `rd` (physical
        /// address `rd_pa`) and brings up the ITS whose frames are mapped at
        /// `base` (physical `pa`), with a device table for IDs up to
        /// `max_device`.
        ///
        /// # Safety
        /// `base` must map the ITS's [`FRAME_LEN`] bytes as device memory for
        /// the kernel's lifetime; `rd` must be the executing CPU's
        /// redistributor, with LPIs not yet enabled; memory from `alloc` must
        /// be zeroed, physically contiguous and never used by anything else.
        pub unsafe fn init(
            gic: &Gicv3,
            rd: Redistributor,
            rd_pa: u64,
            base: usize,
            pa: u64,
            max_device: u32,
            alloc: Alloc<'_>,
        ) -> Result<Self, ItsError> {
            if !gic.has_lpis() || !gic.rd_has_lpis(rd) || gic.id_bits() < ID_BITS {
                return Err(ItsError::NoLpis);
            }
            // Redistributor: configuration and pending tables, then LPIs on.
            let prop = alloc(PROP_BYTES, 0x1000).ok_or(ItsError::NoMemory)?;
            let pend = alloc(PEND_BYTES, PEND_ALIGN).ok_or(ItsError::NoMemory)?;
            let shared = gic.enable_lpis(rd, propbaser(prop.pa), pendbaser(pend.pa));
            // ITS: off and quiescent before its tables change.
            wr32(
                base + GITS_CTLR,
                rd32(base + GITS_CTLR) & !GITS_CTLR_ENABLED,
            );
            let mut quiet = false;
            for _ in 0..SPIN_LIMIT {
                if rd32(base + GITS_CTLR) & GITS_CTLR_QUIESCENT != 0 {
                    quiet = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !quiet {
                return Err(ItsError::Command);
            }
            let typer = Typer::decode(rd64(base + GITS_TYPER));
            let devices = (u64::from(max_device) + 1).min(1 << typer.dev_bits.min(32));
            let mut clean = !shared;
            let (mut have_dev, mut have_coll) = (false, false);
            for n in 0..8 {
                let reg = base + GITS_BASER + 8 * n;
                let old = rd64(reg);
                let ty = (old >> 56) & 0b111;
                let entry = (((old >> 48) & 0x1f) + 1) as usize;
                let entries = match ty {
                    BASER_TYPE_DEVICE => devices,
                    // One collection; one page is plenty.
                    BASER_TYPE_COLLECTION => 1,
                    _ => continue,
                };
                // Try 4 KiB pages; an ITS with a fixed page size reads back
                // its own, and the table is sized again for it.
                let mut field = 0u64;
                let mut done = false;
                for _ in 0..3 {
                    let page = page_bytes(field);
                    let pages = table_pages(entries, entry, page).ok_or(ItsError::DeviceTable)?;
                    let mem = alloc(pages as usize * page, page).ok_or(ItsError::NoMemory)?;
                    wr64(reg, baser(old, mem.pa, field, pages));
                    let back = rd64(reg);
                    if (back >> 8) & 0b11 == field {
                        clean |= !shareable(back);
                        done = true;
                        break;
                    }
                    // The memory stays allocated: a few pages, once.
                    field = (back >> 8) & 0b11;
                }
                if !done {
                    return Err(ItsError::NoTable);
                }
                match ty {
                    BASER_TYPE_DEVICE => have_dev = true,
                    _ => have_coll = true,
                }
            }
            if !have_dev || !have_coll {
                return Err(ItsError::NoTable);
            }
            let cmdq = alloc(CMDQ_BYTES, 0x1000).ok_or(ItsError::NoMemory)?;
            wr64(base + GITS_CBASER, cbaser(cmdq.pa));
            clean |= !shareable(rd64(base + GITS_CBASER));
            wr64(base + GITS_CWRITER, 0);
            wr32(base + GITS_CTLR, rd32(base + GITS_CTLR) | GITS_CTLR_ENABLED);
            let mut its = Self {
                base,
                pa,
                typer,
                devices,
                cmdq,
                wr: 0,
                rdbase: rdbase(typer.pta, rd_pa, gic.processor_number(rd)),
                prop,
                next_lpi: LPI_BASE,
                clean,
            };
            let rdb = its.rdbase;
            its.run(&[mapc(0, rdb), sync(rdb)])?;
            Ok(its)
        }

        /// Maps event 0 of device `device` (its requester ID) to a fresh LPI,
        /// enabled at the default priority, delivered to the boot CPU.
        /// Returns the LPI and the (address, data) the device writes to raise
        /// it.
        pub fn map_msi(
            &mut self,
            device: u32,
            alloc: Alloc<'_>,
        ) -> Result<(u32, u64, u32), ItsError> {
            if u64::from(device) >= self.devices {
                return Err(ItsError::DeviceId);
            }
            let lpi = self.next_lpi;
            if lpi >= LPI_BASE + PROP_BYTES as u32 {
                return Err(ItsError::NoLpi);
            }
            let itt_len = (self.typer.itt_entry << ITT_EVENT_BITS).max(ITT_ALIGN);
            let itt = alloc(itt_len, ITT_ALIGN).ok_or(ItsError::NoMemory)?;
            let slot = self.prop.va + (lpi - LPI_BASE) as usize;
            // SAFETY: inside the configuration table this ITS owns.
            unsafe { (slot as *mut u8).write_volatile(lpi_config(crate::gic::DEFAULT_PRIORITY)) };
            if self.clean {
                clean(slot, 1);
                clean(itt.va, itt.len);
            }
            let rdb = self.rdbase;
            self.run(&[
                mapd(device, itt.pa, ITT_EVENT_BITS),
                mapti(device, 0, lpi, 0),
                inv(device, 0),
                sync(rdb),
            ])?;
            self.next_lpi += 1;
            Ok((lpi, self.pa + TRANSLATER, 0))
        }

        /// Queues `cmds` and waits until the ITS has consumed them.
        fn run(&mut self, cmds: &[Cmd]) -> Result<(), ItsError> {
            for c in cmds {
                let at = self.cmdq.va + self.wr;
                for (i, w) in c.iter().enumerate() {
                    // SAFETY: slot `wr` of the command queue this ITS owns
                    // (32 bytes, inside its page).
                    unsafe { ((at + 8 * i) as *mut u64).write_volatile(*w) };
                }
                if self.clean {
                    clean(at, 32);
                }
                self.wr = (self.wr + 32) % CMDQ_BYTES;
            }
            // The commands must be in memory before the ITS sees the index.
            crate::cpu::dsb_sy();
            wr64(self.base + GITS_CWRITER, self.wr as u64);
            for _ in 0..SPIN_LIMIT {
                let r = rd64(self.base + GITS_CREADR);
                if r & 1 != 0 {
                    return Err(ItsError::Command);
                }
                if (r & 0xf_ffe0) as usize == self.wr {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
            Err(ItsError::Command)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typer_fields() {
        // QEMU's ITS: ITT entry size 12 (field 11), 16 device ID bits (field 15),
        // processor numbers (PTA 0), physical LPIs.
        let t = Typer::decode((11 << 4) | (15 << 13) | 1);
        assert_eq!(
            t,
            Typer {
                itt_entry: 12,
                dev_bits: 16,
                pta: false
            }
        );
        assert!(Typer::decode(1 << 19).pta);
    }

    #[test]
    fn table_sizing() {
        // netcup's NIC is 07:00.0 (requester ID 0x700): 1793 entries of 8 bytes.
        assert_eq!(table_pages(0x701, 8, 0x1000), Some(4));
        assert_eq!(table_pages(0x701, 8, 0x1_0000), Some(1));
        assert_eq!(table_pages(1, 8, 0x1000), Some(1));
        assert_eq!(table_pages(0, 8, 0x1000), Some(1));
        // 16 device ID bits flat at 4 KiB pages: 128 pages; 8-byte entries for
        // 2^20 IDs would need more than 256.
        assert_eq!(table_pages(1 << 16, 8, 0x1000), Some(128));
        assert_eq!(table_pages(1 << 20, 8, 0x1000), None);
        assert_eq!(page_bytes(0), 0x1000);
        assert_eq!(page_bytes(1), 0x4000);
        assert_eq!(page_bytes(2), 0x1_0000);
    }

    #[test]
    fn register_values() {
        // Type (device) and entry size (8) survive; valid, flat, 4 KiB, 4 pages.
        let old = (1u64 << 56) | (7 << 48);
        let v = baser(old, 0x4_1234_5000, 0, 4);
        assert_eq!(v >> 63, 1);
        assert_eq!((v >> 62) & 1, 0, "flat");
        assert_eq!((v >> 56) & 0b111, 1);
        assert_eq!((v >> 48) & 0x1f, 7);
        assert_eq!(v & 0xff, 3);
        assert_eq!((v >> 8) & 0b11, 0);
        assert_eq!(v & 0x0000_ffff_ffff_f000, 0x4_1234_5000);
        assert!(shareable(v));
        assert!(!shareable(v & !(0b11 << 10)));
        let c = cbaser(0x8000_1000);
        assert_eq!(
            (c >> 63, c & 0xff, c & 0x000f_ffff_ffff_f000),
            (1, 0, 0x8000_1000)
        );
        let p = propbaser(0x4000_0000);
        assert_eq!(p & 0x1f, 13);
        assert_eq!(p & 0x000f_ffff_ffff_f000, 0x4000_0000);
        let q = pendbaser(0x4001_0000);
        assert_eq!((q >> 62) & 1, 1, "PTZ");
        assert_eq!(q & 0x000f_ffff_ffff_0000, 0x4001_0000);
    }

    #[test]
    fn command_encodings() {
        // GICv3 architecture specification, chapter 5.3.
        let d = mapd(0x700, 0x4100_0100, 1);
        assert_eq!(d[0], 0x0000_0700_0000_0008);
        assert_eq!(d[1], 0, "Size = event ID bits - 1");
        assert_eq!(d[2], (1 << 63) | 0x4100_0100);
        let c = mapc(0, rdbase(false, 0, 2));
        assert_eq!(c[0], 0x09);
        assert_eq!(c[2], (1 << 63) | (2 << 16));
        assert_eq!(rdbase(true, 0x80a_0000, 9), 0x80a_0000);
        let t = mapti(0x700, 0, 8192, 0);
        assert_eq!(t[0], 0x0000_0700_0000_000a);
        assert_eq!(t[1], 8192u64 << 32);
        assert_eq!(t[2], 0);
        assert_eq!(inv(8, 0), [0x0000_0008_0000_000c, 0, 0, 0]);
        assert_eq!(sync(2 << 16), [0x05, 0, 2 << 16, 0]);
    }

    #[test]
    fn lpi_configuration_byte() {
        assert_eq!(lpi_config(0xa0), 0xa3);
        assert_eq!(lpi_config(0xff), 0xff);
        assert_eq!(PROP_BYTES, 8192);
        assert_eq!(PEND_BYTES, 2048);
    }
}
