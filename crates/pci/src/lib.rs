//! PCIe configuration space: ECAM addressing, enumeration, BARs,
//! capabilities and MSI-X tables.
//!
//! Hardware access goes through [`ConfigSpace`] so enumeration logic is
//! host-tested against a simulated bus. BARs are used as programmed by the
//! firmware (ADR-024); this crate never assigns addresses.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

/// Bus/device/function address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bdf {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

impl Bdf {
    /// Byte offset of this function's 4 KiB window inside an ECAM region
    /// starting at bus `bus_start`.
    pub const fn ecam_offset(self, bus_start: u8) -> u64 {
        ((self.bus.wrapping_sub(bus_start) as u64) << 20)
            | ((self.dev as u64 & 0x1f) << 15)
            | ((self.func as u64 & 0x7) << 12)
    }
}

impl core::fmt::Display for Bdf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.dev, self.func)
    }
}

/// 32-bit configuration space access. Offsets are 4-byte aligned, < 4096.
pub trait ConfigSpace {
    fn read32(&self, bdf: Bdf, offset: u16) -> u32;
    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32);

    fn read16(&self, bdf: Bdf, offset: u16) -> u16 {
        (self.read32(bdf, offset & !3) >> ((offset & 2) * 8)) as u16
    }

    fn read8(&self, bdf: Bdf, offset: u16) -> u8 {
        (self.read32(bdf, offset & !3) >> ((offset & 3) * 8)) as u8
    }

    /// Read-modify-write of a 16-bit field.
    fn write16(&mut self, bdf: Bdf, offset: u16, value: u16) {
        let shift = (offset & 2) * 8;
        let old = self.read32(bdf, offset & !3);
        let new = (old & !(0xffff << shift)) | (u32::from(value) << shift);
        self.write32(bdf, offset & !3, new);
    }
}

pub const VENDOR_ID: u16 = 0x00;
pub const COMMAND: u16 = 0x04;
pub const STATUS: u16 = 0x06;
pub const CLASS_REV: u16 = 0x08;
pub const HEADER_TYPE: u16 = 0x0e;
pub const BAR0: u16 = 0x10;
pub const SUBSYSTEM_ID: u16 = 0x2e;
pub const CAP_PTR: u16 = 0x34;
pub const SECONDARY_BUS: u16 = 0x19;

pub const CMD_MEMORY: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
pub const CMD_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAP_LIST: u16 = 1 << 4;

pub const CAP_VENDOR: u8 = 0x09;
pub const CAP_MSIX: u8 = 0x11;

/// Bound on capability-list walks (a malicious list could loop).
const MAX_CAPS: usize = 48;
/// Bound on functions reported by one enumeration.
pub const MAX_FUNCTIONS: usize = 64;

/// A decoded base address register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    Memory {
        base: u64,
        prefetchable: bool,
        is64: bool,
    },
    Io {
        base: u32,
    },
}

/// One discovered function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Function {
    pub bdf: Bdf,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub subsystem: u16,
    pub bridge: bool,
}

impl Function {
    pub fn is(&self, vendor: u16, device: u16) -> bool {
        self.vendor == vendor && self.device == device
    }
}

/// Fixed-capacity list of functions (no allocation during enumeration).
#[derive(Debug, Clone, Copy)]
pub struct Functions {
    items: [Option<Function>; MAX_FUNCTIONS],
    pub truncated: bool,
}

impl Functions {
    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.items.iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, f: Function) {
        match self.items.iter_mut().find(|s| s.is_none()) {
            Some(slot) => *slot = Some(f),
            None => self.truncated = true,
        }
    }
}

fn probe<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> Option<Function> {
    let id = cfg.read32(bdf, VENDOR_ID);
    let vendor = id as u16;
    if vendor == 0xffff || vendor == 0 {
        return None;
    }
    let class = cfg.read32(bdf, CLASS_REV);
    Some(Function {
        bdf,
        vendor,
        device: (id >> 16) as u16,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        subsystem: cfg.read16(bdf, SUBSYSTEM_ID),
        bridge: cfg.read8(bdf, HEADER_TYPE) & 0x7f == 1,
    })
}

/// Enumerates every function reachable from `bus_start` through bridges,
/// staying within `[bus_start, bus_end]`. Each bus is scanned at most once.
pub fn enumerate<C: ConfigSpace>(cfg: &C, bus_start: u8, bus_end: u8) -> Functions {
    let mut out = Functions {
        items: [None; MAX_FUNCTIONS],
        truncated: false,
    };
    let mut seen = [false; 256];
    let mut stack = [0u8; 32];
    let mut depth = 1usize;
    if let Some(s) = stack.first_mut() {
        *s = bus_start;
    }
    while depth > 0 {
        depth -= 1;
        let bus = stack.get(depth).copied().unwrap_or(bus_start);
        if bus < bus_start || bus > bus_end {
            continue;
        }
        match seen.get_mut(usize::from(bus)) {
            Some(s) if !*s => *s = true,
            _ => continue,
        }
        for dev in 0..32u8 {
            let f0 = Bdf { bus, dev, func: 0 };
            let Some(first) = probe(cfg, f0) else {
                continue;
            };
            let multi = cfg.read8(f0, HEADER_TYPE) & 0x80 != 0;
            let funcs = if multi { 8 } else { 1 };
            for func in 0..funcs {
                let bdf = Bdf { bus, dev, func };
                let f = if func == 0 {
                    Some(first)
                } else {
                    probe(cfg, bdf)
                };
                if let Some(f) = f {
                    out.push(f);
                    if f.bridge {
                        let secondary = cfg.read8(bdf, SECONDARY_BUS);
                        if let Some(slot) = stack.get_mut(depth) {
                            *slot = secondary;
                            depth += 1;
                        }
                    }
                }
            }
        }
    }
    out
}

/// Decodes BAR `index` (0..6) of a type-0 header. 64-bit BARs consume the
/// next index too. Returns `None` for unimplemented or unassigned BARs.
pub fn bar<C: ConfigSpace>(cfg: &C, bdf: Bdf, index: u8) -> Option<Bar> {
    if index > 5 {
        return None;
    }
    let off = BAR0 + u16::from(index) * 4;
    let lo = cfg.read32(bdf, off);
    if lo & 1 == 1 {
        let base = lo & !0x3;
        return (base != 0).then_some(Bar::Io { base });
    }
    let kind = (lo >> 1) & 0x3;
    let prefetchable = lo & 0x8 != 0;
    let (base, is64) = if kind == 0x2 {
        if index == 5 {
            return None;
        }
        let hi = cfg.read32(bdf, off + 4);
        ((u64::from(hi) << 32) | u64::from(lo & !0xf), true)
    } else {
        (u64::from(lo & !0xf), false)
    };
    (base != 0).then_some(Bar::Memory {
        base,
        prefetchable,
        is64,
    })
}

/// Iterates the capability list as (offset, id). Bounded and loop-safe.
pub fn capabilities<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> impl Iterator<Item = (u16, u8)> + '_ {
    let has_caps = cfg.read16(bdf, STATUS) & STATUS_CAP_LIST != 0;
    let mut next = if has_caps {
        u16::from(cfg.read8(bdf, CAP_PTR) & 0xfc)
    } else {
        0
    };
    let mut budget = MAX_CAPS;
    core::iter::from_fn(move || {
        if next < 0x40 || budget == 0 {
            return None;
        }
        budget -= 1;
        let off = next;
        let id = cfg.read8(bdf, off);
        next = u16::from(cfg.read8(bdf, off + 1) & 0xfc);
        Some((off, id))
    })
}

/// Location of an MSI-X table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixInfo {
    /// Capability offset in config space.
    pub cap: u16,
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

pub fn msix<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> Option<MsixInfo> {
    let (cap, _) = capabilities(cfg, bdf).find(|&(_, id)| id == CAP_MSIX)?;
    let ctrl = cfg.read16(bdf, cap + 2);
    let table = cfg.read32(bdf, cap + 4);
    let pba = cfg.read32(bdf, cap + 8);
    Some(MsixInfo {
        cap,
        table_size: (ctrl & 0x7ff) + 1,
        table_bar: (table & 0x7) as u8,
        table_offset: table & !0x7,
        pba_bar: (pba & 0x7) as u8,
        pba_offset: pba & !0x7,
    })
}

/// Sets bits in the command register.
pub fn enable<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, bits: u16) {
    let cmd = cfg.read16(bdf, COMMAND);
    cfg.write16(bdf, COMMAND, cmd | bits);
}

/// Enables (or disables) MSI-X with the function mask cleared.
pub fn msix_enable<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, info: &MsixInfo, on: bool) {
    let ctrl = cfg.read16(bdf, info.cap + 2);
    let ctrl = if on {
        (ctrl | 0x8000) & !0x4000
    } else {
        ctrl & !0x8000
    };
    cfg.write16(bdf, info.cap + 2, ctrl);
}

/// One MSI-X table entry as 4 little-endian words.
pub const fn msix_entry(address: u64, data: u32, masked: bool) -> [u32; 4] {
    [address as u32, (address >> 32) as u32, data, masked as u32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A simulated configuration space: 4 KiB per function.
    #[derive(Default)]
    struct Sim(BTreeMap<Bdf, [u32; 1024]>);

    impl Sim {
        fn add(
            &mut self,
            bdf: Bdf,
            vendor: u16,
            device: u16,
            class: u32,
            header: u8,
        ) -> &mut [u32; 1024] {
            let regs = self.0.entry(bdf).or_insert([0; 1024]);
            regs[0] = u32::from(vendor) | (u32::from(device) << 16);
            regs[2] = class << 8;
            regs[3] = u32::from(header) << 16;
            regs
        }
    }

    impl ConfigSpace for Sim {
        fn read32(&self, bdf: Bdf, off: u16) -> u32 {
            self.0
                .get(&bdf)
                .map_or(0xffff_ffff, |r| r[usize::from(off / 4)])
        }
        fn write32(&mut self, bdf: Bdf, off: u16, v: u32) {
            if let Some(r) = self.0.get_mut(&bdf) {
                r[usize::from(off / 4)] = v;
            }
        }
    }

    const fn bdf(bus: u8, dev: u8, func: u8) -> Bdf {
        Bdf { bus, dev, func }
    }

    #[test]
    fn ecam_offsets() {
        assert_eq!(bdf(0, 0, 0).ecam_offset(0), 0);
        assert_eq!(
            bdf(1, 2, 3).ecam_offset(0),
            (1 << 20) | (2 << 15) | (3 << 12)
        );
        assert_eq!(bdf(5, 0, 0).ecam_offset(4), 1 << 20);
        assert_eq!(bdf(0, 31, 7).to_string(), "00:1f.7");
    }

    #[test]
    fn enumerates_through_bridges_and_multifunction() {
        let mut sim = Sim::default();
        sim.add(bdf(0, 0, 0), 0x1b36, 0x0008, 0x06_00_00, 0); // host bridge
        let br = sim.add(bdf(0, 1, 0), 0x1b36, 0x000c, 0x06_04_00, 0x81); // bridge, multifunction
        br[6] = 0x0000_0200; // secondary bus 2 at byte 0x19
        sim.add(bdf(0, 1, 1), 0x1af4, 0x1041, 0x02_00_00, 0);
        sim.add(bdf(2, 0, 0), 0x1af4, 0x1042, 0x01_00_00, 0);
        sim.add(bdf(3, 0, 0), 0x1af4, 0x1044, 0x00_ff_00, 0); // unreachable bus
        let fs = enumerate(&sim, 0, 255);
        let ids: Vec<_> = fs.iter().map(|f| (f.bdf, f.device)).collect();
        assert_eq!(
            ids,
            vec![
                (bdf(0, 0, 0), 0x0008),
                (bdf(0, 1, 0), 0x000c),
                (bdf(0, 1, 1), 0x1041),
                (bdf(2, 0, 0), 0x1042)
            ]
        );
        assert!(fs.iter().any(|f| f.bridge));
        assert!(!fs.truncated);
    }

    #[test]
    fn bridge_loops_and_out_of_range_buses_terminate() {
        let mut sim = Sim::default();
        let br = sim.add(bdf(0, 0, 0), 1, 2, 0x06_04_00, 1);
        br[6] = 0x0000_0000; // secondary = own bus: a loop
        let br = sim.add(bdf(0, 1, 0), 1, 3, 0x06_04_00, 1);
        br[6] = 0x0000_0900; // secondary 9, outside the range below
        let fs = enumerate(&sim, 0, 4);
        assert_eq!(fs.len(), 2);
    }

    #[test]
    fn bar_decoding() {
        let mut sim = Sim::default();
        let r = sim.add(bdf(0, 2, 0), 0x1af4, 0x1041, 0, 0);
        r[4] = 0x1000_0000; // BAR0: 32-bit memory
        r[5] = 0x0000_c001; // BAR1: I/O
        r[8] = 0x8000_000c; // BAR4: 64-bit prefetchable
        r[9] = 0x0000_0080;
        assert_eq!(
            bar(&sim, bdf(0, 2, 0), 0),
            Some(Bar::Memory {
                base: 0x1000_0000,
                prefetchable: false,
                is64: false
            })
        );
        assert_eq!(bar(&sim, bdf(0, 2, 0), 1), Some(Bar::Io { base: 0xc000 }));
        assert_eq!(bar(&sim, bdf(0, 2, 0), 2), None, "unassigned");
        assert_eq!(
            bar(&sim, bdf(0, 2, 0), 4),
            Some(Bar::Memory {
                base: 0x80_8000_0000,
                prefetchable: true,
                is64: true
            })
        );
        assert_eq!(bar(&sim, bdf(0, 2, 0), 6), None);
    }

    #[test]
    fn capabilities_and_msix() {
        let mut sim = Sim::default();
        let r = sim.add(bdf(0, 3, 0), 0x1af4, 0x1042, 0, 0);
        r[1] = 0x0010_0000; // status: capability list
        r[0x34 / 4] = 0x40;
        r[0x40 / 4] = 0x0003_5009; // vendor cap, next 0x50, len 3
        r[0x50 / 4] = 0x0003_0011; // MSI-X, next 0, table size 4
        r[0x54 / 4] = 0x0000_2001; // table in BAR1 at 0x2000
        r[0x58 / 4] = 0x0000_3001; // PBA in BAR1 at 0x3000
        let caps: Vec<_> = capabilities(&sim, bdf(0, 3, 0)).collect();
        assert_eq!(caps, vec![(0x40, CAP_VENDOR), (0x50, CAP_MSIX)]);
        let m = msix(&sim, bdf(0, 3, 0)).unwrap();
        assert_eq!(
            (m.table_size, m.table_bar, m.table_offset, m.pba_offset),
            (4, 1, 0x2000, 0x3000)
        );
        msix_enable(&mut sim, bdf(0, 3, 0), &m, true);
        assert_eq!(sim.read16(bdf(0, 3, 0), 0x52) & 0xc000, 0x8000);
        enable(&mut sim, bdf(0, 3, 0), CMD_MEMORY | CMD_BUS_MASTER);
        assert_eq!(sim.read16(bdf(0, 3, 0), COMMAND), 0x6);
        assert_eq!(
            sim.read16(bdf(0, 3, 0), STATUS),
            0x10,
            "status untouched by write16"
        );
    }

    #[test]
    fn looping_capability_list_is_bounded() {
        let mut sim = Sim::default();
        let r = sim.add(bdf(0, 4, 0), 1, 1, 0, 0);
        r[1] = 0x0010_0000;
        r[0x34 / 4] = 0x40;
        r[0x40 / 4] = 0x0000_4009; // points at itself
        assert_eq!(capabilities(&sim, bdf(0, 4, 0)).count(), MAX_CAPS);
    }

    #[test]
    fn msix_entry_layout() {
        assert_eq!(
            msix_entry(0x1_0802_0040, 80, false),
            [0x0802_0040, 1, 80, 0]
        );
        assert_eq!(msix_entry(0, 0, true)[3], 1);
    }
}
