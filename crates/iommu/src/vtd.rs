//! Intel VT-d DMA remapping, legacy mode (root and context tables, second-
//! level page tables), register-based invalidation. Interrupt remapping is
//! left as the firmware set it (off on every machine tested): with it off, an
//! MSI is not a DMA and is not translated.
//!
//! Bring-up ([`Vtd::init`]): translation off if the firmware left it on, an
//! empty root table, global context-cache and IOTLB invalidation, translation
//! on. From then on every device's DMA faults until [`Vtd::attach`] gives it
//! a context entry pointing to its own domain.

use crate::pt::{Format, Tables};
use crate::{Env, Error, Fault, PAGE, Poll, Regs, wait};

pub const CAP: usize = 0x08;
pub const ECAP: usize = 0x10;
pub const GCMD: usize = 0x18;
pub const GSTS: usize = 0x1c;
pub const RTADDR: usize = 0x20;
pub const CCMD: usize = 0x28;
pub const FSTS: usize = 0x34;
pub const FECTL: usize = 0x38;

pub const GCMD_TE: u32 = 1 << 31;
pub const GCMD_SRTP: u32 = 1 << 30;
pub const GCMD_WBF: u32 = 1 << 27;
pub const GCMD_QIE: u32 = 1 << 26;
pub const GCMD_IRE: u32 = 1 << 25;
/// GSTS bits that are status of a one-shot command, not an enable: never
/// written back into GCMD.
const ONE_SHOT: u32 = GCMD_SRTP | GCMD_WBF | (1 << 29) | (1 << 24);

pub const CCMD_ICC: u64 = 1 << 63;
pub const CCMD_GLOBAL: u64 = 1 << 61;
pub const IOTLB_IVT: u64 = 1 << 63;
pub const IOTLB_GLOBAL: u64 = 1 << 60;
pub const IOTLB_DR: u64 = 1 << 49;
pub const IOTLB_DW: u64 = 1 << 48;

pub const FSTS_PFO: u32 = 1;
pub const FSTS_PPF: u32 = 1 << 1;
pub const FECTL_IM: u32 = 1 << 31;

/// What CAP and ECAP say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Domain IDs: 2^(4 + 2 * ND).
    pub domains: u32,
    /// Supported adjusted guest address widths (bit 1 = 39-bit 3-level,
    /// bit 2 = 48-bit 4-level, bit 3 = 57-bit 5-level).
    pub sagaw: u8,
    pub mgaw: u8,
    /// Caching mode: not-present entries may be cached (an emulated unit).
    pub caching_mode: bool,
    /// Write buffer flushing required.
    pub rwbf: bool,
    /// Fault recording registers: offset and count.
    pub fro: usize,
    pub nfr: usize,
    /// Table walks snoop the CPU caches.
    pub coherent: bool,
    pub queued_invalidation: bool,
    pub interrupt_remapping: bool,
    /// IOTLB registers' offset.
    pub iro: usize,
}

impl Caps {
    pub const fn decode(cap: u64, ecap: u64) -> Self {
        Self {
            domains: 1 << (4 + 2 * (cap & 7) as u32),
            sagaw: ((cap >> 8) & 0x1f) as u8,
            mgaw: (((cap >> 16) & 0x3f) + 1) as u8,
            caching_mode: (cap >> 7) & 1 != 0,
            rwbf: (cap >> 4) & 1 != 0,
            fro: (((cap >> 24) & 0x3ff) * 16) as usize,
            nfr: (((cap >> 40) & 0xff) + 1) as usize,
            coherent: ecap & 1 != 0,
            queued_invalidation: (ecap >> 1) & 1 != 0,
            interrupt_remapping: (ecap >> 3) & 1 != 0,
            iro: (((ecap >> 8) & 0x3ff) * 16) as usize,
        }
    }

    /// The table depth to use: 4 levels (48 bits) when supported, else 3.
    pub const fn levels(&self) -> Option<u8> {
        if self.sagaw & 0b100 != 0 {
            Some(4)
        } else if self.sagaw & 0b010 != 0 {
            Some(3)
        } else {
            None
        }
    }

    /// The bytes of register frame the driver touches.
    pub const fn frame_len(&self) -> usize {
        let a = self.fro + 16 * self.nfr;
        let b = self.iro + 16;
        let m = if a > b { a } else { b };
        if m > 0x1000 {
            m.div_ceil(0x1000) * 0x1000
        } else {
            0x1000
        }
    }
}

/// A root-table entry (low doubleword; the high one is reserved).
pub const fn root_entry(context_table: u64) -> u64 {
    (context_table & !(PAGE - 1)) | 1
}

/// A context entry: (low, high). Translation type 0 (untranslated requests
/// through the second-level tables), address width from the depth, domain.
pub const fn context_entry(tables: u64, levels: u8, domain: u16) -> (u64, u64) {
    let aw = (levels - 2) as u64;
    ((tables & !(PAGE - 1)) | 1, aw | ((domain as u64) << 8))
}

/// Decodes a fault recording register (low, high).
pub const fn decode_fault(lo: u64, hi: u64) -> Fault {
    Fault {
        source: (hi & 0xffff) as u32,
        addr: lo & !(PAGE - 1),
        // T: 0 = write request, 1 = read.
        write: (hi >> 62) & 1 == 0,
        reason: ((hi >> 32) & 0xff) as u8,
    }
}

/// One VT-d unit.
pub struct Vtd<R: Regs> {
    regs: R,
    pub caps: Caps,
    pub levels: u8,
    root: u64,
    /// The context table of each bus, once one exists (0 = none).
    contexts: [u64; 256],
    next_domain: u16,
}

impl<R: Regs> Vtd<R> {
    /// Reads the capabilities and brings the unit up blocking everything.
    pub fn init<E: Env>(mut regs: R, env: &mut E) -> Result<Self, Error> {
        let caps = Caps::decode(regs.read64(CAP), regs.read64(ECAP));
        let levels = caps
            .levels()
            .ok_or(Error::Unsupported("no 39- or 48-bit address width"))?;
        let gsts = regs.read32(GSTS);
        if gsts & GCMD_IRE != 0 {
            // Interrupt remapping uses the invalidation queue; this driver
            // invalidates by register and leaves interrupts to the firmware's
            // setup, which it would have to take over.
            return Err(Error::Unsupported(
                "interrupt remapping already enabled by the firmware",
            ));
        }
        // The fault event interrupt stays masked: faults are polled.
        regs.write32(FECTL, FECTL_IM);
        let mut v = Self {
            regs,
            caps,
            levels,
            root: 0,
            contexts: [0; 256],
            next_domain: 1,
        };
        if gsts & GCMD_TE != 0 {
            v.command(env, GCMD_TE, false, "translation off")?;
        }
        if gsts & GCMD_QIE != 0 {
            v.command(env, GCMD_QIE, false, "queued invalidation off")?;
        }
        v.root = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        env.flush(v.root, PAGE as usize);
        v.regs.write64(RTADDR, v.root);
        v.one_shot(env, GCMD_SRTP, "root table pointer")?;
        v.invalidate(env)?;
        v.command(env, GCMD_TE, true, "translation on")?;
        Ok(v)
    }

    /// Sets (or clears) a persistent enable bit and waits for GSTS to follow.
    fn command<E: Env>(
        &mut self,
        env: &E,
        bit: u32,
        on: bool,
        what: &'static str,
    ) -> Result<(), Error> {
        let keep = self.regs.read32(GSTS) & !ONE_SHOT;
        let v = if on { keep | bit } else { keep & !bit };
        self.regs.write32(GCMD, v);
        let regs = &self.regs;
        wait(env, what, || (regs.read32(GSTS) & bit != 0) == on)
    }

    /// Issues a one-shot command whose GSTS bit is set when done (SRTP).
    fn one_shot<E: Env>(&mut self, env: &E, bit: u32, what: &'static str) -> Result<(), Error> {
        let keep = self.regs.read32(GSTS) & !ONE_SHOT;
        self.regs.write32(GCMD, keep | bit);
        let regs = &self.regs;
        wait(env, what, || regs.read32(GSTS) & bit != 0)
    }

    /// Global context-cache and IOTLB invalidation (and the write buffer
    /// flush where the unit asks for it).
    pub fn invalidate<E: Env>(&mut self, env: &E) -> Result<(), Error> {
        if self.caps.rwbf {
            let keep = self.regs.read32(GSTS) & !ONE_SHOT;
            self.regs.write32(GCMD, keep | GCMD_WBF);
            let regs = &self.regs;
            wait(env, "write buffer flush", || {
                regs.read32(GSTS) & GCMD_WBF == 0
            })?;
        }
        self.regs.write64(CCMD, CCMD_ICC | CCMD_GLOBAL);
        let regs = &self.regs;
        wait(env, "context-cache invalidation", || {
            regs.read64(CCMD) & CCMD_ICC == 0
        })?;
        let iotlb = self.caps.iro + 8;
        self.regs
            .write64(iotlb, IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DR | IOTLB_DW);
        let regs = &self.regs;
        wait(env, "IOTLB invalidation", || {
            regs.read64(iotlb) & IOTLB_IVT == 0
        })
    }

    /// Creates the domain of requester ID `rid`: empty tables and its context
    /// entry. The caller maps into the returned tables and then calls
    /// [`invalidate`](Self::invalidate).
    pub fn attach<E: Env>(&mut self, env: &mut E, rid: u16) -> Result<Tables, Error> {
        if u32::from(self.next_domain) >= self.caps.domains {
            return Err(Error::IdOutOfRange);
        }
        let bus = usize::from(rid >> 8);
        let devfn = u64::from(rid & 0xff);
        let ctx = match self.contexts.get(bus).copied() {
            Some(0) => {
                let t = env.alloc(1, 1).ok_or(Error::NoMemory)?;
                env.flush(t, PAGE as usize);
                let slot = self.root + 16 * bus as u64;
                env.write(slot + 8, 0);
                env.write(slot, root_entry(t));
                env.flush(slot, 16);
                if let Some(c) = self.contexts.get_mut(bus) {
                    *c = t;
                }
                t
            }
            Some(t) => t,
            None => return Err(Error::IdOutOfRange),
        };
        let tables = Tables::new(env, self.levels, Format::VtdSecondLevel)?;
        let (lo, hi) = context_entry(tables.root, self.levels, self.next_domain);
        self.next_domain += 1;
        let slot = ctx + 16 * devfn;
        // The high half first: the entry becomes present with the low one.
        env.write(slot + 8, hi);
        env.write(slot, lo);
        env.flush(slot, 16);
        self.invalidate(env)?;
        Ok(tables)
    }

    /// Reads (and clears) at most `max` recorded faults, calling `each` for
    /// every one.
    pub fn poll_faults(&mut self, max: u32, mut each: impl FnMut(Fault)) -> Poll {
        let mut p = Poll::default();
        let fsts = self.regs.read32(FSTS);
        if fsts & FSTS_PFO != 0 {
            p.overflowed = true;
            self.regs.write32(FSTS, FSTS_PFO);
        }
        if fsts & FSTS_PPF == 0 {
            return p;
        }
        let n = self.caps.nfr.max(1);
        let start = ((fsts >> 8) & 0xff) as usize % n;
        for i in 0..n {
            let at = self.caps.fro + 16 * ((start + i) % n);
            let hi = self.regs.read64(at + 8);
            if hi >> 63 == 0 {
                continue;
            }
            if p.read >= max {
                p.more = true;
                break;
            }
            let lo = self.regs.read64(at);
            each(decode_fault(lo, hi));
            // F is write-1-to-clear (bit 127: bit 31 of the last dword).
            self.regs.write32(at + 12, 1 << 31);
            p.read += 1;
        }
        p
    }

    /// Whether translation is on (read back from the unit).
    pub fn enabled(&self) -> bool {
        self.regs.read32(GSTS) & GCMD_TE != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mem, RegFile};
    use crate::pt::Access;

    /// QEMU's `intel-iommu` (aw-bits=48, caching-mode=on): CAP and ECAP as it
    /// reports them, GSTS following GCMD, invalidations completing at once,
    /// and a walker that resolves a DMA through the in-memory tables.
    struct Unit {
        r: RegFile,
    }

    /// 256 domains, caching mode, 39- and 48-bit widths, MGAW 48, fault
    /// records at 0x220 (four of them).
    const QEMU_CAP: u64 = 2 | (1 << 7) | (0b110 << 8) | (47 << 16) | (0x22 << 24) | (3 << 40);
    /// Queued invalidation and interrupt remapping available, IOTLB at 0xf0.
    const QEMU_ECAP: u64 = 0b1010 | (0xf << 8);

    impl Unit {
        fn new() -> Self {
            let mut r = RegFile::default();
            r.set64(CAP, QEMU_CAP);
            r.set64(ECAP, QEMU_ECAP);
            Self { r }
        }

        /// The unit's own walk: root, context, second-level tables.
        fn dma(&self, m: &Mem, rid: u16, addr: u64, write: bool) -> Option<u64> {
            if self.r.get32(GSTS) & GCMD_TE == 0 {
                return Some(addr);
            }
            let root = self.r.get64(RTADDR) & !0xfff;
            let re = m.read(root + 16 * u64::from(rid >> 8));
            if re & 1 == 0 {
                return None;
            }
            let ce = (re & !0xfff) + 16 * u64::from(rid & 0xff);
            let (lo, hi) = (m.read(ce), m.read(ce + 8));
            if lo & 1 == 0 || (lo >> 2) & 3 != 0 {
                return None;
            }
            let levels = (hi & 7) as u8 + 2;
            let mut t = lo & !0xfff;
            for level in (1..=levels).rev() {
                let e = m.read(t + 8 * crate::pt::index(addr, level));
                if e & 1 == 0 || (write && e & 2 == 0) {
                    return None;
                }
                t = e & crate::pt::ADDR_MASK;
            }
            Some(t | (addr & 0xfff))
        }
    }

    impl Regs for Unit {
        fn read32(&self, off: usize) -> u32 {
            self.r.get32(off)
        }
        fn write32(&mut self, off: usize, v: u32) {
            match off {
                GCMD => {
                    // Enables follow; SRTP sets RTPS.
                    let mut s = v & !(GCMD_WBF);
                    if v & GCMD_SRTP == 0 {
                        s &= !GCMD_SRTP;
                    }
                    self.r.set32(GSTS, s);
                }
                FSTS => {
                    let s = self.r.get32(FSTS) & !(v & FSTS_PFO);
                    self.r.set32(FSTS, s);
                }
                o if (0x220..0x220 + 16 * 4).contains(&o) && o % 16 == 12 => {
                    let cur = self.r.get32(o);
                    self.r.set32(o, cur & !(v & (1 << 31)));
                }
                _ => self.r.set32(off, v),
            }
        }
        fn read64(&self, off: usize) -> u64 {
            self.r.get64(off)
        }
        fn write64(&mut self, off: usize, v: u64) {
            // Invalidations complete at once.
            let v = match off {
                CCMD => v & !CCMD_ICC,
                o if o == Caps::decode(QEMU_CAP, QEMU_ECAP).iro + 8 => v & !IOTLB_IVT,
                _ => v,
            };
            self.r.set64(off, v);
        }
    }

    impl Regs for &mut Unit {
        fn read32(&self, off: usize) -> u32 {
            (**self).read32(off)
        }
        fn write32(&mut self, off: usize, v: u32) {
            (**self).write32(off, v)
        }
        fn read64(&self, off: usize) -> u64 {
            (**self).read64(off)
        }
        fn write64(&mut self, off: usize, v: u64) {
            (**self).write64(off, v)
        }
    }

    #[test]
    fn qemu_capabilities() {
        let c = Caps::decode(QEMU_CAP, QEMU_ECAP);
        assert_eq!(c.levels(), Some(4));
        assert!(c.caching_mode);
        assert_eq!(c.fro, 0x220);
        assert_eq!(c.iro, 0xf0);
        assert_eq!(c.frame_len(), 0x1000);
        assert_eq!(Caps::decode(0, 0).levels(), None);
        assert_eq!(Caps::decode(1 << 9, 0).levels(), Some(3));
    }

    #[test]
    fn only_attached_devices_reach_only_their_pages() {
        let mut unit = Unit::new();
        let mut m = Mem::default();
        // Before bring-up the unit passes everything (the firmware's state).
        assert_eq!(unit.dma(&m, 0x18, 0x5000, true), Some(0x5000));
        let mut v = Vtd::init(&mut unit, &mut m).unwrap();
        assert!(v.enabled());
        let mut net = v.attach(&mut m, 0x0018).unwrap();
        let mut blk = v.attach(&mut m, 0x0020).unwrap();
        let mut far = v.attach(&mut m, 0x0300).unwrap();
        net.map(&mut m, 0x4000_0000, 0x3000, Access::RW).unwrap();
        blk.map(&mut m, 0x5000_0000, 0x1000, Access::RW).unwrap();
        far.map(&mut m, 0x6000_0000, 0x1000, Access::RW).unwrap();
        v.invalidate(&m).unwrap();
        assert_eq!(unit.dma(&m, 0x18, 0x4000_2abc, true), Some(0x4000_2abc));
        assert_eq!(
            unit.dma(&m, 0x18, 0x4000_3000, false),
            None,
            "past its buffer"
        );
        assert_eq!(
            unit.dma(&m, 0x18, 0x5000_0000, false),
            None,
            "another device's page"
        );
        assert_eq!(unit.dma(&m, 0x20, 0x5000_0010, true), Some(0x5000_0010));
        assert_eq!(unit.dma(&m, 0x0300, 0x6000_0000, true), Some(0x6000_0000));
        assert_eq!(unit.dma(&m, 0x28, 0x4000_0000, false), None, "not attached");
        assert_eq!(
            unit.dma(&m, 0x0400, 0x4000_0000, false),
            None,
            "a bus with no context table"
        );
    }

    #[test]
    fn firmware_left_translation_on_or_interrupt_remapping() {
        let mut unit = Unit::new();
        unit.r.set32(GSTS, GCMD_TE | GCMD_QIE);
        let mut m = Mem::default();
        let v = Vtd::init(&mut unit, &mut m).unwrap();
        assert!(v.enabled());
        assert_eq!(unit.r.get32(GSTS) & GCMD_QIE, 0);
        let mut unit = Unit::new();
        unit.r.set32(GSTS, GCMD_IRE);
        assert!(matches!(
            Vtd::init(&mut unit, &mut m),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn a_unit_that_never_answers_times_out() {
        struct Dead(RegFile);
        impl Regs for Dead {
            fn read32(&self, off: usize) -> u32 {
                self.0.get32(off)
            }
            fn write32(&mut self, _: usize, _: u32) {}
            fn read64(&self, off: usize) -> u64 {
                self.0.get64(off)
            }
            fn write64(&mut self, _: usize, _: u64) {}
        }
        let mut r = RegFile::default();
        r.set64(CAP, QEMU_CAP);
        let mut m = Mem::default();
        assert_eq!(
            Vtd::init(Dead(r), &mut m).err(),
            Some(Error::Timeout("root table pointer"))
        );
    }

    #[test]
    fn faults_are_read_cleared_and_bounded() {
        let mut unit = Unit::new();
        let mut m = Mem::default();
        Vtd::init(&mut unit, &mut m).unwrap();
        // Three recorded faults and an overflow.
        for (i, (sid, addr, read)) in [
            (0x18u64, 0x1234_5000u64, 1u64),
            (0x20, 0x9000, 0),
            (0x28, 0, 1),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 0x220 + 16 * i;
            unit.r.set64(at, addr);
            unit.r
                .set64(at + 8, (1 << 63) | (read << 62) | (6 << 32) | sid);
        }
        unit.r.set32(FSTS, FSTS_PPF | FSTS_PFO);
        let mut v = Vtd {
            regs: &mut unit,
            caps: Caps::decode(QEMU_CAP, QEMU_ECAP),
            levels: 4,
            root: 0,
            contexts: [0; 256],
            next_domain: 1,
        };
        let mut seen = Vec::new();
        let p = v.poll_faults(2, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (2, true, true));
        assert_eq!(
            seen[0],
            Fault {
                source: 0x18,
                addr: 0x1234_5000,
                write: false,
                reason: 6
            }
        );
        assert!(seen[1].write);
        let p = v.poll_faults(8, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (1, false, false));
        assert_eq!(seen[2].source, 0x28);
        // Cleared: nothing more, even with PPF still set.
        assert_eq!(v.poll_faults(8, |_| {}).read, 0);
    }

    #[test]
    fn domain_ids_are_bounded() {
        let mut unit = Unit::new();
        // ND = 0: 16 domains, 0 reserved.
        unit.r.set64(CAP, QEMU_CAP & !7);
        let mut m = Mem::default();
        let mut v = Vtd::init(&mut unit, &mut m).unwrap();
        for rid in 0..15u16 {
            v.attach(&mut m, rid).unwrap();
        }
        assert_eq!(v.attach(&mut m, 15).err(), Some(Error::IdOutOfRange));
    }
}
