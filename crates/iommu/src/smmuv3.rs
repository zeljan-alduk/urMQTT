//! Arm SMMUv3: a linear stream table, one context descriptor per attached
//! stream (stage 1, AArch64 tables, 4 KiB granule), a command queue for
//! configuration and TLB invalidation, and an event queue for faults.
//!
//! Bring-up ([`Smmu::init`]) leaves every stream table entry invalid, which
//! aborts the stream's transactions (and records `C_BAD_STE`), so nothing
//! reaches memory until [`Smmu::attach`] gives a stream its own tables. On a
//! GIC an MSI is a write to the ITS or GICv2m doorbell, which the SMMU
//! translates like any DMA: the kernel maps the doorbell page into each
//! domain as device memory.

use crate::pt::{Format, Tables};
use crate::{Env, Error, Fault, PAGE, Poll, Regs, wait};

pub const IDR0: usize = 0x00;
pub const IDR1: usize = 0x04;
pub const IDR5: usize = 0x14;
pub const CR0: usize = 0x20;
pub const CR0ACK: usize = 0x24;
pub const CR1: usize = 0x28;
pub const CR2: usize = 0x2c;
pub const GBPA: usize = 0x44;
pub const IRQ_CTRL: usize = 0x50;
pub const GERROR: usize = 0x60;
pub const STRTAB_BASE: usize = 0x80;
pub const STRTAB_BASE_CFG: usize = 0x88;
pub const CMDQ_BASE: usize = 0x90;
pub const CMDQ_PROD: usize = 0x98;
pub const CMDQ_CONS: usize = 0x9c;
pub const EVENTQ_BASE: usize = 0xa0;
/// The event queue's producer and consumer live in register page 1.
pub const EVENTQ_PROD: usize = 0x1_00a8;
pub const EVENTQ_CONS: usize = 0x1_00ac;
/// Two 64 KiB register pages.
pub const FRAME_LEN: usize = 0x2_0000;

pub const CR0_SMMUEN: u32 = 1;
pub const CR0_EVENTQEN: u32 = 1 << 2;
pub const CR0_CMDQEN: u32 = 1 << 3;

/// Normal inner-shareable write-back for tables and queues (CR1).
pub const CR1_WB_ISH: u32 = (0b11 << 10) | (1 << 8) | (1 << 6) | (0b11 << 4) | (1 << 2) | 1;
/// Record C_BAD_STREAMID events (CR2).
pub const CR2_RECINVSID: u32 = 1 << 1;

/// MAIR of every context descriptor: index 0 normal write-back, index 1
/// device-nGnRE (the MSI doorbell).
pub const MAIR: u64 = 0x04_ff;

pub const CMDQ_LOG2: u32 = 8;
pub const EVENTQ_LOG2: u32 = 7;
const CMD_BYTES: u64 = 16;
const EVENT_BYTES: u64 = 32;
const STE_BYTES: u64 = 64;
const CD_BYTES: u64 = 64;

pub const CMD_CFGI_STE: u64 = 0x03;
pub const CMD_CFGI_ALL: u64 = 0x04;
pub const CMD_TLBI_NH_ASID: u64 = 0x11;
pub const CMD_TLBI_NSNH_ALL: u64 = 0x30;
pub const CMD_SYNC: u64 = 0x46;
/// CMDQ_CONS.ERR (30:24).
const CONS_ERR: u32 = 0x7f << 24;

/// What the ID registers say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub stage1: bool,
    pub aarch64_tables: bool,
    pub coherent: bool,
    pub asid16: bool,
    pub sid_bits: u32,
    pub cmdq_log2: u32,
    pub eventq_log2: u32,
    /// Output address size, bits.
    pub oas: u32,
    pub gran4k: bool,
    /// Two-level stream tables only (linear not supported is not a thing in
    /// SMMUv3; recorded for the log).
    pub two_level: bool,
}

impl Caps {
    pub const fn decode(idr0: u32, idr1: u32, idr5: u32) -> Self {
        let oas = match idr5 & 7 {
            0 => 32,
            1 => 36,
            2 => 40,
            3 => 42,
            4 => 44,
            5 => 48,
            _ => 52,
        };
        Self {
            stage1: (idr0 >> 1) & 1 != 0,
            aarch64_tables: (idr0 >> 3) & 1 != 0,
            coherent: (idr0 >> 4) & 1 != 0,
            asid16: (idr0 >> 12) & 1 != 0,
            two_level: (idr0 >> 27) & 3 == 1,
            sid_bits: idr1 & 0x3f,
            cmdq_log2: (idr1 >> 21) & 0x1f,
            eventq_log2: (idr1 >> 16) & 0x1f,
            oas,
            gran4k: (idr5 >> 4) & 1 != 0,
        }
    }

    /// IPS / OAS field value for the context descriptor.
    pub const fn ips(&self) -> u64 {
        match self.oas {
            32 => 0,
            36 => 1,
            40 => 2,
            42 => 3,
            44 => 4,
            48 => 5,
            _ => 6,
        }
    }

    /// Table depth: 4 levels (48-bit input) when the output can reach that
    /// far, else 3 (39-bit).
    pub const fn levels(&self) -> u8 {
        if self.oas >= 48 { 4 } else { 3 }
    }
}

/// An STE for stage-1 translation through the context descriptor at `cd`
/// (eight doublewords): valid, config S1-translate/S2-bypass, one CD, the
/// CD fetched write-back inner-shareable, non-secure EL1 stream world,
/// incoming shareability.
pub const fn ste(cd: u64) -> [u64; 8] {
    let d0 = 1 | (0b101 << 1) | (cd & 0x000f_ffff_ffff_ffc0);
    // S1CIR = S1COR = write-back (1), S1CSH = inner (3), SHCFG = incoming (1).
    let d1 = (1 << 2) | (1 << 4) | (0b11 << 6) | (1 << 44);
    [d0, d1, 0, 0, 0, 0, 0, 0]
}

/// A context descriptor (eight doublewords) for the tables at `ttb0` with
/// `levels` levels: 4 KiB granule, TTB0 walks write-back inner-shareable,
/// TTB1 off, AArch64, faults recorded and aborted, ASID `asid`.
pub const fn cd(ttb0: u64, levels: u8, ips: u64, asid: u16) -> [u64; 8] {
    let t0sz = 64 - (12 + 9 * levels as u64);
    let d0 = t0sz
        | (1 << 8)          // IR0 write-back
        | (1 << 10)         // OR0 write-back
        | (0b11 << 12)      // SH0 inner shareable
        | (1 << 30)         // EPD1
        | (1 << 31)         // V
        | ((ips & 7) << 32) // IPS
        | (1 << 41)         // AA64
        | (1 << 45)         // R: record faults
        | (1 << 46)         // A: abort on fault
        | (1 << 47)         // ASET: not shared with the CPU
        | ((asid as u64) << 48);
    [d0, ttb0 & 0x000f_ffff_ffff_fff0, 0, MAIR, 0, 0, 0, 0]
}

pub const fn cmd_cfgi_ste(sid: u32) -> [u64; 2] {
    [CMD_CFGI_STE | ((sid as u64) << 32), 1]
}

pub const fn cmd_cfgi_all() -> [u64; 2] {
    [CMD_CFGI_ALL, 31]
}

pub const fn cmd_tlbi_asid(asid: u16) -> [u64; 2] {
    [CMD_TLBI_NH_ASID | ((asid as u64) << 48), 0]
}

pub const fn cmd_tlbi_all() -> [u64; 2] {
    [CMD_TLBI_NSNH_ALL, 0]
}

/// CMD_SYNC with no completion signal: done when the consumer passes it.
pub const fn cmd_sync() -> [u64; 2] {
    [CMD_SYNC, 0]
}

/// Decodes an event record (four doublewords used of 32 bytes).
pub const fn decode_event(e: [u64; 4]) -> Fault {
    let ty = (e[0] & 0xff) as u8;
    let translation = matches!(ty, 0x10..=0x13);
    Fault {
        source: (e[0] >> 32) as u32,
        addr: if translation { e[2] } else { 0 },
        // RnW (bit 35 of the second doubleword): 0 = write.
        write: translation && (e[1] >> 35) & 1 == 0,
        reason: ty,
    }
}

/// One SMMUv3.
pub struct Smmu<R: Regs> {
    regs: R,
    pub caps: Caps,
    pub levels: u8,
    strtab: u64,
    pub sid_log2: u32,
    cmdq: u64,
    prod: u32,
    eventq: u64,
    next_asid: u16,
}

impl<R: Regs> Smmu<R> {
    /// Brings the unit up with a linear stream table for stream IDs below
    /// `max_sid + 1` (rounded up to a power of two), all invalid.
    pub fn init<E: Env>(mut regs: R, env: &mut E, max_sid: u32) -> Result<Self, Error> {
        let caps = Caps::decode(regs.read32(IDR0), regs.read32(IDR1), regs.read32(IDR5));
        if !caps.stage1 || !caps.aarch64_tables || !caps.gran4k {
            return Err(Error::Unsupported(
                "stage-1 AArch64 tables with a 4 KiB granule",
            ));
        }
        let sid_log2 = 32 - max_sid.leading_zeros();
        if sid_log2 > caps.sid_bits || sid_log2 > 16 {
            return Err(Error::IdOutOfRange);
        }
        let cmdq_log2 = CMDQ_LOG2.min(caps.cmdq_log2);
        let eventq_log2 = EVENTQ_LOG2.min(caps.eventq_log2);
        if cmdq_log2 == 0 {
            return Err(Error::Unsupported("command queue"));
        }
        // Off while the tables are replaced.
        if regs.read32(CR0) != 0 {
            regs.write32(CR0, 0);
            let r = &regs;
            wait(env, "SMMU disable", || r.read32(CR0ACK) == 0)?;
        }
        let st_bytes = (STE_BYTES << sid_log2) as usize;
        let st_pages = st_bytes.div_ceil(PAGE as usize);
        let strtab = env.alloc(st_pages, st_pages).ok_or(Error::NoMemory)?;
        env.flush(strtab, st_bytes);
        let cmdq = env
            .alloc(
                ((CMD_BYTES << cmdq_log2) as usize).div_ceil(PAGE as usize),
                1,
            )
            .ok_or(Error::NoMemory)?;
        let eq_bytes = (EVENT_BYTES << eventq_log2) as usize;
        let eventq = env
            .alloc(eq_bytes.div_ceil(PAGE as usize), 1)
            .ok_or(Error::NoMemory)?;
        env.flush(eventq, eq_bytes);
        regs.write32(IRQ_CTRL, 0);
        regs.write32(CR1, CR1_WB_ISH);
        regs.write32(CR2, CR2_RECINVSID);
        regs.write64(STRTAB_BASE, (1 << 62) | (strtab & 0x000f_ffff_ffff_ffc0));
        regs.write32(STRTAB_BASE_CFG, sid_log2);
        regs.write64(
            CMDQ_BASE,
            (1 << 62) | (cmdq & 0x000f_ffff_ffff_ffe0) | u64::from(cmdq_log2),
        );
        regs.write32(CMDQ_PROD, 0);
        regs.write32(CMDQ_CONS, 0);
        regs.write64(
            EVENTQ_BASE,
            (1 << 62) | (eventq & 0x000f_ffff_ffff_ffe0) | u64::from(eventq_log2),
        );
        regs.write32(EVENTQ_PROD, 0);
        regs.write32(EVENTQ_CONS, 0);
        let queues = CR0_CMDQEN | CR0_EVENTQEN;
        regs.write32(CR0, queues);
        {
            let r = &regs;
            wait(env, "SMMU queues", || r.read32(CR0ACK) == queues)?;
        }
        let mut s = Self {
            regs,
            caps,
            levels: caps.levels(),
            strtab,
            sid_log2,
            cmdq: cmdq | u64::from(cmdq_log2),
            prod: 0,
            eventq: eventq | u64::from(eventq_log2),
            next_asid: 1,
        };
        s.submit(env, &[cmd_cfgi_all(), cmd_tlbi_all()])?;
        s.regs.write32(CR0, queues | CR0_SMMUEN);
        let r = &s.regs;
        wait(env, "SMMU enable", || {
            r.read32(CR0ACK) == queues | CR0_SMMUEN
        })?;
        Ok(s)
    }

    fn cmdq_log2(&self) -> u32 {
        (self.cmdq & 0x1f) as u32
    }

    /// Queues `cmds` and a CMD_SYNC, and waits for the consumer to pass it.
    pub fn submit<E: Env>(&mut self, env: &mut E, cmds: &[[u64; 2]]) -> Result<(), Error> {
        let log2 = self.cmdq_log2();
        let entries = 1u32 << log2;
        let wrap = entries;
        let mask = (entries << 1) - 1;
        let base = self.cmdq & 0x000f_ffff_ffff_ffe0;
        let full = |prod: u32, cons: u32| {
            (prod & (entries - 1)) == (cons & (entries - 1)) && (prod & wrap) != (cons & wrap)
        };
        for c in cmds.iter().chain(core::iter::once(&cmd_sync())) {
            {
                let r = &self.regs;
                let prod = self.prod;
                wait(env, "SMMU command queue space", || {
                    !full(prod, r.read32(CMDQ_CONS))
                })?;
            }
            let at = base + CMD_BYTES * u64::from(self.prod & (entries - 1));
            env.write(at, c[0]);
            env.write(at + 8, c[1]);
            env.flush(at, CMD_BYTES as usize);
            self.prod = (self.prod + 1) & mask;
        }
        self.regs.write32(CMDQ_PROD, self.prod);
        let prod = self.prod;
        let r = &self.regs;
        let mut err = false;
        wait(env, "SMMU CMD_SYNC", || {
            let cons = r.read32(CMDQ_CONS);
            err = cons & CONS_ERR != 0;
            err || cons & mask == prod
        })?;
        if err {
            return Err(Error::CommandError);
        }
        Ok(())
    }

    /// Gives stream `sid` its own (empty) tables.
    pub fn attach<E: Env>(&mut self, env: &mut E, sid: u32) -> Result<(Tables, u16), Error> {
        if sid >> self.sid_log2 != 0 {
            return Err(Error::IdOutOfRange);
        }
        let limit = if self.caps.asid16 { u16::MAX } else { 255 };
        if self.next_asid >= limit {
            return Err(Error::IdOutOfRange);
        }
        let asid = self.next_asid;
        self.next_asid += 1;
        let tables = Tables::new(env, self.levels, Format::ArmStage1)?;
        let cd_pa = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        for (i, w) in cd(tables.root, self.levels, self.caps.ips(), asid)
            .iter()
            .enumerate()
        {
            env.write(cd_pa + 8 * i as u64, *w);
        }
        env.flush(cd_pa, CD_BYTES as usize);
        let at = self.strtab + STE_BYTES * u64::from(sid);
        let e = ste(cd_pa);
        // The valid doubleword last.
        for (i, w) in e.iter().enumerate().rev() {
            env.write(at + 8 * i as u64, *w);
        }
        env.flush(at, STE_BYTES as usize);
        self.submit(env, &[cmd_cfgi_ste(sid), cmd_tlbi_asid(asid)])?;
        Ok((tables, asid))
    }

    /// After mapping into the tables of `asid`.
    pub fn invalidate<E: Env>(&mut self, env: &mut E, asid: u16) -> Result<(), Error> {
        self.submit(env, &[cmd_tlbi_asid(asid)])
    }

    /// Reads at most `max` events.
    pub fn poll_faults<E: Env>(&mut self, env: &E, max: u32, mut each: impl FnMut(Fault)) -> Poll {
        let mut p = Poll::default();
        let log2 = (self.eventq & 0x1f) as u32;
        let entries = 1u32 << log2;
        let base = self.eventq & 0x000f_ffff_ffff_ffe0;
        let prod_reg = self.regs.read32(EVENTQ_PROD);
        // EVENTQ_PROD.OVFLG (bit 31) toggles on an overflow; acknowledged by
        // copying it into EVENTQ_CONS.OVACKFLG.
        let ovflg = prod_reg & (1 << 31);
        let cons_reg = self.regs.read32(EVENTQ_CONS);
        if ovflg != cons_reg & (1 << 31) {
            p.overflowed = true;
        }
        let mask = (entries << 1) - 1;
        let prod = prod_reg & mask;
        let mut cons = cons_reg & mask;
        while cons != prod {
            if p.read >= max {
                p.more = true;
                break;
            }
            let at = base + EVENT_BYTES * u64::from(cons & (entries - 1));
            let e = [
                env.read(at),
                env.read(at + 8),
                env.read(at + 16),
                env.read(at + 24),
            ];
            each(decode_event(e));
            p.read += 1;
            cons = (cons + 1) & mask;
        }
        self.regs.write32(EVENTQ_CONS, cons | ovflg);
        p
    }

    /// Global errors the unit reports (GERROR, for the log).
    pub fn gerror(&self) -> u32 {
        self.regs.read32(GERROR)
    }

    pub fn enabled(&self) -> bool {
        self.regs.read32(CR0ACK) & CR0_SMMUEN != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mem, RegFile};
    use crate::pt::Access;
    use std::cell::RefCell;

    /// QEMU's `smmuv3`: stage 1, AArch64 tables, coherent, 16-bit stream
    /// and ASID, OAS 44 bits; CR0ACK follows CR0, the command queue is
    /// consumed when PROD moves, and a walker resolves a stream's DMA.
    struct Unit<'m> {
        r: RegFile,
        mem: &'m RefCell<Mem>,
        bad_command: bool,
    }

    const QEMU_IDR0: u32 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 12) | (1 << 27);
    const QEMU_IDR1: u32 = 16 | (19 << 16) | (19 << 21);
    const QEMU_IDR5: u32 = 4 | (1 << 4);

    impl<'m> Unit<'m> {
        fn new(mem: &'m RefCell<Mem>) -> Self {
            let mut r = RegFile::default();
            r.set32(IDR0, QEMU_IDR0);
            r.set32(IDR1, QEMU_IDR1);
            r.set32(IDR5, QEMU_IDR5);
            Self {
                r,
                mem,
                bad_command: false,
            }
        }

        fn dma(&self, sid: u32, addr: u64, write: bool) -> Option<u64> {
            if self.r.get32(CR0) & CR0_SMMUEN == 0 {
                return Some(addr);
            }
            let m = self.mem.borrow();
            let log2 = self.r.get32(STRTAB_BASE_CFG) & 0x3f;
            if sid >> log2 != 0 {
                return None;
            }
            let st = self.r.get64(STRTAB_BASE) & 0x000f_ffff_ffff_ffc0;
            let d0 = m.read(st + 64 * u64::from(sid));
            if d0 & 1 == 0 || (d0 >> 1) & 7 != 0b101 {
                return None;
            }
            let cd = d0 & 0x000f_ffff_ffff_ffc0;
            let c0 = m.read(cd);
            if (c0 >> 31) & 1 == 0 {
                return None;
            }
            let levels = ((64 - (c0 & 0x3f)) - 12) / 9;
            let mut t = m.read(cd + 8) & 0x000f_ffff_ffff_f000;
            for level in (1..=levels as u8).rev() {
                let e = m.read(t + 8 * crate::pt::index(addr, level));
                if e & 0b11 != 0b11 {
                    return None;
                }
                if level == 1 && (e & (1 << 10) == 0 || (write && e & (1 << 7) != 0)) {
                    return None;
                }
                t = e & crate::pt::ADDR_MASK;
            }
            Some(t | (addr & 0xfff))
        }
    }

    impl Regs for Unit<'_> {
        fn read32(&self, off: usize) -> u32 {
            self.r.get32(off)
        }
        fn write32(&mut self, off: usize, v: u32) {
            self.r.set32(off, v);
            match off {
                CR0 => self.r.set32(CR0ACK, v),
                CMDQ_PROD => {
                    let cons = if self.bad_command { v | (1 << 24) } else { v };
                    self.r.set32(CMDQ_CONS, cons);
                }
                _ => {}
            }
        }
        fn read64(&self, off: usize) -> u64 {
            self.r.get64(off)
        }
        fn write64(&mut self, off: usize, v: u64) {
            self.r.set64(off, v)
        }
    }

    impl Regs for &mut Unit<'_> {
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

    struct Shared<'m>(&'m RefCell<Mem>);

    impl Env for Shared<'_> {
        fn alloc(&mut self, pages: usize, align: usize) -> Option<u64> {
            self.0.borrow_mut().alloc(pages, align)
        }
        fn read(&self, pa: u64) -> u64 {
            self.0.borrow().read(pa)
        }
        fn write(&mut self, pa: u64, v: u64) {
            self.0.borrow_mut().write(pa, v)
        }
        fn flush(&mut self, pa: u64, len: usize) {
            self.0.borrow_mut().flush(pa, len)
        }
        fn now_ns(&self) -> u64 {
            self.0.borrow().now_ns()
        }
    }

    #[test]
    fn qemu_capabilities() {
        let c = Caps::decode(QEMU_IDR0, QEMU_IDR1, QEMU_IDR5);
        assert!(c.stage1 && c.aarch64_tables && c.coherent && c.asid16 && c.gran4k);
        assert_eq!((c.sid_bits, c.oas, c.levels(), c.ips()), (16, 44, 3, 4));
        assert_eq!(Caps::decode(0, 0, 5).levels(), 4);
    }

    #[test]
    fn streams_reach_only_their_pages_and_the_doorbell() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit::new(&mem);
        let mut env = Shared(&mem);
        assert_eq!(
            unit.dma(0x10, 0x4000_0000, true),
            Some(0x4000_0000),
            "bypass before"
        );
        let mut s = Smmu::init(&mut unit, &mut env, 0x20).unwrap();
        assert_eq!(s.sid_log2, 6);
        assert!(s.enabled());
        let (mut net, asid) = s.attach(&mut env, 0x10).unwrap();
        net.map(&mut env, 0x4000_0000, 0x1000, Access::RW).unwrap();
        net.map(&mut env, 0x0809_0000, 0x1000, Access::DOORBELL)
            .unwrap();
        s.invalidate(&mut env, asid).unwrap();
        assert_eq!(unit.dma(0x10, 0x4000_0123, true), Some(0x4000_0123));
        assert_eq!(unit.dma(0x10, 0x0809_0040, true), Some(0x0809_0040));
        assert_eq!(unit.dma(0x10, 0x4000_1000, false), None);
        assert_eq!(unit.dma(0x18, 0x4000_0000, false), None, "invalid STE");
        assert_eq!(
            unit.dma(0x80, 0x4000_0000, false),
            None,
            "beyond the stream table"
        );
    }

    #[test]
    fn stream_ids_beyond_the_table_and_command_errors() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit::new(&mem);
        let mut env = Shared(&mem);
        let mut s = Smmu::init(&mut unit, &mut env, 0xff).unwrap();
        assert_eq!(s.attach(&mut env, 0x100).err(), Some(Error::IdOutOfRange));
        assert!(matches!(
            Smmu::init(&mut unit, &mut env, 0x1_0000),
            Err(Error::IdOutOfRange)
        ));
        unit.bad_command = true;
        assert_eq!(
            Smmu::init(&mut unit, &mut env, 0xff).err(),
            Some(Error::CommandError)
        );
    }

    #[test]
    fn events_are_bounded_and_overflow_acknowledged() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit::new(&mem);
        let mut env = Shared(&mem);
        let s = Smmu::init(&mut unit, &mut env, 0xff).unwrap();
        let base = s.eventq & !0x1f;
        for i in 0..3u64 {
            let at = base + 32 * i;
            env.write(at, 0x10 | ((0x10 + i) << 32));
            env.write(at + 8, if i == 0 { 1 << 35 } else { 0 });
            env.write(at + 16, 0x1234_0000 + i);
        }
        unit.r.set32(EVENTQ_PROD, 3 | (1 << 31));
        let mut s = Smmu {
            regs: &mut unit,
            caps: Caps::decode(QEMU_IDR0, QEMU_IDR1, QEMU_IDR5),
            levels: 3,
            strtab: 0,
            sid_log2: 8,
            cmdq: 0,
            prod: 0,
            eventq: base | u64::from(EVENTQ_LOG2),
            next_asid: 1,
        };
        let mut seen = Vec::new();
        let p = s.poll_faults(&env, 2, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (2, true, true));
        assert_eq!(
            seen[0],
            Fault {
                source: 0x10,
                addr: 0x1234_0000,
                write: false,
                reason: 0x10
            }
        );
        assert!(seen[1].write);
        let p = s.poll_faults(&env, 2, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (1, false, false));
        assert_eq!(unit.r.get32(EVENTQ_CONS), 3 | (1 << 31));
    }

    #[test]
    fn encodings() {
        let e = ste(0x4000_0040);
        assert_eq!(e[0], 0x4000_0040 | 0b1011);
        let c = cd(0x5000_0000, 4, 5, 3);
        assert_eq!(c[0] & 0x3f, 16, "T0SZ for 48 bits");
        assert_eq!((c[0] >> 48) as u16, 3);
        assert_eq!(c[3], MAIR);
        assert_eq!(cmd_cfgi_ste(0x18), [0x18_0000_0003, 1]);
        assert_eq!(
            decode_event([0x02 | (7 << 32), 0, 0xdead, 0]).addr,
            0,
            "C_BAD_STREAMID has no address"
        );
    }
}
