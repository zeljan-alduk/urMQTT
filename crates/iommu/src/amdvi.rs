//! AMD-Vi (AMD I/O virtualization) DMA remapping: a device table for all
//! 65536 device IDs, v1 host page tables, a command buffer for invalidations
//! and an event log for faults. Interrupt remapping is not enabled: a device
//! table entry with IV = 0 passes MSIs through.
//!
//! Bring-up ([`AmdVi::init`]) writes every device table entry as "valid,
//! translation valid, mode 0, no read, no write", which blocks every DMA, then
//! enables the unit; [`AmdVi::attach`] gives one device ID its own tables.

use crate::pt::{Format, Tables};
use crate::{Env, Error, Fault, PAGE, Poll, Regs, wait};

pub const DEV_TAB_BASE: usize = 0x0000;
pub const CMD_BUF_BASE: usize = 0x0008;
pub const EVENT_LOG_BASE: usize = 0x0010;
pub const CONTROL: usize = 0x0018;
pub const EXCLUSION_BASE: usize = 0x0020;
pub const EXT_FEATURE: usize = 0x0030;
pub const CMD_HEAD: usize = 0x2000;
pub const CMD_TAIL: usize = 0x2008;
pub const EVENT_HEAD: usize = 0x2010;
pub const EVENT_TAIL: usize = 0x2018;
pub const STATUS: usize = 0x2020;
/// The register frame the driver touches.
pub const FRAME_LEN: usize = 0x4000;

pub const CTRL_IOMMU_EN: u64 = 1;
pub const CTRL_EVENT_LOG_EN: u64 = 1 << 2;
pub const CTRL_COHERENT: u64 = 1 << 10;
pub const CTRL_CMD_BUF_EN: u64 = 1 << 12;

pub const STATUS_EVENT_OVERFLOW: u64 = 1;
pub const STATUS_EVENT_LOG_RUN: u64 = 1 << 3;
pub const STATUS_CMD_BUF_RUN: u64 = 1 << 4;

/// Device IDs: the whole 16-bit space, 32 bytes each (2 MiB).
pub const DEVICES: usize = 0x1_0000;
pub const DTE_BYTES: u64 = 32;
const DEV_TAB_PAGES: usize = DEVICES * DTE_BYTES as usize / PAGE as usize;
/// Command buffer and event log: one page each (256 commands of 16 bytes,
/// 256 events of 16 bytes); the length field is log2 of the entries.
const RING_ENTRIES: u64 = 256;
const RING_LEN_FIELD: u64 = 8;

/// DTE bits (first doubleword).
pub const DTE_V: u64 = 1;
pub const DTE_TV: u64 = 1 << 1;
pub const DTE_IR: u64 = 1 << 61;
pub const DTE_IW: u64 = 1 << 62;

/// A device table entry blocking all DMA (four doublewords).
pub const fn blocked_dte() -> [u64; 4] {
    [DTE_V | DTE_TV, 0, 0, 0]
}

/// A device table entry translating through `levels`-level tables at `root`
/// in domain `domain`.
pub const fn dte(root: u64, levels: u8, domain: u16) -> [u64; 4] {
    [
        DTE_V
            | DTE_TV
            | ((levels as u64 & 7) << 9)
            | (root & 0x000f_ffff_ffff_f000)
            | DTE_IR
            | DTE_IW,
        domain as u64,
        0,
        0,
    ]
}

/// Commands (two doublewords; the opcode in bits 63:60 of the first).
pub const fn cmd_invalidate_dte(devid: u16) -> [u64; 2] {
    [devid as u64 | (2 << 60), 0]
}

/// Invalidates every page of `domain` (S = 1, the all-pages address).
pub const fn cmd_invalidate_pages(domain: u16) -> [u64; 2] {
    [
        ((domain as u64) << 32) | (3 << 60),
        0x7fff_ffff_ffff_f000 | 0b11,
    ]
}

/// Completion wait storing `data` at `pa` (8-byte aligned) when every
/// earlier command is done.
pub const fn cmd_completion_wait(pa: u64, data: u64) -> [u64; 2] {
    [(pa & 0x000f_ffff_ffff_fff8) | 1 | (1 << 60), data]
}

/// Decodes an event log entry (two doublewords).
pub const fn decode_event(e0: u64, e1: u64) -> Fault {
    let code = ((e0 >> 60) & 0xf) as u8;
    Fault {
        source: (e0 & 0xffff) as u32,
        addr: e1,
        // IO_PAGE_FAULT: RW (bit 5 of the flags at 59:48), 1 = write.
        write: code == 2 && (e0 >> 53) & 1 != 0,
        reason: code,
    }
}

/// One AMD-Vi unit.
pub struct AmdVi<R: Regs> {
    regs: R,
    pub levels: u8,
    dev_tab: u64,
    cmd: u64,
    cmd_tail: u64,
    events: u64,
    sem: u64,
    sem_seq: u64,
    next_domain: u16,
    pub coherent: bool,
}

impl<R: Regs> AmdVi<R> {
    pub fn init<E: Env>(mut regs: R, env: &mut E) -> Result<Self, Error> {
        // Off while the tables are replaced.
        let ctrl = regs.read64(CONTROL);
        if ctrl & (CTRL_IOMMU_EN | CTRL_CMD_BUF_EN | CTRL_EVENT_LOG_EN) != 0 {
            regs.write64(CONTROL, 0);
        }
        let dev_tab = env.alloc(DEV_TAB_PAGES, 1).ok_or(Error::NoMemory)?;
        for d in 0..DEVICES as u64 {
            let at = dev_tab + d * DTE_BYTES;
            env.write(at, blocked_dte()[0]);
        }
        env.flush(dev_tab, DEVICES * DTE_BYTES as usize);
        let cmd = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        let events = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        let sem = env.alloc(1, 1).ok_or(Error::NoMemory)?;
        regs.write64(DEV_TAB_BASE, dev_tab | (DEV_TAB_PAGES as u64 - 1));
        regs.write64(CMD_BUF_BASE, cmd | (RING_LEN_FIELD << 56));
        regs.write64(EVENT_LOG_BASE, events | (RING_LEN_FIELD << 56));
        regs.write64(EXCLUSION_BASE, 0);
        regs.write64(CMD_HEAD, 0);
        regs.write64(CMD_TAIL, 0);
        regs.write64(EVENT_HEAD, 0);
        regs.write64(EVENT_TAIL, 0);
        // Coherent: the unit snoops the caches for its table walks (every
        // machine this runs on; the kernel flushes anyway when told it is
        // not, through `Env::flush`).
        regs.write64(CONTROL, CTRL_CMD_BUF_EN | CTRL_EVENT_LOG_EN | CTRL_COHERENT);
        regs.write64(
            CONTROL,
            CTRL_CMD_BUF_EN | CTRL_EVENT_LOG_EN | CTRL_COHERENT | CTRL_IOMMU_EN,
        );
        let mut a = Self {
            regs,
            levels: 4,
            dev_tab,
            cmd,
            cmd_tail: 0,
            events,
            sem,
            sem_seq: 0,
            next_domain: 1,
            coherent: true,
        };
        {
            let r = &a.regs;
            wait(env, "command buffer running", || {
                r.read64(STATUS) & STATUS_CMD_BUF_RUN != 0
            })?;
        }
        a.sync(env)?;
        Ok(a)
    }

    fn push<E: Env>(&mut self, env: &mut E, c: [u64; 2]) -> Result<(), Error> {
        let next = (self.cmd_tail + 16) % (RING_ENTRIES * 16);
        {
            let r = &self.regs;
            wait(env, "command buffer space", || {
                r.read64(CMD_HEAD) & 0x7_fff0 != next
            })?;
        }
        env.write(self.cmd + self.cmd_tail, c[0]);
        env.write(self.cmd + self.cmd_tail + 8, c[1]);
        env.flush(self.cmd + self.cmd_tail, 16);
        self.cmd_tail = next;
        self.regs.write64(CMD_TAIL, next);
        Ok(())
    }

    /// Waits until every command issued so far is done.
    pub fn sync<E: Env>(&mut self, env: &mut E) -> Result<(), Error> {
        self.sem_seq += 1;
        let seq = self.sem_seq;
        env.write(self.sem, 0);
        self.push(env, cmd_completion_wait(self.sem, seq))?;
        let sem = self.sem;
        wait(env, "completion wait", || env.read(sem) == seq)
    }

    /// Gives device ID `devid` its own (empty) tables.
    pub fn attach<E: Env>(&mut self, env: &mut E, devid: u16) -> Result<(Tables, u16), Error> {
        if self.next_domain == u16::MAX {
            return Err(Error::IdOutOfRange);
        }
        let tables = Tables::new(env, self.levels, Format::AmdV1)?;
        let domain = self.next_domain;
        self.next_domain += 1;
        let e = dte(tables.root, self.levels, domain);
        let at = self.dev_tab + u64::from(devid) * DTE_BYTES;
        for (i, w) in e.iter().enumerate().rev() {
            env.write(at + 8 * i as u64, *w);
        }
        env.flush(at, DTE_BYTES as usize);
        self.push(env, cmd_invalidate_dte(devid))?;
        self.push(env, cmd_invalidate_pages(domain))?;
        self.sync(env)?;
        Ok((tables, domain))
    }

    /// After mapping into `domain`'s tables.
    pub fn invalidate<E: Env>(&mut self, env: &mut E, domain: u16) -> Result<(), Error> {
        self.push(env, cmd_invalidate_pages(domain))?;
        self.sync(env)
    }

    /// Reads at most `max` events.
    pub fn poll_faults<E: Env>(&mut self, env: &E, max: u32, mut each: impl FnMut(Fault)) -> Poll {
        let mut p = Poll::default();
        let status = self.regs.read64(STATUS);
        if status & STATUS_EVENT_OVERFLOW != 0 {
            p.overflowed = true;
            // The log stopped: clear the overflow and start it again.
            self.regs.write64(STATUS, STATUS_EVENT_OVERFLOW);
            let ctrl = self.regs.read64(CONTROL);
            self.regs.write64(CONTROL, ctrl & !CTRL_EVENT_LOG_EN);
            self.regs.write64(CONTROL, ctrl | CTRL_EVENT_LOG_EN);
        }
        let ring = RING_ENTRIES * 16;
        let tail = self.regs.read64(EVENT_TAIL) & 0x7_fff0;
        let mut head = self.regs.read64(EVENT_HEAD) & 0x7_fff0;
        while head != tail && head < ring && tail < ring {
            if p.read >= max {
                p.more = true;
                break;
            }
            let e0 = env.read(self.events + head);
            let e1 = env.read(self.events + head + 8);
            each(decode_event(e0, e1));
            p.read += 1;
            head = (head + 16) % ring;
        }
        self.regs.write64(EVENT_HEAD, head);
        p
    }

    pub fn enabled(&self) -> bool {
        self.regs.read64(CONTROL) & CTRL_IOMMU_EN != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mem, RegFile};
    use crate::pt::Access;
    use std::cell::RefCell;

    /// An AMD-Vi model: commands run when the tail moves (completion waits
    /// store their data), status follows control, and a walker resolves DMA
    /// through the device table.
    struct Unit<'m> {
        r: RegFile,
        mem: &'m RefCell<Mem>,
    }

    impl Unit<'_> {
        fn dma(&self, devid: u16, addr: u64, write: bool) -> Option<u64> {
            let m = self.mem.borrow();
            let base = self.r.get64(DEV_TAB_BASE) & !0xfff;
            let d0 = m.read(base + u64::from(devid) * 32);
            if d0 & DTE_V == 0 || d0 & DTE_TV == 0 {
                return Some(addr);
            }
            let need = if write { DTE_IW } else { DTE_IR };
            let mode = (d0 >> 9) & 7;
            if d0 & need == 0 {
                return None;
            }
            if mode == 0 {
                return Some(addr);
            }
            let mut t = d0 & 0x000f_ffff_ffff_f000;
            for level in (1..=mode as u8).rev() {
                let e = m.read(t + 8 * crate::pt::index(addr, level));
                if e & 1 == 0 || e & need == 0 {
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
            self.r.set32(off, v)
        }
        fn read64(&self, off: usize) -> u64 {
            self.r.get64(off)
        }
        fn write64(&mut self, off: usize, v: u64) {
            match off {
                CONTROL => {
                    self.r.set64(CONTROL, v);
                    let mut s = self.r.get64(STATUS) & STATUS_EVENT_OVERFLOW;
                    if v & CTRL_CMD_BUF_EN != 0 && v & CTRL_IOMMU_EN != 0 {
                        s |= STATUS_CMD_BUF_RUN;
                    }
                    self.r.set64(STATUS, s);
                }
                STATUS => {
                    let s = self.r.get64(STATUS) & !v;
                    self.r.set64(STATUS, s);
                }
                CMD_TAIL => {
                    self.r.set64(CMD_TAIL, v);
                    let base = self.r.get64(CMD_BUF_BASE) & 0x000f_ffff_ffff_f000;
                    let mut head = self.r.get64(CMD_HEAD);
                    let mut m = self.mem.borrow_mut();
                    while head != v {
                        let c0 = m.read(base + head);
                        let c1 = m.read(base + head + 8);
                        if c0 >> 60 == 1 && c0 & 1 != 0 {
                            m.write(c0 & 0x000f_ffff_ffff_fff8, c1);
                        }
                        head = (head + 16) % 4096;
                    }
                    self.r.set64(CMD_HEAD, head);
                }
                _ => self.r.set64(off, v),
            }
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

    /// `Env` over the shared memory the model also reads.
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
    fn everything_blocked_until_attached_then_only_its_pages() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit {
            r: RegFile::default(),
            mem: &mem,
        };
        let mut env = Shared(&mem);
        let mut a = AmdVi::init(&mut unit, &mut env).unwrap();
        assert!(a.enabled());
        let (mut net, dom) = a.attach(&mut env, 0x0018).unwrap();
        net.map(&mut env, 0x7000_0000, 0x2000, Access::RW).unwrap();
        a.invalidate(&mut env, dom).unwrap();
        assert_eq!(unit.dma(0x18, 0x7000_1008, true), Some(0x7000_1008));
        assert_eq!(unit.dma(0x18, 0x7000_2000, false), None);
        assert_eq!(unit.dma(0x20, 0x7000_0000, false), None, "never attached");
        assert_eq!(unit.dma(0xffff, 0, true), None, "the last device ID too");
    }

    #[test]
    fn events_are_bounded_and_overflow_restarts_the_log() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit {
            r: RegFile::default(),
            mem: &mem,
        };
        let mut env = Shared(&mem);
        let a = AmdVi::init(&mut unit, &mut env).unwrap();
        let log = a.events;
        for i in 0..3u64 {
            env.write(log + 16 * i, (2 << 60) | (1 << 53) | (0x18 + i));
            env.write(log + 16 * i + 8, 0xdead_0000 + i * 0x1000);
        }
        unit.r.set64(EVENT_TAIL, 48);
        unit.r
            .set64(STATUS, STATUS_EVENT_OVERFLOW | STATUS_CMD_BUF_RUN);
        let mut a = AmdVi {
            regs: &mut unit,
            levels: 4,
            dev_tab: 0,
            cmd: 0,
            cmd_tail: 0,
            events: log,
            sem: 0,
            sem_seq: 0,
            next_domain: 1,
            coherent: true,
        };
        let mut seen = Vec::new();
        let p = a.poll_faults(&env, 2, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (2, true, true));
        assert_eq!(
            seen[0],
            Fault {
                source: 0x18,
                addr: 0xdead_0000,
                write: true,
                reason: 2
            }
        );
        let p = a.poll_faults(&env, 2, |f| seen.push(f));
        assert_eq!((p.read, p.overflowed, p.more), (1, false, false));
        assert_eq!(a.poll_faults(&env, 2, |_| {}).read, 0);
        assert_eq!(unit.r.get64(STATUS) & STATUS_EVENT_OVERFLOW, 0);
        assert_ne!(unit.r.get64(CONTROL) & CTRL_EVENT_LOG_EN, 0);
    }

    #[test]
    fn a_garbage_tail_reads_nothing() {
        let mem = RefCell::new(Mem::default());
        let mut unit = Unit {
            r: RegFile::default(),
            mem: &mem,
        };
        let mut env = Shared(&mem);
        AmdVi::init(&mut unit, &mut env).unwrap();
        unit.r.set64(EVENT_TAIL, 0x7_fff0);
        let mut a = AmdVi {
            regs: &mut unit,
            levels: 4,
            dev_tab: 0,
            cmd: 0,
            cmd_tail: 0,
            events: 0,
            sem: 0,
            sem_seq: 0,
            next_domain: 1,
            coherent: true,
        };
        assert_eq!(a.poll_faults(&env, 8, |_| {}).read, 0);
    }

    #[test]
    fn encodings() {
        let d = dte(0x1234_5000, 4, 7);
        assert_eq!(d[0] & 0xfff, 0b1000_0000_0011);
        assert_eq!(d[1], 7);
        assert_eq!(cmd_completion_wait(0x8008, 5), [0x8009 | (1 << 60), 5]);
        assert_eq!(cmd_invalidate_dte(0x18)[0] >> 60, 2);
        assert_eq!(cmd_invalidate_pages(3)[0], (3 << 32) | (3 << 60));
        assert!(!decode_event(1 << 60, 0).write);
    }
}
