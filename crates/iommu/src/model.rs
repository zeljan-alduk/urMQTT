//! Host models for the tests: memory the "unit" reads, and a register file.

use std::cell::Cell;
use std::collections::HashMap;

use crate::{Env, PAGE};

/// Physical memory in 4 KiB pages, allocated upwards from 1 GiB.
#[derive(Default)]
pub struct Mem {
    pages: HashMap<u64, Box<[u64; 512]>>,
    next: u64,
    pub fail_after: Option<usize>,
    pub allocs: usize,
    pub flushed: usize,
    clock: Cell<u64>,
}

impl Env for Mem {
    fn alloc(&mut self, pages: usize, align_pages: usize) -> Option<u64> {
        if self.fail_after.is_some_and(|n| self.allocs >= n) {
            return None;
        }
        self.allocs += 1;
        if self.next == 0 {
            self.next = 1 << 30;
        }
        let align = align_pages.max(1) as u64 * PAGE;
        let pa = self.next.div_ceil(align) * align;
        self.next = pa + pages as u64 * PAGE;
        for i in 0..pages as u64 {
            self.pages.insert(pa + i * PAGE, Box::new([0; 512]));
        }
        Some(pa)
    }

    fn read(&self, pa: u64) -> u64 {
        let page = self
            .pages
            .get(&(pa & !(PAGE - 1)))
            .expect("read of unallocated memory");
        page[((pa & (PAGE - 1)) / 8) as usize]
    }

    fn write(&mut self, pa: u64, v: u64) {
        let page = self
            .pages
            .get_mut(&(pa & !(PAGE - 1)))
            .expect("write to unallocated memory");
        page[((pa & (PAGE - 1)) / 8) as usize] = v;
    }

    fn flush(&mut self, _pa: u64, _len: usize) {
        self.flushed += 1;
    }

    fn now_ns(&self) -> u64 {
        // Every look at the clock is a millisecond: a wait that never ends
        // times out after about a hundred polls.
        self.clock.set(self.clock.get() + 1_000_000);
        self.clock.get()
    }
}

/// A register file: 64-bit cells keyed by offset (32-bit registers live in
/// the low or high half of their 8-byte cell).
#[derive(Default, Clone)]
pub struct RegFile {
    pub cells: HashMap<usize, u64>,
}

impl RegFile {
    pub fn get64(&self, off: usize) -> u64 {
        *self.cells.get(&off).unwrap_or(&0)
    }

    pub fn set64(&mut self, off: usize, v: u64) {
        self.cells.insert(off, v);
    }

    pub fn get32(&self, off: usize) -> u32 {
        let cell = self.get64(off & !7);
        if off & 4 == 0 {
            cell as u32
        } else {
            (cell >> 32) as u32
        }
    }

    pub fn set32(&mut self, off: usize, v: u32) {
        let cell = self.get64(off & !7);
        let new = if off & 4 == 0 {
            (cell & !0xffff_ffff) | u64::from(v)
        } else {
            (cell & 0xffff_ffff) | (u64::from(v) << 32)
        };
        self.set64(off & !7, new);
    }
}
