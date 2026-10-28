//! Physical frame allocator: one bit per 4 KiB frame over the span of RAM.
//!
//! A set bit means "free". The bitmap covers `[base, base + frames * 4 KiB)`;
//! holes in the memory map simply stay marked as used. Single-frame
//! allocation scans from a rotating hint; contiguous runs (for DMA rings)
//! scan linearly. Double frees and foreign addresses are reported, never
//! silently accepted.

use urmqtt_arch_aarch64::paging::{FrameSource, PAGE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Address outside the managed span or not page aligned.
    Foreign(u64),
    /// The frame was already free.
    DoubleFree(u64),
}

pub struct FrameAllocator<'a> {
    bitmap: &'a mut [u64],
    base: u64,
    frames: usize,
    free: usize,
    hint: usize,
}

/// Bytes of bitmap needed to manage `span` bytes of physical address space.
pub const fn bitmap_bytes(span: u64) -> usize {
    let frames = span.div_ceil(PAGE_SIZE) as usize;
    frames.div_ceil(64) * 8
}

impl<'a> FrameAllocator<'a> {
    /// Creates an allocator over `[base, base + frames * 4 KiB)` with every
    /// frame marked used. `bitmap` must hold at least `frames` bits.
    pub fn new(bitmap: &'a mut [u64], base: u64, frames: usize) -> Option<Self> {
        if !base.is_multiple_of(PAGE_SIZE) || bitmap.len() * 64 < frames {
            return None;
        }
        bitmap.fill(0);
        Some(Self {
            bitmap,
            base,
            frames,
            free: 0,
            hint: 0,
        })
    }

    pub fn free_frames(&self) -> usize {
        self.free
    }

    pub fn total_frames(&self) -> usize {
        self.frames
    }

    fn index(&self, pa: u64) -> Result<usize, FrameError> {
        if !pa.is_multiple_of(PAGE_SIZE) || pa < self.base {
            return Err(FrameError::Foreign(pa));
        }
        let i = ((pa - self.base) / PAGE_SIZE) as usize;
        if i >= self.frames {
            return Err(FrameError::Foreign(pa));
        }
        Ok(i)
    }

    fn is_free(&self, i: usize) -> bool {
        self.bitmap
            .get(i / 64)
            .is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    fn set(&mut self, i: usize, free: bool) {
        if let Some(w) = self.bitmap.get_mut(i / 64) {
            if free {
                *w |= 1 << (i % 64);
            } else {
                *w &= !(1 << (i % 64));
            }
        }
    }

    /// Marks the whole pages inside `[pa, pa + len)` free. Pages outside the
    /// span are ignored; already-free pages stay free.
    pub fn add_free_range(&mut self, pa: u64, len: u64) {
        let start = pa.next_multiple_of(PAGE_SIZE);
        let end = pa.saturating_add(len) / PAGE_SIZE * PAGE_SIZE;
        let mut a = start;
        while a < end {
            if let Ok(i) = self.index(a)
                && !self.is_free(i)
            {
                self.set(i, true);
                self.free += 1;
            }
            a += PAGE_SIZE;
        }
    }

    /// Marks every page touching `[pa, pa + len)` used (e.g. frames taken
    /// before this allocator existed).
    pub fn reserve_range(&mut self, pa: u64, len: u64) {
        let start = pa / PAGE_SIZE * PAGE_SIZE;
        let end = pa.saturating_add(len).next_multiple_of(PAGE_SIZE);
        let mut a = start;
        while a < end {
            if let Ok(i) = self.index(a)
                && self.is_free(i)
            {
                self.set(i, false);
                self.free -= 1;
            }
            a += PAGE_SIZE;
        }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        if self.free == 0 {
            return None;
        }
        let words = self.frames.div_ceil(64);
        let start = self.hint / 64;
        for k in 0..words {
            let w = (start + k) % words;
            let word = self.bitmap.get(w).copied().unwrap_or(0);
            if word != 0 {
                let i = w * 64 + word.trailing_zeros() as usize;
                if i < self.frames {
                    self.set(i, false);
                    self.free -= 1;
                    self.hint = i;
                    return Some(self.base + i as u64 * PAGE_SIZE);
                }
            }
        }
        None
    }

    /// `n` physically contiguous frames whose first frame index is a
    /// multiple of `align` frames (relative to physical address 0).
    pub fn alloc_contiguous(&mut self, n: usize, align: usize) -> Option<u64> {
        if n == 0 || n > self.free {
            return None;
        }
        let align = align.max(1);
        let base_frame = (self.base / PAGE_SIZE) as usize;
        let mut i = 0usize;
        while i + n <= self.frames {
            let abs = base_frame + i;
            if !abs.is_multiple_of(align) {
                i += align - abs % align;
                continue;
            }
            match (i..i + n).find(|&j| !self.is_free(j)) {
                None => {
                    for j in i..i + n {
                        self.set(j, false);
                    }
                    self.free -= n;
                    return Some(self.base + i as u64 * PAGE_SIZE);
                }
                Some(used) => i = used + 1,
            }
        }
        None
    }

    pub fn free(&mut self, pa: u64) -> Result<(), FrameError> {
        let i = self.index(pa)?;
        if self.is_free(i) {
            return Err(FrameError::DoubleFree(pa));
        }
        self.set(i, true);
        self.free += 1;
        Ok(())
    }

    pub fn free_contiguous(&mut self, pa: u64, n: usize) -> Result<(), FrameError> {
        // Validate everything first so a bad call changes nothing.
        for k in 0..n {
            let a = pa + (k as u64) * PAGE_SIZE;
            if self.is_free(self.index(a)?) {
                return Err(FrameError::DoubleFree(a));
            }
        }
        for k in 0..n {
            self.free(pa + (k as u64) * PAGE_SIZE)?;
        }
        Ok(())
    }
}

impl FrameSource for FrameAllocator<'_> {
    fn alloc_frame(&mut self) -> Option<u64> {
        self.alloc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn alloc_over(frames: usize) -> (Vec<u64>, usize) {
        (vec![0u64; frames.div_ceil(64)], frames)
    }

    #[test]
    fn starts_empty_then_frees_ranges() {
        let (mut bm, n) = alloc_over(100);
        let mut a = FrameAllocator::new(&mut bm, 0x4000_0000, n).unwrap();
        assert_eq!(a.alloc(), None);
        a.add_free_range(0x4000_0800, 3 * PAGE_SIZE); // partial pages ignored
        assert_eq!(a.free_frames(), 2);
        a.add_free_range(0x4000_0000, 200 * PAGE_SIZE); // clipped to span
        assert_eq!(a.free_frames(), 100);
        a.reserve_range(0x4000_1001, 10); // touches one page
        assert_eq!(a.free_frames(), 99);
    }

    #[test]
    fn alloc_free_roundtrip_and_errors() {
        let (mut bm, n) = alloc_over(130);
        let mut a = FrameAllocator::new(&mut bm, 0x1000_0000, n).unwrap();
        a.add_free_range(0x1000_0000, n as u64 * PAGE_SIZE);
        let mut got = BTreeSet::new();
        while let Some(f) = a.alloc() {
            assert!(got.insert(f), "frame handed out twice");
            assert!(f % PAGE_SIZE == 0);
        }
        assert_eq!(got.len(), 130);
        let f = *got.iter().next().unwrap();
        assert_eq!(a.free(f), Ok(()));
        assert_eq!(a.free(f), Err(FrameError::DoubleFree(f)));
        assert_eq!(a.free(f + 1), Err(FrameError::Foreign(f + 1)));
        assert_eq!(a.free(0x2000_0000), Err(FrameError::Foreign(0x2000_0000)));
        assert_eq!(a.free(0x0fff_f000), Err(FrameError::Foreign(0x0fff_f000)));
    }

    #[test]
    fn contiguous_aligned_runs() {
        let (mut bm, n) = alloc_over(64);
        let mut a = FrameAllocator::new(&mut bm, 0x8000_1000, n).unwrap();
        a.add_free_range(0x8000_1000, 64 * PAGE_SIZE);
        a.reserve_range(0x8000_4000, PAGE_SIZE);
        // 16-frame alignment (64 KiB) relative to physical 0.
        let run = a.alloc_contiguous(8, 16).unwrap();
        assert_eq!(run % (16 * PAGE_SIZE), 0);
        for k in 0..8 {
            assert_eq!(a.free(run + k * PAGE_SIZE), Ok(()));
        }
        let run = a.alloc_contiguous(8, 16).unwrap();
        assert_eq!(a.free_contiguous(run, 8), Ok(()));
        assert_eq!(
            a.free_contiguous(run, 8),
            Err(FrameError::DoubleFree(run)),
            "second free must fail atomically"
        );
        assert_eq!(a.alloc_contiguous(64, 1), None, "one frame is reserved");
        assert_eq!(a.alloc_contiguous(0, 1), None);
    }

    #[test]
    fn rejects_bad_construction() {
        let mut bm = vec![0u64; 1];
        assert!(FrameAllocator::new(&mut bm, 0x1000, 65).is_none());
        assert!(FrameAllocator::new(&mut bm, 0x1001, 64).is_none());
        assert_eq!(bitmap_bytes(64 * PAGE_SIZE), 8);
        assert_eq!(bitmap_bytes(65 * PAGE_SIZE), 16);
    }

    proptest::proptest! {
        #[test]
        fn random_alloc_free_keeps_accounting(ops in proptest::collection::vec(0u8..3, 1..400)) {
            let (mut bm, n) = alloc_over(200);
            let mut a = FrameAllocator::new(&mut bm, 0, n).unwrap();
            a.add_free_range(0, 200 * PAGE_SIZE);
            let mut live = Vec::new();
            for op in ops {
                match op {
                    0 | 1 => if let Some(f) = a.alloc() { live.push(f) },
                    _ => if let Some(f) = live.pop() { a.free(f).unwrap() },
                }
                let set: BTreeSet<_> = live.iter().collect();
                proptest::prop_assert_eq!(set.len(), live.len());
                proptest::prop_assert_eq!(a.free_frames() + live.len(), 200);
            }
        }
    }
}
