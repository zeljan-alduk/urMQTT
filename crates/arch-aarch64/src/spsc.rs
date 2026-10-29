//! Bounded lock-free single-producer/single-consumer ring (PROMPT §7.2):
//! the only way cores hand work to each other (DB requests and responses
//! now, cross-core fan-out in M13).
//!
//! Memory ordering (AArch64 is weakly ordered):
//! - The producer writes the slot, then publishes it with a `Release` store
//!   of `tail`. The consumer's `Acquire` load of `tail` therefore sees the
//!   slot contents.
//! - The consumer moves the value out, then frees the slot with a `Release`
//!   store of `head`. The producer's `Acquire` load of `head` therefore
//!   never overwrites a slot that is still being read.
//! - Each side reads its own index with `Relaxed` (only it writes it).
//!
//! The single-producer/single-consumer contract is enforced by handing out
//! one [`Producer`] and one [`Consumer`] per ring.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Spsc<T, const N: usize> {
    slots: [UnsafeCell<MaybeUninit<T>>; N],
    /// Next slot to read; written only by the consumer.
    head: AtomicUsize,
    /// Next slot to write; written only by the producer.
    tail: AtomicUsize,
    producer_taken: AtomicBool,
    consumer_taken: AtomicBool,
}

// SAFETY: a slot is accessed by exactly one side at a time, as arbitrated
// by `head`/`tail` with the orderings above; values move between threads,
// so `T: Send` is required.
unsafe impl<T: Send, const N: usize> Sync for Spsc<T, N> {}

impl<T, const N: usize> Spsc<T, N> {
    const CHECK: () = assert!(
        N.is_power_of_two() && N >= 2,
        "capacity must be a power of two"
    );

    pub const fn new() -> Self {
        let () = Self::CHECK;
        Self {
            slots: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            producer_taken: AtomicBool::new(false),
            consumer_taken: AtomicBool::new(false),
        }
    }

    /// The producer end, once.
    pub fn producer(&self) -> Option<Producer<'_, T, N>> {
        // AcqRel: the winner owns the producer side from here on.
        (!self.producer_taken.swap(true, Ordering::AcqRel)).then_some(Producer { ring: self })
    }

    /// The consumer end, once.
    pub fn consumer(&self) -> Option<Consumer<'_, T, N>> {
        // AcqRel: as for `producer`.
        (!self.consumer_taken.swap(true, Ordering::AcqRel)).then_some(Consumer { ring: self })
    }

    /// Entries currently queued (a snapshot; exact only from either end).
    pub fn len(&self) -> usize {
        // Acquire on both: a consistent-enough snapshot for statistics.
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    fn slot(&self, index: usize) -> *mut MaybeUninit<T> {
        // `N` is a power of two, so masking is the modulo; the index is in
        // bounds by construction.
        let cell = self.slots.get(index & (N - 1));
        cell.map_or(core::ptr::null_mut(), UnsafeCell::get)
    }
}

impl<T, const N: usize> Default for Spsc<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for Spsc<T, N> {
    fn drop(&mut self) {
        // `&mut self`: no other side exists any more.
        while let Some(v) = (Consumer { ring: &*self }).pop() {
            drop(v);
        }
    }
}

pub struct Producer<'a, T, const N: usize> {
    ring: &'a Spsc<T, N>,
}

// SAFETY: the handle may move to the producing core; `T: Send`.
unsafe impl<T: Send, const N: usize> Send for Producer<'_, T, N> {}

impl<T, const N: usize> Producer<'_, T, N> {
    /// Enqueues `v`, or gives it back if the ring is full.
    pub fn push(&mut self, v: T) -> Result<(), T> {
        let r = self.ring;
        // Relaxed: only this side writes `tail`.
        let tail = r.tail.load(Ordering::Relaxed);
        // Acquire: pairs with the consumer's Release of `head`, so the slot
        // we are about to reuse has been fully read.
        let head = r.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= N {
            return Err(v);
        }
        // SAFETY: the slot at `tail` is free (checked above) and only the
        // producer writes free slots.
        unsafe { (*r.slot(tail)).write(v) };
        // Release: publishes the slot contents to the consumer.
        r.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    pub fn is_full(&self) -> bool {
        self.ring.len() >= N
    }
}

pub struct Consumer<'a, T, const N: usize> {
    ring: &'a Spsc<T, N>,
}

// SAFETY: the handle may move to the consuming core; `T: Send`.
unsafe impl<T: Send, const N: usize> Send for Consumer<'_, T, N> {}

impl<T, const N: usize> Consumer<'_, T, N> {
    pub fn pop(&mut self) -> Option<T> {
        let r = self.ring;
        // Relaxed: only this side writes `head`.
        let head = r.head.load(Ordering::Relaxed);
        // Acquire: pairs with the producer's Release of `tail`, so the slot
        // contents are visible.
        let tail = r.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: the slot at `head` was published by the producer and is
        // read exactly once before `head` moves past it.
        let slot = unsafe { core::ptr::read(r.slot(head)) };
        // SAFETY: published slots hold an initialised value (written by
        // `push` before the Release of `tail`).
        let v = unsafe { slot.assume_init() };
        // Release: the slot may be reused by the producer after this.
        r.head.store(head.wrapping_add(1), Ordering::Release);
        Some(v)
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn fifo_full_and_single_handles() {
        let r: Spsc<u32, 4> = Spsc::new();
        let mut p = r.producer().unwrap();
        let mut c = r.consumer().unwrap();
        assert!(r.producer().is_none() && r.consumer().is_none());
        for i in 0..4 {
            p.push(i).unwrap();
        }
        assert_eq!(p.push(9), Err(9));
        assert!(p.is_full());
        assert_eq!(c.pop(), Some(0));
        p.push(4).unwrap();
        assert_eq!(
            (1..=4).map(|_| c.pop().unwrap()).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(c.pop(), None);
    }

    #[test]
    fn drops_unconsumed_values() {
        let v = Arc::new(());
        {
            let r: Spsc<Arc<()>, 8> = Spsc::new();
            let mut p = r.producer().unwrap();
            for _ in 0..5 {
                p.push(v.clone()).unwrap();
            }
            assert_eq!(Arc::strong_count(&v), 6);
        }
        assert_eq!(Arc::strong_count(&v), 1);
    }

    #[test]
    fn two_threads_transfer_everything_in_order() {
        static R: Spsc<Box<u64>, 64> = Spsc::new();
        const COUNT: u64 = 200_000;
        let t = std::thread::spawn(|| {
            let mut p = R.producer().unwrap();
            for i in 0..COUNT {
                let mut v = Box::new(i);
                loop {
                    match p.push(v) {
                        Ok(()) => break,
                        Err(back) => {
                            v = back;
                            std::hint::spin_loop();
                        }
                    }
                }
            }
        });
        let mut c = R.consumer().unwrap();
        let mut next = 0;
        while next < COUNT {
            if let Some(v) = c.pop() {
                assert_eq!(*v, next);
                next += 1;
            }
        }
        t.join().unwrap();
        assert!(c.pop().is_none());
    }
}
