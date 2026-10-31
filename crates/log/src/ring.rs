//! One core's log ring (ADR-090): single producer (the core itself, IRQs
//! masked), single consumer (whoever drains), fixed slots, no allocation.
//!
//! The producer never waits: if the ring is full or the producer side is
//! somehow entered twice, the line is dropped and counted. Both sides claim
//! their end with a try-flag, so even a misuse (two threads on one ring in
//! a test, an interrupt that was not masked) cannot corrupt a slot; it only
//! loses a line, counted. Slots are never copied on the way in or out: the
//! producer formats into the free slot, the consumer reads the head slot in
//! place.
#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::Record;

/// The rate limiter's state (token bucket per core), owned by the
/// producer side.
pub struct Limiter {
    pub tokens: u64,
    pub refilled_ns: u64,
    /// Lines the limiter refused since the last note.
    pub suppressed: u64,
    /// `tokens` holds the burst after the first use. The all-zero state is
    /// the initial one, so the rings live in `.bss`, not in the image.
    pub primed: bool,
}

impl Limiter {
    pub const fn new() -> Self {
        Self {
            tokens: 0,
            refilled_ns: 0,
            suppressed: 0,
            primed: false,
        }
    }
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Ring<const N: usize> {
    slots: [UnsafeCell<Record>; N],
    /// Next slot to read; written by the consumer only.
    head: AtomicUsize,
    /// Next slot to write; written by the producer only.
    tail: AtomicUsize,
    /// The producer end is in use.
    pbusy: AtomicBool,
    /// The consumer end is in use.
    cbusy: AtomicBool,
    /// Lines dropped (ring full, or producer end busy) and not yet reported.
    dropped: AtomicU64,
    prod: UnsafeCell<Limiter>,
}

// SAFETY: a slot is written only by the holder of `pbusy`, and only while it
// lies outside head..tail; it is read only by the holder of `cbusy`, and only
// while it lies inside head..tail (published by the Release store of `tail`,
// handed back by the Release store of `head`). `prod` is touched only by the
// holder of `pbusy`.
unsafe impl<const N: usize> Sync for Ring<N> {}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        Self {
            slots: [const { UnsafeCell::new(Record::EMPTY) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            pbusy: AtomicBool::new(false),
            cbusy: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            prod: UnsafeCell::new(Limiter::new()),
        }
    }

    /// Lines queued (a snapshot).
    pub fn len(&self) -> usize {
        // Acquire on both: a consistent-enough snapshot.
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Takes (and zeroes) the count of lines dropped since the last call.
    pub fn take_dropped(&self) -> u64 {
        // Relaxed: a counter; the note it produces is for the operator.
        self.dropped.swap(0, Ordering::Relaxed)
    }

    pub fn has_dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed) > 0
    }

    /// Counts a line that never reached the ring.
    pub fn count_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Runs `f` with the producer end, or returns `None` (without waiting)
    /// if it is in use. `f` gets the rate limiter state and a way to
    /// enqueue; nothing in it may block.
    pub fn produce<R>(&self, f: impl FnOnce(&mut Limiter, &mut Pusher<'_, N>) -> R) -> Option<R> {
        // Acquire: pairs with the Release below; the previous holder's
        // writes to `prod` are visible.
        if self.pbusy.swap(true, Ordering::Acquire) {
            return None;
        }
        // SAFETY: `pbusy` was false and is now ours until released below.
        let prod = unsafe { &mut *self.prod.get() };
        let mut pusher = Pusher { ring: self };
        let r = f(prod, &mut pusher);
        // Release: hands `prod` over.
        self.pbusy.store(false, Ordering::Release);
        Some(r)
    }

    /// The timestamp of the oldest queued line (the consumer's merge key),
    /// `None` if empty or the consumer end is in use.
    pub fn head_ns(&self) -> Option<u64> {
        self.consume(|r| r.ns)
    }

    /// Runs `f` on the oldest queued line without removing it.
    fn consume<R>(&self, f: impl FnOnce(&Record) -> R) -> Option<R> {
        if self.cbusy.swap(true, Ordering::Acquire) {
            return None;
        }
        let head = self.head.load(Ordering::Relaxed);
        // Acquire: pairs with the producer's Release of `tail`.
        let tail = self.tail.load(Ordering::Acquire);
        let out = if head == tail {
            None
        } else {
            // SAFETY: the slot at `head` is published and stays untouched by
            // the producer until `head` moves past it; we hold `cbusy`.
            self.slots.get(head % N).map(|c| f(unsafe { &*c.get() }))
        };
        self.cbusy.store(false, Ordering::Release);
        out
    }

    /// Removes the oldest line, handing it to `f` first. `None` if empty.
    pub fn pop<R>(&self, f: impl FnOnce(&Record) -> R) -> Option<R> {
        if self.cbusy.swap(true, Ordering::Acquire) {
            return None;
        }
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let out = if head == tail {
            None
        } else {
            // SAFETY: as in `consume`.
            let r = self.slots.get(head % N).map(|c| f(unsafe { &*c.get() }));
            // Release: the producer may reuse the slot after this.
            self.head.store(head.wrapping_add(1), Ordering::Release);
            r
        };
        self.cbusy.store(false, Ordering::Release);
        out
    }
}

/// The enqueue operation, valid inside [`Ring::produce`].
pub struct Pusher<'a, const N: usize> {
    ring: &'a Ring<N>,
}

impl<const N: usize> Pusher<'_, N> {
    /// Formats a line into the next free slot (`fill` writes it), or drops
    /// it, counted, if more than `limit` lines are queued. Returns whether
    /// it was queued.
    pub fn push(&mut self, limit: usize, count: bool, fill: impl FnOnce(&mut Record)) -> bool {
        let r = self.ring;
        // Relaxed: only this side writes `tail`.
        let tail = r.tail.load(Ordering::Relaxed);
        // Acquire: pairs with the consumer's Release of `head`.
        let head = r.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= limit.min(N) {
            if count {
                r.count_dropped();
            }
            return false;
        }
        if let Some(cell) = r.slots.get(tail % N) {
            // SAFETY: the slot is free (outside head..tail) and the caller
            // holds `pbusy` (this type exists only inside `produce`).
            let slot = unsafe { &mut *cell.get() };
            *slot = Record::EMPTY;
            fill(slot);
        }
        // Release: publishes the slot to the consumer.
        r.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }
}
