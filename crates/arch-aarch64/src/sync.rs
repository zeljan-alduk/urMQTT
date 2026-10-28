//! Minimal ticket spinlock for boot-time and cold-path shared state.
//!
//! The data path is shared-nothing and never takes this lock; it protects
//! things like the global log sinks before per-CPU rings exist.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct SpinLock<T> {
    next: AtomicU32,
    serving: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: access to `value` is serialized by the ticket protocol, so sharing
// the lock between cores is sound whenever `T` itself may be sent across them.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: moving the lock moves the owned `T`; requires `T: Send`.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        // Relaxed: taking a ticket only needs atomicity; ordering with the
        // protected data is established by the Acquire load below.
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        // Acquire: pairs with the Release store in `drop`, making the previous
        // holder's writes to `value` visible before we touch it.
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }

    /// Takes the lock only if it is free right now.
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        // Relaxed: just a snapshot to decide whether to try.
        let serving = self.serving.load(Ordering::Relaxed);
        // Acquire on success: same pairing as in `lock`. Relaxed on failure:
        // nothing was acquired.
        self.next
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .ok()
            .map(|_| SpinGuard { lock: self })
    }
}

pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves exclusive ownership of the ticket.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves exclusive ownership of the ticket.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // Release: publishes our writes to `value` to the next ticket holder.
        // Only the holder writes `serving`, so a plain add is race-free.
        let s = self.lock.serving.load(Ordering::Relaxed);
        self.lock
            .serving
            .store(s.wrapping_add(1), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn mutual_exclusion_across_threads() {
        let lock = Arc::new(SpinLock::new(0u64));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let l = Arc::clone(&lock);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        *l.lock() += 1;
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*lock.lock(), 80_000);
    }

    #[test]
    fn try_lock_fails_while_held() {
        let lock = SpinLock::new(1);
        let g = lock.lock();
        assert!(lock.try_lock().is_none());
        drop(g);
        assert_eq!(*lock.try_lock().unwrap(), 1);
    }
}
