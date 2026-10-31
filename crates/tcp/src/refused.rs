//! Memory of flows the application refused a moment ago (PERF, ADR-080).
//!
//! SYN cookies keep no state, so a segment that follows a refused final ACK
//! (a client sends its ClientHello right behind the ACK) carries a valid
//! cookie again. Without a memory the stack would ask the application a
//! second time, and an application with a free slot by then would admit a
//! connection whose peer already received the RST: crypto work and a
//! handshake slot spent on a socket that is closed. The memory is a small
//! direct-mapped table of 32-bit tags; a collision costs one dropped
//! segment, which TCP retransmits.

use alloc::vec;
use alloc::vec::Vec;

use crate::table::{Key, mix};

/// Entries; a power of two.
const SLOTS: usize = 512;
/// How long a refusal is remembered.
const TTL_MS: u32 = 1_000;
/// RSTs a remembered flow may still provoke (the first one was sent at the
/// refusal; a repeat covers a lost RST without opening an amplifier).
const MAX_REPEAT_RST: u8 = 1;

#[derive(Clone, Copy, Default)]
struct Entry {
    tag: u32,
    at_ms: u32,
    /// RSTs sent on top of the first one.
    rsts: u8,
    used: bool,
}

/// What to do with a segment of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not remembered: process normally.
    Unknown,
    /// Remembered: send one more RST.
    Reset,
    /// Remembered: drop silently.
    Drop,
}

pub struct RefusedFlows {
    slots: Vec<Entry>,
    seed: u64,
}

impl RefusedFlows {
    pub fn new(seed: u64) -> Self {
        Self {
            slots: vec![Entry::default(); SLOTS],
            seed,
        }
    }

    fn locate(&self, key: &Key) -> (usize, u32) {
        let h = mix(key, self.seed ^ 0x5bd1_e995_5bd1_e995);
        ((h as usize) & (SLOTS - 1), (h >> 32) as u32)
    }

    /// Remembers that `key` was refused at `now_ms`.
    pub fn note(&mut self, key: &Key, now_ms: u64) {
        let (i, tag) = self.locate(key);
        if let Some(e) = self.slots.get_mut(i) {
            *e = Entry {
                tag,
                at_ms: now_ms as u32,
                rsts: 0,
                used: true,
            };
        }
    }

    /// Looks `key` up for a segment arriving at `now_ms`.
    pub fn check(&mut self, key: &Key, now_ms: u64) -> Verdict {
        let (i, tag) = self.locate(key);
        let Some(e) = self.slots.get_mut(i) else {
            return Verdict::Unknown;
        };
        if !e.used || e.tag != tag {
            return Verdict::Unknown;
        }
        if (now_ms as u32).wrapping_sub(e.at_ms) >= TTL_MS {
            e.used = false;
            return Verdict::Unknown;
        }
        if e.rsts < MAX_REPEAT_RST {
            e.rsts += 1;
            Verdict::Reset
        } else {
            Verdict::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> Key {
        Key {
            addr: [10, 0, 0, 1],
            rport: port,
            lport: 8883,
        }
    }

    #[test]
    fn unknown_until_noted() {
        let mut r = RefusedFlows::new(7);
        assert_eq!(r.check(&key(1000), 0), Verdict::Unknown);
        r.note(&key(1000), 0);
        assert_ne!(r.check(&key(1000), 1), Verdict::Unknown);
        assert_eq!(r.check(&key(1001), 1), Verdict::Unknown);
    }

    #[test]
    fn one_repeat_reset_then_drops() {
        let mut r = RefusedFlows::new(7);
        r.note(&key(1000), 0);
        assert_eq!(r.check(&key(1000), 1), Verdict::Reset);
        assert_eq!(r.check(&key(1000), 2), Verdict::Drop);
        assert_eq!(r.check(&key(1000), 3), Verdict::Drop);
    }

    #[test]
    fn forgotten_after_the_ttl() {
        let mut r = RefusedFlows::new(7);
        r.note(&key(1000), 100);
        let ttl = u64::from(TTL_MS);
        assert_eq!(r.check(&key(1000), 100 + ttl - 1), Verdict::Reset);
        assert_eq!(r.check(&key(1000), 100 + ttl), Verdict::Unknown);
        // And stays forgotten.
        assert_eq!(r.check(&key(1000), 100 + ttl + 1), Verdict::Unknown);
    }

    #[test]
    fn survives_clock_wrap() {
        let mut r = RefusedFlows::new(7);
        let t = u64::from(u32::MAX) - 10;
        r.note(&key(1000), t);
        assert_eq!(r.check(&key(1000), t + 20), Verdict::Reset);
    }

    #[test]
    fn renoting_resets_the_budget() {
        let mut r = RefusedFlows::new(7);
        r.note(&key(1000), 0);
        let _ = r.check(&key(1000), 1);
        r.note(&key(1000), 2);
        assert_eq!(r.check(&key(1000), 3), Verdict::Reset);
    }
}
