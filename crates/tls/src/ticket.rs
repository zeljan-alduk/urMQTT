//! TLS 1.3 session-ticket keys (H2, ADR-054).
//!
//! The keys are random (the CSPRNG), never derived from anything in the
//! image and never written anywhere: a copy of the image or of the disk
//! cannot forge a ticket. The previous scheme derived the key from the
//! server key, which is inside every image.
//!
//! - A key is current for `interval` seconds of uptime, then previous for
//!   `interval` more, then dropped and zeroised. Tickets carry
//!   `lifetime = interval`, so every ticket outlives its use, never its key.
//! - Time is the monotonic uptime, not the wall clock: rotation works
//!   without a clock and cannot be moved by one.
//! - Ticket: `key id (4) || nonce (12) || ChaCha20-Poly1305(state)`, the
//!   key id is in the associated data. Ids are random, so a ticket from an
//!   earlier boot or another replica names no key here.
//! - A ticket that does not open is a quiet full handshake (rustls falls
//!   back), counted by reason in [`TicketKeys::stats`].
//! - One [`TicketKeys`] is shared by every core's server: a session may
//!   resume on any core.

use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use rustls::server::ProducesTickets;
use urmqtt_sync::sync::SpinLock;
use zeroize::Zeroize;

/// The production rotation interval (and ticket lifetime): 12 hours.
pub const INTERVAL_S: u64 = 12 * 3600;

const ID_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const AAD_LABEL: &[u8] = b"urmqtt ticket v2";
/// Ids of dropped keys remembered, to tell "expired" from "unknown".
const RETIRED_IDS: usize = 4;

/// Seconds since boot, monotonic.
pub type Uptime = fn() -> u64;

/// Why a ticket did not resume a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Its key was dropped: the ticket is older than its lifetime allows.
    Expired,
    /// No key here has its id: an earlier boot, another replica, a forgery.
    UnknownKey,
    /// The id is known but the ticket does not authenticate: tampered.
    Invalid,
    /// Too short to be a ticket.
    Malformed,
}

impl Refused {
    pub const ALL: [Self; 4] = [
        Self::Expired,
        Self::UnknownKey,
        Self::Invalid,
        Self::Malformed,
    ];

    /// The metric suffix (`tls.resume_refused.<reason>`).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::UnknownKey => "unknown_key",
            Self::Invalid => "invalid",
            Self::Malformed => "malformed",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Counters since boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TicketStats {
    pub issued: u64,
    pub opened: u64,
    pub rotations: u64,
    /// Tickets not issued because the CSPRNG failed.
    pub not_issued: u64,
    /// By [`Refused::ALL`] order.
    pub refused: [u64; 4],
}

#[derive(Default)]
struct Key {
    live: bool,
    id: [u8; ID_LEN],
    /// Uptime at which it became current.
    born: u64,
    key: [u8; 32],
}

impl Drop for Key {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Two fixed slots: a key is written into its slot once and zeroised there,
/// never moved (a move would leave a copy behind). "Current" is an index.
#[derive(Default)]
struct Keys {
    slots: [Key; 2],
    cur: usize,
    retired: [Option<[u8; ID_LEN]>; RETIRED_IDS],
    next_retired: usize,
}

/// The shared ticket keys and their counters.
pub struct TicketKeys {
    keys: SpinLock<Keys>,
    interval: u64,
    uptime: Uptime,
    issued: AtomicU64,
    opened: AtomicU64,
    rotations: AtomicU64,
    not_issued: AtomicU64,
    refused: [AtomicU64; 4],
}

impl fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the keys.
        f.debug_struct("TicketKeys")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Keys {
    fn prev(&self) -> usize {
        1 - self.cur
    }

    fn current(&self) -> Option<&Key> {
        self.slots.get(self.cur).filter(|k| k.live)
    }

    fn previous(&self) -> Option<&Key> {
        self.slots.get(self.prev()).filter(|k| k.live)
    }

    /// Zeroises slot `i` in place and remembers its id.
    fn retire(&mut self, i: usize) {
        let Some(k) = self.slots.get_mut(i) else {
            return;
        };
        if !k.live {
            return;
        }
        k.key.zeroize();
        k.live = false;
        let id = k.id;
        if let Some(r) = self.retired.get_mut(self.next_retired) {
            *r = Some(id);
        }
        self.next_retired = (self.next_retired + 1) % RETIRED_IDS;
    }

    /// Ages the keys to `now`: a key is current for one interval from its
    /// birth and previous for the next. Returns the keys moved or dropped.
    fn age(&mut self, now: u64, interval: u64) -> u64 {
        let mut moved = 0;
        let end = |k: &Key, n: u64| k.born.saturating_add(interval.saturating_mul(n));
        if self.previous().is_some_and(|p| now >= end(p, 2)) {
            self.retire(self.prev());
            moved += 1;
        }
        if self.current().is_some_and(|c| now >= end(c, 2)) {
            self.retire(self.cur);
            moved += 1;
        } else if self.current().is_some_and(|c| now >= end(c, 1)) {
            self.retire(self.prev());
            self.cur = self.prev();
            moved += 1;
        }
        moved
    }

    /// A new current key, born at `born`, filled in its slot by `rng`.
    fn create(&mut self, born: u64, rng: &mut dyn FnMut(&mut [u8]) -> bool) -> bool {
        let prev_id = self.previous().map(|p| p.id);
        let Some(k) = self.slots.get_mut(self.cur) else {
            return false;
        };
        k.born = born;
        k.live = true;
        if !(rng(&mut k.id) && rng(&mut k.key)) {
            self.retire(self.cur);
            return false;
        }
        if prev_id == Some(k.id) {
            // Two live keys never share an id.
            k.id[0] ^= 1;
        }
        true
    }
}

impl TicketKeys {
    /// Keys rotating every `interval` seconds of `uptime` (at least 1 s).
    pub fn new(interval: u64, uptime: Uptime) -> Self {
        Self {
            keys: SpinLock::new(Keys::default()),
            interval: interval.max(1),
            uptime,
            issued: AtomicU64::new(0),
            opened: AtomicU64::new(0),
            rotations: AtomicU64::new(0),
            not_issued: AtomicU64::new(0),
            refused: [const { AtomicU64::new(0) }; 4],
        }
    }

    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Relaxed loads: statistics.
    pub fn stats(&self) -> TicketStats {
        TicketStats {
            issued: self.issued.load(Ordering::Relaxed),
            opened: self.opened.load(Ordering::Relaxed),
            rotations: self.rotations.load(Ordering::Relaxed),
            not_issued: self.not_issued.load(Ordering::Relaxed),
            refused: self.refused.each_ref().map(|c| c.load(Ordering::Relaxed)),
        }
    }

    fn aged(&self, now: u64) -> urmqtt_sync::sync::SpinGuard<'_, Keys> {
        let mut keys = self.keys.lock();
        let moved = keys.age(now, self.interval);
        // Relaxed: statistics.
        self.rotations.fetch_add(moved, Ordering::Relaxed);
        keys
    }

    /// Seals `plain` at uptime `now`, drawing the key, its id and the nonce
    /// from `rng` (which returns `false` on failure: then no ticket).
    pub fn seal_at(
        &self,
        now: u64,
        rng: &mut dyn FnMut(&mut [u8]) -> bool,
        plain: &[u8],
    ) -> Option<Vec<u8>> {
        let mut keys = self.aged(now);
        if keys.current().is_none() {
            // Current from the end of the previous key's interval, or from
            // now after a long sleep: never back-dated past that.
            let born = keys
                .previous()
                .map_or(now, |p| p.born.saturating_add(self.interval));
            if !keys.create(born, rng) {
                self.not_issued.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        let cur = keys.current()?;
        let mut nonce = [0u8; NONCE_LEN];
        if !rng(&mut nonce) {
            self.not_issued.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&cur.key).ok()?;
        let mut body = Vec::with_capacity(ID_LEN + NONCE_LEN + plain.len() + TAG_LEN);
        body.extend_from_slice(plain);
        aead.encrypt_in_place((&nonce).into(), &aad(&cur.id), &mut body)
            .ok()?;
        let mut out = Vec::with_capacity(ID_LEN + NONCE_LEN + body.len());
        out.extend_from_slice(&cur.id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        self.issued.fetch_add(1, Ordering::Relaxed);
        Some(out)
    }

    /// Opens a ticket at uptime `now`.
    pub fn open_at(&self, now: u64, ticket: &[u8]) -> Result<Vec<u8>, Refused> {
        let r = self.open_inner(now, ticket);
        // Relaxed: statistics.
        match r {
            Ok(_) => self.opened.fetch_add(1, Ordering::Relaxed),
            Err(e) => self
                .refused
                .get(e.index())
                .map_or(0, |c| c.fetch_add(1, Ordering::Relaxed)),
        };
        r
    }

    fn open_inner(&self, now: u64, ticket: &[u8]) -> Result<Vec<u8>, Refused> {
        if ticket.len() < ID_LEN + NONCE_LEN + TAG_LEN {
            return Err(Refused::Malformed);
        }
        let (id, rest) = ticket.split_at(ID_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let keys = self.aged(now);
        let key = [keys.current(), keys.previous()]
            .into_iter()
            .flatten()
            .find(|k| k.id == id);
        let Some(key) = key else {
            let retired = keys.retired.iter().flatten().any(|r| r == id);
            return Err(if retired {
                Refused::Expired
            } else {
                Refused::UnknownKey
            });
        };
        let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key.key)
            .map_err(|_| Refused::Invalid)?;
        let mut body = sealed.to_vec();
        aead.decrypt_in_place(nonce.into(), &aad(&key.id), &mut body)
            .map_err(|_| Refused::Invalid)?;
        Ok(body)
    }

    /// How many keys are live at `now` (0, 1 or 2).
    pub fn live_keys_at(&self, now: u64) -> usize {
        let keys = self.aged(now);
        usize::from(keys.current().is_some()) + usize::from(keys.previous().is_some())
    }

    /// The raw key slots, live or not (tests: a retired slot holds zeros).
    #[cfg(test)]
    fn slot_bytes(&self) -> [(bool, [u8; 32]); 2] {
        let keys = self.keys.lock();
        keys.slots.each_ref().map(|k| (k.live, k.key))
    }
}

fn aad(id: &[u8; ID_LEN]) -> [u8; AAD_LABEL.len() + ID_LEN] {
    let mut a = [0u8; AAD_LABEL.len() + ID_LEN];
    let (l, r) = a.split_at_mut(AAD_LABEL.len());
    l.copy_from_slice(AAD_LABEL);
    r.copy_from_slice(id);
    a
}

/// rustls's view: the shared keys at the current uptime.
#[derive(Debug)]
pub(crate) struct Ticketer(pub(crate) alloc::sync::Arc<TicketKeys>);

impl ProducesTickets for Ticketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        u32::try_from(self.0.interval).unwrap_or(u32::MAX)
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let now = (self.0.uptime)();
        self.0
            .seal_at(now, &mut |b| crate::rng::fill_global(b).is_ok(), plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let now = (self.0.uptime)();
        self.0.open_at(now, cipher).ok()
    }
}

#[cfg(test)]
mod tests;
