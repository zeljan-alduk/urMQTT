//! Publisher back-pressure, the transport's side (NOW-13, ADR-269).
//!
//! The broker shard decides (`urmqtt_broker`'s `flow` module): it stops
//! parsing a publisher whose QoS 0 message had one recipient, and that one is
//! over its high-water mark. Here the decision becomes TCP flow control: the
//! publisher's receive window is closed (`TcpStack::set_recv_space(c, 0)`:
//! what was promised still arrives and is held by the broker, then the peer's
//! TCP stops) and opened again in one step (`TcpStack::reset_recv_space`).
//! A relayed publisher's window is on its transport core, which gets
//! `CoreMsg::Flow`. Shards that deliver a publisher's routed messages tell its
//! origin shard to how many sessions (`CoreMsg::Seen`, at most every
//! [`TELL_EVERY_MS`] per publisher), so a publisher with a consumer on another
//! shard is never paused for a local one; a shard whose one subscriber of it is
//! full asks the origin to pause it and later to resume it (`CoreMsg::Hold`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_tcp::TcpStack;

use crate::dataplane::{CoreMsg, Link, Tconn};

/// A shard repeats "I deliver this publisher's messages" this often at most
/// (the origin forgets it after `urmqtt_broker::flow::REMOTE_SEEN_MS`, 1 s).
const TELL_EVERY_MS: u64 = 250;

/// Receive windows closed and opened by this mechanism, all cores
/// (statistics; the pauses themselves are counted by the shards).
pub static WINDOWS_CLOSED: AtomicU64 = AtomicU64::new(0);

/// "No origin" in `CoreMsg::Route`.
pub const NO_ORIGIN: u32 = u32::MAX;

/// Whether the configuration asks for it at all (`limits.publisher_backpressure`).
pub fn enabled() -> bool {
    urmqtt_config::CONFIG.limits.publisher_backpressure
}

/// One core's pending window changes and its "seen" notes to other shards.
pub struct FlowLink {
    /// (TCP connection, its relay/generation tag, close).
    tcp: Vec<(u32, Tconn, bool)>,
    /// (origin shard, publisher) -> when it was last told.
    told: BTreeMap<(u16, u32), u64>,
    pruned_ms: u64,
}

impl FlowLink {
    pub const fn new() -> Self {
        Self {
            tcp: Vec::new(),
            told: BTreeMap::new(),
            pruned_ms: 0,
        }
    }

    /// Queues a window change for this core's TCP connection `c` (tagged
    /// `tconn`, so a reused slot is never touched).
    pub fn window(&mut self, c: u32, tconn: Tconn, closed: bool) {
        self.tcp.push((c, tconn, closed));
    }

    /// Applies the queued window changes to the connections `live` confirms.
    pub fn apply(&mut self, tcp: &mut TcpStack, live: impl Fn(u32, Tconn) -> bool) {
        for (c, tconn, closed) in self.tcp.drain(..) {
            if !live(c, tconn) {
                continue;
            }
            if closed {
                // Relaxed: statistics.
                WINDOWS_CLOSED.fetch_add(1, Ordering::Relaxed);
                tcp.set_recv_space(c, 0);
            } else {
                tcp.reset_recv_space(c);
            }
        }
    }

    /// A message routed from shard `peer` (publisher `origin` there) went to
    /// `n` sessions here: tell `peer`, rate-limited.
    pub fn delivered(&mut self, peer: usize, origin: u32, n: usize, link: &mut Link, now_ms: u64) {
        if n == 0 || origin == NO_ORIGIN || !enabled() {
            return;
        }
        let key = (peer as u16, origin);
        let due = self
            .told
            .get(&key)
            .is_none_or(|&t| now_ms.saturating_sub(t) >= TELL_EVERY_MS);
        if !due {
            return;
        }
        self.told.insert(key, now_ms);
        link.send(
            peer,
            CoreMsg::Seen {
                conn: origin,
                n: u32::try_from(n).unwrap_or(u32::MAX),
            },
        );
        if now_ms.saturating_sub(self.pruned_ms) >= 5_000 {
            self.pruned_ms = now_ms;
            self.told
                .retain(|_, t| now_ms.saturating_sub(*t) < TELL_EVERY_MS * 8);
        }
    }

    /// Memory left by a past peak.
    pub fn shrink(&mut self) {
        if self.tcp.is_empty() {
            self.tcp.shrink_to_fit();
        }
    }
}
