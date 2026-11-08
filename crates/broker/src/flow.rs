//! Publisher back-pressure (NOW-13, ADR-269).
//!
//! When a QoS 0 message has exactly one recipient on this shard, no other
//! shard has delivered the publisher's messages lately, and the recipient's
//! output buffer is over the high-water mark, the publisher is **paused**:
//! the broker stops parsing its input after the packet that caused it. The
//! bytes that still arrive are held unparsed, and the transport closes the
//! connection's TCP receive window ([`Broker::drain_flow`]), so the
//! publisher's own TCP stops sending instead of the broker reading and
//! dropping. Anything else (fan-out to two or more, QoS 1 deliveries, a
//! publisher in cool-down) keeps the old rule: QoS 0 to a full buffer is
//! dropped and counted.
//!
//! A pause ends when the recipient's buffer is below the low-water mark, the
//! recipient is gone or closing, or [`PAUSE_MAX_MS`] passed. The held bytes
//! are then parsed in slices ([`DRAIN_SLICE`] per [`Broker::poll_flow`]); the
//! window opens again once nothing complete is left in them. A pause that
//! ran out puts the publisher in cool-down for [`COOLDOWN_MS`]: it is read
//! and its messages dropped as before, whatever its recipient does.
//!
//! No cycle of pauses can form: a publisher is paused only for a recipient
//! whose own input is not held (and never for itself). Suppose a cycle of
//! "P paused for R" edges existed; take the edge created last, P -> R. R is
//! on the cycle, so it has an edge R -> S, created earlier and still there:
//! R was paused when P -> R was created, which the rule forbids. Every other
//! wait (a client that stops reading while its own write blocks) is cut by
//! the time bound.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use urmqtt_mqtt::QoS;

use crate::{Broker, ConnId, SessionId};

/// The policy (`limits.publisher_backpressure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherBackpressure {
    /// Never pause a publisher: QoS 0 to a full buffer is dropped.
    Off,
    /// Pause a publisher whose message has one recipient, and it is full.
    Single,
}

/// Input of the connection is held: it is not parsed until the pause ends.
pub(crate) const PAUSED: u8 = 1;
/// The pause ended; the held bytes are being parsed, the window is still
/// closed.
pub(crate) const DRAINING: u8 = 2;

/// Longest pause; then the publisher is read again, in cool-down.
pub const PAUSE_MAX_MS: u64 = 500;
/// After a pause that ran out, the publisher is not paused for this long.
pub const COOLDOWN_MS: u64 = 2_000;
/// A publisher whose messages another shard delivered within this is never
/// paused: it has more than one consumer, or one we cannot see.
pub const REMOTE_SEEN_MS: u64 = 1_000;
/// The `remote_seen` mark of a publisher in its first [`REMOTE_SEEN_MS`].
const LEARNING: u16 = u16::MAX;
/// A subscriber whose publisher on another shard was asked to pause takes
/// what was already on its way up to this much beyond `max_outbound_bytes`
/// (the request needs a message on the mesh; meanwhile the publisher's shard
/// routes on) ...
pub const OVERSHOOT: usize = 256 * 1024;
/// ... and all such subscribers of a shard together this much.
pub const OVERSHOOT_TOTAL: usize = 4 << 20;
/// Held bytes parsed per connection per [`Broker::poll_flow`].
pub const DRAIN_SLICE: usize = 32 * 1024;
/// Bytes a shard holds unparsed for all its paused publishers; beyond it, no
/// new pause (the transport's window bounds each one, this bounds them all).
pub const HOLD_TOTAL: usize = 16 << 20;
/// Bytes one connection may hold beyond its packet limit before it is put
/// in cool-down (a transport that did not close its window).
pub const HOLD_CONN: usize = 2 << 20;

/// Why [`Broker::parse`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// What is left is not a complete packet.
    Incomplete,
    /// The byte budget is used up; complete packets may be left.
    Budget,
    /// The connection got paused.
    Paused,
    /// The connection is gone or closing.
    Gone,
}

/// The sessions a routed message was for.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Recipients {
    pub n: usize,
    /// The one session and the QoS it got, when there was exactly one.
    pub one: Option<(SessionId, QoS)>,
}

/// Counters of the back-pressure (`$SYS/broker/messages/backpressure/...`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowStats {
    /// Pauses started.
    pub pauses: u64,
    /// Milliseconds publishers spent paused, summed over the ended pauses.
    pub paused_ms: u64,
    /// Pauses that ran out ([`PAUSE_MAX_MS`]).
    pub timeouts: u64,
    /// Publishers paused or draining now.
    pub holding: u64,
}

/// What a paused publisher waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recipient {
    /// A connection of this shard.
    Local(ConnId),
    /// The single subscriber on shard N, which says when it drained.
    Remote(u16),
}

struct Paused {
    publisher: ConnId,
    recipient: Recipient,
    since_ms: u64,
}

/// This shard holds a subscriber for a publisher of another shard, which it
/// asked to pause that publisher.
struct Wait {
    shard: u16,
    publisher: ConnId,
    recipient: ConnId,
    since_ms: u64,
}

#[derive(Default)]
pub(crate) struct Flow {
    paused: Vec<Paused>,
    draining: Vec<ConnId>,
    /// Publisher -> end of its cool-down.
    cooldown: BTreeMap<ConnId, u64>,
    /// Publisher -> the shards that said they delivered its messages:
    /// (shard, when, to how many sessions).
    remote_seen: BTreeMap<ConnId, Vec<(u16, u64, u32)>>,
    /// Window changes for the transport: (connection, closed).
    events: Vec<(ConnId, bool)>,
    /// Subscribers here that other shards' publishers wait for.
    waits: Vec<Wait>,
    /// For the other shards: (shard, its publisher, pause or resume).
    remote_events: Vec<(u16, ConnId, bool)>,
    stats: FlowStats,
}

impl Broker {
    /// Bytes held unparsed now, all connections.
    fn held_total(&self) -> usize {
        let len = |c: &ConnId| self.conns.get(*c).map_or(0, |k| k.inbuf.len());
        self.flow
            .paused
            .iter()
            .map(|p| len(&p.publisher))
            .sum::<usize>()
            + self.flow.draining.iter().map(len).sum::<usize>()
    }

    /// A message of publisher `c` was routed to `to`: pause `c` if that
    /// was its only recipient and it is over the high-water mark.
    pub(crate) fn after_publish(&mut self, c: ConnId, to: Recipients, now_ms: u64) {
        if self.cfg.publisher_backpressure == PublisherBackpressure::Off {
            return;
        }
        if let Some(k) = self.conns.get_mut(c) {
            k.last_local = u8::try_from(to.n).unwrap_or(u8::MAX - 1);
        }
        let Some(r) = self.single_full(to) else {
            return;
        };
        if r == c {
            return;
        }
        // Another shard delivers it too: more than one consumer.
        if self.cfg.fanout && (self.learning(c, now_ms) || self.seen_elsewhere(c, None, now_ms)) {
            return;
        }
        self.pause(c, Recipient::Local(r), now_ms);
    }

    /// The connection of the one session `to` names, when the delivery was
    /// QoS 0 (QoS 1 has its window and queue, ADR-269 point 3) and that
    /// connection is open, its own input not held, and its output at or above
    /// the high-water mark.
    fn single_full(&self, to: Recipients) -> Option<ConnId> {
        let (sid, qos) = to.one.filter(|_| to.n == 1)?;
        if qos != QoS::AtMostOnce {
            return None;
        }
        let r = self.sessions.get(sid)?.conn()?;
        let high = self.cfg.max_outbound_bytes / 2;
        self.conns
            .get(r)
            .is_some_and(|k| k.close.is_none() && k.flow == 0 && k.outbuf.len() >= high)
            .then_some(r)
    }

    /// With several shards, a publisher is first watched for [`REMOTE_SEEN_MS`]
    /// before it can be paused: the other shards' notes about it need a route
    /// and a message back. Starts that period at `c`'s first full recipient
    /// and says whether it is still on.
    fn learning(&mut self, c: ConnId, now_ms: u64) -> bool {
        match self.flow.remote_seen.get(&c) {
            Some(v) => v
                .iter()
                .any(|&(s, at, _)| s == LEARNING && now_ms.saturating_sub(at) < REMOTE_SEEN_MS),
            None => {
                self.flow
                    .remote_seen
                    .insert(c, alloc::vec![(LEARNING, now_ms, 0)]);
                true
            }
        }
    }

    /// Did a shard other than `except` (or `except` itself, for more than one
    /// session) deliver `c`'s messages within [`REMOTE_SEEN_MS`]?
    fn seen_elsewhere(&self, c: ConnId, except: Option<u16>, now_ms: u64) -> bool {
        self.flow.remote_seen.get(&c).is_some_and(|v| {
            v.iter().any(|&(shard, at, n)| {
                shard != LEARNING
                    && now_ms.saturating_sub(at) < REMOTE_SEEN_MS
                    && (Some(shard) != except || n > 1)
            })
        })
    }

    /// Pauses publisher `c` for `recipient`, unless it is already paused, in
    /// cool-down, or this shard holds too much.
    fn pause(&mut self, c: ConnId, recipient: Recipient, now_ms: u64) {
        if !self
            .conns
            .get(c)
            .is_some_and(|k| k.flow & PAUSED == 0 && k.close.is_none())
        {
            return;
        }
        match self.flow.cooldown.get(&c) {
            Some(&until) if now_ms < until => return,
            Some(_) => {
                self.flow.cooldown.remove(&c);
            }
            None => {}
        }
        if self.held_total() >= HOLD_TOTAL {
            return;
        }
        let Some(k) = self.conns.get_mut(c) else {
            return;
        };
        let was = k.flow;
        k.flow = PAUSED;
        if was & DRAINING != 0 {
            // The window is still closed: no event.
            self.flow.draining.retain(|&x| x != c);
        } else {
            self.flow.events.push((c, true));
        }
        self.flow.paused.push(Paused {
            publisher: c,
            recipient,
            since_ms: now_ms,
        });
        self.flow.stats.pauses += 1;
    }

    /// A message of publisher `origin.1` on shard `origin.0` went to `to`
    /// here: if that is one full subscriber, ask the origin to pause it.
    pub(crate) fn remote_single(&mut self, origin: (u16, ConnId), to: Recipients, now_ms: u64) {
        if self.cfg.publisher_backpressure == PublisherBackpressure::Off {
            return;
        }
        let Some(r) = self.single_full(to) else {
            return;
        };
        let (shard, publisher) = origin;
        if self
            .flow
            .waits
            .iter()
            .any(|w| w.shard == shard && w.publisher == publisher)
        {
            return;
        }
        self.flow.waits.push(Wait {
            shard,
            publisher,
            recipient: r,
            since_ms: now_ms,
        });
        self.flow.remote_events.push((shard, publisher, true));
    }

    /// The connection that may take a message of `origin` beyond its buffer,
    /// and up to which length: the subscriber of a wait for that publisher,
    /// within [`OVERSHOOT`] and the shard's [`OVERSHOOT_TOTAL`].
    pub(crate) fn overshoot_for(&self, origin: (u16, ConnId)) -> Option<(ConnId, usize)> {
        if self.flow.waits.is_empty() {
            return None;
        }
        let max_out = self.cfg.max_outbound_bytes;
        let over = |c: ConnId| {
            self.conns
                .get(c)
                .map_or(0, |k| k.outbuf.len().saturating_sub(max_out))
        };
        let w = self
            .flow
            .waits
            .iter()
            .find(|w| (w.shard, w.publisher) == origin)?;
        let total: usize = self.flow.waits.iter().map(|w| over(w.recipient)).sum();
        (total < OVERSHOOT_TOTAL).then_some((w.recipient, max_out + OVERSHOOT))
    }

    /// Shard `shard` asks to pause publisher `c`: its message went there to
    /// one subscriber, which is full. Done if no other shard (nor this one)
    /// delivers `c`'s messages.
    pub fn remote_full(&mut self, c: ConnId, shard: u16, now_ms: u64) {
        if self.cfg.publisher_backpressure == PublisherBackpressure::Off
            || !self.conns.get(c).is_some_and(|k| k.last_local == 0)
            || self.learning(c, now_ms)
            || self.seen_elsewhere(c, Some(shard), now_ms)
        {
            return;
        }
        self.pause(c, Recipient::Remote(shard), now_ms);
    }

    /// Shard `shard` says the subscriber publisher `c` waited for drained (or
    /// left).
    pub fn remote_drained(&mut self, c: ConnId, shard: u16, now_ms: u64) {
        let waiting = self
            .flow
            .paused
            .iter()
            .any(|p| p.publisher == c && p.recipient == Recipient::Remote(shard));
        if waiting {
            self.end_pause(c, now_ms, false);
        }
    }

    /// Takes the requests for the other shards since the last call: (shard,
    /// its publisher, `true` to pause it, `false` to resume it).
    pub fn drain_remote_flow(&mut self, out: &mut Vec<(u16, ConnId, bool)>) {
        out.append(&mut self.flow.remote_events);
    }

    /// Bytes arrived for a connection whose input is held.
    pub(crate) fn held_input(&mut self, c: ConnId, now_ms: u64) {
        let cap = HOLD_CONN + self.cfg.limits.max_packet_size as usize;
        if self.conns.get(c).is_some_and(|k| k.inbuf.len() > cap) {
            self.end_pause(c, now_ms, true);
        }
    }

    /// Ends `c`'s pause: its held bytes are parsed from the next
    /// [`Broker::poll_flow`] on. `timeout`: it is put in cool-down.
    fn end_pause(&mut self, c: ConnId, now_ms: u64, timeout: bool) {
        if let Some(i) = self.flow.paused.iter().position(|p| p.publisher == c) {
            let p = self.flow.paused.swap_remove(i);
            self.flow.stats.paused_ms += now_ms.saturating_sub(p.since_ms);
        }
        if timeout {
            self.flow.stats.timeouts += 1;
            self.flow.cooldown.insert(c, now_ms + COOLDOWN_MS);
        }
        if let Some(k) = self.conns.get_mut(c)
            && k.flow & PAUSED != 0
        {
            k.flow = DRAINING;
            self.flow.draining.push(c);
        }
    }

    /// Ends the pauses whose time came, and parses a slice of every held
    /// input. The transport calls it once per loop pass (cheap while nothing
    /// is held), then [`Broker::drain_flow`].
    pub fn poll_flow(&mut self, now_ms: u64) {
        if self.flow.paused.is_empty()
            && self.flow.draining.is_empty()
            && self.flow.waits.is_empty()
        {
            return;
        }
        let low = self.cfg.max_outbound_bytes / 4;
        let free = |c: ConnId| {
            self.conns
                .get(c)
                .is_none_or(|k| k.close.is_some() || k.outbuf.len() <= low)
        };
        // Subscribers other shards wait for: tell them when to go on (also at
        // the bound, so a lost message cannot hold a publisher).
        let mut i = 0;
        while let Some(w) = self.flow.waits.get(i) {
            if free(w.recipient) || now_ms.saturating_sub(w.since_ms) >= PAUSE_MAX_MS {
                let w = self.flow.waits.swap_remove(i);
                self.flow.remote_events.push((w.shard, w.publisher, false));
            } else {
                i += 1;
            }
        }
        let mut ended: Vec<(ConnId, bool)> = Vec::new();
        for p in &self.flow.paused {
            if now_ms.saturating_sub(p.since_ms) >= PAUSE_MAX_MS {
                ended.push((p.publisher, true));
            } else if let Recipient::Local(r) = p.recipient
                && free(r)
            {
                ended.push((p.publisher, false));
            }
        }
        for (c, timeout) in ended {
            self.end_pause(c, now_ms, timeout);
        }
        let draining = core::mem::take(&mut self.flow.draining);
        let mut still = Vec::new();
        for c in draining {
            match self.parse(c, now_ms, DRAIN_SLICE) {
                // Paused again: listed in `paused` (and the window is closed).
                Stop::Paused => {}
                Stop::Budget => still.push(c),
                Stop::Incomplete | Stop::Gone => {
                    if let Some(k) = self.conns.get_mut(c) {
                        k.flow = 0;
                        // The held time counts as alive (ADR-269).
                        k.last_rx_ms = now_ms;
                        self.flow.events.push((c, false));
                    }
                }
            }
        }
        // A pause during the slices pushed nothing here (it removed itself).
        self.flow.draining.append(&mut still);
        if self.flow.cooldown.len() > 64 {
            self.flow.cooldown.retain(|_, until| *until > now_ms);
        }
        if self.flow.remote_seen.len() > 1024 {
            self.flow.remote_seen.retain(|_, v| {
                v.retain(|&(_, at, _)| now_ms.saturating_sub(at) < REMOTE_SEEN_MS);
                !v.is_empty()
            });
        }
    }

    /// Takes the receive-window changes since the last call: (connection,
    /// `true` to close it, `false` to open it again).
    pub fn drain_flow(&mut self, out: &mut Vec<(ConnId, bool)>) {
        out.append(&mut self.flow.events);
    }

    /// Shard `shard` delivered a message of publisher `c` to `n` sessions of
    /// its own: for [`REMOTE_SEEN_MS`] `c` is not paused for a subscriber of
    /// this shard, nor for one of another shard unless that is the one.
    pub fn note_remote_recipients(&mut self, c: ConnId, shard: u16, n: u32, now_ms: u64) {
        if !self.conns.contains(c) || n == 0 {
            return;
        }
        let v = self.flow.remote_seen.entry(c).or_default();
        match v.iter_mut().find(|e| e.0 == shard) {
            Some(e) => *e = (shard, now_ms, n),
            None => v.push((shard, now_ms, n)),
        }
    }

    /// Whether `c`'s input is held (paused or draining).
    pub fn input_held(&self, c: ConnId) -> bool {
        self.conns.get(c).is_some_and(|k| k.flow != 0)
    }

    /// The back-pressure counters. Cheap, unlike [`Broker::stats`].
    pub fn flow_stats(&self) -> FlowStats {
        FlowStats {
            holding: (self.flow.paused.len() + self.flow.draining.len()) as u64,
            ..self.flow.stats
        }
    }

    /// `c` is gone: forgets it.
    pub(crate) fn flow_forget(&mut self, c: ConnId) {
        if let Some(i) = self.flow.paused.iter().position(|p| p.publisher == c) {
            self.flow.paused.swap_remove(i);
        }
        self.flow.draining.retain(|&x| x != c);
        self.flow.cooldown.remove(&c);
        self.flow.remote_seen.remove(&c);
        self.flow.events.retain(|&(x, _)| x != c);
        // A subscriber that leaves releases whoever waits for it at the next
        // `poll_flow` (it is no longer found).
    }
}
