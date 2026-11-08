//! Server-only TCP stack (M14, PROMPT §5.2, ADR-033).
//!
//! Sans-IO: segments come in through [`TcpStack::input`] with an [`App`]
//! that receives events synchronously, and leave through an `out` callback
//! as finished TCP segments (the IPv4 layer wraps them). Time is passed in
//! milliseconds.
//!
//! - **Passive open only.** SYN cookies are always on, so a half-open
//!   connection holds no state. A connection exists from the handshake's
//!   final ACK.
//! - **Per-core table:** open addressing on the 4-tuple, O(1). No hot path
//!   iterates over all connections. Timers sit in a hierarchical wheel
//!   ([`urmqtt_timer_wheel`]).
//! - **No buffers while idle:** received data goes to the app straight
//!   from the segment. The transmit buffer exists only while data is
//!   queued or unacknowledged.
//! - **ACK coalescing:** acknowledgements are deferred to [`TcpStack::flush`]
//!   at the end of the event-loop pass. A reply the application sends in
//!   the meantime carries the ACK, so PUBACK/CONNACK/PINGRESP share the
//!   segment that acknowledges the request.
//! - NewReno congestion control, RFC 6298 RTO, persist timer, no TCP
//!   keepalive (MQTT keepalive is the liveness mechanism).
//! - No TIME_WAIT. The client closes or is closed and the server forgets the
//!   connection right after the final ACK; a late duplicate gets a RST
//!   (server-side RST policy).
//! - Out-of-order data is kept (PERF, ADR-222): a segment beyond a hole is
//!   buffered in a small per-connection list of ranges (allocated on the first
//!   one, freed when the hole fills, bounded per connection and per core),
//!   answered at once with a duplicate ACK that carries SACK blocks when the
//!   peer negotiated them. One loss costs one retransmission, not the rest of
//!   the window.
//! - Window scaling, SACK and timestamps (RFC 7323, RFC 2018) are negotiated
//!   through the SYN cookie: the options the peer offered ride in the low six
//!   bits of our timestamp value (as Linux does), the peer echoes them in the
//!   final ACK, and the stack stays stateless until then. A peer that offers
//!   no timestamps gets the plain 16-bit window and no SACK.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::panic
    )
)]

extern crate alloc;

pub mod cc;
pub mod cookie;
pub mod seq;

mod ooo;
mod sack;

mod refused;
mod siphash;
pub mod table;
pub mod wire;

#[cfg(test)]
mod model;
#[cfg(test)]
mod ooo_tests;
#[cfg(test)]
mod opt_tests;
#[cfg(test)]
mod sack_tests;
#[cfg(test)]
mod script;
#[cfg(test)]
mod scripts;
#[cfg(test)]
mod tests;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use cc::{Congestion, NewReno};
use cookie::Cookies;
use ooo::Ooo;
use refused::{RefusedFlows, Verdict};
use sack::Board;
use seq::{ge, gt, le, lt};
use table::{Key, Table};
use urmqtt_mm::slab::Slab;
use urmqtt_timer_wheel::{TimerId, Wheel};
use wire::{ACK, Ext, FIN, Header, Out, PSH, RST, SYN};

pub type ConnId = u32;

/// IPv4 and TCP headers without options: what an MTU holds beyond the MSS.
pub const IPV4_TCP_HEADERS: u16 = 40;
/// Largest MSS this stack announces or uses: the size of its segment buffers
/// and the top of the SYN-cookie table ([`cookie::MSS_TABLE`]). A 1500-byte
/// Ethernet MTU minus [`IPV4_TCP_HEADERS`].
pub const MAX_MSS: u16 = 1460;
/// Smallest MSS (RFC 9293 §3.7.1: 536, the IPv4 default; the cookie's lowest).
pub const MIN_MSS: u16 = 536;

/// The MSS for an IPv4 link MTU (NOW-19, ADR-264): `mtu - 40`, clamped to
/// what this stack can send ([`MIN_MSS`]..=[`MAX_MSS`]). A segment then fills
/// at most the MTU: timestamps take 12 bytes of the MSS, not more.
pub const fn mss_for_mtu(mtu: u16) -> u16 {
    let m = mtu.saturating_sub(IPV4_TCP_HEADERS);
    if m < MIN_MSS {
        MIN_MSS
    } else if m > MAX_MSS {
        MAX_MSS
    } else {
        m
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: [u8; 4],
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Both sides closed in order.
    Normal,
    /// The peer sent RST.
    Reset,
    /// Retransmissions (or FIN-WAIT-2) timed out.
    Timeout,
}

/// The application side of the stack, called synchronously from
/// [`TcpStack::input`], [`TcpStack::poll`] and [`TcpStack::flush`].
pub trait App {
    /// A SYN for `local_port` from `remote` arrived. Return false to drop
    /// it without a SYN-ACK: no state exists yet, and the peer's own TCP
    /// retransmits after its backoff (1 s, 2 s, ...). Used to shed load
    /// before any work is done (PERF, ADR-080). The default accepts all.
    fn syn_ok(&mut self, _local_port: u16, _remote: [u8; 4]) -> bool {
        true
    }
    /// A handshake completed; return false to refuse (the peer gets RST).
    fn accept(&mut self, c: ConnId, local_port: u16, remote: Endpoint) -> bool;
    /// In-order payload; must be consumed (processed or copied) now.
    fn data(&mut self, c: ConnId, data: &[u8]);
    /// The peer sent FIN: no more data will arrive.
    fn peer_closed(&mut self, c: ConnId);
    /// The connection is gone; its id may be reused once this returns.
    fn closed(&mut self, c: ConnId, why: CloseReason);
}

#[derive(Debug, Clone)]
pub struct Config {
    pub local_addr: [u8; 4],
    pub ports: Vec<u16>,
    /// MSS we announce and the most a connection uses: [`mss_for_mtu`] of
    /// the link MTU (clamped to [`MIN_MSS`]..=[`MAX_MSS`]).
    pub mss: u16,
    /// Receive window when the application has not set one (and the window
    /// announced on a SYN-ACK, which is never scaled).
    pub rcv_wnd: u16,
    /// Receive window of a connection that negotiated window scaling, bytes
    /// (0: no scaling is offered). The shift is the smallest that fits 16 bits.
    pub rcv_wnd_scaled: u32,
    pub max_conns: usize,
    /// Most bytes queued for sending per connection while its congestion
    /// window is small ...
    pub tx_max: usize,
    /// ... and as many as twice the congestion window, up to this.
    pub tx_cap: usize,
    /// Bytes of out-of-order data this stack may hold in all (0: none is kept).
    pub ooo_budget: usize,
    /// ... and per connection.
    pub ooo_conn_max: usize,
    pub cookie_key: [u8; 16],
    /// RST/challenge-ACK segments per second sent for unknown connections.
    pub rst_per_sec: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub segs_in: u64,
    pub segs_out: u64,
    pub bad_segments: u64,
    pub cookies_sent: u64,
    pub cookies_ok: u64,
    pub cookies_bad: u64,
    pub cookie_rotations: u64,
    /// SYNs with an MSS below 536, dropped.
    pub refused_small_mss: u64,
    pub retransmits: u64,
    pub fast_retransmits: u64,
    /// Retransmission timer expiries that sent data again (ADR-268: the
    /// counter `timeouts` only counts connections given up).
    pub rto_fired: u64,
    pub timeouts: u64,
    pub rst_sent: u64,
    pub rst_limited: u64,
    pub out_of_order: u64,
    pub refused_full: u64,
    pub accepted: u64,
    /// SYNs dropped without a SYN-ACK because the application was full
    /// ([`App::syn_ok`]).
    pub syn_dropped: u64,
    /// Connections the application refused at the final ACK ([`App::accept`]
    /// returned false): the peer got a RST.
    pub refused_app: u64,
    /// Segments of a flow refused a moment ago, answered or dropped without
    /// asking the application again (see `RefusedFlows`).
    pub refused_repeat: u64,
    /// Segments kept because they arrived beyond a hole.
    pub ooo_buffered: u64,
    /// Out-of-order segments dropped: connection or core budget used up, or
    /// the list of ranges full (the peer retransmits them).
    pub ooo_dropped: u64,
    /// Bytes of out-of-order data held now.
    pub ooo_bytes: u64,
    /// Connections that negotiated window scaling, and SACK.
    pub scaled: u64,
    pub sack_neg: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Established,
    /// Peer sent FIN, we have not closed yet.
    CloseWait,
    /// We sent FIN (after our data), waiting for its ACK.
    FinWait1,
    /// Our FIN is acknowledged, waiting for the peer's FIN.
    FinWait2,
    /// Both FINs sent, ours not yet acknowledged.
    Closing,
    /// Peer closed first, our FIN sent, waiting for its ACK.
    LastAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    Retransmit,
    Persist,
    FinWait2,
}

/// Bytes of buffered data handed to the application per call.
const DELIVER_SLICE: usize = 16 * 1024;

const RTO_INIT_MS: u16 = 1000;
const RTO_MIN_MS: u32 = 200;
const RTO_MAX_MS: u16 = 60_000;
const MAX_RETRIES: u8 = 8;
const FIN_WAIT2_MS: u64 = 60_000;

/// Per-connection state (compact; the send buffer is separate and absent
/// while nothing is queued).
struct Conn {
    key: Key,
    state: State,
    /// `FIN_QUEUED`, `FIN_SENT`, `ACK_PENDING`, … (one byte, M15).
    flags: u8,
    dupacks: u8,
    /// Retransmission timeouts in a row (low four bits, at most `MAX_RETRIES`) and
    /// how often a retransmission proved needless (high four bits, see
    /// `reorder`).
    retries: u8,
    /// In-order data segments received since the last ACK went out: every
    /// second one is acknowledged at once (RFC 5681 §4.2).
    ack_segs: u8,
    mss: u16,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent so far (ACKs are valid up to here even
    /// after a go-back-N rollback of `snd_nxt`).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    recover: u32,
    rcv_nxt: u32,
    /// Receive space set by the application.
    rcv_space: u32,
    /// Window scale: the peer's (applies to what it advertises) and ours.
    snd_shift: u8,
    rcv_shift: u8,
    /// The peer's latest timestamp, echoed in our segments.
    ts_recent: u32,
    /// Data beyond a hole, if any.
    ooo: Option<Box<Ooo>>,
    /// Right edge we last advertised (never moved left).
    rcv_adv: u32,
    rtt_seq: u32,
    /// When the timed segment was sent (ms, wrapping).
    rtt_start: u32,
    /// RTT estimates and timeout in ms (≤ `RTO_MAX_MS`, so 16 bits).
    srtt: u16,
    rttvar: u16,
    rto: u16,
    cc: NewReno,
    timer: Option<(TimerId, TimerKind)>,
    /// Bytes from `snd_una` on: unacknowledged, then unsent, and what the peer
    /// said about holes. Boxed so an idle connection pays 8 bytes for it.
    tx: Option<Box<Sender>>,
}

/// The sending side of a connection that has data queued.
struct Sender {
    /// Bytes from `snd_una` on: unacknowledged, then unsent.
    q: VecDeque<u8>,
    /// The peer's SACK blocks and the recovery's frontier (RFC 6675), while
    /// the peer reports holes (ADR-265).
    board: Option<Box<Board>>,
    /// How long this flow's data segments are lately (a running average, 0:
    /// none sent yet): the "segment" that loss detection counts in (ADR-268).
    seg: u16,
}

/// FIN queued by the application (sent after the data).
const FIN_QUEUED: u8 = 1;
const FIN_SENT: u8 = 2;
/// An ACK is owed; sent by `flush` unless data carries it first.
const ACK_PENDING: u8 = 4;
const IN_DIRTY: u8 = 8;
const IN_RECOVERY: u8 = 16;
const RTT_TIMING: u8 = 32;
/// SACK-permitted was negotiated: we report out-of-order ranges.
const SACK_OK: u8 = 64;
/// Timestamps were negotiated: every segment carries them, and costs 12 bytes of payload.
const TS_OK: u8 = 128;

impl Conn {
    fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    fn set(&mut self, f: u8, on: bool) {
        if on {
            self.flags |= f;
        } else {
            self.flags &= !f;
        }
    }

    fn tx_len(&self) -> usize {
        self.tx.as_ref().map_or(0, |t| t.q.len())
    }

    /// Retransmission timeouts in a row.
    fn timeouts(&self) -> u8 {
        self.retries & 15
    }

    fn set_timeouts(&mut self, n: u8) {
        self.retries = (self.retries & 0xf0) | n.min(15);
    }

    /// How many times the peer reported a duplicate of data we may have sent
    /// again (RFC 2883): the network reorders more than the loss detection
    /// waited for, and the window it waits grows by a factor of two each time.
    fn reorder(&self) -> u8 {
        self.retries >> 4
    }

    fn bump_reorder(&mut self) {
        if self.reorder() < 7 {
            self.retries += 16;
        }
    }

    /// The size of segment this flow's loss detection counts in: what it sent
    /// lately, at most the MSS (ADR-268). A flow of 100-byte MQTT messages has
    /// three of them above a hole well before it has three full segments.
    fn seg_size(&self) -> u32 {
        let mss = self.eff_mss() as u32;
        match self.tx.as_ref().map_or(0, |t| u32::from(t.seg)) {
            0 => mss,
            s => s.min(mss),
        }
    }

    /// The pipe of a recovery driven by the peer's SACK blocks (RFC 6675 §4):
    /// what is in the network, being what is in flight less what the peer holds
    /// and what is lost and not yet sent again. `None` outside such a recovery.
    fn sack_pipe(&self) -> Option<u32> {
        if !self.has(IN_RECOVERY) {
            return None;
        }
        let b = self.tx.as_ref()?.board.as_ref()?;
        let t = b.tally(self.snd_una, self.seg_size());
        Some(
            self.flight()
                .saturating_sub(t.sacked)
                .saturating_sub(t.lost.saturating_sub(t.resent)),
        )
    }

    /// Data bytes in flight (sent, not acknowledged), excluding our FIN.
    fn flight(&self) -> u32 {
        (self.snd_max.wrapping_sub(self.snd_una) as usize).min(self.tx_len()) as u32
    }

    /// The receive window in bytes.
    fn window_bytes(&self) -> u32 {
        // The advertised window never shrinks below what was promised.
        let edge = self.rcv_nxt.wrapping_add(self.rcv_space);
        let edge = if gt(edge, self.rcv_adv) {
            edge
        } else {
            self.rcv_adv
        };
        edge.wrapping_sub(self.rcv_nxt)
    }

    /// The window field to announce (scaled down, rounded down).
    fn window(&self) -> u16 {
        (self.window_bytes() >> self.rcv_shift).min(65535) as u16
    }

    /// The right edge the announced field promises.
    fn adv_edge(&self, field: u16) -> u32 {
        self.rcv_nxt
            .wrapping_add(u32::from(field) << self.rcv_shift)
    }

    /// Payload bytes a full segment carries (timestamps take 12 of the MSS).
    fn eff_mss(&self) -> usize {
        usize::from(self.mss) - if self.has(TS_OK) { 12 } else { 0 }
    }

    /// Bytes the application may queue: twice what the sender may have in
    /// flight (the smaller of the congestion window and the peer's window),
    /// between the base and the cap. A reader that stops (a zero window) keeps
    /// only the base queued however large its congestion window grew.
    fn tx_limit(&self, base: usize, cap: usize) -> usize {
        (self.cc.window().min(self.snd_wnd) as usize)
            .saturating_mul(2)
            .clamp(base, cap.max(base))
    }

    fn can_receive(&self) -> bool {
        matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        )
    }
}

pub struct TcpStack {
    cfg: Config,
    cookies: Cookies,
    conns: Slab<Conn>,
    table: Table,
    wheel: Wheel<u32>,
    /// Connections owing an ACK or with new data to send.
    dirty: Vec<u32>,
    rst_tokens: u32,
    rst_last_ms: u64,
    refused: RefusedFlows,
    buf: Vec<u8>,
    /// Out-of-order bytes held by all connections.
    ooo_used: usize,
    /// The timestamp clock (ms, wrapping), set on every entry.
    clock: u32,
    pub stats: Stats,
}

impl TcpStack {
    pub fn new(mut cfg: Config, now_ms: u64) -> Self {
        cfg.mss = cfg.mss.clamp(MIN_MSS, MAX_MSS);
        let seed = u64::from_le_bytes([
            cfg.cookie_key[0],
            cfg.cookie_key[3],
            cfg.cookie_key[5],
            cfg.cookie_key[7],
            cfg.cookie_key[9],
            cfg.cookie_key[11],
            cfg.cookie_key[13],
            cfg.cookie_key[15],
        ]);
        Self {
            cookies: Cookies::new(cfg.cookie_key),
            table: Table::new(cfg.max_conns, seed),
            wheel: Wheel::new(now_ms),
            conns: Slab::new(),
            dirty: Vec::new(),
            rst_tokens: cfg.rst_per_sec,
            rst_last_ms: now_ms,
            refused: RefusedFlows::new(seed),
            buf: Vec::with_capacity(1600),
            ooo_used: 0,
            clock: now_ms as u32,
            cfg,
            stats: Stats::default(),
        }
    }

    /// Our address changed (DHCP); existing connections keep theirs.
    pub fn set_local_addr(&mut self, addr: [u8; 4]) {
        self.cfg.local_addr = addr;
    }

    /// The link MTU changed (DHCP option 26, NOW-19): new connections
    /// announce and use `mss` (clamped to [`MIN_MSS`]..=[`MAX_MSS`]), and
    /// open ones never send a segment larger than it from now on (their
    /// congestion state counts bytes, so it stays valid).
    pub fn set_mss(&mut self, mss: u16) {
        let mss = mss.clamp(MIN_MSS, MAX_MSS);
        self.cfg.mss = mss;
        for (_, k) in self.conns.iter_mut() {
            k.mss = k.mss.min(mss);
        }
    }

    /// The MSS new connections announce.
    pub fn mss(&self) -> u16 {
        self.cfg.mss
    }

    pub fn local_addr(&self) -> [u8; 4] {
        self.cfg.local_addr
    }

    pub fn connections(&self) -> usize {
        self.table.len()
    }

    /// Bytes the application may still queue on `c`.
    pub fn send_space(&self, c: ConnId) -> usize {
        self.conn(c).map_or(0, |k| {
            k.tx_limit(self.cfg.tx_max, self.cfg.tx_cap)
                .saturating_sub(k.tx_len())
        })
    }

    /// Bytes queued and not yet acknowledged.
    pub fn send_queue(&self, c: ConnId) -> usize {
        self.conn(c).map_or(0, Conn::tx_len)
    }

    pub fn remote(&self, c: ConnId) -> Option<Endpoint> {
        self.conn(c).map(|k| Endpoint {
            addr: k.key.addr,
            port: k.key.rport,
        })
    }

    fn conn(&self, c: ConnId) -> Option<&Conn> {
        self.conns.get(c)
    }

    fn conn_mut(&mut self, c: ConnId) -> Option<&mut Conn> {
        self.conns.get_mut(c)
    }

    fn mark_dirty(&mut self, c: ConnId) {
        if let Some(k) = self.conn_mut(c)
            && !k.has(IN_DIRTY)
        {
            k.set(IN_DIRTY, true);
            self.dirty.push(c);
        }
    }

    /// Sets how much the application can take (flow control tied to the
    /// broker's backpressure). Growing it announces the new window.
    pub fn set_recv_space(&mut self, c: ConnId, bytes: u32) {
        let mut update = false;
        if let Some(k) = self.conn_mut(c) {
            let before = k.window();
            k.rcv_space = bytes.min(65535 << k.rcv_shift);
            let after = k.window();
            // Announce a reopened window (at least one MSS more, or from 0).
            if after > before && (before == 0 || u32::from(after - before) >= u32::from(k.mss)) {
                k.set(ACK_PENDING, true);
                update = true;
            }
        }
        if update {
            self.mark_dirty(c);
        }
    }

    /// Queues `data`; returns how many bytes were accepted.
    pub fn send(&mut self, c: ConnId, data: &[u8]) -> usize {
        let (base, cap) = (self.cfg.tx_max, self.cfg.tx_cap);
        let Some(k) = self.conn_mut(c) else { return 0 };
        let max = k.tx_limit(base, cap);
        if k.has(FIN_QUEUED) || !matches!(k.state, State::Established | State::CloseWait) {
            return 0;
        }
        let n = data.len().min(max.saturating_sub(k.tx_len()));
        if n > 0 {
            let tx = k.tx.get_or_insert_with(|| {
                Box::new(Sender {
                    q: VecDeque::new(),
                    board: None,
                    seg: 0,
                })
            });
            tx.q.extend(data.get(..n).unwrap_or(&[]));
            self.mark_dirty(c);
        }
        n
    }

    /// Closes our side after the queued data (FIN).
    pub fn close(&mut self, c: ConnId) {
        if let Some(k) = self.conn_mut(c)
            && !k.has(FIN_QUEUED)
            && matches!(k.state, State::Established | State::CloseWait)
        {
            k.set(FIN_QUEUED, true);
            self.mark_dirty(c);
        }
    }

    /// Resets the connection now (RST). The application gets no `closed`.
    pub fn abort(&mut self, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) {
        let Some(k) = self.conn(c) else { return };
        let o = Out {
            sport: k.key.lport,
            dport: k.key.rport,
            seq: k.snd_nxt,
            ack: k.rcv_nxt,
            flags: RST | ACK,
            window: 0,
            mss: None,
        };
        let dst = k.key.addr;
        self.emit(dst, &o, &[], out);
        self.stats.rst_sent += 1;
        self.remove(c);
    }

    fn remove(&mut self, c: ConnId) {
        let Some(k) = self.conns.remove(c) else {
            return;
        };
        if let Some(o) = &k.ooo {
            self.ooo_used = self.ooo_used.saturating_sub(o.bytes());
            self.stats.ooo_bytes = self.ooo_used as u64;
        }
        if let Some((t, _)) = k.timer {
            self.wheel.cancel(t);
        }
        let conns = &self.conns;
        let gone = k.key;
        self.table.remove(&gone, |x| {
            if x == c {
                Some(gone)
            } else {
                conns.get(x).map(|k| k.key)
            }
        });
    }

    fn close_with(&mut self, c: ConnId, why: CloseReason, app: &mut impl App) {
        self.remove(c);
        app.closed(c, why);
    }

    fn emit(
        &mut self,
        dst: [u8; 4],
        o: &Out,
        payload: &[u8],
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        self.emit_x(dst, o, &Ext::NONE, payload, out);
    }

    fn emit_x(
        &mut self,
        dst: [u8; 4],
        o: &Out,
        x: &Ext,
        payload: &[u8],
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        let mut buf = core::mem::take(&mut self.buf);
        wire::emit_ext(self.cfg.local_addr, dst, o, x, payload, &mut buf);
        out(dst, &buf);
        self.buf = buf;
        self.stats.segs_out += 1;
    }

    /// The options an established connection's segment carries: timestamps
    /// and, on a segment without data, the SACK blocks.
    fn ext_of(&self, k: &Conn, sacks: bool) -> Ext {
        let mut x = Ext::NONE;
        if k.has(TS_OK) {
            x.ts = Some((self.clock, k.ts_recent));
        }
        if sacks
            && k.has(SACK_OK)
            && let Some(o) = &k.ooo
        {
            (x.sacks, x.nsack) = o.blocks();
        }
        x
    }

    /// RSTs for segments that match no connection, rate-limited.
    fn reset_unknown(
        &mut self,
        now_ms: u64,
        src: [u8; 4],
        h: &Header,
        len: u32,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        if h.flags & RST != 0 {
            return;
        }
        let elapsed = now_ms.saturating_sub(self.rst_last_ms);
        if elapsed >= 1000 {
            self.rst_tokens = self.cfg.rst_per_sec;
            self.rst_last_ms = now_ms;
        }
        if self.rst_tokens == 0 {
            self.stats.rst_limited += 1;
            return;
        }
        self.rst_tokens -= 1;
        let o = if h.flags & ACK != 0 {
            Out {
                sport: h.dport,
                dport: h.sport,
                seq: h.ack,
                ack: 0,
                flags: RST,
                window: 0,
                mss: None,
            }
        } else {
            let syn_fin = u32::from(h.flags & SYN != 0) + u32::from(h.flags & FIN != 0);
            Out {
                sport: h.dport,
                dport: h.sport,
                seq: 0,
                ack: h.seq.wrapping_add(len + syn_fin),
                flags: RST | ACK,
                window: 0,
                mss: None,
            }
        };
        self.emit(src, &o, &[], out);
        self.stats.rst_sent += 1;
    }

    /// Processes one TCP segment from `src` to us.
    pub fn input(
        &mut self,
        now_ms: u64,
        src: [u8; 4],
        seg: &[u8],
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        self.stats.segs_in += 1;
        self.clock = now_ms as u32;
        let h = match wire::parse(src, self.cfg.local_addr, seg) {
            Ok(h) => h,
            Err(_) => {
                self.stats.bad_segments += 1;
                return;
            }
        };
        let payload = seg.get(h.data_off..).unwrap_or(&[]);
        let key = Key {
            addr: src,
            rport: h.sport,
            lport: h.dport,
        };
        let conns = &self.conns;
        match self.table.get(&key, |c| conns.get(c).map(|k| k.key)) {
            Some(c) => self.segment(now_ms, c, &h, payload, app, out),
            None => self.listen(now_ms, src, key, &h, payload, app, out),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn listen(
        &mut self,
        now_ms: u64,
        src: [u8; 4],
        key: Key,
        h: &Header,
        payload: &[u8],
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        if !self.cfg.ports.contains(&h.dport) {
            self.reset_unknown(now_ms, src, h, payload.len() as u32, out);
            return;
        }
        let now_s = now_ms / 1000;
        let local = self.cfg.local_addr;
        if h.flags & SYN != 0 && h.flags & ACK == 0 {
            // A peer asking for segments under 536 bytes cannot be served:
            // a cookie encodes nothing smaller, and sending more than the
            // peer's MSS breaks RFC 9293 §3.7.1 (H3). Refused.
            if h.mss.is_some_and(|m| m < cookie::MSS_TABLE[0]) {
                self.stats.refused_small_mss += 1;
                return;
            }
            // The application is full: no SYN-ACK and no state. The peer's
            // own TCP retransmits the SYN after its backoff (PERF, ADR-080).
            if !app.syn_ok(h.dport, src) {
                self.stats.syn_dropped += 1;
                return;
            }
            // Stateless SYN-ACK: the cookie is our ISN.
            let flow = cookie::Flow {
                src,
                sport: h.sport,
                dst: local,
                dport: h.dport,
            };
            let isn = self.cookies.make(now_s, &flow, h.seq, h.mss.unwrap_or(536));
            let o = Out {
                sport: h.dport,
                dport: h.sport,
                seq: isn,
                ack: h.seq.wrapping_add(1),
                flags: SYN | ACK,
                window: self.cfg.rcv_wnd,
                mss: Some(self.cfg.mss),
            };
            // Options only for a peer that offered timestamps: they carry the
            // rest through the cookie.
            let mut x = Ext::NONE;
            if let Some((tsval, _)) = h.ts {
                let scale = self.cfg.rcv_wnd_scaled > 0;
                let opts = cookie::Opts {
                    sack_ok: h.sack_ok,
                    wscale: if scale { h.wscale } else { None },
                };
                x.ts = Some((cookie::ts_encode(self.clock, opts), tsval));
                x.sack_perm = h.sack_ok;
                if opts.wscale.is_some() {
                    x.wscale = Some(self.rcv_shift());
                }
            }
            self.emit_x(src, &o, &x, &[], out);
            self.stats.cookies_sent += 1;
            return;
        }
        if h.flags & (SYN | RST) != 0 || h.flags & ACK == 0 {
            self.reset_unknown(now_ms, src, h, payload.len() as u32, out);
            return;
        }
        // A flow refused a moment ago (its ClientHello follows the refused
        // ACK): do not ask the application again.
        match self.refused.check(&key, now_ms) {
            Verdict::Unknown => {}
            Verdict::Reset => {
                self.stats.refused_repeat += 1;
                let o = Out {
                    sport: h.dport,
                    dport: h.sport,
                    seq: h.ack,
                    ack: 0,
                    flags: RST,
                    window: 0,
                    mss: None,
                };
                self.emit(src, &o, &[], out);
                self.stats.rst_sent += 1;
                return;
            }
            Verdict::Drop => {
                self.stats.refused_repeat += 1;
                return;
            }
        }
        // Final ACK of the handshake: validate the cookie.
        let our_isn = h.ack.wrapping_sub(1);
        let client_isn = h.seq.wrapping_sub(1);
        let flow = cookie::Flow {
            src,
            sport: h.sport,
            dst: local,
            dport: h.dport,
        };
        let Some(mss) = self.cookies.check(now_s, &flow, client_isn, our_isn) else {
            self.stats.cookies_bad += 1;
            // A data segment may simply have overtaken a lost final ACK (its
            // sequence number no longer encodes the client's ISN): drop it,
            // the client retransmits from its first byte. A pure ACK or FIN
            // that does not check out gets a RST (e.g. after a restart).
            if payload.is_empty() {
                self.reset_unknown(now_ms, src, h, 0, out);
            }
            return;
        };
        self.stats.cookies_ok += 1;
        if !self.table.has_room() || self.table.len() >= self.cfg.max_conns {
            self.stats.refused_full += 1;
            self.reset_unknown(now_ms, src, h, payload.len() as u32, out);
            return;
        }
        let mss = mss.min(self.cfg.mss);
        // What the cookie carried (an ACK without timestamps negotiated nothing).
        let opts = match h.ts {
            Some((_, tsecr)) => cookie::ts_decode(tsecr),
            None => cookie::Opts::default(),
        };
        let mut flags = 0;
        if h.ts.is_some() {
            flags |= TS_OK;
        }
        if opts.sack_ok && h.ts.is_some() {
            flags |= SACK_OK;
            self.stats.sack_neg += 1;
        }
        let (snd_shift, rcv_shift) = match opts.wscale {
            Some(sh) if h.ts.is_some() => {
                self.stats.scaled += 1;
                (sh, self.rcv_shift())
            }
            _ => (0, 0),
        };
        let rcv_space = if opts.wscale.is_some() && h.ts.is_some() {
            self.cfg.rcv_wnd_scaled.max(u32::from(self.cfg.rcv_wnd))
        } else {
            u32::from(self.cfg.rcv_wnd)
        };
        let conn = Conn {
            key,
            state: State::Established,
            flags,
            dupacks: 0,
            retries: 0,
            ack_segs: 0,
            mss,
            snd_una: h.ack,
            snd_nxt: h.ack,
            snd_max: h.ack,
            snd_wnd: u32::from(h.window) << snd_shift,
            snd_wl1: h.seq,
            snd_wl2: h.ack,
            recover: h.ack,
            rcv_nxt: h.seq,
            rcv_space,
            snd_shift,
            rcv_shift,
            ts_recent: h.ts.map_or(0, |(v, _)| v),
            ooo: None,
            rcv_adv: h.seq.wrapping_add(u32::from(self.cfg.rcv_wnd)),
            rtt_seq: 0,
            rtt_start: 0,
            srtt: 0,
            rttvar: 0,
            rto: RTO_INIT_MS,
            cc: NewReno::new(u32::from(mss)),
            timer: None,
            tx: None,
        };
        let c = self.conns.insert(conn);
        let conns = &self.conns;
        self.table.insert(key, c, |x| conns.get(x).map(|k| k.key));
        self.stats.accepted += 1;
        if !app.accept(
            c,
            h.dport,
            Endpoint {
                addr: src,
                port: h.sport,
            },
        ) {
            self.stats.refused_app += 1;
            self.refused.note(&key, now_ms);
            self.abort(c, out);
            return;
        }
        // Data (or FIN) may ride on the final ACK.
        if !payload.is_empty() || h.flags & FIN != 0 {
            self.segment(now_ms, c, h, payload, app, out);
        }
    }

    /// Our window shift: the smallest that fits `rcv_wnd_scaled` in 16 bits.
    fn rcv_shift(&self) -> u8 {
        let mut sh = 0;
        while sh < 14 && (self.cfg.rcv_wnd_scaled >> sh) > 65535 {
            sh += 1;
        }
        sh
    }

    fn send_ack_now(&mut self, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) {
        let Some(k) = self.conn(c) else { return };
        let x = self.ext_of(k, true);
        let Some(k) = self.conn_mut(c) else { return };
        k.set(ACK_PENDING, false);
        k.ack_segs = 0;
        let o = Out {
            sport: k.key.lport,
            dport: k.key.rport,
            seq: k.snd_nxt,
            ack: k.rcv_nxt,
            flags: ACK,
            window: k.window(),
            mss: None,
        };
        k.rcv_adv = k.adv_edge(o.window);
        let dst = k.key.addr;
        self.emit_x(dst, &o, &x, &[], out);
    }

    fn arm(&mut self, c: ConnId, now_ms: u64, kind: TimerKind, after_ms: u64) {
        let Some(k) = self.conns.get_mut(c) else {
            return;
        };
        if let Some((t, _)) = k.timer.take() {
            self.wheel.cancel(t);
        }
        let id = self.wheel.insert(now_ms + after_ms, c);
        k.timer = Some((id, kind));
    }

    fn disarm(&mut self, c: ConnId) {
        if let Some(k) = self.conns.get_mut(c)
            && let Some((t, _)) = k.timer.take()
        {
            self.wheel.cancel(t);
        }
    }

    fn rtt_sample(k: &mut Conn, rtt_ms: u32) {
        // RFC 6298 §2 (srtt in ms, rttvar in ms).
        let rtt_ms = rtt_ms.min(u32::from(RTO_MAX_MS));
        let (mut srtt, mut rttvar) = (u32::from(k.srtt), u32::from(k.rttvar));
        if srtt == 0 {
            srtt = rtt_ms.max(1);
            rttvar = rtt_ms / 2;
        } else {
            let err = srtt.abs_diff(rtt_ms);
            rttvar = (3 * rttvar + err) / 4;
            srtt = (7 * srtt + rtt_ms) / 8;
        }
        let rto = (srtt + (4 * rttvar).max(10)).clamp(RTO_MIN_MS, u32::from(RTO_MAX_MS));
        // All three are at most `RTO_MAX_MS` (rttvar ≤ the clamped sample).
        (k.srtt, k.rttvar, k.rto) = (srtt as u16, rttvar as u16, rto as u16);
    }

    #[allow(clippy::too_many_arguments)]
    fn segment(
        &mut self,
        now_ms: u64,
        c: ConnId,
        h: &Header,
        payload: &[u8],
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        let Some(k) = self.conn(c) else { return };
        let seg_len = payload.len() as u32 + u32::from(h.flags & FIN != 0);
        let wnd = k.window_bytes().max(1);
        // Acceptability (RFC 793 §3.3): the segment must overlap the window.
        let acceptable = if seg_len == 0 {
            seq::in_window(h.seq, k.rcv_nxt, wnd) || h.seq == k.rcv_nxt
        } else {
            seq::in_window(h.seq, k.rcv_nxt, wnd)
                || seq::in_window(h.seq.wrapping_add(seg_len - 1), k.rcv_nxt, wnd)
                || (lt(h.seq, k.rcv_nxt) && gt(h.seq.wrapping_add(seg_len), k.rcv_nxt))
        };
        if h.flags & RST != 0 {
            // RFC 5961 §3: exact match resets, in-window gets a challenge ACK.
            if h.seq == k.rcv_nxt {
                self.close_with(c, CloseReason::Reset, app);
            } else if acceptable {
                self.send_ack_now(c, out);
            }
            return;
        }
        // A pure ACK is useful even with a stale sequence number (the peer
        // went back after our ACKs were lost): its acknowledgement is
        // processed (RFC 5961 §5 bounds it); only data needs the window.
        if !acceptable && seg_len > 0 {
            self.send_ack_now(c, out);
            return;
        }
        if h.flags & SYN != 0 {
            // RFC 5961 §4: challenge ACK for a SYN in a synchronized state.
            self.send_ack_now(c, out);
            return;
        }
        if h.flags & ACK == 0 {
            return;
        }
        if !self.process_ack(now_ms, c, h, payload.is_empty(), app, out) {
            return;
        }
        // Data: in order is delivered, beyond a hole it is kept.
        let Some(k) = self.conn_mut(c) else { return };
        if let Some((tsval, _)) = h.ts
            && k.has(TS_OK)
            && le(h.seq, k.rcv_nxt)
            && ge(tsval, k.ts_recent)
        {
            k.ts_recent = tsval;
        }
        let mut data = payload;
        let mut seq_no = h.seq;
        if lt(seq_no, k.rcv_nxt) {
            let skip = k.rcv_nxt.wrapping_sub(seq_no) as usize;
            data = data.get(skip.min(data.len())..).unwrap_or(&[]);
            seq_no = k.rcv_nxt;
        }
        if !data.is_empty() || h.flags & FIN != 0 {
            if seq_no != k.rcv_nxt {
                self.stats.out_of_order += 1;
                self.keep_out_of_order(c, seq_no, data);
                self.send_ack_now(c, out);
                return;
            }
            if !k.can_receive() {
                data = &[];
            }
            let room = k.window_bytes() as usize;
            let n = data.len().min(room);
            let fin = h.flags & FIN != 0 && n == data.len();
            let take = data.get(..n).unwrap_or(&[]);
            // The application consumes data synchronously; `rcv_space` is
            // its backpressure limit, not a buffer that fills up.
            k.rcv_nxt = k.rcv_nxt.wrapping_add(n as u32);
            // Even a segment that did not fit (a zero-window probe) is
            // answered, with the current window.
            k.set(ACK_PENDING, true);
            // Every second segment is acknowledged at once, *before* the
            // application works on the data: at the end of the pass only, a
            // sender saw one ACK per batch of 64 frames (every 8 to 50 ms on a
            // VPS whose cores are preempted), and its window waited for it
            // (ADR-265).
            k.ack_segs = k.ack_segs.saturating_add(1);
            let early_ack = !fin && k.ack_segs >= 2;
            if fin {
                k.rcv_nxt = k.rcv_nxt.wrapping_add(1);
                k.state = match k.state {
                    State::Established => State::CloseWait,
                    State::FinWait1 => State::Closing,
                    State::FinWait2 => {
                        // No TIME_WAIT (ADR-033): ACK the FIN and forget.
                        self.send_ack_now(c, out);
                        if !take.is_empty() {
                            app.data(c, take);
                        }
                        app.peer_closed(c);
                        self.close_with(c, CloseReason::Normal, app);
                        return;
                    }
                    s => s,
                };
            }
            if early_ack {
                self.send_ack_now(c, out);
            }
            if !take.is_empty() {
                app.data(c, take);
            }
            if fin {
                app.peer_closed(c);
                // A FIN is acknowledged right away.
                self.send_ack_now(c, out);
            } else if self.deliver_buffered(c, app) {
                // A hole was filled: the sender is waiting for this ACK.
                self.send_ack_now(c, out);
            } else {
                self.mark_dirty(c);
            }
        }
    }

    /// Keeps `data` (which starts beyond `rcv_nxt`) for when the hole fills.
    fn keep_out_of_order(&mut self, c: ConnId, seq_no: u32, data: &[u8]) {
        let (conn_max, budget) = (self.cfg.ooo_conn_max, self.cfg.ooo_budget);
        let used = self.ooo_used;
        let Some(k) = self.conns.get_mut(c) else {
            return;
        };
        // Only what lies inside the window we announced.
        let edge = k.rcv_nxt.wrapping_add(k.window_bytes());
        let start_off = seq_no.wrapping_sub(k.rcv_nxt);
        let room = edge.wrapping_sub(seq_no) as usize;
        if data.is_empty() || !k.can_receive() || start_off >= k.window_bytes() {
            return;
        }
        let data = data.get(..data.len().min(room)).unwrap_or(&[]);
        let held = k.ooo.as_ref().map_or(0, |o| o.bytes());
        if budget == 0 || held + data.len() > conn_max || used + data.len() > budget {
            self.stats.ooo_dropped += 1;
            return;
        }
        let o = k.ooo.get_or_insert_with(|| Box::new(Ooo::default()));
        let before = o.bytes();
        if o.insert(seq_no, data).is_none() {
            self.stats.ooo_dropped += 1;
            return;
        }
        let after = o.bytes();
        self.stats.ooo_buffered += 1;
        self.ooo_used = (self.ooo_used + after).saturating_sub(before);
        self.stats.ooo_bytes = self.ooo_used as u64;
    }

    /// Hands the application the buffered ranges the new `rcv_nxt` reached.
    /// Returns whether any was delivered.
    fn deliver_buffered(&mut self, c: ConnId, app: &mut impl App) -> bool {
        let mut any = false;
        loop {
            let Some(k) = self.conns.get_mut(c) else {
                return any;
            };
            let rcv_nxt = k.rcv_nxt;
            let Some(o) = k.ooo.as_mut() else {
                return any;
            };
            let before = o.bytes();
            let chunk = o.take_front(rcv_nxt);
            let after = o.bytes();
            if after == 0 {
                k.ooo = None;
            }
            self.ooo_used = self.ooo_used.saturating_sub(before - after);
            self.stats.ooo_bytes = self.ooo_used as u64;
            let Some(chunk) = chunk else {
                return any;
            };
            if let Some(k) = self.conns.get_mut(c) {
                k.rcv_nxt = k.rcv_nxt.wrapping_add(chunk.len() as u32);
            }
            if !chunk.is_empty() {
                any = true;
                // In slices: each call is one watchdog-supervised handler in
                // the application, and a hole that closes after half a
                // megabyte arrived must not look like one very long handler.
                for part in chunk.chunks(DELIVER_SLICE) {
                    app.data(c, part);
                }
            }
        }
    }

    /// ACK processing; returns false if the connection is gone or the
    /// segment must not be processed further.
    #[allow(clippy::too_many_arguments)]
    fn process_ack(
        &mut self,
        now_ms: u64,
        c: ConnId,
        h: &Header,
        pure: bool,
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) -> bool {
        let Some(k) = self.conn_mut(c) else {
            return false;
        };
        if gt(h.ack, k.snd_max) {
            // Acknowledges something never sent.
            self.send_ack_now(c, out);
            return false;
        }
        let mss = u32::from(k.mss);
        let peer_wnd = u32::from(h.window) << k.snd_shift;
        let window_changed = peer_wnd != k.snd_wnd;
        // Window update (RFC 793 SND.WL1/WL2 rule).
        if lt(k.snd_wl1, h.seq) || (k.snd_wl1 == h.seq && le(k.snd_wl2, h.ack)) {
            k.snd_wnd = peer_wnd;
            k.snd_wl1 = h.seq;
            k.snd_wl2 = h.ack;
        }
        let fresh = self.sack_input(c, h, now_ms);
        let Some(k) = self.conn_mut(c) else {
            return false;
        };
        if gt(h.ack, k.snd_una) {
            let acked = h.ack.wrapping_sub(k.snd_una);
            let data_acked = (acked as usize).min(k.tx_len());
            // Our FIN sits one past the last data byte.
            let fin_acked = k.has(FIN_SENT) && acked as usize == k.tx_len() + 1;
            if let Some(tx) = k.tx.as_mut() {
                tx.q.drain(..data_acked.min(tx.q.len()));
                if tx.q.is_empty() {
                    k.tx = None;
                } else if let Some(b) = tx.board.as_mut() {
                    b.advance(h.ack);
                    if b.is_empty() {
                        tx.board = None;
                    }
                }
            }
            // The timed segment is acknowledged: a round trip is over.
            let round = k.has(RTT_TIMING) && ge(h.ack, k.rtt_seq);
            if round {
                k.set(RTT_TIMING, false);
                let rtt = (now_ms as u32).wrapping_sub(k.rtt_start);
                Self::rtt_sample(k, rtt);
            }
            k.snd_una = h.ack;
            if lt(k.snd_nxt, k.snd_una) {
                k.snd_nxt = k.snd_una;
            }
            k.set_timeouts(0);
            if k.has(IN_RECOVERY) {
                let full = ge(h.ack, k.recover);
                let sack = k.has(SACK_OK);
                // With the peer's SACK blocks the window stays at the reduced
                // value and the holes the blocks name are sent again; without,
                // NewReno deflates and sends the next segment on a partial ACK.
                if full || !sack {
                    k.cc.on_recovery_ack(acked, mss, full);
                }
                if full {
                    k.set(IN_RECOVERY, false);
                    k.dupacks = 0;
                    if let Some(tx) = k.tx.as_mut() {
                        tx.board = None;
                    }
                } else if !sack {
                    // Partial ACK: retransmit the next hole (RFC 6582).
                    let una = k.snd_una;
                    self.retransmit_one(c, una, usize::MAX, out);
                }
            } else {
                k.dupacks = 0;
                let flight = k.flight();
                k.cc.on_ack(acked, mss, flight, round);
            }
            let Some(k) = self.conn_mut(c) else {
                return false;
            };
            if fin_acked {
                match k.state {
                    State::FinWait1 => {
                        k.state = State::FinWait2;
                        self.arm(c, now_ms, TimerKind::FinWait2, FIN_WAIT2_MS);
                    }
                    State::Closing | State::LastAck => {
                        // No TIME_WAIT (ADR-033).
                        self.close_with(c, CloseReason::Normal, app);
                        return false;
                    }
                    _ => {}
                }
            } else if k.snd_una == k.snd_max {
                self.disarm(c);
            } else {
                let rto = u64::from(k.rto);
                self.arm(c, now_ms, TimerKind::Retransmit, rto);
            }
            self.mark_dirty(c);
            self.sack_decide(c, now_ms);
        } else if h.ack == k.snd_una && pure && !window_changed && k.snd_max != k.snd_una {
            // Duplicate ACK.
            // A peer that reports its holes (SACK) is believed: its duplicate
            // ACKs without blocks are not evidence of a loss, and a loss is
            // acted on when the blocks say so (`sack_decide`). With blocks, a
            // duplicate ACK counts when they report new data (RFC 6675 §2): one
            // per segment that arrived above the hole.
            let has_board = k.tx.as_ref().is_some_and(|t| t.board.is_some());
            let classic = !k.has(SACK_OK) || !has_board;
            if classic || fresh {
                k.dupacks = k.dupacks.saturating_add(1);
            }
            if k.has(IN_RECOVERY) {
                if !k.has(SACK_OK) {
                    k.cc.on_dupack_in_recovery(mss);
                }
                self.mark_dirty(c);
            } else if classic && k.dupacks == 3 {
                let flight = k.flight();
                k.cc.on_fast_retransmit(flight, mss);
                k.set(IN_RECOVERY, true);
                k.recover = k.snd_max;
                k.set(RTT_TIMING, false);
                let una = k.snd_una;
                self.stats.fast_retransmits += 1;
                self.retransmit_one(c, una, usize::MAX, out);
            } else {
                self.sack_decide(c, now_ms);
            }
        } else if window_changed {
            self.mark_dirty(c);
        }
        true
    }

    /// Takes the SACK blocks of an ACK into the scoreboard (RFC 6675 §5): a
    /// block must lie within what was sent and not yet acknowledged to say
    /// anything, and the board holds a few ranges only. Returns whether the
    /// blocks told something new.
    fn sack_input(&mut self, c: ConnId, h: &Header, now_ms: u64) -> bool {
        let Some(k) = self.conn_mut(c) else {
            return false;
        };
        if !k.has(SACK_OK) || h.nsack == 0 {
            return false;
        }
        let (una, max) = (k.snd_una, k.snd_max);
        // A first block below the ACK's own cumulative number, or inside the
        // second block, reports data that arrived twice (RFC 2883): a
        // retransmission that was not needed, so reordering is what the network
        // does here and the wait before a loss is acted on grows.
        let first = h.sack.first().copied().unwrap_or((0, 0));
        let second = h.sack.get(1).copied().unwrap_or((0, 0));
        if h.nsack > 0
            && !ge(first.0, first.1)
            && (le(first.1, h.ack)
                || (h.nsack > 1 && le(second.0, first.0) && le(first.1, second.1)))
        {
            k.bump_reorder();
        }
        let Some(tx) = k.tx.as_mut() else {
            return false;
        };
        let mut fresh = false;
        for &(l, r) in h.sack.iter().take(usize::from(h.nsack)) {
            // At or below the cumulative ACK (a duplicate report) or beyond
            // what was sent: nothing to learn (RFC 2883, RFC 6675 §5 step 1).
            if le(r, una) || gt(r, max) || ge(l, r) {
                continue;
            }
            let l = if lt(l, una) { una } else { l };
            let b = tx
                .board
                .get_or_insert_with(|| Box::new(Board::new(now_ms as u32, una)));
            fresh |= b.insert(l, r);
        }
        if tx.board.as_ref().is_some_and(|b| b.is_empty()) {
            tx.board = None;
        }
        fresh
    }

    /// Whether the holes the peer reported make a recovery (RFC 6675 §4:
    /// more than two segments, or three ranges, SACKed above the first
    /// hole, or three duplicate ACKs, §5), once the hole has stayed that way
    /// for the reordering window (an eighth of the round trip, at least a
    /// millisecond: segments that the network reorders by a few places come
    /// in that time). A segment is the flow's own (ADR-268).
    fn sack_decide(&mut self, c: ConnId, now_ms: u64) {
        let Some(k) = self.conn_mut(c) else { return };
        if k.has(IN_RECOVERY) || !k.has(SACK_OK) {
            return;
        }
        let (una, seg) = (k.snd_una, k.seg_size());
        let dupthresh = k.dupacks >= 3;
        // The reordering window: an eighth of the round trip, doubled for every
        // retransmission that proved needless, but not more than a round trip.
        let rtt = u32::from(k.srtt).max(4);
        let reo = ((rtt / 8).max(1) << k.reorder()).min(rtt);
        let flight = k.flight();
        let now = now_ms as u32;
        let Some(b) = k.tx.as_mut().and_then(|t| t.board.as_mut()) else {
            return;
        };
        if !(b.first_hole_lost(una, seg) || (dupthresh && b.hole_at(una))) {
            b.since = 0;
            return;
        }
        if b.since == 0 {
            b.since = now.max(1);
        }
        if now.wrapping_sub(b.since) < reo {
            // Looked at again at the next pass.
            self.mark_dirty(c);
            return;
        }
        b.next = una;
        k.cc.on_fast_retransmit(flight, u32::from(k.mss));
        // The pipe, not inflation, paces what is sent in this recovery.
        k.cc.cwnd = k.cc.ssthresh();
        k.set(IN_RECOVERY, true);
        k.recover = k.snd_max;
        k.set(RTT_TIMING, false);
        self.stats.fast_retransmits += 1;
        self.mark_dirty(c);
    }

    /// Sends the holes the scoreboard calls lost, each once, while the pipe
    /// leaves room for a segment.
    fn sack_resend(&mut self, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) -> bool {
        let mut sent = false;
        loop {
            let Some(k) = self.conn(c) else { return sent };
            let Some(pipe) = k.sack_pipe() else {
                return sent;
            };
            let (mss, seg) = (k.eff_mss() as u32, k.seg_size());
            // Room for a segment of the flow's size: a window cut to a few small
            // segments still repairs them.
            if k.cc.window().saturating_sub(pipe) < seg {
                return sent;
            }
            let Some((seq, len)) =
                k.tx.as_ref()
                    .and_then(|t| t.board.as_ref())
                    .and_then(|b| b.next_hole(k.snd_una, seg, mss))
            else {
                return sent;
            };
            self.retransmit_one(c, seq, len as usize, out);
            sent = true;
            if let Some(b) = self
                .conn_mut(c)
                .and_then(|k| k.tx.as_mut())
                .and_then(|t| t.board.as_mut())
            {
                b.next = seq.wrapping_add(len);
            }
        }
    }

    /// Sends one segment starting at `from`, of at most `limit` bytes (a
    /// retransmission).
    fn retransmit_one(
        &mut self,
        c: ConnId,
        from: u32,
        limit: usize,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        let Some(k) = self.conn(c) else { return };
        let off = from.wrapping_sub(k.snd_una) as usize;
        let mss = k.eff_mss().min(limit);
        let mut payload = [0u8; MAX_MSS as usize];
        let n = k.tx.as_ref().map_or(0, |tx| {
            let avail = tx.q.len().saturating_sub(off).min(mss).min(payload.len());
            copy_out(&tx.q, off, payload.get_mut(..avail).unwrap_or(&mut []))
        });
        let x = self.ext_of(k, false);
        // Our FIN follows the last data byte.
        let fin = k.has(FIN_SENT) && off + n == k.tx_len();
        if n == 0 && !fin {
            return;
        }
        let o = Out {
            sport: k.key.lport,
            dport: k.key.rport,
            seq: from,
            ack: k.rcv_nxt,
            flags: ACK | if fin { FIN } else { 0 } | if n > 0 { PSH } else { 0 },
            window: k.window(),
            mss: None,
        };
        let dst = k.key.addr;
        self.emit_x(dst, &o, &x, payload.get(..n).unwrap_or(&[]), out);
        self.stats.retransmits += 1;
        if let Some(k) = self.conn_mut(c) {
            k.set(ACK_PENDING, false);
            k.ack_segs = 0;
        }
    }

    /// Sends what the windows allow (data, then FIN), from `snd_nxt`.
    /// Returns whether a segment went out (it carried the pending ACK).
    fn transmit(&mut self, now_ms: u64, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) -> bool {
        // The holes of a SACK recovery go first; the loss itself may be decided now.
        self.sack_decide(c, now_ms);
        let mut sent_any = self.sack_resend(c, out);
        loop {
            let Some(k) = self.conn(c) else {
                return sent_any;
            };
            let mss = k.eff_mss();
            let data_len = k.tx_len();
            // Offset of `snd_nxt` from `snd_una`; past `data_len` once our
            // FIN went out.
            let off = k.snd_nxt.wrapping_sub(k.snd_una) as usize;
            let unsent = data_len.saturating_sub(off);
            let wnd = k.snd_wnd.min(k.cc.window()) as usize;
            let room = match k.sack_pipe() {
                // In a SACK recovery the pipe says how much is in the network,
                // the peer's window where the right edge is.
                Some(pipe) => (k.cc.window().saturating_sub(pipe) as usize)
                    .min((k.snd_wnd as usize).saturating_sub(off.min(data_len))),
                None => wnd.saturating_sub(off.min(data_len)),
            };
            let n = unsent.min(room).min(mss);
            // The FIN goes out once (and again only as a retransmission, from
            // `snd_una`, while it is unacknowledged). Once it is acknowledged
            // (`snd_una == snd_max` with FIN_SENT) the acknowledged data is
            // gone and `off == data_len == 0`, so without this test every ACK
            // in FIN-WAIT-2 sent a new FIN one sequence number further, and a
            // peer that acknowledges each one kept both sides busy forever
            // (A261-W1, ADR-261).
            let fin_acked = k.has(FIN_SENT) && k.snd_una == k.snd_max;
            let fin = k.has(FIN_QUEUED) && !fin_acked && off <= data_len && off + n == data_len;
            if n == 0 && !fin {
                // Zero window with data waiting: probe later.
                let persist = unsent > 0 && k.snd_wnd == 0 && k.timer.is_none();
                let rto = u64::from(k.rto);
                if persist {
                    self.arm(c, now_ms, TimerKind::Persist, rto);
                }
                return sent_any;
            }
            let mut payload = [0u8; MAX_MSS as usize];
            if let Some(tx) = k.tx.as_ref() {
                copy_out(&tx.q, off, payload.get_mut(..n).unwrap_or(&mut []));
            }
            // A segment with data carries no SACK blocks (no room next to the
            // payload); the next pure ACK does.
            let x = self.ext_of(k, false);
            let o = Out {
                sport: k.key.lport,
                dport: k.key.rport,
                seq: k.snd_nxt,
                ack: k.rcv_nxt,
                flags: ACK | if n > 0 { PSH } else { 0 } | if fin { FIN } else { 0 },
                window: k.window(),
                mss: None,
            };
            let dst = k.key.addr;
            self.emit_x(dst, &o, &x, payload.get(..n).unwrap_or(&[]), out);
            sent_any = true;
            let Some(k) = self.conn_mut(c) else {
                return true;
            };
            k.set(ACK_PENDING, false);
            k.ack_segs = 0;
            k.rcv_adv = k.adv_edge(o.window);
            k.snd_nxt = k.snd_nxt.wrapping_add(n as u32 + u32::from(fin));
            if gt(k.snd_nxt, k.snd_max) {
                k.snd_max = k.snd_nxt;
            }
            let flight = k.flight();
            k.cc.on_sent(flight);
            // A running average over about four segments (ADR-268) of the
            // segments the application decided: full ones and those that sent
            // all it had. A segment the window cut short says nothing about
            // the flow (a bulk transfer sends a few of them after every ACK).
            if let Some(t) = k.tx.as_mut()
                && n > 0
                && (n == mss || n == unsent)
            {
                let n = n.min(usize::from(u16::MAX)) as u32;
                t.seg = match u32::from(t.seg) {
                    0 => n,
                    s => (3 * s + n).div_ceil(4),
                } as u16;
            }
            if !k.has(RTT_TIMING) && n > 0 && k.snd_nxt == k.snd_max {
                k.set(RTT_TIMING, true);
                k.rtt_seq = k.snd_nxt;
                k.rtt_start = now_ms as u32;
            }
            if fin && !k.has(FIN_SENT) {
                k.set(FIN_SENT, true);
                k.state = match k.state {
                    State::Established => State::FinWait1,
                    State::CloseWait => State::LastAck,
                    s => s,
                };
            }
            if !matches!(k.timer, Some((_, TimerKind::Retransmit))) {
                let rto = u64::from(k.rto);
                self.arm(c, now_ms, TimerKind::Retransmit, rto);
            }
            if fin {
                return true;
            }
        }
    }

    /// End of an event-loop pass: sends queued data and FINs, and the ACKs
    /// no reply has carried (coalescing).
    /// Rotates the SYN-cookie key (H3); the old key still validates the
    /// cookies it issued for their lifetime.
    pub fn rotate_cookie_key(&mut self, key: [u8; 16], now_ms: u64) {
        self.cookies.rotate(key, now_ms / 1000);
        self.stats.cookie_rotations += 1;
    }

    pub fn flush(&mut self, now_ms: u64, out: &mut impl FnMut([u8; 4], &[u8])) {
        self.clock = now_ms as u32;
        let dirty = core::mem::take(&mut self.dirty);
        for &c in &dirty {
            if let Some(k) = self.conn_mut(c) {
                k.set(IN_DIRTY, false);
            }
            let sent = self.transmit(now_ms, c, out);
            if !sent && self.conn(c).is_some_and(|k| k.has(ACK_PENDING)) {
                self.send_ack_now(c, out);
            }
        }
        let mut dirty = dirty;
        dirty.clear();
        if self.dirty.is_empty() {
            self.dirty = dirty;
        }
    }

    /// Runs expired timers (retransmission, persist, FIN-WAIT-2).
    pub fn poll(&mut self, now_ms: u64, app: &mut impl App, out: &mut impl FnMut([u8; 4], &[u8])) {
        self.clock = now_ms as u32;
        let mut due: Vec<u32> = Vec::new();
        self.wheel.advance(now_ms, |c| due.push(c));
        for c in due {
            let Some(k) = self.conn_mut(c) else { continue };
            let Some((_, kind)) = k.timer.take() else {
                continue;
            };
            match kind {
                TimerKind::FinWait2 => self.close_with(c, CloseReason::Timeout, app),
                TimerKind::Persist => {
                    if k.snd_wnd == 0 && k.tx_len() > 0 {
                        // Window probe: one byte beyond the window. Every
                        // probe is that same first unacknowledged byte: a
                        // probe the peer did not take is sent again, so a
                        // lost window update cannot stall the connection
                        // (H3; before, the second probe sent nothing).
                        k.rto = k.rto.saturating_mul(2).min(RTO_MAX_MS);
                        let rto = u64::from(k.rto);
                        k.snd_nxt = k.snd_una;
                        let saved = k.snd_wnd;
                        k.snd_wnd = 1;
                        self.transmit(now_ms, c, out);
                        if let Some(k) = self.conn_mut(c) {
                            k.snd_wnd = saved;
                        }
                        self.arm(c, now_ms, TimerKind::Persist, rto);
                    }
                }
                TimerKind::Retransmit => {
                    if k.snd_una == k.snd_max {
                        continue;
                    }
                    k.set_timeouts(k.timeouts() + 1);
                    if k.timeouts() > MAX_RETRIES {
                        self.stats.timeouts += 1;
                        self.close_with(c, CloseReason::Timeout, app);
                        continue;
                    }
                    let mss = u32::from(k.mss);
                    let flight = k.flight();
                    k.cc.on_timeout(flight, mss);
                    k.set(IN_RECOVERY, false);
                    k.dupacks = 0;
                    if let Some(tx) = k.tx.as_mut() {
                        tx.board = None;
                    }
                    k.set(RTT_TIMING, false);
                    k.rto = k.rto.saturating_mul(2).min(RTO_MAX_MS);
                    // Go back to the first unacknowledged byte (Karn: no RTT
                    // sample from retransmitted data).
                    k.snd_nxt = k.snd_una;
                    let rto = u64::from(k.rto);
                    self.stats.retransmits += 1;
                    self.stats.rto_fired += 1;
                    self.transmit(now_ms, c, out);
                    self.arm(c, now_ms, TimerKind::Retransmit, rto);
                }
            }
        }
    }

    /// When the next timer is due (for idle sleeping), if any.
    pub fn next_timer(&self) -> Option<u64> {
        (!self.wheel.is_empty()).then(|| self.wheel.now() + 1)
    }

    /// Whether `flush` has work.
    /// Returns memory a past peak left behind: empty connection chunks and
    /// table slots (M16). Callers run it every few seconds.
    pub fn shrink(&mut self) {
        self.conns.shrink();
        let conns = &self.conns;
        self.table.shrink(|c| conns.get(c).map(|k| k.key));
    }

    pub fn has_pending(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// The connection with the most data queued for sending (looking at no
    /// more than 8 192 of them), for the log: where a flow's rate is decided.
    pub fn busiest_sender(&self) -> Option<SendInfo> {
        self.conns
            .iter()
            .take(8192)
            .map(|(_, k)| k)
            .max_by_key(|k| k.tx_len())
            .filter(|k| k.tx_len() > 0)
            .map(|k| SendInfo {
                queued: k.tx_len(),
                in_flight: k.flight(),
                cwnd: k.cc.window(),
                ssthresh: k.cc.ssthresh(),
                peer_window: k.snd_wnd,
                srtt_ms: k.srtt,
                rto_ms: k.rto,
                recovering: k.has(IN_RECOVERY),
            })
    }
}

/// What [`TcpStack::busiest_sender`] reports.
#[derive(Debug, Clone, Copy)]
pub struct SendInfo {
    /// Bytes queued: unacknowledged and unsent.
    pub queued: usize,
    /// Bytes sent and not acknowledged.
    pub in_flight: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
    /// The window the peer announces (scaled).
    pub peer_window: u32,
    pub srtt_ms: u16,
    pub rto_ms: u16,
    pub recovering: bool,
}

/// Copies `dst.len()` bytes of `tx` starting at `off` into `dst`; returns how
/// many it could copy.
fn copy_out(tx: &VecDeque<u8>, off: usize, dst: &mut [u8]) -> usize {
    let (a, b) = tx.as_slices();
    let mut n = 0;
    let mut skip = off;
    for part in [a, b] {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let src = part.get(skip..).unwrap_or(&[]);
        skip = 0;
        let take = src.len().min(dst.len() - n);
        if let (Some(d), Some(s)) = (dst.get_mut(n..n + take), src.get(..take)) {
            d.copy_from_slice(s);
        }
        n += take;
        if n == dst.len() {
            break;
        }
    }
    n
}

#[cfg(kani)]
mod proofs;
