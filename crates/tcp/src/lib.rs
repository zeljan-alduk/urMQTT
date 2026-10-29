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
//! - In-order receive only: an out-of-order segment is dropped and answered
//!   with a duplicate ACK, which triggers the sender's fast retransmit.

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
mod siphash;
pub mod table;
pub mod wire;

#[cfg(test)]
mod tests;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use cc::{Congestion, NewReno};
use cookie::Cookies;
use seq::{ge, gt, le, lt};
use table::{Key, Table};
use urmqtt_mm::slab::Slab;
use urmqtt_timer_wheel::{TimerId, Wheel};
use wire::{ACK, FIN, Header, Out, PSH, RST, SYN};

pub type ConnId = u32;

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
    /// MSS we announce (Ethernet MTU 1500 minus headers).
    pub mss: u16,
    /// Receive window when the application has not set one.
    pub rcv_wnd: u16,
    pub max_conns: usize,
    /// Most bytes queued for sending per connection.
    pub tx_max: usize,
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
    pub retransmits: u64,
    pub fast_retransmits: u64,
    pub timeouts: u64,
    pub rst_sent: u64,
    pub rst_limited: u64,
    pub out_of_order: u64,
    pub refused_full: u64,
    pub accepted: u64,
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
    retries: u8,
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
    /// Bytes from `snd_una` on: unacknowledged, then unsent. Boxed so an
    /// idle connection pays 8 bytes for it instead of 32.
    #[allow(clippy::box_collection)]
    tx: Option<Box<VecDeque<u8>>>,
}

/// FIN queued by the application (sent after the data).
const FIN_QUEUED: u8 = 1;
const FIN_SENT: u8 = 2;
/// An ACK is owed; sent by `flush` unless data carries it first.
const ACK_PENDING: u8 = 4;
const IN_DIRTY: u8 = 8;
const IN_RECOVERY: u8 = 16;
const RTT_TIMING: u8 = 32;

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
        self.tx.as_ref().map_or(0, |b| b.len())
    }

    /// Data bytes in flight (sent, not acknowledged), excluding our FIN.
    fn flight(&self) -> u32 {
        (self.snd_max.wrapping_sub(self.snd_una) as usize).min(self.tx_len()) as u32
    }

    fn window(&self) -> u16 {
        // The advertised window never shrinks below what was promised.
        let edge = self.rcv_nxt.wrapping_add(self.rcv_space);
        let edge = if gt(edge, self.rcv_adv) {
            edge
        } else {
            self.rcv_adv
        };
        edge.wrapping_sub(self.rcv_nxt).min(65535) as u16
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
    buf: Vec<u8>,
    pub stats: Stats,
}

impl TcpStack {
    pub fn new(cfg: Config, now_ms: u64) -> Self {
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
            buf: Vec::with_capacity(1600),
            cfg,
            stats: Stats::default(),
        }
    }

    /// Our address changed (DHCP); existing connections keep theirs.
    pub fn set_local_addr(&mut self, addr: [u8; 4]) {
        self.cfg.local_addr = addr;
    }

    pub fn local_addr(&self) -> [u8; 4] {
        self.cfg.local_addr
    }

    pub fn connections(&self) -> usize {
        self.table.len()
    }

    /// Bytes the application may still queue on `c`.
    pub fn send_space(&self, c: ConnId) -> usize {
        self.conn(c)
            .map_or(0, |k| self.cfg.tx_max.saturating_sub(k.tx_len()))
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
            k.rcv_space = bytes.min(65535);
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
        let max = self.cfg.tx_max;
        let Some(k) = self.conn_mut(c) else { return 0 };
        if k.has(FIN_QUEUED) || !matches!(k.state, State::Established | State::CloseWait) {
            return 0;
        }
        let n = data.len().min(max.saturating_sub(k.tx_len()));
        if n > 0 {
            let tx = k.tx.get_or_insert_with(|| Box::new(VecDeque::new()));
            tx.extend(data.get(..n).unwrap_or(&[]));
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
        let mut buf = core::mem::take(&mut self.buf);
        wire::emit(self.cfg.local_addr, dst, o, payload, &mut buf);
        out(dst, &buf);
        self.buf = buf;
        self.stats.segs_out += 1;
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
            self.emit(src, &o, &[], out);
            self.stats.cookies_sent += 1;
            return;
        }
        if h.flags & (SYN | RST) != 0 || h.flags & ACK == 0 {
            self.reset_unknown(now_ms, src, h, payload.len() as u32, out);
            return;
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
        let conn = Conn {
            key,
            state: State::Established,
            flags: 0,
            dupacks: 0,
            retries: 0,
            mss,
            snd_una: h.ack,
            snd_nxt: h.ack,
            snd_max: h.ack,
            snd_wnd: u32::from(h.window),
            snd_wl1: h.seq,
            snd_wl2: h.ack,
            recover: h.ack,
            rcv_nxt: h.seq,
            rcv_space: u32::from(self.cfg.rcv_wnd),
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
            self.abort(c, out);
            return;
        }
        // Data (or FIN) may ride on the final ACK.
        if !payload.is_empty() || h.flags & FIN != 0 {
            self.segment(now_ms, c, h, payload, app, out);
        }
    }

    fn send_ack_now(&mut self, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) {
        let Some(k) = self.conn_mut(c) else { return };
        k.set(ACK_PENDING, false);
        let o = Out {
            sport: k.key.lport,
            dport: k.key.rport,
            seq: k.snd_nxt,
            ack: k.rcv_nxt,
            flags: ACK,
            window: k.window(),
            mss: None,
        };
        k.rcv_adv = k.rcv_nxt.wrapping_add(u32::from(o.window));
        let dst = k.key.addr;
        self.emit(dst, &o, &[], out);
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
        let wnd = u32::from(k.window()).max(1);
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
        // Data, in order only.
        let Some(k) = self.conn_mut(c) else { return };
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
                self.send_ack_now(c, out);
                return;
            }
            if !k.can_receive() {
                data = &[];
            }
            let room = u32::from(k.window()) as usize;
            let n = data.len().min(room);
            let fin = h.flags & FIN != 0 && n == data.len();
            let take = data.get(..n).unwrap_or(&[]);
            // The application consumes data synchronously; `rcv_space` is
            // its backpressure limit, not a buffer that fills up.
            k.rcv_nxt = k.rcv_nxt.wrapping_add(n as u32);
            // Even a segment that did not fit (a zero-window probe) is
            // answered, with the current window.
            k.set(ACK_PENDING, true);
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
            if !take.is_empty() {
                app.data(c, take);
            }
            if fin {
                app.peer_closed(c);
                // A FIN is acknowledged right away.
                self.send_ack_now(c, out);
            } else {
                self.mark_dirty(c);
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
        let window_changed = u32::from(h.window) != k.snd_wnd;
        // Window update (RFC 793 SND.WL1/WL2 rule).
        if lt(k.snd_wl1, h.seq) || (k.snd_wl1 == h.seq && le(k.snd_wl2, h.ack)) {
            k.snd_wnd = u32::from(h.window);
            k.snd_wl1 = h.seq;
            k.snd_wl2 = h.ack;
        }
        if gt(h.ack, k.snd_una) {
            let acked = h.ack.wrapping_sub(k.snd_una);
            let data_acked = (acked as usize).min(k.tx_len());
            // Our FIN sits one past the last data byte.
            let fin_acked = k.has(FIN_SENT) && acked as usize == k.tx_len() + 1;
            if let Some(tx) = k.tx.as_mut() {
                tx.drain(..data_acked.min(tx.len()));
                if tx.is_empty() {
                    k.tx = None;
                }
            }
            if k.has(RTT_TIMING) && ge(h.ack, k.rtt_seq) {
                k.set(RTT_TIMING, false);
                let rtt = (now_ms as u32).wrapping_sub(k.rtt_start);
                Self::rtt_sample(k, rtt);
            }
            k.snd_una = h.ack;
            if lt(k.snd_nxt, k.snd_una) {
                k.snd_nxt = k.snd_una;
            }
            k.retries = 0;
            if k.has(IN_RECOVERY) {
                let full = ge(h.ack, k.recover);
                k.cc.on_recovery_ack(acked, mss, full);
                if full {
                    k.set(IN_RECOVERY, false);
                    k.dupacks = 0;
                } else {
                    // Partial ACK: retransmit the next hole (RFC 6582).
                    let una = k.snd_una;
                    self.retransmit_one(c, una, out);
                }
            } else {
                k.dupacks = 0;
                k.cc.on_ack(acked, mss);
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
        } else if h.ack == k.snd_una && pure && !window_changed && k.snd_max != k.snd_una {
            // Duplicate ACK.
            k.dupacks = k.dupacks.saturating_add(1);
            if k.has(IN_RECOVERY) {
                k.cc.on_dupack_in_recovery(mss);
                self.mark_dirty(c);
            } else if k.dupacks == 3 {
                let flight = k.flight();
                k.cc.on_fast_retransmit(flight, mss);
                k.set(IN_RECOVERY, true);
                k.recover = k.snd_max;
                k.set(RTT_TIMING, false);
                let una = k.snd_una;
                self.stats.fast_retransmits += 1;
                self.retransmit_one(c, una, out);
            }
        } else if window_changed {
            self.mark_dirty(c);
        }
        true
    }

    /// Sends one segment starting at `from` (a retransmission).
    fn retransmit_one(&mut self, c: ConnId, from: u32, out: &mut impl FnMut([u8; 4], &[u8])) {
        let Some(k) = self.conn(c) else { return };
        let off = from.wrapping_sub(k.snd_una) as usize;
        let mss = usize::from(k.mss);
        let mut payload = [0u8; 1460];
        let n = k.tx.as_ref().map_or(0, |tx| {
            let avail = tx.len().saturating_sub(off).min(mss).min(payload.len());
            for (i, b) in tx.range(off..off + avail).enumerate() {
                if let Some(p) = payload.get_mut(i) {
                    *p = *b;
                }
            }
            avail
        });
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
        self.emit(dst, &o, payload.get(..n).unwrap_or(&[]), out);
        self.stats.retransmits += 1;
        if let Some(k) = self.conn_mut(c) {
            k.set(ACK_PENDING, false);
        }
    }

    /// Sends what the windows allow (data, then FIN), from `snd_nxt`.
    /// Returns whether a segment went out (it carried the pending ACK).
    fn transmit(&mut self, now_ms: u64, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) -> bool {
        let mut sent_any = false;
        loop {
            let Some(k) = self.conn(c) else {
                return sent_any;
            };
            let mss = usize::from(k.mss);
            let data_len = k.tx_len();
            // Offset of `snd_nxt` from `snd_una`; past `data_len` once our
            // FIN went out.
            let off = k.snd_nxt.wrapping_sub(k.snd_una) as usize;
            let unsent = data_len.saturating_sub(off);
            let wnd = k.snd_wnd.min(k.cc.window()) as usize;
            let room = wnd.saturating_sub(off.min(data_len));
            let n = unsent.min(room).min(mss);
            let fin = k.has(FIN_QUEUED) && off <= data_len && off + n == data_len;
            if n == 0 && !fin {
                // Zero window with data waiting: probe later.
                let persist = unsent > 0 && k.snd_wnd == 0 && k.timer.is_none();
                let rto = u64::from(k.rto);
                if persist {
                    self.arm(c, now_ms, TimerKind::Persist, rto);
                }
                return sent_any;
            }
            let mut payload = [0u8; 1460];
            if let Some(tx) = k.tx.as_ref() {
                for (i, b) in tx.range(off..off + n).enumerate() {
                    if let Some(p) = payload.get_mut(i) {
                        *p = *b;
                    }
                }
            }
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
            self.emit(dst, &o, payload.get(..n).unwrap_or(&[]), out);
            sent_any = true;
            let Some(k) = self.conn_mut(c) else {
                return true;
            };
            k.set(ACK_PENDING, false);
            k.rcv_adv = k.rcv_nxt.wrapping_add(u32::from(o.window));
            k.snd_nxt = k.snd_nxt.wrapping_add(n as u32 + u32::from(fin));
            if gt(k.snd_nxt, k.snd_max) {
                k.snd_max = k.snd_nxt;
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
    pub fn flush(&mut self, now_ms: u64, out: &mut impl FnMut([u8; 4], &[u8])) {
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
                        // Window probe: one byte beyond the window.
                        k.rto = k.rto.saturating_mul(2).min(RTO_MAX_MS);
                        let rto = u64::from(k.rto);
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
                    k.retries += 1;
                    if k.retries > MAX_RETRIES {
                        self.stats.timeouts += 1;
                        self.close_with(c, CloseReason::Timeout, app);
                        continue;
                    }
                    let mss = u32::from(k.mss);
                    let flight = k.flight();
                    k.cc.on_timeout(flight, mss);
                    k.set(IN_RECOVERY, false);
                    k.dupacks = 0;
                    k.set(RTT_TIMING, false);
                    k.rto = k.rto.saturating_mul(2).min(RTO_MAX_MS);
                    // Go back to the first unacknowledged byte (Karn: no RTT
                    // sample from retransmitted data).
                    k.snd_nxt = k.snd_una;
                    let rto = u64::from(k.rto);
                    self.stats.retransmits += 1;
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
    pub fn has_pending(&self) -> bool {
        !self.dirty.is_empty()
    }
}
