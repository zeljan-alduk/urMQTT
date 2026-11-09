//! Active open (NEXT-7, ADR-315): the client side of the stack.
//!
//! A connection opened here starts in SYN-SENT, the only half-open state
//! the stack keeps (a passive open keeps none, thanks to the SYN cookies).
//! It is bounded by [`TcpStack::set_max_active`], which is 0 until the
//! kernel allows outbound connections: a server-only stack can never open
//! one. Everything after the handshake is the code the server side uses.
//!
//! - **Initial sequence number** (RFC 6528): a keyed hash of the 4-tuple
//!   plus a 4 µs clock, the key derived from the SYN-cookie key. The first
//!   SYN is not predictable from outside, and a reused 4-tuple starts far
//!   from where the previous one ended.
//! - **SYN retransmission** with exponential backoff (1, 2, 4, 8, 16 s by
//!   default, then the connection is given up: [`CloseReason::Timeout`]).
//! - **Ephemeral ports** (RFC 6056 algorithm 3 in spirit): a keyed hash
//!   chooses where the search through 49152..=65535 starts; a port that a
//!   listener uses, that the caller reserves (the ports core 0 steers to the
//!   worker cores) or that the same 4-tuple already uses is skipped.
//! - **SYN-SENT rules** (RFC 9293 §3.10.7.3): an ACK outside ISS+1 gets a
//!   RST and is dropped; a RST with an acceptable ACK refuses the
//!   connection; a SYN without an ACK (simultaneous open) is dropped, the
//!   peer's retransmission or ours sorts it out. Options are negotiated from
//!   the SYN-ACK: MSS (an MSS below 536 is refused, as on the server side),
//!   window scaling, SACK and timestamps.

use super::*;
use siphash::SipHasher;

/// SYN retransmissions before an active open is given up: with the initial
/// RTO of 1 s the SYNs leave at 0, 1, 3, 7, 15 and 31 s, and the connection
/// is closed with [`CloseReason::Timeout`] at 63 s.
pub const SYN_RETRIES: u8 = 5;
/// The most SYN retries [`TcpStack::set_syn_retries`] accepts.
pub const MAX_SYN_RETRIES: u8 = 10;
/// The ephemeral port range (RFC 6335 §6, the dynamic ports).
pub const EPHEMERAL_FIRST: u16 = 49152;
pub const EPHEMERAL_LAST: u16 = 65535;
/// The most active connections one stack may be allowed.
pub const MAX_ACTIVE_LIMIT: usize = 64;

/// Why [`TcpStack::connect`] did not start a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// Outbound connections are not allowed ([`TcpStack::set_max_active`]
    /// is 0) or all of them are in use.
    NotAllowed,
    /// The stack has no address yet (no DHCP lease).
    NoAddress,
    /// The connection table is full.
    TableFull,
    /// The local port is 0, a listener's, or the 4-tuple exists.
    PortInUse,
    /// The destination is not a unicast address and port: 0.0.0.0, a
    /// broadcast, multicast or loopback address, our own address, port 0.
    BadDestination,
}

/// The secret of the initial sequence numbers and the port choice: two
/// SipHash outputs of the cookie key under their own domain, so neither
/// reveals anything about the other or about the cookie key.
pub(crate) fn isn_key(cookie_key: &[u8; 16]) -> [u8; 16] {
    let mut k = [0u8; 16];
    for (i, half) in k.chunks_mut(8).enumerate() {
        let mut h = SipHasher::new(cookie_key);
        h.write(b"urmqtt-tcp-isn");
        h.write(&[i as u8]);
        half.copy_from_slice(&h.finish().to_le_bytes());
    }
    k
}

/// Whether `a` can be the far end of a connection: not 0.0.0.0/8, not
/// 127.0.0.0/8, not multicast or reserved (224.0.0.0/3, which includes the
/// limited broadcast).
pub fn unicast(a: [u8; 4]) -> bool {
    !matches!(a[0], 0 | 127 | 224..=255)
}

impl TcpStack {
    /// How many active connections (SYN-SENT or open) this stack may have,
    /// at most [`MAX_ACTIVE_LIMIT`]. 0, the default, refuses every
    /// [`TcpStack::connect`]. Lowering it closes nothing.
    pub fn set_max_active(&mut self, n: usize) {
        self.max_active = n.min(MAX_ACTIVE_LIMIT);
    }

    /// SYN retransmissions before an active open is given up (1 to
    /// [`MAX_SYN_RETRIES`]; the default is [`SYN_RETRIES`]).
    pub fn set_syn_retries(&mut self, n: u8) {
        self.syn_retries = n.clamp(1, MAX_SYN_RETRIES);
    }

    /// Active connections now (SYN-SENT or later).
    pub fn active_connections(&self) -> usize {
        self.active.len()
    }

    /// Whether `c` exists and has completed its handshake.
    pub fn is_established(&self, c: ConnId) -> bool {
        self.conn(c).is_some_and(|k| k.state != State::SynSent)
    }

    /// The local port of `c`.
    pub fn local_port(&self, c: ConnId) -> Option<u16> {
        self.conn(c).map(|k| k.key.lport)
    }

    /// RFC 6528: a keyed hash of the connection's identity plus a clock
    /// that moves by one every 4 µs (here: 250 per millisecond).
    pub(crate) fn isn(&self, key: &Key, now_ms: u64) -> u32 {
        let mut h = SipHasher::new(&self.isn_key);
        h.write(&self.cfg.local_addr);
        h.write(&key.lport.to_be_bytes());
        h.write(&key.addr);
        h.write(&key.rport.to_be_bytes());
        (h.finish() as u32).wrapping_add((now_ms as u32).wrapping_mul(250))
    }

    /// A free ephemeral port for a connection to `remote`: not a listener's,
    /// not one `reserved` names, and not in use towards `remote` already.
    /// Where the search starts is a keyed hash of the destination, the clock
    /// and a counter, so consecutive connections do not use neighbouring
    /// ports. `None` when every port is taken.
    pub fn ephemeral_port(
        &mut self,
        remote: Endpoint,
        reserved: impl Fn(u16) -> bool,
    ) -> Option<u16> {
        let span = u32::from(EPHEMERAL_LAST - EPHEMERAL_FIRST) + 1;
        let mut h = SipHasher::new(&self.isn_key);
        h.write(b"port");
        h.write(&remote.addr);
        h.write(&remote.port.to_be_bytes());
        h.write(&self.port_salt.to_le_bytes());
        h.write(&self.clock.to_le_bytes());
        self.port_salt = self.port_salt.wrapping_add(1);
        let start = (h.finish() % u64::from(span)) as u32;
        let conns = &self.conns;
        for i in 0..span {
            let p = EPHEMERAL_FIRST + ((start + i) % span) as u16;
            if self.cfg.ports.contains(&p) || reserved(p) {
                continue;
            }
            let key = Key {
                addr: remote.addr,
                rport: remote.port,
                lport: p,
            };
            if self
                .table
                .get(&key, |c| conns.get(c).map(|k| k.key))
                .is_none()
            {
                return Some(p);
            }
        }
        None
    }

    /// Opens a connection from `lport` to `remote`: sends the SYN now and
    /// returns the connection, which the application hears of again through
    /// [`App::connected`] or [`App::closed`] (refused, timed out). The local
    /// port comes from [`TcpStack::ephemeral_port`]. Data can be sent once
    /// the connection is established ([`TcpStack::send`] takes nothing
    /// before); [`TcpStack::close`] before that sends the FIN after the
    /// handshake, [`TcpStack::abort`] gives up at once.
    pub fn connect(
        &mut self,
        now_ms: u64,
        remote: Endpoint,
        lport: u16,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) -> Result<ConnId, ConnectError> {
        self.clock = now_ms as u32;
        if self.active.len() >= self.max_active {
            return Err(ConnectError::NotAllowed);
        }
        let local = self.cfg.local_addr;
        if local == [0; 4] {
            return Err(ConnectError::NoAddress);
        }
        if !unicast(remote.addr) || remote.addr == local || remote.port == 0 {
            return Err(ConnectError::BadDestination);
        }
        if lport == 0 || self.cfg.ports.contains(&lport) {
            return Err(ConnectError::PortInUse);
        }
        if !self.table.has_room() || self.table.len() >= self.cfg.max_conns {
            return Err(ConnectError::TableFull);
        }
        let key = Key {
            addr: remote.addr,
            rport: remote.port,
            lport,
        };
        let conns = &self.conns;
        if self
            .table
            .get(&key, |c| conns.get(c).map(|k| k.key))
            .is_some()
        {
            return Err(ConnectError::PortInUse);
        }
        let iss = self.isn(&key, now_ms);
        let mss = self.cfg.mss;
        let conn = Conn {
            key,
            state: State::SynSent,
            flags: RTT_TIMING,
            dupacks: 0,
            retries: 0,
            ack_segs: 0,
            mss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_max: iss.wrapping_add(1),
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: iss,
            recover: iss,
            rcv_nxt: 0,
            rcv_space: u32::from(self.cfg.rcv_wnd),
            snd_shift: 0,
            rcv_shift: 0,
            ts_recent: 0,
            ooo: None,
            rcv_adv: 0,
            rtt_seq: iss.wrapping_add(1),
            rtt_start: now_ms as u32,
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
        self.active.push(c);
        self.stats.active_opens += 1;
        self.send_syn(c, out);
        self.arm(c, now_ms, TimerKind::Retransmit, u64::from(RTO_INIT_MS));
        Ok(c)
    }

    /// Our SYN: the MSS of the link, and the options this stack can use
    /// (SACK-permitted, timestamps, window scaling when configured).
    fn send_syn(&mut self, c: ConnId, out: &mut impl FnMut([u8; 4], &[u8])) {
        let Some(k) = self.conn(c) else { return };
        let o = Out {
            sport: k.key.lport,
            dport: k.key.rport,
            seq: k.snd_una,
            ack: 0,
            flags: SYN,
            window: self.cfg.rcv_wnd,
            mss: Some(self.cfg.mss),
        };
        let x = Ext {
            sack_perm: true,
            wscale: (self.cfg.rcv_wnd_scaled > 0).then(|| self.rcv_shift()),
            ts: Some((self.clock, 0)),
            ..Ext::NONE
        };
        let dst = k.key.addr;
        self.emit_x(dst, &o, &x, &[], out);
    }

    /// The retransmission timer of a SYN-SENT connection: the SYN again
    /// with the timeout doubled, or the connection given up.
    pub(crate) fn syn_timeout(
        &mut self,
        now_ms: u64,
        c: ConnId,
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        let retries = self.syn_retries;
        let Some(k) = self.conn_mut(c) else { return };
        k.set_timeouts(k.timeouts() + 1);
        // Karn: a SYN sent twice gives no round-trip sample.
        k.set(RTT_TIMING, false);
        if k.timeouts() > retries {
            self.stats.active_timeouts += 1;
            self.close_with(c, CloseReason::Timeout, app);
            return;
        }
        k.rto = k.rto.saturating_mul(2).min(RTO_MAX_MS);
        let rto = u64::from(k.rto);
        self.send_syn(c, out);
        self.stats.syn_retransmits += 1;
        self.arm(c, now_ms, TimerKind::Retransmit, rto);
    }

    /// A segment for a connection in SYN-SENT (RFC 9293 §3.10.7.3).
    pub(crate) fn syn_sent(
        &mut self,
        now_ms: u64,
        c: ConnId,
        h: &Header,
        payload: &[u8],
        app: &mut impl App,
        out: &mut impl FnMut([u8; 4], &[u8]),
    ) {
        let Some(k) = self.conn(c) else { return };
        let (iss, nxt) = (k.snd_una, k.snd_max);
        let has_ack = h.flags & ACK != 0;
        if has_ack && (le(h.ack, iss) || gt(h.ack, nxt)) {
            // Acknowledges something we never sent (an old connection's
            // segment, or a forgery): a RST for it, unless it is one.
            if h.flags & RST == 0 {
                let o = Out {
                    sport: h.dport,
                    dport: h.sport,
                    seq: h.ack,
                    ack: 0,
                    flags: RST,
                    window: 0,
                    mss: None,
                };
                let dst = k.key.addr;
                self.emit(dst, &o, &[], out);
                self.stats.rst_sent += 1;
            }
            return;
        }
        if h.flags & RST != 0 {
            // Only a RST that acknowledges our SYN refuses the connection;
            // one without an ACK cannot be told from a blind forgery.
            if has_ack {
                self.stats.active_refused += 1;
                self.close_with(c, CloseReason::Refused, app);
            }
            return;
        }
        if h.flags & SYN == 0 || !has_ack {
            // Not a SYN-ACK; a bare SYN would be a simultaneous open, which
            // this stack does not do: dropped.
            return;
        }
        let peer_mss = h.mss.unwrap_or(MIN_MSS);
        if peer_mss < MIN_MSS {
            // As on the server side: a peer that wants segments under 536
            // bytes is not served (RFC 9293 §3.7.1, H3).
            self.stats.refused_small_mss += 1;
            self.stats.active_refused += 1;
            self.abort(c, out);
            app.closed(c, CloseReason::Refused);
            return;
        }
        let offered_scale = self.cfg.rcv_wnd_scaled > 0;
        let our_shift = self.rcv_shift();
        let (rcv_wnd, rcv_wnd_scaled, cfg_mss) =
            (self.cfg.rcv_wnd, self.cfg.rcv_wnd_scaled, self.cfg.mss);
        let Some(k) = self.conn_mut(c) else { return };
        let mut flags = k.flags & FIN_QUEUED;
        if h.ts.is_some() {
            flags |= TS_OK;
        }
        if h.sack_ok {
            flags |= SACK_OK;
        }
        let (snd_shift, rcv_shift) = match h.wscale {
            // RFC 7323 §2.3: a shift above 14 is used as 14.
            Some(sh) if offered_scale => (sh.min(14), our_shift),
            _ => (0, 0),
        };
        let sample = (k.has(RTT_TIMING) && k.timeouts() == 0)
            .then(|| (now_ms as u32).wrapping_sub(k.rtt_start));
        k.flags = flags;
        k.state = State::Established;
        k.set_timeouts(0);
        k.rcv_nxt = h.seq.wrapping_add(1);
        k.snd_una = h.ack;
        k.snd_nxt = h.ack;
        k.snd_max = h.ack;
        k.snd_wl1 = h.seq;
        k.snd_wl2 = h.ack;
        k.recover = h.ack;
        // The window of a SYN is never scaled (RFC 7323 §2.2).
        k.snd_wnd = u32::from(h.window);
        k.snd_shift = snd_shift;
        k.rcv_shift = rcv_shift;
        k.rcv_space = if rcv_shift > 0 {
            rcv_wnd_scaled.max(u32::from(rcv_wnd))
        } else {
            u32::from(rcv_wnd)
        };
        // What our SYN announced (unscaled): never moved left.
        k.rcv_adv = k.rcv_nxt.wrapping_add(u32::from(rcv_wnd));
        k.ts_recent = h.ts.map_or(0, |(v, _)| v);
        let mss = peer_mss.min(cfg_mss);
        k.mss = mss;
        k.cc = NewReno::new(u32::from(mss));
        if let Some(rtt) = sample {
            Self::rtt_sample(k, rtt);
        } else {
            // RFC 6298 §5.7: after a lost SYN the data starts with 3 s.
            k.rto = 3000;
        }
        let fin_queued = k.has(FIN_QUEUED);
        if flags & SACK_OK != 0 {
            self.stats.sack_neg += 1;
        }
        if snd_shift > 0 || rcv_shift > 0 {
            self.stats.scaled += 1;
        }
        self.disarm(c);
        self.stats.active_established += 1;
        self.send_ack_now(c, out);
        app.connected(c);
        // Data or a FIN may ride on the SYN-ACK: they start at ISN + 1.
        if self.conn(c).is_some() && (!payload.is_empty() || h.flags & FIN != 0) {
            let mut rest = *h;
            rest.flags &= !SYN;
            rest.seq = h.seq.wrapping_add(1);
            self.segment(now_ms, c, &rest, payload, app, out);
        }
        if fin_queued {
            self.mark_dirty(c);
        }
    }
}
