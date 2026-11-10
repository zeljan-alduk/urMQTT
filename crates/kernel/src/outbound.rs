//! Outbound connections (NEXT-7, ADR-315 to ADR-317): TLS 1.3 over the
//! client side of core 0's TCP stack, to a destination the configuration
//! names. Nothing a peer sends can make the broker open a connection: the
//! destination, the trust anchors and the server name come from the image.
//!
//! The internal API for the users of an outbound connection (log shipping
//! today; an export bridge, log shipping of other kinds and a DNS client are
//! the later ones):
//!
//! - [`TlsLink::new`]: a destination, its trust anchors, its server name and
//!   the reconnect policy (`urmqtt_tcp::dial`);
//! - [`TlsLink::poll`], from core 0's loop: ARP for the next hop, connect,
//!   the connect deadline, the TLS handshake's bytes, the reconnect backoff;
//! - the TCP events, routed by [`TlsLink::owns`] from core 0's `App`:
//!   [`TlsLink::on_connected`], [`TlsLink::on_data`],
//!   [`TlsLink::on_peer_closed`], [`TlsLink::on_closed`];
//! - for its user: [`TlsLink::is_up`], [`TlsLink::room`],
//!   [`TlsLink::write`], [`TlsLink::take_received`] and [`TlsLink::stats`].
//!
//! Core 0 runs it: the replies come to an ephemeral port no listener uses,
//! which the dispatcher never steers to a worker core, so they stay on the
//! core that owns the connection.

use alloc::string::String;
use alloc::vec::Vec;

use urmqtt_log::{info, warn};
use urmqtt_net::iface::Iface;
use urmqtt_tcp::dial::{Action, Dialer, Policy};
use urmqtt_tcp::{CloseReason, ConnId, Endpoint, TcpStack};
use urmqtt_tls::client::{ClientSession, TlsClient};

/// Ciphertext waiting for room in the TCP send queue, at most.
const TX_MAX: usize = 64 * 1024;
/// Plaintext from the peer kept for the user, at most (a collector sends
/// nothing; more is dropped and counted).
const RX_MAX: usize = 16 * 1024;
/// Outbound connections core 0's stack may have (ADR-315): the log
/// connection today, room for the later users.
pub const MAX_ACTIVE: usize = 4;

/// Counters of one link, for the log and statsd.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinkStats {
    pub attempts: u64,
    pub up: u64,
    pub failures: u64,
    pub bytes_out: u64,
    pub rx_dropped: u64,
}

pub struct TlsLink {
    /// For the log: "logtls".
    what: &'static str,
    dst: Endpoint,
    name: String,
    client: TlsClient,
    dialer: Dialer,
    session: Option<ClientSession>,
    /// Ciphertext for the TCP stack.
    tx: Vec<u8>,
    /// Plaintext from the peer, for the user.
    rx: Vec<u8>,
    /// A TCP event asked for something only `poll` can do (it holds the
    /// stack): close our side, or abort with the reason.
    close_pending: bool,
    /// The peer has ended the connection (FIN or close_notify): nothing more
    /// is written into it, so what waits stays queued for the next one.
    closing: bool,
    fail: Option<String>,
    /// The wall clock was missing at the last poll (said once).
    waiting_clock: bool,
    rx_dropped: u64,
    bytes_out: u64,
}

impl TlsLink {
    /// A link to `dst`, verified against `anchors` (PEM) and `name` (a DNS
    /// name, or empty: `dst`'s address, which must be an IP SAN).
    pub fn new(
        what: &'static str,
        dst: Endpoint,
        name: &str,
        anchors: &[&[u8]],
        now_ms: u64,
    ) -> Result<Self, &'static str> {
        let client = TlsClient::verifying(anchors).map_err(|e| match e {
            urmqtt_tls::TlsError::Config(m) => m,
            _ => "the trust anchors are unusable",
        })?;
        let name = if name.is_empty() {
            alloc::format!("{}", dst.addr)
        } else {
            String::from(name)
        };
        // A bad name fails here, at boot, not at every attempt.
        client
            .connect_to(&name)
            .map_err(|_| "the server name is not usable")?;
        let mut seed = [0u8; 8];
        let _ = urmqtt_tls::rng::fill_global(&mut seed);
        Ok(Self {
            what,
            dst,
            name,
            client,
            dialer: Dialer::new(Policy::DEFAULT, now_ms, u64::from_le_bytes(seed)),
            session: None,
            tx: Vec::new(),
            rx: Vec::new(),
            close_pending: false,
            closing: false,
            fail: None,
            waiting_clock: false,
            rx_dropped: 0,
            bytes_out: 0,
        })
    }

    pub fn owns(&self, c: ConnId) -> bool {
        self.dialer.conn() == Some(c)
    }

    /// The TLS handshake is done and data can be written.
    pub fn is_up(&self) -> bool {
        self.dialer.is_up()
            && !self.closing
            && self.session.as_ref().is_some_and(|s| !s.is_closed())
    }

    /// Plaintext bytes [`TlsLink::write`] takes now without growing the
    /// queues past their bounds (0 while not up).
    pub fn room(&self, tcp: &TcpStack) -> usize {
        let Some(c) = self.dialer.conn().filter(|_| self.is_up()) else {
            return 0;
        };
        // Keep what TLS and TCP hold small: what is written but not yet
        // acknowledged is what a broken connection loses.
        let queued = tcp.send_queue(c) + self.tx.len();
        TX_MAX.saturating_sub(queued) / 2
    }

    /// Encrypts `data` for the peer. False if the link is not up.
    pub fn write(&mut self, data: &[u8]) -> bool {
        if !self.is_up() {
            return false;
        }
        let Some(s) = self.session.as_mut() else {
            return false;
        };
        let before = self.tx.len();
        if let Err(e) = s.write(data, &mut self.tx) {
            self.fail = Some(alloc::format!("TLS: {e:?}"));
            return false;
        }
        self.bytes_out += (self.tx.len() - before) as u64;
        true
    }

    /// What the peer sent (plaintext), at most [`RX_MAX`] bytes of it.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.rx)
    }

    pub fn stats(&self) -> LinkStats {
        let d = self.dialer.stats;
        LinkStats {
            attempts: d.attempts,
            up: d.up,
            failures: d.failures,
            bytes_out: self.bytes_out,
            rx_dropped: self.rx_dropped,
        }
    }

    fn addr(&self) -> String {
        // The outbound client is IPv4 only (ADR-319); an IPv6 one would need
        // brackets around the address.
        alloc::format!("{}:{}", self.dst.addr, self.dst.port)
    }

    fn retry_note(&self, now_ms: u64) -> String {
        match self.dialer.retry_at() {
            Some(t) => alloc::format!(
                "; next attempt in {} s",
                t.saturating_sub(now_ms).div_ceil(1000)
            ),
            None => String::new(),
        }
    }

    /// Core 0's loop: what the dialer asks for, the bytes TLS made, a failure
    /// a TCP event reported. `reserved`: local ports the stack must not use
    /// (the ones the dispatcher steers).
    pub fn poll(
        &mut self,
        now_ms: u64,
        iface: &mut Iface,
        tcp: &mut TcpStack,
        reserved: &impl Fn(u16) -> bool,
        emit: &mut impl FnMut(&[u8]),
    ) {
        if let Some(why) = self.fail.take()
            && let Some(c) = self.dialer.conn()
        {
            tcp.abort(c, &mut |dst, s| iface.send_tcp(dst, s, emit));
            self.session = None;
            self.dialer.closed(c, now_ms);
            warn!(
                "{}: connection to {} failed: {why}{}",
                self.what,
                self.addr(),
                self.retry_note(now_ms)
            );
        }
        // Certificates are checked against the wall clock: without one every
        // handshake would fail, so the link waits for it.
        if crate::boot::now_unix().is_none() {
            if !self.waiting_clock {
                self.waiting_clock = true;
                info!(
                    "{}: waiting for the wall clock before connecting to {}",
                    self.what,
                    self.addr()
                );
            }
            return;
        }
        self.waiting_clock = false;
        // IPv4 only (ADR-319): the configuration holds an IPv4 address.
        let v4 = self.dst.addr.as_v4().unwrap_or([0; 4]);
        let reachable = iface.addr().is_some() && iface.can_reach(v4);
        match self.dialer.poll(now_ms, reachable) {
            Action::None => {}
            Action::Resolve => {
                if let Some(hop) = iface.next_hop(v4)
                    && iface.addr().is_some()
                {
                    iface.resolve(hop, emit);
                }
            }
            Action::Connect => {
                let started = tcp
                    .ephemeral_port(self.dst, reserved)
                    .ok_or(urmqtt_tcp::ConnectError::PortInUse)
                    .and_then(|p| {
                        tcp.connect(now_ms, self.dst, p, &mut |dst, s| {
                            iface.send_tcp(dst, s, emit)
                        })
                    });
                match started {
                    Ok(c) => {
                        self.dialer.started(c, now_ms);
                        self.tx.clear();
                        self.rx.clear();
                        self.close_pending = false;
                        self.closing = false;
                    }
                    Err(e) => {
                        self.dialer.failed(now_ms);
                        warn!(
                            "{}: cannot connect to {}: {e:?}{}",
                            self.what,
                            self.addr(),
                            self.retry_note(now_ms)
                        );
                    }
                }
            }
            Action::Abort(c) => {
                tcp.abort(c, &mut |dst, s| iface.send_tcp(dst, s, emit));
                self.session = None;
                warn!(
                    "{}: connection to {} not up within {} s{}",
                    self.what,
                    self.addr(),
                    Policy::DEFAULT.connect_timeout_ms / 1000,
                    self.retry_note(now_ms)
                );
            }
        }
        let Some(c) = self.dialer.conn() else {
            return;
        };
        if !self.tx.is_empty() {
            let n = tcp.send(c, &self.tx);
            self.tx.drain(..n.min(self.tx.len()));
        }
        if self.close_pending && self.tx.is_empty() {
            self.close_pending = false;
            tcp.close(c);
        }
    }

    /// The TCP connection is open: the ClientHello goes out.
    pub fn on_connected(&mut self, c: ConnId) {
        if !self.owns(c) {
            return;
        }
        match self.client.connect_to(&self.name) {
            Ok(mut s) => {
                let mut ignored = Vec::new();
                if let Err(e) = s.input(&[], &mut self.tx, &mut ignored) {
                    self.fail = Some(alloc::format!("TLS: {e:?}"));
                }
                self.session = Some(s);
            }
            Err(e) => self.fail = Some(alloc::format!("TLS: {e:?}")),
        }
    }

    /// Bytes from the peer: the handshake, then (unexpected for a collector)
    /// data.
    pub fn on_data(&mut self, c: ConnId, data: &[u8], now_ms: u64) {
        if !self.owns(c) {
            return;
        }
        let Some(s) = self.session.as_mut() else {
            return;
        };
        let was_up = s.is_established();
        let mut app = Vec::new();
        if let Err(e) = s.input(data, &mut self.tx, &mut app) {
            self.fail = Some(alloc::format!("TLS: {e:?}"));
            return;
        }
        let room = RX_MAX.saturating_sub(self.rx.len());
        if app.len() > room {
            self.rx_dropped += (app.len() - room) as u64;
        }
        self.rx
            .extend_from_slice(app.get(..room.min(app.len())).unwrap_or(&[]));
        let (up, closed) = (!was_up && s.is_established(), s.is_closed());
        if up {
            self.dialer.up(c, now_ms);
            info!(
                "{}: connected to {} (TLS 1.3, certificate verified for {:?})",
                self.what,
                self.addr(),
                self.name
            );
        }
        if closed {
            // The peer's close_notify: we close too.
            self.close_pending = true;
            self.closing = true;
        }
    }

    /// The peer sent FIN: our side closes after what is queued.
    pub fn on_peer_closed(&mut self, c: ConnId) {
        if self.owns(c) {
            // A collector that sent FIN is going away (a half-closed
            // collector that still reads is not a thing): records written
            // now would be lost with it, so none are (they wait in the
            // user's queue for the next connection).
            self.close_pending = true;
            self.closing = true;
        }
    }

    /// The connection is gone (closed, reset, refused, timed out).
    pub fn on_closed(&mut self, c: ConnId, why: CloseReason, now_ms: u64) {
        if !self.owns(c) {
            return;
        }
        let was_up = self.dialer.is_up();
        self.session = None;
        self.tx.clear();
        self.dialer.closed(c, now_ms);
        let why = match why {
            CloseReason::Normal => "closed",
            CloseReason::Reset => "reset by the peer",
            CloseReason::Timeout => "timed out",
            CloseReason::Refused => "refused",
        };
        warn!(
            "{}: connection to {} {why}{}{}",
            self.what,
            self.addr(),
            if was_up {
                ""
            } else {
                " before the TLS handshake finished"
            },
            self.retry_note(now_ms)
        );
    }
}
