//! MQTT over secure WebSocket, the listener's state (NEXT-5, ADR-272).
//!
//! The listener is off unless the image's configuration switches it on
//! (`websocket.enabled`). The protocol work is in `urmqtt-ws` (host-tested,
//! fuzzed, Autobahn-checked); the connection glue is in
//! `mqtt_service::ws`. This module holds what the cores share (the table of
//! source addresses, the counters), the per-core state (connections, the
//! upgrade deadline, the login rate) and the messages the operator reads.
//!
//! A connection goes through, in order:
//!
//! 1. **The SYN and the final ACK**: the TLS admission of the core (in-flight
//!    limits per core and per address, the handshake rate, memory), and this
//!    listener's own limits (connections in all, per address, a locked-out
//!    address, the login rate in password mode). Refusals cost no state.
//! 2. **TLS 1.3**: the TLS listener's server (`auth = "mtls"`: a client
//!    certificate, identity and role as on the TLS port) or the same server
//!    without a client certificate (`auth = "password"`).
//! 3. **The upgrade**: one HTTP request of at most 4 KiB within
//!    `websocket.upgrade_timeout_s` of the accept, checked by
//!    `urmqtt_ws::upgrade` (path, version, subprotocol, origin).
//! 4. **The login** (password mode): the first MQTT packet is a CONNECT whose
//!    user name and password match an account of `websocket.users`, decided
//!    before the broker sees it, with the plaintext listener's checker,
//!    decoy and lock-out rules.
//! 5. **MQTT**: frames are decoded by `urmqtt_ws::frame` and their bytes go to
//!    the broker's parser with the broker's limits (or the section's packet
//!    limit in password mode).
//!
//! Until step 4 (step 3 with mtls) the connection counts as a handshake in
//! flight, for the admission and for the watchdog's handshake budget.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use urmqtt_net::addr::Addr;

use urmqtt_broker::sys::{WS_REFUSALS, WsInfo, ws_close_index};
use urmqtt_config::{CONFIG, WsAuth};
use urmqtt_log::{info, warn};
use urmqtt_plain::{Authenticator, Limits, Open, Sources, Syn, Verdict};
use urmqtt_sync::sync::{OnceCell, SpinLock};
use urmqtt_tls::{TlsError, TlsSession};
use urmqtt_ws::frame::{self, Decoder};
use urmqtt_ws::upgrade::{self, Policy};

/// Counter indices of [`WS_REFUSALS`] beyond the parser's six.
pub const REFUSED_TOO_LARGE: usize = 6;
pub const REFUSED_TIMEOUT: usize = 7;
pub const REFUSED_LIMIT: usize = 8;
pub const REFUSED_LOCKED: usize = 9;

/// Counters since boot, all cores (`$SYS/broker/websocket/...`).
pub struct Stats {
    pub open: AtomicU64,
    pub accepted: AtomicU64,
    pub upgrades: AtomicU64,
    pub refused: [AtomicU64; 10],
    pub auth_ok: AtomicU64,
    pub auth_failed: AtomicU64,
    pub lockouts: AtomicU64,
    pub frames_in: AtomicU64,
    pub frames_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub closes_client: [AtomicU64; 9],
    pub closes_server: [AtomicU64; 9],
    pub closes_abrupt: AtomicU64,
}

pub static STATS: Stats = Stats {
    open: AtomicU64::new(0),
    accepted: AtomicU64::new(0),
    upgrades: AtomicU64::new(0),
    refused: [const { AtomicU64::new(0) }; 10],
    auth_ok: AtomicU64::new(0),
    auth_failed: AtomicU64::new(0),
    lockouts: AtomicU64::new(0),
    frames_in: AtomicU64::new(0),
    frames_out: AtomicU64::new(0),
    bytes_in: AtomicU64::new(0),
    bytes_out: AtomicU64::new(0),
    closes_client: [const { AtomicU64::new(0) }; 9],
    closes_server: [const { AtomicU64::new(0) }; 9],
    closes_abrupt: AtomicU64::new(0),
};

/// Adds `n` to a statistic and returns the new value (Relaxed: statistics).
fn add(a: &AtomicU64, n: u64) -> u64 {
    a.fetch_add(n, Ordering::Relaxed) + n
}

fn bump(a: &AtomicU64) -> u64 {
    add(a, 1)
}

/// What the cores share, made once at boot.
struct Shared {
    /// Per source address: connections, failed logins, lock-out (the
    /// plaintext listener's table type, a separate instance).
    sources: SpinLock<Sources>,
    /// New password logins per second and core.
    login_rate: u32,
}

static SHARED: OnceCell<Shared> = OnceCell::new();

/// The cost of one password check at the dearest account, ns ([`measure`]).
static PASSWD_NS: AtomicU64 = AtomicU64::new(0);

/// The WebSocket port, if the listener is on.
pub fn port() -> Option<u16> {
    let w = &CONFIG.websocket;
    (w.enabled && CONFIG.network.mqtt_tls_port != 0).then_some(w.port)
}

fn password() -> bool {
    CONFIG.websocket.auth == WsAuth::Password
}

fn auth_name() -> &'static str {
    match CONFIG.websocket.auth {
        WsAuth::Mtls => "mtls",
        WsAuth::Password => "password",
    }
}

/// Times a password check at the dearest account (0 outside password mode);
/// boot calls it before calibrating the watchdog's handshake budget, which
/// then covers it (the check runs in one handler step).
pub fn measure() -> u64 {
    if port().is_none() || !password() {
        return 0;
    }
    // Run-time accounts (ADR-285) are at most as dear as the default.
    let runtime = if CONFIG.limits.max_runtime_accounts > 0 {
        urmqtt_control::MAX_ACCOUNT_ITERATIONS
    } else {
        0
    };
    let iterations = u64::from(
        Authenticator::password_only(CONFIG.websocket.users)
            .max_iterations()
            .max(runtime),
    );
    const PROBE: u32 = 128;
    let mut best = u64::MAX;
    for _ in 0..3 {
        let t0 = urmqtt_arch::time::uptime_ns();
        core::hint::black_box(urmqtt_plain::auth::probe(PROBE));
        best = best.min(urmqtt_arch::time::uptime_ns().saturating_sub(t0));
    }
    let ns = best.saturating_mul(iterations) / u64::from(PROBE);
    // Relaxed: set once at boot, before the data cores run.
    PASSWD_NS.store(ns, Ordering::Relaxed);
    info!(
        "websocket: one password check costs about {} us ({iterations} iterations of PBKDF2-HMAC-SHA-256)",
        ns / 1000
    );
    ns
}

/// Makes what the cores share, if the listener is on. Boot calls it once,
/// after the random generator is up and before the data cores start.
pub fn init() {
    let w = &CONFIG.websocket;
    if port().is_none() {
        return;
    }
    let mut key = [0u8; 8];
    // Fail closed, as for the plaintext table: hashed under a secret key.
    if urmqtt_tls::rng::fill_global(&mut key).is_err() {
        crate::boot::fatal("websocket: no random generator for the address table's key");
    }
    let capacity = (w.max_connections.min(65_536) as usize).saturating_mul(2);
    let sources = Sources::new(
        capacity,
        u64::from_le_bytes(key),
        Limits {
            max_per_ip: w.max_connections_per_ip,
            max_failures: w.max_failed_auths_per_ip,
            lockout_s: w.lockout_s,
        },
    );
    // Half a core's worth of password checks a second at most (ADR-267).
    let login_rate = urmqtt_plain::auth::login_rate(
        PASSWD_NS.load(Ordering::Relaxed),
        CONFIG.limits.handshakes_per_core_per_sec,
    );
    let _ = SHARED.set(Shared {
        sources: SpinLock::new(sources),
        login_rate,
    });
}

/// The numbers `$SYS/broker/websocket/...` and the info query report.
pub fn info() -> WsInfo<'static> {
    let w = &CONFIG.websocket;
    if port().is_none() || SHARED.get().is_none() {
        return WsInfo::default();
    }
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let arr = |a: &[AtomicU64; 9]| core::array::from_fn(|i| a.get(i).map_or(0, g));
    WsInfo {
        enabled: true,
        port: w.port,
        path: w.path,
        auth: auth_name(),
        origins: w.origins.len() as u64,
        accounts: w.users.len() as u64,
        connections: g(&STATS.open),
        accepted: g(&STATS.accepted),
        upgrades: g(&STATS.upgrades),
        refused: core::array::from_fn(|i| STATS.refused.get(i).map_or(0, g)),
        auth_ok: g(&STATS.auth_ok),
        auth_failed: g(&STATS.auth_failed),
        lockouts: g(&STATS.lockouts),
        frames_in: g(&STATS.frames_in),
        frames_out: g(&STATS.frames_out),
        bytes_in: g(&STATS.bytes_in),
        bytes_out: g(&STATS.bytes_out),
        closes_client: arr(&STATS.closes_client),
        closes_server: arr(&STATS.closes_server),
        closes_abrupt: g(&STATS.closes_abrupt),
    }
}

/// The MQTT limits of a password connection's first packet.
pub fn mqtt_limits() -> urmqtt_mqtt::Limits {
    let l = &CONFIG.limits;
    urmqtt_mqtt::Limits {
        max_packet_size: CONFIG.websocket.max_packet_size,
        max_topic_len: crate::mqtt_service::limit16(l.max_topic_len),
        max_topic_levels: crate::mqtt_service::limit16(l.max_topic_levels),
        max_client_id_len: crate::mqtt_service::limit16(l.max_topic_len),
        max_topics_per_packet: crate::mqtt_service::limit16(l.max_subscriptions_per_session),
    }
}

/// The broker's rules for password sessions (`None` with mtls: those are
/// ordinary certificate sessions).
pub fn broker_policy() -> Option<urmqtt_broker::PlainPolicy> {
    let w = &CONFIG.websocket;
    (port().is_some() && password()).then_some(urmqtt_broker::PlainPolicy {
        publish: w.acl_publish,
        subscribe: w.acl_subscribe,
        max_packet_size: w.max_packet_size,
        rate_tokens: w.publish_rate_per_device.tokens,
        rate_period_ms: w.publish_rate_per_device.per_ms,
        retain: w.retain,
    })
}

/// The largest WebSocket message accepted: what the MQTT packet limit in
/// force allows, plus room for a few small packets sent along in the same
/// message. No buffer is sized by it (the decoder streams).
fn max_message() -> u64 {
    let packet = if password() {
        CONFIG.websocket.max_packet_size
    } else {
        CONFIG.limits.max_packet_size
    };
    u64::from(packet) + 5 + 4096
}

/// The boot line (once, from one core) and the warnings that go with it.
pub fn announce(cores: usize) {
    let w = &CONFIG.websocket;
    if w.enabled && CONFIG.network.mqtt_tls_port == 0 {
        // The configuration check refuses this; a hand-made blob could not
        // reach it either. Said anyway, so nobody wonders where it went.
        warn!("websocket: listener off: it needs the TLS listener (network.mqtt_tls_port)");
        return;
    }
    if port().is_none() {
        return;
    }
    let origins = if w.origins.is_empty() {
        alloc::string::String::from("any origin")
    } else {
        w.origins.join(", ")
    };
    let who = match w.auth {
        WsAuth::Mtls => alloc::format!(
            "client certificate (identity {:?})",
            CONFIG.tls.identity_field
        ),
        WsAuth::Password => alloc::format!(
            "password login inside TLS, {} account(s), packets up to {} bytes, {}/{} ms publish rate, {} failed login(s) lock an address out for {} s",
            w.users.len(),
            w.max_packet_size,
            w.publish_rate_per_device.tokens,
            w.publish_rate_per_device.per_ms,
            w.max_failed_auths_per_ip,
            w.lockout_s
        ),
    };
    info!(
        "mqtt: WebSocket listener on port {} (wss://...{}, TLS 1.3, subprotocol mqtt): {who}; origins: {origins}; upgrade within {} s; at most {} connection(s), {} per address; {} data core(s)",
        w.port, w.path, w.upgrade_timeout_s, w.max_connections, w.max_connections_per_ip, cores
    );
    if w.auth == WsAuth::Mtls && w.origins.is_empty() {
        info!(
            "websocket: no origin list: any web page may open a connection, but only a browser holding a client certificate gets past TLS"
        );
    }
}

/// What the login of a password connection decided.
pub enum Decision {
    Accept(String),
    /// The CONNACK return code to answer with; the connection closes.
    Refuse(u8),
}

/// Where a connection is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// TLS handshake.
    Tls,
    /// Receiving the upgrade request.
    Request,
    /// Password mode: upgraded, waiting for the CONNECT.
    Login,
    /// MQTT flows.
    Open,
    /// A close frame was sent or received, or the upgrade refused.
    Closing,
}

/// One WebSocket connection of this core.
struct WsConn {
    ip: Addr,
    /// Accepted at (ms), also the upgrade queue's check that an entry is
    /// still this connection.
    at_ms: u64,
    phase: Phase,
    /// The certificate identity (mtls) until the upgrade attaches it, and
    /// whether it is a bootstrap one.
    identity: Option<(Box<str>, bool)>,
    dec: Decoder,
    /// The close frame to send when the connection closes (a code, or the
    /// empty one echoing a close without a code), unless already sent.
    close: Option<Option<u16>>,
    close_sent: bool,
    close_received: bool,
    /// Answered 101.
    upgraded: bool,
    /// Counted as an abrupt end already.
    abrupt: bool,
}

/// A token bucket: password logins a second on this core.
struct Bucket {
    rate: u32,
    tokens: u32,
    last_ms: u64,
}

impl Bucket {
    fn refill(&mut self, now_ms: u64) {
        let add = now_ms.saturating_sub(self.last_ms) * u64::from(self.rate) / 1000;
        if add > 0 {
            self.tokens = (u64::from(self.tokens) + add).min(u64::from(self.rate)) as u32;
            self.last_ms = now_ms;
        }
    }

    fn available(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        self.tokens > 0
    }

    fn take(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// The WebSocket listener of one data core.
pub struct WsState {
    port: u16,
    path: &'static str,
    origins: &'static [&'static str],
    /// Password mode: the TLS server without client certificates, the
    /// account checker and the login rate.
    server_only: Option<urmqtt_tls::TlsServer>,
    auth: Option<Authenticator<'static>>,
    bucket: Option<Bucket>,
    conns: urmqtt_mm::slab::Slab<WsConn>,
    /// Connections waiting for their upgrade, oldest first (`at_ms`, id).
    waiting: VecDeque<(u64, u32)>,
    deadline_ms: u64,
    /// Frame header plus payload, for one `TlsSession::send`.
    scratch: Vec<u8>,
    /// Refusals already logged, by kind (logged at powers of two); 10:
    /// protocol violations.
    logged: [u64; 12],
    /// Protocol violations seen on this core.
    violations: u64,
}

impl WsState {
    /// The state of a core, if the listener is on and `init` ran.
    /// `server_only` builds the certificate-less TLS server (password mode).
    pub fn new(server_only: impl FnOnce() -> Option<urmqtt_tls::TlsServer>) -> Option<Box<Self>> {
        let w = &CONFIG.websocket;
        let shared = SHARED.get()?;
        port()?;
        let pw = password();
        let server_only = if pw {
            let s = server_only();
            if s.is_none() {
                warn!(
                    "websocket: the TLS server for password logins could not be set up; listener off"
                );
                return None;
            }
            s
        } else {
            None
        };
        Some(Box::new(Self {
            port: w.port,
            path: w.path,
            origins: w.origins,
            server_only,
            auth: pw.then(|| {
                let mut a = Authenticator::password_only(w.users);
                a.set_runtime(crate::plain::runtime_accounts());
                a
            }),
            bucket: pw.then_some(Bucket {
                rate: shared.login_rate,
                tokens: shared.login_rate,
                last_ms: 0,
            }),
            conns: urmqtt_mm::slab::Slab::new(),
            waiting: VecDeque::new(),
            deadline_ms: u64::from(w.upgrade_timeout_s) * 1000,
            scratch: Vec::new(),
            logged: [0; 12],
            violations: 0,
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether `c` is a connection of this listener.
    pub fn has(&self, c: u32) -> bool {
        self.conns.contains(c)
    }

    pub fn phase(&self, c: u32) -> Option<Phase> {
        self.conns.get(c).map(|w| w.phase)
    }

    /// Output to `c` goes through [`send`](Self::send) (in frames, or
    /// nowhere once our close frame left).
    /// The run-time accounts changed (control epoch, ADR-285).
    pub fn set_accounts(&mut self, accounts: urmqtt_plain::Accounts) {
        if let Some(a) = self.auth.as_mut() {
            a.set_runtime(Some(accounts).filter(|a| !a.is_empty()));
        }
    }

    pub fn framed(&self, c: u32) -> bool {
        self.conns.contains(c)
    }

    /// The TLS server of password mode (`None` with mtls: the TLS port's).
    pub fn server_only(&self) -> Option<&urmqtt_tls::TlsServer> {
        self.server_only.as_ref()
    }

    pub fn is_password(&self) -> bool {
        self.auth.is_some()
    }

    fn log_power_of_two(&mut self, kind: usize, n: u64, text: &str) {
        if n.is_power_of_two()
            && let Some(l) = self.logged.get_mut(kind)
            && n > *l
        {
            *l = n;
            warn!("websocket: {n} {text}");
        }
    }

    /// Counts a refusal of `kind` ([`WS_REFUSALS`]) and logs it at powers of
    /// two.
    pub fn refused(&mut self, kind: usize) {
        let n = STATS.refused.get(kind).map_or(0, bump);
        let name = WS_REFUSALS.get(kind).copied().unwrap_or("?");
        self.log_power_of_two(kind, n, &alloc::format!("connection(s) refused: {name}"));
    }

    /// A SYN from `ip`: the listener's own limits (the core's TLS admission
    /// is asked after). Nothing is kept.
    pub fn syn_ok(&mut self, ip: Addr, now_ms: u64) -> bool {
        let Some(shared) = SHARED.get() else {
            return false;
        };
        match shared
            .sources
            .lock()
            .syn(crate::plain::src(ip), (now_ms / 1000) as u32)
        {
            Syn::LockedOut => {
                self.refused(REFUSED_LOCKED);
                return false;
            }
            Syn::TooMany => {
                self.refused(REFUSED_LIMIT);
                return false;
            }
            Syn::Allow => {}
        }
        // Relaxed: statistics; the exact bound is enforced at the ACK.
        if STATS.open.load(Ordering::Relaxed) >= u64::from(CONFIG.websocket.max_connections)
            || self.bucket.as_mut().is_some_and(|b| !b.available(now_ms))
        {
            self.refused(REFUSED_LIMIT);
            return false;
        }
        true
    }

    /// The final ACK of `c` from `ip`, after the TLS admission admitted it:
    /// counts it, or says no.
    pub fn accept(&mut self, c: u32, ip: Addr, now_ms: u64) -> bool {
        let Some(shared) = SHARED.get() else {
            return false;
        };
        let open = STATS.open.fetch_add(1, Ordering::AcqRel) + 1;
        let refuse = if open > u64::from(CONFIG.websocket.max_connections)
            || self.bucket.as_mut().is_some_and(|b| !b.take(now_ms))
        {
            Some(REFUSED_LIMIT)
        } else {
            match shared
                .sources
                .lock()
                .open(crate::plain::src(ip), (now_ms / 1000) as u32)
            {
                Open::Ok => None,
                Open::LockedOut => Some(REFUSED_LOCKED),
                Open::TooMany | Open::Full => Some(REFUSED_LIMIT),
            }
        };
        if let Some(kind) = refuse {
            STATS.open.fetch_sub(1, Ordering::AcqRel);
            self.refused(kind);
            return false;
        }
        bump(&STATS.accepted);
        self.conns.insert_at(
            c,
            WsConn {
                ip,
                at_ms: now_ms,
                phase: Phase::Tls,
                identity: None,
                dec: Decoder::new(frame::Config {
                    max_message: max_message(),
                    // MQTT is binary: a text frame is closed with 1003.
                    text: false,
                }),
                close: None,
                close_sent: false,
                close_received: false,
                upgraded: false,
                abrupt: false,
            },
        );
        if self.waiting.len() > 2 * self.conns.len() + 64 {
            let conns = &self.conns;
            self.waiting.retain(|&(at, c)| {
                conns.get(c).is_some_and(|w| {
                    w.at_ms == at && matches!(w.phase, Phase::Tls | Phase::Request)
                })
            });
        }
        self.waiting.push_back((now_ms, c));
        true
    }

    /// The TLS handshake of `c` finished; `identity`: the certificate's
    /// (mtls) and whether it is a bootstrap one.
    pub fn tls_done(&mut self, c: u32, identity: Option<(Box<str>, bool)>) {
        if let Some(w) = self.conns.get_mut(c) {
            w.phase = Phase::Request;
            w.identity = identity;
        }
    }

    /// The client ended TCP (FIN): abrupt, unless it sent its close frame
    /// first or we had sent ours.
    pub fn peer_gone(&mut self, c: u32) {
        if let Some(w) = self.conns.get_mut(c)
            && w.upgraded
            && !w.close_received
            && !w.close_sent
            && !w.abrupt
        {
            w.abrupt = true;
            bump(&STATS.closes_abrupt);
        }
    }

    /// The connection `c` is gone: gives its place back.
    pub fn release(&mut self, c: u32, now_ms: u64) {
        let Some(w) = self.conns.take_at(c) else {
            return;
        };
        // Upgraded, and gone (reset, timed out) without a close frame from
        // either side.
        if w.upgraded && !w.close_received && !w.close_sent && !w.abrupt {
            bump(&STATS.closes_abrupt);
        }
        if let Some(shared) = SHARED.get() {
            shared
                .sources
                .lock()
                .close(crate::plain::src(w.ip), (now_ms / 1000) as u32);
        }
        STATS.open.fetch_sub(1, Ordering::AcqRel);
    }

    /// Connections whose upgrade did not complete within the deadline (the
    /// caller resets them). Counted as refused (timeout).
    pub fn expire(&mut self, now_ms: u64) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(&(at, c)) = self.waiting.front() {
            let live = self
                .conns
                .get(c)
                .is_some_and(|w| w.at_ms == at && matches!(w.phase, Phase::Tls | Phase::Request));
            if !live {
                self.waiting.pop_front();
                continue;
            }
            if now_ms.saturating_sub(at) <= self.deadline_ms {
                break;
            }
            self.waiting.pop_front();
            self.refused(REFUSED_TIMEOUT);
            out.push(c);
        }
        if self.waiting.is_empty() && self.waiting.capacity() > 64 {
            self.waiting.shrink_to_fit();
        }
        out
    }

    /// The upgrade request of `c` (`req`, exactly as `upgrade::scan`
    /// delimited it): the response to send, and whether it was accepted.
    pub fn upgrade(&mut self, c: u32, req: &[u8]) -> (Vec<u8>, bool) {
        let policy = Policy {
            path: self.path,
            origins: self.origins,
        };
        match upgrade::parse(req, &policy) {
            Ok(a) => {
                let mut out = [0u8; upgrade::MAX_RESPONSE];
                let n = a.response(&mut out);
                if let Some(w) = self.conns.get_mut(c) {
                    w.phase = if self.auth.is_some() {
                        Phase::Login
                    } else {
                        Phase::Open
                    };
                    w.upgraded = true;
                }
                bump(&STATS.upgrades);
                (out.get(..n).unwrap_or(&[]).to_vec(), true)
            }
            Err(r) => {
                if let Some(w) = self.conns.get_mut(c) {
                    w.phase = Phase::Closing;
                    w.close_sent = true;
                }
                self.refused(r.index());
                (r.response().to_vec(), false)
            }
        }
    }

    /// The request of `c` grew past 4 KiB without an end.
    pub fn too_large(&mut self, c: u32) -> &'static [u8] {
        if let Some(w) = self.conns.get_mut(c) {
            w.phase = Phase::Closing;
            w.close_sent = true;
        }
        self.refused(REFUSED_TOO_LARGE);
        upgrade::Refusal::Malformed.response()
    }

    /// Takes the certificate identity of `c` (mtls), to attach it.
    pub fn take_identity(&mut self, c: u32) -> Option<(Box<str>, bool)> {
        self.conns.get_mut(c).and_then(|w| w.identity.take())
    }

    /// The login of `c` succeeded or the mtls upgrade attached it.
    pub fn opened(&mut self, c: u32) {
        if let Some(w) = self.conns.get_mut(c)
            && w.phase == Phase::Login
        {
            w.phase = Phase::Open;
        }
    }

    /// Decodes frames of `c` from `data` (unmasked in place): the MQTT bytes
    /// go to `mqtt`, pongs to `pongs` (as payloads), and the result says how
    /// the stream stands.
    pub fn frames(
        &mut self,
        c: u32,
        data: &mut [u8],
        mqtt: &mut Vec<u8>,
        pongs: &mut Vec<Vec<u8>>,
    ) -> Frames {
        let Some(w) = self.conns.get_mut(c) else {
            return Frames::Gone;
        };
        let mut close: Option<Option<u16>> = None;
        let mut events = 0u64;
        let before = mqtt.len();
        let r = w.dec.feed(data, &mut |e| match e {
            frame::Event::Data { bytes, .. } => mqtt.extend_from_slice(bytes),
            frame::Event::End { .. } | frame::Event::Pong(_) => events += 1,
            frame::Event::Ping(p) => {
                events += 1;
                pongs.push(p.to_vec());
            }
            frame::Event::Close { code, .. } => {
                events += 1;
                close = Some(code);
            }
        });
        add(&STATS.frames_in, events);
        add(&STATS.bytes_in, (mqtt.len() - before) as u64);
        if let Err(v) = r {
            w.phase = Phase::Closing;
            w.close = Some(Some(v.code()));
            self.violations += 1;
            let n = self.violations;
            self.log_power_of_two(
                10,
                n,
                &alloc::format!(
                    "WebSocket protocol violation(s) by clients on this core (the last: {}, closed with {})",
                    v.text(),
                    v.code()
                ),
            );
            return Frames::Violation(v);
        }
        if let Some(code) = close {
            w.phase = Phase::Closing;
            w.close_received = true;
            // Echo the code (RFC 6455 5.5.1), or close without one.
            w.close = Some(code);
            if let Some(slot) = STATS.closes_client.get(code.map_or(8, ws_close_index)) {
                bump(slot);
            }
            return Frames::Closed;
        }
        Frames::More
    }

    /// The close frame to send for `c` now, once: its payload code (`None`:
    /// the empty close). Called when the connection closes for any reason.
    fn close_to_send(&mut self, c: u32) -> Option<Option<u16>> {
        let w = self.conns.get_mut(c)?;
        if w.close_sent || !matches!(w.phase, Phase::Login | Phase::Open | Phase::Closing) {
            return None;
        }
        w.close_sent = true;
        w.phase = Phase::Closing;
        let code = w.close.take().unwrap_or(Some(frame::close::NORMAL));
        if !w.close_received
            && let Some(slot) = STATS.closes_server.get(code.map_or(8, ws_close_index))
        {
            bump(slot);
        }
        Some(code)
    }

    /// Marks that `c` closes with `code` (a refused login: 1008).
    pub fn set_close(&mut self, c: u32, code: u16) {
        if let Some(w) = self.conns.get_mut(c) {
            w.close = Some(Some(code));
        }
    }

    /// Sends `payload` to `c`'s client as one frame of `opcode` through its
    /// TLS session. Nothing goes out before the upgrade or after the close
    /// frame (RFC 6455 5.5.1): such output is dropped.
    pub fn send(
        &mut self,
        c: u32,
        sess: &mut TlsSession,
        opcode: u8,
        payload: &[u8],
        tx: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        let open = self.conns.get(c).is_some_and(|w| {
            !w.close_sent && matches!(w.phase, Phase::Login | Phase::Open | Phase::Closing)
        });
        if !open {
            return Ok(());
        }
        self.send_frame(sess, opcode, payload, tx)
    }

    /// The close frame for `c`, if one is due ([`close_to_send`](Self::close_to_send)).
    pub fn send_close(&mut self, c: u32, sess: &mut TlsSession, tx: &mut Vec<u8>) {
        if let Some(code) = self.close_to_send(c) {
            let payload = code.map(u16::to_be_bytes);
            let _ = self.send_frame(
                sess,
                frame::op::CLOSE,
                payload.as_ref().map_or(&[][..], |p| p),
                tx,
            );
        }
    }

    fn send_frame(
        &mut self,
        sess: &mut TlsSession,
        opcode: u8,
        payload: &[u8],
        tx: &mut Vec<u8>,
    ) -> Result<(), TlsError> {
        let (h, n) = frame::header(opcode, payload.len());
        self.scratch.clear();
        self.scratch.extend_from_slice(h.get(..n).unwrap_or(&[]));
        self.scratch.extend_from_slice(payload);
        let r = sess.send(&self.scratch, tx);
        self.scratch.clear();
        if self.scratch.capacity() > 64 * 1024 {
            self.scratch = Vec::new();
        }
        bump(&STATS.frames_out);
        add(&STATS.bytes_out, payload.len() as u64);
        r
    }

    /// Decides the CONNECT of password connection `c` (parsed already).
    pub fn decide(&mut self, c: u32, p: &crate::mqtt5::ConnectView<'_>, now_ms: u64) -> Decision {
        let (Some(w), Some(auth)) = (self.conns.get(c), self.auth.as_ref()) else {
            return Decision::Refuse(5);
        };
        let ip = w.ip;
        // An address locked out after this connection was opened is not
        // judged (ADR-363), as on the plaintext listener.
        if let Some(shared) = SHARED.get()
            && shared
                .sources
                .lock()
                .locked_out(crate::plain::src(ip), (now_ms / 1000) as u32)
        {
            bump(&STATS.auth_failed);
            return Decision::Refuse(5);
        }
        // Owned, so that the authenticator is free again (it borrows the
        // identity of a run-time account from its table).
        let verdict = match auth.authenticate(ip.as_v4(), p.username, p.password) {
            Verdict::Accept(id) => Ok(String::from(id)),
            v @ Verdict::Reject(why) => Err((why, v.connack_code())),
        };
        match verdict {
            Ok(identity) => {
                // (This does not clear the address's failure count,
                // ADR-363.)
                if let Some(shared) = SHARED.get() {
                    shared.sources.lock().succeeded(crate::plain::src(ip));
                }
                bump(&STATS.auth_ok);
                if p.client_id.is_empty() && !p.clean_session {
                    return Decision::Refuse(2);
                }
                // Clean sessions only (as plaintext, ADR-230).
                if !p.clean_session {
                    return Decision::Refuse(5);
                }
                // The registry's allowlist applies to these identities too.
                if !crate::control::admitted(&identity) {
                    let n = crate::control::REGISTRY_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_power_of_two() {
                        warn!(
                            "registry: websocket login {identity} is not on the allowlist, refused ({n} so far)"
                        );
                    }
                    return Decision::Refuse(5);
                }
                Decision::Accept(identity)
            }
            Err((why, code)) => {
                let n = bump(&STATS.auth_failed);
                if n.is_power_of_two() {
                    let a = ip;
                    // The user name is not printed: the client chose it.
                    warn!(
                        "websocket: login refused for {a} ({}), {n} so far",
                        why.text()
                    );
                }
                self.fail(ip, now_ms);
                Decision::Refuse(code.unwrap_or(5))
            }
        }
    }

    /// A first packet that is no CONNECT: a failure of the address.
    pub fn garbage(&mut self, c: u32, now_ms: u64) {
        if let Some(ip) = self.conns.get(c).map(|w| w.ip) {
            bump(&STATS.auth_failed);
            self.fail(ip, now_ms);
        }
    }

    fn fail(&mut self, ip: Addr, now_ms: u64) {
        let Some(shared) = SHARED.get() else {
            return;
        };
        if shared
            .sources
            .lock()
            .failed(crate::plain::src(ip), (now_ms / 1000) as u32)
        {
            let n = bump(&STATS.lockouts);
            let a = ip;
            warn!(
                "websocket: {a} is locked out for {} s after {} failed login(s) ({n} lock-out(s) so far)",
                CONFIG.websocket.lockout_s, CONFIG.websocket.max_failed_auths_per_ip
            );
        }
    }

    /// Returns memory a past peak left.
    pub fn shrink(&mut self) {
        self.conns.shrink();
    }
}

/// How a batch of frames left the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frames {
    /// Keep reading.
    More,
    /// The client sent a close frame.
    Closed,
    /// The client broke RFC 6455; close with the violation's code.
    Violation(frame::Violation),
    /// No such connection.
    Gone,
}
