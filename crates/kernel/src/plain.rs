//! Plaintext MQTT for trusted networks, the kernel's side (P1, ADR-229,
//! ADR-230).
//!
//! The listener is off unless the image's configuration switches it on
//! (`plaintext.enabled`). Everything it decides is in `urmqtt-plain`, tested
//! on the host; this module holds what has to be shared by the cores (the table
//! of source addresses, the counters), the per-core admission state, and the
//! messages the operator reads.
//!
//! Where a refused connection stops:
//!
//! 1. **At the SYN** ([`PlainState::syn_ok`]): an address outside
//!    `plaintext.allow_from`, a locked-out address, an address at its
//!    connection limit, a full listener or a login rate that is used up get no
//!    SYN-ACK. Nothing is kept: no connection, no table entry.
//! 2. **At the final ACK** ([`PlainState::accept`]): the same checks again
//!    (state may have changed in between) and the counting of the connection.
//! 3. **At the CONNECT** ([`PlainState::decide`]): who the client is (the three
//!    modes), the registry's allowlist, the client id, the stored-session
//!    request. A refusal is a CONNACK and a close, and a failed login counts
//!    toward the lock-out of the source address.

use alloc::boxed::Box;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_config::{CONFIG, PlainAuth};
use urmqtt_log::{info, warn};
use urmqtt_net::admission::{Admission, Limits as AdmissionLimits, Outcome};
use urmqtt_plain::{AllowList, Authenticator, Exposure, Limits, Open, Sources, Syn, Verdict};
use urmqtt_sync::sync::{OnceCell, SpinLock};

/// Counters since boot, all cores (`$SYS/broker/plaintext/...`).
pub struct Stats {
    /// Connections open now (those the table of addresses counts).
    pub open: AtomicU64,
    pub accepted: AtomicU64,
    pub refused_source: AtomicU64,
    pub refused_locked: AtomicU64,
    pub refused_limit: AtomicU64,
    pub refused_registry: AtomicU64,
    pub refused_session: AtomicU64,
    pub auth_ok: AtomicU64,
    pub auth_failed: AtomicU64,
    pub lockouts: AtomicU64,
}

impl Stats {
    const fn new() -> Self {
        Self {
            open: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            refused_source: AtomicU64::new(0),
            refused_locked: AtomicU64::new(0),
            refused_limit: AtomicU64::new(0),
            refused_registry: AtomicU64::new(0),
            refused_session: AtomicU64::new(0),
            auth_ok: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
            lockouts: AtomicU64::new(0),
        }
    }
}

pub static STATS: Stats = Stats::new();

/// Adds one to a statistic and returns the new value (Relaxed: statistics).
fn bump(a: &AtomicU64) -> u64 {
    a.fetch_add(1, Ordering::Relaxed) + 1
}

/// What the cores share, made once at boot.
struct Shared {
    allow: AllowList,
    allow_text: String,
    sources: SpinLock<Sources>,
    /// New connections per second and core that may need a password check.
    auth_rate: u32,
}

static SHARED: OnceCell<Shared> = OnceCell::new();

/// The cost of one password check at the dearest account, nanoseconds
/// ([`measure`]).
static PASSWD_NS: AtomicU64 = AtomicU64::new(0);

/// The plaintext port, if the listener is on.
pub fn port() -> Option<u16> {
    CONFIG.plaintext.enabled.then_some(CONFIG.plaintext.port)
}

fn auth_name() -> &'static str {
    match CONFIG.plaintext.auth {
        PlainAuth::Password => "password",
        PlainAuth::Anonymous => "anonymous",
        PlainAuth::Ip => "ip",
    }
}

/// Times a password check at the dearest configured account and returns its
/// cost in nanoseconds (0: no password mode). The watchdog's handshake budget
/// is sized for it (boot calls this before calibrating) and so is the rate at
/// which new plaintext connections are admitted.
pub fn measure() -> u64 {
    let p = &CONFIG.plaintext;
    if !p.enabled || p.auth != PlainAuth::Password {
        return 0;
    }
    let iterations = u64::from(Authenticator::new(p).max_iterations());
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
        "plaintext: one password check costs about {} us ({iterations} iterations of PBKDF2-HMAC-SHA-256)",
        ns / 1000
    );
    ns
}

/// Makes what the cores share, if the listener is on. Boot calls it once,
/// after the random generator is up and before the data cores start.
pub fn init() {
    let p = &CONFIG.plaintext;
    if !p.enabled {
        return;
    }
    let mut key = [0u8; 8];
    // Fail closed, as for the SYN-cookie key: the table of addresses is hashed
    // under a key an attacker must not know.
    if urmqtt_tls::rng::fill_global(&mut key).is_err() {
        crate::boot::fatal("plaintext: no random generator for the address table's key");
    }
    let allow = AllowList::new(p.allow_from, p.allow_from_anywhere);
    let capacity = (p.max_connections.min(65_536) as usize).saturating_mul(2);
    let sources = Sources::new(
        capacity,
        u64::from_le_bytes(key),
        Limits {
            max_per_ip: p.max_connections_per_ip,
            max_failures: p.max_failed_auths_per_ip,
            lockout_s: p.lockout_s,
        },
    );
    // A password check costs CPU: a core admits at most as many new plaintext
    // connections a second as would use half of it, at least 1 (ADR-267).
    let auth_rate = urmqtt_plain::auth::login_rate(
        PASSWD_NS.load(Ordering::Relaxed),
        CONFIG.limits.handshakes_per_core_per_sec,
    );
    let allow_text = allow.describe();
    let _ = SHARED.set(Shared {
        allow,
        allow_text,
        sources: SpinLock::new(sources),
        auth_rate,
    });
}

/// The networks that may connect, for `$SYS`.
pub fn allow_text() -> &'static str {
    SHARED.get().map_or("", |s| s.allow_text.as_str())
}

/// The numbers `$SYS/broker/plaintext/...` and the info query report.
pub fn info() -> urmqtt_broker::sys::PlainInfo<'static> {
    let p = &CONFIG.plaintext;
    if !p.enabled || SHARED.get().is_none() {
        return urmqtt_broker::sys::PlainInfo::default();
    }
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    urmqtt_broker::sys::PlainInfo {
        enabled: true,
        port: p.port,
        auth: auth_name(),
        allow_from: allow_text(),
        accounts: p.users.len() as u64,
        connections: g(&STATS.open),
        accepted: g(&STATS.accepted),
        refused_source: g(&STATS.refused_source),
        refused_locked: g(&STATS.refused_locked),
        refused_limit: g(&STATS.refused_limit),
        refused_registry: g(&STATS.refused_registry),
        refused_session: g(&STATS.refused_session),
        auth_ok: g(&STATS.auth_ok),
        auth_failed: g(&STATS.auth_failed),
        lockouts: g(&STATS.lockouts),
    }
}

/// The MQTT limits of a plaintext connection's first packet.
pub fn mqtt_limits() -> urmqtt_mqtt::Limits {
    let l = &CONFIG.limits;
    urmqtt_mqtt::Limits {
        max_packet_size: CONFIG.plaintext.max_packet_size,
        max_topic_len: l.max_topic_len as u16,
        max_topic_levels: l.max_topic_levels as u16,
        max_client_id_len: l.max_topic_len as u16,
        max_topics_per_packet: l.max_subscriptions_per_session as u16,
    }
}

/// The broker's rules for plaintext sessions, from the configuration.
pub fn broker_policy() -> Option<urmqtt_broker::PlainPolicy> {
    let p = &CONFIG.plaintext;
    p.enabled.then_some(urmqtt_broker::PlainPolicy {
        publish: p.acl_publish,
        subscribe: p.acl_subscribe,
        max_packet_size: p.max_packet_size,
        rate_tokens: p.publish_rate_per_device.tokens,
        rate_period_ms: p.publish_rate_per_device.per_ms,
        retain: p.retain,
    })
}

/// The log line (once, from one core) that says the listener is on, and the
/// warnings that go with some settings.
pub fn announce(cores: usize) {
    let p = &CONFIG.plaintext;
    if !p.enabled {
        return;
    }
    let who = match p.auth {
        PlainAuth::Password => alloc::format!("password login, {} account(s)", p.users.len()),
        PlainAuth::Anonymous => {
            alloc::format!("no login, every client is {:?}", p.anonymous_identity)
        }
        PlainAuth::Ip => alloc::format!(
            "the client's address decides, {} network(s)",
            p.ip_identities.len()
        ),
    };
    warn!(
        "mqtt: PLAINTEXT listener on port {} (NOT ENCRYPTED): {who}; allowed from {}; at most {} connection(s), {} per address, packets up to {} bytes, {}/{} ms publish rate; \
         {} failed login(s) lock an address out for {} s; {} data core(s)",
        p.port,
        allow_text(),
        p.max_connections,
        p.max_connections_per_ip,
        p.max_packet_size,
        p.publish_rate_per_device.tokens,
        p.publish_rate_per_device.per_ms,
        p.max_failed_auths_per_ip,
        p.lockout_s,
        cores
    );
    if p.allow_from_anywhere {
        warn!(
            "mqtt: plaintext.allow_from_anywhere is set: the plaintext port answers EVERY address. \
             Never use this on a machine with a public address."
        );
    }
    if p.auth == PlainAuth::Anonymous {
        warn!(
            "mqtt: plaintext.auth = \"anonymous\": everybody who can reach the plaintext port is {:?} and may do what acl_publish and acl_subscribe allow",
            p.anonymous_identity
        );
    }
    if p.auth == PlainAuth::Ip {
        warn!(
            "mqtt: plaintext.auth = \"ip\": a client is who its source address says it is; this holds only as far as nobody on the network can forge an address"
        );
    }
}

/// What the listener is told when a CONNECT is decided.
pub enum Decision {
    /// The identity the session gets.
    Accept(&'static str),
    /// The CONNACK return code to answer with; the connection closes.
    Refuse(u8),
}

/// One plaintext connection of this core.
#[derive(Clone, Copy)]
struct PlainConn {
    ip: [u8; 4],
    /// Counted in the table of addresses and in `STATS.open`.
    counted: bool,
    /// Between the final ACK and the CONNECT's decision.
    in_flight: bool,
    t0_ms: u32,
}

/// The plaintext listener of one data core.
pub struct PlainState {
    port: u16,
    auth: Authenticator<'static>,
    adm: Admission,
    /// Each new connection may cost a password check, so it takes a token.
    needs_token: bool,
    conns: urmqtt_mm::slab::Slab<PlainConn>,
    /// The address the exposure was last judged for.
    last_addr: [u8; 4],
    /// Refusals already logged, by kind (logged at powers of two).
    logged: [u64; 4],
}

impl PlainState {
    /// The state of core `me`, if the listener is on and `init` ran.
    pub fn new() -> Option<Box<Self>> {
        let p = &CONFIG.plaintext;
        let shared = SHARED.get()?;
        if !p.enabled {
            return None;
        }
        let l = &CONFIG.limits;
        let needs_token = p.auth == PlainAuth::Password;
        Some(Box::new(Self {
            port: p.port,
            auth: Authenticator::new(p),
            adm: Admission::new(AdmissionLimits {
                per_core: l.max_handshakes_in_flight_per_core,
                per_ip: l.max_handshakes_in_flight_per_ip,
                rate_per_sec: shared.auth_rate,
            }),
            needs_token,
            conns: urmqtt_mm::slab::Slab::new(),
            last_addr: [0; 4],
            logged: [0; 4],
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether `c` is a connection of this listener.
    pub fn has(&self, c: u32) -> bool {
        self.conns.contains(c)
    }

    fn shared() -> Option<&'static Shared> {
        SHARED.get()
    }

    fn log_every_power_of_two(&mut self, kind: usize, n: u64, text: &str) {
        if n.is_power_of_two()
            && let Some(l) = self.logged.get_mut(kind)
            && n > *l
        {
            *l = n;
            warn!("plaintext: {n} {text}");
        }
    }

    /// A SYN for the plaintext port from `ip`: whether to answer it. No state
    /// is kept for a SYN that is refused, and none is made for one that is
    /// answered (the SYN cookie carries it).
    pub fn syn_ok(&mut self, ip: [u8; 4], now_ms: u64, heap_ok: bool, db_behind: bool) -> bool {
        let Some(shared) = Self::shared() else {
            return false;
        };
        if !shared.allow.allows(ip) {
            let n = bump(&STATS.refused_source);
            self.log_every_power_of_two(
                0,
                n,
                "SYN(s) from addresses outside plaintext.allow_from dropped without an answer",
            );
            return false;
        }
        let verdict = shared.sources.lock().syn(ip, (now_ms / 1000) as u32);
        match verdict {
            Syn::LockedOut => {
                let n = bump(&STATS.refused_locked);
                self.log_every_power_of_two(
                    1,
                    n,
                    "SYN(s) from locked-out addresses dropped without an answer",
                );
                return false;
            }
            Syn::TooMany => {
                bump(&STATS.refused_limit);
                return false;
            }
            Syn::Allow => {}
        }
        // Relaxed: statistics; the exact bound is enforced at the ACK.
        if STATS.open.load(Ordering::Relaxed) >= u64::from(CONFIG.plaintext.max_connections) {
            bump(&STATS.refused_limit);
            return false;
        }
        match self
            .adm
            .syn_check(ip, self.needs_token, now_ms, heap_ok, db_behind)
        {
            Ok(()) => true,
            Err(_) => {
                let n = bump(&STATS.refused_limit);
                self.log_every_power_of_two(
                    2,
                    n,
                    "plaintext SYN(s) or connection(s) dropped for a limit (connections, per address, login rate, memory)",
                );
                false
            }
        }
    }

    /// The final ACK of a connection `c` from `ip`: admits and counts it, or
    /// says no (the peer gets a RST).
    pub fn accept(
        &mut self,
        c: u32,
        ip: [u8; 4],
        now_ms: u64,
        heap_ok: bool,
        db_behind: bool,
    ) -> bool {
        let Some(shared) = Self::shared() else {
            return false;
        };
        let now_s = (now_ms / 1000) as u32;
        if !shared.allow.allows(ip) {
            bump(&STATS.refused_source);
            return false;
        }
        if self
            .adm
            .admit(ip, self.needs_token, now_ms, heap_ok, db_behind)
            .is_err()
        {
            bump(&STATS.refused_limit);
            return false;
        }
        // The listener's bound over all cores: count first, then check, so
        // that two cores cannot both take the last place.
        let open = STATS.open.fetch_add(1, Ordering::AcqRel) + 1;
        let refuse = if open > u64::from(CONFIG.plaintext.max_connections) {
            Some(false)
        } else {
            match shared.sources.lock().open(ip, now_s) {
                Open::Ok => None,
                Open::LockedOut => Some(true),
                Open::TooMany | Open::Full => Some(false),
            }
        };
        if let Some(locked) = refuse {
            STATS.open.fetch_sub(1, Ordering::AcqRel);
            self.adm.leave(ip, Outcome::Failed);
            bump(if locked {
                &STATS.refused_locked
            } else {
                &STATS.refused_limit
            });
            return false;
        }
        bump(&STATS.accepted);
        self.conns.insert_at(
            c,
            PlainConn {
                ip,
                counted: true,
                in_flight: true,
                t0_ms: now_ms as u32,
            },
        );
        true
    }

    /// The connection `c` is no longer waiting for its CONNECT (`outcome`
    /// computes how, from the time it was accepted).
    pub fn leave_flight(&mut self, c: u32, outcome: impl Fn(u32) -> Outcome) {
        if let Some(pc) = self.conns.get_mut(c)
            && core::mem::take(&mut pc.in_flight)
        {
            self.adm.leave(pc.ip, outcome(pc.t0_ms));
        }
    }

    /// The connection `c` is gone: gives its place back.
    pub fn release(&mut self, c: u32, now_s: u32) {
        let Some(pc) = self.conns.take_at(c) else {
            return;
        };
        if pc.in_flight {
            self.adm.leave(pc.ip, Outcome::Failed);
        }
        if pc.counted {
            if let Some(shared) = Self::shared() {
                shared.sources.lock().close(pc.ip, now_s);
            }
            STATS.open.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// A first packet that is no CONNECT, or garbage: a failure of the source
    /// address like a wrong password, so a scanner locks itself out.
    pub fn garbage(&mut self, c: u32, now_ms: u64) {
        bump(&STATS.refused_session);
        self.fail(c, now_ms);
    }

    fn fail(&mut self, c: u32, now_ms: u64) {
        let (Some(pc), Some(shared)) = (self.conns.get(c).copied(), Self::shared()) else {
            return;
        };
        let locked = shared.sources.lock().failed(pc.ip, (now_ms / 1000) as u32);
        if locked {
            let n = bump(&STATS.lockouts);
            let [a, b, c, d] = pc.ip;
            warn!(
                "plaintext: {a}.{b}.{c}.{d} is locked out for {} s after {} failed login(s) ({n} lock-out(s) so far)",
                CONFIG.plaintext.lockout_s, CONFIG.plaintext.max_failed_auths_per_ip
            );
        }
    }

    /// Decides the CONNECT of connection `c` (the packet is parsed already).
    pub fn decide(&mut self, c: u32, p: &crate::mqtt5::ConnectView<'_>, now_ms: u64) -> Decision {
        let Some(pc) = self.conns.get(c).copied() else {
            return Decision::Refuse(5);
        };
        let verdict = self.auth.authenticate(pc.ip, p.username, p.password);
        let identity = match verdict {
            Verdict::Accept(id) => id,
            Verdict::Reject(why) => {
                let n = bump(&STATS.auth_failed);
                if n.is_power_of_two() {
                    let [a, b, cc, d] = pc.ip;
                    // The user name is not printed: the client chose it.
                    warn!(
                        "plaintext: login refused for {a}.{b}.{cc}.{d} ({}), {n} so far",
                        why.text()
                    );
                }
                self.fail(c, now_ms);
                return Decision::Refuse(verdict.connack_code().unwrap_or(5));
            }
        };
        if let Some(shared) = Self::shared() {
            shared.sources.lock().succeeded(pc.ip);
        }
        bump(&STATS.auth_ok);
        // The client id is only the tail of the session's name, so it is free
        // (mosquitto's default one has a slash), and a clean session may bring
        // none at all: the broker names it (MQTT 3.1.1 3.1.3.1, which also says
        // that none with a stored session is refused as an identifier).
        if p.client_id.is_empty() && !p.clean_session {
            bump(&STATS.refused_session);
            return Decision::Refuse(2);
        }
        // A stored session is not available to a plaintext client (ADR-230).
        if !p.clean_session {
            bump(&STATS.refused_session);
            return Decision::Refuse(5);
        }
        // The registry's allowlist applies to plaintext identities too (H1).
        if !crate::control::admitted(identity) {
            let n = bump(&STATS.refused_registry);
            if n.is_power_of_two() {
                warn!(
                    "registry: plaintext login {identity} is not on the allowlist, refused ({n} so far)"
                );
            }
            return Decision::Refuse(5);
        }
        Decision::Accept(identity)
    }

    /// Once in a while (the service's 100 ms tick): judges the exposure when the
    /// interface address becomes known or changes, and warns if it is public.
    pub fn tick(&mut self, local: [u8; 4], first_core: bool) {
        if local == self.last_addr {
            return;
        }
        self.last_addr = local;
        if !first_core || local == [0; 4] {
            return;
        }
        let Some(shared) = Self::shared() else {
            return;
        };
        let [a, b, c, d] = local;
        match shared.allow.exposure(local) {
            Exposure::Private => {}
            Exposure::PublicAddressPrivateAllowList => warn!(
                "plaintext: this machine has a public address ({a}.{b}.{c}.{d}); only private networks may connect to the plaintext port, \
                 which holds only while the network between them cannot forge an address. Keep a firewall in front."
            ),
            Exposure::Open => warn!(
                "plaintext: this machine has a PUBLIC address ({a}.{b}.{c}.{d}) and the plaintext port admits public addresses: \
                 everything on that port can be read and changed by anyone on the way. Narrow plaintext.allow_from, or use TLS."
            ),
        }
    }
}
