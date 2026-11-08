//! The system namespace `$SYS/` (O1, O2, ADR-060): what the broker says
//! about itself, the console command parser and its rate limiter.
//!
//! Pure functions over plain values, so they are tested on the host. The
//! kernel gathers the numbers ([`Info`]) and runs the commands; the broker
//! only carries the messages ([`crate::Broker::sys_publish`],
//! [`crate::Broker::console_line`], [`crate::Broker::drain_sys_requests`]).

use alloc::string::String;
use core::fmt::Write;

/// Statistics prefix; every retained `$SYS/broker/...` topic starts here.
pub const BROKER_PREFIX: &str = "$SYS/broker";
/// The console's output: kernel log lines and command replies.
pub const CONSOLE_OUT: &str = "$SYS/console/out";
/// The console's input: one command per message (operator only).
pub const CONSOLE_IN: &str = "$SYS/console/in";
/// The request topic (operator only); the JSON reply goes to
/// [`QUERY_INFO_RESPONSE`]. MQTT 3.1.1 has no Response Topic property, so
/// the reply topic is fixed (ADR-060).
pub const QUERY_INFO: &str = "$SYS/query/info";
pub const QUERY_INFO_RESPONSE: &str = "$SYS/query/info/response";

/// Console lines a shard keeps to replay to a new subscriber.
pub const CONSOLE_RING: usize = 64;
/// Longest console command, bytes.
pub const MAX_COMMAND: usize = 64;
/// Operator requests held between drains; beyond this they are dropped.
pub const MAX_REQUESTS: usize = 16;

/// What connection admission did (all cores, since boot; PERF, ADR-080).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Handshakes {
    /// Connections admitted (their TCP handshake completed and admission
    /// let them in).
    pub started: u64,
    /// TLS handshakes completed.
    pub done: u64,
    /// Ended before completing.
    pub failed: u64,
    /// Not finished within the handshake timeout.
    pub timed_out: u64,
    /// Refused at the final ACK (a RST was sent).
    pub refused: u64,
    /// SYNs dropped without an answer.
    pub syn_dropped: u64,
    /// In flight now.
    pub in_flight: u64,
    /// The most in flight on one core in the last 5 s.
    pub in_flight_max: u64,
    /// Completed handshakes slower than 250 ms.
    pub slow: u64,
    /// Sum of accept-to-done times of completed handshakes, ms.
    pub latency_sum_ms: u64,
    /// The longest accept-to-done time on one core in the last 5 s, ms.
    pub latency_max_ms: u64,
}

/// Messages and frames the broker did not deliver, by cause (PERF, ADR-223).
/// QoS 0 loss under overload is deliberate and bounded; it is also counted
/// here, per cause, so that it is never silent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops {
    /// QoS 0: the subscriber's output buffer was full.
    pub slow_subscriber: u64,
    /// QoS 0: the subscriber's client is not connected.
    pub offline: u64,
    /// QoS 0 fan-out to another core: that core was too far behind.
    pub cross_core: u64,
    /// QoS 1: the session's queue was full.
    pub qos1_queue_full: u64,
    /// Publishes refused by the per-identity rate limit.
    pub publish_rate: u64,
    /// Frames (TCP retransmits them) dropped because a worker core was behind.
    pub frames_steer: u64,
    /// ... because the dispatcher was behind.
    pub frames_worker_tx: u64,
    /// ... because the NIC queue and the dispatcher's backlog were full.
    pub frames_nic: u64,
}

/// The plaintext listener, as `$SYS/broker/plaintext/...` reports it (P1,
/// ADR-230). Counters are since boot, all cores together.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainInfo<'a> {
    pub enabled: bool,
    pub port: u16,
    /// `password`, `anonymous` or `ip`.
    pub auth: &'a str,
    /// The networks that may connect, or `anywhere`.
    pub allow_from: &'a str,
    pub accounts: u64,
    /// Connections open now.
    pub connections: u64,
    /// Connections accepted.
    pub accepted: u64,
    /// SYNs dropped because the address is not in `allow_from`.
    pub refused_source: u64,
    /// SYNs dropped because the address is locked out.
    pub refused_locked: u64,
    /// Connections or SYNs refused for a limit: all connections, per address,
    /// in flight, the login rate, memory.
    pub refused_limit: u64,
    /// Logins refused because the identity is not on the allowlist.
    pub refused_registry: u64,
    /// CONNECT packets refused for the session (a stored session was asked for, a
    /// client id that cannot be used).
    pub refused_session: u64,
    pub auth_ok: u64,
    pub auth_failed: u64,
    /// Addresses locked out for failed logins.
    pub lockouts: u64,
}

/// The close codes the WebSocket counters keep apart (ADR-272); anything else
/// is `other`.
pub const WS_CLOSE_CODES: [&str; 9] = [
    "1000", "1001", "1002", "1003", "1007", "1008", "1009", "1011", "other",
];

/// The index of `code` in [`WS_CLOSE_CODES`].
pub fn ws_close_index(code: u16) -> usize {
    match code {
        1000 => 0,
        1001 => 1,
        1002 => 2,
        1003 => 3,
        1007 => 4,
        1008 => 5,
        1009 => 6,
        1011 => 7,
        _ => 8,
    }
}

/// Why an upgrade was refused, as the counters name them (ADR-272): the six
/// answers of the request parser, then the listener's own.
pub const WS_REFUSALS: [&str; 10] = [
    "request",
    "method",
    "path",
    "version",
    "protocol",
    "origin",
    "too_large",
    "timeout",
    "limit",
    "locked_out",
];

/// The WebSocket listener, as `$SYS/broker/websocket/...` reports it
/// (ADR-272). Counters are since boot, all cores together.
#[derive(Debug, Clone, Copy, Default)]
pub struct WsInfo<'a> {
    pub enabled: bool,
    pub port: u16,
    pub path: &'a str,
    /// `mtls` or `password`.
    pub auth: &'a str,
    /// Entries of `websocket.origins` (0: any origin).
    pub origins: u64,
    pub accounts: u64,
    /// Connections open now.
    pub connections: u64,
    /// TCP connections accepted.
    pub accepted: u64,
    /// Upgrades answered 101.
    pub upgrades: u64,
    /// Refused upgrades and connections, by [`WS_REFUSALS`].
    pub refused: [u64; 10],
    pub auth_ok: u64,
    pub auth_failed: u64,
    pub lockouts: u64,
    /// Data and control frames from clients, and frames sent to them.
    pub frames_in: u64,
    pub frames_out: u64,
    /// MQTT bytes carried in each direction (frame payload).
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Close frames received from clients and sent by the broker, by
    /// [`WS_CLOSE_CODES`]; `closes_abrupt`: connections that ended without
    /// the client's close frame.
    pub closes_client: [u64; 9],
    pub closes_server: [u64; 9],
    pub closes_abrupt: u64,
}

/// Everything `$SYS/broker/...` and the info query report.
#[derive(Debug, Clone, Copy)]
pub struct Info<'a> {
    pub version: &'a str,
    pub uptime_s: u64,
    pub arch: &'a str,
    /// Busy percentage per core (its length is the core count).
    pub busy: &'a [u8],
    pub memory_total: u64,
    pub memory_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    pub clients_connected: u64,
    pub clients_total: u64,
    pub subscriptions: u64,
    pub retained: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
    pub connections_refused: u64,
    /// Days until the server certificate expires; `None`: no wall clock.
    pub server_cert_days: Option<i64>,
    /// Where the wall clock comes from: `rtc`, `sntp` or `unknown` (T1).
    pub time_source: &'a str,
    /// The last SNTP offset against the clock as it was, ms; `None`: none
    /// measured against a known clock yet.
    pub time_offset_ms: Option<i64>,
    /// What seeded the random number generator at boot (ADR-263), from
    /// [`entropy_source`]: `virtio-rng`, `rndr`, `virtio-rng+rndr`,
    /// `jitter+firmware`, ...
    pub entropy_source: &'a str,
    /// Console lines lost because a reader fell behind.
    pub console_dropped: u64,
    /// The link MTU in use, bytes (NOW-19, ADR-264): from DHCP option 26,
    /// `network.mtu`, or 1500.
    pub net_mtu: u16,
    pub drops: Drops,
    pub handshakes: Handshakes,
    /// Connections accepted per core since boot (how evenly the flows
    /// spread over the cores).
    pub accepted: &'a [u64],
    pub plaintext: PlainInfo<'a>,
    pub websocket: WsInfo<'a>,
}

/// The name of what seeded the random number generator, for
/// `$SYS/broker/entropy/source` (ADR-263): the hardware sources that
/// delivered (`virtio-rng`, then the CPU's own, `cpu` is `rndr` or
/// `rdrand`), joined by `+`; without any, the fallback: `jitter+firmware`
/// (`jitter` alone when the bootloader gave no non-zero value), or `none`
/// when the jitter fallback did not run either.
pub fn entropy_source(virtio_rng: bool, cpu: Option<&str>, jitter: bool, firmware: bool) -> String {
    let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    if virtio_rng {
        parts.push("virtio-rng");
    }
    if let Some(c) = cpu {
        parts.push(c);
    }
    if parts.is_empty() {
        if jitter {
            parts.push("jitter");
        }
        if firmware && jitter {
            parts.push("firmware");
        }
    }
    if parts.is_empty() {
        return "none".into();
    }
    parts.join("+")
}

/// Calls `f(topic, payload)` for every retained topic, in a fixed order.
pub fn topics(i: &Info<'_>, mut f: impl FnMut(&str, &str)) {
    let mut put = |suffix: &str, v: &dyn core::fmt::Display| {
        let mut topic = String::with_capacity(BROKER_PREFIX.len() + 1 + suffix.len());
        let _ = write!(topic, "{BROKER_PREFIX}/{suffix}");
        let mut val = String::new();
        let _ = write!(val, "{v}");
        f(&topic, &val);
    };
    put("version", &i.version);
    put("uptime", &i.uptime_s);
    put("arch", &i.arch);
    put("cpu/cores", &i.busy.len());
    for (core, b) in i.busy.iter().enumerate() {
        put(&alloc::format!("cpu/busy/{core}"), b);
    }
    put("memory/total", &i.memory_total);
    put("memory/used", &i.memory_used);
    put("disk/total", &i.disk_total);
    put("disk/used", &i.disk_used);
    put("clients/connected", &i.clients_connected);
    put("clients/total", &i.clients_total);
    put("subscriptions", &i.subscriptions);
    put("retained", &i.retained);
    put("messages/received", &i.messages_received);
    put("messages/sent", &i.messages_sent);
    put("connections/refused", &i.connections_refused);
    match i.server_cert_days {
        Some(d) => put("tls/server_cert_days", &d),
        None => put("tls/server_cert_days", &"unknown"),
    }
    put("time/source", &i.time_source);
    match i.time_offset_ms {
        Some(o) => put("time/offset_ms", &o),
        None => put("time/offset_ms", &"unknown"),
    }
    put("entropy/source", &i.entropy_source);
    put("console/dropped", &i.console_dropped);
    put("net/mtu", &i.net_mtu);
    let d = &i.drops;
    put("messages/dropped/slow_subscriber", &d.slow_subscriber);
    put("messages/dropped/offline", &d.offline);
    put("messages/dropped/cross_core", &d.cross_core);
    put("messages/dropped/qos1_queue_full", &d.qos1_queue_full);
    put("messages/dropped/publish_rate", &d.publish_rate);
    put("frames/dropped/steer", &d.frames_steer);
    put("frames/dropped/worker_tx", &d.frames_worker_tx);
    put("frames/dropped/nic", &d.frames_nic);
    let h = &i.handshakes;
    put("handshakes/started", &h.started);
    put("handshakes/done", &h.done);
    put("handshakes/failed", &h.failed);
    put("handshakes/timed_out", &h.timed_out);
    put("handshakes/refused", &h.refused);
    put("handshakes/syn_dropped", &h.syn_dropped);
    put("handshakes/in_flight", &h.in_flight);
    put("handshakes/in_flight_max", &h.in_flight_max);
    put("handshakes/slow", &h.slow);
    put("handshakes/latency_sum_ms", &h.latency_sum_ms);
    put("handshakes/latency_max_ms", &h.latency_max_ms);
    for (core, a) in i.accepted.iter().enumerate() {
        put(&alloc::format!("cpu/accepted/{core}"), a);
    }
    // The plaintext listener (P1): one topic while it is off.
    let p = &i.plaintext;
    put("plaintext/enabled", &p.enabled);
    if p.enabled {
        put("plaintext/port", &p.port);
        put("plaintext/auth", &p.auth);
        put("plaintext/allow_from", &p.allow_from);
        put("plaintext/accounts", &p.accounts);
        put("plaintext/connections", &p.connections);
        put("plaintext/accepted", &p.accepted);
        put("plaintext/refused/source", &p.refused_source);
        put("plaintext/refused/locked_out", &p.refused_locked);
        put("plaintext/refused/limit", &p.refused_limit);
        put("plaintext/refused/registry", &p.refused_registry);
        put("plaintext/refused/session", &p.refused_session);
        put("plaintext/auth_ok", &p.auth_ok);
        put("plaintext/auth_failed", &p.auth_failed);
        put("plaintext/lockouts", &p.lockouts);
    }
    // The WebSocket listener (ADR-272): one topic while it is off.
    let w = &i.websocket;
    put("websocket/enabled", &w.enabled);
    if w.enabled {
        put("websocket/port", &w.port);
        put("websocket/path", &w.path);
        put("websocket/auth", &w.auth);
        put("websocket/origins", &w.origins);
        put("websocket/accounts", &w.accounts);
        put("websocket/connections", &w.connections);
        put("websocket/accepted", &w.accepted);
        put("websocket/upgrades", &w.upgrades);
        for (name, n) in WS_REFUSALS.iter().zip(w.refused) {
            put(&alloc::format!("websocket/refused/{name}"), &n);
        }
        put("websocket/auth_ok", &w.auth_ok);
        put("websocket/auth_failed", &w.auth_failed);
        put("websocket/lockouts", &w.lockouts);
        put("websocket/frames/in", &w.frames_in);
        put("websocket/frames/out", &w.frames_out);
        put("websocket/bytes/in", &w.bytes_in);
        put("websocket/bytes/out", &w.bytes_out);
        for (code, n) in WS_CLOSE_CODES.iter().zip(w.closes_client) {
            put(&alloc::format!("websocket/close/client/{code}"), &n);
        }
        for (code, n) in WS_CLOSE_CODES.iter().zip(w.closes_server) {
            put(&alloc::format!("websocket/close/server/{code}"), &n);
        }
        put("websocket/close/abrupt", &w.closes_abrupt);
    }
}

/// The topics of [`topics`] as a list, for tests and the docs (with the
/// plaintext listener on, so every topic is listed).
pub fn topic_names(cores: usize) -> alloc::vec::Vec<String> {
    let busy = alloc::vec![0u8; cores];
    let accepted = alloc::vec![0u64; cores];
    let info = Info {
        version: "",
        uptime_s: 0,
        arch: "",
        busy: &busy,
        memory_total: 0,
        memory_used: 0,
        disk_total: 0,
        disk_used: 0,
        clients_connected: 0,
        clients_total: 0,
        subscriptions: 0,
        retained: 0,
        messages_received: 0,
        messages_sent: 0,
        connections_refused: 0,
        server_cert_days: None,
        time_source: "",
        time_offset_ms: None,
        entropy_source: "",
        console_dropped: 0,
        net_mtu: 1500,
        drops: Drops::default(),
        handshakes: Handshakes::default(),
        accepted: &accepted,
        plaintext: PlainInfo {
            enabled: true,
            ..PlainInfo::default()
        },
        websocket: WsInfo {
            enabled: true,
            ..WsInfo::default()
        },
    };
    let mut v = alloc::vec::Vec::new();
    topics(&info, |t, _| v.push(t.into()));
    v
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The same numbers as one JSON document (the reply to [`QUERY_INFO`]).
pub fn json(i: &Info<'_>) -> String {
    let mut o = String::with_capacity(512);
    o.push_str("{\"version\":");
    json_str(&mut o, i.version);
    let _ = write!(o, ",\"uptime_s\":{},\"arch\":", i.uptime_s);
    json_str(&mut o, i.arch);
    let _ = write!(o, ",\"cpu\":{{\"cores\":{},\"busy\":[", i.busy.len());
    for (n, b) in i.busy.iter().enumerate() {
        let _ = write!(o, "{}{b}", if n == 0 { "" } else { "," });
    }
    let _ = write!(
        o,
        "]}},\"memory\":{{\"total\":{},\"used\":{}}},\"disk\":{{\"total\":{},\"used\":{}}},\
         \"clients\":{{\"connected\":{},\"total\":{}}},\"subscriptions\":{},\"retained\":{},\
         \"messages\":{{\"received\":{},\"sent\":{}}},\"connections_refused\":{},\
         \"tls\":{{\"server_cert_days\":",
        i.memory_total,
        i.memory_used,
        i.disk_total,
        i.disk_used,
        i.clients_connected,
        i.clients_total,
        i.subscriptions,
        i.retained,
        i.messages_received,
        i.messages_sent,
        i.connections_refused
    );
    match i.server_cert_days {
        Some(d) => {
            let _ = write!(o, "{d}");
        }
        None => o.push_str("null"),
    }
    o.push_str("},\"time\":{\"source\":");
    json_str(&mut o, i.time_source);
    o.push_str(",\"offset_ms\":");
    match i.time_offset_ms {
        Some(d) => {
            let _ = write!(o, "{d}");
        }
        None => o.push_str("null"),
    }
    let h = &i.handshakes;
    let d = &i.drops;
    o.push_str("},\"entropy\":{\"source\":");
    json_str(&mut o, i.entropy_source);
    let _ = write!(
        o,
        "}},\"console_dropped\":{},\"net\":{{\"mtu\":{}}},\"dropped\":{{\"slow_subscriber\":{},\"offline\":{},\"cross_core\":{},\
         \"qos1_queue_full\":{},\"publish_rate\":{},\"frames_steer\":{},\"frames_worker_tx\":{},\"frames_nic\":{}}},\
         \"handshakes\":{{\"started\":{},\"done\":{},\"failed\":{},\
         \"timed_out\":{},\"refused\":{},\"syn_dropped\":{},\"in_flight\":{},\"in_flight_max\":{},\
         \"slow\":{},\"latency_sum_ms\":{},\"latency_max_ms\":{}}},\"accepted\":[",
        i.console_dropped,
        i.net_mtu,
        d.slow_subscriber,
        d.offline,
        d.cross_core,
        d.qos1_queue_full,
        d.publish_rate,
        d.frames_steer,
        d.frames_worker_tx,
        d.frames_nic,
        h.started,
        h.done,
        h.failed,
        h.timed_out,
        h.refused,
        h.syn_dropped,
        h.in_flight,
        h.in_flight_max,
        h.slow,
        h.latency_sum_ms,
        h.latency_max_ms
    );
    for (n, a) in i.accepted.iter().enumerate() {
        let _ = write!(o, "{}{a}", if n == 0 { "" } else { "," });
    }
    o.push(']');
    let p = &i.plaintext;
    let _ = write!(o, ",\"plaintext\":{{\"enabled\":{}", p.enabled);
    if p.enabled {
        let _ = write!(o, ",\"port\":{},\"auth\":", p.port);
        json_str(&mut o, p.auth);
        o.push_str(",\"allow_from\":");
        json_str(&mut o, p.allow_from);
        let _ = write!(
            o,
            ",\"accounts\":{},\"connections\":{},\"accepted\":{},\"refused\":{{\"source\":{},\"locked_out\":{},\"limit\":{},\"registry\":{},\"session\":{}}},\
             \"auth_ok\":{},\"auth_failed\":{},\"lockouts\":{}",
            p.accounts,
            p.connections,
            p.accepted,
            p.refused_source,
            p.refused_locked,
            p.refused_limit,
            p.refused_registry,
            p.refused_session,
            p.auth_ok,
            p.auth_failed,
            p.lockouts
        );
    }
    o.push('}');
    let w = &i.websocket;
    let _ = write!(o, ",\"websocket\":{{\"enabled\":{}", w.enabled);
    if w.enabled {
        let _ = write!(o, ",\"port\":{},\"path\":", w.port);
        json_str(&mut o, w.path);
        o.push_str(",\"auth\":");
        json_str(&mut o, w.auth);
        let _ = write!(
            o,
            ",\"origins\":{},\"accounts\":{},\"connections\":{},\"accepted\":{},\"upgrades\":{},\"refused\":{{",
            w.origins, w.accounts, w.connections, w.accepted, w.upgrades
        );
        for (n, (name, v)) in WS_REFUSALS.iter().zip(w.refused).enumerate() {
            let _ = write!(o, "{}\"{name}\":{v}", if n == 0 { "" } else { "," });
        }
        let _ = write!(
            o,
            "}},\"auth_ok\":{},\"auth_failed\":{},\"lockouts\":{},\"frames\":{{\"in\":{},\"out\":{}}},\"bytes\":{{\"in\":{},\"out\":{}}},\"close\":{{\"abrupt\":{}",
            w.auth_ok,
            w.auth_failed,
            w.lockouts,
            w.frames_in,
            w.frames_out,
            w.bytes_in,
            w.bytes_out,
            w.closes_abrupt
        );
        for (side, counts) in [("client", w.closes_client), ("server", w.closes_server)] {
            let _ = write!(o, ",\"{side}\":{{");
            for (n, (code, v)) in WS_CLOSE_CODES.iter().zip(counts).enumerate() {
                let _ = write!(o, "{}\"{code}\":{v}", if n == 0 { "" } else { "," });
            }
            o.push('}');
        }
        o.push('}');
    }
    o.push_str("}}");
    o
}

/// The reply to `status`, one console line each.
pub fn status_lines(i: &Info<'_>, level: &str, max_level: &str) -> alloc::vec::Vec<String> {
    let mib = |b: u64| b >> 20;
    let mut out = alloc::vec::Vec::new();
    out.push(alloc::format!(
        "urmqtt {} {} up {} s",
        i.version,
        i.arch,
        i.uptime_s
    ));
    let mut busy = String::new();
    for (n, b) in i.busy.iter().enumerate() {
        let _ = write!(busy, "{}{b}", if n == 0 { "" } else { "/" });
    }
    out.push(alloc::format!(
        "cpu {} core(s), busy % {busy}",
        i.busy.len()
    ));
    out.push(alloc::format!(
        "memory {} of {} MiB used, disk {} of {} MiB used",
        mib(i.memory_used),
        mib(i.memory_total),
        mib(i.disk_used),
        mib(i.disk_total)
    ));
    out.push(alloc::format!(
        "clients {} connected, {} sessions, {} subscription(s), {} retained",
        i.clients_connected,
        i.clients_total,
        i.subscriptions,
        i.retained
    ));
    out.push(alloc::format!(
        "messages {} received, {} sent, {} connection(s) refused",
        i.messages_received,
        i.messages_sent,
        i.connections_refused
    ));
    match i.server_cert_days {
        Some(d) => out.push(alloc::format!(
            "tls server certificate valid for {d} day(s)"
        )),
        None => out.push("tls server certificate lifetime unknown (no wall clock)".into()),
    }
    match i.time_offset_ms {
        Some(o) => out.push(alloc::format!(
            "time source {}, last sntp offset {o} ms",
            i.time_source
        )),
        None => out.push(alloc::format!("time source {}", i.time_source)),
    }
    out.push(alloc::format!("entropy source {}", i.entropy_source));
    let d = &i.drops;
    out.push(alloc::format!(
        "dropped QoS0 slow {} offline {} xcore {}; QoS1 {}; rate {}; frames {}/{}/{}",
        d.slow_subscriber,
        d.offline,
        d.cross_core,
        d.qos1_queue_full,
        d.publish_rate,
        d.frames_steer,
        d.frames_worker_tx,
        d.frames_nic
    ));
    let p = &i.plaintext;
    if p.enabled {
        out.push(alloc::format!(
            "plaintext MQTT ON (not encrypted): port {}, auth {}, from {}; {} open, {} accepted, \
             {} login(s) failed, {} lock-out(s); SYNs dropped: {} not allowed, {} locked out",
            p.port,
            p.auth,
            p.allow_from,
            p.connections,
            p.accepted,
            p.auth_failed,
            p.lockouts,
            p.refused_source,
            p.refused_locked
        ));
    }
    let w = &i.websocket;
    if w.enabled {
        let refused: u64 = w.refused.iter().sum();
        out.push(alloc::format!(
            "websocket (wss) ON: port {} path {}, auth {}, {} origin(s); {} open, {} upgrade(s), {} refused, {} login(s) failed, {} lock-out(s)",
            w.port,
            w.path,
            w.auth,
            w.origins,
            w.connections,
            w.upgrades,
            refused,
            w.auth_failed,
            w.lockouts
        ));
    }
    out.push(alloc::format!(
        "log level {level} (build maximum {max_level}), {} console line(s) dropped",
        i.console_dropped
    ));
    out
}

/// A log level a command can set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// The whole command set. Nothing else is ever executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Help,
    Status,
    LogLevel(Level),
    Reboot,
}

/// Why a console line is not a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Empty,
    TooLong,
    /// Not printable ASCII on one line.
    NotText,
    Unknown,
    /// A known command with a missing or invalid argument.
    Usage,
}

impl Refused {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong => "too long",
            Self::NotText => "not one line of printable ASCII",
            Self::Unknown => "unknown command",
            Self::Usage => "wrong arguments",
        }
    }
}

/// The help text, one console line each.
pub const HELP: &[&str] = &[
    "commands: help | status | log level <error|warn|info|debug|trace> | reboot",
    "one command per message on $SYS/console/in; no shell, nothing else runs",
];

/// Parses one console message. Leading and trailing whitespace (including
/// the newline a terminal adds) is ignored; case is not.
pub fn parse(payload: &[u8]) -> Result<Command, Refused> {
    let text = core::str::from_utf8(payload).map_err(|_| Refused::NotText)?;
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    if text.is_empty() {
        return Err(Refused::Empty);
    }
    if text.len() > MAX_COMMAND {
        return Err(Refused::TooLong);
    }
    if !text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Refused::NotText);
    }
    let mut words = text.split(' ').filter(|w| !w.is_empty());
    let cmd = words.next().ok_or(Refused::Empty)?;
    let rest: alloc::vec::Vec<&str> = words.collect();
    match (cmd, rest.as_slice()) {
        ("help", []) => Ok(Command::Help),
        ("status", []) => Ok(Command::Status),
        ("reboot", []) => Ok(Command::Reboot),
        ("log", ["level", lvl]) => Ok(Command::LogLevel(match *lvl {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => return Err(Refused::Usage),
        })),
        ("help" | "status" | "reboot" | "log", _) => Err(Refused::Usage),
        _ => Err(Refused::Unknown),
    }
}

/// Token bucket for console commands and queries: a burst, then one per
/// period. Shared by every operator on a shard.
#[derive(Debug, Clone, Copy)]
pub struct Limiter {
    burst: u32,
    period_ms: u64,
    tokens: u32,
    refilled_ms: u64,
}

impl Limiter {
    pub const fn new(burst: u32, period_ms: u64) -> Self {
        Self {
            burst,
            period_ms,
            tokens: burst,
            refilled_ms: 0,
        }
    }

    /// Takes a token at `now_ms`; false if none is left.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.refilled_ms);
        let refill = elapsed / self.period_ms.max(1);
        if refill > 0 {
            self.tokens = u32::try_from(refill)
                .unwrap_or(u32::MAX)
                .saturating_add(self.tokens)
                .min(self.burst);
            self.refilled_ms = self
                .refilled_ms
                .saturating_add(refill * self.period_ms.max(1));
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(busy: &[u8]) -> Info<'_> {
        Info {
            version: "0.1.0",
            uptime_s: 12,
            arch: "aarch64",
            busy,
            memory_total: 1000,
            memory_used: 400,
            disk_total: 0,
            disk_used: 0,
            clients_connected: 3,
            clients_total: 5,
            subscriptions: 7,
            retained: 2,
            messages_received: 100,
            messages_sent: 250,
            connections_refused: 1,
            server_cert_days: Some(90),
            time_source: "sntp",
            time_offset_ms: Some(-12),
            entropy_source: "jitter+firmware",
            console_dropped: 0,
            net_mtu: 1460,
            drops: Drops {
                slow_subscriber: 3,
                ..Drops::default()
            },
            handshakes: Handshakes {
                started: 9,
                done: 8,
                ..Handshakes::default()
            },
            accepted: &[4, 5],
            plaintext: PlainInfo::default(),
            websocket: WsInfo::default(),
        }
    }

    #[test]
    fn the_websocket_listener_is_reported_when_it_is_on() {
        let mut on = info(&[10]);
        let mut refused = [0u64; 10];
        refused[5] = 3;
        let mut closes = [0u64; 9];
        closes[ws_close_index(1000)] = 7;
        closes[ws_close_index(4000)] = 1;
        on.websocket = WsInfo {
            enabled: true,
            port: 8084,
            path: "/mqtt",
            auth: "password",
            origins: 2,
            accounts: 4,
            connections: 5,
            accepted: 6,
            upgrades: 5,
            refused,
            auth_ok: 4,
            auth_failed: 1,
            lockouts: 0,
            frames_in: 100,
            frames_out: 90,
            bytes_in: 1000,
            bytes_out: 900,
            closes_client: closes,
            closes_server: [0; 9],
            closes_abrupt: 2,
        };
        let mut got = alloc::vec::Vec::new();
        topics(&on, |t, v| got.push((t.to_owned(), v.to_owned())));
        let val = |t: &str| got.iter().find(|(k, _)| k == t).map(|(_, v)| v.as_str());
        assert_eq!(val("$SYS/broker/websocket/enabled"), Some("true"));
        assert_eq!(val("$SYS/broker/websocket/path"), Some("/mqtt"));
        assert_eq!(val("$SYS/broker/websocket/refused/origin"), Some("3"));
        assert_eq!(val("$SYS/broker/websocket/close/client/1000"), Some("7"));
        assert_eq!(val("$SYS/broker/websocket/close/client/other"), Some("1"));
        assert_eq!(val("$SYS/broker/websocket/close/abrupt"), Some("2"));
        let on_names: alloc::vec::Vec<&str> = got
            .iter()
            .map(|(t, _)| t.as_str())
            .filter(|t| t.starts_with("$SYS/broker/websocket/"))
            .collect();
        let all = topic_names(1);
        let listed: alloc::vec::Vec<&str> = all
            .iter()
            .map(String::as_str)
            .filter(|t| t.starts_with("$SYS/broker/websocket/"))
            .collect();
        assert_eq!(on_names, listed);
        let j = json(&on);
        assert!(j.contains("\"websocket\":{\"enabled\":true,\"port\":8084,\"path\":\"/mqtt\",\"auth\":\"password\",\"origins\":2,\"accounts\":4,\"connections\":5,\"accepted\":6,\"upgrades\":5,\"refused\":{\"request\":0,\"method\":0,\"path\":0,\"version\":0,\"protocol\":0,\"origin\":3,\"too_large\":0,\"timeout\":0,\"limit\":0,\"locked_out\":0},\"auth_ok\":4,\"auth_failed\":1,\"lockouts\":0,\"frames\":{\"in\":100,\"out\":90},\"bytes\":{\"in\":1000,\"out\":900},\"close\":{\"abrupt\":2,\"client\":{\"1000\":7,"), "{j}");
        assert!(j.ends_with("}}}}"), "{j}");
        // Off: one key, and the JSON stays well formed.
        let off = json(&info(&[10]));
        assert!(
            off.ends_with(",\"websocket\":{\"enabled\":false}}"),
            "{off}"
        );
        let lines = status_lines(&on, "info", "debug");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("websocket (wss) ON: port 8084 path /mqtt, auth password")),
            "{lines:?}"
        );
    }

    fn plain_on() -> PlainInfo<'static> {
        PlainInfo {
            enabled: true,
            port: 1883,
            auth: "password",
            allow_from: "10.0.0.0/8, 192.168.0.0/16",
            accounts: 3,
            connections: 4,
            accepted: 40,
            refused_source: 5,
            refused_locked: 6,
            refused_limit: 7,
            refused_registry: 8,
            refused_session: 9,
            auth_ok: 30,
            auth_failed: 10,
            lockouts: 2,
        }
    }

    #[test]
    fn the_plaintext_listener_is_reported_when_it_is_on() {
        let mut on = info(&[10]);
        on.plaintext = plain_on();
        let mut got = alloc::vec::Vec::new();
        topics(&on, |t, v| got.push((t.to_owned(), v.to_owned())));
        let val = |t: &str| got.iter().find(|(k, _)| k == t).map(|(_, v)| v.as_str());
        assert_eq!(val("$SYS/broker/plaintext/enabled"), Some("true"));
        assert_eq!(val("$SYS/broker/plaintext/port"), Some("1883"));
        assert_eq!(val("$SYS/broker/plaintext/auth"), Some("password"));
        assert_eq!(
            val("$SYS/broker/plaintext/allow_from"),
            Some("10.0.0.0/8, 192.168.0.0/16")
        );
        assert_eq!(val("$SYS/broker/plaintext/connections"), Some("4"));
        assert_eq!(val("$SYS/broker/plaintext/refused/source"), Some("5"));
        assert_eq!(val("$SYS/broker/plaintext/refused/locked_out"), Some("6"));
        assert_eq!(val("$SYS/broker/plaintext/auth_failed"), Some("10"));
        assert_eq!(val("$SYS/broker/plaintext/lockouts"), Some("2"));
        assert!(got.iter().all(|(_, v)| !v.is_empty()));
        // The listed names are the ones published when it is on.
        let on_names: alloc::vec::Vec<&str> = got
            .iter()
            .map(|(t, _)| t.as_str())
            .filter(|t| t.starts_with("$SYS/broker/plaintext/"))
            .collect();
        let all = topic_names(1);
        let listed: alloc::vec::Vec<&str> = all
            .iter()
            .map(String::as_str)
            .filter(|t| t.starts_with("$SYS/broker/plaintext/"))
            .collect();
        assert_eq!(on_names, listed);
        // The query reply carries it as an object; the status gets one line.
        let j = json(&on);
        assert!(
            j.contains("\"plaintext\":{\"enabled\":true,\"port\":1883,\"auth\":\"password\",\"allow_from\":\"10.0.0.0/8, 192.168.0.0/16\",\"accounts\":3,\"connections\":4,\"accepted\":40,\"refused\":{\"source\":5,\"locked_out\":6,\"limit\":7,\"registry\":8,\"session\":9},\"auth_ok\":30,\"auth_failed\":10,\"lockouts\":2}"),
            "{j}"
        );
        assert!(j.ends_with("}}"));
        let lines = status_lines(&on, "info", "debug");
        assert!(
            lines
                .iter()
                .any(|l| l
                    .starts_with("plaintext MQTT ON (not encrypted): port 1883, auth password")),
            "{lines:?}"
        );
        assert!(
            !status_lines(&info(&[10]), "info", "debug")
                .iter()
                .any(|l| l.contains("plaintext")),
            "nothing about plaintext while it is off"
        );
    }

    #[test]
    fn the_entropy_source_names_what_seeded_the_generator() {
        assert_eq!(entropy_source(true, None, false, true), "virtio-rng");
        assert_eq!(entropy_source(false, Some("rndr"), false, true), "rndr");
        assert_eq!(
            entropy_source(true, Some("rndr"), false, true),
            "virtio-rng+rndr"
        );
        assert_eq!(
            entropy_source(false, Some("rdrand"), false, false),
            "rdrand"
        );
        assert_eq!(entropy_source(false, None, true, true), "jitter+firmware");
        assert_eq!(entropy_source(false, None, true, false), "jitter");
        assert_eq!(entropy_source(false, None, false, true), "none");
        let j = json(&info(&[10]));
        assert!(
            j.contains("\"entropy\":{\"source\":\"jitter+firmware\"}"),
            "{j}"
        );
        assert!(
            status_lines(&info(&[10]), "info", "debug")
                .iter()
                .any(|l| l == "entropy source jitter+firmware")
        );
    }

    #[test]
    fn the_topic_list_is_fixed() {
        let mut got = alloc::vec::Vec::new();
        topics(&info(&[10, 20]), |t, v| {
            got.push((t.to_owned(), v.to_owned()))
        });
        let names: alloc::vec::Vec<&str> = got.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            names,
            [
                "$SYS/broker/version",
                "$SYS/broker/uptime",
                "$SYS/broker/arch",
                "$SYS/broker/cpu/cores",
                "$SYS/broker/cpu/busy/0",
                "$SYS/broker/cpu/busy/1",
                "$SYS/broker/memory/total",
                "$SYS/broker/memory/used",
                "$SYS/broker/disk/total",
                "$SYS/broker/disk/used",
                "$SYS/broker/clients/connected",
                "$SYS/broker/clients/total",
                "$SYS/broker/subscriptions",
                "$SYS/broker/retained",
                "$SYS/broker/messages/received",
                "$SYS/broker/messages/sent",
                "$SYS/broker/connections/refused",
                "$SYS/broker/tls/server_cert_days",
                "$SYS/broker/time/source",
                "$SYS/broker/time/offset_ms",
                "$SYS/broker/entropy/source",
                "$SYS/broker/console/dropped",
                "$SYS/broker/net/mtu",
                "$SYS/broker/messages/dropped/slow_subscriber",
                "$SYS/broker/messages/dropped/offline",
                "$SYS/broker/messages/dropped/cross_core",
                "$SYS/broker/messages/dropped/qos1_queue_full",
                "$SYS/broker/messages/dropped/publish_rate",
                "$SYS/broker/frames/dropped/steer",
                "$SYS/broker/frames/dropped/worker_tx",
                "$SYS/broker/frames/dropped/nic",
                "$SYS/broker/handshakes/started",
                "$SYS/broker/handshakes/done",
                "$SYS/broker/handshakes/failed",
                "$SYS/broker/handshakes/timed_out",
                "$SYS/broker/handshakes/refused",
                "$SYS/broker/handshakes/syn_dropped",
                "$SYS/broker/handshakes/in_flight",
                "$SYS/broker/handshakes/in_flight_max",
                "$SYS/broker/handshakes/slow",
                "$SYS/broker/handshakes/latency_sum_ms",
                "$SYS/broker/handshakes/latency_max_ms",
                "$SYS/broker/cpu/accepted/0",
                "$SYS/broker/cpu/accepted/1",
                "$SYS/broker/plaintext/enabled",
                "$SYS/broker/websocket/enabled",
            ]
        );
        let val = |t: &str| got.iter().find(|(k, _)| k == t).map(|(_, v)| v.as_str());
        assert_eq!(val("$SYS/broker/cpu/cores"), Some("2"));
        assert_eq!(val("$SYS/broker/cpu/busy/1"), Some("20"));
        assert_eq!(val("$SYS/broker/memory/used"), Some("400"));
        assert_eq!(val("$SYS/broker/tls/server_cert_days"), Some("90"));
        assert_eq!(val("$SYS/broker/time/source"), Some("sntp"));
        assert_eq!(val("$SYS/broker/time/offset_ms"), Some("-12"));
        assert_eq!(val("$SYS/broker/entropy/source"), Some("jitter+firmware"));
        assert_eq!(val("$SYS/broker/handshakes/done"), Some("8"));
        assert_eq!(
            val("$SYS/broker/messages/dropped/slow_subscriber"),
            Some("3")
        );
        assert_eq!(val("$SYS/broker/cpu/accepted/1"), Some("5"));
        assert_eq!(val("$SYS/broker/net/mtu"), Some("1460"));
        // No payload is empty: an empty retained payload would clear it.
        assert!(got.iter().all(|(_, v)| !v.is_empty()));
        assert_eq!(val("$SYS/broker/plaintext/enabled"), Some("false"));
        // (`topic_names` lists the topics with plaintext and websocket on.)
        let plain = topic_names(2)
            .iter()
            .filter(|t| t.starts_with("$SYS/broker/plaintext/"))
            .count();
        let ws = topic_names(2)
            .iter()
            .filter(|t| t.starts_with("$SYS/broker/websocket/"))
            .count();
        assert_eq!(topic_names(2).len() - plain + 1 - ws + 1, got.len());
    }

    #[test]
    fn json_is_one_valid_document() {
        let j = json(&info(&[10, 20]));
        assert_eq!(
            j,
            "{\"version\":\"0.1.0\",\"uptime_s\":12,\"arch\":\"aarch64\",\
             \"cpu\":{\"cores\":2,\"busy\":[10,20]},\"memory\":{\"total\":1000,\"used\":400},\
             \"disk\":{\"total\":0,\"used\":0},\"clients\":{\"connected\":3,\"total\":5},\
             \"subscriptions\":7,\"retained\":2,\"messages\":{\"received\":100,\"sent\":250},\
             \"connections_refused\":1,\"tls\":{\"server_cert_days\":90},\"time\":{\"source\":\"sntp\",\"offset_ms\":-12},\"entropy\":{\"source\":\"jitter+firmware\"},\"console_dropped\":0,\"net\":{\"mtu\":1460},\
             \"dropped\":{\"slow_subscriber\":3,\"offline\":0,\"cross_core\":0,\"qos1_queue_full\":0,\
             \"publish_rate\":0,\"frames_steer\":0,\"frames_worker_tx\":0,\"frames_nic\":0},\
             \"handshakes\":{\"started\":9,\"done\":8,\"failed\":0,\"timed_out\":0,\"refused\":0,\
             \"syn_dropped\":0,\"in_flight\":0,\"in_flight_max\":0,\"slow\":0,\"latency_sum_ms\":0,\
             \"latency_max_ms\":0},\"accepted\":[4,5],\"plaintext\":{\"enabled\":false},\"websocket\":{\"enabled\":false}}"
        );
        let mut unknown = info(&[]);
        unknown.server_cert_days = None;
        assert!(json(&unknown).contains("\"server_cert_days\":null"));
        assert!(json(&unknown).contains("\"busy\":[]"));
        let mut s = String::new();
        json_str(&mut s, "a\"b\\c\n");
        assert_eq!(s, "\"a\\\"b\\\\c\\u000a\"");
    }

    #[test]
    fn the_command_set_is_closed() {
        assert_eq!(parse(b"help"), Ok(Command::Help));
        assert_eq!(parse(b"status\n"), Ok(Command::Status));
        assert_eq!(parse(b"  reboot \r\n"), Ok(Command::Reboot));
        assert_eq!(
            parse(b"log level debug"),
            Ok(Command::LogLevel(Level::Debug))
        );
        assert_eq!(
            parse(b"log  level   warn"),
            Ok(Command::LogLevel(Level::Warn))
        );
        for (bad, why) in [
            (&b""[..], Refused::Empty),
            (b"  \n", Refused::Empty),
            (b"STATUS", Refused::Unknown),
            (b"ls", Refused::Unknown),
            (b"sh", Refused::Unknown),
            (b"status; reboot", Refused::Unknown),
            (b"status now", Refused::Usage),
            (b"log", Refused::Usage),
            (b"log level", Refused::Usage),
            (b"log level loud", Refused::Usage),
            (b"log level info extra", Refused::Usage),
            (b"reboot now", Refused::Usage),
            (b"status\nreboot", Refused::NotText),
            (b"\xff\xfe", Refused::NotText),
            (b"stat\x00us", Refused::NotText),
        ] {
            assert_eq!(parse(bad), Err(why), "{:?}", core::str::from_utf8(bad));
        }
        assert_eq!(parse(&[b'a'; MAX_COMMAND + 1]), Err(Refused::TooLong));
        assert_eq!(parse(&[b'a'; MAX_COMMAND]), Err(Refused::Unknown));
    }

    #[test]
    fn status_is_a_few_short_lines() {
        let lines = status_lines(&info(&[10, 20]), "info", "debug");
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], "urmqtt 0.1.0 aarch64 up 12 s");
        assert_eq!(lines[1], "cpu 2 core(s), busy % 10/20");
        assert!(lines[3].starts_with("clients 3 connected, 5 sessions"));
        assert_eq!(lines[6], "time source sntp, last sntp offset -12 ms");
        assert_eq!(lines[7], "entropy source jitter+firmware");
        assert_eq!(
            lines[8],
            "dropped QoS0 slow 3 offline 0 xcore 0; QoS1 0; rate 0; frames 0/0/0"
        );
        assert!(lines[9].starts_with("log level info (build maximum debug)"));
        assert!(lines.iter().all(|l| l.len() < 120 && !l.contains('\n')));
    }

    #[test]
    fn the_limiter_allows_a_burst_then_the_rate() {
        let mut l = Limiter::new(3, 1000);
        assert!(l.allow(0) && l.allow(0) && l.allow(0));
        assert!(!l.allow(0));
        assert!(!l.allow(999));
        assert!(l.allow(1000));
        assert!(!l.allow(1000));
        // A long pause refills to the burst, not beyond.
        assert!(l.allow(100_000) && l.allow(100_000) && l.allow(100_000));
        assert!(!l.allow(100_000));
    }
}
