//! The Prometheus exposition of the broker's numbers (NEXT-9, ADR-290).
//!
//! Everything `$SYS/broker/...` reports ([`crate::sys::topics`]) is exposed
//! under a stable metric name, from the same [`Info`]: there is no second
//! collection of numbers that could disagree with `$SYS` or the info query.
//! The mapping is the table [`RULES`]; a test walks every topic the broker
//! can publish and fails when one has no rule (so a new `$SYS` counter cannot
//! be added without a decision about its metric), and another checks the
//! rules themselves (names, counters end in `_total`, gauges do not, labels
//! bounded and fixed).
//!
//! Conventions (the names are an interface; changing one is a breaking
//! change and goes in the CHANGELOG, see OPERATE.md "Metrics"):
//!
//! - every name starts with `urmqtt_`; base units in the name (`_seconds`,
//!   `_bytes`, `_ratio`), counters end in `_total`;
//! - a counter is a value that only grows while the machine is up (it
//!   restarts from 0 at boot, which Prometheus handles as a counter reset); a
//!   gauge is a value that goes both ways;
//! - **labels are bounded and come from the kernel, never from a client**:
//!   `core` (at most 64), `queue` (a NIC queue pair, at most 16, ADR-312),
//!   a reason or code from a closed list, a listener
//!   name, a version string. There is no client id, user name, topic, address
//!   or certificate in any label, so the number of series is fixed by the
//!   image's configuration and the core count and cannot be grown by anyone
//!   on the network;
//! - text values (`$SYS/broker/version`, `arch`, `time/source`, ...) become
//!   `..._info` gauges with the value as a label and the sample 1;
//! - values that are unknown (`unknown` in `$SYS`: no wall clock, no
//!   certificate) are left out, not exposed as 0;
//! - two config texts are not exposed: `plaintext/allow_from` (the operator's
//!   network plan) and `websocket/path`.
//!
//! Output is the Prometheus text format 0.0.4 or, when asked, OpenMetrics
//! 1.0.0 text (counter families named without `_total`, `# EOF` at the end).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::sys::{Info, topics};

/// Counter or gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Counter,
    Gauge,
}

/// How a topic's text becomes the sample's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// The integer as it is.
    Int,
    /// An integer in thousandths (milliseconds to seconds).
    Milli,
    /// An integer in hundredths (percent to a ratio).
    Centi,
    /// Days to seconds.
    Days,
    /// `true` is 1, `false` is 0.
    Bool,
    /// Text: the sample is 1 and the text is the value of this label.
    Info(&'static str),
}

/// One topic (or, with `label`, the topics below a prefix) and the metric it
/// becomes.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// The topic below `$SYS/broker/`; with `label`, its prefix (the last
    /// level is the label's value).
    pub topic: &'static str,
    pub label: Option<&'static str>,
    /// Constant labels of the series.
    pub fixed: &'static [(&'static str, &'static str)],
    pub name: &'static str,
    pub kind: Kind,
    pub value: Value,
    pub help: &'static str,
}

const NO: &[(&str, &str)] = &[];
const PLAIN: &[(&str, &str)] = &[("listener", "plaintext")];
const WS: &[(&str, &str)] = &[("listener", "websocket")];

const fn r(
    topic: &'static str,
    name: &'static str,
    kind: Kind,
    value: Value,
    help: &'static str,
) -> Rule {
    Rule {
        topic,
        label: None,
        fixed: NO,
        name,
        kind,
        value,
        help,
    }
}

const fn c(topic: &'static str, name: &'static str, help: &'static str) -> Rule {
    r(topic, name, Kind::Counter, Value::Int, help)
}

const fn g(topic: &'static str, name: &'static str, help: &'static str) -> Rule {
    r(topic, name, Kind::Gauge, Value::Int, help)
}

impl Rule {
    /// The series below a prefix, the last topic level being the value of `label`.
    const fn by(mut self, label: &'static str) -> Self {
        self.label = Some(label);
        self
    }

    const fn with(mut self, fixed: &'static [(&'static str, &'static str)]) -> Self {
        self.fixed = fixed;
        self
    }
}

const fn info(
    topic: &'static str,
    name: &'static str,
    label: &'static str,
    help: &'static str,
) -> Rule {
    r(topic, name, Kind::Gauge, Value::Info(label), help)
}

use Kind::{Counter, Gauge};
use Value::{Bool, Centi, Days, Milli};

/// The mapping from `$SYS/broker/...` to metrics. Rules of one family are
/// adjacent (a test checks it): their samples are written under one `# HELP`
/// and `# TYPE`.
pub static RULES: &[Rule] = &[
    info(
        "version",
        "urmqtt_version_info",
        "version",
        "The kernel version (the value is the label).",
    ),
    info(
        "arch",
        "urmqtt_arch_info",
        "arch",
        "The CPU architecture (aarch64 or x86_64).",
    ),
    r(
        "uptime",
        "urmqtt_uptime_seconds",
        Gauge,
        Value::Int,
        "Seconds since boot.",
    ),
    g("cpu/cores", "urmqtt_cpu_cores", "Cores the kernel runs on."),
    r(
        "cpu/busy",
        "urmqtt_cpu_busy_ratio",
        Gauge,
        Centi,
        "Share of the last window a core spent working (0 to 1).",
    )
    .by("core"),
    c(
        "cpu/accepted",
        "urmqtt_core_connections_accepted_total",
        "TCP connections accepted, per core.",
    )
    .by("core"),
    g(
        "memory/total",
        "urmqtt_memory_heap_bytes",
        "Kernel heap size.",
    ),
    g(
        "memory/used",
        "urmqtt_memory_heap_used_bytes",
        "Kernel heap in use.",
    ),
    g(
        "memory/topic_aliases",
        "urmqtt_memory_topic_alias_bytes",
        "Bytes held by MQTT 5.0 topic-alias tables.",
    ),
    g(
        "disk/total",
        "urmqtt_disk_bytes",
        "Size of the data partition.",
    ),
    g(
        "disk/used",
        "urmqtt_disk_used_bytes",
        "Data partition bytes in use by the database.",
    ),
    g(
        "clients/connected",
        "urmqtt_clients_connected",
        "MQTT clients connected now, all versions.",
    ),
    g(
        "clients/connected/v311",
        "urmqtt_clients_connected_by_version",
        "MQTT clients connected now, by protocol version.",
    )
    .with(&[("version", "3.1.1")]),
    g(
        "clients/connected/v5",
        "urmqtt_clients_connected_by_version",
        "MQTT clients connected now, by protocol version.",
    )
    .with(&[("version", "5")]),
    g(
        "clients/total",
        "urmqtt_sessions",
        "MQTT sessions held, online or not.",
    ),
    g(
        "subscriptions",
        "urmqtt_subscriptions",
        "Subscriptions held.",
    ),
    g(
        "retained",
        "urmqtt_retained_messages",
        "Retained messages held.",
    ),
    g(
        "retained/expiring",
        "urmqtt_retained_expiring_messages",
        "Retained messages with a Message Expiry Interval running.",
    ),
    c(
        "messages/received",
        "urmqtt_messages_received_total",
        "PUBLISH packets received from clients.",
    ),
    c(
        "messages/sent",
        "urmqtt_messages_sent_total",
        "PUBLISH packets delivered to clients.",
    ),
    c(
        "messages/expired",
        "urmqtt_messages_expired_total",
        "Messages not delivered because their Message Expiry Interval passed.",
    ),
    c(
        "messages/dropped",
        "urmqtt_messages_dropped_total",
        "Messages not delivered, by reason.",
    )
    .by("reason"),
    c(
        "frames/dropped",
        "urmqtt_frames_dropped_total",
        "Network frames dropped under overload (TCP resends them), by reason.",
    )
    .by("reason"),
    c(
        "messages/qos2/received",
        "urmqtt_qos2_received_total",
        "QoS 2 PUBLISH packets received with a new packet id.",
    ),
    c(
        "messages/qos2/duplicates",
        "urmqtt_qos2_duplicates_total",
        "QoS 2 PUBLISH packets whose id was still held.",
    ),
    c(
        "messages/qos2/completed",
        "urmqtt_qos2_completed_total",
        "QoS 2 deliveries completed with PUBCOMP.",
    ),
    c(
        "messages/qos2/inbound_full",
        "urmqtt_qos2_inbound_full_total",
        "Connections closed for holding too many QoS 2 ids.",
    ),
    info(
        "messages/backpressure/mode",
        "urmqtt_backpressure_info",
        "mode",
        "Publisher back-pressure mode (single or off).",
    ),
    c(
        "messages/backpressure/paused",
        "urmqtt_backpressure_paused_total",
        "Publishers paused because their only subscriber was full.",
    ),
    r(
        "messages/backpressure/paused_ms",
        "urmqtt_backpressure_paused_seconds_total",
        Counter,
        Milli,
        "Seconds publishers spent paused (ended pauses).",
    ),
    c(
        "messages/backpressure/timeouts",
        "urmqtt_backpressure_timeouts_total",
        "Pauses that ran out and fell back to dropping.",
    ),
    g(
        "messages/backpressure/holding",
        "urmqtt_backpressure_holding",
        "Publishers held now.",
    ),
    c(
        "connections/refused",
        "urmqtt_connections_refused_total",
        "Connections refused at the final ACK of the TCP handshake.",
    ),
    c(
        "connections/refused/v5",
        "urmqtt_mqtt5_connections_refused_total",
        "MQTT 5.0 CONNECT packets refused, by CONNACK reason code.",
    )
    .by("code"),
    g(
        "connections/per_address/limit",
        "urmqtt_connections_per_address_limit",
        "limits.max_connections_per_ip: established TLS connections one source address may hold (0: no limit).",
    ),
    g(
        "connections/per_address/established",
        "urmqtt_connections_per_address_established",
        "Established TLS connections the per-address table counts now, all cores.",
    ),
    g(
        "connections/per_address/addresses",
        "urmqtt_connections_per_address_addresses",
        "Distinct source addresses holding at least one counted connection.",
    ),
    g(
        "connections/per_address/peak",
        "urmqtt_connections_per_address_peak",
        "The most connections one source address has held at once since boot.",
    ),
    c(
        "connections/per_address/syn_dropped",
        "urmqtt_connections_per_address_syn_dropped_total",
        "SYNs dropped without an answer because the source address was at its limit.",
    ),
    c(
        "connections/per_address/refused",
        "urmqtt_connections_per_address_refused_total",
        "Connections refused with a RST at the final ACK because the source address was at its limit.",
    ),
    c(
        "connections/per_address/untracked",
        "urmqtt_connections_per_address_untracked_total",
        "Connections let through uncounted because the address's bucket was full.",
    ),
    info(
        "iommu/mode",
        "urmqtt_iommu_mode_info",
        "mode",
        "devices.iommu: off, auto or require.",
    ),
    info(
        "iommu/state",
        "urmqtt_iommu_state_info",
        "state",
        "off, none (no IOMMU found), failed (found, not working) or active.",
    ),
    g(
        "iommu/units",
        "urmqtt_iommu_units",
        "IOMMU units translating.",
    ),
    g(
        "iommu/domains",
        "urmqtt_iommu_domains",
        "Devices with a DMA domain of their own.",
    ),
    g(
        "iommu/pages",
        "urmqtt_iommu_pages",
        "Pages mapped for device DMA.",
    ),
    c(
        "iommu/faults",
        "urmqtt_iommu_faults_total",
        "Blocked DMA accesses and unit errors read from the fault logs.",
    ),
    c(
        "iommu/overflows",
        "urmqtt_iommu_fault_overflows_total",
        "Times a unit's fault log overflowed (faults lost).",
    ),
    c(
        "disconnects/sent",
        "urmqtt_mqtt5_disconnects_sent_total",
        "MQTT 5.0 DISCONNECT packets sent by the broker, by reason code.",
    )
    .by("code"),
    c(
        "sessions/expired",
        "urmqtt_sessions_expired_total",
        "Sessions ended by their Session Expiry Interval.",
    ),
    g(
        "sessions/expiring",
        "urmqtt_sessions_expiring",
        "Offline sessions whose expiry runs now.",
    ),
    c(
        "wills/delayed",
        "urmqtt_wills_delayed_total",
        "Wills armed with a Will Delay Interval.",
    ),
    g(
        "wills/pending",
        "urmqtt_wills_pending",
        "Wills armed with a Will Delay Interval, waiting now.",
    ),
    g(
        "shared/groups",
        "urmqtt_shared_groups",
        "Shared-subscription groups held.",
    ),
    g(
        "shared/members",
        "urmqtt_shared_members",
        "Shared-subscription group members.",
    ),
    c(
        "shared/messages/delivered",
        "urmqtt_shared_messages_delivered_total",
        "Messages delivered to shared-subscription members.",
    ),
    c(
        "shared/messages/dropped",
        "urmqtt_shared_messages_dropped_total",
        "Shared-subscription messages dropped.",
    ),
    c(
        "shared/messages/redispatched",
        "urmqtt_shared_messages_redispatched_total",
        "Shared-subscription messages handed to another member.",
    ),
    c(
        "shared/joins/refused",
        "urmqtt_shared_joins_refused_total",
        "Shared-subscription joins refused by a limit.",
    ),
    c(
        "handshakes/started",
        "urmqtt_handshakes_started_total",
        "Connections admitted after the TCP handshake.",
    ),
    c(
        "handshakes/done",
        "urmqtt_handshakes_done_total",
        "TLS handshakes completed.",
    ),
    c(
        "handshakes/failed",
        "urmqtt_handshakes_failed_total",
        "Connections that ended before their handshake completed.",
    ),
    c(
        "handshakes/timed_out",
        "urmqtt_handshakes_timed_out_total",
        "Handshakes not finished within the timeout.",
    ),
    c(
        "handshakes/refused",
        "urmqtt_handshakes_refused_total",
        "Connections refused at the final ACK by admission.",
    ),
    c(
        "handshakes/syn_dropped",
        "urmqtt_handshakes_syn_dropped_total",
        "SYN packets dropped without an answer by admission.",
    ),
    g(
        "handshakes/in_flight",
        "urmqtt_handshakes_in_flight",
        "Handshakes in flight now.",
    ),
    g(
        "handshakes/in_flight_max",
        "urmqtt_handshakes_in_flight_max",
        "The most handshakes in flight on one core in the last 5 s.",
    ),
    c(
        "handshakes/slow",
        "urmqtt_handshakes_slow_total",
        "Completed handshakes slower than 250 ms.",
    ),
    r(
        "handshakes/latency_sum_ms",
        "urmqtt_handshakes_latency_seconds_total",
        Counter,
        Milli,
        "Sum of accept-to-done times of completed handshakes.",
    ),
    r(
        "handshakes/latency_max_ms",
        "urmqtt_handshakes_latency_max_seconds",
        Gauge,
        Milli,
        "The longest accept-to-done time on one core in the last 5 s.",
    ),
    r(
        "tls/server_cert_days",
        "urmqtt_tls_server_certificate_expiry_seconds",
        Gauge,
        Days,
        "Seconds (whole days) until the server certificate expires; absent without a wall clock.",
    ),
    info(
        "time/source",
        "urmqtt_time_source_info",
        "source",
        "Where the wall clock comes from (rtc, sntp or unknown).",
    ),
    r(
        "time/offset_ms",
        "urmqtt_time_offset_seconds",
        Gauge,
        Milli,
        "The last SNTP offset against the clock as it was; absent until measured.",
    ),
    info(
        "entropy/source",
        "urmqtt_entropy_source_info",
        "source",
        "What seeded the random number generator.",
    ),
    c(
        "console/dropped",
        "urmqtt_console_lines_dropped_total",
        "Console lines lost because a reader was too slow.",
    ),
    g(
        "net/mtu",
        "urmqtt_network_mtu_bytes",
        "The link MTU in use.",
    ),
    g(
        "net/queues",
        "urmqtt_network_queue_pairs",
        "virtio-net queue pairs in use (1 without multiqueue).",
    ),
    c(
        "net/queue/received",
        "urmqtt_network_queue_frames_received_total",
        "Frames received on a NIC queue pair (the pair of the core with the same number).",
    )
    .by("queue"),
    c(
        "net/queue/sent",
        "urmqtt_network_queue_frames_sent_total",
        "Frames sent on a NIC queue pair.",
    )
    .by("queue"),
    c(
        "net/queue/forwarded",
        "urmqtt_network_queue_frames_forwarded_total",
        "Frames a core received on its own pair for another core's flow and passed to core 0.",
    )
    .by("queue"),
    c(
        "net/queue/interrupts",
        "urmqtt_network_queue_interrupts_total",
        "Receive interrupts of a NIC queue pair.",
    )
    .by("queue"),
    // The plaintext and WebSocket listeners: one family per fact, the
    // listener a label, so a dashboard sums or splits them.
    r(
        "plaintext/enabled",
        "urmqtt_listener_enabled",
        Gauge,
        Bool,
        "Whether an optional listener is on (1) or off (0).",
    )
    .with(PLAIN),
    r(
        "websocket/enabled",
        "urmqtt_listener_enabled",
        Gauge,
        Bool,
        "Whether an optional listener is on (1) or off (0).",
    )
    .with(WS),
    g(
        "plaintext/port",
        "urmqtt_listener_port",
        "TCP port of an optional listener.",
    )
    .with(PLAIN),
    g(
        "websocket/port",
        "urmqtt_listener_port",
        "TCP port of an optional listener.",
    )
    .with(WS),
    info(
        "plaintext/auth",
        "urmqtt_listener_auth_info",
        "auth",
        "How clients of an optional listener prove who they are.",
    )
    .with(PLAIN),
    info(
        "websocket/auth",
        "urmqtt_listener_auth_info",
        "auth",
        "How clients of an optional listener prove who they are.",
    )
    .with(WS),
    g(
        "plaintext/accounts",
        "urmqtt_listener_accounts",
        "Password accounts configured for an optional listener.",
    )
    .with(PLAIN),
    g(
        "websocket/accounts",
        "urmqtt_listener_accounts",
        "Password accounts configured for an optional listener.",
    )
    .with(WS),
    g(
        "plaintext/connections",
        "urmqtt_listener_connections",
        "Connections open on an optional listener.",
    )
    .with(PLAIN),
    g(
        "websocket/connections",
        "urmqtt_listener_connections",
        "Connections open on an optional listener.",
    )
    .with(WS),
    c(
        "plaintext/accepted",
        "urmqtt_listener_accepted_total",
        "Connections accepted by an optional listener.",
    )
    .with(PLAIN),
    c(
        "websocket/accepted",
        "urmqtt_listener_accepted_total",
        "Connections accepted by an optional listener.",
    )
    .with(WS),
    c(
        "plaintext/auth_ok",
        "urmqtt_listener_logins_total",
        "Password logins of an optional listener, by result.",
    )
    .with(&[("listener", "plaintext"), ("result", "ok")]),
    c(
        "plaintext/auth_failed",
        "urmqtt_listener_logins_total",
        "Password logins of an optional listener, by result.",
    )
    .with(&[("listener", "plaintext"), ("result", "failed")]),
    c(
        "websocket/auth_ok",
        "urmqtt_listener_logins_total",
        "Password logins of an optional listener, by result.",
    )
    .with(&[("listener", "websocket"), ("result", "ok")]),
    c(
        "websocket/auth_failed",
        "urmqtt_listener_logins_total",
        "Password logins of an optional listener, by result.",
    )
    .with(&[("listener", "websocket"), ("result", "failed")]),
    c(
        "plaintext/lockouts",
        "urmqtt_listener_lockouts_total",
        "Source addresses locked out for failed logins.",
    )
    .with(PLAIN),
    c(
        "websocket/lockouts",
        "urmqtt_listener_lockouts_total",
        "Source addresses locked out for failed logins.",
    )
    .with(WS),
    c(
        "plaintext/refused",
        "urmqtt_plaintext_refused_total",
        "Plaintext connections and logins refused, by reason.",
    )
    .by("reason"),
    c(
        "websocket/refused",
        "urmqtt_websocket_refused_total",
        "WebSocket upgrades and connections refused, by reason.",
    )
    .by("reason"),
    c(
        "websocket/upgrades",
        "urmqtt_websocket_upgrades_total",
        "WebSocket upgrades answered 101.",
    ),
    g(
        "websocket/origins",
        "urmqtt_websocket_origins",
        "Entries of websocket.origins (0: any origin).",
    ),
    c(
        "websocket/frames/in",
        "urmqtt_websocket_frames_total",
        "WebSocket frames, by direction.",
    )
    .with(&[("direction", "in")]),
    c(
        "websocket/frames/out",
        "urmqtt_websocket_frames_total",
        "WebSocket frames, by direction.",
    )
    .with(&[("direction", "out")]),
    c(
        "websocket/bytes/in",
        "urmqtt_websocket_bytes_total",
        "MQTT bytes carried in WebSocket frames, by direction.",
    )
    .with(&[("direction", "in")]),
    c(
        "websocket/bytes/out",
        "urmqtt_websocket_bytes_total",
        "MQTT bytes carried in WebSocket frames, by direction.",
    )
    .with(&[("direction", "out")]),
    c(
        "websocket/close/client",
        "urmqtt_websocket_closes_total",
        "WebSocket close frames, by who sent them and the close code.",
    )
    .by("code")
    .with(&[("side", "client")]),
    c(
        "websocket/close/server",
        "urmqtt_websocket_closes_total",
        "WebSocket close frames, by who sent them and the close code.",
    )
    .by("code")
    .with(&[("side", "server")]),
    c(
        "websocket/close/abrupt",
        "urmqtt_websocket_closes_abrupt_total",
        "WebSocket connections that ended without a close frame.",
    ),
];

/// `$SYS` topics that are not exposed, and why.
pub const NOT_EXPOSED: &[(&str, &str)] = &[
    ("plaintext/allow_from", "the operator's network plan, text"),
    ("websocket/path", "configuration text without a number"),
];

/// The metrics listener's own numbers (not part of `$SYS`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Own {
    pub port: u16,
    /// Connections open now.
    pub connections: u64,
    /// TCP connections accepted.
    pub accepted: u64,
    /// SYNs and connections refused: source not in `metrics.allow_from`,
    /// limits (connections, per address, rate, memory).
    pub refused_source: u64,
    pub refused_limit: u64,
    /// Requests answered: 200, then the refusals in the order of
    /// [`OWN_RESULTS`].
    pub ok: u64,
    pub refused: [u64; 5],
    /// Connections cut because no complete request came in time, or the
    /// answer was not taken in time.
    pub timeouts: u64,
}

fn escape(out: &mut String, v: &str) {
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            ch => out.push(ch),
        }
    }
}

/// `{a="x",b="y"}` (empty without labels).
fn labels(pairs: &[(&str, &str)]) -> String {
    let mut s = String::new();
    if pairs.is_empty() {
        return s;
    }
    s.push('{');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(k);
        s.push_str("=\"");
        escape(&mut s, v);
        s.push('"');
    }
    s.push('}');
    s
}

/// The sample value for the topic's text, or `None` when it is not a number
/// (`unknown`).
fn value_of(rule: &Rule, text: &str) -> Option<String> {
    let mut out = String::new();
    match rule.value {
        Value::Info(_) => out.push('1'),
        Value::Bool => out.push(match text {
            "true" => '1',
            "false" => '0',
            _ => return None,
        }),
        Value::Int => {
            let n: i128 = text.parse().ok()?;
            let _ = write!(out, "{n}");
        }
        Value::Milli | Value::Centi => {
            let n: i128 = text.parse().ok()?;
            let (div, width) = if rule.value == Value::Milli {
                (1000i128, 3)
            } else {
                (100, 2)
            };
            let sign = if n < 0 { "-" } else { "" };
            let a = n.abs();
            let _ = write!(out, "{sign}{}.{:0width$}", a / div, a % div);
        }
        Value::Days => {
            let n: i128 = text.parse().ok()?;
            let _ = write!(out, "{}", n * 86_400);
        }
    }
    Some(out)
}

/// One sample of a family under construction.
struct Sample {
    labels: String,
    value: String,
}

/// The metric families of `i`, in the order of [`RULES`], as text.
/// `openmetrics`: OpenMetrics 1.0.0 (counter families without `_total`, a
/// terminating `# EOF`), else Prometheus text 0.0.4.
pub fn render(i: &Info<'_>, own: &Own, openmetrics: bool) -> String {
    let mut seen: Vec<(String, String)> = Vec::new();
    topics(i, |t, v| {
        if let Some(rest) = t.strip_prefix(crate::sys::BROKER_PREFIX)
            && let Some(rest) = rest.strip_prefix('/')
        {
            seen.push((rest.into(), v.into()));
        }
    });
    let mut out = String::with_capacity(32 * 1024);
    let mut idx = 0;
    while idx < RULES.len() {
        // The rules of this family (adjacent, same name).
        let Some(first) = RULES.get(idx) else { break };
        let end = RULES
            .get(idx..)
            .unwrap_or(&[])
            .iter()
            .position(|x| x.name != first.name)
            .map_or(RULES.len(), |n| idx + n);
        let mut samples: Vec<Sample> = Vec::new();
        for rule in RULES.get(idx..end).unwrap_or(&[]) {
            for (topic, text) in &seen {
                let dynamic = match rule.label {
                    None => (topic == rule.topic).then_some(""),
                    Some(_) => topic
                        .strip_prefix(rule.topic)
                        .and_then(|r| r.strip_prefix('/'))
                        .filter(|r| !r.is_empty() && !r.contains('/')),
                };
                let Some(dynamic) = dynamic else { continue };
                let Some(value) = value_of(rule, text) else {
                    continue;
                };
                let mut pairs: Vec<(&str, &str)> = rule.fixed.to_vec();
                if let Some(l) = rule.label {
                    pairs.push((l, dynamic));
                }
                if let Value::Info(l) = rule.value {
                    pairs.push((l, text));
                }
                samples.push(Sample {
                    labels: labels(&pairs),
                    value,
                });
            }
        }
        family(&mut out, first, &samples, openmetrics);
        idx = end;
    }
    listener(&mut out, own, openmetrics);
    if openmetrics {
        out.push_str("# EOF\n");
    }
    out
}

fn header(out: &mut String, name: &str, kind: Kind, help: &str, openmetrics: bool) {
    // OpenMetrics names a counter family without `_total`; the samples keep it.
    let fam = match (openmetrics, kind) {
        (true, Kind::Counter) => name.strip_suffix("_total").unwrap_or(name),
        _ => name,
    };
    let _ = writeln!(out, "# HELP {fam} {help}");
    let _ = writeln!(
        out,
        "# TYPE {fam} {}",
        match kind {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        }
    );
}

fn family(out: &mut String, rule: &Rule, samples: &[Sample], openmetrics: bool) {
    if samples.is_empty() {
        return;
    }
    header(out, rule.name, rule.kind, rule.help, openmetrics);
    for s in samples {
        let _ = writeln!(out, "{}{} {}", rule.name, s.labels, s.value);
    }
}

/// The metrics listener's own families (always present when the listener
/// answers: it is on).
fn listener(out: &mut String, own: &Own, openmetrics: bool) {
    let mut one = |name: &str, kind: Kind, help: &str, rows: &[(&[(&str, &str)], u64)]| {
        header(out, name, kind, help, openmetrics);
        for (l, v) in rows {
            let _ = writeln!(out, "{name}{} {v}", labels(l));
        }
    };
    one(
        "urmqtt_metrics_listener_port",
        Gauge,
        "TCP port of this endpoint.",
        &[(&[], u64::from(own.port))],
    );
    one(
        "urmqtt_metrics_connections",
        Gauge,
        "Connections open on this endpoint now.",
        &[(&[], own.connections)],
    );
    one(
        "urmqtt_metrics_accepted_total",
        Counter,
        "Connections accepted by this endpoint.",
        &[(&[], own.accepted)],
    );
    one(
        "urmqtt_metrics_refused_total",
        Counter,
        "SYNs and connections this endpoint refused, by reason.",
        &[
            (&[("reason", "source")], own.refused_source),
            (&[("reason", "limit")], own.refused_limit),
        ],
    );
    let mut rows: Vec<(&[(&str, &str)], u64)> = Vec::new();
    // One slice per row, with the result label spelled out.
    const RES: [&[(&str, &str)]; 6] = [
        &[("result", "ok")],
        &[("result", "malformed")],
        &[("result", "too_large")],
        &[("result", "method")],
        &[("result", "version")],
        &[("result", "not_found")],
    ];
    rows.push((RES[0], own.ok));
    for (k, n) in own.refused.iter().enumerate() {
        if let Some(l) = RES.get(k + 1) {
            rows.push((l, *n));
        }
    }
    one(
        "urmqtt_metrics_requests_total",
        Counter,
        "Requests this endpoint answered, by result.",
        &rows,
    );
    one(
        "urmqtt_metrics_timeouts_total",
        Counter,
        "Connections cut for being too slow.",
        &[(&[], own.timeouts)],
    );
}

#[cfg(test)]
mod tests;
