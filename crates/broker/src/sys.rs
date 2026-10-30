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
    /// Console lines lost because a reader fell behind.
    pub console_dropped: u64,
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
    put("console/dropped", &i.console_dropped);
}

/// The topics of [`topics`] as a list, for tests and the docs.
pub fn topic_names(cores: usize) -> alloc::vec::Vec<String> {
    let busy = alloc::vec![0u8; cores];
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
        console_dropped: 0,
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
    let _ = write!(o, "}},\"console_dropped\":{}}}", i.console_dropped);
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
            console_dropped: 0,
        }
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
                "$SYS/broker/console/dropped",
            ]
        );
        let val = |t: &str| got.iter().find(|(k, _)| k == t).map(|(_, v)| v.as_str());
        assert_eq!(val("$SYS/broker/cpu/cores"), Some("2"));
        assert_eq!(val("$SYS/broker/cpu/busy/1"), Some("20"));
        assert_eq!(val("$SYS/broker/memory/used"), Some("400"));
        assert_eq!(val("$SYS/broker/tls/server_cert_days"), Some("90"));
        // No payload is empty: an empty retained payload would clear it.
        assert!(got.iter().all(|(_, v)| !v.is_empty()));
        assert_eq!(topic_names(2).len(), got.len());
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
             \"connections_refused\":1,\"tls\":{\"server_cert_days\":90},\"console_dropped\":0}"
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
        assert_eq!(lines.len(), 7);
        assert_eq!(lines[0], "urmqtt 0.1.0 aarch64 up 12 s");
        assert_eq!(lines[1], "cpu 2 core(s), busy % 10/20");
        assert!(lines[3].starts_with("clients 3 connected, 5 sessions"));
        assert!(lines[6].starts_with("log level info (build maximum debug)"));
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
