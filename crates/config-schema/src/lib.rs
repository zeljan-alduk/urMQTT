//! Schema, validation and code generation for `deploy/<env>/config.toml`.
//!
//! This crate runs on the build host only (from `urmqtt-config`'s build
//! script). It turns a TOML file into a validated [`Config`] and renders it as
//! Rust source for the `no_std` kernel. Every rule lives here so that an
//! invalid configuration fails the build with a precise message instead of
//! reaching a running VM.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use core::fmt;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};

use serde::Deserialize;

/// Largest packet MQTT can encode (remaining length is at most 268 435 455).
pub const MQTT_MAX_PACKET_SIZE: u32 = 268_435_455;
/// Smallest `max_packet_size` that still fits a CONNECT with a short client id.
pub const MIN_PACKET_SIZE: u32 = 64;
/// Topic names are length-prefixed with a u16.
pub const MQTT_MAX_TOPIC_LEN: u32 = 65_535;
/// Placeholder in ACL patterns replaced by the session's device id.
pub const ID_PLACEHOLDER: &str = "{id}";

/// One validation problem, addressed by its TOML key path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

fn err(path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        path: path.to_owned(),
        message: message.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkModeKind {
    Dhcp,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityField {
    Cn,
    SanUri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogAction {
    Log,
    Drop,
    Reset,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    network: RawNetwork,
    tls: RawTls,
    limits: RawLimits,
    acl: RawAcl,
    storage: RawStorage,
    observability: RawObservability,
    watchdog: RawWatchdog,
    memory: RawMemory,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemory {
    kernel_heap_mb: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    mode: NetworkModeKind,
    address: Option<String>,
    gateway: Option<String>,
    mqtt_tls_port: u16,
    mqtt_plain_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    ca: String,
    cert: String,
    key: String,
    identity_field: IdentityField,
    resumption: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_connections_per_core: u32,
    max_packet_size: u32,
    max_topic_len: u32,
    max_topic_levels: u32,
    max_subscriptions_per_session: u32,
    max_inflight_qos1: u32,
    max_queued_per_offline_session: u32,
    publish_rate_per_device: String,
    handshakes_per_core_per_sec: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcl {
    device_publish: Vec<String>,
    device_subscribe: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    sqlite_heap_mb: u32,
    telemetry_topics: Vec<String>,
    retention_days: u32,
    require_flush: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObservability {
    log_level: LogLevel,
    syslog_udp: String,
    metrics_udp: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWatchdog {
    handler_budget_ms: u32,
    action: WatchdogAction,
}

/// IPv4 address with prefix length, e.g. `10.0.0.10/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Dhcp,
    Static {
        address: Ipv4Cidr,
        gateway: Ipv4Addr,
    },
}

/// Token-bucket rate: `tokens` per `per_ms` milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub tokens: u32,
    pub per_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub mode: NetworkMode,
    pub mqtt_tls_port: u16,
    pub mqtt_plain_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls {
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub identity_field: IdentityField,
    pub resumption: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections_per_core: u32,
    pub max_packet_size: u32,
    pub max_topic_len: u32,
    pub max_topic_levels: u32,
    pub max_subscriptions_per_session: u32,
    pub max_inflight_qos1: u32,
    pub max_queued_per_offline_session: u32,
    pub publish_rate_per_device: Rate,
    pub handshakes_per_core_per_sec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    pub device_publish: Vec<String>,
    pub device_subscribe: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Storage {
    pub sqlite_heap_mb: u32,
    pub telemetry_topics: Vec<String>,
    pub retention_days: u32,
    pub require_flush: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observability {
    pub log_level: LogLevel,
    pub syslog_udp: Option<SocketAddrV4>,
    pub metrics_udp: Option<SocketAddrV4>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    pub kernel_heap_mb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watchdog {
    pub handler_budget_ms: u32,
    pub action: WatchdogAction,
}

/// A fully validated build-time configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub env: String,
    pub network: Network,
    pub tls: Tls,
    pub limits: Limits,
    pub acl: Acl,
    pub storage: Storage,
    pub observability: Observability,
    pub watchdog: Watchdog,
    pub memory: Memory,
}

/// Environments allowed to open the plaintext MQTT port.
const PLAINTEXT_ENVS: &[&str] = &["dev"];

/// Parses and validates `text` as the configuration for environment `env`.
///
/// All problems found are returned together, not just the first one.
pub fn parse(env: &str, text: &str) -> Result<Config, Vec<ConfigError>> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| vec![err("", e.to_string())])?;
    let mut errors = Vec::new();

    if !is_valid_env_name(env) {
        errors.push(err(
            "",
            format!("environment name {env:?} must match [a-z0-9-]+"),
        ));
    }

    let network = validate_network(env, &raw.network, &mut errors);
    let tls = validate_tls(&raw.tls, &mut errors);
    let limits = validate_limits(&raw.limits, &mut errors);
    let acl = validate_acl(&raw.acl, &limits, &mut errors);
    let storage = validate_storage(&raw.storage, &limits, &mut errors);
    let observability = validate_observability(&raw.observability, &mut errors);
    let watchdog = validate_watchdog(&raw.watchdog, &mut errors);
    let memory = validate_memory(&raw.memory, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(Config {
        env: env.to_owned(),
        network,
        tls,
        limits,
        acl,
        storage,
        observability,
        watchdog,
        memory,
    })
}

fn is_valid_env_name(env: &str) -> bool {
    !env.is_empty()
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn validate_network(env: &str, raw: &RawNetwork, errors: &mut Vec<ConfigError>) -> Network {
    let mode = match raw.mode {
        NetworkModeKind::Dhcp => {
            if raw.address.is_some() || raw.gateway.is_some() {
                errors.push(err(
                    "network",
                    "address/gateway are only allowed with mode = \"static\"",
                ));
            }
            NetworkMode::Dhcp
        }
        NetworkModeKind::Static => {
            let address = match raw.address.as_deref() {
                Some(s) => parse_cidr(s).unwrap_or_else(|m| {
                    errors.push(err("network.address", m));
                    Ipv4Cidr {
                        addr: Ipv4Addr::UNSPECIFIED,
                        prefix_len: 0,
                    }
                }),
                None => {
                    errors.push(err("network.address", "required when mode = \"static\""));
                    Ipv4Cidr {
                        addr: Ipv4Addr::UNSPECIFIED,
                        prefix_len: 0,
                    }
                }
            };
            let gateway = match raw.gateway.as_deref() {
                Some(s) => s.parse::<Ipv4Addr>().unwrap_or_else(|_| {
                    errors.push(err(
                        "network.gateway",
                        format!("{s:?} is not an IPv4 address"),
                    ));
                    Ipv4Addr::UNSPECIFIED
                }),
                None => {
                    errors.push(err("network.gateway", "required when mode = \"static\""));
                    Ipv4Addr::UNSPECIFIED
                }
            };
            NetworkMode::Static { address, gateway }
        }
    };

    if raw.mqtt_tls_port == 0 {
        errors.push(err("network.mqtt_tls_port", "must be a non-zero port"));
    }
    let mqtt_plain_port = match raw.mqtt_plain_port {
        0 => None,
        p => {
            if !PLAINTEXT_ENVS.contains(&env) {
                errors.push(err(
                    "network.mqtt_plain_port",
                    format!("plaintext MQTT is only allowed in {PLAINTEXT_ENVS:?}, set it to 0"),
                ));
            }
            if p == raw.mqtt_tls_port {
                errors.push(err(
                    "network.mqtt_plain_port",
                    "must differ from mqtt_tls_port",
                ));
            }
            Some(p)
        }
    };

    Network {
        mode,
        mqtt_tls_port: raw.mqtt_tls_port,
        mqtt_plain_port,
    }
}

fn parse_cidr(s: &str) -> Result<Ipv4Cidr, String> {
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| format!("{s:?} must be in a.b.c.d/len form"))?;
    let addr = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{addr:?} is not an IPv4 address"))?;
    let prefix_len = len
        .parse::<u8>()
        .ok()
        .filter(|l| (1..=32).contains(l))
        .ok_or_else(|| format!("prefix length {len:?} must be 1..=32"))?;
    Ok(Ipv4Cidr { addr, prefix_len })
}

fn validate_tls(raw: &RawTls, errors: &mut Vec<ConfigError>) -> Tls {
    for (key, name) in [
        ("tls.ca", &raw.ca),
        ("tls.cert", &raw.cert),
        ("tls.key", &raw.key),
    ] {
        if let Err(m) = check_file_name(name) {
            errors.push(err(key, m));
        }
    }
    Tls {
        ca: raw.ca.clone(),
        cert: raw.cert.clone(),
        key: raw.key.clone(),
        identity_field: raw.identity_field,
        resumption: raw.resumption,
    }
}

/// Embedded files must be plain names inside `deploy/<env>/`.
pub fn check_file_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || name.starts_with('.')
    {
        return Err(format!(
            "{name:?} must be a plain file name inside deploy/<env>/"
        ));
    }
    Ok(())
}

fn validate_limits(raw: &RawLimits, errors: &mut Vec<ConfigError>) -> Limits {
    let positive = [
        (
            "limits.max_connections_per_core",
            raw.max_connections_per_core,
        ),
        ("limits.max_topic_levels", raw.max_topic_levels),
        (
            "limits.max_subscriptions_per_session",
            raw.max_subscriptions_per_session,
        ),
        ("limits.max_inflight_qos1", raw.max_inflight_qos1),
        (
            "limits.handshakes_per_core_per_sec",
            raw.handshakes_per_core_per_sec,
        ),
    ];
    for (key, v) in positive {
        if v == 0 {
            errors.push(err(key, "must be greater than 0"));
        }
    }
    if !(MIN_PACKET_SIZE..=MQTT_MAX_PACKET_SIZE).contains(&raw.max_packet_size) {
        errors.push(err(
            "limits.max_packet_size",
            format!("must be in {MIN_PACKET_SIZE}..={MQTT_MAX_PACKET_SIZE}"),
        ));
    }
    if raw.max_topic_len == 0 || raw.max_topic_len > MQTT_MAX_TOPIC_LEN {
        errors.push(err(
            "limits.max_topic_len",
            format!("must be in 1..={MQTT_MAX_TOPIC_LEN}"),
        ));
    } else if raw.max_topic_len >= raw.max_packet_size {
        errors.push(err(
            "limits.max_topic_len",
            "must be smaller than limits.max_packet_size",
        ));
    }
    let publish_rate_per_device = parse_rate(&raw.publish_rate_per_device).unwrap_or_else(|m| {
        errors.push(err("limits.publish_rate_per_device", m));
        Rate {
            tokens: 0,
            per_ms: 0,
        }
    });
    Limits {
        max_connections_per_core: raw.max_connections_per_core,
        max_packet_size: raw.max_packet_size,
        max_topic_len: raw.max_topic_len,
        max_topic_levels: raw.max_topic_levels,
        max_subscriptions_per_session: raw.max_subscriptions_per_session,
        max_inflight_qos1: raw.max_inflight_qos1,
        max_queued_per_offline_session: raw.max_queued_per_offline_session,
        publish_rate_per_device,
        handshakes_per_core_per_sec: raw.handshakes_per_core_per_sec,
    }
}

/// Parses `"<n>/s"`, `"<n>/m"` or `"<n>/h"` with `n > 0`.
pub fn parse_rate(s: &str) -> Result<Rate, String> {
    let (n, unit) = s
        .split_once('/')
        .ok_or_else(|| format!("{s:?} must look like \"10/s\", \"600/m\" or \"3600/h\""))?;
    let tokens = n
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&t| t > 0)
        .ok_or_else(|| format!("{n:?} must be a positive integer"))?;
    let per_ms = match unit.trim() {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        u => return Err(format!("unknown unit {u:?}, expected s, m or h")),
    };
    Ok(Rate { tokens, per_ms })
}

/// How `{id}` may appear in a topic filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    Allowed,
    Forbidden,
}

/// Validates an MQTT topic filter (MQTT 3.1.1 §4.7) against the limits.
///
/// `{id}` is accepted only as a whole level and only when `placeholder` allows
/// it; its length is counted as written, the broker checks the expanded form.
pub fn check_topic_filter(
    filter: &str,
    limits: &Limits,
    placeholder: Placeholder,
) -> Result<(), String> {
    if filter.is_empty() {
        return Err("topic filter must not be empty".into());
    }
    if filter.len() > usize::try_from(limits.max_topic_len).unwrap_or(usize::MAX) {
        return Err(format!(
            "{filter:?} is longer than limits.max_topic_len ({})",
            limits.max_topic_len
        ));
    }
    if filter.contains('\0') {
        return Err(format!("{filter:?} contains a NUL character"));
    }
    let levels: Vec<&str> = filter.split('/').collect();
    if levels.len() > usize::try_from(limits.max_topic_levels).unwrap_or(usize::MAX) {
        return Err(format!(
            "{filter:?} has more than limits.max_topic_levels ({}) levels",
            limits.max_topic_levels
        ));
    }
    let last = levels.len().saturating_sub(1);
    for (i, level) in levels.iter().enumerate() {
        if level.contains('#') && (*level != "#" || i != last) {
            return Err(format!("{filter:?}: '#' must be the whole last level"));
        }
        if level.contains('+') && *level != "+" {
            return Err(format!("{filter:?}: '+' must be a whole level"));
        }
        if level.contains(['{', '}']) {
            if *level != ID_PLACEHOLDER {
                return Err(format!(
                    "{filter:?}: braces are only allowed as the whole level {ID_PLACEHOLDER}"
                ));
            }
            if placeholder == Placeholder::Forbidden {
                return Err(format!("{filter:?}: {ID_PLACEHOLDER} is not allowed here"));
            }
        }
    }
    Ok(())
}

fn validate_filters(
    key: &str,
    filters: &[String],
    limits: &Limits,
    placeholder: Placeholder,
    errors: &mut Vec<ConfigError>,
) {
    for (i, f) in filters.iter().enumerate() {
        if let Err(m) = check_topic_filter(f, limits, placeholder) {
            errors.push(err(&format!("{key}[{i}]"), m));
        }
    }
}

fn validate_acl(raw: &RawAcl, limits: &Limits, errors: &mut Vec<ConfigError>) -> Acl {
    validate_filters(
        "acl.device_publish",
        &raw.device_publish,
        limits,
        Placeholder::Allowed,
        errors,
    );
    validate_filters(
        "acl.device_subscribe",
        &raw.device_subscribe,
        limits,
        Placeholder::Allowed,
        errors,
    );
    Acl {
        device_publish: raw.device_publish.clone(),
        device_subscribe: raw.device_subscribe.clone(),
    }
}

fn validate_storage(raw: &RawStorage, limits: &Limits, errors: &mut Vec<ConfigError>) -> Storage {
    if !(1..=4096).contains(&raw.sqlite_heap_mb) {
        errors.push(err("storage.sqlite_heap_mb", "must be in 1..=4096"));
    }
    if raw.retention_days == 0 {
        errors.push(err("storage.retention_days", "must be greater than 0"));
    }
    validate_filters(
        "storage.telemetry_topics",
        &raw.telemetry_topics,
        limits,
        Placeholder::Forbidden,
        errors,
    );
    Storage {
        sqlite_heap_mb: raw.sqlite_heap_mb,
        telemetry_topics: raw.telemetry_topics.clone(),
        retention_days: raw.retention_days,
        require_flush: raw.require_flush,
    }
}

fn parse_optional_addr(key: &str, s: &str, errors: &mut Vec<ConfigError>) -> Option<SocketAddrV4> {
    if s.is_empty() {
        return None;
    }
    match s.parse::<SocketAddrV4>() {
        Ok(a) if a.port() != 0 => Some(a),
        _ => {
            errors.push(err(key, format!("{s:?} must be \"a.b.c.d:port\" or empty")));
            None
        }
    }
}

fn validate_observability(raw: &RawObservability, errors: &mut Vec<ConfigError>) -> Observability {
    Observability {
        log_level: raw.log_level,
        syslog_udp: parse_optional_addr("observability.syslog_udp", &raw.syslog_udp, errors),
        metrics_udp: parse_optional_addr("observability.metrics_udp", &raw.metrics_udp, errors),
    }
}

fn validate_watchdog(raw: &RawWatchdog, errors: &mut Vec<ConfigError>) -> Watchdog {
    if !(1..=10_000).contains(&raw.handler_budget_ms) {
        errors.push(err("watchdog.handler_budget_ms", "must be in 1..=10000"));
    }
    Watchdog {
        handler_budget_ms: raw.handler_budget_ms,
        action: raw.action,
    }
}

fn validate_memory(raw: &RawMemory, errors: &mut Vec<ConfigError>) -> Memory {
    let mb = raw.kernel_heap_mb;
    if !(1..=1024).contains(&mb) || !mb.is_power_of_two() {
        errors.push(err(
            "memory.kernel_heap_mb",
            "must be a power of two in 1..=1024 (the heap is one buddy region)",
        ));
    }
    Memory { kernel_heap_mb: mb }
}

/// Kind of PEM object expected in an embedded file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemKind {
    Certificate,
    PrivateKey,
}

/// Cheap structural check of an embedded PEM file.
///
/// Full parsing happens in the TLS crate; this only catches swapped or
/// encrypted files early, at build time.
pub fn check_pem(bytes: &[u8], kind: PemKind) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "file is not valid UTF-8 PEM".to_owned())?;
    match kind {
        PemKind::Certificate => {
            if !text.contains("-----BEGIN CERTIFICATE-----") {
                return Err("expected a PEM certificate (BEGIN CERTIFICATE)".into());
            }
        }
        PemKind::PrivateKey => {
            if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
                return Err("encrypted private keys cannot be used: the VM has no way to obtain a passphrase".into());
            }
            if !(text.contains("-----BEGIN PRIVATE KEY-----")
                || text.contains("-----BEGIN EC PRIVATE KEY-----"))
            {
                return Err("expected an unencrypted PEM private key (BEGIN PRIVATE KEY)".into());
            }
            if text.contains("-----BEGIN CERTIFICATE-----") {
                return Err(
                    "key file also contains a certificate; keep them in separate files".into(),
                );
            }
        }
    }
    Ok(())
}

/// Absolute paths of the files the kernel embeds with `include_bytes!`.
#[derive(Debug, Clone)]
pub struct EmbeddedFiles {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

fn render_ipv4(a: Ipv4Addr) -> String {
    let [a, b, c, d] = a.octets();
    format!("[{a}, {b}, {c}, {d}]")
}

fn render_addr(a: Option<SocketAddrV4>) -> String {
    match a {
        None => "None".into(),
        Some(a) => format!(
            "Some(SocketAddrV4 {{ addr: {}, port: {} }})",
            render_ipv4(*a.ip()),
            a.port()
        ),
    }
}

fn render_strs(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
    format!("&[{}]", items.join(", "))
}

/// Renders the configuration as Rust items for `urmqtt-config`.
///
/// The output refers to types defined in that crate (`BuildConfig`, ...).
pub fn render(cfg: &Config, files: &EmbeddedFiles) -> String {
    let mode = match cfg.network.mode {
        NetworkMode::Dhcp => "NetworkMode::Dhcp".to_owned(),
        NetworkMode::Static { address, gateway } => format!(
            "NetworkMode::Static {{ address: Ipv4Cidr {{ addr: {}, prefix_len: {} }}, gateway: {} }}",
            render_ipv4(address.addr),
            address.prefix_len,
            render_ipv4(gateway)
        ),
    };
    let plain = match cfg.network.mqtt_plain_port {
        None => "None".to_owned(),
        Some(p) => format!("Some({p})"),
    };
    let l = &cfg.limits;
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = write!(
        out,
        r#"// @generated by urmqtt-config-schema from deploy/{env}/config.toml. Do not edit.

/// The configuration compiled into this image.
pub const CONFIG: BuildConfig = BuildConfig {{
    env: {env:?},
    network: Network {{
        mode: {mode},
        mqtt_tls_port: {tls_port},
        mqtt_plain_port: {plain},
    }},
    tls: Tls {{
        identity_field: IdentityField::{identity:?},
        resumption: {resumption},
    }},
    limits: Limits {{
        max_connections_per_core: {mcpc},
        max_packet_size: {mps},
        max_topic_len: {mtl},
        max_topic_levels: {mtlv},
        max_subscriptions_per_session: {msps},
        max_inflight_qos1: {miq},
        max_queued_per_offline_session: {mqos},
        publish_rate_per_device: Rate {{ tokens: {rt}, per_ms: {rp} }},
        handshakes_per_core_per_sec: {hpc},
    }},
    acl: Acl {{
        device_publish: {dp},
        device_subscribe: {ds},
    }},
    storage: Storage {{
        sqlite_heap_mb: {heap},
        telemetry_topics: {tt},
        retention_days: {rd},
        require_flush: {rf},
    }},
    observability: Observability {{
        log_level: LogLevel::{ll:?},
        syslog_udp: {syslog},
        metrics_udp: {metrics},
    }},
    watchdog: Watchdog {{
        handler_budget_ms: {hb},
        action: WatchdogAction::{wa:?},
    }},
    memory: Memory {{
        kernel_heap_mb: {heap_kernel},
    }},
}};

/// CA certificate (PEM) that device certificates must chain to.
pub static CA_PEM: &[u8] = include_bytes!({ca:?});
/// Server certificate chain (PEM).
pub static SERVER_CERT_PEM: &[u8] = include_bytes!({cert:?});
/// Server private key (PEM).
pub static SERVER_KEY_PEM: &[u8] = include_bytes!({key:?});
"#,
        env = cfg.env,
        tls_port = cfg.network.mqtt_tls_port,
        identity = cfg.tls.identity_field,
        resumption = cfg.tls.resumption,
        mcpc = l.max_connections_per_core,
        mps = l.max_packet_size,
        mtl = l.max_topic_len,
        mtlv = l.max_topic_levels,
        msps = l.max_subscriptions_per_session,
        miq = l.max_inflight_qos1,
        mqos = l.max_queued_per_offline_session,
        rt = l.publish_rate_per_device.tokens,
        rp = l.publish_rate_per_device.per_ms,
        hpc = l.handshakes_per_core_per_sec,
        dp = render_strs(&cfg.acl.device_publish),
        ds = render_strs(&cfg.acl.device_subscribe),
        heap = cfg.storage.sqlite_heap_mb,
        tt = render_strs(&cfg.storage.telemetry_topics),
        rd = cfg.storage.retention_days,
        rf = cfg.storage.require_flush,
        ll = cfg.observability.log_level,
        syslog = render_addr(cfg.observability.syslog_udp),
        metrics = render_addr(cfg.observability.metrics_udp),
        hb = cfg.watchdog.handler_budget_ms,
        wa = cfg.watchdog.action,
        heap_kernel = cfg.memory.kernel_heap_mb,
        ca = files.ca,
        cert = files.cert,
        key = files.key,
    );
    out
}

#[cfg(test)]
mod tests;
