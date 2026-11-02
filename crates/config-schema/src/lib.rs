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
    Auto,
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
    entropy: RawEntropy,
    /// Optional: without it nothing is disabled.
    #[serde(default)]
    cpu: RawCpu,
    /// Optional: without it there is no SNTP (T1, ADR-100).
    #[serde(default)]
    time: RawTime,
    trust: RawTrust,
    registry: RawRegistry,
    control: RawControl,
    /// Optional: without it there is no plaintext listener (P1, ADR-229).
    #[serde(default)]
    plaintext: RawPlaintext,
}

/// How a plaintext client proves who it is (P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextAuth {
    /// An MQTT user name and password; the user name is the identity.
    Password,
    /// No login: every client is `anonymous_identity`.
    Anonymous,
    /// The client's address decides (`ip_identities`).
    Ip,
}

/// An account of the plaintext listener (TOML: `{ id = ..., password_hash = ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainUser {
    pub id: String,
    pub password_hash: String,
}

/// A network and its identity (TOML: `{ from = ..., id = ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainIpIdentity {
    pub from: String,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawPlaintext {
    enabled: bool,
    port: u16,
    allow_from: Vec<String>,
    allow_from_anywhere: bool,
    auth: PlaintextAuth,
    anonymous_identity: String,
    users: Vec<PlainUser>,
    ip_identities: Vec<PlainIpIdentity>,
    max_connections: u32,
    max_connections_per_ip: u32,
    max_packet_size: u32,
    publish_rate_per_device: String,
    max_failed_auths_per_ip: u32,
    lockout_s: u32,
    acl_publish: Vec<String>,
    acl_subscribe: Vec<String>,
    retain: bool,
}

/// The default of a field of the table (the one place defaults live).
fn default_of(key: &str) -> Option<urmqtt_cfg::fields::Kind> {
    urmqtt_cfg::fields::by_key(key).map(|f| f.kind)
}

fn default_uint(key: &str) -> u64 {
    match default_of(key) {
        Some(urmqtt_cfg::fields::Kind::UInt { default, .. }) => default,
        _ => 0,
    }
}

fn default_bool(key: &str) -> bool {
    matches!(default_of(key), Some(urmqtt_cfg::fields::Kind::Bool(true)))
}

fn default_strs(key: &str) -> Vec<String> {
    match default_of(key) {
        Some(urmqtt_cfg::fields::Kind::Strs { default, .. }) => {
            default.iter().map(|s| (*s).to_owned()).collect()
        }
        _ => Vec::new(),
    }
}

impl Default for RawPlaintext {
    fn default() -> Self {
        let u32_of = |k: &str| u32::try_from(default_uint(k)).unwrap_or(u32::MAX);
        let rate = match default_of("plaintext.publish_rate_per_device") {
            Some(urmqtt_cfg::fields::Kind::Rate { tokens, per_ms }) => {
                pack::rate_text(tokens, per_ms)
            }
            _ => "5/s".to_owned(),
        };
        let text = |k: &str| match default_of(k) {
            Some(urmqtt_cfg::fields::Kind::Str { default, .. }) => default.to_owned(),
            _ => String::new(),
        };
        Self {
            enabled: default_bool("plaintext.enabled"),
            port: u16::try_from(default_uint("plaintext.port")).unwrap_or(0),
            allow_from: default_strs("plaintext.allow_from"),
            allow_from_anywhere: default_bool("plaintext.allow_from_anywhere"),
            auth: PlaintextAuth::Password,
            anonymous_identity: text("plaintext.anonymous_identity"),
            users: Vec::new(),
            ip_identities: Vec::new(),
            max_connections: u32_of("plaintext.max_connections"),
            max_connections_per_ip: u32_of("plaintext.max_connections_per_ip"),
            max_packet_size: u32_of("plaintext.max_packet_size"),
            publish_rate_per_device: rate,
            max_failed_auths_per_ip: u32_of("plaintext.max_failed_auths_per_ip"),
            lockout_s: u32_of("plaintext.lockout_s"),
            acl_publish: default_strs("plaintext.acl_publish"),
            acl_subscribe: default_strs("plaintext.acl_subscribe"),
            retain: default_bool("plaintext.retain"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrust {
    operational: Vec<String>,
    bootstrap: Vec<String>,
    min_anchor_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    mode: RegistryMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControl {
    public_key: String,
    service_ids: Vec<String>,
    allow_unrevoke: bool,
    max_message_age_s: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryMode {
    /// Every identity with a valid certificate may connect.
    Open,
    /// Only identities on the allowlist (control channel, H1).
    Allowlist,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawTime {
    servers: Vec<String>,
    interval_s: u32,
    max_step_s: u32,
}

impl Default for RawTime {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            interval_s: 3600,
            max_step_s: 600,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCpu {
    disable: Vec<String>,
    /// Core 0 also serves MQTT connections (default false, ADR-081).
    #[serde(default)]
    dispatcher_serves: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntropy {
    fallback: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemory {
    kernel_heap_mb: u32,
    min_free_mb: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    mode: NetworkModeKind,
    address: Option<String>,
    gateway: Option<String>,
    dhcp_timeout_s: Option<u32>,
    mqtt_tls_port: u16,
    mqtt_plain_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    cert: String,
    key: String,
    identity_field: IdentityField,
    resumption: bool,
    revocation_list: String,
    min_server_cert_days: u32,
    early_data: bool,
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
    max_retained_per_device: u32,
    max_retained_bytes: u64,
    publish_rate_per_device: String,
    handshakes_per_core_per_sec: u32,
    max_handshakes_in_flight_per_core: u32,
    max_handshakes_in_flight_per_ip: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcl {
    device_publish: Vec<String>,
    device_subscribe: Vec<String>,
    service_ids: Vec<String>,
    service_publish: Vec<String>,
    service_subscribe: Vec<String>,
    operator_ids: Vec<String>,
}

/// Where the data partition lives (O3, ADR-054).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    /// The boot disk's data partition; the live entry is refused.
    Disk,
    /// The disk, except in the ISO's live entry (`live` on the kernel
    /// command line), which runs from RAM.
    Auto,
    /// Always RAM: ephemeral, whatever the boot medium.
    Ram,
}

/// What the store tells the disk about space it no longer uses (S4,
/// ADR-150).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscardMode {
    /// Use the device's discard (or write-zeroes with unmap) when it has one.
    Auto,
    /// Never.
    Off,
}

/// Encryption of the data partition at rest (S7, ADR-240).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EncryptionMode {
    #[serde(rename = "off")]
    Off,
    /// AES-256-XTS per 512-byte sector.
    #[serde(rename = "aes-256-xts")]
    Aes256Xts,
}

/// Bounds of `storage.ram_percent`: the floor keeps the RAM store above
/// the data layout's 16 MiB minimum on ordinary machines, the ceiling
/// leaves most of RAM to the connections.
pub const RAM_PERCENT_MIN: u32 = 2;
pub const RAM_PERCENT_MAX: u32 = 50;
pub const RAM_PERCENT_DEFAULT: u32 = 10;

const fn default_ram_percent() -> u32 {
    RAM_PERCENT_DEFAULT
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    /// Required outside dev: the choice is explicit in the baked config.
    #[serde(default)]
    mode: Option<StorageMode>,
    #[serde(default = "default_ram_percent")]
    ram_percent: u32,
    /// Whether the ISO's diagnostic entry may run on this image (O4).
    /// Off unless the configuration says so.
    #[serde(default)]
    diagnostic: bool,
    sqlite_heap_mb: u32,
    telemetry_topics: Vec<String>,
    retention_days: u32,
    /// Percent of new disk space (after the volume grew) that goes to the
    /// SQLite database; the rest goes to the telemetry ring (S3).
    #[serde(default = "default_grow_ratio_db")]
    grow_ratio_db: u32,
    /// Release retired telemetry segments, the tail of truncated files and
    /// space a grow added to the device (S4).
    #[serde(default = "default_discard")]
    discard: DiscardMode,
    /// Minutes between two in-disk database backups; 0 turns the backups
    /// off (S5, ADR-162).
    #[serde(default = "default_backup_interval_min")]
    backup_interval_min: u32,
    /// Restore the newest intact backup when the database fails its
    /// integrity check at boot (S5, ADR-163). With `false` the disk is
    /// refused (or the dev fallback applies), as before S5.
    #[serde(default = "default_auto_restore")]
    auto_restore: bool,
    /// Hours between two scrub passes (re-reading the telemetry ring,
    /// checking the database and the backups); 0 turns scrubbing off
    /// (S6, ADR-164).
    #[serde(default = "default_scrub_interval_h")]
    scrub_interval_h: u32,
    /// Megabytes per second a scrub pass may read (S6).
    #[serde(default = "default_scrub_io_budget_mb_s")]
    scrub_io_budget_mb_s: u32,
    /// `"off"` (default) or `"aes-256-xts"`: the data partition is
    /// encrypted at rest (S7, ADR-240).
    #[serde(default = "default_encryption")]
    encryption: EncryptionMode,
    /// The key file (only with encryption).
    #[serde(default)]
    disk_key: String,
    require_flush: bool,
    require_data_disk: bool,
    refuse_on_corruption: bool,
}

const fn default_encryption() -> EncryptionMode {
    EncryptionMode::Off
}

fn default_grow_ratio_db() -> u32 {
    50
}

const fn default_discard() -> DiscardMode {
    DiscardMode::Auto
}

/// One backup an hour by default.
pub const BACKUP_INTERVAL_DEFAULT_MIN: u32 = 60;
/// Longest interval: a week.
pub const BACKUP_INTERVAL_MAX_MIN: u32 = 7 * 24 * 60;

const fn default_backup_interval_min() -> u32 {
    BACKUP_INTERVAL_DEFAULT_MIN
}

const fn default_auto_restore() -> bool {
    true
}

/// One scrub pass a day by default.
pub const SCRUB_INTERVAL_DEFAULT_H: u32 = 24;
/// Longest interval: 90 days.
pub const SCRUB_INTERVAL_MAX_H: u32 = 90 * 24;
/// Default read budget of a scrub pass, MB/s.
pub const SCRUB_BUDGET_DEFAULT_MB_S: u32 = 8;
/// Largest read budget accepted, MB/s.
pub const SCRUB_BUDGET_MAX_MB_S: u32 = 1024;

const fn default_scrub_interval_h() -> u32 {
    SCRUB_INTERVAL_DEFAULT_H
}

const fn default_scrub_io_budget_mb_s() -> u32 {
    SCRUB_BUDGET_DEFAULT_MB_S
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
    /// 0 (the default): derived at boot from the measured handshake cost.
    #[serde(default)]
    handshake_budget_ms: u32,
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
    /// DHCP first; without a lease after `dhcp_timeout_s` (or when the lease
    /// is lost) the static address and gateway are used.
    Auto {
        address: Ipv4Cidr,
        gateway: Ipv4Addr,
        dhcp_timeout_s: u32,
    },
}

/// Default and limits of `network.dhcp_timeout_s` (mode `auto`).
pub const DHCP_TIMEOUT_DEFAULT_S: u32 = 15;
pub const DHCP_TIMEOUT_RANGE_S: core::ops::RangeInclusive<u32> = 3..=120;

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
    pub cert: String,
    pub key: String,
    pub identity_field: IdentityField,
    pub resumption: bool,
    /// File of revoked certificate serials (hex, one per line), or empty.
    pub revocation_list: String,
    /// The build fails if the server certificate expires sooner.
    pub min_server_cert_days: u32,
}

/// Trust anchors by role (H1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// CA files granting device and service rights (at least one).
    pub operational: Vec<String>,
    /// CA files granting only `provision/{id}/#` (may be empty).
    pub bootstrap: Vec<String>,
    /// The build fails if any anchor expires sooner.
    pub min_anchor_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// Ed25519 public key file (`BEGIN PUBLIC KEY`).
    pub public_key: String,
    /// Operational identities that may publish control messages; empty
    /// disables the control channel.
    pub service_ids: Vec<String>,
    pub allow_unrevoke: bool,
    pub max_message_age_s: u32,
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
    /// Retained messages one identity may hold (H3).
    pub max_retained_per_device: u32,
    /// Retained bytes per data core (each core holds a replica).
    pub max_retained_bytes: u64,
    pub publish_rate_per_device: Rate,
    pub handshakes_per_core_per_sec: u32,
    pub max_handshakes_in_flight_per_core: u32,
    pub max_handshakes_in_flight_per_ip: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    pub device_publish: Vec<String>,
    pub device_subscribe: Vec<String>,
    pub service_ids: Vec<String>,
    pub service_publish: Vec<String>,
    pub service_subscribe: Vec<String>,
    /// Identities with the operator role (O1, O2): the only ones that read
    /// `$SYS/` and publish to the console. Exact ids; empty: no operator.
    pub operator_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Storage {
    pub mode: StorageMode,
    /// Share of RAM reserved for the in-memory data store (live mode).
    pub ram_percent: u32,
    /// The ISO's diagnostic boot entry is allowed (O4, ADR-063).
    pub diagnostic: bool,
    pub sqlite_heap_mb: u32,
    pub telemetry_topics: Vec<String>,
    pub retention_days: u32,
    /// Percent of new disk space that goes to the SQLite database when the
    /// volume grows; the rest goes to the telemetry ring (S3).
    pub grow_ratio_db: u32,
    /// `"auto"` (default) or `"off"`: release retired telemetry segments,
    /// the tail of truncated files and space a grow added (S4).
    pub discard: DiscardMode,
    /// Minutes between two in-disk database backups (S5); 0: none.
    pub backup_interval_min: u32,
    /// Restore the newest intact backup when the database is corrupt at
    /// boot (S5); `false`: refuse, as before.
    pub auto_restore: bool,
    /// Hours between scrub passes (S6); 0: none.
    pub scrub_interval_h: u32,
    /// Megabytes per second a scrub pass may read (S6).
    pub scrub_io_budget_mb_s: u32,
    /// Encryption at rest (S7).
    pub encryption: EncryptionMode,
    /// Name of the key file, empty when encryption is off.
    pub disk_key: String,
    pub require_flush: bool,
    /// Without a data disk: refuse to serve (true) or run in memory only.
    pub require_data_disk: bool,
    /// `PRAGMA quick_check` failure: refuse to serve (true) or run without
    /// persistence.
    pub refuse_on_corruption: bool,
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
    pub min_free_mb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watchdog {
    pub handler_budget_ms: u32,
    /// Budget of a TLS handshake step; 0 means "calibrate at boot" (ADR-071).
    pub handshake_budget_ms: u32,
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
    pub entropy: Entropy,
    pub cpu: Cpu,
    pub time: Time,
    pub trust: Trust,
    pub registry: RegistryMode,
    pub control: Control,
    pub plaintext: Plaintext,
}

/// Plaintext MQTT for trusted networks (P1, ADR-229). Off by default; the
/// other keys are inert while `enabled` is false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plaintext {
    pub enabled: bool,
    pub port: u16,
    /// Networks that may connect, as `a.b.c.d/len` text.
    pub allow_from: Vec<String>,
    pub allow_from_anywhere: bool,
    pub auth: PlaintextAuth,
    pub anonymous_identity: String,
    pub users: Vec<PlainUser>,
    pub ip_identities: Vec<PlainIpIdentity>,
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_packet_size: u32,
    pub publish_rate_per_device: Rate,
    pub max_failed_auths_per_ip: u32,
    pub lockout_s: u32,
    pub acl_publish: Vec<String>,
    pub acl_subscribe: Vec<String>,
    pub retain: bool,
}

/// The SNTP wall clock (T1, ADR-100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    /// NTP servers as IPv4 literals (there is no DNS resolver), at most
    /// four, port 123 unless given. Empty: no SNTP, the clock is the RTC.
    pub servers: Vec<SocketAddrV4>,
    /// Seconds between queries.
    pub interval_s: u32,
    /// The most one correction may move the clock after the first, and all
    /// of them together, seconds.
    pub max_step_s: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// CPU features the dispatch must not use (`urmqtt_dispatch::Feature`
    /// names, validated).
    pub disable: Vec<String>,
    /// With two or more data cores, core 0 owns the NIC and steers frames;
    /// by default it serves no connections. `true`: it takes its share of
    /// the flows too, with its connection work cut into slices so the NIC
    /// is served in between (ADR-081). For benchmarking on a VPS; the
    /// production default stays `false`.
    pub dispatcher_serves: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entropy {
    /// Seed from CPU timing jitter when no hardware source exists.
    pub jitter_fallback: bool,
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

    let network = validate_network(env, &raw.network, raw.plaintext.enabled, &mut errors);
    let tls = validate_tls(&raw.tls, &mut errors);
    let limits = validate_limits(&raw.limits, &mut errors);
    let acl = validate_acl(&raw.acl, &limits, &mut errors);
    let storage = validate_storage(env, &raw.storage, &limits, &mut errors);
    let observability = validate_observability(&raw.observability, &mut errors);
    let watchdog = validate_watchdog(&raw.watchdog, &mut errors);
    let memory = validate_memory(&raw.memory, &mut errors);
    // Every data core keeps a replica of the retained messages (M13): with
    // up to eight of them the budget may take an eighth of the heap.
    let heap = u64::from(memory.kernel_heap_mb) << 20;
    if limits.max_retained_bytes == 0 || limits.max_retained_bytes > heap / 8 {
        errors.push(err(
            "limits.max_retained_bytes",
            format!(
                "must be in 1..={} (an eighth of memory.kernel_heap_mb: one replica per data core)",
                heap / 8
            ),
        ));
    }
    let jitter_fallback = match raw.entropy.fallback.as_str() {
        "jitter" => true,
        "none" => false,
        _ => {
            errors.push(err("entropy.fallback", "must be \"jitter\" or \"none\""));
            false
        }
    };

    let cpu = validate_cpu(&raw.cpu, &mut errors);
    let time = validate_time(&raw.time, &mut errors);
    let trust = validate_trust(&raw.trust, &mut errors);
    let control = validate_control(&raw.control, &mut errors);
    let plaintext = validate_plaintext(
        &raw.plaintext,
        &network,
        &limits,
        &acl,
        &control,
        &mut errors,
    );

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
        entropy: Entropy { jitter_fallback },
        cpu,
        time,
        trust,
        registry: raw.registry.mode,
        control,
        plaintext,
    })
}

/// The `[plaintext]` section (P1, ADR-229). The same rules as
/// `urmqtt_cfg::check` applies to a blob (the kernel's copy), with messages
/// that name the offending entry. Entries must be well formed whether or not
/// the listener is on; what the listener needs is checked when it is on.
fn validate_plaintext(
    raw: &RawPlaintext,
    network: &Network,
    limits: &Limits,
    acl: &Acl,
    control: &Control,
    errors: &mut Vec<ConfigError>,
) -> Plaintext {
    use urmqtt_cfg::net::Cidr;
    use urmqtt_cfg::plain;

    let port_key = "plaintext.port";
    if raw.port == 0 {
        errors.push(err(port_key, "must be a non-zero port"));
    }
    for (key, v, min, max) in [
        (
            "plaintext.max_connections",
            raw.max_connections,
            1,
            1_000_000,
        ),
        (
            "plaintext.max_connections_per_ip",
            raw.max_connections_per_ip,
            1,
            65_535,
        ),
        (
            "plaintext.max_failed_auths_per_ip",
            raw.max_failed_auths_per_ip,
            1,
            1000,
        ),
        ("plaintext.lockout_s", raw.lockout_s, 1, 86_400),
    ] {
        if !(min..=max).contains(&v) {
            errors.push(err(key, format!("must be in {min}..={max}")));
        }
    }
    if !(MIN_PACKET_SIZE..=MQTT_MAX_PACKET_SIZE).contains(&raw.max_packet_size) {
        errors.push(err(
            "plaintext.max_packet_size",
            format!("must be in {MIN_PACKET_SIZE}..={MQTT_MAX_PACKET_SIZE}"),
        ));
    }
    let publish_rate_per_device = parse_rate(&raw.publish_rate_per_device).unwrap_or_else(|m| {
        errors.push(err("plaintext.publish_rate_per_device", m));
        Rate {
            tokens: 0,
            per_ms: 0,
        }
    });

    // Lists: their sizes first (the kernel's arrays), then each entry.
    for (key, len, max) in [
        (
            "plaintext.allow_from",
            raw.allow_from.len(),
            urmqtt_cfg::fields::MAX_PLAIN_NETWORKS,
        ),
        (
            "plaintext.users",
            raw.users.len(),
            urmqtt_cfg::fields::MAX_PLAIN_USERS,
        ),
        (
            "plaintext.ip_identities",
            raw.ip_identities.len(),
            urmqtt_cfg::fields::MAX_PLAIN_IP_IDENTITIES,
        ),
        (
            "plaintext.acl_publish",
            raw.acl_publish.len(),
            urmqtt_cfg::fields::MAX_PLAIN_ACL,
        ),
        (
            "plaintext.acl_subscribe",
            raw.acl_subscribe.len(),
            urmqtt_cfg::fields::MAX_PLAIN_ACL,
        ),
    ] {
        if len > max {
            errors.push(err(key, format!("at most {max} entries")));
        }
    }
    let mut nets: Vec<Cidr> = Vec::new();
    for (i, s) in raw.allow_from.iter().enumerate() {
        match plain::parse_allow(s) {
            Ok(c) if nets.contains(&c) => {
                errors.push(err(
                    &format!("plaintext.allow_from[{i}]"),
                    format!("{s:?} is listed twice"),
                ));
            }
            Ok(c) => nets.push(c),
            Err(m) => errors.push(err(
                &format!("plaintext.allow_from[{i}]"),
                format!("{s:?}: {m}"),
            )),
        }
    }
    for (i, u) in raw.users.iter().enumerate() {
        let path = format!("plaintext.users[{i}]");
        if let Err(m) = plain::check_identity(&u.id) {
            errors.push(err(&format!("{path}.id"), format!("{:?}: {m}", u.id)));
        } else if raw.users.iter().take(i).any(|o| o.id == u.id) {
            errors.push(err(
                &format!("{path}.id"),
                format!("{:?} is listed twice", u.id),
            ));
        }
        if let Err(m) = urmqtt_cfg::passwd::PasswordHash::parse(&u.password_hash) {
            errors.push(err(&format!("{path}.password_hash"), m.msg()));
        }
    }
    let mut id_nets: Vec<Cidr> = Vec::new();
    for (i, e) in raw.ip_identities.iter().enumerate() {
        let path = format!("plaintext.ip_identities[{i}]");
        match Cidr::parse(&e.from) {
            Ok(c) if c.prefix == 0 => errors.push(err(
                &format!("{path}.from"),
                "0.0.0.0/0 is every address: use auth = \"anonymous\" for that",
            )),
            Ok(c) if id_nets.contains(&c) => {
                errors.push(err(
                    &format!("{path}.from"),
                    format!("{:?} is listed twice", e.from),
                ));
            }
            Ok(c) => id_nets.push(c),
            Err(m) => errors.push(err(&format!("{path}.from"), format!("{:?}: {m}", e.from))),
        }
        if let Err(m) = plain::check_identity(&e.id) {
            errors.push(err(&format!("{path}.id"), format!("{:?}: {m}", e.id)));
        }
    }
    if let Err(m) = plain::check_identity(&raw.anonymous_identity) {
        errors.push(err(
            "plaintext.anonymous_identity",
            format!("{:?}: {m}", raw.anonymous_identity),
        ));
    }
    for (key, list) in [
        ("plaintext.acl_publish", &raw.acl_publish),
        ("plaintext.acl_subscribe", &raw.acl_subscribe),
    ] {
        for (i, f) in list.iter().enumerate() {
            let path = format!("{key}[{i}]");
            if let Err(m) = check_topic_filter(f, limits, Placeholder::Allowed) {
                errors.push(err(&path, m));
            } else if f.starts_with('$') {
                errors.push(err(&path, "no filter may start with $ (broker topics)"));
            }
        }
    }

    if !raw.enabled {
        if raw.allow_from_anywhere {
            errors.push(err(
                "plaintext.allow_from_anywhere",
                "is set but plaintext is not enabled: remove it, so the file does not look more dangerous than it is",
            ));
        }
    } else {
        validate_plaintext_enabled(raw, &nets, network, acl, control, errors);
    }

    Plaintext {
        enabled: raw.enabled,
        port: raw.port,
        allow_from: raw.allow_from.clone(),
        allow_from_anywhere: raw.allow_from_anywhere,
        auth: raw.auth,
        anonymous_identity: raw.anonymous_identity.clone(),
        users: raw.users.clone(),
        ip_identities: raw.ip_identities.clone(),
        max_connections: raw.max_connections,
        max_connections_per_ip: raw.max_connections_per_ip,
        max_packet_size: raw.max_packet_size,
        publish_rate_per_device,
        max_failed_auths_per_ip: raw.max_failed_auths_per_ip,
        lockout_s: raw.lockout_s,
        acl_publish: raw.acl_publish.clone(),
        acl_subscribe: raw.acl_subscribe.clone(),
        retain: raw.retain,
    }
}

/// What a plaintext listener that is on needs, and what must not contradict
/// its mode.
fn validate_plaintext_enabled(
    raw: &RawPlaintext,
    nets: &[urmqtt_cfg::net::Cidr],
    network: &Network,
    acl: &Acl,
    control: &Control,
    errors: &mut Vec<ConfigError>,
) {
    let other_role = |id: &str| {
        acl.service_ids.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => p == id,
        }) || acl.operator_ids.iter().any(|o| o == id)
            || control.service_ids.iter().any(|c| c == id)
    };
    const ROLE: &str = "is also an acl.service_ids, acl.operator_ids or control.service_ids identity: plaintext clients never hold those roles, pick another name";
    if raw.allow_from_anywhere && !raw.allow_from.is_empty() {
        errors.push(err(
            "plaintext.allow_from_anywhere",
            "overrides allow_from: remove one of the two",
        ));
    }
    if !raw.allow_from_anywhere && raw.allow_from.is_empty() {
        errors.push(err(
            "plaintext.allow_from",
            "required when plaintext is enabled: the networks that may connect (for example 10.0.0.0/8), or allow_from_anywhere = true",
        ));
    }
    if network.mqtt_tls_port != 0 && raw.port == network.mqtt_tls_port {
        errors.push(err(
            "plaintext.port",
            "must differ from network.mqtt_tls_port",
        ));
    }
    if network.mqtt_plain_port == Some(raw.port) {
        errors.push(err(
            "plaintext.port",
            "must differ from network.mqtt_plain_port",
        ));
    }
    let anon_default = raw.anonymous_identity == "lan";
    match raw.auth {
        PlaintextAuth::Password => {
            if raw.users.is_empty() {
                errors.push(err(
                    "plaintext.users",
                    "auth = \"password\" needs at least one account",
                ));
            }
            if !raw.ip_identities.is_empty() {
                errors.push(err(
                    "plaintext.ip_identities",
                    "only used with auth = \"ip\"",
                ));
            }
            if !anon_default {
                errors.push(err(
                    "plaintext.anonymous_identity",
                    "only used with auth = \"anonymous\"",
                ));
            }
            for (i, u) in raw.users.iter().enumerate() {
                if other_role(&u.id) {
                    errors.push(err(
                        &format!("plaintext.users[{i}].id"),
                        format!("{:?} {ROLE}", u.id),
                    ));
                }
            }
        }
        PlaintextAuth::Anonymous => {
            if !raw.users.is_empty() {
                errors.push(err("plaintext.users", "only used with auth = \"password\""));
            }
            if !raw.ip_identities.is_empty() {
                errors.push(err(
                    "plaintext.ip_identities",
                    "only used with auth = \"ip\"",
                ));
            }
            if other_role(&raw.anonymous_identity) {
                errors.push(err(
                    "plaintext.anonymous_identity",
                    format!("{:?} {ROLE}", raw.anonymous_identity),
                ));
            }
        }
        PlaintextAuth::Ip => {
            if raw.ip_identities.is_empty() {
                errors.push(err(
                    "plaintext.ip_identities",
                    "auth = \"ip\" needs at least one network",
                ));
            }
            if !raw.users.is_empty() {
                errors.push(err("plaintext.users", "only used with auth = \"password\""));
            }
            if !anon_default {
                errors.push(err(
                    "plaintext.anonymous_identity",
                    "only used with auth = \"anonymous\"",
                ));
            }
            for (i, e) in raw.ip_identities.iter().enumerate() {
                let path = format!("plaintext.ip_identities[{i}]");
                if other_role(&e.id) {
                    errors.push(err(&format!("{path}.id"), format!("{:?} {ROLE}", e.id)));
                }
                if let Ok(net) = urmqtt_cfg::net::Cidr::parse(&e.from)
                    && net.prefix != 0
                    && !raw.allow_from_anywhere
                    && !nets.iter().any(|a| a.contains_net(&net))
                {
                    errors.push(err(
                        &format!("{path}.from"),
                        format!(
                            "{:?} is not inside allow_from, so no client could ever match it",
                            e.from
                        ),
                    ));
                }
            }
        }
    }
}

fn validate_trust(raw: &RawTrust, errors: &mut Vec<ConfigError>) -> Trust {
    if raw.operational.is_empty() {
        errors.push(err("trust.operational", "at least one CA file is required"));
    }
    for (key, list) in [
        ("trust.operational", &raw.operational),
        ("trust.bootstrap", &raw.bootstrap),
    ] {
        for (i, name) in list.iter().enumerate() {
            if let Err(m) = check_file_name(name) {
                errors.push(err(&format!("{key}[{i}]"), m));
            }
        }
    }
    if raw.bootstrap.iter().any(|b| raw.operational.contains(b)) {
        errors.push(err(
            "trust.bootstrap",
            "a CA file cannot be both operational and bootstrap",
        ));
    }
    if raw.min_anchor_days == 0 {
        errors.push(err("trust.min_anchor_days", "must be at least 1"));
    }
    Trust {
        operational: raw.operational.clone(),
        bootstrap: raw.bootstrap.clone(),
        min_anchor_days: raw.min_anchor_days,
    }
}

fn validate_control(raw: &RawControl, errors: &mut Vec<ConfigError>) -> Control {
    if let Err(m) = check_file_name(&raw.public_key) {
        errors.push(err("control.public_key", m));
    }
    for (i, id) in raw.service_ids.iter().enumerate() {
        // Exact identities only: a control right is never granted by prefix.
        if id.ends_with('*') || check_identity_pattern(id).is_err() {
            errors.push(err(
                &format!("control.service_ids[{i}]"),
                "must be an exact identity ([A-Za-z0-9-_.:]+, no wildcard)",
            ));
        }
    }
    if !(1..=86_400).contains(&raw.max_message_age_s) {
        errors.push(err("control.max_message_age_s", "must be 1..=86400"));
    }
    Control {
        public_key: raw.public_key.clone(),
        service_ids: raw.service_ids.clone(),
        allow_unrevoke: raw.allow_unrevoke,
        max_message_age_s: raw.max_message_age_s,
    }
}

fn validate_cpu(raw: &RawCpu, errors: &mut Vec<ConfigError>) -> Cpu {
    let names: Vec<&str> = raw.disable.iter().map(String::as_str).collect();
    match urmqtt_dispatch::parse_disable(&names) {
        Ok(_) => {}
        Err(urmqtt_dispatch::DisableError::Unknown) => {
            let known: Vec<&str> = urmqtt_dispatch::Feature::ALL
                .iter()
                .map(|f| f.name())
                .collect();
            errors.push(err(
                "cpu.disable",
                format!(
                    "unknown feature; switchable features are {}",
                    known.join(", ")
                ),
            ));
        }
        Err(urmqtt_dispatch::DisableError::Duplicate) => {
            errors.push(err("cpu.disable", "a feature is listed twice"));
        }
    }
    Cpu {
        disable: raw.disable.clone(),
        dispatcher_serves: raw.dispatcher_serves,
    }
}

/// Most servers a round asks (`urmqtt_sntp::MAX_SERVERS`).
const MAX_TIME_SERVERS: usize = 4;

fn validate_time(raw: &RawTime, errors: &mut Vec<ConfigError>) -> Time {
    let mut servers: Vec<SocketAddrV4> = Vec::new();
    if raw.servers.len() > MAX_TIME_SERVERS {
        errors.push(err(
            "time.servers",
            format!("at most {MAX_TIME_SERVERS} servers"),
        ));
    }
    for s in &raw.servers {
        // "a.b.c.d" or "a.b.c.d:port". A name would need DNS, which the
        // broker does not have.
        let parsed = s.parse::<SocketAddrV4>().ok().or_else(|| {
            s.parse::<Ipv4Addr>()
                .ok()
                .map(|a| SocketAddrV4::new(a, 123))
        });
        match parsed {
            Some(a)
                if a.port() != 0
                    && !a.ip().is_unspecified()
                    && !a.ip().is_broadcast()
                    && !a.ip().is_multicast()
                    && !a.ip().is_loopback() =>
            {
                if servers.contains(&a) {
                    errors.push(err("time.servers", format!("{s:?} is listed twice")));
                } else {
                    servers.push(a);
                }
            }
            _ => errors.push(err(
                "time.servers",
                format!(
                    "{s:?} must be an IPv4 address \"a.b.c.d\" or \"a.b.c.d:port\" (there is no DNS resolver; \
                     not 0.0.0.0, loopback, multicast or broadcast)"
                ),
            )),
        }
    }
    if !(60..=86_400).contains(&raw.interval_s) {
        errors.push(err("time.interval_s", "must be in 60..=86400"));
    }
    if !(1..=86_400).contains(&raw.max_step_s) {
        errors.push(err("time.max_step_s", "must be in 1..=86400"));
    }
    Time {
        servers,
        interval_s: raw.interval_s,
        max_step_s: raw.max_step_s,
    }
}

fn is_valid_env_name(env: &str) -> bool {
    !env.is_empty()
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn validate_network(
    env: &str,
    raw: &RawNetwork,
    plaintext_on: bool,
    errors: &mut Vec<ConfigError>,
) -> Network {
    let mode = match raw.mode {
        NetworkModeKind::Dhcp => {
            if raw.address.is_some() || raw.gateway.is_some() {
                errors.push(err(
                    "network",
                    "address/gateway are only allowed with mode = \"static\" or \"auto\"",
                ));
            }
            if raw.dhcp_timeout_s.is_some() {
                errors.push(err(
                    "network.dhcp_timeout_s",
                    "only allowed with mode = \"auto\"",
                ));
            }
            NetworkMode::Dhcp
        }
        kind @ (NetworkModeKind::Static | NetworkModeKind::Auto) => {
            let name = if kind == NetworkModeKind::Auto {
                "auto"
            } else {
                "static"
            };
            let address = match raw.address.as_deref() {
                Some(s) => parse_cidr(s).unwrap_or_else(|m| {
                    errors.push(err("network.address", m));
                    Ipv4Cidr {
                        addr: Ipv4Addr::UNSPECIFIED,
                        prefix_len: 0,
                    }
                }),
                None => {
                    errors.push(err(
                        "network.address",
                        format!("required when mode = \"{name}\""),
                    ));
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
                    errors.push(err(
                        "network.gateway",
                        format!("required when mode = \"{name}\""),
                    ));
                    Ipv4Addr::UNSPECIFIED
                }
            };
            if kind == NetworkModeKind::Auto {
                let t = raw.dhcp_timeout_s.unwrap_or(DHCP_TIMEOUT_DEFAULT_S);
                if !DHCP_TIMEOUT_RANGE_S.contains(&t) {
                    errors.push(err(
                        "network.dhcp_timeout_s",
                        format!("must be in {DHCP_TIMEOUT_RANGE_S:?} seconds"),
                    ));
                }
                NetworkMode::Auto {
                    address,
                    gateway,
                    dhcp_timeout_s: t,
                }
            } else {
                if raw.dhcp_timeout_s.is_some() {
                    errors.push(err(
                        "network.dhcp_timeout_s",
                        "only allowed with mode = \"auto\"",
                    ));
                }
                NetworkMode::Static { address, gateway }
            }
        }
    };

    if raw.mqtt_tls_port == 0 && !plaintext_on {
        errors.push(err(
            "network.mqtt_tls_port",
            "0 (the TLS listener off) is only allowed with plaintext.enabled = true: a broker needs at least one listener",
        ));
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
            if raw.mqtt_tls_port != 0 && p == raw.mqtt_tls_port {
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
    if raw.early_data {
        errors.push(err(
            "tls.early_data",
            "must be false: 0-RTT data is replayable (PROMPT-security §2)",
        ));
    }
    if raw.min_server_cert_days == 0 {
        errors.push(err("tls.min_server_cert_days", "must be at least 1"));
    }
    for (key, name) in [("tls.cert", &raw.cert), ("tls.key", &raw.key)] {
        if let Err(m) = check_file_name(name) {
            errors.push(err(key, m));
        }
    }
    if !raw.revocation_list.is_empty()
        && let Err(m) = check_file_name(&raw.revocation_list)
    {
        errors.push(err("tls.revocation_list", m));
    }
    Tls {
        cert: raw.cert.clone(),
        key: raw.key.clone(),
        identity_field: raw.identity_field,
        resumption: raw.resumption,
        revocation_list: raw.revocation_list.clone(),
        min_server_cert_days: raw.min_server_cert_days,
    }
}

/// Parses a revocation list: one hex serial per line, `#` comments allowed.
pub fn parse_revocation_list(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .replace(':', "")
            .to_ascii_lowercase();
        if l.is_empty() {
            continue;
        }
        if l.len() % 2 != 0 || l.len() > 40 || !l.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "line {}: {line:?} is not a hex certificate serial",
                i + 1
            ));
        }
        out.push(l);
    }
    Ok(out)
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
        (
            "limits.max_handshakes_in_flight_per_core",
            raw.max_handshakes_in_flight_per_core,
        ),
        (
            "limits.max_handshakes_in_flight_per_ip",
            raw.max_handshakes_in_flight_per_ip,
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
        max_retained_per_device: raw.max_retained_per_device,
        max_retained_bytes: raw.max_retained_bytes,
        publish_rate_per_device,
        handshakes_per_core_per_sec: raw.handshakes_per_core_per_sec,
        max_handshakes_in_flight_per_core: raw.max_handshakes_in_flight_per_core,
        max_handshakes_in_flight_per_ip: raw.max_handshakes_in_flight_per_ip,
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
        } else if f.split('/').next() == Some("$urmqtt") {
            // The broker ignores such patterns anyway (H1); say so here.
            errors.push(err(
                &format!("{key}[{i}]"),
                "the $urmqtt/ namespace is reserved for the control channel",
            ));
        } else if f.split('/').next() == Some("$SYS") {
            // Likewise (O1, O2): `$SYS/` is for operators, by role.
            errors.push(err(
                &format!("{key}[{i}]"),
                "the $SYS/ namespace belongs to acl.operator_ids; no pattern grants it",
            ));
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
    for (i, id) in raw.service_ids.iter().enumerate() {
        if let Err(m) = check_identity_pattern(id) {
            errors.push(err(&format!("acl.service_ids[{i}]"), m));
        }
    }
    for (key, list) in [
        ("acl.service_publish", &raw.service_publish),
        ("acl.service_subscribe", &raw.service_subscribe),
    ] {
        validate_filters(key, list, limits, Placeholder::Allowed, errors);
    }
    for (i, id) in raw.operator_ids.iter().enumerate() {
        // Exact identities only: the operator role is never granted by prefix.
        if id.ends_with('*') || check_identity_pattern(id).is_err() {
            errors.push(err(
                &format!("acl.operator_ids[{i}]"),
                "must be an exact identity ([A-Za-z0-9-_.:]+, no wildcard)",
            ));
        } else if raw.service_ids.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => p == id,
        }) {
            errors.push(err(
                &format!("acl.operator_ids[{i}]"),
                "also matches acl.service_ids: an identity has one role",
            ));
        } else if raw.operator_ids.iter().take(i).any(|o| o == id) {
            errors.push(err(&format!("acl.operator_ids[{i}]"), "listed twice"));
        }
    }
    Acl {
        device_publish: raw.device_publish.clone(),
        device_subscribe: raw.device_subscribe.clone(),
        service_ids: raw.service_ids.clone(),
        service_publish: raw.service_publish.clone(),
        service_subscribe: raw.service_subscribe.clone(),
        operator_ids: raw.operator_ids.clone(),
    }
}

/// Identity patterns: an exact id, or a prefix ending in `*`.
pub fn check_identity_pattern(p: &str) -> Result<(), String> {
    let core = p.strip_suffix('*').unwrap_or(p);
    if core.is_empty() && !p.ends_with('*') {
        return Err("empty identity pattern".into());
    }
    if !core
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!(
            "{p:?}: identities use [A-Za-z0-9-_.:], `*` only at the end"
        ));
    }
    Ok(())
}

fn validate_storage(
    env: &str,
    raw: &RawStorage,
    limits: &Limits,
    errors: &mut Vec<ConfigError>,
) -> Storage {
    // Durability shortcuts are for development only (ADR-030).
    if env != "dev" {
        for (key, on) in [
            ("storage.require_flush", raw.require_flush),
            ("storage.require_data_disk", raw.require_data_disk),
            ("storage.refuse_on_corruption", raw.refuse_on_corruption),
        ] {
            if !on {
                errors.push(err(key, "may only be false in [\"dev\"]"));
            }
        }
    }
    // The medium is chosen in the configuration, never by a fallback at
    // run time: a production image must say which (O3).
    if env != "dev" && raw.mode.is_none() {
        errors.push(err(
            "storage.mode",
            "required outside [\"dev\"]: \"disk\", \"auto\" (the ISO's live entry runs from RAM) or \"ram\"",
        ));
    }
    if !(RAM_PERCENT_MIN..=RAM_PERCENT_MAX).contains(&raw.ram_percent) {
        errors.push(err(
            "storage.ram_percent",
            format!("must be in {RAM_PERCENT_MIN}..={RAM_PERCENT_MAX}"),
        ));
    }
    if !(1..=4096).contains(&raw.sqlite_heap_mb) {
        errors.push(err("storage.sqlite_heap_mb", "must be in 1..=4096"));
    }
    if raw.retention_days == 0 {
        errors.push(err("storage.retention_days", "must be greater than 0"));
    }
    if raw.backup_interval_min > BACKUP_INTERVAL_MAX_MIN {
        errors.push(err(
            "storage.backup_interval_min",
            format!("must be in 0..={BACKUP_INTERVAL_MAX_MIN} (minutes; 0 turns the backups off)"),
        ));
    }
    if raw.scrub_interval_h > SCRUB_INTERVAL_MAX_H {
        errors.push(err(
            "storage.scrub_interval_h",
            format!("must be in 0..={SCRUB_INTERVAL_MAX_H} (hours; 0 turns scrubbing off)"),
        ));
    }
    if !(1..=SCRUB_BUDGET_MAX_MB_S).contains(&raw.scrub_io_budget_mb_s) {
        errors.push(err(
            "storage.scrub_io_budget_mb_s",
            format!("must be in 1..={SCRUB_BUDGET_MAX_MB_S} (megabytes per second)"),
        ));
    }
    if raw.grow_ratio_db > 100 {
        errors.push(err("storage.grow_ratio_db", "must be in 0..=100 (percent)"));
    }
    match (raw.encryption, raw.disk_key.is_empty()) {
        (EncryptionMode::Aes256Xts, true) => errors.push(err(
            "storage.disk_key",
            "required with storage.encryption = \"aes-256-xts\": the name of a file with the key",
        )),
        (EncryptionMode::Off, false) => errors.push(err(
            "storage.disk_key",
            "only with storage.encryption = \"aes-256-xts\"",
        )),
        _ => {}
    }
    if !raw.disk_key.is_empty()
        && let Err(m) = check_file_name(&raw.disk_key)
    {
        errors.push(err("storage.disk_key", m));
    }
    validate_filters(
        "storage.telemetry_topics",
        &raw.telemetry_topics,
        limits,
        Placeholder::Forbidden,
        errors,
    );
    Storage {
        mode: raw.mode.unwrap_or(StorageMode::Disk),
        ram_percent: raw.ram_percent,
        diagnostic: raw.diagnostic,
        sqlite_heap_mb: raw.sqlite_heap_mb,
        telemetry_topics: raw.telemetry_topics.clone(),
        retention_days: raw.retention_days,
        grow_ratio_db: raw.grow_ratio_db,
        discard: raw.discard,
        backup_interval_min: raw.backup_interval_min,
        auto_restore: raw.auto_restore,
        scrub_interval_h: raw.scrub_interval_h,
        scrub_io_budget_mb_s: raw.scrub_io_budget_mb_s,
        encryption: raw.encryption,
        disk_key: raw.disk_key.clone(),
        require_flush: raw.require_flush,
        require_data_disk: raw.require_data_disk,
        refuse_on_corruption: raw.refuse_on_corruption,
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
    // 0 asks for the boot calibration; an explicit value stays below the
    // one-second stuck-core reset (ADR-071).
    if raw.handshake_budget_ms > 900 {
        errors.push(err(
            "watchdog.handshake_budget_ms",
            "must be 0 (calibrate at boot) or in 1..=900",
        ));
    }
    Watchdog {
        handler_budget_ms: raw.handler_budget_ms,
        handshake_budget_ms: raw.handshake_budget_ms,
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
    // New connections are refused below this much free heap, so a
    // reconnect storm cannot exhaust it (M16).
    if raw.min_free_mb == 0 || raw.min_free_mb >= mb {
        errors.push(err(
            "memory.min_free_mb",
            "must be greater than 0 and smaller than memory.kernel_heap_mb",
        ));
    }
    Memory {
        kernel_heap_mb: mb,
        min_free_mb: raw.min_free_mb,
    }
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

/// One certificate's subject and notAfter (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertValidity {
    pub subject: String,
    pub not_before: u64,
    pub not_after: u64,
}

/// Validity of every certificate in a PEM file.
pub fn cert_validity(pem: &[u8]) -> Result<Vec<CertValidity>, String> {
    use x509_cert::Certificate;
    let certs = Certificate::load_pem_chain(pem).map_err(|e| format!("cannot parse: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate".into());
    }
    Ok(certs
        .iter()
        .map(|c| {
            let v = c.tbs_certificate().validity();
            CertValidity {
                subject: c.tbs_certificate().subject().to_string(),
                not_before: v.not_before.to_unix_duration().as_secs(),
                not_after: v.not_after.to_unix_duration().as_secs(),
            }
        })
        .collect())
}

/// Fails if any certificate in `pem` expires within `min_days` of
/// `now_unix` (H1 expiry safety). Returns the earliest notAfter.
pub fn check_expiry(pem: &[u8], now_unix: u64, min_days: u32) -> Result<u64, String> {
    let certs = cert_validity(pem)?;
    let limit = now_unix + u64::from(min_days) * 86_400;
    for c in &certs {
        if c.not_after < limit {
            let days = (c.not_after as i64 - now_unix as i64).div_euclid(86_400);
            return Err(format!(
                "{} expires in {days} day(s), fewer than the required {min_days}",
                c.subject
            ));
        }
    }
    Ok(certs.iter().map(|c| c.not_after).min().unwrap_or(0))
}

pub mod pack;

#[cfg(test)]
mod encryption_tests;
#[cfg(test)]
mod pack_tests;
#[cfg(test)]
mod plain_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_off_tests;

#[cfg(kani)]
mod proofs;
