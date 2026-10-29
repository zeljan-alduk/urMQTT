//! Build-time configuration compiled into an urMQTT image.
//!
//! Values come from `deploy/<env>/config.toml` (selected with `URMQTT_ENV`,
//! default `dev`), validated by `urmqtt-config-schema` in `build.rs`. Every
//! limit used by the data path is read from [`CONFIG`]; there are no magic
//! numbers in logic crates.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// IPv4 address with prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub addr: [u8; 4],
    pub prefix_len: u8,
}

/// IPv4 socket address of a private collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddrV4 {
    pub addr: [u8; 4],
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Dhcp,
    Static { address: Ipv4Cidr, gateway: [u8; 4] },
}

/// Certificate field that becomes the device id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityField {
    Cn,
    SanUri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// What the watchdog does when a handler exceeds its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    Log,
    Drop,
    Reset,
}

/// Token-bucket rate: `tokens` per `per_ms` milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub tokens: u32,
    pub per_ms: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Network {
    pub mode: NetworkMode,
    pub mqtt_tls_port: u16,
    /// `None` when plaintext MQTT is disabled (always in non-dev builds).
    pub mqtt_plain_port: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct Tls {
    pub identity_field: IdentityField,
    pub resumption: bool,
    /// Revoked client certificate serials (lowercase hex, no leading zeros
    /// guaranteed only after normalisation by the TLS layer).
    pub revoked_serials: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
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
    /// TLS handshakes a core runs at once; more are refused (M16).
    pub max_handshakes_in_flight_per_core: u32,
    /// Of those, from one source address (an unauthenticated peer cannot
    /// take every slot; devices behind one NAT share it).
    pub max_handshakes_in_flight_per_ip: u32,
}

/// Topic filter patterns; `{id}` expands to the session's device id.
#[derive(Debug, Clone, Copy)]
pub struct Acl {
    pub device_publish: &'static [&'static str],
    pub device_subscribe: &'static [&'static str],
    /// Identities (exact, or prefix with trailing `*`) with service rights.
    pub service_ids: &'static [&'static str],
    pub service_publish: &'static [&'static str],
    pub service_subscribe: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Storage {
    pub sqlite_heap_mb: u32,
    pub telemetry_topics: &'static [&'static str],
    pub retention_days: u32,
    pub require_flush: bool,
    pub require_data_disk: bool,
    pub refuse_on_corruption: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Observability {
    pub log_level: LogLevel,
    pub syslog_udp: Option<SocketAddrV4>,
    pub metrics_udp: Option<SocketAddrV4>,
}

#[derive(Debug, Clone, Copy)]
pub struct Watchdog {
    pub handler_budget_ms: u32,
    pub action: WatchdogAction,
}

#[derive(Debug, Clone, Copy)]
pub struct Memory {
    /// Kernel heap (buddy allocator), a power of two.
    pub kernel_heap_mb: u32,
    /// New connections are refused while less heap than this is free.
    pub min_free_mb: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Entropy {
    /// No virtio-rng and no `RNDR`: seed from CPU timing jitter (health-
    /// tested, conservatively estimated) instead of refusing to boot.
    pub jitter_fallback: bool,
}

/// The complete build-time configuration.
#[derive(Debug, Clone, Copy)]
pub struct BuildConfig {
    /// Environment name, e.g. `dev` or `prod`.
    pub env: &'static str,
    pub network: Network,
    pub tls: Tls,
    pub limits: Limits,
    pub acl: Acl,
    pub storage: Storage,
    pub observability: Observability,
    pub watchdog: Watchdog,
    pub memory: Memory,
    pub entropy: Entropy,
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
