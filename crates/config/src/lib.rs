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
    /// Warnings start this many days before the server certificate
    /// expires (the build refuses a certificate closer than this).
    pub min_server_cert_days: u32,
    /// The server certificate's notAfter, Unix seconds (read at build time).
    pub server_cert_not_after: u64,
}

/// Who may connect besides holding a valid certificate (H1).
#[derive(Debug, Clone, Copy)]
pub struct Registry {
    /// Only identities on the allowlist (control channel) are admitted;
    /// otherwise every valid certificate is.
    pub allowlist: bool,
}

/// The control channel (H1).
#[derive(Debug, Clone, Copy)]
pub struct Control {
    /// Operational identities that may publish control messages (empty:
    /// the channel is off).
    pub service_ids: &'static [&'static str],
    pub allow_unrevoke: bool,
    pub max_message_age_s: u32,
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
    pub max_retained_per_device: u32,
    pub max_retained_bytes: u64,
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
    /// Operator identities (exact): `$SYS/` and the console (O1, O2).
    pub operator_ids: &'static [&'static str],
}

/// Where the data partition lives (O3, ADR-054).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    /// The boot disk's data partition; the live entry is refused.
    Disk,
    /// The disk, except in the ISO's live entry (`live` on the kernel
    /// command line), which runs from RAM.
    Auto,
    /// Always RAM: ephemeral, whatever the boot medium.
    Ram,
}

/// Where the data store ends up for this boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    Disk,
    /// An in-memory block device: lost on reboot.
    Ram,
}

impl StorageMode {
    /// What `live` (the ISO live entry's kernel command-line word) and the
    /// configuration make of the store. `Err`: live was asked for but the
    /// image's configuration does not allow it (`storage.mode = "disk"`);
    /// there is no silent fallback in either direction.
    pub const fn backing(self, live: bool) -> Result<Backing, LiveRefused> {
        match (self, live) {
            (Self::Ram, _) | (Self::Auto, true) => Ok(Backing::Ram),
            (Self::Auto, false) | (Self::Disk, false) => Ok(Backing::Disk),
            (Self::Disk, true) => Err(LiveRefused),
        }
    }
}

/// `live` was requested but `storage.mode = "disk"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveRefused;

#[derive(Debug, Clone, Copy)]
pub struct Storage {
    pub mode: StorageMode,
    /// Share of RAM reserved for the in-memory store (live mode), percent.
    pub ram_percent: u32,
    /// The ISO's diagnostic boot entry may run (O4, ADR-063).
    pub diagnostic: bool,
    pub sqlite_heap_mb: u32,
    pub telemetry_topics: &'static [&'static str],
    pub retention_days: u32,
    /// Percent of new disk space that goes to the SQLite database when the
    /// volume grows; the rest goes to the telemetry ring (S3).
    pub grow_ratio_db: u32,
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
    /// TLS handshake steps; 0: calibrated at boot (ADR-071).
    pub handshake_budget_ms: u32,
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

#[derive(Debug, Clone, Copy)]
pub struct Cpu {
    /// CPU features the crypto and checksum dispatch must not use, by
    /// `urmqtt_dispatch::Feature` name (validated at build time).
    pub disable: &'static [&'static str],
    /// Core 0 also serves connections next to the NIC work (ADR-081).
    pub dispatcher_serves: bool,
}

/// The SNTP wall clock (T1, ADR-100).
#[derive(Debug, Clone, Copy)]
pub struct Time {
    /// NTP servers (IPv4 literals); empty: no SNTP.
    pub servers: &'static [SocketAddrV4],
    pub interval_s: u32,
    pub max_step_s: u32,
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
    pub cpu: Cpu,
    pub time: Time,
    pub registry: Registry,
    pub control: Control,
}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    /// O3 (ADR-054): the whole decision table of `storage.mode` x `live`.
    #[test]
    fn mode_and_live_word_decide_the_backing() {
        use Backing::{Disk, Ram};
        use StorageMode as M;
        assert_eq!(M::Disk.backing(false), Ok(Disk));
        assert_eq!(M::Disk.backing(true), Err(LiveRefused));
        assert_eq!(M::Auto.backing(false), Ok(Disk));
        assert_eq!(M::Auto.backing(true), Ok(Ram));
        assert_eq!(M::Ram.backing(false), Ok(Ram));
        assert_eq!(M::Ram.backing(true), Ok(Ram));
    }
}
