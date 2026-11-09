//! The configuration of a running urMQTT image (C1, ADR-215, ADR-216).
//!
//! The values come from the `urmqtt-cfg` blob the bootloader hands the
//! kernel as a module ([`load`]); until then, or when there is none, from
//! the documented defaults. Every limit used by the data path is read from
//! [`CONFIG`]; there are no magic numbers in logic crates. The kernel
//! itself is built once: the only build-time switch is [`DEV_KERNEL`].

#![cfg_attr(not(test), no_std)]
// The one place that needs `unsafe` is `store` (initialise-once storage in
// `.bss`, no allocator before the heap exists).
#![deny(unsafe_code)]

mod store;
pub use store::{CONFIG, ConfigHandle, LoadError, LoadInfo, info, load, load_defaults};
/// The newest configuration format this build reads (the kernel's build note, ADR-296).
pub use urmqtt_cfg::FORMAT_VERSION;
pub use urmqtt_cfg::blob::Hex;

/// How the console names the signer of a configuration: the first 8 bytes of
/// the domain-separated SHA-256 (`urmqtt_cfg::blob::fingerprint_of`) of its
/// public key (`urmqtt-config show` prints the same id).
pub fn signer_id(key: &[u8; 32]) -> [u8; 8] {
    use urmqtt_cfg::blob::fingerprint_of;
    let fp = fingerprint_of(key);
    let mut id = [0u8; 8];
    for (o, i) in id.iter_mut().zip(fp) {
        *o = i;
    }
    id
}

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
    Static {
        address: Ipv4Cidr,
        gateway: [u8; 4],
    },
    /// DHCP first; the static address and gateway when no lease arrives
    /// within `dhcp_timeout_s` or when the lease is lost.
    Auto {
        address: Ipv4Cidr,
        gateway: [u8; 4],
        dhcp_timeout_s: u32,
    },
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
    /// `network.mtu` (NOW-19, ADR-264): `None` takes the MTU from DHCP
    /// option 26, else 1500; a value (576..=9000) is used as it is, in every
    /// mode, and is the only source with a static address.
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
pub struct Tls {
    /// Server certificate chain (PEM); empty when none is configured.
    pub cert_pem: &'static [u8],
    /// Server private key (PEM); empty when none is configured.
    pub key_pem: &'static [u8],
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
    /// Ed25519 public key that verifies control messages (all zero when
    /// none is configured; then `service_ids` is empty).
    pub public_key: [u8; 32],
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
    /// `limits.publisher_backpressure` (NOW-13, ADR-269): pause a publisher
    /// whose QoS 0 message has one subscriber, and that one is full (true,
    /// "single", the default), or always read and drop (false, "off").
    pub publisher_backpressure: bool,
    /// The longest Session Expiry Interval granted, seconds, to 5.0 clients
    /// and 3.1.1 persistent sessions alike; `u32::MAX`: never (ADR-273).
    pub max_session_expiry_s: u32,
    /// The Session Expiry Interval of a 3.1.1 persistent session
    /// (clean_session 0), seconds; at most `max_session_expiry_s`.
    pub default_session_expiry_s: u32,
    /// The longest Message Expiry Interval a publisher may ask for, seconds;
    /// 0: no cap (ADR-273 rule 5).
    pub max_message_expiry_s: u32,
    /// Shared-subscription groups (`$share/{group}/{filter}`) one data core
    /// may own, 1..=65535; one more: SUBACK 0x97 (5.0) / 0x80 (3.1.1)
    /// (ADR-275).
    pub max_shared_groups: u32,
    /// Members one shared-subscription group may have, 1..=65535; one more:
    /// SUBACK 0x97 / 0x80 (ADR-275).
    pub max_shared_group_members: u32,
    /// Established TLS connections (MQTT and WebSocket) one source address
    /// may hold at once, all cores together; 0: no limit (NOW-14, ADR-280).
    pub max_connections_per_ip: u32,
    /// Password accounts the control channel may hold on the data disk
    /// (NOW-15, ADR-285); 0: the control channel refuses account commands.
    pub max_runtime_accounts: u32,
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

/// What the store tells the disk about space it no longer uses (S4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardMode {
    /// Use the device's discard (or write-zeroes with unmap) when it has one.
    Auto,
    /// Never.
    Off,
}

/// Whether the console drives a virtio-gpu display (`console.virtio_gpu`, ADR-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioGpuMode {
    /// Never (the default): the driver is not started.
    Off,
    /// When a virtio-gpu is found and the bootloader's framebuffer is missing
    /// or is RAM that nothing presents.
    Auto,
    /// Whenever a virtio-gpu is found.
    On,
}

impl VirtioGpuMode {
    /// The TOML word.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::On => "on",
        }
    }
}

/// The `[console]` section (ADR-256).
#[derive(Debug, Clone, Copy)]
pub struct Console {
    pub virtio_gpu: VirtioGpuMode,
}

/// Who confirms a trial boot after an A/B update (`update.confirm`, ADR-297).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateConfirm {
    /// The kernel itself, after `confirm_after_s` of health (the default).
    Auto,
    /// An operator, with a `boot-confirm` control message.
    Operator,
}

impl UpdateConfirm {
    /// The TOML word.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Operator => "operator",
        }
    }
}

/// The `[update]` section (NEXT-11, ADR-297): how a trial boot after an A/B
/// update is confirmed.
#[derive(Debug, Clone, Copy)]
pub struct Update {
    pub confirm: UpdateConfirm,
    /// Seconds of health (store open, a listener up) before an automatic
    /// confirmation.
    pub confirm_after_s: u32,
    /// A trial boot not confirmed this long resets; 0: never.
    pub trial_timeout_s: u32,
}

/// Whether an optional virtio driver runs (`[devices]`, ADR-257).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    /// Never (the default): the driver is not started.
    Off,
    /// When a device is found.
    Auto,
    /// When a device is found; its absence or failure is a warning.
    On,
}

impl DeviceMode {
    /// The TOML word.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::On => "on",
        }
    }

    const fn from_variant(v: u8) -> Self {
        match v {
            1 => Self::Auto,
            2 => Self::On,
            _ => Self::Off,
        }
    }
}

/// How the dispatcher learns of received frames
/// (`devices.virtio_net_interrupt`, ADR-270).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetInterrupt {
    /// The receive queue's MSI-X interrupt where the platform has one (the
    /// default), else polling.
    Auto,
    /// Always poll (ADR-224's 200 us while connections exist).
    Off,
}

impl NetInterrupt {
    /// The TOML word.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Off => "off",
        }
    }

    const fn from_variant(v: u8) -> Self {
        match v {
            1 => Self::Off,
            _ => Self::Auto,
        }
    }
}

/// DMA remapping (`devices.iommu`, ADR-305).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iommu {
    /// The IOMMU is left as the firmware set it (the default).
    Off,
    /// Used when present and covering the driven devices, else a warning.
    Auto,
    /// Refuse to boot without it.
    Require,
}

impl Iommu {
    /// The TOML word.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::Require => "require",
        }
    }

    const fn from_variant(v: u8) -> Self {
        match v {
            1 => Self::Auto,
            2 => Self::Require,
            _ => Self::Off,
        }
    }
}

/// The `[devices]` section (ADR-257): one mode per optional virtio driver,
/// in the order of `urmqtt_cfg::fields::DEVICE_KEYS`, and the NIC's receive
/// interrupt (ADR-270).
#[derive(Debug, Clone, Copy)]
pub struct Devices {
    modes: [DeviceMode; urmqtt_cfg::fields::DEVICE_KEYS.len()],
    /// `devices.virtio_net_interrupt`.
    pub virtio_net_interrupt: NetInterrupt,
    /// `devices.iommu`.
    pub iommu: Iommu,
}

impl Devices {
    pub const OFF: Self = Self {
        modes: [DeviceMode::Off; urmqtt_cfg::fields::DEVICE_KEYS.len()],
        virtio_net_interrupt: NetInterrupt::Auto,
        iommu: Iommu::Off,
    };

    /// The mode of `key` (`devices.virtio_console`, ...); `None` for a key
    /// that is not in the section.
    pub fn mode(&self, key: &str) -> Option<DeviceMode> {
        urmqtt_cfg::fields::DEVICE_KEYS
            .iter()
            .position(|(_, k, _)| *k == key)
            .and_then(|i| self.modes.get(i).copied())
    }

    /// Every key with its mode.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, DeviceMode)> + '_ {
        urmqtt_cfg::fields::DEVICE_KEYS
            .iter()
            .zip(self.modes.iter())
            .map(|((_, k, _), m)| (*k, *m))
    }

    /// From the blob's variants (each tag of `DEVICE_KEYS`).
    pub fn from_variants(get: impl Fn(u16) -> u8) -> Self {
        let mut d = Self::OFF;
        for (m, (t, _, _)) in d.modes.iter_mut().zip(urmqtt_cfg::fields::DEVICE_KEYS) {
            *m = DeviceMode::from_variant(get(*t));
        }
        d.virtio_net_interrupt =
            NetInterrupt::from_variant(get(urmqtt_cfg::fields::tag::DEV_NET_INTERRUPT));
        d.iommu = Iommu::from_variant(get(urmqtt_cfg::fields::tag::DEV_IOMMU));
        d
    }
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
    /// Release retired telemetry segments, the tail of truncated files and
    /// space a grow added (S4).
    pub discard: DiscardMode,
    /// Minutes between two in-disk database backups (S5); 0: none.
    pub backup_interval_min: u32,
    /// Restore the newest intact backup when the database fails its
    /// integrity check at boot (S5).
    pub auto_restore: bool,
    /// Hours between scrub passes (S6); 0: none.
    pub scrub_interval_h: u32,
    /// Megabytes per second a scrub pass may read (S6).
    pub scrub_io_budget_mb_s: u32,
    /// AES-256-XTS over the data partition (S7, ADR-240).
    pub encryption: bool,
    /// The 64-byte disk key, empty when `encryption` is off.
    pub disk_key: Secret,
    pub require_flush: bool,
    pub require_data_disk: bool,
    pub refuse_on_corruption: bool,
}

/// Key material that never prints: `Debug` shows only its length.
#[derive(Clone, Copy)]
pub struct Secret(pub &'static [u8]);

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{} bytes, not shown>", self.0.len())
    }
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

/// Trust anchors by role (PEM files).
#[derive(Debug, Clone, Copy)]
pub struct Trust {
    /// Device and service rights.
    pub operational: &'static [&'static [u8]],
    /// `provision/{id}/#` only.
    pub bootstrap: &'static [&'static [u8]],
}

/// A network, as the plaintext allow-list and `ip_identities` hold it.
pub use urmqtt_cfg::net::Cidr;

/// How a plaintext client proves who it is (P1, ADR-229).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainAuth {
    /// An MQTT user name and password; the user name is the identity.
    Password,
    /// No login: every client is `anonymous_identity`.
    Anonymous,
    /// The client's address decides (`ip_identities`).
    Ip,
}

/// One plaintext account: the id (the MQTT user name, also the device id of
/// the ACL) and the stored password hash (`urmqtt_cfg::passwd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainUser {
    pub id: &'static str,
    pub hash: &'static str,
}

/// A network and the identity every client in it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainNetwork {
    pub net: Cidr,
    pub id: &'static str,
}

/// Plaintext MQTT for trusted networks (P1, ADR-229). Off unless the image's
/// configuration says so; the other fields mean nothing while `enabled` is false.
#[derive(Debug, Clone, Copy)]
pub struct Plaintext {
    pub enabled: bool,
    pub port: u16,
    /// Networks that may connect; empty and `allow_from_anywhere` false only
    /// while disabled (a configuration check refuses it otherwise).
    pub allow_from: &'static [Cidr],
    pub allow_from_anywhere: bool,
    pub auth: PlainAuth,
    pub anonymous_identity: &'static str,
    pub users: &'static [PlainUser],
    pub ip_identities: &'static [PlainNetwork],
    /// All plaintext connections together, over all cores.
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub max_packet_size: u32,
    pub publish_rate_per_device: Rate,
    pub max_failed_auths_per_ip: u32,
    pub lockout_s: u32,
    pub acl_publish: &'static [&'static str],
    pub acl_subscribe: &'static [&'static str],
    pub retain: bool,
}

/// How a WebSocket client proves who it is (ADR-272).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsAuth {
    /// A client certificate, as on the TLS port.
    Mtls,
    /// No client certificate; an MQTT user name and password from
    /// `websocket.users`, with the section's own ACL.
    Password,
}

/// MQTT over secure WebSocket (NEXT-5, ADR-272). Off unless the image's
/// configuration says so; the other fields mean nothing while `enabled` is
/// false.
#[derive(Debug, Clone, Copy)]
pub struct Websocket {
    pub enabled: bool,
    pub port: u16,
    /// The request target, e.g. `/mqtt`.
    pub path: &'static str,
    pub auth: WsAuth,
    /// Allowed `Origin` values; empty only with `auth = mtls` (any origin).
    pub origins: &'static [&'static str],
    /// `auth = password`: the accounts.
    pub users: &'static [PlainUser],
    pub upgrade_timeout_s: u32,
    /// All WebSocket connections together, over all cores.
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    /// `auth = password`: the packet limit, publish rate, lock-out and ACL of
    /// a session.
    pub max_packet_size: u32,
    pub publish_rate_per_device: Rate,
    pub max_failed_auths_per_ip: u32,
    pub lockout_s: u32,
    pub acl_publish: &'static [&'static str],
    pub acl_subscribe: &'static [&'static str],
    pub retain: bool,
}

/// The Prometheus endpoint (NEXT-9, ADR-290). Off unless the image's
/// configuration says so; the other fields mean nothing while `enabled` is
/// false.
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub enabled: bool,
    pub port: u16,
    /// Networks that may scrape; never empty while enabled (the check refuses
    /// it), and there is no "anywhere".
    pub allow_from: &'static [Cidr],
    /// Connections held at once on one data core.
    pub max_connections: u32,
    /// ... from one source address on one data core.
    pub max_connections_per_ip: u32,
    /// Seconds from the TCP connection to the end of the answer.
    pub request_timeout_s: u32,
}

/// MQTT 5.0 (NEXT-3, ADR-273 rule 21). On by default.
#[derive(Debug, Clone, Copy)]
pub struct Mqtt5 {
    /// Accept CONNECT packets with protocol level 5 on every listener; false: CONNACK 0x84.
    pub enabled: bool,
    /// The announced Receive Maximum (1..=65535): QoS 2 publications a 5.0
    /// client may have awaiting PUBREL; one more is DISCONNECT 0x93.
    pub receive_maximum: u32,
    /// The announced Topic Alias Maximum (0..=65535, client to server only);
    /// 0 disables aliases.
    pub topic_alias_maximum: u32,
    /// User Properties per property block (0..=1024); more: refused (0x83).
    pub max_user_properties: u32,
    /// 0: the client's keep alive; otherwise the most a 5.0 client gets
    /// (Server Keep Alive in CONNACK). 0..=65535.
    pub max_keep_alive_s: u32,
    /// Shared subscriptions (`$share/{group}/{filter}`, rule 16), also for
    /// 3.1.1 clients; false: Shared Subscription Available 0 and SUBACK 0x9E
    /// (3.1.1: 0x80) for a `$share/` filter.
    pub shared_subscriptions: bool,
    /// Subscription Identifiers (rule 17); false: Subscription Identifier
    /// Available 0 and SUBACK 0xA1 for a SUBSCRIBE that carries one.
    pub subscription_identifiers: bool,
}

/// The complete configuration.
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
    pub trust: Trust,
    pub plaintext: Plaintext,
    pub websocket: Websocket,
    pub metrics: Metrics,
    pub mqtt5: Mqtt5,
    pub console: Console,
    pub devices: Devices,
    pub update: Update,
}

impl BuildConfig {
    /// Development options are in effect: a dev kernel running an
    /// `env = "dev"` configuration.
    pub fn dev(&self) -> bool {
        DEV_KERNEL && self.env == "dev"
    }

    /// What is missing for a production run (`None`: nothing). The broker
    /// refuses to serve without a server certificate, its key and at least
    /// one operational CA.
    pub fn missing_to_serve(&self) -> Option<&'static str> {
        // The TLS listener is off (plaintext only, ADR-233): nothing of the TLS side is needed.
        if self.network.mqtt_tls_port == 0 {
            return None;
        }
        if self.tls.cert_pem.is_empty() || self.tls.key_pem.is_empty() {
            Some("no server certificate and key (tls.cert, tls.key)")
        } else if self.trust.operational.is_empty() {
            Some("no operational CA (trust.operational)")
        } else {
            None
        }
    }
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

/// The Miri negative control (ADR-262): one deliberate use-after-free that
/// `scripts/miri.sh --negative-control` expects Miri to REPORT, so a Miri job
/// proves it still detects undefined behaviour with the runner, flags and
/// toolchain it ran the real tests with. Compiled only under Miri and
/// `#[ignore]`d, so neither `cargo test` nor the normal Miri run executes it.
#[cfg(all(test, miri))]
#[allow(unsafe_code)]
mod miri_negative_control {
    #[test]
    #[ignore = "deliberate UB: run only by scripts/miri.sh --negative-control, which expects it to FAIL"]
    fn deliberate_use_after_free_must_be_reported() {
        let b = std::boxed::Box::new(0x5au8);
        let p: *const u8 = &raw const *b;
        drop(b);
        // SAFETY: none, on purpose: `p` dangles (its box was freed above). Miri must
        // stop here with "Undefined Behavior"; the script fails if it does not.
        let v = unsafe { p.read() };
        assert_eq!(v, 0x5a);
    }
}
