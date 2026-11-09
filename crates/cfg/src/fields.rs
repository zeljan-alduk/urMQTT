//! The field table: the single list of everything a configuration blob can
//! say, with its type, default, range, help text and whether it is allowed
//! outside the dev environment. The kernel's decoder, the validator, the
//! packer, the JSON schema for the web form and the tests all read this
//! table; there is no second copy of a default or a range.
//!
//! Tags are part of the format (ADR-215): a tag is never reused or renumbered;
//! a new field gets a new tag and, if old kernels must refuse it, a new
//! format version.

/// How a field is encoded and what it may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One byte, 0 or 1.
    Bool(bool),
    /// Little-endian integer of `bytes` (1, 2, 4 or 8) bytes in `min..=max`.
    UInt {
        bytes: u8,
        min: u64,
        max: u64,
        default: u64,
    },
    /// One byte, an index into `variants`.
    Enum {
        variants: &'static [&'static str],
        default: u8,
    },
    /// UTF-8 text of at most `max` bytes.
    Str { max: u16, default: &'static str },
    /// A list of UTF-8 strings, each framed by a `u16` length.
    Strs {
        max_items: u16,
        max_len: u16,
        default: &'static [&'static str],
    },
    /// Raw bytes (a PEM file) of at most `max` bytes. No default: absent.
    Bin { max: u32 },
    /// A list of byte strings (PEM files), each framed by a `u32` length.
    BinList { max_items: u8, max: u32 },
    /// IPv4 address, 4 bytes. No default: absent.
    Ipv4,
    /// IPv4 address and prefix length, 5 bytes. No default: absent.
    Cidr,
    /// `tokens` per `per_ms` milliseconds, two `u32`.
    Rate { tokens: u32, per_ms: u32 },
    /// One optional IPv4 socket address (address, port `u16`), 6 bytes.
    Addr,
    /// A list of IPv4 socket addresses, 6 bytes each, default empty.
    Addrs { max_items: u8 },
    /// An Ed25519 public key, 32 bytes. No default: absent.
    Key32,
}

/// What the entries of a string-list field are (P1): plain text, or a
/// grammar the semantic check and the builder know. Only a hint for them; the
/// blob stores every list the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    /// Free text (topic filters, identities, serials, ...).
    Text,
    /// An IPv4 network, `a.b.c.d/len` ([`crate::net::Cidr`]).
    Cidr,
    /// A plaintext account, `<id> <password hash>` ([`crate::plain::parse_user`]).
    User,
    /// A network and the identity it gets, `<a.b.c.d/len> <id>`
    /// ([`crate::plain::parse_ip_identity`]).
    IpIdentity,
}

impl Item {
    /// For the JSON schema; `None` for plain text.
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::Cidr => Some("cidr"),
            Self::User => Some("user"),
            Self::IpIdentity => Some("ip_identity"),
        }
    }
}

/// One configuration key.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// Stable identifier inside the blob.
    pub tag: u16,
    /// TOML key path, `section.name` (`env` has no section).
    pub key: &'static str,
    pub kind: Kind,
    /// One sentence for the form and `urmqtt-config schema`.
    pub help: &'static str,
    /// A value other than the default is allowed only in the dev
    /// environment on a dev kernel (ADR-215).
    pub dev_only: bool,
    /// Written into the blob. `false`: used by the packer only (checks).
    pub stored: bool,
    /// Computed by the packer from other inputs (not set by the user).
    pub derived: bool,
    /// The first blob format version that has this field (ADR-229). A blob
    /// of an older version cannot hold it (the decoder refuses the record), so
    /// a version 1 blob keeps meaning exactly what it meant.
    pub since: u16,
    /// What the entries of a `Strs` field are.
    pub item: Item,
}

const fn f(tag: u16, key: &'static str, kind: Kind, help: &'static str) -> Field {
    Field {
        tag,
        key,
        kind,
        help,
        dev_only: false,
        stored: true,
        derived: false,
        since: 1,
        item: Item::Text,
    }
}

/// The field first appears in blob format `v`.
const fn since(mut x: Field, v: u16) -> Field {
    x.since = v;
    x
}

/// The entries of a string-list field follow the grammar `i`.
const fn items(mut x: Field, i: Item) -> Field {
    x.item = i;
    x
}

const fn dev(mut x: Field) -> Field {
    x.dev_only = true;
    x
}

const fn derived(mut x: Field) -> Field {
    x.derived = true;
    x
}

const fn pack_only(mut x: Field) -> Field {
    x.stored = false;
    x
}

const fn uint(bytes: u8, min: u64, max: u64, default: u64) -> Kind {
    Kind::UInt {
        bytes,
        min,
        max,
        default,
    }
}

const U32: u64 = u32::MAX as u64;

/// Largest value of `limits.max_packet_size` (MQTT remaining length).
pub const MQTT_MAX_PACKET_SIZE: u64 = 268_435_455;
/// Smallest `limits.max_packet_size`.
pub const MIN_PACKET_SIZE: u64 = 64;
/// Longest topic (a `u16` length prefix).
pub const MQTT_MAX_TOPIC_LEN: u64 = 65_535;
/// `network.mtu` (NOW-19, ADR-264): 0 (the default) takes the MTU from DHCP
/// option 26, else 1500; otherwise a value in `MIN_MTU..=MAX_MTU`.
pub const MIN_MTU: u64 = 576;
pub const MAX_MTU: u64 = 9000;
/// Most NTP servers a round asks.
pub const MAX_TIME_SERVERS: usize = 4;

/// Tags, by name, for the code that reads them.
pub mod tag {
    pub const ENV: u16 = 1;
    pub const NET_MODE: u16 = 10;
    pub const NET_ADDRESS: u16 = 11;
    pub const NET_GATEWAY: u16 = 12;
    pub const NET_DHCP_TIMEOUT: u16 = 13;
    pub const NET_TLS_PORT: u16 = 14;
    pub const NET_PLAIN_PORT: u16 = 15;
    pub const TLS_CERT: u16 = 20;
    pub const TLS_KEY: u16 = 21;
    pub const TLS_IDENTITY: u16 = 22;
    pub const TLS_RESUMPTION: u16 = 23;
    pub const TLS_REVOKED: u16 = 24;
    pub const TLS_MIN_CERT_DAYS: u16 = 25;
    pub const TLS_CERT_NOT_AFTER: u16 = 26;
    pub const TRUST_OPERATIONAL: u16 = 30;
    pub const TRUST_BOOTSTRAP: u16 = 31;
    pub const TRUST_MIN_ANCHOR_DAYS: u16 = 32;
    pub const LIM_CONNECTIONS: u16 = 40;
    pub const LIM_PACKET: u16 = 41;
    pub const LIM_TOPIC_LEN: u16 = 42;
    pub const LIM_TOPIC_LEVELS: u16 = 43;
    pub const LIM_SUBSCRIPTIONS: u16 = 44;
    pub const LIM_INFLIGHT: u16 = 45;
    pub const LIM_QUEUED: u16 = 46;
    pub const LIM_RETAINED_PER_DEVICE: u16 = 47;
    pub const LIM_RETAINED_BYTES: u16 = 48;
    pub const LIM_PUBLISH_RATE: u16 = 49;
    pub const LIM_HANDSHAKES_PER_SEC: u16 = 50;
    pub const LIM_HANDSHAKES_CORE: u16 = 51;
    pub const LIM_HANDSHAKES_IP: u16 = 52;
    // Publisher back-pressure (NOW-13, ADR-269): format version 8.
    pub const LIM_PUBLISHER_BACKPRESSURE: u16 = 53;
    pub const ACL_DEVICE_PUBLISH: u16 = 60;
    pub const ACL_DEVICE_SUBSCRIBE: u16 = 61;
    pub const ACL_SERVICE_IDS: u16 = 62;
    pub const ACL_SERVICE_PUBLISH: u16 = 63;
    pub const ACL_SERVICE_SUBSCRIBE: u16 = 64;
    pub const ACL_OPERATOR_IDS: u16 = 65;
    pub const ST_MODE: u16 = 70;
    pub const ST_RAM_PERCENT: u16 = 71;
    pub const ST_DIAGNOSTIC: u16 = 72;
    pub const ST_SQLITE_HEAP: u16 = 73;
    pub const ST_TELEMETRY: u16 = 74;
    pub const ST_RETENTION: u16 = 75;
    pub const ST_GROW_RATIO: u16 = 76;
    pub const ST_DISCARD: u16 = 77;
    pub const ST_BACKUP_INTERVAL: u16 = 78;
    pub const ST_AUTO_RESTORE: u16 = 79;
    pub const ST_SCRUB_INTERVAL: u16 = 80;
    pub const ST_SCRUB_BUDGET: u16 = 81;
    pub const ST_REQUIRE_FLUSH: u16 = 82;
    pub const ST_REQUIRE_DATA_DISK: u16 = 83;
    pub const ST_REFUSE_ON_CORRUPTION: u16 = 84;
    pub const ST_ENCRYPTION: u16 = 85;
    pub const ST_DISK_KEY: u16 = 86;
    pub const OBS_LOG_LEVEL: u16 = 90;
    pub const OBS_SYSLOG: u16 = 91;
    pub const OBS_METRICS: u16 = 92;
    pub const WD_HANDLER: u16 = 100;
    pub const WD_HANDSHAKE: u16 = 101;
    pub const WD_ACTION: u16 = 102;
    pub const MEM_HEAP: u16 = 110;
    pub const MEM_MIN_FREE: u16 = 111;
    pub const ENTROPY_JITTER: u16 = 120;
    pub const CPU_DISABLE: u16 = 130;
    pub const CPU_DISPATCHER_SERVES: u16 = 131;
    pub const TIME_SERVERS: u16 = 140;
    pub const TIME_INTERVAL: u16 = 141;
    pub const TIME_MAX_STEP: u16 = 142;
    pub const REG_ALLOWLIST: u16 = 150;
    pub const CTL_PUBLIC_KEY: u16 = 160;
    pub const CTL_SERVICE_IDS: u16 = 161;
    pub const CTL_ALLOW_UNREVOKE: u16 = 162;
    pub const CTL_MAX_AGE: u16 = 163;
    // Plaintext MQTT for trusted networks (P1, ADR-229): format version 2.
    pub const PL_ENABLED: u16 = 170;
    pub const PL_PORT: u16 = 171;
    pub const PL_ALLOW_FROM: u16 = 172;
    pub const PL_ANYWHERE: u16 = 173;
    pub const PL_AUTH: u16 = 174;
    pub const PL_ANON_ID: u16 = 175;
    pub const PL_USERS: u16 = 176;
    pub const PL_IP_IDENTITIES: u16 = 177;
    pub const PL_MAX_CONNS: u16 = 178;
    pub const PL_MAX_PER_IP: u16 = 179;
    pub const PL_MAX_PACKET: u16 = 180;
    pub const PL_PUBLISH_RATE: u16 = 181;
    pub const PL_MAX_FAILS: u16 = 182;
    pub const PL_LOCKOUT: u16 = 183;
    pub const PL_ACL_PUBLISH: u16 = 184;
    pub const PL_ACL_SUBSCRIBE: u16 = 185;
    pub const PL_RETAIN: u16 = 186;
    // The console (ADR-256): format version 5.
    pub const CON_VIRTIO_GPU: u16 = 190;
    // The optional virtio drivers (ADR-257): format version 6.
    pub const DEV_VIRTIO_CONSOLE: u16 = 191;
    pub const DEV_VIRTIO_BALLOON: u16 = 192;
    pub const DEV_VIRTIO_INPUT: u16 = 193;
    pub const DEV_VIRTIO_VSOCK: u16 = 194;
    // The link MTU (NOW-19, ADR-264): format version 7.
    pub const NET_MTU: u16 = 195;
    // The NIC's receive interrupt (NOW-13, ADR-270): format version 11
    // (10 is unused, 12 is MQTT 5.0's).
    pub const DEV_NET_INTERRUPT: u16 = 211;
    // MQTT over WebSocket (NEXT-5, ADR-272): format version 9.
    pub const WS_ENABLED: u16 = 230;
    pub const WS_PORT: u16 = 231;
    pub const WS_PATH: u16 = 232;
    pub const WS_AUTH: u16 = 233;
    pub const WS_ORIGINS: u16 = 234;
    pub const WS_USERS: u16 = 235;
    pub const WS_UPGRADE_TIMEOUT: u16 = 236;
    pub const WS_MAX_CONNS: u16 = 237;
    pub const WS_MAX_PER_IP: u16 = 238;
    pub const WS_MAX_PACKET: u16 = 239;
    pub const WS_PUBLISH_RATE: u16 = 240;
    pub const WS_MAX_FAILS: u16 = 241;
    pub const WS_LOCKOUT: u16 = 242;
    pub const WS_ACL_PUBLISH: u16 = 243;
    pub const WS_ACL_SUBSCRIBE: u16 = 244;
    pub const WS_RETAIN: u16 = 245;
    // MQTT 5.0 (NEXT-3, ADR-273 rule 21): format version 12. The expiry
    // limits belong to `[limits]` but came with 5.0 (tags are ascending, so
    // they follow the older fields here).
    pub const LIM_MAX_SESSION_EXPIRY: u16 = 250;
    pub const LIM_DEFAULT_SESSION_EXPIRY: u16 = 251;
    pub const LIM_MAX_MESSAGE_EXPIRY: u16 = 252;
    pub const MQTT5_ENABLED: u16 = 253;
    pub const MQTT5_RECEIVE_MAXIMUM: u16 = 254;
    pub const MQTT5_TOPIC_ALIAS_MAXIMUM: u16 = 255;
    pub const MQTT5_MAX_USER_PROPERTIES: u16 = 256;
    pub const MQTT5_MAX_KEEP_ALIVE: u16 = 257;
    pub const MQTT5_SHARED_SUBSCRIPTIONS: u16 = 258;
    pub const MQTT5_SUBSCRIPTION_IDENTIFIERS: u16 = 259;
    // MQTT 5.0 part 3 (ADR-275): format version 13.
    pub const LIM_MAX_SHARED_GROUPS: u16 = 260;
    pub const LIM_MAX_SHARED_GROUP_MEMBERS: u16 = 261;
    // NOW-14 (ADR-280): format version 14.
    pub const LIM_MAX_CONNECTIONS_PER_IP: u16 = 270;
    // Run-time password accounts (NOW-15, ADR-285): format version 15.
    pub const LIM_MAX_RUNTIME_ACCOUNTS: u16 = 275;
    // The Prometheus endpoint (NEXT-9, ADR-290): format version 16. Tags 262 to
    // 299 are left to the other items of the release.
    pub const METRICS_ENABLED: u16 = 300;
    pub const METRICS_PORT: u16 = 301;
    pub const METRICS_ALLOW_FROM: u16 = 302;
    pub const METRICS_MAX_CONNS: u16 = 303;
    pub const METRICS_MAX_PER_IP: u16 = 304;
    pub const METRICS_REQUEST_TIMEOUT: u16 = 305;
    // A/B updates (NEXT-11, ADR-297): format version 17.
    pub const UPD_CONFIRM: u16 = 340;
    pub const UPD_CONFIRM_AFTER: u16 = 341;
    pub const UPD_TRIAL_TIMEOUT: u16 = 342;
    // DMA remapping (LATER-5, H4b, ADR-305): format version 18. The tag is
    // apart from the others of v0.6.0 so that items built in parallel do not
    // collide.
    pub const DEV_IOMMU: u16 = 318;
}

use tag as t;

pub const NETWORK_MODES: &[&str] = &["dhcp", "static", "auto"];
pub const IDENTITY_FIELDS: &[&str] = &["cn", "san_uri"];
pub const STORAGE_MODES: &[&str] = &["disk", "auto", "ram"];
pub const DISCARD_MODES: &[&str] = &["auto", "off"];
pub const ENCRYPTION_MODES: &[&str] = &["off", "aes-256-xts"];
pub const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
pub const ENTROPY_FALLBACKS: &[&str] = &["jitter", "none"];
pub const REGISTRY_MODES: &[&str] = &["open", "allowlist"];
/// `limits.publisher_backpressure` (ADR-269); the first is the default.
pub const BACKPRESSURE_MODES: &[&str] = &["single", "off"];
pub const WATCHDOG_ACTIONS: &[&str] = &["log", "drop", "reset"];
/// Who confirms a trial boot after an A/B update (`update.confirm`, ADR-297).
pub const UPDATE_CONFIRM_MODES: &[&str] = &["auto", "operator"];
/// How a plaintext client proves who it is (P1).
pub const PLAINTEXT_AUTH: &[&str] = &["password", "anonymous", "ip"];
/// How a WebSocket client proves who it is (ADR-272).
pub const WEBSOCKET_AUTH: &[&str] = &["mtls", "password"];
/// Most entries of `websocket.origins`.
pub const MAX_WS_ORIGINS: usize = 16;
/// Longest `websocket.origins` entry.
pub const MAX_WS_ORIGIN_LEN: usize = 255;
/// Longest `websocket.path`.
pub const MAX_WS_PATH_LEN: usize = 64;
/// The upgrade deadline's range, seconds (at most the handshake timeout).
pub const MAX_WS_UPGRADE_TIMEOUT_S: u64 = 10;
/// Most User Properties in one MQTT 5.0 property block (`mqtt5.max_user_properties`).
pub const MAX_MQTT5_USER_PROPERTIES: u64 = 1024;
/// The default Session Expiry Interval cap, seconds (30 days, ADR-273 rule 4).
pub const DEFAULT_SESSION_EXPIRY_S: u64 = 2_592_000;
/// Whether the console drives a virtio-gpu device (ADR-256).
pub const VIRTIO_GPU_MODES: &[&str] = &["off", "auto", "on"];
/// Whether an optional virtio driver runs (`[devices]`, ADR-257).
pub const DEVICE_MODES: &[&str] = &["off", "auto", "on"];
/// How the dispatcher learns of received frames (`devices.virtio_net_interrupt`,
/// ADR-270): the receive queue's MSI-X interrupt where the platform has one,
/// or polling.
pub const NET_INTERRUPT_MODES: &[&str] = &["auto", "off"];
/// DMA remapping (`devices.iommu`, ADR-305); the first is the default.
pub const IOMMU_MODES: &[&str] = &["off", "auto", "require"];
/// The `[devices]` keys, one per optional virtio driver (ADR-257): tag, key
/// and the driver's feature (as `urmqtt_virtio::registry::KINDS` names it; a
/// test there keeps the two equal).
pub const DEVICE_KEYS: &[(u16, &str, &str)] = &[
    (tag::DEV_VIRTIO_CONSOLE, "devices.virtio_console", "console"),
    (tag::DEV_VIRTIO_BALLOON, "devices.virtio_balloon", "balloon"),
    (tag::DEV_VIRTIO_INPUT, "devices.virtio_input", "input"),
    (tag::DEV_VIRTIO_VSOCK, "devices.virtio_vsock", "vsock"),
];

/// Limits of the plaintext lists (they size arrays in the kernel).
pub const MAX_PLAIN_NETWORKS: usize = 64;
pub const MAX_PLAIN_USERS: usize = 256;
pub const MAX_PLAIN_IP_IDENTITIES: usize = 64;
pub const MAX_PLAIN_ACL: usize = 16;
/// Most entries of `metrics.allow_from` (a scrape comes from a few hosts).
pub const MAX_METRICS_NETWORKS: usize = 16;
/// The request deadline's range of the metrics endpoint, seconds.
pub const MAX_METRICS_TIMEOUT_S: u64 = 30;
/// Longest identity (a user name, the anonymous identity, an `ip_identities` id).
pub const MAX_IDENTITY_LEN: usize = 64;

/// Every field, in ascending tag order.
pub static FIELDS: &[Field] = &[
    f(
        t::ENV,
        "env",
        Kind::Str {
            max: 32,
            default: "prod",
        },
        "Environment name ([a-z0-9-]+), used as the domain of signed control messages. \"dev\" enables development options and is refused by a release kernel.",
    ),
    // network
    f(
        t::NET_MODE,
        "network.mode",
        Kind::Enum {
            variants: NETWORK_MODES,
            default: 0,
        },
        "dhcp: lease from DHCP. static: fixed address. auto: DHCP first, the static address when no lease arrives.",
    ),
    f(
        t::NET_ADDRESS,
        "network.address",
        Kind::Cidr,
        "IPv4 address with prefix length (a.b.c.d/len); required for static and auto.",
    ),
    f(
        t::NET_GATEWAY,
        "network.gateway",
        Kind::Ipv4,
        "IPv4 default gateway; required for static and auto.",
    ),
    f(
        t::NET_DHCP_TIMEOUT,
        "network.dhcp_timeout_s",
        uint(4, 3, 120, 15),
        "Seconds to wait for a DHCP lease before using the static address (auto only).",
    ),
    f(
        t::NET_TLS_PORT,
        "network.mqtt_tls_port",
        uint(2, 0, 65_535, 8883),
        "TCP port of MQTT over TLS; 0 turns the TLS listener off (only with plaintext.enabled = true: then there is no mutual TLS, so no operator, service or control rights, no $SYS and no certificate is needed).",
    ),
    dev(f(
        t::NET_PLAIN_PORT,
        "network.mqtt_plain_port",
        uint(2, 0, 65_535, 0),
        "TCP port of plaintext MQTT; 0 disables it. Development only.",
    )),
    // tls
    f(
        t::TLS_CERT,
        "tls.cert",
        Kind::Bin { max: 65_536 },
        "Server certificate chain (PEM). Required to serve in production.",
    ),
    f(
        t::TLS_KEY,
        "tls.key",
        Kind::Bin { max: 16_384 },
        "Server private key (unencrypted PEM). Required to serve in production.",
    ),
    f(
        t::TLS_IDENTITY,
        "tls.identity_field",
        Kind::Enum {
            variants: IDENTITY_FIELDS,
            default: 0,
        },
        "Client certificate field that becomes the device id: cn or san_uri.",
    ),
    f(
        t::TLS_RESUMPTION,
        "tls.resumption",
        Kind::Bool(true),
        "Allow TLS 1.3 session resumption (tickets).",
    ),
    f(
        t::TLS_REVOKED,
        "tls.revoked_serials",
        Kind::Strs {
            max_items: 1024,
            max_len: 40,
            default: &[],
        },
        "Revoked client certificate serial numbers (hex), one per entry.",
    ),
    f(
        t::TLS_MIN_CERT_DAYS,
        "tls.min_server_cert_days",
        uint(4, 1, U32, 60),
        "Warnings start this many days before the server certificate expires; the packer refuses a certificate closer to expiry.",
    ),
    derived(f(
        t::TLS_CERT_NOT_AFTER,
        "tls.server_cert_not_after",
        uint(8, 0, 253_402_300_799, 0),
        "Server certificate notAfter, Unix seconds (computed by the packer; X.509 times end in the year 9999).",
    )),
    // trust
    f(
        t::TRUST_OPERATIONAL,
        "trust.operational",
        Kind::BinList {
            max_items: 8,
            max: 65_536,
        },
        "CA certificates (PEM) that grant device and service rights. At least one is required to serve.",
    ),
    f(
        t::TRUST_BOOTSTRAP,
        "trust.bootstrap",
        Kind::BinList {
            max_items: 8,
            max: 65_536,
        },
        "CA certificates (PEM) that grant provision/{id}/# only.",
    ),
    pack_only(f(
        t::TRUST_MIN_ANCHOR_DAYS,
        "trust.min_anchor_days",
        uint(4, 1, U32, 365),
        "The packer refuses a CA that expires sooner than this many days.",
    )),
    // limits
    f(
        t::LIM_CONNECTIONS,
        "limits.max_connections_per_core",
        uint(4, 1, U32, 2_000_000),
        "Connections one data core accepts.",
    ),
    f(
        t::LIM_PACKET,
        "limits.max_packet_size",
        uint(4, MIN_PACKET_SIZE, MQTT_MAX_PACKET_SIZE, 4096),
        "Largest MQTT packet in bytes.",
    ),
    f(
        t::LIM_TOPIC_LEN,
        "limits.max_topic_len",
        uint(4, 1, MQTT_MAX_TOPIC_LEN, 256),
        "Longest topic name in bytes; smaller than max_packet_size.",
    ),
    f(
        t::LIM_TOPIC_LEVELS,
        "limits.max_topic_levels",
        uint(4, 1, U32, 16),
        "Most levels in a topic.",
    ),
    f(
        t::LIM_SUBSCRIPTIONS,
        "limits.max_subscriptions_per_session",
        uint(4, 1, U32, 8),
        "Subscriptions one session may hold.",
    ),
    f(
        t::LIM_INFLIGHT,
        "limits.max_inflight_qos1",
        uint(4, 1, U32, 16),
        "QoS 1 messages in flight per session.",
    ),
    f(
        t::LIM_QUEUED,
        "limits.max_queued_per_offline_session",
        uint(4, 0, U32, 64),
        "Messages queued for an offline persistent session.",
    ),
    f(
        t::LIM_RETAINED_PER_DEVICE,
        "limits.max_retained_per_device",
        uint(4, 0, U32, 32),
        "Retained messages one identity may hold; more are delivered but not retained.",
    ),
    f(
        t::LIM_RETAINED_BYTES,
        "limits.max_retained_bytes",
        uint(8, 1, 134_217_728, 1_048_576),
        "Bytes of retained topics and payloads per data core; at most an eighth of memory.kernel_heap_mb (so never more than 128 MiB).",
    ),
    f(
        t::LIM_PUBLISH_RATE,
        "limits.publish_rate_per_device",
        Kind::Rate {
            tokens: 10,
            per_ms: 1000,
        },
        "Publish rate per device as \"N/s\", \"N/m\" or \"N/h\".",
    ),
    f(
        t::LIM_HANDSHAKES_PER_SEC,
        "limits.handshakes_per_core_per_sec",
        uint(4, 1, U32, 2000),
        "TLS handshakes one core starts per second.",
    ),
    f(
        t::LIM_HANDSHAKES_CORE,
        "limits.max_handshakes_in_flight_per_core",
        uint(4, 1, U32, 256),
        "TLS handshakes a core runs at once; more are refused.",
    ),
    f(
        t::LIM_HANDSHAKES_IP,
        "limits.max_handshakes_in_flight_per_ip",
        uint(4, 1, U32, 32),
        "Of those, from one source address.",
    ),
    // limits, continued (NOW-13, ADR-269)
    since(
        f(
            t::LIM_PUBLISHER_BACKPRESSURE,
            "limits.publisher_backpressure",
            Kind::Enum {
                variants: BACKPRESSURE_MODES,
                default: 0,
            },
            "What happens when a QoS 0 message has a single subscriber and that subscriber reads slower than it is published. single (the default): the broker stops reading the publisher until the subscriber has caught up (its TCP window closes, at most 0.5 s at a time), as Mosquitto does; with two or more subscribers it still drops for the slow one. off: the publisher is always read and the slow subscriber's messages are dropped (counted in $SYS/broker/messages/dropped/slow_subscriber). Format 8.",
        ),
        8,
    ),
    // acl
    f(
        t::ACL_DEVICE_PUBLISH,
        "acl.device_publish",
        Kind::Strs {
            max_items: 64,
            max_len: 512,
            default: &["devices/{id}/#"],
        },
        "Topic filters a device may publish to; {id} is the device id.",
    ),
    f(
        t::ACL_DEVICE_SUBSCRIBE,
        "acl.device_subscribe",
        Kind::Strs {
            max_items: 64,
            max_len: 512,
            default: &["devices/{id}/cmd/#"],
        },
        "Topic filters a device may subscribe to.",
    ),
    f(
        t::ACL_SERVICE_IDS,
        "acl.service_ids",
        Kind::Strs {
            max_items: 64,
            max_len: 128,
            default: &["backend"],
        },
        "Backend identities (exact id or prefix*) with wider rights.",
    ),
    f(
        t::ACL_SERVICE_PUBLISH,
        "acl.service_publish",
        Kind::Strs {
            max_items: 64,
            max_len: 512,
            default: &["devices/+/cmd/#", "fleet/#"],
        },
        "Topic filters a service may publish to.",
    ),
    f(
        t::ACL_SERVICE_SUBSCRIBE,
        "acl.service_subscribe",
        Kind::Strs {
            max_items: 64,
            max_len: 512,
            default: &["devices/#", "fleet/#"],
        },
        "Topic filters a service may subscribe to.",
    ),
    f(
        t::ACL_OPERATOR_IDS,
        "acl.operator_ids",
        Kind::Strs {
            max_items: 32,
            max_len: 128,
            default: &["operator"],
        },
        "Identities (exact) that read $SYS/ and use the console.",
    ),
    // storage
    f(
        t::ST_MODE,
        "storage.mode",
        Kind::Enum {
            variants: STORAGE_MODES,
            default: 1,
        },
        "disk: the boot disk's data partition. auto: the disk, but the ISO's live entry runs from RAM. ram: always RAM (ephemeral).",
    ),
    f(
        t::ST_RAM_PERCENT,
        "storage.ram_percent",
        uint(4, 2, 50, 10),
        "Share of RAM for the in-memory data store (live and ram modes), percent.",
    ),
    f(
        t::ST_DIAGNOSTIC,
        "storage.diagnostic",
        Kind::Bool(false),
        "The ISO's Diagnostic entry may run (hardware detection, benchmarks).",
    ),
    f(
        t::ST_SQLITE_HEAP,
        "storage.sqlite_heap_mb",
        uint(4, 1, 4096, 8),
        "SQLite heap in MiB.",
    ),
    f(
        t::ST_TELEMETRY,
        "storage.telemetry_topics",
        Kind::Strs {
            max_items: 64,
            max_len: 512,
            default: &["devices/+/telemetry/#"],
        },
        "Topic filters whose messages are kept in the telemetry ring.",
    ),
    f(
        t::ST_RETENTION,
        "storage.retention_days",
        uint(4, 1, U32, 30),
        "Days of telemetry kept.",
    ),
    f(
        t::ST_GROW_RATIO,
        "storage.grow_ratio_db",
        uint(4, 0, 100, 50),
        "Percent of newly available disk space given to the database; the rest goes to the telemetry ring.",
    ),
    f(
        t::ST_DISCARD,
        "storage.discard",
        Kind::Enum {
            variants: DISCARD_MODES,
            default: 0,
        },
        "auto: tell the disk about space no longer used (discard/UNMAP). off: never.",
    ),
    f(
        t::ST_BACKUP_INTERVAL,
        "storage.backup_interval_min",
        uint(4, 0, 7 * 24 * 60, 60),
        "Minutes between in-disk database backups; 0 turns them off.",
    ),
    f(
        t::ST_AUTO_RESTORE,
        "storage.auto_restore",
        Kind::Bool(true),
        "Restore the newest intact backup when the database is corrupt at boot.",
    ),
    f(
        t::ST_SCRUB_INTERVAL,
        "storage.scrub_interval_h",
        uint(4, 0, 90 * 24, 24),
        "Hours between scrub passes; 0 turns scrubbing off.",
    ),
    f(
        t::ST_SCRUB_BUDGET,
        "storage.scrub_io_budget_mb_s",
        uint(4, 1, 1024, 8),
        "Megabytes per second a scrub pass may read.",
    ),
    dev(f(
        t::ST_REQUIRE_FLUSH,
        "storage.require_flush",
        Kind::Bool(true),
        "Refuse a disk that cannot flush its write cache. false: development only.",
    )),
    dev(f(
        t::ST_REQUIRE_DATA_DISK,
        "storage.require_data_disk",
        Kind::Bool(true),
        "Refuse to serve without a data disk. false (memory only): development only.",
    )),
    dev(f(
        t::ST_REFUSE_ON_CORRUPTION,
        "storage.refuse_on_corruption",
        Kind::Bool(true),
        "Refuse to serve when the database fails its integrity check. false: development only.",
    )),
    f(
        t::ST_ENCRYPTION,
        "storage.encryption",
        Kind::Enum {
            variants: ENCRYPTION_MODES,
            default: 0,
        },
        "off, or aes-256-xts: the data partition is encrypted at rest (needs storage.disk_key; format 4). Protects a stolen volume or snapshot, not a stolen ISO.",
    ),
    f(
        t::ST_DISK_KEY,
        "storage.disk_key",
        Kind::Bin { max: 128 },
        "File with the disk key: 64 raw bytes or 128 hex digits (two different AES-256 keys). Only with storage.encryption; never commit it.",
    ),
    // observability
    f(
        t::OBS_LOG_LEVEL,
        "observability.log_level",
        Kind::Enum {
            variants: LOG_LEVELS,
            default: 2,
        },
        "Most verbose level logged.",
    ),
    f(
        t::OBS_SYSLOG,
        "observability.syslog_udp",
        Kind::Addr,
        "Private collector for syslog records over UDP (a.b.c.d:port); empty: off.",
    ),
    f(
        t::OBS_METRICS,
        "observability.metrics_udp",
        Kind::Addr,
        "Private collector for statsd metrics over UDP (a.b.c.d:port); empty: off.",
    ),
    // watchdog
    f(
        t::WD_HANDLER,
        "watchdog.handler_budget_ms",
        uint(4, 1, 10_000, 20),
        "Milliseconds an ordinary handler may run.",
    ),
    f(
        t::WD_HANDSHAKE,
        "watchdog.handshake_budget_ms",
        uint(4, 0, 900, 0),
        "Milliseconds of a TLS handshake step; 0 calibrates at boot.",
    ),
    f(
        t::WD_ACTION,
        "watchdog.action",
        Kind::Enum {
            variants: WATCHDOG_ACTIONS,
            default: 1,
        },
        "What happens when a handler exceeds its budget: log, drop the connection or reset.",
    ),
    // memory
    f(
        t::MEM_HEAP,
        "memory.kernel_heap_mb",
        uint(4, 1, 1024, 64),
        "Kernel heap in MiB; a power of two. Sized at boot from this value.",
    ),
    f(
        t::MEM_MIN_FREE,
        "memory.min_free_mb",
        uint(4, 1, 1023, 8),
        "New connections are refused while less heap than this is free; smaller than the heap.",
    ),
    // entropy
    f(
        t::ENTROPY_JITTER,
        "entropy.fallback",
        Kind::Enum {
            variants: ENTROPY_FALLBACKS,
            default: 0,
        },
        "jitter (the default): on a host without virtio-rng and without RNDR/RDRAND, seed the generator from CPU timing jitter and the firmware's values; weaker than a hardware source, and the boot log, $SYS and `urmqtt-config pack` say so. none: refuse to boot without a hardware random source.",
    ),
    // cpu
    f(
        t::CPU_DISABLE,
        "cpu.disable",
        Kind::Strs {
            max_items: 16,
            max_len: 16,
            default: &[],
        },
        "CPU features the crypto and checksum code must not use (aes, pmull, sha2, crc32, ...).",
    ),
    f(
        t::CPU_DISPATCHER_SERVES,
        "cpu.dispatcher_serves",
        Kind::Bool(false),
        "Core 0 also serves connections next to the NIC work (benchmarking).",
    ),
    // time
    f(
        t::TIME_SERVERS,
        "time.servers",
        Kind::Addrs {
            max_items: MAX_TIME_SERVERS as u8,
        },
        "NTP servers as IPv4 addresses (a.b.c.d or a.b.c.d:port), at most four; empty: no SNTP.",
    ),
    f(
        t::TIME_INTERVAL,
        "time.interval_s",
        uint(4, 60, 86_400, 3600),
        "Seconds between SNTP queries.",
    ),
    f(
        t::TIME_MAX_STEP,
        "time.max_step_s",
        uint(4, 1, 86_400, 600),
        "Largest clock correction after the first, seconds.",
    ),
    // registry
    f(
        t::REG_ALLOWLIST,
        "registry.mode",
        Kind::Enum {
            variants: REGISTRY_MODES,
            default: 0,
        },
        "open: every valid certificate may connect. allowlist: only allowlisted identities.",
    ),
    // control
    f(
        t::CTL_PUBLIC_KEY,
        "control.public_key",
        Kind::Key32,
        "Ed25519 public key that verifies signed control messages; required when control.service_ids is not empty.",
    ),
    f(
        t::CTL_SERVICE_IDS,
        "control.service_ids",
        Kind::Strs {
            max_items: 32,
            max_len: 128,
            default: &[],
        },
        "Operational identities that may publish control messages; empty turns the channel off.",
    ),
    f(
        t::CTL_ALLOW_UNREVOKE,
        "control.allow_unrevoke",
        Kind::Bool(false),
        "Allow control messages that lift a revocation. Keep false in production.",
    ),
    f(
        t::CTL_MAX_AGE,
        "control.max_message_age_s",
        uint(4, 1, 86_400, 600),
        "Longest validity window of a control message, seconds.",
    ),
    // plaintext MQTT for trusted networks (P1, ADR-229)
    since(
        f(
            t::PL_ENABLED,
            "plaintext.enabled",
            Kind::Bool(false),
            "Accept plain, unencrypted MQTT on plaintext.port. Anyone on the path can read and change the traffic, and a client is identified only by a password or by its address. Use it on a network you control, with allow_from set. Off by default.",
        ),
        2,
    ),
    since(
        f(
            t::PL_PORT,
            "plaintext.port",
            uint(2, 1, 65_535, 1883),
            "TCP port of plaintext MQTT (1883 is the usual one); different from network.mqtt_tls_port.",
        ),
        2,
    ),
    since(
        items(
            f(
                t::PL_ALLOW_FROM,
                "plaintext.allow_from",
                Kind::Strs {
                    max_items: MAX_PLAIN_NETWORKS as u16,
                    max_len: 18,
                    default: &[],
                },
                "Networks (a.b.c.d/len, for example 10.0.0.0/8) that may connect. Required when plaintext is enabled. Any other address gets no answer at all and the broker keeps no state for it.",
            ),
            Item::Cidr,
        ),
        2,
    ),
    since(
        f(
            t::PL_ANYWHERE,
            "plaintext.allow_from_anywhere",
            Kind::Bool(false),
            "DANGEROUS: accept connections from every address instead of allow_from. Not for a machine with a public address.",
        ),
        2,
    ),
    since(
        f(
            t::PL_AUTH,
            "plaintext.auth",
            Kind::Enum {
                variants: PLAINTEXT_AUTH,
                default: 0,
            },
            "password: an MQTT user name and password per client (the user name is the device id in the ACL). anonymous: no login; every client gets anonymous_identity. ip: the client's address decides who it is (ip_identities).",
        ),
        2,
    ),
    since(
        f(
            t::PL_ANON_ID,
            "plaintext.anonymous_identity",
            Kind::Str {
                max: MAX_IDENTITY_LEN as u16,
                default: "lan",
            },
            "auth = anonymous: the identity every plaintext client gets; it is the {id} of acl_publish and acl_subscribe.",
        ),
        2,
    ),
    since(
        items(
            f(
                t::PL_USERS,
                "plaintext.users",
                Kind::Strs {
                    max_items: MAX_PLAIN_USERS as u16,
                    max_len: 256,
                    default: &[],
                },
                "auth = password: the accounts. Each has an id (the MQTT user name and the device id in the ACL) and a salted, iterated PBKDF2-SHA-256 hash of the password, made by the builder page or `urmqtt-config hash-password`. The password itself is never stored.",
            ),
            Item::User,
        ),
        2,
    ),
    since(
        items(
            f(
                t::PL_IP_IDENTITIES,
                "plaintext.ip_identities",
                Kind::Strs {
                    max_items: MAX_PLAIN_IP_IDENTITIES as u16,
                    max_len: 96,
                    default: &[],
                },
                "auth = ip: networks (a.b.c.d/len) and the identity every client in them gets; the longest matching network wins and each must lie within allow_from.",
            ),
            Item::IpIdentity,
        ),
        2,
    ),
    since(
        f(
            t::PL_MAX_CONNS,
            "plaintext.max_connections",
            uint(4, 1, 1_000_000, 1000),
            "Plaintext connections held at once, all cores together; more are refused.",
        ),
        2,
    ),
    since(
        f(
            t::PL_MAX_PER_IP,
            "plaintext.max_connections_per_ip",
            uint(4, 1, 65_535, 16),
            "Plaintext connections held at once from one source address (devices behind one NAT share it).",
        ),
        2,
    ),
    since(
        f(
            t::PL_MAX_PACKET,
            "plaintext.max_packet_size",
            uint(4, MIN_PACKET_SIZE, MQTT_MAX_PACKET_SIZE, 1024),
            "Largest MQTT packet a plaintext client may send, in bytes.",
        ),
        2,
    ),
    since(
        f(
            t::PL_PUBLISH_RATE,
            "plaintext.publish_rate_per_device",
            Kind::Rate {
                tokens: 5,
                per_ms: 1000,
            },
            "Publish rate per plaintext session as \"N/s\", \"N/m\" or \"N/h\".",
        ),
        2,
    ),
    since(
        f(
            t::PL_MAX_FAILS,
            "plaintext.max_failed_auths_per_ip",
            uint(4, 1, 1000, 5),
            "Failed logins from one address, within lockout_s, before it is locked out.",
        ),
        2,
    ),
    since(
        f(
            t::PL_LOCKOUT,
            "plaintext.lockout_s",
            uint(4, 1, 86_400, 300),
            "Seconds a locked-out address gets no answer; also the window in which its failed logins are counted.",
        ),
        2,
    ),
    since(
        f(
            t::PL_ACL_PUBLISH,
            "plaintext.acl_publish",
            Kind::Strs {
                max_items: MAX_PLAIN_ACL as u16,
                max_len: 512,
                default: &["devices/{id}/#"],
            },
            "Topic filters a plaintext client may publish to; {id} is its identity. No filter may start with $.",
        ),
        2,
    ),
    since(
        f(
            t::PL_ACL_SUBSCRIBE,
            "plaintext.acl_subscribe",
            Kind::Strs {
                max_items: MAX_PLAIN_ACL as u16,
                max_len: 512,
                default: &["devices/{id}/cmd/#"],
            },
            "Topic filters a plaintext client may subscribe to; {id} is its identity. No filter may start with $.",
        ),
        2,
    ),
    since(
        f(
            t::PL_RETAIN,
            "plaintext.retain",
            Kind::Bool(false),
            "Let plaintext clients publish retained messages. Off: such a message is delivered but not retained.",
        ),
        2,
    ),
    // console
    since(
        f(
            t::CON_VIRTIO_GPU,
            "console.virtio_gpu",
            Kind::Enum {
                variants: VIRTIO_GPU_MODES,
                default: 0,
            },
            "Show the console on a virtio-gpu display (2D). off: never. auto: when the boot framebuffer is missing or is RAM nothing shows (edk2 virtio-gpu, e.g. netcup ARM). on: whenever a virtio-gpu is found. Format 5.",
        ),
        5,
    ), // devices (ADR-257, ADR-258)
    since(
        f(
            t::DEV_VIRTIO_CONSOLE,
            "devices.virtio_console",
            Kind::Enum {
                variants: DEVICE_MODES,
                default: 0,
            },
            "Drive a virtio-console (port 0): the log goes there too, and the Diagnostic entry reads its prompts' keys from it. off: never. auto: when one is found. on: when one is found, and say loudly when none is. Format 6.",
        ),
        6,
    ),
    since(
        f(
            t::DEV_VIRTIO_BALLOON,
            "devices.virtio_balloon",
            Kind::Enum {
                variants: DEVICE_MODES,
                default: 0,
            },
            "Drive a virtio-balloon: report total and free memory to the host. It never inflates (the heap is fixed). off: never. auto: when one is found. on: when one is found, and say loudly when none is. Format 6.",
        ),
        6,
    ),
    since(
        f(
            t::DEV_VIRTIO_INPUT,
            "devices.virtio_input",
            Kind::Enum {
                variants: DEVICE_MODES,
                default: 0,
            },
            "Drive virtio-input keyboards for the Diagnostic entry's prompts (a provider's VNC console). off: never. auto: when one is found. on: when one is found, and say loudly when none is. Format 6.",
        ),
        6,
    ),
    since(
        f(
            t::DEV_VIRTIO_VSOCK,
            "devices.virtio_vsock",
            Kind::Enum {
                variants: DEVICE_MODES,
                default: 0,
            },
            "Drive a virtio-vsock and serve the Diagnostic report, read-only, to the host on vsock port 2883. off: never. auto: when one is found. on: when one is found, and say loudly when none is. Format 6.",
        ),
        6,
    ),
    // network, continued (NOW-19, ADR-264)
    since(
        f(
            t::NET_MTU,
            "network.mtu",
            uint(2, 0, MAX_MTU, 0),
            "Largest IPv4 packet in bytes (576 to 9000). 0 (the default): the MTU DHCP announces (option 26), else 1500. Set it when the network is smaller than 1500 and does not say so, e.g. 1460 on Google Cloud with a static address. TCP segments follow it (MSS = MTU - 40); frames larger than 1500 are not sent. Format 7.",
        ),
        7,
    ),
    // devices, continued (NOW-13, ADR-270)
    since(
        f(
            t::DEV_NET_INTERRUPT,
            "devices.virtio_net_interrupt",
            Kind::Enum {
                variants: NET_INTERRUPT_MODES,
                default: 0,
            },
            "How the NIC wakes the core that owns it when a frame arrives. auto (the default): the receive queue's MSI-X interrupt where the platform has one (x86 local APIC, aarch64 GICv2m frame or GICv3 ITS); polling while NIC traffic is recent (2 ms) and where there is none. off: always poll (every 200 us while connections exist, and the 10 ms tick), for a hypervisor whose interrupt misbehaves. Format 11.",
        ),
        11,
    ),
    // MQTT over WebSocket (NEXT-5, ADR-272): format version 9.
    since(
        f(
            t::WS_ENABLED,
            "websocket.enabled",
            Kind::Bool(false),
            "Accept MQTT over secure WebSocket (wss://, TLS 1.3, subprotocol mqtt) on websocket.port, for browsers and web stacks. Off by default. Needs the TLS listener (network.mqtt_tls_port) and its certificates. Format 9.",
        ),
        9,
    ),
    since(
        f(
            t::WS_PORT,
            "websocket.port",
            uint(2, 1, 65_535, 8084),
            "TCP port of the wss:// listener; different from the other MQTT ports.",
        ),
        9,
    ),
    since(
        f(
            t::WS_PATH,
            "websocket.path",
            Kind::Str {
                max: MAX_WS_PATH_LEN as u16,
                default: "/mqtt",
            },
            "The URL path clients connect to (wss://host:port/mqtt). Starts with /; letters, digits and - . _ ~ / only. Any other path is answered 404.",
        ),
        9,
    ),
    since(
        f(
            t::WS_AUTH,
            "websocket.auth",
            Kind::Enum {
                variants: WEBSOCKET_AUTH,
                default: 0,
            },
            "mtls: a client certificate, exactly as on the TLS port (identity, roles, revocation). password: no client certificate; an MQTT user name and password from websocket.users, checked inside TLS, with its own ACL (acl_publish, acl_subscribe) and lock-out, for browsers.",
        ),
        9,
    ),
    since(
        f(
            t::WS_ORIGINS,
            "websocket.origins",
            Kind::Strs {
                max_items: MAX_WS_ORIGINS as u16,
                max_len: MAX_WS_ORIGIN_LEN as u16,
                default: &[],
            },
            "Web pages allowed to connect, as exact origins (https://app.example.com, http://localhost:3000). A browser's upgrade from any other origin is refused (403): the defence against cross-site WebSocket hijacking. Required with auth = password; empty with mtls admits any origin.",
        ),
        9,
    ),
    since(
        items(
            f(
                t::WS_USERS,
                "websocket.users",
                Kind::Strs {
                    max_items: MAX_PLAIN_USERS as u16,
                    max_len: 256,
                    default: &[],
                },
                "auth = password: the accounts, as in plaintext.users (an id and a PBKDF2-SHA-256 hash made by the builder page or `urmqtt-config hash-password`). The password travels only inside TLS and is never stored.",
            ),
            Item::User,
        ),
        9,
    ),
    since(
        f(
            t::WS_UPGRADE_TIMEOUT,
            "websocket.upgrade_timeout_s",
            uint(4, 1, MAX_WS_UPGRADE_TIMEOUT_S, 5),
            "Seconds from the TCP connection to a complete upgrade request (TLS handshake included); a slower client is cut off.",
        ),
        9,
    ),
    since(
        f(
            t::WS_MAX_CONNS,
            "websocket.max_connections",
            uint(4, 1, 1_000_000, 1000),
            "WebSocket connections held at once, all cores together; more are refused.",
        ),
        9,
    ),
    since(
        f(
            t::WS_MAX_PER_IP,
            "websocket.max_connections_per_ip",
            uint(4, 1, 65_535, 16),
            "WebSocket connections held at once from one source address (browsers behind one NAT share it).",
        ),
        9,
    ),
    since(
        f(
            t::WS_MAX_PACKET,
            "websocket.max_packet_size",
            uint(4, MIN_PACKET_SIZE, MQTT_MAX_PACKET_SIZE, 16_384),
            "auth = password: largest MQTT packet a client may send, in bytes (with mtls the broker's limits.max_packet_size applies).",
        ),
        9,
    ),
    since(
        f(
            t::WS_PUBLISH_RATE,
            "websocket.publish_rate_per_device",
            Kind::Rate {
                tokens: 10,
                per_ms: 1000,
            },
            "auth = password: publish rate per session as \"N/s\", \"N/m\" or \"N/h\".",
        ),
        9,
    ),
    since(
        f(
            t::WS_MAX_FAILS,
            "websocket.max_failed_auths_per_ip",
            uint(4, 1, 1000, 5),
            "auth = password: failed logins from one address, within lockout_s, before it is locked out.",
        ),
        9,
    ),
    since(
        f(
            t::WS_LOCKOUT,
            "websocket.lockout_s",
            uint(4, 1, 86_400, 300),
            "auth = password: seconds a locked-out address gets no answer; also the window in which its failed logins are counted.",
        ),
        9,
    ),
    since(
        f(
            t::WS_ACL_PUBLISH,
            "websocket.acl_publish",
            Kind::Strs {
                max_items: MAX_PLAIN_ACL as u16,
                max_len: 512,
                default: &["web/{id}/#"],
            },
            "auth = password: topic filters a client may publish to; {id} is its account id. No filter may start with $.",
        ),
        9,
    ),
    since(
        f(
            t::WS_ACL_SUBSCRIBE,
            "websocket.acl_subscribe",
            Kind::Strs {
                max_items: MAX_PLAIN_ACL as u16,
                max_len: 512,
                default: &["web/{id}/#"],
            },
            "auth = password: topic filters a client may subscribe to; {id} is its account id. No filter may start with $.",
        ),
        9,
    ),
    since(
        f(
            t::WS_RETAIN,
            "websocket.retain",
            Kind::Bool(false),
            "auth = password: let clients publish retained messages. Off: such a message is delivered but not retained.",
        ),
        9,
    ),
    // MQTT 5.0 (NEXT-3, ADR-273 rule 21): format version 12.
    since(
        f(
            t::LIM_MAX_SESSION_EXPIRY,
            "limits.max_session_expiry_s",
            uint(4, 0, U32, DEFAULT_SESSION_EXPIRY_S),
            "The longest Session Expiry Interval granted, in seconds, to MQTT 5.0 clients and to 3.1.1 persistent sessions alike; a session offline longer is deleted with its subscriptions and queue. 4294967295 = never expire. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::LIM_DEFAULT_SESSION_EXPIRY,
            "limits.default_session_expiry_s",
            uint(4, 0, U32, DEFAULT_SESSION_EXPIRY_S),
            "The Session Expiry Interval of an MQTT 3.1.1 persistent session (clean_session 0), in seconds; at most limits.max_session_expiry_s. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::LIM_MAX_MESSAGE_EXPIRY,
            "limits.max_message_expiry_s",
            uint(4, 0, U32, 0),
            "The longest Message Expiry Interval a publisher may ask for, in seconds (retained and queued messages included); 0: no cap. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_ENABLED,
            "mqtt5.enabled",
            Kind::Bool(true),
            "Accept MQTT 5.0 clients (CONNECT with protocol level 5) on every listener. Off: they are answered CONNACK 0x84 (unsupported protocol version) and closed; MQTT 3.1.1 is always accepted. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_RECEIVE_MAXIMUM,
            "mqtt5.receive_maximum",
            uint(4, 1, 65_535, 32),
            "Receive Maximum announced to MQTT 5.0 clients: QoS 2 publications a client may have awaiting PUBREL; one more is DISCONNECT 0x93. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_TOPIC_ALIAS_MAXIMUM,
            "mqtt5.topic_alias_maximum",
            uint(4, 0, 65_535, 10),
            "Topic Alias Maximum announced to MQTT 5.0 clients (client to broker only); 0 disables aliases. A connection that uses aliases may hold up to topic_alias_maximum × (limits.max_topic_len + 16) bytes. Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_MAX_USER_PROPERTIES,
            "mqtt5.max_user_properties",
            uint(4, 0, MAX_MQTT5_USER_PROPERTIES, 16),
            "User Properties allowed in one MQTT 5.0 property block; a packet with more is refused (0x83). Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_MAX_KEEP_ALIVE,
            "mqtt5.max_keep_alive_s",
            uint(4, 0, 65_535, 0),
            "0: an MQTT 5.0 client keeps the keep alive it asked for. Otherwise the longest keep alive, in seconds, a 5.0 client gets (announced as Server Keep Alive in CONNACK). Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_SHARED_SUBSCRIPTIONS,
            "mqtt5.shared_subscriptions",
            Kind::Bool(true),
            "Shared subscriptions ($share/{group}/{filter}, MQTT 5.0 4.8.2; also for 3.1.1 clients): each matching message goes to one member of the group. Off: CONNACK announces Shared Subscription Available 0 and a $share/ filter gets SUBACK 0x9E (3.1.1: 0x80). Format 12.",
        ),
        12,
    ),
    since(
        f(
            t::MQTT5_SUBSCRIPTION_IDENTIFIERS,
            "mqtt5.subscription_identifiers",
            Kind::Bool(true),
            "Subscription Identifiers (MQTT 5.0 3.8.2.1.2): returned in each PUBLISH the subscription matched. Off: CONNACK announces Subscription Identifier Available 0 and a SUBSCRIBE that carries one gets SUBACK 0xA1. Format 12.",
        ),
        12,
    ),
    // MQTT 5.0 part 3 (ADR-275): format version 13.
    since(
        f(
            t::LIM_MAX_SHARED_GROUPS,
            "limits.max_shared_groups",
            uint(4, 1, 65_535, 1024),
            "Shared-subscription groups ($share/{group}/{filter}) one data core may own; a SUBSCRIBE that would create one more gets SUBACK 0x97 (MQTT 5.0) / 0x80 (3.1.1). Each group lives on one core chosen by a hash of (role class, group, filter). Format 13.",
        ),
        13,
    ),
    since(
        f(
            t::LIM_MAX_SHARED_GROUP_MEMBERS,
            "limits.max_shared_group_members",
            uint(4, 1, 65_535, 1024),
            "Members one shared-subscription group may have; one more gets SUBACK 0x97 / 0x80. Format 13.",
        ),
        13,
    ),
    // NOW-14 (ADR-280): format version 14.
    since(
        f(
            t::LIM_MAX_CONNECTIONS_PER_IP,
            "limits.max_connections_per_ip",
            uint(4, 0, 1_000_000, 1024),
            "Established TLS connections (MQTT and WebSocket) one source address may hold at once, all cores together; 0: no limit. Over it the SYN gets no answer (or the final ACK a RST) before any TLS work, and the refusal is counted (`$SYS/broker/connections/per_address/...`). Devices behind one NAT share an address, so size it for the largest site. The handshakes in flight per address are bounded separately (`limits.max_handshakes_in_flight_per_ip`). Format 14.",
        ),
        14,
    ),
    // Run-time password accounts (NOW-15, ADR-285): format version 15.
    since(
        f(
            t::LIM_MAX_RUNTIME_ACCOUNTS,
            "limits.max_runtime_accounts",
            uint(2, 0, 1_024, 0),
            "Password accounts the signed control channel may hold on the data disk (set-account, remove-account), for the plaintext and WebSocket listeners in password mode; 0 (the default): the control channel refuses account commands. Needs control.service_ids and a data disk. Format 15.",
        ),
        15,
    ),
    // The Prometheus endpoint (NEXT-9, ADR-290): format version 16.
    since(
        f(
            t::METRICS_ENABLED,
            "metrics.enabled",
            Kind::Bool(false),
            "Serve the broker's numbers in the Prometheus text format (and OpenMetrics) as HTTP on metrics.port, to the networks in metrics.allow_from only. Plain HTTP, read-only, no client data in it. Off by default. Format 16.",
        ),
        16,
    ),
    since(
        f(
            t::METRICS_PORT,
            "metrics.port",
            uint(2, 1, 65_535, 9100),
            "TCP port of the metrics endpoint (GET /metrics); different from every other listener's port.",
        ),
        16,
    ),
    since(
        items(
            f(
                t::METRICS_ALLOW_FROM,
                "metrics.allow_from",
                Kind::Strs {
                    max_items: MAX_METRICS_NETWORKS as u16,
                    max_len: 18,
                    default: &[],
                },
                "Networks (a.b.c.d/len, for example 10.0.0.0/8) that may scrape. Required when metrics are enabled; there is no \"anywhere\". Any other address gets no answer at all and the broker keeps no state for it.",
            ),
            Item::Cidr,
        ),
        16,
    ),
    since(
        f(
            t::METRICS_MAX_CONNS,
            "metrics.max_connections",
            uint(1, 1, 64, 8),
            "Metrics connections held at once on each data core; more are refused. One scrape is one short connection.",
        ),
        16,
    ),
    since(
        f(
            t::METRICS_MAX_PER_IP,
            "metrics.max_connections_per_ip",
            uint(1, 1, 16, 2),
            "Metrics connections held at once from one source address on each data core.",
        ),
        16,
    ),
    since(
        f(
            t::METRICS_REQUEST_TIMEOUT,
            "metrics.request_timeout_s",
            uint(1, 1, MAX_METRICS_TIMEOUT_S, 5),
            "Seconds from the TCP connection to the end of the answer; a slower client is cut off (slowloris). Prometheus scrapes in well under a second.",
        ),
        16,
    ),
    // DMA remapping (LATER-5, ADR-305): format version 18.
    since(
        f(
            t::DEV_IOMMU,
            "devices.iommu",
            Kind::Enum {
                variants: IOMMU_MODES,
                default: 0,
            },
            "DMA remapping through the machine's IOMMU (Intel VT-d, AMD-Vi, Arm SMMUv3): each device the broker drives can reach only the memory the kernel gave it, and a DMA anywhere else is blocked and counted. off (the default): the IOMMU is left as the firmware set it (in a VM the hypervisor's devices are trusted, and an emulated IOMMU costs throughput). auto: used when the firmware describes one that covers the devices, else a warning and the broker runs without. require: refuse to boot unless every driven device is behind a working IOMMU (bare metal, a hypervisor you do not trust). Format 18.",
        ),
        18,
    ),
    // A/B updates (NEXT-11, ADR-297): format version 17.
    since(
        f(
            t::UPD_CONFIRM,
            "update.confirm",
            Kind::Enum {
                variants: UPDATE_CONFIRM_MODES,
                default: 0,
            },
            "Who confirms a new kernel after an A/B update (urmqtt-disk slots activate): auto, once the store is open and a listener has been up for update.confirm_after_s; or operator, with a boot-confirm control message (urmqtt-control). Unconfirmed, it is replaced by the previous slot after its trial boots. Format 17.",
        ),
        17,
    ),
    since(
        f(
            t::UPD_CONFIRM_AFTER,
            "update.confirm_after_s",
            uint(4, 0, 86_400, 60),
            "update.confirm = auto: seconds a trial boot must serve (store open, listener up) before it is confirmed. Format 17.",
        ),
        17,
    ),
    since(
        f(
            t::UPD_TRIAL_TIMEOUT,
            "update.trial_timeout_s",
            uint(4, 0, 86_400, 900),
            "A trial boot not confirmed within this many seconds resets the machine, which uses one of its trial boots; 0: it waits as long as it runs. When not 0, longer than update.confirm_after_s. Format 17.",
        ),
        17,
    ),
];

/// The field with this tag.
pub fn by_tag(tag: u16) -> Option<&'static Field> {
    FIELDS
        .binary_search_by_key(&tag, |f| f.tag)
        .ok()
        .and_then(|i| FIELDS.get(i))
}

/// The field with this TOML key.
pub fn by_key(key: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.key == key)
}
