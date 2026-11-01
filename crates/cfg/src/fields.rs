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
}

use tag as t;

pub const NETWORK_MODES: &[&str] = &["dhcp", "static", "auto"];
pub const IDENTITY_FIELDS: &[&str] = &["cn", "san_uri"];
pub const STORAGE_MODES: &[&str] = &["disk", "auto", "ram"];
pub const DISCARD_MODES: &[&str] = &["auto", "off"];
pub const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
pub const ENTROPY_FALLBACKS: &[&str] = &["jitter", "none"];
pub const REGISTRY_MODES: &[&str] = &["open", "allowlist"];
pub const WATCHDOG_ACTIONS: &[&str] = &["log", "drop", "reset"];
/// How a plaintext client proves who it is (P1).
pub const PLAINTEXT_AUTH: &[&str] = &["password", "anonymous", "ip"];

/// Limits of the plaintext lists (they size arrays in the kernel).
pub const MAX_PLAIN_NETWORKS: usize = 64;
pub const MAX_PLAIN_USERS: usize = 256;
pub const MAX_PLAIN_IP_IDENTITIES: usize = 64;
pub const MAX_PLAIN_ACL: usize = 16;
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
        uint(2, 1, 65_535, 8883),
        "TCP port of MQTT over TLS.",
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
        "jitter: seed from CPU timing jitter when no hardware random source exists. none: refuse to boot without one.",
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
