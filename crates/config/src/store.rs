//! Initialise-once storage for the loaded configuration.
//!
//! The kernel needs the configuration before its heap exists (the heap is
//! sized from it), so the typed [`BuildConfig`] and the tables behind its
//! slices live in `.bss`, filled in place by [`load`]. Strings and PEM
//! files are not copied: they point into the module's memory, which the
//! bootloader keeps mapped and the kernel never reclaims.
#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::{MaybeUninit, take};
use core::ops::Deref;
use core::sync::atomic::{AtomicU8, Ordering};

use urmqtt_cfg::blob::{self, Blob, SlotKind};
use urmqtt_cfg::check;
use urmqtt_cfg::fields::tag;
use urmqtt_cfg::{CfgError, fields};

use crate::{
    Acl, BuildConfig, Cidr, Control, Cpu, DEV_KERNEL, DiscardMode, Entropy, IdentityField,
    Ipv4Cidr, Limits, LogLevel, Memory, Network, NetworkMode, Observability, PlainAuth,
    PlainNetwork, PlainUser, Plaintext, Rate, Registry, SocketAddrV4, Storage, StorageMode, Time,
    Tls, Trust, Watchdog, WatchdogAction,
};

/// Room for every plain-text string list of the field table at its
/// documented maximum (the sum of the `max_items` of the `Strs` fields whose
/// entries are text; the typed lists have arrays of their own; checked by a
/// test).
const STR_SLOTS: usize = 1520;
/// Operational plus bootstrap CAs at their maxima.
const PEM_SLOTS: usize = 16;
const ADDR_SLOTS: usize = fields::MAX_TIME_SERVERS;
/// The plaintext lists (P1): networks, accounts, per-network identities.
const NET_SLOTS: usize = fields::MAX_PLAIN_NETWORKS;
const USER_SLOTS: usize = fields::MAX_PLAIN_USERS;
const IPID_SLOTS: usize = fields::MAX_PLAIN_IP_IDENTITIES;

const NO_NET: Cidr = Cidr { addr: 0, prefix: 0 };

struct Arena {
    strs: [&'static str; STR_SLOTS],
    pems: [&'static [u8]; PEM_SLOTS],
    addrs: [SocketAddrV4; ADDR_SLOTS],
    nets: [Cidr; NET_SLOTS],
    users: [PlainUser; USER_SLOTS],
    ipids: [PlainNetwork; IPID_SLOTS],
}

impl Arena {
    const fn new() -> Self {
        Self {
            strs: [""; STR_SLOTS],
            pems: [&[]; PEM_SLOTS],
            addrs: [SocketAddrV4 {
                addr: [0; 4],
                port: 0,
            }; ADDR_SLOTS],
            nets: [NO_NET; NET_SLOTS],
            users: [PlainUser { id: "", hash: "" }; USER_SLOTS],
            ipids: [PlainNetwork {
                net: NO_NET,
                id: "",
            }; IPID_SLOTS],
        }
    }
}

/// What the loaded blob was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadInfo {
    /// SHA-256 identifying the configuration.
    pub fingerprint: [u8; 32],
    /// The signer's public key, if the blob carries a valid signature.
    pub signer: Option<[u8; 32]>,
    /// Length of the blob in bytes.
    pub blob_len: usize,
    /// Nothing is configured: every field is at its default.
    pub empty: bool,
    /// No module was loaded; these are the built-in defaults.
    pub builtin: bool,
}

/// Why a configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The slot or the blob failed a check (key and reason).
    Refused(CfgError),
    /// The configuration was already loaded (or the defaults were used).
    AlreadyLoaded,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(e) => write!(f, "{e}"),
            Self::AlreadyLoaded => write!(f, "the configuration was already in use"),
        }
    }
}

impl From<CfgError> for LoadError {
    fn from(e: CfgError) -> Self {
        Self::Refused(e)
    }
}

const EMPTY: u8 = 0;
const FILLING: u8 = 1;
const READY: u8 = 2;

struct Store {
    state: AtomicU8,
    arena: UnsafeCell<Arena>,
    cfg: UnsafeCell<MaybeUninit<BuildConfig>>,
    info: UnsafeCell<MaybeUninit<LoadInfo>>,
    default_blob: UnsafeCell<[u8; blob::EMPTY_BLOB_LEN]>,
}

// SAFETY: every field is written only by the one caller that wins the
// EMPTY -> FILLING transition, before READY is published with Release;
// readers look at `cfg` and `info` only after an Acquire load of READY, and
// nothing writes them again.
unsafe impl Sync for Store {}

static STORE: Store = Store {
    state: AtomicU8::new(EMPTY),
    arena: UnsafeCell::new(Arena::new()),
    cfg: UnsafeCell::new(MaybeUninit::uninit()),
    info: UnsafeCell::new(MaybeUninit::uninit()),
    default_blob: UnsafeCell::new([0; blob::EMPTY_BLOB_LEN]),
};

/// Decodes `bytes`, a blob, into `arena`.
fn build(b: &Blob<'static>, arena: &'static mut Arena) -> BuildConfig {
    let mut strs: &'static mut [&'static str] = &mut arena.strs;
    let mut pems: &'static mut [&'static [u8]] = &mut arena.pems;
    let mut list = |t: u16| -> &'static [&'static str] {
        let n = b.strs(t).count();
        let (head, tail) = take(&mut strs).split_at_mut_checked(n).unwrap_or_default();
        strs = tail;
        for (slot, s) in head.iter_mut().zip(b.strs(t)) {
            *slot = s;
        }
        head
    };
    let device_publish = list(tag::ACL_DEVICE_PUBLISH);
    let device_subscribe = list(tag::ACL_DEVICE_SUBSCRIBE);
    let service_ids = list(tag::ACL_SERVICE_IDS);
    let service_publish = list(tag::ACL_SERVICE_PUBLISH);
    let service_subscribe = list(tag::ACL_SERVICE_SUBSCRIBE);
    let operator_ids = list(tag::ACL_OPERATOR_IDS);
    let telemetry_topics = list(tag::ST_TELEMETRY);
    let control_ids = list(tag::CTL_SERVICE_IDS);
    let cpu_disable = list(tag::CPU_DISABLE);
    let revoked_serials = list(tag::TLS_REVOKED);
    let plain_acl_publish = list(tag::PL_ACL_PUBLISH);
    let plain_acl_subscribe = list(tag::PL_ACL_SUBSCRIBE);
    let mut pem_list = |t: u16| -> &'static [&'static [u8]] {
        let n = b.bins(t).count();
        let (head, tail) = take(&mut pems).split_at_mut_checked(n).unwrap_or_default();
        pems = tail;
        for (slot, s) in head.iter_mut().zip(b.bins(t)) {
            *slot = s;
        }
        head
    };
    let operational = pem_list(tag::TRUST_OPERATIONAL);
    let bootstrap = pem_list(tag::TRUST_BOOTSTRAP);
    let mut n = 0;
    for (i, (slot, (ip, port))) in arena
        .addrs
        .iter_mut()
        .zip(b.addrs(tag::TIME_SERVERS))
        .enumerate()
    {
        *slot = SocketAddrV4 { addr: ip, port };
        n = i + 1;
    }
    let servers: &'static [SocketAddrV4] = arena.addrs.get(..n).unwrap_or_default();

    // The plaintext lists (P1): the blob holds text, the kernel wants typed
    // entries it can match on the SYN path. The blob passed the checks, so
    // every entry parses; one that did not would be skipped, never trusted.
    let mut n_nets = 0;
    for (i, (slot, c)) in arena
        .nets
        .iter_mut()
        .zip(
            b.strs(tag::PL_ALLOW_FROM)
                .filter_map(|s| Cidr::parse(s).ok()),
        )
        .enumerate()
    {
        *slot = c;
        n_nets = i + 1;
    }
    let allow_from: &'static [Cidr] = arena.nets.get(..n_nets).unwrap_or_default();
    let mut n_users = 0;
    for (i, (slot, (id, hash))) in arena
        .users
        .iter_mut()
        .zip(b.strs(tag::PL_USERS).filter_map(|s| s.split_once(' ')))
        .enumerate()
    {
        *slot = PlainUser { id, hash };
        n_users = i + 1;
    }
    let users: &'static [PlainUser] = arena.users.get(..n_users).unwrap_or_default();
    let mut n_ids = 0;
    for (i, (slot, (net, id))) in arena
        .ipids
        .iter_mut()
        .zip(
            b.strs(tag::PL_IP_IDENTITIES)
                .filter_map(|s| urmqtt_cfg::plain::parse_ip_identity(s).ok()),
        )
        .enumerate()
    {
        *slot = PlainNetwork { net, id };
        n_ids = i + 1;
    }
    let ip_identities: &'static [PlainNetwork] = arena.ipids.get(..n_ids).unwrap_or_default();
    let (pl_tokens, pl_per_ms) = b.rate(tag::PL_PUBLISH_RATE);

    let sock = |t: u16| b.addr(t).map(|(addr, port)| SocketAddrV4 { addr, port });
    let u32_of = |t: u16| u32::try_from(b.uint(t)).unwrap_or(u32::MAX);
    let cidr = b
        .cidr(tag::NET_ADDRESS)
        .map(|(addr, prefix_len)| Ipv4Cidr { addr, prefix_len })
        .unwrap_or(Ipv4Cidr {
            addr: [0; 4],
            prefix_len: 0,
        });
    let gateway = b.ipv4(tag::NET_GATEWAY).unwrap_or([0; 4]);
    let mode = match b.variant(tag::NET_MODE) {
        1 => NetworkMode::Static {
            address: cidr,
            gateway,
        },
        2 => NetworkMode::Auto {
            address: cidr,
            gateway,
            dhcp_timeout_s: u32_of(tag::NET_DHCP_TIMEOUT),
        },
        _ => NetworkMode::Dhcp,
    };
    let (tokens, per_ms) = b.rate(tag::LIM_PUBLISH_RATE);
    BuildConfig {
        env: b.str(tag::ENV),
        network: Network {
            mode,
            mqtt_tls_port: u16::try_from(b.uint(tag::NET_TLS_PORT)).unwrap_or(0),
            mqtt_plain_port: match b.uint(tag::NET_PLAIN_PORT) {
                0 => None,
                p => u16::try_from(p).ok(),
            },
        },
        tls: Tls {
            cert_pem: b.bin(tag::TLS_CERT),
            key_pem: b.bin(tag::TLS_KEY),
            identity_field: match b.variant(tag::TLS_IDENTITY) {
                1 => IdentityField::SanUri,
                _ => IdentityField::Cn,
            },
            resumption: b.bool(tag::TLS_RESUMPTION),
            revoked_serials,
            min_server_cert_days: u32_of(tag::TLS_MIN_CERT_DAYS),
            server_cert_not_after: b.uint(tag::TLS_CERT_NOT_AFTER),
        },
        limits: Limits {
            max_connections_per_core: u32_of(tag::LIM_CONNECTIONS),
            max_packet_size: u32_of(tag::LIM_PACKET),
            max_topic_len: u32_of(tag::LIM_TOPIC_LEN),
            max_topic_levels: u32_of(tag::LIM_TOPIC_LEVELS),
            max_subscriptions_per_session: u32_of(tag::LIM_SUBSCRIPTIONS),
            max_inflight_qos1: u32_of(tag::LIM_INFLIGHT),
            max_queued_per_offline_session: u32_of(tag::LIM_QUEUED),
            max_retained_per_device: u32_of(tag::LIM_RETAINED_PER_DEVICE),
            max_retained_bytes: b.uint(tag::LIM_RETAINED_BYTES),
            publish_rate_per_device: Rate { tokens, per_ms },
            handshakes_per_core_per_sec: u32_of(tag::LIM_HANDSHAKES_PER_SEC),
            max_handshakes_in_flight_per_core: u32_of(tag::LIM_HANDSHAKES_CORE),
            max_handshakes_in_flight_per_ip: u32_of(tag::LIM_HANDSHAKES_IP),
        },
        acl: Acl {
            device_publish,
            device_subscribe,
            service_ids,
            service_publish,
            service_subscribe,
            operator_ids,
        },
        storage: Storage {
            mode: match b.variant(tag::ST_MODE) {
                0 => StorageMode::Disk,
                2 => StorageMode::Ram,
                _ => StorageMode::Auto,
            },
            ram_percent: u32_of(tag::ST_RAM_PERCENT),
            diagnostic: b.bool(tag::ST_DIAGNOSTIC),
            sqlite_heap_mb: u32_of(tag::ST_SQLITE_HEAP),
            telemetry_topics,
            retention_days: u32_of(tag::ST_RETENTION),
            grow_ratio_db: u32_of(tag::ST_GROW_RATIO),
            discard: match b.variant(tag::ST_DISCARD) {
                1 => DiscardMode::Off,
                _ => DiscardMode::Auto,
            },
            backup_interval_min: u32_of(tag::ST_BACKUP_INTERVAL),
            auto_restore: b.bool(tag::ST_AUTO_RESTORE),
            scrub_interval_h: u32_of(tag::ST_SCRUB_INTERVAL),
            scrub_io_budget_mb_s: u32_of(tag::ST_SCRUB_BUDGET),
            encryption: b.variant(tag::ST_ENCRYPTION) != 0,
            disk_key: crate::Secret(b.bin(tag::ST_DISK_KEY)),
            require_flush: b.bool(tag::ST_REQUIRE_FLUSH),
            require_data_disk: b.bool(tag::ST_REQUIRE_DATA_DISK),
            refuse_on_corruption: b.bool(tag::ST_REFUSE_ON_CORRUPTION),
        },
        observability: Observability {
            log_level: match b.variant(tag::OBS_LOG_LEVEL) {
                0 => LogLevel::Error,
                1 => LogLevel::Warn,
                3 => LogLevel::Debug,
                4 => LogLevel::Trace,
                _ => LogLevel::Info,
            },
            syslog_udp: sock(tag::OBS_SYSLOG),
            metrics_udp: sock(tag::OBS_METRICS),
        },
        watchdog: Watchdog {
            handler_budget_ms: u32_of(tag::WD_HANDLER),
            handshake_budget_ms: u32_of(tag::WD_HANDSHAKE),
            action: match b.variant(tag::WD_ACTION) {
                0 => WatchdogAction::Log,
                2 => WatchdogAction::Reset,
                _ => WatchdogAction::Drop,
            },
        },
        memory: Memory {
            kernel_heap_mb: u32_of(tag::MEM_HEAP),
            min_free_mb: u32_of(tag::MEM_MIN_FREE),
        },
        entropy: Entropy {
            jitter_fallback: b.variant(tag::ENTROPY_JITTER) == 0,
        },
        cpu: Cpu {
            disable: cpu_disable,
            dispatcher_serves: b.bool(tag::CPU_DISPATCHER_SERVES),
        },
        time: Time {
            servers,
            interval_s: u32_of(tag::TIME_INTERVAL),
            max_step_s: u32_of(tag::TIME_MAX_STEP),
        },
        registry: Registry {
            allowlist: b.variant(tag::REG_ALLOWLIST) == 1,
        },
        control: Control {
            public_key: b.key32(tag::CTL_PUBLIC_KEY).unwrap_or([0; 32]),
            service_ids: control_ids,
            allow_unrevoke: b.bool(tag::CTL_ALLOW_UNREVOKE),
            max_message_age_s: u32_of(tag::CTL_MAX_AGE),
        },
        trust: Trust {
            operational,
            bootstrap,
        },
        plaintext: Plaintext {
            enabled: b.bool(tag::PL_ENABLED),
            port: u16::try_from(b.uint(tag::PL_PORT)).unwrap_or(0),
            allow_from,
            allow_from_anywhere: b.bool(tag::PL_ANYWHERE),
            auth: match b.variant(tag::PL_AUTH) {
                1 => PlainAuth::Anonymous,
                2 => PlainAuth::Ip,
                _ => PlainAuth::Password,
            },
            anonymous_identity: b.str(tag::PL_ANON_ID),
            users,
            ip_identities,
            max_connections: u32_of(tag::PL_MAX_CONNS),
            max_connections_per_ip: u32_of(tag::PL_MAX_PER_IP),
            max_packet_size: u32_of(tag::PL_MAX_PACKET),
            publish_rate_per_device: Rate {
                tokens: pl_tokens,
                per_ms: pl_per_ms,
            },
            max_failed_auths_per_ip: u32_of(tag::PL_MAX_FAILS),
            lockout_s: u32_of(tag::PL_LOCKOUT),
            acl_publish: plain_acl_publish,
            acl_subscribe: plain_acl_subscribe,
            retain: b.bool(tag::PL_RETAIN),
        },
    }
}

/// Fills the store from `bytes`; the caller has won EMPTY -> FILLING.
fn fill(bytes: &'static [u8], builtin: bool) -> Result<LoadInfo, CfgError> {
    let b = Blob::parse(bytes)?;
    check::check(&b, DEV_KERNEL)?;
    let info = LoadInfo {
        fingerprint: *b.fingerprint(),
        signer: b.signature().map(|s| s.public_key),
        blob_len: b.len(),
        empty: b.is_empty(),
        builtin,
    };
    // SAFETY: we hold FILLING, so no other writer exists, and no reader
    // touches the arena (readers get slices only through `cfg`, which is
    // published after this write). The `'static` borrow ends the arena's
    // exclusive use: it is never borrowed mutably again.
    let arena: &'static mut Arena = unsafe { &mut *STORE.arena.get() };
    let cfg = build(&b, arena);
    // SAFETY: as above; `cfg` and `info` are written once, before READY.
    unsafe {
        (*STORE.cfg.get()).write(cfg);
    }
    // SAFETY: as above.
    unsafe {
        (*STORE.info.get()).write(info);
    }
    Ok(info)
}

/// The blob inside a slot file. A slot still marked as the installation
/// image's template (an installed disk that was never configured) is read
/// like any other: it holds the empty configuration.
fn blob_in(slot: &[u8]) -> Result<&[u8], CfgError> {
    blob::slot_blob(slot, SlotKind::Boot)
        .or_else(|e| blob::slot_blob(slot, SlotKind::Disk).map_err(|_| e))
}

/// Loads the configuration from the module the bootloader provided: the
/// slot file (marker, blob, padding). Call once, first thing at boot. On an
/// error nothing is installed and the built-in defaults apply (the caller
/// decides whether to stop).
pub fn load(slot: &'static [u8]) -> Result<LoadInfo, LoadError> {
    let bytes = blob_in(slot)?;
    begin()?;
    match fill(bytes, false) {
        Ok(info) => {
            STORE.state.store(READY, Ordering::Release);
            Ok(info)
        }
        Err(e) => {
            STORE.state.store(EMPTY, Ordering::Release);
            Err(e.into())
        }
    }
}

fn begin() -> Result<(), LoadError> {
    STORE
        .state
        .compare_exchange(EMPTY, FILLING, Ordering::Acquire, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| LoadError::AlreadyLoaded)
}

/// Installs the built-in defaults (the empty configuration), if nothing is
/// loaded yet. Reading [`CONFIG`] does this by itself.
pub fn load_defaults() -> LoadInfo {
    if begin().is_ok() {
        // SAFETY: we hold FILLING; nothing else touches `default_blob`.
        let buf: &'static mut [u8; blob::EMPTY_BLOB_LEN] =
            unsafe { &mut *STORE.default_blob.get() };
        blob::write_empty(buf);
        let bytes: &'static [u8] = buf;
        // The empty blob always passes its own checks.
        let _ = fill(bytes, true);
        STORE.state.store(READY, Ordering::Release);
    }
    wait_ready();
    info().unwrap_or(LoadInfo {
        fingerprint: [0; 32],
        signer: None,
        blob_len: 0,
        empty: true,
        builtin: true,
    })
}

fn wait_ready() {
    while STORE.state.load(Ordering::Acquire) != READY {
        if STORE.state.load(Ordering::Acquire) == EMPTY {
            return;
        }
        core::hint::spin_loop();
    }
}

/// How the current configuration was obtained (`None` before any load).
pub fn info() -> Option<LoadInfo> {
    if STORE.state.load(Ordering::Acquire) == READY {
        // SAFETY: READY means `info` was written, and it is never written again.
        let slot = unsafe { &*STORE.info.get() };
        // SAFETY: READY: initialised (see above).
        Some(unsafe { slot.assume_init_read() })
    } else {
        None
    }
}

/// Dereferences to the configuration in use; the first use before [`load`]
/// installs the defaults.
#[derive(Debug, Clone, Copy)]
pub struct ConfigHandle;

/// The configuration of this boot.
pub static CONFIG: ConfigHandle = ConfigHandle;

impl Deref for ConfigHandle {
    type Target = BuildConfig;

    fn deref(&self) -> &BuildConfig {
        while STORE.state.load(Ordering::Acquire) != READY {
            load_defaults();
        }
        // SAFETY: READY: `cfg` was written before the Release store and is
        // never written again.
        let slot = unsafe { &*STORE.cfg.get() };
        // SAFETY: READY: initialised (see above).
        unsafe { slot.assume_init_ref() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_string_arena_holds_every_list_at_its_maximum() {
        // Text lists live in `strs`; the lists with typed entries (networks,
        // accounts, per-network identities) have arrays of their own.
        let total: usize = fields::FIELDS
            .iter()
            .map(|f| match f.kind {
                fields::Kind::Strs { max_items, .. } if f.item == fields::Item::Text => {
                    usize::from(max_items)
                }
                _ => 0,
            })
            .sum();
        assert!(total <= STR_SLOTS, "{total} > {STR_SLOTS}");
        for (item, slots) in [
            (fields::Item::Cidr, NET_SLOTS),
            (fields::Item::User, USER_SLOTS),
            (fields::Item::IpIdentity, IPID_SLOTS),
        ] {
            let max: usize = fields::FIELDS
                .iter()
                .map(|f| match f.kind {
                    fields::Kind::Strs { max_items, .. } if f.item == item => {
                        usize::from(max_items)
                    }
                    _ => 0,
                })
                .sum();
            assert_eq!(max, slots, "{item:?}");
        }
        let pems: usize = fields::FIELDS
            .iter()
            .map(|f| match f.kind {
                fields::Kind::BinList { max_items, .. } => usize::from(max_items),
                _ => 0,
            })
            .sum();
        assert!(pems <= PEM_SLOTS);
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let c = &*CONFIG;
        assert_eq!(c.env, "prod");
        assert_eq!(c.network.mode, NetworkMode::Dhcp);
        assert_eq!(c.network.mqtt_tls_port, 8883);
        assert_eq!(c.network.mqtt_plain_port, None);
        assert_eq!(
            c.limits.publish_rate_per_device,
            Rate {
                tokens: 10,
                per_ms: 1000
            }
        );
        assert_eq!(c.acl.device_publish, ["devices/{id}/#"]);
        assert_eq!(c.memory.kernel_heap_mb, 64);
        assert!(
            c.missing_to_serve().is_some(),
            "no certificate: cannot serve"
        );
        let i = info().expect("loaded");
        assert!(i.builtin && i.empty && i.signer.is_none());
    }

    #[test]
    fn a_packed_blob_is_decoded() {
        use urmqtt_cfg::build::Builder;
        let mut b = Builder::new();
        b.str(tag::ENV, "lab").unwrap();
        b.variant(tag::NET_MODE, 2).unwrap();
        b.cidr(tag::NET_ADDRESS, [10, 1, 2, 3], 24).unwrap();
        b.ipv4(tag::NET_GATEWAY, [10, 1, 2, 1]).unwrap();
        b.uint(tag::NET_DHCP_TIMEOUT, 20).unwrap();
        b.strs(tag::ACL_DEVICE_PUBLISH, &["a/{id}/#", "b/#"])
            .unwrap();
        b.strs::<&str>(tag::ACL_OPERATOR_IDS, &[]).unwrap();
        b.bin(tag::TLS_CERT, b"-----BEGIN CERTIFICATE-----\n")
            .unwrap();
        b.bin(tag::TLS_KEY, b"-----BEGIN PRIVATE KEY-----\n")
            .unwrap();
        b.bins(tag::TRUST_OPERATIONAL, &[b"ca1".as_slice(), b"ca2"])
            .unwrap();
        b.addrs(tag::TIME_SERVERS, &[([192, 0, 2, 1], 123)])
            .unwrap();
        b.addr(tag::OBS_SYSLOG, [10, 0, 0, 9], 514).unwrap();
        b.uint(tag::MEM_HEAP, 128).unwrap();
        let bytes: &'static [u8] = Box::leak(b.finish(false).unwrap().into_boxed_slice());
        let blob = Blob::parse(bytes).unwrap();
        let arena: &'static mut Arena = Box::leak(Box::new(Arena::new()));
        let c = build(&blob, arena);
        assert_eq!(c.env, "lab");
        assert_eq!(
            c.network.mode,
            NetworkMode::Auto {
                address: Ipv4Cidr {
                    addr: [10, 1, 2, 3],
                    prefix_len: 24
                },
                gateway: [10, 1, 2, 1],
                dhcp_timeout_s: 20
            }
        );
        assert_eq!(c.acl.device_publish, ["a/{id}/#", "b/#"]);
        assert!(c.acl.operator_ids.is_empty());
        assert_eq!(
            c.acl.service_ids,
            ["backend"],
            "an untouched list keeps its default"
        );
        assert_eq!(c.trust.operational.len(), 2);
        assert_eq!(c.trust.operational[1], b"ca2");
        assert!(c.missing_to_serve().is_none());
        assert_eq!(
            c.time.servers,
            [SocketAddrV4 {
                addr: [192, 0, 2, 1],
                port: 123
            }]
        );
        assert_eq!(
            c.observability.syslog_udp,
            Some(SocketAddrV4 {
                addr: [10, 0, 0, 9],
                port: 514
            })
        );
        assert_eq!(c.memory.kernel_heap_mb, 128);
    }

    #[test]
    fn plaintext_is_off_by_default_with_the_documented_defaults() {
        let p = CONFIG.plaintext;
        assert!(!p.enabled && !p.allow_from_anywhere && !p.retain);
        assert_eq!((p.port, p.auth), (1883, PlainAuth::Password));
        assert!(p.allow_from.is_empty() && p.users.is_empty() && p.ip_identities.is_empty());
        assert_eq!(p.anonymous_identity, "lan");
        assert_eq!(
            (
                p.max_connections,
                p.max_connections_per_ip,
                p.max_packet_size
            ),
            (1000, 16, 1024)
        );
        assert_eq!(
            p.publish_rate_per_device,
            Rate {
                tokens: 5,
                per_ms: 1000
            }
        );
        assert_eq!((p.max_failed_auths_per_ip, p.lockout_s), (5, 300));
        assert_eq!(p.acl_publish, ["devices/{id}/#"]);
        assert_eq!(p.acl_subscribe, ["devices/{id}/cmd/#"]);
    }

    #[test]
    fn a_plaintext_configuration_is_decoded() {
        use urmqtt_cfg::build::Builder;
        use urmqtt_cfg::passwd;
        let hash = passwd::encode(b"pw", b"0123456789abcdef", 1000).unwrap();
        let mut b = Builder::new();
        b.bool(tag::PL_ENABLED, true).unwrap();
        b.uint(tag::PL_PORT, 1884).unwrap();
        b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8", "192.168.1.0/24"])
            .unwrap();
        b.strs(
            tag::PL_USERS,
            &[format!("sensor-1 {hash}"), format!("boiler {hash}")],
        )
        .unwrap();
        b.uint(tag::PL_MAX_CONNS, 40).unwrap();
        b.rate(tag::PL_PUBLISH_RATE, 2, 1000).unwrap();
        b.strs(tag::PL_ACL_PUBLISH, &["home/{id}/#"]).unwrap();
        b.strs::<&str>(tag::PL_ACL_SUBSCRIBE, &[]).unwrap();
        b.bool(tag::PL_RETAIN, true).unwrap();
        let bytes: &'static [u8] = Box::leak(b.finish(false).unwrap().into_boxed_slice());
        let blob = Blob::parse(bytes).unwrap();
        let arena: &'static mut Arena = Box::leak(Box::new(Arena::new()));
        let c = build(&blob, arena);
        let p = c.plaintext;
        assert!(p.enabled && p.retain && !p.allow_from_anywhere);
        assert_eq!(p.port, 1884);
        assert_eq!(p.allow_from.len(), 2);
        assert!(p.allow_from[0].contains_octets([10, 9, 9, 9]));
        assert!(!p.allow_from[0].contains_octets([11, 0, 0, 1]));
        assert!(p.allow_from[1].contains_octets([192, 168, 1, 77]));
        assert_eq!(p.users.len(), 2);
        assert_eq!(
            (p.users[0].id, p.users[0].hash),
            ("sensor-1", hash.as_str())
        );
        assert_eq!(p.users[1].id, "boiler");
        assert_eq!(p.max_connections, 40);
        assert_eq!(
            p.publish_rate_per_device,
            Rate {
                tokens: 2,
                per_ms: 1000
            }
        );
        assert_eq!(p.acl_publish, ["home/{id}/#"]);
        assert!(
            p.acl_subscribe.is_empty(),
            "an explicit empty list is read-only"
        );
        // Untouched keys keep their defaults.
        assert_eq!((p.max_connections_per_ip, p.lockout_s), (16, 300));
        assert_eq!(c.acl.device_publish, ["devices/{id}/#"]);
    }

    #[test]
    fn an_ip_identity_list_is_decoded_longest_prefix_data_intact() {
        use urmqtt_cfg::build::Builder;
        let mut b = Builder::new();
        b.bool(tag::PL_ENABLED, true).unwrap();
        b.variant(tag::PL_AUTH, 2).unwrap();
        b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
        b.strs(
            tag::PL_IP_IDENTITIES,
            &["10.1.0.0/16 plc", "10.1.2.0/24 gate", "10.9.9.9/32 pump"],
        )
        .unwrap();
        let bytes: &'static [u8] = Box::leak(b.finish(false).unwrap().into_boxed_slice());
        let blob = Blob::parse(bytes).unwrap();
        let arena: &'static mut Arena = Box::leak(Box::new(Arena::new()));
        let c = build(&blob, arena);
        let p = c.plaintext;
        assert_eq!(p.auth, PlainAuth::Ip);
        let ids: Vec<(String, &str)> = p
            .ip_identities
            .iter()
            .map(|e| (e.net.to_string(), e.id))
            .collect();
        assert_eq!(
            ids,
            [
                ("10.1.0.0/16".to_owned(), "plc"),
                ("10.1.2.0/24".to_owned(), "gate"),
                ("10.9.9.9/32".to_owned(), "pump"),
            ]
        );
    }

    #[test]
    fn both_slot_markers_are_read_and_others_refused() {
        use urmqtt_cfg::blob::{DISK_MARKER, SLOT_MARKER, make_slot};
        use urmqtt_cfg::build::Builder;
        let blob = Builder::new().finish(false).unwrap();
        let slot = make_slot(SlotKind::Boot, &blob).unwrap();
        assert_eq!(blob_in(&slot).unwrap().get(..blob.len()), Some(&blob[..]));
        let mut template = slot.clone();
        template[..16].copy_from_slice(&DISK_MARKER);
        assert_eq!(
            blob_in(&template).unwrap().get(..blob.len()),
            Some(&blob[..])
        );
        let mut other = slot.clone();
        other[..16].copy_from_slice(b"URMQTT-CFG-????\0");
        assert!(blob_in(&other).is_err());
        assert!(blob_in(&slot[..SLOT_MARKER.len() + 10]).is_err());
    }

    #[test]
    fn a_bad_slot_is_refused_and_leaves_the_defaults() {
        assert!(matches!(load(&[0u8; 100]), Err(LoadError::Refused(_))));
        let mut slot = std::vec![0u8; blob::SLOT_SIZE];
        slot[..16].copy_from_slice(&blob::SLOT_MARKER);
        slot[16..24].copy_from_slice(b"garbage!");
        let slot: &'static [u8] = Box::leak(slot.into_boxed_slice());
        assert!(load(slot).is_err());
        assert_eq!(CONFIG.network.mqtt_tls_port, 8883);
    }
}
