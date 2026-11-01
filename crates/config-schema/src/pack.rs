//! Packing: a (possibly partial) TOML configuration plus the PEM files it
//! names become a `urmqtt-cfg` blob (C1, ADR-215). The TOML goes through the
//! same [`parse`] as the build-time path, so one set of rules validates both;
//! keys the user leaves out take the defaults of `urmqtt_cfg::fields`.

use std::collections::BTreeSet;

use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::{self, Kind, tag};

use crate::{
    Config, ConfigError, NetworkMode, PemKind, RegistryMode, SocketAddrV4, check_expiry, check_pem,
    parse, parse_revocation_list,
};

fn cerr(path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        path: path.to_owned(),
        message: message.into(),
    }
}

/// Reads a file the TOML names (relative to the TOML's directory).
pub type ReadFile<'a> = &'a mut dyn FnMut(&str) -> Result<Vec<u8>, String>;

/// TOML keys that name files; the blob holds their contents.
const PLACEHOLDER_CERT: &str = "-cert-placeholder.pem";
const PLACEHOLDER_KEY: &str = "-key-placeholder.key";
const PLACEHOLDER_CTL: &str = "-control-placeholder.pub";
const PLACEHOLDER_CA: &str = "-ca-placeholder.pem";

fn rate_text(tokens: u32, per_ms: u32) -> String {
    let unit = match per_ms {
        1_000 => "s",
        60_000 => "m",
        _ => "h",
    };
    format!("{tokens}/{unit}")
}

/// The defaults as TOML text, with every section present: the TOML form of
/// the empty configuration. Keys that have no default are left out.
pub fn default_toml() -> String {
    let mut out = String::new();
    let mut section = "";
    for f in fields::FIELDS {
        let Some((sec, name)) = f.key.split_once('.') else {
            continue;
        };
        let Some(value) = default_value(f) else {
            continue;
        };
        if sec != section {
            out.push_str(&format!("\n[{sec}]\n"));
            section = sec;
        }
        out.push_str(&format!("{name} = {value}\n"));
    }
    out
}

fn quote(s: &str) -> String {
    format!("{s:?}")
}

fn default_value(f: &fields::Field) -> Option<String> {
    if f.derived
        || matches!(
            f.key,
            "tls.revoked_serials"
                | "trust.operational"
                | "trust.bootstrap"
                | "network.dhcp_timeout_s"
        )
    {
        return None;
    }
    Some(match f.kind {
        Kind::Bool(d) => d.to_string(),
        Kind::UInt { default, .. } => default.to_string(),
        Kind::Enum { variants, default } => quote(variants.get(usize::from(default))?),
        Kind::Str { default, .. } => quote(default),
        Kind::Strs { default, .. } => format!(
            "[{}]",
            default
                .iter()
                .map(|s| quote(s))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Kind::Rate { tokens, per_ms } => quote(&rate_text(tokens, per_ms)),
        Kind::Addr => quote(""),
        Kind::Addrs { .. } => "[]".to_owned(),
        Kind::Bin { .. } | Kind::BinList { .. } | Kind::Ipv4 | Kind::Cidr | Kind::Key32 => {
            return None;
        }
    })
}

/// Fills in what the user left out, returning the complete TOML and the file
/// keys the user did give.
fn complete(user: &toml::Table) -> Result<(String, BTreeSet<&'static str>), Vec<ConfigError>> {
    let defaults: toml::Table = default_toml()
        .parse()
        .map_err(|e| vec![cerr("", format!("internal: default TOML: {e}"))])?;
    let mut merged = user.clone();
    for (sec, vals) in &defaults {
        let toml::Value::Table(vals) = vals else {
            continue;
        };
        let entry = merged
            .entry(sec.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(t) = entry {
            for (k, v) in vals {
                t.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    // Keys that exist only in the TOML form.
    let mut supplied = BTreeSet::new();
    let mut set_default = |sec: &str, key: &'static str, name: &'static str, v: toml::Value| {
        let t = merged
            .entry(sec.to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(t) = t {
            if t.contains_key(name) {
                supplied.insert(key);
            } else {
                t.insert(name.to_owned(), v);
            }
        }
    };
    use toml::Value::{Array, Boolean, String as S};
    set_default("tls", "tls.cert", "cert", S(PLACEHOLDER_CERT.into()));
    set_default("tls", "tls.key", "key", S(PLACEHOLDER_KEY.into()));
    set_default(
        "tls",
        "tls.revocation_list",
        "revocation_list",
        S(String::new()),
    );
    set_default("tls", "tls.early_data", "early_data", Boolean(false));
    set_default(
        "control",
        "control.public_key",
        "public_key",
        S(PLACEHOLDER_CTL.into()),
    );
    set_default(
        "trust",
        "trust.operational",
        "operational",
        Array(vec![S(PLACEHOLDER_CA.into())]),
    );
    set_default("trust", "trust.bootstrap", "bootstrap", Array(vec![]));
    // An explicitly empty operational list means "none", like leaving it out.
    if let Some(toml::Value::Table(t)) = merged.get_mut("trust")
        && let Some(Array(a)) = t.get("operational")
        && a.is_empty()
    {
        t.insert("operational".into(), Array(vec![S(PLACEHOLDER_CA.into())]));
        supplied.remove("trust.operational");
    }
    let text = toml::to_string(&merged).map_err(|e| vec![cerr("", e.to_string())])?;
    Ok((text, supplied))
}

/// Everything `pack` needs besides the TOML.
pub struct PackOptions<'a> {
    /// Reads a file named in the TOML.
    pub read: ReadFile<'a>,
    /// The packer's clock, for the certificate expiry checks.
    pub now_unix: u64,
    /// The environment name (`--env`). The TOML's own top-level `env` key must
    /// agree if both are given; with neither it is `prod`.
    pub env: Option<&'a str>,
}

fn variant(list: &[&str], name: &str) -> u8 {
    list.iter()
        .position(|v| *v == name)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(0)
}

fn log_level_name(l: crate::LogLevel) -> &'static str {
    match l {
        crate::LogLevel::Error => "error",
        crate::LogLevel::Warn => "warn",
        crate::LogLevel::Info => "info",
        crate::LogLevel::Debug => "debug",
        crate::LogLevel::Trace => "trace",
    }
}

fn blob_err(e: urmqtt_cfg::CfgError) -> Vec<ConfigError> {
    vec![cerr(e.key, e.msg)]
}

fn sock(a: &SocketAddrV4) -> ([u8; 4], u16) {
    (a.ip().octets(), a.port())
}

/// The packed contents of the PEM files, read and checked.
struct Files {
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    operational: Vec<Vec<u8>>,
    bootstrap: Vec<Vec<u8>>,
    revoked: Vec<String>,
    control_key: Option<[u8; 32]>,
    cert_not_after: u64,
}

fn read_files(
    cfg: &Config,
    supplied: &BTreeSet<&'static str>,
    opts: &mut PackOptions<'_>,
) -> Result<Files, Vec<ConfigError>> {
    let mut errors = Vec::new();
    let mut read = |errors: &mut Vec<ConfigError>, key: &str, name: &str| -> Option<Vec<u8>> {
        match (opts.read)(name) {
            Ok(b) => Some(b),
            Err(e) => {
                errors.push(cerr(key, format!("cannot read {name:?}: {e}")));
                None
            }
        }
    };
    let now = opts.now_unix;
    let mut files = Files {
        cert: None,
        key: None,
        operational: Vec::new(),
        bootstrap: Vec::new(),
        revoked: Vec::new(),
        control_key: None,
        cert_not_after: 0,
    };
    if supplied.contains("tls.cert")
        && let Some(b) = read(&mut errors, "tls.cert", &cfg.tls.cert)
    {
        match check_pem(&b, PemKind::Certificate)
            .and_then(|()| check_expiry(&b, now, cfg.tls.min_server_cert_days))
        {
            Ok(na) => {
                files.cert_not_after = na;
                files.cert = Some(b);
            }
            Err(m) => errors.push(cerr("tls.cert", m)),
        }
    }
    if supplied.contains("tls.key")
        && let Some(b) = read(&mut errors, "tls.key", &cfg.tls.key)
    {
        match check_pem(&b, PemKind::PrivateKey) {
            Ok(()) => files.key = Some(b),
            Err(m) => errors.push(cerr("tls.key", m)),
        }
    }
    if !cfg.tls.revocation_list.is_empty()
        && let Some(b) = read(&mut errors, "tls.revocation_list", &cfg.tls.revocation_list)
    {
        match String::from_utf8(b)
            .map_err(|_| "not valid UTF-8".to_owned())
            .and_then(|t| parse_revocation_list(&t))
        {
            Ok(v) => files.revoked = v,
            Err(m) => errors.push(cerr("tls.revocation_list", m)),
        }
    }
    for (key, supplied_key, list, out) in [
        (
            "trust.operational",
            supplied.contains("trust.operational"),
            &cfg.trust.operational,
            0,
        ),
        ("trust.bootstrap", true, &cfg.trust.bootstrap, 1),
    ] {
        if !supplied_key {
            continue;
        }
        for name in list {
            let Some(b) = read(&mut errors, key, name) else {
                continue;
            };
            match check_pem(&b, PemKind::Certificate)
                .and_then(|()| check_expiry(&b, now, cfg.trust.min_anchor_days))
            {
                Ok(_) => {
                    if out == 0 {
                        files.operational.push(b);
                    } else {
                        files.bootstrap.push(b);
                    }
                }
                Err(m) => errors.push(cerr(key, format!("{name}: {m}"))),
            }
        }
    }
    if supplied.contains("control.public_key")
        && let Some(b) = read(&mut errors, "control.public_key", &cfg.control.public_key)
    {
        match urmqtt_control::parse_public_key(&b) {
            Some(k) => files.control_key = Some(k),
            None => errors.push(cerr(
                "control.public_key",
                "expected an Ed25519 public key (BEGIN PUBLIC KEY, `openssl pkey -pubout`)",
            )),
        }
    }
    if errors.is_empty() {
        Ok(files)
    } else {
        Err(errors)
    }
}

fn build(cfg: &Config, f: &Files) -> Result<Builder, urmqtt_cfg::CfgError> {
    let mut b = Builder::new();
    b.str(tag::ENV, &cfg.env)?;
    match cfg.network.mode {
        NetworkMode::Dhcp => {}
        NetworkMode::Static { address, gateway } => {
            b.variant(tag::NET_MODE, 1)?;
            b.cidr(tag::NET_ADDRESS, address.addr.octets(), address.prefix_len)?;
            b.ipv4(tag::NET_GATEWAY, gateway.octets())?;
        }
        NetworkMode::Auto {
            address,
            gateway,
            dhcp_timeout_s,
        } => {
            b.variant(tag::NET_MODE, 2)?;
            b.cidr(tag::NET_ADDRESS, address.addr.octets(), address.prefix_len)?;
            b.ipv4(tag::NET_GATEWAY, gateway.octets())?;
            b.uint(tag::NET_DHCP_TIMEOUT, u64::from(dhcp_timeout_s))?;
        }
    }
    b.uint(tag::NET_TLS_PORT, u64::from(cfg.network.mqtt_tls_port))?;
    b.uint(
        tag::NET_PLAIN_PORT,
        u64::from(cfg.network.mqtt_plain_port.unwrap_or(0)),
    )?;
    if let Some(c) = &f.cert {
        b.bin(tag::TLS_CERT, c)?;
    }
    if let Some(k) = &f.key {
        b.bin(tag::TLS_KEY, k)?;
    }
    b.variant(
        tag::TLS_IDENTITY,
        match cfg.tls.identity_field {
            crate::IdentityField::Cn => 0,
            crate::IdentityField::SanUri => 1,
        },
    )?;
    b.bool(tag::TLS_RESUMPTION, cfg.tls.resumption)?;
    b.strs(tag::TLS_REVOKED, &f.revoked)?;
    b.uint(
        tag::TLS_MIN_CERT_DAYS,
        u64::from(cfg.tls.min_server_cert_days),
    )?;
    b.uint(tag::TLS_CERT_NOT_AFTER, f.cert_not_after)?;
    b.bins(tag::TRUST_OPERATIONAL, &f.operational)?;
    b.bins(tag::TRUST_BOOTSTRAP, &f.bootstrap)?;
    let l = &cfg.limits;
    b.uint(tag::LIM_CONNECTIONS, u64::from(l.max_connections_per_core))?;
    b.uint(tag::LIM_PACKET, u64::from(l.max_packet_size))?;
    b.uint(tag::LIM_TOPIC_LEN, u64::from(l.max_topic_len))?;
    b.uint(tag::LIM_TOPIC_LEVELS, u64::from(l.max_topic_levels))?;
    b.uint(
        tag::LIM_SUBSCRIPTIONS,
        u64::from(l.max_subscriptions_per_session),
    )?;
    b.uint(tag::LIM_INFLIGHT, u64::from(l.max_inflight_qos1))?;
    b.uint(tag::LIM_QUEUED, u64::from(l.max_queued_per_offline_session))?;
    b.uint(
        tag::LIM_RETAINED_PER_DEVICE,
        u64::from(l.max_retained_per_device),
    )?;
    b.uint(tag::LIM_RETAINED_BYTES, l.max_retained_bytes)?;
    b.rate(
        tag::LIM_PUBLISH_RATE,
        l.publish_rate_per_device.tokens,
        l.publish_rate_per_device.per_ms,
    )?;
    b.uint(
        tag::LIM_HANDSHAKES_PER_SEC,
        u64::from(l.handshakes_per_core_per_sec),
    )?;
    b.uint(
        tag::LIM_HANDSHAKES_CORE,
        u64::from(l.max_handshakes_in_flight_per_core),
    )?;
    b.uint(
        tag::LIM_HANDSHAKES_IP,
        u64::from(l.max_handshakes_in_flight_per_ip),
    )?;
    let a = &cfg.acl;
    b.strs(tag::ACL_DEVICE_PUBLISH, &a.device_publish)?;
    b.strs(tag::ACL_DEVICE_SUBSCRIBE, &a.device_subscribe)?;
    b.strs(tag::ACL_SERVICE_IDS, &a.service_ids)?;
    b.strs(tag::ACL_SERVICE_PUBLISH, &a.service_publish)?;
    b.strs(tag::ACL_SERVICE_SUBSCRIBE, &a.service_subscribe)?;
    b.strs(tag::ACL_OPERATOR_IDS, &a.operator_ids)?;
    let s = &cfg.storage;
    b.variant(
        tag::ST_MODE,
        match s.mode {
            crate::StorageMode::Disk => 0,
            crate::StorageMode::Auto => 1,
            crate::StorageMode::Ram => 2,
        },
    )?;
    b.uint(tag::ST_RAM_PERCENT, u64::from(s.ram_percent))?;
    b.bool(tag::ST_DIAGNOSTIC, s.diagnostic)?;
    b.uint(tag::ST_SQLITE_HEAP, u64::from(s.sqlite_heap_mb))?;
    b.strs(tag::ST_TELEMETRY, &s.telemetry_topics)?;
    b.uint(tag::ST_RETENTION, u64::from(s.retention_days))?;
    b.uint(tag::ST_GROW_RATIO, u64::from(s.grow_ratio_db))?;
    b.variant(
        tag::ST_DISCARD,
        match s.discard {
            crate::DiscardMode::Auto => 0,
            crate::DiscardMode::Off => 1,
        },
    )?;
    b.uint(tag::ST_BACKUP_INTERVAL, u64::from(s.backup_interval_min))?;
    b.bool(tag::ST_AUTO_RESTORE, s.auto_restore)?;
    b.uint(tag::ST_SCRUB_INTERVAL, u64::from(s.scrub_interval_h))?;
    b.uint(tag::ST_SCRUB_BUDGET, u64::from(s.scrub_io_budget_mb_s))?;
    b.bool(tag::ST_REQUIRE_FLUSH, s.require_flush)?;
    b.bool(tag::ST_REQUIRE_DATA_DISK, s.require_data_disk)?;
    b.bool(tag::ST_REFUSE_ON_CORRUPTION, s.refuse_on_corruption)?;
    let o = &cfg.observability;
    b.variant(
        tag::OBS_LOG_LEVEL,
        variant(fields::LOG_LEVELS, log_level_name(o.log_level)),
    )?;
    if let Some(x) = &o.syslog_udp {
        let (ip, port) = sock(x);
        b.addr(tag::OBS_SYSLOG, ip, port)?;
    }
    if let Some(x) = &o.metrics_udp {
        let (ip, port) = sock(x);
        b.addr(tag::OBS_METRICS, ip, port)?;
    }
    b.uint(tag::WD_HANDLER, u64::from(cfg.watchdog.handler_budget_ms))?;
    b.uint(
        tag::WD_HANDSHAKE,
        u64::from(cfg.watchdog.handshake_budget_ms),
    )?;
    b.variant(
        tag::WD_ACTION,
        match cfg.watchdog.action {
            crate::WatchdogAction::Log => 0,
            crate::WatchdogAction::Drop => 1,
            crate::WatchdogAction::Reset => 2,
        },
    )?;
    b.uint(tag::MEM_HEAP, u64::from(cfg.memory.kernel_heap_mb))?;
    b.uint(tag::MEM_MIN_FREE, u64::from(cfg.memory.min_free_mb))?;
    b.variant(tag::ENTROPY_JITTER, u8::from(!cfg.entropy.jitter_fallback))?;
    b.strs(tag::CPU_DISABLE, &cfg.cpu.disable)?;
    b.bool(tag::CPU_DISPATCHER_SERVES, cfg.cpu.dispatcher_serves)?;
    let servers: Vec<([u8; 4], u16)> = cfg.time.servers.iter().map(sock).collect();
    b.addrs(tag::TIME_SERVERS, &servers)?;
    b.uint(tag::TIME_INTERVAL, u64::from(cfg.time.interval_s))?;
    b.uint(tag::TIME_MAX_STEP, u64::from(cfg.time.max_step_s))?;
    b.variant(
        tag::REG_ALLOWLIST,
        u8::from(cfg.registry == RegistryMode::Allowlist),
    )?;
    if let Some(k) = &f.control_key {
        b.key32(tag::CTL_PUBLIC_KEY, k)?;
    }
    b.strs(tag::CTL_SERVICE_IDS, &cfg.control.service_ids)?;
    b.bool(tag::CTL_ALLOW_UNREVOKE, cfg.control.allow_unrevoke)?;
    b.uint(tag::CTL_MAX_AGE, u64::from(cfg.control.max_message_age_s))?;
    Ok(b)
}

/// Packs `toml_text` into an unsigned blob. A top-level `env = "..."` picks
/// the environment (default `prod`). Missing keys take the defaults; every
/// problem found is returned.
pub fn pack(toml_text: &str, mut opts: PackOptions<'_>) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut user: toml::Table = toml_text
        .parse()
        .map_err(|e: toml::de::Error| vec![cerr("", e.to_string())])?;
    let toml_env = match user.remove("env") {
        None => None,
        Some(toml::Value::String(s)) => Some(s),
        Some(_) => return Err(vec![cerr("env", "must be a string")]),
    };
    let env = match (toml_env, opts.env) {
        (Some(a), Some(b)) if a != b => {
            return Err(vec![cerr(
                "env",
                format!("the configuration says {a:?}, the command line {b:?}"),
            )]);
        }
        (Some(a), _) => a,
        (None, Some(b)) => b.to_owned(),
        (None, None) => fields::by_tag(tag::ENV)
            .and_then(|f| match f.kind {
                Kind::Str { default, .. } => Some(default.to_owned()),
                _ => None,
            })
            .unwrap_or_default(),
    };
    let (text, supplied) = complete(&user)?;
    let cfg = parse(&env, &text)?;
    let files = read_files(&cfg, &supplied, &mut opts)?;
    let builder = build(&cfg, &files).map_err(blob_err)?;
    // Packed for a dev kernel when the environment is dev; otherwise the
    // strictest check (a release kernel).
    builder.finish(cfg.env == "dev").map_err(blob_err)
}

// --- the schema as JSON, for the web form ----------------------------------

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json_list(items: &[&str]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| json_str(s))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// The field table as JSON: for each field its key, section, type, default,
/// range, help text and whether it is allowed outside the dev environment.
/// The web form is generated from this, so its defaults are the validator's.
pub fn schema_json() -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "{{\"format\":\"urmqtt-cfg\",\"format_version\":{},\"slot_size\":{},\"fields\":[",
        urmqtt_cfg::FORMAT_VERSION,
        urmqtt_cfg::SLOT_SIZE
    ));
    for (i, f) in fields::FIELDS.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let (section, name) = f.key.split_once('.').unwrap_or(("", f.key));
        let toml_key = match f.key {
            "tls.revoked_serials" => "tls.revocation_list",
            k => k,
        };
        let detail = match f.kind {
            Kind::Bool(d) => format!("\"type\":\"bool\",\"default\":{d}"),
            Kind::UInt {
                min, max, default, ..
            } => format!("\"type\":\"uint\",\"default\":{default},\"min\":{min},\"max\":{max}"),
            Kind::Enum { variants, default } => format!(
                "\"type\":\"enum\",\"default\":{},\"variants\":{}",
                json_str(variants.get(usize::from(default)).copied().unwrap_or("")),
                json_list(variants)
            ),
            Kind::Str { max, default } => {
                format!(
                    "\"type\":\"string\",\"default\":{},\"max_len\":{max}",
                    json_str(default)
                )
            }
            Kind::Strs {
                max_items,
                max_len,
                default,
            } => format!(
                "\"type\":\"string_list\",\"default\":{},\"max_items\":{max_items},\"max_len\":{max_len}",
                json_list(default)
            ),
            Kind::Rate { tokens, per_ms } => format!(
                "\"type\":\"rate\",\"default\":{}",
                json_str(&rate_text(tokens, per_ms))
            ),
            Kind::Bin { max } => format!("\"type\":\"pem\",\"default\":null,\"max_bytes\":{max}"),
            Kind::BinList { max_items, max } => format!(
                "\"type\":\"pem_list\",\"default\":[],\"max_items\":{max_items},\"max_bytes\":{max}"
            ),
            Kind::Ipv4 => "\"type\":\"ipv4\",\"default\":null".to_owned(),
            Kind::Cidr => "\"type\":\"cidr\",\"default\":null".to_owned(),
            Kind::Addr => "\"type\":\"socket_addr\",\"default\":null".to_owned(),
            Kind::Addrs { max_items } => {
                format!("\"type\":\"socket_addr_list\",\"default\":[],\"max_items\":{max_items}")
            }
            Kind::Key32 => "\"type\":\"ed25519_public_key\",\"default\":null".to_owned(),
        };
        o.push_str(&format!(
            "{{\"tag\":{},\"key\":{},\"section\":{},\"name\":{},\"toml_key\":{},{detail},\"help\":{},\"dev_only\":{},\"derived\":{},\"stored\":{}}}",
            f.tag,
            json_str(f.key),
            json_str(section),
            json_str(name),
            json_str(toml_key),
            json_str(f.help),
            f.dev_only,
            f.derived,
            f.stored
        ));
    }
    o.push_str("]}\n");
    o
}
