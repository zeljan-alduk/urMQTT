//! The rules that span fields, run on a parsed [`Blob`]: by the packer
//! before it writes a blob, and by the kernel at every boot (fail closed).
//! They mirror `urmqtt-config-schema`'s validators on the TOML form; the
//! conformance tests in that crate check that both accept and refuse the
//! same configurations.

use crate::blob::Blob;
use crate::fields::{self, tag};
use crate::{CfgError, err};

/// Whether `env` is a valid environment name: `[a-z0-9-]+`.
pub fn valid_env(env: &str) -> bool {
    !env.is_empty()
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a configuration may use development options: the blob says
/// `env = "dev"` and the code running the check is a dev build.
pub const DEV_ENV: &str = "dev";

/// How `{id}` may appear in a topic filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    Allowed,
    Forbidden,
}

/// Placeholder for the device id in ACL patterns.
pub const ID_PLACEHOLDER: &str = "{id}";

/// Validates an MQTT topic filter (MQTT 3.1.1 section 4.7) against the
/// limits; `{id}` is accepted only as a whole level and only when allowed.
pub fn check_topic_filter(
    key: &'static str,
    filter: &str,
    max_len: u64,
    max_levels: u64,
    placeholder: Placeholder,
) -> Result<(), CfgError> {
    if filter.is_empty() {
        return Err(err(key, "topic filter must not be empty"));
    }
    if filter.len() as u64 > max_len {
        return Err(err(key, "a filter is longer than limits.max_topic_len"));
    }
    if filter.contains('\0') {
        return Err(err(key, "a filter contains a NUL character"));
    }
    let levels = filter.split('/').count() as u64;
    if levels > max_levels {
        return Err(err(
            key,
            "a filter has more than limits.max_topic_levels levels",
        ));
    }
    let last = levels.saturating_sub(1);
    for (i, level) in filter.split('/').enumerate() {
        if level.contains('#') && (level != "#" || i as u64 != last) {
            return Err(err(key, "'#' must be the whole last level"));
        }
        if level.contains('+') && level != "+" {
            return Err(err(key, "'+' must be a whole level"));
        }
        if level.contains(['{', '}']) {
            if level != ID_PLACEHOLDER {
                return Err(err(key, "braces are only allowed as the whole level {id}"));
            }
            if placeholder == Placeholder::Forbidden {
                return Err(err(key, "{id} is not allowed here"));
            }
        }
    }
    let first = filter.split('/').next();
    if first == Some("$urmqtt") {
        return Err(err(
            key,
            "the $urmqtt/ namespace is reserved for the control channel",
        ));
    }
    if first == Some("$SYS") {
        return Err(err(
            key,
            "the $SYS/ namespace belongs to acl.operator_ids; no pattern grants it",
        ));
    }
    Ok(())
}

/// Identity patterns: an exact id, or a prefix ending in `*`.
pub fn check_identity_pattern(key: &'static str, p: &str) -> Result<(), CfgError> {
    let core = p.strip_suffix('*').unwrap_or(p);
    if core.is_empty() && !p.ends_with('*') {
        return Err(err(key, "empty identity pattern"));
    }
    if !core
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(err(
            key,
            "identities use [A-Za-z0-9-_.:], `*` only at the end",
        ));
    }
    Ok(())
}

fn exact_identity(key: &'static str, id: &str) -> Result<(), CfgError> {
    if id.ends_with('*') || check_identity_pattern(key, id).is_err() {
        return Err(err(
            key,
            "must be an exact identity ([A-Za-z0-9-_.:]+, no wildcard)",
        ));
    }
    Ok(())
}

fn filters(
    key: &'static str,
    b: &Blob<'_>,
    t: u16,
    max_len: u64,
    max_levels: u64,
    ph: Placeholder,
) -> Result<(), CfgError> {
    b.strs(t)
        .try_for_each(|f| check_topic_filter(key, f, max_len, max_levels, ph))
}

fn is_hex_serial(s: &str) -> bool {
    let s = s.as_bytes();
    s.len().is_multiple_of(2)
        && s.len() <= 40
        && !s.is_empty()
        && s.iter().all(u8::is_ascii_hexdigit)
}

/// Checks the whole configuration. `dev_allowed`: the code running this
/// check may accept development options (a dev kernel, or a host tool
/// packing for the dev environment). Even then they are accepted only for
/// `env = "dev"`.
pub fn check(b: &Blob<'_>, dev_allowed: bool) -> Result<(), CfgError> {
    let env = b.str(tag::ENV);
    if !valid_env(env) {
        return Err(err("env", "must match [a-z0-9-]+"));
    }
    let dev = env == DEV_ENV;
    if dev && !dev_allowed {
        return Err(err(
            "env",
            "the dev environment is refused by a release kernel",
        ));
    }
    // Development-only fields: any value other than the default needs dev.
    if !dev {
        for (f, v) in b.present() {
            if f.dev_only && !is_default(f, v) {
                return Err(err(
                    f.key,
                    "development option, refused outside env = \"dev\"",
                ));
            }
        }
    }

    network(b, dev)?;
    let limits = limits(b)?;
    let (max_len, max_levels) = limits;
    filters(
        "acl.device_publish",
        b,
        tag::ACL_DEVICE_PUBLISH,
        max_len,
        max_levels,
        Placeholder::Allowed,
    )?;
    filters(
        "acl.device_subscribe",
        b,
        tag::ACL_DEVICE_SUBSCRIBE,
        max_len,
        max_levels,
        Placeholder::Allowed,
    )?;
    filters(
        "acl.service_publish",
        b,
        tag::ACL_SERVICE_PUBLISH,
        max_len,
        max_levels,
        Placeholder::Allowed,
    )?;
    filters(
        "acl.service_subscribe",
        b,
        tag::ACL_SERVICE_SUBSCRIBE,
        max_len,
        max_levels,
        Placeholder::Allowed,
    )?;
    filters(
        "storage.telemetry_topics",
        b,
        tag::ST_TELEMETRY,
        max_len,
        max_levels,
        Placeholder::Forbidden,
    )?;
    for id in b.strs(tag::ACL_SERVICE_IDS) {
        check_identity_pattern("acl.service_ids", id)?;
    }
    for (seen, id) in b.strs(tag::ACL_OPERATOR_IDS).enumerate() {
        exact_identity("acl.operator_ids", id)?;
        if b.strs(tag::ACL_SERVICE_IDS)
            .any(|p| match p.strip_suffix('*') {
                Some(prefix) => id.starts_with(prefix),
                None => p == id,
            })
        {
            return Err(err(
                "acl.operator_ids",
                "also matches acl.service_ids: an identity has one role",
            ));
        }
        if b.strs(tag::ACL_OPERATOR_IDS).take(seen).any(|o| o == id) {
            return Err(err("acl.operator_ids", "listed twice"));
        }
    }
    for id in b.strs(tag::CTL_SERVICE_IDS) {
        exact_identity("control.service_ids", id)?;
    }
    if b.strs(tag::CTL_SERVICE_IDS).next().is_some() && b.key32(tag::CTL_PUBLIC_KEY).is_none() {
        return Err(err(
            "control.public_key",
            "required when control.service_ids is not empty",
        ));
    }

    storage(b, dev)?;
    memory(b)?;
    for s in b.strs(tag::TLS_REVOKED) {
        if !is_hex_serial(s) {
            return Err(err(
                "tls.revocation_list",
                "an entry is not a hex certificate serial",
            ));
        }
    }
    for s in b.strs(tag::CPU_DISABLE) {
        if urmqtt_dispatch::Feature::from_name(s).is_none() {
            return Err(err("cpu.disable", "unknown feature"));
        }
    }
    for (i, s) in b.strs(tag::CPU_DISABLE).enumerate() {
        if b.strs(tag::CPU_DISABLE).take(i).any(|o| o == s) {
            return Err(err("cpu.disable", "a feature is listed twice"));
        }
    }
    time(b)?;
    for (key, t) in [
        ("observability.syslog_udp", tag::OBS_SYSLOG),
        ("observability.metrics_udp", tag::OBS_METRICS),
    ] {
        if let Some((_, port)) = b.addr(t)
            && port == 0
        {
            return Err(err(key, "port must not be 0"));
        }
    }
    // The same CA may not be both operational and bootstrap.
    for o in b.bins(tag::TRUST_OPERATIONAL) {
        if b.bins(tag::TRUST_BOOTSTRAP).any(|x| x == o) {
            return Err(err(
                "trust.bootstrap",
                "a CA cannot be both operational and bootstrap",
            ));
        }
    }
    // Certificate and key come together.
    if b.bin(tag::TLS_CERT).is_empty() != b.bin(tag::TLS_KEY).is_empty() {
        return Err(err(
            "tls.cert",
            "tls.cert and tls.key must be given together",
        ));
    }
    Ok(())
}

/// Whether the stored value `v` equals the field's default.
fn is_default(f: &fields::Field, v: &[u8]) -> bool {
    match f.kind {
        fields::Kind::Bool(d) => v == [u8::from(d)],
        fields::Kind::UInt { default, .. } => {
            v.iter()
                .take(8)
                .enumerate()
                .fold(0u64, |a, (i, x)| a | (u64::from(*x) << (8 * i)))
                == default
        }
        _ => false,
    }
}

fn network(b: &Blob<'_>, dev: bool) -> Result<(), CfgError> {
    let mode = b.variant(tag::NET_MODE); // 0 dhcp, 1 static, 2 auto
    let has_addr = b.cidr(tag::NET_ADDRESS).is_some();
    let has_gw = b.ipv4(tag::NET_GATEWAY).is_some();
    if mode == 0 {
        if has_addr || has_gw {
            return Err(err(
                "network",
                "address/gateway are only allowed with mode = \"static\" or \"auto\"",
            ));
        }
        if b.raw(tag::NET_DHCP_TIMEOUT).is_some() {
            return Err(err(
                "network.dhcp_timeout_s",
                "only allowed with mode = \"auto\"",
            ));
        }
    } else {
        if !has_addr {
            return Err(err(
                "network.address",
                "required when mode is static or auto",
            ));
        }
        if !has_gw {
            return Err(err(
                "network.gateway",
                "required when mode is static or auto",
            ));
        }
        if mode == 1 && b.raw(tag::NET_DHCP_TIMEOUT).is_some() {
            return Err(err(
                "network.dhcp_timeout_s",
                "only allowed with mode = \"auto\"",
            ));
        }
    }
    let tls_port = b.uint(tag::NET_TLS_PORT);
    let plain = b.uint(tag::NET_PLAIN_PORT);
    if plain != 0 {
        if !dev {
            return Err(err(
                "network.mqtt_plain_port",
                "plaintext MQTT is only allowed in env = \"dev\"",
            ));
        }
        if plain == tls_port {
            return Err(err(
                "network.mqtt_plain_port",
                "must differ from mqtt_tls_port",
            ));
        }
    }
    Ok(())
}

/// Checks the limits and returns `(max_topic_len, max_topic_levels)`.
fn limits(b: &Blob<'_>) -> Result<(u64, u64), CfgError> {
    let packet = b.uint(tag::LIM_PACKET);
    let topic = b.uint(tag::LIM_TOPIC_LEN);
    if topic >= packet {
        return Err(err(
            "limits.max_topic_len",
            "must be smaller than limits.max_packet_size",
        ));
    }
    // Every data core keeps a replica of the retained messages: with up to
    // eight of them the budget may take an eighth of the heap.
    let heap = b.uint(tag::MEM_HEAP) << 20;
    let retained = b.uint(tag::LIM_RETAINED_BYTES);
    if retained == 0 || retained > heap / 8 {
        return Err(err(
            "limits.max_retained_bytes",
            "must be in 1..=an eighth of memory.kernel_heap_mb",
        ));
    }
    Ok((topic, b.uint(tag::LIM_TOPIC_LEVELS)))
}

fn storage(b: &Blob<'_>, dev: bool) -> Result<(), CfgError> {
    // Durability shortcuts are for development only (ADR-030): also covered
    // by the dev-only table check, kept here as the explicit rule.
    if !dev {
        for (key, t) in [
            ("storage.require_flush", tag::ST_REQUIRE_FLUSH),
            ("storage.require_data_disk", tag::ST_REQUIRE_DATA_DISK),
            ("storage.refuse_on_corruption", tag::ST_REFUSE_ON_CORRUPTION),
        ] {
            if !b.bool(t) {
                return Err(err(key, "may only be false in env = \"dev\""));
            }
        }
    }
    Ok(())
}

fn memory(b: &Blob<'_>) -> Result<(), CfgError> {
    let heap = b.uint(tag::MEM_HEAP);
    if !heap.is_power_of_two() {
        return Err(err(
            "memory.kernel_heap_mb",
            "must be a power of two (the heap is one buddy region)",
        ));
    }
    if b.uint(tag::MEM_MIN_FREE) >= heap {
        return Err(err(
            "memory.min_free_mb",
            "must be smaller than memory.kernel_heap_mb",
        ));
    }
    Ok(())
}

fn time(b: &Blob<'_>) -> Result<(), CfgError> {
    for (n, (ip, port)) in b.addrs(tag::TIME_SERVERS).enumerate() {
        let [a, ..] = ip;
        let unusable = port == 0
            || ip == [0, 0, 0, 0]
            || ip == [255, 255, 255, 255]
            || (224..=239).contains(&a)
            || a == 127;
        if unusable {
            return Err(err(
                "time.servers",
                "not 0.0.0.0, loopback, multicast, broadcast, port 0",
            ));
        }
        if b.addrs(tag::TIME_SERVERS).take(n).any(|x| x == (ip, port)) {
            return Err(err("time.servers", "a server is listed twice"));
        }
    }
    Ok(())
}
