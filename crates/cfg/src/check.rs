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
    plaintext(b, max_len, max_levels)?;
    websocket(b, max_len, max_levels)?;
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
    // 0: from DHCP, else 1500 (NOW-19, ADR-264); otherwise a usable MTU.
    let mtu = b.uint(tag::NET_MTU);
    if mtu != 0 && mtu < fields::MIN_MTU {
        return Err(err(
            "network.mtu",
            "must be 0 (from DHCP, else 1500) or 576 to 9000",
        ));
    }
    let tls_port = b.uint(tag::NET_TLS_PORT);
    if tls_port == 0 && !b.bool(tag::PL_ENABLED) {
        return Err(err(
            "network.mqtt_tls_port",
            "0 (the TLS listener off) is only allowed with plaintext.enabled = true: a broker needs at least one listener",
        ));
    }
    let plain = b.uint(tag::NET_PLAIN_PORT);
    if plain != 0 {
        if !dev {
            return Err(err(
                "network.mqtt_plain_port",
                "plaintext MQTT is only allowed in env = \"dev\"",
            ));
        }
        if tls_port != 0 && plain == tls_port {
            return Err(err(
                "network.mqtt_plain_port",
                "must differ from mqtt_tls_port",
            ));
        }
    }
    Ok(())
}

/// Whether `id` is a role the plaintext listener never grants: a service id
/// (exact or prefix pattern), an operator or a control identity.
fn holds_other_role(b: &Blob<'_>, id: &str) -> bool {
    b.strs(tag::ACL_SERVICE_IDS)
        .any(|p| match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => p == id,
        })
        || b.strs(tag::ACL_OPERATOR_IDS).any(|o| o == id)
        || b.strs(tag::CTL_SERVICE_IDS).any(|c| c == id)
}

const ROLE_MSG: &str = "is also an acl.service_ids, acl.operator_ids or control.service_ids identity: plaintext clients never hold those roles, pick another name";

/// The `[plaintext]` section (P1, ADR-229). What is written must be well
/// formed whether or not the listener is on; what the listener needs, and
/// what must not contradict the mode, is checked when it is on.
fn plaintext(b: &Blob<'_>, max_len: u64, max_levels: u64) -> Result<(), CfgError> {
    use crate::net::Cidr;
    use crate::plain;

    let enabled = b.bool(tag::PL_ENABLED);
    let anywhere = b.bool(tag::PL_ANYWHERE);
    let auth = b.variant(tag::PL_AUTH);
    let (password, anonymous, by_ip) = (auth == 0, auth == 1, auth == 2);

    // Well-formed entries, enabled or not.
    for (n, s) in b.strs(tag::PL_ALLOW_FROM).enumerate() {
        plain::parse_allow(s).map_err(|m| err("plaintext.allow_from", m))?;
        if b.strs(tag::PL_ALLOW_FROM).take(n).any(|o| o == s) {
            return Err(err("plaintext.allow_from", "a network is listed twice"));
        }
    }
    for (n, s) in b.strs(tag::PL_USERS).enumerate() {
        let (id, _) = plain::parse_user(s).map_err(|m| err("plaintext.users", m))?;
        let earlier = b.strs(tag::PL_USERS).take(n);
        if earlier
            .filter_map(|o| o.split_once(' '))
            .any(|(other, _)| other == id)
        {
            return Err(err("plaintext.users", "an id is listed twice"));
        }
    }
    for (n, s) in b.strs(tag::PL_IP_IDENTITIES).enumerate() {
        let (net, _) =
            plain::parse_ip_identity(s).map_err(|m| err("plaintext.ip_identities", m))?;
        let dup = b
            .strs(tag::PL_IP_IDENTITIES)
            .take(n)
            .filter_map(|o| plain::parse_ip_identity(o).ok())
            .any(|(other, _)| other == net);
        if dup {
            return Err(err("plaintext.ip_identities", "a network is listed twice"));
        }
    }
    plain::check_identity(b.str(tag::PL_ANON_ID))
        .map_err(|m| err("plaintext.anonymous_identity", m))?;
    for (key, t) in [
        ("plaintext.acl_publish", tag::PL_ACL_PUBLISH),
        ("plaintext.acl_subscribe", tag::PL_ACL_SUBSCRIBE),
    ] {
        for f in b.strs(t) {
            check_topic_filter(key, f, max_len, max_levels, Placeholder::Allowed)?;
            if f.starts_with('$') {
                return Err(err(key, "no filter may start with $ (broker topics)"));
            }
        }
    }

    if !enabled {
        if anywhere {
            return Err(err(
                "plaintext.allow_from_anywhere",
                "is set but plaintext is not enabled: remove it, so the file does not look more dangerous than it is",
            ));
        }
        return Ok(());
    }

    // The listener is on: it needs its allow-list and its logins.
    let nets = b.strs(tag::PL_ALLOW_FROM).count();
    if anywhere && nets > 0 {
        return Err(err(
            "plaintext.allow_from_anywhere",
            "overrides allow_from: remove one of the two",
        ));
    }
    if !anywhere && nets == 0 {
        return Err(err(
            "plaintext.allow_from",
            "required when plaintext is enabled: the networks that may connect (for example 10.0.0.0/8), or allow_from_anywhere = true",
        ));
    }
    let port = b.uint(tag::PL_PORT);
    if b.uint(tag::NET_TLS_PORT) != 0 && port == b.uint(tag::NET_TLS_PORT) {
        return Err(err(
            "plaintext.port",
            "must differ from network.mqtt_tls_port",
        ));
    }
    if port != 0 && port == b.uint(tag::NET_PLAIN_PORT) {
        return Err(err(
            "plaintext.port",
            "must differ from network.mqtt_plain_port",
        ));
    }
    let users = b.strs(tag::PL_USERS).count();
    let ip_ids = b.strs(tag::PL_IP_IDENTITIES).count();
    let anon_id = b.str(tag::PL_ANON_ID);
    let anon_default = anon_id == "lan";
    if password {
        if users == 0 {
            return Err(err(
                "plaintext.users",
                "auth = \"password\" needs at least one account",
            ));
        }
        if ip_ids > 0 {
            return Err(err(
                "plaintext.ip_identities",
                "only used with auth = \"ip\"",
            ));
        }
        if !anon_default {
            return Err(err(
                "plaintext.anonymous_identity",
                "only used with auth = \"anonymous\"",
            ));
        }
        for s in b.strs(tag::PL_USERS) {
            let id = s.split_once(' ').map_or(s, |(id, _)| id);
            if holds_other_role(b, id) {
                return Err(err("plaintext.users", ROLE_MSG));
            }
        }
    } else if anonymous {
        if users > 0 {
            return Err(err("plaintext.users", "only used with auth = \"password\""));
        }
        if ip_ids > 0 {
            return Err(err(
                "plaintext.ip_identities",
                "only used with auth = \"ip\"",
            ));
        }
        if holds_other_role(b, anon_id) {
            return Err(err("plaintext.anonymous_identity", ROLE_MSG));
        }
    } else if by_ip {
        if ip_ids == 0 {
            return Err(err(
                "plaintext.ip_identities",
                "auth = \"ip\" needs at least one network",
            ));
        }
        if users > 0 {
            return Err(err("plaintext.users", "only used with auth = \"password\""));
        }
        if !anon_default {
            return Err(err(
                "plaintext.anonymous_identity",
                "only used with auth = \"anonymous\"",
            ));
        }
        for s in b.strs(tag::PL_IP_IDENTITIES) {
            let Ok((net, id)) = plain::parse_ip_identity(s) else {
                continue;
            };
            if holds_other_role(b, id) {
                return Err(err("plaintext.ip_identities", ROLE_MSG));
            }
            // A network outside allow_from would never match: say so.
            if !anywhere
                && !b
                    .strs(tag::PL_ALLOW_FROM)
                    .filter_map(|a| Cidr::parse(a).ok())
                    .any(|a| a.contains_net(&net))
            {
                return Err(err(
                    "plaintext.ip_identities",
                    "a network is not inside allow_from, so no client could ever match it",
                ));
            }
        }
    }
    Ok(())
}

const WS_ROLE_MSG: &str = "is also an acl.service_ids, acl.operator_ids or control.service_ids identity: password logins over WebSocket never hold those roles, pick another name";

/// The `[websocket]` section (ADR-272). As for `[plaintext]`: what is written
/// is well formed whether or not the listener is on; what the listener needs,
/// and what must not contradict the mode, is checked when it is on.
fn websocket(b: &Blob<'_>, max_len: u64, max_levels: u64) -> Result<(), CfgError> {
    use crate::plain;
    use crate::ws;

    ws::check_path(b.str(tag::WS_PATH)).map_err(|m| err("websocket.path", m))?;
    for (n, o) in b.strs(tag::WS_ORIGINS).enumerate() {
        ws::check_origin(o).map_err(|m| err("websocket.origins", m))?;
        if b.strs(tag::WS_ORIGINS).take(n).any(|x| x == o) {
            return Err(err("websocket.origins", "an origin is listed twice"));
        }
    }
    for (n, s) in b.strs(tag::WS_USERS).enumerate() {
        let (id, _) = plain::parse_user(s).map_err(|m| err("websocket.users", m))?;
        if b.strs(tag::WS_USERS)
            .take(n)
            .filter_map(|o| o.split_once(' '))
            .any(|(other, _)| other == id)
        {
            return Err(err("websocket.users", "an id is listed twice"));
        }
    }
    for (key, t) in [
        ("websocket.acl_publish", tag::WS_ACL_PUBLISH),
        ("websocket.acl_subscribe", tag::WS_ACL_SUBSCRIBE),
    ] {
        for f in b.strs(t) {
            check_topic_filter(key, f, max_len, max_levels, Placeholder::Allowed)?;
            if f.starts_with('$') {
                return Err(err(key, "no filter may start with $ (broker topics)"));
            }
        }
    }
    if !b.bool(tag::WS_ENABLED) {
        return Ok(());
    }
    // wss:// is TLS: the listener rides on the TLS listener's certificate,
    // key and trust anchors.
    let tls_port = b.uint(tag::NET_TLS_PORT);
    if tls_port == 0 {
        return Err(err(
            "websocket.enabled",
            "needs the TLS listener (network.mqtt_tls_port not 0): wss:// uses its certificate and key",
        ));
    }
    let port = b.uint(tag::WS_PORT);
    if port == tls_port {
        return Err(err(
            "websocket.port",
            "must differ from network.mqtt_tls_port",
        ));
    }
    if port == b.uint(tag::NET_PLAIN_PORT) {
        return Err(err(
            "websocket.port",
            "must differ from network.mqtt_plain_port",
        ));
    }
    if b.bool(tag::PL_ENABLED) && port == b.uint(tag::PL_PORT) {
        return Err(err("websocket.port", "must differ from plaintext.port"));
    }
    let users = b.strs(tag::WS_USERS).count();
    let origins = b.strs(tag::WS_ORIGINS).count();
    if b.variant(tag::WS_AUTH) == 1 {
        if users == 0 {
            return Err(err(
                "websocket.users",
                "auth = \"password\" needs at least one account",
            ));
        }
        if origins == 0 {
            return Err(err(
                "websocket.origins",
                "required with auth = \"password\": the web pages (https://app.example.com) that may connect; without it any web site a user visits could log in with the browser's help",
            ));
        }
        for s in b.strs(tag::WS_USERS) {
            let id = s.split_once(' ').map_or(s, |(id, _)| id);
            if holds_other_role(b, id) {
                return Err(err("websocket.users", WS_ROLE_MSG));
            }
        }
    } else if users > 0 {
        return Err(err("websocket.users", "only used with auth = \"password\""));
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
    // Encryption at rest (S7): on needs a usable key, off takes none.
    let on = b.variant(tag::ST_ENCRYPTION) != 0;
    let key = b.bin(tag::ST_DISK_KEY);
    if on {
        if crate::diskkey::check_key(key).is_err() {
            return Err(err(
                "storage.disk_key",
                "required with storage.encryption: 64 bytes, two different halves, not one repeated byte",
            ));
        }
    } else if !key.is_empty() {
        return Err(err(
            "storage.disk_key",
            "only with storage.encryption = \"aes-256-xts\"",
        ));
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
