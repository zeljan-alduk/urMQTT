use super::*;

const DEV: &str = include_str!("../../../deploy/dev/config.toml");
const PROD: &str = include_str!("../../../deploy/prod/config.toml");

fn messages(r: Result<Config, Vec<ConfigError>>) -> Vec<String> {
    match r {
        Ok(_) => Vec::new(),
        Err(e) => e.iter().map(ToString::to_string).collect(),
    }
}

fn assert_rejected(env: &str, text: &str, needle: &str) {
    let msgs = messages(parse(env, text));
    assert!(
        msgs.iter().any(|m| m.contains(needle)),
        "expected an error containing {needle:?}, got {msgs:?}"
    );
}

/// Replaces the first line starting with `key =` in the dev config (keys
/// that occur in several sections, like `mode`, hit the first one).
fn dev_with(key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    let mut replaced = 0;
    let out: Vec<String> = DEV
        .lines()
        .map(|l| {
            if replaced == 0 && l.starts_with(&prefix) {
                replaced += 1;
                line.to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect();
    assert_eq!(replaced, 1, "key {key} must appear");
    out.join("\n")
}

/// Replaces the line starting with `key =` inside `[section]`.
fn dev_in(section: &str, key: &str, line: &str) -> String {
    let header = format!("[{section}]");
    let prefix = format!("{key} =");
    let mut inside = false;
    let mut replaced = 0;
    let out: Vec<String> = DEV
        .lines()
        .map(|l| {
            if l.starts_with('[') {
                inside = l.trim() == header;
            }
            if inside && l.starts_with(&prefix) {
                replaced += 1;
                line.to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect();
    assert_eq!(replaced, 1, "[{section}] {key} must appear once");
    out.join("\n")
}

fn limits() -> Limits {
    parse("dev", DEV).unwrap().limits
}

#[test]
fn shipped_dev_config_is_valid() {
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.network.mode, NetworkMode::Dhcp);
    assert_eq!(cfg.network.mqtt_tls_port, 8883);
    assert_eq!(cfg.network.mqtt_plain_port, Some(1883));
    assert_eq!(cfg.tls.identity_field, IdentityField::Cn);
    assert_eq!(
        cfg.limits.publish_rate_per_device,
        Rate {
            tokens: 10,
            per_ms: 1000
        }
    );
    assert_eq!(cfg.acl.device_publish, vec!["devices/{id}/#".to_owned()]);
    // Dev sends to the QEMU host, where the smoke test listens.
    assert_eq!(
        cfg.observability.syslog_udp,
        Some(SocketAddrV4::new([10, 0, 2, 2].into(), 5514))
    );
    assert_eq!(parse("prod", PROD).unwrap().observability.syslog_udp, None);
}

#[test]
fn shipped_prod_config_is_valid_and_has_no_plaintext() {
    let cfg = parse("prod", PROD).unwrap();
    assert_eq!(cfg.network.mqtt_plain_port, None);
    // A slow handler costs its connection; a stuck core always resets.
    assert_eq!(cfg.watchdog.action, WatchdogAction::Drop);
}

#[test]
fn plaintext_port_rejected_outside_dev() {
    assert_rejected("prod", DEV, "plaintext MQTT is only allowed");
}

#[test]
fn plaintext_port_must_differ_from_tls_port() {
    assert_rejected(
        "dev",
        &dev_with("mqtt_plain_port", "mqtt_plain_port = 8883"),
        "must differ from mqtt_tls_port",
    );
}

#[test]
fn zero_tls_port_rejected() {
    assert_rejected(
        "dev",
        &dev_with("mqtt_tls_port", "mqtt_tls_port = 0"),
        "network.mqtt_tls_port",
    );
}

#[test]
fn out_of_range_port_is_a_toml_error() {
    assert_rejected(
        "dev",
        &dev_with("mqtt_tls_port", "mqtt_tls_port = 70000"),
        "mqtt_tls_port",
    );
}

#[test]
fn unknown_keys_rejected() {
    let text = DEV.replace("[watchdog]", "[watchdog]\nsurprise = 1");
    assert_rejected("dev", &text, "surprise");
}

#[test]
fn missing_section_rejected() {
    let text: String = DEV.split("[watchdog]").next().unwrap().to_owned();
    assert_rejected("dev", &text, "watchdog");
}

#[test]
fn invalid_env_name_rejected() {
    assert_rejected("Dev/../x", DEV, "environment name");
}

#[test]
fn static_mode_requires_address_and_gateway() {
    let text = dev_with("mode", "mode = \"static\"");
    let msgs = messages(parse("dev", &text));
    assert!(msgs.iter().any(|m| m.starts_with("network.address")));
    assert!(msgs.iter().any(|m| m.starts_with("network.gateway")));
}

#[test]
fn static_mode_parses_cidr() {
    let text = dev_with(
        "mode",
        "mode = \"static\"\naddress = \"10.0.0.10/24\"\ngateway = \"10.0.0.1\"",
    );
    let cfg = parse("dev", &text).unwrap();
    assert_eq!(
        cfg.network.mode,
        NetworkMode::Static {
            address: Ipv4Cidr {
                addr: Ipv4Addr::new(10, 0, 0, 10),
                prefix_len: 24
            },
            gateway: Ipv4Addr::new(10, 0, 0, 1),
        }
    );
}

#[test]
fn dhcp_mode_rejects_static_fields() {
    let text = dev_with("mode", "mode = \"dhcp\"\naddress = \"10.0.0.10/24\"");
    assert_rejected("dev", &text, "only allowed with mode = \"static\"");
}

#[test]
fn cidr_errors() {
    assert!(parse_cidr("10.0.0.1").is_err());
    assert!(parse_cidr("10.0.0.1/0").is_err());
    assert!(parse_cidr("10.0.0.1/33").is_err());
    assert!(parse_cidr("10.0.0/24").is_err());
    assert_eq!(parse_cidr("192.168.1.2/32").unwrap().prefix_len, 32);
}

#[test]
fn rates() {
    assert_eq!(
        parse_rate("600/m").unwrap(),
        Rate {
            tokens: 600,
            per_ms: 60_000
        }
    );
    assert_eq!(parse_rate("1/h").unwrap().per_ms, 3_600_000);
    assert!(parse_rate("0/s").is_err());
    assert!(parse_rate("10").is_err());
    assert!(parse_rate("10/d").is_err());
    assert!(parse_rate("-1/s").is_err());
    assert!(parse_rate("ten/s").is_err());
}

#[test]
fn packet_size_bounds() {
    assert_rejected(
        "dev",
        &dev_with("max_packet_size", "max_packet_size = 10"),
        "limits.max_packet_size",
    );
    assert_rejected(
        "dev",
        &dev_with("max_packet_size", "max_packet_size = 268435456"),
        "limits.max_packet_size",
    );
}

#[test]
fn topic_len_must_fit_in_packet() {
    let text = dev_with("max_packet_size", "max_packet_size = 128")
        .replace("max_topic_len = 256", "max_topic_len = 200");
    assert_rejected("dev", &text, "smaller than limits.max_packet_size");
}

#[test]
fn zero_limits_rejected() {
    assert_rejected(
        "dev",
        &dev_with("max_inflight_qos1", "max_inflight_qos1 = 0"),
        "limits.max_inflight_qos1",
    );
}

#[test]
fn topic_filters() {
    let l = limits();
    let ok = |f: &str| check_topic_filter(f, &l, Placeholder::Allowed);
    assert!(ok("devices/{id}/#").is_ok());
    assert!(ok("#").is_ok());
    assert!(ok("+/a/+").is_ok());
    assert!(ok("a//b").is_ok());
    assert!(ok("").is_err());
    assert!(ok("a/#/b").is_err());
    assert!(ok("a#").is_err());
    assert!(ok("a+/b").is_err());
    assert!(ok("devices/x{id}/#").is_err());
    assert!(ok("a\0b").is_err());
    assert!(ok(&"a/".repeat(20)).is_err());
    assert!(ok(&"a".repeat(257)).is_err());
    assert!(check_topic_filter("devices/{id}", &l, Placeholder::Forbidden).is_err());
}

#[test]
fn acl_and_telemetry_patterns_validated() {
    let text = dev_with("device_publish", "device_publish = [\"devices/#/x\"]");
    assert_rejected("dev", &text, "acl.device_publish[0]");
    let text = dev_with(
        "telemetry_topics",
        "telemetry_topics = [\"devices/{id}/t\"]",
    );
    assert_rejected("dev", &text, "storage.telemetry_topics[0]");
}

#[test]
fn service_identity_patterns() {
    assert!(check_identity_pattern("backend").is_ok());
    assert!(check_identity_pattern("svc-*").is_ok());
    assert!(check_identity_pattern("bad/id").is_err());
    assert!(check_identity_pattern("a*b").is_err());
    assert!(check_identity_pattern("").is_err());
    let text = dev_with("service_ids", "service_ids = [\"ok\", \"no+\"]");
    assert_rejected("dev", &text, "acl.service_ids[1]");
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.acl.service_ids, vec!["backend".to_owned()]);
}

#[test]
fn udp_sinks() {
    let text = dev_with("syslog_udp", "syslog_udp = \"10.0.0.5:514\"");
    let cfg = parse("dev", &text).unwrap();
    assert_eq!(
        cfg.observability.syslog_udp,
        Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 514))
    );
    assert_rejected(
        "dev",
        &dev_with("metrics_udp", "metrics_udp = \"collector:8125\""),
        "observability.metrics_udp",
    );
    assert_rejected(
        "dev",
        &dev_with("metrics_udp", "metrics_udp = \"10.0.0.5:0\""),
        "observability.metrics_udp",
    );
}

#[test]
fn enums_reject_unknown_variants() {
    assert_rejected(
        "dev",
        &dev_with("log_level", "log_level = \"verbose\""),
        "verbose",
    );
    assert_rejected("dev", &dev_with("action", "action = \"panic\""), "panic");
    assert_rejected(
        "dev",
        &dev_with("identity_field", "identity_field = \"email\""),
        "email",
    );
}

#[test]
fn watchdog_budget_bounds() {
    assert_rejected(
        "dev",
        &dev_with("handler_budget_ms", "handler_budget_ms = 0"),
        "watchdog.handler_budget_ms",
    );
}

#[test]
fn handshake_budget_is_optional_and_bounded() {
    // Absent: calibrated at boot (0).
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.watchdog.handshake_budget_ms, 0);
    let text = dev_with(
        "handler_budget_ms",
        "handler_budget_ms = 10\nhandshake_budget_ms = 250",
    );
    assert_eq!(
        parse("dev", &text).unwrap().watchdog.handshake_budget_ms,
        250
    );
    let text = dev_with(
        "handler_budget_ms",
        "handler_budget_ms = 10\nhandshake_budget_ms = 901",
    );
    assert_rejected("dev", &text, "watchdog.handshake_budget_ms");
}

#[test]
fn storage_bounds() {
    assert_rejected(
        "dev",
        &dev_with("sqlite_heap_mb", "sqlite_heap_mb = 0"),
        "storage.sqlite_heap_mb",
    );
    assert_rejected(
        "dev",
        &dev_with("retention_days", "retention_days = 0"),
        "storage.retention_days",
    );
}

/// S3: `storage.grow_ratio_db` is optional (50), a percentage.
#[test]
fn grow_ratio_db_defaults_and_bounds() {
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.storage.grow_ratio_db, 50);
    let text = DEV.replace(
        "retention_days = 30",
        "retention_days = 30\ngrow_ratio_db = 80",
    );
    assert_eq!(parse("dev", &text).unwrap().storage.grow_ratio_db, 80);
    let text = DEV.replace(
        "retention_days = 30",
        "retention_days = 30\ngrow_ratio_db = 101",
    );
    assert_rejected("dev", &text, "storage.grow_ratio_db");
    let text = DEV.replace(
        "retention_days = 30",
        "retention_days = 30\ngrow_ratio_db = 0",
    );
    assert_eq!(parse("dev", &text).unwrap().storage.grow_ratio_db, 0);
}

/// O3 (ADR-054): `storage.mode` and `storage.ram_percent`.
#[test]
fn storage_mode_and_ram_percent() {
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.storage.mode, StorageMode::Auto);
    assert_eq!(cfg.storage.ram_percent, RAM_PERCENT_DEFAULT);
    // Floor and ceiling.
    for bad in [0, RAM_PERCENT_MIN - 1, RAM_PERCENT_MAX + 1, 100] {
        assert_rejected(
            "dev",
            &dev_with("ram_percent", &format!("ram_percent = {bad}")),
            "storage.ram_percent",
        );
    }
    for ok in [RAM_PERCENT_MIN, 10, RAM_PERCENT_MAX] {
        let t = dev_with("ram_percent", &format!("ram_percent = {ok}"));
        assert_eq!(parse("dev", &t).unwrap().storage.ram_percent, ok);
    }
    // All three modes parse; anything else does not.
    for (word, mode) in [
        ("disk", StorageMode::Disk),
        ("auto", StorageMode::Auto),
        ("ram", StorageMode::Ram),
    ] {
        let t = dev_in("storage", "mode", &format!("mode = \"{word}\""));
        assert_eq!(parse("dev", &t).unwrap().storage.mode, mode);
    }
    assert_rejected(
        "dev",
        &dev_in("storage", "mode", "mode = \"memory\""),
        "mode",
    );
}

/// S4: `storage.discard` is optional ("auto"), and takes "auto" or "off".
#[test]
fn discard_defaults_to_auto_and_takes_auto_or_off() {
    // The committed dev and bench templates say so; prod leaves it out and
    // gets the default.
    assert_eq!(
        parse("dev", DEV).unwrap().storage.discard,
        DiscardMode::Auto
    );
    assert_eq!(
        parse("prod", PROD).unwrap().storage.discard,
        DiscardMode::Auto
    );
    let without: String = DEV
        .lines()
        .filter(|l| !l.starts_with("discard ="))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        parse("dev", &without).unwrap().storage.discard,
        DiscardMode::Auto
    );
    for (word, mode) in [("auto", DiscardMode::Auto), ("off", DiscardMode::Off)] {
        let t = dev_in("storage", "discard", &format!("discard = \"{word}\""));
        assert_eq!(parse("dev", &t).unwrap().storage.discard, mode);
        let t = PROD.replace(
            "retention_days = 30",
            &format!("retention_days = 30\ndiscard = \"{word}\""),
        );
        assert_eq!(parse("prod", &t).unwrap().storage.discard, mode);
    }
    for bad in [
        "discard = \"on\"",
        "discard = true",
        "discard = \"Auto\"",
        "discard = 1",
    ] {
        assert_rejected("dev", &dev_in("storage", "discard", bad), "discard");
    }
}

/// S5: `storage.backup_interval_min` (60) and `storage.auto_restore` (true)
/// are optional; production, which does not list them, gets the defaults.
#[test]
fn backup_settings_default_and_are_bounded() {
    assert_eq!(parse("dev", DEV).unwrap().storage.backup_interval_min, 60);
    assert!(parse("dev", DEV).unwrap().storage.auto_restore);
    let prod = parse("prod", PROD).unwrap();
    assert_eq!(
        prod.storage.backup_interval_min,
        BACKUP_INTERVAL_DEFAULT_MIN
    );
    assert!(prod.storage.auto_restore, "the default restores");
    // The bench template turns the backups off.
    let bench = include_str!("../../../deploy/bench/config.toml");
    assert_eq!(
        parse("bench", bench).unwrap().storage.backup_interval_min,
        0
    );
    for ok in [0, 1, 15, BACKUP_INTERVAL_MAX_MIN] {
        let t = dev_in(
            "storage",
            "backup_interval_min",
            &format!("backup_interval_min = {ok}"),
        );
        assert_eq!(parse("dev", &t).unwrap().storage.backup_interval_min, ok);
    }
    for bad in [
        format!("backup_interval_min = {}", BACKUP_INTERVAL_MAX_MIN + 1),
        "backup_interval_min = -1".to_string(),
        "backup_interval_min = \"60\"".to_string(),
        "backup_interval_min = 1.5".to_string(),
    ] {
        assert_rejected(
            "dev",
            &dev_in("storage", "backup_interval_min", &bad),
            "backup_interval_min",
        );
    }
    for (line, want) in [
        ("auto_restore = false", false),
        ("auto_restore = true", true),
    ] {
        let t = dev_in("storage", "auto_restore", line);
        assert_eq!(parse("dev", &t).unwrap().storage.auto_restore, want);
    }
    assert_rejected(
        "dev",
        &dev_in("storage", "auto_restore", "auto_restore = \"yes\""),
        "auto_restore",
    );
}

/// O3: a production configuration must choose the medium explicitly (no
/// silent default), while dev and old configs keep the disk as the default.
#[test]
fn storage_mode_is_explicit_outside_dev() {
    let without: String = PROD
        .lines()
        .filter(|l| !l.starts_with("mode = \"disk\""))
        .collect::<Vec<_>>()
        .join("\n");
    assert_rejected("prod", &without, "storage.mode");
    // The committed template says "disk": prod is safe by default.
    assert_eq!(parse("prod", PROD).unwrap().storage.mode, StorageMode::Disk);
    // Dev may omit it: the disk.
    let dev_without: String = DEV
        .lines()
        .filter(|l| !l.starts_with("mode = \"auto\""))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        parse("dev", &dev_without).unwrap().storage.mode,
        StorageMode::Disk
    );
    // Live-capable prod still needs every durability rule for the disk path.
    let live = PROD.replace("mode = \"disk\"", "mode = \"auto\"");
    assert_eq!(
        parse("prod", &live).unwrap().storage.mode,
        StorageMode::Auto
    );
    let live_nodisk = live.replace("require_data_disk = true", "require_data_disk = false");
    assert_rejected("prod", &live_nodisk, "storage.require_data_disk");
}

#[test]
fn kernel_heap_must_be_power_of_two() {
    assert_rejected(
        "dev",
        &dev_with("kernel_heap_mb", "kernel_heap_mb = 24"),
        "memory.kernel_heap_mb",
    );
    assert_rejected(
        "dev",
        &dev_with("kernel_heap_mb", "kernel_heap_mb = 0"),
        "memory.kernel_heap_mb",
    );
    assert_rejected(
        "dev",
        &dev_with("kernel_heap_mb", "kernel_heap_mb = 2048"),
        "memory.kernel_heap_mb",
    );
    assert_eq!(parse("dev", DEV).unwrap().memory.kernel_heap_mb, 32);
}

#[test]
fn free_heap_reserve_must_fit_the_heap() {
    for line in ["min_free_mb = 0", "min_free_mb = 32", "min_free_mb = 64"] {
        assert_rejected("dev", &dev_with("min_free_mb", line), "memory.min_free_mb");
    }
    assert_rejected(
        "dev",
        &dev_with(
            "max_handshakes_in_flight_per_core",
            "max_handshakes_in_flight_per_core = 0",
        ),
        "limits.max_handshakes_in_flight_per_core",
    );
    assert_eq!(parse("dev", DEV).unwrap().memory.min_free_mb, 4);
    assert_eq!(parse("prod", PROD).unwrap().memory.kernel_heap_mb, 1024);
}

#[test]
fn revocation_lists() {
    assert_eq!(
        parse_revocation_list("# c\nAA:BB\n\n0a1b # x\n").unwrap(),
        vec!["aabb", "0a1b"]
    );
    assert!(parse_revocation_list("xyz").is_err());
    assert!(parse_revocation_list("abc").is_err());
    assert_rejected(
        "dev",
        &dev_with("revocation_list", "revocation_list = \"../r.txt\""),
        "tls.revocation_list",
    );
}

#[test]
fn file_names_must_stay_in_env_dir() {
    for bad in ["", ".", "..", "../x.pem", "a/b.pem", ".hidden", "c:\\x"] {
        assert!(check_file_name(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(check_file_name("server.pem").is_ok());
    assert_rejected(
        "dev",
        &dev_with("cert", "cert = \"../../etc/server.pem\""),
        "tls.cert",
    );
    assert_rejected(
        "dev",
        &dev_with("operational", r#"operational = ["../ca.pem"]"#),
        "trust.operational[0]",
    );
}

#[test]
fn all_errors_reported_together() {
    let text = dev_with("max_inflight_qos1", "max_inflight_qos1 = 0")
        .replace("retention_days = 30", "retention_days = 0");
    let msgs = messages(parse("dev", &text));
    assert_eq!(msgs.len(), 2, "{msgs:?}");
}

#[test]
fn pem_checks() {
    let cert = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    let key = b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
    let ec = b"-----BEGIN EC PRIVATE KEY-----\nMIIB\n-----END EC PRIVATE KEY-----\n";
    let enc = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
    assert!(check_pem(cert, PemKind::Certificate).is_ok());
    assert!(check_pem(key, PemKind::PrivateKey).is_ok());
    assert!(check_pem(ec, PemKind::PrivateKey).is_ok());
    assert!(check_pem(key, PemKind::Certificate).is_err());
    assert!(check_pem(cert, PemKind::PrivateKey).is_err());
    assert!(
        check_pem(enc, PemKind::PrivateKey)
            .unwrap_err()
            .contains("encrypted")
    );
    assert!(check_pem(&[0xff, 0xfe], PemKind::Certificate).is_err());
    let both = [&key[..], &cert[..]].concat();
    assert!(check_pem(&both, PemKind::PrivateKey).is_err());
}

#[test]
fn render_contains_validated_values() {
    let text = dev_with(
        "mode",
        "mode = \"static\"\naddress = \"10.0.0.10/24\"\ngateway = \"10.0.0.1\"",
    )
    .replace(
        "syslog_udp = \"10.0.2.2:5514\"",
        "syslog_udp = \"10.0.0.5:514\"",
    )
    .replace("metrics_udp = \"10.0.2.2:8125\"", "metrics_udp = \"\"");
    let cfg = parse("dev", &text).unwrap();
    let files = EmbeddedFiles {
        operational: vec!["/abs/ca.pem".into(), "/abs/ca-2.pem".into()],
        bootstrap: vec![],
        cert: "/abs/server.pem".into(),
        key: "/abs/server.key".into(),
        revoked: vec!["0a1b".into()],
        control_public_key: [7; 32],
        server_cert_not_after: 1_900_000_000,
    };
    let out = render(&cfg, &files);
    assert!(out.contains("addr: [10, 0, 0, 10], prefix_len: 24"));
    assert!(out.contains("gateway: [10, 0, 0, 1]"));
    assert!(out.contains("mqtt_plain_port: Some(1883)"));
    assert!(out.contains("Rate { tokens: 10, per_ms: 1000 }"));
    assert!(out.contains(r#"device_publish: &["devices/{id}/#"]"#));
    assert!(out.contains("syslog_udp: Some(SocketAddrV4 { addr: [10, 0, 0, 5], port: 514 })"));
    assert!(out.contains("metrics_udp: None"));
    assert!(out.contains("LogLevel::Debug"));
    assert!(out.contains(r#"include_bytes!("/abs/server.key")"#));
    assert!(out.contains("kernel_heap_mb: 32"));
    assert!(out.contains(r#"revoked_serials: &["0a1b"]"#));
    assert!(out.contains(
        r#"OPERATIONAL_CA_PEMS: &[&[u8]] = &[include_bytes!("/abs/ca.pem"), include_bytes!("/abs/ca-2.pem")]"#
    ));
    assert!(out.contains("BOOTSTRAP_CA_PEMS: &[&[u8]] = &[];"));
    assert!(out.contains("CONTROL_PUBLIC_KEY: [u8; 32] = [7, 7,"));
    assert!(out.contains("server_cert_not_after: 1900000000"));
    assert!(out.contains(r#"service_ids: &["operator"]"#));
    assert!(out.contains("allowlist: false"));
}

#[test]
fn durability_shortcuts_are_dev_only() {
    for key in ["require_flush", "require_data_disk", "refuse_on_corruption"] {
        let prod = PROD
            .lines()
            .map(|l| {
                if l.starts_with(&format!("{key} =")) {
                    format!("{key} = false")
                } else {
                    l.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_rejected("prod", &prod, &format!("storage.{key}"));
        assert!(parse("dev", &dev_with(key, &format!("{key} = false"))).is_ok());
    }
}

#[test]
fn entropy_fallback_is_jitter_or_none() {
    assert!(parse("dev", DEV).unwrap().entropy.jitter_fallback);
    assert!(parse("prod", PROD).unwrap().entropy.jitter_fallback);
    let none = DEV.replace("fallback = \"jitter\"", "fallback = \"none\"");
    assert!(!parse("dev", &none).unwrap().entropy.jitter_fallback);
    let bad = DEV.replace("fallback = \"jitter\"", "fallback = \"rdrand\"");
    assert_rejected("dev", &bad, "entropy.fallback");
}

#[test]
fn cpu_disable_is_validated_against_the_dispatch_features() {
    assert!(parse("dev", DEV).unwrap().cpu.disable.is_empty());
    let some = dev_with("disable", r#"disable = ["aes", "crc32"]"#);
    assert_eq!(parse("dev", &some).unwrap().cpu.disable, ["aes", "crc32"]);
    assert_rejected(
        "dev",
        &dev_with("disable", r#"disable = ["bti"]"#),
        "cpu.disable",
    );
    assert_rejected(
        "dev",
        &dev_with("disable", r#"disable = ["aes", "aes"]"#),
        "cpu.disable",
    );
    // The section is optional: without it nothing is disabled.
    let without = DEV.replace("[cpu]", "").replace("disable = []", "");
    assert!(parse("dev", &without).unwrap().cpu.disable.is_empty());
}

#[test]
fn the_dispatcher_serves_no_connections_unless_asked() {
    // The default, in both shipped templates and without the key.
    assert!(!parse("dev", DEV).unwrap().cpu.dispatcher_serves);
    assert!(!parse("prod", PROD).unwrap().cpu.dispatcher_serves);
    let on = DEV.replace("disable = []", "disable = []\ndispatcher_serves = true");
    assert!(parse("dev", &on).unwrap().cpu.dispatcher_serves);
    assert_rejected(
        "dev",
        &DEV.replace("disable = []", "disable = []\ndispatcher_serves = \"yes\""),
        "",
    );
}

#[test]
fn trust_registry_and_control_keys() {
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.trust.operational, ["ca.pem", "ca-2.pem"]);
    assert_eq!(cfg.trust.bootstrap, ["ca-bootstrap.pem"]);
    assert_eq!(cfg.registry, RegistryMode::Open);
    assert_eq!(cfg.control.service_ids, ["operator"]);
    let prod = parse("prod", PROD).unwrap();
    assert!(
        !prod.control.allow_unrevoke,
        "prod must not allow unrevoke by default"
    );
    assert!(prod.control.service_ids.is_empty());

    let allow = dev_in("registry", "mode", r#"mode = "allowlist""#);
    assert_eq!(
        parse("dev", &allow).unwrap().registry,
        RegistryMode::Allowlist
    );
    assert_rejected("dev", &dev_in("registry", "mode", r#"mode = "closed""#), "");
    assert_rejected(
        "dev",
        &dev_with("operational", "operational = []"),
        "trust.operational",
    );
    assert_rejected(
        "dev",
        &dev_with("bootstrap", r#"bootstrap = ["ca.pem"]"#),
        "trust.bootstrap",
    );
    assert_rejected(
        "dev",
        &dev_with("min_anchor_days", "min_anchor_days = 0"),
        "trust.min_anchor_days",
    );
    for bad in [r#"["svc-*"]"#, r#"["a/b"]"#, r#"[""]"#, r#"["$x"]"#] {
        assert_rejected(
            "dev",
            &dev_in("control", "service_ids", &format!("service_ids = {bad}")),
            "control.service_ids[0]",
        );
    }
    for bad in ["0", "86401"] {
        assert_rejected(
            "dev",
            &dev_with("max_message_age_s", &format!("max_message_age_s = {bad}")),
            "control.max_message_age_s",
        );
    }
    assert_rejected(
        "dev",
        &dev_with("public_key", r#"public_key = "../k.pub""#),
        "control.public_key",
    );
}

/// PROMPT-security §2: early data must stay off; the build fails otherwise.
#[test]
fn early_data_fails_the_build() {
    assert_rejected(
        "dev",
        &dev_with("early_data", "early_data = true"),
        "tls.early_data",
    );
    assert_rejected(
        "dev",
        &dev_with("min_server_cert_days", "min_server_cert_days = 0"),
        "tls.min_server_cert_days",
    );
}

/// H1: ACL patterns may not name the reserved control namespace.
#[test]
fn acl_cannot_reach_the_reserved_namespace() {
    assert_rejected(
        "dev",
        &dev_with("service_subscribe", r#"service_subscribe = ["$urmqtt/#"]"#),
        "the $urmqtt/ namespace is reserved",
    );
}

/// H1 `expiry-build-check`: the build refuses certificates that expire too
/// soon, measured from the build time.
#[test]
fn expiry_build_check() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev");
    let Ok(pem) = std::fs::read(dir.join("server.pem")) else {
        return; // `make certs` not run
    };
    let v = cert_validity(&pem).unwrap();
    let not_after = v[0].not_after;
    let day = 86_400;
    // 61 days left: passes a 60-day minimum and returns notAfter.
    assert_eq!(check_expiry(&pem, not_after - 61 * day, 60), Ok(not_after));
    // 59 days left, or already expired: refused, with the subject named.
    let e = check_expiry(&pem, not_after - 59 * day, 60).unwrap_err();
    assert!(e.contains("CN=localhost") && e.contains("59 day"), "{e}");
    assert!(check_expiry(&pem, not_after + day, 60).is_err());
    // The CA, with the anchor minimum.
    let ca = std::fs::read(dir.join("ca.pem")).unwrap();
    let ca_after = cert_validity(&ca).unwrap()[0].not_after;
    assert!(check_expiry(&ca, ca_after - 364 * day, 365).is_err());
    assert!(check_expiry(&ca, ca_after - 366 * day, 365).is_ok());
    assert!(cert_validity(b"not a pem").is_err());
}

/// H3: the retained byte budget fits a replica per data core in the heap.
#[test]
fn retained_byte_budget_is_bounded_by_the_heap() {
    // dev heap: 32 MiB, so at most 4 MiB.
    assert!(
        parse(
            "dev",
            &dev_with("max_retained_bytes", "max_retained_bytes = 4194304")
        )
        .is_ok()
    );
    for bad in ["0", "4194305"] {
        assert_rejected(
            "dev",
            &dev_with("max_retained_bytes", &format!("max_retained_bytes = {bad}")),
            "limits.max_retained_bytes",
        );
    }
}

/// O1, O2: the operator role is a build-time list of exact identities,
/// checked like the control identities and never overlapping a service.
#[test]
fn operator_ids_are_validated() {
    let cfg = parse("dev", DEV).unwrap();
    assert_eq!(cfg.acl.operator_ids, ["operator"]);
    assert!(parse("prod", PROD).is_ok());
    assert!(
        parse("dev", &dev_with("operator_ids", "operator_ids = []"))
            .unwrap()
            .acl
            .operator_ids
            .is_empty()
    );
    for bad in [
        r#"["ops*"]"#,
        r#"["a/b"]"#,
        r#"[""]"#,
        r#"["a+"]"#,
        r#"["$SYS"]"#,
    ] {
        assert_rejected(
            "dev",
            &dev_with("operator_ids", &format!("operator_ids = {bad}")),
            "acl.operator_ids[0]",
        );
    }
    // One role per identity: not also a service (exact or by prefix).
    assert_rejected(
        "dev",
        &dev_with("operator_ids", r#"operator_ids = ["backend"]"#),
        "also matches acl.service_ids",
    );
    assert_rejected(
        "dev",
        &dev_with("service_ids", r#"service_ids = ["svc-*"]"#).replace(
            "operator_ids = [\"operator\"]",
            "operator_ids = [\"svc-ops\"]",
        ),
        "also matches acl.service_ids",
    );
    assert_rejected(
        "dev",
        &dev_with("operator_ids", r#"operator_ids = ["a", "a"]"#),
        "listed twice",
    );
    // The key is required, like every other.
    let without: String = DEV
        .lines()
        .filter(|l| !l.starts_with("operator_ids"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_rejected("dev", &without, "operator_ids");
}

/// O1, O2: no ACL pattern grants `$SYS/`; the role does.
#[test]
fn acl_cannot_grant_the_system_namespace() {
    for key in [
        "device_publish",
        "device_subscribe",
        "service_publish",
        "service_subscribe",
    ] {
        assert_rejected(
            "dev",
            &dev_with(key, &format!(r#"{key} = ["$SYS/#"]"#)),
            "the $SYS/ namespace belongs to acl.operator_ids",
        );
    }
}

/// O4 (ADR-063): `storage.diagnostic` is off unless the configuration says so.
#[test]
fn diagnostic_entry_is_off_by_default() {
    assert!(parse("dev", DEV).unwrap().storage.diagnostic);
    let off = DEV.replace("diagnostic = true", "");
    assert!(!parse("dev", &off).unwrap().storage.diagnostic);
    let bad = DEV.replace("diagnostic = true", "diagnostic = \"yes\"");
    assert!(parse("dev", &bad).is_err());
}

#[test]
fn time_servers_are_ipv4_literals_and_off_by_default() {
    let t = parse("dev", DEV).unwrap().time;
    assert!(t.servers.is_empty());
    assert_eq!((t.interval_s, t.max_step_s), (3600, 600));
    // Prod ships without a [time] section: the same defaults.
    let t = parse("prod", PROD).unwrap().time;
    assert!(t.servers.is_empty());
    let on = DEV.replace(
        "servers = []\ninterval_s = 3600",
        "servers = [\"192.0.2.1\", \"198.51.100.7:12300\"]\ninterval_s = 900",
    );
    let t = parse("dev", &on).unwrap().time;
    assert_eq!(t.servers.len(), 2);
    assert_eq!((t.servers[0].port(), t.servers[1].port()), (123, 12300));
    assert_eq!(t.interval_s, 900);
}

#[test]
fn time_rejects_names_bad_addresses_and_bad_numbers() {
    let with = |servers: &str| {
        DEV.replace(
            "servers = []\ninterval_s",
            &format!("servers = {servers}\ninterval_s"),
        )
    };
    for bad in [
        "[\"pool.ntp.org\"]",
        "[\"0.0.0.0\"]",
        "[\"127.0.0.1\"]",
        "[\"224.0.0.1\"]",
        "[\"255.255.255.255\"]",
        "[\"192.0.2.1:0\"]",
        "[\"192.0.2.1\", \"192.0.2.1\"]",
        "[\"192.0.2.1\", \"192.0.2.2\", \"192.0.2.3\", \"192.0.2.4\", \"192.0.2.5\"]",
    ] {
        assert_rejected("dev", &with(bad), "time.servers");
    }
    assert_rejected(
        "dev",
        &DEV.replace("interval_s = 3600", "interval_s = 5"),
        "time.interval_s",
    );
    assert_rejected(
        "dev",
        &DEV.replace("max_step_s = 600", "max_step_s = 0"),
        "time.max_step_s",
    );
    assert_rejected(
        "dev",
        &DEV.replace("max_step_s = 600", "max_step_s = 86401"),
        "time.max_step_s",
    );
    assert_rejected("dev", &DEV.replace("max_step_s = 600", "step = 600"), "");
}
