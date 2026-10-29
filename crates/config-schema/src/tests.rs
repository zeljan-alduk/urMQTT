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

/// Replaces exactly one line starting with `key =` in the dev config.
fn dev_with(key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    let mut replaced = 0;
    let out: Vec<String> = DEV
        .lines()
        .map(|l| {
            if l.starts_with(&prefix) {
                replaced += 1;
                line.to_owned()
            } else {
                l.to_owned()
            }
        })
        .collect();
    assert_eq!(replaced, 1, "key {key} must appear exactly once");
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
    assert_eq!(cfg.observability.syslog_udp, None);
}

#[test]
fn shipped_prod_config_is_valid_and_has_no_plaintext() {
    let cfg = parse("prod", PROD).unwrap();
    assert_eq!(cfg.network.mqtt_plain_port, None);
    assert_eq!(cfg.watchdog.action, WatchdogAction::Reset);
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
        &dev_with("ca", "ca = \"../../etc/ca.pem\""),
        "tls.ca",
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
    .replace("syslog_udp = \"\"", "syslog_udp = \"10.0.0.5:514\"");
    let cfg = parse("dev", &text).unwrap();
    let files = EmbeddedFiles {
        ca: "/abs/ca.pem".into(),
        cert: "/abs/server.pem".into(),
        key: "/abs/server.key".into(),
        revoked: vec!["0a1b".into()],
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
