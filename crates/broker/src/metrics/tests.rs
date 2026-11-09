//! The exposition: every `$SYS` topic has a metric (or a stated reason), the
//! rules are well formed, the text parses as the Prometheus and OpenMetrics
//! grammars say, and the numbers are the ones `$SYS` reports.

use super::*;
use crate::sys::{
    self, Backpressure, Drops, Handshakes, Info, Mqtt5Info, PlainInfo, Qos2, WsInfo, topic_names,
};
use std::collections::{BTreeMap, BTreeSet};

fn full<'a>(busy: &'a [u8], accepted: &'a [u64]) -> Info<'a> {
    Info {
        version: "0.6.0",
        uptime_s: 12_345,
        arch: "aarch64",
        busy,
        memory_total: 268_435_456,
        memory_used: 12_345_678,
        disk_total: 1_000_000_000,
        disk_used: 4096,
        clients_connected: 7,
        clients_total: 20,
        subscriptions: 33,
        retained: 5,
        messages_received: 1_000_000,
        messages_sent: 2_500_000,
        connections_refused: 3,
        server_cert_days: Some(89),
        time_source: "sntp",
        time_offset_ms: Some(-1234),
        entropy_source: "virtio-rng+rndr",
        console_dropped: 2,
        net_mtu: 1500,
        drops: Drops {
            slow_subscriber: 1,
            offline: 2,
            cross_core: 3,
            qos1_queue_full: 4,
            publish_rate: 5,
            frames_steer: 6,
            frames_worker_tx: 7,
            frames_nic: 8,
        },
        qos2: Qos2 {
            received: 10,
            duplicates: 11,
            completed: 12,
            inbound_full: 13,
        },
        backpressure: Backpressure {
            single: true,
            paused: 4,
            paused_ms: 1500,
            timeouts: 1,
            holding: 2,
        },
        mqtt5: {
            let mut m = Mqtt5Info {
                connected: 3,
                messages_expired: 9,
                dropped_too_large: 8,
                sessions_expired: 6,
                sessions_expiring: 5,
                wills_delayed: 4,
                wills_pending: 3,
                shared_groups: 2,
                shared_members: 6,
                shared_delivered: 100,
                shared_dropped: 1,
                shared_redispatched: 2,
                shared_refused: 3,
                retained_expiring: 4,
                alias_bytes: 2720,
                ..Mqtt5Info::default()
            };
            m.disconnects[0x8e - 0x80] = 7;
            m.disconnects[0x99 - 0x80] = 1;
            m.refused[0x87 - 0x80] = 5;
            m
        },
        handshakes: Handshakes {
            started: 100,
            done: 90,
            failed: 5,
            timed_out: 2,
            refused: 3,
            syn_dropped: 4,
            in_flight: 1,
            in_flight_max: 6,
            slow: 7,
            latency_sum_ms: 4500,
            latency_max_ms: 250,
        },
        accepted,
        plaintext: PlainInfo {
            enabled: true,
            port: 1884,
            auth: "password",
            allow_from: "10.0.0.0/8",
            accounts: 2,
            connections: 1,
            accepted: 9,
            refused_source: 1,
            refused_locked: 2,
            refused_limit: 3,
            refused_registry: 4,
            refused_session: 5,
            auth_ok: 6,
            auth_failed: 7,
            lockouts: 8,
        },
        websocket: WsInfo {
            enabled: true,
            port: 8084,
            path: "/mqtt",
            auth: "mtls",
            origins: 1,
            accounts: 0,
            connections: 2,
            accepted: 3,
            upgrades: 4,
            refused: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            auth_ok: 0,
            auth_failed: 0,
            lockouts: 0,
            frames_in: 11,
            frames_out: 12,
            bytes_in: 13,
            bytes_out: 14,
            closes_client: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            closes_server: [9, 8, 7, 6, 5, 4, 3, 2, 1],
            closes_abrupt: 15,
        },
    }
}

fn own() -> Own {
    Own {
        port: 9100,
        connections: 1,
        accepted: 50,
        refused_source: 2,
        refused_limit: 3,
        ok: 40,
        refused: [1, 0, 2, 0, 4],
        timeouts: 1,
    }
}

fn text(openmetrics: bool) -> String {
    let (busy, acc) = ([10u8, 55, 0, 100], [1u64, 2, 3, 4]);
    render(&full(&busy, &acc), &own(), openmetrics)
}

// ---- the table ---------------------------------------------------------------

#[test]
fn every_sys_topic_has_a_metric_or_a_reason() {
    for cores in [1usize, 4, 64] {
        for topic in topic_names(cores) {
            let rest = topic
                .strip_prefix("$SYS/broker/")
                .unwrap_or_else(|| panic!("{topic}"));
            let rule = RULES.iter().find(|r| match r.label {
                None => r.topic == rest,
                Some(_) => rest
                    .strip_prefix(r.topic)
                    .and_then(|x| x.strip_prefix('/'))
                    .is_some_and(|x| !x.is_empty() && !x.contains('/')),
            });
            let hidden = NOT_EXPOSED.iter().any(|(t, _)| *t == rest);
            assert!(
                rule.is_some() != hidden,
                "{topic}: needs exactly one of a rule in metrics::RULES or a line in NOT_EXPOSED"
            );
        }
    }
}

#[test]
fn every_rule_matches_a_topic() {
    let names: Vec<String> = topic_names(4);
    for r in RULES {
        let hit = names.iter().any(|t| {
            let rest = t.strip_prefix("$SYS/broker/").unwrap_or("");
            match r.label {
                None => rest == r.topic,
                Some(_) => rest
                    .strip_prefix(r.topic)
                    .and_then(|x| x.strip_prefix('/'))
                    .is_some_and(|x| !x.is_empty() && !x.contains('/')),
            }
        });
        assert!(hit, "{}: no $SYS topic", r.topic);
    }
    for (t, _) in NOT_EXPOSED {
        assert!(
            names.iter().any(|n| n == &format!("$SYS/broker/{t}")),
            "{t}"
        );
    }
}

#[test]
fn rules_are_well_formed() {
    let mut families: BTreeMap<&str, (Kind, &str)> = BTreeMap::new();
    let mut last = "";
    let mut closed: BTreeSet<&str> = BTreeSet::new();
    let mut series: BTreeSet<(String, Vec<(&str, &str)>)> = BTreeSet::new();
    for r in RULES {
        assert!(r.name.starts_with("urmqtt_"), "{}", r.name);
        assert!(
            r.name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{}",
            r.name
        );
        assert!(
            !r.name.contains("__") && !r.name.ends_with('_'),
            "{}",
            r.name
        );
        match r.kind {
            Kind::Counter => assert!(r.name.ends_with("_total"), "{} is a counter", r.name),
            Kind::Gauge => assert!(!r.name.ends_with("_total"), "{} is a gauge", r.name),
        }
        // Units are base units, never a scaled one.
        for bad in ["ms", "milliseconds", "days", "percent", "kb", "mb", "us"] {
            assert!(
                !r.name.split('_').any(|w| w == bad),
                "{}: use base units",
                r.name
            );
        }
        // Scaled values say their unit.
        match r.value {
            Value::Milli => assert!(r.name.contains("seconds"), "{}", r.name),
            Value::Days => assert!(r.name.contains("seconds"), "{}", r.name),
            Value::Centi => assert!(r.name.contains("ratio"), "{}", r.name),
            _ => {}
        }
        assert!(!r.help.is_empty() && r.help.len() <= 120 && !r.help.contains('\n'));
        // A family is one run of rules with one kind and one help.
        if r.name != last {
            assert!(closed.insert(r.name), "{} is split in two runs", r.name);
            last = r.name;
        }
        match families.get(r.name) {
            Some(&(k, h)) => assert!((k, h) == (r.kind, r.help), "{}", r.name),
            None => {
                families.insert(r.name, (r.kind, r.help));
            }
        }
        // Labels: names are fixed here; none may be one a client could pick.
        let mut names: Vec<&str> = r.fixed.iter().map(|(k, _)| *k).collect();
        names.extend(r.label);
        if let Value::Info(l) = r.value {
            names.push(l);
        }
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "{}: a label twice", r.name);
        for l in &names {
            assert!(
                matches!(
                    *l,
                    "core"
                        | "reason"
                        | "code"
                        | "listener"
                        | "result"
                        | "direction"
                        | "side"
                        | "version"
                        | "arch"
                        | "source"
                        | "mode"
                        | "auth"
                ),
                "{}: label {l} is not on the list of bounded labels",
                r.name
            );
        }
        // The same series from two rules would be a duplicate sample.
        if r.label.is_none() && !matches!(r.value, Value::Info(_)) {
            assert!(
                series.insert((r.name.to_owned(), r.fixed.to_vec())),
                "{}: two rules, one series",
                r.name
            );
        }
    }
}

// ---- the text ----------------------------------------------------------------

/// A strict reader of the text formats: what a scraper would refuse, this
/// refuses. Returns the samples as `name{labels}` -> value.
fn parse(text: &str, openmetrics: bool) -> BTreeMap<String, String> {
    assert!(text.ends_with('\n'));
    let mut typed: BTreeMap<String, String> = BTreeMap::new();
    let mut helped: BTreeSet<String> = BTreeSet::new();
    let mut samples = BTreeMap::new();
    let mut eof = false;
    let mut current: Option<String> = None;
    for line in text.lines() {
        assert!(!eof, "text after # EOF");
        assert!(!line.is_empty(), "empty line");
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').expect("HELP needs text");
            assert!(helped.insert(name.to_owned()), "second HELP for {name}");
            assert!(!help.is_empty());
            assert!(current.is_none() || !typed.contains_key(name));
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').expect("TYPE needs a kind");
            assert!(helped.contains(name), "TYPE before HELP: {name}");
            assert!(matches!(kind, "counter" | "gauge"), "{kind}");
            assert!(typed.insert(name.to_owned(), kind.to_owned()).is_none());
            if openmetrics && kind == "counter" {
                assert!(!name.ends_with("_total"), "OpenMetrics family {name}");
            }
            current = Some(name.to_owned());
        } else if line == "# EOF" {
            assert!(openmetrics, "# EOF in the classic format");
            eof = true;
        } else {
            assert!(!line.starts_with('#'), "{line}");
            let (series, value) = line.rsplit_once(' ').expect("sample needs a value");
            let (name, labels) = match series.split_once('{') {
                Some((n, l)) => (n, l.strip_suffix('}').expect("unclosed labels")),
                None => (series, ""),
            };
            let fam = current.as_deref().expect("sample before TYPE");
            let kind = &typed[fam];
            let want = if openmetrics && kind == "counter" {
                format!("{fam}_total")
            } else {
                fam.to_owned()
            };
            assert_eq!(name, want, "sample outside its family: {line}");
            // Labels: name="value" pairs, values escaped.
            let mut rest = labels;
            while !rest.is_empty() {
                let (k, r) = rest.split_once("=\"").expect("label");
                assert!(
                    k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                    "label name {k}"
                );
                let mut end = None;
                let mut esc = false;
                for (i, ch) in r.char_indices() {
                    if esc {
                        assert!(matches!(ch, '\\' | '"' | 'n'), "escape {ch}");
                        esc = false;
                    } else if ch == '\\' {
                        esc = true;
                    } else if ch == '"' {
                        end = Some(i);
                        break;
                    }
                }
                let end = end.expect("unterminated label value");
                rest = &r[end + 1..];
                rest = rest.strip_prefix(',').unwrap_or(rest);
            }
            // The value is a number: an integer or a decimal.
            assert!(
                value.parse::<f64>().is_ok()
                    && !value.contains(['e', 'E', 'n', 'N', 'i', 'I'])
                    && !value.starts_with('+'),
                "value {value}"
            );
            if *kind == "counter" {
                assert!(!value.starts_with('-'), "negative counter {line}");
            }
            assert!(
                samples
                    .insert(series.to_owned(), value.to_owned())
                    .is_none(),
                "duplicate series {series}"
            );
        }
    }
    assert_eq!(eof, openmetrics, "# EOF exactly in OpenMetrics");
    samples
}

#[test]
fn both_formats_parse_and_carry_the_same_samples() {
    let classic = parse(&text(false), false);
    let open = parse(&text(true), true);
    // OpenMetrics spells counter samples with _total as the classic one does.
    assert_eq!(classic, open);
    assert!(classic.len() > 150, "{}", classic.len());
}

#[test]
fn the_numbers_are_the_sys_numbers() {
    let s = parse(&text(false), false);
    let get = |k: &str| s.get(k).unwrap_or_else(|| panic!("missing {k}")).as_str();
    assert_eq!(get("urmqtt_uptime_seconds"), "12345");
    assert_eq!(get("urmqtt_version_info{version=\"0.6.0\"}"), "1");
    assert_eq!(get("urmqtt_arch_info{arch=\"aarch64\"}"), "1");
    assert_eq!(get("urmqtt_cpu_cores"), "4");
    assert_eq!(get("urmqtt_cpu_busy_ratio{core=\"0\"}"), "0.10");
    assert_eq!(get("urmqtt_cpu_busy_ratio{core=\"1\"}"), "0.55");
    assert_eq!(get("urmqtt_cpu_busy_ratio{core=\"3\"}"), "1.00");
    assert_eq!(
        get("urmqtt_core_connections_accepted_total{core=\"2\"}"),
        "3"
    );
    assert_eq!(get("urmqtt_memory_heap_bytes"), "268435456");
    assert_eq!(get("urmqtt_memory_heap_used_bytes"), "12345678");
    assert_eq!(get("urmqtt_clients_connected"), "7");
    assert_eq!(
        get("urmqtt_clients_connected_by_version{version=\"5\"}"),
        "3"
    );
    assert_eq!(
        get("urmqtt_clients_connected_by_version{version=\"3.1.1\"}"),
        "4"
    );
    assert_eq!(get("urmqtt_messages_received_total"), "1000000");
    assert_eq!(get("urmqtt_messages_sent_total"), "2500000");
    assert_eq!(
        get("urmqtt_messages_dropped_total{reason=\"offline\"}"),
        "2"
    );
    assert_eq!(
        get("urmqtt_messages_dropped_total{reason=\"too_large\"}"),
        "8"
    );
    assert_eq!(get("urmqtt_frames_dropped_total{reason=\"nic\"}"), "8");
    assert_eq!(get("urmqtt_qos2_completed_total"), "12");
    assert_eq!(get("urmqtt_backpressure_info{mode=\"single\"}"), "1");
    assert_eq!(get("urmqtt_backpressure_paused_seconds_total"), "1.500");
    assert_eq!(
        get("urmqtt_mqtt5_disconnects_sent_total{code=\"0x8e\"}"),
        "7"
    );
    assert_eq!(
        get("urmqtt_mqtt5_disconnects_sent_total{code=\"other\"}"),
        "1"
    );
    assert_eq!(
        get("urmqtt_mqtt5_connections_refused_total{code=\"0x87\"}"),
        "5"
    );
    assert_eq!(get("urmqtt_handshakes_latency_seconds_total"), "4.500");
    assert_eq!(get("urmqtt_handshakes_latency_max_seconds"), "0.250");
    assert_eq!(
        get("urmqtt_tls_server_certificate_expiry_seconds"),
        "7689600"
    );
    assert_eq!(get("urmqtt_time_offset_seconds"), "-1.234");
    assert_eq!(get("urmqtt_time_source_info{source=\"sntp\"}"), "1");
    assert_eq!(get("urmqtt_network_mtu_bytes"), "1500");
    assert_eq!(get("urmqtt_listener_enabled{listener=\"plaintext\"}"), "1");
    assert_eq!(get("urmqtt_listener_port{listener=\"websocket\"}"), "8084");
    assert_eq!(
        get("urmqtt_listener_logins_total{listener=\"plaintext\",result=\"failed\"}"),
        "7"
    );
    assert_eq!(
        get("urmqtt_plaintext_refused_total{reason=\"locked_out\"}"),
        "2"
    );
    assert_eq!(
        get("urmqtt_websocket_refused_total{reason=\"locked_out\"}"),
        "10"
    );
    assert_eq!(
        get("urmqtt_websocket_closes_total{side=\"client\",code=\"1000\"}"),
        "1"
    );
    assert_eq!(
        get("urmqtt_websocket_closes_total{side=\"server\",code=\"other\"}"),
        "1"
    );
    assert_eq!(get("urmqtt_websocket_bytes_total{direction=\"out\"}"), "14");
    // The listener's own.
    assert_eq!(get("urmqtt_metrics_listener_port"), "9100");
    assert_eq!(get("urmqtt_metrics_requests_total{result=\"ok\"}"), "40");
    assert_eq!(get("urmqtt_metrics_requests_total{result=\"method\"}"), "2");
    assert_eq!(
        get("urmqtt_metrics_requests_total{result=\"not_found\"}"),
        "4"
    );
    assert_eq!(get("urmqtt_metrics_refused_total{reason=\"source\"}"), "2");
}

/// Every number the info query reports as a counter or gauge reaches the
/// text: the text is generated from the same topics, so the cheapest check
/// is that no topic's number is lost on the way.
#[test]
fn nothing_the_sys_tree_reports_is_lost() {
    let (busy, acc) = ([10u8, 55, 0, 100], [1u64, 2, 3, 4]);
    let info = full(&busy, &acc);
    let mut numeric = 0;
    sys::topics(&info, |t, v| {
        let rest = t.strip_prefix("$SYS/broker/").unwrap();
        if NOT_EXPOSED.iter().any(|(n, _)| *n == rest) {
            return;
        }
        let r = RULES
            .iter()
            .find(|r| match r.label {
                None => r.topic == rest,
                Some(_) => rest
                    .strip_prefix(r.topic)
                    .and_then(|x| x.strip_prefix('/'))
                    .is_some(),
            })
            .unwrap();
        // Known values always make a sample.
        assert!(value_of(r, v).is_some(), "{t} = {v}");
        numeric += 1;
    });
    assert!(numeric > 150);
    let s = parse(&text(false), false);
    let samples = s
        .keys()
        .filter(|k| !k.starts_with("urmqtt_metrics_"))
        .count();
    assert_eq!(samples, numeric);
}

#[test]
fn unknown_values_are_left_out_not_zero() {
    let (busy, acc) = ([0u8], [0u64]);
    let mut i = full(&busy, &acc);
    i.server_cert_days = None;
    i.time_offset_ms = None;
    let s = parse(&render(&i, &own(), false), false);
    assert!(
        !s.keys()
            .any(|k| k.starts_with("urmqtt_tls_server_certificate"))
    );
    assert!(!s.keys().any(|k| k.starts_with("urmqtt_time_offset")));
    assert!(s.contains_key("urmqtt_time_source_info{source=\"sntp\"}"));
}

#[test]
fn a_listener_that_is_off_says_so_and_nothing_else() {
    let (busy, acc) = ([0u8], [0u64]);
    let mut i = full(&busy, &acc);
    i.plaintext = PlainInfo::default();
    i.websocket = WsInfo::default();
    let s = parse(&render(&i, &own(), false), false);
    assert_eq!(s["urmqtt_listener_enabled{listener=\"plaintext\"}"], "0");
    assert_eq!(s["urmqtt_listener_enabled{listener=\"websocket\"}"], "0");
    assert!(!s.keys().any(|k| k.starts_with("urmqtt_websocket_")));
    assert!(!s.keys().any(|k| k.starts_with("urmqtt_plaintext_")));
    assert!(!s.keys().any(|k| k.starts_with("urmqtt_listener_port")));
}

/// The number of series depends on the core count and the configuration
/// only: counters changing, clients coming and going, change no name or label.
#[test]
fn the_series_do_not_depend_on_the_traffic() {
    let (busy, acc) = ([10u8, 55], [1u64, 2]);
    let a = full(&busy, &acc);
    let mut b = full(&busy, &acc);
    b.clients_connected = 0;
    b.messages_received = 7;
    b.drops = Drops::default();
    b.mqtt5.disconnects = [3; crate::REASON_SLOTS];
    b.handshakes = Handshakes::default();
    let keys = |i: &Info<'_>| -> Vec<String> {
        parse(&render(i, &own(), false), false)
            .into_keys()
            .collect()
    };
    assert_eq!(keys(&a), keys(&b));
    // And it is bounded: 64 cores is the most, and the text stays small.
    let (busy, acc) = ([0u8; 64], [0u64; 64]);
    let t = render(&full(&busy, &acc), &own(), true);
    assert!(t.len() < 48 * 1024, "{}", t.len());
}

#[test]
fn label_values_are_escaped() {
    let (busy, acc) = ([0u8], [0u64]);
    let mut i = full(&busy, &acc);
    i.version = "a\"b\\c\nd";
    let t = render(&i, &own(), false);
    assert!(
        t.contains("urmqtt_version_info{version=\"a\\\"b\\\\c\\nd\"} 1\n"),
        "{t}"
    );
    parse(&t, false);
}

#[test]
fn openmetrics_names_counter_families_without_total() {
    let t = text(true);
    assert!(t.contains("# TYPE urmqtt_messages_received counter\n"));
    assert!(t.contains("\nurmqtt_messages_received_total 1000000\n"));
    assert!(t.ends_with("# EOF\n"));
    let c = text(false);
    assert!(c.contains("# TYPE urmqtt_messages_received_total counter\n"));
    assert!(!c.contains("# EOF"));
}
