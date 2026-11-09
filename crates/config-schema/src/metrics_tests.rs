//! ADR-290: the `[metrics]` section through the TOML path. A configuration
//! that does not use it is the blob it always was; any key set needs format
//! 16; the strict parser and the kernel's blob check (`urmqtt_cfg::check`)
//! accept and refuse the same sections.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, parse};

const NOW: u64 = 1_800_000_000;

fn pack_toml(text: &str) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: NOW,
            env: None,
        },
    )
}

const ON: &str = "[metrics]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\n";

/// Off by default, with the documented numbers, also for the shipped
/// configurations, which do not name the section.
#[test]
fn off_by_default_and_the_blob_is_unchanged() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let m = parse(env, text).unwrap().metrics;
        assert!(!m.enabled && m.allow_from.is_empty(), "{env}");
        assert_eq!(
            (
                m.port,
                m.max_connections,
                m.max_connections_per_ip,
                m.request_timeout_s
            ),
            (9100, 8, 2, 5),
            "{env}"
        );
    }
    // Spelled out at the defaults: no record, the base format.
    let blob = pack_toml(
        "[metrics]\nenabled = false\nport = 9100\nallow_from = []\nmax_connections = 8\nmax_connections_per_ip = 2\nrequest_timeout_s = 5\n",
    )
    .unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

/// Each key set needs format 16, and what is written is read back.
#[test]
fn any_key_set_needs_format_16() {
    for (toml, t) in [
        (
            "enabled = true\nallow_from = [\"10.0.0.0/8\"]",
            tag::METRICS_ENABLED,
        ),
        ("port = 9273", tag::METRICS_PORT),
        ("allow_from = [\"10.0.0.0/8\"]", tag::METRICS_ALLOW_FROM),
        ("max_connections = 1", tag::METRICS_MAX_CONNS),
        ("max_connections_per_ip = 16", tag::METRICS_MAX_PER_IP),
        ("request_timeout_s = 30", tag::METRICS_REQUEST_TIMEOUT),
    ] {
        let blob = pack_toml(&format!("[metrics]\n{toml}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 16, "{toml}");
        assert!(b.present().any(|(f, _)| f.tag == t), "{toml}");
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
    let blob = pack_toml(ON).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert!(b.bool(tag::METRICS_ENABLED));
    assert_eq!(
        b.strs(tag::METRICS_ALLOW_FROM).collect::<Vec<_>>(),
        ["10.0.0.0/8"]
    );
    // The full-TOML path.
    let cfg = parse(
        "prod",
        &include_str!("../../../deploy/prod/config.toml").replace(
            "[limits]\n",
            "[metrics]\nenabled = true\nport = 9273\nallow_from = [\"10.0.0.0/8\", \"192.168.1.5/32\"]\n\n[limits]\n",
        ),
    )
    .unwrap();
    assert!(cfg.metrics.enabled);
    assert_eq!(cfg.metrics.port, 9273);
    assert_eq!(cfg.metrics.allow_from, ["10.0.0.0/8", "192.168.1.5/32"]);
}

#[test]
fn refusals_name_their_keys() {
    let key_of = |toml: &str| -> Vec<(String, String)> {
        pack_toml(toml)
            .unwrap_err()
            .into_iter()
            .map(|e| (e.path, e.message))
            .collect()
    };
    // Enabled needs an allow-list; no "anywhere" exists.
    let e = key_of("[metrics]\nenabled = true\n");
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].0, "metrics.allow_from");
    assert!(e[0].1.contains("no \"anywhere\""));
    assert!(pack_toml("[metrics]\nenabled = true\nallow_from_anywhere = true\n").is_err());
    // Entries.
    for bad in ["0.0.0.0/0", "10.0.0.0", "10.0.0.0/33", "x", ""] {
        let e = key_of(&format!("[metrics]\nallow_from = [\"{bad}\"]\n"));
        assert_eq!(e[0].0, "metrics.allow_from[0]", "{bad}");
    }
    let e = key_of("[metrics]\nallow_from = [\"10.0.0.0/8\", \"10.0.0.0/8\"]\n");
    assert_eq!(e[0].0, "metrics.allow_from[1]");
    assert!(e[0].1.contains("twice"));
    let many: Vec<String> = (0..17).map(|i| format!("\"10.{i}.0.0/16\"")).collect();
    let e = key_of(&format!("[metrics]\nallow_from = [{}]\n", many.join(", ")));
    assert!(
        e.iter()
            .any(|(p, m)| p == "metrics.allow_from" && m.contains("at most 16"))
    );
    // Ranges.
    for (key, bad) in [
        ("port", "0"),
        ("max_connections", "0"),
        ("max_connections", "65"),
        ("max_connections_per_ip", "17"),
        ("request_timeout_s", "0"),
        ("request_timeout_s", "31"),
    ] {
        let e = key_of(&format!("[metrics]\n{key} = {bad}\n"));
        assert_eq!(e[0].0, format!("metrics.{key}"), "{key} = {bad}: {e:?}");
    }
    for bad in ["-1", "65536", "\"x\""] {
        assert!(
            pack_toml(&format!("[metrics]\nport = {bad}\n")).is_err(),
            "{bad}"
        );
    }
    // An unknown key is refused, not ignored.
    assert!(pack_toml("[metrics]\nenabld = true\n").is_err());
}

#[test]
fn the_port_is_its_own() {
    let on = |extra: &str, port: u16| {
        format!(
            "{extra}\n[metrics]\nenabled = true\nport = {port}\nallow_from = [\"10.0.0.0/8\"]\n"
        )
    };
    let e = pack_toml(&on("", 8883)).unwrap_err();
    assert_eq!(e[0].path, "metrics.port");
    let e = pack_toml(&on(
        "[websocket]\nenabled = true\nport = 8084\norigins = [\"https://a.example\"]\n",
        8084,
    ))
    .unwrap_err();
    assert!(e.iter().any(|x| x.path == "metrics.port"), "{e:?}");
    // Off: no constraint.
    assert!(pack_toml("[metrics]\nport = 8883\n").is_ok());
    // A port of its own is fine.
    assert!(pack_toml(&on("", 9100)).is_ok());
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check, over a grid of sections.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    let nets: [&[&str]; 4] = [
        &[],
        &["10.0.0.0/8"],
        &["0.0.0.0/0"],
        &["10.0.0.0/8", "10.0.0.0/8"],
    ];
    for enabled in [false, true] {
        for net in nets {
            for port in [0u64, 1, 8883, 9100, 65_535] {
                let list = net
                    .iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                let toml = format!(
                    "[metrics]\nenabled = {enabled}\nport = {port}\nallow_from = [{list}]\n"
                );
                let by_toml = pack_toml(&toml).is_ok();
                let mut b = Builder::new();
                b.bool(tag::METRICS_ENABLED, enabled).unwrap();
                let by_blob = b.uint(tag::METRICS_PORT, port).is_ok()
                    && b.strs(tag::METRICS_ALLOW_FROM, net).is_ok()
                    && b.finish(false).is_ok();
                assert_eq!(by_toml, by_blob, "{toml:?}");
            }
        }
    }
}

#[test]
fn the_schema_describes_the_keys() {
    let json = schema_json();
    assert_eq!(json.matches("\"section\":\"metrics\"").count(), 6);
    assert!(json.contains(
        "\"key\":\"metrics.port\",\"section\":\"metrics\",\"name\":\"port\",\"toml_key\":\"metrics.port\",\"type\":\"uint\",\"default\":9100,\"min\":1,\"max\":65535"
    ));
}
