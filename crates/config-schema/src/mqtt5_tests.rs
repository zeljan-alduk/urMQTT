//! ADR-273 rule 21: the `[mqtt5]` section and the expiry limits through the
//! TOML path. The strict parser (`parse`, plus the packer) and the kernel's
//! blob check (`urmqtt_cfg::check`) must accept and refuse the same
//! configurations, and a configuration that does not touch these keys must be
//! the blob it always was: any of them set needs format 12.

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

/// The documented defaults (ADR-273 rule 21), also for a full configuration
/// written before format 12 (the shipped ones do not name the keys).
#[test]
fn the_defaults_are_the_documented_ones() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let cfg = parse(env, text).unwrap();
        let m = cfg.mqtt5;
        assert!(m.enabled && m.shared_subscriptions && m.subscription_identifiers);
        assert_eq!(
            (
                m.receive_maximum,
                m.topic_alias_maximum,
                m.max_user_properties,
                m.max_keep_alive_s
            ),
            (32, 10, 16, 0)
        );
        let l = cfg.limits;
        assert_eq!(
            (
                l.max_session_expiry_s,
                l.default_session_expiry_s,
                l.max_message_expiry_s
            ),
            (2_592_000, 2_592_000, 0),
            "{env}"
        );
    }
}

/// Without the keys, or with them spelled out at their defaults, the blob has
/// none of their records and keeps the base format.
#[test]
fn an_untouched_configuration_keeps_its_format() {
    let blob = pack_toml("").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 2);
    assert!(b.present().all(|(f, _)| f.since < 12));
    let spelled = "[mqtt5]\nenabled = true\nreceive_maximum = 32\ntopic_alias_maximum = 10\n\
        max_user_properties = 16\nmax_keep_alive_s = 0\nshared_subscriptions = true\n\
        subscription_identifiers = true\n[limits]\nmax_session_expiry_s = 2592000\n\
        default_session_expiry_s = 2592000\nmax_message_expiry_s = 0\n";
    assert_eq!(pack_toml(spelled).unwrap(), blob);
    // A configuration that needs an older format keeps it.
    let ws = pack_toml("[websocket]\nenabled = true\n").unwrap();
    assert_eq!(Blob::parse(&ws).unwrap().version(), 9);
    let mtu = pack_toml("[network]\nmtu = 1400\n").unwrap();
    assert_eq!(Blob::parse(&mtu).unwrap().version(), 7);
}

/// Any one key set needs format 12 and writes exactly one record.
#[test]
fn any_key_set_needs_format_12() {
    for (section, set, t) in [
        ("mqtt5", "enabled = false", tag::MQTT5_ENABLED),
        ("mqtt5", "receive_maximum = 1", tag::MQTT5_RECEIVE_MAXIMUM),
        (
            "mqtt5",
            "receive_maximum = 65535",
            tag::MQTT5_RECEIVE_MAXIMUM,
        ),
        (
            "mqtt5",
            "topic_alias_maximum = 0",
            tag::MQTT5_TOPIC_ALIAS_MAXIMUM,
        ),
        (
            "mqtt5",
            "max_user_properties = 1024",
            tag::MQTT5_MAX_USER_PROPERTIES,
        ),
        ("mqtt5", "max_keep_alive_s = 600", tag::MQTT5_MAX_KEEP_ALIVE),
        (
            "mqtt5",
            "shared_subscriptions = false",
            tag::MQTT5_SHARED_SUBSCRIPTIONS,
        ),
        (
            "mqtt5",
            "subscription_identifiers = false",
            tag::MQTT5_SUBSCRIPTION_IDENTIFIERS,
        ),
        (
            "limits",
            "max_session_expiry_s = 4294967295",
            tag::LIM_MAX_SESSION_EXPIRY,
        ),
        (
            "limits",
            "default_session_expiry_s = 0",
            tag::LIM_DEFAULT_SESSION_EXPIRY,
        ),
        (
            "limits",
            "max_message_expiry_s = 86400",
            tag::LIM_MAX_MESSAGE_EXPIRY,
        ),
    ] {
        let blob = pack_toml(&format!("[{section}]\n{set}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 12, "{set}");
        assert_eq!(b.present().count(), 1, "{set}: one record");
        assert!(b.raw(t).is_some(), "{set}");
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
}

/// What a configuration that sets everything becomes in the blob.
#[test]
fn a_full_section_packs() {
    let toml = "[mqtt5]\nenabled = false\nreceive_maximum = 100\ntopic_alias_maximum = 50\n\
        max_user_properties = 4\nmax_keep_alive_s = 120\nshared_subscriptions = false\n\
        subscription_identifiers = false\n[limits]\nmax_session_expiry_s = 86400\n\
        default_session_expiry_s = 3600\nmax_message_expiry_s = 600\n";
    // The full-TOML path too (the shipped file has a [limits] table already).
    let cfg = parse(
        "prod",
        &format!(
            "{}\n[mqtt5]\nenabled = false\nreceive_maximum = 100\n",
            include_str!("../../../deploy/prod/config.toml")
        ),
    )
    .unwrap();
    assert!(!cfg.mqtt5.enabled);
    assert_eq!(cfg.mqtt5.receive_maximum, 100);
    let blob = pack_toml(toml).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 12);
    assert!(!b.bool(tag::MQTT5_ENABLED));
    assert!(!b.bool(tag::MQTT5_SHARED_SUBSCRIPTIONS));
    assert!(!b.bool(tag::MQTT5_SUBSCRIPTION_IDENTIFIERS));
    assert_eq!(b.uint(tag::MQTT5_RECEIVE_MAXIMUM), 100);
    assert_eq!(b.uint(tag::MQTT5_TOPIC_ALIAS_MAXIMUM), 50);
    assert_eq!(b.uint(tag::MQTT5_MAX_USER_PROPERTIES), 4);
    assert_eq!(b.uint(tag::MQTT5_MAX_KEEP_ALIVE), 120);
    assert_eq!(b.uint(tag::LIM_MAX_SESSION_EXPIRY), 86_400);
    assert_eq!(b.uint(tag::LIM_DEFAULT_SESSION_EXPIRY), 3600);
    assert_eq!(b.uint(tag::LIM_MAX_MESSAGE_EXPIRY), 600);
    urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
}

/// Each refusal names its key and says why.
#[test]
fn refusals_name_their_keys() {
    let has = |toml: &str, path: &str, words: &str| {
        let e = pack_toml(toml).unwrap_err();
        assert!(
            e.iter()
                .any(|x| x.path == path && x.message.contains(words)),
            "{toml}\n=> {e:?}"
        );
    };
    for (set, key, range) in [
        ("receive_maximum = 0", "receive_maximum", "1..=65535"),
        ("receive_maximum = 65536", "receive_maximum", "1..=65535"),
        (
            "topic_alias_maximum = 65536",
            "topic_alias_maximum",
            "0..=65535",
        ),
        (
            "max_user_properties = 1025",
            "max_user_properties",
            "0..=1024",
        ),
        ("max_keep_alive_s = 65536", "max_keep_alive_s", "0..=65535"),
    ] {
        has(&format!("[mqtt5]\n{set}\n"), &format!("mqtt5.{key}"), range);
    }
    // The default session expiry above the maximum names both keys.
    has(
        "[limits]\nmax_session_expiry_s = 3600\n",
        "limits.default_session_expiry_s",
        "limits.max_session_expiry_s",
    );
    has(
        "[limits]\ndefault_session_expiry_s = 4294967295\n",
        "limits.default_session_expiry_s",
        "limits.max_session_expiry_s",
    );
    // Not a u32, not a bool, not a key: the TOML parser refuses them.
    for bad in [
        "[limits]\nmax_session_expiry_s = 4294967296\n",
        "[limits]\nmax_message_expiry_s = -1\n",
        "[mqtt5]\nreceive_maximum = -1\n",
        "[mqtt5]\nenabled = 1\n",
        "[mqtt5]\nauth_methods = []\n",
        "[mqtt5]\nbogus = true\n",
    ] {
        assert!(pack_toml(bad).is_err(), "{bad}");
    }
    // Several at once.
    let e = pack_toml(
        "[mqtt5]\nreceive_maximum = 0\nmax_user_properties = 2000\n[limits]\nmax_session_expiry_s = 1\n",
    )
    .unwrap_err();
    assert!(e.len() >= 3, "{e:?}");
    // Equal is fine, and so is 0 for both.
    pack_toml("[limits]\nmax_session_expiry_s = 3600\ndefault_session_expiry_s = 3600\n").unwrap();
    pack_toml("[limits]\nmax_session_expiry_s = 0\ndefault_session_expiry_s = 0\n").unwrap();
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check. A value the blob builder cannot hold counts as refused there.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    let u = |t: u16, v: u64| (t, v);
    let cases: Vec<(&str, Vec<(u16, u64)>)> = vec![
        ("", vec![]),
        ("[mqtt5]\nenabled = false\n", vec![u(tag::MQTT5_ENABLED, 0)]),
        (
            "[mqtt5]\nshared_subscriptions = false\nsubscription_identifiers = false\n",
            vec![
                u(tag::MQTT5_SHARED_SUBSCRIPTIONS, 0),
                u(tag::MQTT5_SUBSCRIPTION_IDENTIFIERS, 0),
            ],
        ),
        (
            "[mqtt5]\nreceive_maximum = 1\n",
            vec![u(tag::MQTT5_RECEIVE_MAXIMUM, 1)],
        ),
        (
            "[mqtt5]\nreceive_maximum = 0\n",
            vec![u(tag::MQTT5_RECEIVE_MAXIMUM, 0)],
        ),
        (
            "[mqtt5]\nreceive_maximum = 65535\n",
            vec![u(tag::MQTT5_RECEIVE_MAXIMUM, 65_535)],
        ),
        (
            "[mqtt5]\nreceive_maximum = 65536\n",
            vec![u(tag::MQTT5_RECEIVE_MAXIMUM, 65_536)],
        ),
        (
            "[mqtt5]\ntopic_alias_maximum = 0\n",
            vec![u(tag::MQTT5_TOPIC_ALIAS_MAXIMUM, 0)],
        ),
        (
            "[mqtt5]\ntopic_alias_maximum = 65536\n",
            vec![u(tag::MQTT5_TOPIC_ALIAS_MAXIMUM, 65_536)],
        ),
        (
            "[mqtt5]\nmax_user_properties = 0\n",
            vec![u(tag::MQTT5_MAX_USER_PROPERTIES, 0)],
        ),
        (
            "[mqtt5]\nmax_user_properties = 1024\n",
            vec![u(tag::MQTT5_MAX_USER_PROPERTIES, 1024)],
        ),
        (
            "[mqtt5]\nmax_user_properties = 1025\n",
            vec![u(tag::MQTT5_MAX_USER_PROPERTIES, 1025)],
        ),
        (
            "[mqtt5]\nmax_keep_alive_s = 65535\n",
            vec![u(tag::MQTT5_MAX_KEEP_ALIVE, 65_535)],
        ),
        (
            "[mqtt5]\nmax_keep_alive_s = 65536\n",
            vec![u(tag::MQTT5_MAX_KEEP_ALIVE, 65_536)],
        ),
        (
            "[limits]\nmax_session_expiry_s = 4294967295\n",
            vec![u(tag::LIM_MAX_SESSION_EXPIRY, 4_294_967_295)],
        ),
        (
            "[limits]\nmax_session_expiry_s = 3600\n",
            vec![u(tag::LIM_MAX_SESSION_EXPIRY, 3600)],
        ),
        (
            "[limits]\nmax_session_expiry_s = 3600\ndefault_session_expiry_s = 3600\n",
            vec![
                u(tag::LIM_MAX_SESSION_EXPIRY, 3600),
                u(tag::LIM_DEFAULT_SESSION_EXPIRY, 3600),
            ],
        ),
        (
            "[limits]\nmax_session_expiry_s = 3600\ndefault_session_expiry_s = 3601\n",
            vec![
                u(tag::LIM_MAX_SESSION_EXPIRY, 3600),
                u(tag::LIM_DEFAULT_SESSION_EXPIRY, 3601),
            ],
        ),
        (
            "[limits]\ndefault_session_expiry_s = 2592001\n",
            vec![u(tag::LIM_DEFAULT_SESSION_EXPIRY, 2_592_001)],
        ),
        (
            "[limits]\ndefault_session_expiry_s = 0\nmax_session_expiry_s = 0\n",
            vec![
                u(tag::LIM_DEFAULT_SESSION_EXPIRY, 0),
                u(tag::LIM_MAX_SESSION_EXPIRY, 0),
            ],
        ),
        (
            "[limits]\nmax_message_expiry_s = 4294967295\n",
            vec![u(tag::LIM_MAX_MESSAGE_EXPIRY, 4_294_967_295)],
        ),
    ];
    for (toml, sets) in cases {
        let t = pack_toml(toml).is_ok();
        let mut b = Builder::new();
        let mut k = true;
        for (tg, v) in sets {
            let r = match tg {
                tag::MQTT5_ENABLED
                | tag::MQTT5_SHARED_SUBSCRIPTIONS
                | tag::MQTT5_SUBSCRIPTION_IDENTIFIERS => b.bool(tg, v != 0),
                _ => b.uint(tg, v),
            };
            k &= r.is_ok();
        }
        k &= b.finish(false).is_ok();
        assert_eq!(
            t, k,
            "{toml:?}: the TOML path says {t}, the blob check says {k}"
        );
    }
}

#[test]
fn the_schema_describes_the_section() {
    let json = schema_json();
    for key in [
        "mqtt5.enabled",
        "mqtt5.receive_maximum",
        "mqtt5.topic_alias_maximum",
        "mqtt5.max_user_properties",
        "mqtt5.max_keep_alive_s",
        "mqtt5.shared_subscriptions",
        "mqtt5.subscription_identifiers",
        "limits.max_session_expiry_s",
        "limits.default_session_expiry_s",
        "limits.max_message_expiry_s",
    ] {
        assert!(json.contains(&format!("\"key\":\"{key}\"")), "{key}");
    }
    assert_eq!(json.matches("\"since\":12").count(), 10);
    assert!(json.contains(
        "\"key\":\"limits.max_session_expiry_s\",\"section\":\"limits\",\"name\":\"max_session_expiry_s\",\"toml_key\":\"limits.max_session_expiry_s\",\"type\":\"uint\",\"default\":2592000,\"min\":0,\"max\":4294967295"
    ));
}
