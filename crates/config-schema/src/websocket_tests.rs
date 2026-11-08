//! ADR-272: the `[websocket]` section through the TOML path. The strict
//! parser (`parse`, plus the packer) and the kernel's blob check
//! (`urmqtt_cfg::check`) must accept and refuse the same configurations, and
//! a configuration that does not use the section must be the blob it always
//! was: any key of the section set needs format 9.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;
use urmqtt_cfg::passwd;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, WebsocketAuth, parse};

const NOW: u64 = 1_800_000_000;

fn hash(pw: &str) -> String {
    passwd::encode(pw.as_bytes(), b"0123456789abcdef", 1000).unwrap()
}

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

fn user_toml(id: &str) -> String {
    format!("{{ id = {id:?}, password_hash = {:?} }}", hash("pw"))
}

fn account(id: &str) -> String {
    format!("{id} {}", hash("pw"))
}

const ORIGIN: &str = "https://app.example.com";

/// A password listener that works, with `extra` appended to the section.
fn base(extra: &str) -> String {
    format!(
        "[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\nusers = [{}]\n{extra}",
        user_toml("web1")
    )
}

/// The documented defaults (ADR-272).
#[test]
fn the_defaults_are_the_documented_ones() {
    let cfg = parse("prod", include_str!("../../../deploy/prod/config.toml")).unwrap();
    let w = cfg.websocket;
    assert!(!w.enabled && !w.retain);
    assert_eq!((w.port, w.path.as_str()), (8084, "/mqtt"));
    assert_eq!(w.auth, WebsocketAuth::Mtls);
    assert!(w.origins.is_empty() && w.users.is_empty());
    assert_eq!(w.upgrade_timeout_s, 5);
    assert_eq!((w.max_connections, w.max_connections_per_ip), (1000, 16));
    assert_eq!(w.max_packet_size, 16_384);
    assert_eq!(
        (
            w.publish_rate_per_device.tokens,
            w.publish_rate_per_device.per_ms
        ),
        (10, 1000)
    );
    assert_eq!((w.max_failed_auths_per_ip, w.lockout_s), (5, 300));
    assert_eq!(w.acl_publish, ["web/{id}/#"]);
    assert_eq!(w.acl_subscribe, ["web/{id}/#"]);
}

#[test]
fn the_shipped_configurations_do_not_use_the_section() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let cfg = parse(env, text).unwrap();
        assert!(!cfg.websocket.enabled, "{env}");
    }
}

/// Without the section, or with it spelled out at its defaults, the blob has
/// no websocket record and keeps the base format.
#[test]
fn a_configuration_without_the_section_keeps_its_format() {
    let blob = pack_toml("").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 2);
    assert!(b.present().all(|(f, _)| !f.key.starts_with("websocket.")));
    let spelled = "[websocket]\nenabled = false\nport = 8084\npath = \"/mqtt\"\nauth = \"mtls\"\n\
        origins = []\nusers = []\nupgrade_timeout_s = 5\nmax_connections = 1000\n\
        max_connections_per_ip = 16\nmax_packet_size = 16384\npublish_rate_per_device = \"10/s\"\n\
        max_failed_auths_per_ip = 5\nlockout_s = 300\nacl_publish = [\"web/{id}/#\"]\n\
        acl_subscribe = [\"web/{id}/#\"]\nretain = false\n";
    assert_eq!(pack_toml(spelled).unwrap(), blob);
}

/// Any key of the section set, even with the listener off, needs format 9: a
/// kernel without the listener refuses the image by its version.
#[test]
fn any_key_set_needs_format_9() {
    for set in [
        "enabled = true",
        "port = 9443",
        "path = \"/ws\"",
        "origins = [\"https://a.example\"]",
        "upgrade_timeout_s = 3",
        "max_connections = 10",
        "max_connections_per_ip = 2",
        "max_packet_size = 4096",
        "publish_rate_per_device = \"2/s\"",
        "max_failed_auths_per_ip = 3",
        "lockout_s = 60",
        "acl_publish = [\"x/{id}/#\"]",
        "acl_subscribe = []",
        "retain = true",
    ] {
        let blob = pack_toml(&format!("[websocket]\n{set}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 9, "{set}");
        assert_eq!(
            b.present()
                .filter(|(f, _)| f.key.starts_with("websocket."))
                .count(),
            1,
            "{set}: one record"
        );
    }
}

/// A working password configuration and what it becomes in the blob.
#[test]
fn a_password_configuration_packs() {
    let toml = format!(
        "[websocket]\nenabled = true\nauth = \"password\"\npath = \"/ws/mqtt\"\n\
         origins = [{ORIGIN:?}, \"http://localhost:3000\"]\nusers = [{}, {}]\n\
         max_connections = 50\npublish_rate_per_device = \"2/s\"\nretain = true\n",
        user_toml("alice"),
        user_toml("bob")
    );
    let blob = pack_toml(&toml).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 9);
    assert!(b.bool(tag::WS_ENABLED) && b.bool(tag::WS_RETAIN));
    assert_eq!(b.variant(tag::WS_AUTH), 1);
    assert_eq!(b.str(tag::WS_PATH), "/ws/mqtt");
    assert_eq!(
        b.strs(tag::WS_ORIGINS).collect::<Vec<_>>(),
        [ORIGIN, "http://localhost:3000"]
    );
    assert_eq!(
        b.strs(tag::WS_USERS).collect::<Vec<_>>(),
        [account("alice"), account("bob")]
    );
    assert_eq!(b.uint(tag::WS_MAX_CONNS), 50);
    assert_eq!(b.rate(tag::WS_PUBLISH_RATE), (2, 1000));
    for t in [
        tag::WS_PORT,
        tag::WS_UPGRADE_TIMEOUT,
        tag::WS_MAX_PACKET,
        tag::WS_LOCKOUT,
        tag::WS_ACL_PUBLISH,
        tag::WS_ACL_SUBSCRIBE,
    ] {
        assert!(b.raw(t).is_none(), "tag {t} should be left out");
    }
    urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    assert_eq!(pack_toml(&toml).unwrap(), blob);
    // mtls needs nothing more than the switch.
    let m = pack_toml("[websocket]\nenabled = true\n").unwrap();
    let b = Blob::parse(&m).unwrap();
    assert_eq!((b.version(), b.variant(tag::WS_AUTH)), (9, 0));
}

/// Each refusal names its key, with the entry that is wrong, and says why.
#[test]
fn refusals_name_their_keys() {
    let errs = |toml: &str| pack_toml(toml).unwrap_err();
    let has = |toml: &str, path: &str, words: &str| {
        let e = errs(toml);
        assert!(
            e.iter()
                .any(|x| x.path == path && x.message.contains(words)),
            "{toml}\n=> {e:?}"
        );
    };
    // Well formed whether or not the listener is on.
    has(
        "[websocket]\npath = \"mqtt\"\n",
        "websocket.path",
        "start with /",
    );
    has("[websocket]\npath = \"/a/../b\"\n", "websocket.path", "..");
    has(
        "[websocket]\npath = \"/a b\"\n",
        "websocket.path",
        "characters",
    );
    has(
        "[websocket]\norigins = [\"https://*.example.com\"]\n",
        "websocket.origins[0]",
        "wildcards",
    );
    has(
        "[websocket]\norigins = [\"null\"]\n",
        "websocket.origins[0]",
        "null",
    );
    has(
        "[websocket]\norigins = [\"https://app.example.com/\"]\n",
        "websocket.origins[0]",
        "no trailing slash",
    );
    has(
        "[websocket]\norigins = [\"https://App.example.com\"]\n",
        "websocket.origins[0]",
        "lower-case",
    );
    has(
        "[websocket]\norigins = [\"https://app.example.com:443\"]\n",
        "websocket.origins[0]",
        "default port",
    );
    has(
        &format!("[websocket]\norigins = [{ORIGIN:?}, {ORIGIN:?}]\n"),
        "websocket.origins[1]",
        "listed twice",
    );
    let many: Vec<String> = (0..17)
        .map(|i| format!("\"https://h{i}.example\""))
        .collect();
    has(
        &format!("[websocket]\norigins = [{}]\n", many.join(", ")),
        "websocket.origins",
        "at most 16",
    );
    has(
        "[websocket]\nusers = [{ id = \"a b\", password_hash = \"x\" }]\n",
        "websocket.users[0].id",
        "",
    );
    has(
        "[websocket]\nusers = [{ id = \"a\", password_hash = \"secret\" }]\n",
        "websocket.users[0].password_hash",
        "hash-password",
    );
    has(
        &format!("[websocket]\nusers = [{0}, {0}]\n", user_toml("a")),
        "websocket.users[1].id",
        "listed twice",
    );
    has(
        "[websocket]\nacl_publish = [\"$SYS/#\"]\n",
        "websocket.acl_publish[0]",
        "$",
    );
    has(
        "[websocket]\nacl_subscribe = [\"a/#/b\"]\n",
        "websocket.acl_subscribe[0]",
        "",
    );
    has("[websocket]\nport = 0\n", "websocket.port", "non-zero");
    has(
        "[websocket]\nupgrade_timeout_s = 0\n",
        "websocket.upgrade_timeout_s",
        "1..=10",
    );
    has(
        "[websocket]\nupgrade_timeout_s = 11\n",
        "websocket.upgrade_timeout_s",
        "1..=10",
    );
    has(
        "[websocket]\nmax_connections = 0\n",
        "websocket.max_connections",
        "1..=",
    );
    has(
        "[websocket]\nmax_connections_per_ip = 0\n",
        "websocket.max_connections_per_ip",
        "1..=",
    );
    has(
        "[websocket]\nmax_packet_size = 10\n",
        "websocket.max_packet_size",
        "64..=",
    );
    has(
        "[websocket]\npublish_rate_per_device = \"lots\"\n",
        "websocket.publish_rate_per_device",
        "",
    );
    has(
        "[websocket]\nmax_failed_auths_per_ip = 0\n",
        "websocket.max_failed_auths_per_ip",
        "1..=1000",
    );
    has(
        "[websocket]\nlockout_s = 0\n",
        "websocket.lockout_s",
        "1..=86400",
    );
    has("[websocket]\nauth = \"nonsense\"\n", "", "");
    has("[websocket]\nbogus = 1\n", "", "");
    // What the listener needs when it is on.
    has(
        "[network]\nmqtt_tls_port = 0\n[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\n[websocket]\nenabled = true\n",
        "websocket.enabled",
        "TLS listener",
    );
    has(
        "[websocket]\nenabled = true\nport = 8883\n",
        "websocket.port",
        "network.mqtt_tls_port",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\nport = 8084\n[websocket]\nenabled = true\n",
        "websocket.port",
        "plaintext.port",
    );
    has(
        &format!("[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\n"),
        "websocket.users",
        "at least one account",
    );
    has(
        &format!(
            "[websocket]\nenabled = true\nauth = \"password\"\nusers = [{}]\n",
            user_toml("web1")
        ),
        "websocket.origins",
        "required with auth = \"password\"",
    );
    has(
        &format!(
            "[websocket]\nenabled = true\nusers = [{}]\n",
            user_toml("web1")
        ),
        "websocket.users",
        "only used with auth = \"password\"",
    );
    has(
        &format!(
            "[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\nusers = [{}]\n",
            user_toml("operator")
        ),
        "websocket.users[0].id",
        "never hold those roles",
    );
    // And several at once.
    let e = errs("[websocket]\nport = 0\nmax_connections = 0\nlockout_s = 0\npath = \"x\"\n");
    assert!(e.len() >= 4, "{e:?}");
    // The working base is accepted.
    pack_toml(&base("")).unwrap();
}

/// The development environment's plain port is another listener the
/// WebSocket port may not take.
#[test]
fn the_dev_plain_port_is_taken() {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    let e = pack(
        "[network]\nmqtt_plain_port = 8084\n[websocket]\nenabled = true\n",
        PackOptions {
            read: &mut read,
            now_unix: NOW,
            env: Some("dev"),
        },
    )
    .unwrap_err();
    assert!(
        e.iter()
            .any(|x| x.path == "websocket.port" && x.message.contains("network.mqtt_plain_port")),
        "{e:?}"
    );
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check, for many shapes of the section.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    type Build = Box<dyn Fn(&mut Builder)>;
    let h = hash("pw");
    let acct = move |id: &str| format!("{id} {h}");
    let password_on = |b: &mut Builder| {
        b.bool(tag::WS_ENABLED, true).unwrap();
        b.variant(tag::WS_AUTH, 1).unwrap();
    };
    let cases: Vec<(String, Build)> = vec![
        // Off, defaults and well-formed leftovers.
        ("[websocket]\nenabled = false\n".into(), Box::new(|_| {})),
        ("[websocket]\nport = 8883\n".into(), Box::new(|b| b.uint(tag::WS_PORT, 8883).unwrap())),
        ("[websocket]\npath = \"/ws\"\n".into(), Box::new(|b| b.str(tag::WS_PATH, "/ws").unwrap())),
        ("[websocket]\npath = \"ws\"\n".into(), Box::new(|b| b.str(tag::WS_PATH, "ws").unwrap())),
        ("[websocket]\npath = \"/./x\"\n".into(), Box::new(|b| b.str(tag::WS_PATH, "/./x").unwrap())),
        (format!("[websocket]\norigins = [{ORIGIN:?}]\n"), Box::new(|b| b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap())),
        ("[websocket]\norigins = [\"*\"]\n".into(), Box::new(|b| b.strs(tag::WS_ORIGINS, &["*"]).unwrap())),
        ("[websocket]\norigins = [\"http://x:80\"]\n".into(), Box::new(|b| b.strs(tag::WS_ORIGINS, &["http://x:80"]).unwrap())),
        (format!("[websocket]\norigins = [{ORIGIN:?}, {ORIGIN:?}]\n"), Box::new(|b| b.strs(tag::WS_ORIGINS, &[ORIGIN, ORIGIN]).unwrap())),
        ("[websocket]\nauth = \"password\"\n".into(), Box::new(|b| b.variant(tag::WS_AUTH, 1).unwrap())),
        (format!("[websocket]\nusers = [{}]\n", user_toml("a")), {
            let a = acct("a");
            Box::new(move |b| b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap())
        }),
        (format!("[websocket]\nusers = [{0}, {0}]\n", user_toml("a")), {
            let a = acct("a");
            Box::new(move |b| b.strs(tag::WS_USERS, &[a.clone(), a.clone()]).unwrap())
        }),
        ("[websocket]\nacl_publish = [\"$SYS/#\"]\n".into(), Box::new(|b| b.strs(tag::WS_ACL_PUBLISH, &["$SYS/#"]).unwrap())),
        ("[websocket]\nacl_subscribe = [\"x/{id}/#\", \"y/+\"]\n".into(), Box::new(|b| b.strs(tag::WS_ACL_SUBSCRIBE, &["x/{id}/#", "y/+"]).unwrap())),
        ("[websocket]\nacl_publish = [\"a/#/b\"]\n".into(), Box::new(|b| b.strs(tag::WS_ACL_PUBLISH, &["a/#/b"]).unwrap())),
        // On with mtls.
        ("[websocket]\nenabled = true\n".into(), Box::new(|b| b.bool(tag::WS_ENABLED, true).unwrap())),
        ("[websocket]\nenabled = true\nport = 8883\n".into(), Box::new(|b| {
            b.bool(tag::WS_ENABLED, true).unwrap();
            b.uint(tag::WS_PORT, 8883).unwrap();
        })),
        (format!("[websocket]\nenabled = true\nusers = [{}]\n", user_toml("a")), {
            let a = acct("a");
            Box::new(move |b| {
                b.bool(tag::WS_ENABLED, true).unwrap();
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (format!("[websocket]\nenabled = true\norigins = [{ORIGIN:?}]\n"), Box::new(|b| {
            b.bool(tag::WS_ENABLED, true).unwrap();
            b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
        })),
        ("[network]\nmqtt_tls_port = 0\n[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\n[websocket]\nenabled = true\n".into(), Box::new(|b| {
            b.uint(tag::NET_TLS_PORT, 0).unwrap();
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 1).unwrap();
            b.bool(tag::WS_ENABLED, true).unwrap();
        })),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\nport = 8084\n[websocket]\nenabled = true\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 1).unwrap();
            b.uint(tag::PL_PORT, 8084).unwrap();
            b.bool(tag::WS_ENABLED, true).unwrap();
        })),
        // A disabled plaintext listener does not hold its port.
        ("[plaintext]\nport = 8084\n[websocket]\nenabled = true\n".into(), Box::new(|b| {
            b.uint(tag::PL_PORT, 8084).unwrap();
            b.bool(tag::WS_ENABLED, true).unwrap();
        })),
        // On with password: the minimal configuration, and what it lacks.
        (base(""), {
            let a = acct("web1");
            Box::new(move |b| {
                password_on(b);
                b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (format!("[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\n"), Box::new(move |b| {
            password_on(b);
            b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
        })),
        (format!("[websocket]\nenabled = true\nauth = \"password\"\nusers = [{}]\n", user_toml("web1")), {
            let a = acct("web1");
            Box::new(move |b| {
                password_on(b);
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        // Roles.
        (format!("[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\nusers = [{}]\n", user_toml("operator")), {
            let a = acct("operator");
            Box::new(move |b| {
                password_on(b);
                b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (format!("[acl]\nservice_ids = [\"svc-*\"]\n[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\nusers = [{}]\n", user_toml("svc-7")), {
            let a = acct("svc-7");
            Box::new(move |b| {
                b.strs(tag::ACL_SERVICE_IDS, &["svc-*"]).unwrap();
                password_on(b);
                b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        // The same id on both listeners is allowed (two separate account lists).
        (format!("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{0}]\n[websocket]\nenabled = true\nauth = \"password\"\norigins = [{ORIGIN:?}]\nusers = [{0}]\n", user_toml("both")), {
            let a = acct("both");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
                password_on(b);
                b.strs(tag::WS_ORIGINS, &[ORIGIN]).unwrap();
                b.strs(tag::WS_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
    ];
    for (toml, build) in cases {
        let t = pack_toml(&toml).is_ok();
        let mut b = Builder::new();
        build(&mut b);
        let k = b.finish(false).is_ok();
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
        "enabled",
        "port",
        "path",
        "auth",
        "origins",
        "users",
        "upgrade_timeout_s",
        "max_connections",
        "max_connections_per_ip",
        "max_packet_size",
        "publish_rate_per_device",
        "max_failed_auths_per_ip",
        "lockout_s",
        "acl_publish",
        "acl_subscribe",
        "retain",
    ] {
        assert!(
            json.contains(&format!("\"key\":\"websocket.{key}\"")),
            "{key}"
        );
    }
    // Both account lists are rendered as accounts by the builder.
    assert_eq!(json.matches("\"item\":\"user\"").count(), 2);
    assert_eq!(json.matches("\"since\":9").count(), 16);
    assert!(json.contains("\"variants\":[\"mtls\",\"password\"]"));
}
