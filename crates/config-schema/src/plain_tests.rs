//! P1 (ADR-229): the `[plaintext]` section through the TOML path. The strict
//! parser (`parse`, plus the packer) and the kernel's blob check
//! (`urmqtt_cfg::check`) must accept and refuse the same configurations, and
//! a configuration that does not use the section must be the blob it always
//! was.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;
use urmqtt_cfg::passwd;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, PlaintextAuth, parse};

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

/// A configuration that does not mention the section is the empty
/// configuration: no plaintext records at all, whatever else it says.
#[test]
fn a_configuration_without_the_section_has_no_plaintext_records() {
    let blob = pack_toml("").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 2);
    assert!(b.present().all(|(f, _)| !f.key.starts_with("plaintext.")));
    assert!(!b.bool(tag::PL_ENABLED));
    // The section spelled out at its defaults is the same thing.
    let spelled = "[plaintext]\nenabled = false\nport = 1883\nallow_from = []\nallow_from_anywhere = false\n\
        auth = \"password\"\nanonymous_identity = \"lan\"\nusers = []\nip_identities = []\n\
        max_connections = 1000\nmax_connections_per_ip = 16\nmax_packet_size = 1024\n\
        publish_rate_per_device = \"5/s\"\nmax_failed_auths_per_ip = 5\nlockout_s = 300\n\
        acl_publish = [\"devices/{id}/#\"]\nacl_subscribe = [\"devices/{id}/cmd/#\"]\nretain = false\n";
    assert_eq!(pack_toml(spelled).unwrap(), blob);
    // Other settings next to a disabled section leave it out too.
    let other = pack_toml("[network]\nmqtt_tls_port = 9883\n").unwrap();
    assert!(
        Blob::parse(&other)
            .unwrap()
            .present()
            .all(|(f, _)| !f.key.starts_with("plaintext."))
    );
}

#[test]
fn the_shipped_configurations_do_not_use_the_section() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let cfg = parse(env, text).unwrap();
        assert!(!cfg.plaintext.enabled, "{env}");
        assert_eq!(cfg.plaintext.port, 1883);
        assert_eq!(cfg.plaintext.auth, PlaintextAuth::Password);
        assert!(cfg.plaintext.users.is_empty() && cfg.plaintext.allow_from.is_empty());
    }
}

/// The documented defaults (docs/PLAN.md P1, ADR-229).
#[test]
fn the_defaults_are_the_documented_ones() {
    let cfg = parse("prod", include_str!("../../../deploy/prod/config.toml")).unwrap();
    let p = cfg.plaintext;
    assert!(!p.enabled && !p.allow_from_anywhere && !p.retain);
    assert_eq!(
        (p.port, p.max_connections, p.max_connections_per_ip),
        (1883, 1000, 16)
    );
    assert_eq!(p.max_packet_size, 1024);
    assert_eq!(
        (
            p.publish_rate_per_device.tokens,
            p.publish_rate_per_device.per_ms
        ),
        (5, 1000)
    );
    assert_eq!((p.max_failed_auths_per_ip, p.lockout_s), (5, 300));
    assert_eq!(p.anonymous_identity, "lan");
    assert_eq!(p.acl_publish, ["devices/{id}/#"]);
    assert_eq!(p.acl_subscribe, ["devices/{id}/cmd/#"]);
}

/// A working password configuration and what it becomes in the blob.
#[test]
fn a_password_configuration_packs_into_a_version_2_blob() {
    let toml = format!(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\", \"192.168.1.0/24\"]\n\
         users = [{}, {}]\nmax_connections = 50\npublish_rate_per_device = \"2/s\"\nretain = true\n\
         acl_publish = [\"home/{{id}}/#\"]\n",
        user_toml("sensor-1"),
        user_toml("boiler")
    );
    let blob = pack_toml(&toml).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 2);
    assert!(b.bool(tag::PL_ENABLED) && b.bool(tag::PL_RETAIN));
    assert_eq!(
        b.strs(tag::PL_ALLOW_FROM).collect::<Vec<_>>(),
        ["10.0.0.0/8", "192.168.1.0/24"]
    );
    assert_eq!(
        b.strs(tag::PL_USERS).collect::<Vec<_>>(),
        [account("sensor-1"), account("boiler")]
    );
    assert_eq!(b.uint(tag::PL_MAX_CONNS), 50);
    assert_eq!(b.rate(tag::PL_PUBLISH_RATE), (2, 1000));
    assert_eq!(
        b.strs(tag::PL_ACL_PUBLISH).collect::<Vec<_>>(),
        ["home/{id}/#"]
    );
    // Untouched keys are not written: no port, no packet size, no lockout.
    for t in [
        tag::PL_PORT,
        tag::PL_MAX_PACKET,
        tag::PL_LOCKOUT,
        tag::PL_AUTH,
        tag::PL_ACL_SUBSCRIBE,
    ] {
        assert!(b.raw(t).is_none(), "tag {t} should be left out");
    }
    urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    // The same input, the same bytes.
    assert_eq!(pack_toml(&toml).unwrap(), blob);
}

#[test]
fn the_three_modes() {
    let anon = pack_toml(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\nanonymous_identity = \"house\"\n",
    )
    .unwrap();
    let b = Blob::parse(&anon).unwrap();
    assert_eq!(
        (b.variant(tag::PL_AUTH), b.str(tag::PL_ANON_ID)),
        (1, "house")
    );
    let ip = pack_toml(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\n\
         ip_identities = [{ from = \"10.1.0.0/16\", id = \"plc\" }, { from = \"10.2.3.4/32\", id = \"gate\" }]\n",
    )
    .unwrap();
    let b = Blob::parse(&ip).unwrap();
    assert_eq!(b.variant(tag::PL_AUTH), 2);
    assert_eq!(
        b.strs(tag::PL_IP_IDENTITIES).collect::<Vec<_>>(),
        ["10.1.0.0/16 plc", "10.2.3.4/32 gate"]
    );
}

fn base(extra: &str) -> String {
    format!(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{}]\n{extra}",
        user_toml("dev1")
    )
}

/// Each problem names its key, with the entry that is wrong.
#[test]
fn problems_name_their_keys() {
    let paths = |toml: &str| -> Vec<String> {
        pack_toml(toml)
            .unwrap_err()
            .into_iter()
            .map(|e| e.path)
            .collect()
    };
    let has = |toml: &str, path: &str| {
        let p = paths(toml);
        assert!(p.iter().any(|x| x == path), "{toml}\n=> {p:?}");
    };
    has("[plaintext]\nenabled = true\n", "plaintext.allow_from");
    has(
        &base("allow_from_anywhere = true\n"),
        "plaintext.allow_from_anywhere",
    );
    has(
        "[plaintext]\nallow_from_anywhere = true\n",
        "plaintext.allow_from_anywhere",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\n",
        "plaintext.users",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"0.0.0.0/0\"]\nauth = \"anonymous\"\n",
        "plaintext.allow_from[0]",
    );
    has(
        "[plaintext]\nallow_from = [\"10.0.0.7/8\"]\n",
        "plaintext.allow_from[0]",
    );
    has(
        "[plaintext]\nallow_from = [\"10.0.0.0/8\", \"10.0.0.0/8\"]\n",
        "plaintext.allow_from[1]",
    );
    has(
        "[plaintext]\nusers = [{ id = \"a b\", password_hash = \"x\" }]\n",
        "plaintext.users[0].id",
    );
    has(
        "[plaintext]\nusers = [{ id = \"a\", password_hash = \"hunter2\" }]\n",
        "plaintext.users[0].password_hash",
    );
    has(
        &format!("[plaintext]\nusers = [{0}, {0}]\n", user_toml("a")),
        "plaintext.users[1].id",
    );
    has(&base("port = 8883\n"), "plaintext.port");
    has(&base("port = 0\n"), "plaintext.port");
    has(&base("max_packet_size = 10\n"), "plaintext.max_packet_size");
    has(
        &base("publish_rate_per_device = \"lots\"\n"),
        "plaintext.publish_rate_per_device",
    );
    has(&base("lockout_s = 0\n"), "plaintext.lockout_s");
    has(
        &base("max_failed_auths_per_ip = 0\n"),
        "plaintext.max_failed_auths_per_ip",
    );
    has(
        &base("acl_publish = [\"$SYS/#\"]\n"),
        "plaintext.acl_publish[0]",
    );
    has(
        &base("acl_subscribe = [\"$anything/#\"]\n"),
        "plaintext.acl_subscribe[0]",
    );
    has(
        &base("anonymous_identity = \"x\"\n"),
        "plaintext.anonymous_identity",
    );
    has(
        &base("ip_identities = [{ from = \"10.1.0.0/16\", id = \"p\" }]\n"),
        "plaintext.ip_identities",
    );
    has(&base("auth = \"nonsense\"\n"), "");
    // Another role's identity.
    has(
        &format!(
            "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{}]\n",
            user_toml("backend")
        ),
        "plaintext.users[0].id",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\n\
         ip_identities = [{ from = \"192.168.0.0/16\", id = \"plc\" }]\n",
        "plaintext.ip_identities[0].from",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\n\
         ip_identities = [{ from = \"0.0.0.0/0\", id = \"plc\" }]\n",
        "plaintext.ip_identities[0].from",
    );
    has(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\n\
         ip_identities = [{ from = \"10.1.0.0/16\", id = \"operator\" }]\n",
        "plaintext.ip_identities[0].id",
    );
    has("[plaintext]\nbogus = 1\n", "");
    // And several at once.
    let many = paths("[plaintext]\nenabled = true\nport = 0\nmax_connections = 0\nlockout_s = 0\n");
    assert!(many.len() >= 4, "{many:?}");
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check, for many shapes of the section.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    type Build = Box<dyn Fn(&mut Builder)>;
    let h = hash("pw");
    let acct = |id: &str| format!("{id} {h}");
    let cases: Vec<(String, Build)> = vec![
        // Off, defaults and well-formed leftovers.
        ("[plaintext]\nenabled = false\n".into(), Box::new(|_| {})),
        ("[plaintext]\nallow_from = [\"10.0.0.0/8\"]\n".into(), Box::new(|b| b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap())),
        ("[plaintext]\nallow_from = [\"10.0.0.1/8\"]\n".into(), Box::new(|b| b.strs(tag::PL_ALLOW_FROM, &["10.0.0.1/8"]).unwrap())),
        ("[plaintext]\nport = 8883\n".into(), Box::new(|b| b.uint(tag::PL_PORT, 8883).unwrap())),
        ("[plaintext]\nallow_from_anywhere = true\n".into(), Box::new(|b| b.bool(tag::PL_ANYWHERE, true).unwrap())),
        ("[plaintext]\nacl_publish = []\n".into(), Box::new(|b| b.strs::<&str>(tag::PL_ACL_PUBLISH, &[]).unwrap())),
        ("[plaintext]\nacl_subscribe = [\"$SYS/#\"]\n".into(), Box::new(|b| b.strs(tag::PL_ACL_SUBSCRIBE, &["$SYS/#"]).unwrap())),
        ("[plaintext]\nacl_subscribe = [\"x/{id}/#\", \"y/+\"]\n".into(), Box::new(|b| b.strs(tag::PL_ACL_SUBSCRIBE, &["x/{id}/#", "y/+"]).unwrap())),
        ("[plaintext]\nacl_publish = [\"a/#/b\"]\n".into(), Box::new(|b| b.strs(tag::PL_ACL_PUBLISH, &["a/#/b"]).unwrap())),
        // On: the minimal password configuration, and what it lacks.
        (base(""), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        ("[plaintext]\nenabled = true\n".into(), Box::new(|b| b.bool(tag::PL_ENABLED, true).unwrap())),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
        })),
        (base("allow_from_anywhere = true\n"), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.bool(tag::PL_ANYWHERE, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (base("port = 8883\n"), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.uint(tag::PL_PORT, 8883).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (base("port = 1884\n"), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.uint(tag::PL_PORT, 1884).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        // Modes that exclude each other's keys.
        (base("anonymous_identity = \"x\"\n"), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
                b.str(tag::PL_ANON_ID, "x").unwrap();
            })
        }),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 1).unwrap();
        })),
        (format!("{}auth = \"anonymous\"\n", base("")), {
            let a = acct("dev1");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
                b.variant(tag::PL_AUTH, 1).unwrap();
            })
        }),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\nanonymous_identity = \"backend\"\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 1).unwrap();
            b.str(tag::PL_ANON_ID, "backend").unwrap();
        })),
        // ip mode.
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\nip_identities = [{ from = \"10.1.0.0/16\", id = \"plc\" }]\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 2).unwrap();
            b.strs(tag::PL_IP_IDENTITIES, &["10.1.0.0/16 plc"]).unwrap();
        })),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\nip_identities = [{ from = \"11.1.0.0/16\", id = \"plc\" }]\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 2).unwrap();
            b.strs(tag::PL_IP_IDENTITIES, &["11.1.0.0/16 plc"]).unwrap();
        })),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 2).unwrap();
        })),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\nip_identities = [{ from = \"10.1.0.0/16\", id = \"a\" }, { from = \"10.1.0.0/16\", id = \"b\" }]\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 2).unwrap();
            b.strs(tag::PL_IP_IDENTITIES, &["10.1.0.0/16 a", "10.1.0.0/16 b"]).unwrap();
        })),
        ("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"ip\"\nip_identities = [{ from = \"10.1.0.0/16\", id = \"a\" }, { from = \"10.1.2.0/24\", id = \"a\" }]\n".into(), Box::new(|b| {
            b.bool(tag::PL_ENABLED, true).unwrap();
            b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
            b.variant(tag::PL_AUTH, 2).unwrap();
            b.strs(tag::PL_IP_IDENTITIES, &["10.1.0.0/16 a", "10.1.2.0/24 a"]).unwrap();
        })),
        // Roles.
        (format!("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{}]\n", user_toml("operator")), {
            let a = acct("operator");
            Box::new(move |b| {
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
            })
        }),
        (format!("[acl]\nservice_ids = [\"svc-*\"]\n[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{}]\n", user_toml("svc-7")), {
            let a = acct("svc-7");
            Box::new(move |b| {
                b.strs(tag::ACL_SERVICE_IDS, &["svc-*"]).unwrap();
                b.bool(tag::PL_ENABLED, true).unwrap();
                b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
                b.strs(tag::PL_USERS, std::slice::from_ref(&a)).unwrap();
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
    assert!(json.contains("\"format_version\":9,\"format_min\":1"));
    for key in [
        "enabled",
        "port",
        "allow_from",
        "allow_from_anywhere",
        "auth",
        "anonymous_identity",
        "users",
        "ip_identities",
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
            json.contains(&format!("\"key\":\"plaintext.{key}\"")),
            "{key}"
        );
    }
    // Entries that are more than text say what they are; the builder needs it.
    assert!(json.contains("\"key\":\"plaintext.users\""));
    // Accounts: plaintext.users and websocket.users (ADR-272).
    assert_eq!(json.matches("\"item\":\"user\"").count(), 2);
    assert_eq!(json.matches("\"item\":\"ip_identity\"").count(), 1);
    assert_eq!(json.matches("\"item\":\"cidr\"").count(), 1);
    // Version 2 fields say so; older ones are version 1.
    assert_eq!(json.matches("\"since\":2").count(), 17);
    assert!(json.contains("\"since\":1"));
}

/// A user's TOML with a plain password instead of a hash is refused with a
/// message that says what to do.
#[test]
fn a_clear_text_password_is_refused() {
    let e = pack_toml(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{ id = \"a\", password_hash = \"secret\" }]\n",
    )
    .unwrap_err();
    let m = e
        .iter()
        .find(|x| x.path == "plaintext.users[0].password_hash")
        .unwrap();
    assert!(m.message.contains("hash-password"), "{}", m.message);
    assert!(!m.message.contains("secret"), "the value is not echoed");
}
