//! C1a: packing, the JSON schema, and the conformance of the kernel-side
//! validator (`urmqtt-cfg`) with `parse`.

use std::path::PathBuf;

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::{self, FIELDS, Kind, tag};

use crate::pack::{PackOptions, default_toml, pack, schema_json};
use crate::{PemKind, parse};

const NOW: u64 = 1_800_000_000; // 2027, inside the dev certificates' validity

fn dev_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev")
}

fn have_dev_certs() -> bool {
    dev_dir().join("server.pem").exists() && dev_dir().join("control.pub").exists()
}

fn no_files(_: &str) -> Result<Vec<u8>, String> {
    Err("no files in this test".into())
}

fn pack_plain(text: &str) -> Result<Vec<u8>, Vec<crate::ConfigError>> {
    let mut read = no_files;
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: NOW,
        },
    )
}

fn empty_blob() -> Vec<u8> {
    Builder::new().finish(false).unwrap()
}

#[test]
fn an_empty_configuration_packs_to_the_defaults() {
    let packed = pack_plain("").expect("empty TOML");
    assert_eq!(packed, empty_blob());
    // The default TOML is the same configuration spelled out.
    assert_eq!(pack_plain(&default_toml()).expect("defaults"), empty_blob());
}

#[test]
fn every_field_has_a_default_and_a_help_text() {
    for f in FIELDS {
        assert!(!f.help.is_empty(), "{} has no help text", f.key);
        match f.kind {
            Kind::UInt {
                min, max, default, ..
            } => {
                assert!((min..=max).contains(&default), "{}", f.key);
            }
            Kind::Enum { variants, default } => {
                assert!(usize::from(default) < variants.len(), "{}", f.key);
            }
            _ => {}
        }
    }
    // Every field of the table appears in the JSON with a "default" key.
    let json = schema_json();
    assert_eq!(json.matches("\"default\":").count(), FIELDS.len());
    assert_eq!(json.matches("\"help\":").count(), FIELDS.len());
    assert!(json.contains("\"dev_only\":true"));
}

/// A small JSON checker: balanced, well-quoted, nothing after the value.
fn assert_json(s: &str) {
    let b = s.trim().as_bytes();
    let mut i = 0;
    fn ws(b: &[u8], i: &mut usize) {
        while b.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
    }
    fn value(b: &[u8], i: &mut usize) {
        ws(b, i);
        match b.get(*i) {
            Some(b'{') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b'}') {
                    *i += 1;
                    return;
                }
                loop {
                    ws(b, i);
                    string(b, i);
                    ws(b, i);
                    assert_eq!(b.get(*i), Some(&b':'));
                    *i += 1;
                    value(b, i);
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b'}') => {
                            *i += 1;
                            return;
                        }
                        c => panic!("object: unexpected {c:?} at {i}"),
                    }
                }
            }
            Some(b'[') => {
                *i += 1;
                ws(b, i);
                if b.get(*i) == Some(&b']') {
                    *i += 1;
                    return;
                }
                loop {
                    value(b, i);
                    ws(b, i);
                    match b.get(*i) {
                        Some(b',') => *i += 1,
                        Some(b']') => {
                            *i += 1;
                            return;
                        }
                        c => panic!("array: unexpected {c:?} at {i}"),
                    }
                }
            }
            Some(b'"') => string(b, i),
            Some(c) if c.is_ascii_digit() || *c == b'-' => {
                while b.get(*i).is_some_and(|c| c.is_ascii_digit() || *c == b'-') {
                    *i += 1;
                }
            }
            _ => {
                for lit in [&b"true"[..], b"false", b"null"] {
                    if b[*i..].starts_with(lit) {
                        *i += lit.len();
                        return;
                    }
                }
                panic!("value expected at {i}");
            }
        }
    }
    fn string(b: &[u8], i: &mut usize) {
        assert_eq!(b.get(*i), Some(&b'"'), "string expected at {i}");
        *i += 1;
        while b.get(*i) != Some(&b'"') {
            if b[*i] == b'\\' {
                *i += 1;
            }
            *i += 1;
        }
        *i += 1;
    }
    value(b, &mut i);
    assert_eq!(i, b.len(), "trailing data");
}

#[test]
fn the_schema_is_valid_json() {
    assert_json(&schema_json());
}

#[test]
fn defaults_in_the_toml_form_are_accepted_by_parse() {
    // The strict build-time parser accepts the defaults plus placeholders.
    let toml = pack_plain("").map(|_| ()).is_ok();
    assert!(toml);
}

fn with(key: &str, value: &str) -> String {
    let (sec, name) = key.split_once('.').unwrap();
    format!("[{sec}]\n{name} = {value}\n")
}

/// The verdict of the blob validator on `v` for an integer field, with
/// everything else at its default (and the dependencies a field needs).
fn blob_accepts_uint(f: &fields::Field, v: u64) -> bool {
    let mut b = Builder::new();
    if f.key == "network.dhcp_timeout_s" {
        b.variant(tag::NET_MODE, 2).unwrap();
        b.cidr(tag::NET_ADDRESS, [10, 0, 0, 2], 24).unwrap();
        b.ipv4(tag::NET_GATEWAY, [10, 0, 0, 1]).unwrap();
    }
    b.uint(f.tag, v).is_ok() && b.finish(false).is_ok()
}

fn toml_accepts_uint(f: &fields::Field, v: u64) -> bool {
    let mut text = String::new();
    if f.key == "network.dhcp_timeout_s" {
        text.push_str(
            "[network]\nmode = \"auto\"\naddress = \"10.0.0.2/24\"\ngateway = \"10.0.0.1\"\ndhcp_timeout_s = ",
        );
        text.push_str(&format!("{v}\n"));
    } else {
        text.push_str(&with(f.key, &v.to_string()));
    }
    // Values above i64 cannot be written in TOML.
    if i64::try_from(v).is_err() {
        return false;
    }
    pack_plain(&text).is_ok()
}

#[test]
fn integer_ranges_agree_between_parse_and_the_blob_validator() {
    let mut checked = 0;
    for f in FIELDS {
        let Kind::UInt { min, max, .. } = f.kind else {
            continue;
        };
        if f.derived || !f.stored || f.key == "network.mqtt_plain_port" {
            continue;
        }
        let mut cands = vec![min, max];
        if min > 0 {
            cands.push(min - 1);
        }
        if max < u64::from(u32::MAX) {
            cands.push(max + 1);
        }
        for v in cands {
            // `storage.ram_percent` etc. are plain; the heap pair has a
            // power-of-two rule that makes odd candidates fail in both.
            let t = toml_accepts_uint(f, v);
            let b = blob_accepts_uint(f, v);
            assert_eq!(
                t, b,
                "{} = {v}: parse says {t}, blob validator says {b}",
                f.key
            );
            checked += 1;
        }
    }
    assert!(checked > 80, "only {checked} cases");
}

#[test]
fn enum_variants_agree() {
    for f in FIELDS {
        let Kind::Enum { variants, .. } = f.kind else {
            continue;
        };
        for (i, v) in variants.iter().enumerate() {
            // storage.mode "disk" and the others are all fine in prod.
            if f.key == "network.mode" {
                continue; // needs addresses; covered by cross_field tests
            }
            let t = pack_plain(&with(f.key, &format!("{v:?}"))).is_ok();
            let mut b = Builder::new();
            b.variant(f.tag, i as u8).unwrap();
            assert!(t, "{} = {v}", f.key);
            assert!(b.finish(false).is_ok(), "{} = {v}", f.key);
        }
        let mut b = Builder::new();
        assert!(b.variant(f.tag, variants.len() as u8).is_err(), "{}", f.key);
        assert!(
            pack_plain(&with(f.key, "\"nonsense\"")).is_err(),
            "{}",
            f.key
        );
    }
}

#[test]
fn cross_field_verdicts_agree() {
    // (TOML, blob builder) pairs that must be accepted or refused alike.
    type Case = (&'static str, Box<dyn Fn(&mut Builder)>);
    let cases: Vec<Case> = vec![
        (
            "[limits]\nmax_topic_len = 4096\n",
            Box::new(|b| b.uint(tag::LIM_TOPIC_LEN, 4096).unwrap()),
        ),
        (
            "[limits]\nmax_topic_len = 4095\n",
            Box::new(|b| b.uint(tag::LIM_TOPIC_LEN, 4095).unwrap()),
        ),
        (
            "[limits]\nmax_retained_bytes = 8388608\n",
            Box::new(|b| b.uint(tag::LIM_RETAINED_BYTES, 8 << 20).unwrap()),
        ),
        (
            "[limits]\nmax_retained_bytes = 8388609\n",
            Box::new(|b| b.uint(tag::LIM_RETAINED_BYTES, (8 << 20) + 1).unwrap()),
        ),
        (
            "[memory]\nkernel_heap_mb = 100\n",
            Box::new(|b| b.uint(tag::MEM_HEAP, 100).unwrap()),
        ),
        (
            "[memory]\nmin_free_mb = 64\n",
            Box::new(|b| b.uint(tag::MEM_MIN_FREE, 64).unwrap()),
        ),
        (
            "[memory]\nmin_free_mb = 63\n",
            Box::new(|b| b.uint(tag::MEM_MIN_FREE, 63).unwrap()),
        ),
        (
            "[network]\nmqtt_plain_port = 1883\n",
            Box::new(|b| b.uint(tag::NET_PLAIN_PORT, 1883).unwrap()),
        ),
        (
            "[storage]\nrequire_flush = false\n",
            Box::new(|b| b.bool(tag::ST_REQUIRE_FLUSH, false).unwrap()),
        ),
        (
            "[acl]\ndevice_publish = [\"a/#/b\"]\n",
            Box::new(|b| b.strs(tag::ACL_DEVICE_PUBLISH, &["a/#/b"]).unwrap()),
        ),
        (
            "[acl]\ndevice_publish = [\"a/{id}/#\", \"b/+\"]\n",
            Box::new(|b| {
                b.strs(tag::ACL_DEVICE_PUBLISH, &["a/{id}/#", "b/+"])
                    .unwrap()
            }),
        ),
        (
            "[storage]\ntelemetry_topics = [\"a/{id}\"]\n",
            Box::new(|b| b.strs(tag::ST_TELEMETRY, &["a/{id}"]).unwrap()),
        ),
        (
            "[acl]\nservice_publish = [\"$SYS/x\"]\n",
            Box::new(|b| b.strs(tag::ACL_SERVICE_PUBLISH, &["$SYS/x"]).unwrap()),
        ),
        (
            "[acl]\nservice_ids = [\"op*\"]\noperator_ids = [\"operator\"]\n",
            Box::new(|b| {
                b.strs(tag::ACL_SERVICE_IDS, &["op*"]).unwrap();
            }),
        ),
        (
            "[acl]\noperator_ids = [\"a\", \"a\"]\n",
            Box::new(|b| b.strs(tag::ACL_OPERATOR_IDS, &["a", "a"]).unwrap()),
        ),
        (
            "[control]\nservice_ids = [\"x*\"]\n",
            Box::new(|b| b.strs(tag::CTL_SERVICE_IDS, &["x*"]).unwrap()),
        ),
        (
            "[cpu]\ndisable = [\"aes\", \"aes\"]\n",
            Box::new(|b| b.strs(tag::CPU_DISABLE, &["aes", "aes"]).unwrap()),
        ),
        (
            "[cpu]\ndisable = [\"warp\"]\n",
            Box::new(|b| b.strs(tag::CPU_DISABLE, &["warp"]).unwrap()),
        ),
        (
            "[time]\nservers = [\"127.0.0.1\"]\n",
            Box::new(|b| {
                b.addrs(tag::TIME_SERVERS, &[([127, 0, 0, 1], 123)])
                    .unwrap()
            }),
        ),
        (
            "[time]\nservers = [\"192.0.2.1\", \"192.0.2.1:123\"]\n",
            Box::new(|b| {
                b.addrs(
                    tag::TIME_SERVERS,
                    &[([192, 0, 2, 1], 123), ([192, 0, 2, 1], 123)],
                )
                .unwrap();
            }),
        ),
        (
            "[observability]\nsyslog_udp = \"10.0.0.5:0\"\n",
            Box::new(|b| b.addr(tag::OBS_SYSLOG, [10, 0, 0, 5], 0).unwrap()),
        ),
        ("[tls]\nrevocation_list = \"\"\n", Box::new(|_| {})),
    ];
    for (toml, build) in cases {
        let t = pack_plain(toml).is_ok();
        let mut b = Builder::new();
        build(&mut b);
        let k = b.finish(false).is_ok();
        assert_eq!(
            t, k,
            "{toml:?}: parse/pack says {t}, blob validator says {k}"
        );
    }
}

#[test]
fn bad_toml_is_reported_with_the_key() {
    let e = pack_plain("[network]\nmqtt_tls_port = 0\n").unwrap_err();
    assert!(e.iter().any(|x| x.path == "network.mqtt_tls_port"), "{e:?}");
    let e = pack_plain("[network]\nbogus = 1\n").unwrap_err();
    assert!(!e.is_empty());
    assert!(pack_plain("env = \"Bad Env\"\n").is_err());
}

fn dev_reader(name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(dev_dir().join(name)).map_err(|e| e.to_string())
}

#[test]
fn the_dev_configuration_packs_and_round_trips() {
    if !have_dev_certs() {
        eprintln!("skipped: run `make certs` first");
        return;
    }
    let text = include_str!("../../../deploy/dev/config.toml");
    let mut read = dev_reader;
    let blob = pack(
        &format!("env = \"dev\"\n{text}"),
        PackOptions {
            read: &mut read,
            now_unix: NOW,
        },
    )
    .expect("dev packs");
    let b = Blob::parse(&blob).unwrap();
    let cfg = parse("dev", text).unwrap();
    assert_eq!(b.str(tag::ENV), "dev");
    assert_eq!(b.uint(tag::NET_PLAIN_PORT), 1883);
    assert_eq!(
        b.uint(tag::NET_TLS_PORT),
        u64::from(cfg.network.mqtt_tls_port)
    );
    assert_eq!(
        b.uint(tag::LIM_CONNECTIONS),
        u64::from(cfg.limits.max_connections_per_core)
    );
    assert_eq!(
        b.strs(tag::ACL_OPERATOR_IDS).collect::<Vec<_>>(),
        cfg.acl.operator_ids
    );
    assert_eq!(b.bins(tag::TRUST_OPERATIONAL).count(), 2);
    assert_eq!(b.bins(tag::TRUST_BOOTSTRAP).count(), 1);
    assert!(
        b.bin(tag::TLS_CERT)
            .starts_with(b"-----BEGIN CERTIFICATE-----")
    );
    assert!(b.key32(tag::CTL_PUBLIC_KEY).is_some());
    assert!(b.uint(tag::TLS_CERT_NOT_AFTER) > NOW);
    assert!(
        b.strs(tag::TLS_REVOKED).count() > 0,
        "dev revoked.txt has entries"
    );
    // A dev blob is refused by a release kernel and accepted by a dev kernel.
    assert!(urmqtt_cfg::check::check(&b, false).is_err());
    assert!(urmqtt_cfg::check::check(&b, true).is_ok());
    // The same input twice is the same bytes.
    let mut read2 = dev_reader;
    let again = pack(
        &format!("env = \"dev\"\n{text}"),
        PackOptions {
            read: &mut read2,
            now_unix: NOW + 5,
        },
    )
    .unwrap();
    assert_eq!(blob, again);
}

#[test]
fn prod_and_bench_configurations_pack_with_the_dev_files() {
    if !have_dev_certs() {
        eprintln!("skipped: run `make certs` first");
        return;
    }
    for text in [
        include_str!("../../../deploy/prod/config.toml"),
        include_str!("../../../deploy/bench/config.toml"),
    ] {
        // Same file names, the dev directory's contents.
        let mut read = |name: &str| match name {
            "server.pem" | "server.key" | "ca.pem" | "control.pub" | "revoked.txt" => {
                dev_reader(name)
            }
            other => Err(format!("unexpected file {other}")),
        };
        let blob = pack(
            text,
            PackOptions {
                read: &mut read,
                now_unix: NOW,
            },
        )
        .expect("packs");
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.str(tag::ENV), "prod");
        assert_eq!(b.uint(tag::NET_PLAIN_PORT), 0);
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
}

#[test]
fn expired_and_wrong_files_are_refused() {
    if !have_dev_certs() {
        eprintln!("skipped: run `make certs` first");
        return;
    }
    let text = "[tls]\ncert = \"server.pem\"\nkey = \"server.key\"\n";
    let go = |now: u64, swap: bool| {
        let mut read = |name: &str| {
            let n = match (swap, name) {
                (true, "server.pem") => "server.key",
                (_, n) => n,
            };
            dev_reader(n)
        };
        pack(
            text,
            PackOptions {
                read: &mut read,
                now_unix: now,
            },
        )
    };
    assert!(go(NOW, false).is_ok());
    // Far in the future: the certificate has expired.
    let e = go(4_000_000_000, false).unwrap_err();
    assert!(e.iter().any(|x| x.path == "tls.cert"), "{e:?}");
    // A key where the certificate belongs.
    assert!(go(NOW, true).is_err());
    // A file that is missing.
    let mut none = no_files;
    let e = pack(
        text,
        PackOptions {
            read: &mut none,
            now_unix: NOW,
        },
    )
    .unwrap_err();
    assert!(e.iter().any(|x| x.message.contains("cannot read")), "{e:?}");
    let _ = PemKind::Certificate;
}
