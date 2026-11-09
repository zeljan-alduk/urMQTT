//! ADR-318: the `observability.log_tls*` keys (log shipping over TLS on the
//! outbound TCP client, NEXT-7) through the TOML path. A configuration that
//! does not use them is the blob it always was; set, they need format 20;
//! the strict parser and the kernel's blob check accept and refuse the same
//! values, and the trust anchors are read and checked like the operational
//! CAs.

use std::path::PathBuf;

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, parse};

const NOW: u64 = 1_800_000_000;

fn dev_ca() -> Option<Vec<u8>> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev/ca.pem")).ok()
}

fn pack_with_ca(text: &str, ca: Option<&[u8]>) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |name: &str| match (name, ca) {
        ("log-ca.pem", Some(b)) => Ok(b.to_vec()),
        ("not-a-cert.pem", _) => Ok(b"hello".to_vec()),
        _ => Err("no such file in this test".to_owned()),
    };
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: NOW,
            env: None,
        },
    )
}

fn keys(r: Result<Vec<u8>, Vec<ConfigError>>) -> Vec<String> {
    match r {
        Ok(_) => Vec::new(),
        Err(e) => e.into_iter().map(|e| e.path).collect(),
    }
}

/// Off by default, also in the shipped development and benchmark
/// configurations; the defaults written out change nothing.
#[test]
fn off_by_default_and_the_blob_is_unchanged() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let o = parse(env, text).unwrap().observability;
        assert_eq!(
            (
                o.log_tls,
                o.log_tls_name.as_str(),
                o.log_tls_ca.len(),
                o.log_tls_queue_kb
            ),
            (None, "", 0, 256),
            "{env}"
        );
    }
    let blob = pack_with_ca(
        "[observability]\nlog_tls = \"\"\nlog_tls_name = \"\"\nlog_tls_ca = []\nlog_tls_queue_kb = 256\n",
        None,
    )
    .unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

/// A collector with its anchors: format 20, the PEM in the blob, and a
/// release kernel's check accepts it.
#[test]
fn a_collector_needs_format_20_and_carries_its_anchors() {
    let Some(ca) = dev_ca() else {
        return eprintln!("no dev certs, run make certs");
    };
    let blob = pack_with_ca(
        "[observability]\nlog_tls = \"10.0.2.2:6514\"\nlog_tls_name = \"logs.example.com\"\nlog_tls_ca = [\"log-ca.pem\"]\nlog_tls_queue_kb = 64\n",
        Some(&ca),
    )
    .unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 20);
    assert_eq!(b.addr(tag::OBS_LOG_TLS), Some(([10, 0, 2, 2], 6514)));
    assert_eq!(b.str(tag::OBS_LOG_TLS_NAME), "logs.example.com");
    assert_eq!(b.bins(tag::OBS_LOG_TLS_CA).collect::<Vec<_>>(), [&ca[..]]);
    assert_eq!(b.uint(tag::OBS_LOG_TLS_QUEUE_KB), 64);
    urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    // Without a name the address is the name: still format 20 (the address).
    let blob = pack_with_ca(
        "[observability]\nlog_tls = \"192.0.2.7:6514\"\nlog_tls_ca = [\"log-ca.pem\"]\n",
        Some(&ca),
    )
    .unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!((b.version(), b.present().count()), (20, 2));
}

/// Every refusal names its key, in the TOML path as in the blob check.
#[test]
fn refusals_name_their_keys() {
    let ca = dev_ca();
    let with = |extra: &str| format!("[observability]\n{extra}\n");
    let ca_line = "log_tls_ca = [\"log-ca.pem\"]";
    for (text, key) in [
        (
            with("log_tls = \"10.0.2.2:6514\""),
            "observability.log_tls_ca",
        ),
        (with("log_tls = \"10.0.2.2\""), "observability.log_tls"),
        (
            with("log_tls = \"logs.example.com:6514\""),
            "observability.log_tls",
        ),
        (with("log_tls = \"10.0.2.2:0\""), "observability.log_tls"),
        (
            with(&format!("log_tls = \"127.0.0.1:6514\"\n{ca_line}")),
            "observability.log_tls",
        ),
        (
            with(&format!("log_tls = \"224.0.0.9:6514\"\n{ca_line}")),
            "observability.log_tls",
        ),
        (
            with(&format!("log_tls = \"0.0.0.0:6514\"\n{ca_line}")),
            "observability.log_tls",
        ),
        (
            with(&format!(
                "log_tls = \"10.0.2.2:6514\"\n{ca_line}\nlog_tls_name = \"bad name\""
            )),
            "observability.log_tls_name",
        ),
        (
            with(&format!(
                "log_tls = \"10.0.2.2:6514\"\n{ca_line}\nlog_tls_name = \"10.0.2.2\""
            )),
            "observability.log_tls_name",
        ),
        (
            with(&format!(
                "log_tls = \"10.0.2.2:6514\"\n{ca_line}\nlog_tls_queue_kb = 15"
            )),
            "observability.log_tls_queue_kb",
        ),
        (
            with(&format!(
                "log_tls = \"10.0.2.2:6514\"\n{ca_line}\nlog_tls_queue_kb = 4097"
            )),
            "observability.log_tls_queue_kb",
        ),
        (
            with("log_tls = \"10.0.2.2:6514\"\nlog_tls_ca = [\"not-a-cert.pem\"]"),
            "observability.log_tls_ca",
        ),
        (
            with("log_tls = \"10.0.2.2:6514\"\nlog_tls_ca = [\"missing.pem\"]"),
            "observability.log_tls_ca",
        ),
        (
            with(&format!(
                "log_tls = \"10.0.2.2:6514\"\nlog_tls_ca = [{}]",
                ["\"log-ca.pem\""; 9].join(", ")
            )),
            "observability.log_tls_ca",
        ),
        // The collector's keys without the collector.
        (
            with("log_tls_name = \"logs.example.com\""),
            "observability.log_tls_name",
        ),
        (with(ca_line), "observability.log_tls_ca"),
        (
            with("log_tls_queue_kb = 64"),
            "observability.log_tls_queue_kb",
        ),
    ] {
        let got = keys(pack_with_ca(&text, ca.as_deref()));
        assert!(got.iter().any(|k| k == key), "{text}: {got:?}");
    }
}

/// The TOML path and the kernel's check agree on blobs made directly.
#[test]
fn the_blob_check_refuses_what_the_toml_path_refuses() {
    let pem = b"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n".to_vec();
    let check = |b: &Builder| b.finish(false).map_err(|e| e.key);
    let mut b = Builder::new();
    b.addr(tag::OBS_LOG_TLS, [10, 0, 2, 2], 6514).unwrap();
    assert_eq!(check(&b), Err("observability.log_tls_ca"));
    b.bins(tag::OBS_LOG_TLS_CA, std::slice::from_ref(&pem))
        .unwrap();
    assert!(check(&b).is_ok());
    b.str(tag::OBS_LOG_TLS_NAME, "under_score").unwrap();
    assert_eq!(check(&b), Err("observability.log_tls_name"));
    let mut b = Builder::new();
    b.bins(tag::OBS_LOG_TLS_CA, &[pem]).unwrap();
    assert_eq!(check(&b), Err("observability.log_tls_ca"));
}

/// The form gets the keys from the schema: format 20, the defaults, and the
/// anchors as a list of files.
#[test]
fn the_schema_describes_the_keys() {
    let s = schema_json();
    for key in [
        "observability.log_tls",
        "observability.log_tls_name",
        "observability.log_tls_ca",
        "observability.log_tls_queue_kb",
    ] {
        let at = s
            .find(&format!("\"key\":\"{key}\""))
            .unwrap_or_else(|| panic!("{key}"));
        let rest = &s[at..];
        let end = rest.find('}').unwrap();
        assert!(
            rest[..end].contains("\"since\":20"),
            "{key}: {}",
            &rest[..end]
        );
    }
}
