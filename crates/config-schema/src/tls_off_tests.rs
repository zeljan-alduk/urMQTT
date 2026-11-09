//! ADR-233: `network.mqtt_tls_port = 0` turns the TLS listener off, only with the plaintext listener on. The
//! strict parser, the packer and the kernel's blob check must agree, and the blob needs format version 3.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;
use urmqtt_cfg::passwd;

use crate::ConfigError;
use crate::pack::{PackOptions, pack, pack_with};

fn run(text: &str, newest: bool) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack_with(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
        newest,
    )
}

fn plain_only(extra: &str) -> String {
    format!(
        "[network]\nmqtt_tls_port = 0\n[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\n{extra}"
    )
}

#[test]
fn tls_off_needs_the_plaintext_listener() {
    for text in [
        "[network]\nmqtt_tls_port = 0\n",
        "[network]\nmqtt_tls_port = 0\n[plaintext]\nenabled = false\n",
    ] {
        let e = run(text, false).unwrap_err();
        assert!(
            e.iter()
                .any(|x| x.path == "network.mqtt_tls_port"
                    && x.message.contains("plaintext.enabled")),
            "{e:?}"
        );
    }
}

#[test]
fn plain_only_packs_without_a_certificate_a_key_or_a_ca_and_is_format_3() {
    let blob = run(&plain_only(""), false).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 3);
    assert_eq!(b.uint(tag::NET_TLS_PORT), 0);
    assert!(b.bool(tag::PL_ENABLED));
    // The packer ran the strict parser; the kernel-side check on the finished blob agrees.
    urmqtt_cfg::check::check(&b, false).unwrap();
    // Plain MQTT may now use the TLS port number.
    assert!(run(&plain_only("port = 8883\n"), false).is_ok());
}

#[test]
fn both_listeners_and_tls_only_stay_format_2() {
    let tls_only = run("", false).unwrap();
    assert_eq!(Blob::parse(&tls_only).unwrap().version(), 2);
    let both = run(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\n",
        false,
    )
    .unwrap();
    assert_eq!(
        Blob::parse(&both).unwrap().version(),
        2,
        "an image that needs nothing new stays readable by the older kernel"
    );
}

#[test]
fn the_newest_format_can_be_asked_for_and_never_a_lower_one_than_needed() {
    let empty = run("", true).unwrap();
    assert_eq!(Blob::parse(&empty).unwrap().version(), 18);
    assert_eq!(
        pack(
            "",
            PackOptions {
                read: &mut |_: &str| Err(String::new()),
                now_unix: 1,
                env: None
            }
        )
        .unwrap(),
        Builder::new().finish(false).unwrap()
    );
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 0).unwrap();
    assert_eq!(b.lowest_version(), 3);
    assert!(b.finish_as(false, 2).is_err());
    assert!(b.finish_as(false, 7).is_err());
}

#[test]
fn the_old_checks_still_hold_with_tls_on() {
    // A development image may still not put the two plain listeners on one port, and the TLS port may not repeat.
    let e = run("[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nauth = \"anonymous\"\nport = 8883\n", false).unwrap_err();
    assert!(e.iter().any(|x| x.path == "plaintext.port"), "{e:?}");
    let _ = passwd::encode;
}
