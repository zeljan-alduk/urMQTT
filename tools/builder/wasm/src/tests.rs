//! Host tests of the module's functions. The decisive test, that the compiled
//! `.wasm` and the command line tool produce the same bytes, runs under Node
//! (`tools/builder/test/wasm-vs-cli.test.mjs`); these cover the Rust side.

use std::path::{Path, PathBuf};

use urmqtt_config_tool::{PackArgs, image, pack_blob};

use crate::core::{self, Files};
use crate::exports::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/tests/fixtures")
}

fn lab_toml() -> String {
    std::fs::read_to_string(fixtures().join("lab.toml")).unwrap()
}

#[test]
fn packing_equals_the_command_line_tool() {
    let blob = core::pack(&lab_toml(), &Files::new(), None, 1_900_000_000, None).unwrap();
    let cli = pack_blob(&PackArgs {
        latest_format: false,
        toml: fixtures().join("lab.toml"),
        now_unix: Some(1_900_000_000),
        ..PackArgs::default()
    })
    .unwrap();
    assert_eq!(blob, cli);
    assert_eq!(blob, std::fs::read(fixtures().join("lab.blob")).unwrap());
}

#[test]
fn problems_come_back_as_json_addressed_by_key() {
    let bad = std::fs::read_to_string(fixtures().join("bad.toml")).unwrap();
    let e = core::pack(&bad, &Files::new(), None, 1_900_000_000, None).unwrap_err();
    assert!(e.starts_with('['), "{e}");
    assert!(e.contains(r#""path":"network.mqtt_tls_port""#), "{e}");
    assert!(e.contains(r#""path":"memory.kernel_heap_mb""#), "{e}");
    // The release kernel's rules apply even though a dev blob would pack:
    // a plaintext port is refused, with the key it is about.
    let e = core::pack(
        "[network]\nmqtt_plain_port = 1883\n",
        &Files::new(),
        None,
        1_900_000_000,
        None,
    )
    .unwrap_err();
    assert!(e.contains("network.mqtt_plain_port"), "{e}");
    let e = core::pack("", &Files::new(), Some("dev"), 1_900_000_000, None).unwrap_err();
    assert!(e.contains("dev"), "{e}");
}

#[test]
fn a_file_the_toml_names_but_nobody_chose_is_reported() {
    let e = core::pack(
        "[tls]\ncert = \"server.pem\"\n",
        &Files::new(),
        None,
        1_900_000_000,
        None,
    )
    .unwrap_err();
    assert!(e.contains("tls.cert") && e.contains("server.pem"), "{e}");
}

#[test]
fn signing_is_optional_and_checked() {
    let k = core::new_signing_key(&[5u8; 32]).unwrap();
    let pem = k
        .split("\"private_pem\":\"")
        .nth(1)
        .unwrap()
        .split("\",\"public_pem\"")
        .next()
        .unwrap()
        .replace("\\n", "\n");
    let blob = core::pack(
        &lab_toml(),
        &Files::new(),
        None,
        1_900_000_000,
        Some(pem.as_bytes()),
    )
    .unwrap();
    let info = core::blob_info(&blob).unwrap();
    assert!(info.contains(r#""signed":true"#), "{info}");
    // Signing does not change the fingerprint.
    let plain = core::pack(&lab_toml(), &Files::new(), None, 1_900_000_000, None).unwrap();
    let fp = |i: &str| i.split("\"fingerprint\":\"").nth(1).unwrap()[..64].to_owned();
    assert_eq!(fp(&info), fp(&core::blob_info(&plain).unwrap()));
    let e = core::pack(
        &lab_toml(),
        &Files::new(),
        None,
        1_900_000_000,
        Some(b"nope"),
    )
    .unwrap_err();
    assert!(e.contains("signing key"), "{e}");
}

#[test]
fn the_schema_is_the_command_line_schema() {
    assert_eq!(core::schema(), urmqtt_config_schema::pack::schema_json());
    assert!(core::default_toml().contains("[network]"));
}

#[test]
fn toml_becomes_json() {
    let j =
        core::toml_to_json("a = 1\n[s]\nb = [\"x\", \"y\"]\nc = true\nd = \"q\\\"\"\n").unwrap();
    assert_eq!(j, r#"{"a":1,"s":{"b":["x","y"],"c":true,"d":"q\""}}"#);
    assert!(core::toml_to_json("a = ").is_err());
    assert!(core::toml_to_json("a = 1.5").is_err());
}

#[test]
fn the_handle_interface_round_trips() {
    // Buffers are zeroed, freed handles are reused, bad handles are refused.
    let a = ub_buf_new(16);
    assert_ne!(a, 0);
    assert_eq!(ub_buf_len(a), 16);
    ub_buf_free(a);
    assert_eq!(ub_buf_len(a), 0);
    let b = ub_buf_new(4);
    assert_eq!(b, a, "the freed slot is reused");
    ub_buf_free(b);
    assert_eq!(ub_blob_info(999), 0);
    let e = ub_error();
    assert_ne!(e, 0);
    ub_buf_free(e);
    assert_eq!(ub_error(), 0, "the error text is consumed");
    // A call with handles: the schema.
    let s = ub_schema();
    assert_ne!(s, 0);
    assert!(ub_buf_len(s) > 1000);
    ub_buf_free(s);
    assert_eq!(ub_abi_version(), core::ABI_VERSION);
    assert_eq!(ub_format_version(), 7);
}

/// P1: the page hashes a plaintext account's password in the module, with a
/// salt of its own; the clear text does not stay in the module's memory.
#[test]
fn a_password_is_hashed_with_the_pages_salt_and_wiped() {
    let put = |b: &[u8]| {
        let h = ub_buf_new(b.len() as u32);
        assert_ne!(h, 0);
        with(|s| {
            let slot = s.bufs[(h - 1) as usize].as_mut().unwrap();
            slot.copy_from_slice(b);
        });
        h
    };
    let read = |h: u32| with(|s| s.get(h).unwrap().to_vec());
    let pw = put(b"correct horse");
    let salt = put(&[7u8; 16]);
    let out = ub_hash_password(pw, salt, 1000);
    assert_ne!(out, 0);
    let text = String::from_utf8(read(out)).unwrap();
    assert!(
        text.starts_with("pbkdf2-sha256$1000$07070707070707070707070707070707$"),
        "{text}"
    );
    // The same as the command line's function, and the kernel's parser verifies it.
    assert_eq!(
        text,
        urmqtt_config_tool::hash_password(b"correct horse", &[7u8; 16], 1000).unwrap()
    );
    let parsed = urmqtt_cfg::passwd::PasswordHash::parse(&text).unwrap();
    assert!(parsed.verify(b"correct horse"));
    // The password buffer is zeros now; the salt buffer is untouched.
    assert!(read(pw).iter().all(|b| *b == 0));
    assert_eq!(read(salt), vec![7u8; 16]);
    // A failure wipes it too and says why.
    let pw2 = put(b"secret");
    assert_eq!(ub_hash_password(pw2, salt, 5), 0);
    assert!(read(pw2).iter().all(|b| *b == 0));
    let e = ub_error();
    assert!(String::from_utf8(read(e)).unwrap().contains("iterations"));
    // An empty or a too long password is refused, as by the command line.
    let nothing = ub_buf_new(0);
    assert_eq!(ub_hash_password(nothing, salt, 1000), 0);
    let e2 = ub_error();
    assert!(String::from_utf8(read(e2)).unwrap().contains("empty"));
    let long = put(&[b'x'; 300]);
    assert_eq!(ub_hash_password(long, salt, 1000), 0);
    let e3 = ub_error();
    assert!(
        String::from_utf8(read(e3))
            .unwrap()
            .contains("longer than 256")
    );
    for h in [pw, pw2, salt, out, e, nothing, e2, long, e3] {
        ub_buf_free(h);
    }
    assert_eq!(
        ub_hash_password(999, 998, 1000),
        0,
        "bad handles are refused"
    );
}

/// A stand-in template (see tools/config/tests/cli.rs), built with the
/// library's own helpers.
fn synthetic_template() -> Vec<u8> {
    use urmqtt_cfg::blake2b;
    use urmqtt_cfg::blob::{DISK_MARKER, SlotKind, make_slot};
    let empty = urmqtt_cfg::build::Builder::new()
        .finish_as(false, urmqtt_cfg::FORMAT_VERSION)
        .unwrap();
    assert_eq!(
        empty[8],
        urmqtt_cfg::FORMAT_VERSION as u8,
        "a template declares the newest format"
    );
    let slot = make_slot(SlotKind::Boot, &empty).unwrap();
    let mut disk = slot.clone();
    disk[..16].copy_from_slice(&DISK_MARKER);
    let hash: String = blake2b::hash(&slot)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let conf = format!(
        "timeout: 0\n/urMQTT\n    protocol: limine\n    module_path: boot():/boot/urmqtt.cfg#{hash}\n"
    );
    let mut img = Vec::new();
    for part in 0..4 {
        img.extend(std::iter::repeat_n(0x5a_u8, 4096 + part * 512));
        img.extend_from_slice(if part % 2 == 0 { &slot } else { &disk });
        img.extend_from_slice(conf.as_bytes());
        img.resize(img.len().next_multiple_of(512), 0);
    }
    img
}

#[test]
fn an_iso_is_probed_and_configured_in_place_like_the_tool_does() {
    let tpl = synthetic_template();
    let probe = core::iso_probe(&tpl).unwrap();
    assert!(
        probe.contains(r#""format_version":7"#) && probe.contains(r#""supported":true"#),
        "{probe}"
    );
    let blob = core::pack(&lab_toml(), &Files::new(), None, 1_900_000_000, None).unwrap();
    let mut iso = tpl.clone();
    let report = core::iso_configure(&mut iso, &blob).unwrap();
    assert_eq!(iso, image::configure_iso(&tpl, &blob).unwrap().bytes);
    assert!(report.starts_with("configured:"), "{report}");
    assert!(core::iso_verify(&iso).unwrap().contains("match"));
    // A configuration the release kernel would refuse never reaches the image.
    let dev = urmqtt_config_tool::pack_text(
        "env = \"dev\"\n[network]\nmqtt_plain_port = 1883\n",
        &mut |_: &str| Err("none".into()),
        None,
        1_900_000_000,
    )
    .unwrap();
    let mut untouched = tpl.clone();
    assert!(core::iso_configure(&mut untouched, &dev).is_err());
    assert_eq!(untouched, tpl);
    assert!(core::iso_probe(&[0u8; 1000]).is_err());
}

#[test]
fn a_release_is_verified_with_the_embedded_key() {
    let pubkey = include_str!("../../../../minisign.pub");
    let dir = fixtures().join("minisign");
    let sums = std::fs::read(dir.join("SHA256SUMS")).unwrap();
    let sig = std::fs::read_to_string(dir.join("SHA256SUMS.minisig")).unwrap();
    let j = core::verify_release(pubkey, &sums, &sig).unwrap();
    assert!(j.contains(r#""key_id":"9229E05252D01F8E""#), "{j}");
    assert!(j.contains("urmqtt-dev-v0.1.0.iso"), "{j}");
    assert_eq!(core::minisign_key_id(pubkey).unwrap(), "9229E05252D01F8E");
    let mut bad = sums.clone();
    bad[0] ^= 1;
    assert!(core::verify_release(pubkey, &bad, &sig).is_err());
}

fn dev(name: &str) -> Option<Vec<u8>> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../deploy/dev")
            .join(name),
    )
    .ok()
}

#[test]
fn certificates_keys_and_their_relations_are_reported() {
    let (Some(cert), Some(key), Some(ca)) = (dev("server.pem"), dev("server.key"), dev("ca.pem"))
    else {
        eprintln!("skipped: run `make certs` for the development certificates");
        return;
    };
    let info = core::cert_info(&cert).unwrap();
    assert!(info.contains(r#""key_type":"ECDSA P-256""#), "{info}");
    assert!(info.contains("\"names\":["), "{info}");
    let ki = core::key_info(&key).unwrap();
    assert!(
        ki.contains("ECDSA P-256") && !ki.contains("PRIVATE"),
        "{ki}"
    );
    let x = core::cross_check(&cert, &key, &ca).unwrap();
    assert!(x.contains(r#""key_matches":true"#), "{x}");
    assert!(
        x.contains(r#""by":"ca""#) && x.contains(r#""verified":true"#),
        "{x}"
    );
    // The CA's key is not the server's key; a second CA did not sign the certificate.
    let other = dev("ca-2.key").unwrap();
    assert!(
        core::cross_check(&cert, &other, &[])
            .unwrap()
            .contains(r#""key_matches":false"#)
    );
    let ca2 = dev("ca-2.pem").unwrap();
    let x2 = core::cross_check(&cert, &key, &ca2).unwrap();
    assert!(
        x2.contains(r#""by":null"#) || x2.contains(r#""verified":false"#),
        "{x2}"
    );
    // Nothing chosen yet.
    assert!(
        core::cross_check(&[], &[], &[])
            .unwrap()
            .contains(r#""key_matches":null"#)
    );
    // Garbage is an error, never a panic.
    assert!(
        core::cert_info(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err()
    );
    assert!(
        core::key_info(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err()
    );
    assert!(core::key_info(&cert).is_err());
}

#[test]
fn a_control_key_is_taken_from_either_half() {
    let (Some(publ), Some(private)) = (dev("control.pub"), dev("control.key")) else {
        eprintln!("skipped: run `make certs` for the development certificates");
        return;
    };
    let a = core::control_key(&publ).unwrap();
    let b = core::control_key(&private).unwrap();
    assert!(a.contains(r#""from_private":false"#) && b.contains(r#""from_private":true"#));
    let key = |j: &str| j.split("\"public_key\":\"").nth(1).unwrap()[..64].to_owned();
    assert_eq!(key(&a), key(&b));
    assert!(core::control_key(b"nothing").is_err());
}
