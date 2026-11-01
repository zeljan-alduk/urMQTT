//! C1d: `urmqtt-config` end to end (the binary), and the image patching on
//! synthetic images. Fixtures are in `tests/fixtures/`; the certificate tests
//! use the development certificates `make certs` creates (skipped without).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use urmqtt_cfg::blake2b;
use urmqtt_cfg::blob::{DISK_MARKER, SLOT_SIZE, SlotKind, make_slot};
use urmqtt_config_tool::image;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_urmqtt-config"))
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn dev_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev")
}

fn have_dev_certs() -> bool {
    dev_dir().join("server.pem").exists()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("urmqtt-config-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("runs")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "failed: {}\n{}",
        String::from_utf8_lossy(&o.stderr),
        String::from_utf8_lossy(&o.stdout)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn pack_is_deterministic_and_matches_the_golden_blob() {
    let out = tmp("lab.blob");
    let o = run(bin()
        .args(["pack"])
        .arg(fixtures().join("lab.toml"))
        .arg("--out")
        .arg(&out));
    let text = ok(&o);
    assert!(
        text.contains(
            "fingerprint 1a5d4dcce0a2767a29f39c984e55ae5cdd92b8940257de0ac7a23de64f386cd6"
        ),
        "{text}"
    );
    let packed = std::fs::read(&out).unwrap();
    // The golden blob pins the format (ADR-215): if this fails, a tag or an
    // encoding changed, which must not happen without a format version.
    assert_eq!(packed, std::fs::read(fixtures().join("lab.blob")).unwrap());
    // Packing twice, even with another clock, gives the same bytes.
    let out2 = tmp("lab2.blob");
    ok(&run(bin()
        .args(["pack"])
        .arg(fixtures().join("lab.toml"))
        .args(["--now", "1900000000", "--out"])
        .arg(&out2)));
    assert_eq!(packed, std::fs::read(&out2).unwrap());
}

#[test]
fn invalid_input_reports_every_problem_and_writes_nothing() {
    let out = tmp("bad.blob");
    let _ = std::fs::remove_file(&out);
    let o = run(bin()
        .args(["pack"])
        .arg(fixtures().join("bad.toml"))
        .arg("--out")
        .arg(&out));
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    for needle in [
        "network.mqtt_tls_port",
        "network.mqtt_plain_port",
        "acl.device_publish[0]",
        "memory.kernel_heap_mb",
    ] {
        assert!(err.contains(needle), "{needle} missing from:\n{err}");
    }
    assert!(!out.exists(), "nothing is written on error");
}

#[test]
fn show_prints_values_that_differ_from_the_defaults() {
    let o = run(bin().arg("show").arg(fixtures().join("lab.blob")));
    let text = ok(&o);
    for line in [
        "fingerprint: 1a5d4dcce0a2767a29f39c984e55ae5cdd92b8940257de0ac7a23de64f386cd6",
        "signature:   none",
        "mode = static",
        "address = 192.0.2.10/24",
        "mqtt_tls_port = 8884",
        "publish_rate_per_device = 600/m",
        "kernel_heap_mb = 128",
        "servers = 192.0.2.123:123",
    ] {
        assert!(text.contains(line), "{line:?} missing from:\n{text}");
    }
    assert!(!text.contains("max_topic_len"), "defaults are not listed");
    let all = ok(&run(bin()
        .arg("show")
        .arg(fixtures().join("lab.blob"))
        .arg("--all")));
    assert!(all.contains("max_topic_len = 256  (default)"), "{all}");
}

#[test]
fn verify_accepts_a_release_blob_and_refuses_a_dev_one_as_a_release_kernel() {
    let o = run(bin().arg("verify").arg(fixtures().join("lab.blob")));
    assert!(ok(&o).starts_with("ok: fingerprint 1a5d"));
    // A tampered blob is refused.
    let mut bad = std::fs::read(fixtures().join("lab.blob")).unwrap();
    bad[20] ^= 1;
    let p = tmp("tampered.blob");
    std::fs::write(&p, &bad).unwrap();
    let o = run(bin().arg("verify").arg(&p));
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("fingerprint mismatch"));
}

#[test]
fn schema_lists_every_field_with_a_default() {
    let json = ok(&run(bin().arg("schema")));
    assert!(json.starts_with("{\"format\":\"urmqtt-cfg\""));
    assert_eq!(
        json.matches("\"default\":").count(),
        urmqtt_cfg::fields::FIELDS.len()
    );
}

#[test]
fn slots_wrap_blobs_and_signing_round_trips() {
    let slot = tmp("lab.slot");
    ok(&run(bin()
        .arg("slot")
        .arg(fixtures().join("lab.blob"))
        .arg(&slot)));
    assert_eq!(std::fs::metadata(&slot).unwrap().len() as usize, SLOT_SIZE);
    // show/verify read a slot too.
    assert!(ok(&run(bin().arg("verify").arg(&slot))).starts_with("ok: fingerprint 1a5d"));
    // An Ed25519 key (PKCS#8 PEM, as `openssl genpkey -algorithm ed25519` writes it).
    let key = tmp("sign.key");
    let seed = [7u8; 32];
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&seed);
    let b64 = {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in der.chunks(3) {
            let n = c.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - c.len()));
            for i in 0..=c.len() {
                s.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
            for _ in c.len()..3 {
                s.push('=');
            }
        }
        s
    };
    std::fs::write(
        &key,
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();
    let out = tmp("signed.blob");
    let text = ok(&run(bin()
        .arg("pack")
        .arg(fixtures().join("lab.toml"))
        .arg("--sign")
        .arg(&key)
        .arg("--out")
        .arg(&out)));
    // The fingerprint is the unsigned blob's.
    assert!(text.contains("1a5d4dcce0a2767a"), "{text}");
    assert!(text.contains("signed"));
    let shown = ok(&run(bin().arg("show").arg(&out)));
    assert!(shown.contains("signature:   valid, signer key "), "{shown}");
}

#[test]
fn the_development_configuration_packs_with_its_certificates() {
    if !have_dev_certs() {
        eprintln!("skipped: run `make certs` first");
        return;
    }
    let out = tmp("dev.slot");
    let o = run(bin()
        .arg("pack")
        .arg(dev_dir().join("config.toml"))
        .args(["--env", "dev", "--out-slot"])
        .arg(&out));
    ok(&o);
    let shown = ok(&run(bin().arg("show").arg(&out)));
    assert!(shown.contains("mqtt_plain_port = 1883"));
    assert!(shown.contains("CN=localhost"));
    assert!(
        shown.contains("private key,"),
        "keys are summarised: {shown}"
    );
    assert!(!shown.contains("BEGIN"), "no PEM is ever printed");
    // As a release kernel: refused (env = dev).
    let o = run(bin().arg("verify").arg(&out));
    assert!(!o.status.success());
    ok(&run(bin().arg("verify").arg(&out).arg("--dev")));
}

// --- images ---------------------------------------------------------------

fn lab_blob() -> Vec<u8> {
    std::fs::read(fixtures().join("lab.blob")).unwrap()
}

fn empty_blob() -> Vec<u8> {
    urmqtt_cfg::build::Builder::new().finish(false).unwrap()
}

fn conf(hash: &str) -> Vec<u8> {
    let mut t = String::from("timeout: 0\n");
    for entry in ["urMQTT", "Install", "Diagnostic"] {
        t.push_str(&format!(
            "/{entry}\n    protocol: limine\n    module_path: boot():/boot/urmqtt.cfg#{hash}\n"
        ));
    }
    t.into_bytes()
}

/// A stand-in for the template ISO: filler, the slot twice (the ISO 9660 file
/// and the one in the FAT image), the unconfigured slot of the installation
/// image twice, and four `limine.conf` copies naming the slot's hash.
fn synthetic_template() -> (Vec<u8>, Vec<usize>) {
    let slot = make_slot(SlotKind::Boot, &empty_blob()).unwrap();
    let mut disk = slot.clone();
    disk[..16].copy_from_slice(&DISK_MARKER);
    let hash: String = blake2b::hash(&slot)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut img = Vec::new();
    let pad = |img: &mut Vec<u8>, n: usize| img.extend((0..n).map(|i| (i * 31 % 251) as u8));
    let mut slot_offs = Vec::new();
    for part in 0..4 {
        pad(&mut img, 4096 + part * 512);
        match part {
            0 | 2 => {
                slot_offs.push(img.len());
                img.extend_from_slice(&slot);
            }
            _ => img.extend_from_slice(&disk),
        }
        pad(&mut img, 1000);
        img.extend_from_slice(&conf(&hash));
        // Text is not 512-aligned; keep the next slot aligned.
        img.resize(img.len().next_multiple_of(512), 0);
    }
    // The stray marker (as in the kernel's constants) is not a slot.
    img.extend_from_slice(&urmqtt_cfg::SLOT_MARKER);
    img.extend_from_slice(&[0xAA; 1000]);
    (img, slot_offs)
}

#[test]
fn the_template_is_configured_in_place() {
    let (tpl, slot_offs) = synthetic_template();
    let blob = lab_blob();
    let p = image::configure_iso(&tpl, &blob).unwrap();
    assert_eq!(p.bytes.len(), tpl.len(), "same size");
    assert!(
        p.report.contains("2 copies of the slot replaced"),
        "{}",
        p.report
    );
    assert!(
        p.report.contains("12 module hash references"),
        "{}",
        p.report
    );
    let new_slot = make_slot(SlotKind::Boot, &blob).unwrap();
    for o in &slot_offs {
        assert_eq!(&p.bytes[*o..*o + SLOT_SIZE], &new_slot[..]);
    }
    // Everything else outside the slots and the hash text is unchanged, the
    // installation image's template slots included.
    for (i, (a, b)) in tpl.iter().zip(&p.bytes).enumerate() {
        let in_slot = slot_offs.iter().any(|o| (*o..*o + SLOT_SIZE).contains(&i));
        if !in_slot && a != b {
            // Must be a hex digit of a hash.
            assert!(
                a.is_ascii_hexdigit() && b.is_ascii_hexdigit(),
                "byte {i} changed"
            );
        }
    }
    // It verifies, and shows the new fingerprint.
    let v = image::verify(&p.bytes, false).unwrap();
    assert!(
        v.contains("2 slot copies identical, 12 module hash reference(s) match"),
        "{v}"
    );
    let shown = image::show(&p.bytes, false).unwrap();
    assert!(shown.contains("1a5d4dcce0a2767a"), "{shown}");
    assert!(shown.contains("2 configuration slot copies"), "{shown}");
    assert!(
        shown.contains("2 installation-image template copies"),
        "{shown}"
    );
    // Deterministic, and re-configurable.
    assert_eq!(image::configure_iso(&tpl, &blob).unwrap().bytes, p.bytes);
    let again = image::configure_iso(&p.bytes, &empty_blob()).unwrap();
    assert_eq!(again.bytes, tpl, "back to the template, byte for byte");
}

#[test]
fn inconsistent_or_foreign_images_are_refused() {
    let (tpl, slot_offs) = synthetic_template();
    let blob = lab_blob();
    // No slot at all.
    assert!(image::configure_iso(&vec![0u8; 100_000], &blob).is_err());
    // The copies of the slot differ.
    let mut diff = tpl.clone();
    let other = make_slot(SlotKind::Boot, &lab_blob()).unwrap();
    diff[slot_offs[1]..slot_offs[1] + SLOT_SIZE].copy_from_slice(&other);
    let e = image::configure_iso(&diff, &blob).err().unwrap();
    assert!(e.contains("differ"), "{e}");
    // A limine.conf names another hash than the slot's.
    let mut wrong = tpl.clone();
    let at = wrong
        .windows(17)
        .position(|w| w == b"/boot/urmqtt.cfg#")
        .unwrap()
        + 17;
    wrong[at] = if wrong[at] == b'0' { b'1' } else { b'0' };
    let e = image::configure_iso(&wrong, &blob).err().unwrap();
    assert!(e.contains("different module hash"), "{e}");
    assert!(image::verify(&wrong, false).is_err());
    // No limine.conf names the module.
    let mut nohash = tpl.clone();
    for w in 0..nohash.len() - 17 {
        if &nohash[w..w + 17] == b"/boot/urmqtt.cfg#" {
            nohash[w + 16] = b'!';
        }
    }
    assert!(image::configure_iso(&nohash, &blob).is_err());
    // A blob a release kernel would refuse is not written into an image.
    let mut dev = urmqtt_cfg::build::Builder::new();
    dev.str(urmqtt_cfg::fields::tag::ENV, "dev").unwrap();
    dev.uint(urmqtt_cfg::fields::tag::NET_PLAIN_PORT, 1883)
        .unwrap();
    let dev = dev.finish(true).unwrap();
    // (dev blobs are allowed for packing: the tool checks them as a dev kernel;
    // the verdict for a release kernel is `verify`'s.)
    assert!(image::configure_iso(&tpl, &dev).is_ok());
    assert!(image::verify(&image::configure_iso(&tpl, &dev).unwrap().bytes, false).is_err());
}

#[test]
fn a_raw_image_gets_its_unconfigured_slot_replaced() {
    let slot = make_slot(SlotKind::Boot, &empty_blob()).unwrap();
    let mut disk = slot;
    disk[..16].copy_from_slice(&DISK_MARKER);
    let mut img = vec![0x55u8; 8192];
    img.extend_from_slice(&disk);
    img.extend_from_slice(&[0x66; 4096]);
    let blob = lab_blob();
    let p = image::configure_raw(&img, &blob).unwrap();
    assert_eq!(p.bytes.len(), img.len());
    assert_eq!(&p.bytes[..8192], &img[..8192]);
    assert!(image::show(&p.bytes, false).unwrap().contains("1a5d4dcc"));
    // Two slots: an ISO, not a raw image.
    let mut two = p.bytes.clone();
    two.extend_from_slice(&make_slot(SlotKind::Boot, &blob).unwrap());
    assert!(image::configure_raw(&two, &blob).is_err());
    assert!(image::configure_raw(&[0u8; 5000], &blob).is_err());
}
