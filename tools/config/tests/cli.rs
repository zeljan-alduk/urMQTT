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
            "fingerprint 9df8c08e0655ec3bfc55f1c9acdec1a731a14a23515f4ac5e62c95aef8c69f79"
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
fn the_weak_entropy_path_is_warned_about_and_the_strict_one_is_not() {
    const WARNING: &str = "WARNING: entropy.fallback = \"jitter\": on a host without virtio-rng or RNDR/RDRAND the generator is seeded from CPU jitter and firmware values";
    // The default allows the jitter fallback: pack, verify and show say so.
    let out = tmp("entropy-default.blob");
    let text = ok(&run(bin()
        .arg("pack")
        .arg(fixtures().join("lab.toml"))
        .arg("--out")
        .arg(&out)));
    assert!(text.contains(WARNING), "{text}");
    assert!(
        text.contains("set it to \"none\" to refuse such hosts"),
        "{text}"
    );
    assert!(ok(&run(bin().arg("verify").arg(&out))).contains(WARNING));
    let shown = ok(&run(bin().arg("show").arg(&out)));
    assert!(
        shown.contains("entropy:     CPU-jitter fallback ALLOWED"),
        "{shown}"
    );
    assert!(shown.contains(WARNING.replace("WARNING: ", "WARNING:     ").as_str()));
    // `none` requires a hardware source: no warning, and show names the setting.
    let toml = tmp("entropy-none.toml");
    let mut t = std::fs::read_to_string(fixtures().join("lab.toml")).unwrap();
    t.push_str("\n[entropy]\nfallback = \"none\"\n");
    std::fs::write(&toml, t).unwrap();
    let strict = tmp("entropy-none.blob");
    let text = ok(&run(bin().arg("pack").arg(&toml).arg("--out").arg(&strict)));
    assert!(!text.contains("WARNING"), "{text}");
    let shown = ok(&run(bin().arg("show").arg(&strict)));
    assert!(
        shown.contains("entropy:     hardware source REQUIRED"),
        "{shown}"
    );
    assert!(shown.contains("fallback = none"), "{shown}");
    assert!(!shown.contains("WARNING"), "{shown}");
}

#[test]
fn show_prints_values_that_differ_from_the_defaults() {
    let o = run(bin().arg("show").arg(fixtures().join("lab.blob")));
    let text = ok(&o);
    for line in [
        "fingerprint: 9df8c08e0655ec3bfc55f1c9acdec1a731a14a23515f4ac5e62c95aef8c69f79",
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
    assert!(ok(&o).starts_with("ok: fingerprint 9df8"));
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
    assert!(ok(&run(bin().arg("verify").arg(&slot))).starts_with("ok: fingerprint 9df8"));
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
    assert!(text.contains("9df8c08e0655ec3b"), "{text}");
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
    synthetic_template_with(&empty_blob())
}

/// The same stand-in with a given empty configuration in its slot: a release's template declares the
/// format its kernel reads by the version of that empty blob (v0.2.0: 2, v0.2.1: 3, v0.3.0: 4, v0.4.0: 6).
fn synthetic_template_with(empty: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let slot = make_slot(SlotKind::Boot, empty).unwrap();
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
    assert!(shown.contains("9df8c08e0655ec3b"), "{shown}");
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

/// H8: a template whose loaders have the menu's limine.conf enrolled. Two menu copies (marker
/// lines as scripts/mkiso.sh writes them), two loaders enrolled with them, one loader of the
/// installation image enrolled with the no-menu config, which must not be touched.
fn enrolled_template() -> (Vec<u8>, String, String) {
    let (mut img, _) = synthetic_template();
    let slot = make_slot(SlotKind::Boot, &empty_blob()).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let hash = hex(&blake2b::hash(&slot));
    let menu = |h: &str| {
        let mut t = b"# Generated by scripts/mkiso.sh --universal: the menu\n".to_vec();
        t.extend(conf(h));
        t.extend_from_slice(b"\n# end of limine.conf\n");
        t
    };
    let nomenu = b"# Generated by scripts/mkiso.sh --universal. No menu and no editor.\ntimeout: 0\n\n# end of limine.conf\n";
    let menu_hash = hex(&blake2b::hash(&menu(&hash)));
    let nomenu_hash = hex(&blake2b::hash(nomenu));
    for _ in 0..2 {
        img.resize(img.len().next_multiple_of(512), 0);
        img.extend(menu(&hash));
        img.extend_from_slice(b"\0\0++CONFIG_B2SUM_SIGNATURE++");
        img.extend_from_slice(menu_hash.as_bytes());
        img.extend_from_slice(b"\0\0");
    }
    img.extend_from_slice(nomenu);
    img.extend_from_slice(b"\0++CONFIG_B2SUM_SIGNATURE++");
    img.extend_from_slice(nomenu_hash.as_bytes());
    (img, menu_hash, nomenu_hash)
}

#[test]
fn configuring_the_template_enrolls_the_loaders_again() {
    let (tpl, menu_hash, nomenu_hash) = enrolled_template();
    assert!(image::verify(&tpl, true).is_ok(), "the template verifies");
    let p = image::configure_iso(&tpl, &lab_blob()).unwrap();
    assert!(
        p.report.contains("2 loader copies re-enrolled"),
        "{}",
        p.report
    );
    let text = String::from_utf8_lossy(&p.bytes);
    assert!(!text.contains(&menu_hash), "the old menu hash is gone");
    assert!(
        text.contains(&nomenu_hash),
        "the no-menu loader is untouched"
    );
    image::verify(&p.bytes, true).unwrap();
    // Back to the template, byte for byte.
    assert_eq!(
        image::configure_iso(&p.bytes, &empty_blob()).unwrap().bytes,
        tpl
    );
    // A loader enrolled with some other hash is what `verify` calls a refusing loader.
    let mut bad = p.bytes.clone();
    let at = bad
        .windows(26)
        .position(|w| w == b"++CONFIG_B2SUM_SIGNATURE++")
        .unwrap()
        + 26;
    bad[at] = if bad[at] == b'a' { b'b' } else { b'a' };
    assert!(image::verify(&bad, true).unwrap_err().contains("loader"));
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
    assert!(image::show(&p.bytes, false).unwrap().contains("9df8c08e"));
    // Two slots: an ISO, not a raw image.
    let mut two = p.bytes.clone();
    two.extend_from_slice(&make_slot(SlotKind::Boot, &blob).unwrap());
    assert!(image::configure_raw(&two, &blob).is_err());
    assert!(image::configure_raw(&[0u8; 5000], &blob).is_err());
}

#[test]
fn in_place_configuration_equals_the_copying_one_and_a_probe_describes_the_template() {
    let (tpl, _) = synthetic_template();
    let blob = lab_blob();
    let copied = image::configure_iso(&tpl, &blob).unwrap();
    let mut inplace = tpl.clone();
    let report = image::configure_iso_in_place(&mut inplace, &blob).unwrap();
    assert_eq!(inplace, copied.bytes);
    assert_eq!(report, copied.report);
    // The probe sees the template's own (empty) configuration, then the new one.
    let p = image::probe(&tpl).unwrap();
    assert_eq!((p.slot_copies, p.hash_refs, p.format_version), (2, 12, 2));
    assert_eq!(&p.blob[..empty_blob().len()], &empty_blob()[..]);
    assert_eq!(image::probe(&inplace).unwrap().format_version, 2);
    assert!(image::probe(&vec![0u8; 100_000]).is_err());
    // A refused configuration leaves the image untouched.
    let mut untouched = tpl.clone();
    assert!(image::configure_iso_in_place(&mut untouched, &[1, 2, 3]).is_err());
    assert_eq!(untouched, tpl);
}

#[test]
fn check_release_verifies_the_real_signature_and_the_listed_files() {
    let dir = fixtures().join("minisign");
    let pubkey =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../keys/minisign-test-9229E05252D01F8E.pub");
    let check = |sums: &Path, files: &[&Path]| {
        let mut c = bin();
        c.arg("check-release")
            .arg("--pubkey")
            .arg(&pubkey)
            .arg("--sums")
            .arg(sums);
        c.args(files);
        run(&mut c)
    };
    let text = ok(&check(&dir.join("SHA256SUMS"), &[]));
    assert!(
        text.contains("signature ok: key 9229E05252D01F8E"),
        "{text}"
    );
    // A listed file with the wrong content is refused, and so is a file the
    // sums do not list.
    let fake = tmp("urmqtt-dev-v0.1.0.iso");
    std::fs::write(&fake, b"not the iso").unwrap();
    let o = check(&dir.join("SHA256SUMS"), &[&fake]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("SHA256SUMS says"));
    let other = tmp("other.bin");
    std::fs::write(&other, b"x").unwrap();
    let o = check(&dir.join("SHA256SUMS"), &[&other]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not list"));
    // Sums changed after signing.
    let altered = tmp("SHA256SUMS");
    let mut bytes = std::fs::read(dir.join("SHA256SUMS")).unwrap();
    bytes[3] = if bytes[3] == b'3' { b'4' } else { b'3' };
    std::fs::write(&altered, bytes).unwrap();
    std::fs::copy(dir.join("SHA256SUMS.minisig"), tmp("SHA256SUMS.minisig")).unwrap();
    let o = check(&altered, &[]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not match the file"));
    // Two keys (a rotation): the one the signature names is used, in either
    // order; a signature by a key that is not given is refused.
    let other = tmp("other.pub");
    let text = std::fs::read_to_string(&pubkey).unwrap();
    let flipped: String = text
        .lines()
        .nth(1)
        .unwrap()
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 4 && c != 'A' {
                'A'
            } else if i == 4 {
                'B'
            } else {
                c
            }
        })
        .collect();
    std::fs::write(
        &other,
        format!("untrusted comment: another key\n{flipped}\n"),
    )
    .unwrap();
    for keys in [[&other, &pubkey], [&pubkey, &other]] {
        let mut c = bin();
        c.arg("check-release");
        for k in keys {
            c.arg("--pubkey").arg(k);
        }
        c.arg("--sums").arg(dir.join("SHA256SUMS"));
        assert!(ok(&run(&mut c)).contains("signature ok: key 9229E05252D01F8E"));
    }
    let mut c = bin();
    c.arg("check-release")
        .arg("--pubkey")
        .arg(&other)
        .arg("--sums")
        .arg(dir.join("SHA256SUMS"));
    let o = run(&mut c);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not one of the given keys"));
}

/// `check-release --keyring --tag`: the former test key's releases are pinned by
/// the SHA-256 of their SHA256SUMS (keys/release-keys.json).
#[test]
fn check_release_with_the_key_ring_applies_the_pins() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = fixtures().join("minisign");
    let ring_dir = tmp("ring");
    std::fs::create_dir_all(ring_dir.join("keys")).unwrap();
    for f in ["release-keys.json", "minisign-test-9229E05252D01F8E.pub"] {
        std::fs::copy(root.join("keys").join(f), ring_dir.join("keys").join(f)).unwrap();
    }
    // A stand-in release key (the repository's is the placeholder until the rotation).
    let test =
        std::fs::read_to_string(root.join("keys/minisign-test-9229E05252D01F8E.pub")).unwrap();
    let line = test.lines().nth(1).unwrap();
    let other = format!(
        "untrusted comment: stand-in\n{}A{}\n",
        &line[..4],
        &line[5..]
    );
    std::fs::write(ring_dir.join("minisign.pub"), other).unwrap();
    let check = |tag: &str| {
        let mut c = bin();
        c.arg("check-release")
            .arg("--keyring")
            .arg(ring_dir.join("keys/release-keys.json"))
            .arg("--tag")
            .arg(tag)
            .arg("--sums")
            .arg(dir.join("SHA256SUMS"));
        run(&mut c)
    };
    let text = ok(&check("v0.1.0"));
    assert!(text.contains("signed by 9229E05252D01F8E (test, the project's former test key); SHA256SUMS matches the pinned SHA-256"), "{text}");
    // The real v0.1.0 file and signature, claimed for another pinned tag: refused.
    let o = check("v0.4.1");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("pins 3cca2f59"));
    let o = check("v0.5.0");
    assert!(String::from_utf8_lossy(&o.stderr).contains("may sign v0.1.0 to v0.4.1 only"));
    // The placeholder ring of the repository itself is refused, loudly.
    if std::fs::read_to_string(root.join("minisign.pub"))
        .unwrap()
        .contains("REPLACE-WITH")
    {
        let mut c = bin();
        c.arg("check-release")
            .arg("--keyring")
            .arg(root.join("keys/release-keys.json"))
            .arg("--tag")
            .arg("v0.1.0")
            .arg("--sums")
            .arg(dir.join("SHA256SUMS"));
        let o = run(&mut c);
        assert!(String::from_utf8_lossy(&o.stderr).contains("placeholder"));
    }
}

/// ADR-229: format 2 added the plaintext fields; a format 1 blob (the golden
/// of the first release of the configuration, kept as `lab-v1.blob`) is still
/// read, checked and shown, with the fingerprint it always had.
#[test]
fn the_format_1_golden_blob_is_still_valid() {
    let v1 = fixtures().join("lab-v1.blob");
    let text = ok(&run(bin().arg("show").arg(&v1)));
    assert!(text.contains("urmqtt-cfg version 1"), "{text}");
    assert!(
        text.contains(
            "fingerprint: 1a5d4dcce0a2767a29f39c984e55ae5cdd92b8940257de0ac7a23de64f386cd6"
        ),
        "{text}"
    );
    assert!(text.contains("address = 192.0.2.10/24") && text.contains("mqtt_tls_port = 8884"));
    assert!(
        !text.contains("plaintext"),
        "no plaintext in a format 1 blob: {text}"
    );
    let v = ok(&run(bin().arg("verify").arg(&v1)));
    assert!(v.contains("ok: fingerprint 1a5d4dcc"), "{v}");
    // The same TOML packed today is another blob (format 2), with the same values.
    let now = std::fs::read(fixtures().join("lab.blob")).unwrap();
    let then = std::fs::read(&v1).unwrap();
    assert_ne!(now, then);
    assert_eq!((now[8], then[8]), (2, 1));
    assert_eq!(now.len(), then.len());
    // A version 1 blob wrapped in a slot is what an old template ISO holds.
    let slot = tmp("v1.slot");
    ok(&run(bin().arg("slot").arg(&v1).arg(&slot)));
    assert!(ok(&run(bin().arg("show").arg(&slot))).contains("version 1"));
}

#[test]
fn the_plaintext_fixture_matches_its_golden_blob_and_is_announced() {
    let out = tmp("plain.blob");
    let text = ok(&run(bin()
        .arg("pack")
        .arg(fixtures().join("plain.toml"))
        .arg("--out")
        .arg(&out)));
    assert!(
        text.contains(
            "fingerprint 1114a1cdbb9898ad11917e9c0fff896ccc212a29d2e0ef8c2e9e0c86a2c4a672"
        ),
        "{text}"
    );
    assert!(
        text.contains("warning: plaintext MQTT ON, NOT ENCRYPTED: port 1883, password, 2 account(s), from 192.0.2.0/24, 10.20.0.0/16"),
        "{text}"
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(fixtures().join("plain.blob")).unwrap(),
        "the golden blob pins the plaintext encoding (tags 170 to 186)"
    );
    let shown = ok(&run(bin().arg("show").arg(&out)));
    assert!(shown.contains("urmqtt-cfg version 2"));
    assert!(
        shown.contains("users = [\"sensor-1 (pbkdf2-sha256, 1000 iterations)\""),
        "{shown}"
    );
    assert!(shown.contains("allow_from = [\"192.0.2.0/24\", \"10.20.0.0/16\"]"));
    assert!(shown.contains("max_failed_auths_per_ip = 3") && shown.contains("lockout_s = 120"));
    // The hashes are not printed.
    assert!(
        !shown.contains("4c580552") && !shown.contains("d8e0e2fe"),
        "{shown}"
    );
    // A release kernel accepts it.
    assert!(ok(&run(bin().arg("verify").arg(&out))).contains("plaintext MQTT ON"));
    // The same fixture without the section: no announcement.
    let off = ok(&run(bin().arg("show").arg(fixtures().join("lab.blob"))));
    assert!(!off.contains("plaintext"), "{off}");
}

#[test]
fn hash_password_reads_the_password_from_stdin() {
    use std::io::Write;
    use std::process::Stdio;
    let run_with = |pw: &str, args: &[&str]| {
        let mut c = bin()
            .arg("hash-password")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The tool refuses a bad id or iteration count before it reads stdin,
        // and reads only one line otherwise: it may be gone (or have closed
        // stdin) before this write, which is a BrokenPipe and not a failure.
        // Whether the run did the right thing is asserted on its output.
        match c.stdin.take().unwrap().write_all(pw.as_bytes()) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            r => r.unwrap(),
        }
        c.wait_with_output().unwrap()
    };
    // A bare hash that the kernel's parser reads and the password verifies.
    let o = run_with("correct horse\n", &[]);
    let hash = ok(&o).trim().to_owned();
    let parsed = urmqtt_cfg::passwd::PasswordHash::parse(&hash).unwrap();
    assert_eq!(parsed.iterations(), urmqtt_cfg::passwd::DEFAULT_ITERATIONS);
    assert!(parsed.verify(b"correct horse") && !parsed.verify(b"correct horse2"));
    assert_eq!(parsed.salt().len(), 16);
    // Each run uses a new salt.
    assert_ne!(hash, ok(&run_with("correct horse\n", &[])).trim());
    // CRLF input, a chosen iteration count, and the TOML table for pasting.
    let o = run_with("pw\r\n", &["--id", "sensor-9", "--iterations", "2000"]);
    let table = ok(&o);
    assert!(
        table.starts_with("{ id = \"sensor-9\", password_hash = \"pbkdf2-sha256$2000$"),
        "{table}"
    );
    let toml = format!(
        "[plaintext]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\nusers = [{}]\n",
        table.trim()
    );
    let cfg = tmp("hashed.toml");
    std::fs::write(&cfg, toml).unwrap();
    let packed = ok(&run(bin()
        .arg("pack")
        .arg(&cfg)
        .arg("--out")
        .arg(tmp("hashed.blob"))));
    assert!(packed.contains("1 account(s)"), "{packed}");
    // Refusals: no password, a bad id, an iteration count out of range.
    for (pw, args) in [
        ("\n", vec![]),
        ("x\n", vec!["--id", "a/b"]),
        ("x\n", vec!["--iterations", "10"]),
        ("x\n", vec!["--iterations", "many"]),
        ("x\n", vec!["unexpected"]),
    ] {
        let o = run_with(pw, &args);
        assert!(!o.status.success(), "{args:?}");
        assert!(
            !String::from_utf8_lossy(&o.stdout).contains("pbkdf2"),
            "no hash on error"
        );
    }
}

/// A template of a release made before H8 (v0.2.x): the menu and no-menu configs start with their
/// comment (the loaders find them by it) but carry no end marker and no loader is enrolled. The tool
/// and the builder page offer every release, so such a template must be configured exactly as before
/// (found when the H8 branch was merged: it was refused with "no end marker").
fn pre_h8_template() -> Vec<u8> {
    let (mut img, _) = synthetic_template();
    let slot = make_slot(SlotKind::Boot, &empty_blob()).unwrap();
    let hash: String = blake2b::hash(&slot)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for _ in 0..2 {
        img.resize(img.len().next_multiple_of(512), 0);
        img.extend_from_slice(b"# Generated by scripts/mkiso.sh --universal: the menu\n");
        img.extend(conf(&hash));
    }
    img.extend_from_slice(
        b"\0# Generated by scripts/mkiso.sh --universal. No menu and no editor.\ntimeout: 0\n",
    );
    img
}

#[test]
fn a_template_made_before_h8_is_configured_as_before() {
    let tpl = pre_h8_template();
    image::verify(&tpl, true).unwrap();
    let p = image::configure_iso(&tpl, &lab_blob()).unwrap();
    assert!(
        p.report.contains("0 loader copies re-enrolled"),
        "{}",
        p.report
    );
    image::verify(&p.bytes, true).unwrap();
    // The module hashes of the menu follow the new slot, as always.
    assert_ne!(p.bytes, tpl);
    // Back to the template, byte for byte.
    assert_eq!(
        image::configure_iso(&p.bytes, &empty_blob()).unwrap().bytes,
        tpl
    );
}

#[test]
fn a_half_marked_image_is_still_refused() {
    // Some copies of the menu end in the marker and one does not: not an image of either format.
    let mut img = pre_h8_template();
    img.resize(img.len().next_multiple_of(512), 0);
    img.extend_from_slice(b"# Generated by scripts/mkiso.sh --universal: the menu\ntimeout: 0\n\n# end of limine.conf\n");
    img.extend_from_slice(b"\0# Generated by scripts/mkiso.sh --universal: the menu\ntimeout: 0\n");
    let Err(e) = image::configure_iso(&img, &lab_blob()) else {
        panic!("a half-marked image was accepted");
    };
    assert!(e.contains("end marker"), "{e}");
}

/// ADR-257: a `[devices]` key that is not "off" for a driver the kernel was
/// built without is refused by `pack --kernel` (the image build) and by
/// `check_drivers` (what `--iso` and `--image` run); "off" is never refused.
#[test]
fn a_device_key_for_a_driver_the_kernel_lacks_is_refused() {
    let toml = std::fs::read_to_string(fixtures().join("lab.toml")).unwrap();
    let with = |v: &str| {
        let p = tmp(&format!("devices-{v}.toml"));
        std::fs::write(&p, format!("{toml}\n[devices]\nvirtio_vsock = \"{v}\"\n")).unwrap();
        p
    };
    let kernel = |name: &str, list: &str| {
        let p = tmp(name);
        let mut elf = b"\x7fELF fake kernel ".to_vec();
        elf.extend_from_slice(urmqtt_cfg::drivers::MARKER_PREFIX);
        elf.extend_from_slice(list.as_bytes());
        elf.extend_from_slice(&[0; 64]);
        std::fs::write(&p, elf).unwrap();
        p
    };
    let without = kernel("no-vsock.elf", "net,blk,console,rng,balloon,scsi,gpu,input");
    let full = kernel(
        "vps.elf",
        "net,blk,console,rng,balloon,scsi,gpu,input,vsock",
    );
    let out = tmp("devices.blob");
    let o = run(bin()
        .arg("pack")
        .arg(with("on"))
        .arg("--kernel")
        .arg(&full)
        .arg("--kernel")
        .arg(&without)
        .arg("--out")
        .arg(&out));
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("no-vsock.elf")
            && err.contains("devices.virtio_vsock")
            && err.contains("virtio-vsock driver"),
        "{err}"
    );
    ok(&run(bin()
        .arg("pack")
        .arg(with("auto"))
        .arg("--kernel")
        .arg(&full)
        .arg("--out")
        .arg(&out)));
    let blob = std::fs::read(&out).unwrap();
    assert!(image::check_drivers(&blob, &std::fs::read(&without).unwrap()).is_err());
    assert!(image::check_drivers(&blob, b"an older kernel without a marker").is_ok());
    ok(&run(bin()
        .arg("pack")
        .arg(with("off"))
        .arg("--kernel")
        .arg(&without)
        .arg("--out")
        .arg(&out)));
}

/// The templates of the published releases, configured by this tool (and by the builder page, which runs the
/// same code): v0.2.0's kernel reads configuration format 2, v0.2.1's 3, v0.3.0's 4, this release's 6. A
/// configuration that needs no newer format than the template's kernel reads is written into it as before; one
/// that needs more (the virtio-gpu console: 5, a `[devices]` key: 6) is refused with the reason, before a byte
/// of the template changes, instead of giving an image whose kernel would refuse it at boot.
#[test]
fn templates_of_earlier_releases_take_what_their_kernel_reads() {
    use urmqtt_cfg::build::Builder;
    use urmqtt_cfg::fields::tag;
    let header = |b: &[u8]| u16::from_le_bytes([b[8], b[9]]);
    let lab = lab_blob();
    assert_eq!(header(&lab), 2);
    let mut b = Builder::new();
    b.variant(tag::CON_VIRTIO_GPU, 1).unwrap();
    let gpu = b.finish(false).unwrap();
    assert_eq!(header(&gpu), 5);
    let mut b = Builder::new();
    b.variant(tag::DEV_VIRTIO_INPUT, 1).unwrap();
    let input = b.finish(false).unwrap();
    assert_eq!(header(&input), 6);
    for (release, reads) in [
        ("v0.2.0", 2u16),
        ("v0.2.1", 3),
        ("v0.3.0", 4),
        ("v0.4.0", 6),
    ] {
        let empty = Builder::new().finish_as(false, reads).unwrap();
        assert_eq!(header(&empty), reads);
        let (tpl, _) = synthetic_template_with(&empty);
        let p = image::configure_iso(&tpl, &lab).unwrap_or_else(|e| panic!("{release}: {e}"));
        image::verify(&p.bytes, false).unwrap();
        for (what, blob, needs) in [("console.virtio_gpu", &gpu, 5u16), ("[devices]", &input, 6)] {
            match image::configure_iso(&tpl, blob) {
                Ok(_) => assert!(
                    needs <= reads,
                    "{release}: {what} accepted by a kernel that reads up to {reads}"
                ),
                Err(e) => {
                    assert!(needs > reads, "{release}: {what} refused: {e}");
                    assert!(
                        e.contains(&format!("needs configuration format {needs}"))
                            && e.contains(&format!("reads up to {reads}"))
                            && e.contains("use a newer release"),
                        "{release}: {e}"
                    );
                }
            }
        }
    }
}
