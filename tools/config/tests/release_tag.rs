//! Regression tests of the security review of v0.6.0 (lens: boot chain,
//! updates and installation): a signed release is bound to its tag (ADR-365),
//! the former test key is held to the key ring in `--pubkey` mode too
//! (ADR-366), and a raw image is not configured with a format its kernel does
//! not read (ADR-367).
use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use urmqtt_config_tool::{keyring, release};

const RING: &str = include_str!("../../../keys/release-keys.json");
const TEST_KEY: &str = include_str!("../../../keys/minisign-test-9229E05252D01F8E.pub");
const RELEASE_KEY: &str = include_str!("../../../minisign.pub");
// The real v0.1.0 SHA256SUMS and its signature by the former test key (pinned).
const SUMS_V010: &[u8] = include_bytes!("fixtures/minisign/SHA256SUMS");
const SIG_V010: &str = include_str!("fixtures/minisign/SHA256SUMS.minisig");

/// A throwaway minisign key with key id `id` (as stored, little-endian):
/// (public key file, signer).
fn throwaway(seed: u8, id: [u8; 8]) -> (String, impl Fn(&[u8], &str) -> String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = [b"Ed".as_slice(), &id, sk.verifying_key().as_bytes()].concat();
    let public = format!(
        "untrusted comment: throwaway\n{}\n",
        Base64::encode_string(&pk)
    );
    let sign = move |msg: &[u8], comment: &str| {
        let sig = sk.sign(&urmqtt_cfg::blake2b::hash(msg)).to_bytes();
        let global = sk
            .sign(&[sig.as_slice(), comment.as_bytes()].concat())
            .to_bytes();
        format!(
            "untrusted comment: x\n{}\ntrusted comment: {comment}\n{}\n",
            Base64::encode_string(&[b"ED".as_slice(), &id, &sig].concat()),
            Base64::encode_string(&global)
        )
    };
    (public, sign)
}

/// The id as minisign prints it (big-endian hex) of a key stored as `id`.
fn id_text(id: [u8; 8]) -> String {
    id.iter().rev().map(|b| format!("{b:02X}")).collect()
}

/// The id bytes (as stored) of a printed key id.
fn id_bytes(hexid: &str) -> [u8; 8] {
    let mut b = [0u8; 8];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&hexid[2 * (7 - i)..2 * (7 - i) + 2], 16).unwrap();
    }
    b
}

/// The repository ring, with the release key replaced by `release`, and the
/// former test key by `test` when given.
fn ring_with(release: &str, release_id: [u8; 8], test: Option<&str>) -> Vec<keyring::RingKey> {
    let ring = RING.replace("721316B961DCB94B", &id_text(release_id));
    keyring::parse(&ring, &mut |f| match f {
        "../minisign.pub" => Ok(release.to_owned()),
        "minisign-test-9229E05252D01F8E.pub" => Ok(test.unwrap_or(TEST_KEY).to_owned()),
        _ => Err(format!("no {f}")),
    })
    .unwrap()
}

/// BOOT-1 (ADR-365): the release named by the caller (the mirror's
/// releases.json, `--tag`) was never compared with the release the signature
/// is about (the trusted comment `urMQTT vX.Y.Z release <commit>`); an older,
/// genuinely signed release was accepted as v0.6.0 or v9.9.9.
#[test]
fn an_old_signed_release_is_refused_under_a_newer_tag() {
    let (release, sign) = throwaway(1, [1; 8]);
    let keys = ring_with(&release, [1; 8], None);
    let sums_v050 = b"1111111111111111111111111111111111111111111111111111111111111111  urmqtt-template-v0.5.0-universal.iso\n";
    let sig_v050 = sign(sums_v050, "urMQTT v0.5.0 release 0123456789abcdef");
    for tag in ["v0.6.0", "v9.9.9", "v0.5.1"] {
        let e = keyring::verify(&keys, tag, sums_v050, &sig_v050).unwrap_err();
        assert!(
            e.contains("is the release \"urMQTT v0.5.0 release 0123456789abcdef\", not"),
            "{tag}: {e}"
        );
    }
    // Its own tag (with or without the v) still verifies.
    let v = keyring::verify(&keys, "v0.5.0", sums_v050, &sig_v050).unwrap();
    assert_eq!(v.key.name, "release");
    assert!(keyring::verify(&keys, "0.5.0", sums_v050, &sig_v050).is_ok());
    // A comment that is not a release's names no tag: refused.
    let odd = sign(sums_v050, "signed by hand");
    assert!(keyring::verify(&keys, "v0.5.0", sums_v050, &odd).is_err());
    // A tag that only starts like the signed one is another tag.
    let rc = sign(sums_v050, "urMQTT v0.5.0-rc.1 release x");
    assert!(keyring::verify(&keys, "v0.5.0", sums_v050, &rc).is_err());
    // The real v0.1.0 release of the former test key (pinned) still verifies.
    let v = keyring::verify(&keys, "v0.1.0", SUMS_V010, SIG_V010).unwrap();
    assert!(v.pinned);
}

/// BOOT-2 (ADR-366): `--pubkey` mode (`check-release --pubkey`, `slots stage
/// --pubkey`, `verify_sums_any`) applied no range and no pin, so a file signed
/// with the leaked former test key was accepted for any tag and any content.
#[test]
fn the_former_test_key_is_held_to_the_ring_in_pubkey_mode() {
    let test_id = id_bytes("9229E05252D01F8E");
    // A stand-in "leaked test key" with the test key's id (the code goes by the id).
    let (leaked, leaked_sign) = throwaway(9, test_id);
    let forged = b"2222222222222222222222222222222222222222222222222222222222222222  urmqtt-template-v0.6.1-universal.img\n";
    let sig = leaked_sign(forged, "urMQTT v0.6.1 release deadbeef");
    // The --pubkey form with the real keys of the repository: refused (the
    // built-in ring's test key does not verify the stand-in's signature).
    assert!(release::verify_sums_any(&[RELEASE_KEY, &leaked], forged, &sig).is_err());
    // The rule itself, with the stand-in in the ring as the former test key:
    // outside its range, refused...
    let (release_pub, _) = throwaway(1, [1; 8]);
    let ring = ring_with(&release_pub, [1; 8], Some(&leaked));
    let e = keyring::check_untagged(&ring, forged, &sig).unwrap_err();
    assert!(e.contains("may sign v0.1.0 to v0.4.1 only"), "{e}");
    // ... inside its range with other bytes than the pinned ones, refused ...
    let sig = leaked_sign(forged, "urMQTT v0.4.1 release deadbeef");
    let e = keyring::check_untagged(&ring, forged, &sig).unwrap_err();
    assert!(e.contains("pins 3cca2f59"), "{e}");
    // ... and with no tag in the comment, refused.
    let sig = leaked_sign(forged, "anything");
    assert!(keyring::check_untagged(&ring, forged, &sig).is_err());
    // The published v0.1.0 file of the real test key: accepted in both forms.
    assert!(release::verify_sums_any(&[RELEASE_KEY, TEST_KEY], SUMS_V010, SIG_V010).is_ok());
    assert!(keyring::check_builtin(SUMS_V010, SIG_V010).is_ok());
    // An operator's own key (not in the ring) is not restricted.
    let (own, own_sign) = throwaway(7, [7; 8]);
    let sig = own_sign(forged, "my own build");
    assert!(release::verify_sums_any(&[own.as_str()], forged, &sig).is_ok());
}

/// The ring built into the tool is the repository's, and it parses.
#[test]
fn the_built_in_ring_is_the_repository_ring() {
    let ring = keyring::builtin().unwrap();
    let ids: Vec<String> = ring.iter().map(|k| k.public.key_id()).collect();
    assert_eq!(ids, ["721316B961DCB94B", "9229E05252D01F8E"]);
}

/// BOOT-6 (ADR-367): `configure_raw` (`urmqtt-config pack --image`) applied
/// no format rule: a raw image whose kernel reads up to format 13 (its
/// unconfigured slot says so) took a configuration of a newer format, which
/// that kernel refuses at boot.
#[test]
fn a_raw_image_is_not_configured_with_a_format_its_kernel_cannot_read() {
    use urmqtt_cfg::blob::{DISK_MARKER, SlotKind, make_slot};
    use urmqtt_cfg::build::Builder;
    use urmqtt_cfg::fields::tag;
    use urmqtt_config_tool::image;
    let empty13 = Builder::new().finish_as(false, 13).unwrap();
    let mut disk_slot = make_slot(SlotKind::Boot, &empty13).unwrap();
    disk_slot[..16].copy_from_slice(&DISK_MARKER);
    let mut raw = vec![0x11u8; 8192];
    raw.extend_from_slice(&disk_slot);
    raw.extend_from_slice(&[0x22u8; 4096]);
    let mut b = Builder::new();
    b.variant(tag::NET_IPV6, 1).unwrap();
    let ipv6 = b.finish(false).unwrap();
    let need = u16::from_le_bytes([ipv6[8], ipv6[9]]);
    assert!(need > 13, "the configuration needs format {need}");
    let e = image::configure_raw(&raw, &ipv6).err().expect("refused");
    assert!(e.contains("it reads up to 13"), "{e}");
    // A configuration the kernel reads is accepted, and once configured the
    // image (no build note, no unconfigured slot left) takes no newer format.
    let plain = include_bytes!("fixtures/lab.blob").to_vec();
    assert!(u16::from_le_bytes([plain[8], plain[9]]) <= 13);
    let once = image::configure_raw(&raw, &plain).unwrap();
    let e = image::configure_raw(&once.bytes, &ipv6)
        .err()
        .expect("refused");
    assert!(e.contains("no build note and no unconfigured slot"), "{e}");
    assert!(image::configure_raw(&once.bytes, &plain).is_ok());
}
