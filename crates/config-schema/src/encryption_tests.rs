//! ADR-240 (S7): `storage.encryption = "aes-256-xts"` and `storage.disk_key`.
//! The strict parser, the packer and the kernel's blob check agree; the blob
//! needs format version 4 and carries the 64 key bytes; the key file may be
//! raw or hex; weak keys are refused; a key without encryption is refused.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::fields::tag;

use crate::ConfigError;
use crate::pack::{PackOptions, pack};

const ENC: &str = "[storage]\nencryption = \"aes-256-xts\"\ndisk_key = \"disk.key\"\n";

fn run(text: &str, file: &[u8]) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |name: &str| {
        if name == "disk.key" {
            Ok(file.to_vec())
        } else {
            Err("no such file in this test".to_owned())
        }
    };
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
    )
}

fn key() -> Vec<u8> {
    (0..64u32).map(|i| (i * 7 + 3) as u8).collect()
}

fn has(e: &[ConfigError], path: &str) -> bool {
    e.iter().any(|x| x.path == path)
}

#[test]
fn a_raw_key_packs_into_format_4_with_the_key_in_the_blob() {
    let blob = run(ENC, &key()).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 4);
    assert_eq!(b.variant(tag::ST_ENCRYPTION), 1);
    assert_eq!(b.bin(tag::ST_DISK_KEY), &key()[..]);
    urmqtt_cfg::check::check(&b, false).unwrap();
}

#[test]
fn a_hex_key_file_gives_the_same_blob_bytes() {
    let hex: String = key().iter().map(|b| format!("{b:02x}")).collect();
    let a = run(ENC, &key()).unwrap();
    let b = run(ENC, format!("{hex}\n").as_bytes()).unwrap();
    assert_eq!(Blob::parse(&a).unwrap().bin(tag::ST_DISK_KEY), Blob::parse(&b).unwrap().bin(tag::ST_DISK_KEY));
}

#[test]
fn encryption_off_is_format_2_and_has_no_key_record() {
    let blob = run("", &[]).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 2);
    assert_eq!(b.variant(tag::ST_ENCRYPTION), 0);
    assert!(b.bin(tag::ST_DISK_KEY).is_empty());
}

#[test]
fn refusals() {
    // No key named.
    let e = run("[storage]\nencryption = \"aes-256-xts\"\n", &[]).unwrap_err();
    assert!(has(&e, "storage.disk_key"), "{e:?}");
    // A key without encryption.
    let e = run("[storage]\ndisk_key = \"disk.key\"\n", &key()).unwrap_err();
    assert!(has(&e, "storage.disk_key"), "{e:?}");
    // Wrong length, equal halves, one repeated byte.
    let mut same = key();
    let (a, b) = same.split_at_mut(32);
    b.copy_from_slice(a);
    for bad in [vec![1u8; 10], same, vec![0x41u8; 64], vec![0u8; 64]] {
        let e = run(ENC, &bad).unwrap_err();
        assert!(has(&e, "storage.disk_key"), "{e:?}");
    }
    // An unreadable file.
    let e = run(
        "[storage]\nencryption = \"aes-256-xts\"\ndisk_key = \"other.key\"\n",
        &key(),
    )
    .unwrap_err();
    assert!(has(&e, "storage.disk_key"), "{e:?}");
    // A path, not a file name.
    let e = run(
        "[storage]\nencryption = \"aes-256-xts\"\ndisk_key = \"../disk.key\"\n",
        &key(),
    )
    .unwrap_err();
    assert!(has(&e, "storage.disk_key"), "{e:?}");
}

#[test]
fn the_blob_check_refuses_what_the_packer_would() {
    use urmqtt_cfg::build::Builder;
    let mut b = Builder::new();
    b.variant(tag::ST_ENCRYPTION, 1).unwrap();
    assert!(b.finish(false).is_err(), "encryption without a key");
    b.bin(tag::ST_DISK_KEY, &[7u8; 64]).unwrap();
    assert!(b.finish(false).is_err(), "one repeated byte");
    let mut b = Builder::new();
    b.bin(tag::ST_DISK_KEY, &key()).unwrap();
    assert!(b.finish(false).is_err(), "a key without encryption");
    b.variant(tag::ST_ENCRYPTION, 1).unwrap();
    let blob = b.finish(false).unwrap();
    assert_eq!(Blob::parse(&blob).unwrap().version(), 4);
}
