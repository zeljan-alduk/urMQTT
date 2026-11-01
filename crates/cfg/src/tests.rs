use crate::blob::{self, Blob, SlotKind};
use crate::build::{self, Builder};
use crate::check;
use crate::fields::{self, FIELDS, Kind, tag};

fn empty() -> Vec<u8> {
    Builder::new().finish(false).expect("empty configuration")
}

#[test]
fn tags_are_ascending_and_unique() {
    for w in FIELDS.windows(2) {
        assert!(w[0].tag < w[1].tag, "{} / {}", w[0].key, w[1].key);
    }
}

#[test]
fn every_field_has_a_default_or_is_optional_by_design() {
    // Fields without a default value are absent by default; each must be
    // one of the kinds where "absent" is meaningful.
    for f in FIELDS {
        match f.kind {
            Kind::Bool(_)
            | Kind::UInt { .. }
            | Kind::Enum { .. }
            | Kind::Str { .. }
            | Kind::Strs { .. }
            | Kind::Rate { .. } => {}
            Kind::Bin { .. }
            | Kind::BinList { .. }
            | Kind::Ipv4
            | Kind::Cidr
            | Kind::Addr
            | Kind::Addrs { .. }
            | Kind::Key32 => assert!(!f.key.is_empty()),
        }
        // A default value respects its own range.
        if let Kind::UInt {
            min, max, default, ..
        } = f.kind
        {
            assert!((min..=max).contains(&default), "{}", f.key);
        }
        if let Kind::Enum { variants, default } = f.kind {
            assert!(usize::from(default) < variants.len(), "{}", f.key);
        }
    }
}

#[test]
fn the_empty_configuration_is_the_defaults() {
    let bytes = empty();
    // magic, version, flags, length 0, fingerprint, no signature
    assert_eq!(bytes.len(), 16 + 32 + 1);
    let b = Blob::parse(&bytes).expect("parses");
    assert!(b.is_empty());
    assert_eq!(b.str(tag::ENV), "prod");
    assert_eq!(b.uint(tag::NET_TLS_PORT), 8883);
    assert_eq!(b.uint(tag::NET_PLAIN_PORT), 0);
    assert_eq!(b.variant(tag::NET_MODE), 0);
    assert_eq!(b.rate(tag::LIM_PUBLISH_RATE), (10, 1000));
    assert_eq!(
        b.strs(tag::ACL_DEVICE_PUBLISH).collect::<Vec<_>>(),
        ["devices/{id}/#"]
    );
    assert!(b.bin(tag::TLS_CERT).is_empty());
    check::check(&b, false).expect("defaults pass the checks");
}

#[test]
fn setting_the_default_changes_nothing() {
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 8883).unwrap();
    b.bool(tag::TLS_RESUMPTION, true).unwrap();
    b.str(tag::ENV, "prod").unwrap();
    b.rate(tag::LIM_PUBLISH_RATE, 10, 1000).unwrap();
    b.strs(tag::ACL_DEVICE_PUBLISH, &["devices/{id}/#"])
        .unwrap();
    assert_eq!(b.finish(false).unwrap(), empty());
}

#[test]
fn round_trip_every_kind() {
    let mut b = Builder::new();
    b.str(tag::ENV, "lab-1").unwrap();
    b.variant(tag::NET_MODE, 2).unwrap();
    b.cidr(tag::NET_ADDRESS, [10, 0, 0, 5], 24).unwrap();
    b.ipv4(tag::NET_GATEWAY, [10, 0, 0, 1]).unwrap();
    b.uint(tag::NET_DHCP_TIMEOUT, 30).unwrap();
    b.uint(tag::NET_TLS_PORT, 9883).unwrap();
    b.bin(tag::TLS_CERT, b"-----BEGIN CERTIFICATE-----\nAA\n")
        .unwrap();
    b.bin(tag::TLS_KEY, b"-----BEGIN PRIVATE KEY-----\nAA\n")
        .unwrap();
    b.strs(tag::TLS_REVOKED, &["01ab", "ff"]).unwrap();
    b.bins(tag::TRUST_OPERATIONAL, &[b"ca-one".as_slice(), b"ca-two"])
        .unwrap();
    b.rate(tag::LIM_PUBLISH_RATE, 600, 60_000).unwrap();
    b.uint(tag::LIM_RETAINED_BYTES, 4 << 20).unwrap();
    b.strs::<&str>(tag::ACL_OPERATOR_IDS, &[]).unwrap();
    b.addr(tag::OBS_SYSLOG, [10, 0, 0, 9], 514).unwrap();
    b.addrs(
        tag::TIME_SERVERS,
        &[([192, 0, 2, 1], 123), ([192, 0, 2, 2], 1230)],
    )
    .unwrap();
    b.key32(tag::CTL_PUBLIC_KEY, &[7; 32]).unwrap();
    b.strs(tag::CTL_SERVICE_IDS, &["svc"]).unwrap();
    b.uint(tag::MEM_HEAP, 128).unwrap();
    b.uint(tag::TLS_CERT_NOT_AFTER, 2_000_000_000).unwrap();
    let bytes = b.finish(false).unwrap();
    let p = Blob::parse(&bytes).unwrap();
    assert_eq!(p.str(tag::ENV), "lab-1");
    assert_eq!(p.variant(tag::NET_MODE), 2);
    assert_eq!(p.cidr(tag::NET_ADDRESS), Some(([10, 0, 0, 5], 24)));
    assert_eq!(p.ipv4(tag::NET_GATEWAY), Some([10, 0, 0, 1]));
    assert_eq!(p.uint(tag::NET_DHCP_TIMEOUT), 30);
    assert_eq!(p.uint(tag::NET_TLS_PORT), 9883);
    assert_eq!(p.strs(tag::TLS_REVOKED).collect::<Vec<_>>(), ["01ab", "ff"]);
    assert_eq!(
        p.bins(tag::TRUST_OPERATIONAL).collect::<Vec<_>>(),
        [b"ca-one".as_slice(), b"ca-two"]
    );
    assert_eq!(p.rate(tag::LIM_PUBLISH_RATE), (600, 60_000));
    assert_eq!(p.strs(tag::ACL_OPERATOR_IDS).count(), 0);
    assert_eq!(p.addr(tag::OBS_SYSLOG), Some(([10, 0, 0, 9], 514)));
    assert_eq!(p.addrs(tag::TIME_SERVERS).count(), 2);
    assert_eq!(p.key32(tag::CTL_PUBLIC_KEY), Some([7; 32]));
    assert_eq!(p.uint(tag::MEM_HEAP), 128);
    assert_eq!(p.uint(tag::TLS_CERT_NOT_AFTER), 2_000_000_000);
    // Deterministic: building again gives the same bytes and fingerprint.
    assert_eq!(b.finish(false).unwrap(), bytes);
}

#[test]
fn any_flipped_bit_is_refused() {
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 9883).unwrap();
    b.str(tag::ENV, "lab").unwrap();
    let bytes = b.finish(false).unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut m = bytes.clone();
            m[i] ^= 1 << bit;
            assert!(Blob::parse(&m).is_err(), "byte {i} bit {bit} accepted");
        }
    }
}

#[test]
fn truncation_and_trailing_garbage_are_refused() {
    let bytes = empty();
    for n in 0..bytes.len() {
        assert!(Blob::parse(&bytes[..n]).is_err(), "{n} bytes accepted");
    }
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0; 100]);
    assert!(Blob::parse(&padded).is_ok(), "zero padding is the slot's");
    padded.push(1);
    assert!(Blob::parse(&padded).is_err());
}

/// Hand-assembled blob with a valid fingerprint, for structural attacks.
fn assemble(payload: &[u8]) -> Vec<u8> {
    let mut v = blob::MAGIC.to_vec();
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    let fp = blob::fingerprint_of(&v);
    v.extend_from_slice(&fp);
    v.push(0);
    v
}

fn record(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = tag.to_le_bytes().to_vec();
    v.extend_from_slice(&(value.len() as u32).to_le_bytes());
    v.extend_from_slice(value);
    v
}

#[test]
fn structural_attacks_fail_closed() {
    // Sanity: a well formed record is accepted.
    let ok = record(tag::NET_TLS_PORT, &9883u16.to_le_bytes());
    assert!(Blob::parse(&assemble(&ok)).is_ok());
    // Unknown tag.
    assert!(Blob::parse(&assemble(&record(9999, &[0]))).is_err());
    // A tag that is never stored.
    assert!(
        Blob::parse(&assemble(&record(
            tag::TRUST_MIN_ANCHOR_DAYS,
            &[1, 0, 0, 0]
        )))
        .is_err()
    );
    // Out of order and duplicated.
    let mut two = record(tag::NET_TLS_PORT, &1u16.to_le_bytes());
    two.extend(record(tag::NET_MODE, &[0]));
    assert!(Blob::parse(&assemble(&two)).is_err());
    let mut dup = record(tag::NET_TLS_PORT, &1u16.to_le_bytes());
    dup.extend(record(tag::NET_TLS_PORT, &2u16.to_le_bytes()));
    assert!(Blob::parse(&assemble(&dup)).is_err());
    // Wrong width, out of range, bad variant, port 0.
    assert!(Blob::parse(&assemble(&record(tag::NET_TLS_PORT, &[1]))).is_err());
    assert!(Blob::parse(&assemble(&record(tag::NET_TLS_PORT, &0u16.to_le_bytes()))).is_err());
    assert!(Blob::parse(&assemble(&record(tag::NET_MODE, &[3]))).is_err());
    // A record that overruns the payload.
    let mut over = record(tag::NET_MODE, &[0]);
    over[2] = 200;
    assert!(Blob::parse(&assemble(&over)).is_err());
    // Version 2 is not understood.
    let mut v = assemble(&ok);
    v[8] = 2;
    let fp = blob::fingerprint_of(&v[..v.len() - 33]);
    let n = v.len();
    v[n - 33..n - 1].copy_from_slice(&fp);
    assert!(Blob::parse(&v).is_err());
}

#[test]
fn dev_options_need_the_dev_environment_and_a_dev_kernel() {
    let mut b = Builder::new();
    b.uint(tag::NET_PLAIN_PORT, 1883).unwrap();
    // env = prod: refused everywhere.
    assert!(b.finish(false).is_err());
    assert!(b.finish(true).is_err());
    b.str(tag::ENV, "dev").unwrap();
    // env = dev: refused by a release kernel, accepted by a dev kernel.
    assert!(b.finish(false).is_err());
    assert!(b.finish(true).is_ok());
    // The durability shortcuts are dev-only too.
    let mut s = Builder::new();
    s.bool(tag::ST_REQUIRE_FLUSH, false).unwrap();
    assert!(s.finish(true).is_err());
    s.str(tag::ENV, "dev").unwrap();
    assert!(s.finish(false).is_err());
    assert!(s.finish(true).is_ok());
}

#[test]
fn cross_field_rules() {
    let bad = |f: &dyn Fn(&mut Builder)| {
        let mut b = Builder::new();
        f(&mut b);
        b.finish(true).is_err()
    };
    // static needs an address and a gateway; dhcp refuses them.
    assert!(bad(&|b| b.variant(tag::NET_MODE, 1).unwrap()));
    assert!(bad(&|b| b
        .cidr(tag::NET_ADDRESS, [10, 0, 0, 2], 24)
        .unwrap()));
    // The retained budget is at most an eighth of the heap (default 64 MiB).
    assert!(bad(&|b| b.uint(tag::LIM_RETAINED_BYTES, 9 << 20).unwrap()));
    // The heap is a power of two; min_free is below it.
    assert!(bad(&|b| b.uint(tag::MEM_HEAP, 100).unwrap()));
    assert!(bad(&|b| b.uint(tag::MEM_MIN_FREE, 64).unwrap()));
    // Topic filters are checked against the limits.
    assert!(bad(&|b| b
        .strs(tag::ACL_DEVICE_PUBLISH, &["a/#/b"])
        .unwrap()));
    assert!(bad(&|b| b
        .strs(tag::ST_TELEMETRY, &["devices/{id}/x"])
        .unwrap()));
    assert!(bad(&|b| b
        .strs(tag::ACL_SERVICE_PUBLISH, &["$SYS/#"])
        .unwrap()));
    // An operator may not also be a service.
    assert!(bad(&|b| b
        .strs(tag::ACL_OPERATOR_IDS, &["backend"])
        .unwrap()));
    // The control channel needs its key.
    assert!(bad(&|b| b.strs(tag::CTL_SERVICE_IDS, &["svc"]).unwrap()));
    // Certificate and key come together.
    assert!(bad(&|b| b.bin(tag::TLS_CERT, b"x").unwrap()));
    // Unknown CPU feature, bad serial.
    assert!(bad(&|b| b.strs(tag::CPU_DISABLE, &["nope"]).unwrap()));
    assert!(bad(&|b| b.strs(tag::TLS_REVOKED, &["xyz"]).unwrap()));
}

#[test]
fn signature_round_trip_and_tamper() {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[9; 32]);
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 9883).unwrap();
    let unsigned = b.finish(false).unwrap();
    let signed = build::sign(&unsigned, |m| {
        (sk.verifying_key().to_bytes(), sk.sign(m).to_bytes())
    })
    .unwrap();
    let p = Blob::parse(&signed).unwrap();
    assert_eq!(
        p.signature().unwrap().public_key,
        sk.verifying_key().to_bytes()
    );
    // Same fingerprint with or without the signature.
    assert_eq!(
        p.fingerprint(),
        Blob::parse(&unsigned).unwrap().fingerprint()
    );
    assert_eq!(build::strip_signature(&signed).unwrap(), unsigned);
    // Any change of the signature bytes is refused.
    for i in unsigned.len()..signed.len() {
        let mut m = signed.clone();
        m[i] ^= 1;
        assert!(Blob::parse(&m).is_err(), "byte {i}");
    }
    // A signature over another message is refused.
    assert!(
        build::sign(&unsigned, |_| (
            sk.verifying_key().to_bytes(),
            sk.sign(b"other").to_bytes()
        ))
        .is_err()
    );
}

#[test]
fn slots_are_found_by_marker_and_structure() {
    let blob = empty();
    let slot = blob::make_slot(SlotKind::Boot, &blob).unwrap();
    assert_eq!(slot.len(), blob::SLOT_SIZE);
    assert_eq!(
        blob::slot_blob(&slot, SlotKind::Boot)
            .unwrap()
            .get(..blob.len()),
        Some(&blob[..])
    );
    assert!(blob::slot_blob(&slot, SlotKind::Disk).is_err());
    // An image with one slot at a 512 multiple and a stray marker elsewhere.
    let mut img = vec![0xAAu8; 3000];
    img.extend_from_slice(&blob::SLOT_MARKER); // stray, unaligned and no blob
    img.resize(4096, 0xAA);
    img.extend_from_slice(&slot);
    img.extend_from_slice(&[0; 777]);
    assert_eq!(blob::find_slots(&img, SlotKind::Boot), [4096]);
    assert!(blob::find_slots(&img, SlotKind::Disk).is_empty());
}

#[test]
fn the_default_toml_free_table_matches_the_field_lookup() {
    for f in FIELDS {
        assert_eq!(fields::by_tag(f.tag).map(|x| x.key), Some(f.key));
        assert_eq!(fields::by_key(f.key).map(|x| x.tag), Some(f.tag));
    }
}

/// Random bytes must never panic the parser (the fuzz target runs the same
/// function for longer).
#[test]
fn garbage_never_panics() {
    let mut x = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let base = empty();
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..(next() % 6) {
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
        }
        let _ = Blob::parse(&m).map(|b| check::check(&b, true));
        let n = (next() % 200) as usize;
        let junk: Vec<u8> = (0..n).map(|_| next() as u8).collect();
        let _ = Blob::parse(&junk);
    }
}
