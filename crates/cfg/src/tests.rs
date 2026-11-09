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
    // Port 0 is in range now (the TLS listener off, ADR-233) but the check refuses it without plaintext.
    let off = assemble(&record(tag::NET_TLS_PORT, &0u16.to_le_bytes()));
    let off = Blob::parse(&off).unwrap();
    assert!(check::check(&off, false).is_err());
    assert!(Blob::parse(&assemble(&record(tag::NET_MODE, &[3]))).is_err());
    // A record that overruns the payload.
    let mut over = record(tag::NET_MODE, &[0]);
    over[2] = 200;
    assert!(Blob::parse(&assemble(&over)).is_err());
    // A version this code does not know (0, 10 which no format ever used, and
    // one above the newest).
    for unknown in [0u8, 10, 16, 17] {
        let v = with_version(&assemble(&ok), unknown);
        assert!(Blob::parse(&v).is_err(), "version {unknown}");
    }
    // The versions of the formats that came after 7, each its own feature
    // (8 back-pressure, 9 WebSocket, 11 the receive interrupt, 12 MQTT 5.0,
    // 13 the shared-group limits, 14 the per-address connection limit, 15 the run-time account limit).
    for known in [8u8, 9, 11, 12, 13, 14, 15] {
        let v = with_version(&assemble(&ok), known);
        assert_eq!(Blob::parse(&v).map(|b| b.version()), Ok(u16::from(known)));
    }
}

/// The same blob with another version number in its header, fingerprint
/// recomputed (the blob is unsigned).
fn with_version(blob: &[u8], version: u8) -> Vec<u8> {
    let mut v = blob.to_vec();
    v[8] = version;
    let fp = blob::fingerprint_of(&v[..v.len() - 33]);
    let n = v.len();
    v[n - 33..n - 1].copy_from_slice(&fp);
    v
}

/// ADR-229: the writer writes the newest format (2) and the reader still
/// reads version 1. A version 1 blob cannot hold a record that came with
/// version 2, so it keeps meaning exactly what it meant.
#[test]
fn format_2_is_written_and_format_1_is_still_read() {
    assert_eq!((blob::FORMAT_MIN, blob::FORMAT_VERSION), (1, 15));
    // What the builder and the built-in default write.
    let e = empty();
    assert_eq!(Blob::parse(&e).unwrap().version(), 2);
    assert_eq!(&e[8..10], &[2, 0]);
    let mut buf = [0u8; blob::EMPTY_BLOB_LEN];
    blob::write_empty(&mut buf);
    assert_eq!(
        &buf[8..10],
        &[15, 0],
        "the built-in empty slot declares the newest format this kernel reads"
    );
    // A version 1 blob made by the previous release's tool: the same records,
    // the version in its header and its own fingerprint. It still parses and
    // passes the checks, and its values are read as before.
    let old = assemble(&record(tag::NET_TLS_PORT, &9883u16.to_le_bytes()));
    assert_eq!(&old[8..10], &[1, 0]);
    let p = Blob::parse(&old).unwrap();
    assert_eq!(p.version(), 1);
    assert_eq!(p.uint(tag::NET_TLS_PORT), 9883);
    check::check(&p, false).unwrap();
    // The empty version 1 blob (a template ISO or an installed disk made
    // before this change) is the defaults, plaintext off.
    let old_empty = assemble(&[]);
    let p = Blob::parse(&old_empty).unwrap();
    assert!(p.is_empty() && !p.bool(tag::PL_ENABLED));
    assert_eq!(p.uint(tag::PL_PORT), 1883);
    check::check(&p, false).unwrap();
    // A version 1 blob holding a version 2 record is refused; version 2 is fine.
    let rec = record(tag::PL_PORT, &1884u16.to_le_bytes());
    assert!(Blob::parse(&assemble(&rec)).is_err());
    assert!(Blob::parse(&with_version(&assemble(&rec), 2)).is_ok());
    // Every record of a version 1 blob is allowed in version 2, with the same value.
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 9883).unwrap();
    let v2 = b.finish(false).unwrap();
    assert_eq!(Blob::parse(&v2).unwrap().uint(tag::NET_TLS_PORT), 9883);
    // The default value of a version 2 field is not written.
    let mut d = Builder::new();
    d.uint(tag::PL_PORT, 1883).unwrap();
    d.bool(tag::PL_ENABLED, false).unwrap();
    d.strs(tag::PL_ACL_PUBLISH, &["devices/{id}/#"]).unwrap();
    assert_eq!(d.finish(false).unwrap(), e);
}

/// NOW-13, ADR-269: `limits.publisher_backpressure` came with format 8.
/// "single" (the default) writes nothing, so the blob keeps its version and
/// boots on an older kernel; "off" needs version 8 (a version 7 blob holding
/// it is refused).
#[test]
fn publisher_backpressure_needs_format_8_and_single_writes_nothing() {
    let f = crate::fields::by_key("limits.publisher_backpressure").unwrap();
    assert_eq!(
        (f.tag, f.since, f.dev_only),
        (tag::LIM_PUBLISHER_BACKPRESSURE, 8, false)
    );
    let mut single = Builder::new();
    single.variant(tag::LIM_PUBLISHER_BACKPRESSURE, 0).unwrap();
    assert_eq!(single.lowest_version(), 2);
    assert_eq!(single.finish(false).unwrap(), empty());
    assert_eq!(
        Blob::parse(&empty())
            .unwrap()
            .variant(tag::LIM_PUBLISHER_BACKPRESSURE),
        0
    );
    let mut off = Builder::new();
    off.variant(tag::LIM_PUBLISHER_BACKPRESSURE, 1).unwrap();
    assert_eq!(off.lowest_version(), 8);
    assert!(off.finish_as(false, 7).is_err(), "version 7 cannot hold it");
    let blob = off.finish(false).unwrap();
    let p = Blob::parse(&blob).unwrap();
    assert_eq!(
        (p.version(), p.variant(tag::LIM_PUBLISHER_BACKPRESSURE)),
        (8, 1)
    );
    check::check(&p, false).unwrap();
    assert!(Blob::parse(&with_version(&blob, 7)).is_err());
    assert!(
        Builder::new()
            .variant(tag::LIM_PUBLISHER_BACKPRESSURE, 2)
            .is_err()
    );
}

/// NOW-19, ADR-264: `network.mtu` came with format 7. 0 (the default: from
/// DHCP, else 1500) writes nothing, so the blob keeps its version and boots
/// on an older kernel; a value needs version 7 (a version 6 blob holding it
/// is refused); the checks allow 0 and 576..=9000, in every network mode.
#[test]
fn network_mtu_needs_format_7_and_absent_writes_nothing() {
    let f = crate::fields::by_key("network.mtu").unwrap();
    assert_eq!((f.tag, f.since, f.dev_only), (tag::NET_MTU, 7, false));
    let mut zero = Builder::new();
    zero.uint(tag::NET_MTU, 0).unwrap();
    assert_eq!(zero.lowest_version(), 2);
    assert_eq!(zero.finish(false).unwrap(), empty());
    assert_eq!(Blob::parse(&empty()).unwrap().uint(tag::NET_MTU), 0);
    for v in [576u64, 1460, 1500, 9000] {
        let mut b = Builder::new();
        b.uint(tag::NET_MTU, v).unwrap();
        assert_eq!(b.lowest_version(), 7);
        assert!(b.finish_as(false, 6).is_err(), "version 6 cannot hold {v}");
        let blob = b.finish(false).unwrap();
        let p = Blob::parse(&blob).unwrap();
        assert_eq!((p.version(), p.uint(tag::NET_MTU)), (7, v));
        check::check(&p, false).unwrap();
        assert!(Blob::parse(&with_version(&blob, 6)).is_err());
        // With a static address too (there it is the only source).
        let mut s = Builder::new();
        s.variant(tag::NET_MODE, 1).unwrap();
        s.cidr(tag::NET_ADDRESS, [10, 0, 0, 2], 24).unwrap();
        s.ipv4(tag::NET_GATEWAY, [10, 0, 0, 1]).unwrap();
        s.uint(tag::NET_MTU, v).unwrap();
        s.finish(false).unwrap();
    }
    for v in [1u64, 68, 575] {
        let mut b = Builder::new();
        b.uint(tag::NET_MTU, v).unwrap();
        assert!(b.finish(false).is_err(), "{v} is no usable MTU");
    }
    // Above the range: refused when set.
    assert!(Builder::new().uint(tag::NET_MTU, 9001).is_err());
}

/// NOW-13, ADR-270: `devices.virtio_net_interrupt` came with format 11.
/// "auto" (the default) writes nothing, so the blob keeps its version and
/// boots on an older kernel; "off" needs version 11 (a version 10 or 7 blob
/// holding it is refused by an older kernel by its version).
#[test]
fn net_interrupt_needs_format_11_and_auto_writes_nothing() {
    use crate::fields::NET_INTERRUPT_MODES;
    let f = crate::fields::by_key("devices.virtio_net_interrupt").unwrap();
    assert_eq!(
        (f.tag, f.since, f.dev_only),
        (tag::DEV_NET_INTERRUPT, 11, false)
    );
    assert_eq!(NET_INTERRUPT_MODES, ["auto", "off"]);
    let mut auto = Builder::new();
    auto.variant(tag::DEV_NET_INTERRUPT, 0).unwrap();
    assert_eq!(auto.lowest_version(), 2);
    assert_eq!(auto.finish(false).unwrap(), empty());
    assert_eq!(
        Blob::parse(&empty())
            .unwrap()
            .variant(tag::DEV_NET_INTERRUPT),
        0
    );
    let mut off = Builder::new();
    off.variant(tag::DEV_NET_INTERRUPT, 1).unwrap();
    assert_eq!(off.lowest_version(), 11);
    assert!(off.finish_as(false, 10).is_err());
    let blob = off.finish(false).unwrap();
    let p = Blob::parse(&blob).unwrap();
    assert_eq!((p.version(), p.variant(tag::DEV_NET_INTERRUPT)), (11, 1));
    check::check(&p, false).unwrap();
    assert!(Blob::parse(&with_version(&blob, 10)).is_err());
    assert!(Blob::parse(&with_version(&blob, 7)).is_err());
    assert!(Builder::new().variant(tag::DEV_NET_INTERRUPT, 2).is_err());
}

/// ADR-257: the `[devices]` keys came with format 6, one enum each. Off (the
/// default) writes nothing, so the blob keeps its version and boots on an
/// older kernel; auto and on need version 6, and a version 5 blob holding
/// such a record is refused (an older kernel refuses it by the version).
#[test]
fn device_keys_need_format_6_and_off_writes_nothing() {
    use crate::fields::{DEVICE_KEYS, DEVICE_MODES};
    assert_eq!(DEVICE_MODES, ["off", "auto", "on"]);
    assert_eq!(DEVICE_KEYS.len(), 4);
    for &(t, key, _) in DEVICE_KEYS {
        let f = crate::fields::by_key(key).unwrap();
        assert_eq!((f.tag, f.since, f.dev_only), (t, 6, false), "{key}");
        let mut off = Builder::new();
        off.variant(t, 0).unwrap();
        assert_eq!(off.lowest_version(), 2);
        assert_eq!(off.finish(false).unwrap(), empty());
        for v in [1u8, 2] {
            let mut b = Builder::new();
            b.variant(t, v).unwrap();
            assert_eq!(b.lowest_version(), 6);
            assert!(
                b.finish_as(false, 5).is_err(),
                "version 5 cannot hold {key}"
            );
            let blob = b.finish(false).unwrap();
            let p = Blob::parse(&blob).unwrap();
            assert_eq!((p.version(), p.variant(t)), (6, v));
            assert!(Blob::parse(&with_version(&blob, 5)).is_err());
        }
        let mut bad = Builder::new();
        assert!(bad.variant(t, 3).is_err());
    }
    // With the virtio-gpu console on as well, still 6; the gpu alone, 5.
    let mut b = Builder::new();
    b.variant(tag::CON_VIRTIO_GPU, 1).unwrap();
    assert_eq!(b.lowest_version(), 5);
    b.variant(tag::DEV_VIRTIO_INPUT, 2).unwrap();
    assert_eq!(b.lowest_version(), 6);
}

/// ADR-256: `console.virtio_gpu` came with format 5. Off (the default) writes
/// nothing, so such a configuration stays at the base version and boots on an
/// older kernel; auto and on need version 5, and a version 4 blob holding the
/// record is refused (an older kernel refuses it by the version).
#[test]
fn virtio_gpu_needs_format_5_and_off_writes_nothing() {
    use crate::fields::VIRTIO_GPU_MODES;
    let f = crate::fields::by_key("console.virtio_gpu").unwrap();
    assert_eq!(
        (f.tag, f.since, f.dev_only),
        (tag::CON_VIRTIO_GPU, 5, false)
    );
    assert_eq!(VIRTIO_GPU_MODES, ["off", "auto", "on"]);
    let mut off = Builder::new();
    off.variant(tag::CON_VIRTIO_GPU, 0).unwrap();
    assert_eq!(off.lowest_version(), 2);
    assert_eq!(off.finish(false).unwrap(), empty());
    assert_eq!(
        Blob::parse(&empty()).unwrap().variant(tag::CON_VIRTIO_GPU),
        0
    );
    for v in [1u8, 2] {
        let mut b = Builder::new();
        b.variant(tag::CON_VIRTIO_GPU, v).unwrap();
        assert_eq!(b.lowest_version(), 5);
        assert!(b.finish_as(false, 4).is_err(), "version 4 cannot hold it");
        let blob = b.finish(false).unwrap();
        let p = Blob::parse(&blob).unwrap();
        assert_eq!((p.version(), p.variant(tag::CON_VIRTIO_GPU)), (5, v));
        // The same record in a version 4 header: refused.
        assert!(Blob::parse(&with_version(&blob, 4)).is_err());
    }
    // A variant past the list is refused.
    let mut bad = Builder::new();
    assert!(bad.variant(tag::CON_VIRTIO_GPU, 3).is_err());
    assert!(
        Blob::parse(&with_version(
            &assemble(&record(tag::CON_VIRTIO_GPU, &[3])),
            5
        ))
        .is_err()
    );
}

/// The plaintext section's rules (the TOML-side validator has a twin of each,
/// compared in `config-schema`).
#[test]
fn plaintext_rules() {
    use crate::passwd;
    let hash = passwd::encode(b"pw", b"0123456789abcdef", 1000).unwrap();
    let user = |id: &str| format!("{id} {hash}");
    // Disabled, with nothing else set: fine. Enabled needs a network and an account.
    let mut off = Builder::new();
    assert!(off.finish(false).is_ok());
    off.bool(tag::PL_ENABLED, true).unwrap();
    assert!(off.finish(false).is_err(), "no network");
    off.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
    assert!(off.finish(false).is_err(), "password mode without accounts");
    off.strs(tag::PL_USERS, &[user("sensor-1")]).unwrap();
    let ok = off
        .finish(false)
        .expect("the minimal password configuration");
    assert_eq!(Blob::parse(&ok).unwrap().version(), 2);

    // The plaintext listener is on, with these strings, flags, integers and
    // enum variants set; does the check accept it?
    let try_with = |strs: Vec<(u16, Vec<String>)>,
                    flags: Vec<(u16, bool)>,
                    uints: Vec<(u16, u64)>,
                    variants: Vec<(u16, u8)>| {
        let mut b = Builder::new();
        b.bool(tag::PL_ENABLED, true).unwrap();
        for (t, v) in flags {
            b.bool(t, v).unwrap();
        }
        for (t, v) in uints {
            b.uint(t, v).unwrap();
        }
        for (t, v) in variants {
            b.variant(t, v).unwrap();
        }
        for (t, v) in strs {
            b.strs(t, &v).unwrap();
        }
        b.finish(false).is_ok()
    };
    let net = |s: &str| (tag::PL_ALLOW_FROM, vec![s.to_owned()]);
    let users = |ids: &[&str]| {
        (
            tag::PL_USERS,
            ids.iter().map(|i| user(i)).collect::<Vec<_>>(),
        )
    };
    let ids = |l: &[&str]| {
        (
            tag::PL_IP_IDENTITIES,
            l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
    };
    // allow_from or anywhere, never both, never neither.
    assert!(try_with(
        vec![net("10.0.0.0/8"), users(&["a"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(
        !try_with(vec![users(&["a"])], vec![], vec![], vec![]),
        "no network"
    );
    assert!(try_with(
        vec![users(&["a"])],
        vec![(tag::PL_ANYWHERE, true)],
        vec![],
        vec![]
    ));
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["a"])],
            vec![(tag::PL_ANYWHERE, true)],
            vec![],
            vec![]
        ),
        "both"
    );
    // Malformed networks and accounts.
    assert!(!try_with(
        vec![net("0.0.0.0/0"), users(&["a"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(!try_with(
        vec![net("10.0.0.1/8"), users(&["a"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(!try_with(
        vec![net("nonsense"), users(&["a"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(
        !try_with(
            vec![
                (
                    tag::PL_ALLOW_FROM,
                    vec!["10.0.0.0/8".into(), "10.0.0.0/8".into()]
                ),
                users(&["a"])
            ],
            vec![],
            vec![],
            vec![]
        ),
        "twice"
    );
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["a", "a"])],
            vec![],
            vec![],
            vec![]
        ),
        "same id twice"
    );
    assert!(!try_with(
        vec![
            net("10.0.0.0/8"),
            (tag::PL_USERS, vec!["a not-a-hash".into()])
        ],
        vec![],
        vec![],
        vec![]
    ));
    assert!(!try_with(
        vec![net("10.0.0.0/8"), users(&["a/b"])],
        vec![],
        vec![],
        vec![]
    ));
    // Modes exclude each other's settings.
    assert!(!try_with(
        vec![net("10.0.0.0/8"), users(&["a"]), ids(&["10.0.0.0/24 plc"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(
        try_with(
            vec![net("10.0.0.0/8")],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 1)]
        ),
        "anonymous needs nothing else"
    );
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["a"])],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 1)]
        ),
        "accounts with anonymous"
    );
    assert!(try_with(
        vec![net("10.0.0.0/8"), ids(&["10.1.0.0/16 plc"])],
        vec![],
        vec![],
        vec![(tag::PL_AUTH, 2)]
    ));
    assert!(
        !try_with(
            vec![net("10.0.0.0/8")],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "ip without networks"
    );
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), ids(&["192.168.0.0/16 plc"])],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "outside allow_from"
    );
    assert!(
        try_with(
            vec![ids(&["192.168.0.0/16 plc"])],
            vec![(tag::PL_ANYWHERE, true)],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "anywhere covers all"
    );
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), ids(&["10.0.0.0/16 a", "10.0.0.0/16 b"])],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "network twice"
    );
    assert!(
        try_with(
            vec![
                net("10.0.0.0/8"),
                ids(&["10.0.0.0/16 a", "10.0.0.0/24 a", "10.1.0.0/16 b"])
            ],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "overlap is fine"
    );
    assert!(
        !try_with(
            vec![
                net("10.0.0.0/8"),
                ids(&["10.0.0.0/16 plc"]),
                (tag::ACL_OPERATOR_IDS, vec!["plc".into()])
            ],
            vec![],
            vec![],
            vec![(tag::PL_AUTH, 2)]
        ),
        "operator id"
    );
    // Another role's identity is refused for a plaintext account.
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["backend"])],
            vec![],
            vec![],
            vec![]
        ),
        "service id"
    );
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["operator"])],
            vec![],
            vec![],
            vec![]
        ),
        "operator id"
    );
    assert!(
        !try_with(
            vec![
                net("10.0.0.0/8"),
                users(&["ctl"]),
                (tag::CTL_SERVICE_IDS, vec!["ctl".into()])
            ],
            vec![],
            vec![],
            vec![]
        ),
        "control id"
    );
    assert!(try_with(
        vec![net("10.0.0.0/8"), users(&["backend2"])],
        vec![],
        vec![],
        vec![]
    ));
    assert!(
        !try_with(
            vec![
                net("10.0.0.0/8"),
                (tag::ACL_SERVICE_IDS, vec!["svc-*".into()]),
                users(&["svc-1"])
            ],
            vec![],
            vec![],
            vec![]
        ),
        "service prefix"
    );
    // Ports.
    assert!(
        !try_with(
            vec![net("10.0.0.0/8"), users(&["a"])],
            vec![],
            vec![(tag::PL_PORT, 8883)],
            vec![]
        ),
        "the TLS port"
    );
    assert!(try_with(
        vec![net("10.0.0.0/8"), users(&["a"])],
        vec![],
        vec![(tag::PL_PORT, 1884)],
        vec![]
    ));
}

/// The anonymous identity is a string field, not a list.
#[test]
fn the_anonymous_identity() {
    let anon = |id: &str, extra: &dyn Fn(&mut Builder)| {
        let mut b = Builder::new();
        b.bool(tag::PL_ENABLED, true).unwrap();
        b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
        b.variant(tag::PL_AUTH, 1).unwrap();
        // Too long a name is refused already by the field's own bound.
        if b.str(tag::PL_ANON_ID, id).is_err() {
            return false;
        }
        extra(&mut b);
        b.finish(false).is_ok()
    };
    assert!(anon("lan", &|_| {}));
    assert!(anon("house-1", &|_| {}));
    assert!(!anon("", &|_| {}), "an identity is not empty");
    assert!(!anon("a/b", &|_| {}));
    assert!(!anon("a b", &|_| {}));
    assert!(!anon(&"x".repeat(65), &|_| {}));
    assert!(!anon("backend", &|_| {}), "a service id");
    assert!(!anon("operator", &|b| b
        .strs(tag::ACL_OPERATOR_IDS, &["operator"])
        .unwrap()));
    // A non-default name is only for the anonymous mode.
    let mut b = Builder::new();
    b.bool(tag::PL_ENABLED, true).unwrap();
    b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
    b.str(tag::PL_ANON_ID, "house").unwrap();
    b.strs(
        tag::PL_USERS,
        &[format!(
            "a {}",
            crate::passwd::encode(b"x", b"0123456789abcdef", 1000).unwrap()
        )],
    )
    .unwrap();
    assert!(b.finish(false).is_err());
}

/// A disabled section is inert but not allowed to look dangerous, and what is
/// written in it must still be well formed.
#[test]
fn a_disabled_plaintext_section_is_checked_but_inert() {
    let go = |f: &dyn Fn(&mut Builder)| {
        let mut b = Builder::new();
        f(&mut b);
        b.finish(false).is_ok()
    };
    assert!(go(&|b| b
        .strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"])
        .unwrap()));
    assert!(
        !go(&|b| b.strs(tag::PL_ALLOW_FROM, &["10.0.0.9/8"]).unwrap()),
        "malformed even when off"
    );
    assert!(!go(&|b| b.strs(tag::PL_USERS, &["x y"]).unwrap()));
    assert!(
        !go(&|b| b.bool(tag::PL_ANYWHERE, true).unwrap()),
        "anywhere without enabled"
    );
    assert!(
        go(&|b| b.uint(tag::PL_PORT, 8883).unwrap()),
        "port clashes only matter when on"
    );
    assert!(!go(&|b| b.strs(tag::PL_ACL_PUBLISH, &["$SYS/#"]).unwrap()));
    assert!(!go(&|b| b
        .strs(tag::PL_ACL_SUBSCRIBE, &["$foo/#"])
        .unwrap()));
    assert!(
        go(&|b| b.strs::<&str>(tag::PL_ACL_PUBLISH, &[]).unwrap()),
        "an empty list means read-only"
    );
    assert!(!go(&|b| b.strs(tag::PL_ACL_PUBLISH, &["a/#/b"]).unwrap()));
    assert!(go(&|b| b
        .strs(tag::PL_ACL_SUBSCRIBE, &["home/{id}/#", "lights/+"])
        .unwrap()));
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

#[test]
fn the_built_in_empty_blob_equals_the_builders() {
    let mut buf = [0u8; blob::EMPTY_BLOB_LEN];
    blob::write_empty(&mut buf);
    assert_eq!(
        &buf[..],
        &Builder::new()
            .finish_as(false, blob::FORMAT_VERSION)
            .unwrap()[..]
    );
    assert!(Blob::parse(&buf).is_ok());
}

/// ADR-272: the `[websocket]` section. Off with nothing set is fine and keeps
/// the base format; on needs the TLS listener and a port of its own; password
/// mode needs accounts and an origin list; settings of the other mode are
/// refused; any key set needs format 9.
#[test]
fn websocket_rules() {
    use crate::passwd;
    let hash = passwd::encode(b"pw", b"0123456789abcdef", 1000).unwrap();
    let user = |id: &str| format!("{id} {hash}");
    let base = || {
        let mut b = Builder::new();
        b.bool(tag::WS_ENABLED, true).unwrap();
        b
    };
    // mtls, the default: nothing else needed.
    let ok = base().finish(false).expect("mtls with defaults");
    assert_eq!(Blob::parse(&ok).unwrap().version(), 9);
    // Off and untouched: the base format.
    assert_eq!(
        Blob::parse(&Builder::new().finish(false).unwrap())
            .unwrap()
            .version(),
        2
    );
    // Ports.
    for (t, v) in [(tag::WS_PORT, 8883u64), (tag::NET_PLAIN_PORT, 8084)] {
        let mut b = base();
        b.uint(t, v).unwrap();
        assert!(b.finish(true).is_err(), "port clash {t}");
    }
    let mut b = base();
    b.bool(tag::PL_ENABLED, true).unwrap();
    b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
    b.strs(tag::PL_USERS, &[user("p")]).unwrap();
    b.uint(tag::PL_PORT, 8084).unwrap();
    assert_eq!(b.finish(false).unwrap_err().key, "websocket.port");
    // TLS off: no wss.
    let mut b = base();
    b.uint(tag::NET_TLS_PORT, 0).unwrap();
    b.bool(tag::PL_ENABLED, true).unwrap();
    b.strs(tag::PL_ALLOW_FROM, &["10.0.0.0/8"]).unwrap();
    b.strs(tag::PL_USERS, &[user("p")]).unwrap();
    assert_eq!(b.finish(false).unwrap_err().key, "websocket.enabled");
    // Password mode.
    let mut b = base();
    b.variant(tag::WS_AUTH, 1).unwrap();
    assert_eq!(b.finish(false).unwrap_err().key, "websocket.users");
    b.strs(tag::WS_USERS, &[user("web-1")]).unwrap();
    assert_eq!(b.finish(false).unwrap_err().key, "websocket.origins");
    b.strs(tag::WS_ORIGINS, &["https://app.example.com"])
        .unwrap();
    assert!(b.finish(false).is_ok());
    // Roles.
    let mut r = base();
    r.variant(tag::WS_AUTH, 1).unwrap();
    r.strs(tag::WS_ORIGINS, &["https://app.example.com"])
        .unwrap();
    r.strs(tag::WS_USERS, &[user("ops")]).unwrap();
    r.strs(tag::ACL_OPERATOR_IDS, &["ops"]).unwrap();
    assert_eq!(r.finish(false).unwrap_err().key, "websocket.users");
    // Accounts with mtls.
    let mut m = base();
    m.strs(tag::WS_USERS, &[user("web-1")]).unwrap();
    assert_eq!(m.finish(false).unwrap_err().key, "websocket.users");
    // Well-formed whether on or off.
    for (t, bad) in [
        (tag::WS_ORIGINS, vec!["https://App.example.com".to_string()]),
        (
            tag::WS_ORIGINS,
            vec!["https://a.b".into(), "https://a.b".into()],
        ),
        (tag::WS_USERS, vec![user("a"), user("a")]),
        (tag::WS_USERS, vec!["nohash".into()]),
        (tag::WS_ACL_PUBLISH, vec!["$SYS/#".into()]),
        (tag::WS_ACL_SUBSCRIBE, vec!["a/#/b".into()]),
    ] {
        let mut b = Builder::new();
        b.strs(t, &bad).unwrap();
        assert!(b.finish(false).is_err(), "{t} {bad:?}");
    }
    let mut b = Builder::new();
    b.str(tag::WS_PATH, "/a/../b").unwrap();
    assert_eq!(b.finish(false).unwrap_err().key, "websocket.path");
}

/// ADR-273 rule 21: the `[mqtt5]` section and the expiry limits. Defaults
/// write nothing and keep the base format; any of them set needs format 12;
/// values outside their ranges are refused by the builder (and the blob
/// parser); the default session expiry may not exceed the maximum.
#[test]
fn mqtt5_rules() {
    // Untouched, or spelled out at the defaults: no record, the base format.
    let mut d = Builder::new();
    d.bool(tag::MQTT5_ENABLED, true).unwrap();
    d.uint(tag::MQTT5_RECEIVE_MAXIMUM, 32).unwrap();
    d.uint(tag::MQTT5_TOPIC_ALIAS_MAXIMUM, 10).unwrap();
    d.uint(tag::MQTT5_MAX_USER_PROPERTIES, 16).unwrap();
    d.uint(tag::MQTT5_MAX_KEEP_ALIVE, 0).unwrap();
    d.bool(tag::MQTT5_SHARED_SUBSCRIPTIONS, true).unwrap();
    d.bool(tag::MQTT5_SUBSCRIPTION_IDENTIFIERS, true).unwrap();
    d.uint(tag::LIM_MAX_SESSION_EXPIRY, 2_592_000).unwrap();
    d.uint(tag::LIM_DEFAULT_SESSION_EXPIRY, 2_592_000).unwrap();
    d.uint(tag::LIM_MAX_MESSAGE_EXPIRY, 0).unwrap();
    assert_eq!(d.finish(false).unwrap(), empty());
    // Any one set: format 12.
    type Set = fn(&mut Builder);
    let sets: [Set; 10] = [
        |b| b.bool(tag::MQTT5_ENABLED, false).unwrap(),
        |b| b.uint(tag::MQTT5_RECEIVE_MAXIMUM, 1).unwrap(),
        |b| b.uint(tag::MQTT5_TOPIC_ALIAS_MAXIMUM, 0).unwrap(),
        |b| b.uint(tag::MQTT5_MAX_USER_PROPERTIES, 1024).unwrap(),
        |b| b.uint(tag::MQTT5_MAX_KEEP_ALIVE, 600).unwrap(),
        |b| b.bool(tag::MQTT5_SHARED_SUBSCRIPTIONS, false).unwrap(),
        |b| b.bool(tag::MQTT5_SUBSCRIPTION_IDENTIFIERS, false).unwrap(),
        |b| {
            b.uint(tag::LIM_MAX_SESSION_EXPIRY, u64::from(u32::MAX))
                .unwrap()
        },
        |b| b.uint(tag::LIM_DEFAULT_SESSION_EXPIRY, 3600).unwrap(),
        |b| b.uint(tag::LIM_MAX_MESSAGE_EXPIRY, 86_400).unwrap(),
    ];
    for set in sets {
        let mut b = Builder::new();
        set(&mut b);
        let blob = b.finish(false).unwrap();
        let p = Blob::parse(&blob).unwrap();
        assert_eq!(p.version(), 12);
        assert_eq!(p.present().count(), 1);
    }
    // Ranges.
    let mut b = Builder::new();
    for (t, v) in [
        (tag::MQTT5_RECEIVE_MAXIMUM, 0u64),
        (tag::MQTT5_RECEIVE_MAXIMUM, 65_536),
        (tag::MQTT5_TOPIC_ALIAS_MAXIMUM, 65_536),
        (tag::MQTT5_MAX_USER_PROPERTIES, 1025),
        (tag::MQTT5_MAX_KEEP_ALIVE, 65_536),
        (tag::LIM_MAX_SESSION_EXPIRY, 1 << 32),
        (tag::LIM_DEFAULT_SESSION_EXPIRY, 1 << 32),
        (tag::LIM_MAX_MESSAGE_EXPIRY, 1 << 32),
    ] {
        assert!(b.uint(t, v).is_err(), "{t} = {v}");
    }
    // The default session expiry within the maximum.
    let mut b = Builder::new();
    b.uint(tag::LIM_MAX_SESSION_EXPIRY, 3600).unwrap();
    assert_eq!(
        b.finish(false).unwrap_err().key,
        "limits.default_session_expiry_s"
    );
    b.uint(tag::LIM_DEFAULT_SESSION_EXPIRY, 3600).unwrap();
    assert!(b.finish(false).is_ok());
    b.uint(tag::LIM_DEFAULT_SESSION_EXPIRY, 0).unwrap();
    assert!(b.finish(false).is_ok());
    let mut b = Builder::new();
    b.uint(tag::LIM_DEFAULT_SESSION_EXPIRY, u64::from(u32::MAX))
        .unwrap();
    assert!(b.finish(false).is_err());
    b.uint(tag::LIM_MAX_SESSION_EXPIRY, u64::from(u32::MAX))
        .unwrap();
    assert!(b.finish(false).is_ok());
    // A blob of an older format cannot hold them.
    let rec = record(tag::MQTT5_RECEIVE_MAXIMUM, &64u32.to_le_bytes());
    assert!(Blob::parse(&with_version(&assemble(&rec), 9)).is_err());
    assert!(Blob::parse(&with_version(&assemble(&rec), 12)).is_ok());
}

/// ADR-275: the shared-subscription group limits. Defaults write nothing and
/// keep the base format; either set needs format 13; 0 and 65536 are refused;
/// a blob of format 12 cannot hold them.
#[test]
fn shared_group_limits() {
    let mut d = Builder::new();
    d.uint(tag::LIM_MAX_SHARED_GROUPS, 1024).unwrap();
    d.uint(tag::LIM_MAX_SHARED_GROUP_MEMBERS, 1024).unwrap();
    assert_eq!(d.finish(false).unwrap(), empty());
    for t in [
        tag::LIM_MAX_SHARED_GROUPS,
        tag::LIM_MAX_SHARED_GROUP_MEMBERS,
    ] {
        for v in [1u64, 65_535] {
            let mut b = Builder::new();
            b.uint(t, v).unwrap();
            let blob = b.finish(false).unwrap();
            let p = Blob::parse(&blob).unwrap();
            assert_eq!(p.version(), 13, "{t} = {v}");
            assert_eq!(p.present().count(), 1);
            assert_eq!(p.uint(t), v);
        }
        let mut b = Builder::new();
        for v in [0u64, 65_536] {
            assert!(b.uint(t, v).is_err(), "{t} = {v}");
        }
        let rec = record(t, &64u32.to_le_bytes());
        assert!(Blob::parse(&with_version(&assemble(&rec), 12)).is_err());
        assert!(Blob::parse(&with_version(&assemble(&rec), 13)).is_ok());
    }
}

/// NOW-14, ADR-280: `limits.max_connections_per_ip`. Its default (1024) writes
/// nothing and keeps the base format; any other value, 0 (no limit) included,
/// needs format 14; 1000001 is refused; a blob of format 13 cannot hold it.
#[test]
fn connections_per_ip_limit() {
    let t = tag::LIM_MAX_CONNECTIONS_PER_IP;
    let mut d = Builder::new();
    d.uint(t, 1024).unwrap();
    assert_eq!(d.finish(false).unwrap(), empty());
    for v in [0u64, 1, 1_000_000] {
        let mut b = Builder::new();
        b.uint(t, v).unwrap();
        let blob = b.finish(false).unwrap();
        let p = Blob::parse(&blob).unwrap();
        assert_eq!(p.version(), 14, "{v}");
        assert_eq!(p.present().count(), 1);
        assert_eq!(p.uint(t), v);
    }
    assert!(Builder::new().uint(t, 1_000_001).is_err());
    let rec = record(t, &64u32.to_le_bytes());
    assert!(Blob::parse(&with_version(&assemble(&rec), 13)).is_err());
    assert!(Blob::parse(&with_version(&assemble(&rec), 14)).is_ok());
}

/// ADR-285: `limits.max_runtime_accounts`. 0 is the default and writes
/// nothing (the base format); any other value in 1..=1024 needs format 15;
/// 1025 is refused; a blob of format 13 cannot hold it.
#[test]
fn runtime_account_limit() {
    let t = tag::LIM_MAX_RUNTIME_ACCOUNTS;
    let mut d = Builder::new();
    d.uint(t, 0).unwrap();
    assert_eq!(d.finish(false).unwrap(), empty());
    for v in [1u64, 1_024] {
        let mut b = Builder::new();
        b.uint(t, v).unwrap();
        let bytes = b.finish(false).unwrap();
        let p = Blob::parse(&bytes).unwrap();
        assert_eq!(p.version(), 15, "{v}");
        assert_eq!(p.uint(t), v);
    }
    assert!(Builder::new().uint(t, 1_025).is_err());
    let rec = record(t, &64u16.to_le_bytes());
    assert!(Blob::parse(&with_version(&assemble(&rec), 13)).is_err());
    assert!(Blob::parse(&with_version(&assemble(&rec), 15)).is_ok());
}
