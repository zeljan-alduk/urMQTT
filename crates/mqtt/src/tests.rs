use super::*;
use proptest::prelude::*;

const L: Limits = Limits::PROTOCOL_MAX;
const SMALL: Limits = Limits {
    max_packet_size: 64,
    max_topic_len: 16,
    max_topic_levels: 3,
    max_client_id_len: 8,
    max_topics_per_packet: 2,
};

fn enc(p: &Packet<'_>) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len(p)];
    let n = encode(p, &mut out).unwrap();
    assert_eq!(n, out.len(), "encoded_len must be exact");
    out
}

fn dec(b: &[u8]) -> Result<Packet<'_>, Error> {
    decode(b, &L).map(|(p, n)| {
        assert_eq!(n, b.len());
        p
    })
}

// --- Spec byte vectors -------------------------------------------------

#[test]
fn connect_minimal_from_spec_layout() {
    // CONNECT, clean session, keep alive 60, client id "abc".
    let b = [
        0x10, 15, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 3, b'a', b'b', b'c',
    ];
    match dec(&b).unwrap() {
        Packet::Connect(c) => {
            assert_eq!(c.protocol_level, 4);
            assert!(c.clean_session);
            assert_eq!(c.keep_alive, 60);
            assert_eq!(c.client_id, "abc");
            assert!(c.will.is_none() && c.username.is_none() && c.password.is_none());
        }
        p => panic!("{p:?}"),
    }
}

#[test]
fn connect_with_will_user_password() {
    let c = Connect {
        protocol_level: 4,
        clean_session: false,
        keep_alive: 30,
        client_id: "device-001",
        will: Some(Will {
            topic: "devices/device-001/status",
            payload: b"offline",
            qos: QoS::AtLeastOnce,
            retain: true,
        }),
        username: Some("u"),
        password: Some(b"\x00\xffsecret"),
    };
    let b = enc(&Packet::Connect(c));
    assert_eq!(b[9], 0x80 | 0x40 | 0x20 | 0x08 | 0x04, "flags byte");
    assert_eq!(dec(&b).unwrap(), Packet::Connect(c));
}

#[test]
fn connect_rejections() {
    let base = [
        0x10u8, 12, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 0,
    ];
    assert!(dec(&base).is_ok(), "empty client id is syntactically fine");
    let mut b = base;
    b[9] |= 0x01; // reserved flag
    assert_eq!(dec(&b), Err(Error::InvalidConnectFlags));
    let mut b = base;
    b[9] = 0x02 | 0x40; // password without username
    assert_eq!(dec(&b), Err(Error::InvalidConnectFlags));
    let mut b = base;
    b[9] = 0x02 | 0x08; // will QoS without will flag
    assert_eq!(dec(&b), Err(Error::InvalidConnectFlags));
    let mut b = base;
    b[8] = 5; // MQTT 5
    assert_eq!(dec(&b), Err(Error::UnsupportedProtocolLevel(5)));
    let mut b = base;
    b[4] = b'X';
    assert_eq!(dec(&b), Err(Error::InvalidProtocolName));
    let mut b = base;
    b[0] = 0x11; // flags on CONNECT
    assert_eq!(dec(&b), Err(Error::InvalidFixedHeaderFlags));
    // MQTT 3.1 ("MQIsdp", level 3) is recognised as unsupported.
    let v31 = [
        0x10u8, 14, 0, 6, b'M', b'Q', b'I', b's', b'd', b'p', 3, 0x02, 0, 60, 0, 0,
    ];
    assert_eq!(
        decode(&v31, &L).map(|_| ()),
        Err(Error::UnsupportedProtocolLevel(3))
    );
    // Trailing garbage inside the remaining length.
    let mut t = base.to_vec();
    t[1] += 1;
    t.push(0);
    assert_eq!(dec(&t), Err(Error::MalformedPacket));
    // Will QoS 3.
    let mut b = base;
    b[9] = 0x02 | 0x04 | 0x18;
    assert_eq!(dec(&b), Err(Error::InvalidQos));
}

#[test]
fn client_id_limit() {
    let p = Packet::Connect(Connect {
        protocol_level: 4,
        clean_session: true,
        keep_alive: 0,
        client_id: "123456789",
        will: None,
        username: None,
        password: None,
    });
    assert_eq!(
        decode(&enc(&p), &SMALL).map(|_| ()),
        Err(Error::ClientIdTooLong)
    );
}

#[test]
fn connack_codes() {
    assert_eq!(
        dec(&[0x20, 2, 1, 0]),
        Ok(Packet::ConnAck(ConnAck {
            session_present: true,
            code: ConnectReturnCode::Accepted
        }))
    );
    assert_eq!(dec(&[0x20, 2, 0, 5]).map(|_| ()), Ok(()));
    assert_eq!(dec(&[0x20, 2, 0, 6]), Err(Error::InvalidReturnCode));
    assert_eq!(dec(&[0x20, 2, 2, 0]), Err(Error::MalformedPacket));
}

#[test]
fn publish_qos0_and_qos1() {
    // QoS 0, topic "a/b", payload "hi".
    let b = [0x30, 7, 0, 3, b'a', b'/', b'b', b'h', b'i'];
    assert_eq!(
        dec(&b),
        Ok(Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "a/b",
            packet_id: None,
            payload: b"hi"
        }))
    );
    // QoS 1, retain, dup, packet id 10, empty payload.
    let b = [0x3b, 5, 0, 1, b't', 0, 10];
    match dec(&b).unwrap() {
        Packet::Publish(p) => {
            assert!(p.dup && p.retain);
            assert_eq!(
                (p.qos, p.packet_id, p.payload),
                (QoS::AtLeastOnce, Some(10), &b""[..])
            );
        }
        p => panic!("{p:?}"),
    }
}

#[test]
fn publish_rejections() {
    assert_eq!(dec(&[0x36, 3, 0, 1, b't']), Err(Error::InvalidQos), "QoS 3");
    assert_eq!(
        dec(&[0x38, 3, 0, 1, b't']),
        Err(Error::InvalidFixedHeaderFlags),
        "DUP on QoS 0"
    );
    assert_eq!(dec(&[0x32, 5, 0, 1, b't', 0, 0]), Err(Error::ZeroPacketId));
    assert_eq!(dec(&[0x30, 3, 0, 1, b'+']), Err(Error::InvalidTopicName));
    assert_eq!(dec(&[0x30, 3, 0, 1, b'#']), Err(Error::InvalidTopicName));
    assert_eq!(
        dec(&[0x30, 2, 0, 0]),
        Err(Error::InvalidTopicName),
        "empty topic"
    );
    assert_eq!(
        dec(&[0x30, 3, 0, 1, 0x00]),
        Err(Error::InvalidUtf8),
        "U+0000"
    );
    assert_eq!(dec(&[0x30, 4, 0, 2, 0xc3, 0x28]), Err(Error::InvalidUtf8));
    assert_eq!(
        dec(&[0x30, 4, 0, 5, b'a', b'b']),
        Err(Error::MalformedPacket),
        "string past end"
    );
    let deep = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "a/b/c/d",
        packet_id: None,
        payload: b"",
    });
    assert_eq!(
        decode(&enc(&deep), &SMALL).map(|_| ()),
        Err(Error::TooManyTopicLevels)
    );
    let long = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "aaaaaaaaaaaaaaaaa",
        packet_id: None,
        payload: b"",
    });
    assert_eq!(
        decode(&enc(&long), &SMALL).map(|_| ()),
        Err(Error::TopicTooLong)
    );
}

#[test]
fn acks_and_empty_packets() {
    for (t, f) in [(0x40, 0u8), (0x50, 0), (0x62, 0), (0x70, 0), (0xb0, 0)] {
        let bytes = [t | f, 2, 0x12, 0x34];
        let p = dec(&bytes).unwrap();
        let id = match p {
            Packet::PubAck(i)
            | Packet::PubRec(i)
            | Packet::PubRel(i)
            | Packet::PubComp(i)
            | Packet::UnsubAck(i) => i,
            p => panic!("{p:?}"),
        };
        assert_eq!(id, 0x1234);
    }
    assert_eq!(
        dec(&[0x60, 2, 0, 1]),
        Err(Error::InvalidFixedHeaderFlags),
        "PUBREL needs 0b0010"
    );
    assert_eq!(dec(&[0x40, 3, 0, 1, 0]), Err(Error::MalformedPacket));
    assert_eq!(dec(&[0xc0, 0]), Ok(Packet::PingReq));
    assert_eq!(dec(&[0xd0, 0]), Ok(Packet::PingResp));
    assert_eq!(dec(&[0xe0, 0]), Ok(Packet::Disconnect));
    assert_eq!(dec(&[0xe0, 1, 0]), Err(Error::MalformedPacket));
    assert_eq!(dec(&[0xc1, 0]), Err(Error::InvalidFixedHeaderFlags));
    assert_eq!(dec(&[0x00, 0]), Err(Error::InvalidPacketType(0)));
    assert_eq!(dec(&[0xf0, 0]), Err(Error::InvalidPacketType(15)));
}

#[test]
fn subscribe_and_suback() {
    let b = [
        0x82, 14, 0x00, 0x0a, 0, 3, b'a', b'/', b'+', 1, 0, 3, b'b', b'/', b'#', 0,
    ];
    match dec(&b).unwrap() {
        Packet::Subscribe(s) => {
            assert_eq!(s.packet_id, 10);
            let v: Vec<_> = s.topics.iter().collect();
            assert_eq!(v, vec![("a/+", QoS::AtLeastOnce), ("b/#", QoS::AtMostOnce)]);
        }
        p => panic!("{p:?}"),
    }
    assert_eq!(dec(&[0x80, 2, 0, 1]), Err(Error::InvalidFixedHeaderFlags));
    assert_eq!(dec(&[0x82, 2, 0, 1]), Err(Error::EmptySubscription));
    assert_eq!(dec(&[0x82, 6, 0, 1, 0, 1, b'a', 3]), Err(Error::InvalidQos));
    assert_eq!(
        dec(&[0x82, 6, 0, 1, 0, 1, b'a', 0x41]),
        Err(Error::InvalidQos),
        "reserved bits"
    );
    assert_eq!(
        dec(&[0x82, 7, 0, 1, 0, 2, b'#', b'/', 0]),
        Err(Error::InvalidTopicFilter)
    );
    let three = [0x82, 14, 0, 1, 0, 1, b'a', 0, 0, 1, b'b', 0, 0, 1, b'c', 0];
    assert_eq!(
        decode(&three, &SMALL).map(|_| ()),
        Err(Error::TooManyTopics)
    );
    assert_eq!(
        dec(&[0x90, 5, 0, 7, 0, 1, 0x80]),
        Ok(Packet::SubAck(SubAck {
            packet_id: 7,
            return_codes: &[0, 1, 0x80]
        }))
    );
    assert_eq!(dec(&[0x90, 3, 0, 7, 3]), Err(Error::InvalidReturnCode));
    assert_eq!(dec(&[0x90, 2, 0, 7]), Err(Error::InvalidReturnCode));
}

#[test]
fn unsubscribe() {
    let b = [0xa2, 9, 0, 3, 0, 5, b'x', b'/', b'+', b'/', b'y'];
    match dec(&b).unwrap() {
        Packet::Unsubscribe(u) => {
            assert_eq!(u.packet_id, 3);
            assert_eq!(u.topics.iter().collect::<Vec<_>>(), vec!["x/+/y"]);
        }
        p => panic!("{p:?}"),
    }
    assert_eq!(dec(&[0xa2, 2, 0, 3]), Err(Error::EmptySubscription));
}

#[test]
fn remaining_length_encoding() {
    // Max 4 bytes, minimal encodings only.
    assert_eq!(
        decode(&[0x30, 0x80, 0x80, 0x80, 0x80, 1], &L).map(|_| ()),
        Err(Error::MalformedRemainingLength)
    );
    assert_eq!(
        decode(&[0xc0, 0x80, 0x00], &L).map(|_| ()),
        Err(Error::MalformedRemainingLength)
    );
    // 321 = 0xC1 0x02
    let payload = vec![0u8; 321 - 3]; // body = 2 + 1 (topic "t") + payload
    let p = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "t",
        packet_id: None,
        payload: &payload,
    });
    let b = enc(&p);
    assert_eq!(&b[1..3], &[0xc1, 0x02]);
    assert_eq!(dec(&b), Ok(p));
}

#[test]
fn packet_size_checked_before_body_arrives() {
    // Declares 2 MiB but only 5 bytes are here: rejected immediately, not
    // "incomplete", so a peer cannot make us buffer it.
    let b = [0x30, 0x80, 0x80, 0x80, 0x01];
    assert_eq!(decode(&b, &SMALL).map(|_| ()), Err(Error::PacketTooLarge));
    assert_eq!(
        decode(&b, &L).map(|_| ()),
        Err(Error::Incomplete(5 + 2_097_152))
    );
}

#[test]
fn streaming_prefixes_are_incomplete() {
    let p = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        topic: "devices/x/telemetry",
        packet_id: Some(99),
        payload: &[7u8; 200],
    });
    let b = enc(&p);
    for cut in 0..b.len() {
        match decode(&b[..cut], &L) {
            Err(Error::Incomplete(need)) => {
                assert!(need > cut && need <= b.len(), "cut {cut} need {need}")
            }
            other => panic!("prefix {cut}: {other:?}"),
        }
    }
    // Two packets back to back: the first decode consumes exactly one.
    let mut two = b.clone();
    two.extend_from_slice(&enc(&Packet::PingReq));
    let (_, n) = decode(&two, &L).unwrap();
    assert_eq!(n, b.len());
    assert_eq!(decode(&two[n..], &L).unwrap(), (Packet::PingReq, 2));
}

#[test]
fn encode_errors() {
    let mut small = [0u8; 3];
    assert_eq!(
        encode(&Packet::PubAck(1), &mut small[..2]),
        Err(EncodeError::BufferTooSmall)
    );
    let bad = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        topic: "t",
        packet_id: None,
        payload: b"",
    });
    assert_eq!(
        encode(&bad, &mut [0u8; 16]),
        Err(EncodeError::InconsistentPacketId)
    );
}

#[test]
fn topic_matching_rules() {
    for (f, t, m) in [
        ("a/b", "a/b", true),
        ("a/+", "a/b", true),
        ("a/+", "a/b/c", false),
        ("a/#", "a", true),
        ("a/#", "a/b/c", true),
        ("#", "a/b", true),
        ("+/+", "a/b", true),
        ("+", "", true),
        ("a/+/c", "a//c", true),
        ("#", "$SYS/x", false),
        ("+/x", "$SYS/x", false),
        ("$SYS/#", "$SYS/x", true),
        ("a/b", "a/c", false),
        ("devices/+/telemetry/#", "devices/d1/telemetry/temp", true),
    ] {
        assert_eq!(topic_matches(f, t), m, "{f} vs {t}");
    }
    assert!(is_valid_topic_filter("a/+/#"));
    assert!(!is_valid_topic_filter("a/#/b"));
    assert!(!is_valid_topic_filter("a+"));
    assert!(!is_valid_topic_name("a/+"));
}

// --- Property tests ----------------------------------------------------

fn topic_name() -> impl Strategy<Value = String> {
    "[a-z0-9_]{1,8}(/[a-z0-9_]{0,8}){0,4}"
}

fn topic_filter() -> impl Strategy<Value = String> {
    prop_oneof![
        topic_name(),
        "[a-z]{1,4}/\\+/[a-z]{1,4}",
        "[a-z]{1,4}(/[a-z]{1,4}){0,2}/#",
        Just("#".to_owned()),
        Just("+".to_owned()),
    ]
}

fn qos() -> impl Strategy<Value = QoS> {
    prop_oneof![
        Just(QoS::AtMostOnce),
        Just(QoS::AtLeastOnce),
        Just(QoS::ExactlyOnce)
    ]
}

proptest! {
    #[test]
    fn publish_roundtrip(t in topic_name(), q in qos(), retain: bool, dup: bool, id in 1u16.., payload in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let p = Packet::Publish(Publish {
            dup: dup && q != QoS::AtMostOnce,
            qos: q,
            retain,
            topic: &t,
            packet_id: (q != QoS::AtMostOnce).then_some(id),
            payload: &payload,
        });
        let bytes = enc(&p);
        prop_assert_eq!(dec(&bytes).unwrap(), p);
    }

    #[test]
    fn connect_roundtrip(id in "[a-zA-Z0-9-]{0,23}", clean: bool, ka: u16, will in proptest::option::of((topic_name(), proptest::collection::vec(any::<u8>(), 0..64), qos(), any::<bool>())), user in proptest::option::of("[a-z]{1,12}"), pw in proptest::collection::vec(any::<u8>(), 0..32)) {
        let will = will.as_ref().map(|(t, p, q, r)| Will { topic: t, payload: p, qos: *q, retain: *r });
        let c = Connect {
            protocol_level: 4,
            clean_session: clean,
            keep_alive: ka,
            client_id: &id,
            will,
            username: user.as_deref(),
            password: user.as_ref().map(|_| &pw[..]),
        };
        let bytes = enc(&Packet::Connect(c));
        prop_assert_eq!(dec(&bytes).unwrap(), Packet::Connect(c));
    }

    #[test]
    fn subscribe_roundtrip(id in 1u16.., filters in proptest::collection::vec((topic_filter(), qos()), 1..8)) {
        let list: Vec<(&str, QoS)> = filters.iter().map(|(f, q)| (f.as_str(), *q)).collect();
        let p = Packet::Subscribe(Subscribe { packet_id: id, topics: SubscribeTopics::List(&list) });
        let bytes = enc(&p);
        prop_assert_eq!(dec(&bytes).unwrap(), p);
        let names: Vec<&str> = filters.iter().map(|(f, _)| f.as_str()).collect();
        let u = Packet::Unsubscribe(Unsubscribe { packet_id: id, topics: UnsubscribeTopics::List(&names) });
        let bytes = enc(&u);
        prop_assert_eq!(dec(&bytes).unwrap(), u);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode(&bytes, &L);
        let _ = decode(&bytes, &SMALL);
    }

    #[test]
    fn mutated_valid_packets_never_panic(t in topic_name(), payload in proptest::collection::vec(any::<u8>(), 0..64), flips in proptest::collection::vec((0usize..128, any::<u8>()), 1..6)) {
        let p = Packet::Publish(Publish { dup: false, qos: QoS::AtLeastOnce, retain: false, topic: &t, packet_id: Some(1), payload: &payload });
        let mut b = enc(&p);
        for (i, v) in flips {
            let n = b.len();
            b[i % n] ^= v;
        }
        let _ = decode(&b, &L);
    }
}
