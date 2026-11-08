//! MQTT 5.0 codec tests: the specification's tables cell by cell, byte
//! vectors, a negative corpus, and round-trip properties.

use super::*;
use proptest::prelude::*;

const L: Limits = Limits::PROTOCOL_MAX;

/// A packet from its first byte and body (the Remaining Length is added).
fn pkt(first: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![first];
    let mut len = [0u8; 4];
    let n = write_varint(u32::try_from(body.len()).unwrap(), &mut len).unwrap();
    v.extend_from_slice(&len[..n]);
    v.extend_from_slice(body);
    v
}

/// A property block with its Property Length.
fn block(props: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 4];
    let n = write_varint(u32::try_from(props.len()).unwrap(), &mut v).unwrap();
    v.truncate(n);
    v.extend_from_slice(props);
    v
}

fn s(x: &str) -> Vec<u8> {
    let mut v = u16::try_from(x.len()).unwrap().to_be_bytes().to_vec();
    v.extend_from_slice(x.as_bytes());
    v
}

fn enc(p: &Packet<'_>) -> Vec<u8> {
    let mut out = vec![0u8; encoded_len(p).unwrap()];
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

fn round_trip(p: &Packet<'_>) -> Vec<u8> {
    let b = enc(p);
    assert_eq!(&dec(&b).unwrap(), p, "{b:02x?}");
    b
}

// --- Variable Byte Integer (§1.5.5) ------------------------------------

#[test]
fn varint_spec_boundaries() {
    // Table 1-1 of §1.5.5.
    let table: [(u32, &[u8]); 8] = [
        (0, &[0x00]),
        (127, &[0x7f]),
        (128, &[0x80, 0x01]),
        (16_383, &[0xff, 0x7f]),
        (16_384, &[0x80, 0x80, 0x01]),
        (2_097_151, &[0xff, 0xff, 0x7f]),
        (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
        (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
    ];
    for (v, bytes) in table {
        assert_eq!(read_varint(bytes), Ok((v, bytes.len())));
        let mut out = [0u8; 4];
        assert_eq!(write_varint(v, &mut out), Ok(bytes.len()));
        assert_eq!(&out[..bytes.len()], bytes);
        assert_eq!(varint_len(v), bytes.len());
    }
    assert_eq!(
        write_varint(MAX_VARINT + 1, &mut [0u8; 8]),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(
        write_varint(128, &mut [0u8; 1]),
        Err(EncodeError::BufferTooSmall)
    );
}

#[test]
fn varint_rejections() {
    for bad in [
        &[][..],
        &[0x80],
        &[0xff, 0xff, 0xff, 0xff, 0x7f], // five bytes
        &[0x80, 0x00],                   // non-minimal 0
        &[0xff, 0x80, 0x00],             // non-minimal 127
        &[0x80, 0x80, 0x80, 0x00],
    ] {
        assert_eq!(read_varint(bad), Err(Error::MalformedVarint), "{bad:02x?}");
    }
}

#[test]
fn remaining_length_streaming() {
    // A PINGREQ split anywhere asks for the rest.
    assert_eq!(decode(&[], &L), Err(Error::Incomplete(2)));
    assert_eq!(decode(&[0xc0], &L), Err(Error::Incomplete(2)));
    // Remaining Length 200 (two bytes): first byte only.
    assert_eq!(decode(&[0x30, 0xc8], &L), Err(Error::Incomplete(3)));
    assert_eq!(decode(&[0x30, 0xc8, 0x01], &L), Err(Error::Incomplete(203)));
    assert_eq!(
        decode(&[0x30, 0xff, 0xff, 0xff, 0xff], &L),
        Err(Error::MalformedRemainingLength)
    );
    assert_eq!(
        decode(&[0xc0, 0x80, 0x00], &L),
        Err(Error::MalformedRemainingLength)
    );
}

#[test]
fn packet_too_large_before_the_body() {
    let small = Limits {
        base: crate::Limits {
            max_packet_size: 100,
            ..crate::Limits::PROTOCOL_MAX
        },
        ..L
    };
    // 1 + 1 + 98 = 100 bytes: fine (but incomplete); 101: too large.
    assert_eq!(decode(&[0x30, 98], &small), Err(Error::Incomplete(100)));
    assert_eq!(decode(&[0x30, 99], &small), Err(Error::PacketTooLarge));
    assert_eq!(
        decode(&[0x30, 0xff, 0xff, 0xff, 0x7f], &small),
        Err(Error::PacketTooLarge)
    );
}

// --- Properties: Table 2-4 of §2.2.2.2, cell by cell -------------------

use PropertyContext as C;
use PropertyType as T;

/// §2.2.2.2 Table 2-4: identifier, name, type, packets (W = Will).
const SPEC_PROPERTIES: [(u8, &str, PropertyType, &[PropertyContext]); 27] = [
    (
        0x01,
        "Payload Format Indicator",
        T::Byte,
        &[C::Publish, C::Will],
    ),
    (
        0x02,
        "Message Expiry Interval",
        T::FourByteInteger,
        &[C::Publish, C::Will],
    ),
    (0x03, "Content Type", T::Utf8String, &[C::Publish, C::Will]),
    (
        0x08,
        "Response Topic",
        T::Utf8String,
        &[C::Publish, C::Will],
    ),
    (
        0x09,
        "Correlation Data",
        T::BinaryData,
        &[C::Publish, C::Will],
    ),
    (
        0x0b,
        "Subscription Identifier",
        T::VariableByteInteger,
        &[C::Publish, C::Subscribe],
    ),
    (
        0x11,
        "Session Expiry Interval",
        T::FourByteInteger,
        &[C::Connect, C::ConnAck, C::Disconnect],
    ),
    (
        0x12,
        "Assigned Client Identifier",
        T::Utf8String,
        &[C::ConnAck],
    ),
    (0x13, "Server Keep Alive", T::TwoByteInteger, &[C::ConnAck]),
    (
        0x15,
        "Authentication Method",
        T::Utf8String,
        &[C::Connect, C::ConnAck, C::Auth],
    ),
    (
        0x16,
        "Authentication Data",
        T::BinaryData,
        &[C::Connect, C::ConnAck, C::Auth],
    ),
    (0x17, "Request Problem Information", T::Byte, &[C::Connect]),
    (0x18, "Will Delay Interval", T::FourByteInteger, &[C::Will]),
    (0x19, "Request Response Information", T::Byte, &[C::Connect]),
    (0x1a, "Response Information", T::Utf8String, &[C::ConnAck]),
    (
        0x1c,
        "Server Reference",
        T::Utf8String,
        &[C::ConnAck, C::Disconnect],
    ),
    (
        0x1f,
        "Reason String",
        T::Utf8String,
        &[
            C::ConnAck,
            C::PubAck,
            C::PubRec,
            C::PubRel,
            C::PubComp,
            C::SubAck,
            C::UnsubAck,
            C::Disconnect,
            C::Auth,
        ],
    ),
    (
        0x21,
        "Receive Maximum",
        T::TwoByteInteger,
        &[C::Connect, C::ConnAck],
    ),
    (
        0x22,
        "Topic Alias Maximum",
        T::TwoByteInteger,
        &[C::Connect, C::ConnAck],
    ),
    (0x23, "Topic Alias", T::TwoByteInteger, &[C::Publish]),
    (0x24, "Maximum QoS", T::Byte, &[C::ConnAck]),
    (0x25, "Retain Available", T::Byte, &[C::ConnAck]),
    (
        0x26,
        "User Property",
        T::Utf8StringPair,
        &[
            C::Connect,
            C::ConnAck,
            C::Publish,
            C::Will,
            C::PubAck,
            C::PubRec,
            C::PubRel,
            C::PubComp,
            C::Subscribe,
            C::SubAck,
            C::Unsubscribe,
            C::UnsubAck,
            C::Disconnect,
            C::Auth,
        ],
    ),
    (
        0x27,
        "Maximum Packet Size",
        T::FourByteInteger,
        &[C::Connect, C::ConnAck],
    ),
    (
        0x28,
        "Wildcard Subscription Available",
        T::Byte,
        &[C::ConnAck],
    ),
    (
        0x29,
        "Subscription Identifier Available",
        T::Byte,
        &[C::ConnAck],
    ),
    (
        0x2a,
        "Shared Subscription Available",
        T::Byte,
        &[C::ConnAck],
    ),
];

/// A valid encoded value of each type (identifier not included).
fn sample_value(t: PropertyType) -> Vec<u8> {
    match t {
        T::Byte => vec![1],
        T::TwoByteInteger => vec![0, 1],
        T::FourByteInteger => vec![0, 0, 0, 1],
        T::VariableByteInteger => vec![1],
        T::Utf8String => s("a"),
        T::BinaryData => vec![0, 1, 0],
        T::Utf8StringPair => [s("k"), s("v")].concat(),
    }
}

fn sample(id: u8, t: PropertyType) -> Vec<u8> {
    [vec![id], sample_value(t)].concat()
}

/// Authentication Data needs an Authentication Method beside it.
fn with_partner(id: u8, t: PropertyType) -> Vec<u8> {
    let mut v = sample(id, t);
    if id == 0x16 {
        v.extend(sample(0x15, T::Utf8String));
    }
    v
}

#[test]
fn property_table_matches_the_spec() {
    assert_eq!(PropertyId::ALL.len(), SPEC_PROPERTIES.len());
    for (id, name, ty, ctxs) in SPEC_PROPERTIES {
        let p = PropertyId::from_u8(id).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(p as u8, id, "{name}");
        assert_eq!(p.ty(), ty, "{name}");
        for ctx in PropertyContext::ALL {
            let want = ctxs.contains(&ctx);
            assert_eq!(p.allowed_in(ctx), want, "{name} in {ctx:?}");
            let raw = with_partner(id, ty);
            let got = validate_properties(&raw, ctx, &L);
            if want {
                assert_eq!(got, Ok(()), "{name} in {ctx:?}");
            } else {
                // The partner (Authentication Method) may itself be refused
                // first; either way this block is refused as not allowed.
                assert!(
                    matches!(got, Err(Error::PropertyNotAllowed(_))),
                    "{name} in {ctx:?}: {got:?}"
                );
            }
        }
    }
    // Every byte that is not in the table is an unknown identifier.
    for b in 0..=255u8 {
        if SPEC_PROPERTIES.iter().any(|(id, ..)| *id == b) {
            continue;
        }
        assert!(PropertyId::from_u8(b).is_none());
        for ctx in PropertyContext::ALL {
            assert_eq!(
                validate_properties(&[b, 0, 0, 0, 0], ctx, &L),
                Err(Error::UnknownProperty(b))
            );
        }
    }
}

#[test]
fn duplicate_property_rules() {
    for (id, name, ty, ctxs) in SPEC_PROPERTIES {
        for &ctx in ctxs {
            let one = sample(id, ty);
            let mut raw = [one.clone(), one].concat();
            if id == 0x16 {
                raw.extend(sample(0x15, T::Utf8String));
            }
            let repeat_ok = id == 0x26 || (id == 0x0b && ctx == C::Publish);
            let got = validate_properties(&raw, ctx, &L);
            if repeat_ok {
                assert_eq!(got, Ok(()), "{name} twice in {ctx:?}");
            } else {
                assert_eq!(
                    got,
                    Err(Error::DuplicateProperty(id)),
                    "{name} twice in {ctx:?}"
                );
            }
        }
    }
}

#[test]
fn property_value_ranges() {
    // Byte flags: 0 and 1 only (§3.1.2.11.6, .7, §3.2.2.3.4, .5, .11-.13,
    // §3.3.2.3.2).
    for (id, ctx) in [
        (0x01, C::Publish),
        (0x17, C::Connect),
        (0x19, C::Connect),
        (0x24, C::ConnAck),
        (0x25, C::ConnAck),
        (0x28, C::ConnAck),
        (0x29, C::ConnAck),
        (0x2a, C::ConnAck),
    ] {
        assert_eq!(validate_properties(&[id, 0], ctx, &L), Ok(()));
        assert_eq!(validate_properties(&[id, 1], ctx, &L), Ok(()));
        for v in 2..=255u8 {
            assert_eq!(
                validate_properties(&[id, v], ctx, &L),
                Err(Error::InvalidPropertyValue(id))
            );
        }
    }
    // Zero is a protocol error: Receive Maximum, Topic Alias, Maximum
    // Packet Size, Subscription Identifier.
    assert_eq!(
        validate_properties(&[0x21, 0, 0], C::Connect, &L),
        Err(Error::InvalidPropertyValue(0x21))
    );
    assert_eq!(
        validate_properties(&[0x23, 0, 0], C::Publish, &L),
        Err(Error::InvalidPropertyValue(0x23))
    );
    assert_eq!(
        validate_properties(&[0x27, 0, 0, 0, 0], C::Connect, &L),
        Err(Error::InvalidPropertyValue(0x27))
    );
    assert_eq!(
        validate_properties(&[0x0b, 0], C::Subscribe, &L),
        Err(Error::InvalidPropertyValue(0x0b))
    );
    // Topic Alias Maximum 0 and Server Keep Alive 0 are meaningful values.
    assert_eq!(validate_properties(&[0x22, 0, 0], C::Connect, &L), Ok(()));
    assert_eq!(validate_properties(&[0x13, 0, 0], C::ConnAck, &L), Ok(()));
    // Subscription Identifier: up to 268 435 455, minimal, at most 4 bytes.
    assert_eq!(
        validate_properties(&[0x0b, 0xff, 0xff, 0xff, 0x7f], C::Subscribe, &L),
        Ok(())
    );
    assert_eq!(
        validate_properties(&[0x0b, 0x81, 0x00], C::Subscribe, &L),
        Err(Error::MalformedVarint)
    );
    assert_eq!(
        validate_properties(&[0x0b, 0xff, 0xff, 0xff, 0xff, 0x01], C::Subscribe, &L),
        Err(Error::MalformedVarint)
    );
    // Response Topic is a Topic Name: no wildcards, not empty.
    for bad in ["a/+", "#", ""] {
        let raw = [vec![0x08], s(bad)].concat();
        assert_eq!(
            validate_properties(&raw, C::Publish, &L),
            Err(Error::InvalidPropertyValue(0x08)),
            "{bad}"
        );
    }
    // Authentication Data without Method.
    assert_eq!(
        validate_properties(&[0x16, 0, 0], C::Connect, &L),
        Err(Error::MissingAuthenticationMethod)
    );
}

#[test]
fn property_strings_follow_the_utf8_rule() {
    for bad in [
        &b"\x00"[..],    // U+0000
        b"\xed\xa0\x80", // a surrogate (U+D800)
        b"\xff",         // not UTF-8
        b"\xc0\x80",     // overlong NUL
        b"a\xe2\x82",    // truncated sequence
    ] {
        let mut raw = vec![0x03];
        raw.extend(u16::try_from(bad.len()).unwrap().to_be_bytes());
        raw.extend_from_slice(bad);
        assert_eq!(
            validate_properties(&raw, C::Publish, &L),
            Err(Error::InvalidUtf8)
        );
        // As a User Property name and value.
        let mut up = vec![0x26];
        up.extend(&raw[1..]);
        up.extend(s("v"));
        assert_eq!(
            validate_properties(&up, C::Publish, &L),
            Err(Error::InvalidUtf8)
        );
    }
    // U+FEFF and non-characters are allowed (§1.5.4: "MUST NOT be skipped").
    let raw = [vec![0x03], s("\u{feff}\u{ffff}")].concat();
    assert_eq!(validate_properties(&raw, C::Publish, &L), Ok(()));
    // Truncated values.
    for bad in [
        &[0x03, 0][..],
        &[0x03, 0, 2, b'a'],
        &[0x02, 0, 0, 0],
        &[0x13, 0],
        &[0x26, 0, 1, b'k'],
    ] {
        assert!(
            validate_properties(bad, C::Publish, &L).is_err(),
            "{bad:02x?}"
        );
    }
}

#[test]
fn list_bounds() {
    let lim = Limits {
        max_user_properties: 2,
        max_subscription_identifiers: 1,
        ..L
    };
    let up = sample(0x26, T::Utf8StringPair);
    assert_eq!(validate_properties(&up.repeat(2), C::Publish, &lim), Ok(()));
    assert_eq!(
        validate_properties(&up.repeat(3), C::Publish, &lim),
        Err(Error::TooManyUserProperties)
    );
    let sid = sample(0x0b, T::VariableByteInteger);
    assert_eq!(validate_properties(&sid, C::Publish, &lim), Ok(()));
    assert_eq!(
        validate_properties(&sid.repeat(2), C::Publish, &lim),
        Err(Error::TooManySubscriptionIdentifiers)
    );
}

#[test]
fn property_length_beyond_the_body() {
    // CONNACK whose Property Length claims 5 bytes but has 1.
    let b = pkt(0x20, &[0, 0, 5, 0x24]);
    assert_eq!(dec(&b), Err(Error::MalformedPacket));
    // Property Length of five bytes.
    let b = pkt(0x20, &[0, 0, 0x80, 0x80, 0x80, 0x80, 0x01]);
    assert_eq!(dec(&b), Err(Error::MalformedVarint));
    // Property Length near the varint maximum.
    let b = pkt(0x20, &[0, 0, 0xff, 0xff, 0xff, 0x7f]);
    assert_eq!(dec(&b), Err(Error::MalformedPacket));
}

// --- Reason codes: Table 2-6 of §2.4 -----------------------------------

use ReasonTable as R;

/// §2.4 Table 2-6: value, name, packets.
const SPEC_REASONS: [(u8, &str, &[ReasonTable]); 43] = [
    (
        0x00,
        "Success / Normal disconnection / Granted QoS 0",
        &[
            R::ConnAck,
            R::PubAck,
            R::PubRec,
            R::PubRel,
            R::PubComp,
            R::UnsubAck,
            R::Auth,
            R::Disconnect,
            R::SubAck,
        ],
    ),
    (0x01, "Granted QoS 1", &[R::SubAck]),
    (0x02, "Granted QoS 2", &[R::SubAck]),
    (0x04, "Disconnect with Will Message", &[R::Disconnect]),
    (0x10, "No matching subscribers", &[R::PubAck, R::PubRec]),
    (0x11, "No subscription existed", &[R::UnsubAck]),
    (0x18, "Continue authentication", &[R::Auth]),
    (0x19, "Re-authenticate", &[R::Auth]),
    (
        0x80,
        "Unspecified error",
        &[
            R::ConnAck,
            R::PubAck,
            R::PubRec,
            R::SubAck,
            R::UnsubAck,
            R::Disconnect,
        ],
    ),
    (0x81, "Malformed Packet", &[R::ConnAck, R::Disconnect]),
    (0x82, "Protocol Error", &[R::ConnAck, R::Disconnect]),
    (
        0x83,
        "Implementation specific error",
        &[
            R::ConnAck,
            R::PubAck,
            R::PubRec,
            R::SubAck,
            R::UnsubAck,
            R::Disconnect,
        ],
    ),
    (0x84, "Unsupported Protocol Version", &[R::ConnAck]),
    (0x85, "Client Identifier not valid", &[R::ConnAck]),
    (0x86, "Bad User Name or Password", &[R::ConnAck]),
    (
        0x87,
        "Not authorized",
        &[
            R::ConnAck,
            R::PubAck,
            R::PubRec,
            R::SubAck,
            R::UnsubAck,
            R::Disconnect,
        ],
    ),
    (0x88, "Server unavailable", &[R::ConnAck]),
    (0x89, "Server busy", &[R::ConnAck, R::Disconnect]),
    (0x8a, "Banned", &[R::ConnAck]),
    (0x8b, "Server shutting down", &[R::Disconnect]),
    (
        0x8c,
        "Bad authentication method",
        &[R::ConnAck, R::Disconnect],
    ),
    (0x8d, "Keep Alive timeout", &[R::Disconnect]),
    (0x8e, "Session taken over", &[R::Disconnect]),
    (
        0x8f,
        "Topic Filter invalid",
        &[R::SubAck, R::UnsubAck, R::Disconnect],
    ),
    (
        0x90,
        "Topic Name invalid",
        &[R::ConnAck, R::PubAck, R::PubRec, R::Disconnect],
    ),
    (
        0x91,
        "Packet Identifier in use",
        &[R::PubAck, R::PubRec, R::SubAck, R::UnsubAck],
    ),
    (
        0x92,
        "Packet Identifier not found",
        &[R::PubRel, R::PubComp],
    ),
    (0x93, "Receive Maximum exceeded", &[R::Disconnect]),
    (0x94, "Topic Alias invalid", &[R::Disconnect]),
    (0x95, "Packet too large", &[R::ConnAck, R::Disconnect]),
    (0x96, "Message rate too high", &[R::Disconnect]),
    (
        0x97,
        "Quota exceeded",
        &[R::ConnAck, R::PubAck, R::PubRec, R::SubAck, R::Disconnect],
    ),
    (0x98, "Administrative action", &[R::Disconnect]),
    (
        0x99,
        "Payload format invalid",
        &[R::ConnAck, R::PubAck, R::PubRec, R::Disconnect],
    ),
    (0x9a, "Retain not supported", &[R::ConnAck, R::Disconnect]),
    (0x9b, "QoS not supported", &[R::ConnAck, R::Disconnect]),
    (0x9c, "Use another server", &[R::ConnAck, R::Disconnect]),
    (0x9d, "Server moved", &[R::ConnAck, R::Disconnect]),
    (
        0x9e,
        "Shared Subscriptions not supported",
        &[R::SubAck, R::Disconnect],
    ),
    (
        0x9f,
        "Connection rate exceeded",
        &[R::ConnAck, R::Disconnect],
    ),
    (0xa0, "Maximum connect time", &[R::Disconnect]),
    (
        0xa1,
        "Subscription Identifiers not supported",
        &[R::SubAck, R::Disconnect],
    ),
    (
        0xa2,
        "Wildcard Subscriptions not supported",
        &[R::SubAck, R::Disconnect],
    ),
];

#[test]
fn reason_table_matches_the_spec() {
    assert_eq!(ReasonCode::ALL.len(), SPEC_REASONS.len());
    for b in 0..=255u8 {
        let spec = SPEC_REASONS.iter().find(|(v, ..)| *v == b);
        let code = ReasonCode::from_u8(b);
        assert_eq!(code.is_some(), spec.is_some(), "{b:#04x}");
        let (Some(code), Some((_, name, tables))) = (code, spec) else {
            continue;
        };
        assert_eq!(code as u8, b, "{name}");
        assert_eq!(code.is_error(), b >= 0x80, "{name}");
        for t in ReasonTable::ALL {
            assert_eq!(code.allowed_in(t), tables.contains(&t), "{name} in {t:?}");
        }
    }
}

/// The smallest packet of `t` carrying reason byte `b`.
fn with_reason(t: ReasonTable, b: u8) -> Vec<u8> {
    match t {
        R::ConnAck => pkt(0x20, &[0, b, 0]),
        R::PubAck => pkt(0x40, &[0, 1, b]),
        R::PubRec => pkt(0x50, &[0, 1, b]),
        R::PubRel => pkt(0x62, &[0, 1, b]),
        R::PubComp => pkt(0x70, &[0, 1, b]),
        R::SubAck => pkt(0x90, &[0, 1, 0, b]),
        R::UnsubAck => pkt(0xb0, &[0, 1, 0, b]),
        R::Disconnect => pkt(0xe0, &[b]),
        R::Auth => pkt(0xf0, &[&[b][..], &block(&[0x15, 0, 1, b'x'])].concat()),
    }
}

#[test]
fn every_reason_byte_in_every_packet() {
    for t in ReasonTable::ALL {
        for b in 0..=255u8 {
            let bytes = with_reason(t, b);
            let want = SPEC_REASONS
                .iter()
                .any(|(v, _, tables)| *v == b && tables.contains(&t));
            match dec(&bytes) {
                Ok(p) => {
                    assert!(want, "{t:?} accepted {b:#04x}");
                    let again = enc(&p);
                    assert_eq!(dec(&again), Ok(p), "{t:?} {b:#04x}");
                    assert!(again.len() <= bytes.len(), "{t:?} {b:#04x}: shortest form");
                }
                Err(e) => {
                    assert!(!want, "{t:?} refused {b:#04x}: {e:?}");
                    assert_eq!(e, Error::InvalidReasonCode(b));
                }
            }
        }
    }
}

#[test]
fn error_reason_codes_are_allowed_where_they_are_sent() {
    // Every error maps to a code a CONNACK or a DISCONNECT may carry.
    let all = [
        Error::Incomplete(1),
        Error::MalformedRemainingLength,
        Error::MalformedVarint,
        Error::PacketTooLarge,
        Error::InvalidPacketType(0),
        Error::InvalidFixedHeaderFlags,
        Error::InvalidProtocolName,
        Error::UnsupportedProtocolLevel(3),
        Error::InvalidConnectFlags,
        Error::InvalidQos,
        Error::InvalidUtf8,
        Error::InvalidTopicName,
        Error::InvalidTopicFilter,
        Error::TopicTooLong,
        Error::TooManyTopicLevels,
        Error::ClientIdTooLong,
        Error::EmptySubscription,
        Error::TooManyTopics,
        Error::ZeroPacketId,
        Error::InvalidReasonCode(3),
        Error::InvalidSubscriptionOptions,
        Error::InvalidRetainHandling,
        Error::SharedNoLocal,
        Error::UnknownProperty(0),
        Error::PropertyNotAllowed(1),
        Error::DuplicateProperty(1),
        Error::InvalidPropertyValue(1),
        Error::MissingAuthenticationMethod,
        Error::TooManyUserProperties,
        Error::TooManySubscriptionIdentifiers,
        Error::SessionPresentWithError,
        Error::MalformedPacket,
    ];
    for e in all {
        let c = e.reason_code();
        assert!(c.is_error(), "{e:?}");
        assert!(
            c.allowed_in(R::ConnAck) || c.allowed_in(R::Disconnect),
            "{e:?} -> {c:?}"
        );
    }
    assert_eq!(
        Error::DuplicateProperty(1).reason_code(),
        ReasonCode::ProtocolError
    );
    assert_eq!(
        Error::PropertyNotAllowed(1).reason_code(),
        ReasonCode::MalformedPacket
    );
    assert_eq!(
        Error::UnsupportedProtocolLevel(4).reason_code(),
        ReasonCode::UnsupportedProtocolVersion
    );
}

// --- Packets: byte vectors -----------------------------------------------

fn connect_body(flags: u8, props: &[u8], payload: &[u8]) -> Vec<u8> {
    [&s("MQTT")[..], &[5, flags, 0, 60], &block(props), payload].concat()
}

#[test]
fn connect_minimal() {
    // Clean Start, keep alive 60, no properties, client id "abc".
    let b = pkt(0x10, &connect_body(0x02, &[], &s("abc")));
    assert_eq!(
        b,
        [
            0x10, 16, 0, 4, b'M', b'Q', b'T', b'T', 5, 2, 0, 60, 0, 0, 3, b'a', b'b', b'c'
        ]
    );
    match dec(&b).unwrap() {
        Packet::Connect(c) => {
            assert!(c.clean_start);
            assert_eq!(c.keep_alive, 60);
            assert_eq!(c.client_id, "abc");
            assert!(c.properties.is_empty());
            assert!(c.will.is_none() && c.username.is_none() && c.password.is_none());
        }
        p => panic!("{p:?}"),
    }
    assert_eq!(connect_protocol_level(&b), Ok(5));
}

#[test]
fn connect_full_round_trip() {
    let props = [
        Property::SessionExpiryInterval(60),
        Property::ReceiveMaximum(10),
        Property::MaximumPacketSize(2000),
        Property::TopicAliasMaximum(5),
        Property::RequestResponseInformation(1),
        Property::RequestProblemInformation(0),
        Property::UserProperty("a", "b"),
        Property::UserProperty("a", "c"),
        Property::AuthenticationMethod("SCRAM-SHA-256"),
        Property::AuthenticationData(b"\x00\x01"),
    ];
    let will_props = [
        Property::WillDelayInterval(5),
        Property::PayloadFormatIndicator(1),
        Property::MessageExpiryInterval(30),
        Property::ContentType("text/plain"),
        Property::ResponseTopic("r/t"),
        Property::CorrelationData(b"abc"),
        Property::UserProperty("w", "x"),
    ];
    let c = Connect {
        clean_start: false,
        keep_alive: 30,
        properties: Properties::List(&props),
        client_id: "device-001",
        will: Some(Will {
            properties: Properties::List(&will_props),
            topic: "devices/device-001/status",
            payload: b"offline",
            qos: QoS::ExactlyOnce,
            retain: true,
        }),
        username: Some("u"),
        password: Some(b"\x00\xffsecret"),
    };
    let b = round_trip(&Packet::Connect(c));
    let flags_at = b.len() - read_varint(&b[1..]).unwrap().0 as usize + 7;
    assert_eq!(b[flags_at], 0x80 | 0x40 | 0x20 | 0x10 | 0x04, "flags byte");
    // The decoded form is raw and still equal; its getters work.
    let Packet::Connect(d) = dec(&b).unwrap() else {
        panic!()
    };
    assert!(matches!(d.properties, Properties::Raw(_)));
    assert_eq!(d.properties.session_expiry_interval(), Some(60));
    assert_eq!(d.properties.receive_maximum(), Some(10));
    assert_eq!(d.properties.maximum_packet_size(), Some(2000));
    assert_eq!(d.properties.topic_alias_maximum(), Some(5));
    assert_eq!(d.properties.authentication_method(), Some("SCRAM-SHA-256"));
    assert_eq!(
        d.properties.user_properties().collect::<Vec<_>>(),
        [("a", "b"), ("a", "c")]
    );
    let w = d.will.unwrap();
    assert_eq!(w.properties.will_delay_interval(), Some(5));
    assert_eq!(w.properties.message_expiry_interval(), Some(30));
}

#[test]
fn connect_password_without_username_is_allowed_in_5() {
    let b = pkt(0x10, &connect_body(0x42, &[], &[s("c"), s("pw")].concat()));
    let Packet::Connect(c) = dec(&b).unwrap() else {
        panic!()
    };
    assert_eq!(c.username, None);
    assert_eq!(c.password, Some(&b"pw"[..]));
    round_trip(&Packet::Connect(c));
}

#[test]
fn connect_rejections() {
    let ok = connect_body(0x02, &[], &s("c"));
    assert!(dec(&pkt(0x10, &ok)).is_ok());
    let flags_at = 2 + 4 + 1; // in the body
    let with_flags = |f: u8| {
        let mut b = ok.clone();
        b[flags_at] = f;
        pkt(0x10, &b)
    };
    assert_eq!(
        dec(&with_flags(0x03)),
        Err(Error::InvalidConnectFlags),
        "reserved"
    );
    assert_eq!(
        dec(&with_flags(0x08)),
        Err(Error::InvalidConnectFlags),
        "will qos, no will"
    );
    assert_eq!(
        dec(&with_flags(0x20)),
        Err(Error::InvalidConnectFlags),
        "will retain, no will"
    );
    let will = [block(&[]), s("t"), s("p")].concat();
    assert!(
        dec(&pkt(
            0x10,
            &connect_body(0x14, &[], &[s("c"), will.clone()].concat())
        ))
        .is_ok()
    );
    assert_eq!(
        dec(&pkt(
            0x10,
            &connect_body(0x1c, &[], &[s("c"), will].concat())
        )),
        Err(Error::InvalidQos),
        "will qos 3"
    );
    // Will Delay Interval is a Will property, not a CONNECT property.
    assert_eq!(
        dec(&pkt(
            0x10,
            &connect_body(0x02, &[0x18, 0, 0, 0, 1], &s("c"))
        )),
        Err(Error::PropertyNotAllowed(0x18))
    );
    // Session Expiry Interval is not a Will property.
    let will = [block(&[0x11, 0, 0, 0, 1]), s("t"), s("p")].concat();
    assert_eq!(
        dec(&pkt(
            0x10,
            &connect_body(0x06, &[], &[s("c"), will].concat())
        )),
        Err(Error::PropertyNotAllowed(0x11))
    );
    // Will topic with a wildcard.
    let will = [block(&[]), s("t/#"), s("p")].concat();
    assert_eq!(
        dec(&pkt(
            0x10,
            &connect_body(0x06, &[], &[s("c"), will].concat())
        )),
        Err(Error::InvalidTopicName)
    );
    // Levels: 3.1.1 is refused by this decoder; 3.1 too.
    let mut v4 = ok.clone();
    v4[6] = 4;
    assert_eq!(
        dec(&pkt(0x10, &v4)),
        Err(Error::UnsupportedProtocolLevel(4))
    );
    assert_eq!(connect_protocol_level(&pkt(0x10, &v4)), Ok(4));
    let v31 = [&s("MQIsdp")[..], &[3, 2, 0, 60], &s("c")].concat();
    assert_eq!(
        dec(&pkt(0x10, &v31)),
        Err(Error::UnsupportedProtocolLevel(3))
    );
    assert_eq!(connect_protocol_level(&pkt(0x10, &v31)), Ok(3));
    let bad_name = [&s("MQTX")[..], &[5, 2, 0, 60, 0], &s("c")].concat();
    assert_eq!(dec(&pkt(0x10, &bad_name)), Err(Error::InvalidProtocolName));
    assert_eq!(
        connect_protocol_level(&pkt(0x10, &bad_name)),
        Err(Error::InvalidProtocolName)
    );
    // Trailing bytes.
    assert_eq!(
        dec(&pkt(0x10, &[ok.clone(), vec![0]].concat())),
        Err(Error::MalformedPacket)
    );
    // Client id bound.
    let lim = Limits {
        base: crate::Limits {
            max_client_id_len: 0,
            ..crate::Limits::PROTOCOL_MAX
        },
        ..L
    };
    assert_eq!(
        decode(&pkt(0x10, &ok), &lim).map(|_| ()),
        Err(Error::ClientIdTooLong)
    );
    // Fixed-header flags.
    assert_eq!(dec(&pkt(0x11, &ok)), Err(Error::InvalidFixedHeaderFlags));
}

#[test]
fn connect_protocol_level_streams() {
    let b = pkt(0x10, &connect_body(0x02, &[], &s("abc")));
    for n in 0..9 {
        assert!(
            matches!(connect_protocol_level(&b[..n]), Err(Error::Incomplete(k)) if k > n),
            "{n}"
        );
    }
    for n in 9..=b.len() {
        assert_eq!(connect_protocol_level(&b[..n]), Ok(5));
    }
    assert_eq!(
        connect_protocol_level(&[0x30, 0]),
        Err(Error::InvalidPacketType(3))
    );
    // A body too short for the name.
    assert_eq!(
        connect_protocol_level(&[0x10, 1, 0]),
        Err(Error::MalformedPacket)
    );
}

#[test]
fn connack_vectors() {
    // Session present, success, Maximum QoS 1, Retain Available 0,
    // Assigned Client Identifier, Server Keep Alive 30, Topic Alias Maximum.
    let props = [
        Property::MaximumQos(1),
        Property::RetainAvailable(0),
        Property::AssignedClientIdentifier("auto-1"),
        Property::ServerKeepAlive(30),
        Property::TopicAliasMaximum(10),
        Property::ReceiveMaximum(20),
        Property::MaximumPacketSize(65536),
        Property::WildcardSubscriptionAvailable(1),
        Property::SubscriptionIdentifierAvailable(1),
        Property::SharedSubscriptionAvailable(0),
        Property::SessionExpiryInterval(0),
        Property::ResponseInformation("resp/"),
        Property::ServerReference("other:8883"),
        Property::ReasonString("ok"),
        Property::UserProperty("k", "v"),
    ];
    let a = ConnAck {
        session_present: true,
        reason: ReasonCode::Success,
        properties: Properties::List(&props),
    };
    round_trip(&Packet::ConnAck(a));
    // The 3-byte minimum.
    let b = [0x20, 3, 0, 0x84, 0];
    assert_eq!(
        dec(&b),
        Ok(Packet::ConnAck(ConnAck {
            session_present: false,
            reason: ReasonCode::UnsupportedProtocolVersion,
            properties: Properties::EMPTY
        }))
    );
    assert_eq!(
        dec(&[0x20, 3, 1, 0x80, 0]),
        Err(Error::SessionPresentWithError)
    );
    assert_eq!(dec(&[0x20, 3, 2, 0, 0]), Err(Error::MalformedPacket));
    assert_eq!(
        dec(&[0x20, 2, 0, 0]),
        Err(Error::MalformedVarint),
        "no Property Length"
    );
    let bad = ConnAck {
        session_present: true,
        reason: ReasonCode::NotAuthorized,
        properties: Properties::EMPTY,
    };
    let mut out = [0u8; 8];
    assert_eq!(
        encode(&Packet::ConnAck(bad), &mut out),
        Err(EncodeError::Invalid(Error::SessionPresentWithError))
    );
}

#[test]
fn publish_vectors() {
    // QoS 0, "a/b", no properties, payload "hi".
    let b = pkt(0x30, &[&s("a/b")[..], &[0], b"hi"].concat());
    let Packet::Publish(p) = dec(&b).unwrap() else {
        panic!()
    };
    assert_eq!((p.topic, p.packet_id, p.payload), ("a/b", None, &b"hi"[..]));
    // QoS 1 with every PUBLISH property; Subscription Identifier twice.
    let props = [
        Property::PayloadFormatIndicator(1),
        Property::MessageExpiryInterval(30),
        Property::TopicAlias(3),
        Property::ResponseTopic("r/t"),
        Property::CorrelationData(b"abc"),
        Property::UserProperty("k", "v"),
        Property::UserProperty("k", "v2"),
        Property::SubscriptionIdentifier(7),
        Property::SubscriptionIdentifier(MAX_VARINT),
        Property::ContentType("text/plain"),
    ];
    let p = Publish {
        dup: true,
        qos: QoS::AtLeastOnce,
        retain: true,
        topic: "a/b",
        packet_id: Some(42),
        properties: Properties::List(&props),
        payload: b"payload",
    };
    let b = round_trip(&Packet::Publish(p));
    assert_eq!(b[0], 0x3b);
    let Packet::Publish(d) = dec(&b).unwrap() else {
        panic!()
    };
    assert_eq!(
        d.properties.subscription_identifiers().collect::<Vec<_>>(),
        [7, MAX_VARINT]
    );
    assert_eq!(d.properties.topic_alias(), Some(3));
    // Empty topic with a Topic Alias: fine; without: refused.
    let b = pkt(0x30, &[&s("")[..], &block(&[0x23, 0, 3])].concat());
    assert!(dec(&b).is_ok());
    let b = pkt(0x30, &[&s("")[..], &block(&[])].concat());
    assert_eq!(dec(&b), Err(Error::InvalidTopicName));
    // Wildcards, QoS 3, DUP on QoS 0, packet id 0.
    assert_eq!(
        dec(&pkt(0x30, &[&s("a/+")[..], &[0]].concat())),
        Err(Error::InvalidTopicName)
    );
    assert_eq!(
        dec(&pkt(0x36, &[&s("a")[..], &[0, 1, 0]].concat())),
        Err(Error::InvalidQos)
    );
    assert_eq!(
        dec(&pkt(0x38, &[&s("a")[..], &[0]].concat())),
        Err(Error::InvalidFixedHeaderFlags)
    );
    assert_eq!(
        dec(&pkt(0x32, &[&s("a")[..], &[0, 0, 0]].concat())),
        Err(Error::ZeroPacketId)
    );
    // Properties a PUBLISH may not carry.
    for (id, v) in [
        (0x11u8, &[0, 0, 0, 1][..]),
        (0x18, &[0, 0, 0, 1]),
        (0x21, &[0, 1]),
        (0x1f, &[0, 0]),
    ] {
        let b = pkt(
            0x30,
            &[&s("a")[..], &block(&[&[id][..], v].concat())].concat(),
        );
        assert_eq!(dec(&b), Err(Error::PropertyNotAllowed(id)), "{id:#x}");
    }
    // Missing Property Length.
    assert_eq!(dec(&pkt(0x30, &s("a"))), Err(Error::MalformedVarint));
}

#[test]
fn ack_forms() {
    for (first, mk) in [
        (
            0x40u8,
            Packet::PubAck as fn(Ack<'static>) -> Packet<'static>,
        ),
        (0x50, Packet::PubRec),
        (0x62, Packet::PubRel),
        (0x70, Packet::PubComp),
    ] {
        let a = |reason, properties| Ack {
            packet_id: 9,
            reason,
            properties,
        };
        // Remaining Length 2: success, no properties.
        assert_eq!(
            dec(&[first, 2, 0, 9]),
            Ok(mk(a(ReasonCode::Success, Properties::EMPTY)))
        );
        // 3 and 4: the same packet, longer.
        assert_eq!(
            dec(&[first, 3, 0, 9, 0]),
            Ok(mk(a(ReasonCode::Success, Properties::EMPTY)))
        );
        assert_eq!(
            dec(&[first, 4, 0, 9, 0, 0]),
            Ok(mk(a(ReasonCode::Success, Properties::EMPTY)))
        );
        // The encoder writes the shortest.
        assert_eq!(
            enc(&mk(a(ReasonCode::Success, Properties::EMPTY))),
            [first, 2, 0, 9]
        );
        let props: &'static [Property<'static>] = &[
            Property::ReasonString("why"),
            Property::UserProperty("a", "b"),
        ];
        let b = round_trip(&mk(a(ReasonCode::Success, Properties::List(props))));
        assert_eq!(b[4], 0, "reason byte kept when properties follow");
        // Trailing bytes, packet id 0, wrong flags.
        assert_eq!(dec(&[first, 5, 0, 9, 0, 0, 0]), Err(Error::MalformedPacket));
        assert_eq!(dec(&[first, 2, 0, 0]), Err(Error::ZeroPacketId));
        assert_eq!(
            dec(&[first ^ 0x02, 2, 0, 9]),
            Err(Error::InvalidFixedHeaderFlags)
        );
        assert_eq!(dec(&[first, 1, 0]), Err(Error::MalformedPacket));
        // A property no acknowledgement may carry.
        assert_eq!(
            dec(&[first, 9, 0, 9, 0, 5, 0x02, 0, 0, 0, 1]),
            Err(Error::PropertyNotAllowed(0x02))
        );
    }
    round_trip(&Packet::PubAck(Ack {
        packet_id: 1,
        reason: ReasonCode::NoMatchingSubscribers,
        properties: Properties::EMPTY,
    }));
    round_trip(&Packet::PubComp(Ack {
        packet_id: 1,
        reason: ReasonCode::PacketIdentifierNotFound,
        properties: Properties::EMPTY,
    }));
}

#[test]
fn subscription_options_every_byte() {
    for b in 0..=255u8 {
        let got = SubscriptionOptions::from_byte(b);
        let want = if b & 0xc0 != 0 {
            Err(Error::InvalidSubscriptionOptions)
        } else if b & 3 == 3 {
            Err(Error::InvalidQos)
        } else if (b >> 4) & 3 == 3 {
            Err(Error::InvalidRetainHandling)
        } else {
            Ok(())
        };
        assert_eq!(got.map(|_| ()), want, "{b:#04x}");
        if let Ok(o) = got {
            assert_eq!(o.to_byte(), b);
            assert_eq!(o.no_local, b & 4 != 0);
            assert_eq!(o.retain_as_published, b & 8 != 0);
        }
    }
}

#[test]
fn subscribe_vectors() {
    let opts = SubscriptionOptions {
        qos: QoS::AtLeastOnce,
        no_local: true,
        retain_as_published: true,
        retain_handling: RetainHandling::DoNotSend,
    };
    let topics = [
        ("a/+", opts),
        ("#", SubscriptionOptions::qos(QoS::ExactlyOnce)),
        (
            "$share/group/a/#",
            SubscriptionOptions::qos(QoS::AtMostOnce),
        ),
    ];
    let props = [
        Property::SubscriptionIdentifier(7),
        Property::UserProperty("x", "y"),
    ];
    let sb = Subscribe {
        packet_id: 5,
        properties: Properties::List(&props),
        topics: SubscribeTopics::List(&topics),
    };
    let b = round_trip(&Packet::Subscribe(sb));
    assert_eq!(b[0], 0x82);
    let Packet::Subscribe(d) = dec(&b).unwrap() else {
        panic!()
    };
    assert_eq!(d.topics.iter().collect::<Vec<_>>(), topics);
    assert_eq!(d.topics.len(), 3);
    let one = |f: &str, o: u8| pkt(0x82, &[&[0, 1, 0][..], &s(f), &[o]].concat());
    assert!(dec(&one("a", 0x2e)).is_ok());
    assert_eq!(dec(&one("a", 0x40)), Err(Error::InvalidSubscriptionOptions));
    assert_eq!(dec(&one("a", 0x03)), Err(Error::InvalidQos));
    assert_eq!(dec(&one("a", 0x30)), Err(Error::InvalidRetainHandling));
    assert_eq!(dec(&one("a/#/b", 0)), Err(Error::InvalidTopicFilter));
    assert_eq!(dec(&one("$share/g/a", 0x04)), Err(Error::SharedNoLocal));
    assert!(dec(&one("$share/g/a", 0x08)).is_ok());
    for bad in [
        "$share/g",
        "$share//a",
        "$share/g/",
        "$share/+/a",
        "$share/#/a",
    ] {
        assert_eq!(dec(&one(bad, 0)), Err(Error::InvalidTopicFilter), "{bad}");
    }
    assert!(dec(&one("$share", 0)).is_ok(), "not a shared subscription");
    assert!(
        dec(&one("$sharex/g/a", 0)).is_ok(),
        "not a shared subscription"
    );
    // No filter at all; Subscription Identifier twice (only PUBLISH may).
    assert_eq!(dec(&pkt(0x82, &[0, 1, 0])), Err(Error::EmptySubscription));
    let two = pkt(
        0x82,
        &[&[0, 1][..], &block(&[0x0b, 1, 0x0b, 2]), &s("a"), &[0]].concat(),
    );
    assert_eq!(dec(&two), Err(Error::DuplicateProperty(0x0b)));
    // Flags, truncation, topic count.
    assert_eq!(
        dec(&pkt(0x80, &[0, 1, 0, 0, 1, b'a', 0])),
        Err(Error::InvalidFixedHeaderFlags)
    );
    assert_eq!(
        dec(&pkt(0x82, &[0, 1, 0, 0, 1, b'a'])),
        Err(Error::MalformedPacket)
    );
    let lim = Limits {
        base: crate::Limits {
            max_topics_per_packet: 2,
            ..crate::Limits::PROTOCOL_MAX
        },
        ..L
    };
    assert_eq!(decode(&b, &lim).map(|_| ()), Err(Error::TooManyTopics));
    // The encoder refuses what the decoder refuses.
    let bad = [("$share/g/a", opts)];
    let sb = Subscribe {
        packet_id: 5,
        properties: Properties::EMPTY,
        topics: SubscribeTopics::List(&bad),
    };
    assert_eq!(
        encoded_len(&Packet::Subscribe(sb)).map(|_| ()),
        Ok(()),
        "length is computed"
    );
    assert_eq!(
        encode(&Packet::Subscribe(sb), &mut [0u8; 64]),
        Err(EncodeError::Invalid(Error::SharedNoLocal))
    );
}

#[test]
fn split_shared_rules() {
    assert_eq!(split_shared("$share/g/a/b"), Some(("g", "a/b")));
    assert_eq!(split_shared("$share/g//"), Some(("g", "/")));
    assert_eq!(split_shared("$share/g/#"), Some(("g", "#")));
    for none in [
        "a/b",
        "$share",
        "$share/",
        "$share/g",
        "$share//a",
        "$share/g/",
        "$share/g+/a",
    ] {
        assert_eq!(split_shared(none), None, "{none}");
    }
}

#[test]
fn suback_unsuback_vectors() {
    let codes = [
        0x00, 0x01, 0x02, 0x80, 0x87, 0x8f, 0x91, 0x97, 0x9e, 0xa1, 0xa2, 0x83,
    ];
    let props = [Property::ReasonString("partial")];
    let a = SubAck {
        packet_id: 3,
        properties: Properties::List(&props),
        reason_codes: &codes,
    };
    round_trip(&Packet::SubAck(a));
    let ucodes = [0x00, 0x11, 0x80, 0x83, 0x87, 0x8f, 0x91];
    let u = UnsubAck {
        packet_id: 3,
        properties: Properties::EMPTY,
        reason_codes: &ucodes,
    };
    round_trip(&Packet::UnsubAck(u));
    assert_eq!(
        dec(&[0x90, 3, 0, 3, 0]),
        Err(Error::MalformedPacket),
        "no codes"
    );
    assert_eq!(
        dec(&[0xb0, 3, 0, 3, 0]),
        Err(Error::MalformedPacket),
        "no codes"
    );
    assert_eq!(
        dec(&[0xb0, 4, 0, 3, 0, 0x01]),
        Err(Error::InvalidReasonCode(1))
    );
    assert_eq!(
        dec(&[0x90, 4, 0, 3, 0, 0x11]),
        Err(Error::InvalidReasonCode(0x11))
    );
}

#[test]
fn unsubscribe_vectors() {
    let topics = ["a/+", "$share/g/x"];
    let props = [Property::UserProperty("k", "v")];
    let u = Unsubscribe {
        packet_id: 4,
        properties: Properties::List(&props),
        topics: UnsubscribeTopics::List(&topics),
    };
    let b = round_trip(&Packet::Unsubscribe(u));
    assert_eq!(b[0], 0xa2);
    assert_eq!(dec(&pkt(0xa2, &[0, 1, 0])), Err(Error::EmptySubscription));
    assert_eq!(
        dec(&pkt(0xa2, &[&[0, 1, 0][..], &s("a+")].concat())),
        Err(Error::InvalidTopicFilter)
    );
    assert_eq!(
        dec(&pkt(
            0xa2,
            &[&[0, 1][..], &block(&[0x0b, 1]), &s("a")].concat()
        )),
        Err(Error::PropertyNotAllowed(0x0b))
    );
    assert_eq!(
        dec(&pkt(0xa0, &[&[0, 1, 0][..], &s("a")].concat())),
        Err(Error::InvalidFixedHeaderFlags)
    );
}

#[test]
fn ping_disconnect_auth() {
    assert_eq!(dec(&[0xc0, 0]), Ok(Packet::PingReq));
    assert_eq!(dec(&[0xd0, 0]), Ok(Packet::PingResp));
    assert_eq!(dec(&[0xc0, 1, 0]), Err(Error::MalformedPacket));
    assert_eq!(dec(&[0xc1, 0]), Err(Error::InvalidFixedHeaderFlags));
    // DISCONNECT: 0, 1 and 2 bytes are the same normal disconnection.
    let normal = Packet::Disconnect(Disconnect {
        reason: ReasonCode::Success,
        properties: Properties::EMPTY,
    });
    assert_eq!(dec(&[0xe0, 0]), Ok(normal));
    assert_eq!(dec(&[0xe0, 1, 0]), Ok(normal));
    assert_eq!(dec(&[0xe0, 2, 0, 0]), Ok(normal));
    assert_eq!(enc(&normal), [0xe0, 0]);
    let props = [
        Property::SessionExpiryInterval(0),
        Property::ReasonString("bye"),
        Property::ServerReference("x"),
    ];
    round_trip(&Packet::Disconnect(Disconnect {
        reason: ReasonCode::DisconnectWithWillMessage,
        properties: Properties::List(&props),
    }));
    assert_eq!(
        enc(&Packet::Disconnect(Disconnect {
            reason: ReasonCode::SessionTakenOver,
            properties: Properties::EMPTY,
        })),
        [0xe0, 1, 0x8e]
    );
    assert_eq!(dec(&[0xe0, 3, 0, 0, 0]), Err(Error::MalformedPacket));
    assert_eq!(
        dec(&[0xe0, 6, 0, 4, 0x21, 0, 1, 0]),
        Err(Error::PropertyNotAllowed(0x21))
    );
    // AUTH: 0 bytes is success; otherwise the method is required.
    let ok = Packet::Auth(Auth {
        reason: ReasonCode::Success,
        properties: Properties::EMPTY,
    });
    assert_eq!(dec(&[0xf0, 0]), Ok(ok));
    assert_eq!(enc(&ok), [0xf0, 0]);
    assert_eq!(dec(&[0xf0, 1, 0x18]), Err(Error::MalformedVarint));
    assert_eq!(
        dec(&[0xf0, 2, 0x18, 0]),
        Err(Error::MissingAuthenticationMethod)
    );
    let props = [
        Property::AuthenticationMethod("SCRAM-SHA-1"),
        Property::AuthenticationData(b"client-first"),
        Property::ReasonString("go on"),
    ];
    round_trip(&Packet::Auth(Auth {
        reason: ReasonCode::ContinueAuthentication,
        properties: Properties::List(&props),
    }));
    assert_eq!(
        encode(
            &Packet::Auth(Auth {
                reason: ReasonCode::ReAuthenticate,
                properties: Properties::EMPTY,
            }),
            &mut [0u8; 8]
        ),
        Err(EncodeError::Invalid(Error::MissingAuthenticationMethod))
    );
    assert_eq!(dec(&[0xf1, 0]), Err(Error::InvalidFixedHeaderFlags));
}

#[test]
fn packet_type_zero_and_flags() {
    assert_eq!(dec(&[0x00, 0]), Err(Error::InvalidPacketType(0)));
    for t in PacketType::ALL {
        assert_eq!(PacketType::from_u8(t as u8), Some(t));
    }
    assert_eq!(PacketType::from_u8(0), None);
    assert_eq!(PacketType::from_u8(16), None);
}

// --- Encoder guarantees -------------------------------------------------

#[test]
fn encoder_refuses_what_the_decoder_refuses() {
    let mut out = [0u8; 256];
    let p = |props: &'static [Property<'static>]| {
        Packet::Publish(Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "a",
            packet_id: None,
            properties: Properties::List(props),
            payload: b"",
        })
    };
    for (props, err) in [
        (
            &[Property::SessionExpiryInterval(1)][..],
            Error::PropertyNotAllowed(0x11),
        ),
        (
            &[Property::TopicAlias(1), Property::TopicAlias(2)],
            Error::DuplicateProperty(0x23),
        ),
        (
            &[Property::TopicAlias(0)],
            Error::InvalidPropertyValue(0x23),
        ),
        (
            &[Property::PayloadFormatIndicator(2)],
            Error::InvalidPropertyValue(0x01),
        ),
        (&[Property::ContentType("a\0b")], Error::InvalidUtf8),
        (
            &[Property::ResponseTopic("a/#")],
            Error::InvalidPropertyValue(0x08),
        ),
        (
            &[Property::SubscriptionIdentifier(0)],
            Error::InvalidPropertyValue(0x0b),
        ),
    ] {
        assert_eq!(
            encode(&p(props), &mut out),
            Err(EncodeError::Invalid(err)),
            "{props:?}"
        );
    }
    assert_eq!(
        encode(
            &p(&[Property::SubscriptionIdentifier(MAX_VARINT + 1)]),
            &mut out
        ),
        Err(EncodeError::TooLarge)
    );
    // Raw bytes that are not a valid block for the target packet.
    let raw = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "a",
        packet_id: None,
        properties: Properties::Raw(&[0x18, 0, 0, 0, 1]),
        payload: b"",
    });
    assert_eq!(
        encode(&raw, &mut out),
        Err(EncodeError::Invalid(Error::PropertyNotAllowed(0x18)))
    );
    // Topic and packet id rules.
    let base = Publish {
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        topic: "a",
        packet_id: Some(1),
        properties: Properties::EMPTY,
        payload: b"",
    };
    for (pb, err) in [
        (
            Publish { topic: "", ..base },
            EncodeError::Invalid(Error::InvalidTopicName),
        ),
        (
            Publish { topic: "+", ..base },
            EncodeError::Invalid(Error::InvalidTopicName),
        ),
        (
            Publish {
                packet_id: None,
                ..base
            },
            EncodeError::InconsistentPacketId,
        ),
        (
            Publish {
                packet_id: Some(0),
                ..base
            },
            EncodeError::Invalid(Error::ZeroPacketId),
        ),
        (
            Publish {
                dup: true,
                qos: QoS::AtMostOnce,
                packet_id: None,
                ..base
            },
            EncodeError::Invalid(Error::InvalidFixedHeaderFlags),
        ),
    ] {
        assert_eq!(encode(&Packet::Publish(pb), &mut out), Err(err), "{pb:?}");
    }
    assert_eq!(
        encode(&Packet::Publish(base), &mut [0u8; 4]),
        Err(EncodeError::BufferTooSmall)
    );
    // A reason code the packet may not carry.
    assert_eq!(
        encode(
            &Packet::PubRel(Ack {
                packet_id: 1,
                reason: ReasonCode::NoMatchingSubscribers,
                properties: Properties::EMPTY
            }),
            &mut out
        ),
        Err(EncodeError::Invalid(Error::InvalidReasonCode(0x10)))
    );
    assert_eq!(
        encode(
            &Packet::SubAck(SubAck {
                packet_id: 1,
                properties: Properties::EMPTY,
                reason_codes: &[0x11]
            }),
            &mut out
        ),
        Err(EncodeError::Invalid(Error::InvalidReasonCode(0x11)))
    );
}

#[test]
fn forward_properties_drop_and_append() {
    // A received PUBLISH block forwarded to a subscriber: the Topic Alias and
    // the expiry are dropped, the subscriber's identifier and the remaining
    // expiry appended (ADR-273).
    let received = [
        Property::TopicAlias(4),
        Property::MessageExpiryInterval(60),
        Property::UserProperty("k", "v"),
        Property::ContentType("c"),
    ];
    let src = Packet::Publish(Publish {
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        topic: "a",
        packet_id: None,
        properties: Properties::List(&received),
        payload: b"x",
    });
    let b = enc(&src);
    let Packet::Publish(d) = dec(&b).unwrap() else {
        panic!()
    };
    let Properties::Raw(raw) = d.properties else {
        panic!()
    };
    let extra = [
        Property::MessageExpiryInterval(42),
        Property::SubscriptionIdentifier(9),
    ];
    let fwd = Publish {
        properties: Properties::Forward {
            raw,
            drop: PropertyMask::EMPTY
                .with(PropertyId::TopicAlias)
                .with(PropertyId::MessageExpiryInterval),
            extra: &extra,
        },
        ..d
    };
    let out = enc(&Packet::Publish(fwd));
    let Packet::Publish(got) = dec(&out).unwrap() else {
        panic!()
    };
    assert_eq!(
        got.properties.iter().collect::<Vec<_>>(),
        [
            Property::UserProperty("k", "v"),
            Property::ContentType("c"),
            Property::MessageExpiryInterval(42),
            Property::SubscriptionIdentifier(9),
        ]
    );
    assert_eq!(got.properties, fwd.properties);
    // Forwarding a Will's block into a PUBLISH without dropping the Will
    // Delay Interval is refused, not emitted.
    let will = [0x18, 0, 0, 0, 5];
    let bad = Publish {
        properties: Properties::Forward {
            raw: &will,
            drop: PropertyMask::EMPTY,
            extra: &[],
        },
        ..d
    };
    assert_eq!(
        encode(&Packet::Publish(bad), &mut [0u8; 64]),
        Err(EncodeError::Invalid(Error::PropertyNotAllowed(0x18)))
    );
    let ok = Publish {
        properties: Properties::Forward {
            raw: &will,
            drop: PropertyMask::EMPTY.with(PropertyId::WillDelayInterval),
            extra: &[],
        },
        ..d
    };
    assert_eq!(enc(&Packet::Publish(ok))[4..], [b'a', 0, b'x']);
}

#[test]
fn every_truncation_is_incomplete_or_refused() {
    // Every prefix of every vector asks for more; every body cut short
    // (with the Remaining Length fixed up) is refused, never a panic.
    let props = [
        Property::UserProperty("k", "v"),
        Property::SessionExpiryInterval(9),
    ];
    let will_props = [Property::WillDelayInterval(1)];
    let topics = [("a/#", SubscriptionOptions::qos(QoS::AtLeastOnce))];
    let packets = [
        Packet::Connect(Connect {
            clean_start: true,
            keep_alive: 5,
            properties: Properties::List(&props),
            client_id: "cid",
            will: Some(Will {
                properties: Properties::List(&will_props),
                topic: "w",
                payload: b"p",
                qos: QoS::AtLeastOnce,
                retain: false,
            }),
            username: Some("u"),
            password: Some(b"p"),
        }),
        Packet::Subscribe(Subscribe {
            packet_id: 1,
            properties: Properties::EMPTY,
            topics: SubscribeTopics::List(&topics),
        }),
        Packet::Disconnect(Disconnect {
            reason: ReasonCode::ServerShuttingDown,
            properties: Properties::List(&props[..1]),
        }),
    ];
    for p in packets {
        let b = round_trip(&p);
        for n in 0..b.len() {
            assert!(matches!(decode(&b[..n], &L), Err(Error::Incomplete(k)) if k > n));
        }
        let body_start = b.len() - (b[1] as usize);
        for cut in body_start..b.len() {
            let body = &b[body_start..cut];
            let short = pkt(b[0], body);
            // A DISCONNECT cut to 0 or 1 byte is still a valid packet.
            if let Ok(q) = dec(&short) {
                assert!(matches!(q, Packet::Disconnect(_)), "{short:02x?}");
            }
        }
    }
}

// --- Round-trip properties ------------------------------------------------

const STRS: [&str; 6] = ["", "a", "key", "välue", "日本", "with space"];
const TOPICS: [&str; 6] = ["a", "a/b", "sensors/1/temp", "$SYS/x", "/", "ü/ß"];
const FILTERS: [&str; 8] = [
    "a",
    "a/+",
    "#",
    "+/x/#",
    "$share/g/a/#",
    "$share/grp/+",
    "/",
    "$share",
];
const BINS: [&[u8]; 3] = [b"", b"\x00\xff", b"abc"];

fn any_property() -> impl Strategy<Value = Property<'static>> {
    let st = || prop::sample::select(&STRS[..]);
    let tp = || prop::sample::select(&TOPICS[..]);
    let bin = || prop::sample::select(&BINS[..]);
    let flag = || 0u8..=2;
    prop_oneof![
        flag().prop_map(Property::PayloadFormatIndicator),
        any::<u32>().prop_map(Property::MessageExpiryInterval),
        st().prop_map(Property::ContentType),
        tp().prop_map(Property::ResponseTopic),
        bin().prop_map(Property::CorrelationData),
        (0u32..=MAX_VARINT + 1).prop_map(Property::SubscriptionIdentifier),
        any::<u32>().prop_map(Property::SessionExpiryInterval),
        st().prop_map(Property::AssignedClientIdentifier),
        any::<u16>().prop_map(Property::ServerKeepAlive),
        st().prop_map(Property::AuthenticationMethod),
        bin().prop_map(Property::AuthenticationData),
        flag().prop_map(Property::RequestProblemInformation),
        any::<u32>().prop_map(Property::WillDelayInterval),
        flag().prop_map(Property::RequestResponseInformation),
        st().prop_map(Property::ResponseInformation),
        st().prop_map(Property::ServerReference),
        st().prop_map(Property::ReasonString),
        any::<u16>().prop_map(Property::ReceiveMaximum),
        any::<u16>().prop_map(Property::TopicAliasMaximum),
        any::<u16>().prop_map(Property::TopicAlias),
        flag().prop_map(Property::MaximumQos),
        flag().prop_map(Property::RetainAvailable),
        (st(), st()).prop_map(|(k, v)| Property::UserProperty(k, v)),
        any::<u32>().prop_map(Property::MaximumPacketSize),
        flag().prop_map(Property::WildcardSubscriptionAvailable),
        flag().prop_map(Property::SubscriptionIdentifierAvailable),
        flag().prop_map(Property::SharedSubscriptionAvailable),
    ]
}

fn any_options() -> impl Strategy<Value = SubscriptionOptions> {
    (0u8..=2, any::<bool>(), any::<bool>(), 0u8..=2).prop_map(|(q, nl, rap, rh)| {
        SubscriptionOptions::from_byte(q | (u8::from(nl) << 2) | (u8::from(rap) << 3) | (rh << 4))
            .unwrap()
    })
}

/// An owned description of a packet; `build` borrows it.
#[derive(Debug, Clone)]
struct Model {
    kind: u8,
    flags: u8,
    id: u16,
    reason: u8,
    props: Vec<Property<'static>>,
    will_props: Vec<Property<'static>>,
    topic: &'static str,
    subs: Vec<(&'static str, SubscriptionOptions)>,
    codes: Vec<u8>,
    payload: Vec<u8>,
}

fn any_model() -> impl Strategy<Value = Model> {
    (
        (
            1u8..=15,
            any::<u8>(),
            any::<u16>(),
            prop::sample::select(SPEC_REASONS.map(|r| r.0).to_vec()),
        ),
        prop::collection::vec(any_property(), 0..6),
        prop::collection::vec(any_property(), 0..4),
        prop::sample::select(
            &[
                TOPICS[0], TOPICS[1], TOPICS[2], TOPICS[3], TOPICS[4], TOPICS[5], "",
            ][..],
        ),
        prop::collection::vec((prop::sample::select(&FILTERS[..]), any_options()), 0..4),
        prop::collection::vec(
            prop::sample::select(SPEC_REASONS.map(|r| r.0).to_vec()),
            0..4,
        ),
        prop::collection::vec(any::<u8>(), 0..16),
    )
        .prop_map(
            |((kind, flags, id, reason), props, will_props, topic, subs, codes, payload)| Model {
                kind,
                flags,
                id,
                reason,
                props,
                will_props,
                topic,
                subs,
                codes,
                payload,
            },
        )
}

fn build(m: &Model) -> Packet<'_> {
    let props = Properties::List(&m.props);
    let reason = ReasonCode::from_u8(m.reason).unwrap();
    let qos = QoS::from_bits(m.flags & 3).unwrap_or(QoS::AtLeastOnce);
    let ack = Ack {
        packet_id: m.id,
        reason,
        properties: props,
    };
    match m.kind {
        1 => Packet::Connect(Connect {
            clean_start: m.flags & 0x80 != 0,
            keep_alive: m.id,
            properties: props,
            client_id: STRS[usize::from(m.flags) % STRS.len()],
            will: (m.flags & 0x40 != 0).then_some(Will {
                properties: Properties::List(&m.will_props),
                topic: m.topic,
                payload: &m.payload,
                qos,
                retain: m.flags & 0x20 != 0,
            }),
            username: (m.flags & 0x10 != 0).then_some("user"),
            password: (m.flags & 0x08 != 0).then_some(&m.payload[..]),
        }),
        2 => Packet::ConnAck(ConnAck {
            session_present: m.flags & 0x80 != 0,
            reason,
            properties: props,
        }),
        3 => Packet::Publish(Publish {
            dup: m.flags & 0x08 != 0,
            qos,
            retain: m.flags & 0x10 != 0,
            topic: m.topic,
            packet_id: (qos != QoS::AtMostOnce).then_some(m.id),
            properties: props,
            payload: &m.payload,
        }),
        4 => Packet::PubAck(ack),
        5 => Packet::PubRec(ack),
        6 => Packet::PubRel(ack),
        7 => Packet::PubComp(ack),
        8 => Packet::Subscribe(Subscribe {
            packet_id: m.id,
            properties: props,
            topics: SubscribeTopics::List(&m.subs),
        }),
        9 => Packet::SubAck(SubAck {
            packet_id: m.id,
            properties: props,
            reason_codes: &m.codes,
        }),
        10 => Packet::Unsubscribe(Unsubscribe {
            packet_id: m.id,
            properties: props,
            topics: UnsubscribeTopics::List(&[]),
        }),
        11 => Packet::UnsubAck(UnsubAck {
            packet_id: m.id,
            properties: props,
            reason_codes: &m.codes,
        }),
        12 => Packet::PingReq,
        13 => Packet::PingResp,
        14 => Packet::Disconnect(Disconnect {
            reason,
            properties: props,
        }),
        _ => Packet::Auth(Auth {
            reason,
            properties: props,
        }),
    }
}

/// The context of the packet's main property block.
fn context(kind: u8) -> Option<PropertyContext> {
    Some(match kind {
        1 => C::Connect,
        2 => C::ConnAck,
        3 => C::Publish,
        4 => C::PubAck,
        5 => C::PubRec,
        6 => C::PubRel,
        7 => C::PubComp,
        8 => C::Subscribe,
        9 => C::SubAck,
        10 => C::Unsubscribe,
        11 => C::UnsubAck,
        14 => C::Disconnect,
        15 => C::Auth,
        _ => return None,
    })
}

/// Keeps the properties `ctx` allows, once each where they may not repeat,
/// with in-range values: what a careful sender builds.
fn sanitize(props: &mut Vec<Property<'static>>, ctx: PropertyContext) {
    let mut seen = PropertyMask::EMPTY;
    props.retain(|p| {
        let id = p.id();
        let keep = id.allowed_in(ctx) && (!seen.contains(id) || id.may_repeat(ctx)) && value_ok(p);
        if keep {
            seen = seen.with(id);
        }
        keep
    });
    if seen.contains(PropertyId::AuthenticationData)
        && !seen.contains(PropertyId::AuthenticationMethod)
    {
        props.push(Property::AuthenticationMethod("m"));
    }
}

/// The value ranges of §3.x (the pools hold only valid strings).
fn value_ok(p: &Property<'_>) -> bool {
    match *p {
        Property::PayloadFormatIndicator(v)
        | Property::RequestProblemInformation(v)
        | Property::RequestResponseInformation(v)
        | Property::MaximumQos(v)
        | Property::RetainAvailable(v)
        | Property::WildcardSubscriptionAvailable(v)
        | Property::SubscriptionIdentifierAvailable(v)
        | Property::SharedSubscriptionAvailable(v) => v <= 1,
        Property::ReceiveMaximum(v) | Property::TopicAlias(v) => v != 0,
        Property::MaximumPacketSize(v) => v != 0,
        Property::SubscriptionIdentifier(v) => (1..=MAX_VARINT).contains(&v),
        Property::ResponseTopic(t) => crate::is_valid_topic_name(t),
        _ => true,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever the encoder accepts decodes to an equal packet, in exactly
    /// encoded_len bytes; whatever it refuses is not silently written.
    #[test]
    fn encode_then_decode(m in any_model()) {
        let p = build(&m);
        if let Ok(len) = encoded_len(&p) {
            let mut out = vec![0u8; len];
            match encode(&p, &mut out) {
                Ok(n) => {
                    prop_assert_eq!(n, len);
                    let (q, used) = decode(&out, &L).map_err(|e| TestCaseError::fail(format!("{e:?} on {out:02x?}")))?;
                    prop_assert_eq!(used, n);
                    prop_assert_eq!(q, p);
                }
                Err(EncodeError::Invalid(_) | EncodeError::TooLarge | EncodeError::InconsistentPacketId) => {}
                Err(e) => prop_assert!(false, "{e:?}"),
            }
        }
    }

    /// Careful senders: properties allowed by the packet, in range, with
    /// valid reason codes and ids: always encodable, always round-trips.
    #[test]
    fn sanitized_packets_round_trip(mut m in any_model()) {
        if let Some(ctx) = context(m.kind) {
            sanitize(&mut m.props, ctx);
        }
        sanitize(&mut m.will_props, C::Will);
        m.id = m.id.max(1);
        let table = match m.kind {
            2 => Some(R::ConnAck), 4 => Some(R::PubAck), 5 => Some(R::PubRec), 6 => Some(R::PubRel),
            7 => Some(R::PubComp), 14 => Some(R::Disconnect), 15 => Some(R::Auth), _ => None,
        };
        if let Some(t) = table
            && !ReasonCode::from_u8(m.reason).unwrap().allowed_in(t)
        {
            m.reason = 0;
        }
        if m.kind == 2 && m.reason != 0 { m.flags &= 0x7f; }
        if m.kind == 3 {
            if m.topic.is_empty() && !m.props.iter().any(|p| p.id() == PropertyId::TopicAlias) {
                m.topic = "t";
            }
            if m.flags & 3 == 0 { m.flags &= !0x08; }
        }
        if m.kind == 1 && m.topic.is_empty() { m.topic = "w"; }
        if m.kind == 8 {
            m.subs.retain(|(f, o)| !(f.starts_with("$share/") && o.no_local));
            if m.subs.is_empty() { m.subs.push(("x", SubscriptionOptions::qos(QoS::AtMostOnce))); }
        }
        if m.kind == 9 || m.kind == 11 {
            let t = if m.kind == 9 { R::SubAck } else { R::UnsubAck };
            m.codes.retain(|&c| ReasonCode::for_packet(c, t).is_some());
            if m.codes.is_empty() { m.codes.push(0); }
        }
        if m.kind == 10 { m.kind = 12; } // Unsubscribe with an empty list: covered in the vectors.
        if m.kind == 15 && !(m.reason == 0 && m.props.is_empty())
            && !m.props.iter().any(|p| p.id() == PropertyId::AuthenticationMethod) {
            m.props.push(Property::AuthenticationMethod("m"));
        }
        let p = build(&m);
        let b = {
            let mut out = vec![0u8; encoded_len(&p).unwrap()];
            let n = encode(&p, &mut out).map_err(|e| TestCaseError::fail(format!("{e:?} for {p:?}")))?;
            out.truncate(n);
            out
        };
        prop_assert_eq!(dec(&b).unwrap(), p);
    }

    /// Arbitrary bytes behind a plausible first byte: the decoder never
    /// panics, and what it accepts re-encodes to an equal packet.
    #[test]
    fn decode_any_bytes(first in any::<u8>(), body in prop::collection::vec(any::<u8>(), 0..48)) {
        let b = pkt(first, &body);
        if let Ok((p, n)) = decode(&b, &L) {
            prop_assert_eq!(n, b.len());
            let mut out = vec![0u8; encoded_len(&p).unwrap()];
            let m = encode(&p, &mut out).unwrap();
            let (q, _) = decode(&out[..m], &L).unwrap();
            prop_assert_eq!(q, p);
        }
    }

    #[test]
    fn varint_round_trip(v in 0u32..=MAX_VARINT) {
        let mut out = [0u8; 4];
        let n = write_varint(v, &mut out).unwrap();
        prop_assert_eq!(n, varint_len(v));
        prop_assert_eq!(read_varint(&out[..n]), Ok((v, n)));
    }
}
