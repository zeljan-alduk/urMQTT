use super::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// A throwaway key pair written by `openssl genpkey -algorithm ed25519`.
const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIE+Id0UCqmPt6gqw0oj/ZNRcelnLXxo7xKrVXbl8gPoY
-----END PRIVATE KEY-----
";
const PUB_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAm6pM2Sat8zRqRr2bENQci2mgS0mmbS945Md9t7+aQFo=
-----END PUBLIC KEY-----
";
const SEED: [u8; 32] = [
    0x4f, 0x88, 0x77, 0x45, 0x02, 0xaa, 0x63, 0xed, 0xea, 0x0a, 0xb0, 0xd2, 0x88, 0xff, 0x64, 0xd4,
    0x5c, 0x7a, 0x59, 0xcb, 0x5f, 0x1a, 0x3b, 0xc4, 0xaa, 0xd5, 0x5d, 0xb9, 0x7c, 0x80, 0xfa, 0x18,
];
const PUB: [u8; 32] = [
    0x9b, 0xaa, 0x4c, 0xd9, 0x26, 0xad, 0xf3, 0x34, 0x6a, 0x46, 0xbd, 0x9b, 0x10, 0xd4, 0x1c, 0x8b,
    0x69, 0xa0, 0x4b, 0x49, 0xa6, 0x6d, 0x2f, 0x78, 0xe4, 0xc7, 0x7d, 0xb7, 0xbf, 0x9a, 0x40, 0x5a,
];

const NOW: u64 = 1_761_696_000;
const POLICY: Policy = Policy {
    max_message_age_s: 600,
    allow_unrevoke: false,
    allowlist_mode: true,
};

fn msg(seq: u64, command: Command, items: &[&[u8]]) -> Message {
    Message {
        seq,
        not_before: NOW - 60,
        not_after: NOW + 240,
        command,
        items: items.iter().map(|i| i.to_vec()).collect(),
    }
}

fn sign(env: &str, m: &Message) -> Vec<u8> {
    let body = encode_body(m).unwrap();
    let sig = SigningKey::from_bytes(&SEED).sign(&signing_input(env, &body));
    let mut out = body;
    out.extend_from_slice(&sig.to_bytes());
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// RFC 8032 §7.1, TEST 1–3: the primitive as the kernel calls it.
#[test]
fn rfc8032_vectors_verify_strictly() {
    let vectors = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (pk, m, sig) in vectors {
        let key = VerifyingKey::from_bytes(&hex(pk).try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&hex(sig).try_into().unwrap());
        assert!(key.verify_strict(&hex(m), &sig).is_ok());
        let mut other = hex(m);
        other.push(0);
        assert!(key.verify_strict(&other, &sig).is_err());
    }
}

#[test]
fn keys_parse_from_openssl_pem() {
    assert_eq!(parse_private_key(KEY_PEM), Some(SEED));
    assert_eq!(parse_public_key(PUB_PEM), Some(PUB));
    assert_eq!(
        SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        PUB
    );
    assert_eq!(parse_public_key(KEY_PEM), None);
    assert_eq!(parse_private_key(PUB_PEM), None);
    assert_eq!(
        parse_public_key(b"-----BEGIN PUBLIC KEY-----\n!!\n-----END PUBLIC KEY-----"),
        None
    );
}

#[test]
fn signed_message_round_trips() {
    for m in [
        msg(1, Command::Revoke, &[&[0x01, 0x23], &[0x7f; 20]]),
        msg(2, Command::Unrevoke, &[&[0x42]]),
        msg(3, Command::Allow, &[b"device-001", b"device-002"]),
        msg(u64::MAX, Command::Disallow, &[b"d"]),
    ] {
        let wire = sign("dev", &m);
        assert_eq!(verify("dev", &PUB, &wire), Ok(m));
    }
}

#[test]
fn any_changed_byte_fails() {
    let wire = sign("dev", &msg(7, Command::Revoke, &[&[1, 2, 3]]));
    for i in 0..wire.len() {
        for bit in [0x01u8, 0x80] {
            let mut w = wire.clone();
            w[i] ^= bit;
            assert!(verify("dev", &PUB, &w).is_err(), "byte {i} bit {bit:#x}");
        }
    }
}

#[test]
fn signature_is_bound_to_the_environment_and_key() {
    let wire = sign("dev", &msg(7, Command::Revoke, &[&[1]]));
    assert_eq!(verify("prod", &PUB, &wire), Err(Reject::BadSignature));
    let other = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    assert_eq!(verify("dev", &other, &wire), Err(Reject::BadSignature));
    // An all-zero (small-order) public key never verifies.
    assert!(verify("dev", &[0; 32], &wire).is_err());
}

#[test]
fn malformed_messages_are_rejected() {
    let good = msg(5, Command::Revoke, &[&[1]]);
    let wire = sign("dev", &good);
    // Trailing byte, truncation, empty.
    let mut long = wire.clone();
    long.push(0);
    assert!(verify("dev", &PUB, &long).is_err());
    assert!(verify("dev", &PUB, &wire[..wire.len() - 1]).is_err());
    assert_eq!(verify("dev", &PUB, &[]), Err(Reject::Malformed));
    // Structurally invalid bodies do not encode.
    let mut bad = good.clone();
    bad.seq = 0;
    assert_eq!(encode_body(&bad), None);
    let mut bad = good.clone();
    bad.items.clear();
    assert_eq!(encode_body(&bad), None);
    let mut bad = good.clone();
    bad.items = vec![vec![1; 21]];
    assert_eq!(encode_body(&bad), None);
    let mut bad = good.clone();
    bad.items = vec![vec![1], vec![1]];
    assert_eq!(encode_body(&bad), None, "duplicate items");
    let mut bad = good.clone();
    bad.not_after = bad.not_before - 1;
    assert_eq!(encode_body(&bad), None);
    for id in [
        &b""[..],
        b"a/b",
        b"+",
        b"#",
        b"$x",
        b"a\0",
        &[0xff, 0xfe],
        &[b'a'; 129],
    ] {
        let m = msg(1, Command::Allow, &[id]);
        assert_eq!(encode_body(&m), None, "{id:?}");
    }
    // Unknown command and wrong magic.
    let mut body = encode_body(&good).unwrap();
    body[32] = 9;
    assert_eq!(decode_body(&body), Err(Reject::Malformed));
    let mut body = encode_body(&good).unwrap();
    body[0] = b'X';
    assert_eq!(decode_body(&body), Err(Reject::Malformed));
}

#[test]
fn freshness_replay_and_permission_rules() {
    let m = msg(10, Command::Revoke, &[&[1]]);
    assert_eq!(check(&m, Some(NOW), 9, &POLICY), Ok(()));
    assert_eq!(check(&m, None, 9, &POLICY), Err(Reject::NoClock));
    assert_eq!(check(&m, Some(NOW), 10, &POLICY), Err(Reject::Replay));
    assert_eq!(check(&m, Some(NOW), 11, &POLICY), Err(Reject::Replay));
    assert_eq!(
        check(&m, Some(NOW - 61), 0, &POLICY),
        Err(Reject::NotYetValid)
    );
    assert_eq!(check(&m, Some(NOW + 241), 0, &POLICY), Err(Reject::Expired));
    assert_eq!(
        check(&m, Some(NOW + 240), 0, &POLICY),
        Ok(()),
        "inclusive end"
    );
    let mut long = m.clone();
    long.not_after = long.not_before + 601;
    assert_eq!(
        check(&long, Some(NOW), 0, &POLICY),
        Err(Reject::WindowTooLong)
    );
    let un = msg(11, Command::Unrevoke, &[&[1]]);
    assert_eq!(
        check(&un, Some(NOW), 0, &POLICY),
        Err(Reject::UnrevokeDisabled)
    );
    let p = Policy {
        allow_unrevoke: true,
        allowlist_mode: false,
        ..POLICY
    };
    assert_eq!(check(&un, Some(NOW), 0, &p), Ok(()));
    let allow = msg(12, Command::Allow, &[b"d1"]);
    assert_eq!(
        check(&allow, Some(NOW), 0, &p),
        Err(Reject::NotAllowlistMode)
    );
    assert_eq!(check(&allow, Some(NOW), 0, &POLICY), Ok(()));
}

#[test]
fn reject_reasons_are_unique() {
    for (i, a) in Reject::ALL.iter().enumerate() {
        assert_eq!(a.index(), i);
        for b in &Reject::ALL[i + 1..] {
            assert_ne!(a.reason(), b.reason());
        }
    }
}

#[test]
fn max_len_message_fits() {
    let items: Vec<Vec<u8>> = (0..MAX_ITEMS)
        .map(|i| {
            let mut v = vec![b'x'; MAX_ID_LEN];
            v[..3].copy_from_slice(format!("{i:03}").as_bytes());
            v
        })
        .collect();
    let m = Message {
        items,
        ..msg(1, Command::Allow, &[])
    };
    let wire = sign("dev", &m);
    assert_eq!(wire.len(), MAX_LEN);
    assert!(verify("dev", &PUB, &wire).is_ok());
}
