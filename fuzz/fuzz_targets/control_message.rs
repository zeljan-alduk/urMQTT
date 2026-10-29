//! Control messages (H1): anything a control identity publishes reaches
//! the decoder and the signature check on the DB core. Neither may panic,
//! a message that verifies must round-trip exactly, and for every
//! well-formed body exactly one signature (the real one) verifies.
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use urmqtt_control::{
    Command, Message, Policy, decode_body, encode_body, signing_input, split, verify,
};

const SEED: [u8; 32] = [0x5a; 32];

fuzz_target!(|data: &[u8]| {
    let key = SigningKey::from_bytes(&SEED);
    let public = key.verifying_key().to_bytes();
    // 1. Arbitrary bytes as a signed message: never accepted (the fuzzer
    //    cannot forge Ed25519) and never a panic.
    assert!(verify("dev", &public, data).is_err() || decode_body(split(data).unwrap().0).is_ok());
    // 2. Arbitrary bytes as a body: if it decodes, it re-encodes to the same
    //    bytes, and signing it gives a message that verifies to the same
    //    content, for this environment only.
    if let Ok(m) = decode_body(data) {
        assert_eq!(encode_body(&m).as_deref(), Some(data));
        let mut wire = data.to_vec();
        wire.extend_from_slice(&key.sign(&signing_input("dev", data)).to_bytes());
        assert_eq!(verify("dev", &public, &wire).as_ref(), Ok(&m));
        assert!(verify("prod", &public, &wire).is_err());
        let p = Policy {
            max_message_age_s: 600,
            allow_unrevoke: data.len() % 2 == 0,
            allowlist_mode: data.len() % 3 == 0,
        };
        for now in [None, Some(m.not_before), Some(m.not_after), Some(u64::MAX)] {
            let _ = urmqtt_control::check(&m, now, m.seq.wrapping_sub(1), &p);
        }
    }
    // 3. Structured: a message built from the input. If it encodes, it
    //    verifies once signed, and flipping any one byte (chosen by the
    //    input) makes it fail.
    if data.len() >= 26 {
        let u = |i: usize| u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        let cmd = Command::from_byte(1 + data[24] % 4).unwrap();
        let items: Vec<Vec<u8>> = data[26..]
            .split(|&b| b == b',')
            .map(|i| i.to_vec())
            .collect();
        let not_before = u(8);
        let m = Message {
            seq: u(0),
            not_before,
            not_after: not_before.saturating_add(u(16) % 1000),
            command: cmd,
            items,
        };
        if let Some(body) = encode_body(&m) {
            assert_eq!(decode_body(&body).as_ref(), Ok(&m));
            let mut wire = body.clone();
            wire.extend_from_slice(&key.sign(&signing_input("dev", &body)).to_bytes());
            assert_eq!(verify("dev", &public, &wire).as_ref(), Ok(&m));
            let i = usize::from(data[25]) % wire.len();
            wire[i] ^= 1;
            assert!(
                verify("dev", &public, &wire).is_err(),
                "flipped byte {i} still verifies"
            );
        }
    }
});
