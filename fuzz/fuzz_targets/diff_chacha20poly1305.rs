//! X0b differential test: ChaCha20-Poly1305 from `chacha20poly1305` (NEON
//! backend with `--cfg chacha20_force_neon`, as in the kernel) against
//! `ring`.
#![no_main]

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use libfuzzer_sys::fuzz_target;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 45 {
        return;
    }
    let (key, rest) = data.split_at(32);
    let (nonce, rest) = rest.split_at(12);
    let aad_len = usize::from(rest[0]) % rest.len();
    let (aad, pt) = rest[1..].split_at(aad_len.min(rest.len() - 1));
    let ours = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap();
    let mut a = pt.to_vec();
    let tag = ours
        .encrypt_in_place_detached(nonce.into(), aad, &mut a)
        .unwrap();
    let theirs = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut b = pt.to_vec();
    let n = Nonce::try_assume_unique_for_key(nonce).unwrap();
    let rtag = theirs
        .seal_in_place_separate_tag(n, Aad::from(aad), &mut b)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(tag.as_slice(), rtag.as_ref());
});
