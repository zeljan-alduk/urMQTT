//! X0b differential test: AES-128-GCM from `aes-gcm` (on an aarch64 host
//! with `--cfg aes_armv8 --cfg polyval_armv8`, the ARMv8 AES and PMULL
//! backends the kernel dispatches to) against `ring`, an independent
//! implementation. Ciphertext and tag must match byte for byte, and both
//! must open each other's output.
#![no_main]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use libfuzzer_sys::fuzz_target;
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 29 {
        return;
    }
    let (key, rest) = data.split_at(16);
    let (nonce, rest) = rest.split_at(12);
    let aad_len = usize::from(rest[0]) % (rest.len());
    let (aad, pt) = rest[1..].split_at(aad_len.min(rest.len() - 1));

    let ours = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    let mut a = pt.to_vec();
    let tag = ours
        .encrypt_in_place_detached(nonce.into(), aad, &mut a)
        .unwrap();

    let theirs = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).unwrap());
    let mut b = pt.to_vec();
    let n = Nonce::try_assume_unique_for_key(nonce).unwrap();
    let rtag = theirs
        .seal_in_place_separate_tag(n, Aad::from(aad), &mut b)
        .unwrap();
    assert_eq!(a, b, "ciphertext differs");
    assert_eq!(tag.as_slice(), rtag.as_ref(), "tag differs");

    let mut back = a.clone();
    ours.decrypt_in_place_detached(nonce.into(), aad, &mut back, &tag)
        .unwrap();
    assert_eq!(back, pt);
    let mut sealed = b;
    sealed.extend_from_slice(rtag.as_ref());
    let n = Nonce::try_assume_unique_for_key(nonce).unwrap();
    let opened = theirs
        .open_in_place(n, Aad::from(aad), &mut sealed)
        .unwrap();
    assert_eq!(opened, pt);
});
