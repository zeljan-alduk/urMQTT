//! Known-answer tests of the primitives the broker relies on, run at every
//! boot after the CPU dispatch is sealed (X0b). Whatever backend was chosen
//! (portable, ARMv8 AES/PMULL/SHA2, NEON), it must reproduce the published
//! vectors exactly, or the kernel refuses to run.
//!
//! - AES-128-GCM: McGrew & Viega, "The Galois/Counter Mode of Operation",
//!   test case 4 (with additional data and a partial final block).
//! - ChaCha20-Poly1305: RFC 8439 §2.8.2.
//! - SHA-256: FIPS 180-4 examples "abc" and the 448-bit message.
//! - HMAC-SHA-256: RFC 4231 test case 2.

use alloc::vec::Vec;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| s.get(2 * i..2 * i + 2))
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect()
}

fn aes_gcm() -> bool {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let key = hex("feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    let ct = hex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    );
    let tag = hex("5bc94fbc3221a5db94fae95ae7121a47");
    let Ok(c) = aes_gcm::Aes128Gcm::new_from_slice(&key) else {
        return false;
    };
    let mut buf = pt.clone();
    let Ok(t) = c.encrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut buf) else {
        return false;
    };
    if buf != ct || t.as_slice() != tag.as_slice() {
        return false;
    }
    c.decrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut buf, &t)
        .is_ok()
        && buf == pt
}

fn chacha20_poly1305() -> bool {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct = hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let tag = hex("1ae10b594f09e26a7e902ecbd0600691");
    let Ok(c) = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key) else {
        return false;
    };
    let mut buf = pt.to_vec();
    let Ok(t) = c.encrypt_in_place_detached(nonce.as_slice().into(), &aad, &mut buf) else {
        return false;
    };
    buf == ct && t.as_slice() == tag.as_slice()
}

fn sha256() -> bool {
    use sha2::Digest;
    let a = sha2::Sha256::digest(b"abc");
    let b = sha2::Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    // Streamed in odd pieces across block boundaries: the same digest.
    let mut h = sha2::Sha256::new();
    for part in [
        &b"abcdbcdecdefdefgefghfghighijhijk"[..],
        b"ijkljklmklmnlmnomnopnopq",
    ] {
        h.update(part);
    }
    a.as_slice() == hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        && b.as_slice() == hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        && h.finalize().as_slice() == b.as_slice()
}

fn hmac_sha256() -> bool {
    use hmac::{KeyInit, Mac};
    let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"Jefe") else {
        return false;
    };
    m.update(b"what do ya want for nothing?");
    m.finalize().into_bytes().as_slice()
        == hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
}

/// Runs every known-answer test; the name of the first failure.
pub fn run() -> Result<(), &'static str> {
    for (name, ok) in [
        ("AES-128-GCM", aes_gcm as fn() -> bool),
        ("ChaCha20-Poly1305", chacha20_poly1305),
        ("SHA-256", sha256),
        ("HMAC-SHA-256", hmac_sha256),
    ] {
        if !ok() {
            return Err(name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_answers_pass_with_the_host_backends() {
        assert_eq!(super::run(), Ok(()));
    }
}
