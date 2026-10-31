//! The primitives of a TLS 1.3 handshake as single, repeatable operations,
//! for the diagnostic entry's cost estimate (O4): X25519, ECDSA P-256 sign
//! and verify, and the record layer's bulk ciphers. Fixed test keys: nothing
//! here is secret and nothing is used by the server.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use p256::ecdsa::signature::{Signer as _, Verifier as _};

/// Prepared keys and a signature to verify.
pub struct Probe {
    key: p256::ecdsa::SigningKey,
    public: p256::ecdsa::VerifyingKey,
    sig: p256::ecdsa::Signature,
}

const MSG: &[u8] = b"urMQTT diagnostic: TLS 1.3 CertificateVerify stand-in";

impl Probe {
    pub fn new() -> Option<Self> {
        let key = p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).ok()?;
        let public = *key.verifying_key();
        let sig: p256::ecdsa::Signature = key.try_sign(MSG).ok()?;
        Some(Self { key, public, sig })
    }

    /// One X25519 scalar multiplication (a key share or the shared secret).
    pub fn x25519(&self, round: u8) -> u8 {
        let mut k = [0x11u8; 32];
        k[5] = round;
        let out = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
        out[0]
    }

    /// One ECDSA P-256 signature.
    pub fn sign(&self) -> bool {
        let s: Result<p256::ecdsa::Signature, _> = self.key.try_sign(MSG);
        s.is_ok_and(|s| s == self.sig)
    }

    /// One ECDSA P-256 verification.
    pub fn verify(&self) -> bool {
        self.public.verify(MSG, &self.sig).is_ok()
    }
}

/// AES-128-GCM over `buf` in place.
pub fn aes_gcm(buf: &mut [u8]) -> bool {
    let nonce = [7u8; 12];
    aes_gcm::Aes128Gcm::new_from_slice(&[1u8; 16]).is_ok_and(|c| {
        c.encrypt_in_place_detached((&nonce).into(), b"", buf)
            .is_ok()
    })
}

/// ChaCha20-Poly1305 over `buf` in place.
pub fn chacha(buf: &mut [u8]) -> bool {
    let nonce = [7u8; 12];
    chacha20poly1305::ChaCha20Poly1305::new_from_slice(&[2u8; 32]).is_ok_and(|c| {
        c.encrypt_in_place_detached((&nonce).into(), b"", buf)
            .is_ok()
    })
}

/// First byte of the SHA-256 of `buf`.
pub fn sha256(buf: &[u8]) -> u8 {
    use sha2::Digest;
    sha2::Sha256::digest(buf).first().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probes_work() {
        let p = Probe::new().unwrap();
        assert!(p.sign());
        assert!(p.verify());
        assert_ne!(p.x25519(1), p.x25519(2));
        let mut b = [0u8; 256];
        assert!(aes_gcm(&mut b) && chacha(&mut b));
        let _ = sha256(&b);
    }
}
