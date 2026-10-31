//! The primitives of a TLS 1.3 handshake as single, repeatable operations,
//! for the diagnostic entry's cost estimate (O4): X25519, ECDSA P-256 sign
//! and verify, and the record layer's bulk ciphers. Fixed test keys: nothing
//! here is secret and nothing is used by the server.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use p256::ecdsa::signature::Signer as _;

/// Prepared keys and a signature to verify.
pub struct Probe {
    key: p256::ecdsa::SigningKey,
    public_sec1: alloc::vec::Vec<u8>,
    peer_share: [u8; 32],
    der: alloc::vec::Vec<u8>,
    issuer: crate::provider::MeasuredIssuer,
}

const MSG: &[u8] = b"urMQTT diagnostic: TLS 1.3 CertificateVerify stand-in";

impl Probe {
    pub fn new() -> Option<Self> {
        let key = p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).ok()?;
        let public = *key.verifying_key();
        let sig: p256::ecdsa::Signature = key.try_sign(MSG).ok()?;
        let der = sig.to_der().as_bytes().to_vec();
        let issuer = crate::provider::MeasuredIssuer::new(&public);
        Some(Self {
            key,
            public_sec1: public.to_sec1_bytes().to_vec(),
            peer_share: crate::provider::x25519_public(&[0x17u8; 32]),
            der,
            issuer,
        })
    }

    /// One X25519 shared-secret computation (the variable-base ladder, as in
    /// a handshake).
    pub fn x25519(&self, round: u8) -> u8 {
        let mut k = [0x11u8; 32];
        k[5] = round;
        let out = crate::provider::x25519(&k, &self.peer_share);
        out[0]
    }

    /// One X25519 key share (fixed-base multiplication).
    pub fn x25519_base(&self, round: u8) -> u8 {
        let mut k = [0x11u8; 32];
        k[5] = round;
        crate::provider::x25519_public(&k)[0]
    }

    /// One ECDSA P-256 signature (the production signing path).
    pub fn sign(&self) -> bool {
        crate::provider::fastec::ecdsa_sign(&self.key, MSG).is_ok_and(|s| s == self.der)
    }

    /// One ECDSA P-256 verification by a key without a table (the client's
    /// CertificateVerify).
    pub fn verify(&self) -> bool {
        crate::provider::fastec::ecdsa_verify(&self.public_sec1, MSG, &self.der).is_ok()
    }

    /// One verification of a certificate signature by a registered trust
    /// anchor (fixed-base tables, ADR-111).
    pub fn verify_ca(&self) -> bool {
        self.issuer.verify(MSG, &self.der)
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
        assert!(p.verify() && p.verify_ca());
        assert_ne!(p.x25519(1), p.x25519(2));
        assert_ne!(p.x25519_base(1), p.x25519_base(2));
        let mut b = [0u8; 256];
        assert!(aes_gcm(&mut b) && chacha(&mut b));
        let _ = sha256(&b);
    }
}
