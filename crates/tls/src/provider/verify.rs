//! Signature verification for certificates and CertificateVerify:
//! ECDSA P-256 with SHA-256 (the dev and recommended production profile).
//!
//! A handshake verifies two signatures: the client certificate against its
//! issuer, and the client's CertificateVerify. Verification is about 40 % of
//! a handshake's CPU (X9 profile). The certificate signature is the same on
//! every reconnect of the same device, so a *successful* verification is
//! remembered by the SHA-256 of (key, message, signature) and not repeated.
//! The result of a verification is a pure function of those three inputs, so
//! a hit says exactly what a fresh check would. Failures are never cached,
//! and CertificateVerify messages (fresh per handshake) are not cached.

use core::sync::atomic::{AtomicU64, Ordering};

use p256::ecdsa::signature::Verifier;
use pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use sha2::Digest;
use urmqtt_sync::sync::SpinLock;

#[derive(Debug)]
struct EcdsaP256Sha256;

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ECDSA_P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256])],
};

/// Entries of the verification memo (direct mapped, 32 bytes each).
const CACHE_ENTRIES: usize = 512;

/// Digests of verified (key, message, signature) triples; all-zero is empty.
static VERIFIED: SpinLock<[[u8; 32]; CACHE_ENTRIES]> = SpinLock::new([[0; 32]; CACHE_ENTRIES]);
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);

/// (hits, full verifications of cacheable signatures) so far (statistics).
pub fn cache_stats() -> (u64, u64) {
    // Relaxed: statistics.
    (HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
}

/// TLS 1.3 CertificateVerify signs 64 spaces first (RFC 8446 §4.4.3).
fn is_certificate_verify(message: &[u8]) -> bool {
    message.len() >= 64 && message.iter().take(64).all(|&b| b == 0x20)
}

/// Domain-separated digest of the triple, with lengths so no two triples
/// share an encoding.
fn digest(public_key: &[u8], message: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"urmqtt-ecdsa-p256-verified\0");
    for part in [public_key, message, signature] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

fn slot(d: &[u8; 32]) -> usize {
    usize::from(u16::from_be_bytes([d[0], d[1]])) % CACHE_ENTRIES
}

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let cacheable = !is_certificate_verify(message);
        let d = cacheable.then(|| digest(public_key, message, signature));
        if let Some(d) = &d
            && VERIFIED.lock().get(slot(d)) == Some(d)
        {
            // Relaxed: statistics.
            HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let sig = p256::ecdsa::DerSignature::try_from(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)?;
        if let Some(d) = d {
            // Relaxed: statistics.
            MISSES.fetch_add(1, Ordering::Relaxed);
            if let Some(e) = VERIFIED.lock().get_mut(slot(&d)) {
                *e = d;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    /// The counters are global: the tests that read them run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn sign(key: &p256::ecdsa::SigningKey, msg: &[u8]) -> alloc::vec::Vec<u8> {
        let sig: p256::ecdsa::DerSignature = key.sign(msg);
        sig.as_bytes().to_vec()
    }

    #[test]
    fn a_verified_signature_is_not_verified_twice_and_tampering_still_fails() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let a = EcdsaP256Sha256;
        let key = p256::ecdsa::SigningKey::from_slice(&[0x5a; 32]).unwrap();
        let pk = key.verifying_key().to_sec1_bytes();
        let msg = b"to-be-signed certificate bytes, unique to this test".to_vec();
        let sig = sign(&key, &msg);
        let (h0, m0) = cache_stats();
        assert!(a.verify_signature(&pk, &msg, &sig).is_ok());
        let (h1, m1) = cache_stats();
        assert_eq!((h1 - h0, m1 - m0), (0, 1), "first check is a full one");
        assert!(a.verify_signature(&pk, &msg, &sig).is_ok());
        let (h2, m2) = cache_stats();
        assert_eq!((h2 - h1, m2 - m1), (1, 0), "second is a memo hit");
        // Any change of key, message or signature is a miss and is checked.
        let mut bad = msg.clone();
        bad[3] ^= 1;
        assert!(a.verify_signature(&pk, &bad, &sig).is_err());
        let mut bad_sig = sig.clone();
        let n = bad_sig.len();
        bad_sig[n - 1] ^= 1;
        assert!(a.verify_signature(&pk, &msg, &bad_sig).is_err());
        let other = p256::ecdsa::SigningKey::from_slice(&[0x5b; 32]).unwrap();
        let pk2 = other.verifying_key().to_sec1_bytes();
        assert!(a.verify_signature(&pk2, &msg, &sig).is_err());
        // Failures are not remembered: they fail again.
        assert!(a.verify_signature(&pk, &bad, &sig).is_err());
    }

    #[test]
    fn certificate_verify_messages_bypass_the_memo() {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let a = EcdsaP256Sha256;
        let key = p256::ecdsa::SigningKey::from_slice(&[0x6c; 32]).unwrap();
        let pk = key.verifying_key().to_sec1_bytes();
        let mut msg = alloc::vec![0x20u8; 64];
        msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\0transcript-hash");
        let sig = sign(&key, &msg);
        let (h0, m0) = cache_stats();
        assert!(a.verify_signature(&pk, &msg, &sig).is_ok());
        assert!(a.verify_signature(&pk, &msg, &sig).is_ok());
        assert_eq!(cache_stats(), (h0, m0), "not cached, not counted");
    }
}
