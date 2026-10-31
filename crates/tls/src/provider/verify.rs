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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Trust anchors with a fixed-base table (ADR-111), at most this many.
const MAX_ISSUERS: usize = 8;

use super::fastec::IssuerTable;

struct Issuer {
    /// SEC1 uncompressed point, as webpki hands it to `verify_signature`.
    point: [u8; 65],
    table: IssuerTable,
}

static ISSUERS: SpinLock<Vec<Arc<Issuer>>> = SpinLock::new(Vec::new());

/// Gives the verifier a fixed-base table for a trust anchor's P-256 key
/// (`spki` is its SubjectPublicKeyInfo DER). Every certificate signed by it
/// is then verified with two table lookups' worth of point additions
/// instead of a variable-base multiplication (about 2.5x faster). Built once
/// at configuration time (about 1 ms, 25 KiB per key); keys that are not
/// registered, and registrations past [`MAX_ISSUERS`], use the ordinary
/// path. Returns whether the key has a table afterwards.
pub fn register_issuer(spki: &[u8]) -> bool {
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::DecodePublicKey;
    let Ok(key) = p256::PublicKey::from_public_key_der(spki) else {
        return false;
    };
    let mut point = [0u8; 65];
    let enc = key.to_sec1_point(false);
    if enc.as_bytes().len() != 65 {
        return false;
    }
    point.copy_from_slice(enc.as_bytes());
    if issuer(&point).is_some() {
        return true;
    }
    // Built outside the lock: a concurrent duplicate is harmless.
    let table = IssuerTable::from_key(key.as_affine());
    let mut all = ISSUERS.lock();
    if all.iter().any(|i| i.point == point) {
        return true;
    }
    if all.len() >= MAX_ISSUERS {
        return false;
    }
    all.push(Arc::new(Issuer { point, table }));
    true
}

/// A table of its own for benchmarks and probes, outside the global registry
/// (so measuring does not use up one of its slots).
pub struct MeasuredIssuer(IssuerTable);

impl MeasuredIssuer {
    pub fn new(key: &p256::ecdsa::VerifyingKey) -> Self {
        Self(IssuerTable::from_key(key.as_affine()))
    }

    /// The table-based verification of a DER signature over `message`.
    pub fn verify(&self, message: &[u8], der: &[u8]) -> bool {
        self.0.verify(message, der).is_ok()
    }
}

fn issuer(public_key: &[u8]) -> Option<Arc<Issuer>> {
    ISSUERS
        .lock()
        .iter()
        .find(|i| i.point[..] == *public_key)
        .cloned()
}

/// Boot known-answer test of the table paths: RFC 6979 A.2.5 (P-256,
/// SHA-256, message "sample"): public key from the generator table, the
/// deterministic signature (fixed-base signing), and its verification through
/// an issuer table, plus a rejected tampered message.
pub fn kat() -> bool {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2)
            .filter_map(|i| s.get(2 * i..2 * i + 2))
            .filter_map(|b| u8::from_str_radix(b, 16).ok())
            .collect()
    };
    let x = hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&x) else {
        return false;
    };
    let mut want_pk = hex("04");
    want_pk.extend(hex(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    ));
    // The production paths: public key and signature through `fastec` (the
    // assembly on x86_64), the stock key encoding as a cross-check.
    let pk = sk.verifying_key().as_affine().to_sec1_point(false);
    if pk.as_bytes() != want_pk.as_slice()
        || super::fastec::p256_public(&p256::SecretKey::from(&sk))[..] != want_pk[..]
    {
        return false;
    }
    let Ok(der_bytes) = super::fastec::ecdsa_sign(&sk, b"sample") else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_der(&der_bytes) else {
        return false;
    };
    let mut want_sig = hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    want_sig.extend(hex(
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ));
    if sig.to_bytes().as_slice() != want_sig.as_slice() {
        return false;
    }
    let table = IssuerTable::from_key(sk.verifying_key().as_affine());
    let der = sig.to_der();
    table.verify(b"sample", der.as_bytes()).is_ok()
        && table.verify(b"sample!", der.as_bytes()).is_err()
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
        match issuer(public_key) {
            Some(issuer) => issuer.table.verify(message, signature)?,
            None => super::fastec::ecdsa_verify(public_key, message, signature)?,
        }
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
    use p256::ecdsa::signature::{Signer, Verifier};

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
    fn rfc6979_known_answer_through_the_tables() {
        assert!(kat());
    }

    /// Differential test against the unmodified implementation (RustCrypto's
    /// `VerifyingKey::verify`, variable-base) on random keys, messages and
    /// signatures: valid, tampered and random-garbage inputs must agree.
    #[test]
    fn issuer_table_verification_agrees_with_the_stock_verifier() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        let mut rng = ChaCha20Rng::seed_from_u64(0x6e75_6c6c);
        let mut agreed = 0;
        for _ in 0..40 {
            let mut kb = [0u8; 32];
            rng.fill_bytes(&mut kb);
            let sk = p256::ecdsa::SigningKey::from_slice(&kb).unwrap();
            let vk = sk.verifying_key();
            let table = IssuerTable::from_key(vk.as_affine());
            for _ in 0..5 {
                let mut msg = alloc::vec![0u8; (rng.next_u32() % 300) as usize];
                rng.fill_bytes(&mut msg);
                let good = sign(&sk, &msg);
                let mut cases = alloc::vec![(msg.clone(), good.clone())];
                let mut m2 = msg.clone();
                m2.push(1);
                cases.push((m2, good.clone()));
                let mut s2 = good.clone();
                let i = (rng.next_u32() as usize) % s2.len();
                s2[i] ^= 1 << (rng.next_u32() % 8);
                cases.push((msg.clone(), s2));
                let mut garbage = alloc::vec![0u8; 70];
                rng.fill_bytes(&mut garbage);
                garbage[0] = 0x30;
                garbage[1] = 68;
                cases.push((msg.clone(), garbage));
                // A signature by another key.
                let other = p256::ecdsa::SigningKey::from_slice(&[0x77; 32]).unwrap();
                cases.push((msg.clone(), sign(&other, &msg)));
                for (m, s) in cases {
                    let stock = match p256::ecdsa::DerSignature::try_from(s.as_slice()) {
                        Ok(sig) => vk.verify(&m, &sig).is_ok(),
                        Err(_) => false,
                    };
                    let fast = table.verify(&m, &s).is_ok();
                    assert_eq!(stock, fast, "disagreement");
                    agreed += 1;
                }
            }
        }
        assert_eq!(agreed, 40 * 5 * 5);
    }

    /// Fixed-base signing (the generator table) against the variable-base
    /// multiplication it replaces: the same public points and the same
    /// deterministic signatures.
    #[test]
    fn generator_table_agrees_with_variable_base_multiplication() {
        use p256::elliptic_curve::Group;
        use p256::elliptic_curve::ops::MulByGeneratorVartime;
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        for _ in 0..200 {
            let mut kb = [0u8; 32];
            rng.fill_bytes(&mut kb);
            let Ok(sk) = p256::SecretKey::from_slice(&kb) else {
                continue;
            };
            let k = *sk.to_nonzero_scalar();
            let stock = p256::ProjectivePoint::generator() * k;
            assert_eq!(p256::ProjectivePoint::mul_by_generator(&k), stock);
            assert_eq!(p256::ProjectivePoint::mul_by_generator_vartime(&k), stock);
            assert_eq!(sk.public_key().to_projective(), stock);
        }
    }

    #[test]
    fn registered_issuers_are_used_and_bounded() {
        use p256::pkcs8::EncodePublicKey;
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x31; 32]).unwrap();
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        assert!(register_issuer(spki.as_bytes()));
        assert!(register_issuer(spki.as_bytes()), "idempotent");
        assert!(!register_issuer(b"not a key"));
        let pk = sk.verifying_key().to_sec1_bytes();
        assert!(issuer(&pk).is_some());
        let msg = b"issued certificate body 31".to_vec();
        let sig = sign(&sk, &msg);
        assert!(EcdsaP256Sha256.verify_signature(&pk, &msg, &sig).is_ok());
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert!(EcdsaP256Sha256.verify_signature(&pk, &bad, &sig).is_err());
        assert!(ISSUERS.lock().len() <= MAX_ISSUERS);
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
