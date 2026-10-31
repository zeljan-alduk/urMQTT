//! Minimal rustls crypto provider on RustCrypto primitives (ADR-029):
//! TLS 1.3 only; AES-128-GCM and ChaCha20-Poly1305 with SHA-256; X25519 and
//! secp256r1; ECDSA P-256 signatures.

use alloc::sync::Arc;
use alloc::vec;

use pki_types::PrivateKeyDer;
use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hmac;
mod kx;
pub mod sign;
mod verify;

pub use verify::cache_stats as verify_cache_stats;

/// Certificate signatures answered from the verification memo (statistics).
pub fn verify_cache_hits() -> u64 {
    verify::cache_stats().0
}

/// AES-GCM may encrypt 2^24.5 records per key (RFC 8446 §5.5).
pub const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: AES_GCM_RECORD_LIMIT,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aes128Gcm,
        quic: None,
    });

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::ChaCha20Poly1305,
        quic: None,
    });

#[derive(Debug)]
struct Kernel;

impl SecureRandom for Kernel {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::rng::fill_global(buf).map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Kernel {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        sign::EcdsaP256::from_der(&key_der)
            .map(|k| Arc::new(k) as Arc<dyn rustls::sign::SigningKey>)
            .ok_or_else(|| {
                rustls::Error::General("server key must be ECDSA P-256 (PKCS#8 or SEC1)".into())
            })
    }
}

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: kx::ALL.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Kernel,
        key_provider: &Kernel,
    }
}
