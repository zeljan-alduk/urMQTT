//! Server signing key: ECDSA P-256 with SHA-256 (PKCS#8 or SEC1 PEM).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::DecodePrivateKey;
use pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

#[derive(Clone, Debug)]
pub struct EcdsaP256 {
    key: Arc<p256::ecdsa::SigningKey>,
}

impl EcdsaP256 {
    pub fn from_der(der: &PrivateKeyDer<'_>) -> Option<Self> {
        let key = match der {
            PrivateKeyDer::Pkcs8(k) => {
                p256::ecdsa::SigningKey::from_pkcs8_der(k.secret_pkcs8_der()).ok()?
            }
            PrivateKeyDer::Sec1(k) => p256::SecretKey::from_sec1_der(k.secret_sec1_der())
                .ok()
                .map(p256::ecdsa::SigningKey::from)?,
            _ => return None,
        };
        Some(Self { key: Arc::new(key) })
    }
}

impl SigningKey for EcdsaP256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaP256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sig: p256::ecdsa::DerSignature = self
            .key
            // Deterministic nonces (RFC 6979): no dependence on the RNG at
            // signing time, and no nonce reuse even if it were weak.
            .try_sign(message)
            .map_err(|_| rustls::Error::General("signing failed".into()))?;
        Ok(sig.as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}
