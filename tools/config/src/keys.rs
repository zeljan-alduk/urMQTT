//! Ed25519 keys as OpenSSL writes them (PKCS#8 private key, SubjectPublicKeyInfo
//! public key), for the optional configuration signature (ADR-219). The browser
//! builder uses [`ed25519_from_seed`] with 32 bytes from
//! `crypto.getRandomValues`; the result is what `openssl genpkey -algorithm
//! ed25519` and `openssl pkey -pubout` would print, so `pack --sign` reads it.

use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;

/// PKCS#8 v1 header of an Ed25519 private key (RFC 8410), followed by the seed.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// SubjectPublicKeyInfo header of an Ed25519 public key, followed by the key.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An Ed25519 key pair in PEM.
pub struct KeyPair {
    pub private_pem: String,
    pub public_pem: String,
    pub public_key: [u8; 32],
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = Base64::encode_string(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The `BEGIN PUBLIC KEY` PEM of an Ed25519 public key.
pub fn public_pem(public_key: &[u8; 32]) -> String {
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(public_key);
    pem("PUBLIC KEY", &spki)
}

/// The key pair whose private key is `seed` (32 random bytes).
pub fn ed25519_from_seed(seed: &[u8; 32]) -> KeyPair {
    let public_key = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut private = PKCS8_PREFIX.to_vec();
    private.extend_from_slice(seed);
    KeyPair {
        private_pem: pem("PRIVATE KEY", &private),
        public_pem: public_pem(&public_key),
        public_key,
    }
}

/// The public key of the Ed25519 private key `pem` (PKCS#8, PEM or DER).
pub fn public_of_private(pem: &[u8]) -> Option<[u8; 32]> {
    let seed = urmqtt_control::parse_private_key(pem)?;
    Some(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_the_parsers() {
        let seed = [7u8; 32];
        let k = ed25519_from_seed(&seed);
        assert!(k.private_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(k.private_pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert_eq!(
            urmqtt_control::parse_private_key(k.private_pem.as_bytes()),
            Some(seed)
        );
        assert_eq!(
            urmqtt_control::parse_public_key(k.public_pem.as_bytes()),
            Some(k.public_key)
        );
        assert_eq!(
            public_of_private(k.private_pem.as_bytes()),
            Some(k.public_key)
        );
        // Lines are at most 64 characters, as OpenSSL writes them.
        assert!(k.private_pem.lines().all(|l| l.len() <= 64));
    }

    #[test]
    fn a_signed_blob_verifies_with_the_generated_key() {
        let blob = urmqtt_cfg::build::Builder::new().finish(false).unwrap();
        let k = ed25519_from_seed(&[9u8; 32]);
        let signed = crate::sign_pem(&blob, k.private_pem.as_bytes()).unwrap();
        let b = urmqtt_cfg::Blob::parse(&signed).unwrap();
        assert_eq!(b.signature().unwrap().public_key, k.public_key);
        // The same key signs the same fingerprint the same way (Ed25519 is
        // deterministic), so a rebuild gives identical bytes.
        assert_eq!(
            signed,
            crate::sign_pem(&blob, k.private_pem.as_bytes()).unwrap()
        );
    }
}
