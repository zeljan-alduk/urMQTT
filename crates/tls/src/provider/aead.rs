//! TLS 1.3 AEADs for the handshake phase: AES-128-GCM and ChaCha20-Poly1305.
//! After the handshake the kernel's own record layer (`crate::record`) takes over.

use alloc::boxed::Box;

use aes_gcm::aead::{AeadInPlace, Buffer, KeyInit};
use rustls::crypto::cipher::{
    AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

const TAG: usize = 16;

pub struct Aes128Gcm;
pub struct ChaCha20Poly1305;

enum Cipher {
    Aes(Box<aes_gcm::Aes128Gcm>),
    ChaCha(Box<chacha20poly1305::ChaCha20Poly1305>),
    /// Key of the wrong length: every operation fails (cannot happen with
    /// rustls-derived keys, but must not panic).
    Invalid,
}

impl Cipher {
    fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut dyn Buffer,
    ) -> Result<(), rustls::Error> {
        let r = match self {
            Self::Aes(c) => c.encrypt_in_place(nonce.into(), aad, buf),
            Self::ChaCha(c) => c.encrypt_in_place(nonce.into(), aad, buf),
            Self::Invalid => return Err(rustls::Error::EncryptError),
        };
        r.map_err(|_| rustls::Error::EncryptError)
    }

    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut dyn Buffer,
    ) -> Result<(), rustls::Error> {
        let r = match self {
            Self::Aes(c) => c.decrypt_in_place(nonce.into(), aad, buf),
            Self::ChaCha(c) => c.decrypt_in_place(nonce.into(), aad, buf),
            Self::Invalid => return Err(rustls::Error::DecryptError),
        };
        r.map_err(|_| rustls::Error::DecryptError)
    }
}

struct Tls13(Cipher, Iv);

fn aes(key: &AeadKey) -> Cipher {
    aes_gcm::Aes128Gcm::new_from_slice(key.as_ref())
        .map_or(Cipher::Invalid, |c| Cipher::Aes(Box::new(c)))
}

fn chacha(key: &AeadKey) -> Cipher {
    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_or(Cipher::Invalid, |c| Cipher::ChaCha(Box::new(c)))
}

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13(aes(&key), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13(aes(&key), iv))
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

impl Tls13AeadAlgorithm for ChaCha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13(chacha(&key), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13(chacha(&key), iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl MessageEncrypter for Tls13 {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let nonce = Nonce::new(&self.1, seq).0;
        self.0
            .seal(&nonce, &make_tls13_aad(total), &mut EncBuf(&mut payload))?;
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG
    }
}

impl MessageDecrypter for Tls13 {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = make_tls13_aad(payload.len());
        self.0.open(&nonce, &aad, &mut DecBuf(payload))?;
        m.into_tls13_unpadded_message()
    }
}

struct EncBuf<'a>(&'a mut PrefixedPayload);

impl AsRef<[u8]> for EncBuf<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncBuf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncBuf<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

struct DecBuf<'a, 'p>(&'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecBuf<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecBuf<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecBuf<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> aes_gcm::aead::Result<()> {
        // decrypt_in_place only shrinks the buffer.
        Err(aes_gcm::aead::Error)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}
