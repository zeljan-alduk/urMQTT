//! HMAC-SHA-256 (drives HKDF in the key schedule).

use alloc::boxed::Box;

use hmac::{Hmac, KeyInit, Mac};
use rustls::crypto;

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        // HMAC accepts keys of any length, so this cannot fail.
        let mac = Hmac::<sha2::Sha256>::new_from_slice(key)
            .unwrap_or_else(|_| Hmac::<sha2::Sha256>::new(&Default::default()));
        Box::new(Key(mac))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct Key(Hmac<sha2::Sha256>);

impl crypto::hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        32
    }
}
