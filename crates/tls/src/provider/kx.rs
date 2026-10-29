//! Key exchange groups: X25519 (preferred) and secp256r1.

use alloc::boxed::Box;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use p256::elliptic_curve::sec1::ToSec1Point;

use crate::rng::{SystemRng, fill_global, is_installed};

#[derive(Debug)]
pub struct X25519;

#[derive(Debug)]
pub struct Secp256r1;

pub static ALL: &[&dyn SupportedKxGroup] = &[&X25519, &Secp256r1];

struct X25519Active {
    secret: x25519_dalek::EphemeralSecret,
    public: x25519_dalek::PublicKey,
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if !is_installed() {
            return Err(Error::FailedToGetRandomBytes);
        }
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(SystemRng);
        Ok(Box::new(X25519Active {
            public: (&secret).into(),
            secret,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // Reject all-zero output (small-order peer key, RFC 7748 §6.1).
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct P256Active {
    secret: p256::SecretKey,
    public: [u8; 65],
}

impl SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if !is_installed() {
            return Err(Error::FailedToGetRandomBytes);
        }
        // Rejection sampling: a uniformly random 32-byte string is a valid
        // scalar (non-zero, below the group order) with overwhelming
        // probability; retry otherwise.
        let secret = loop {
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            fill_global(&mut bytes[..]).map_err(|_| Error::FailedToGetRandomBytes)?;
            if let Ok(k) = p256::SecretKey::from_slice(&bytes[..]) {
                break k;
            }
        };
        let point = secret.public_key().to_sec1_point(false);
        let mut public = [0u8; 65];
        public.copy_from_slice(point.as_bytes());
        Ok(Box::new(P256Active { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

impl ActiveKeyExchange for P256Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // Uncompressed points only (RFC 8446 §4.2.8.2); decoding validates
        // that the point is on the curve.
        if peer.first() != Some(&4) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
