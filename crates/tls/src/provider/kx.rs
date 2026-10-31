//! Key exchange groups: X25519 (preferred) and secp256r1.

use alloc::boxed::Box;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use crate::rng::{fill_global, is_installed};

#[derive(Debug)]
pub struct X25519;

#[derive(Debug)]
pub struct Secp256r1;

pub static ALL: &[&dyn SupportedKxGroup] = &[&X25519, &Secp256r1];

struct X25519Active {
    secret: zeroize::Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

/// `X25519(secret, u)` (RFC 7748; the scalar is clamped inside). On x86_64
/// our 4x64 ladder, MULX/ADX assembly where the CPU has it (ADR-131); on
/// aarch64 dalek's 51-bit ladder, which is faster there (18.8 us against
/// 29.3 us for the 4x64 code on an M4 core).
pub(crate) fn x25519(secret: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "x86_64")]
    {
        urmqtt_x25519::x25519(urmqtt_x25519::Backend::detect(), secret, u)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        curve25519_dalek::MontgomeryPoint(*u)
            .mul_clamped(*secret)
            .to_bytes()
    }
}

/// The public key for `secret`: fixed-base multiplication from dalek's
/// precomputed table (about 2x cheaper than a ladder), RFC 7748 clamping.
pub(crate) fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if !is_installed() {
            return Err(Error::FailedToGetRandomBytes);
        }
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        fill_global(&mut secret[..]).map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = x25519_public(&secret);
        Ok(Box::new(X25519Active { secret, public }))
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
        let shared = zeroize::Zeroizing::new(x25519(&self.secret, &peer));
        // Reject all-zero output (small-order peer key, RFC 7748 §6.1).
        if bool::from(subtle::ConstantTimeEq::ct_eq(&shared[..], &[0u8; 32][..])) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
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
        let public = super::fastec::p256_public(&secret);
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
        let shared = super::fastec::p256_dh(&self.secret, peer)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
