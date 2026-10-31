//! P-256 operations with a fast x86_64 path (ADR-130).
//!
//! On x86_64 (Linux hosts and the bare-metal kernel) signing, key
//! generation, ECDH and the verification of signatures by keys without a
//! table run on the `urmqtt-nistz256` assembly (MULX/ADX where the CPU has
//! it). Everywhere else, and for inputs the fast path does not handle, the
//! RustCrypto implementation runs unchanged. Both produce identical
//! results (differential tests below and in `urmqtt-nistz256`).

use alloc::vec::Vec;

use p256::ecdsa::signature::Signer as _;
use pki_types::InvalidSignature;

#[cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
))]
use urmqtt_nistz256 as nistz;

/// Whether the assembly path is compiled in on this target.
pub const FAST: bool = cfg!(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
));

/// Which variant runs, for the boot log: `adx`, `mul` or `portable`.
pub fn backend() -> &'static str {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    {
        if nistz::Ops::detect().uses_adx() {
            "nistz256-adx"
        } else {
            "nistz256-mul"
        }
    }
    #[cfg(not(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    )))]
    {
        "portable"
    }
}

/// ECDSA P-256/SHA-256 signature of `msg`, DER encoded, with the RFC 6979
/// deterministic nonce.
pub fn ecdsa_sign(key: &p256::ecdsa::SigningKey, msg: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    if let Some(sig) = fast_sign(key, msg) {
        return Ok(sig.to_der().as_bytes().to_vec());
    }
    let sig: p256::ecdsa::DerSignature = key
        .try_sign(msg)
        .map_err(|_| rustls::Error::General("signing failed".into()))?;
    Ok(sig.as_bytes().to_vec())
}

#[cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
))]
fn fast_sign(key: &p256::ecdsa::SigningKey, msg: &[u8]) -> Option<p256::ecdsa::Signature> {
    use p256::elliptic_curve::Curve;
    use sha2::Digest;
    use zeroize::Zeroize;
    let ops = nistz::Ops::detect();
    let z: [u8; 32] = sha2::Sha256::digest(msg).into();
    let mut d = [0u8; 32];
    d.copy_from_slice(&key.to_bytes());
    let order = *p256::NistP256::ORDER.as_ref();
    let mut kgen = rfc6979::KGenerator::<sha2::Sha256, _>::new(&d, &z, &[], &order);
    let mut out = None;
    // A zero r or s (probability 2^-256) asks for the next nonce, as RFC 6979.
    for _ in 0..4 {
        let mut k = [0u8; 32];
        kgen.fill_next_k(&mut k);
        let sig = nistz::sign(ops, &d, &k, &z);
        k.zeroize();
        if let Some((r, s)) = sig {
            let mut rs = [0u8; 64];
            rs[..32].copy_from_slice(&r);
            rs[32..].copy_from_slice(&s);
            out = p256::ecdsa::Signature::from_slice(&rs).ok();
            break;
        }
    }
    d.zeroize();
    out
}

/// Verifies a DER ECDSA P-256/SHA-256 signature by the SEC1 point
/// `public_key` (variable time: all inputs are public).
pub fn ecdsa_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    if let Some(ok) = fast_verify(public_key, message, signature) {
        return if ok { Ok(()) } else { Err(InvalidSignature) };
    }
    use p256::ecdsa::signature::Verifier;
    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
    let sig = p256::ecdsa::DerSignature::try_from(signature).map_err(|_| InvalidSignature)?;
    key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// `None`: not applicable (the key is not an uncompressed point), take the
/// portable path.
#[cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
))]
fn fast_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Option<bool> {
    use sha2::Digest;
    let (qx, qy) = split_point(public_key)?;
    let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
        return Some(false);
    };
    let rs = sig.to_bytes();
    let (r, s) = rs.split_at(32);
    let z: [u8; 32] = sha2::Sha256::digest(message).into();
    Some(nistz::verify(
        nistz::Ops::detect(),
        &qx,
        &qy,
        &z,
        r.try_into().ok()?,
        s.try_into().ok()?,
    ))
}

#[cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(target_os = "linux", target_os = "none")
))]
fn split_point(p: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if p.len() != 65 || p[0] != 4 {
        return None;
    }
    let x: [u8; 32] = p[1..33].try_into().ok()?;
    let y: [u8; 32] = p[33..].try_into().ok()?;
    Some((x, y))
}

/// The uncompressed SEC1 encoding of the public key of `secret`.
pub fn p256_public(secret: &p256::SecretKey) -> [u8; 65] {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    {
        use zeroize::Zeroize;
        let mut d = [0u8; 32];
        d.copy_from_slice(&secret.to_bytes());
        let pt = nistz::public_key(nistz::Ops::detect(), &d);
        d.zeroize();
        if let Some((x, y)) = pt {
            let mut out = [0u8; 65];
            out[0] = 4;
            out[1..33].copy_from_slice(&x);
            out[33..].copy_from_slice(&y);
            return out;
        }
    }
    use p256::elliptic_curve::sec1::ToSec1Point;
    let mut out = [0u8; 65];
    let enc = secret.public_key().to_sec1_point(false);
    if enc.as_bytes().len() == 65 {
        out.copy_from_slice(enc.as_bytes());
    }
    out
}

/// The peer's ECDH share is not a valid uncompressed point of the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadPoint;

/// ECDH: the shared x coordinate of `secret` and the peer's uncompressed
/// SEC1 point, which must be a valid point of the curve. `Err` otherwise.
pub fn p256_dh(secret: &p256::SecretKey, peer: &[u8]) -> Result<[u8; 32], BadPoint> {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    if let Some((qx, qy)) = split_point(peer) {
        use zeroize::Zeroize;
        let mut d = [0u8; 32];
        d.copy_from_slice(&secret.to_bytes());
        let shared = nistz::ecdh(nistz::Ops::detect(), &d, &qx, &qy);
        d.zeroize();
        return shared.ok_or(BadPoint);
    }
    if peer.first() != Some(&4) {
        return Err(BadPoint);
    }
    let peer = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| BadPoint)?;
    let shared = secret.diffie_hellman(&peer);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

/// Boot known-answer tests of the key exchanges as they run in the
/// handshake: ECDH on P-256 and key generation (RFC 5903 §8.1) and X25519
/// (RFC 7748 §5.2, and §6.1 for the public key).
pub fn kx_kat() -> bool {
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2)
            .filter_map(|i| s.get(2 * i..2 * i + 2))
            .filter_map(|b| u8::from_str_radix(b, 16).ok())
            .collect()
    };
    let h32 = |s: &str| -> Option<[u8; 32]> { hex(s).try_into().ok() };
    // RFC 5903 §8.1: both parties' keys and the shared secret.
    let (Ok(i), Ok(r)) = (
        p256::SecretKey::from_slice(&hex(
            "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433",
        )),
        p256::SecretKey::from_slice(&hex(
            "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53",
        )),
    ) else {
        return false;
    };
    let mut gi = hex("04");
    gi.extend(hex(
        "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180",
    ));
    gi.extend(hex(
        "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
    ));
    let mut gr = hex("04");
    gr.extend(hex(
        "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63",
    ));
    gr.extend(hex(
        "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab",
    ));
    let secret = hex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
    let p256_ok = p256_public(&i)[..] == gi[..]
        && p256_public(&r)[..] == gr[..]
        && p256_dh(&i, &gr).is_ok_and(|s| s[..] == secret[..])
        && p256_dh(&r, &gi).is_ok_and(|s| s[..] == secret[..]);
    // RFC 7748 §5.2, first vector, and §6.1 (Alice's public key, the
    // shared secret).
    let (Some(k), Some(u), Some(want)) = (
        h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        h32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ) else {
        return false;
    };
    let (Some(a), Some(pb), Some(pa), Some(shared)) = (
        h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
        h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
    ) else {
        return false;
    };
    p256_ok
        && super::kx::x25519(&k, &u) == want
        && super::kx::x25519_public(&a) == pa
        && super::kx::x25519(&a, &pb) == shared
}

/// The verification of signatures by one fixed trust anchor key (ADR-111,
/// ADR-130): a comb of the key on x86_64 (about 12 us), else primeorder's
/// fixed-base table (25 KiB). Built once, at configuration time; never from
/// peer input.
pub struct IssuerTable(Inner);

enum Inner {
    #[cfg(all(
        target_arch = "x86_64",
        not(miri),
        any(target_os = "linux", target_os = "none")
    ))]
    Nistz(nistz::KeyTable),
    Generic(alloc::boxed::Box<primeorder::BasepointTable<p256::ProjectivePoint, 33>>),
}

impl IssuerTable {
    /// The table of the key `point` (on the curve).
    pub fn from_key(point: &p256::AffinePoint) -> Self {
        #[cfg(all(
            target_arch = "x86_64",
            not(miri),
            any(target_os = "linux", target_os = "none")
        ))]
        {
            use p256::elliptic_curve::sec1::ToSec1Point;
            let enc = point.to_sec1_point(false);
            if let Some((qx, qy)) = split_point(enc.as_bytes())
                && let Some(t) = nistz::KeyTable::new(nistz::Ops::detect(), &qx, &qy)
            {
                return Self(Inner::Nistz(t));
            }
        }
        Self::generic(point)
    }

    /// The portable table, whatever the target (tests compare the two).
    pub fn generic(point: &p256::AffinePoint) -> Self {
        Self(Inner::Generic(alloc::boxed::Box::new(
            primeorder::BasepointTable::from_point(point.into()),
        )))
    }

    /// ECDSA verification (SEC 1 §4.1.4, variable time: every input is
    /// public) of a DER signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use sha2::Digest;
        let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        match &self.0 {
            #[cfg(all(
                target_arch = "x86_64",
                not(miri),
                any(target_os = "linux", target_os = "none")
            ))]
            Inner::Nistz(t) => {
                let rs = sig.to_bytes();
                let (r, s) = rs.split_at(32);
                let z: [u8; 32] = sha2::Sha256::digest(message).into();
                let (r, s): (&[u8; 32], &[u8; 32]) = (
                    r.try_into().map_err(|_| InvalidSignature)?,
                    s.try_into().map_err(|_| InvalidSignature)?,
                );
                t.verify(nistz::Ops::detect(), &z, r, s)
                    .then_some(())
                    .ok_or(InvalidSignature)
            }
            Inner::Generic(table) => {
                use p256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
                use p256::elliptic_curve::point::AffineCoordinates;
                let (r, s) = sig.split_scalars();
                let z = <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&sha2::Sha256::digest(
                    message,
                ));
                let s_inv: p256::Scalar =
                    Option::from(s.invert_vartime()).ok_or(InvalidSignature)?;
                let u1 = z * s_inv;
                let u2 = *r * s_inv;
                let big_r =
                    p256::ProjectivePoint::mul_by_generator_vartime(&u1) + table.mul_vartime(&u2);
                let x = big_r.to_affine().x();
                if <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&x) == *r {
                    Ok(())
                } else {
                    Err(InvalidSignature)
                }
            }
        }
    }

    /// Whether the assembly comb is in use.
    pub fn is_fast(&self) -> bool {
        !matches!(self.0, Inner::Generic(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    fn key(rng: &mut ChaCha20Rng) -> p256::SecretKey {
        loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Ok(k) = p256::SecretKey::from_slice(&b) {
                return k;
            }
        }
    }

    #[test]
    fn signatures_are_the_stock_deterministic_signatures() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for i in 0..200 {
            let sk = p256::ecdsa::SigningKey::from(key(&mut rng));
            let mut msg = alloc::vec![0u8; (rng.next_u32() % 300) as usize];
            rng.fill_bytes(&mut msg);
            let stock: p256::ecdsa::DerSignature = sk.try_sign(&msg).unwrap();
            assert_eq!(ecdsa_sign(&sk, &msg).unwrap(), stock.as_bytes(), "case {i}");
        }
    }

    #[test]
    fn verification_matches_the_stock_verifier_on_good_and_bad_input() {
        use p256::ecdsa::signature::Verifier;
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        for _ in 0..100 {
            let sk = p256::ecdsa::SigningKey::from(key(&mut rng));
            let pk = sk.verifying_key().to_sec1_bytes();
            let mut msg = alloc::vec![0u8; 1 + (rng.next_u32() % 200) as usize];
            rng.fill_bytes(&mut msg);
            let sig = ecdsa_sign(&sk, &msg).unwrap();
            assert!(ecdsa_verify(&pk, &msg, &sig).is_ok());
            let mut m2 = msg.clone();
            m2[0] ^= 0x80;
            let mut s2 = sig.clone();
            let i = rng.next_u32() as usize % s2.len();
            s2[i] ^= 1 << (rng.next_u32() % 8);
            let mut bad_key = pk.to_vec();
            bad_key[40] ^= 1;
            for (k, m, s) in [
                (&pk[..], &m2, &sig),
                (&pk[..], &msg, &s2),
                (&bad_key[..], &msg, &sig),
            ] {
                let stock = p256::ecdsa::VerifyingKey::from_sec1_bytes(k)
                    .ok()
                    .zip(p256::ecdsa::DerSignature::try_from(s.as_slice()).ok())
                    .is_some_and(|(vk, sg)| vk.verify(m, &sg).is_ok());
                assert_eq!(ecdsa_verify(k, m, s).is_ok(), stock);
            }
            // A compressed key takes the portable path and still works.
            let compressed = sk.verifying_key().as_affine().to_sec1_point(true);
            assert!(ecdsa_verify(compressed.as_bytes(), &msg, &sig).is_ok());
        }
    }

    /// Both table kinds against the stock verifier, with valid, tampered and
    /// garbage signatures.
    #[test]
    fn issuer_tables_agree_with_the_stock_verifier() {
        use p256::ecdsa::signature::Verifier;
        let mut rng = ChaCha20Rng::seed_from_u64(14);
        for _ in 0..10 {
            let sk = p256::ecdsa::SigningKey::from(key(&mut rng));
            let vk = *sk.verifying_key();
            let tables = [
                IssuerTable::from_key(vk.as_affine()),
                IssuerTable::generic(vk.as_affine()),
            ];
            assert_eq!(tables[0].is_fast(), FAST);
            for _ in 0..8 {
                let mut msg = alloc::vec![0u8; (rng.next_u32() % 300) as usize];
                rng.fill_bytes(&mut msg);
                let good = ecdsa_sign(&sk, &msg).unwrap();
                let mut flipped = good.clone();
                let i = rng.next_u32() as usize % flipped.len();
                flipped[i] ^= 1 << (rng.next_u32() % 8);
                let mut garbage = alloc::vec![0u8; 70];
                rng.fill_bytes(&mut garbage);
                garbage[0] = 0x30;
                garbage[1] = 68;
                let mut longer = msg.clone();
                longer.extend_from_slice(&[1]);
                for (m, s) in [
                    (&msg, &good),
                    (&msg, &flipped),
                    (&msg, &garbage),
                    (&longer, &good),
                ] {
                    let stock = p256::ecdsa::DerSignature::try_from(s.as_slice())
                        .is_ok_and(|sg| vk.verify(m, &sg).is_ok());
                    for t in &tables {
                        assert_eq!(t.verify(m, s).is_ok(), stock);
                    }
                }
            }
        }
    }

    #[test]
    fn the_key_exchange_known_answers_hold() {
        assert!(kx_kat());
    }

    #[test]
    fn key_exchange_matches_the_stock_implementation() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        for _ in 0..100 {
            let a = key(&mut rng);
            let b = key(&mut rng);
            let stock_pub = a.public_key().to_sec1_point(false);
            assert_eq!(p256_public(&a)[..], *stock_pub.as_bytes());
            let pb = p256_public(&b);
            let want = a.diffie_hellman(&b.public_key());
            assert_eq!(
                p256_dh(&a, &pb).unwrap()[..],
                *want.raw_secret_bytes().as_slice()
            );
            let mut off = pb;
            off[64] ^= 1;
            assert!(p256_dh(&a, &off).is_err());
            assert!(p256_dh(&a, &pb[..64]).is_err());
            assert!(p256_dh(&a, &[2u8; 33]).is_err());
        }
    }
}
