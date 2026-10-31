//! A timed profile of the handshake primitives (X9).
//!
//! Runs on the host (`cargo run --release -p urmqtt-tls --example profile`)
//! and at every kernel boot, so the log of a real machine says where a full
//! TLS 1.3 + mutual TLS handshake spends its time, in microseconds. The
//! clock is passed in: this crate has no time source of its own.
//!
//! The handshake the server performs has these public-key steps: one key
//! share (X25519: base point multiplication and the shared secret), one
//! ECDSA signature (CertificateVerify) and two ECDSA verifications (the
//! client certificate against the CA and the client's CertificateVerify).
//! Around them: HKDF/HMAC-SHA-256 for the key schedule and a few KiB of
//! AEAD record work.

use alloc::vec;
use alloc::vec::Vec;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use hmac::{KeyInit as _, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use sha2::Digest;

/// Each measurement runs for about this long (at least [`MIN_ITERS`] times).
const WINDOW_NS: u64 = 20_000_000;
const MIN_ITERS: u64 = 3;

/// HMAC-SHA-256 calls in a handshake's key schedule and Finished MACs
/// (HKDF-Extract and Expand-Label calls of both directions, rounded up).
pub const HMACS_PER_HANDSHAKE: u64 = 48;
/// SHA-256 compression blocks in the transcript hashes (about 3 KiB of
/// handshake messages hashed, forked a few times).
pub const BLOCKS_PER_HANDSHAKE: u64 = 160;
/// AEAD KiB protected per handshake (the certificates, Finished).
pub const AEAD_KIB_PER_HANDSHAKE: u64 = 4;

/// Nanoseconds per operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Profile {
    pub x25519_base: u64,
    pub x25519_dh: u64,
    pub p256_base: u64,
    pub p256_dh: u64,
    pub ecdsa_sign: u64,
    pub ecdsa_verify: u64,
    /// Verification of a certificate signature by a registered trust anchor
    /// (fixed-base tables, ADR-111).
    pub ecdsa_verify_ca: u64,
    pub hmac_sha256: u64,
    pub sha256_block: u64,
    /// AES-128-GCM seal of 1 KiB.
    pub aes_gcm_kib: u64,
    /// ChaCha20-Poly1305 seal of 1 KiB.
    pub chacha_kib: u64,
}

impl Profile {
    /// Public-key part of one server-side handshake (X25519 key share,
    /// one signature, two verifications).
    pub fn public_key_ns(&self) -> u64 {
        self.x25519_base
            + self.x25519_dh
            + self.ecdsa_sign
            + self.ecdsa_verify
            + self.ecdsa_verify_ca
    }

    /// Hashing and record part of one server-side handshake.
    pub fn symmetric_ns(&self) -> u64 {
        HMACS_PER_HANDSHAKE * self.hmac_sha256
            + BLOCKS_PER_HANDSHAKE * self.sha256_block
            + AEAD_KIB_PER_HANDSHAKE * self.aes_gcm_kib
    }

    /// Estimated CPU time of one full handshake on the server.
    pub fn handshake_ns(&self) -> u64 {
        self.public_key_ns() + self.symmetric_ns()
    }

    /// Percent of the handshake spent in public-key math.
    pub fn public_key_percent(&self) -> u64 {
        self.public_key_ns() * 100 / self.handshake_ns().max(1)
    }
}

/// The calibrated budget is this many times the measured handshake cost.
pub const BUDGET_FACTOR: u64 = 10;
/// Lower bound of the calibrated handshake-step budget.
pub const BUDGET_FLOOR_MS: u32 = 50;
/// Upper bound of the calibrated budget: well below the one-second
/// stuck-core reset, so a handler that never returns still trips it.
pub const BUDGET_CAP_MS: u32 = 500;

/// The watchdog budget for one TLS handshake step (ADR-071): the configured
/// value if there is one, else [`BUDGET_FACTOR`] times the estimated cost of
/// a handshake, rounded up to whole milliseconds, within
/// [`BUDGET_FLOOR_MS`]..=[`BUDGET_CAP_MS`].
pub fn handshake_budget_ms(configured_ms: u32, handshake_ns: u64) -> u32 {
    if configured_ms != 0 {
        return configured_ms;
    }
    let ms = handshake_ns
        .saturating_mul(BUDGET_FACTOR)
        .div_ceil(1_000_000)
        .min(u64::from(BUDGET_CAP_MS));
    u32::try_from(ms)
        .unwrap_or(BUDGET_CAP_MS)
        .clamp(BUDGET_FLOOR_MS, BUDGET_CAP_MS)
}

fn time(now: fn() -> u64, f: &mut dyn FnMut()) -> u64 {
    f(); // warm up (lazy tables, caches)
    let t0 = now();
    let mut n = 0u64;
    loop {
        f();
        n += 1;
        let el = now().saturating_sub(t0);
        if el >= WINDOW_NS && n >= MIN_ITERS {
            return el / n;
        }
    }
}

/// Measures every primitive. `now` returns nanoseconds.
pub fn run(now: fn() -> u64) -> Profile {
    let mut p = Profile::default();
    let k = [0x42u8; 32];
    let base = x25519_dalek::X25519_BASEPOINT_BYTES;
    p.x25519_base = time(now, &mut || {
        core::hint::black_box(x25519_dalek::x25519(core::hint::black_box(k), base));
    });
    let other = x25519_dalek::x25519([0x17u8; 32], base);
    p.x25519_dh = time(now, &mut || {
        core::hint::black_box(x25519_dalek::x25519(core::hint::black_box(k), other));
    });

    if let (Ok(sk), Ok(sk2)) = (
        p256::SecretKey::from_slice(&[0x11u8; 32]),
        p256::SecretKey::from_slice(&[0x23u8; 32]),
    ) {
        p.p256_base = time(now, &mut || {
            core::hint::black_box(sk.public_key());
        });
        let pk2 = sk2.public_key();
        p.p256_dh = time(now, &mut || {
            core::hint::black_box(sk.diffie_hellman(&pk2).raw_secret_bytes());
        });
    }

    if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]) {
        let msg = [0xa5u8; 130]; // TLS 1.3 CertificateVerify content
        let vk = *sk.verifying_key();
        let sig: Result<p256::ecdsa::Signature, _> = sk.try_sign(&msg);
        p.ecdsa_sign = time(now, &mut || {
            let s: Result<p256::ecdsa::Signature, _> = sk.try_sign(&msg);
            core::hint::black_box(s.is_ok());
        });
        if let Ok(sig) = sig {
            p.ecdsa_verify = time(now, &mut || {
                core::hint::black_box(vk.verify(&msg, &sig).is_ok());
            });
            let issuer = crate::provider::MeasuredIssuer::new(&vk);
            let der = sig.to_der();
            p.ecdsa_verify_ca = time(now, &mut || {
                core::hint::black_box(issuer.verify(&msg, der.as_bytes()));
            });
        }
    }

    let hk = [7u8; 32];
    let hdata = [9u8; 40];
    p.hmac_sha256 = time(now, &mut || {
        if let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(&hk) {
            m.update(&hdata);
            core::hint::black_box(m.finalize().into_bytes());
        }
    });

    // 16 blocks hashed at once, reported per block.
    let blocks = vec![0x5au8; 64 * 16];
    p.sha256_block = time(now, &mut || {
        core::hint::black_box(sha2::Sha256::digest(&blocks));
    }) / 16;

    let mut buf: Vec<u8> = vec![0x5au8; 1024];
    let nonce = [3u8; 12];
    if let Ok(c) = aes_gcm::Aes128Gcm::new_from_slice(&[1u8; 16]) {
        p.aes_gcm_kib = time(now, &mut || {
            let _ = c.encrypt_in_place_detached((&nonce).into(), b"", &mut buf);
        });
    }
    if let Ok(c) = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&[2u8; 32]) {
        p.chacha_kib = time(now, &mut || {
            let _ = c.encrypt_in_place_detached((&nonce).into(), b"", &mut buf);
        });
    }
    p
}

impl core::fmt::Display for Profile {
    /// The boot-log line body, microseconds with one decimal.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (name, v) in [
            ("x25519-base", self.x25519_base),
            ("x25519-dh", self.x25519_dh),
            ("p256-base", self.p256_base),
            ("p256-dh", self.p256_dh),
            ("ecdsa-sign", self.ecdsa_sign),
            ("ecdsa-verify", self.ecdsa_verify),
            ("ecdsa-verify-ca", self.ecdsa_verify_ca),
            ("hmac-sha256", self.hmac_sha256),
            ("sha256-block", self.sha256_block),
            ("aes-gcm-1k", self.aes_gcm_kib),
            ("chacha-1k", self.chacha_kib),
        ] {
            write!(
                f,
                "{}{name}={}.{:02}us",
                if first { "" } else { " " },
                v / 1000,
                v % 1000 / 10
            )?;
            first = false;
        }
        let v = self.handshake_ns();
        write!(
            f,
            " => handshake~{}.{:02}us ({}% public-key)",
            v / 1000,
            v % 1000 / 10,
            self.public_key_percent()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_follows_the_cost_within_floor_and_cap() {
        // Fast CPU (0.7 ms): the floor.
        assert_eq!(handshake_budget_ms(0, 700_000), 50);
        // A slow machine, 11.6 ms per handshake (the VPS of the report): 116 ms.
        assert_eq!(handshake_budget_ms(0, 11_600_000), 116);
        // Rounds up.
        assert_eq!(handshake_budget_ms(0, 6_010_000), 61);
        // Absurdly slow (or a bad measurement): the cap.
        assert_eq!(handshake_budget_ms(0, 900_000_000), 500);
        assert_eq!(handshake_budget_ms(0, u64::MAX), 500);
        // Nothing measured: the floor, never zero.
        assert_eq!(handshake_budget_ms(0, 0), 50);
        // A configured value wins, whatever was measured.
        assert_eq!(handshake_budget_ms(30, 11_600_000), 30);
        assert_eq!(handshake_budget_ms(900, 0), 900);
    }

    #[test]
    fn profile_runs_and_adds_up() {
        fn now() -> u64 {
            use std::sync::OnceLock;
            static T0: OnceLock<std::time::Instant> = OnceLock::new();
            T0.get_or_init(std::time::Instant::now).elapsed().as_nanos() as u64
        }
        let p = run(now);
        assert!(p.ecdsa_verify > 0 && p.ecdsa_sign > 0 && p.x25519_dh > 0);
        assert_eq!(p.handshake_ns(), p.public_key_ns() + p.symmetric_ns());
        assert!(p.public_key_percent() <= 100);
        let line = alloc::format!("{p}");
        assert!(line.contains("ecdsa-verify=") && line.contains("% public-key"));
    }
}
