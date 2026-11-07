//! Password hashes for the plaintext MQTT listener (P1, ADR-229): PBKDF2 with
//! HMAC-SHA-256 (RFC 8018), a random salt per password and an iteration count
//! that is part of the stored text. The configuration holds only the hash;
//! the packer, the browser and the kernel use this one implementation, and
//! the kernel compares in constant time.
//!
//! Stored form (ASCII, no spaces):
//!
//! ```text
//! pbkdf2-sha256$<iterations>$<salt, hex>$<derived key, hex>
//! pbkdf2-sha256$10000$00112233445566778899aabbccddeeff$e5b0...(64 hex digits)
//! ```
//!
//! The salt is 16 to 32 bytes, the derived key 32 bytes, the iteration count
//! 1 000 to 200 000. The default is 100 000 (ADR-267; it was 10 000 before):
//! about 25 ms of one core per login under HVF on the test machine and an
//! estimated 50 ms on a VPS vCPU. The kernel computes a check in one go on a
//! data core, so the count is bounded by what a login may hold a core for,
//! not by OWASP's 600 000 for a web server's thread pool. A hash carries its
//! own count: hashes made with another count (10 000 included) keep working.
//! The kernel measures the cost at boot and sizes the login admission rate
//! and the watchdog's handshake budget to it.

use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SCHEME: &str = "pbkdf2-sha256";
pub const MIN_ITERATIONS: u32 = 1_000;
pub const MAX_ITERATIONS: u32 = 200_000;
/// What `urmqtt-config hash-password` and the builder page use (ADR-267).
pub const DEFAULT_ITERATIONS: u32 = 100_000;
pub const SALT_MIN: usize = 16;
pub const SALT_MAX: usize = 32;
pub const KEY_LEN: usize = 32;
/// The longest stored form: scheme, `$`, six digits, `$`, a 32-byte salt and a
/// 32-byte key in hex.
pub const MAX_ENCODED: usize = SCHEME.len() + 1 + 6 + 1 + 2 * SALT_MAX + 1 + 2 * KEY_LEN;
/// The longest password that can match. A longer one is hashed (cut) and
/// refused, so a huge password costs no more than a long one.
pub const MAX_PASSWORD: usize = 256;

/// Why a stored hash was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswdError {
    /// Not `pbkdf2-sha256$iterations$salt$key`.
    Syntax,
    /// A scheme other than `pbkdf2-sha256`.
    Scheme,
    /// Iterations outside [`MIN_ITERATIONS`]..=[`MAX_ITERATIONS`].
    Iterations,
    /// A salt that is not 16 to 32 bytes of hex.
    Salt,
    /// A key that is not 32 bytes of hex.
    Key,
}

impl PasswdError {
    pub const fn msg(self) -> &'static str {
        match self {
            Self::Syntax => {
                "must look like pbkdf2-sha256$<iterations>$<salt hex>$<key hex> (make one with `urmqtt-config hash-password` or the builder page)"
            }
            Self::Scheme => "unknown password hash scheme (only pbkdf2-sha256 is supported)",
            Self::Iterations => "iterations must be between 1000 and 200000",
            Self::Salt => "the salt must be 16 to 32 bytes written as hex",
            Self::Key => "the derived key must be 32 bytes written as hex",
        }
    }
}

impl fmt::Display for PasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg())
    }
}

/// HMAC-SHA-256 with the key schedule done once (RFC 2104).
struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            for (d, s) in k.iter_mut().zip(Sha256::digest(key).iter()) {
                *d = *s;
            }
        } else {
            for (d, s) in k.iter_mut().zip(key) {
                *d = *s;
            }
        }
        let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
        for ((i, o), b) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
            *i ^= *b;
            *o ^= *b;
        }
        let (mut inner, mut outer) = (Sha256::new(), Sha256::new());
        inner.update(ipad);
        outer.update(opad);
        Self { inner, outer }
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut i = self.inner.clone();
        for p in parts {
            i.update(p);
        }
        let mut o = self.outer.clone();
        o.update(i.finalize());
        let mut out = [0u8; 32];
        for (d, s) in out.iter_mut().zip(o.finalize().iter()) {
            *d = *s;
        }
        out
    }
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018 section 5.2) for one 32-byte block, which
/// is all a derived key of 32 bytes needs. `iterations` of 0 is treated as 1.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let h = Hmac::new(password);
    let mut u = h.mac(&[salt, &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..iterations {
        u = h.mac(&[&u]);
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    t
}

fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes hex into `out`, returning the byte count; `None` if it is not
/// hex, has an odd number of digits, or does not fit.
fn decode_hex(s: &str, out: &mut [u8]) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 || b.len() / 2 > out.len() {
        return None;
    }
    // The length is even, so there is no remainder.
    let (pairs, _) = b.as_chunks::<2>();
    for (d, [hi, lo]) in out.iter_mut().zip(pairs) {
        *d = unhex(*hi)? << 4 | unhex(*lo)?;
    }
    Some(b.len() / 2)
}

/// A stored password hash, parsed. The key is never shown by `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PasswordHash {
    iterations: u32,
    salt: [u8; SALT_MAX],
    salt_len: u8,
    key: [u8; KEY_LEN],
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PasswordHash({SCHEME}, {} iterations, {}-byte salt)",
            self.iterations, self.salt_len
        )
    }
}

impl PasswordHash {
    /// Parses the stored form.
    pub fn parse(s: &str) -> Result<Self, PasswdError> {
        let mut it = s.split('$');
        let scheme = it.next().ok_or(PasswdError::Syntax)?;
        let iterations = it.next().ok_or(PasswdError::Syntax)?;
        let salt = it.next().ok_or(PasswdError::Syntax)?;
        let key = it.next().ok_or(PasswdError::Syntax)?;
        if it.next().is_some() {
            return Err(PasswdError::Syntax);
        }
        if scheme != SCHEME {
            return Err(PasswdError::Scheme);
        }
        let digits = iterations.as_bytes();
        if digits.is_empty()
            || digits.len() > 6
            || !digits.iter().all(u8::is_ascii_digit)
            || digits.first() == Some(&b'0')
        {
            return Err(PasswdError::Iterations);
        }
        let iterations: u32 = iterations.parse().map_err(|_| PasswdError::Iterations)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(PasswdError::Iterations);
        }
        let mut salt_buf = [0u8; SALT_MAX];
        let salt_len = decode_hex(salt, &mut salt_buf).ok_or(PasswdError::Salt)?;
        if !(SALT_MIN..=SALT_MAX).contains(&salt_len) {
            return Err(PasswdError::Salt);
        }
        let mut key_buf = [0u8; KEY_LEN];
        if decode_hex(key, &mut key_buf) != Some(KEY_LEN) {
            return Err(PasswdError::Key);
        }
        Ok(Self {
            iterations,
            salt: salt_buf,
            salt_len: salt_len as u8,
            key: key_buf,
        })
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn salt(&self) -> &[u8] {
        self.salt.get(..usize::from(self.salt_len)).unwrap_or(&[])
    }

    /// Whether `password` is the one this hash was made from. The work done
    /// does not depend on the password (beyond its length up to
    /// [`MAX_PASSWORD`]) and the comparison is constant time.
    pub fn verify(&self, password: &[u8]) -> bool {
        let cut = password.get(..MAX_PASSWORD).unwrap_or(password);
        let derived = pbkdf2_hmac_sha256(cut, self.salt(), self.iterations);
        let same: bool = derived.ct_eq(&self.key).into();
        same && password.len() <= MAX_PASSWORD
    }

    /// A hash for a user that does not exist: verifying against it costs what
    /// a real verification costs, so the time does not say whether a user name
    /// is known. It never matches (the key is not the output of any password
    /// that fits [`MAX_PASSWORD`] with overwhelming probability, and the
    /// caller refuses the result regardless).
    pub fn decoy(iterations: u32) -> Self {
        Self {
            iterations: iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS),
            salt: [0x5a; SALT_MAX],
            salt_len: SALT_MIN as u8,
            key: [0xa5; KEY_LEN],
        }
    }
}

/// The stored text for a derived key: for tools (the packer, the browser, the
/// tests). `salt` must be 16 to 32 bytes and `iterations` in range.
#[cfg(any(test, feature = "alloc"))]
pub fn encode(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<alloc::string::String, PasswdError> {
    use alloc::string::String;
    use core::fmt::Write;
    if !(SALT_MIN..=SALT_MAX).contains(&salt.len()) {
        return Err(PasswdError::Salt);
    }
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(PasswdError::Iterations);
    }
    let key = pbkdf2_hmac_sha256(password, salt, iterations);
    let mut out = String::with_capacity(MAX_ENCODED);
    let _ = write!(out, "{SCHEME}${iterations}$");
    for b in salt {
        let _ = write!(out, "{b:02x}");
    }
    out.push('$');
    for b in &key {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 7914 section 11 (PBKDF2-HMAC-SHA-256), first 32 bytes.
    #[test]
    fn rfc_7914_vectors() {
        assert_eq!(
            hex(&pbkdf2_hmac_sha256(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert_eq!(
            hex(&pbkdf2_hmac_sha256(b"Password", b"NaCl", 80_000)),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }

    /// The widely published PBKDF2-HMAC-SHA-256 vectors (also what Python's
    /// `hashlib.pbkdf2_hmac` gives).
    #[test]
    fn published_vectors() {
        for (iters, want) in [
            (
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ] {
            assert_eq!(
                hex(&pbkdf2_hmac_sha256(b"password", b"salt", iters)),
                want,
                "{iters}"
            );
        }
    }

    /// A key longer than the block is hashed first (RFC 2104).
    #[test]
    fn long_keys_are_hashed_first() {
        let long = [0x61u8; 100];
        let hashed = Sha256::digest(long);
        assert_eq!(
            pbkdf2_hmac_sha256(&long, b"0123456789abcdef", 3),
            pbkdf2_hmac_sha256(&hashed, b"0123456789abcdef", 3)
        );
        // Exactly one block is used as it is.
        let block = [0x62u8; 64];
        let h = Hmac::new(&block);
        assert_eq!(h.mac(&[b"x"]), Hmac::new(&block).mac(&[b"x"]));
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        // key "Jefe", data "what do ya want for nothing?"
        let h = Hmac::new(b"Jefe");
        assert_eq!(
            hex(&h.mac(&[b"what do ya want ", b"for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    const SALT: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn encode_parse_verify_round_trip() {
        let s = encode(b"correct horse", &SALT, 1000).unwrap();
        assert!(s.starts_with("pbkdf2-sha256$1000$30313233343536373839616263646566$"));
        assert!(s.len() <= MAX_ENCODED);
        let h = PasswordHash::parse(&s).unwrap();
        assert_eq!(h.iterations(), 1000);
        assert_eq!(h.salt(), &SALT);
        assert!(h.verify(b"correct horse"));
        assert!(!h.verify(b"correct hors"));
        assert!(!h.verify(b"Correct horse"));
        assert!(!h.verify(b""));
        assert!(!h.verify(b" correct horse"));
        // (PBKDF2-HMAC pads a short key with zero bytes, RFC 2104, so a
        // password and the same password with NUL bytes appended derive the
        // same key. That is the algorithm, not this code; whoever knows the
        // password gains nothing from it.)
    }

    #[test]
    fn binary_and_long_passwords() {
        let pw: Vec<u8> = (0..=255u8).collect();
        let s = encode(&pw, &SALT, 1000).unwrap();
        let h = PasswordHash::parse(&s).unwrap();
        assert!(h.verify(&pw));
        // 256 bytes is the longest that can match.
        let ok = vec![7u8; MAX_PASSWORD];
        let h = PasswordHash::parse(&encode(&ok, &SALT, 1000).unwrap()).unwrap();
        assert!(h.verify(&ok));
        // A password that is the cut of a longer one does not match the longer.
        let longer = vec![7u8; MAX_PASSWORD + 1];
        assert!(!h.verify(&longer));
        let huge = vec![7u8; 70_000];
        assert!(!h.verify(&huge));
    }

    #[test]
    fn every_salt_and_iteration_changes_the_hash() {
        let a = encode(b"pw", &SALT, 1000).unwrap();
        let b = encode(b"pw", b"0123456789abcdeg", 1000).unwrap();
        let c = encode(b"pw", &SALT, 1001).unwrap();
        assert!(a != b && a != c && b != c);
        // The same inputs give the same text.
        assert_eq!(a, encode(b"pw", &SALT, 1000).unwrap());
    }

    #[test]
    fn the_stored_form_is_strict() {
        let good = encode(b"pw", &SALT, 1000).unwrap();
        assert!(PasswordHash::parse(&good).is_ok());
        let parts: Vec<&str> = good.split('$').collect();
        let with = |i: usize, v: &str| {
            let mut p = parts.clone();
            p[i] = v;
            p.join("$")
        };
        assert_eq!(PasswordHash::parse(""), Err(PasswdError::Syntax));
        assert_eq!(
            PasswordHash::parse("pbkdf2-sha256"),
            Err(PasswdError::Syntax)
        );
        assert_eq!(
            PasswordHash::parse(&format!("{good}$x")),
            Err(PasswdError::Syntax)
        );
        assert_eq!(
            PasswordHash::parse(&with(0, "pbkdf2-sha1")),
            Err(PasswdError::Scheme)
        );
        assert_eq!(
            PasswordHash::parse(&with(0, "PBKDF2-SHA256")),
            Err(PasswdError::Scheme)
        );
        for it in [
            "", "0", "999", "200001", "01000", "1e3", "+1000", "-1000", "1000000", "1 000",
        ] {
            assert_eq!(
                PasswordHash::parse(&with(1, it)),
                Err(PasswdError::Iterations),
                "{it:?}"
            );
        }
        for it in ["1000", "200000", "10000"] {
            assert!(PasswordHash::parse(&with(1, it)).is_ok(), "{it}");
        }
        assert_eq!(PasswordHash::parse(&with(2, "")), Err(PasswdError::Salt));
        assert_eq!(
            PasswordHash::parse(&with(2, &"ab".repeat(15))),
            Err(PasswdError::Salt)
        );
        assert_eq!(
            PasswordHash::parse(&with(2, &"ab".repeat(33))),
            Err(PasswdError::Salt)
        );
        assert_eq!(
            PasswordHash::parse(&with(2, &"ab".repeat(15).replace('a', "g"))),
            Err(PasswdError::Salt)
        );
        assert_eq!(
            PasswordHash::parse(&with(2, &format!("{}a", "ab".repeat(16)))),
            Err(PasswdError::Salt)
        );
        assert!(
            PasswordHash::parse(&with(2, &"AB".repeat(32))).is_ok(),
            "upper case hex, 32 bytes"
        );
        assert_eq!(
            PasswordHash::parse(&with(3, &"ab".repeat(31))),
            Err(PasswdError::Key)
        );
        assert_eq!(
            PasswordHash::parse(&with(3, &"zz".repeat(32))),
            Err(PasswdError::Key)
        );
        assert_eq!(
            PasswordHash::parse(&with(3, &"ab".repeat(33))),
            Err(PasswdError::Key)
        );
    }

    #[test]
    fn encode_refuses_out_of_range_parameters() {
        assert_eq!(encode(b"x", &SALT, 999), Err(PasswdError::Iterations));
        assert_eq!(encode(b"x", &SALT, 200_001), Err(PasswdError::Iterations));
        assert_eq!(encode(b"x", &SALT[..15], 1000), Err(PasswdError::Salt));
        assert_eq!(encode(b"x", &[0u8; 33], 1000), Err(PasswdError::Salt));
        assert!(encode(b"x", &[0u8; 32], 200_000).is_ok());
    }

    #[test]
    fn the_decoy_costs_the_same_and_never_matches() {
        let d = PasswordHash::decoy(5000);
        assert_eq!(d.iterations(), 5000);
        assert!(!d.verify(b""));
        assert!(!d.verify(b"password"));
        assert_eq!(PasswordHash::decoy(1).iterations(), MIN_ITERATIONS);
        assert_eq!(PasswordHash::decoy(u32::MAX).iterations(), MAX_ITERATIONS);
    }

    /// ADR-267: raising the default changes nothing for a hash made before.
    /// This one was made with the old default (10 000) by Python's
    /// `hashlib.pbkdf2_hmac`, independently of this code.
    #[test]
    fn a_hash_made_with_the_old_default_still_verifies() {
        const OLD: &str = "pbkdf2-sha256$10000$00112233445566778899aabbccddeeff$\
            6f4a42faddac7256d234a1910b2ab79d90a4f16c0a7f9f566cbefb34dbbe894b";
        assert_ne!(DEFAULT_ITERATIONS, 10_000);
        let h = PasswordHash::parse(OLD).unwrap();
        assert_eq!(h.iterations(), 10_000, "the count comes from the text");
        assert!(h.verify(b"sensor-1 old password"));
        assert!(!h.verify(b"sensor-1 old passwore"));
        // A new hash of the same password differs only by its count (and
        // its salt), and both verify.
        let new = encode(b"sensor-1 old password", h.salt(), DEFAULT_ITERATIONS).unwrap();
        assert!(new.starts_with("pbkdf2-sha256$100000$00112233445566778899aabbccddeeff$"));
        assert!(
            PasswordHash::parse(&new)
                .unwrap()
                .verify(b"sensor-1 old password")
        );
    }

    #[test]
    fn debug_never_shows_the_key() {
        let h = PasswordHash::parse(&encode(b"pw", &SALT, 1000).unwrap()).unwrap();
        let shown = format!("{h:?}");
        assert!(shown.contains("1000 iterations"));
        assert!(!shown.contains(&hex(&h.key)));
    }
}
