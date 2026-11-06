//! What a release says about its files: `SHA256SUMS` (the output of
//! `shasum -a 256`) and the minisign signature over it. The browser builder
//! and `urmqtt-config check-release` both use these functions, so the page and
//! the command line accept and refuse the same files.

use sha2::{Digest, Sha256};

use crate::minisign::{self, PublicKey, Verified};

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The lines of a `SHA256SUMS` file: file name and digest, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sums {
    pub entries: Vec<(String, [u8; 32])>,
}

impl Sums {
    /// Reads `<64 hex digits><space><space or *><name>` lines; blank lines
    /// are skipped, anything else is an error (a signed file that does not
    /// parse is not trusted).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                continue;
            }
            let bad = || format!("SHA256SUMS line {}: expected '<sha256>  <file>'", i + 1);
            let (digest, rest) = line.split_at_checked(64).ok_or_else(bad)?;
            let name = rest
                .strip_prefix("  ")
                .or_else(|| rest.strip_prefix(" *"))
                .ok_or_else(bad)?;
            let name = name.strip_prefix("./").unwrap_or(name);
            if name.is_empty() || name.contains('/') || name.contains('\\') {
                return Err(bad());
            }
            let mut d = [0u8; 32];
            for (k, byte) in d.iter_mut().enumerate() {
                let pair = digest.get(2 * k..2 * k + 2).ok_or_else(bad)?;
                *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
            }
            entries.push((name.to_owned(), d));
        }
        if entries.is_empty() {
            return Err("SHA256SUMS lists no file".into());
        }
        Ok(Self { entries })
    }

    /// The digest the sums give for `name`.
    pub fn get(&self, name: &str) -> Option<&[u8; 32]> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, d)| d)
    }

    /// Checks `data` against the digest listed for `name`; returns the digest.
    pub fn check(&self, name: &str, data: &[u8]) -> Result<[u8; 32], String> {
        let want = self
            .get(name)
            .ok_or_else(|| format!("SHA256SUMS does not list {name}"))?;
        let got = sha256(data);
        if &got == want {
            Ok(got)
        } else {
            Err(format!(
                "{name}: SHA-256 is {}, SHA256SUMS says {}",
                hex(&got),
                hex(want)
            ))
        }
    }
}

/// `SHA256SUMS` after its signature has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSums {
    pub sums: Sums,
    pub signature: Verified,
}

/// Verifies the minisign signature `sig` over `sums` with the public key
/// `pubkey` (the contents of `minisign.pub`), then parses the sums.
pub fn verify_sums(pubkey: &str, sums: &[u8], sig: &str) -> Result<SignedSums, String> {
    let pk = PublicKey::parse(pubkey)?;
    let signature = minisign::verify(&pk, sig, sums)?;
    let text = std::str::from_utf8(sums).map_err(|_| "SHA256SUMS is not valid UTF-8")?;
    Ok(SignedSums {
        sums: Sums::parse(text)?,
        signature,
    })
}

/// Like [`verify_sums`], with the key taken from `pubkeys` (the contents of
/// several `minisign.pub` files) by the key id the signature names. A key
/// rotation leaves old releases signed by the old key; this checks each
/// release against the key that signed it, and refuses a signature by a key
/// that is not in the list. Which tags a key may sign is the caller's rule
/// (keys/release-keys.json; the builder page and the mirror enforce it).
pub fn verify_sums_any(pubkeys: &[&str], sums: &[u8], sig: &str) -> Result<SignedSums, String> {
    let wanted = minisign::signature_key_id(sig)?;
    let mut known = Vec::new();
    for text in pubkeys {
        let pk = PublicKey::parse(text)?;
        if pk.key_id() == wanted {
            return verify_sums(text, sums, sig);
        }
        known.push(pk.key_id());
    }
    Err(format!(
        "the signature was made with key {wanted}, which is not one of the given keys ({})",
        if known.is_empty() {
            "none".to_owned()
        } else {
            known.join(", ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &str = include_str!("../../../keys/minisign-test-9229E05252D01F8E.pub");
    const SUMS: &[u8] = include_bytes!("../tests/fixtures/minisign/SHA256SUMS");
    const SIG: &str = include_str!("../tests/fixtures/minisign/SHA256SUMS.minisig");

    #[test]
    fn the_real_release_sums_parse_after_the_signature_verifies() {
        let s = verify_sums(PUB, SUMS, SIG).unwrap();
        assert_eq!(s.sums.entries.len(), 3);
        assert_eq!(
            hex(s.sums.get("urmqtt-dev-v0.1.0.iso").unwrap()),
            "09020f7062a62fe587ab363ae218beb21866ae780a7363f7cf92a06124a38f26"
        );
        assert!(s.sums.get("urmqtt-template-v0.1.0-universal.iso").is_none());
        // A file is checked against its line.
        assert!(
            s.sums
                .check("urmqtt-dev-v0.1.0.iso", b"not the iso")
                .is_err()
        );
        assert!(
            s.sums
                .check("nope", b"")
                .unwrap_err()
                .contains("does not list")
        );
        let tampered = [SUMS, b"\n"].concat();
        assert!(
            verify_sums(PUB, &tampered, SIG).is_err(),
            "the signature covers every byte"
        );
    }

    /// Another key with another id (the test key's bytes, its id changed).
    fn other_key() -> String {
        use base64ct::{Base64, Encoding};
        let line = PUB.lines().nth(1).unwrap();
        let mut raw = Base64::decode_vec(line).unwrap();
        raw[2] ^= 0x55;
        format!(
            "untrusted comment: another key\n{}\n",
            Base64::encode_string(&raw)
        )
    }

    #[test]
    fn the_key_is_picked_by_the_id_the_signature_names() {
        let other = other_key();
        // Either order: the test key is found by its id.
        for keys in [[PUB, other.as_str()], [other.as_str(), PUB]] {
            let s = verify_sums_any(&keys, SUMS, SIG).unwrap();
            assert_eq!(s.signature.key_id, "9229E05252D01F8E");
        }
        // A signature by a key that is not listed is refused, naming both.
        let e = verify_sums_any(&[other.as_str()], SUMS, SIG).unwrap_err();
        assert!(e.contains("made with key 9229E05252D01F8E"), "{e}");
        assert!(e.contains("not one of the given keys"), "{e}");
        assert!(
            verify_sums_any(&[], SUMS, SIG)
                .unwrap_err()
                .contains("none")
        );
        // The bytes are still checked by the chosen key.
        let tampered = [SUMS, b"\n"].concat();
        assert!(verify_sums_any(&[other.as_str(), PUB], &tampered, SIG).is_err());
        // A placeholder in place of a key is an error, not a skipped entry.
        assert!(verify_sums_any(&["REPLACE-WITH-THE-NEW-PUBLIC-KEY", PUB], SUMS, SIG).is_err());
    }

    #[test]
    fn sums_lines_are_parsed_strictly() {
        let d = "a".repeat(64);
        assert!(Sums::parse(&format!("{d}  x.iso\n")).is_ok());
        assert!(
            Sums::parse(&format!("{d} *x.iso\n")).is_ok(),
            "binary mode marker"
        );
        assert!(Sums::parse(&format!("{d}  ./x.iso\n")).is_ok());
        assert!(Sums::parse(&format!("{d}  x.iso\r\n\r\n")).is_ok());
        for bad in [
            "",
            "\n\n",
            &format!("{d} x.iso"),
            &format!("{d}x.iso"),
            &format!("{}  x.iso", "g".repeat(64)),
            &format!("{}  x.iso", "a".repeat(63)),
            &format!("{d}  "),
            &format!("{d}  ../x.iso"),
            &format!("{d}  dir/x.iso"),
        ] {
            assert!(Sums::parse(bad).is_err(), "{bad:?}");
        }
    }
}
