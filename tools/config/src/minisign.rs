//! Verifying minisign signatures (<https://jedisct1.github.io/minisign/>), the
//! signature on a release's `SHA256SUMS`. The web builder runs this in the
//! browser against the public key embedded in the page, and `urmqtt-config
//! check-release` runs it offline, so a customer needs no minisign binary.
//!
//! File formats (all base64 is standard, padded):
//!
//! ```text
//! minisign.pub:   untrusted comment: minisign public key 9229E05252D01F8E
//!                 base64( "Ed" ‖ key id (8) ‖ Ed25519 public key (32) )
//! SHA256SUMS.minisig:
//!                 untrusted comment: <text>
//!                 base64( "ED" or "Ed" ‖ key id (8) ‖ signature (64) )
//!                 trusted comment: <text>
//!                 base64( global signature (64) )
//! ```
//!
//! `ED` signs the BLAKE2b-512 of the file (what `minisign -S` writes), `Ed`
//! the file itself (legacy). The global signature covers the file signature
//! followed by the trusted comment, so the comment cannot be swapped.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, VerifyingKey};
use urmqtt_cfg::blake2b;

/// A minisign public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The key id as stored (little-endian on screen: see [`Self::key_id`]).
    pub id: [u8; 8],
    pub key: [u8; 32],
}

/// What a good signature says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub key_id: String,
    /// `true` for the `ED` (pre-hashed) algorithm `minisign -S` writes.
    pub prehashed: bool,
    pub untrusted_comment: String,
    /// Covered by the signature.
    pub trusted_comment: String,
}

fn decode(line: &str, what: &str) -> Result<Vec<u8>, String> {
    Base64::decode_vec(line.trim()).map_err(|_| format!("{what}: not valid base64"))
}

/// The key id as minisign prints it: the eight bytes in reverse, upper-case hex.
fn id_text(id: &[u8; 8]) -> String {
    id.iter().rev().map(|b| format!("{b:02X}")).collect()
}

impl PublicKey {
    /// Parses a `minisign.pub` file; the bare base64 line is accepted too.
    pub fn parse(text: &str) -> Result<Self, String> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or("public key: no key line")?;
        let raw = decode(line, "public key")?;
        if raw.len() != 42 || raw.get(..2) != Some(b"Ed") {
            return Err("public key: not a minisign Ed25519 public key (42 bytes, 'Ed')".into());
        }
        let id: [u8; 8] = raw
            .get(2..10)
            .and_then(|b| b.try_into().ok())
            .ok_or("public key: truncated")?;
        let key: [u8; 32] = raw
            .get(10..)
            .and_then(|b| b.try_into().ok())
            .ok_or("public key: truncated")?;
        Ok(Self { id, key })
    }

    /// The key id as minisign prints it (`9229E05252D01F8E`).
    pub fn key_id(&self) -> String {
        id_text(&self.id)
    }
}

/// The key id a `.minisig` file names on its second line, as minisign prints
/// it. Nothing is verified: this only says which public key to try (a key
/// ring holds the old and the new release key during a rotation).
pub fn signature_key_id(sig_text: &str) -> Result<String, String> {
    let line = sig_text
        .lines()
        .nth(1)
        .ok_or("signature file: expected four lines")?;
    let raw = decode(line.trim_end_matches('\r'), "signature")?;
    if raw.len() != 74 {
        return Err("signature: wrong length (74 bytes expected)".into());
    }
    let id: [u8; 8] = raw
        .get(2..10)
        .and_then(|b| b.try_into().ok())
        .ok_or("signature: truncated")?;
    Ok(id_text(&id))
}

/// Verifies `sig_text` (the contents of a `.minisig` file) over `message`
/// (the file that was signed) against `pk`.
pub fn verify(pk: &PublicKey, sig_text: &str, message: &[u8]) -> Result<Verified, String> {
    let lines: Vec<&str> = sig_text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let [first, sig_line, comment_line, global_line, ..] = lines.as_slice() else {
        return Err("signature file: expected four lines".into());
    };
    let untrusted = first
        .strip_prefix("untrusted comment:")
        .ok_or("signature file: the first line must start with 'untrusted comment:'")?
        .trim_start()
        .to_owned();
    let trusted = comment_line
        .strip_prefix("trusted comment:")
        .ok_or("signature file: the third line must start with 'trusted comment:'")?
        .trim_start()
        .to_owned();
    let raw = decode(sig_line, "signature")?;
    if raw.len() != 74 {
        return Err("signature: wrong length (74 bytes expected)".into());
    }
    let prehashed = match raw.get(..2) {
        Some(b"ED") => true,
        Some(b"Ed") => false,
        _ => return Err("signature: unknown algorithm (only Ed25519, 'ED' or 'Ed')".into()),
    };
    let id: [u8; 8] = raw
        .get(2..10)
        .and_then(|b| b.try_into().ok())
        .ok_or("signature: truncated")?;
    if id != pk.id {
        return Err(format!(
            "signature was made with key {}, not with the expected key {}",
            id_text(&id),
            pk.key_id()
        ));
    }
    let sig_bytes: [u8; 64] = raw
        .get(10..)
        .and_then(|b| b.try_into().ok())
        .ok_or("signature: truncated")?;
    let key = VerifyingKey::from_bytes(&pk.key).map_err(|_| "public key: not a valid point")?;
    let signed: Vec<u8> = if prehashed {
        blake2b::hash(message).to_vec()
    } else {
        message.to_vec()
    };
    key.verify_strict(&signed, &Signature::from_bytes(&sig_bytes))
        .map_err(
            |_| "the signature does not match the file (it was changed, or signed by another key)",
        )?;
    let global = decode(global_line, "global signature")?;
    let global: [u8; 64] = global
        .as_slice()
        .try_into()
        .map_err(|_| "global signature: wrong length (64 bytes expected)")?;
    let mut covered = sig_bytes.to_vec();
    covered.extend_from_slice(trusted.as_bytes());
    key.verify_strict(&covered, &Signature::from_bytes(&global))
        .map_err(|_| "the trusted comment does not match its signature")?;
    Ok(Verified {
        key_id: id_text(&id),
        prehashed,
        untrusted_comment: untrusted,
        trusted_comment: trusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The project's former test key (it signed v0.1.0 to v0.4.1) and the real
    // signature of the v0.1.0 SHA256SUMS (public data, fetched from the GitHub release).
    const PUB: &str = include_str!("../../../keys/minisign-test-9229E05252D01F8E.pub");
    const SUMS: &[u8] = include_bytes!("../tests/fixtures/minisign/SHA256SUMS");
    const SIG: &str = include_str!("../tests/fixtures/minisign/SHA256SUMS.minisig");

    #[test]
    fn the_real_v0_1_0_signature_verifies() {
        let pk = PublicKey::parse(PUB).unwrap();
        assert_eq!(pk.key_id(), "9229E05252D01F8E");
        let v = verify(&pk, SIG, SUMS).unwrap();
        assert_eq!(v.key_id, "9229E05252D01F8E");
        assert!(v.prehashed);
        assert_eq!(
            v.trusted_comment,
            "urMQTT v0.1.0 dev bf311aa0810a7ad2b31e4dc911cb45d8131c350c"
        );
    }

    #[test]
    fn a_changed_file_comment_key_or_signature_is_refused() {
        let pk = PublicKey::parse(PUB).unwrap();
        let mut sums = SUMS.to_vec();
        sums[0] ^= 1;
        assert!(
            verify(&pk, SIG, &sums)
                .unwrap_err()
                .contains("does not match the file")
        );
        // Another trusted comment.
        let swapped = SIG.replace("v0.1.0 dev", "v9.9.9 dev");
        assert!(
            verify(&pk, &swapped, SUMS)
                .unwrap_err()
                .contains("trusted comment")
        );
        // Another key.
        let mut other = pk.clone();
        other.id[0] ^= 1;
        assert!(
            verify(&other, SIG, SUMS)
                .unwrap_err()
                .contains("expected key")
        );
        let mut other = pk.clone();
        other.key[0] ^= 1;
        assert!(verify(&other, SIG, SUMS).is_err());
        // One bit of the signature itself.
        let mut lines: Vec<String> = SIG.lines().map(str::to_owned).collect();
        let mut raw = Base64::decode_vec(&lines[1]).unwrap();
        raw[20] ^= 1;
        lines[1] = Base64::encode_string(&raw);
        assert!(verify(&pk, &lines.join("\n"), SUMS).is_err());
        // Truncated or malformed files.
        assert!(verify(&pk, "", SUMS).is_err());
        assert!(verify(&pk, "untrusted comment: x\n!!!\n", SUMS).is_err());
        assert!(PublicKey::parse("untrusted comment: x\n").is_err());
        assert!(PublicKey::parse("RWSOH9BS").is_err());
    }

    #[test]
    fn the_signature_names_its_key_id() {
        assert_eq!(signature_key_id(SIG).unwrap(), "9229E05252D01F8E");
        assert_eq!(
            signature_key_id(&SIG.replace('\n', "\r\n")).unwrap(),
            "9229E05252D01F8E"
        );
        assert!(signature_key_id("").is_err());
        assert!(signature_key_id("untrusted comment: x\n!!!\n").is_err());
        assert!(signature_key_id("untrusted comment: x\nRWSOH9BS\n").is_err());
    }

    #[test]
    fn crlf_line_ends_are_accepted() {
        let pk = PublicKey::parse(PUB).unwrap();
        let crlf = SIG.replace('\n', "\r\n");
        assert!(verify(&pk, &crlf, SUMS).is_ok());
    }
}
