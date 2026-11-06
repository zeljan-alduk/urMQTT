//! The release key ring, `keys/release-keys.json` (ROADMAP NOW-2,
//! docs/release-key-rotation.md): the minisign public keys that sign urMQTT
//! releases, each for a range of tags, and for the former test key the
//! SHA-256 of every `SHA256SUMS` it signed (`pinned`). The builder page and the
//! release mirror apply the same rules; `urmqtt-config check-release
//! --keyring ... --tag ...` applies these.
//!
//! The rules, for a release tag, its `SHA256SUMS` and its signature:
//! 1. the key is the one the signature names (key id); unknown: refused;
//! 2. the tag must be in the key's range (`valid_from` to `valid_to`);
//! 3. a key with `pinned` signs only the tags listed there, and only the
//!    `SHA256SUMS` whose SHA-256 is the pinned one (a forged file signed with
//!    a leaked key, labelled with an old tag, is refused);
//! 4. the signature must verify.
//!
//! The ring is parsed by a small strict JSON reader (this crate has no JSON
//! dependency, and the ring is the trust anchor: anything unexpected is an error).

use std::collections::BTreeMap;

use crate::minisign::{self, PublicKey};
use crate::release::{self, SignedSums};

/// One key of the ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingKey {
    pub name: String,
    /// The key file, relative to the ring (as written in the ring).
    pub file: String,
    pub public: PublicKey,
    /// The contents of the key file.
    pub text: String,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub former_test_key: bool,
    /// Tag -> SHA-256 of its `SHA256SUMS`. Empty: no pins.
    pub pinned: BTreeMap<String, [u8; 32]>,
}

/// What a check by the ring found.
#[derive(Debug, Clone)]
pub struct RingVerified {
    pub signed: SignedSums,
    pub key: RingKey,
    /// The tag had a pin and the `SHA256SUMS` matched it.
    pub pinned: bool,
}

/// `v1.2.3` (also `1.2.3`, `v1.2.3-rc.1`) as (1, 2, 3).
pub fn tag_version(tag: &str) -> Option<(u32, u32, u32)> {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    let core = t.split(['-', '+']).next()?;
    let suffix = &t[core.len()..];
    if !suffix.is_empty()
        && !suffix[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
    {
        return None;
    }
    let mut parts = core.split('.');
    let mut num = || -> Option<u32> {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let v = (num()?, num()?, num()?);
    parts.next().is_none().then_some(v)
}

impl RingKey {
    /// May this key sign `tag` (its range only; pins are checked separately)?
    pub fn covers(&self, tag: &str) -> bool {
        if self.valid_from.is_none() && self.valid_to.is_none() {
            return true;
        }
        let Some(v) = tag_version(tag) else {
            return false;
        };
        let low = self.valid_from.as_deref().and_then(tag_version);
        let high = self.valid_to.as_deref().and_then(tag_version);
        low.is_none_or(|l| v >= l) && high.is_none_or(|h| v <= h)
    }

    pub fn range_text(&self) -> String {
        match (&self.valid_from, &self.valid_to) {
            (Some(f), Some(t)) => format!("{f} to {t}"),
            (Some(f), None) => format!("{f} and later"),
            (None, Some(t)) => format!("up to {t}"),
            (None, None) => "any tag".into(),
        }
    }
}

/// Parses a key ring. `read(file)` returns the contents of a key file the
/// ring names (relative to the ring). A key file that is still the placeholder
/// is an error.
pub fn parse(
    text: &str,
    read: &mut dyn FnMut(&str) -> Result<String, String>,
) -> Result<Vec<RingKey>, String> {
    let doc = json::parse(text).map_err(|e| format!("key ring: {e}"))?;
    let obj = doc.as_object().ok_or("key ring: not a JSON object")?;
    if obj.get("schema").and_then(json::Value::as_number) != Some(1.0) {
        return Err("key ring: schema must be 1".into());
    }
    let list = obj
        .get("keys")
        .and_then(json::Value::as_array)
        .filter(|l| !l.is_empty())
        .ok_or("key ring: no keys")?;
    let mut keys: Vec<RingKey> = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let n = i + 1;
        let e = entry
            .as_object()
            .ok_or(format!("key ring, key {n}: not an object"))?;
        for k in e.keys() {
            if ![
                "name",
                "file",
                "key_id",
                "valid_from",
                "valid_to",
                "former_test_key",
                "note",
                "pinned",
            ]
            .contains(&k.as_str())
            {
                return Err(format!("key ring, key {n}: unknown field {k}"));
            }
        }
        let s = |k: &str| e.get(k).and_then(json::Value::as_str).map(str::to_owned);
        let opt_tag = |k: &str| -> Result<Option<String>, String> {
            match e.get(k) {
                None | Some(json::Value::Null) => Ok(None),
                Some(json::Value::String(t)) if tag_version(t).is_some() => Ok(Some(t.clone())),
                _ => Err(format!(
                    "key ring, key {n}: {k} must be a version tag or null"
                )),
            }
        };
        let name = s("name").ok_or(format!("key ring, key {n}: no name"))?;
        let file = s("file").ok_or(format!("key ring, key {n}: no file"))?;
        let (valid_from, valid_to) = (opt_tag("valid_from")?, opt_tag("valid_to")?);
        if let (Some(f), Some(t)) = (&valid_from, &valid_to)
            && tag_version(f) > tag_version(t)
        {
            return Err(format!(
                "key ring, key {name}: valid_from is after valid_to"
            ));
        }
        let former_test_key = match e.get("former_test_key") {
            None => false,
            Some(json::Value::Bool(b)) => *b,
            _ => {
                return Err(format!(
                    "key ring, key {name}: former_test_key must be a boolean"
                ));
            }
        };
        let mut pinned = BTreeMap::new();
        match e.get("pinned") {
            None | Some(json::Value::Null) => {}
            Some(json::Value::Object(m)) => {
                for (tag, v) in m {
                    let hexs = v
                        .as_str()
                        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                        .ok_or(format!(
                            "key ring, key {name}: pin of {tag} is not 64 hex digits"
                        ))?;
                    let mut d = [0u8; 32];
                    for (k, b) in d.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&hexs[2 * k..2 * k + 2], 16)
                            .map_err(|_| format!("key ring, key {name}: bad pin of {tag}"))?;
                    }
                    pinned.insert(tag.clone(), d);
                }
            }
            _ => return Err(format!("key ring, key {name}: pinned must be an object")),
        }
        let text = read(&file)?;
        if text.contains("REPLACE-WITH-THE-NEW-PUBLIC-KEY") {
            return Err(format!(
                "key ring, key {name}: {file} is still the placeholder (docs/release-key-rotation.md)"
            ));
        }
        let public = PublicKey::parse(&text).map_err(|m| format!("{file}: {m}"))?;
        if let Some(id) = s("key_id")
            && id != public.key_id()
        {
            return Err(format!(
                "key ring, key {name}: {file} has key id {}, the ring says {id}",
                public.key_id()
            ));
        }
        if keys.iter().any(|k| k.public.id == public.id) {
            return Err(format!("key ring: key {} is listed twice", public.key_id()));
        }
        keys.push(RingKey {
            name,
            file,
            public,
            text,
            valid_from,
            valid_to,
            former_test_key,
            pinned,
        });
    }
    Ok(keys)
}

/// Checks a release (`tag`, its `SHA256SUMS` bytes and signature) by the
/// rules of the module documentation.
pub fn verify(keys: &[RingKey], tag: &str, sums: &[u8], sig: &str) -> Result<RingVerified, String> {
    let id = minisign::signature_key_id(sig)?;
    let key = keys
        .iter()
        .find(|k| k.public.key_id() == id)
        .ok_or_else(|| {
            format!(
                "the signature was made with key {id}, which is not in the key ring ({})",
                keys.iter()
                    .map(|k| format!("{} ({})", k.public.key_id(), k.name))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let what = if key.former_test_key {
        "the project's former test key".to_owned()
    } else {
        format!("the {} key", key.name)
    };
    if !key.covers(tag) {
        return Err(format!(
            "key {id} ({what}) may sign {} only, not {tag}",
            key.range_text()
        ));
    }
    let pinned = !key.pinned.is_empty();
    if pinned {
        let want = key.pinned.get(tag).ok_or_else(|| {
            format!(
                "key {id} ({what}) signs only the pinned releases, and {tag} is not one of them"
            )
        })?;
        let got = release::sha256(sums);
        if &got != want {
            return Err(format!(
                "SHA256SUMS of {tag} has SHA-256 {}, but the key ring pins {} for it (a file signed with {what} that is not the published one)",
                release::hex(&got),
                release::hex(want)
            ));
        }
    }
    let signed = release::verify_sums(&key.text, sums, sig)?;
    Ok(RingVerified {
        signed,
        key: key.clone(),
        pinned,
    })
}

/// A small strict JSON reader: objects, arrays, strings (with escapes),
/// numbers, booleans, null. Duplicate object keys are an error.
mod json {
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Value>),
        Object(BTreeMap<String, Value>),
    }

    impl Value {
        pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
            if let Value::Object(m) = self {
                Some(m)
            } else {
                None
            }
        }
        pub fn as_array(&self) -> Option<&Vec<Value>> {
            if let Value::Array(a) = self {
                Some(a)
            } else {
                None
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            if let Value::String(s) = self {
                Some(s)
            } else {
                None
            }
        }
        pub fn as_number(&self) -> Option<f64> {
            if let Value::Number(n) = self {
                Some(*n)
            } else {
                None
            }
        }
    }

    pub fn parse(text: &str) -> Result<Value, String> {
        let mut p = Parser {
            b: text.as_bytes(),
            i: 0,
            depth: 0,
        };
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing characters at byte {}", p.i));
        }
        Ok(v)
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
        depth: u32,
    }

    impl Parser<'_> {
        fn ws(&mut self) {
            while self.b.get(self.i).is_some_and(|c| b" \t\r\n".contains(c)) {
                self.i += 1;
            }
        }
        fn err<T>(&self, what: &str) -> Result<T, String> {
            Err(format!("{what} at byte {}", self.i))
        }
        fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
            if self.b[self.i..].starts_with(word.as_bytes()) {
                self.i += word.len();
                Ok(v)
            } else {
                self.err("unexpected token")
            }
        }
        fn value(&mut self) -> Result<Value, String> {
            self.ws();
            match self.b.get(self.i) {
                None => self.err("unexpected end"),
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => Ok(Value::String(self.string()?)),
                Some(b't') => self.lit("true", Value::Bool(true)),
                Some(b'f') => self.lit("false", Value::Bool(false)),
                Some(b'n') => self.lit("null", Value::Null),
                Some(_) => self.number(),
            }
        }
        fn enter(&mut self) -> Result<(), String> {
            self.depth += 1;
            if self.depth > 32 {
                self.err("nested too deeply")
            } else {
                Ok(())
            }
        }
        fn object(&mut self) -> Result<Value, String> {
            self.enter()?;
            self.i += 1;
            let mut m = BTreeMap::new();
            self.ws();
            if self.b.get(self.i) == Some(&b'}') {
                self.i += 1;
                self.depth -= 1;
                return Ok(Value::Object(m));
            }
            loop {
                self.ws();
                if self.b.get(self.i) != Some(&b'"') {
                    return self.err("expected a key");
                }
                let k = self.string()?;
                self.ws();
                if self.b.get(self.i) != Some(&b':') {
                    return self.err("expected ':'");
                }
                self.i += 1;
                let v = self.value()?;
                if m.insert(k.clone(), v).is_some() {
                    return Err(format!("duplicate key {k:?}"));
                }
                self.ws();
                match self.b.get(self.i) {
                    Some(b',') => self.i += 1,
                    Some(b'}') => {
                        self.i += 1;
                        self.depth -= 1;
                        return Ok(Value::Object(m));
                    }
                    _ => return self.err("expected ',' or '}'"),
                }
            }
        }
        fn array(&mut self) -> Result<Value, String> {
            self.enter()?;
            self.i += 1;
            let mut a = Vec::new();
            self.ws();
            if self.b.get(self.i) == Some(&b']') {
                self.i += 1;
                self.depth -= 1;
                return Ok(Value::Array(a));
            }
            loop {
                a.push(self.value()?);
                self.ws();
                match self.b.get(self.i) {
                    Some(b',') => self.i += 1,
                    Some(b']') => {
                        self.i += 1;
                        self.depth -= 1;
                        return Ok(Value::Array(a));
                    }
                    _ => return self.err("expected ',' or ']'"),
                }
            }
        }
        fn string(&mut self) -> Result<String, String> {
            self.i += 1;
            let mut out = String::new();
            loop {
                let rest = std::str::from_utf8(&self.b[self.i..]).map_err(|_| "not UTF-8")?;
                let mut chars = rest.char_indices();
                let Some((_, c)) = chars.next() else {
                    return self.err("unterminated string");
                };
                self.i += c.len_utf8();
                match c {
                    '"' => return Ok(out),
                    '\\' => {
                        let Some(&e) = self.b.get(self.i) else {
                            return self.err("unterminated escape");
                        };
                        self.i += 1;
                        out.push(match e {
                            b'"' => '"',
                            b'\\' => '\\',
                            b'/' => '/',
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let h = self
                                    .b
                                    .get(self.i..self.i + 4)
                                    .and_then(|h| std::str::from_utf8(h).ok())
                                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                                    .and_then(char::from_u32);
                                self.i += 4;
                                match h {
                                    Some(c) => c,
                                    None => return self.err("unsupported \\u escape"),
                                }
                            }
                            _ => return self.err("bad escape"),
                        });
                    }
                    c if (c as u32) < 0x20 => return self.err("control character in string"),
                    c => out.push(c),
                }
            }
        }
        fn number(&mut self) -> Result<Value, String> {
            let start = self.i;
            while self
                .b
                .get(self.i)
                .is_some_and(|c| c.is_ascii_digit() || b"+-.eE".contains(c))
            {
                self.i += 1;
            }
            std::str::from_utf8(&self.b[start..self.i])
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
                .map(Value::Number)
                .ok_or_else(|| format!("bad number at byte {start}"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strict_json() {
            let v = parse(r#" {"a": [1, true, null, "x\"A"], "b": {}} "#).unwrap();
            let m = v.as_object().unwrap();
            assert_eq!(m["a"].as_array().unwrap()[3].as_str(), Some("x\"A"));
            for bad in [
                "",
                "{",
                r#"{"a":1,}"#,
                r#"{"a":1,"a":2}"#,
                "[1 2]",
                "{} x",
                r#"{"a":nul}"#,
                "\"\u{1}\"",
            ] {
                assert!(parse(bad).is_err(), "{bad:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    use ed25519_dalek::{Signer, SigningKey};

    const RING: &str = include_str!("../../../keys/release-keys.json");
    const TEST_KEY: &str = include_str!("../../../keys/minisign-test-9229E05252D01F8E.pub");
    // The real v0.1.0 SHA256SUMS and its signature by the former test key.
    const SUMS: &[u8] = include_bytes!("../tests/fixtures/minisign/SHA256SUMS");
    const SIG: &str = include_str!("../tests/fixtures/minisign/SHA256SUMS.minisig");

    /// A throwaway minisign key: (public key file, signer).
    fn throwaway(seed: u8, id: [u8; 8]) -> (String, impl Fn(&[u8], &str) -> String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = [b"Ed".as_slice(), &id, sk.verifying_key().as_bytes()].concat();
        let public = format!(
            "untrusted comment: throwaway\n{}\n",
            Base64::encode_string(&pk)
        );
        let sign = move |msg: &[u8], comment: &str| {
            let sig = sk.sign(&urmqtt_cfg::blake2b::hash(msg)).to_bytes();
            let global = sk
                .sign(&[sig.as_slice(), comment.as_bytes()].concat())
                .to_bytes();
            format!(
                "untrusted comment: x\n{}\ntrusted comment: {comment}\n{}\n",
                Base64::encode_string(&[b"ED".as_slice(), &id, &sig].concat()),
                Base64::encode_string(&global)
            )
        };
        (public, sign)
    }

    /// The repository ring, with the placeholder release key replaced by `release`.
    fn repo_ring(release: &str) -> Vec<RingKey> {
        parse(RING, &mut |f| match f {
            "../minisign.pub" => Ok(release.to_owned()),
            "minisign-test-9229E05252D01F8E.pub" => Ok(TEST_KEY.to_owned()),
            _ => Err(format!("no {f}")),
        })
        .unwrap()
    }

    #[test]
    fn the_repository_ring_pins_every_test_key_release() {
        let (release, _) = throwaway(1, [1; 8]);
        let ring = repo_ring(&release);
        let test = ring.iter().find(|k| k.former_test_key).unwrap();
        assert_eq!(test.public.key_id(), "9229E05252D01F8E");
        assert_eq!(
            test.pinned.keys().map(String::as_str).collect::<Vec<_>>(),
            ["v0.1.0", "v0.2.0", "v0.2.1", "v0.3.0", "v0.4.0", "v0.4.1"]
        );
        // Every pinned tag is inside the key's range.
        assert!(test.pinned.keys().all(|t| test.covers(t)));
        assert!(
            ring.iter()
                .find(|k| k.name == "release")
                .unwrap()
                .pinned
                .is_empty(),
            "the new key has no pins"
        );
        // The real placeholder is refused.
        assert!(parse(RING, &mut |f| Ok(if f.contains("test") { TEST_KEY.into() } else {
            "untrusted comment: minisign public key REPLACE-WITH-THE-NEW-PUBLIC-KEY\nREPLACE-WITH-THE-NEW-PUBLIC-KEY\n".into()
        }))
        .unwrap_err()
        .contains("placeholder"));
    }

    #[test]
    fn a_pinned_release_with_the_published_sums_verifies() {
        let (release, _) = throwaway(1, [1; 8]);
        let ring = repo_ring(&release);
        let v = verify(&ring, "v0.1.0", SUMS, SIG).unwrap();
        assert!(v.pinned && v.key.former_test_key);
        assert_eq!(v.signed.signature.key_id, "9229E05252D01F8E");
    }

    #[test]
    fn a_pinned_tag_with_other_bytes_is_refused_even_with_a_valid_signature() {
        // The real v0.1.0 sums and signature, claimed for v0.2.0: the signature is
        // valid and v0.2.0 is in range, but the pin of v0.2.0 is another file.
        let (release, _) = throwaway(1, [1; 8]);
        let ring = repo_ring(&release);
        let e = verify(&ring, "v0.2.0", SUMS, SIG).unwrap_err();
        assert!(e.contains("the key ring pins f230dc34"), "{e}");
        // A leaked test key signs a forged SHA256SUMS for v0.4.1: a valid
        // signature by "the test key" (a throwaway one here, pinned the same way).
        let (fake_test, sign) = throwaway(2, [2; 8]);
        let mut ring = repo_ring(&release);
        let t = ring.iter_mut().find(|k| k.former_test_key).unwrap();
        t.public = PublicKey::parse(&fake_test).unwrap();
        t.text = fake_test.clone();
        let forged = b"0000000000000000000000000000000000000000000000000000000000000000  urmqtt-template-v0.4.1-universal.iso\n";
        let sig = sign(forged, "urMQTT v0.4.1 dev forged");
        assert!(
            release::verify_sums(&fake_test, forged, &sig).is_ok(),
            "the signature itself is valid"
        );
        let e = verify(&ring, "v0.4.1", forged, &sig).unwrap_err();
        assert!(e.contains("pins 3cca2f59"), "{e}");
        // A tag in range but not pinned is refused for a pinned key.
        let t = ring.iter_mut().find(|k| k.former_test_key).unwrap();
        t.pinned.remove("v0.3.0");
        let e = verify(&ring, "v0.3.0", forged, &sign(forged, "x")).unwrap_err();
        assert!(e.contains("signs only the pinned releases"), "{e}");
        // Outside the range: refused before any pin.
        let e = verify(&ring, "v0.5.0", forged, &sign(forged, "x")).unwrap_err();
        assert!(e.contains("may sign v0.1.0 to v0.4.1 only"), "{e}");
    }

    #[test]
    fn the_release_key_signs_new_tags_without_pins_and_unknown_keys_are_refused() {
        let (release, sign) = throwaway(1, [1; 8]);
        let ring = repo_ring(&release);
        let sums = b"1111111111111111111111111111111111111111111111111111111111111111  urmqtt-v0.5.0.iso\n";
        let v = verify(
            &ring,
            "v0.5.0",
            sums,
            &sign(sums, "urMQTT v0.5.0 release x"),
        )
        .unwrap();
        assert!(!v.pinned && v.key.name == "release");
        assert!(
            verify(&ring, "v0.4.1", sums, &sign(sums, "x"))
                .unwrap_err()
                .contains("v0.4.2 and later")
        );
        let (_, stranger) = throwaway(3, [3; 8]);
        assert!(
            verify(&ring, "v0.5.0", sums, &stranger(sums, "x"))
                .unwrap_err()
                .contains("not in the key ring")
        );
    }

    #[test]
    fn versions_and_bad_rings() {
        assert_eq!(tag_version("v0.4.1"), Some((0, 4, 1)));
        assert_eq!(tag_version("0.10.2-rc.1"), Some((0, 10, 2)));
        for bad in ["v0.4", "v0.4.1.2", "nightly", "v0.4.x", "v0.4.1 "] {
            assert_eq!(tag_version(bad), None, "{bad}");
        }
        let read = &mut |_: &str| Ok(TEST_KEY.to_owned());
        for (ring, why) in [
            (r#"{"schema":2,"keys":[]}"#, "schema"),
            (
                r#"{"schema":1,"keys":[{"name":"t","file":"f","pinned":{"v0.1.0":"zz"}}]}"#,
                "64 hex",
            ),
            (
                r#"{"schema":1,"keys":[{"name":"t","file":"f","key_id":"0000000000000000"}]}"#,
                "has key id",
            ),
            (
                r#"{"schema":1,"keys":[{"name":"t","file":"f","valid_from":"v0.5.0","valid_to":"v0.4.1"}]}"#,
                "after",
            ),
            (
                r#"{"schema":1,"keys":[{"name":"t","file":"f","extra":1}]}"#,
                "unknown field",
            ),
            (
                r#"{"schema":1,"keys":[{"name":"t","file":"f"},{"name":"u","file":"f"}]}"#,
                "twice",
            ),
        ] {
            let e = parse(ring, read).unwrap_err();
            assert!(e.contains(why), "{ring}: {e}");
        }
    }
}
