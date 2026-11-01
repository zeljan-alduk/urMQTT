//! What the builder page asks of the module, as plain Rust functions on bytes
//! and strings (the C ABI in `exports.rs` only moves buffers around). Each
//! function calls the code the `urmqtt-config` command line tool calls; the
//! equality test packs the same input both ways and compares the bytes.
//!
//! Answers that are more than bytes are JSON text. Errors are `Err(String)`;
//! for [`pack`] the string is a JSON array of `{"path","message"}` objects
//! (`path` is the TOML key a problem belongs to).

use std::collections::BTreeMap;

use urmqtt_cfg::Blob;
use urmqtt_cfg::fields::tag;
use urmqtt_config_schema::ConfigError;
use urmqtt_config_tool::certs::{self, CertInfo};
use urmqtt_config_tool::release::{hex, sha256};
use urmqtt_config_tool::{describe, image, keys, minisign, release};

use crate::json::{self, Object};

/// The files a configuration names, by the name the TOML gives them.
pub type Files = BTreeMap<String, Vec<u8>>;

/// The module's interface version; the page refuses a module it does not know.
/// 2: `ub_hash_password` (plaintext accounts, P1).
pub const ABI_VERSION: u32 = 2;

fn errors_json(errors: &[ConfigError]) -> String {
    json::array(
        &errors
            .iter()
            .map(|e| {
                Object::new()
                    .str("path", &e.path)
                    .str("message", &e.message)
                    .build()
            })
            .collect::<Vec<_>>(),
    )
}

fn one_error(path: &str, message: &str) -> String {
    errors_json(&[ConfigError {
        path: path.to_owned(),
        message: message.to_owned(),
    }])
}

// --- schema and defaults -----------------------------------------------------

/// The field table as JSON (the same text as `urmqtt-config schema`).
pub fn schema() -> String {
    urmqtt_config_schema::pack::schema_json()
}

/// The defaults as TOML (the TOML form of the empty configuration).
pub fn default_toml() -> String {
    urmqtt_config_schema::pack::default_toml()
}

// --- the configuration ---------------------------------------------------------

/// Packs the configuration `toml` and the `files` it names into a blob, for a
/// **release** kernel (the template ISO carries release kernels only), signed
/// with the Ed25519 key `sign_pem` if given. `now_unix` is the clock for the
/// certificate expiry rules. On failure the error is a JSON array of
/// `{"path","message"}`.
pub fn pack(
    toml: &str,
    files: &Files,
    env: Option<&str>,
    now_unix: u64,
    sign_key_pem: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let mut read = |name: &str| {
        files
            .get(name)
            .cloned()
            .ok_or_else(|| "no file with this name was chosen".to_owned())
    };
    let blob = urmqtt_config_tool::pack_text(toml, &mut read, env, now_unix)
        .map_err(|errors| errors_json(&errors))?;
    // The rules of the kernel that will read it: a blob that asks for the
    // development environment or a plaintext port packs for a dev kernel but
    // the release kernel in the template would refuse it at boot.
    let parsed = Blob::parse(&blob).map_err(|e| one_error(e.key, e.msg))?;
    urmqtt_cfg::check::check(&parsed, false).map_err(|e| one_error(e.key, e.msg))?;
    match sign_key_pem {
        None => Ok(blob),
        Some(pem) => {
            urmqtt_config_tool::sign_pem(&blob, pem).map_err(|m| one_error("signing key", &m))
        }
    }
}

/// Which of the things the broker needs to serve a blob lacks (`tls.cert`,
/// `tls.key`, `trust.operational`).
pub fn missing_for_serving(b: &Blob<'_>) -> Vec<&'static str> {
    let mut missing = Vec::new();
    // The TLS listener is off (plaintext only, ADR-233): no certificate, key or CA is needed.
    if b.uint(urmqtt_cfg::fields::tag::NET_TLS_PORT) == 0 {
        return missing;
    }
    if b.bin(tag::TLS_CERT).is_empty() {
        missing.push("tls.cert");
    }
    if b.bin(tag::TLS_KEY).is_empty() {
        missing.push("tls.key");
    }
    if b.bins(tag::TRUST_OPERATIONAL).next().is_none() {
        missing.push("trust.operational");
    }
    missing
}

/// What is in a blob: fingerprint, signature, size, what is missing to serve,
/// and the text `urmqtt-config show` prints.
pub fn blob_info(blob: &[u8]) -> Result<String, String> {
    let b = Blob::parse(blob).map_err(|e| e.to_string())?;
    let sig = b.signature();
    Ok(Object::new()
        .str("fingerprint", &hex(b.fingerprint()))
        .num("size", b.len() as u64)
        .bool("signed", sig.is_some())
        .opt_str(
            "signer_id",
            sig.map(|s| urmqtt_config_tool::signer_id(&s.public_key))
                .as_deref(),
        )
        .opt_str("public_key", sig.map(|s| hex(&s.public_key)).as_deref())
        .str("env", b.str(tag::ENV))
        .strs("missing", &missing_for_serving(&b))
        .str("summary", &describe(blob, false)?)
        .build())
}

/// The configuration as `urmqtt-config show --all` would print it.
pub fn describe_all(blob: &[u8]) -> Result<String, String> {
    describe(blob, true)
}

/// A TOML configuration as JSON (tables as objects), so the page can fill the
/// form from a file the user imports. Datetimes cannot occur in a valid
/// configuration and are refused.
pub fn toml_to_json(text: &str) -> Result<String, String> {
    fn value(v: &toml::Value) -> Result<String, String> {
        Ok(match v {
            toml::Value::String(s) => json::string(s),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Float(_) => return Err("floating point numbers are not used".into()),
            toml::Value::Boolean(b) => b.to_string(),
            toml::Value::Datetime(_) => return Err("dates are not used".into()),
            toml::Value::Array(a) => {
                json::array(&a.iter().map(value).collect::<Result<Vec<_>, _>>()?)
            }
            toml::Value::Table(t) => table(t)?,
        })
    }
    fn table(t: &toml::Table) -> Result<String, String> {
        let mut o = Object::new();
        for (k, v) in t {
            o = o.raw(k, value(v)?);
        }
        Ok(o.build())
    }
    let parsed: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    table(&parsed)
}

// --- certificates and keys -------------------------------------------------

fn cert_json(c: &CertInfo) -> String {
    Object::new()
        .str("subject", &c.subject)
        .str("issuer", &c.issuer)
        .str("serial", &c.serial)
        .num("not_before", c.not_before)
        .num("not_after", c.not_after)
        .strs("names", &c.names)
        .bool("is_ca", c.is_ca)
        .str("key_type", &c.key_type)
        .str("signature_type", &c.signature_type)
        .str("sha256", &c.sha256)
        .bool("self_issued", c.self_issued)
        .bool("supported_key", c.public_key.is_some())
        .build()
}

/// Every certificate in a PEM file, for the import dialog.
pub fn cert_info(pem: &[u8]) -> Result<String, String> {
    let certs = certs::inspect_certs(pem)?;
    Ok(json::array(
        &certs.iter().map(cert_json).collect::<Vec<_>>(),
    ))
}

/// What kind of private key a PEM file holds, without ever returning the key.
pub fn key_info(pem: &[u8]) -> Result<String, String> {
    let k = certs::inspect_key(pem)?;
    Ok(Object::new()
        .str("key_type", &k.key_type)
        .str("public_key_sha256", &hex(&sha256(&k.public_key)))
        .build())
}

/// How a server certificate, its key and the CAs fit together. Any of the
/// three may be empty (not chosen yet). `key_matches` is `null` unless both
/// the certificate and the key are present. For every certificate of
/// `cert_pem`, `signers` says who signed it: another certificate of the same
/// file (`"chain"`), one of the CAs (`"ca"`), itself, or nobody we know.
pub fn cross_check(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> Result<String, String> {
    let leaves = if cert_pem.is_empty() {
        Vec::new()
    } else {
        certs::inspect_certs(cert_pem)?
    };
    let cas = if ca_pem.is_empty() {
        Vec::new()
    } else {
        certs::inspect_certs(ca_pem)?
    };
    let key_matches = match (leaves.first(), key_pem.is_empty()) {
        (Some(leaf), false) => Some(certs::key_matches(leaf, &certs::inspect_key(key_pem)?)),
        _ => None,
    };
    let mut signers = Vec::new();
    for (i, c) in leaves.iter().enumerate() {
        let mut found: Option<(&str, usize, Option<bool>)> = None;
        let candidates = leaves
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(j, x)| ("chain", j, x))
            .chain(cas.iter().enumerate().map(|(j, x)| ("ca", j, x)));
        for (kind, j, cand) in candidates {
            if cand.subject != c.issuer {
                continue;
            }
            let ok = certs::signed_by(cert_pem, i, cand)?;
            if ok != Some(false) {
                found = Some((kind, j, ok));
                break;
            }
            found.get_or_insert((kind, j, ok));
        }
        let o = Object::new()
            .num("index", i as u64)
            .bool("self_issued", c.self_issued);
        signers.push(match found {
            Some((kind, j, ok)) => o
                .str("by", kind)
                .num("signer", j as u64)
                .opt_bool("verified", ok)
                .build(),
            None => o.opt_str("by", None).opt_bool("verified", None).build(),
        });
    }
    Ok(Object::new()
        .opt_bool("key_matches", key_matches)
        .raw("signers", json::array(&signers))
        .build())
}

/// The public half of an Ed25519 control key the user chose: the file may be a
/// public key (`openssl pkey -pubout`) or the private key it belongs to. The
/// result carries the public key in PEM (what `control.public_key` names) and
/// never anything private.
pub fn control_key(pem: &[u8]) -> Result<String, String> {
    let (public, from_private) = match urmqtt_control::parse_public_key(pem) {
        Some(k) => (k, false),
        None => match keys::public_of_private(pem) {
            Some(k) => (k, true),
            None => {
                return Err(
                    "expected an Ed25519 public key (BEGIN PUBLIC KEY, `openssl pkey -pubout`)"
                        .into(),
                );
            }
        },
    };
    Ok(Object::new()
        .str("public_key", &hex(&public))
        .str("public_pem", &keys::public_pem(&public))
        .bool("from_private", from_private)
        .build())
}

/// A new Ed25519 signing key from `seed` (32 random bytes from the browser).
pub fn new_signing_key(seed: &[u8]) -> Result<String, String> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| "the seed must be 32 bytes")?;
    let k = keys::ed25519_from_seed(&seed);
    Ok(Object::new()
        .str("private_pem", &k.private_pem)
        .str("public_pem", &k.public_pem)
        .str("public_key", &hex(&k.public_key))
        .str("signer_id", &urmqtt_config_tool::signer_id(&k.public_key))
        .build())
}

/// The stored hash of a plaintext account's password (P1, ADR-229):
/// PBKDF2-HMAC-SHA-256 with the salt the page drew from
/// `crypto.getRandomValues` (16 bytes) and the iteration count. This is the
/// command line's `hash-password`; the configuration keeps only the result.
pub fn hash_password(password: &[u8], salt: &[u8], iterations: u32) -> Result<String, String> {
    urmqtt_config_tool::hash_password(password, salt, iterations)
}

/// Who an Ed25519 private key (the optional configuration signature) belongs to.
pub fn signing_key_info(pem: &[u8]) -> Result<String, String> {
    let public = keys::public_of_private(pem).ok_or(urmqtt_config_tool::NOT_AN_ED25519_KEY)?;
    Ok(Object::new()
        .str("public_key", &hex(&public))
        .str("signer_id", &urmqtt_config_tool::signer_id(&public))
        .build())
}

// --- the image ---------------------------------------------------------------

/// What a template ISO is: copies of the slot, module hash references, the
/// format version of its configuration and what that configuration says.
pub fn iso_probe(iso: &[u8]) -> Result<String, String> {
    let p = image::probe(iso)?;
    Ok(Object::new()
        .num("slot_copies", p.slot_copies as u64)
        .num("hash_refs", p.hash_refs as u64)
        .num("format_version", u64::from(p.format_version))
        .bool(
            "supported",
            (urmqtt_cfg::FORMAT_MIN..=urmqtt_cfg::FORMAT_VERSION).contains(&p.format_version),
        )
        .str("summary", &describe(&p.blob, false).unwrap_or_default())
        .build())
}

/// Writes `blob` into the template ISO `iso`, in place (the browser holds the
/// image once). A configuration a release kernel would refuse is not written.
pub fn iso_configure(iso: &mut [u8], blob: &[u8]) -> Result<String, String> {
    urmqtt_config_tool::verify_blob(blob, false)?;
    image::configure_iso_in_place(iso, blob)
}

/// Checks an image the way `urmqtt-config verify` does (as a release kernel).
pub fn iso_verify(iso: &[u8]) -> Result<String, String> {
    image::verify(iso, false)
}

// --- releases ------------------------------------------------------------------

/// Verifies the minisign signature `sig` over `sums` with `pubkey` and lists
/// the files the sums name: `{"key_id","trusted_comment","files":[{"name",
/// "sha256"}]}`.
pub fn verify_release(pubkey: &str, sums: &[u8], sig: &str) -> Result<String, String> {
    let s = release::verify_sums(pubkey, sums, sig)?;
    let files: Vec<String> = s
        .sums
        .entries
        .iter()
        .map(|(n, d)| Object::new().str("name", n).str("sha256", &hex(d)).build())
        .collect();
    Ok(Object::new()
        .str("key_id", &s.signature.key_id)
        .bool("prehashed", s.signature.prehashed)
        .str("untrusted_comment", &s.signature.untrusted_comment)
        .str("trusted_comment", &s.signature.trusted_comment)
        .raw("files", json::array(&files))
        .build())
}

/// The key id of a minisign public key file, as minisign prints it.
pub fn minisign_key_id(pubkey: &str) -> Result<String, String> {
    Ok(minisign::PublicKey::parse(pubkey)?.key_id())
}
