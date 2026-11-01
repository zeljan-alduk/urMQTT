//! Looking at certificates and keys the way the page shows them (ADR-226):
//! subject, issuer, validity, names, key type, fingerprint; whether a private
//! key belongs to a certificate; whether a certificate was signed by a CA.
//! All of it is local computation on the bytes the user chose; the browser
//! builder and the host tool share it. Only ECDSA P-256 is supported, as in
//! the broker's TLS stack.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::Encode;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};

use crate::release::hex;

/// `id-ecPublicKey`, `prime256v1` and `ecdsa-with-SHA256`.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// One certificate of a PEM file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// Serial number, lower-case hex.
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
    /// `DNS:`, `URI:`, `IP:` and `email:` names from the subjectAltName extension.
    pub names: Vec<String>,
    pub is_ca: bool,
    /// `ECDSA P-256`, or the algorithm's OID when it is something else.
    pub key_type: String,
    pub signature_type: String,
    /// SHA-256 of the DER certificate, lower-case hex.
    pub sha256: String,
    /// Subject and issuer are the same name.
    pub self_issued: bool,
    /// The public key as an uncompressed SEC1 point, when it is a P-256 key.
    pub public_key: Option<Vec<u8>>,
}

fn name_of(n: &x509_cert::name::Name) -> String {
    n.to_string()
}

fn oid_text(o: &x509_cert::der::asn1::ObjectIdentifier) -> String {
    o.to_string()
}

/// Every certificate in `pem`, in file order.
pub fn inspect_certs(pem: &[u8]) -> Result<Vec<CertInfo>, String> {
    let certs = Certificate::load_pem_chain(pem).map_err(|e| format!("cannot parse: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate".into());
    }
    certs.iter().map(info).collect()
}

fn info(c: &Certificate) -> Result<CertInfo, String> {
    let tbs = c.tbs_certificate();
    let spki = tbs.subject_public_key_info();
    let der = c.to_der().map_err(|e| format!("cannot encode: {e}"))?;
    let key_oid = oid_text(&spki.algorithm.oid);
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok())
        .map(|o| oid_text(&o));
    let p256 = key_oid == OID_EC_PUBLIC_KEY && curve.as_deref() == Some(OID_P256);
    let key_type = if p256 {
        "ECDSA P-256".to_owned()
    } else {
        match (key_oid.as_str(), curve) {
            ("1.2.840.113549.1.1.1", _) => "RSA".to_owned(),
            ("1.3.101.112", _) => "Ed25519".to_owned(),
            (OID_EC_PUBLIC_KEY, Some(c)) => format!("EC (curve {c})"),
            (o, _) => format!("key algorithm {o}"),
        }
    };
    let sig_oid = oid_text(&c.signature_algorithm().oid);
    let signature_type = if sig_oid == OID_ECDSA_SHA256 {
        "ECDSA with SHA-256".to_owned()
    } else {
        format!("signature algorithm {sig_oid}")
    };
    let mut names = Vec::new();
    if let Ok(Some((_, SubjectAltName(list)))) = tbs.get_extension::<SubjectAltName>() {
        for n in &list {
            match n {
                GeneralName::DnsName(d) => names.push(format!("DNS:{d}")),
                GeneralName::UniformResourceIdentifier(u) => names.push(format!("URI:{u}")),
                GeneralName::Rfc822Name(e) => names.push(format!("email:{e}")),
                GeneralName::IpAddress(ip) => {
                    let b = ip.as_bytes();
                    let text = match b.len() {
                        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                        _ => hex(b),
                    };
                    names.push(format!("IP:{text}"));
                }
                _ => {}
            }
        }
    }
    let is_ca = matches!(
        tbs.get_extension::<BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    );
    let validity = tbs.validity();
    let subject = name_of(tbs.subject());
    let issuer = name_of(tbs.issuer());
    Ok(CertInfo {
        self_issued: subject == issuer,
        subject,
        issuer,
        serial: hex(tbs.serial_number().as_bytes()),
        not_before: validity.not_before.to_unix_duration().as_secs(),
        not_after: validity.not_after.to_unix_duration().as_secs(),
        names,
        is_ca,
        key_type,
        signature_type,
        sha256: hex(&Sha256::digest(&der)),
        public_key: p256.then(|| spki.subject_public_key.raw_bytes().to_vec()),
    })
}

/// A private key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// `ECDSA P-256`.
    pub key_type: String,
    /// The matching public key, uncompressed SEC1 point.
    pub public_key: Vec<u8>,
}

/// Reads an unencrypted ECDSA P-256 private key (PKCS#8 `BEGIN PRIVATE KEY` or
/// SEC1 `BEGIN EC PRIVATE KEY`). The key itself is never returned.
pub fn inspect_key(pem: &[u8]) -> Result<KeyInfo, String> {
    let text = std::str::from_utf8(pem).map_err(|_| "file is not valid UTF-8 PEM".to_owned())?;
    let sk = if text.contains("-----BEGIN EC PRIVATE KEY-----") {
        p256::SecretKey::from_sec1_pem(text).map_err(|e| format!("cannot parse the EC key: {e}"))?
    } else if text.contains("-----BEGIN PRIVATE KEY-----") {
        p256::SecretKey::from_pkcs8_pem(text).map_err(|_| {
            "cannot parse the key: only ECDSA P-256 private keys are supported (RSA and Ed25519 server keys are not)"
                .to_owned()
        })?
    } else {
        return Err("expected an unencrypted PEM private key (BEGIN PRIVATE KEY)".into());
    };
    Ok(KeyInfo {
        key_type: "ECDSA P-256".into(),
        public_key: sk.public_key().to_sec1_bytes().to_vec(),
    })
}

/// Whether `key` is the private half of the certificate's public key.
pub fn key_matches(cert: &CertInfo, key: &KeyInfo) -> bool {
    cert.public_key.as_deref() == Some(&key.public_key[..])
}

/// Whether `cert` carries a valid signature by the public key of `ca`.
/// `Ok(None)` when it cannot be decided (not a P-256 / ECDSA-SHA256 pair).
pub fn signed_by(cert_pem: &[u8], index: usize, ca: &CertInfo) -> Result<Option<bool>, String> {
    let certs = Certificate::load_pem_chain(cert_pem).map_err(|e| format!("cannot parse: {e}"))?;
    let c = certs.get(index).ok_or("no such certificate")?;
    if oid_text(&c.signature_algorithm().oid) != OID_ECDSA_SHA256 {
        return Ok(None);
    }
    let Some(ca_key) = &ca.public_key else {
        return Ok(None);
    };
    let vk = VerifyingKey::from_sec1_bytes(ca_key).map_err(|e| e.to_string())?;
    let tbs = c.tbs_certificate().to_der().map_err(|e| e.to_string())?;
    let Ok(sig) = Signature::from_der(c.signature().raw_bytes()) else {
        return Ok(Some(false));
    };
    Ok(Some(vk.verify(&tbs, &sig).is_ok()))
}
