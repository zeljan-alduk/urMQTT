//! Device identity from a client certificate (PROMPT §6): the configured
//! field (CN or a SAN URI) normalised to a `device_id`, plus the serial
//! number for revocation checks.

use alloc::string::String;
use alloc::vec::Vec;

use der::Decode;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

const OID_CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_SAN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");
/// SAN URI prefixes that carry an identity; the rest of the URI is the id.
pub const URI_PREFIXES: [&str; 2] = ["urn:urmqtt:device:", "urn:urmqtt:service:"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityField {
    Cn,
    SanUri,
}

/// The serial number bytes of a DER certificate (as encoded, big-endian).
pub fn serial(cert_der: &[u8]) -> Option<Vec<u8>> {
    let c = Certificate::from_der(cert_der).ok()?;
    Some(c.tbs_certificate().serial_number().as_bytes().to_vec())
}

fn common_name(c: &Certificate) -> Option<String> {
    for atv in c.tbs_certificate().subject().iter() {
        if atv.oid == OID_CN {
            if let Ok(s) = der::asn1::Utf8StringRef::try_from(&atv.value) {
                return Some(s.as_str().into());
            }
            if let Ok(s) = der::asn1::PrintableStringRef::try_from(&atv.value) {
                return Some(s.as_str().into());
            }
        }
    }
    None
}

fn san_uri(c: &Certificate) -> Option<String> {
    let ext = c
        .tbs_certificate()
        .extensions()
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == OID_SAN)?;
    let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).ok()?;
    san.0.iter().find_map(|g| match g {
        GeneralName::UniformResourceIdentifier(u) => {
            let s = u.as_str();
            URI_PREFIXES
                .iter()
                .find_map(|p| s.strip_prefix(p))
                .map(String::from)
        }
        _ => None,
    })
}

/// The identity of `cert_der` according to `field`, if present.
pub fn identity(cert_der: &[u8], field: IdentityField) -> Option<String> {
    let c = Certificate::from_der(cert_der).ok()?;
    match field {
        IdentityField::Cn => common_name(&c),
        IdentityField::SanUri => san_uri(&c),
    }
}
