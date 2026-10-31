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

/// One DER element: `(tag, content, rest)`. Definite lengths only, as DER
/// requires; the length must fit the input.
fn der_next(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (usize::from(l0), rest)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (lb, rest) = rest.split_at(n);
        let mut len = 0usize;
        for &b in lb {
            len = (len << 8) | usize::from(b);
        }
        // DER: the long form is only for lengths of 128 and up, minimal.
        if len < 0x80 || lb.first() == Some(&0) {
            return None;
        }
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    Some((tag, content, rest))
}

/// The serial number bytes of a DER certificate (big-endian, as encoded,
/// with the DER sign byte if there is one), read straight from the DER without decoding the rest of the
/// certificate (it is asked for on every handshake: revocation check and
/// connection tag). `None` for anything that is not a positive INTEGER of at
/// most 20 octets in the first fields of the TBSCertificate (RFC 5280
/// 4.1.2.2), which counts as revoked at the call sites.
pub fn serial(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (tag, cert, _) = der_next(cert_der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_next(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (mut tag, mut content, rest) = der_next(tbs)?;
    if tag == 0xa0 {
        // [0] EXPLICIT version
        (tag, content, _) = der_next(rest)?;
    }
    if tag != 0x02 {
        return None;
    }
    let (&first, tail) = content.split_first()?;
    if first & 0x80 != 0 {
        return None; // negative
    }
    if first == 0 && tail.first().is_some_and(|b| b & 0x80 == 0) {
        return None; // not minimal
    }
    // The sign byte of a value with the top bit set does not count.
    let magnitude = if first == 0 {
        tail.len()
    } else {
        content.len()
    };
    (magnitude <= 20).then(|| content.to_vec())
}

/// The same serial through the full X.509 decoder (reference for the tests).
#[cfg(test)]
fn serial_full(cert_der: &[u8]) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn certs() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        use pki_types::CertificateDer;
        use pki_types::pem::PemObject;
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/dev");
        let mut out = alloc::vec::Vec::new();
        for sub in ["", "devices", "services", "negative", "bootstrap"] {
            let Ok(rd) = std::fs::read_dir(dir.join(sub)) else {
                continue;
            };
            for e in rd.flatten() {
                if e.path().extension().is_some_and(|x| x == "pem") {
                    for c in CertificateDer::pem_file_iter(e.path())
                        .into_iter()
                        .flatten()
                        .flatten()
                    {
                        out.push(c.as_ref().to_vec());
                    }
                }
            }
        }
        out
    }

    #[test]
    fn the_light_serial_reader_agrees_with_the_full_decoder() {
        let all = certs();
        if all.is_empty() {
            return; // no dev certificates: make certs
        }
        for c in &all {
            assert!(serial_full(c).is_some());
            assert_eq!(serial(c), serial_full(c));
        }
        // Single-byte corruptions and truncations: whenever the light reader
        // answers, it answers what the full decoder would, unless the
        // corruption is outside the serial (then only the full decoder may
        // refuse).
        let mut rng_state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };
        for c in all.iter().take(8) {
            for _ in 0..400 {
                let mut m = c.clone();
                let i = (next() as usize) % m.len();
                m[i] ^= 1 << (next() % 8);
                if let (Some(a), Some(b)) = (serial(&m), serial_full(&m)) {
                    assert_eq!(a, b);
                }
            }
            for cut in [0, 1, 2, 3, 4, 8, 12, 20] {
                assert_eq!(serial(&c[..cut.min(c.len())]), None);
            }
        }
        assert_eq!(serial(&[]), None);
        assert_eq!(serial(&[0x30, 0x80]), None);
        // 30 L { 30 L { 02 01 05 } }
        assert_eq!(serial(&[0x30, 5, 0x30, 3, 2, 1, 5]), Some(alloc::vec![5]));
        // with explicit version
        assert_eq!(
            serial(&[0x30, 10, 0x30, 8, 0xa0, 3, 2, 1, 2, 2, 1, 5]),
            Some(alloc::vec![5])
        );
        // padded positive, negative, empty, too long
        assert_eq!(
            serial(&[0x30, 7, 0x30, 5, 2, 3, 0, 0x80, 1]),
            Some(alloc::vec![0, 0x80, 1])
        );
        assert_eq!(serial(&[0x30, 5, 0x30, 3, 2, 1, 0x85]), None);
        assert_eq!(serial(&[0x30, 4, 0x30, 2, 2, 0]), None);
        let mut long = alloc::vec![0x30, 25, 0x30, 23, 2, 21, 0];
        long.extend_from_slice(&[0xff; 20]);
        assert_eq!(serial(&long).map(|s| s.len()), Some(21)); // 20 octets and the sign byte
        let mut too_long = alloc::vec![0x30, 26, 0x30, 24, 2, 22, 0];
        too_long.extend_from_slice(&[0xff; 21]);
        assert_eq!(serial(&too_long), None);
    }
}
