//! Builds blobs. A field set to its default is left out, records are sorted
//! by tag, so one configuration is one byte string and one fingerprint.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::blob::{
    self, BASE_VERSION, Blob, FORMAT_VERSION, HEADER_LEN, MAGIC, SIG_KEY_LEN, SIG_LEN,
};
use crate::fields::{self, Field, Kind};
use crate::{CfgError, err};

/// Collects field values and encodes them canonically.
#[derive(Debug, Default, Clone)]
pub struct Builder {
    records: BTreeMap<u16, Vec<u8>>,
}

fn field(tag: u16) -> Result<&'static Field, CfgError> {
    fields::by_tag(tag).ok_or(err("blob", "unknown field tag"))
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores the already-encoded `value` of `tag` after checking its shape
    /// and range; a value equal to the default removes the record.
    pub fn set_raw(&mut self, tag: u16, value: &[u8]) -> Result<(), CfgError> {
        let f = field(tag)?;
        if !f.stored {
            return Ok(());
        }
        blob::check_value(f, value)?;
        if is_default(f, value) {
            self.records.remove(&tag);
        } else {
            self.records.insert(tag, value.to_vec());
        }
        Ok(())
    }

    pub fn bool(&mut self, tag: u16, v: bool) -> Result<(), CfgError> {
        self.set_raw(tag, &[u8::from(v)])
    }

    pub fn uint(&mut self, tag: u16, v: u64) -> Result<(), CfgError> {
        let f = field(tag)?;
        let Kind::UInt { bytes, .. } = f.kind else {
            return Err(err(f.key, "not an integer field"));
        };
        let le = v.to_le_bytes();
        let n = usize::from(bytes);
        if le.get(n..).is_some_and(|hi| hi.iter().any(|&b| b != 0)) {
            return Err(err(f.key, "out of range"));
        }
        self.set_raw(tag, le.get(..n).unwrap_or(&[]))
    }

    pub fn variant(&mut self, tag: u16, index: u8) -> Result<(), CfgError> {
        self.set_raw(tag, &[index])
    }

    pub fn str(&mut self, tag: u16, v: &str) -> Result<(), CfgError> {
        self.set_raw(tag, v.as_bytes())
    }

    pub fn strs<S: AsRef<str>>(&mut self, tag: u16, items: &[S]) -> Result<(), CfgError> {
        let f = field(tag)?;
        let mut v = Vec::new();
        for s in items {
            let s = s.as_ref();
            let n = u16::try_from(s.len()).map_err(|_| err(f.key, "an entry is too long"))?;
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(s.as_bytes());
        }
        // An empty list is a real value when the default is not empty.
        if v.is_empty() && matches!(f.kind, Kind::Strs { default, .. } if !default.is_empty()) {
            blob::check_value(f, &v)?;
            self.records.insert(tag, v);
            return Ok(());
        }
        self.set_raw(tag, &v)
    }

    pub fn bin(&mut self, tag: u16, v: &[u8]) -> Result<(), CfgError> {
        self.set_raw(tag, v)
    }

    pub fn bins<B: AsRef<[u8]>>(&mut self, tag: u16, items: &[B]) -> Result<(), CfgError> {
        let mut v = Vec::new();
        for s in items {
            let s = s.as_ref();
            let n = u32::try_from(s.len()).map_err(|_| err("blob", "an entry is too long"))?;
            v.extend_from_slice(&n.to_le_bytes());
            v.extend_from_slice(s);
        }
        self.set_raw(tag, &v)
    }

    pub fn ipv4(&mut self, tag: u16, a: [u8; 4]) -> Result<(), CfgError> {
        self.set_raw(tag, &a)
    }

    pub fn cidr(&mut self, tag: u16, a: [u8; 4], prefix: u8) -> Result<(), CfgError> {
        let mut v = a.to_vec();
        v.push(prefix);
        self.set_raw(tag, &v)
    }

    pub fn key32(&mut self, tag: u16, k: &[u8; 32]) -> Result<(), CfgError> {
        self.set_raw(tag, k)
    }

    pub fn rate(&mut self, tag: u16, tokens: u32, per_ms: u32) -> Result<(), CfgError> {
        let mut v = tokens.to_le_bytes().to_vec();
        v.extend_from_slice(&per_ms.to_le_bytes());
        self.set_raw(tag, &v)
    }

    pub fn addr(&mut self, tag: u16, a: [u8; 4], port: u16) -> Result<(), CfgError> {
        let mut v = a.to_vec();
        v.extend_from_slice(&port.to_le_bytes());
        self.set_raw(tag, &v)
    }

    pub fn addrs(&mut self, tag: u16, list: &[([u8; 4], u16)]) -> Result<(), CfgError> {
        let mut v = Vec::new();
        for (a, p) in list {
            v.extend_from_slice(a);
            v.extend_from_slice(&p.to_le_bytes());
        }
        self.set_raw(tag, &v)
    }

    /// Encodes the unsigned blob and validates it as the kernel will.
    /// `dev_allowed`: the target kernel is a dev build.
    pub fn finish(&self, dev_allowed: bool) -> Result<Vec<u8>, CfgError> {
        self.finish_as(dev_allowed, self.lowest_version())
    }

    /// The lowest format version that can hold this configuration: 2 (the base), 3 when the TLS listener is off,
    /// otherwise the newest `since` of the records written: 4 with disk encryption, 5 with `console.virtio_gpu`
    /// set (ADR-256), 6 with a `[devices]` key set (ADR-257), 7 with `network.mtu` set (ADR-264), 8 with
    /// `limits.publisher_backpressure` set (ADR-269), 9 with a `[websocket]` key set (ADR-272), 11 with
    /// `devices.virtio_net_interrupt` set (ADR-270), 12 with an `[mqtt5]` key or an expiry limit set (ADR-273). A
    /// field at its default writes no record.
    pub fn lowest_version(&self) -> u16 {
        let tls_off = self
            .records
            .iter()
            .any(|(t, v)| *t == crate::fields::tag::NET_TLS_PORT && v.iter().all(|b| *b == 0));
        let newest = self
            .records
            .keys()
            .filter_map(|t| crate::fields::by_tag(*t))
            .map(|f| f.since)
            .max()
            .unwrap_or(BASE_VERSION);
        // Disk encryption's fields predate format 4 (since 1); the version
        // is what refuses them on an older kernel.
        let encrypted = self
            .records
            .iter()
            .any(|(t, v)| *t == crate::fields::tag::ST_ENCRYPTION && v.iter().any(|b| *b != 0));
        let floor = if encrypted {
            4
        } else if tls_off {
            3
        } else {
            BASE_VERSION
        };
        newest.max(floor)
    }

    /// [`finish`](Self::finish) with a format version of the caller's choice (the newest, for the empty
    /// configuration of a template ISO, which is how a template says what its kernel reads). A version
    /// below [`lowest_version`](Self::lowest_version) is refused.
    pub fn finish_as(&self, dev_allowed: bool, version: u16) -> Result<Vec<u8>, CfgError> {
        if version < self.lowest_version()
            || version > FORMAT_VERSION
            || version == blob::UNUSED_VERSION
        {
            return Err(err(
                "blob",
                "this configuration needs a newer format version than the one asked for",
            ));
        }
        let mut payload = Vec::new();
        for (tag, value) in &self.records {
            payload.extend_from_slice(&tag.to_le_bytes());
            let n = u32::try_from(value.len()).map_err(|_| err("blob", "value too long"))?;
            payload.extend_from_slice(&n.to_le_bytes());
            payload.extend_from_slice(value);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + 33);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        let plen = u32::try_from(payload.len()).map_err(|_| err("blob", "payload too long"))?;
        out.extend_from_slice(&plen.to_le_bytes());
        out.extend_from_slice(&payload);
        let fp = blob::fingerprint_of(&out);
        out.extend_from_slice(&fp);
        out.push(0);
        if out.len() > blob::MAX_BLOB {
            return Err(err(
                "blob",
                "the configuration does not fit in a slot (256 KiB)",
            ));
        }
        let parsed = Blob::parse(&out)?;
        crate::check::check(&parsed, dev_allowed)?;
        Ok(out)
    }
}

/// Whether `value` is the field's default (so the record can be left out).
fn is_default(f: &Field, v: &[u8]) -> bool {
    match f.kind {
        Kind::Bool(d) => v == [u8::from(d)],
        Kind::UInt { default, .. } => {
            v.iter()
                .take(8)
                .enumerate()
                .fold(0u64, |a, (i, x)| a | (u64::from(*x) << (8 * i)))
                == default
        }
        Kind::Enum { default, .. } => v == [default],
        Kind::Str { default, .. } => v == default.as_bytes(),
        Kind::Strs { default, .. } => {
            let mut enc = Vec::new();
            for s in default {
                enc.extend_from_slice(&(s.len() as u16).to_le_bytes());
                enc.extend_from_slice(s.as_bytes());
            }
            v == enc
        }
        Kind::Rate { tokens, per_ms } => {
            let mut enc = tokens.to_le_bytes().to_vec();
            enc.extend_from_slice(&per_ms.to_le_bytes());
            v == enc
        }
        Kind::BinList { .. } | Kind::Addrs { .. } => v.is_empty(),
        Kind::Bin { .. } | Kind::Ipv4 | Kind::Cidr | Kind::Addr | Kind::Key32 => false,
    }
}

/// Appends a signature to an unsigned blob made by [`Builder::finish`]:
/// `sign` receives the message to sign and returns the signer's public key
/// and the signature. The result is re-parsed, so a wrong signature is an
/// error here, not at boot.
pub fn sign(
    unsigned: &[u8],
    sign: impl FnOnce(&[u8]) -> ([u8; SIG_KEY_LEN], [u8; SIG_LEN]),
) -> Result<Vec<u8>, CfgError> {
    let b = Blob::parse(unsigned)?;
    if b.signature().is_some() {
        return Err(err("signature", "the blob is already signed"));
    }
    let (key, sig) = sign(&blob::signing_message(b.fingerprint()));
    let mut out = unsigned.get(..b.len() - 1).unwrap_or(&[]).to_vec();
    out.push(1);
    out.extend_from_slice(&key);
    out.extend_from_slice(&sig);
    Blob::parse(&out)?;
    Ok(out)
}

/// The same blob without its signature (the fingerprint does not cover it).
pub fn strip_signature(signed: &[u8]) -> Result<Vec<u8>, CfgError> {
    let b = Blob::parse(signed)?;
    let end = HEADER_LEN
        + (signed
            .get(12..16)
            .and_then(|x| <[u8; 4]>::try_from(x).ok())
            .map_or(0, u32::from_le_bytes) as usize)
        + 32;
    let mut out = signed.get(..end).unwrap_or(&[]).to_vec();
    out.push(0);
    let _ = b;
    Ok(out)
}
