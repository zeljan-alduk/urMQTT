//! The container: header, records, fingerprint, optional signature, and the
//! padded slot the blob lives in inside an ISO or an installed ESP.
//!
//! ```text
//! blob  = magic[8] "URMQCFG\0" | version u16 | flags u16 (0) | payload_len u32
//!         | payload | fingerprint[32] | sig_kind u8 [| public_key[32] | signature[64]]
//! payload = record*      record = tag u16 | len u32 | value[len]   (tags strictly ascending)
//! fingerprint = SHA-256("urmqtt-cfg-v1" | blob bytes up to the fingerprint)
//! signature   = Ed25519(private key, "urmqtt-cfg-sig-v1" | fingerprint)
//! slot  = marker[16] | blob | zero padding up to SLOT_SIZE
//! ```
//!
//! All integers are little-endian. The same configuration always encodes to
//! the same bytes: fields at their default are omitted and the tags are
//! sorted, so the fingerprint identifies the configuration.

use crate::fields::{self, Field, Kind};
use crate::{CfgError, err};

pub const MAGIC: [u8; 8] = *b"URMQCFG\0";
/// The newest format version this code reads (and writes for a configuration that needs it). Version 2
/// added the `plaintext.*` fields (P1, ADR-229); version 3 allows `network.mqtt_tls_port = 0` (the TLS
/// listener off, with `plaintext.enabled`; ADR-233); version 4 adds `storage.encryption` and
/// `storage.disk_key` (S7, ADR-240: a kernel that does not know them must not boot an encrypted disk); version 5
/// adds `console.virtio_gpu` (ADR-256: a kernel without the driver refuses the record by the version, at build
/// time through the template check, instead of by an unknown tag at boot); version 6 adds the `[devices]` keys of
/// the optional virtio drivers (ADR-257, the same reason); version 7 adds `network.mtu` (ADR-264: a kernel that
/// does not know it would send 1500-byte frames into the smaller network it was set for); version 8 adds
/// `limits.publisher_backpressure` (ADR-269: "off" on a kernel that pauses publishers regardless would be
/// ignored, so it is refused by the version); version 9 adds the `[websocket]` section (ADR-272: a kernel without
/// the listener must refuse an image that asks for it); version 11 adds `devices.virtio_net_interrupt` (ADR-270;
/// 10 is unused); version 12 adds the `[mqtt5]` section and the session and message expiry limits (ADR-273 rule
/// 21: a kernel that does not know them would ignore the operator's expiry policy); version 13 adds
/// `limits.max_shared_groups` and `limits.max_shared_group_members` (ADR-275: a kernel that does not know them
/// would ignore the operator's bound); version 18 adds `devices.iommu` (ADR-305: a kernel that does not know it would
/// run without the DMA isolation the operator required; 14 to 17 belong to other items of v0.6.0 and are unknown
/// to this code until they are merged). The records of 2 and 3 are the same: the packer writes the lowest version
/// that can hold the configuration ([`BASE_VERSION`]), so a kernel of the older kind still boots every image that
/// does not use what came later.
pub const FORMAT_VERSION: u16 = 18;

/// The one version between [`FORMAT_MIN`] and [`FORMAT_VERSION`] no format ever had.
pub const UNUSED_VERSION: u16 = 10;
/// The versions between [`FORMAT_MIN`] and [`FORMAT_VERSION`] this code does not read: 10, which no format ever
/// had, and 14 to 17, the formats of other v0.6.0 items (the release merge removes the ones it brings in).
pub const UNUSED_VERSIONS: &[u16] = &[UNUSED_VERSION, 14, 15, 16, 17];

/// Whether this code reads format `version`.
pub fn known_version(version: u16) -> bool {
    (FORMAT_MIN..=FORMAT_VERSION).contains(&version) && !UNUSED_VERSIONS.contains(&version)
}
/// The version a configuration is written in unless it needs a newer one.
pub const BASE_VERSION: u16 = 2;
/// The oldest format version it still reads. Blobs of the older versions stay
/// valid (an installed disk keeps its configuration across a kernel update):
/// the records of version 1 are the same in version 2, and a version 1 blob
/// cannot hold a record that came later (see [`crate::fields::Field::since`]).
/// A kernel that only knows version 1 refuses a version 2 blob by its version,
/// before it reads a record.
pub const FORMAT_MIN: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const FINGERPRINT_LEN: usize = 32;
/// Size of the file the bootloader loads as the configuration module.
pub const SLOT_SIZE: usize = 256 * 1024;
/// Marks a slot the bootloader loads (ISO, installed ESP).
pub const SLOT_MARKER: [u8; 16] = *b"URMQTT-CFG-SLOT\0";
/// Marks the not yet configured slot of the installation image: the ISO's
/// builder leaves it alone; the installer overwrites it with its own slot.
pub const DISK_MARKER: [u8; 16] = *b"URMQTT-CFG-DISK\0";
pub const MARKER_LEN: usize = 16;
/// Largest blob a slot can hold.
pub const MAX_BLOB: usize = SLOT_SIZE - MARKER_LEN;
pub const SIG_KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
/// Length of the empty configuration: header, fingerprint, no signature.
pub const EMPTY_BLOB_LEN: usize = HEADER_LEN + FINGERPRINT_LEN + 1;

/// Writes the empty configuration (every field at its default) into `out`.
#[allow(clippy::indexing_slicing)] // constant ranges inside a fixed-size array
pub fn write_empty(out: &mut [u8; EMPTY_BLOB_LEN]) {
    out.fill(0);
    out[..8].copy_from_slice(&MAGIC);
    // The newest format: a template ISO's empty configuration declares the
    // format its kernel reads (the release mirror and the builder page ask).
    out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    let fp = fingerprint_of(&out[..HEADER_LEN]);
    out[HEADER_LEN..HEADER_LEN + FINGERPRINT_LEN].copy_from_slice(&fp);
}

const FINGERPRINT_DOMAIN: &[u8] = b"urmqtt-cfg-v1";
const SIGNATURE_DOMAIN: &[u8] = b"urmqtt-cfg-sig-v1";

/// SHA-256 over the domain tag and `data`.
pub fn fingerprint_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The bytes a signature covers.
pub fn signing_message(fingerprint: &[u8; 32]) -> [u8; SIGNATURE_DOMAIN.len() + 32] {
    let mut m = [0u8; SIGNATURE_DOMAIN.len() + 32];
    let (a, b) = m.split_at_mut(SIGNATURE_DOMAIN.len());
    a.copy_from_slice(SIGNATURE_DOMAIN);
    b.copy_from_slice(fingerprint);
    m
}

/// A detached signature slot's content.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub public_key: [u8; SIG_KEY_LEN],
    pub signature: [u8; SIG_LEN],
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({})", Hex(&self.public_key[..8]))
    }
}

/// Lower-case hex of a byte slice, for `Display`.
pub struct Hex<'a>(pub &'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

fn le16(b: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
}

fn le32(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

/// Little-endian integer of up to 8 bytes.
fn le_uint(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, x) in b.iter().take(8).enumerate() {
        v |= u64::from(*x) << (8 * i);
    }
    v
}

/// A parsed, structurally valid blob (fingerprint checked, tags known, each
/// value of the right shape and inside its range). Semantic rules that span
/// fields are [`crate::check`]'s.
#[derive(Clone, Copy)]
pub struct Blob<'a> {
    payload: &'a [u8],
    fingerprint: [u8; 32],
    signature: Option<Signature>,
    len: usize,
    version: u16,
}

impl core::fmt::Debug for Blob<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Blob(fingerprint {}, {} bytes)",
            Hex(&self.fingerprint),
            self.len
        )
    }
}

/// Iterator over the records of a payload.
#[derive(Clone)]
struct Records<'a>(&'a [u8]);

impl<'a> Iterator for Records<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let tag = le16(self.0)?;
        let len = le32(self.0.get(2..)?)? as usize;
        let value = self.0.get(6..6usize.checked_add(len)?)?;
        self.0 = self.0.get(6 + len..)?;
        Some((tag, value))
    }
}

impl<'a> Blob<'a> {
    /// Parses and validates `bytes` (a blob, possibly followed by padding,
    /// which must be zero). Fails closed on anything unexpected.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CfgError> {
        let bad = |m| err("blob", m);
        if bytes.get(..8) != Some(&MAGIC[..]) {
            return Err(bad("not a urmqtt-cfg blob (bad magic)"));
        }
        let version = bytes.get(8..).and_then(le16).ok_or(bad("truncated"))?;
        // Version 10 was never used by any format (and 14 to 17 are not
        // this code's): unknown, like one above the newest.
        if !known_version(version) {
            return Err(bad("unsupported format version"));
        }
        if bytes.get(10..).and_then(le16) != Some(0) {
            return Err(bad("reserved flags are set"));
        }
        let plen = bytes.get(12..).and_then(le32).ok_or(bad("truncated"))? as usize;
        if plen > MAX_BLOB {
            return Err(bad("payload longer than a slot"));
        }
        let payload_end = HEADER_LEN + plen;
        let payload = bytes
            .get(HEADER_LEN..payload_end)
            .ok_or(bad("payload is cut off"))?;
        let fp_end = payload_end + FINGERPRINT_LEN;
        let stored_fp: [u8; 32] = bytes
            .get(payload_end..fp_end)
            .and_then(|b| b.try_into().ok())
            .ok_or(bad("fingerprint is cut off"))?;
        let fingerprint = fingerprint_of(bytes.get(..payload_end).ok_or(bad("truncated"))?);
        if fingerprint != stored_fp {
            return Err(bad(
                "fingerprint mismatch: the blob is corrupt or was edited",
            ));
        }
        let (signature, len) = match bytes.get(fp_end) {
            Some(0) => (None, fp_end + 1),
            Some(1) => {
                let k = bytes
                    .get(fp_end + 1..fp_end + 1 + SIG_KEY_LEN)
                    .and_then(|b| <[u8; SIG_KEY_LEN]>::try_from(b).ok())
                    .ok_or(bad("signature is cut off"))?;
                let s = bytes
                    .get(fp_end + 1 + SIG_KEY_LEN..fp_end + 1 + SIG_KEY_LEN + SIG_LEN)
                    .and_then(|b| <[u8; SIG_LEN]>::try_from(b).ok())
                    .ok_or(bad("signature is cut off"))?;
                verify_signature(&fingerprint, &k, &s)?;
                (
                    Some(Signature {
                        public_key: k,
                        signature: s,
                    }),
                    fp_end + 1 + SIG_KEY_LEN + SIG_LEN,
                )
            }
            _ => return Err(bad("unknown signature kind")),
        };
        if bytes
            .get(len..)
            .is_some_and(|rest| rest.iter().any(|&b| b != 0))
        {
            return Err(bad("data after the blob is not zero padding"));
        }
        let blob = Self {
            payload,
            fingerprint,
            signature,
            len,
            version,
        };
        blob.check_records()?;
        Ok(blob)
    }

    fn check_records(&self) -> Result<(), CfgError> {
        let mut rest = self.payload;
        let mut last: Option<u16> = None;
        while !rest.is_empty() {
            let mut it = Records(rest);
            let (tag, value) = it
                .next()
                .ok_or(err("blob", "a record is cut off or overruns the payload"))?;
            if last.is_some_and(|l| tag <= l) {
                return Err(err(
                    "blob",
                    "records are not in strictly ascending tag order",
                ));
            }
            last = Some(tag);
            let field = fields::by_tag(tag).ok_or(err("blob", "unknown field tag"))?;
            if !field.stored {
                return Err(err(field.key, "this field is not stored in a blob"));
            }
            if field.since > self.version {
                return Err(err(
                    field.key,
                    "needs a newer blob format version than the blob declares",
                ));
            }
            check_value(field, value)?;
            rest = it.0;
        }
        Ok(())
    }

    /// The blob format version it declares.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// SHA-256 identifying this configuration.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Whether a (valid) signature is attached; the key is the signer's.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    /// Length of the blob proper (without padding).
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// The raw value of a field, if present.
    pub fn raw(&self, tag: u16) -> Option<&'a [u8]> {
        Records(self.payload)
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| v)
    }

    /// Every present record, in tag order.
    pub fn present(&self) -> impl Iterator<Item = (&'static Field, &'a [u8])> + 'a {
        Records(self.payload).filter_map(|(t, v)| fields::by_tag(t).map(|f| (f, v)))
    }

    // Typed accessors. Each returns the stored value or the field's
    // default. Passing a tag of another kind is a programming error and
    // yields the zero value.

    pub fn bool(&self, tag: u16) -> bool {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => v.first() == Some(&1),
            (None, Some(Kind::Bool(d))) => d,
            _ => false,
        }
    }

    pub fn uint(&self, tag: u16) -> u64 {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => le_uint(v),
            (None, Some(Kind::UInt { default, .. })) => default,
            _ => 0,
        }
    }

    /// An enum field's variant index.
    pub fn variant(&self, tag: u16) -> u8 {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => v.first().copied().unwrap_or(0),
            (None, Some(Kind::Enum { default, .. })) => default,
            _ => 0,
        }
    }

    pub fn str(&self, tag: u16) -> &'a str {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => core::str::from_utf8(v).unwrap_or(""),
            (None, Some(Kind::Str { default, .. })) => default,
            _ => "",
        }
    }

    /// A string-list field; the default list when absent.
    pub fn strs(&self, tag: u16) -> StrIter<'a> {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => StrIter::Raw(v),
            (None, Some(Kind::Strs { default, .. })) => StrIter::Default(default.iter()),
            _ => StrIter::Raw(&[]),
        }
    }

    /// A byte-string field (PEM); empty when absent.
    pub fn bin(&self, tag: u16) -> &'a [u8] {
        self.raw(tag).unwrap_or(&[])
    }

    /// A byte-string list field; empty when absent.
    pub fn bins(&self, tag: u16) -> BinIter<'a> {
        BinIter(self.raw(tag).unwrap_or(&[]))
    }

    pub fn ipv4(&self, tag: u16) -> Option<[u8; 4]> {
        self.raw(tag).and_then(|v| v.get(..4)?.try_into().ok())
    }

    /// Address and prefix length.
    pub fn cidr(&self, tag: u16) -> Option<([u8; 4], u8)> {
        let v = self.raw(tag)?;
        Some((v.get(..4)?.try_into().ok()?, *v.get(4)?))
    }

    pub fn key32(&self, tag: u16) -> Option<[u8; 32]> {
        self.raw(tag).and_then(|v| v.try_into().ok())
    }

    pub fn rate(&self, tag: u16) -> (u32, u32) {
        match (self.raw(tag), fields::by_tag(tag).map(|f| f.kind)) {
            (Some(v), _) => (
                v.get(..4).and_then(le32).unwrap_or(0),
                v.get(4..).and_then(le32).unwrap_or(0),
            ),
            (None, Some(Kind::Rate { tokens, per_ms })) => (tokens, per_ms),
            _ => (0, 0),
        }
    }

    /// One optional socket address.
    pub fn addr(&self, tag: u16) -> Option<([u8; 4], u16)> {
        let v = self.raw(tag)?;
        if v.is_empty() {
            return None;
        }
        Some((v.get(..4)?.try_into().ok()?, v.get(4..).and_then(le16)?))
    }

    pub fn addrs(&self, tag: u16) -> AddrIter<'a> {
        AddrIter(self.raw(tag).unwrap_or(&[]))
    }
}

/// The string list of a field.
#[derive(Clone)]
pub enum StrIter<'a> {
    Raw(&'a [u8]),
    Default(core::slice::Iter<'static, &'static str>),
}

impl<'a> Iterator for StrIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        match self {
            Self::Default(it) => it.next().copied(),
            Self::Raw(b) => {
                let n = le16(b)? as usize;
                let s = b.get(2..2 + n)?;
                *b = b.get(2 + n..)?;
                core::str::from_utf8(s).ok()
            }
        }
    }
}

/// The byte strings of a list field.
#[derive(Clone)]
pub struct BinIter<'a>(&'a [u8]);

impl<'a> Iterator for BinIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let n = le32(self.0)? as usize;
        let s = self.0.get(4..4usize.checked_add(n)?)?;
        self.0 = self.0.get(4 + n..)?;
        Some(s)
    }
}

/// The socket addresses of a list field.
#[derive(Clone)]
pub struct AddrIter<'a>(&'a [u8]);

impl Iterator for AddrIter<'_> {
    type Item = ([u8; 4], u16);
    fn next(&mut self) -> Option<Self::Item> {
        let ip: [u8; 4] = self.0.get(..4)?.try_into().ok()?;
        let port = le16(self.0.get(4..)?)?;
        self.0 = self.0.get(6..)?;
        Some((ip, port))
    }
}

fn verify_signature(
    fingerprint: &[u8; 32],
    key: &[u8; SIG_KEY_LEN],
    sig: &[u8; SIG_LEN],
) -> Result<(), CfgError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let bad = |m| err("signature", m);
    let k = VerifyingKey::from_bytes(key).map_err(|_| bad("not a valid Ed25519 public key"))?;
    k.verify_strict(&signing_message(fingerprint), &Signature::from_bytes(sig))
        .map_err(|_| bad("does not verify: the configuration was changed after signing"))
}

pub(crate) fn check_value(field: &Field, v: &[u8]) -> Result<(), CfgError> {
    let k = field.key;
    let shape = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(err(k, "value has the wrong size or shape"))
        }
    };
    match field.kind {
        Kind::Bool(_) => shape(matches!(v, [0] | [1])),
        Kind::UInt {
            bytes, min, max, ..
        } => {
            shape(v.len() == usize::from(bytes))?;
            let x = le_uint(v);
            if x < min || x > max {
                return Err(err(k, "out of range"));
            }
            Ok(())
        }
        Kind::Enum { variants, .. } => {
            shape(v.len() == 1)?;
            if usize::from(v.first().copied().unwrap_or(255)) >= variants.len() {
                return Err(err(k, "unknown variant"));
            }
            Ok(())
        }
        Kind::Str { max, .. } => {
            shape(v.len() <= usize::from(max))?;
            core::str::from_utf8(v)
                .map(|_| ())
                .map_err(|_| err(k, "not valid UTF-8"))
        }
        Kind::Strs {
            max_items, max_len, ..
        } => {
            let mut rest = v;
            let mut n = 0usize;
            while !rest.is_empty() {
                let len = rest
                    .get(..2)
                    .and_then(le16)
                    .ok_or(err(k, "list is cut off"))? as usize;
                let s = rest.get(2..2 + len).ok_or(err(k, "list is cut off"))?;
                if len > usize::from(max_len) {
                    return Err(err(k, "an entry is too long"));
                }
                if core::str::from_utf8(s).is_err() {
                    return Err(err(k, "an entry is not valid UTF-8"));
                }
                rest = rest.get(2 + len..).unwrap_or(&[]);
                n += 1;
            }
            if n > usize::from(max_items) {
                return Err(err(k, "too many entries"));
            }
            Ok(())
        }
        Kind::Bin { max } => shape(v.len() <= max as usize && !v.is_empty()),
        Kind::BinList { max_items, max } => {
            let mut rest = v;
            let mut n = 0usize;
            while !rest.is_empty() {
                let len = rest
                    .get(..4)
                    .and_then(le32)
                    .ok_or(err(k, "list is cut off"))? as usize;
                if len == 0 || len > max as usize {
                    return Err(err(k, "an entry is empty or too long"));
                }
                rest = rest.get(4 + len..).ok_or(err(k, "list is cut off"))?;
                n += 1;
            }
            if n > usize::from(max_items) {
                return Err(err(k, "too many entries"));
            }
            Ok(())
        }
        Kind::Ipv4 => shape(v.len() == 4),
        Kind::Cidr => {
            shape(v.len() == 5)?;
            if !(1..=32).contains(&v.get(4).copied().unwrap_or(0)) {
                return Err(err(k, "prefix length must be 1..=32"));
            }
            Ok(())
        }
        Kind::Rate { .. } => {
            shape(v.len() == 8)?;
            if v.get(..4).and_then(le32).unwrap_or(0) == 0
                || v.get(4..).and_then(le32).unwrap_or(0) == 0
            {
                return Err(err(k, "rate must be positive"));
            }
            Ok(())
        }
        Kind::Addr => shape(v.len() == 6),
        Kind::Addrs { max_items } => {
            shape(v.len().is_multiple_of(6))?;
            if v.len() / 6 > usize::from(max_items) {
                return Err(err(k, "too many entries"));
            }
            Ok(())
        }
        Kind::Key32 => shape(v.len() == 32),
    }
}

// --- the slot ------------------------------------------------------------

/// Which kind of slot a file or a region of an image is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// What the bootloader loads as the configuration.
    Boot,
    /// The installation image's unconfigured slot.
    Disk,
}

impl SlotKind {
    pub const fn marker(self) -> [u8; MARKER_LEN] {
        match self {
            Self::Boot => SLOT_MARKER,
            Self::Disk => DISK_MARKER,
        }
    }
}

/// The blob inside a slot of `kind`: the marker must match, the slot must be
/// exactly [`SLOT_SIZE`] bytes.
pub fn slot_blob(slot: &[u8], kind: SlotKind) -> Result<&[u8], CfgError> {
    if slot.len() != SLOT_SIZE {
        return Err(err("slot", "wrong size"));
    }
    if slot.get(..MARKER_LEN) != Some(&kind.marker()[..]) {
        return Err(err("slot", "marker mismatch"));
    }
    slot.get(MARKER_LEN..).ok_or(err("slot", "truncated"))
}

/// A slot file with `blob` in it: marker, blob, zero padding. `None` if the
/// blob does not fit.
#[cfg(any(test, feature = "alloc"))]
pub fn make_slot(kind: SlotKind, blob: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if blob.len() > MAX_BLOB {
        return None;
    }
    let mut v = alloc::vec![0u8; SLOT_SIZE];
    v.get_mut(..MARKER_LEN)?.copy_from_slice(&kind.marker());
    v.get_mut(MARKER_LEN..MARKER_LEN + blob.len())?
        .copy_from_slice(blob);
    Some(v)
}

/// Offsets of every slot of `kind` in `image`: the marker at a multiple of
/// 512, a parseable blob, and zeros to the end of the slot. A marker
/// elsewhere (for example the constant inside the kernel) is not a slot.
#[cfg(any(test, feature = "alloc"))]
pub fn find_slots(image: &[u8], kind: SlotKind) -> alloc::vec::Vec<usize> {
    let marker = kind.marker();
    let mut out = alloc::vec::Vec::new();
    let mut off = 0usize;
    while off + SLOT_SIZE <= image.len() {
        if image.get(off..off + MARKER_LEN) == Some(&marker[..])
            && image
                .get(off..off + SLOT_SIZE)
                .is_some_and(|s| slot_blob(s, kind).is_ok_and(|b| Blob::parse(b).is_ok()))
        {
            out.push(off);
            off += SLOT_SIZE;
        } else {
            off += 512;
        }
    }
    out
}
