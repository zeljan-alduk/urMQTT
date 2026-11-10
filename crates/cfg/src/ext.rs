//! The configuration of code that is not in this repository (NOW-18, ADR-337).
//!
//! A kernel built from this repository's crates by another repository (an
//! "edition", docs/EDITIONS.md §5) may add drivers that need configuration
//! keys of their own. Their fields live in a reserved tag range,
//! [`FIRST_TAG`]`..=`[`LAST_TAG`], and under the reserved TOML table `[ext]`
//! ([`KEY_PREFIX`]), so they never collide with a key this repository adds
//! later: no field of [`crate::fields::FIELDS`] uses either (a test checks).
//!
//! The open kernel, the open `urmqtt-config` and the builder page pass no
//! extension table: a blob with a record in the reserved range is refused
//! there like any unknown tag ("unknown field tag"), so an image configured
//! for a driver it does not have never boots without a word (the rule of
//! ADR-257). An edition passes its table to [`crate::Blob::parse_ext`], to
//! [`crate::build::Builder::with_extensions`] and to the packer.
//!
//! Only the simple kinds are allowed: `Bool`, `UInt`, `Enum`, `Str` and
//! `Strs`. [`check`] is a `const fn`, so an edition's table is checked when
//! its kernel is compiled (`urmqtt_kernel::image!`).

use crate::blob::Blob;
use crate::fields::{Field, Kind};

/// The first tag of the reserved range.
pub const FIRST_TAG: u16 = 0xF000;
/// The last tag of the reserved range (0xFFFF stays unused).
pub const LAST_TAG: u16 = 0xFFFE;
/// Every extension key starts with this: `ext.<section>.<name>`.
pub const KEY_PREFIX: &str = "ext.";
/// The most fields one edition may declare.
pub const MAX_FIELDS: usize = 256;

/// An extension field: stored, not derived, not dev-only, plain text items.
/// `since` is the oldest format version whose kernel of this edition reads it
/// (usually the format of the release the edition is built on).
pub const fn field(
    tag: u16,
    key: &'static str,
    kind: Kind,
    help: &'static str,
    since: u16,
) -> Field {
    Field {
        tag,
        key,
        kind,
        help,
        dev_only: false,
        stored: true,
        derived: false,
        since,
        item: crate::fields::Item::Text,
    }
}

/// Whether `tag` is in the reserved range.
pub const fn is_ext_tag(tag: u16) -> bool {
    tag >= FIRST_TAG && tag <= LAST_TAG
}

/// The extension field with this tag (only a tag of the reserved range can be one).
pub fn lookup(tag: u16, ext: &[Field]) -> Option<&Field> {
    if !is_ext_tag(tag) {
        return None;
    }
    ext.iter().find(|f| f.tag == tag)
}

/// The extension field with this TOML key.
pub fn lookup_key<'f>(key: &str, ext: &'f [Field]) -> Option<&'f Field> {
    ext.iter().find(|f| f.key == key)
}

#[allow(clippy::indexing_slicing)] // const fn: every index is below the length the loop checks
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `ext.<section>.<name>`: the prefix, then at least two dot-separated parts
/// of `[a-z0-9_]`, none empty.
#[allow(clippy::indexing_slicing)] // as in `bytes_eq`
const fn key_ok(key: &str) -> bool {
    let k = key.as_bytes();
    let p = KEY_PREFIX.as_bytes();
    if k.len() <= p.len() || k.len() > 64 {
        return false;
    }
    let mut i = 0;
    while i < p.len() {
        if k[i] != p[i] {
            return false;
        }
        i += 1;
    }
    let mut parts = 1;
    let mut run = 0;
    while i < k.len() {
        let c = k[i];
        if c == b'.' {
            if run == 0 {
                return false;
            }
            parts += 1;
            run = 0;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' {
            run += 1;
        } else {
            return false;
        }
        i += 1;
    }
    run > 0 && parts >= 2
}

#[allow(clippy::indexing_slicing)] // as in `bytes_eq`
const fn version_ok(v: u16) -> bool {
    if v < crate::blob::FORMAT_MIN || v > crate::blob::FORMAT_VERSION {
        return false;
    }
    let u = crate::blob::UNUSED_VERSIONS;
    let mut i = 0;
    while i < u.len() {
        if u[i] == v {
            return false;
        }
        i += 1;
    }
    true
}

#[allow(clippy::indexing_slicing)] // as in `bytes_eq`
const fn kind_ok(kind: Kind) -> bool {
    match kind {
        Kind::Bool(_) => true,
        Kind::UInt {
            bytes,
            min,
            max,
            default,
        } => {
            let width_ok = matches!(bytes, 1 | 2 | 4 | 8);
            let fits = bytes == 8 || max < (1u64 << (8 * bytes as u32));
            width_ok && fits && min <= default && default <= max
        }
        Kind::Enum { variants, default } => {
            !variants.is_empty() && variants.len() <= 255 && (default as usize) < variants.len()
        }
        Kind::Str { max, default } => default.len() <= max as usize,
        Kind::Strs {
            max_items,
            max_len,
            default,
        } => {
            if default.len() > max_items as usize {
                return false;
            }
            let mut i = 0;
            while i < default.len() {
                if default[i].len() > max_len as usize {
                    return false;
                }
                i += 1;
            }
            true
        }
        _ => false,
    }
}

/// Checks an edition's field table: at most [`MAX_FIELDS`]; tags in the
/// reserved range and strictly ascending; keys `ext.<section>.<name>`
/// (lower case, digits, `_`), unique; stored, not derived; a simple kind
/// whose default lies in its own range; `since` a format version this code
/// reads.
#[allow(clippy::indexing_slicing)] // as in `bytes_eq`
pub const fn check(fields: &[Field]) -> Result<(), &'static str> {
    if fields.len() > MAX_FIELDS {
        return Err("too many extension fields");
    }
    let mut i = 0;
    while i < fields.len() {
        let f = &fields[i];
        if !is_ext_tag(f.tag) {
            return Err("an extension field's tag is outside the reserved range 0xF000..=0xFFFE");
        }
        if i > 0 && fields[i - 1].tag >= f.tag {
            return Err("extension field tags must be strictly ascending");
        }
        if !key_ok(f.key) {
            return Err("an extension field's key must be ext.<section>.<name> ([a-z0-9_])");
        }
        let mut j = 0;
        while j < i {
            if bytes_eq(fields[j].key.as_bytes(), f.key.as_bytes()) {
                return Err("two extension fields have the same key");
            }
            j += 1;
        }
        if !f.stored || f.derived {
            return Err("an extension field must be stored and not derived");
        }
        if !kind_ok(f.kind) {
            return Err(
                "an extension field must be Bool, UInt, Enum, Str or Strs with a default in its range",
            );
        }
        if !version_ok(f.since) {
            return Err("an extension field's `since` must be a format version this code reads");
        }
        i += 1;
    }
    Ok(())
}

/// A `Bool` extension field's value in `blob`, or its default (also with no blob:
/// the built-in defaults). An accessor of another kind yields the zero value.
pub fn bool_of(blob: Option<&Blob<'_>>, f: &Field) -> bool {
    match (blob.and_then(|b| b.raw(f.tag)), f.kind) {
        (Some(v), Kind::Bool(_)) => v.first() == Some(&1),
        (None, Kind::Bool(d)) => d,
        _ => false,
    }
}

/// A `UInt` extension field's value in `blob`, or its default.
pub fn uint_of(blob: Option<&Blob<'_>>, f: &Field) -> u64 {
    match (blob.and_then(|b| b.raw(f.tag)), f.kind) {
        (Some(v), Kind::UInt { .. }) => crate::blob::le_uint(v),
        (None, Kind::UInt { default, .. }) => default,
        _ => 0,
    }
}

/// An `Enum` extension field's variant name in `blob`, or its default's.
pub fn variant_of(blob: Option<&Blob<'_>>, f: &Field) -> &'static str {
    let Kind::Enum { variants, default } = f.kind else {
        return "";
    };
    let i = blob
        .and_then(|b| b.raw(f.tag))
        .and_then(|v| v.first().copied())
        .unwrap_or(default);
    variants.get(usize::from(i)).copied().unwrap_or("")
}

/// A `Str` extension field's value in `blob`, or its default.
pub fn str_of<'a>(blob: Option<&Blob<'a>>, f: &Field) -> &'a str {
    match (blob.and_then(|b| b.raw(f.tag)), f.kind) {
        (Some(v), Kind::Str { .. }) => core::str::from_utf8(v).unwrap_or(""),
        (None, Kind::Str { default, .. }) => default,
        _ => "",
    }
}

/// A `Strs` extension field's entries in `blob`, or its default list.
pub fn strs_of<'a>(blob: Option<&Blob<'a>>, f: &Field) -> crate::blob::StrIter<'a> {
    match (blob.and_then(|b| b.raw(f.tag)), f.kind) {
        (Some(v), Kind::Strs { .. }) => crate::blob::StrIter::Raw(v),
        (None, Kind::Strs { default, .. }) => crate::blob::StrIter::Default(default.iter()),
        _ => crate::blob::StrIter::Raw(&[]),
    }
}
