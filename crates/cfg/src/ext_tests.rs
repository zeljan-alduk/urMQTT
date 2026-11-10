//! The reserved tag range and the extension fields of an edition (NOW-18, ADR-337).

use crate::blob::{self, Blob};
use crate::build::{self, Builder};
use crate::ext::{self, FIRST_TAG, LAST_TAG, field};
use crate::fields::{FIELDS, Field, Kind, tag};

const QUEUES: Field = field(
    0xF000,
    "ext.example.queues",
    Kind::UInt {
        bytes: 2,
        min: 1,
        max: 64,
        default: 1,
    },
    "Queues of the example device.",
    23,
);
const MODE: Field = field(
    0xF001,
    "ext.example.mode",
    Kind::Enum {
        variants: &["auto", "off", "on"],
        default: 0,
    },
    "Whether the example driver runs.",
    2,
);
const NAME: Field = field(
    0xF002,
    "ext.example.name",
    Kind::Str {
        max: 16,
        default: "",
    },
    "A label.",
    2,
);
const FLAG: Field = field(0xF003, "ext.example.flag", Kind::Bool(false), "A switch.", 2);
const LIST: Field = field(
    0xF010,
    "ext.other.list",
    Kind::Strs {
        max_items: 4,
        max_len: 8,
        default: &["a"],
    },
    "A list.",
    2,
);
const EXT: &[Field] = &[QUEUES, MODE, NAME, FLAG, LIST];
const _: () = assert!(ext::check(EXT).is_ok());

#[test]
fn no_open_field_is_in_the_reserved_range_or_the_ext_table() {
    for f in FIELDS {
        assert!(!ext::is_ext_tag(f.tag), "{} uses a reserved tag", f.key);
        assert!(!f.key.starts_with(ext::KEY_PREFIX), "{} uses the [ext] table", f.key);
        assert!(f.key != "ext", "{}", f.key);
    }
    assert!(FIRST_TAG < LAST_TAG && LAST_TAG < u16::MAX);
}

#[test]
fn an_open_reader_refuses_a_reserved_tag() {
    let mut b = Builder::with_extensions(EXT).unwrap();
    b.uint(QUEUES.tag, 4).unwrap();
    let bytes = b.finish(false).unwrap();
    // The open kernel and the open tools pass no table: an unknown tag.
    let e = Blob::parse(&bytes).err().unwrap();
    assert_eq!((e.key, e.msg), ("blob", "unknown field tag"));
    // The open builder cannot write it either.
    assert!(Builder::new().uint(QUEUES.tag, 4).is_err());
    // The edition reads it.
    let p = Blob::parse_ext(&bytes, EXT).unwrap();
    assert_eq!(ext::uint_of(Some(&p), &QUEUES), 4);
    assert_eq!(p.version(), 23, "the field's `since` decides the format");
}

#[test]
fn values_and_defaults_round_trip() {
    let empty = Builder::with_extensions(EXT).unwrap().finish(false).unwrap();
    assert_eq!(empty, Builder::new().finish(false).unwrap(), "defaults write nothing");
    let p = Blob::parse_ext(&empty, EXT).unwrap();
    assert_eq!(ext::uint_of(Some(&p), &QUEUES), 1);
    assert_eq!(ext::variant_of(Some(&p), &MODE), "auto");
    assert_eq!(ext::str_of(Some(&p), &NAME), "");
    assert!(!ext::bool_of(Some(&p), &FLAG));
    assert_eq!(ext::strs_of(Some(&p), &LIST).collect::<Vec<_>>(), ["a"]);
    // No configuration at all (no module): the same defaults.
    assert_eq!(ext::uint_of(None, &QUEUES), 1);
    assert_eq!(ext::variant_of(None, &MODE), "auto");
    assert_eq!(ext::str_of(None, &NAME), "");
    assert!(!ext::bool_of(None, &FLAG));
    assert_eq!(ext::strs_of(None, &LIST).collect::<Vec<_>>(), ["a"]);

    let mut b = Builder::with_extensions(EXT).unwrap();
    b.variant(MODE.tag, 2).unwrap();
    b.str(NAME.tag, "gvnic").unwrap();
    b.bool(FLAG.tag, true).unwrap();
    b.strs(LIST.tag, &["x", "yy"]).unwrap();
    b.uint(tag::NET_TLS_PORT, 9883).unwrap();
    let bytes = b.finish(false).unwrap();
    let p = Blob::parse_ext(&bytes, EXT).unwrap();
    assert_eq!(p.version(), blob::BASE_VERSION);
    assert_eq!(ext::variant_of(Some(&p), &MODE), "on");
    assert_eq!(ext::str_of(Some(&p), &NAME), "gvnic");
    assert!(ext::bool_of(Some(&p), &FLAG));
    assert_eq!(ext::strs_of(Some(&p), &LIST).collect::<Vec<_>>(), ["x", "yy"]);
    assert_eq!(p.uint(tag::NET_TLS_PORT), 9883);
    // An accessor of another kind yields the zero value, never a panic.
    assert_eq!(ext::uint_of(Some(&p), &NAME), 0);
    assert_eq!(ext::str_of(Some(&p), &QUEUES), "");
    // Signed like any blob.
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[7; 32]);
    let signed = build::sign_ext(&bytes, EXT, |m| {
        (sk.verifying_key().to_bytes(), sk.sign(m).to_bytes())
    })
    .unwrap();
    assert!(Blob::parse_ext(&signed, EXT).unwrap().signature().is_some());
    assert!(build::sign(&bytes, |m| (sk.verifying_key().to_bytes(), sk.sign(m).to_bytes())).is_err());
}

#[test]
fn ranges_and_shapes_of_extension_fields_are_checked() {
    let mut b = Builder::with_extensions(EXT).unwrap();
    assert!(b.uint(QUEUES.tag, 65).is_err());
    assert!(b.uint(QUEUES.tag, 0).is_err());
    assert!(b.variant(MODE.tag, 3).is_err());
    assert!(b.str(NAME.tag, "seventeen chars!!").is_err());
    assert!(b.strs(LIST.tag, &["a", "b", "c", "d", "e"]).is_err());
    // A tag in the range the edition does not declare.
    assert!(b.uint(0xF0FF, 1).is_err());
}

#[test]
fn a_bad_table_is_refused() {
    let bad = |fields: &[Field]| ext::check(fields).is_err() && Builder::with_extensions(fields).is_err();
    let mut f = QUEUES;
    f.tag = 0x0100;
    assert!(bad(&[f]), "outside the range");
    f = QUEUES;
    f.tag = 0xFFFF;
    assert!(bad(&[f]), "0xFFFF is not in the range");
    assert!(bad(&[MODE, QUEUES]), "not ascending");
    for key in ["queues", "ext.queues", "ext..x", "ext.a.", "ext.A.b", "ext.a-b.c", "net.mtu"] {
        f = QUEUES;
        f.key = key;
        assert!(bad(&[f]), "{key}");
    }
    f = MODE;
    f.key = QUEUES.key;
    assert!(bad(&[QUEUES, f]), "duplicate key");
    f = QUEUES;
    f.stored = false;
    assert!(bad(&[f]));
    f = QUEUES;
    f.derived = true;
    assert!(bad(&[f]));
    for since in [0, 10, 21, blob::FORMAT_VERSION + 1] {
        f = QUEUES;
        f.since = since;
        assert!(bad(&[f]), "since {since}");
    }
    for kind in [
        Kind::Ipv4,
        Kind::Bin { max: 4 },
        Kind::Rate {
            tokens: 1,
            per_ms: 1,
        },
        Kind::UInt {
            bytes: 3,
            min: 0,
            max: 1,
            default: 0,
        },
        Kind::UInt {
            bytes: 1,
            min: 0,
            max: 256,
            default: 0,
        },
        Kind::UInt {
            bytes: 2,
            min: 2,
            max: 4,
            default: 1,
        },
        Kind::Enum {
            variants: &[],
            default: 0,
        },
        Kind::Enum {
            variants: &["a"],
            default: 1,
        },
        Kind::Str {
            max: 1,
            default: "ab",
        },
        Kind::Strs {
            max_items: 0,
            max_len: 4,
            default: &["a"],
        },
    ] {
        f = QUEUES;
        f.kind = kind;
        assert!(bad(&[f]), "{kind:?}");
    }
    let many: Vec<Field> = (0..=ext::MAX_FIELDS as u16)
        .map(|i| field(FIRST_TAG + i, "ext.a.b", Kind::Bool(false), "", 2))
        .collect();
    assert!(ext::check(&many).is_err());
    // A parser handed a bad table refuses every blob rather than guess.
    let empty = Builder::new().finish(false).unwrap();
    f = QUEUES;
    f.tag = 7;
    assert!(Blob::parse_ext(&empty, &[f]).is_err());
}

#[test]
fn an_extension_blob_is_still_checked_as_a_whole() {
    // Records stay ascending: an extension record sorts after every open one.
    let mut b = Builder::with_extensions(EXT).unwrap();
    b.uint(QUEUES.tag, 2).unwrap();
    b.uint(tag::NET_TLS_PORT, 9000).unwrap();
    let bytes = b.finish(false).unwrap();
    let p = Blob::parse_ext(&bytes, EXT).unwrap();
    // Only the open fields are `present` (the open tools list those).
    assert!(p.present().all(|(f, _)| !ext::is_ext_tag(f.tag)));
    // Every flipped bit is still refused.
    for i in 0..bytes.len() * 8 {
        let mut m = bytes.clone();
        m[i / 8] ^= 1 << (i % 8);
        assert!(Blob::parse_ext(&m, EXT).is_err(), "bit {i}");
    }
}
