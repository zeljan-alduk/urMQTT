//! NOW-18 (ADR-337): an edition's extension keys in the TOML table `[ext]`.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::ext::{self, field};
use urmqtt_cfg::fields::{Field, Kind, tag};

use crate::pack::{PackOptions, pack, pack_ext};

const NOW: u64 = 1_800_000_000;

const CHECK: Field = field(
    0xF000,
    "ext.example.edu_check",
    Kind::UInt {
        bytes: 4,
        min: 0,
        max: u32::MAX as u64,
        default: 0x5a5a_5a5a,
    },
    "A value written to the device.",
    2,
);
const MODE: Field = field(
    0xF001,
    "ext.example.mode",
    Kind::Enum {
        variants: &["auto", "off"],
        default: 0,
    },
    "Whether the driver runs.",
    2,
);
const ON: Field = field(
    0xF002,
    "ext.example.verbose",
    Kind::Bool(false),
    "Log more.",
    2,
);
const NAME: Field = field(
    0xF003,
    "ext.example.name",
    Kind::Str {
        max: 8,
        default: "",
    },
    "A label.",
    2,
);
const LIST: Field = field(
    0xF100,
    "ext.other.deep.list",
    Kind::Strs {
        max_items: 2,
        max_len: 4,
        default: &[],
    },
    "A list.",
    2,
);
const EXT: &[Field] = &[CHECK, MODE, ON, NAME, LIST];

fn no_files(_: &str) -> Result<Vec<u8>, String> {
    Err("no files in this test".into())
}

fn opts(read: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>) -> PackOptions<'_> {
    PackOptions {
        read,
        now_unix: NOW,
        env: None,
    }
}

fn packed(text: &str) -> Result<Vec<u8>, Vec<crate::ConfigError>> {
    let mut read = no_files;
    pack_ext(text, opts(&mut read), false, EXT)
}

fn errors(text: &str) -> Vec<(String, String)> {
    packed(text)
        .err()
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.path, e.message))
        .collect()
}

#[test]
fn the_open_packer_refuses_an_ext_table() {
    let mut read = no_files;
    let e = pack("[ext.example]\nedu_check = 1\n", opts(&mut read)).unwrap_err();
    assert!(!e.is_empty());
    // And with no `[ext]` table an edition packs what the open packer packs.
    let mut read = no_files;
    let open = pack("[network]\nmqtt_tls_port = 9883\n", opts(&mut read)).unwrap();
    assert_eq!(packed("[network]\nmqtt_tls_port = 9883\n").unwrap(), open);
}

#[test]
fn extension_keys_are_packed_in_the_reserved_range() {
    let text = "[network]\nmqtt_tls_port = 9883\n\n[ext.example]\nedu_check = 0x1234\nmode = \"off\"\nverbose = true\nname = \"lab\"\n\n[ext.other.deep]\nlist = [\"a\", \"bc\"]\n";
    let bytes = packed(text).unwrap();
    assert!(Blob::parse(&bytes).is_err(), "the open reader refuses it");
    let b = Blob::parse_ext(&bytes, EXT).unwrap();
    assert_eq!(b.uint(tag::NET_TLS_PORT), 9883);
    assert_eq!(ext::uint_of(Some(&b), &CHECK), 0x1234);
    assert_eq!(ext::variant_of(Some(&b), &MODE), "off");
    assert!(ext::bool_of(Some(&b), &ON));
    assert_eq!(ext::str_of(Some(&b), &NAME), "lab");
    assert_eq!(
        ext::strs_of(Some(&b), &LIST).collect::<Vec<_>>(),
        ["a", "bc"]
    );
    // Defaults write nothing.
    let defaults = packed("[ext.example]\nedu_check = 0x5a5a5a5a\nmode = \"auto\"\n").unwrap();
    assert_eq!(defaults, packed("").unwrap());
}

#[test]
fn wrong_extension_keys_and_values_are_named() {
    let e = errors(
        "[ext.example]\nunknown = 1\nedu_check = -1\nmode = \"on\"\nverbose = 1\nname = \"too long name\"\n[ext.other.deep]\nlist = [1]\n",
    );
    let paths: Vec<&str> = e.iter().map(|(p, _)| p.as_str()).collect();
    for key in [
        "ext.example.unknown",
        "ext.example.edu_check",
        "ext.example.mode",
        "ext.example.verbose",
        "ext.example.name",
        "ext.other.deep.list",
    ] {
        assert!(paths.contains(&key), "{key} in {e:?}");
    }
    assert!(!errors("ext = 1\n").is_empty());
    assert!(!errors("[ext]\nloose = true\n").is_empty());
    // An edition's own bad table is refused before anything is packed.
    let mut bad = CHECK;
    bad.tag = 0x10;
    let mut read = no_files;
    assert!(pack_ext("", opts(&mut read), false, &[bad]).is_err());
}
