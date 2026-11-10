//! An edition's configuration keys (NOW-18, ADR-337): arbitrary bytes as a
//! blob payload into `Blob::parse_ext` with an extension table, and as TOML
//! into `pack_ext`. Never a panic; the extension table only ever adds what
//! it declares: every blob `parse` accepts, `parse_ext` accepts with the same
//! fingerprint, and a blob without a record in the reserved range means the
//! same to both; whatever `pack_ext` writes parses with the table and passes
//! the kernel's checks, and without an `[ext]` table it is what `pack` writes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_cfg::blob::{Blob, FORMAT_VERSION, MAGIC, fingerprint_of};
use urmqtt_cfg::ext::{self, field};
use urmqtt_cfg::fields::{Field, Kind, tag};
use urmqtt_config_schema::pack::{PackOptions, pack, pack_ext};

const EXT: &[Field] = &[
    field(
        0xF000,
        "ext.fuzz.n",
        Kind::UInt {
            bytes: 2,
            min: 1,
            max: 100,
            default: 1,
        },
        "",
        2,
    ),
    field(0xF001, "ext.fuzz.on", Kind::Bool(false), "", 2),
    field(
        0xF002,
        "ext.fuzz.mode",
        Kind::Enum {
            variants: &["a", "b"],
            default: 0,
        },
        "",
        23,
    ),
    field(
        0xF003,
        "ext.fuzz.name",
        Kind::Str {
            max: 8,
            default: "x",
        },
        "",
        2,
    ),
    field(
        0xFFFE,
        "ext.z.list",
        Kind::Strs {
            max_items: 3,
            max_len: 4,
            default: &[],
        },
        "",
        2,
    ),
];

fn assemble(payload: &[u8]) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    let fp = fingerprint_of(&v);
    v.extend_from_slice(&fp);
    v.push(0);
    v
}

fn read_all(b: &Blob<'_>) {
    for f in EXT {
        let _ = ext::bool_of(Some(b), f);
        let _ = ext::uint_of(Some(b), f);
        let _ = ext::variant_of(Some(b), f);
        let _ = ext::str_of(Some(b), f);
        let _ = ext::strs_of(Some(b), f).count();
    }
}

fuzz_target!(|data: &[u8]| {
    let wrapped = assemble(data);
    for bytes in [data, &wrapped[..]] {
        let open = Blob::parse(bytes);
        let with = Blob::parse_ext(bytes, EXT);
        if let Ok(o) = &open {
            let w = with.as_ref().expect("the table only adds");
            assert_eq!(o.fingerprint(), w.fingerprint());
        }
        if let Ok(w) = &with {
            read_all(w);
            let reserved = w.records().any(|(t, _)| ext::is_ext_tag(t));
            assert_eq!(
                open.is_ok(),
                !reserved,
                "only a reserved record tells them apart"
            );
            for dev in [false, true] {
                let _ = urmqtt_cfg::check::check(w, dev);
            }
        }
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut read = |_: &str| Err("no files".to_owned());
    let packed = pack_ext(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
        false,
        EXT,
    );
    if let Ok(blob) = &packed {
        let b = Blob::parse_ext(blob, EXT).expect("a packed blob parses with the table");
        read_all(&b);
        let dev = b.str(tag::ENV) == "dev";
        urmqtt_cfg::check::check(&b, dev).expect("a packed blob passes the kernel checks");
    }
    // The open packer refuses an `[ext]` table: whatever it packs has none, and the
    // edition packs the same bytes.
    let mut read = |_: &str| Err("no files".to_owned());
    if let Ok(plain) = pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
    ) {
        assert_eq!(
            Some(plain),
            packed.ok(),
            "without [ext] an edition packs what the open packer packs"
        );
    }
});
