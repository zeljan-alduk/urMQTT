//! ADR-285: `limits.max_runtime_accounts` through the TOML path. A
//! configuration that does not touch it is the blob it always was (0: the
//! control channel refuses account commands); any other value needs format
//! 15; the strict parser and the kernel's blob check (`urmqtt_cfg::check`)
//! accept and refuse the same values.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, parse};

const NOW: u64 = 1_800_000_000;

fn pack_toml(text: &str) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: NOW,
            env: None,
        },
    )
}

#[test]
fn off_by_default_and_spelled_out_at_the_default_it_writes_nothing() {
    let l = parse("dev", include_str!("../../../deploy/dev/config.toml"))
        .unwrap()
        .limits;
    assert_eq!(l.max_runtime_accounts, 0);
    let blob = pack_toml("[limits]\nmax_runtime_accounts = 0\n").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

#[test]
fn a_value_needs_format_15_and_one_record() {
    for v in [1u64, 64, 1_024] {
        let blob = pack_toml(&format!("[limits]\nmax_runtime_accounts = {v}\n")).unwrap();
        let p = Blob::parse(&blob).unwrap();
        assert_eq!(p.version(), 15, "{v}");
        assert_eq!(p.present().count(), 1);
        assert_eq!(p.uint(tag::LIM_MAX_RUNTIME_ACCOUNTS), v);
    }
}

#[test]
fn the_range_is_checked_and_names_the_key() {
    let e = pack_toml("[limits]\nmax_runtime_accounts = 1025\n").unwrap_err();
    assert!(
        e.iter().any(|x| x.to_string().contains("max_runtime_accounts")),
        "{e:?}"
    );
    assert!(pack_toml("[limits]\nmax_runtime_accounts = -1\n").is_err());
    assert!(pack_toml("[limits]\nmax_runtime_accounts = 4294967296\n").is_err());
    assert!(pack_toml("[limits]\nmax_runtime_accounts = true\n").is_err());
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    for v in [0u64, 1, 2, 1023, 1024, 1025, 65_535, 4_294_967_295] {
        let by_toml = pack_toml(&format!("[limits]\nmax_runtime_accounts = {v}\n")).is_ok();
        let mut b = Builder::new();
        let by_blob = b.uint(tag::LIM_MAX_RUNTIME_ACCOUNTS, v).is_ok() && b.finish(false).is_ok();
        assert_eq!(by_toml, by_blob, "{v}");
        assert_eq!(by_toml, v <= 1024, "{v}");
    }
}

#[test]
fn the_schema_lists_the_key_with_its_range() {
    let json = schema_json();
    assert!(json.contains("max_runtime_accounts"));
}
