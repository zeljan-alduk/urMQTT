//! ADR-280: `limits.max_connections_per_ip` through the TOML path. A
//! configuration that does not touch it is the blob it always was (the limit is
//! then 1024); any other value, 0 (no limit) included, needs format 14; the
//! strict parser and the kernel's blob check accept and refuse the same values.

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
fn the_default_is_1024_and_writes_nothing() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
    ] {
        assert_eq!(
            parse(env, text).unwrap().limits.max_connections_per_ip,
            1024,
            "{env}"
        );
    }
    let blob = pack_toml("[limits]\nmax_connections_per_ip = 1024\n").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

#[test]
fn any_other_value_needs_format_14() {
    for v in [0u64, 1, 16, 1023, 1025, 1_000_000] {
        let blob = pack_toml(&format!("[limits]\nmax_connections_per_ip = {v}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 14, "{v}");
        assert_eq!(b.present().count(), 1, "{v}: one record");
        assert_eq!(b.uint(tag::LIM_MAX_CONNECTIONS_PER_IP), v);
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
    let cfg = parse(
        "dev",
        &include_str!("../../../deploy/dev/config.toml")
            .replace("[limits]\n", "[limits]\nmax_connections_per_ip = 5\n"),
    )
    .unwrap();
    assert_eq!(cfg.limits.max_connections_per_ip, 5);
}

#[test]
fn refusals_name_their_key() {
    for v in [1_000_001u64, 4_294_967_295] {
        let e = pack_toml(&format!("[limits]\nmax_connections_per_ip = {v}\n")).unwrap_err();
        assert!(
            e.iter().any(|x| x.path == "limits.max_connections_per_ip"
                && x.message.contains("0..=1000000")),
            "{v}: {e:?}"
        );
    }
    for bad in ["-1", "4294967296", "true", "\"many\""] {
        assert!(
            pack_toml(&format!("[limits]\nmax_connections_per_ip = {bad}\n")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn the_toml_path_and_the_blob_check_agree() {
    for v in [0u64, 1, 1023, 1024, 1025, 1_000_000, 1_000_001, 4_294_967_295] {
        let toml = format!("[limits]\nmax_connections_per_ip = {v}\n");
        let by_toml = pack_toml(&toml).is_ok();
        let mut b = Builder::new();
        let by_blob = b.uint(tag::LIM_MAX_CONNECTIONS_PER_IP, v).is_ok() && b.finish(false).is_ok();
        assert_eq!(by_toml, by_blob, "{toml:?}");
        assert_eq!(by_toml, v <= 1_000_000, "{toml:?}");
    }
}

#[test]
fn the_schema_describes_the_key() {
    let json = schema_json();
    assert!(
        json.contains("\"key\":\"limits.max_connections_per_ip\",\"section\":\"limits\",\"name\":\"max_connections_per_ip\",\"toml_key\":\"limits.max_connections_per_ip\",\"type\":\"uint\",\"default\":1024,\"min\":0,\"max\":1000000"),
        "{json}"
    );
    assert!(json.contains("\"since\":14"));
}
