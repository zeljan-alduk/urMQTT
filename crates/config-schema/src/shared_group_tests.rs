//! ADR-275: the shared-subscription group limits (`limits.max_shared_groups`,
//! `limits.max_shared_group_members`) through the TOML path. A configuration
//! that does not touch them is the blob it always was; either set needs
//! format 13; the strict parser and the kernel's blob check
//! (`urmqtt_cfg::check`) accept and refuse the same values.

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

/// The documented defaults (1024 and 1024), also for the shipped
/// configurations, which do not name the keys.
#[test]
fn the_defaults_are_the_documented_ones() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/prod/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let l = parse(env, text).unwrap().limits;
        assert_eq!(
            (l.max_shared_groups, l.max_shared_group_members),
            (1024, 1024),
            "{env}"
        );
    }
    // Spelled out at the defaults: no record, the base format.
    let blob =
        pack_toml("[limits]\nmax_shared_groups = 1024\nmax_shared_group_members = 1024\n").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

/// Either key set needs format 13 and writes exactly one record.
#[test]
fn either_key_set_needs_format_13() {
    for (set, t, v) in [
        ("max_shared_groups = 1", tag::LIM_MAX_SHARED_GROUPS, 1),
        (
            "max_shared_groups = 65535",
            tag::LIM_MAX_SHARED_GROUPS,
            65_535,
        ),
        (
            "max_shared_group_members = 1",
            tag::LIM_MAX_SHARED_GROUP_MEMBERS,
            1,
        ),
        (
            "max_shared_group_members = 65535",
            tag::LIM_MAX_SHARED_GROUP_MEMBERS,
            65_535,
        ),
    ] {
        let blob = pack_toml(&format!("[limits]\n{set}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 13, "{set}");
        assert_eq!(b.present().count(), 1, "{set}: one record");
        assert_eq!(b.uint(t), v, "{set}");
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
    // The full-TOML path too.
    let cfg = parse(
        "prod",
        &include_str!("../../../deploy/prod/config.toml").replace(
            "[limits]\n",
            "[limits]\nmax_shared_groups = 16\nmax_shared_group_members = 4\n",
        ),
    )
    .unwrap();
    assert_eq!(
        (
            cfg.limits.max_shared_groups,
            cfg.limits.max_shared_group_members
        ),
        (16, 4)
    );
}

/// 0 and 65536 are refused, naming the key and the range; a negative value
/// or one beyond u32 is refused by the TOML parser.
#[test]
fn refusals_name_their_keys() {
    for key in ["max_shared_groups", "max_shared_group_members"] {
        for v in [0u64, 65_536, 4_294_967_295] {
            let e = pack_toml(&format!("[limits]\n{key} = {v}\n")).unwrap_err();
            assert!(
                e.iter()
                    .any(|x| x.path == format!("limits.{key}") && x.message.contains("1..=65535")),
                "{key} = {v}: {e:?}"
            );
        }
        for bad in ["-1", "4294967296", "true"] {
            assert!(
                pack_toml(&format!("[limits]\n{key} = {bad}\n")).is_err(),
                "{key} = {bad}"
            );
        }
    }
    let e =
        pack_toml("[limits]\nmax_shared_groups = 0\nmax_shared_group_members = 0\n").unwrap_err();
    assert_eq!(e.len(), 2, "{e:?}");
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check. A value the blob builder cannot hold counts as refused there.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    for t in [
        tag::LIM_MAX_SHARED_GROUPS,
        tag::LIM_MAX_SHARED_GROUP_MEMBERS,
    ] {
        let key = urmqtt_cfg::fields::by_tag(t).unwrap().key;
        let name = key.strip_prefix("limits.").unwrap();
        for v in [0u64, 1, 2, 1023, 1024, 1025, 65_535, 65_536, 4_294_967_295] {
            let toml = format!("[limits]\n{name} = {v}\n");
            let by_toml = pack_toml(&toml).is_ok();
            let mut b = Builder::new();
            let by_blob = b.uint(t, v).is_ok() && b.finish(false).is_ok();
            assert_eq!(
                by_toml, by_blob,
                "{toml:?}: the TOML path says {by_toml}, the blob check says {by_blob}"
            );
            assert_eq!(by_toml, (1..=65_535).contains(&v), "{toml:?}");
        }
    }
}

#[test]
fn the_schema_describes_the_keys() {
    let json = schema_json();
    assert_eq!(json.matches("\"since\":13").count(), 2);
    for name in ["max_shared_groups", "max_shared_group_members"] {
        assert!(
            json.contains(&format!(
                "\"key\":\"limits.{name}\",\"section\":\"limits\",\"name\":\"{name}\",\"toml_key\":\"limits.{name}\",\"type\":\"uint\",\"default\":1024,\"min\":1,\"max\":65535"
            )),
            "{name}"
        );
    }
}
