//! ADR-297: the `[update]` section (`update.confirm`,
//! `update.confirm_after_s`, `update.trial_timeout_s`) through the TOML path.
//! A configuration that does not touch it is the blob it always was; any key
//! set needs format 17; the strict parser and the kernel's blob check
//! (`urmqtt_cfg::check`) accept and refuse the same values.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack, schema_json};
use crate::{ConfigError, UpdateConfirm, parse};

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

/// The documented defaults (auto, 60 s, 900 s), also for the shipped
/// development and benchmark configurations, which do not name the section.
#[test]
fn the_defaults_are_the_documented_ones() {
    for (env, text) in [
        ("dev", include_str!("../../../deploy/dev/config.toml")),
        ("prod", include_str!("../../../deploy/bench/config.toml")),
    ] {
        let u = parse(env, text).unwrap().update;
        assert_eq!(
            (u.confirm, u.confirm_after_s, u.trial_timeout_s),
            (UpdateConfirm::Auto, 60, 900),
            "{env}"
        );
    }
    let blob = pack_toml(
        "[update]\nconfirm = \"auto\"\nconfirm_after_s = 60\ntrial_timeout_s = 900\n",
    )
    .unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
    assert_eq!(Blob::parse(&blob).unwrap().version(), 2);
}

/// Any key set needs format 17 and writes exactly one record.
#[test]
fn any_key_set_needs_format_17() {
    for (set, t, v) in [
        ("confirm = \"operator\"", tag::UPD_CONFIRM, 1u64),
        ("confirm_after_s = 0", tag::UPD_CONFIRM_AFTER, 0),
        ("confirm_after_s = 899", tag::UPD_CONFIRM_AFTER, 899),
        ("trial_timeout_s = 0", tag::UPD_TRIAL_TIMEOUT, 0),
        ("trial_timeout_s = 86400", tag::UPD_TRIAL_TIMEOUT, 86_400),
    ] {
        let blob = pack_toml(&format!("[update]\n{set}\n")).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(b.version(), 17, "{set}");
        assert_eq!(b.present().count(), 1, "{set}: one record");
        let got = if t == tag::UPD_CONFIRM {
            u64::from(b.variant(t))
        } else {
            b.uint(t)
        };
        assert_eq!(got, v, "{set}");
        urmqtt_cfg::check::check(&b, false).expect("a release kernel accepts it");
    }
    let cfg = parse(
        "dev",
        &format!(
            "{}\n[update]\nconfirm = \"operator\"\nconfirm_after_s = 5\ntrial_timeout_s = 0\n",
            include_str!("../../../deploy/dev/config.toml")
        ),
    )
    .unwrap();
    assert_eq!(
        (
            cfg.update.confirm,
            cfg.update.confirm_after_s,
            cfg.update.trial_timeout_s
        ),
        (UpdateConfirm::Operator, 5, 0)
    );
}

/// Out of range, a word that is not a mode, an unknown key, and a trial
/// timeout an automatic confirmation cannot beat are refused, naming the key.
#[test]
fn refusals_name_their_keys() {
    for (text, key, what) in [
        ("confirm_after_s = 86401", "update.confirm_after_s", "0..=86400"),
        ("trial_timeout_s = 86401", "update.trial_timeout_s", "0..=86400"),
        ("trial_timeout_s = 60", "update.trial_timeout_s", "longer than"),
        (
            "confirm_after_s = 120\ntrial_timeout_s = 100",
            "update.trial_timeout_s",
            "longer than",
        ),
    ] {
        let e = pack_toml(&format!("[update]\n{text}\n")).unwrap_err();
        assert!(
            e.iter().any(|x| x.path == key && x.message.contains(what)),
            "{text}: {e:?}"
        );
    }
    for bad in [
        "confirm = \"manual\"",
        "confirm = \"Auto\"",
        "confirm = true",
        "confirm_after_s = -1",
        "trial_timeout_s = 4294967296",
        "tries = 3",
    ] {
        assert!(pack_toml(&format!("[update]\n{bad}\n")).is_err(), "{bad}");
    }
    // An operator confirms: the timeout is theirs to beat, any value goes.
    assert!(pack_toml("[update]\nconfirm = \"operator\"\ntrial_timeout_s = 30\n").is_ok());
}

/// The same verdict from the strict TOML path and from the kernel's blob
/// check, over the corner values of both numbers and both modes.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    for (mode, variant) in [("auto", 0u8), ("operator", 1)] {
        for after in [0u64, 1, 60, 899, 900, 86_400, 86_401] {
            for timeout in [0u64, 1, 60, 61, 900, 86_400, 86_401] {
                let toml = format!(
                    "[update]\nconfirm = \"{mode}\"\nconfirm_after_s = {after}\ntrial_timeout_s = {timeout}\n"
                );
                let by_toml = pack_toml(&toml).is_ok();
                let mut b = Builder::new();
                let by_blob = b.variant(tag::UPD_CONFIRM, variant).is_ok()
                    && b.uint(tag::UPD_CONFIRM_AFTER, after).is_ok()
                    && b.uint(tag::UPD_TRIAL_TIMEOUT, timeout).is_ok()
                    && b.finish(false).is_ok();
                assert_eq!(by_toml, by_blob, "{toml:?}");
            }
        }
    }
}

#[test]
fn the_schema_describes_the_keys() {
    let json = schema_json();
    assert_eq!(json.matches("\"since\":17").count(), 3);
    for (name, default) in [("confirm_after_s", 60), ("trial_timeout_s", 900)] {
        assert!(
            json.contains(&format!(
                "\"key\":\"update.{name}\",\"section\":\"update\",\"name\":\"{name}\",\"toml_key\":\"update.{name}\",\"type\":\"uint\",\"default\":{default},\"min\":0,\"max\":86400"
            )),
            "{name}"
        );
    }
    assert!(json.contains("\"key\":\"update.confirm\",\"section\":\"update\""));
}
