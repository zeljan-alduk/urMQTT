//! ADR-257: `[devices] virtio_<name> = "off" | "auto" | "on"`, one key per
//! optional virtio driver. Optional, off by default; off writes nothing (the
//! blob keeps its version), auto and on need format 6; the strict parser,
//! the packer and the kernel's blob agree.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::fields::DEVICE_KEYS;

use crate::pack::{PackOptions, pack};
use crate::{ConfigError, DeviceMode, parse};

const DEV: &str = include_str!("../../../deploy/dev/config.toml");
const PROD: &str = include_str!("../../../deploy/prod/config.toml");
const BENCH: &str = include_str!("../../../deploy/bench/config.toml");
const DEMO: &str = include_str!("../../../deploy/demo/config.toml");

fn run(text: &str) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
    )
}

fn without_devices(t: &str) -> String {
    let mut inside = false;
    t.lines()
        .filter(|l| {
            if l.starts_with('[') {
                inside = l.trim() == "[devices]";
            }
            !inside
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_templates_say_auto_for_dev_and_off_elsewhere() {
    let dev = parse("dev", DEV).unwrap().devices;
    assert!(dev.iter().iter().all(|(_, m)| *m == DeviceMode::Auto));
    let prod = parse("prod", PROD).unwrap().devices;
    assert!(prod.iter().iter().all(|(_, m)| *m == DeviceMode::Off));
    for (env, t) in [("prod", PROD), ("bench", BENCH), ("demo", DEMO)] {
        // Every key is written out, off, so an operator sees what exists.
        for (_, key, _) in DEVICE_KEYS {
            let name = key.trim_start_matches("devices.");
            assert!(t.contains(&format!("\n{name} = \"off\"")), "{env}: {key}");
        }
    }
    // The section is optional: without it, everything off.
    let d = parse("dev", &without_devices(DEV)).unwrap().devices;
    assert!(d.iter().iter().all(|(_, m)| *m == DeviceMode::Off));
}

#[test]
fn the_keys_are_the_format_s_keys_in_its_order() {
    let d = crate::Devices::default();
    let ours: Vec<&str> = d.iter().iter().map(|(k, _)| *k).collect();
    let format: Vec<&str> = DEVICE_KEYS.iter().map(|(_, k, _)| *k).collect();
    assert_eq!(ours, format);
}

#[test]
fn the_three_words_parse_and_nothing_else_does() {
    let base = without_devices(DEV);
    for (_, key, _) in DEVICE_KEYS {
        let name = key.trim_start_matches("devices.");
        for (word, mode) in [
            ("off", DeviceMode::Off),
            ("auto", DeviceMode::Auto),
            ("on", DeviceMode::On),
        ] {
            let t = format!("{base}\n[devices]\n{name} = \"{word}\"\n");
            let d = parse("dev", &t).unwrap().devices;
            for (k, m) in d.iter() {
                assert_eq!(m, if k == *key { mode } else { DeviceMode::Off });
            }
            // Allowed outside dev too: the drivers are part of the release.
            let p = format!(
                "{}\n[devices]\n{name} = \"{word}\"\n",
                without_devices(PROD)
            );
            assert!(parse("prod", &p).is_ok(), "{key} = {word} in prod");
        }
        for bad in ["\"yes\"", "true", "\"On\"", "1"] {
            let t = format!("{base}\n[devices]\n{name} = {bad}\n");
            assert!(parse("dev", &t).is_err(), "{name} = {bad}");
        }
    }
    let t = format!("{base}\n[devices]\nvirtio_9p = \"on\"\n");
    assert!(parse("dev", &t).is_err(), "an unknown driver key");
}

#[test]
fn off_is_format_2_and_auto_and_on_are_format_6() {
    for (_, key, _) in DEVICE_KEYS {
        let name = key.trim_start_matches("devices.");
        let tag = urmqtt_cfg::fields::by_key(key).unwrap().tag;
        for (word, version, variant) in [("off", 2, 0), ("auto", 6, 1), ("on", 6, 2)] {
            let text = format!("[devices]\n{name} = \"{word}\"\n");
            let blob = run(&text).unwrap();
            let b = Blob::parse(&blob).unwrap();
            assert_eq!((b.version(), b.variant(tag)), (version, variant), "{text}");
            urmqtt_cfg::check::check(&b, false).unwrap();
        }
    }
    // Off is byte for byte the configuration without the section.
    assert_eq!(
        run("").unwrap(),
        run("[devices]\nvirtio_console = \"off\"\nvirtio_balloon = \"off\"\nvirtio_input = \"off\"\nvirtio_vsock = \"off\"\n").unwrap()
    );
}

/// ADR-270: `devices.virtio_net_interrupt = "auto" | "off"`. Optional, auto
/// by default; auto writes nothing (the blob keeps its version), off needs
/// format 11; anything else is refused.
#[test]
fn the_net_interrupt_key() {
    use crate::NetInterrupt;
    use urmqtt_cfg::fields::tag;
    for (env, t) in [("dev", DEV), ("prod", PROD)] {
        assert_eq!(
            parse(env, t).unwrap().devices.virtio_net_interrupt,
            NetInterrupt::Auto,
            "{env}"
        );
    }
    let auto = run("[devices]\nvirtio_net_interrupt = \"auto\"\n").unwrap();
    assert_eq!(auto, run("").unwrap(), "auto writes nothing");
    assert_eq!(Blob::parse(&auto).unwrap().version(), 2);
    let off = run("[devices]\nvirtio_net_interrupt = \"off\"\n").unwrap();
    let b = Blob::parse(&off).unwrap();
    assert_eq!((b.version(), b.variant(tag::DEV_NET_INTERRUPT)), (11, 1));
    for bad in ["\"on\"", "\"polling\"", "1", "true"] {
        assert!(
            run(&format!("[devices]\nvirtio_net_interrupt = {bad}\n")).is_err(),
            "{bad}"
        );
    }
}
