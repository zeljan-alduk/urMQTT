//! ADR-256: `[console] virtio_gpu = "off" | "auto" | "on"`. Optional, off by
//! default; off writes nothing (the blob keeps its version), auto and on need
//! format 5; the strict parser, the packer and the kernel's blob agree.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack};
use crate::{ConfigError, VirtioGpuMode, parse};

const DEV: &str = include_str!("../../../deploy/dev/config.toml");
const PROD: &str = include_str!("../../../deploy/prod/config.toml");

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

/// The templates without their `[console]` section.
fn without_console(t: &str) -> String {
    let mut inside = false;
    t.lines()
        .filter(|l| {
            if l.starts_with('[') {
                inside = l.trim() == "[console]";
            }
            !inside
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_templates_say_auto_for_dev_and_off_for_production() {
    assert_eq!(
        parse("dev", DEV).unwrap().console.virtio_gpu,
        VirtioGpuMode::Auto
    );
    assert_eq!(
        parse("prod", PROD).unwrap().console.virtio_gpu,
        VirtioGpuMode::Off
    );
    // The section is optional: without it, off.
    for (env, t) in [("dev", DEV), ("prod", PROD)] {
        assert_eq!(
            parse(env, &without_console(t)).unwrap().console.virtio_gpu,
            VirtioGpuMode::Off
        );
    }
}

#[test]
fn the_three_words_parse_and_nothing_else_does() {
    let base = without_console(DEV);
    for (word, mode) in [
        ("off", VirtioGpuMode::Off),
        ("auto", VirtioGpuMode::Auto),
        ("on", VirtioGpuMode::On),
    ] {
        let t = format!("{base}\n[console]\nvirtio_gpu = \"{word}\"\n");
        assert_eq!(parse("dev", &t).unwrap().console.virtio_gpu, mode);
        // Allowed outside dev too: it changes what is shown, not what is served.
        let p = format!("{}\n[console]\nvirtio_gpu = \"{word}\"\n", without_console(PROD));
        assert_eq!(parse("prod", &p).unwrap().console.virtio_gpu, mode);
    }
    for bad in [
        "virtio_gpu = \"yes\"",
        "virtio_gpu = true",
        "virtio_gpu = \"Auto\"",
        "virtio_gpu = 1",
        "framebuffer = \"off\"",
    ] {
        let t = format!("{base}\n[console]\n{bad}\n");
        assert!(parse("dev", &t).is_err(), "{bad}");
    }
}

#[test]
fn off_is_format_2_and_auto_and_on_are_format_5() {
    for (text, version, variant) in [
        ("", 2, 0),
        ("[console]\nvirtio_gpu = \"off\"\n", 2, 0),
        ("[console]\nvirtio_gpu = \"auto\"\n", 5, 1),
        ("[console]\nvirtio_gpu = \"on\"\n", 5, 2),
    ] {
        let blob = run(text).unwrap();
        let b = Blob::parse(&blob).unwrap();
        assert_eq!(
            (b.version(), b.variant(tag::CON_VIRTIO_GPU)),
            (version, variant),
            "{text}"
        );
        urmqtt_cfg::check::check(&b, false).unwrap();
    }
    // Off is byte for byte the configuration without the section.
    assert_eq!(run("").unwrap(), run("[console]\nvirtio_gpu = \"off\"\n").unwrap());
}
