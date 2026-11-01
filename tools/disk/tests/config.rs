//! C1c (ADR-217): the configuration slot in the ESP of a boot disk, through
//! the `urmqtt-disk` binary: `create --config`, `info`, and `update-boot`
//! keeping (or replacing) the configuration.

use std::path::PathBuf;
use std::process::{Command, Output};

use urmqtt_cfg::blob::{DISK_MARKER, SLOT_SIZE, SlotKind, make_slot};
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("urmqtt-disk-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn disk(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_urmqtt-disk"))
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn blob(port: u64) -> Vec<u8> {
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, port).unwrap();
    b.finish(false).unwrap()
}

/// An ESP of 4 MiB with a slot at 1 MiB.
fn esp(slot: &[u8]) -> Vec<u8> {
    let mut e: Vec<u8> = (0..4 << 20).map(|i| (i * 7 % 241) as u8).collect();
    e[1 << 20..(1 << 20) + SLOT_SIZE].copy_from_slice(slot);
    e
}

fn template_slot() -> Vec<u8> {
    let mut s = make_slot(SlotKind::Boot, &Builder::new().finish(false).unwrap()).unwrap();
    s[..16].copy_from_slice(&DISK_MARKER);
    s
}

fn fingerprint_of(port: u64) -> String {
    let b = blob(port);
    let p = urmqtt_cfg::Blob::parse(&b).unwrap();
    urmqtt_cfg::blob::Hex(p.fingerprint()).to_string()
}

#[test]
fn create_info_and_update_keep_the_configuration() {
    // A template ESP and a configuration.
    let template = tmp("template.esp");
    std::fs::write(&template, esp(&template_slot())).unwrap();
    let cfg = tmp("mine.blob");
    std::fs::write(&cfg, blob(9443)).unwrap();
    let img = tmp("disk.img");
    let o = disk(&[
        "create",
        img.to_str().unwrap(),
        "--esp",
        template.to_str().unwrap(),
        "--size",
        "64M",
        "--config",
        cfg.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", text(&o));

    // info shows it.
    let o = disk(&["info", img.to_str().unwrap()]);
    let t = text(&o);
    assert!(
        t.contains(&format!(
            "config: fingerprint {} (unsigned)",
            fingerprint_of(9443)
        )),
        "{t}"
    );

    // An update with the unconfigured template ESP keeps the disk's own.
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        template.to_str().unwrap(),
        "--write",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("kept the disk's own"), "{}", text(&o));
    let t = text(&disk(&["info", img.to_str().unwrap()]));
    assert!(t.contains(&fingerprint_of(9443)), "{t}");

    // An update with an ESP that carries another configuration also keeps it...
    let other = tmp("other.esp");
    let other_slot = make_slot(SlotKind::Boot, &blob(7777)).unwrap();
    std::fs::write(&other, esp(&other_slot)).unwrap();
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        other.to_str().unwrap(),
        "--write",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&disk(&["info", img.to_str().unwrap()]));
    assert!(t.contains(&fingerprint_of(9443)), "kept: {t}");

    // ...unless asked to replace it.
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        other.to_str().unwrap(),
        "--replace-config",
        "--write",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&disk(&["info", img.to_str().unwrap()]));
    assert!(t.contains(&fingerprint_of(7777)), "replaced: {t}");

    // --config sets one explicitly.
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        template.to_str().unwrap(),
        "--config",
        cfg.to_str().unwrap(),
        "--write",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&disk(&["info", img.to_str().unwrap()]));
    assert!(t.contains(&fingerprint_of(9443)), "set: {t}");

    // A dry run changes nothing and says what it would do.
    let before = std::fs::read(&img).unwrap();
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        other.to_str().unwrap(),
        "--replace-config",
    ]);
    assert!(text(&o).contains("dry run"), "{}", text(&o));
    assert_eq!(std::fs::read(&img).unwrap(), before);

    // Two policies at once are refused.
    let o = disk(&[
        "update-boot",
        img.to_str().unwrap(),
        "--esp",
        other.to_str().unwrap(),
        "--keep-config",
        "--replace-config",
    ]);
    assert!(!o.status.success());
}

#[test]
fn an_unconfigured_disk_says_so() {
    let template = tmp("t2.esp");
    std::fs::write(&template, esp(&template_slot())).unwrap();
    let img = tmp("t2.img");
    let o = disk(&[
        "create",
        img.to_str().unwrap(),
        "--esp",
        template.to_str().unwrap(),
    ]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&disk(&["info", img.to_str().unwrap()]));
    assert!(
        t.contains("config: not configured (the installation image's template slot)"),
        "{t}"
    );
    // An ESP without any slot (an image from before the runtime configuration).
    let old = tmp("old.esp");
    std::fs::write(&old, vec![0x5Au8; 2 << 20]).unwrap();
    let img2 = tmp("old.img");
    assert!(
        disk(&[
            "create",
            img2.to_str().unwrap(),
            "--esp",
            old.to_str().unwrap()
        ])
        .status
        .success()
    );
    let t = text(&disk(&["info", img2.to_str().unwrap()]));
    assert!(t.contains("config: none (an ESP from before"), "{t}");
}
