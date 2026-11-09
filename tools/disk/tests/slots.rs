//! NEXT-11 (ADR-295 to ADR-299): `urmqtt-disk slots` through the binary, on a
//! disk whose first boot (`gpt::prepare_with`, as the kernel runs it)
//! reserved the standby slot: status, the release signature, the build note,
//! the downgrade rules, one-way activation, confirm and rollback, update-boot
//! refusing an A/B disk, and a power cut at every write of each command.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use urmqtt_cfg::blob::{SLOT_SIZE, SlotKind, make_slot};
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;
use urmqtt_store::disk::MemDisk;
use urmqtt_store::gpt::{self, Options};
use urmqtt_store::slots::{self, Init};

const MIB: usize = 1 << 20;

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("urmqtt-disk-slots-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tmp(name: &str) -> PathBuf {
    dir().join(name)
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

fn ok(args: &[&str]) -> String {
    let o = disk(args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

fn refused(args: &[&str], why: &str) {
    let o = disk(args);
    let t = text(&o);
    assert!(!o.status.success(), "{args:?} succeeded: {t}");
    assert!(t.contains(why), "{args:?}: expected {why:?} in {t}");
}

/// A configuration slot of `format` (a key of that format set when 17).
fn config_slot(format17: bool) -> Vec<u8> {
    let mut b = Builder::new();
    b.uint(tag::NET_TLS_PORT, 8884).unwrap();
    if format17 {
        b.uint(tag::UPD_CONFIRM_AFTER, 5).unwrap();
    }
    make_slot(SlotKind::Boot, &b.finish(false).unwrap()).unwrap()
}

/// A 4 MiB ESP with a configuration slot at 1 MiB and the build note of
/// `version` (schema `schema`, configuration formats up to `cfg`) at 2 MiB
/// and 3 MiB (two kernels), or no note.
fn esp(version: Option<&str>, schema: u32, cfg: u16, slot: &[u8], seed: u8) -> Vec<u8> {
    let mut e: Vec<u8> = (0..4 * MIB).map(|i| (i * 7 % 241) as u8 ^ seed).collect();
    e[MIB..MIB + SLOT_SIZE].copy_from_slice(slot);
    if let Some(v) = version {
        let n = slots::build_note(v, schema, cfg);
        e[2 * MIB..2 * MIB + n.len()].copy_from_slice(&n);
        e[3 * MIB..3 * MIB + n.len()].copy_from_slice(&n);
    }
    e
}

/// An installed A/B disk: the image of `esp`, on 64 MiB, after the first
/// boot of a kernel of version `v0.6.0` and store schema 5.
fn ab_disk(name: &str, esp: &[u8]) -> PathBuf {
    let mut img = gpt::raw_image(esp).unwrap();
    img.resize(64 * MIB, 0);
    let m = MemDisk::from_image(img);
    let mut n = 0u8;
    let (_, steps) = gpt::prepare_with(
        m.device().as_mut(),
        || {
            n += 1;
            [n; 16]
        },
        Options {
            boot_slot: Some(Init {
                label: "v0.6.0",
                schema: 5,
            }),
        },
    )
    .unwrap();
    assert!(steps.created_boot_slot);
    let p = tmp(name);
    std::fs::write(&p, m.raw(0, 64 * MIB)).unwrap();
    p
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn write(name: &str, bytes: &[u8]) -> PathBuf {
    let p = tmp(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn status(p: &Path) -> String {
    ok(&["slots", "status", s(p)])
}

#[test]
fn stage_activate_confirm_and_roll_back() {
    let base = esp(Some("v0.6.0"), 5, 17, &config_slot(false), 0);
    let d = ab_disk("cycle.img", &base);
    let st = status(&d);
    assert!(
        st.contains("slot A [active]")
            && st.contains("v0.6.0 (store schema 5): confirmed, as installed"),
        "{st}"
    );
    assert!(
        st.contains("slot B [standby]") && st.contains(": empty"),
        "{st}"
    );
    assert!(st.contains("disk GUID "), "{st}");
    // The new release's ESP carries the dev template's configuration: the
    // disk's own is kept.
    let new = write(
        "new.esp",
        &esp(Some("v0.6.1"), 5, 17, &config_slot(false), 9),
    );
    refused(&["slots", "stage", s(&d), "--esp", s(&new)], "--unsigned");
    let before = std::fs::read(&d).unwrap();
    let t = ok(&["slots", "stage", s(&d), "--esp", s(&new), "--unsigned"]);
    assert!(t.contains("dry run"), "{t}");
    assert_eq!(
        std::fs::read(&d).unwrap(),
        before,
        "a dry run changes nothing"
    );
    let t = ok(&[
        "slots",
        "stage",
        s(&d),
        "--esp",
        s(&new),
        "--unsigned",
        "--write",
    ]);
    assert!(
        t.contains("UNSIGNED") && t.contains("slot B holds v0.6.1"),
        "{t}"
    );
    assert!(
        t.contains("kernel v0.6.1 (A/B protocol 1, store schema 5"),
        "{t}"
    );
    let st = status(&d);
    assert!(
        st.contains("v0.6.1 (store schema 5): confirmed, staged, commitment"),
        "{st}"
    );
    assert!(st.contains("slots activate"), "{st}");
    // Activation: B on trial, A the way back.
    let t = ok(&["slots", "activate", s(&d), "--tries", "2", "--write"]);
    assert!(t.contains("slot B (v0.6.1) is the boot entry, on trial for 2 boot(s); slot A (v0.6.0) is the way back"), "{t}");
    let st = status(&d);
    assert!(
        st.contains("slot B [active]") && st.contains("ON TRIAL, 2 trial boot(s) left"),
        "{st}"
    );
    refused(
        &[
            "slots",
            "stage",
            s(&d),
            "--esp",
            s(&new),
            "--unsigned",
            "--write",
        ],
        "still on trial",
    );
    // The data partition and the configuration: unchanged by all of this.
    let after = std::fs::read(&d).unwrap();
    let m = MemDisk::from_image(after.clone());
    let s0 = slots::read(m.device().as_mut()).unwrap().unwrap();
    let b = s0.active();
    let region = &after[b.first_lba as usize * 512..][..4 * MIB];
    assert_eq!(&region[MIB..MIB + SLOT_SIZE], &config_slot(false)[..]);
    // Confirm, then an operator's rollback.
    assert!(ok(&["slots", "confirm", s(&d), "--write"]).contains("is confirmed"));
    assert!(ok(&["slots", "confirm", s(&d), "--write"]).contains("nothing to do"));
    let t = ok(&["slots", "rollback", s(&d), "--write"]);
    assert!(
        t.contains("slot A is the boot entry again, slot B is marked bad"),
        "{t}"
    );
    let st = status(&d);
    assert!(st.contains("slot A [active]") && st.contains("BAD"), "{st}");
    refused(
        &["slots", "activate", s(&d), "--write"],
        "failed or was rolled back from",
    );
    assert!(
        ok(&["slots", "activate", s(&d), "--retry", "--write"]).contains("on trial for 3 boot(s)")
    );
    // update-boot does not overwrite a running slot of an A/B disk.
    refused(
        &["update-boot", s(&d), "--esp", s(&new), "--write"],
        "two boot slots",
    );
    refused(
        &[
            "update-boot",
            s(&d),
            "--esp",
            s(&new),
            "--write",
            "--in-place",
        ],
        "still on trial",
    );
}

/// minisign's legacy (`Ed`) format, signed with a throwaway key.
fn minisign(key: &SigningKey, id: [u8; 8], msg: &[u8]) -> (String, String) {
    let mut pk = b"Ed".to_vec();
    pk.extend_from_slice(&id);
    pk.extend_from_slice(&key.verifying_key().to_bytes());
    let public = format!(
        "untrusted comment: minisign public key (test)\n{}\n",
        Base64::encode_string(&pk)
    );
    let sig = key.sign(msg).to_bytes();
    let mut line = b"Ed".to_vec();
    line.extend_from_slice(&id);
    line.extend_from_slice(&sig);
    let trusted = "timestamp:0\tfile:SHA256SUMS";
    let mut covered = sig.to_vec();
    covered.extend_from_slice(trusted.as_bytes());
    let global = key.sign(&covered).to_bytes();
    let signature = format!(
        "untrusted comment: signature (test)\n{}\ntrusted comment: {trusted}\n{}\n",
        Base64::encode_string(&line),
        Base64::encode_string(&global)
    );
    (public, signature)
}

fn sha256_hex(b: &[u8]) -> String {
    urmqtt_config_tool::release::hex(&urmqtt_config_tool::release::sha256(b))
}

#[test]
fn a_release_image_is_staged_only_with_its_signature() {
    let d = ab_disk(
        "signed.img",
        &esp(Some("v0.6.0"), 5, 17, &config_slot(false), 0),
    );
    let rel = gpt::raw_image(&esp(Some("v0.6.1"), 5, 17, &config_slot(false), 3)).unwrap();
    let name = "urmqtt-template-v0.6.1-universal.img";
    let img = write(name, &rel);
    let sums = format!("{}  {name}\n", sha256_hex(&rel));
    let key = SigningKey::from_bytes(&[0x11; 32]);
    let (public, sig) = minisign(&key, [1, 2, 3, 4, 5, 6, 7, 8], sums.as_bytes());
    let (other_pub, _) = minisign(&SigningKey::from_bytes(&[0x22; 32]), [8; 8], b"");
    let sums_p = write("SHA256SUMS", sums.as_bytes());
    let sig_p = write("SHA256SUMS.minisig", sig.as_bytes());
    let pub_p = write("minisign.pub", public.as_bytes());
    let other_p = write("other.pub", other_pub.as_bytes());
    refused(
        &["slots", "stage", s(&d), "--image", s(&img), "--write"],
        "--sums SHA256SUMS",
    );
    refused(
        &[
            "slots",
            "stage",
            s(&d),
            "--image",
            s(&img),
            "--sums",
            s(&sums_p),
            "--sig",
            s(&sig_p),
            "--pubkey",
            s(&other_p),
            "--write",
        ],
        "not one of the given keys",
    );
    // A changed image is not the one the signature lists.
    let mut bad = rel.clone();
    bad[5 * MIB / 2] ^= 1;
    let tampered = tmp("tampered").join(name);
    std::fs::create_dir_all(tampered.parent().unwrap()).unwrap();
    std::fs::write(&tampered, &bad).unwrap();
    let o = disk(&[
        "slots",
        "stage",
        s(&d),
        "--image",
        s(&tampered),
        "--sums",
        s(&sums_p),
        "--sig",
        s(&sig_p),
        "--pubkey",
        s(&pub_p),
        "--write",
    ]);
    assert!(!o.status.success(), "{}", text(&o));
    // A changed SHA256SUMS fails the signature.
    let forged = write(
        "SHA256SUMS.forged",
        format!("{}  {name}\n", sha256_hex(&bad)).as_bytes(),
    );
    refused(
        &[
            "slots",
            "stage",
            s(&d),
            "--image",
            s(&tampered),
            "--sums",
            s(&forged),
            "--sig",
            s(&sig_p),
            "--pubkey",
            s(&pub_p),
            "--write",
        ],
        "signature",
    );
    let t = ok(&[
        "slots",
        "stage",
        s(&d),
        "--image",
        s(&img),
        "--sums",
        s(&sums_p),
        "--sig",
        s(&sig_p),
        "--pubkey",
        s(&other_p),
        "--pubkey",
        s(&pub_p),
        "--write",
    ]);
    assert!(
        t.contains("release signature ok: SHA256SUMS signed by key 0807060504030201"),
        "{t}"
    );
    assert!(t.contains("slot B holds v0.6.1"), "{t}");
}

#[test]
fn downgrades_and_kernels_without_a_note_are_refused() {
    let d = ab_disk(
        "rules.img",
        &esp(Some("v0.6.0"), 5, 17, &config_slot(true), 0),
    );
    for (what, e, why) in [
        (
            "no note",
            esp(None, 5, 17, &config_slot(false), 1),
            "carry no build note",
        ),
        (
            "older release",
            esp(Some("v0.5.9"), 5, 17, &config_slot(false), 2),
            "older than the running v0.6.0",
        ),
        (
            "older schema",
            esp(Some("v0.6.2"), 4, 17, &config_slot(false), 3),
            "store schema 4 but the store on the disk is schema 5",
        ),
        (
            "older config format",
            esp(Some("v0.6.2"), 5, 13, &config_slot(false), 4),
            "reads formats up to 13",
        ),
        (
            "two releases",
            {
                let mut e = esp(Some("v0.6.2"), 5, 17, &config_slot(false), 5);
                let n = slots::build_note("v0.6.3", 5, 17);
                e[3 * MIB..3 * MIB + n.len()].copy_from_slice(&n);
                e
            },
            "disagree",
        ),
    ] {
        let p = write(&format!("{what}.esp"), &e);
        refused(
            &[
                "slots",
                "stage",
                s(&d),
                "--esp",
                s(&p),
                "--unsigned",
                "--write",
            ],
            why,
        );
    }
    let old = write(
        "old.esp",
        &esp(Some("v0.5.9"), 5, 17, &config_slot(false), 2),
    );
    let t = ok(&[
        "slots",
        "stage",
        s(&d),
        "--esp",
        s(&old),
        "--unsigned",
        "--allow-downgrade",
        "--write",
    ]);
    assert!(t.contains("downgrade from v0.6.0 to v0.5.9 allowed"), "{t}");
    refused(
        &["slots", "activate", s(&d), "--write"],
        "older than the running",
    );
    // A store schema newer than the running kernel's: one-way, said so.
    let newer = write(
        "newer.esp",
        &esp(Some("v0.6.4"), 6, 17, &config_slot(false), 6),
    );
    ok(&[
        "slots",
        "stage",
        s(&d),
        "--esp",
        s(&newer),
        "--unsigned",
        "--write",
    ]);
    refused(&["slots", "activate", s(&d), "--write"], "--one-way");
    let t = ok(&["slots", "activate", s(&d), "--one-way", "--write"]);
    assert!(t.contains("on trial"), "{t}");
    assert!(status(&d).contains("one-way"));
}

/// A power cut at every write of stage, activate, confirm and rollback: the
/// disk is always in the state before or after (the active slot's bytes
/// whole, the states consistent), and the command can be run again.
#[test]
fn every_command_survives_a_cut_at_every_write() {
    let base = esp(Some("v0.6.0"), 5, 17, &config_slot(false), 0);
    let pristine = std::fs::read(ab_disk("cut-base.img", &base)).unwrap();
    let new = write(
        "cut-new.esp",
        &esp(Some("v0.6.1"), 5, 17, &config_slot(false), 9),
    );
    let staged_esp = {
        // What the staged slot holds: the new ESP with the disk's slot
        // (identical here) and zeros to the end of the region.
        let mut e = std::fs::read(&new).unwrap();
        e.resize(4 * MIB, 0);
        e
    };
    type Check<'a> = dyn Fn(&slots::Slots, &[u8]) -> bool + 'a;
    let active_bytes = |img: &[u8], sl: &slots::Slots| -> Vec<u8> {
        let a = sl.active();
        img[a.first_lba as usize * 512..][..4 * MIB].to_vec()
    };
    let run = |start: &[u8], cmd: &[&str], check: &Check<'_>| {
        for n in 1..=16u32 {
            let p = write("cut.img", start);
            let mut args: Vec<String> = cmd.iter().map(|x| x.replace("DISK", s(&p))).collect();
            args.push("--fault".into());
            args.push(format!("stop-after-write={n}"));
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let o = disk(&refs);
            let img = std::fs::read(&p).unwrap();
            let m = MemDisk::from_image(img.clone());
            let mut dev = m.device();
            gpt::prepare(dev.as_mut(), || [7; 16]).unwrap();
            let sl = slots::read(dev.as_mut()).unwrap().unwrap();
            let img = m.raw(0, 64 * MIB);
            assert!(
                check(&sl, &active_bytes(&img, &sl)),
                "{cmd:?} cut after write {n}: {:?} {:?}",
                sl.active(),
                sl.standby_slot()
            );
            if o.status.success() {
                return n;
            }
        }
        panic!("{cmd:?}: still cut after 16 writes");
    };
    let stage_cmd = [
        "slots",
        "stage",
        "DISK",
        "--esp",
        s(&new),
        "--unsigned",
        "--write",
    ];
    let n = run(&pristine, &stage_cmd, &|sl, a| {
        let b = sl.standby_slot().state;
        a == &base[..] && !sl.active().state.trial && (b.empty != b.sealed)
    });
    assert!(n >= 4, "stage writes {n} times");
    let p = write("cut-staged.img", &pristine);
    ok(&[
        "slots",
        "stage",
        s(&p),
        "--esp",
        s(&new),
        "--unsigned",
        "--write",
    ]);
    let staged = std::fs::read(&p).unwrap();
    run(
        &staged,
        &["slots", "activate", "DISK", "--write"],
        &|sl, a| {
            (a == &base[..] && !sl.active().state.trial)
                || (a == &staged_esp[..] && sl.active().state.trial)
        },
    );
    ok(&["slots", "activate", s(&p), "--write"]);
    let trial = std::fs::read(&p).unwrap();
    run(&trial, &["slots", "confirm", "DISK", "--write"], &|_, a| {
        a == &staged_esp[..]
    });
    run(
        &trial,
        &["slots", "rollback", "DISK", "--write"],
        &|sl, a| {
            (a == &staged_esp[..] && sl.active().state.trial)
                || (a == &base[..] && sl.standby_slot().state.bad)
        },
    );
}

#[test]
fn a_single_slot_disk_is_told_to_use_update_boot() {
    let e = esp(Some("v0.6.0"), 5, 17, &config_slot(false), 0);
    let mut img = gpt::raw_image(&e).unwrap();
    img.resize(64 * MIB, 0);
    let m = MemDisk::from_image(img);
    gpt::prepare(m.device().as_mut(), || [1; 16]).unwrap();
    let p = write("single.img", &m.raw(0, 64 * MIB));
    refused(&["slots", "status", s(&p)], "update-boot");
    let new = write(
        "single-new.esp",
        &esp(Some("v0.6.1"), 5, 17, &config_slot(false), 1),
    );
    refused(
        &[
            "slots",
            "stage",
            s(&p),
            "--esp",
            s(&new),
            "--unsigned",
            "--write",
        ],
        "one boot slot",
    );
    // update-boot still works on it.
    ok(&["update-boot", s(&p), "--esp", s(&new), "--write"]);
}
