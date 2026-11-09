//! `urmqtt-disk keys` and `--passphrase-file` (LATER-7, ADR-327):
//! - an image-key disk gets a passphrase without a rewrite, after which the
//!   passphrase opens it for every command;
//! - change, a recovery slot, remove (never the last), unwrap back to a key
//!   file (`--key-out`), the dry run that writes nothing;
//! - wrong passphrases, a too-short new passphrase, misuse of the options;
//! - a power cut at every write of `keys add` and `keys change` (clean and
//!   torn, through `--fault`): the old passphrase or the new one opens the
//!   disk, never neither, and the data is intact;
//! - `rekey` empties the slots that wrapped the old key.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use urmqtt_disk::host;
use urmqtt_disk::keys::{self, Auth, Op};
use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::disk::{MemDisk, unlock};
use urmqtt_store::gpt;
use urmqtt_store::keyslot::{MIN_ITERATIONS, Zeroizing};
use urmqtt_store::part::Partition;
use urmqtt_store::{BlockDevice, Disk};

const MIB: usize = 1 << 20;
const OLD: &str = "the old passphrase";
const NEW: &str = "the new passphrase";
const REC: &str = "the recovery passphrase";

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("urmqtt-disk-keys-{}", std::process::id()));
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

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn write(name: &str, bytes: &[u8]) -> PathBuf {
    let p = tmp(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn key() -> [u8; KEY_BYTES] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(5))
}

fn key_file() -> PathBuf {
    let hex: String = key().iter().map(|b| format!("{b:02x}")).collect();
    write("disk.key", format!("{hex}\n").as_bytes())
}

/// A booted boot disk (GPT, ESP, data partition) of 64 MiB whose data
/// partition is encrypted with `key()` (the image-key way of S7) and holds
/// the populated fixture.
fn image_key_disk(name: &str) -> PathBuf {
    // SQLite runs in this process (populate): one test at a time.
    let _g = lock();
    let esp: Vec<u8> = (0..4 * MIB).map(|i| (i * 7 % 241) as u8).collect();
    let mut img = gpt::raw_image(&esp).unwrap();
    img.resize(64 * MIB, 0);
    let m = MemDisk::from_image(img);
    let mut n = 0u8;
    let (d, _) = gpt::prepare(m.device().as_mut(), || {
        n += 1;
        [n; 16]
    })
    .unwrap();
    let part = Partition::new(m.device(), d.first_lba, d.sectors()).unwrap();
    let (disk, _) = Disk::open_keyed(Box::new(part), || [0x42; 16], 8, Some(&key())).unwrap();
    host::populate(disk).unwrap();
    let p = tmp(name);
    std::fs::write(&p, m.raw(0, 64 * MIB)).unwrap();
    p
}

fn pass(name: &str, p: &str) -> PathBuf {
    write(name, format!("{p}\n").as_bytes())
}

#[test]
fn the_key_commands_end_to_end() {
    let d = image_key_disk("e2e.img");
    let p = s(&d);
    let kf = key_file();
    let (old, new, rec) = (pass("old", OLD), pass("new", NEW), pass("rec", REC));
    let it = MIN_ITERATIONS.to_string();
    let it = it.as_str();
    // No key needed to list.
    let l = ok(&["keys", p]);
    assert!(
        l.contains("key from the image") && l.contains("key slot 0: empty"),
        "{l}"
    );
    // A dry run writes nothing.
    let before = std::fs::read(&d).unwrap();
    let o = ok(&[
        "keys",
        p,
        "add",
        "--key",
        s(&kf),
        "--new-passphrase-file",
        s(&old),
        "--iterations",
        it,
    ]);
    assert!(o.contains("dry run"), "{o}");
    assert_eq!(std::fs::read(&d).unwrap(), before);
    // Wrap the image key under a passphrase: the data is not rewritten (only
    // the two superblock sectors change).
    ok(&[
        "keys",
        p,
        "add",
        "--key",
        s(&kf),
        "--new-passphrase-file",
        s(&old),
        "--iterations",
        it,
        "--write",
    ]);
    let after = std::fs::read(&d).unwrap();
    let changed: Vec<usize> = (0..after.len() / 512)
        .filter(|i| before[i * 512..(i + 1) * 512] != after[i * 512..(i + 1) * 512])
        .collect();
    // Only sectors of the two superblocks (LBA 0..8 and 24..32 of the data
    // partition) changed, some in each.
    let first = gpt_first_lba(&after);
    let rel: Vec<u64> = changed.iter().map(|&i| i as u64 - first).collect();
    assert!(
        rel.iter().all(|&r| r < 8 || (24..32).contains(&r)),
        "{rel:?}"
    );
    assert!(
        rel.iter().any(|&r| r < 8) && rel.iter().any(|&r| r >= 24),
        "{rel:?}"
    );
    let l = ok(&["keys", p]);
    assert!(
        l.contains("not in the image")
            && l.contains("key slot 0: passphrase, PBKDF2-HMAC-SHA-256 10000 iterations"),
        "{l}"
    );
    // The passphrase opens the disk for every command.
    assert!(ok(&["verify", p, "--passphrase-file", s(&old)]).contains("verify"));
    refused(
        &["verify", p, "--passphrase-file", s(&new)],
        "no key slot opens with this passphrase",
    );
    refused(&["verify", p], "give its key with --key FILE");
    refused(
        &["verify", p, "--key", s(&kf), "--passphrase-file", s(&old)],
        "not both",
    );
    // A recovery passphrase in slot 1, opened by the first one.
    ok(&[
        "keys",
        p,
        "add",
        "--passphrase-file",
        s(&old),
        "--new-passphrase-file",
        s(&rec),
        "--iterations",
        it,
        "--write",
    ]);
    refused(
        &[
            "keys",
            p,
            "add",
            "--passphrase-file",
            s(&old),
            "--new-passphrase-file",
            s(&new),
            "--write",
        ],
        "both key slots are in use",
    );
    // Change the one the old passphrase opens.
    let o = ok(&[
        "keys",
        p,
        "change",
        "--passphrase-file",
        s(&old),
        "--new-passphrase-file",
        s(&new),
        "--iterations",
        it,
        "--write",
    ]);
    assert!(o.contains("key slot 0: new passphrase"), "{o}");
    refused(
        &["verify", p, "--passphrase-file", s(&old)],
        "no key slot opens",
    );
    ok(&["verify", p, "--passphrase-file", s(&new)]);
    ok(&["verify", p, "--passphrase-file", s(&rec)]);
    // New passphrases follow the rules.
    let short = pass("short", "too short");
    refused(
        &[
            "keys",
            p,
            "change",
            "--passphrase-file",
            s(&new),
            "--new-passphrase-file",
            s(&short),
            "--write",
        ],
        "at least 12 characters",
    );
    refused(
        &[
            "keys",
            p,
            "change",
            "--passphrase-file",
            s(&new),
            "--new-passphrase-file",
            s(&rec),
            "--iterations",
            "5",
            "--write",
        ],
        "--iterations must be in",
    );
    // Remove the recovery slot; the last one cannot go.
    refused(
        &["keys", p, "remove", "--passphrase-file", s(&new), "--write"],
        "--slot N",
    );
    ok(&[
        "keys",
        p,
        "remove",
        "--slot",
        "1",
        "--passphrase-file",
        s(&new),
        "--write",
    ]);
    refused(
        &["verify", p, "--passphrase-file", s(&rec)],
        "no key slot opens",
    );
    refused(
        &[
            "keys",
            p,
            "remove",
            "--slot",
            "0",
            "--passphrase-file",
            s(&new),
            "--write",
        ],
        "the last key slot",
    );
    // Unwrap with the passphrase: the key goes to a file, the slots go.
    refused(
        &["keys", p, "unwrap", "--passphrase-file", s(&new), "--write"],
        "--key-out FILE",
    );
    // A key file that cannot be written (it exists already) is refused
    // before the slots go: otherwise the key would be left nowhere.
    let taken = write("taken.key", b"something else\n");
    for w in [&["--write"][..], &[][..]] {
        let mut args = vec![
            "keys",
            p,
            "unwrap",
            "--passphrase-file",
            s(&new),
            "--key-out",
            s(&taken),
        ];
        args.extend_from_slice(w);
        refused(&args, "exists");
    }
    assert_eq!(std::fs::read(&taken).unwrap(), b"something else\n");
    assert!(ok(&["keys", p]).contains("key slot 0: passphrase"));
    ok(&["verify", p, "--passphrase-file", s(&new)]);
    let out = tmp("unwrapped.key");
    let _ = std::fs::remove_file(&out);
    ok(&[
        "keys",
        p,
        "unwrap",
        "--passphrase-file",
        s(&new),
        "--key-out",
        s(&out),
        "--write",
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&kf).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(ok(&["keys", p]).contains("key from the image"));
    refused(
        &["verify", p, "--passphrase-file", s(&new)],
        "comes from the image",
    );
    ok(&["verify", p, "--key", s(&out)]);
}

#[test]
fn rekey_empties_the_slots_of_the_old_key() {
    let d = image_key_disk("rekey.img");
    let p = s(&d);
    let kf = key_file();
    let old = pass("old2", OLD);
    let it = MIN_ITERATIONS.to_string();
    ok(&[
        "keys",
        p,
        "add",
        "--key",
        s(&kf),
        "--new-passphrase-file",
        s(&old),
        "--iterations",
        &it,
        "--write",
    ]);
    let k2: String = (0..64u32)
        .map(|i| format!("{:02x}", (i * 3 + 1) as u8))
        .collect();
    let k2f = write("k2.key", k2.as_bytes());
    let journal = tmp("rekey.journal");
    let o = ok(&[
        "rekey",
        p,
        "--passphrase-file",
        s(&old),
        "--key-new",
        s(&k2f),
        "--journal",
        s(&journal),
        "--write",
    ]);
    assert!(o.contains("any key slots were emptied"), "{o}");
    assert!(ok(&["keys", p]).contains("key from the image"));
    ok(&["verify", p, "--key", s(&k2f)]);
    refused(
        &["verify", p, "--passphrase-file", s(&old)],
        "comes from the image",
    );
}

/// The first sector of the data partition of a disk image.
fn gpt_first_lba(img: &[u8]) -> u64 {
    partition_of(img.to_vec()).1.first_lba
}

/// The data partition of a disk image file, as a device in memory.
fn partition_of(img: Vec<u8>) -> (MemDisk, gpt::DataPartition) {
    let m = MemDisk::from_image(img);
    let (d, _) = gpt::prepare(m.device().as_mut(), || [9; 16]).unwrap();
    (m, d)
}

fn part(m: &MemDisk, d: &gpt::DataPartition) -> Box<dyn BlockDevice> {
    Box::new(Partition::new(m.device(), d.first_lba, d.sectors()).unwrap())
}

fn digest(m: &MemDisk, d: &gpt::DataPartition, k: &[u8; KEY_BYTES]) -> host::TelemetryDigest {
    let f = m.fork();
    let (mut disk, _) = Disk::open_keyed(part(&f, d), || [0; 16], 8, Some(k)).unwrap();
    host::telemetry_digest(&mut disk).unwrap()
}

/// `keys add` and `keys change` with a power cut at every write: clean and
/// torn, the volatile cache lost and kept.
#[test]
fn a_cut_at_every_write_of_a_key_change_leaves_one_passphrase() {
    let d = image_key_disk("cut.img");
    let (m0, dp) = partition_of(std::fs::read(&d).unwrap());
    let want = digest(&m0, &dp, &key());
    let base = m0.raw(0, m0.len() as usize);
    let salt = [7u8; 32];
    let cases: [(Op, Auth, &str, &str); 2] = [
        (Op::Add, Auth::Key(Zeroizing::new(key())), "", OLD),
        (
            Op::Change,
            Auth::Passphrase(Zeroizing::new(OLD.as_bytes().to_vec())),
            OLD,
            NEW,
        ),
    ];
    let mut start = base.clone();
    for (op, auth, before, after) in cases {
        // How many writes the command makes.
        let probe = MemDisk::from_image(start.clone());
        let f = urmqtt_store::fault::FaultDevice::new(part(&probe, &dp), Default::default());
        keys::apply(
            Box::new(f),
            op,
            &auth,
            None,
            Some(after.as_bytes()),
            MIN_ITERATIONS,
            salt,
        )
        .unwrap();
        let writes = 3u64;
        let (mut saw_before, mut saw_after) = (0, 0);
        for n in 1..=writes {
            for spec in [
                urmqtt_store::fault::FaultSpec {
                    stop_after_writes: Some(n),
                    ..Default::default()
                },
                urmqtt_store::fault::FaultSpec {
                    tear_write: Some((n, 1)),
                    ..Default::default()
                },
            ] {
                for keep in [false, true] {
                    let m = MemDisk::from_image(start.clone());
                    let f = urmqtt_store::fault::FaultDevice::new(part(&m, &dp), spec);
                    let _ = keys::apply(
                        Box::new(f),
                        op,
                        &auth,
                        None,
                        Some(after.as_bytes()),
                        MIN_ITERATIONS,
                        salt,
                    );
                    m.crash(|_| keep);
                    let opens = |p: &str| unlock(part(&m, &dp).as_mut(), p.as_bytes()).is_ok();
                    let (b, a) = (before.is_empty() || opens(before), opens(after));
                    match (b, a) {
                        (true, false) => saw_before += 1,
                        (false, true) => saw_after += 1,
                        // Add: the image key still opens it whatever happened;
                        // the new passphrase may or may not.
                        (true, true) if before.is_empty() => saw_after += 1,
                        _ => panic!("{op:?} {spec:?} keep={keep}: before {b}, after {a}"),
                    }
                    assert_eq!(digest(&m, &dp, &key()), want, "{op:?} {spec:?} keep={keep}");
                }
            }
        }
        assert!(saw_after > 0, "{op:?}");
        if !before.is_empty() {
            assert!(saw_before > 0, "{op:?}");
        }
        // The next case starts from the finished state of this one.
        let m = MemDisk::from_image(start.clone());
        keys::apply(
            part(&m, &dp),
            op,
            &auth,
            None,
            Some(after.as_bytes()),
            MIN_ITERATIONS,
            salt,
        )
        .unwrap();
        start = m.raw(0, m.len() as usize);
    }
}
