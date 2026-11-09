//! `urmqtt-disk keys`: the key slots of an encrypted data partition
//! (LATER-7, ADR-327). The disk key wrapped under passphrases, so that the
//! image need not hold it: list, add, change, remove, and unwrap (back to a
//! key from the image). Every change is one superblock write into the slot
//! not in force and one into the other (the store's `Disk::set_key_slot`):
//! the data is never rewritten, a cut leaves the old slots or the new ones,
//! and no superblock keeps a replaced wrap once the command has finished.
//!
//! These functions work on the data partition's device; `main.rs` finds it,
//! chooses between the file and an in-memory overlay (`--write`) and prints.

use std::io::Read;

use urmqtt_store::crypt::KEY_BYTES;
use urmqtt_store::disk::{Probe, probe, unlock};
use urmqtt_store::keyslot::{
    DEFAULT_ITERATIONS, KeySlot, MAX_ITERATIONS, MIN_ITERATIONS, PassphraseError, SLOTS, Zeroizing,
    check_passphrase,
};
use urmqtt_store::{BlockDevice, Disk, DiskError, Opened};

pub type Key = [u8; KEY_BYTES];
type Res<T> = Result<T, String>;

/// What a key command does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Wrap the key under a new passphrase in an empty slot (the first one
    /// unless `slot` names one).
    Add,
    /// Replace the passphrase of a slot in use (the one the old passphrase
    /// opened, unless `slot` names one).
    Change,
    /// Empty a slot (never the last).
    Remove,
    /// Empty every slot: the key must then come from the image again.
    Unwrap,
}

/// How the operator proves the right to change the slots: the disk key
/// itself, or a passphrase one of the slots opens.
pub enum Auth {
    Key(Zeroizing<Key>),
    Passphrase(Zeroizing<Vec<u8>>),
}

/// Reads a passphrase file: its bytes without one final newline (LF or
/// CR LF). The rules of `check_passphrase` are applied to new passphrases
/// only (an old one is whatever the slot was made with).
pub fn read_passphrase(path: &str) -> Res<Zeroizing<Vec<u8>>> {
    let mut b = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|mut f| f.read_to_end(&mut b))
        .map_err(|e| format!("{path}: {e}"))?;
    if b.last() == Some(&b'\n') {
        b.pop();
        if b.last() == Some(&b'\r') {
            b.pop();
        }
    }
    Ok(b)
}

pub fn passphrase_rule(e: PassphraseError) -> &'static str {
    match e {
        PassphraseError::TooShort => "too short: at least 12 characters",
        PassphraseError::TooLong => "too long: at most 256 characters",
        PassphraseError::NotPrintable => {
            "only printable ASCII and spaces (the console's keyboard must type it again)"
        }
    }
}

/// The text of a `DiskError` for these commands.
pub fn disk_error(e: DiskError) -> String {
    match e {
        DiskError::WrongPassphrase => "no key slot opens with this passphrase".into(),
        DiskError::NotWrapped => {
            "the disk key is in no key slot (it comes from the image): use --key FILE".into()
        }
        DiskError::NotEncrypted => "the data partition is not encrypted".into(),
        DiskError::KeySlotMismatch => "a key slot opened but its key does not match the key check: the header was edited".into(),
        DiskError::WrongKey => "the key does not match this disk".into(),
        DiskError::LastKeySlot => "that is the last key slot: `keys DISK unwrap` empties them all, after which the key must come from the image".into(),
        DiskError::ConversionPending => "an encrypt, decrypt or rekey run was interrupted: resume it first".into(),
        DiskError::Blank => "the data partition is blank (never booted)".into(),
        e => format!("data partition: {e:?}"),
    }
}

/// The key slots, as `urmqtt-disk keys DISK` prints them. Reads only the
/// superblock; no key needed.
pub fn list(dev: &mut dyn BlockDevice) -> Res<String> {
    let mut out = String::new();
    match probe(dev).map_err(disk_error)? {
        Probe::Blank => out.push_str("data partition: blank (never booted)\n"),
        Probe::Plain => out.push_str("data partition: not encrypted\n"),
        Probe::Encrypted { slots, .. } => {
            let (a, b) = read_two(dev)?;
            let l = urmqtt_store::layout::Layout::select(&a, &b, dev.sectors())
                .map_err(|e| format!("data partition layout: {e:?}"))?
                .ok_or("data partition: blank")?
                .0;
            if slots.contains(&true) {
                out.push_str("data partition: encrypted (aes-256-xts), key wrapped in key slots: not in the image (storage.disk_key_source = \"console\")\n");
            } else {
                out.push_str("data partition: encrypted (aes-256-xts), key from the image (storage.disk_key); no key slot\n");
            }
            for (i, s) in l.key_slots.iter().enumerate() {
                match s {
                    Some(s) => out.push_str(&format!(
                        "key slot {i}: passphrase, PBKDF2-HMAC-SHA-256 {} iterations, AES-256 key wrap\n",
                        s.iterations
                    )),
                    None => out.push_str(&format!("key slot {i}: empty\n")),
                }
            }
        }
    }
    Ok(out)
}

fn read_two(
    dev: &mut dyn BlockDevice,
) -> Res<(
    [u8; urmqtt_store::layout::BLOCK],
    [u8; urmqtt_store::layout::BLOCK],
)> {
    let mut a = [0u8; urmqtt_store::layout::BLOCK];
    let mut b = [0u8; urmqtt_store::layout::BLOCK];
    for (buf, lba) in [&mut a, &mut b]
        .into_iter()
        .zip(urmqtt_store::layout::SB_SLOT_LBA)
    {
        dev.read(lba, buf)
            .map_err(|e| format!("read the superblock: {e:?}"))?;
    }
    Ok((a, b))
}

/// The disk key from `auth`, and the slot a passphrase opened.
pub fn key_of(dev: &mut dyn BlockDevice, auth: &Auth) -> Res<(Zeroizing<Key>, Option<usize>)> {
    match auth {
        Auth::Key(k) => Ok((k.clone(), None)),
        Auth::Passphrase(p) => {
            let (k, slot) = unlock(dev, p).map_err(disk_error)?;
            Ok((k, Some(slot)))
        }
    }
}

/// What a key command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub op: Op,
    pub slot: Option<usize>,
    /// The older superblock had to be brought up to date as well.
    pub scrubbed: bool,
}

/// Runs `op` on the data partition `dev`. `new` is the new passphrase of
/// `Add` and `Change` (checked here); `salt` its random salt; `slot` the
/// slot the operator named, if any.
pub fn apply(
    mut dev: Box<dyn BlockDevice>,
    op: Op,
    auth: &Auth,
    slot: Option<usize>,
    new: Option<&[u8]>,
    iterations: u32,
    salt: [u8; 32],
) -> Res<Done> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(format!(
            "--iterations must be in {MIN_ITERATIONS}..={MAX_ITERATIONS} (default {DEFAULT_ITERATIONS})"
        ));
    }
    if let Some(s) = slot
        && s >= SLOTS
    {
        return Err(format!(
            "--slot must be 0 or 1 (a disk has {SLOTS} key slots)"
        ));
    }
    let (key, opened) = key_of(dev.as_mut(), auth)?;
    let (mut disk, how) = Disk::open_keyed(dev, || [0; 16], 8, Some(&key)).map_err(disk_error)?;
    if how != Opened::Existing {
        return Err("the data partition is blank (never booted)".into());
    }
    let uuid = disk.layout().uuid;
    let in_use = disk.layout().key_slots.map(|s| s.is_some());
    let seal = |p: &[u8]| -> Res<KeySlot> {
        check_passphrase(p).map_err(|e| format!("the new passphrase is {}", passphrase_rule(e)))?;
        Ok(KeySlot::seal(&key, p, &uuid, salt, iterations))
    };
    let target = match op {
        Op::Add => {
            let s = match slot {
                Some(s) => s,
                None => in_use
                    .iter()
                    .position(|u| !u)
                    .ok_or("both key slots are in use: change or remove one")?,
            };
            if in_use.get(s).copied().unwrap_or(true) {
                return Err(format!("key slot {s} is in use: use `change`"));
            }
            let new = new.ok_or("add: give --new-passphrase-file FILE")?;
            disk.set_key_slot(s, Some(seal(new)?)).map_err(disk_error)?;
            Some(s)
        }
        Op::Change => {
            let s = slot
                .or(opened)
                .ok_or("change: name the slot with --slot N (or open it with --passphrase-file)")?;
            if !in_use.get(s).copied().unwrap_or(false) {
                return Err(format!("key slot {s} is empty: use `add`"));
            }
            let new = new.ok_or("change: give --new-passphrase-file FILE")?;
            disk.set_key_slot(s, Some(seal(new)?)).map_err(disk_error)?;
            Some(s)
        }
        Op::Remove => {
            let s = slot.ok_or("remove: name the slot with --slot N")?;
            if !in_use.get(s).copied().unwrap_or(false) {
                return Err(format!("key slot {s} is already empty"));
            }
            disk.set_key_slot(s, None).map_err(disk_error)?;
            Some(s)
        }
        Op::Unwrap => {
            disk.unwrap_key_slots().map_err(disk_error)?;
            None
        }
    };
    let scrubbed = disk.scrub_key_slots().map_err(disk_error)?;
    disk.sync().map_err(disk_error)?;
    Ok(Done {
        op,
        slot: target,
        scrubbed,
    })
}

/// The key as 128 hex digits and a newline (the key file format of
/// `storage.disk_key`), for `unwrap --key-out`.
pub fn key_hex(k: &Key) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(2 * KEY_BYTES + 1));
    for b in k {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('\n');
    s
}
