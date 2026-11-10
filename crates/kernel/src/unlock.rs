//! The disk passphrase at the console (LATER-7, ADR-326):
//! `storage.disk_key_source = "console"`.
//!
//! The image holds no disk key. The data partition's superblock holds the
//! key wrapped under one or two passphrases (`urmqtt_store::keyslot`); this
//! module asks for one on every console the kernel reads (the serial port,
//! the PS/2 keyboard of a VNC console, a virtio-console, a virtio-input
//! keyboard) and opens the disk with the key it unwraps. It runs on the boot
//! CPU from `db::init`, before the other cores start and before any
//! listener exists: until the passphrase is right the machine serves
//! nothing (the availability trade-off of ADR-326).
//!
//! - A **blank** data partition asks for a new passphrase twice, makes a
//!   random disk key and formats the partition with it wrapped in slot 0.
//! - An **encrypted** one asks for the passphrase; a wrong one is answered
//!   after a pause and asked again, for as long as it takes. The word
//!   `change` instead of the passphrase starts a passphrase change: the
//!   current one, then the new one twice; the slot that opened is rewrapped
//!   (two superblock writes, no data rewrite, ADR-327).
//! - Nothing typed is echoed or logged; the line buffer is wiped.
//!
//! The time spent waiting is not counted against an A/B trial boot's
//! timeout (`bootslot::credit_wait`).

use alloc::boxed::Box;

use urmqtt_arch::time;
use urmqtt_diag::keys::Ps2;
use urmqtt_log::{info, warn};
use urmqtt_store::crypt::{KEY_BYTES, check_key};
use urmqtt_store::disk::{Probe, probe, unlock};
use urmqtt_store::keyslot::Zeroizing;
use urmqtt_store::keyslot::{
    DEFAULT_ITERATIONS, KeySlot, LineEditor, LineEvent, PassphraseError, check_passphrase,
};
use urmqtt_store::{BlockDevice, Disk, DiskError, Opened};

/// The word that starts a passphrase change at the prompt (shorter than any
/// passphrase may be, so it can never be one).
const CHANGE: &[u8] = b"change";
/// The prompt is shown again (and a log line written) this often while
/// nobody types.
const REMIND_NS: u64 = 60_000_000_000;
/// The pause after a wrong passphrase, on top of the derivation's own cost.
const WRONG_PAUSE_NS: u64 = 2_000_000_000;

fn now() -> u64 {
    time::uptime_ns()
}

fn say(args: core::fmt::Arguments<'_>) {
    urmqtt_log::raw(args);
}

fn pause(ns: u64) {
    let until = now().saturating_add(ns);
    while now() < until {
        core::hint::spin_loop();
    }
}

/// Reads one line into `ed` (wiped first): waits as long as it takes,
/// showing `prompt` again every minute.
fn read_line(ed: &mut LineEditor, ps2: &mut Ps2, prompt: &str) {
    ed.clear();
    say(format_args!("\n{prompt}"));
    let mut remind = now().saturating_add(REMIND_NS);
    loop {
        let Some(b) = crate::diag::read_byte(ps2) else {
            if now() >= remind {
                info!("storage: waiting for the disk passphrase on the console");
                say(format_args!("\n{prompt}"));
                remind = now().saturating_add(REMIND_NS);
            }
            core::hint::spin_loop();
            continue;
        };
        match ed.feed(b) {
            LineEvent::Done => {
                say(format_args!("\n"));
                return;
            }
            LineEvent::Overflow => {
                say(format_args!("\nstorage: too long, type it again\n{prompt}"));
            }
            LineEvent::Cleared => say(format_args!(" [cleared]\n{prompt}")),
            LineEvent::None => {}
        }
    }
}

fn reason(e: PassphraseError) -> &'static str {
    match e {
        PassphraseError::TooShort => "too short (at least 12 characters)",
        PassphraseError::TooLong => "too long (at most 256 characters)",
        PassphraseError::NotPrintable => "only printable ASCII characters and spaces",
    }
}

/// Asks for a new passphrase twice until both agree and it follows the
/// rules; returns it (wiped on drop).
fn new_passphrase(ed: &mut LineEditor, ps2: &mut Ps2) -> Zeroizing<[u8; 256]> {
    loop {
        read_line(
            ed,
            ps2,
            "storage: new disk passphrase (12 to 256 characters, not shown): ",
        );
        if let Err(e) = check_passphrase(ed.line()) {
            say(format_args!("storage: refused: {}\n", reason(e)));
            continue;
        }
        let mut first = Zeroizing::new([0u8; 256]);
        let n = ed.line().len();
        if let Some(d) = first.get_mut(..n) {
            d.copy_from_slice(ed.line());
        }
        read_line(ed, ps2, "storage: the same passphrase again: ");
        if first.get(..n) == Some(ed.line()) {
            let mut out = Zeroizing::new([0u8; 256]);
            if let Some(d) = out.get_mut(..n) {
                d.copy_from_slice(ed.line());
            }
            ed.clear();
            return out;
        }
        say(format_args!("storage: the two passphrases differ\n"));
    }
}

/// The length of a passphrase kept in a 256-byte buffer: the bytes before
/// the first zero (a passphrase is printable ASCII, so never zero).
fn len_of(p: &[u8; 256]) -> usize {
    p.iter().position(|&b| b == 0).unwrap_or(p.len())
}

fn random<const N: usize>() -> Result<[u8; N], DiskError> {
    let mut b = [0u8; N];
    urmqtt_tls::rng::fill_global(&mut b)
        .map_err(|_| DiskError::Io(urmqtt_store::IoError::Device))?;
    Ok(b)
}

/// A fresh disk key: 64 random bytes that pass the S7 key rules.
fn new_key() -> Result<Zeroizing<[u8; KEY_BYTES]>, DiskError> {
    loop {
        let k = Zeroizing::new(random::<KEY_BYTES>()?);
        if check_key(&k[..]).is_ok() {
            return Ok(k);
        }
    }
}

/// Opens the data partition `dev` with a passphrase typed on the console:
/// formats a blank one, unlocks an encrypted one, changes the passphrase
/// on request. Errors are the ones `db::init` reports for the image key,
/// plus [`DiskError::NotWrapped`] (an encrypted disk with no key slot) and
/// [`DiskError::KeySlotMismatch`] (an edited header).
pub fn open(
    dev: Box<dyn BlockDevice>,
    uuid: impl FnOnce() -> [u8; 16],
    partitions: u32,
) -> Result<(Disk, Opened), DiskError> {
    let started = now();
    let r = run(dev, uuid, partitions);
    crate::bootslot::credit_wait(now().saturating_sub(started) / 1_000_000);
    r
}

fn run(
    mut dev: Box<dyn BlockDevice>,
    uuid: impl FnOnce() -> [u8; 16],
    partitions: u32,
) -> Result<(Disk, Opened), DiskError> {
    // A RAM store (the live entry, `storage.mode = "ram"`) is blank at every
    // boot and gone at power-off: nothing to protect with a passphrase, and
    // nobody to wait for. It is encrypted under a random key of this boot.
    if crate::live::ephemeral() {
        let key = new_key()?;
        info!("storage: RAM store: encrypted under a random key of this boot, no passphrase asked");
        return Disk::open_keyed(dev, uuid, partitions, Some(&key));
    }
    let mut ed = LineEditor::new();
    let mut ps2 = Ps2::default();
    match probe(dev.as_mut())? {
        Probe::Plain => Err(DiskError::NotEncrypted),
        Probe::Blank => {
            info!(
                "storage: the data partition is blank: it is formatted encrypted, its key wrapped under a passphrase typed now"
            );
            say(format_args!(
                "\nstorage: the data partition is blank. It will be encrypted with a new random key, kept only\n\
                 storage: wrapped under the passphrase you choose now. Without the passphrase the data cannot be read.\n"
            ));
            let pass = new_passphrase(&mut ed, &mut ps2);
            let key = new_key()?;
            let salt = random::<32>()?;
            let p = pass.get(..len_of(&pass)).unwrap_or(&[]);
            let disk = Disk::format_sealed(dev, uuid, partitions, &key, |u| {
                KeySlot::seal(&key, p, u, salt, DEFAULT_ITERATIONS)
            })?;
            info!(
                "storage: data partition formatted with a new key, wrapped under the console passphrase in key slot 0 ({DEFAULT_ITERATIONS} PBKDF2 iterations)"
            );
            Ok((disk, Opened::Formatted))
        }
        Probe::Encrypted { slots, .. } if !slots.contains(&true) => Err(DiskError::NotWrapped),
        Probe::Encrypted { .. } => {
            info!(
                "storage: the data partition is locked: waiting for the disk passphrase on the console"
            );
            let mut wrong = 0u32;
            loop {
                read_line(
                    &mut ed,
                    &mut ps2,
                    "storage: the data partition is locked. Disk passphrase (or \"change\" to change it): ",
                );
                let change = ed.line() == CHANGE;
                if change {
                    read_line(&mut ed, &mut ps2, "storage: current disk passphrase: ");
                }
                if ed.line().is_empty() {
                    continue;
                }
                match unlock(dev.as_mut(), ed.line()) {
                    Ok((key, slot)) => {
                        ed.clear();
                        if wrong > 0 {
                            warn!("storage: unlocked after {wrong} wrong disk passphrase(s)");
                        }
                        if !change {
                            info!(
                                "storage: data partition unlocked with the console passphrase (key slot {slot})"
                            );
                            return Disk::open_keyed(dev, || [0; 16], partitions, Some(&key));
                        }
                        let pass = new_passphrase(&mut ed, &mut ps2);
                        let salt = random::<32>()?;
                        let (mut disk, how) =
                            Disk::open_keyed(dev, || [0; 16], partitions, Some(&key))?;
                        let id = disk.layout().uuid;
                        let p = pass.get(..len_of(&pass)).unwrap_or(&[]);
                        disk.set_key_slot(
                            slot,
                            Some(KeySlot::seal(&key, p, &id, salt, DEFAULT_ITERATIONS)),
                        )?;
                        info!(
                            "storage: the disk passphrase of key slot {slot} was changed; the disk key is the same, so a copy of the old header still opens the disk with the old passphrase (if it leaked: urmqtt-disk rekey, then keys add)"
                        );
                        return Ok((disk, how));
                    }
                    Err(DiskError::WrongPassphrase) => {
                        ed.clear();
                        wrong += 1;
                        warn!("storage: wrong disk passphrase ({wrong} so far)");
                        pause(WRONG_PAUSE_NS);
                        say(format_args!("storage: wrong passphrase\n"));
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}
