//! A/B boot slots (ROADMAP NEXT-11, ADR-295 to ADR-299, DISK-FORMAT §0a):
//! two regions of the boot disk that each hold a complete EFI system
//! partition (loaders, `limine.conf`, kernels, configuration slot), a boot
//! attempt counter, a health confirmation and an automatic return to the
//! previous slot.
//!
//! **The boot entry is the partition table.** Exactly one GPT entry has
//! the EFI system partition type; firmware and Limine boot whatever region
//! it covers. A second entry, of the type [`SLOT_TYPE`], covers the other
//! region (the *standby*). Activating a slot moves the two ranges between
//! the entries in one table write ([`gpt::write_table`]: backup copy, then
//! primary): a cut leaves the old table in force or the new one, never a
//! mix. The entries keep their own unique GUIDs, so a firmware boot option
//! that names the ESP by GUID follows the switch; the entry order keeps the
//! ESP before the standby, and the standby is flagged "no block I/O"
//! (UEFI 2.10 table 5-13, attribute bit 1), so firmware that enumerates
//! partitions finds the active one first or only.
//!
//! **State** lives in the type-specific attribute bits 48..63 of each entry
//! and moves with its region ([`State`]); the version label and a
//! commitment to the region's bytes live in the entry name ([`Slot`]).
//! Nothing of this is read by the bootloader: the counting and the
//! fall-back are the kernel's ([`boot_step`]), which runs before the store,
//! the network and anything else a broken update could break, and the
//! offline tool's (`urmqtt-disk slots`).
//!
//! The kernel writes only the partition table here; the ESP regions are
//! written by the offline tool alone ([`stage`]).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sha2::Digest;

use crate::disk::{BlockDevice, IoError};
use crate::gpt::{self, ESP_TYPE, Entry, Guid, Table};
use crate::layout::SECTOR;

/// The standby boot slot, `8F3A6E21-5C7B-4D19-A2E4-6B0C9D513F7E`
/// (urMQTT's own type: no other system mounts or boots it).
pub const SLOT_TYPE: Guid = Guid::from_rfc([
    0x8f, 0x3a, 0x6e, 0x21, 0x5c, 0x7b, 0x4d, 0x19, 0xa2, 0xe4, 0x6b, 0x0c, 0x9d, 0x51, 0x3f, 0x7e,
]);

/// UEFI partition attribute bit 1: firmware must not produce a Block I/O
/// protocol for the partition. Set on the standby entry only.
pub const NO_BLOCK_IO: u64 = 1 << 1;
/// The attribute bits this module owns (type-specific bits 48..63).
pub const STATE_MASK: u64 = 0xffff << 48;
const TRIES_SHIFT: u32 = 48;
const TRIES_MASK: u64 = 0x7;
const TRIAL: u64 = 1 << 51;
const BAD: u64 = 1 << 52;
const ONE_WAY: u64 = 1 << 53;
const SEALED: u64 = 1 << 54;
const EMPTY: u64 = 1 << 55;
const SCHEMA_SHIFT: u32 = 56;

/// The most trial boots an activation may allow.
pub const MAX_TRIES: u8 = 7;
/// Trial boots an activation allows unless told otherwise.
pub const DEFAULT_TRIES: u8 = 3;
/// UTF-16 code units of a GPT entry name.
const NAME_UNITS: usize = 36;
/// Hex digits of the commitment kept in the name.
const DIGEST_HEX: usize = 16;

/// The state of one slot, from its entry's attribute bits 48..63.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct State {
    /// Trial boots left (0..=[`MAX_TRIES`]); meaningful while `trial`.
    pub tries: u8,
    /// Activated and not yet confirmed.
    pub trial: bool,
    /// Failed its trial, was rolled back from, or can no longer read the
    /// store (a one-way migration ran): never chosen automatically.
    pub bad: bool,
    /// Its activation allowed a store migration the other slot cannot read.
    pub one_way: bool,
    /// The entry name carries a commitment to the region's bytes.
    pub sealed: bool,
    /// Nothing was ever staged here (or a staging run did not finish).
    pub empty: bool,
    /// The store schema the slot's kernel writes; 0 when not known.
    pub schema: u8,
}

impl State {
    pub fn decode(attr: u64) -> Self {
        Self {
            tries: ((attr >> TRIES_SHIFT) & TRIES_MASK) as u8,
            trial: attr & TRIAL != 0,
            bad: attr & BAD != 0,
            one_way: attr & ONE_WAY != 0,
            sealed: attr & SEALED != 0,
            empty: attr & EMPTY != 0,
            schema: (attr >> SCHEMA_SHIFT) as u8,
        }
    }

    /// The bits 48..63 of this state (the rest of the attributes is the
    /// entry's own).
    pub fn encode(&self) -> u64 {
        let flag = |b: bool, bit: u64| if b { bit } else { 0 };
        (u64::from(self.tries.min(MAX_TRIES)) << TRIES_SHIFT)
            | flag(self.trial, TRIAL)
            | flag(self.bad, BAD)
            | flag(self.one_way, ONE_WAY)
            | flag(self.sealed, SEALED)
            | flag(self.empty, EMPTY)
            | (u64::from(self.schema) << SCHEMA_SHIFT)
    }

    /// Whether the slot may be booted again without an operator: it was
    /// confirmed, never failed, holds what was staged.
    pub fn eligible(&self) -> Result<(), NotEligible> {
        if self.empty {
            Err(NotEligible::Empty)
        } else if self.bad {
            Err(NotEligible::Bad)
        } else if self.trial {
            Err(NotEligible::Unconfirmed)
        } else {
            Ok(())
        }
    }
}

/// Why a slot cannot be switched to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEligible {
    Empty,
    Bad,
    Unconfirmed,
    /// Its bytes are not what was staged (the commitment differs).
    Changed,
}

impl NotEligible {
    pub const fn text(self) -> &'static str {
        match self {
            Self::Empty => "it holds nothing",
            Self::Bad => "it failed or was rolled back from",
            Self::Unconfirmed => "it was never confirmed",
            Self::Changed => "its bytes are not what was staged",
        }
    }
}

/// One slot: its region and state, the version label and the commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub first_lba: u64,
    pub last_lba: u64,
    pub state: State,
    /// The release the slot holds (the kernel's version), as staged.
    pub label: String,
    /// The first eight bytes of the SHA-256 of the whole region, as staged
    /// (`state.sealed`).
    pub digest: Option<[u8; 8]>,
}

impl Slot {
    pub fn sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }

    fn from_entry(e: &Entry) -> Self {
        let state = State::decode(e.attributes);
        let name = name_text(&e.name);
        let (label, digest) = match name.rsplit_once('|') {
            Some((l, h)) if state.sealed => (String::from(l), parse_hex8(h)),
            _ => (name, None),
        };
        Self {
            first_lba: e.first_lba,
            last_lba: e.last_lba,
            state,
            label,
            digest,
        }
    }
}

/// The text of a GPT entry name (UTF-16LE, NUL padded); unpaired surrogates
/// become U+FFFD.
pub fn name_text(name: &[u8; 72]) -> String {
    let units = name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0);
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn encode_name(text: &str) -> [u8; 72] {
    let mut n = [0u8; 72];
    for (i, u) in text.encode_utf16().take(NAME_UNITS).enumerate() {
        if let Some(s) = n.get_mut(2 * i..2 * i + 2) {
            s.copy_from_slice(&u.to_le_bytes());
        }
    }
    n
}

fn parse_hex8(h: &str) -> Option<[u8; 8]> {
    if h.len() != DIGEST_HEX {
        return None;
    }
    let mut d = [0u8; 8];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(d)
}

/// The entry name of a slot: the label (cut so the commitment fits) and,
/// when sealed, `|` and the commitment in hex.
fn slot_name(label: &str, digest: Option<[u8; 8]>) -> [u8; 72] {
    let mut text: String = match digest {
        Some(_) => label.chars().take(NAME_UNITS - 1 - DIGEST_HEX).collect(),
        None => label.chars().take(NAME_UNITS).collect(),
    };
    // A label must not look like it carries a commitment of its own.
    text = text.replace('|', "/");
    if let Some(d) = digest {
        text.push('|');
        for b in d {
            text.push_str(&alloc::format!("{b:02x}"));
        }
    }
    encode_name(&text)
}

/// What the first boot records about the slot it runs from.
#[derive(Debug, Clone, Copy)]
pub struct Init<'a> {
    /// The running kernel's version.
    pub label: &'a str,
    /// The store schema it writes.
    pub schema: u8,
}

/// The EFI system partition entry of a table that has no standby slot yet:
/// one ESP and no [`SLOT_TYPE`] entry (`None` otherwise).
pub fn reservable(entries: &[Entry]) -> Option<(Entry, usize)> {
    if entries.iter().any(|e| e.type_guid == SLOT_TYPE) {
        return None;
    }
    let mut esps = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.type_guid == ESP_TYPE);
    let (i, esp) = esps.next()?;
    esps.next().is_none().then_some((*esp, i))
}

/// Adds the standby entry over `[first, last]` and labels the ESP's slot
/// (the first boot, inside [`gpt::prepare_with`]'s table write).
pub fn reserve(entries: &mut Vec<Entry>, init: Init<'_>, first: u64, last: u64, random: [u8; 16]) {
    if let Some(esp) = entries.iter_mut().find(|e| e.type_guid == ESP_TYPE) {
        let state = State {
            schema: init.schema,
            ..State::default()
        };
        esp.attributes = (esp.attributes & !STATE_MASK) | state.encode();
        esp.name = slot_name(init.label, None);
    }
    let mut standby = Entry::new(SLOT_TYPE, Guid::random(random), first, last, "");
    standby.attributes = NO_BLOCK_IO
        | State {
            empty: true,
            ..State::default()
        }
        .encode();
    standby.name = slot_name("empty", None);
    entries.push(standby);
}

/// Errors of the slot operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    Io(IoError),
    /// The primary table is not valid, or the backup copy disagrees: the
    /// next boot (or `urmqtt-disk grow`) repairs it first.
    NeedsRepair,
    /// Not exactly one ESP and one standby entry, or regions of different
    /// sizes.
    Inconsistent,
    /// The disk has no standby slot (installed before v0.6.0).
    NotAb,
    /// The slot to switch to cannot be booted.
    NotEligible(NotEligible),
    /// The active slot is still on trial: confirm it or roll it back first.
    TrialPending,
    /// The image does not fit the slot.
    TooLarge {
        image: u64,
        slot: u64,
    },
    /// What was read back is not what was written.
    ReadBack,
    /// The active slot is not on trial: nothing to confirm.
    NotOnTrial,
}

impl From<IoError> for SlotError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

/// The two slots of an A/B disk, as the valid primary table says.
#[derive(Debug, Clone)]
pub struct Slots {
    pub table: Table,
    /// Index into `table.entries` of the ESP entry (the active slot).
    pub esp: usize,
    /// Index of the standby entry.
    pub standby: usize,
}

impl Slots {
    fn entry(&self, i: usize) -> Result<&Entry, SlotError> {
        self.table.entries.get(i).ok_or(SlotError::Inconsistent)
    }

    pub fn active(&self) -> Slot {
        self.entry(self.esp)
            .map(Slot::from_entry)
            .unwrap_or_else(|_| empty_slot())
    }

    pub fn standby_slot(&self) -> Slot {
        self.entry(self.standby)
            .map(Slot::from_entry)
            .unwrap_or_else(|_| empty_slot())
    }

    /// The ESP entry's unique GUID: what Limine reports as the boot
    /// partition when the active slot booted.
    pub fn esp_guid(&self) -> Guid {
        self.entry(self.esp)
            .map_or(Guid::default(), |e| e.unique_guid)
    }

    pub fn standby_guid(&self) -> Guid {
        self.entry(self.standby)
            .map_or(Guid::default(), |e| e.unique_guid)
    }

    /// "A" for the region nearer the start of the disk, "B" for the other.
    pub fn letter(&self, s: &Slot) -> char {
        let other = if s.first_lba == self.active().first_lba {
            self.standby_slot()
        } else {
            self.active()
        };
        if s.first_lba < other.first_lba {
            'A'
        } else {
            'B'
        }
    }

    /// The entries with new states for the active and the standby slot.
    fn with_states(&self, active: State, standby: State) -> Vec<Entry> {
        let mut entries = self.table.entries.clone();
        if let Some(e) = entries.get_mut(self.esp) {
            e.attributes = (e.attributes & !STATE_MASK) | active.encode();
        }
        if let Some(e) = entries.get_mut(self.standby) {
            e.attributes = (e.attributes & !STATE_MASK) | standby.encode();
        }
        entries
    }

    /// The entries with the regions exchanged: the standby's region (and
    /// name) becomes the ESP's with state `new_active`, the ESP's becomes
    /// the standby's with `new_standby`. Each entry keeps its type, unique
    /// GUID and own attribute bits; the standby keeps "no block I/O" and
    /// the ESP never has it.
    fn flipped(&self, new_active: State, new_standby: State) -> Result<Vec<Entry>, SlotError> {
        let mut entries = self.table.entries.clone();
        let a = *self.entry(self.esp)?;
        let s = *self.entry(self.standby)?;
        let esp = entries.get_mut(self.esp).ok_or(SlotError::Inconsistent)?;
        esp.first_lba = s.first_lba;
        esp.last_lba = s.last_lba;
        esp.name = s.name;
        esp.attributes = (a.attributes & !STATE_MASK & !NO_BLOCK_IO) | new_active.encode();
        let st = entries
            .get_mut(self.standby)
            .ok_or(SlotError::Inconsistent)?;
        st.first_lba = a.first_lba;
        st.last_lba = a.last_lba;
        st.name = a.name;
        st.attributes = (s.attributes & !STATE_MASK) | NO_BLOCK_IO | new_standby.encode();
        Ok(entries)
    }

    fn commit(&self, dev: &mut dyn BlockDevice, entries: &[Entry]) -> Result<(), SlotError> {
        gpt::write_table(dev, &self.table.header, entries)?;
        Ok(())
    }
}

fn empty_slot() -> Slot {
    Slot {
        first_lba: 0,
        last_lba: 0,
        state: State::default(),
        label: String::new(),
        digest: None,
    }
}

/// Finds the slots on `entries` (the used entries of a table, in order):
/// `Ok(None)` without a standby entry, an error when the table has a
/// standby but not exactly one ESP and one standby of equal size.
pub fn locate(entries: &[Entry]) -> Result<Option<(usize, usize)>, SlotError> {
    let find = |ty: Guid| -> Vec<usize> {
        entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.type_guid == ty)
            .map(|(i, _)| i)
            .collect()
    };
    let standby = find(SLOT_TYPE);
    if standby.is_empty() {
        return Ok(None);
    }
    let esp = find(ESP_TYPE);
    match (esp.as_slice(), standby.as_slice()) {
        ([e], [s]) => {
            let (a, b) = (
                entries.get(*e).ok_or(SlotError::Inconsistent)?,
                entries.get(*s).ok_or(SlotError::Inconsistent)?,
            );
            if a.sectors() != b.sectors() {
                return Err(SlotError::Inconsistent);
            }
            Ok(Some((*e, *s)))
        }
        _ => Err(SlotError::Inconsistent),
    }
}

/// Reads the slots of a disk whose table is in its normal form (a valid
/// primary, the same backup at its end): `Ok(None)` on a single-slot disk.
pub fn read(dev: &mut dyn BlockDevice) -> Result<Option<Slots>, SlotError> {
    let primary = gpt::read_table(dev, 1)?.ok_or(SlotError::NeedsRepair)?;
    let backup = gpt::read_table(dev, primary.header.backup_lba)?.ok_or(SlotError::NeedsRepair)?;
    if backup.entries != primary.entries || backup.header.disk_guid != primary.header.disk_guid {
        return Err(SlotError::NeedsRepair);
    }
    Ok(locate(&primary.entries)?.map(|(esp, standby)| Slots {
        table: primary,
        esp,
        standby,
    }))
}

/// SHA-256 of `sectors` sectors from `first`, read in pieces of 1 MiB.
pub fn region_sha256(
    dev: &mut dyn BlockDevice,
    first: u64,
    sectors: u64,
) -> Result<[u8; 32], IoError> {
    let mut h = sha2::Sha256::new();
    let chunk = 2048u64;
    let mut buf = vec![0u8; (chunk * SECTOR) as usize];
    let mut at = 0u64;
    while at < sectors {
        let n = (sectors - at).min(chunk);
        let piece = buf
            .get_mut(..(n * SECTOR) as usize)
            .ok_or(IoError::Device)?;
        dev.read(first + at, piece)?;
        h.update(&*piece);
        at += n;
    }
    Ok(h.finalize().into())
}

/// The commitment of a whole region: the first 8 bytes of its SHA-256.
pub fn commitment(sha: &[u8; 32]) -> [u8; 8] {
    let mut d = [0u8; 8];
    d.copy_from_slice(sha.get(..8).unwrap_or(&[0; 8]));
    d
}

/// Whether slot `s` may be switched to: [`State::eligible`] and, for a
/// sealed slot, its bytes still match the commitment.
pub fn check_eligible(dev: &mut dyn BlockDevice, s: &Slot) -> Result<(), SlotError> {
    s.state.eligible().map_err(SlotError::NotEligible)?;
    if s.state.sealed {
        let sha = region_sha256(dev, s.first_lba, s.sectors())?;
        if Some(commitment(&sha)) != s.digest {
            return Err(SlotError::NotEligible(NotEligible::Changed));
        }
    }
    Ok(())
}

/// Why the kernel switched back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The trial boots ran out without a confirmation.
    Attempts,
    /// The running kernel writes a newer store schema than the standby can
    /// read, and the activation did not allow a one-way update.
    OneWayNotAllowed,
    /// The firmware booted the standby while the active slot was on trial.
    FirmwareFellBack,
}

impl Why {
    pub const fn text(self) -> &'static str {
        match self {
            Self::Attempts => "no trial boots left and no confirmation",
            Self::OneWayNotAllowed => {
                "this kernel's store schema is newer than the previous slot's and the update was not activated as one-way (urmqtt-disk slots activate --one-way)"
            }
            Self::FirmwareFellBack => {
                "the firmware booted the previous slot: the new one did not even load"
            }
        }
    }
}

/// What [`boot_step`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Boot {
    /// One boot slot (a disk prepared before v0.6.0).
    Single,
    /// The kernel was not loaded from this disk's ESP or standby entry
    /// (unknown partition): nothing done.
    Unknown,
    /// The active slot is confirmed: nothing written (unless its recorded
    /// schema was refreshed).
    Confirmed { slot: char, schema_updated: bool },
    /// A trial boot: one attempt used, `left` remain after this one.
    Trial { slot: char, left: u8 },
    /// The table now points at the previous slot: reset to boot it.
    RolledBack { from: char, to: char, why: Why },
    /// The firmware booted the standby during a trial: the table now says
    /// so too, and this boot continues.
    AdoptedStandby { slot: char },
    /// The standby booted while the active slot is confirmed (firmware
    /// fell back on a damaged ESP): nothing written.
    StandbyBooted { slot: char },
    /// The trial is over but there is nothing to go back to: this boot
    /// continues on the trial slot.
    Exhausted {
        slot: char,
        why: Why,
        standby: NotEligible,
    },
}

/// The kernel's step at every boot of an A/B disk, after
/// [`gpt::prepare_with`] and before the store (ADR-296). `booted` is the
/// partition GUID the bootloader reports for the kernel file, `own_schema`
/// the store schema this kernel writes.
///
/// - Booted from the ESP, its slot confirmed: nothing (one write if the
///   recorded schema is not this kernel's: an in-place `update-boot`).
/// - On trial with attempts left: one attempt is used (a table write)
///   before anything else runs, so a crash, a reset by the watchdog or a
///   hang the operator resets counts.
/// - On trial with none left, or a one-way schema change that was not
///   allowed: the table switches back to the standby if it is eligible
///   ([`check_eligible`]); the caller resets.
/// - Booted from the standby while the active slot is on trial: the table
///   switches to the standby, the trial slot is marked bad, the boot goes on.
pub fn boot_step(
    dev: &mut dyn BlockDevice,
    booted: Option<Guid>,
    own_schema: u8,
) -> Result<Boot, SlotError> {
    let Some(s) = read(dev)? else {
        return Ok(Boot::Single);
    };
    let active = s.active();
    let standby = s.standby_slot();
    let (la, ls) = (s.letter(&active), s.letter(&standby));
    let Some(g) = booted else {
        return Ok(Boot::Unknown);
    };
    if g == s.standby_guid() {
        if !active.state.trial {
            return Ok(Boot::StandbyBooted { slot: ls });
        }
        let back = State {
            tries: 0,
            trial: false,
            bad: false,
            ..standby.state
        };
        let failed = State {
            tries: 0,
            trial: false,
            bad: true,
            ..active.state
        };
        s.commit(dev, &s.flipped(back, failed)?)?;
        return Ok(Boot::AdoptedStandby { slot: ls });
    }
    if g != s.esp_guid() {
        return Ok(Boot::Unknown);
    }
    if !active.state.trial {
        if active.state.schema != own_schema && !active.state.bad {
            let st = State {
                schema: own_schema,
                ..active.state
            };
            s.commit(dev, &s.with_states(st, standby.state))?;
            return Ok(Boot::Confirmed {
                slot: la,
                schema_updated: true,
            });
        }
        return Ok(Boot::Confirmed {
            slot: la,
            schema_updated: false,
        });
    }
    let why = if own_schema > standby.state.schema && !active.state.one_way {
        Some(Why::OneWayNotAllowed)
    } else if active.state.tries == 0 {
        Some(Why::Attempts)
    } else {
        None
    };
    let Some(why) = why else {
        let left = active.state.tries - 1;
        let st = State {
            tries: left,
            ..active.state
        };
        s.commit(dev, &s.with_states(st, standby.state))?;
        return Ok(Boot::Trial { slot: la, left });
    };
    match check_eligible(dev, &standby) {
        Ok(()) => {
            let failed = State {
                tries: 0,
                trial: false,
                bad: true,
                ..active.state
            };
            s.commit(dev, &s.flipped(standby.state, failed)?)?;
            Ok(Boot::RolledBack {
                from: la,
                to: ls,
                why,
            })
        }
        Err(SlotError::NotEligible(n)) => Ok(Boot::Exhausted {
            slot: la,
            why,
            standby: n,
        }),
        Err(e) => Err(e),
    }
}

/// Confirms the active slot (the health check passed, the operator said
/// so, or `urmqtt-disk slots confirm`). `Ok(false)`: it was not on trial.
pub fn confirm(dev: &mut dyn BlockDevice) -> Result<bool, SlotError> {
    let s = read(dev)?.ok_or(SlotError::NotAb)?;
    let active = s.active();
    if !active.state.trial {
        return Ok(false);
    }
    let st = State {
        tries: 0,
        trial: false,
        ..active.state
    };
    s.commit(dev, &s.with_states(st, s.standby_slot().state))?;
    Ok(true)
}

/// Switches to the standby slot (an operator's rollback, from the control
/// channel or the offline tool): it must be eligible; the slot left behind
/// is marked bad. Returns the letters (from, to).
pub fn rollback(dev: &mut dyn BlockDevice) -> Result<(char, char), SlotError> {
    let s = read(dev)?.ok_or(SlotError::NotAb)?;
    let active = s.active();
    let standby = s.standby_slot();
    check_eligible(dev, &standby)?;
    let left = State {
        tries: 0,
        trial: false,
        bad: true,
        ..active.state
    };
    s.commit(dev, &s.flipped(standby.state, left)?)?;
    Ok((s.letter(&active), s.letter(&standby)))
}

/// After a one-way store migration on a trial boot: the standby's kernel
/// can no longer read the store, so it is marked bad (no automatic return
/// to it). `Ok(false)`: nothing to do.
pub fn strand_standby(dev: &mut dyn BlockDevice, own_schema: u8) -> Result<bool, SlotError> {
    let Some(s) = read(dev)? else {
        return Ok(false);
    };
    let standby = s.standby_slot();
    if standby.state.bad || standby.state.empty || standby.state.schema >= own_schema {
        return Ok(false);
    }
    let st = State {
        bad: true,
        ..standby.state
    };
    s.commit(dev, &s.with_states(s.active().state, st))?;
    Ok(true)
}

/// What [`stage`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub slot: char,
    pub sha256: [u8; 32],
}

/// Writes `esp` into the standby region (offline tool): the standby is
/// marked empty first (a table write), then the region is written (the
/// image, zeros to its end) and flushed, read back and hashed, and only
/// then sealed with `label`, `schema` and the commitment (a table write).
/// A cut anywhere leaves an empty standby, never a half-written one that
/// looks staged. Refused while the active slot is on trial (the standby is
/// then its way back).
pub fn stage(
    dev: &mut dyn BlockDevice,
    esp: &[u8],
    label: &str,
    schema: u8,
) -> Result<Staged, SlotError> {
    let s = read(dev)?.ok_or(SlotError::NotAb)?;
    let active = s.active();
    let standby = s.standby_slot();
    if active.state.trial {
        return Err(SlotError::TrialPending);
    }
    let room = standby.sectors() * SECTOR;
    if esp.is_empty() || esp.len() as u64 > room || !(esp.len() as u64).is_multiple_of(SECTOR) {
        return Err(SlotError::TooLarge {
            image: esp.len() as u64,
            slot: room,
        });
    }
    let empty = State {
        empty: true,
        ..State::default()
    };
    if standby.state != empty {
        s.commit(dev, &s.with_states(active.state, empty))?;
    }
    // The region: the image, then zeros to its end, so the commitment is
    // over bytes this run wrote.
    let mut expect = sha2::Sha256::new();
    let chunk = (2048 * SECTOR) as usize;
    let mut buf = vec![0u8; chunk];
    let mut at = 0u64;
    while at < room {
        let n = ((room - at) as usize).min(chunk);
        let piece = buf.get_mut(..n).ok_or(IoError::Device)?;
        piece.fill(0);
        let from = at as usize;
        if from < esp.len() {
            let take = (esp.len() - from).min(n);
            if let (Some(dst), Some(src)) = (piece.get_mut(..take), esp.get(from..from + take)) {
                dst.copy_from_slice(src);
            }
        }
        expect.update(&*piece);
        dev.write(standby.first_lba + at / SECTOR, piece)?;
        at += n as u64;
    }
    dev.flush()?;
    let expect: [u8; 32] = expect.finalize().into();
    let got = region_sha256(dev, standby.first_lba, standby.sectors())?;
    if got != expect {
        return Err(SlotError::ReadBack);
    }
    // Re-read the table: the first write above changed it.
    let s = read(dev)?.ok_or(SlotError::NotAb)?;
    let sealed = State {
        sealed: true,
        schema,
        ..State::default()
    };
    let mut entries = s.with_states(s.active().state, sealed);
    if let Some(e) = entries.get_mut(s.standby) {
        e.name = slot_name(label, Some(commitment(&got)));
    }
    s.commit(dev, &entries)?;
    Ok(Staged {
        slot: s.letter(&s.standby_slot()),
        sha256: got,
    })
}

/// How [`activate`] switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    /// Trial boots allowed (1..=[`MAX_TRIES`]).
    pub tries: u8,
    /// The new slot's store schema is newer than the store the old one
    /// reads, and the operator accepted that a rollback is possible only
    /// until the new kernel has migrated the store.
    pub one_way: bool,
    /// Activate a slot marked bad (a retry of a failed update).
    pub retry: bool,
}

/// Switches the active slot to the staged standby (offline tool), in one
/// table write: the new slot on trial with `tries` boots, the old one kept
/// confirmed as the way back. The standby's commitment is checked first.
pub fn activate(dev: &mut dyn BlockDevice, a: Activation) -> Result<(char, char), SlotError> {
    let s = read(dev)?.ok_or(SlotError::NotAb)?;
    let active = s.active();
    let standby = s.standby_slot();
    if active.state.trial {
        return Err(SlotError::TrialPending);
    }
    let mut want = standby.state;
    if a.retry {
        want.bad = false;
        want.trial = false;
    }
    if !standby.state.sealed {
        return Err(SlotError::NotEligible(NotEligible::Empty));
    }
    check_eligible(
        dev,
        &Slot {
            state: want,
            ..standby.clone()
        },
    )?;
    let new_active = State {
        tries: a.tries.clamp(1, MAX_TRIES),
        trial: true,
        bad: false,
        one_way: a.one_way,
        ..standby.state
    };
    let old = State {
        tries: 0,
        trial: false,
        ..active.state
    };
    s.commit(dev, &s.flipped(new_active, old)?)?;
    Ok((s.letter(&active), s.letter(&standby)))
}

// --- the build note -------------------------------------------------------------

/// The magic of the kernel's build note: what an offline tool finds in an
/// ESP image to learn the version and the store schema of its kernels.
pub const NOTE_MAGIC: [u8; 16] = *b"urMQTT-buildnote";
/// Bytes of a build note.
pub const NOTE_LEN: usize = 64;
/// The note's own format.
pub const NOTE_VERSION: u16 = 1;
/// The A/B protocol a kernel speaks: 1 is this module's (trial counting,
/// confirmation, roll back). A kernel without a note speaks none and must
/// not be activated (it would never confirm).
pub const AB_PROTOCOL: u16 = 1;
/// Bytes of the version text in a note.
const NOTE_TEXT: usize = 32;

/// The build note of a kernel of version `version` that writes store
/// schema `schema` and reads configuration formats up to `cfg_format`:
/// `magic[16] | note version u16 | A/B protocol u16 | store schema u32 |
/// configuration format u16 | 0[6] | version text, NUL padded [32]`, all
/// little-endian.
// Every index is bounded by its loop against the fixed sizes (16, 2, 4, 32 of
// 64 bytes); the kernel evaluates it in a static initialiser, where an
// out-of-bounds index would be a compile error.
#[allow(clippy::indexing_slicing)]
pub const fn build_note(version: &str, schema: u32, cfg_format: u16) -> [u8; NOTE_LEN] {
    let mut n = [0u8; NOTE_LEN];
    let mut i = 0;
    while i < 16 {
        n[i] = NOTE_MAGIC[i];
        i += 1;
    }
    let v = NOTE_VERSION.to_le_bytes();
    n[16] = v[0];
    n[17] = v[1];
    let p = AB_PROTOCOL.to_le_bytes();
    n[18] = p[0];
    n[19] = p[1];
    let s = schema.to_le_bytes();
    n[20] = s[0];
    n[21] = s[1];
    n[22] = s[2];
    n[23] = s[3];
    let c = cfg_format.to_le_bytes();
    n[24] = c[0];
    n[25] = c[1];
    let t = version.as_bytes();
    let mut k = 0;
    while k < t.len() && k < NOTE_TEXT {
        n[32 + k] = t[k];
        k += 1;
    }
    n
}

/// A build note, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub ab_protocol: u16,
    pub schema: u32,
    pub cfg_format: u16,
    pub version: String,
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Decodes the note at the start of `b`: the magic, version 1, a protocol
/// and a schema that are not 0, zero reserved bytes and a version text of
/// printable ASCII followed only by NULs.
pub fn parse_note(b: &[u8]) -> Option<Note> {
    let b = b.get(..NOTE_LEN)?;
    if b.get(..16)? != NOTE_MAGIC || le16(b, 16)? != NOTE_VERSION {
        return None;
    }
    let (ab_protocol, schema, cfg_format) = (le16(b, 18)?, le32(b, 20)?, le16(b, 24)?);
    if ab_protocol == 0 || schema == 0 || b.get(26..32)?.iter().any(|&x| x != 0) {
        return None;
    }
    let text = b.get(32..)?;
    let len = text.iter().position(|&x| x == 0).unwrap_or(NOTE_TEXT);
    if len == 0
        || text.get(len..)?.iter().any(|&x| x != 0)
        || !text.get(..len)?.iter().all(|&x| (0x21..0x7f).contains(&x))
    {
        return None;
    }
    Some(Note {
        ab_protocol,
        schema,
        cfg_format,
        version: String::from(core::str::from_utf8(text.get(..len)?).ok()?),
    })
}

/// Every valid build note in `image` (an ESP image holds one per kernel).
pub fn find_notes(image: &[u8]) -> Vec<Note> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(rest) = image.get(at..) {
        let Some(i) = rest.windows(NOTE_MAGIC.len()).position(|w| w == NOTE_MAGIC) else {
            break;
        };
        if let Some(n) = rest.get(i..).and_then(parse_note) {
            out.push(n);
        }
        at += i + 1;
    }
    out
}

/// A release version `v1.2.3[-n-gHASH][-dirty]` (what `git describe`
/// prints, with or without the `v`): (major, minor, patch, commits after
/// the tag). `None` for anything else.
pub fn parse_version(v: &str) -> Option<(u32, u32, u32, u32)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.splitn(2, '-');
    let core = parts.next()?;
    let mut nums = core.split('.');
    let mut num = || nums.next()?.parse::<u32>().ok();
    let (a, b, c) = (num()?, num()?, num()?);
    if nums.next().is_some() {
        return None;
    }
    let after = parts
        .next()
        .and_then(|r| r.split('-').next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    Some((a, b, c, after))
}

#[cfg(test)]
mod tests;
