//! `urmqtt-disk slots`: A/B updates of an installed disk, offline (ROADMAP
//! NEXT-11, ADR-295 to ADR-299, DISK-FORMAT §0a). The partition-table work is
//! `urmqtt_store::slots`; this module is what the tool checks before it lets
//! a write happen:
//!
//! - **the release signature**: an `--image` (the release's raw `.img`) is
//!   staged only with its `SHA256SUMS` verified by minisign against the given
//!   public key(s) and the image's SHA-256 listed there; anything else needs
//!   `--unsigned`, said out loud;
//! - **the kernel's build note**: a kernel without one does not speak the
//!   A/B protocol and would never confirm a trial;
//! - **downgrade rules** (AUDIT H8-W6): never a kernel whose store schema is
//!   older than the store on the disk (it would refuse it, and the old
//!   kernel's schema-5 one-way note says why going back is not possible); an
//!   older release only with `--allow-downgrade`; a store schema newer than
//!   the other slot's only with `activate --one-way`; a configuration format
//!   the new kernel cannot read is refused before anything is written.

use urmqtt_cfg::blob::{Blob, SlotKind, find_slots, slot_blob};
use urmqtt_store::BlockDevice;
use urmqtt_store::gpt::{self, ESP_TYPE};
use urmqtt_store::slots::{self, Note, Slot, Slots};

/// The EFI system partition of a raw disk image (a release `.img`).
pub fn esp_of_image(img: &[u8]) -> Result<Vec<u8>, String> {
    let d = urmqtt_store::disk::MemDisk::from_image(img.to_vec());
    let mut dev = d.device();
    let t = gpt::read_table(dev.as_mut(), 1)
        .map_err(|e| format!("image: {e:?}"))?
        .ok_or("image: no valid GPT (not a raw boot image)")?;
    let e = t
        .entries
        .iter()
        .find(|e| e.type_guid == ESP_TYPE)
        .ok_or("image: no EFI system partition")?;
    let from = (e.first_lba * 512) as usize;
    let to = ((e.last_lba + 1) * 512) as usize;
    let esp = img
        .get(from..to)
        .ok_or("image: the EFI system partition lies beyond the file")?
        .to_vec();
    Ok(esp)
}

/// The one build note of an ESP's kernels (every kernel of the image must
/// say the same).
pub fn note_of(esp: &[u8]) -> Result<Note, String> {
    let notes = slots::find_notes(esp);
    let first = notes.first().cloned().ok_or(
        "the image's kernels carry no build note: they predate A/B updates (v0.6.0) and would never confirm a trial boot; update this disk with `urmqtt-disk update-boot` instead",
    )?;
    if first.ab_protocol != slots::AB_PROTOCOL {
        return Err(format!(
            "the image's kernels speak A/B protocol {}, this tool protocol {}: use the urmqtt-disk of that release",
            first.ab_protocol,
            slots::AB_PROTOCOL
        ));
    }
    if notes.iter().any(|n| *n != first) {
        return Err(format!(
            "the image's kernels disagree about what they are ({} notes, not all equal): not one release",
            notes.len()
        ));
    }
    Ok(first)
}

/// The release signature: `SHA256SUMS` signed by one of `pubkeys`, and the
/// image's SHA-256 listed under its file name. Returns a line for the log.
pub fn verify_release(
    name: &str,
    image: &[u8],
    sums: &[u8],
    sig: &str,
    pubkeys: &[String],
) -> Result<String, String> {
    let keys: Vec<&str> = pubkeys.iter().map(String::as_str).collect();
    let signed = urmqtt_config_tool::release::verify_sums_any(&keys, sums, sig)?;
    let digest = signed.sums.check(name, image)?;
    Ok(format!(
        "release signature ok: SHA256SUMS signed by key {}, {name} has SHA-256 {}",
        signed.signature.key_id,
        urmqtt_config_tool::release::hex(&digest)
    ))
}

/// The configuration format of the ESP's configured slot, if it has one.
pub fn config_format(esp: &[u8]) -> Option<u16> {
    let [off] = find_slots(esp, SlotKind::Boot)[..] else {
        return None;
    };
    let slot = esp.get(off..off + urmqtt_cfg::blob::SLOT_SIZE)?;
    let bytes = slot_blob(slot, SlotKind::Boot).ok()?;
    Blob::parse(bytes).ok().map(|b| b.version())
}

/// What a slot says, on one line.
pub fn describe(s: &Slots, x: &Slot) -> String {
    let st = x.state;
    let what = if st.empty {
        "empty".to_string()
    } else {
        let mut w = Vec::new();
        if st.trial {
            w.push(format!("ON TRIAL, {} trial boot(s) left", st.tries));
        } else if st.bad {
            w.push("BAD (failed, rolled back from, or its store schema is gone)".to_string());
        } else {
            w.push("confirmed".to_string());
        }
        if st.one_way {
            w.push("one-way".into());
        }
        w.push(if st.sealed {
            format!(
                "staged, commitment {}",
                x.digest.map(|d| hex(&d)).unwrap_or_else(|| "?".into())
            )
        } else {
            "as installed".into()
        });
        format!(
            "{} (store schema {}): {}",
            if x.label.is_empty() { "?" } else { &x.label },
            st.schema,
            w.join(", ")
        )
    };
    format!(
        "slot {}{}: LBA {}..{} ({} MiB): {what}",
        s.letter(x),
        if x.first_lba == s.active().first_lba {
            " [active]"
        } else {
            " [standby]"
        },
        x.first_lba,
        x.last_lba,
        x.sectors() >> 11
    )
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Release order of two version labels; `None` when either is not a
/// release version (a commit hash): the rule cannot judge it.
pub fn older(new: &str, than: &str) -> Option<bool> {
    Some(slots::parse_version(new)? < slots::parse_version(than)?)
}

/// The downgrade rules for a kernel described by `note`, on a disk whose
/// active slot is `active` and whose store is at `db_schema` (when it could
/// be read). Returns warnings; an `Err` refuses.
pub fn rules(
    note: &Note,
    active: &Slot,
    db_schema: Option<u32>,
    allow_downgrade: bool,
) -> Result<Vec<String>, String> {
    rules_for(
        note,
        &active.label,
        u32::from(active.state.schema),
        "the active slot's recorded schema",
        db_schema,
        allow_downgrade,
    )
}

/// [`rules`] against a running kernel known by its label and store schema
/// (`what_schema` says where that schema comes from, for the warning).
pub fn rules_for(
    note: &Note,
    running: &str,
    running_schema: u32,
    what_schema: &str,
    db_schema: Option<u32>,
    allow_downgrade: bool,
) -> Result<Vec<String>, String> {
    let mut warn = Vec::new();
    let store = match db_schema {
        Some(s) => s,
        None => {
            warn.push(format!(
                "the store could not be read (encrypted without --key, or newer than this tool): judging by {what_schema} {running_schema}"
            ));
            running_schema
        }
    };
    if note.schema < store {
        return Err(format!(
            "this kernel writes store schema {} but the store on the disk is schema {store}: it would refuse the store (a store migration is one-way, docs/DISK-FORMAT.md §5.1.1). Never allowed",
            note.schema
        ));
    }
    match older(&note.version, running) {
        Some(true) if !allow_downgrade => {
            return Err(format!(
                "{} is older than the running {}: refused (rollback protection, AUDIT H8-W6); add --allow-downgrade if that is what you want",
                note.version, running
            ));
        }
        Some(true) => warn.push(format!(
            "downgrade from {} to {} allowed by --allow-downgrade",
            running, note.version
        )),
        Some(false) => {}
        None => warn.push(format!(
            "cannot compare {:?} with {:?} (not release versions): no downgrade check",
            note.version, running
        )),
    }
    Ok(warn)
}

/// Reads `sectors` sectors from `first` of `dev`.
pub fn read_region(dev: &mut dyn BlockDevice, first: u64, sectors: u64) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; (sectors * 512) as usize];
    for (i, c) in buf.chunks_mut(1 << 20).enumerate() {
        dev.read(first + (i as u64) * 2048, c)
            .map_err(|e| format!("read failed: {e:?}"))?;
    }
    Ok(buf)
}

/// A refusal of the slot operations, in words.
pub fn slot_error(e: &slots::SlotError) -> String {
    use slots::SlotError as E;
    match e {
        E::Io(e) => format!("I/O error: {e:?}"),
        E::NeedsRepair => "the partition table's two copies disagree or the primary is damaged: boot the disk once (the kernel repairs it), or run `urmqtt-disk grow DISK --write`".into(),
        E::Inconsistent => "the partition table is not one EFI system partition and one standby slot of the same size".into(),
        E::NotAb => "this disk has one boot slot (prepared before v0.6.0): A/B updates need a disk installed by v0.6.0 or later; use `urmqtt-disk update-boot`".into(),
        E::NotEligible(n) => format!("the slot cannot be switched to: {}", n.text()),
        E::TrialPending => "the active slot is still on trial: confirm it (`slots confirm`) or roll it back (`slots rollback`) first; the standby is its way back".into(),
        E::TooLarge { image, slot } => format!("the image's EFI system partition ({image} bytes) does not fit the slot ({slot} bytes) or is not whole sectors"),
        E::ReadBack => "what was read back is not what was written: the disk is failing; the standby is left empty".into(),
        E::NotOnTrial => "the active slot is not on trial".into(),
    }
}
