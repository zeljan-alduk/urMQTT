//! Configuring ISO and raw images in place (C1d, ADR-218).
//!
//! The universal ISO holds the configuration slot several times: as a file
//! of the ISO 9660 tree and inside the FAT image of the El Torito/UEFI boot
//! partition (the installation image inside it keeps an *unconfigured*
//! slot, ADR-217, and is not touched). Every `limine.conf` copy names the
//! slot by `module_path: boot():/boot/urmqtt.cfg#<blake2b>`. Nothing is
//! parsed except those two things: slots are found by their marker and
//! structure (`urmqtt_cfg::blob::find_slots`), the hashes by text. All
//! replacements have the same length, so no ISO 9660 directory record, FAT
//! chain or El Torito entry changes, and the kernel bytes (pinned by their
//! own hashes) are not touched.

use urmqtt_cfg::blake2b;
use urmqtt_cfg::blob::{SLOT_SIZE, SlotKind, find_slots, make_slot, slot_blob};

use crate::{blob_of, describe, verify_blob};

/// A patched image and a short report of what changed.
pub struct Patched {
    pub bytes: Vec<u8>,
    pub report: String,
}

const HASH_PREFIX: &[u8] = b"/boot/urmqtt.cfg#";
const HASH_LEN: usize = 128;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn slot_hash(slot: &[u8]) -> String {
    hex(&blake2b::hash(slot))
}

/// Positions of the 128 hex characters after every `urmqtt.cfg#` in `data`.
fn hash_refs(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = data
        .get(i..)
        .and_then(|d| d.windows(HASH_PREFIX.len()).position(|w| w == HASH_PREFIX))
    {
        let at = i + p + HASH_PREFIX.len();
        if data
            .get(at..at + HASH_LEN)
            .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
        {
            out.push(at);
        }
        i = at;
    }
    out
}

/// The slot copies of `kind` in `image`, which must all be identical.
fn slots_of(image: &[u8], kind: SlotKind) -> Result<(Vec<usize>, Option<Vec<u8>>), String> {
    let offs = find_slots(image, kind);
    let Some(first) = offs.first() else {
        return Ok((offs, None));
    };
    let one = image
        .get(*first..*first + SLOT_SIZE)
        .ok_or("slot is cut off")?
        .to_vec();
    for o in &offs {
        if image.get(*o..*o + SLOT_SIZE) != Some(&one[..]) {
            return Err(format!(
                "the copies of the configuration slot differ (at byte {first} and {o}): the image is inconsistent"
            ));
        }
    }
    Ok((offs, Some(one)))
}

fn check_blob(blob: &[u8]) -> Result<(), String> {
    verify_blob(blob, true).map(|_| ())
}

/// A copy of the template ISO with `blob` as its configuration: every boot
/// slot replaced, every module hash in the `limine.conf` copies updated.
pub fn configure_iso(iso: &[u8], blob: &[u8]) -> Result<Patched, String> {
    let mut bytes = iso.to_vec();
    let report = configure_iso_in_place(&mut bytes, blob)?;
    Ok(Patched { bytes, report })
}

/// What [`configure_iso`] does, on the image itself (the browser holds the
/// 60 MB ISO once, in WebAssembly memory, and must not copy it). Every check
/// runs before the first byte changes; if the final read-back fails after
/// that (an internal error, never seen with a consistent template) the
/// buffer must be discarded.
pub fn configure_iso_in_place(iso: &mut [u8], blob: &[u8]) -> Result<String, String> {
    check_blob(blob)?;
    let new_slot = make_slot(SlotKind::Boot, blob)
        .ok_or("the configuration does not fit in a 256 KiB slot")?;
    let (offs, old) = slots_of(iso, SlotKind::Boot)?;
    let old = old.ok_or(
        "no configuration slot found: this is not a template ISO of this format (build 0.1.x releases and earlier have none)",
    )?;
    let old_hash = slot_hash(&old);
    let refs = hash_refs(iso);
    if refs.is_empty() {
        return Err(
            "no limine.conf names the configuration module: not a template ISO of this format"
                .into(),
        );
    }
    for r in &refs {
        let h = iso.get(*r..*r + HASH_LEN).ok_or("hash is cut off")?;
        if h != old_hash.as_bytes() {
            return Err(format!(
                "a limine.conf at byte {r} names a different module hash than the slot's: the template is inconsistent"
            ));
        }
    }
    let new_hash = slot_hash(&new_slot);
    for o in &offs {
        iso.get_mut(*o..*o + SLOT_SIZE)
            .ok_or("slot is cut off")?
            .copy_from_slice(&new_slot);
    }
    for r in &refs {
        iso.get_mut(*r..*r + HASH_LEN)
            .ok_or("hash is cut off")?
            .copy_from_slice(new_hash.as_bytes());
    }
    // Read it back the way verify does.
    verify(iso, true)
        .map_err(|e| format!("internal error: the patched image does not verify: {e}"))?;
    Ok(format!(
        "configured: {} copies of the slot replaced, {} module hash references updated (blake2b {}…)",
        offs.len(),
        refs.len(),
        &new_hash[..16]
    ))
}

/// What a template ISO is, before anything is changed: how many copies of the
/// configuration slot and how many module hash references it holds, and the
/// blob in the slot. The page uses it to refuse a file that is not a template
/// before it offers anything.
pub struct Probe {
    pub slot_copies: usize,
    pub hash_refs: usize,
    pub format_version: u16,
    pub blob: Vec<u8>,
}

/// Looks at a template ISO without changing it.
pub fn probe(iso: &[u8]) -> Result<Probe, String> {
    let (offs, slot) = slots_of(iso, SlotKind::Boot)?;
    let slot = slot.ok_or(
        "no configuration slot found: this is not a template ISO of this format (build 0.1.x releases and earlier have none)",
    )?;
    let blob = slot_blob(&slot, SlotKind::Boot)
        .map_err(|e| e.to_string())?
        .to_vec();
    let format_version = blob
        .get(8..10)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, u16::from_le_bytes);
    Ok(Probe {
        slot_copies: offs.len(),
        hash_refs: hash_refs(iso).len(),
        format_version,
        blob,
    })
}

/// A copy of the raw disk image (or installation image) with `blob` as its
/// configuration: its unconfigured slot, or its configured one, replaced.
pub fn configure_raw(img: &[u8], blob: &[u8]) -> Result<Patched, String> {
    check_blob(blob)?;
    let new_slot = make_slot(SlotKind::Boot, blob)
        .ok_or("the configuration does not fit in a 256 KiB slot")?;
    let mut offs = find_slots(img, SlotKind::Disk);
    offs.extend(find_slots(img, SlotKind::Boot));
    match offs.len() {
        1 => {}
        0 => return Err("no configuration slot found in this image".into()),
        n => {
            return Err(format!(
                "{n} configuration slots found; a raw image has exactly one (is this an ISO? use --iso)"
            ));
        }
    }
    let mut out = img.to_vec();
    let off = offs[0];
    out.get_mut(off..off + SLOT_SIZE)
        .ok_or("slot is cut off")?
        .copy_from_slice(&new_slot);
    Ok(Patched {
        bytes: out,
        report: "configured: the slot of the disk image replaced".into(),
    })
}

/// What an image or file holds, for `show`.
pub fn show(data: &[u8], all: bool) -> Result<String, String> {
    if let Ok(blob) = blob_of(data) {
        return describe(blob, all);
    }
    let (offs, slot) = slots_of(data, SlotKind::Boot)?;
    let (disk_offs, disk_slot) = slots_of(data, SlotKind::Disk)?;
    let mut o = String::new();
    let which = slot.as_ref().or(disk_slot.as_ref()).ok_or(
        "no configuration slot found: not a blob, a slot, nor a urMQTT image of this format",
    )?;
    o.push_str(&format!(
        "image: {} configuration slot cop{} (offsets {:?}), {} installation-image template cop{} (offsets {:?}), {} module hash reference(s)\n\n",
        offs.len(),
        if offs.len() == 1 { "y" } else { "ies" },
        offs,
        disk_offs.len(),
        if disk_offs.len() == 1 { "y" } else { "ies" },
        disk_offs,
        hash_refs(data).len(),
    ));
    let kind = if slot.is_some() {
        SlotKind::Boot
    } else {
        SlotKind::Disk
    };
    let blob = slot_blob(which, kind).map_err(|e| e.to_string())?;
    o.push_str(&describe(blob, all)?);
    Ok(o)
}

/// Checks a blob, slot, ISO or raw image the way the kernel and the
/// bootloader will: the configuration passes the kernel's checks, every
/// copy of it is the same, every module hash in a `limine.conf` is the
/// slot's.
pub fn verify(data: &[u8], dev: bool) -> Result<String, String> {
    if let Ok(blob) = blob_of(data) {
        return verify_blob(blob, dev);
    }
    let (offs, slot) = slots_of(data, SlotKind::Boot)?;
    let (_, disk) = slots_of(data, SlotKind::Disk)?;
    let (slot, kind) = match (slot, disk) {
        (Some(s), _) => (s, SlotKind::Boot),
        (None, Some(d)) => (d, SlotKind::Disk),
        (None, None) => return Err("no configuration slot found in this image".into()),
    };
    let blob = slot_blob(&slot, kind).map_err(|e| e.to_string())?;
    let verdict = verify_blob(blob, dev)?;
    let refs = hash_refs(data);
    let want = slot_hash(&slot);
    for r in &refs {
        if data.get(*r..*r + HASH_LEN) != Some(want.as_bytes()) {
            return Err(format!(
                "the module hash at byte {r} is not the slot's blake2b: the bootloader would refuse this image"
            ));
        }
    }
    let n_refs = refs.len();
    if kind == SlotKind::Boot && !offs.is_empty() && n_refs == 0 {
        // A raw image's limine.conf lists the module without a hash.
        return Ok(format!(
            "{verdict}; {} slot copy/copies, no module hash pinned",
            offs.len()
        ));
    }
    Ok(format!(
        "{verdict}; {} slot cop{} identical, {n_refs} module hash reference(s) match",
        offs.len().max(1),
        if offs.len() == 1 { "y" } else { "ies" }
    ))
}
