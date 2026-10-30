//! The self-installing ISO's writer (S1b, STORAGE-PLAN §2b): choosing the
//! target disk and putting the raw boot image on it, byte for byte what
//! `scripts/mkraw.py` would produce, verified by reading it back.
//!
//! Write order, chosen so that a power cut leaves a disk that does not boot
//! (and is simply installed again) instead of a half-written one that does:
//! 1. Destroy the old tables: first the disk's last 33 sectors (the backup),
//!    then LBA 0..=33. Until the second write the old install still boots
//!    unchanged from its primary copy (and repairs its backup).
//! 2. The image from LBA 34 on: the ESP, and the backup table at the
//!    image's end. Firmware looks for a backup at the disk's last LBA, which
//!    step 1 cleared.
//! 3. The primary entry array, then the protective MBR.
//! 4. The primary header last. Only now does the disk carry a valid GPT.
//! 5. Flush, then read back the image's length and compare SHA-256.

use alloc::vec;
use alloc::vec::Vec;

use crate::disk::{BlockDevice, IoError};
use crate::gpt::{self, ENTRY_SECTORS};
use crate::layout::{MIN_SECTORS, SECTOR};

/// A disk the installer may consider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub sectors: u64,
    pub read_only: bool,
    /// The medium the installer itself was booted from.
    pub boot_medium: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// Install onto candidate `i`.
    Target(usize),
    /// No disk qualifies.
    None,
    /// Several do: refuse rather than guess.
    Several(Vec<usize>),
}

/// Sectors a target needs: the image and room for the minimum data
/// partition (1 MiB alignment slack included).
pub fn needed_sectors(image_bytes: u64) -> u64 {
    image_bytes / SECTOR + MIN_SECTORS + gpt::ALIGN
}

/// The target: exactly one disk that is not the boot medium, not
/// read-only and large enough.
pub fn choose(disks: &[Candidate], image_bytes: u64) -> Choice {
    let need = needed_sectors(image_bytes);
    let ok: Vec<usize> = disks
        .iter()
        .enumerate()
        .filter(|(_, d)| !d.boot_medium && !d.read_only && d.sectors >= need)
        .map(|(i, _)| i)
        .collect();
    match ok.as_slice() {
        [] => Choice::None,
        [one] => Choice::Target(*one),
        _ => Choice::Several(ok),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    Io(IoError),
    /// Not a usable EFI system partition image.
    BadImage,
    TooSmall,
    /// The read-back differs from what was written.
    Verify,
}

impl From<IoError> for InstallError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

fn write_chunked(dev: &mut dyn BlockDevice, lba: u64, data: &[u8]) -> Result<(), IoError> {
    let chunk = (dev.max_io() / SECTOR as usize).max(1) * SECTOR as usize;
    for (i, c) in data.chunks(chunk).enumerate() {
        dev.write(lba + (i * chunk) as u64 / SECTOR, c)?;
    }
    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha2::Sha256::digest(data));
    out
}

/// Writes the boot image built around `esp` onto `dev` (module docs).
/// Returns the image's length in bytes.
pub fn write_image(dev: &mut dyn BlockDevice, esp: &[u8]) -> Result<u64, InstallError> {
    let img = gpt::raw_image(esp).ok_or(InstallError::BadImage)?;
    write_boot_image(dev, &img)
}

/// Whether `img` is a whole disk image the installer can write: a multiple
/// of 512 bytes, a protective MBR, a primary GPT header whose backup copy
/// is the image's last sector. Anything else would not be a boot disk.
fn is_boot_image(img: &[u8]) -> bool {
    let s = SECTOR as usize;
    let head = (2 + ENTRY_SECTORS) as usize;
    if !img.len().is_multiple_of(s)
        || img.len() < (head + 1) * s
        || img.get(510..512) != Some(&[0x55, 0xaa])
    {
        return false;
    }
    let header = img.get(s..2 * s).unwrap_or(&[]);
    let backup = header
        .get(32..40)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes);
    header.get(..8) == Some(b"EFI PART") && backup == Some((img.len() / s) as u64 - 1)
}

/// Writes the finished disk image `img` onto `dev` (module docs). The
/// universal ISO's install module is such an image: besides the GPT and the
/// ESP it carries the BIOS boot code in sector 0 and the gap before the
/// ESP (X10). Returns the image's length in bytes.
pub fn write_boot_image(dev: &mut dyn BlockDevice, img: &[u8]) -> Result<u64, InstallError> {
    if !is_boot_image(img) {
        return Err(InstallError::BadImage);
    }
    let s = SECTOR as usize;
    let total = dev.sectors();
    let img_sectors = (img.len() / s) as u64;
    if total < needed_sectors(img.len() as u64) {
        return Err(InstallError::TooSmall);
    }
    let head = (2 + ENTRY_SECTORS) as usize; // LBA 0..=33
    // 1. Old tables gone: backup first, then the primary.
    write_chunked(
        dev,
        total - ENTRY_SECTORS - 1,
        &vec![0u8; (ENTRY_SECTORS as usize + 1) * s],
    )?;
    dev.flush()?;
    write_chunked(dev, 0, &vec![0u8; head * s])?;
    dev.flush()?;
    // 2. Everything after the primary table: ESP and the image's backup.
    write_chunked(
        dev,
        head as u64,
        img.get(head * s..).ok_or(InstallError::BadImage)?,
    )?;
    dev.flush()?;
    // 3. Primary entries, then the protective MBR.
    write_chunked(
        dev,
        2,
        img.get(2 * s..head * s).ok_or(InstallError::BadImage)?,
    )?;
    write_chunked(dev, 0, img.get(..s).ok_or(InstallError::BadImage)?)?;
    dev.flush()?;
    // 4. The primary header: from here on the disk is a boot disk.
    write_chunked(dev, 1, img.get(s..2 * s).ok_or(InstallError::BadImage)?)?;
    dev.flush()?;
    // 5. Read back, one request at a time (no second copy of the image:
    // the installer runs in the kernel's heap), into one running hash.
    use sha2::Digest;
    let chunk = (dev.max_io() / s).max(1) * s;
    let mut buf = vec![0u8; chunk];
    let mut h = sha2::Sha256::new();
    for (i, want) in img.chunks(chunk).enumerate() {
        let b = buf.get_mut(..want.len()).ok_or(InstallError::Verify)?;
        dev.read((i * chunk / s) as u64, b)?;
        h.update(&*b);
    }
    let mut back = [0u8; 32];
    back.copy_from_slice(&h.finalize());
    if back != sha256(img) {
        return Err(InstallError::Verify);
    }
    Ok(img_sectors * SECTOR)
}

/// Whether `dev` already holds a urMQTT data partition (for the
/// installer's warning: it will be overwritten).
pub fn holds_urmqtt_data(dev: &mut dyn BlockDevice) -> bool {
    gpt::read_table(dev, 1)
        .ok()
        .flatten()
        .is_some_and(|t| t.data_partition().is_some())
}

#[cfg(test)]
mod tests;
