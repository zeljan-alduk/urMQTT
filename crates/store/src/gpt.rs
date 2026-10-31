//! The boot disk's GUID partition table (STORAGE-PLAN §2a, DISK-FORMAT.md
//! "Boot disk"): reading and validating it, the crash-safe first-boot steps
//! that make room for the urMQTT data partition, and the writer that
//! builds a raw boot image byte for byte like `scripts/mkraw.py`.
//!
//! Every step of [`prepare`] re-checks the disk, so a crash at any write
//! leaves a state the next boot finishes:
//! - The backup copy is always written before the primary, and the
//!   partition entries before their header.
//! - A torn primary is repaired from a complete backup.
//! - A primary that still lacks the data partition makes the next boot
//!   redo the creation (with fresh GUIDs).

use alloc::vec;
use alloc::vec::Vec;

use crate::disk::{BlockDevice, IoError};
use crate::layout::{BLOCK_SECTORS, HEADER_SECTORS, MIN_SECTORS, SECTOR};

pub const SIGNATURE: &[u8; 8] = b"EFI PART";
pub const REVISION: u32 = 0x0001_0000;
pub const HEADER_SIZE: u32 = 92;
pub const ENTRIES: usize = 128;
pub const ENTRY_SIZE: usize = 128;
/// Sectors of one copy of the entry array (128 × 128 B).
pub const ENTRY_SECTORS: u64 = (ENTRIES * ENTRY_SIZE) as u64 / SECTOR;
/// Partitions start on 1 MiB boundaries.
pub const ALIGN: u64 = 2048;

/// EFI system partition, `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`.
pub const ESP_TYPE: Guid = Guid::from_rfc([
    0xc1, 0x2a, 0x73, 0x28, 0xf8, 0x1f, 0x11, 0xd2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
]);
/// urMQTT data partition, `58D3F720-BDF5-4DB7-99EC-DE26C8B8850F`.
pub const DATA_TYPE: Guid = Guid::from_rfc([
    0x58, 0xd3, 0xf7, 0x20, 0xbd, 0xf5, 0x4d, 0xb7, 0x99, 0xec, 0xde, 0x26, 0xc8, 0xb8, 0x85, 0x0f,
]);
pub const DATA_NAME: &str = "urMQTT data";
pub const ESP_NAME: &str = "EFI system partition";

/// A GUID as GPT stores it (the first three fields little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// From the RFC 4122 (big-endian, as printed) byte order.
    pub const fn from_rfc(b: [u8; 16]) -> Self {
        Self([
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ])
    }

    /// A random (version 4) GUID from 16 random bytes.
    pub fn random(mut b: [u8; 16]) -> Self {
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        Self::from_rfc(b)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9]
        )?;
        for x in &b[10..] {
            write!(f, "{x:02x}")?;
        }
        Ok(())
    }
}

// Indexing is checked at compile time in a const block.
#[allow(clippy::indexing_slicing)]
const CRC32_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE 802.3, reflected 0xEDB88320), as UEFI uses for GPT.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        // The index is masked to 0..=255, the table's length.
        let t = CRC32_TABLE
            .get(((c ^ u32::from(b)) & 0xff) as usize)
            .copied()
            .unwrap_or(0);
        c = t ^ (c >> 8);
    }
    !c
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: Guid,
    pub entries_lba: u64,
    pub entries_crc: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    /// UTF-16LE, NUL padded.
    pub name: [u8; 72],
}

impl Entry {
    pub fn new(type_guid: Guid, unique: Guid, first: u64, last: u64, name: &str) -> Self {
        let mut n = [0u8; 72];
        for (i, u) in name.encode_utf16().take(36).enumerate() {
            let [lo, hi] = u.to_le_bytes();
            if let Some(s) = n.get_mut(2 * i..2 * i + 2) {
                s.copy_from_slice(&[lo, hi]);
            }
        }
        Self {
            type_guid,
            unique_guid: unique,
            first_lba: first,
            last_lba: last,
            attributes: 0,
            name: n,
        }
    }

    pub fn is_used(&self) -> bool {
        !self.type_guid.is_zero()
    }

    pub fn sectors(&self) -> u64 {
        self.last_lba.saturating_sub(self.first_lba) + 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    Io(IoError),
    /// Neither copy is a valid GPT: not a urMQTT boot disk.
    NoGpt,
    /// The disk is smaller than the table claims (it shrank).
    Shrunk,
    /// No room for a data partition of at least the layout's minimum.
    TooSmall,
    /// All 128 entries are in use.
    TableFull,
    /// A structurally impossible table (overlaps, out of range).
    Inconsistent,
}

impl From<IoError> for GptError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn guid_at(b: &[u8], o: usize) -> Guid {
    Guid(
        b.get(o..o + 16)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 16]),
    )
}

fn put(b: &mut [u8], o: usize, v: &[u8]) {
    if let Some(s) = b.get_mut(o..o + v.len()) {
        s.copy_from_slice(v);
    }
}

impl Header {
    /// The header sector (92 bytes, CRC filled in, zero padded).
    pub fn encode(&self) -> [u8; SECTOR as usize] {
        let mut b = [0u8; SECTOR as usize];
        put(&mut b, 0, SIGNATURE);
        put(&mut b, 8, &REVISION.to_le_bytes());
        put(&mut b, 12, &HEADER_SIZE.to_le_bytes());
        put(&mut b, 24, &self.current_lba.to_le_bytes());
        put(&mut b, 32, &self.backup_lba.to_le_bytes());
        put(&mut b, 40, &self.first_usable.to_le_bytes());
        put(&mut b, 48, &self.last_usable.to_le_bytes());
        put(&mut b, 56, &self.disk_guid.0);
        put(&mut b, 72, &self.entries_lba.to_le_bytes());
        put(&mut b, 80, &(ENTRIES as u32).to_le_bytes());
        put(&mut b, 84, &(ENTRY_SIZE as u32).to_le_bytes());
        put(&mut b, 88, &self.entries_crc.to_le_bytes());
        let crc = crc32(b.get(..HEADER_SIZE as usize).unwrap_or(&[]));
        put(&mut b, 16, &crc.to_le_bytes());
        b
    }

    /// Parses and checks a header found at `lba` of a disk of `total`
    /// sectors. Only the layout this crate writes is accepted (128 entries
    /// of 128 bytes, a 92-byte header).
    pub fn decode(b: &[u8], lba: u64, total: u64) -> Option<Self> {
        if b.get(..8) != Some(&SIGNATURE[..])
            || u32_at(b, 8) != REVISION
            || u32_at(b, 12) != HEADER_SIZE
            || u32_at(b, 80) as usize != ENTRIES
            || u32_at(b, 84) as usize != ENTRY_SIZE
        {
            return None;
        }
        let mut h = [0u8; HEADER_SIZE as usize];
        h.copy_from_slice(b.get(..HEADER_SIZE as usize)?);
        put(&mut h, 16, &[0; 4]);
        if crc32(&h) != u32_at(b, 16) {
            return None;
        }
        let hdr = Self {
            current_lba: u64_at(b, 24),
            backup_lba: u64_at(b, 32),
            first_usable: u64_at(b, 40),
            last_usable: u64_at(b, 48),
            disk_guid: guid_at(b, 56),
            entries_lba: u64_at(b, 72),
            entries_crc: u32_at(b, 88),
        };
        let entries_end = hdr.entries_lba.checked_add(ENTRY_SECTORS)?;
        // `last_usable` and `backup_lba` may lie beyond the end: a disk
        // that shrank, which `prepare` reports as such.
        let sane = hdr.current_lba == lba
            && hdr.first_usable <= hdr.last_usable
            && entries_end <= total
            && hdr.entries_lba >= 2;
        sane.then_some(hdr)
    }
}

/// Encodes the entry array (`ENTRIES` slots).
pub fn encode_entries(entries: &[Entry]) -> Vec<u8> {
    let mut t = vec![0u8; ENTRIES * ENTRY_SIZE];
    for (i, e) in entries.iter().take(ENTRIES).enumerate() {
        let o = i * ENTRY_SIZE;
        put(&mut t, o, &e.type_guid.0);
        put(&mut t, o + 16, &e.unique_guid.0);
        put(&mut t, o + 32, &e.first_lba.to_le_bytes());
        put(&mut t, o + 40, &e.last_lba.to_le_bytes());
        put(&mut t, o + 48, &e.attributes.to_le_bytes());
        put(&mut t, o + 56, &e.name);
    }
    t
}

/// Decodes the used entries of an entry array.
pub fn decode_entries(t: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    for i in 0..ENTRIES {
        let o = i * ENTRY_SIZE;
        let Some(raw) = t.get(o..o + ENTRY_SIZE) else {
            break;
        };
        let e = Entry {
            type_guid: guid_at(raw, 0),
            unique_guid: guid_at(raw, 16),
            first_lba: u64_at(raw, 32),
            last_lba: u64_at(raw, 40),
            attributes: u64_at(raw, 48),
            name: raw
                .get(56..128)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 72]),
        };
        if e.is_used() {
            out.push(e);
        }
    }
    out
}

/// One valid copy of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub header: Header,
    pub entries: Vec<Entry>,
    /// The raw entry array (CRC-checked), kept for exact rewrites.
    pub raw_entries: Vec<u8>,
}

impl Table {
    fn check(&self) -> bool {
        let h = &self.header;
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for e in &self.entries {
            if e.first_lba < h.first_usable
                || e.last_lba > h.last_usable
                || e.first_lba > e.last_lba
            {
                return false;
            }
            if ranges
                .iter()
                .any(|&(a, b)| e.first_lba <= b && a <= e.last_lba)
            {
                return false;
            }
            ranges.push((e.first_lba, e.last_lba));
        }
        true
    }

    /// The urMQTT data partition, if the table has one.
    pub fn data_partition(&self) -> Option<Entry> {
        self.entries
            .iter()
            .copied()
            .find(|e| e.type_guid == DATA_TYPE)
    }
}

/// Reads the copy whose header is at `lba` and checks header, entries and
/// partition sanity.
pub fn read_table(dev: &mut dyn BlockDevice, lba: u64) -> Result<Option<Table>, IoError> {
    let total = dev.sectors();
    if lba >= total {
        return Ok(None);
    }
    let mut s = [0u8; SECTOR as usize];
    dev.read(lba, &mut s)?;
    let Some(header) = Header::decode(&s, lba, total) else {
        return Ok(None);
    };
    let mut raw = vec![0u8; ENTRIES * ENTRY_SIZE];
    dev.read(header.entries_lba, &mut raw)?;
    if crc32(&raw) != header.entries_crc {
        return Ok(None);
    }
    let t = Table {
        header,
        entries: decode_entries(&raw),
        raw_entries: raw,
    };
    Ok(t.check().then_some(t))
}

/// Sectors 1..=33 of a disk: the primary header and an entry array at
/// LBA 2, where every table this crate writes keeps it.
pub const HEAD_SECTORS: u64 = 1 + ENTRY_SECTORS;

/// The disk GUID of a valid primary GPT, from sectors 1..=33 (`head`) of a
/// disk of `total` sectors. For identifying the boot disk among devices
/// that are only read, never written.
pub fn primary_guid(head: &[u8], total: u64) -> Option<Guid> {
    let h = Header::decode(head.get(..SECTOR as usize)?, 1, total)?;
    let entries = head.get(SECTOR as usize..(HEAD_SECTORS * SECTOR) as usize)?;
    (h.entries_lba == 2 && crc32(entries) == h.entries_crc).then_some(h.disk_guid)
}

/// The disk GUID of a disk's primary GPT, if it has a valid one (boot-disk
/// identification only reads, never writes).
pub fn disk_guid(dev: &mut dyn BlockDevice) -> Result<Option<Guid>, IoError> {
    Ok(read_table(dev, 1)?.map(|t| t.header.disk_guid))
}

/// Writes one copy: entries first, then the header, then a flush.
fn write_copy(dev: &mut dyn BlockDevice, h: &Header, raw_entries: &[u8]) -> Result<(), IoError> {
    dev.write(h.entries_lba, raw_entries)?;
    dev.write(h.current_lba, &h.encode())?;
    dev.flush()
}

/// What [`prepare`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Steps {
    /// The primary copy was invalid and restored from the backup.
    pub repaired_primary: bool,
    /// The backup copy was moved to the end of a larger disk.
    pub moved_backup: bool,
    /// The backup copy was invalid and rewritten from the primary.
    pub repaired_backup: bool,
    /// The data partition was created (and a fresh disk GUID assigned).
    pub created_partition: bool,
    /// The data partition was extended over free space at the end of a
    /// larger disk (STORAGE-PLAN S3).
    pub extended_partition: bool,
}

/// The data partition, as LBAs of the whole disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPartition {
    pub first_lba: u64,
    pub last_lba: u64,
    pub unique_guid: Guid,
}

impl DataPartition {
    pub fn sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// Leading sectors of a new data partition that are zeroed before its
/// entry exists, so it classifies as blank whatever the disk held before:
/// the layout header (superblock and both size-table slots).
pub const CLEARED_SECTORS: u64 = HEADER_SECTORS;

/// Brings the boot disk to its single-disk form and returns the data
/// partition (STORAGE-PLAN §2a): repair the primary from the backup if
/// needed, move the backup to the end of a larger disk, and create the data
/// partition over the free space (1 MiB aligned start, a whole number of
/// 4 KiB blocks) with a fresh disk GUID. Idempotent and
/// crash-safe (module docs). `random` supplies 16 random bytes per call.
pub fn prepare(
    dev: &mut dyn BlockDevice,
    mut random: impl FnMut() -> [u8; 16],
) -> Result<(DataPartition, Steps), GptError> {
    let total = dev.sectors();
    if total < 2 * (ENTRY_SECTORS + 2) {
        return Err(GptError::NoGpt);
    }
    let last = total - 1;
    let mut steps = Steps::default();
    let mut t = match read_table(dev, 1)? {
        Some(t) => t,
        None => {
            // The primary is torn or gone: the backup at the end (a disk
            // that never grew, or one whose backup was already moved).
            let b = read_table(dev, last)?.ok_or(GptError::NoGpt)?;
            let h = Header {
                current_lba: 1,
                backup_lba: last,
                entries_lba: 2,
                ..b.header
            };
            write_copy(dev, &h, &b.raw_entries)?;
            steps.repaired_primary = true;
            Table { header: h, ..b }
        }
    };
    // 1. A larger disk: the backup moves to the very end.
    let backup_entries = last - ENTRY_SECTORS;
    let last_usable = backup_entries - 1;
    if t.header.backup_lba != last || t.header.last_usable != last_usable {
        if t.entries.iter().any(|e| e.last_lba > last_usable) {
            return Err(GptError::Shrunk);
        }
        let old_backup = t.header.backup_lba;
        let backup = Header {
            current_lba: last,
            backup_lba: 1,
            last_usable,
            entries_lba: backup_entries,
            ..t.header
        };
        write_copy(dev, &backup, &t.raw_entries)?;
        t.header = Header {
            backup_lba: last,
            last_usable,
            ..t.header
        };
        write_copy(dev, &t.header, &t.raw_entries)?;
        // The old backup header now lies in free space: clear it, so no tool
        // takes it for a table. A crash before this leaves a harmless stale
        // sector inside space the data partition only ever overwrites.
        if old_backup > t.header.first_usable && old_backup < backup_entries {
            dev.write(old_backup, &[0u8; SECTOR as usize])?;
            dev.flush()?;
        }
        steps.moved_backup = true;
    }
    // A valid primary with a missing or damaged backup at the end (an
    // interrupted reinstall cleared it, or the sector went bad): rewrite it.
    if !steps.moved_backup && read_table(dev, last)?.is_none() {
        let backup = Header {
            current_lba: last,
            backup_lba: 1,
            entries_lba: backup_entries,
            ..t.header
        };
        write_copy(dev, &backup, &t.raw_entries)?;
        steps.repaired_backup = true;
    }
    if let Some(e) = t.data_partition() {
        let mut last_lba = e.last_lba;
        // S3: the disk grew and the data partition is the last one: extend
        // it to the end, a whole number of 4 KiB blocks. The backup copy is
        // written before the primary, entries before their header, so a cut
        // at any write leaves the old table or the new one; the next boot
        // repeats whatever is missing.
        let last_block =
            e.first_lba + (last_usable + 1 - e.first_lba) / BLOCK_SECTORS * BLOCK_SECTORS - 1;
        let is_last = t.entries.iter().all(|o| o.first_lba <= e.first_lba);
        if is_last && last_block >= e.last_lba + ALIGN {
            let entries: Vec<Entry> = t
                .entries
                .iter()
                .map(|o| {
                    if o.unique_guid == e.unique_guid {
                        Entry {
                            last_lba: last_block,
                            ..*o
                        }
                    } else {
                        *o
                    }
                })
                .collect();
            let raw = encode_entries(&entries);
            let header = Header {
                entries_crc: crc32(&raw),
                ..t.header
            };
            let backup = Header {
                current_lba: last,
                backup_lba: 1,
                entries_lba: backup_entries,
                ..header
            };
            write_copy(dev, &backup, &raw)?;
            write_copy(dev, &header, &raw)?;
            last_lba = last_block;
            steps.extended_partition = true;
        }
        return Ok((
            DataPartition {
                first_lba: e.first_lba,
                last_lba,
                unique_guid: e.unique_guid,
            },
            steps,
        ));
    }
    // 2. The data partition over the free space after the last partition.
    let used_end = t
        .entries
        .iter()
        .map(|e| e.last_lba + 1)
        .max()
        .unwrap_or(t.header.first_usable);
    let first = used_end.div_ceil(ALIGN) * ALIGN;
    if first > last_usable {
        return Err(GptError::TooSmall);
    }
    // Whole 4 KiB blocks: the data layout works in them (DISK-FORMAT G7).
    let sectors = (last_usable + 1 - first) / BLOCK_SECTORS * BLOCK_SECTORS;
    if sectors < MIN_SECTORS {
        return Err(GptError::TooSmall);
    }
    let part_last = first + sectors - 1;
    if t.entries.len() >= ENTRIES {
        return Err(GptError::TableFull);
    }
    // Blank head first: the partition classifies as new from the moment
    // its entry exists.
    let zeros = vec![0u8; (CLEARED_SECTORS * SECTOR) as usize];
    dev.write(first, &zeros)?;
    dev.flush()?;
    let unique = Guid::random(random());
    let mut entries = t.entries.clone();
    entries.push(Entry::new(DATA_TYPE, unique, first, part_last, DATA_NAME));
    let raw = encode_entries(&entries);
    let header = Header {
        disk_guid: Guid::random(random()),
        entries_crc: crc32(&raw),
        ..t.header
    };
    let backup = Header {
        current_lba: last,
        backup_lba: 1,
        entries_lba: backup_entries,
        ..header
    };
    write_copy(dev, &backup, &raw)?;
    write_copy(dev, &header, &raw)?;
    steps.created_partition = true;
    Ok((
        DataPartition {
            first_lba: first,
            last_lba: part_last,
            unique_guid: unique,
        },
        steps,
    ))
}

/// A deterministic version-4 GUID derived from `seed` and `label`, exactly
/// as `scripts/mkraw.py` derives them (SHA-256 of label || seed).
pub fn derived_guid(seed: &[u8; 32], label: &str) -> Guid {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(label.as_bytes());
    h.update(seed);
    let d = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    Guid::random(b)
}

/// Bytes of the raw boot image around an ESP of `esp_bytes` (see
/// [`raw_image`]): whole MiBs with the tables and at least 1 MiB after the
/// ESP.
pub fn raw_image_len(esp_bytes: u64) -> u64 {
    let esp_sectors = esp_bytes.div_ceil(SECTOR);
    (ALIGN + esp_sectors + ALIGN).div_ceil(ALIGN) * ALIGN * SECTOR
}

/// The raw boot image around an EFI system partition, byte for byte what
/// `scripts/mkraw.py` writes (shared by `urmqtt-disk create` and, in S1b,
/// the self-installing ISO): protective MBR, primary GPT, the ESP at 1 MiB,
/// backup GPT at the end of whole MiBs with at least 1 MiB after the ESP.
pub fn raw_image(esp: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest;
    if !esp.len().is_multiple_of(SECTOR as usize) || esp.is_empty() {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sha2::Sha256::digest(esp));
    let esp_sectors = esp.len() as u64 / SECTOR;
    let total = (ALIGN + esp_sectors + ALIGN).div_ceil(ALIGN) * ALIGN;
    let last = total - 1;
    let backup_entries = last - ENTRY_SECTORS;
    let entry = Entry::new(
        ESP_TYPE,
        derived_guid(&seed, "esp"),
        ALIGN,
        ALIGN + esp_sectors - 1,
        ESP_NAME,
    );
    let raw = encode_entries(&[entry]);
    let primary = Header {
        current_lba: 1,
        backup_lba: last,
        first_usable: ALIGN,
        last_usable: backup_entries - 1,
        disk_guid: derived_guid(&seed, "disk"),
        entries_lba: 2,
        entries_crc: crc32(&raw),
    };
    let backup = Header {
        current_lba: last,
        backup_lba: 1,
        entries_lba: backup_entries,
        ..primary
    };
    let mut img = vec![0u8; (total * SECTOR) as usize];
    // Protective MBR: one partition of type 0xEE over the whole disk.
    let mut mbr = [0u8; 16];
    mbr[1..4].copy_from_slice(&[0, 2, 0]);
    mbr[4] = 0xee;
    mbr[5..8].copy_from_slice(&[0xff, 0xff, 0xff]);
    mbr[8..12].copy_from_slice(&1u32.to_le_bytes());
    mbr[12..16].copy_from_slice(&(last.min(u64::from(u32::MAX)) as u32).to_le_bytes());
    put(&mut img, 446, &mbr);
    put(&mut img, 510, &[0x55, 0xaa]);
    let s = SECTOR as usize;
    put(&mut img, s, &primary.encode());
    put(&mut img, 2 * s, &raw);
    put(&mut img, ALIGN as usize * s, esp);
    put(&mut img, backup_entries as usize * s, &raw);
    put(&mut img, last as usize * s, &backup.encode());
    Some(img)
}

#[cfg(test)]
mod tests;
