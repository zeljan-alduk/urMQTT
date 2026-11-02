//! `urmqtt-disk encrypt | decrypt | rekey` (STORAGE-PLAN S7, ADR-240):
//! offline conversion of a data partition between plain and AES-256-XTS, or
//! from one key to another. The VM must be stopped.
//!
//! **Order of writes.** A conversion record at `CONVERT_LBA` (plaintext, with
//! the key checks of both states and the next sector to convert) is written
//! first; from then on the kernel refuses to open the partition. The
//! sectors are converted in chunks of 1 MiB: the chunk's old bytes go to the
//! journal first (a host file, flushed), then the converted chunk is written
//! and flushed, then the record's watermark moves. The superblock (the only
//! plaintext) is switched last, into the other slot with the next
//! generation, and the record is cleared after it.
//!
//! **After a cut** the same command with `--resume` (and the same keys)
//! restores the chunk the journal holds if it is the one the watermark
//! points at, and carries on. A chunk is therefore never converted twice and
//! never lost. The journal is not part of the disk: without it, a cut in the
//! middle of a chunk cannot be mended, which is why it is flushed before the
//! chunk is touched and why the command refuses to start without one.
//!
//! A sector that is all zero on the medium is a hole in both states (XTS
//! layer, ADR-240) and stays one; so do sectors that decrypt to zeros.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use urmqtt_store::BlockDevice;
use urmqtt_store::crc::crc32c;
use urmqtt_store::crypt::{DiskKey, KEY_BYTES};
use urmqtt_store::layout::{
    BLOCK, CONVERT_LBA, CONVERT_MAGIC, FLAG_ENCRYPTED, Layout, SB_SLOT_LBA, SECTOR,
};

pub type Key = [u8; KEY_BYTES];
type Res<T> = Result<T, String>;

const S: usize = SECTOR as usize;
/// Sectors per chunk: 1 MiB.
pub const CHUNK_SECTORS: u64 = 2048;
const CONVERT_SECTORS: u64 = BLOCK as u64 / SECTOR;

/// Where the old bytes of the chunk in flight go.
pub trait Journal {
    /// Keeps `first` (the chunk's first sector) and its old raw bytes;
    /// returns only when they are durable.
    fn save(&mut self, first: u64, raw: &[u8]) -> Res<()>;
    fn load(&mut self) -> Res<Option<(u64, Vec<u8>)>>;
    fn clear(&mut self) -> Res<()>;
}

/// A journal in memory (tests).
#[derive(Default)]
pub struct MemJournal(pub Option<(u64, Vec<u8>)>);

impl Journal for MemJournal {
    fn save(&mut self, first: u64, raw: &[u8]) -> Res<()> {
        self.0 = Some((first, raw.to_vec()));
        Ok(())
    }
    fn load(&mut self) -> Res<Option<(u64, Vec<u8>)>> {
        Ok(self.0.clone())
    }
    fn clear(&mut self) -> Res<()> {
        self.0 = None;
        Ok(())
    }
}

/// A journal in a host file: 16 bytes of header (the sector, the length), a
/// CRC, then the bytes.
pub struct FileJournal(pub PathBuf);

impl Journal for FileJournal {
    fn save(&mut self, first: u64, raw: &[u8]) -> Res<()> {
        let mut b = Vec::with_capacity(raw.len() + 24);
        b.extend_from_slice(&first.to_le_bytes());
        b.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        b.extend_from_slice(raw);
        let crc = crc32c(&b);
        b.extend_from_slice(&crc.to_le_bytes());
        let tmp = self.0.with_extension("tmp");
        let mut f = File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&b).map_err(|e| format!("journal: {e}"))?;
        f.sync_all().map_err(|e| format!("journal: {e}"))?;
        std::fs::rename(&tmp, &self.0).map_err(|e| format!("journal: {e}"))
    }
    fn load(&mut self) -> Res<Option<(u64, Vec<u8>)>> {
        let mut b = Vec::new();
        match OpenOptions::new().read(true).open(&self.0) {
            Ok(mut f) => {
                f.read_to_end(&mut b).map_err(|e| format!("journal: {e}"))?;
            }
            Err(_) => return Ok(None),
        }
        if b.len() < 20 {
            return Err("the journal file is damaged".into());
        }
        let (body, crc) = b.split_at(b.len() - 4);
        if crc32c(body).to_le_bytes() != crc {
            return Err("the journal file is damaged".into());
        }
        let first = u64::from_le_bytes(body[..8].try_into().map_err(|_| "journal")?);
        let len = u64::from_le_bytes(body[8..16].try_into().map_err(|_| "journal")?) as usize;
        let raw = body.get(16..16 + len).ok_or("the journal file is damaged")?;
        Ok(Some((first, raw.to_vec())))
    }
    fn clear(&mut self) -> Res<()> {
        let _ = std::fs::remove_file(&self.0);
        Ok(())
    }
}

/// What a conversion did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub sectors_rewritten: u64,
    pub chunks_skipped: u64,
    pub resumed: bool,
}

fn io<T>(r: Result<T, urmqtt_store::IoError>, what: &str) -> Res<T> {
    r.map_err(|e| format!("{what}: {e:?}"))
}

fn read_block(dev: &mut dyn BlockDevice, lba: u64) -> Res<[u8; BLOCK]> {
    let mut b = [0u8; BLOCK];
    io(dev.read(lba, &mut b), &format!("read LBA {lba}"))?;
    Ok(b)
}

fn put(dev: &mut dyn BlockDevice, lba: u64, b: &[u8]) -> Res<()> {
    io(dev.write(lba, b), &format!("write LBA {lba}"))?;
    io(dev.flush(), "flush")
}

/// The conversion record.
struct Record {
    from: [u8; 32],
    to: [u8; 32],
    next: u64,
    total: u64,
}

impl Record {
    /// One sector: written in one piece even by a device that tears a
    /// larger write.
    fn encode(&self) -> [u8; S] {
        let mut b = [0u8; S];
        b[..8].copy_from_slice(&CONVERT_MAGIC);
        b[8..40].copy_from_slice(&self.from);
        b[40..72].copy_from_slice(&self.to);
        b[72..80].copy_from_slice(&self.next.to_le_bytes());
        b[80..88].copy_from_slice(&self.total.to_le_bytes());
        let crc = crc32c(&b[..S - 4]);
        b[S - 4..].copy_from_slice(&crc.to_le_bytes());
        b
    }

    fn decode(b: &[u8; BLOCK]) -> Res<Option<Self>> {
        if b[..8] != CONVERT_MAGIC {
            return Ok(None);
        }
        if crc32c(&b[..S - 4]).to_le_bytes() != b[S - 4..S] {
            return Err("the conversion record is damaged".into());
        }
        let u = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
        Ok(Some(Self {
            from: b[8..40].try_into().unwrap_or([0; 32]),
            to: b[40..72].try_into().unwrap_or([0; 32]),
            next: u(72),
            total: u(80),
        }))
    }
}

fn is_plain(lba: u64) -> bool {
    SB_SLOT_LBA
        .iter()
        .any(|&s| lba >= s && lba < s + CONVERT_SECTORS)
        || (CONVERT_LBA..CONVERT_LBA + CONVERT_SECTORS).contains(&lba)
}

/// Converts the sectors of `raw` (starting at `first`) from `from` to `to`.
fn transform(raw: &[u8], first: u64, from: Option<&DiskKey>, to: Option<&DiskKey>) -> Vec<u8> {
    let mut out = raw.to_vec();
    for (i, s) in out.chunks_exact_mut(S).enumerate() {
        let lba = first + i as u64;
        if is_plain(lba) || s.iter().all(|&b| b == 0) {
            continue;
        }
        if let Some(k) = from {
            k.sector(lba, s, false);
        }
        if let Some(k) = to {
            if s.iter().any(|&b| b != 0) {
                k.sector(lba, s, true);
            }
        }
        // Plain sectors that are all zero were holes or written zeros; as a
        // hole they stay zero in either state.
    }
    out
}

fn check_of(k: Option<&DiskKey>, uuid: &[u8; 16]) -> [u8; 32] {
    k.map_or([0; 32], |k| k.key_check(uuid))
}

/// Converts the partition `dev` (a window over the data partition, below
/// the crypt layer) from `from` to `to`: `encrypt` is `(None, Some)`,
/// `decrypt` `(Some, None)`, `rekey` `(Some, Some)`. `resume` carries on a
/// conversion a cut interrupted. `progress(done, total)` is called after
/// every chunk.
pub fn convert(
    dev: &mut dyn BlockDevice,
    from: Option<&Key>,
    to: Option<&Key>,
    journal: &mut dyn Journal,
    resume: bool,
    mut progress: impl FnMut(u64, u64),
) -> Res<Report> {
    if from.is_none() && to.is_none() {
        return Err("nothing to convert: give --key and/or --new-key".into());
    }
    if let (Some(a), Some(b)) = (from, to)
        && a == b
    {
        return Err("the new key is the old key".into());
    }
    let total_dev = dev.sectors();
    let a = read_block(dev, SB_SLOT_LBA[0])?;
    let b = read_block(dev, SB_SLOT_LBA[1])?;
    let (layout, slot) = Layout::select(&a, &b, total_dev)
        .map_err(|e| format!("data partition layout: {e:?}"))?
        .ok_or("the data partition is blank: nothing to convert")?;
    let kf = from.map(DiskKey::new);
    let kt = to.map(DiskKey::new);
    let cf = check_of(kf.as_ref(), &layout.uuid);
    let ct = check_of(kt.as_ref(), &layout.uuid);
    let rec = Record::decode(&read_block(dev, CONVERT_LBA)?)?;
    let at_from = layout.encrypted() == from.is_some()
        && (from.is_none() || layout.key_check == cf);
    let at_to = layout.encrypted() == to.is_some() && (to.is_none() || layout.key_check == ct);

    let (mut next, resumed) = match rec {
        None => {
            if resume {
                return Err("no interrupted conversion to resume".into());
            }
            if layout.encrypted() && from.is_none() {
                return Err("the disk is encrypted: give its key with --key".into());
            }
            if !layout.encrypted() && from.is_some() {
                return Err("the disk is not encrypted: --key is only for an encrypted disk".into());
            }
            if !at_from {
                return Err("the key does not match this disk".into());
            }
            let r = Record {
                from: cf,
                to: ct,
                next: 0,
                total: layout.total_sectors,
            };
            put(dev, CONVERT_LBA, &r.encode())?;
            (0, false)
        }
        Some(r) => {
            if !resume {
                return Err(
                    "an earlier conversion was interrupted: run it again with --resume and the same keys"
                        .into(),
                );
            }
            if r.from != cf || r.to != ct || r.total != layout.total_sectors {
                return Err("the keys are not the ones of the interrupted conversion".into());
            }
            if at_to && !at_from && r.next >= r.total {
                // The superblock was switched; only the record is left.
                put(dev, CONVERT_LBA, &[0u8; S])?;
                journal.clear()?;
                return Ok(Report {
                    sectors_rewritten: 0,
                    chunks_skipped: 0,
                    resumed: true,
                });
            }
            // A chunk that was cut half way is put back as it was.
            if let Some((first, raw)) = journal.load()?
                && first == r.next
            {
                put(dev, first, &raw)?;
            }
            (r.next, true)
        }
    };

    let total = layout.total_sectors;
    let (mut rewritten, mut skipped) = (0u64, 0u64);
    while next < total {
        let n = CHUNK_SECTORS.min(total - next);
        let mut old = vec![0u8; n as usize * S];
        io(dev.read(next, &mut old), &format!("read LBA {next}"))?;
        let new = transform(&old, next, kf.as_ref(), kt.as_ref());
        if new == old {
            skipped += 1;
        } else {
            journal.save(next, &old)?;
            io(dev.write(next, &new), &format!("write LBA {next}"))?;
            io(dev.flush(), "flush")?;
            rewritten += n;
        }
        next += n;
        let r = Record {
            from: cf,
            to: ct,
            next,
            total,
        };
        put(dev, CONVERT_LBA, &r.encode())?;
        progress(next, total);
    }

    // The superblock last, into the other slot, with the next generation.
    let mut l2 = layout.clone();
    l2.generation += 1;
    if to.is_some() {
        l2.flags |= FLAG_ENCRYPTED;
        l2.key_check = ct;
    } else {
        l2.flags &= !FLAG_ENCRYPTED;
        l2.key_check = [0; 32];
    }
    put(dev, SB_SLOT_LBA[1 - slot], &l2.encode())?;
    put(dev, CONVERT_LBA, &[0u8; S])?;
    journal.clear()?;
    Ok(Report {
        sectors_rewritten: rewritten,
        chunks_skipped: skipped,
        resumed,
    })
}
