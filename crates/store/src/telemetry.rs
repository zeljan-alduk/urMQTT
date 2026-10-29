//! Telemetry log (PROMPT §7.4, M12, ADR-031): append-only segments in the
//! telemetry region of the data disk, one partition per source core, a
//! CRC per record, batched writes, recovery with torn-tail truncation,
//! and size- plus age-based retention.
//!
//! ```text
//! region   [ header 4 KiB ][ partition 0 ][ partition 1 ] … [ partition P-1 ]
//! partition [ segment 0 ][ segment 1 ] … [ segment S-1 ]   (a ring)
//! segment  [ header 512 B: magic, partition, seq, created, CRC ][ records … ][ zeros ]
//! record   [ len u32 ][ crc u32 ][ ts_ms u64 ][ topic_len u16 ][ topic ][ payload ]
//! ```
//!
//! `len` counts the bytes after the `crc` field. The CRC-32C covers the
//! segment's sequence number followed by those bytes. Records left over
//! from an earlier pass of the ring therefore never validate in a reused
//! segment. A record never spans segments. Every flush writes whole
//! sectors, zero-padded after the last record, so recovery stops at the
//! first `len == 0` (clean end) or at the first record that does not
//! check out (a torn tail, which is truncated).

use alloc::vec;
use alloc::vec::Vec;

use crate::crc::{crc32c, update};
use crate::disk::{Disk, DiskError};
use crate::layout::{BLOCK, RegionKind, SECTOR};

pub const MAGIC: [u8; 8] = *b"URMQTLH1";
pub const SEGMENT_MAGIC: [u8; 8] = *b"URMQTSG1";
pub const VERSION: u32 = 1;
/// Partitions per log: source core `c` writes partition `c % PARTITIONS`.
pub const PARTITIONS: usize = 8;
const SEGMENT_HEADER: u64 = SECTOR;
const RECORD_HEADER: usize = 8;
/// Fixed record fields after `crc`: timestamp and topic length.
const RECORD_FIXED: usize = 10;
const MIN_SEGMENT: u64 = 64 * 1024;
const MAX_SEGMENT: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
    Disk(DiskError),
    /// The region holds data that is not a telemetry log: never formatted over.
    UnknownData,
    BadHeader,
    /// The telemetry region is too small for the minimum geometry.
    TooSmall,
    /// A single record is larger than a segment.
    RecordTooLarge,
}

impl From<DiskError> for LogError {
    fn from(e: DiskError) -> Self {
        Self::Disk(e)
    }
}

/// A record as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    pub ts_ms: u64,
    pub topic: &'a str,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recovery {
    pub records: u64,
    pub segments: u32,
    /// Partitions whose active segment ended in a damaged record.
    pub torn_tails: u32,
    /// Records older than the retention period (still on disk until their
    /// segment is reused).
    pub expired: u64,
}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    seg_bytes: u64,
    segments: u64,
    part_bytes: u64,
}

impl Geometry {
    fn plan(region_bytes: u64) -> Result<Self, LogError> {
        let usable = region_bytes.saturating_sub(BLOCK as u64);
        let part = usable / PARTITIONS as u64;
        let seg = ((part / 8).clamp(MIN_SEGMENT, MAX_SEGMENT) / BLOCK as u64) * BLOCK as u64;
        let segments = part / seg.max(1);
        if segments < 2 {
            return Err(LogError::TooSmall);
        }
        Ok(Self {
            seg_bytes: seg,
            segments,
            part_bytes: seg * segments,
        })
    }

    fn segment_offset(&self, p: usize, s: u64) -> u64 {
        BLOCK as u64 + p as u64 * self.part_bytes + s * self.seg_bytes
    }
}

#[derive(Debug, Clone)]
struct Partition {
    /// Ring index of the active segment and its sequence number (0: none).
    active: u64,
    seq: u64,
    /// Byte offset of the next record inside the active segment.
    pos: u64,
    /// Bytes of the active segment from the last sector boundary before
    /// `pos` (kept so a flush writes whole sectors without reading).
    tail: Vec<u8>,
    /// Encoded records waiting for the next flush.
    pending: Vec<u8>,
    pending_records: u64,
    /// A fresh segment header to write with the next flush.
    pending_header: Option<(u64, [u8; SECTOR as usize])>,
    /// Records appended since the last flush started at this offset.
    pending_at: u64,
    /// Records written to the disk but not yet made durable by a sync.
    unsynced: u64,
    /// Start a new segment before the next record. Set after recovery: a
    /// recovered segment is never extended, because bytes after its last
    /// valid record may be valid records of an unacknowledged batch whose
    /// earlier sectors were lost; extending it could resurrect them.
    roll: bool,
}

pub struct TelemetryLog {
    geo: Geometry,
    parts: Vec<Partition>,
    now_unix: u64,
    pub durable_records: u64,
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn encode_header(geo: &Geometry) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    put(&mut b, 0, &MAGIC);
    put(&mut b, 8, &VERSION.to_le_bytes());
    put(&mut b, 12, &(PARTITIONS as u32).to_le_bytes());
    put(&mut b, 16, &geo.seg_bytes.to_le_bytes());
    put(&mut b, 24, &geo.segments.to_le_bytes());
    let crc = crc32c(b.get(..BLOCK - 4).unwrap_or(&[]));
    put(&mut b, BLOCK - 4, &crc.to_le_bytes());
    b
}

fn decode_header(b: &[u8; BLOCK], region_bytes: u64) -> Result<Option<Geometry>, LogError> {
    if b.iter().all(|&x| x == 0) {
        return Ok(None);
    }
    if b.get(..8) != Some(&MAGIC[..]) {
        return Err(LogError::UnknownData);
    }
    let crc_ok = crc32c(b.get(..BLOCK - 4).unwrap_or(&[])) == u32_at(b, BLOCK - 4).unwrap_or(0);
    let (Some(ver), Some(parts), Some(seg), Some(segs)) =
        (u32_at(b, 8), u32_at(b, 12), u64_at(b, 16), u64_at(b, 24))
    else {
        return Err(LogError::BadHeader);
    };
    if !crc_ok || ver != VERSION || parts as usize != PARTITIONS || seg < MIN_SEGMENT || segs < 2 {
        return Err(LogError::BadHeader);
    }
    let geo = Geometry {
        seg_bytes: seg,
        segments: segs,
        part_bytes: seg.checked_mul(segs).ok_or(LogError::BadHeader)?,
    };
    let need = geo
        .part_bytes
        .checked_mul(PARTITIONS as u64)
        .and_then(|x| x.checked_add(BLOCK as u64))
        .ok_or(LogError::BadHeader)?;
    if need > region_bytes || !seg.is_multiple_of(BLOCK as u64) {
        return Err(LogError::BadHeader);
    }
    Ok(Some(geo))
}

fn segment_header(p: usize, seq: u64, created: u64) -> [u8; SECTOR as usize] {
    let mut b = [0u8; SECTOR as usize];
    put(&mut b, 0, &SEGMENT_MAGIC);
    put(&mut b, 8, &(p as u32).to_le_bytes());
    put(&mut b, 16, &seq.to_le_bytes());
    put(&mut b, 24, &created.to_le_bytes());
    let crc = crc32c(b.get(..SECTOR as usize - 4).unwrap_or(&[]));
    put(&mut b, SECTOR as usize - 4, &crc.to_le_bytes());
    b
}

/// (seq, created) of a valid segment header for partition `p`.
fn parse_segment_header(b: &[u8], p: usize) -> Option<(u64, u64)> {
    let n = SECTOR as usize;
    if b.get(..8) != Some(&SEGMENT_MAGIC[..])
        || crc32c(b.get(..n - 4)?) != u32_at(b, n - 4)?
        || u32_at(b, 8)? as usize != p
    {
        return None;
    }
    let seq = u64_at(b, 16)?;
    (seq > 0).then_some((seq, u64_at(b, 24)?))
}

fn record_crc(seq: u64, body: &[u8]) -> u32 {
    update(crc32c(&seq.to_le_bytes()), body)
}

/// Encoded size of a record.
pub fn record_size(topic: &str, payload: &[u8]) -> usize {
    RECORD_HEADER + RECORD_FIXED + topic.len() + payload.len()
}

/// Outcome of scanning one segment's records.
struct SegmentScan {
    /// Offset just past the last valid record.
    end: u64,
    records: u64,
    expired: u64,
    /// Stopped at a damaged record rather than a clean end.
    torn: bool,
}

impl TelemetryLog {
    /// Opens the log in the telemetry region, formatting it if blank, and
    /// recovers every partition. Records older than `retention_ms` (from
    /// `now_unix`) count as expired.
    pub fn open(
        disk: &mut Disk,
        now_unix: u64,
        retention_ms: u64,
    ) -> Result<(Self, Recovery), LogError> {
        let region = disk
            .region(RegionKind::Telemetry)
            .ok_or(LogError::TooSmall)?;
        let mut hb = [0u8; BLOCK];
        disk.read_at(RegionKind::Telemetry, 0, &mut hb)?;
        let geo = match decode_header(&hb, region.bytes())? {
            Some(g) => g,
            None => {
                let g = Geometry::plan(region.bytes())?;
                disk.write_at(RegionKind::Telemetry, 0, &encode_header(&g))?;
                disk.sync()?;
                g
            }
        };
        let mut log = Self {
            geo,
            parts: Vec::with_capacity(PARTITIONS),
            now_unix,
            durable_records: 0,
        };
        let cutoff = (now_unix * 1000).saturating_sub(retention_ms);
        let mut rec = Recovery::default();
        for p in 0..PARTITIONS {
            let part = log.recover_partition(disk, p, cutoff, &mut rec)?;
            log.parts.push(part);
        }
        log.durable_records = rec.records;
        Ok((log, rec))
    }

    fn read_segment_headers(
        &self,
        disk: &mut Disk,
        p: usize,
    ) -> Result<Vec<Option<(u64, u64)>>, LogError> {
        let mut out = Vec::with_capacity(self.geo.segments as usize);
        let mut sec = [0u8; SECTOR as usize];
        for s in 0..self.geo.segments {
            disk.read_at(
                RegionKind::Telemetry,
                self.geo.segment_offset(p, s),
                &mut sec,
            )?;
            out.push(parse_segment_header(&sec, p));
        }
        Ok(out)
    }

    fn recover_partition(
        &self,
        disk: &mut Disk,
        p: usize,
        cutoff_ms: u64,
        rec: &mut Recovery,
    ) -> Result<Partition, LogError> {
        let headers = self.read_segment_headers(disk, p)?;
        let mut order: Vec<(u64, u64)> = headers
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.map(|(seq, _)| (seq, i as u64)))
            .collect();
        order.sort_unstable();
        let mut part = Partition {
            active: 0,
            seq: 0,
            pos: SEGMENT_HEADER,
            tail: Vec::new(),
            pending: Vec::new(),
            pending_records: 0,
            pending_header: None,
            pending_at: SEGMENT_HEADER,
            unsynced: 0,
            roll: false,
        };
        let newest = order.last().copied();
        for &(seq, idx) in &order {
            let scan = self.scan_segment(disk, p, idx, seq, cutoff_ms, &mut |_| {})?;
            rec.segments += 1;
            rec.records += scan.records;
            rec.expired += scan.expired;
            if Some((seq, idx)) == newest {
                if scan.torn {
                    rec.torn_tails += 1;
                }
                part.active = idx;
                part.seq = seq;
                part.pos = scan.end;
            }
        }
        // Empty partitions start their first segment with the first record;
        // recovered ones continue in a new segment (see `Partition::roll`).
        part.roll = part.seq != 0;
        Ok(part)
    }

    fn scan_segment(
        &self,
        disk: &mut Disk,
        p: usize,
        seg: u64,
        seq: u64,
        cutoff_ms: u64,
        f: &mut dyn FnMut(Record<'_>),
    ) -> Result<SegmentScan, LogError> {
        let base = self.geo.segment_offset(p, seg);
        let mut data = vec![0u8; self.geo.seg_bytes as usize];
        disk.read_at(RegionKind::Telemetry, base, &mut data)?;
        let mut pos = SEGMENT_HEADER as usize;
        let (mut records, mut expired, mut torn) = (0u64, 0u64, false);
        // `len == 0` (zero padding) is the clean end of the segment.
        while let Some(len) = u32_at(&data, pos).filter(|&l| l != 0) {
            let len = len as usize;
            let body = data.get(pos + RECORD_HEADER..pos + RECORD_HEADER + len);
            let valid = body.and_then(|b| {
                let crc = u32_at(&data, pos + 4)?;
                if len < RECORD_FIXED || record_crc(seq, b) != crc {
                    return None;
                }
                let ts = u64_at(b, 0)?;
                let tl = u16::from_le_bytes(b.get(8..10)?.try_into().ok()?) as usize;
                let topic = core::str::from_utf8(b.get(10..10 + tl)?).ok()?;
                let payload = b.get(10 + tl..)?;
                Some(Record {
                    ts_ms: ts,
                    topic,
                    payload,
                })
            });
            let Some(r) = valid else {
                torn = true;
                break;
            };
            if r.ts_ms < cutoff_ms {
                expired += 1;
            } else {
                f(r);
            }
            records += 1;
            pos += RECORD_HEADER + len;
        }
        Ok(SegmentScan {
            end: pos as u64,
            records,
            expired,
            torn,
        })
    }

    /// Calls `f` for every live record of partition `p`, oldest first.
    pub fn scan(
        &self,
        disk: &mut Disk,
        p: usize,
        retention_ms: u64,
        mut f: impl FnMut(Record<'_>),
    ) -> Result<u64, LogError> {
        let headers = self.read_segment_headers(disk, p)?;
        let mut order: Vec<(u64, u64)> = headers
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.map(|(seq, _)| (seq, i as u64)))
            .collect();
        order.sort_unstable();
        let cutoff = (self.now_unix * 1000).saturating_sub(retention_ms);
        let mut n = 0;
        for (seq, idx) in order {
            n += self
                .scan_segment(disk, p, idx, seq, cutoff, &mut f)?
                .records;
        }
        Ok(n)
    }

    pub fn partition_of(core: usize) -> usize {
        core % PARTITIONS
    }

    pub fn set_now(&mut self, now_unix: u64) {
        self.now_unix = now_unix;
    }

    /// Bytes a partition can hold (all segments, minus headers).
    pub fn capacity_bytes(&self) -> u64 {
        (self.geo.seg_bytes - SEGMENT_HEADER) * self.geo.segments
    }

    /// Queues a record for partition `p`. It is written by [`Self::flush`]
    /// (or earlier, without a sync, when its segment fills up).
    pub fn append(
        &mut self,
        disk: &mut Disk,
        p: usize,
        ts_ms: u64,
        topic: &str,
        payload: &[u8],
    ) -> Result<(), LogError> {
        let size = record_size(topic, payload) as u64;
        if size + SEGMENT_HEADER > self.geo.seg_bytes || topic.len() > usize::from(u16::MAX) {
            return Err(LogError::RecordTooLarge);
        }
        let geo = self.geo;
        let now = self.now_unix;
        let p = p % PARTITIONS;
        let part = self.parts.get_mut(p).ok_or(LogError::BadHeader)?;
        let used = part.pending_at + part.pending.len() as u64;
        if part.seq == 0 || part.roll || used + size > geo.seg_bytes {
            // Roll over to the next segment of the ring, reclaiming the
            // oldest one. What is pending for the old segment goes first.
            let n = write_pending(part, disk, &geo, p)?;
            part.unsynced += n;
            let next = if part.seq == 0 {
                0
            } else {
                (part.active + 1) % geo.segments
            };
            part.roll = false;
            part.seq += 1;
            part.active = next;
            part.pos = SEGMENT_HEADER;
            part.pending_at = SEGMENT_HEADER;
            part.tail.clear();
            part.pending_header = Some((next, segment_header(p, part.seq, now)));
        }
        let seq = part.seq;
        let start = part.pending.len();
        part.pending.resize(start + size as usize, 0);
        let body_len = size as usize - RECORD_HEADER;
        let Some(rec) = part.pending.get_mut(start..) else {
            return Err(LogError::BadHeader);
        };
        put(rec, 0, &(body_len as u32).to_le_bytes());
        put(rec, 8, &ts_ms.to_le_bytes());
        put(rec, 16, &(topic.len() as u16).to_le_bytes());
        put(rec, 18, topic.as_bytes());
        put(rec, 18 + topic.len(), payload);
        let crc = record_crc(seq, rec.get(RECORD_HEADER..).unwrap_or(&[]));
        put(rec, 4, &crc.to_le_bytes());
        part.pending_records += 1;
        Ok(())
    }

    /// Records appended but not yet durable.
    pub fn pending_records(&self) -> u64 {
        self.parts
            .iter()
            .map(|p| p.pending_records + p.unsynced)
            .sum()
    }

    /// Bytes waiting to be written.
    pub fn pending_bytes(&self) -> usize {
        self.parts.iter().map(|p| p.pending.len()).sum()
    }

    /// Writes every pending record (whole, zero-padded sectors) and makes
    /// them durable. Returns how many records became durable.
    pub fn flush(&mut self, disk: &mut Disk) -> Result<u64, LogError> {
        let geo = self.geo;
        let mut wrote = 0u64;
        for (p, part) in self.parts.iter_mut().enumerate() {
            let n = write_pending(part, disk, &geo, p)?;
            wrote += n + part.unsynced;
        }
        disk.sync()?;
        for part in &mut self.parts {
            part.unsynced = 0;
        }
        self.durable_records += wrote;
        Ok(wrote)
    }
}

impl TelemetryLog {
    /// Fault injection for the boot self-test (`test=log-tear`): writes only
    /// the first `keep` bytes of partition `p`'s pending records, cutting a
    /// record in half like a torn device write, and makes that durable.
    /// The in-memory state is discarded: the caller must reboot.
    #[doc(hidden)]
    pub fn simulate_torn_flush(
        &mut self,
        disk: &mut Disk,
        p: usize,
        keep: usize,
    ) -> Result<(), LogError> {
        let geo = self.geo;
        let part = self
            .parts
            .get_mut(p % PARTITIONS)
            .ok_or(LogError::BadHeader)?;
        if let Some((seg, hdr)) = part.pending_header.take() {
            disk.write_at(RegionKind::Telemetry, geo.segment_offset(p, seg), &hdr)?;
        }
        let keep = keep.min(part.pending.len());
        let torn = part.pending.get(..keep).unwrap_or(&[]).to_vec();
        disk.write_at(
            RegionKind::Telemetry,
            geo.segment_offset(p, part.active) + part.pending_at,
            &torn,
        )?;
        disk.sync()?;
        part.pending.clear();
        part.pending_records = 0;
        Ok(())
    }
}

impl TelemetryLog {
    /// Test hook: writes pending records without the final sync.
    #[cfg(test)]
    fn write_all_without_sync(&mut self, disk: &mut Disk) -> Result<(), LogError> {
        let geo = self.geo;
        for (p, part) in self.parts.iter_mut().enumerate() {
            write_pending(part, disk, &geo, p)?;
        }
        Ok(())
    }
}

/// Writes a partition's pending header and records (no sync). Returns the
/// number of records written.
fn write_pending(
    part: &mut Partition,
    disk: &mut Disk,
    geo: &Geometry,
    p: usize,
) -> Result<u64, LogError> {
    if let Some((seg, hdr)) = part.pending_header.take() {
        disk.write_at(RegionKind::Telemetry, geo.segment_offset(p, seg), &hdr)?;
    }
    if part.pending.is_empty() {
        return Ok(0);
    }
    let start = part.pending_at - part.tail.len() as u64;
    let mut buf = core::mem::take(&mut part.tail);
    buf.extend_from_slice(&part.pending);
    let end = start + buf.len() as u64;
    let padded = end.div_ceil(SECTOR) * SECTOR;
    buf.resize((padded - start) as usize, 0);
    disk.write_at(
        RegionKind::Telemetry,
        geo.segment_offset(p, part.active) + start,
        &buf,
    )?;
    // Keep the bytes after the last sector boundary for the next write.
    let keep_from = (end - end % SECTOR - start) as usize;
    buf.truncate((end - start) as usize);
    part.tail = buf.split_off(keep_from);
    part.pos = end;
    part.pending_at = end;
    part.pending.clear();
    let n = part.pending_records;
    part.pending_records = 0;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::MemDisk;
    use alloc::format;
    use alloc::string::String;

    const DAY_MS: u64 = 86_400_000;

    fn disk(m: &MemDisk) -> Disk {
        Disk::open(m.device(), || [1; 16]).unwrap().0
    }

    fn all(log: &TelemetryLog, d: &mut Disk, p: usize) -> Vec<(u64, String, Vec<u8>)> {
        within(log, d, p, u64::MAX)
    }

    fn within(
        log: &TelemetryLog,
        d: &mut Disk,
        p: usize,
        retention_ms: u64,
    ) -> Vec<(u64, String, Vec<u8>)> {
        let mut v = Vec::new();
        log.scan(d, p, retention_ms, |r| {
            v.push((r.ts_ms, r.topic.into(), r.payload.to_vec()))
        })
        .unwrap();
        v
    }

    #[test]
    fn append_flush_reopen() {
        let m = MemDisk::new(32 << 20);
        let mut d = disk(&m);
        let now = 1_761_696_000;
        let (mut log, rec) = TelemetryLog::open(&mut d, now, 30 * DAY_MS).unwrap();
        assert_eq!(rec, Recovery::default());
        for i in 0..1000u64 {
            let p = (i % 3) as usize;
            log.append(
                &mut d,
                p,
                now * 1000 + i,
                &format!("devices/d{p}/telemetry/t"),
                &i.to_le_bytes(),
            )
            .unwrap();
            if i % 97 == 0 {
                assert!(log.flush(&mut d).unwrap() > 0);
            }
        }
        log.flush(&mut d).unwrap();
        assert_eq!(log.durable_records, 1000);
        drop(d);
        m.crash(|_| false);
        let mut d = disk(&m);
        let (log, rec) = TelemetryLog::open(&mut d, now, 30 * DAY_MS).unwrap();
        assert_eq!(rec.records, 1000);
        assert_eq!(rec.torn_tails, 0);
        let p1 = all(&log, &mut d, 1);
        assert_eq!(p1.len(), 333);
        assert_eq!(
            p1[0],
            (
                now * 1000 + 1,
                "devices/d1/telemetry/t".into(),
                1u64.to_le_bytes().to_vec()
            )
        );
        assert!(p1.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn unflushed_and_torn_records_are_dropped_flushed_ones_kept() {
        let m = MemDisk::new(32 << 20);
        let mut d = disk(&m);
        let (mut log, _) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        for i in 0..100u64 {
            log.append(&mut d, 0, i, "t", &[7u8; 50]).unwrap();
        }
        log.flush(&mut d).unwrap();
        for i in 100..200u64 {
            log.append(&mut d, 0, i, "t", &[7u8; 50]).unwrap();
        }
        log.flush(&mut d).unwrap();
        // A third batch reaches the disk only partially: a torn write that
        // corrupts the middle of a record.
        for i in 200..300u64 {
            log.append(&mut d, 0, i, "t", &[7u8; 50]).unwrap();
        }
        let geo = log.geo;
        let pos = log.parts[0].pending_at;
        drop(log);
        let base = geo.segment_offset(0, 0);
        let mut junk = vec![0u8; 700];
        for (i, b) in junk.iter_mut().enumerate() {
            *b = (i * 13 + 1) as u8;
        }
        d.write_at(RegionKind::Telemetry, base + pos, &junk)
            .unwrap();
        d.sync().unwrap();
        let (log, rec) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        assert_eq!(rec.records, 200);
        assert_eq!(rec.torn_tails, 1);
        // Appending after recovery continues in a new segment; the torn
        // segment keeps its valid prefix.
        let mut log = log;
        log.append(&mut d, 0, 999, "t", b"after").unwrap();
        log.flush(&mut d).unwrap();
        let (log, rec) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        assert_eq!(rec.records, 201);
        assert_eq!(rec.torn_tails, 0);
        assert_eq!(all(&log, &mut d, 0).last().unwrap().2, b"after");
    }

    #[test]
    fn ring_wraps_and_old_generation_records_never_reappear() {
        let m = MemDisk::new(16 << 20);
        let mut d = disk(&m);
        let (mut log, _) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        let cap = log.capacity_bytes();
        let payload = [3u8; 200];
        let per = record_size("w", &payload) as u64;
        let total = cap / per * 3;
        for i in 0..total {
            log.append(&mut d, 0, i, "w", &payload).unwrap();
            if i % 50 == 0 {
                log.flush(&mut d).unwrap();
            }
        }
        log.flush(&mut d).unwrap();
        let (log, rec) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        let got = all(&log, &mut d, 0);
        assert_eq!(got.len() as u64, rec.records);
        // Only the newest records survive, contiguous and in order.
        assert!(got.len() as u64 > cap / per / 2);
        assert_eq!(got.last().unwrap().0, total - 1);
        assert!(got.windows(2).all(|w| w[1].0 == w[0].0 + 1));
    }

    #[test]
    fn retention_by_age_and_power_loss_mid_flush() {
        let m = MemDisk::new(32 << 20);
        let mut d = disk(&m);
        let now = 100 * 86_400;
        let (mut log, _) = TelemetryLog::open(&mut d, now, DAY_MS).unwrap();
        log.append(&mut d, 2, (now - 3 * 86_400) * 1000, "old", b"x")
            .unwrap();
        log.append(&mut d, 2, now * 1000, "new", b"y").unwrap();
        log.flush(&mut d).unwrap();
        for i in 0..500u64 {
            log.append(&mut d, 2, now * 1000 + i, "z", &[1u8; 90])
                .unwrap();
        }
        // Power fails during the flush: some writes reach the volatile
        // cache, the rest fail, there is no device flush, and any subset of
        // the cached writes may survive.
        m.fail_after(4);
        assert!(log.flush(&mut d).is_err());
        drop(d);
        m.crash(|i| i % 3 != 1);
        let mut d = disk(&m);
        let (log, rec) = TelemetryLog::open(&mut d, now, DAY_MS).unwrap();
        assert_eq!(rec.expired, 1);
        assert!(rec.records >= 2);
        let live = within(&log, &mut d, 2, DAY_MS);
        assert!(live.iter().all(|r| r.1 != "old"));
        // Whatever survived is a contiguous prefix.
        let zs: Vec<u64> = live
            .iter()
            .filter(|r| r.1 == "z")
            .map(|r| r.0 - now * 1000)
            .collect();
        assert!(zs.iter().enumerate().all(|(i, &v)| v == i as u64));
    }

    #[test]
    fn foreign_region_data_is_refused() {
        let m = MemDisk::new(16 << 20);
        let mut d = disk(&m);
        d.write_at(RegionKind::Telemetry, 0, b"not a log").unwrap();
        assert_eq!(
            TelemetryLog::open(&mut d, 0, 0).err(),
            Some(LogError::UnknownData)
        );
    }
}

#[cfg(test)]
mod resurrection {
    use super::*;
    use crate::disk::MemDisk;

    /// A batch whose middle sectors were lost while a later sector
    /// survived must never come back after new appends.
    #[test]
    fn lost_middle_of_a_batch_is_never_resurrected() {
        let m = MemDisk::new(32 << 20);
        let mut d = Disk::open(m.device(), || [1; 16]).unwrap().0;
        let (mut log, _) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        for i in 0..10u64 {
            log.append(&mut d, 0, i, "a", &[1u8; 40]).unwrap();
        }
        log.flush(&mut d).unwrap();
        // 300 records, written in several 8 KiB device writes; the second
        // is lost, the others survive.
        for i in 10..310u64 {
            log.append(&mut d, 0, i, "a", &[1u8; 40]).unwrap();
        }
        m.fail_after(1_000);
        let _ = log.write_all_without_sync(&mut d);
        drop(log);
        drop(d);
        m.crash(|i| i != 1);
        let mut d = Disk::open(m.device(), || [1; 16]).unwrap().0;
        let (mut log, rec) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        let first = rec.records;
        assert!(first >= 10);
        for i in 1000..1003u64 {
            log.append(&mut d, 0, i, "a", &[2u8; 40]).unwrap();
        }
        log.flush(&mut d).unwrap();
        let (log, _) = TelemetryLog::open(&mut d, 0, u64::MAX).unwrap();
        let mut ts = Vec::new();
        log.scan(&mut d, 0, u64::MAX, |r| ts.push(r.ts_ms)).unwrap();
        // A contiguous prefix of the old batch, then exactly the new records.
        let old: Vec<u64> = ts.iter().copied().filter(|&t| t < 1000).collect();
        assert!(old.iter().enumerate().all(|(i, &t)| t == i as u64));
        assert_eq!(ts.iter().filter(|&&t| t >= 1000).count(), 3);
        assert_eq!(&ts[ts.len() - 3..], &[1000, 1001, 1002]);
    }
}
