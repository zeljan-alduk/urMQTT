//! Scrubbing (STORAGE-PLAN S6, ADR-164, ADR-165): when the broker has
//! nothing better to do, the DB core re-reads what is on the disk and checks
//! it, so that rot is found while a good copy may still exist, not when the
//! data is needed.
//!
//! One pass visits, in this order:
//! 1. **the database**, one table (with its indexes) at a time with `PRAGMA
//!    quick_check(table)` (after `shrink_memory`, so the pages come from the
//!    disk and not from SQLite's cache);
//! 2. **the backup region**: the control block, both slot headers, and the
//!    payload CRC of every valid snapshot;
//! 3. **the telemetry ring**: every segment with a valid header, read and
//!    its records checked against their CRCs.
//!
//! A [`Scrubber`] does a bounded amount of reading per [`step`](Scrubber::step)
//! (the telemetry and backup parts exactly, the database part one object at a
//! time), and a [`Pacer`] decides how many bytes the next step may read so
//! that the average stays under `storage.scrub_io_budget_mb_s`. The caller
//! (the DB core) runs steps only between transactions and mostly when
//! nothing waits for it.
//!
//! What it can and cannot find: telemetry records and backup payloads carry
//! CRCs, so any flipped bit in them is found. SQLite pages carry none (the
//! build has no checksum VFS), so `quick_check` finds structural damage (a
//! broken tree, a bad page header, a bad cell pointer) and not a flipped bit
//! inside a row's value. The boot-time check and the backup are the same.

use alloc::string::String;
use alloc::vec::Vec;

use crate::backup::{self, SlotState, Verifier};
use crate::db::Db;
use crate::telemetry::{SegmentEnd, TelemetryEvent, TelemetryLog, TelemetryScrub};
use crate::vfs;

/// Most bytes a step may be granted at once.
pub const MAX_STEP_BYTES: usize = 256 * 1024;
/// Least worth running a step for.
pub const MIN_STEP_BYTES: usize = 64 * 1024;

/// Something a pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A record fails its checks with valid records after it in the same
    /// segment: damage, not a torn write.
    TelemetryDamaged {
        partition: usize,
        index: u64,
        seq: u64,
        at: u32,
        resumes_at: u32,
    },
    /// A record fails its checks and nothing valid follows: a torn write
    /// from a crash, or damage to the last record.
    TelemetryBadTail {
        partition: usize,
        index: u64,
        seq: u64,
        at: u32,
    },
    /// A segment header with the magic but a failing check: the segment is
    /// invisible to recovery.
    TelemetryBadHeader { partition: usize, index: u64 },
    /// SQLite's `quick_check` of one table or index reported a problem.
    Database { object: String, message: String },
    /// A backup slot: its header is damaged, or its payload fails the CRC in
    /// the header.
    BackupSlot {
        slot: usize,
        seq: u64,
        why: &'static str,
    },
    /// The backup control block has its magic and fails its checks.
    BackupControl,
    /// A read failed.
    ReadError { what: &'static str },
}

impl Finding {
    /// Whether the broker's data is at risk (true) or only a note (false:
    /// a torn tail is what a crash leaves).
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::TelemetryBadTail { .. })
    }
}

/// Counters of one pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    /// Bytes read from the disk by the pass (SQLite's included).
    pub bytes_read: u64,
    pub telemetry_segments: u64,
    pub telemetry_records: u64,
    pub telemetry_damaged: u64,
    pub telemetry_bad_tails: u64,
    pub telemetry_bad_headers: u64,
    /// Segments reused or retired while being read (nothing concluded).
    pub telemetry_recycled: u64,
    pub db_objects: u64,
    pub db_errors: u64,
    pub backup_slots_ok: u64,
    pub backup_slots_bad: u64,
    pub read_errors: u64,
}

impl Report {
    /// Findings that mean data is at risk (bad tails are not counted).
    pub fn errors(&self) -> u64 {
        self.telemetry_damaged
            + self.telemetry_bad_headers
            + self.db_errors
            + self.backup_slots_bad
            + self.read_errors
    }
}

#[derive(Debug, Clone)]
enum Phase {
    Database {
        objects: Option<Vec<String>>,
        next: usize,
    },
    Backup {
        slot: usize,
        verify: Option<(Verifier, backup::SlotHeader)>,
        control_done: bool,
    },
    Telemetry,
    Done,
}

/// One pass over the database, the backup region and the telemetry ring.
#[derive(Debug, Clone)]
pub struct Scrubber {
    phase: Phase,
    tel: TelemetryScrub,
    pub report: Report,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new()
    }
}

/// What one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepOutcome {
    /// The pass is over.
    pub done: bool,
    /// Bytes the step read from the disk (to charge to the [`Pacer`]).
    pub bytes: u64,
}

impl Scrubber {
    pub fn new() -> Self {
        Self {
            phase: Phase::Database {
                objects: None,
                next: 0,
            },
            tel: TelemetryScrub::default(),
            report: Report::default(),
        }
    }

    /// Starts the backup part over (a backup began and may rewrite the slot
    /// being read): call it when a backup job starts.
    pub fn restart_backup_part(&mut self) {
        if let Phase::Backup {
            slot,
            verify,
            control_done,
        } = &mut self.phase
        {
            *slot = 0;
            *verify = None;
            *control_done = false;
        }
    }

    /// Does one bounded piece of work, reading about `max_bytes` (a
    /// database object is checked whole, so that step may read more), and
    /// appends what it found to `findings`.
    pub fn step(
        &mut self,
        db: &Db,
        log: Option<&mut TelemetryLog>,
        max_bytes: usize,
        findings: &mut Vec<Finding>,
    ) -> StepOutcome {
        let before = vfs::disk_stats().bytes_read;
        match &mut self.phase {
            Phase::Database { objects, next } => {
                Self::database_step(db, objects, next, &mut self.report, findings);
                let finished = objects.as_ref().is_some_and(|o| *next >= o.len());
                if finished {
                    self.phase = Phase::Backup {
                        slot: 0,
                        verify: None,
                        control_done: false,
                    };
                }
            }
            Phase::Backup { .. } => {
                if self.backup_step(max_bytes, findings) {
                    self.phase = Phase::Telemetry;
                }
            }
            Phase::Telemetry => {
                let Some(log) = log else {
                    self.phase = Phase::Done;
                    return self.finish(before);
                };
                let mut events = Vec::new();
                let r =
                    vfs::with_disk(|d| log.scrub_step(d, &mut self.tel, max_bytes, &mut events));
                self.telemetry_events(&events, findings);
                match r {
                    Some(Ok(true)) => self.phase = Phase::Done,
                    Some(Ok(false)) => {}
                    _ => {
                        self.report.read_errors += 1;
                        findings.push(Finding::ReadError {
                            what: "telemetry segment",
                        });
                        self.phase = Phase::Done;
                    }
                }
            }
            Phase::Done => {}
        }
        self.finish(before)
    }

    fn finish(&mut self, before: u64) -> StepOutcome {
        let bytes = vfs::disk_stats().bytes_read.saturating_sub(before);
        self.report.bytes_read += bytes;
        StepOutcome {
            done: matches!(self.phase, Phase::Done),
            bytes,
        }
    }

    /// One table or index per call: `quick_check(object)` with the page
    /// cache released first, so the disk is what is checked.
    fn database_step(
        db: &Db,
        objects: &mut Option<Vec<String>>,
        next: &mut usize,
        report: &mut Report,
        findings: &mut Vec<Finding>,
    ) {
        let Some(list) = objects else {
            let mut names = Vec::new();
            if let Ok(mut s) =
                db.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            {
                while matches!(s.step(), Ok(crate::db::Step::Row)) {
                    names.push(String::from(s.text(0)));
                }
            }
            *objects = Some(names);
            return;
        };
        let Some(name) = list.get(*next) else {
            return;
        };
        *next += 1;
        report.db_objects += 1;
        // Only names a schema of ours can have are put into SQL.
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            report.db_errors += 1;
            findings.push(Finding::Database {
                object: name.clone(),
                message: "unexpected name in the schema".into(),
            });
            return;
        }
        let _ = db.exec("PRAGMA shrink_memory");
        match db.query_text(&alloc::format!("PRAGMA quick_check({name})")) {
            Ok(r) if r == "ok" => {}
            Ok(r) => {
                report.db_errors += 1;
                findings.push(Finding::Database {
                    object: name.clone(),
                    message: r,
                });
            }
            Err(e) => {
                report.db_errors += 1;
                findings.push(Finding::Database {
                    object: name.clone(),
                    message: alloc::format!("{e}"),
                });
            }
        }
    }

    /// The backup region: control block, then each slot. Returns true when
    /// this part is over.
    fn backup_step(&mut self, max_bytes: usize, findings: &mut Vec<Finding>) -> bool {
        let Phase::Backup {
            slot,
            verify,
            control_done,
        } = &mut self.phase
        else {
            return true;
        };
        let report = &mut self.report;
        let r = vfs::with_disk(|d| -> Result<bool, backup::BackupError> {
            if d.layout().backup().is_none() {
                return Ok(true);
            }
            if !*control_done {
                *control_done = true;
                if backup::control_damaged(d)? {
                    report.backup_slots_bad += 1;
                    findings.push(Finding::BackupControl);
                }
                return Ok(false);
            }
            if let Some((v, h)) = verify {
                if let Some(crc) = v.step(d, max_bytes)? {
                    let (s, hdr) = (*slot, *h);
                    *verify = None;
                    *slot += 1;
                    // The slot may have been rewritten since the header was
                    // read; only a snapshot that is still the same counts.
                    let same = matches!(backup::slot_state(d, s)?, SlotState::Valid(n) if n == hdr);
                    if !same {
                        // A backup rewrote it: not a finding.
                    } else if crc == hdr.payload_crc {
                        report.backup_slots_ok += 1;
                    } else {
                        report.backup_slots_bad += 1;
                        findings.push(Finding::BackupSlot {
                            slot: s,
                            seq: hdr.seq,
                            why: "the payload does not match the CRC in its header",
                        });
                    }
                }
                return Ok(false);
            }
            if *slot >= 2 {
                return Ok(true);
            }
            match backup::slot_state(d, *slot)? {
                SlotState::Valid(h) => {
                    *verify = Some((Verifier::new(*slot, h.payload_bytes), h));
                }
                SlotState::Damaged => {
                    report.backup_slots_bad += 1;
                    findings.push(Finding::BackupSlot {
                        slot: *slot,
                        seq: 0,
                        why: "the header has its magic and fails its checks",
                    });
                    *slot += 1;
                }
                SlotState::Empty => *slot += 1,
            }
            Ok(false)
        });
        match r {
            Some(Ok(done)) => done,
            _ => {
                self.report.read_errors += 1;
                findings.push(Finding::ReadError {
                    what: "backup region",
                });
                true
            }
        }
    }

    fn telemetry_events(&mut self, events: &[TelemetryEvent], findings: &mut Vec<Finding>) {
        for e in events {
            match *e {
                TelemetryEvent::Segment {
                    partition,
                    index,
                    seq,
                    records,
                    end,
                    ..
                } => {
                    self.report.telemetry_segments += 1;
                    self.report.telemetry_records += records;
                    match end {
                        SegmentEnd::Clean => {}
                        SegmentEnd::BadTail { at } => {
                            self.report.telemetry_bad_tails += 1;
                            findings.push(Finding::TelemetryBadTail {
                                partition,
                                index,
                                seq,
                                at,
                            });
                        }
                        SegmentEnd::Damaged { at, resumes_at } => {
                            self.report.telemetry_damaged += 1;
                            findings.push(Finding::TelemetryDamaged {
                                partition,
                                index,
                                seq,
                                at,
                                resumes_at,
                            });
                        }
                    }
                }
                TelemetryEvent::BadHeader { partition, index } => {
                    self.report.telemetry_bad_headers += 1;
                    findings.push(Finding::TelemetryBadHeader { partition, index });
                }
                TelemetryEvent::Recycled { .. } => self.report.telemetry_recycled += 1,
            }
        }
    }
}

/// A token bucket for the scrub's reads: `grant` says how many bytes the
/// next step may read, `spend` charges what it did read. The bucket fills at
/// the budget's rate, holds at most one step's worth, and may go into debt
/// (a database object is checked whole), after which the pacer waits until
/// the debt is repaid. Over any period the bytes spent are therefore at
/// most the budget times the period plus one step.
#[derive(Debug, Clone, Copy)]
pub struct Pacer {
    bytes_per_s: u64,
    /// Bytes available; negative: in debt.
    tokens: i64,
    last_ms: u64,
}

impl Pacer {
    /// `mb_per_s` megabytes (of 2^20 bytes) per second, at least 1.
    pub fn new(mb_per_s: u32, now_ms: u64) -> Self {
        Self {
            bytes_per_s: u64::from(mb_per_s.max(1)) << 20,
            tokens: 0,
            last_ms: now_ms,
        }
    }

    pub fn rate(&self) -> u64 {
        self.bytes_per_s
    }

    /// Bytes the next step may read: 0 until [`MIN_STEP_BYTES`] are
    /// available, at most [`MAX_STEP_BYTES`].
    pub fn grant(&mut self, now_ms: u64) -> usize {
        let dt = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms.max(self.last_ms);
        let add =
            (u128::from(self.bytes_per_s) * u128::from(dt) / 1000).min(i64::MAX as u128) as i64;
        self.tokens = self.tokens.saturating_add(add).min(MAX_STEP_BYTES as i64);
        if self.tokens >= MIN_STEP_BYTES as i64 {
            self.tokens as usize
        } else {
            0
        }
    }

    /// Charges bytes read.
    pub fn spend(&mut self, bytes: u64) {
        self.tokens = self
            .tokens
            .saturating_sub(i64::try_from(bytes).unwrap_or(i64::MAX));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pacer_never_runs_ahead_of_its_rate() {
        for mb in [1u32, 4, 8, 64] {
            let mut p = Pacer::new(mb, 0);
            let mut spent = 0u64;
            for ms in 0..20_000u64 {
                let g = p.grant(ms);
                if g > 0 {
                    // A step reads a little more than it was granted, as a
                    // database object may.
                    let used = g as u64 + 5000;
                    p.spend(used);
                    spent += used;
                }
                let allowed =
                    (u64::from(mb) << 20) * (ms + 1) / 1000 + MAX_STEP_BYTES as u64 + 5000;
                assert!(
                    spent <= allowed,
                    "{mb} MB/s at {ms} ms: {spent} > {allowed}"
                );
            }
            // And it uses the budget: within 10 % over 20 s.
            let full = (u64::from(mb) << 20) * 20;
            assert!(spent * 10 >= full * 9, "{mb} MB/s: only {spent} of {full}");
        }
    }

    #[test]
    fn debt_is_repaid_before_the_next_step() {
        let mut p = Pacer::new(1, 0);
        assert_eq!(p.grant(1000), MAX_STEP_BYTES.min(1 << 20));
        // One whole object, 3 MiB, charged at once.
        p.spend(3 << 20);
        assert_eq!(p.grant(1100), 0);
        assert_eq!(p.grant(2000), 0);
        // 3 MiB less the 256 KiB held takes about 2.75 s at 1 MiB/s to repay,
        // plus the minimum step.
        assert_eq!(p.grant(3000), 0);
        assert!(p.grant(5000) >= MIN_STEP_BYTES);
    }
}
