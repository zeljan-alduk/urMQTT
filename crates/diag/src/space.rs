//! Unallocated space of a disk: what is covered by no partition and by no
//! region of the data layout. The diagnostic's write test may touch only
//! sectors computed here, and never the first or the last mebibyte (the
//! boot sectors and the partition table at the front, the backup GPT at the
//! end). Sectors are 512 bytes; extents are half-open `[start, end)`.

use alloc::vec::Vec;

/// Alignment of a usable extent: 1 MiB.
pub const ALIGN_SECTORS: u64 = 2048;
/// The front of every disk is never written: MBR, GPT, boot loaders.
pub const HEAD_GUARD: u64 = 2048;
/// The end of every disk is never written: the backup GPT lives there.
pub const TAIL_GUARD: u64 = 2048;

/// A half-open range of sectors `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub end: u64,
}

impl Extent {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// From a first sector and a length.
    pub const fn span(start: u64, sectors: u64) -> Self {
        Self {
            start,
            end: start.saturating_add(sectors),
        }
    }

    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    pub const fn overlaps(&self, o: &Self) -> bool {
        !self.is_empty() && !o.is_empty() && self.start < o.end && o.start < self.end
    }

    /// Whether `self` lies entirely inside `o`.
    pub const fn within(&self, o: &Self) -> bool {
        !self.is_empty() && o.start <= self.start && self.end <= o.end
    }
}

/// What the superblock of the data partition says (STORAGE-PLAN, the
/// layout in `urmqtt_store::layout`): region offsets are relative to the
/// start of the partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLayout {
    /// The partition, in sectors of the whole disk.
    pub partition: Extent,
    /// Sectors at the start of the partition holding the superblock and
    /// the size tables.
    pub header_sectors: u64,
    /// `(start, sectors)` of every region, relative to the partition.
    pub regions: Vec<(u64, u64)>,
}

/// Everything on a disk that is taken: the partitions, with the data
/// partition replaced by its header and regions when its layout is known
/// (`data`). A data partition whose superblock cannot be read has no
/// layout: it stays in `partitions` and is taken whole.
pub fn taken(partitions: &[Extent], data: Option<&DataLayout>) -> Vec<Extent> {
    let mut out: Vec<Extent> = Vec::new();
    for p in partitions {
        if data.is_some_and(|d| *p == d.partition) {
            continue;
        }
        out.push(*p);
    }
    if let Some(d) = data {
        out.push(Extent::span(d.partition.start, d.header_sectors));
        for &(rel, sectors) in &d.regions {
            out.push(Extent::span(d.partition.start.saturating_add(rel), sectors));
        }
    }
    out
}

/// The free extents of a disk of `total` sectors: everything not in
/// `taken`, minus the head and tail guards, sorted, merged and trimmed
/// inward to [`ALIGN_SECTORS`]. Extents shorter than one alignment unit
/// vanish.
pub fn free_extents(total: u64, taken: &[Extent]) -> Vec<Extent> {
    let mut busy: Vec<Extent> = taken.iter().copied().filter(|e| !e.is_empty()).collect();
    busy.push(Extent::new(0, HEAD_GUARD.min(total)));
    busy.push(Extent::new(total.saturating_sub(TAIL_GUARD), total));
    busy.sort_unstable_by_key(|e| e.start);
    let mut free: Vec<Extent> = Vec::new();
    let mut at = 0u64;
    for b in &busy {
        if b.start > at {
            free.push(Extent::new(at, b.start.min(total)));
        }
        at = at.max(b.end);
    }
    if at < total {
        free.push(Extent::new(at, total));
    }
    free.into_iter()
        .map(|e| {
            Extent::new(
                e.start.div_ceil(ALIGN_SECTORS) * ALIGN_SECTORS,
                e.end / ALIGN_SECTORS * ALIGN_SECTORS,
            )
        })
        .filter(|e| !e.is_empty())
        .collect()
}

/// The longest extent (the first of equals).
pub fn largest(free: &[Extent]) -> Option<Extent> {
    let mut best: Option<Extent> = None;
    for e in free {
        if best.is_none_or(|b| e.len() > b.len()) {
            best = Some(*e);
        }
    }
    best
}

/// Whether `window` lies inside one of the free extents (the check made
/// again before every write).
pub fn window_is_free(window: Extent, free: &[Extent]) -> bool {
    free.iter().any(|f| window.within(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 2048;

    fn layout(part: Extent, regions: &[(u64, u64)]) -> DataLayout {
        DataLayout {
            partition: part,
            header_sectors: 64,
            regions: regions.to_vec(),
        }
    }

    #[test]
    fn a_blank_disk_is_free_between_the_guards() {
        let f = free_extents(100 * MIB, &[]);
        assert_eq!(f, [Extent::new(MIB, 99 * MIB)]);
    }

    #[test]
    fn guards_hold_on_tiny_and_odd_disks() {
        assert!(free_extents(0, &[]).is_empty());
        assert!(free_extents(10, &[]).is_empty());
        assert!(free_extents(2 * MIB, &[]).is_empty());
        assert!(free_extents(2 * MIB + 5, &[]).is_empty());
        // 3 MiB + 7 sectors: [1 MiB, 2 MiB + 7) trimmed to [1 MiB, 2 MiB).
        assert_eq!(free_extents(3 * MIB + 7, &[]), [Extent::new(MIB, 2 * MIB)]);
    }

    #[test]
    fn partitions_are_not_free() {
        // ESP at 1 MiB..65 MiB, the rest of a 1 GiB disk is unallocated.
        let esp = Extent::new(MIB, 65 * MIB);
        let f = free_extents(1024 * MIB, &[esp]);
        assert_eq!(f, [Extent::new(65 * MIB, 1023 * MIB)]);
        assert!(!f.iter().any(|e| e.overlaps(&esp)));
    }

    #[test]
    fn an_installed_disk_has_no_space_the_layout_does_not_own() {
        // The installer's layout: ESP, then a data partition to the end
        // whose regions are contiguous (see store::layout::Layout::plan).
        let total = 1024 * MIB;
        let esp = Extent::new(MIB, 65 * MIB);
        let part = Extent::new(65 * MIB, total - 33);
        let plen = part.len();
        // header 64, db, wal, journal, telemetry, scratch at the end.
        let scratch = plen - 8;
        let usable = (scratch - 64) / 8 * 8;
        let db = usable / 2 / 8 * 8;
        let wal = 2 * MIB;
        let journal = MIB;
        let tele = usable - db - wal - journal;
        let regions = [
            (64, db),
            (64 + db, wal),
            (64 + db + wal, journal),
            (64 + db + wal + journal, tele),
            (scratch, 8),
        ];
        let d = layout(part, &regions);
        let t = taken(&[esp, part], Some(&d));
        let f = free_extents(total, &t);
        assert!(f.is_empty(), "nothing free on a fully used disk: {f:?}");
    }

    #[test]
    fn a_gap_between_regions_is_free_but_only_when_big_enough() {
        let total = 1024 * MIB;
        let part = Extent::new(MIB, total - 33);
        // Header, a 10 MiB region, an 8 MiB gap, another 10 MiB region.
        let d = layout(part, &[(64, 10 * MIB), (64 + 10 * MIB + 8 * MIB, 10 * MIB)]);
        let t = taken(&[part], Some(&d));
        let f = free_extents(total, &t);
        // The gap [MIB+64+10 MiB, ... +8 MiB) trims inward to whole MiB.
        let gap_start = MIB + 64 + 10 * MIB;
        let gap_end = gap_start + 8 * MIB;
        assert!(f.iter().any(|e| e.start >= gap_start && e.end <= gap_end));
        for e in &f {
            for r in &d.regions {
                assert!(!e.overlaps(&Extent::span(part.start + r.0, r.1)));
            }
            assert!(!e.overlaps(&Extent::span(part.start, 64)));
        }
        // And what lies after the last region (inside the partition) too.
        assert!(f.iter().any(|e| e.end > part.start + 64 + 28 * MIB));
    }

    #[test]
    fn an_unreadable_superblock_takes_the_whole_partition() {
        let total = 512 * MIB;
        let part = Extent::new(65 * MIB, total - 33);
        let t = taken(&[Extent::new(MIB, 65 * MIB), part], None);
        let f = free_extents(total, &t);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn extents_never_overlap_anything_taken() {
        // A deterministic sweep over layouts of three partitions.
        let total = 4096 * MIB;
        let mut s = 0x1234_5678_9abc_def0u64;
        for _ in 0..500 {
            let mut parts = Vec::new();
            let mut at = MIB;
            for _ in 0..3 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let gap = s % (200 * MIB);
                let len = 1 + (s >> 20) % (300 * MIB);
                let start = at + gap;
                let e = Extent::span(start, len);
                if e.end >= total {
                    break;
                }
                parts.push(e);
                at = e.end;
            }
            let f = free_extents(total, &parts);
            for e in &f {
                assert_eq!(e.start % ALIGN_SECTORS, 0);
                assert_eq!(e.end % ALIGN_SECTORS, 0);
                assert!(e.start >= HEAD_GUARD && e.end <= total - TAIL_GUARD);
                for p in &parts {
                    assert!(!e.overlaps(p), "{e:?} overlaps {p:?}");
                }
            }
            for w in f.windows(2) {
                assert!(w[0].end <= w[1].start, "sorted and disjoint");
            }
        }
    }

    #[test]
    fn largest_and_window_checks() {
        let f = [
            Extent::new(10, 20),
            Extent::new(100, 300),
            Extent::new(400, 500),
        ];
        assert_eq!(largest(&f), Some(Extent::new(100, 300)));
        assert_eq!(largest(&[]), None);
        assert!(window_is_free(Extent::new(100, 150), &f));
        assert!(window_is_free(Extent::new(100, 300), &f));
        assert!(
            !window_is_free(Extent::new(250, 350), &f),
            "crosses the end"
        );
        assert!(!window_is_free(Extent::new(0, 5), &f));
        assert!(!window_is_free(Extent::new(5, 5), &f), "empty");
        assert!(!window_is_free(Extent::new(290, 410), &f), "spans two");
    }
}
