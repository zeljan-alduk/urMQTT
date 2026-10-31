# Data disk format, layout version 2 (minor 1)

The byte-level specification of the urMQTT data disk (STORAGE-PLAN S0, S2, S3, S5).
Since S1 the "data disk" is the **data partition of the boot disk** (§0);
everything below §0 is relative to that partition's first sector. Layout v2
(S2) adds alignment, the partition count and an A/B superblock; S3 adds the
grow (§9); S5 adds minor version 1 and the backup region (§12). Layout v1 (S0/S1) is described only as far as `urmqtt-disk migrate`
reads it (§10). The data has **no
filesystem**: the kernel accesses it raw, as a superblock, a region table and
fixed regions. The code is in `crates/store`
(`layout.rs`, `disk.rs`, `vfs.rs`, `telemetry.rs`); ADR-030 and ADR-031 give
the reasons.

The tables marked `<!-- struct: … -->` are machine-read by
`crates/store/tests/disk_format_spec.rs`. That test encodes every structure
with the real code, then checks two things:
- each listed field is at the listed offset with the listed encoding;
- every byte the encoder writes belongs to a listed field.

So a field in the code that is missing here fails the test, and so does a
field listed here that the code does not write.

## 0. The boot disk (S1)

urMQTT uses exactly one disk: the one it boots from (single-disk model,
STORAGE-PLAN §2a). It is a standard UEFI GPT disk (UEFI 2.10, §5.3) with 128
entries of 128 bytes, the entry arrays at LBA 2 and at `last - 32`, CRC-32
(IEEE) as UEFI defines it:

```
LBA 0            protective MBR (one 0xEE entry over the disk), 0x55AA
LBA 1            primary GPT header
LBA 2 .. 33      primary entry array
LBA 2048 ..      EFI system partition (Limine, kernel, limine.conf), whole MiBs
1 MiB aligned .. urMQTT data partition (§1 onward), a whole number of 4 KiB blocks
last-32 .. last-1 backup entry array
last             backup GPT header
```

| Partition | Type GUID | Name | Created by |
|---|---|---|---|
| EFI system partition | `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | `EFI system partition` | the image (`scripts/mkraw.py`, `gpt::raw_image`) |
| urMQTT data | `58D3F720-BDF5-4DB7-99EC-DE26C8B8850F` | `urMQTT data` | the first boot |

**The image** (`make raw`, the release `.img`) is the first three items and a
backup table right after the ESP. Its GUIDs are derived from the ESP's SHA-256
(`v4(SHA-256(label ‖ sha256(esp))[0..16])` for the labels `disk` and `esp`), so
the same ESP always gives the same bytes. The Rust writer `gpt::raw_image` is
byte-identical to `mkraw.py` (test `raw_image_equals_mkraw_py`, five ESP sizes).

**Identification.** The bootloader reports the boot volume's GPT disk GUID
(Limine's executable-file response). The kernel reads LBA 1..33 of every disk
it drives and uses the one whose valid primary header carries that GUID. Every
other disk is only read, never written. Booting from optical media (the ISO)
gives no data partition.

**First boot and growth** (`gpt::prepare`), checked again at every boot, each
step idempotent:
1. If the primary copy is invalid, it is restored from a valid backup at the
   last LBA.
2. If the backup is not at the last LBA (the image on a larger disk), the
   backup copy is written at the end and then the primary is rewritten with
   the new `backup_lba` and `last_usable`. The old backup header is then zeroed.
3. If there is no data partition:
   - the first 64 sectors (32 KiB) of the free space at the next 1 MiB
     boundary are zeroed, so the partition classifies as blank whatever the
     disk held before;
   - the entry is added with a fresh random partition GUID and a fresh random
     disk GUID;
   - the backup copy is written before the primary.
4. If there is a data partition, it is the last one on the disk and at least
   1 MiB of free space follows it (the cloud volume was enlarged): its entry
   is extended to the new last usable sector, a whole number of 4 KiB blocks.
   The backup copy is written before the primary, so a cut leaves the old
   partition size or the new one (and the next boot repeats the step).

Within one copy, the entry array is always written before its header, and
every copy ends with a flush. A power cut after any write therefore leaves
one of three states:
- a valid primary still without the partition, so the next boot redoes step 3
  with new GUIDs;
- a torn primary with a complete backup, so step 1 applies;
- the finished disk.

The host test `first_boot_survives_a_crash_at_every_write` checks every write,
cut cleanly or torn, with and without the volatile cache surviving. Smoke
`first-boot-crash` does the same in the kernel at four points.

**Classification of the data partition** (`Disk::open` on the partition):
- blank → formatted (§6);
- a valid v2 superblock → opened (and grown if the partition is larger, §9);
- a valid v1 superblock → **refused, nothing written** (§10), message `data disk is layout v1; this image needs v2: run urmqtt-disk migrate (docs/DEPLOY.md)`;
- anything else → **damaged**: refused and never written. Dev images then run
  memory-only (smoke `own-damaged-refused`); a backup restore is S5.

## 1. Conventions

- All integers are **little-endian**, fixed width, independent of the CPU architecture. A disk written on aarch64 is valid on x86_64.
- **Sector:** 512 bytes. Addresses on the device are in sectors (LBA). The device must have 512-byte logical blocks; 4Kn devices are not supported by the boot path (G3 below). The store layer itself writes whole physical blocks and is tested against a strict 4096/4096 device.
- **Block:** 4096 bytes (8 sectors). The superblock slots, the size-table slots and the telemetry header are one block each.
- **Physical block / I/O granularity:** the device's physical block size, within 512 B and 4 KiB (§2a). Every write the store sends to the device starts and ends on that boundary; the partial blocks at the edges of a smaller write are read first.
- **CRC:** CRC-32C (Castagnoli, reflected polynomial `0x82F63B78`, initial value and final XOR `0xFFFFFFFF`; `crc32c("123456789") = 0xE3069283`), stored as `u32`. Unless stated otherwise it covers bytes `0 .. size-4` of its structure and is stored in the last four bytes.
- **Unlisted bytes** inside a structure are written as zero and are covered by its CRC. Readers do not interpret them, except that a v2 superblock with a non-zero reserved field is refused; a future version may use them only together with a version bump.
- **Magics** are 8 ASCII bytes without a terminator.

## 2. Disk map

```
LBA 0          superblock slot A             1 block
LBA 8          size table slot A             1 block
LBA 16         size table slot B             1 block
LBA 24         superblock slot B             1 block
LBA 32 .. 63   reserved: the migration record (§10), zero on a fresh disk
LBA 64 .. align-1  unused (zero), the rest of the first alignment unit
LBA align ..   regions (from the region table), each starting on an alignment boundary
               and a multiple of 8 sectors long:
               SQLite main database (one or more extents), WAL, rollback journal,
               telemetry log (one or more extents)
last 8 sectors scratch (the boot block-device self-test writes here)
```

The **formatter** (`Layout::plan`, used only on a blank disk, §6) rounds the
disk size down to a multiple of 8 sectors, places the regions in the order
database, WAL, journal, telemetry, scratch, and sizes them as follows (all in
sectors; `A` = `align_sectors`):

| Region | Start | Size |
|---|---|---|
| `end` | | `floor_A(total - 8)` |
| `usable` | | `end - A` |
| database | `A` | `floor_A(usable / 2)` |
| WAL | after the database | `max(A, floor_A(clamp(usable / 8, 2 MiB, 64 MiB)))` |
| journal | after the WAL | `ceil_A(1 MiB)` |
| telemetry | after the journal | `usable - database - WAL - journal` (at least `A`) |
| scratch | `total - 8` | 8 sectors |

The smallest disk is 16 MiB (32 768 sectors).

### 2a. Alignment and topology (S2, ADR-140)

`A` is the least common multiple of 1 MiB, the device's physical block size
and its optimal I/O size, in sectors, a multiple of 2048 and at most 64 MiB;
an optimal I/O size that would push it past 64 MiB is ignored. The partition
starts on a 1 MiB boundary (§0), so a region start that is a multiple of `A`
is aligned on the disk as well. The topology comes from:

| Device | Source |
|---|---|
| virtio-blk | `VIRTIO_BLK_F_TOPOLOGY`: `physical_block_exp`, `alignment_offset`, `min_io_size`, `opt_io_size` (units of `blk_size`) |
| virtio-scsi | READ CAPACITY (16): logical blocks per physical block exponent and lowest aligned LBA; the Block Limits VPD page (B0h): optimal transfer length granularity and optimal transfer length |
| NVMe, ATA | deferred to X13 (namespace LBA format and NPWG/NOWS; IDENTIFY logical/physical sector size) |

A device that reports nothing is a plain 512-byte device and `A` is 1 MiB.
The superblock stores `A` (`align_sectors`); a disk keeps it for life, so a
disk moved to a device with other hints is not re-laid-out.

**Writes.** Telemetry flushes, and every other write through `Disk::write_at`,
cover whole physical blocks. The debug counter `misaligned_writes` counts the
device requests that start or end off a physical block on the real disk; it
stays 0 on the data partition and the kernel logs it (smoke checks it). The
unavoidable exceptions, which are not counted because they are not store
writes through a partition: the GPT and the MBR at the first boot and the
installer (512-byte sectors by definition of GPT), and the boot self-test
(one 4 KiB write at the last 8 sectors of the partition, which is 4 KiB
aligned). A **migrated** disk keeps its telemetry ring where it was (§10): its
segments are 4 KiB aligned, but not 1 MiB aligned.

## 3. Superblock (LBA 0 = slot A, LBA 24 = slot B)

<!-- struct: superblock size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTTDK` |
| 8 | 4 | u32 | version | layout version, `2` |
| 12 | 4 | u32 | region_count | number of region entries, at most 128 |
| 16 | 16 | bytes | uuid | random at format time; identifies the disk and its telemetry segments |
| 32 | 8 | u64 | total_sectors | formatted size in sectors, a multiple of 8; at most the device's current size |
| 40 | 8 | u64 | generation | 1 at format, plus 1 with every superblock write |
| 48 | 4 | u32 | partitions | telemetry partitions, 1 to 64 |
| 52 | 4 | u32 | align_sectors | alignment unit `A` in sectors: a multiple of 2048, at most 131072 |
| 56 | 4 | u32 | flags | bit 0: the telemetry ring is a v1 ring kept in place (§5.2); other bits must be 0 |
| 60 | 4 | u32 | minor | minor version: `0` (no backup region, every disk formatted before S5) or `1` (the layout may have a backup region, §12) |
| 64 | 24 | region[] | regions | `region_count` entries of §3.1, back to back (up to offset 3136) |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

The word at 60 was reserved-and-zero up to S4, and a reader of that age refuses a
non-zero value (`Inconsistent`). Setting it to 1 is therefore what keeps an
older kernel from opening a disk whose backup region it would not understand
(it would otherwise read it as a gap and might claim it); this build reads
minor 0 and 1 and refuses a larger one (`UnsupportedMinor`).

### 3.1 Region entry (24 bytes, at 64 + 24·i)

<!-- struct: region size=24 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 4 | u32 | kind | 1 database, 2 WAL, 3 journal, 4 telemetry, 5 scratch, 6 backup (minor 1 only) |
| 8 | 8 | u64 | start | first sector (LBA), a multiple of 8 and of `align_sectors` |
| 16 | 8 | u64 | sectors | length in sectors, a multiple of 8 |

Bytes 4..8 are zero.

The kinds 1 (database) and 4 (telemetry) may appear several times: each entry
is an **extent**, and the logical region is the extents back to back in table
order (§9). The other kinds appear once.

**Choosing the superblock** (`Layout::select`): both slots are decoded.
- Both all zero: the disk is **blank** (§6).
- One valid: that one. Both valid: the higher `generation`; slot A on a tie.
- A valid v2 slot beats a v1 superblock in the other slot (a finished migration, §10).
- None valid: the error names the first of: a valid v1 superblock (`OldVersion`, refused as in §0), a damaged v2 superblock (bad CRC, inconsistent), foreign data (`UnknownData`, never formatted over).

**Validity of one slot** (`Layout::decode`):
1. The 4096 bytes are all zero: the slot is **blank**.
2. Otherwise the magic must match, or the result is `UnknownData`: foreign data, never formatted over.
3. The CRC must match; `version` must be 2 (1 is `OldVersion`); `region_count` ≤ 128; every `kind` must be known; `flags` has only bit 0; `minor` is 0 or 1.
4. `total_sectors` ≤ the device size and a multiple of 8; `partitions` and `align_sectors` in range.
5. Regions are non-empty, a multiple of 8 sectors long, start at or after `align_sectors`, do not overlap and end within `total_sectors`. Every region except scratch starts on a multiple of `align_sectors`; the first telemetry extent is exempt when flag bit 0 is set.
6. Database, WAL and journal regions exist; WAL, journal, scratch and backup have one extent. Telemetry and scratch are optional for the reader.
7. A backup region needs `minor` 1 and room for a control block and two slots of at least a header and one page (§12).

## 4. Size table (LBA 8 = slot A, LBA 16 = slot B)

The logical sizes of the three SQLite "files", which the VFS maps onto the
database, WAL and journal regions. Two slots make updates atomic: a write goes
to the slot that does not hold the newest valid copy. The same in v1 and v2.

<!-- struct: size_table size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQSZT1` |
| 8 | 8 | u64 | seq | incremented by one with every update |
| 16 | 4 | u32 | file_count | `3` |
| 24 | 8 | u64 | size_db | logical size of the main database file, bytes |
| 32 | 8 | u64 | size_wal | logical size of the WAL file, bytes |
| 40 | 8 | u64 | size_journal | logical size of the rollback journal, bytes |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

**Rules:**
- A slot is valid if its magic, CRC and `file_count` are correct.
- The newest valid slot (the highest `seq`) wins; with equal `seq`, slot A wins.
- The next update, with `seq + 1`, goes to slot `(seq + 1) mod 2` (0 = A, 1 = B).
- A formatted disk with no valid slot is refused (`SizeTableLost`).

**Ordering** (`Disk::sync`): data writes, flush, size-table write, flush.
A size therefore never covers data that is not durable, and a torn size-table
write loses only the update in flight.

## 5. Regions

### 5.1 SQLite database, WAL, journal (kinds 1–3)

Each file is one flat byte range starting at the first byte of its region
(for the database: the first byte of its first extent, continuing in the next
extent). Its logical length is in the size table, and growth beyond the region
fails with `SQLITE_FULL`.

The file contents are SQLite's own formats (database file format, WAL
format), version 3.54.1, with:
- 4096-byte pages (`SQLITE_DEFAULT_PAGE_SIZE`);
- `journal_mode = WAL`, `locking_mode = EXCLUSIVE` (no shared-memory index);
- `synchronous = FULL`;
- a WAL auto-checkpoint at half the WAL region (32 to 1000 frames).

The VFS reports a 512-byte sector size and no device characteristics, so
SQLite assumes a torn sector can damage its neighbours. Truncation
(`xTruncate`) changes the logical size; the bytes beyond it are free (§11:
they may be released to the device, and what they hold is never read). A write
beyond the logical end, or a truncate to a larger size, first fills the gap
with zeros.

### 5.2 Telemetry log (kind 4)

```
region     [ log header 4 KiB ][ band 0 ] [ band 1 ] …        (all telemetry extents back to back)
band       [ partition 0 ] … [ partition P-1 ]                 one band per extent
partition  [ segment 0 ] … [ segment n-1 ]                     n segments of this band
segment    [ segment header 512 B ][ records … ][ zero padding ]
```

A partition is a ring over its segments in all bands: ring index `s` is in
band 0 for `s < n0`, in band 1 for `n0 <= s < n0 + n1`, and so on.

**Geometry,** chosen at format time (`Geometry::plan`) and stored in the log
header: with `P` the superblock's `partitions` and `E0` the first extent's
bytes,
- `part = (E0 - 4096) / P`;
- `segment_bytes = floor4K(clamp(part / 8, 64 KiB, 8 MiB))`;
- band 0 has `n0 = (E0 - 4096) / (P · segment_bytes)` segments per partition, at least 2.

Band `e` (extent `e`, `e > 0`) has `ne = bytes(e) / (P · segment_bytes)`
segments per partition; an extent too small for one is skipped. Segment `s` of
partition `p` in band `e` starts at the band's first byte plus
`(p · ne + j) · segment_bytes`, `j` the index inside the band; band 0 starts at
region offset 4096. Source core `c` writes partition `c mod P`.

No segment that exists ever changes position when the disk grows (§9): a new
extent only adds a band.

#### Log header (region offset 0)

<!-- struct: telemetry_header size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTLH1` |
| 8 | 4 | u32 | version | `2`; `1` only on a ring kept from layout v1 (flag bit 0) |
| 12 | 4 | u32 | partitions | equal to the superblock's `partitions` |
| 16 | 8 | u64 | segment_bytes | a multiple of 4096, 64 KiB to 8 MiB |
| 24 | 8 | u64 | segments | segments per partition in band 0, at least 2, equal to `n0` |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

An all-zero header means a blank log, formatted at open. Non-zero data without
the magic is `UnknownData`, never formatted over. A bad CRC or version, a
partition count other than the layout's, or a geometry that does not match the
first extent is `BadHeader`, and the disk is refused.

#### Segment header (first sector of a segment)

<!-- struct: segment_header size=512 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTSG1` |
| 8 | 4 | u32 | partition | the partition this segment belongs to |
| 16 | 8 | u64 | seq | per-partition segment sequence, starting at 1; 0 is invalid |
| 24 | 8 | u64 | created | Unix seconds when the segment was started |
| 32 | 16 | bytes | uuid | the superblock's `uuid`; all zero in a segment written by layout v1 |
| 508 | 4 | crc32c | crc | over bytes 0..508 |

A segment is valid if its magic, CRC and partition match, `seq` > 0 and the
`uuid` equals the layout's. A segment of an earlier incarnation of the disk,
or stale bytes in space a grow just claimed, therefore never counts. The one
exception: when the superblock's flag bit 0 is set (a ring kept from layout
v1), an all-zero `uuid` is also accepted in **band 0** only. New segments
always carry the `uuid`.

#### Record

Records follow the segment header back to back, from segment offset 512. A
record never spans segments.

<!-- struct: record size=variable -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 4 | u32 | len | bytes after the `crc` field: `10 + topic_len + payload length`; `0` marks the end |
| 4 | 4 | crc32c | crc | CRC-32C of the segment's `seq` (8 bytes, LE) followed by the `len` bytes from offset 8 |
| 8 | 8 | u64 | ts_ms | Unix milliseconds |
| 16 | 2 | u16 | topic_len | length of the topic in bytes |
| 18 | topic_len | utf8 | topic | the MQTT topic |
| 18+topic_len | len-10-topic_len | bytes | payload | the message payload |

**Writing:**
- Records are batched and written as whole physical blocks, zero-padded after the last record, followed by a flush. A new segment's header goes out in the same write as its first records.
- A new segment (the next ring index, `seq + 1`) starts:
  - when the next record does not fit;
  - for the first record of a partition, which goes to segment 0 with seq 1;
  - after recovery: a recovered segment is never extended.

**Recovery** (`TelemetryLog::open`). For each partition:
1. Read every segment header and order the valid segments by `seq`.
2. Scan each segment's records until `len == 0` (a clean end) or the first record that fails its CRC, its length bounds or UTF-8 (a torn tail; the rest of the segment is ignored).
3. The segment with the highest `seq` is the partition's active segment. New records go to a new segment, the next ring index after it.

**Why stale data never resurrects:** the CRC is salted with the segment's
`seq`. Records from an earlier pass of the ring therefore fail in a reused
segment. When a batch ends exactly on a block boundary, the next block may
still hold such stale bytes. They are read as a torn tail (counted, harmless),
never as records.

**Retention:** by size, as the ring overwrites the oldest segment. Age
(`storage.retention_days`) only hides expired records from reads. After a
grow, a ring whose active segment is not the last one keeps overwriting the
oldest segments next to it before it reaches the new bands (correct, and the
new space is used from the next wrap).

### 5.3 Scratch (kind 5)

Eight sectors that the boot block-device self-test overwrites with a random
pattern, then reads back. They hold no data. The self-test runs inside the
data partition, at its last 8 sectors, before the store opens; after a grow
the scratch area is at the new end of the layout, which is the same place.

## 6. Blank disks and formatting

`Disk::open` reads both superblock slots (`Layout::select`):

| Superblocks | Result |
|---|---|
| both all zero | **blank**: formatted (below) |
| a valid v2 superblock | opened |
| a valid v1 superblock only | refused (`OldVersion`), nothing is written |
| anything else | refused, nothing is written |

**Formatting:**
1. Plan the regions (§2) from the device's topology (§2a) and the partition count.
2. Write size-table slot A with `seq = 0`, all sizes 0, and write slot B as zeros; flush.
3. Write superblock slot A with `generation = 1`; flush.

A crash before step 3 leaves a disk whose superblocks are still zero, so it is
formatted again on the next boot. The telemetry header is written separately
when the log is first opened (§5.2).

Since S1 this layout starts at the first sector of the boot disk's data
partition (§0), and "blank" means the partition's first 4 KiB are zero (and
slot B's, which the first-boot head clearing also zeroes).

## 7. Invariants

- No region overlaps another or the header area (LBA 0 up to `align_sectors`).
- A size in the size table never exceeds its (summed) region, and never covers data written after the last flush.
- Every on-disk structure except SQLite's own files and record payloads has a CRC-32C, so a torn or stale structure is detected, never trusted.
- A disk is only ever formatted when both superblock slots are all zero.
- The format has no pointers into memory and no host-endian fields.
- **Superblock updates are single block writes to the slot not in force**, then a flush. A torn write leaves the slot invalid and the other slot in force.
- A layout update never moves existing data (grow), or switches only after the copy is verified (migrate).
- **Nothing reads the content of a range the store released** (§11): a byte beyond a file's logical size is never returned, a telemetry segment exists only by its header and record checksums, and the superblocks, size table and telemetry header are never inside a released range.

## 8. Known gaps (STORAGE-PLAN)

| Gap | Description | Fixed in |
|---|---|---|
| ~~G1~~ | ~~the data is on a separate disk chosen by "not partitioned"~~ | **fixed in S1**: the boot disk's data partition, found by GPT disk GUID (§0) |
| ~~G2~~ | ~~a damaged urMQTT disk must not be taken for a blank one~~ | **fixed in S1**: damaged partitions are refused and left unwritten (smoke `own-damaged-refused`) |
| ~~G3~~ | ~~regions are aligned to 4 KiB, not 1 MiB or the device topology; telemetry writes are 512 B granular~~ | **fixed in S2** for virtio-blk and virtio-scsi (§2a). Open: NVMe/ATA topology (X13); 4Kn devices cannot boot (the GPT code is 512-byte based), the store layer is tested on a 4096/4096 device |
| ~~G4~~ | ~~the telemetry partition count is fixed at 8~~ | **fixed in S2**: `partitions` in the superblock |
| ~~G7~~ | ~~disks whose size is not a multiple of 4 KiB are refused~~ | **fixed in S2**: the formatted size is rounded down |
| G8 | recovery reads the whole telemetry region at boot, so boot time grows with the disk | **not done in S2**: only the newest segment per partition needs a full scan, with a per-segment summary; moves to S6 with the scrubber |

## 9. Growing (S3, ADR-142)

Boot-time, after `gpt::prepare` has extended the data partition (§0, step 4) and
before the store opens. When the device holds more sectors than the layout's
`total_sectors` (`spare`):

1. `new_end = floor_A(device - 8)`; the new space is `[ceil_A(end of the last data region), new_end)`. If it is shorter than `A`, nothing happens.
2. It is split by `storage.grow_ratio_db` (percent, default 50) between the database and the telemetry ring, as new extents after the existing ones. The region that already ends the layout gets its share first, and a database extent that touches the previous database extent is merged into it. A telemetry share smaller than one segment row (`P · segment_bytes`) goes to the database instead. WAL and journal keep their size.
3. The scratch area moves to `new_total - 8`. `total_sectors` becomes the device size rounded down, `generation` is incremented.
4. The new superblock is written to the slot **not** in force, then flushed. This is the only write of the layout part of the grow.

A cut before the write completes leaves the old slot in force; a torn write
leaves an invalid slot and the old one in force; a completed write puts the new
layout in force. No byte moves. The disk never shrinks automatically: a device
smaller than the layout's `total_sectors` is refused by the superblock checks
(§3, rule 4) and by `gpt::prepare` (`Shrunk`).

## 10. Layout v1 and the migration (S2, ADR-141)

**Layout v1** (S0/S1) had one superblock at LBA 0 (version 1, at most 16 regions, no partition count, no alignment), the same size table, regions from LBA 64 and one telemetry extent in a fixed 8-partition ring with segment headers without a UUID.

<!-- struct: superblock_v1 size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTTDK` |
| 8 | 4 | u32 | version | `1` |
| 12 | 4 | u32 | region_count | at most 16 |
| 16 | 16 | bytes | uuid | |
| 32 | 8 | u64 | total_sectors | |
| 40 | 24 | region[] | regions | `region_count` entries of §3.1 (offsets from 40) |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

The kernel recognises a valid v1 superblock and refuses it. Only
`urmqtt-disk migrate` reads and converts it. The conversion keeps the
telemetry ring where it is (no copy of up to hundreds of GB), moves the small
live files (database, WAL, journal) into aligned regions carved out of the
dead tail of the old database region, and makes the rest of the old space
database extents:

**Migration record** (header sectors 32..63; the kernel ignores it): a copy of
the v1 superblock at LBA 32 and two state blocks at LBA 40 and 48, the higher
valid `seq` winning.

<!-- struct: migration_record size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQMIG1` |
| 8 | 8 | u64 | seq | incremented by one with every state write |
| 16 | 4 | u32 | state | 1 planned, 2 copied and verified, 3 switched (v2 in slot B), 4 done (v2 in slot A as well) |
| 20 | 4 | u32 | v1_crc | CRC-32C of the saved v1 superblock block |
| 24 | 4 | u32 | v2_crc | CRC-32C of the planned v2 superblock block (generation 1) |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

**Order of writes** (each followed by a flush):
1. The rollback file (host) and the saved v1 superblock at LBA 32; then state `planned`.
2. The live bytes of the database, WAL and journal into the new regions; read back and compared; state `copied`.
3. **Superblock slot B := v2, generation 1.** This single block write is the switch: v1 stays in force (slot A still holds it) until it is complete and valid.
4. State `switched`; then slot A := v2, generation 2 (so no v1 reader can open the disk any more); state `done`.

A cut anywhere leaves a valid v1 disk (before step 3) or a valid v2 disk (after
it). `migrate --resume` finishes from the recorded state, `migrate --rollback`
returns to v1 (it restores LBA 0 from the saved copy or the rollback file,
zeroes slot B, clears the state blocks).

## 11. Released space (S4, ADR-150, ADR-151)

Not a format change: no field is added and a v2 disk written before S4 is read
as it was. The store may tell the device that a range holds no data
(virtio-blk DISCARD, SCSI UNMAP, or zeroing that may unmap; NVMe and AHCI in
X13), for three kinds of range, always inside a region extent and shrunk
inwards to the device's granule and the physical block:

| Range | When |
|---|---|
| a telemetry segment | its newest record is older than `storage.retention_days` and it is not the active segment of its partition; its first block (the header) is zeroed first |
| the logical tail of a file | `xTruncate` or `xDelete` made the file shorter (after the size table is durable) |
| space added by a grow | the new extents, after the superblock that references them |

What such a range reads back as afterwards is undefined: zeros, the old bytes,
or garbage. Every reader therefore treats it as unwritten, which is already how
the format works: file bytes beyond the logical size are not read, a segment is
valid only with the magic, this layout's UUID and a valid CRC, and a record only
with its CRC. `storage.discard = "off"` stops all of it.

## 12. The backup region (S5, ADR-160 to ADR-164)

Layout minor 1. A copy of the broker's database kept on the same disk, so that
a damaged database file can be replaced at boot without an operator. It does
not replace an off-disk backup (the disk is one failure domain, §0); it covers
corruption of the database file itself, which the other regions' CRCs and
SQLite's own checks can detect but not mend.

### 12.1 Where it comes from

A disk formatted before S5 has no backup region and no spare space: the
formatter gives the database half of the usable space, the telemetry ring the
rest. The region is therefore **carved from the tail of the last database
extent**, beyond the database file's logical end (the size table), by
`Disk::ensure_backup` at boot:

| Step | Write |
|---|---|
| 1 | the control block and both slot headers of the new region are zeroed; flush |
| 2 | the new superblock (`minor` 1, a `backup` region entry, the last database extent shortened, `generation` + 1) goes to the slot **not in force**; flush |

Step 2 is the only write that changes what the disk means, and it is one block
into the slot not in force, as in the grow (§9). A cut before it leaves the old
layout; a torn write leaves an invalid slot and the old one in force; a
complete write puts the new layout in force. No byte that is read moves.

The carve needs the database to keep at least twice its file size plus 1 MiB.
It takes `4 KiB + 2 × slot` where `slot = clamp(database region / 8, 1 MiB, 1 GiB)`
(4 KiB aligned), rounded to the alignment unit. If the database has no such
room the layout stays as it is (`NoRoom`), the broker runs without a backup and
says so. A fresh disk is formatted as minor 0 and carved at its first boot by
the same code, so there is one path.

### 12.2 Inside the region

```
region offset 0                    control block (4 KiB)
region offset 4096                 slot 0: header (4 KiB), then the payload
region offset 4096 + slot_bytes    slot 1: the same
```

`slot_bytes = floor_4K((region - 4096) / 2)`. The payload is a complete SQLite
database file (the main database, WAL applied), copied by SQLite's online backup
API; it holds at most `slot_bytes - 4096` bytes.

<!-- struct: backup_slot_header size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQBKP1` |
| 8 | 8 | u64 | seq | snapshot number, increases by one per snapshot, at least 1; the highest valid one is the newest |
| 16 | 8 | u64 | created | Unix seconds when the snapshot finished, 0 if the clock was unknown |
| 24 | 16 | bytes | uuid | the superblock's `uuid`: a snapshot of another incarnation of the disk never counts |
| 40 | 4 | u32 | schema_version | the snapshot's `PRAGMA user_version` (the broker's schema version) |
| 44 | 4 | u32 | page_size | the database page size, a power of two from 512 to 65536 |
| 48 | 8 | u64 | page_count | pages in the payload |
| 56 | 8 | u64 | payload_bytes | `page_size × page_count`, at most the slot's payload capacity |
| 64 | 4 | u32 | payload_crc | CRC-32C of the payload's `payload_bytes` bytes |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

<!-- struct: backup_control size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQBKC1` |
| 8 | 8 | u64 | seq | incremented by one with every write of the block |
| 16 | 16 | bytes | uuid | the superblock's `uuid` |
| 32 | 4 | u32 | state | `0` idle, `1` a restore was started and not finished |
| 36 | 4 | u32 | slot | state 1: the slot being restored from |
| 40 | 8 | u64 | backup_seq | state 1: the `seq` of the snapshot being restored |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

A header is **valid** if its magic, CRC and `uuid` match and its fields are
consistent. A snapshot is **intact** if its header is valid and the payload's
CRC-32C equals `payload_crc`. Nothing else makes bytes a snapshot, so garbage
in a slot (including what a device returns for a released range, §11) is never
mistaken for one. A control block that is blank, torn or foreign reads as idle.

### 12.3 Writing a snapshot

Let `N` be the slot holding the newest *intact* snapshot (a newest slot whose
payload fails its CRC does not count). The snapshot goes to the other slot:

1. **Only if the newest snapshot has not been read back since boot:** its payload is read and checked.
2. The target slot's header block is zeroed; flush. (From here the target is invalid.)
3. SQLite's backup API copies the database into the target's payload area in steps of a few pages, between the broker's own transactions; flush.
4. The payload is read back and its CRC-32C computed, and the SQLite header (page size, page count, `user_version`) is read from it.
5. The target's header is written in one block, with `seq` one above the highest header's; flush.

Slot `N` is never written, read-modify-written or discarded. A cut anywhere
leaves `N` as it was; the target is invalid until step 5 completes. If the
database does not fit the slot the job stops before step 2.

### 12.4 Restoring

At boot, with the store closed:
1. If the control block says a restore was started, it is continued with the same snapshot.
2. Otherwise, if `PRAGMA quick_check` (or opening the file) found the database corrupt and `storage.auto_restore` is set, the newest intact snapshot whose `schema_version` the build can read is chosen.

The restore then:
1. writes the control block (`state` 1, the snapshot); flush;
2. sets the WAL and journal sizes to 0; flush (a stale WAL frame is never applied to the restored file);
3. copies the payload over the start of the database region and flushes (the copy's CRC is checked against the header);
4. sets the database file size to `payload_bytes` and flushes;
5. writes the control block idle; flush.

The snapshot is only read, so a cut at any point leaves it intact and the next
boot repeats the restore from step 1 or 2. The lost time window is `now - created`.

### 12.5 Invariants

- A slot other than the target is not written while a snapshot is made.
- A header never becomes valid before its payload is complete and read back.
- The database's logical size never exceeds its (shortened) region: the carve leaves it twice its size.
- Released space (§11) cannot reach the backup region: the region is no longer part of the database's extents, and the carve cancels queued discards over it.
