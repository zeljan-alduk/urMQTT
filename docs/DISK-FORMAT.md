# Data disk format, layout version 1

The byte-level specification of the urMQTT data disk (STORAGE-PLAN S0). The
disk has **no filesystem**: the kernel accesses it raw, as a superblock, a
region table and fixed regions. The code is in `crates/store`
(`layout.rs`, `disk.rs`, `vfs.rs`, `telemetry.rs`); ADR-030 and ADR-031 give
the reasons.

The tables marked `<!-- struct: … -->` are machine-read by
`crates/store/tests/disk_format_spec.rs`. That test encodes every structure
with the real code, then checks two things:
- each listed field is at the listed offset with the listed encoding;
- every byte the encoder writes belongs to a listed field.

So a field in the code that is missing here fails the test, and so does a
field listed here that the code does not write.

## 1. Conventions

- All integers are **little-endian**, fixed width, independent of the CPU architecture. A disk written on aarch64 is valid on x86_64.
- **Sector:** 512 bytes. Addresses on the device are in sectors (LBA). The device must have 512-byte logical blocks; 4Kn devices are not supported in v1 (G3).
- **Block:** 4096 bytes (8 sectors). The superblock, the size-table slots and the telemetry header are one block each.
- **CRC:** CRC-32C (Castagnoli, reflected polynomial `0x82F63B78`, initial value and final XOR `0xFFFFFFFF`; `crc32c("123456789") = 0xE3069283`), stored as `u32`. Unless stated otherwise it covers bytes `0 .. size-4` of its structure and is stored in the last four bytes.
- **Unlisted bytes** inside a structure are written as zero and are covered by its CRC. Readers do not interpret them; a future version may use them only together with a version bump.
- **Magics** are 8 ASCII bytes without a terminator.

## 2. Disk map

```
LBA 0          superblock                    1 block
LBA 8          size table slot A             1 block
LBA 16         size table slot B             1 block
LBA 24 .. 63   unused (zero)                 20 KiB
LBA 64 ..      regions (from the region table), each a multiple of 8 sectors and 8-sector aligned:
               SQLite main database, WAL, rollback journal, telemetry log
last 8 sectors scratch (the boot block-device self-test writes here)
```

The **formatter** (`Layout::plan`, used only on a blank disk, §6) places the
regions in the order database, WAL, journal, telemetry, scratch, and sizes
them as follows (all in sectors, rounded down to a multiple of 8):

| Region | Size |
|---|---|
| `usable` | `align8(total_sectors - 8 - 64)` |
| journal | 1 MiB (2048 sectors) |
| WAL | `align8(clamp(usable / 8, 2 MiB, 64 MiB))` |
| database | `align8(usable / 2)` |
| telemetry | `usable - journal - WAL - database` |
| scratch | `total_sectors - 8`, 8 sectors |

The smallest disk is 16 MiB (32 768 sectors). A disk whose size is not a
multiple of 4 KiB is refused at format time, because its scratch region would
not be 8-sector aligned (G7).

## 3. Superblock (LBA 0)

<!-- struct: superblock size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTTDK` |
| 8 | 4 | u32 | version | layout version, `1` |
| 12 | 4 | u32 | region_count | number of region entries, at most 16 |
| 16 | 16 | bytes | uuid | random at format time; identifies the disk |
| 32 | 8 | u64 | total_sectors | disk size in sectors **when formatted**; at most the device's current size |
| 40 | 24 | region[] | regions | `region_count` entries of §3.1, back to back (up to offset 424) |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

### 3.1 Region entry (24 bytes, at 40 + 24·i)

<!-- struct: region size=24 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 4 | u32 | kind | 1 database, 2 WAL, 3 journal, 4 telemetry, 5 scratch |
| 8 | 8 | u64 | start | first sector (LBA), a multiple of 8 |
| 16 | 8 | u64 | sectors | length in sectors, a multiple of 8 |

Bytes 4..8 are zero.

**Validity** (`Layout::decode`; any failure refuses the disk, nothing is written):
1. The 4096 bytes are all zero: the disk is **blank** (§6).
2. Otherwise the magic must match, or the result is `UnknownData`: foreign data, never formatted over.
3. The CRC must match; `version` must be 1; `region_count` ≤ 16; every `kind` must be known.
4. `total_sectors` ≤ the device size.
5. Regions are non-empty, 8-sector aligned, start at or after LBA 64, do not overlap and end within `total_sectors`.
6. Database, WAL and journal regions exist. Telemetry and scratch are optional for the reader.

## 4. Size table (LBA 8 = slot A, LBA 16 = slot B)

The logical sizes of the three SQLite "files", which the VFS maps onto the
database, WAL and journal regions. Two slots make updates atomic: a write goes
to the slot that does not hold the newest valid copy.

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

Each region holds one SQLite file as a flat byte range starting at the
region's first byte. Its logical length is in the size table, and growth
beyond the region fails with `SQLITE_FULL`.

The file contents are SQLite's own formats (database file format, WAL
format), version 3.54.1, with:
- 4096-byte pages (`SQLITE_DEFAULT_PAGE_SIZE`);
- `journal_mode = WAL`, `locking_mode = EXCLUSIVE` (no shared-memory index);
- `synchronous = FULL`;
- a WAL auto-checkpoint at half the WAL region (32 to 1000 frames).

The VFS reports a 512-byte sector size and no device characteristics, so
SQLite assumes a torn sector can damage its neighbours. Truncation
(`xTruncate`) only changes the logical size; the bytes stay on disk.

### 5.2 Telemetry log (kind 4)

```
region     [ log header 4 KiB ][ partition 0 ] … [ partition 7 ]
partition  [ segment 0 ] … [ segment S-1 ]        a ring
segment    [ segment header 512 B ][ records … ][ zero padding ]
```

**Geometry,** chosen at format time (`Geometry::plan`) and stored in the log header:
- `part = (region_bytes - 4096) / 8`;
- `segment_bytes = floor4K(clamp(part / 8, 64 KiB, 8 MiB))`;
- `segments = part / segment_bytes`, at least 2.

The segment `s` of partition `p` starts at region offset
`4096 + p·segments·segment_bytes + s·segment_bytes`. Source core `c` writes
partition `c mod 8`.

#### Log header (region offset 0)

<!-- struct: telemetry_header size=4096 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTLH1` |
| 8 | 4 | u32 | version | `1` |
| 12 | 4 | u32 | partitions | `8` |
| 16 | 8 | u64 | segment_bytes | a multiple of 4096, at least 64 KiB |
| 24 | 8 | u64 | segments | segments per partition, at least 2 |
| 4092 | 4 | crc32c | crc | over bytes 0..4092 |

An all-zero header means a blank log, formatted at open. Non-zero data without
the magic is `UnknownData`, never formatted over. A bad CRC or version, a
partition count other than 8, or a geometry that does not fit the region is
`BadHeader`, and the disk is refused.

#### Segment header (first sector of a segment)

<!-- struct: segment_header size=512 -->
| Offset | Size | Type | Field | Description |
|---|---|---|---|---|
| 0 | 8 | magic | magic | `URMQTSG1` |
| 8 | 4 | u32 | partition | the partition this segment belongs to |
| 16 | 8 | u64 | seq | per-partition segment sequence, starting at 1; 0 is invalid |
| 24 | 8 | u64 | created | Unix seconds when the segment was started |
| 508 | 4 | crc32c | crc | over bytes 0..508 |

A segment is valid if its magic, CRC and partition match and `seq` > 0.

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
- Records are batched and written as whole sectors, zero-padded after the last record, followed by a flush.
- A new segment (the next ring index, `seq + 1`) starts:
  - when the next record does not fit;
  - for the first record of a partition, which goes to segment 0 with seq 1;
  - after recovery: a recovered segment is never extended.
- Its header is written with the first batch.

**Recovery** (`TelemetryLog::open`). For each partition:
1. Read every segment header and order the valid segments by `seq`.
2. Scan each segment's records until `len == 0` (a clean end) or the first record that fails its CRC, its length bounds or UTF-8 (a torn tail; the rest of the segment is ignored).
3. The segment with the highest `seq` is the partition's active segment. New records go to a new segment.

**Why stale data never resurrects:** the CRC is salted with the segment's
`seq`. Records from an earlier pass of the ring therefore fail in a reused
segment. When a batch ends exactly on a sector boundary, the next sector may
still hold such stale bytes. They are read as a torn tail (counted, harmless),
never as records.

**Retention:** by size, as the ring overwrites the oldest segment. Age
(`storage.retention_days`) only hides expired records from reads.

### 5.3 Scratch (kind 5)

Eight sectors that the boot block-device self-test overwrites with a random
pattern, then reads back. They hold no data. Today the self-test runs on the
first disk without partitions, before the store looks at it (G1).

## 6. Blank disks and formatting

`Disk::open` reads the superblock:

| Superblock | Result |
|---|---|
| all zero | **blank**: formatted (below) |
| a valid v1 superblock | opened |
| anything else | refused, nothing is written |

**Formatting:**
1. Plan the regions (§2).
2. Write size-table slot A with `seq = 0`, all sizes 0, and write slot B as zeros; flush.
3. Write the superblock; flush.

A crash before step 3 leaves a disk whose superblock is still zero, so it is
formatted again on the next boot. The telemetry header is written separately
when the log is first opened (§5.2).

Today a disk counts as blank when its first 4 KiB are zero, and the kernel
skips disks with an MBR or GPT. Since 2026-10-29 the data disk belongs to
urMQTT entirely, so previous content does not matter (PLAN.md decision 6).
S1 replaces the "skip partitioned disks" rule with an exact boot-disk
identification and an explicit disk choice (G1, G2).

## 7. Invariants

- No region overlaps another or the header area (LBA 0–63).
- A size in the size table never exceeds its region, and never covers data written after the last flush.
- Every on-disk structure except SQLite's own files and record payloads has a CRC-32C, so a torn or stale structure is detected, never trusted.
- A disk is only ever formatted when its superblock is all zero.
- The format has no pointers into memory and no host-endian fields.

## 8. Known gaps (STORAGE-PLAN)

| Gap | Description | Fixed in |
|---|---|---|
| G1 | the data disk is chosen by "not partitioned" instead of by identity | S1 |
| G2 | a damaged urMQTT disk must not be taken for a blank one | S1 |
| G3 | regions are aligned to 4 KiB, not 1 MiB or the device topology; telemetry writes are 512 B granular, which causes read-modify-write on 4 KiB-physical devices | S2 |
| G4 | the telemetry partition count is fixed at 8 | S2 |
| G7 | disks whose size is not a multiple of 4 KiB are refused instead of rounded down | S2 |
| G8 | recovery reads the whole telemetry region at boot, so boot time grows with the disk | S2 |
