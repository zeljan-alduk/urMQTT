# Storage: implementation and test plan (S0–S8)

Plan for [`PROMPT-storage.md`](../PROMPT-storage.md). Written 2026-10-29
against commit `8186a61`. It is part of the overall plan in
[PLAN.md](PLAN.md), next to [X86-PLAN.md](X86-PLAN.md) and
[SECURITY-PLAN.md](SECURITY-PLAN.md).

**The principle stays: no filesystem.** The data disk is accessed raw. It
holds a superblock, a region table and fixed regions, and SQLite sees three
fixed "files" mapped onto regions by its own VFS. There is no filesystem code
to attack or to corrupt, and the layout fits on one page of specification.
This work removes the practical downsides of a raw disk (tooling, resize,
discard, backup, scrubbing, encryption) without adding a filesystem.

---

## 1. Current layout (read from `crates/store`)

```
LBA 0        superblock, 4 KiB: magic "URMQTTDK", version 1, uuid, ≤ 16 regions × 24 B, CRC-32C
LBA 8, 16    file-size table slots A/B ("URMQSZT1", the highest valid sequence wins)
LBA 64       regions, 4 KiB aligned, in order:
               SQLite main DB    = usable/2
               WAL               = usable/8 clamped to 2–64 MiB
               rollback journal  = 1 MiB
               telemetry         = the rest: 8 partitions, segments of 64 KiB – 8 MiB,
                                   segment header "URMQTSG1", records with CRC-32C
                                   salted by the segment sequence
last 8 sect. scratch for the boot block-device self-test
```

Blank means the superblock is all zeros, and the disk is then formatted. A
partitioned disk (MBR/GPT) is never the data disk. The SQLite side runs WAL
with exclusive locking, `synchronous=FULL`, `quick_check` at boot and
`refuse_on_corruption`.

## 2. Findings

| # | Finding | Consequence |
|---|---|---|
| G1 | **The blk self-test writes the last 8 sectors of every non-partitioned disk at device probe**, before the store decides whether the disk is blank, ours or foreign (`kernel/src/devices.rs:387-400`, `blk_selftest`). | A foreign disk without a partition table (e.g. a whole-disk filesystem) has its last 4 KiB overwritten even when it is then refused. Harmless in a VM with a blank volume, data loss on bare metal. Fixed in **S1**: the self-test runs only on a disk positively identified as urMQTT or confirmed blank. |
| G2 | **Blank detection checks only the superblock** (`layout.rs` `decode` → `Ok(None)` for all zeros). ext4, among others, keeps its first 1024 bytes zero (X86-PLAN F10). | **S1:** a signature scan (MBR/GPT, ext2/3/4, XFS, btrfs, NTFS, FAT/exFAT, LVM, mdraid, LUKS, ZFS labels, swap, ISO 9660), a zero check of the first and last 1 MiB, and on bare metal formatting only the disk named in config. |
| G3 | Regions are 4 KiB aligned from LBA 64 (32 KiB), not 1 MiB or the device's optimal I/O size. virtio-blk negotiates only `RO | BLK_SIZE | FLUSH`: no `TOPOLOGY`, `DISCARD` or `WRITE_ZEROES`. | S2 and S4. |
| G4 | Telemetry has a fixed `PARTITIONS = 8`. | With more than 8 cores (bare metal, X12 raises MAX_CPUS), cores have to share partitions. That is a format question for **S2** (partition count in the layout, not a constant). |
| G5 | `store` is kernel-only (no host build of the VFS). | S1: host build with the same vendored amalgamation. This also helps SECURITY-PLAN H5 (sanitizers on the VFS). |
| G6 | The cross-architecture disk test (X86-PLAN X8) needs a stable format. | **S2 comes before X8**, so the cross-arch tests are written against v2 and golden v1 images, and the two efforts do not diverge. |

---

## 3. Milestones

Each milestone ends with:
- `make check` and `make smoke`;
- commit `S<n>: …`, a PROGRESS entry and ADRs;
- stop and report.

**Rules for all milestones:**
- Every format change bumps the version and comes with a migration path and tests.
- Every multi-step on-disk update has fault-injection tests (§4).
- The kernel and the host tool share one parser per format.
- No new network surface.

### S0 — Audit and specification · S (no format change)

**Work**
- `docs/DISK-FORMAT.md`: byte-level specification of v1:
  - every structure, field, offset, width and endianness;
  - CRC coverage and salting;
  - the A/B rules;
  - the telemetry segment and record format;
  - the recovery algorithm (torn tail, sequence order);
  - invariants;
  - which writes are FUA or flush-ordered.
- Gaps against PROMPT-storage go into PROGRESS (G1–G6 above, plus whatever the spec turns up).
- **Golden vectors:** a generator writes small v1 images (blank, fresh, with data, with a torn tail), and their hashes are checked by host tests.
- **Spec/code cross-check:** a host test walks the encoders and asserts that every field offset appears in a table the spec is generated from (or the reverse), so the two cannot drift.

**Accept:** every field in the code is in the spec and the reverse; the golden-image tests are green.

### S1 — Host-buildable store, `urmqtt-disk`, fault injection, disk safety · L

**Work**
- **Split `crates/store` for the host:**
  - an `std` feature builds layout, superblock, regions, the size table, CRC-32C, the telemetry format and recovery for the host;
  - the SQLite VFS gets a second backend over a host file or block device;
  - the host build uses **the same vendored amalgamation and compile options** as the kernel, never the system SQLite.
- **`tools/urmqtt-disk`** (std, offline, macOS and Linux, image files and block devices; read-only by default, every write behind `--write`). Commands as in PROMPT-storage S1:

  | Command | Does |
  |---|---|
  | `info` | layout and region overview |
  | `verify` | non-zero exit on any error |
  | `create` | a blank image (documented as deliberately blank, so the first boot formats it) |
  | `export-db` | WAL applied |
  | `export-telemetry` | csv or jsonl, with time and topic filters |
  | `import-devices` | through the kernel's schema and migrations |
  | `migrate`, `backup-extract` | from S2 and S5 on |

  `--key` arrives with S7.
- **Fault-injection framework (§4)**, built here and used everywhere afterwards.
- **Disk safety (G1, G2):**
  - the signature scanner lives in `store`, shared with the host tool, so `urmqtt-disk info` shows what the kernel would decide;
  - the self-test moves behind identification;
  - config `storage.data_disk = { serial | model+size }` and `storage.allow_format`; the bare-metal default is to format only a disk named in config, while a VM keeps today's behaviour through an explicit setting.

**Tests**
- **Round trip:**
  1. Boot a VM, publish telemetry, create sessions, stop.
  2. `verify` is clean, and `export-db` opens in the host `sqlite3`.
  3. `export-telemetry` matches what was published.
  4. `import-devices`, then boot: the devices are present.
- **Safety:**
  - fixtures for every signature;
  - smoke `refuse-foreign-ext4`: whole-disk ext4, nothing written, which is checked by hashing the disk before and after;
  - `select-by-serial`: two disks, only the configured one is used.
- Fuzz targets for the scanner and the host-side parsers (shared code, so the existing targets cover most of it).

### S2 — Layout v2: alignment, topology, partition count · M

**Work**
- **Topology:**
  - virtio-blk `F_TOPOLOGY` (physical block exponent, alignment offset, minimum and optimal I/O size);
  - the virtio-scsi Block Limits VPD (B0h) where available;
  - for bare metal (X13): NVMe LBA format and NPWG/NOWS, ATA IDENTIFY logical and physical sector.
- **Alignment:** every region to 1 MiB and to the optimal I/O size; telemetry writes to the physical block (at least 4 KiB). Unavoidable exceptions are documented, and a debug counter `misaligned_writes` is checked by smoke.
- **Format v2:** the partition count becomes part of the layout (G4).
- **Migration: offline** (decided 2026-10-29, PLAN.md decision 4).
  - **Kernel side:** the kernel reads only the current layout. An older one is refused before anything is written, with the message `data disk is layout v1; this image needs v2: run urmqtt-disk migrate (docs/DEPLOY.md)` and a statsd reason. The kernel keeps only one parser in the TCB, and it never copies gigabytes at boot unattended.
  - **`urmqtt-disk migrate`, following the usual practice for offline format conversion:**
    - **Plan first:** `--dry-run` is the default. It prints the plan (old and new regions, bytes to copy, free space needed) and changes nothing; `--write` executes.
    - **Preconditions:** a clean last shutdown, or a successful `verify` (WAL checkpointed, telemetry recovered); the tool refuses otherwise.
    - **Order of writes:**
      1. Back up every metadata block it will change into a rollback area on the same disk, and into a file next to the tool (`--rollback-file`).
      2. Copy data into the new regions (copy-then-switch, in an order where a source is never overwritten before its copy is verified by CRC or hash).
      3. Write the new superblock last, in a single atomic block write.
    - **Recovery:** an interrupted run either leaves the old v1 disk valid, or can be finished or rolled back with `migrate --resume` or `--rollback`.
    - **Verification:** a full `verify` of the result, plus a comparison of the row counts of every SQLite table and of the telemetry record count with the source.
  - **Tests:**
    - every golden v1 image migrated and verified;
    - fault injection at every write of `migrate` (§4): each case ends in a valid v1 or a valid v2 disk, never a corrupt one;
    - the kernel's refusal of v1 as a smoke scenario (`layout-v1-refused`, nothing written, checked by hashing the disk before and after).
  - DEPLOY.md documents the procedure per platform: a VM image file on the host, a cloud volume attached to a helper VM, and bare metal via a Linux live USB.

**Tests**
- QEMU `logical_block_size=512,physical_block_size=4096`, and 4096/4096: zero misaligned writes.
- Migration of every golden v1 image, with fault injection at every write of `migrate`.
- The X8 cross-arch test is written against v2.

### S3 — Growing the disk · M

**Work**
- **Boot-time grow:** when capacity exceeds the layout size, grow. Online grow through a virtio-blk config-change interrupt, if QEMU `block_resize` delivers it (**to verify**); otherwise boot-time only, documented.
- **The update is crash-safe** (ADR: an A/B superblock pair vs a journaled superblock). New space is split by `grow_ratio_db` between the SQLite main region and telemetry; WAL and journal sizes stay. Data does not move unless unavoidable, and then only by copy-then-switch with recovery.
- **Never shrink automatically.**

**Tests:** grow 1 GiB → 4 GiB → 64 GiB with data present; fault injection at every write of the grow procedure always yields the old or the new layout, never a corrupt one.

### S4 — Discard and write-zeroes · M

**Work**
- **Where it is used:** retired telemetry segments, space freed by grow or rebalance, and the logical tail on VFS `xTruncate`.
- **How, per device:**

  | Device | Commands |
  |---|---|
  | virtio-blk | `F_DISCARD`, `F_WRITE_ZEROES` |
  | virtio-scsi | UNMAP, WRITE SAME |
  | NVMe (X13) | Dataset Management Deallocate, Write Zeroes |
  | AHCI | TRIM |

  Device limits (max sectors, segment count, alignment) are respected. Discards are batched and rate-limited, never in front of a commit. Config `storage.discard = "auto" | "off"`.
- **Recovery never trusts discarded content.** This is verified for every region type, with a test that fills discarded ranges with garbage.

**Tests:**
- smoke `discard-qcow2`: a qcow2 with `discard=unmap` shrinks on the host after retention runs, checked by the file's allocated size;
- db-bench without regression.

### S5 — In-disk database backup · M

**Work**
- **Backup region** with two slots (A/B). The DB core writes a consistent snapshot into the older slot (SQLite online backup API in bounded steps between batches, or `VACUUM INTO` through the VFS; ADR by measurement), then a header with sequence, time, schema version and CRC/hash.
- **Config:** `backup_interval_min`.
- **Restore at boot:** if `quick_check` fails and a valid backup exists, then with `auto_restore = true` restore it and log the lost time window loudly; otherwise refuse, as today.
- **DEPLOY.md** explains how this relates to provider snapshots: those are crash-consistent, which the kill -9 tests already cover.

**Tests**
- `test=db-corrupt` (dev) followed by a restore that is logged.
- Fault injection during the backup never invalidates the previous good slot.
- The data plane is not stalled: measured.

### S6 — Scrubbing · S–M

**Work**
- When idle, the DB core:
  - re-reads telemetry segments and checks their CRCs;
  - runs `PRAGMA quick_check` in bounded steps;
  - checks the backup headers.
- statsd `urmqtt.scrub.*` and syslog. Config `scrub_interval_h` and `scrub_io_budget_mb_s`.

**Tests:** injected bit flips (fault injector, read flip) in telemetry and the DB are found and reported; scrubbing I/O stays within budget during a load test.

### S7 — Encryption at rest (optional, off by default) · L

**Work**
- **Config:** `storage.encryption = "off" | "aes-256-xts"` and `storage.disk_key`, a file separate from the TLS key, never committed. The build fails when encryption is on and the key is missing or weak.
- **What is encrypted:** everything except the plaintext superblock, per physical 4 KiB block, with tweak = block number. The superblock holds a key-check value (HMAC of a constant), never the key.
- **Crypto through the dispatch framework** (X86-PLAN D2): ARMv8 AES (X0b) on aarch64, AES-NI/VAES (X9) on x86. Without hardware AES, either Adiantum or a clear refusal (ADR); never a silent fall back to slow table-based AES.
- **Encryption happens only in the DB core's I/O path.** Page cache and telemetry buffers stay plaintext in memory.
- **SECURITY.md limits:**
  - it protects stolen volumes and snapshots, **not** a stolen ISO (the key is inside it);
  - XTS gives confidentiality, not integrity;
  - rekeying is offline.

  On bare metal, the stolen-disk case is the main benefit; a TPM-sealed key is SECURITY-PLAN H8's spike.
- **`urmqtt-disk`:** `--key` for every command, plus `rekey`, `encrypt` and `decrypt` (offline, `--write`).

**Measured** (aarch64 HVF, and x86 KVM or the Intel PC), with encryption off and on:
- XTS throughput per core per implementation;
- db-bench, telemetry MB/s, handshakes and messages;
- boot time.

**Accept:** the storage smoke set passes with encryption on; a wrong key gives a clear refusal; overhead ≤ 5 % on hardware with AES instructions, or a report of what dominates.

### S8 — Documentation and hardening · S–M

**Work**
- `DISK-FORMAT.md` final (v2, backup region, encryption); DEPLOY (resize per provider and on bare metal, snapshots, backup and restore, export); SECURITY (encryption threat model); README.
- Fuzz targets: superblock and regions v1 and v2, migration input, backup header, encrypted blocks under wrong keys. Golden images for every version.

**Accept:** the docs match the code; every fuzz target runs in CI.

---

## 4. Fault-injection framework (S1, then everywhere)

- **Kernel (dev/test builds only, compiled out of prod):** a block-device wrapper behind `DataDisk`, controlled by `test=disk-fault:<spec>`. It can:
  - stop the VM after the N-th write or flush;
  - tear a write (persist only the first K sectors);
  - drop a flush;
  - flip bits on read.
- **Host runner** (`scripts/fault-loop.sh` + `urmqtt-disk`): for a procedure (grow, migrate, backup, rekey) it loops N over every write and checks after each case:
  - that the disk recovers to a valid state;
  - that no committed data is lost (compared against a journal of acknowledged commits).
- The host tool's own writes go through the same wrapper in tests.
- The existing db-crash, log-crash and log-tear scenarios become special cases of it.

## 5. Coordination with the other tracks

- **X86-PLAN:**
  - S2 (v2 format) comes before X8 (cross-arch disk test);
  - NVMe and AHCI (X13) implement topology (S2) and discard (S4) for their devices;
  - S7 uses the dispatch framework from X0/X0b/X9;
  - the disk safety of X12 is S1's.
- **SECURITY-PLAN:**
  - H5 sanitizers use S1's host build of the VFS;
  - H6 (SQLite at EL0) changes how the VFS reaches the disk (through rings), so S5's backup and S6's scrub, which also run SQLite, follow the same path;
  - S7's key handling goes into H0's inventory and H10's audit scope.

## 6. Exact plan for S0 and S1

1. **S0:**
   - DISK-FORMAT.md from the code;
   - the field table plus the cross-check test;
   - the golden v1 image generator and hash tests;
   - gaps (G1–G6) into PROGRESS.

   No behaviour change.
2. **S1:**
   - the `std` feature for store's pure parts;
   - the host VFS backend with the same amalgamation;
   - `urmqtt-disk info/verify/create/export-db/export-telemetry/import-devices`;
   - the fault-injection wrapper and runner;
   - the signature scanner;
   - the self-test moved behind identification;
   - `data_disk` and `allow_format` config;
   - the round-trip and safety scenarios.
