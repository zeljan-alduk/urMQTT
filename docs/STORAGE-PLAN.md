# Storage: implementation and test plan (S0–S8)

Plan for [`PROMPT-storage.md`](../PROMPT-storage.md). Written 2026-10-29
against commit `8186a61`. It is part of the overall plan in
[PLAN.md](PLAN.md), next to [X86-PLAN.md](X86-PLAN.md) and
[SECURITY-PLAN.md](SECURITY-PLAN.md).

**The principle stays: no filesystem.** The data is accessed raw: a
superblock, a region table and fixed regions, and SQLite sees three fixed
"files" mapped onto regions by its own VFS. Since 2026-10-29 it lives on
**the disk urMQTT boots from**, in a partition after the boot partition, and
no other disk is used (PLAN.md decision 6, §2a below). There is no filesystem code
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
| G1 | **The data disk is a separate disk, chosen by "not partitioned".** The boot block self-test and the store skip every disk with an MBR or GPT and use the first other one (`kernel/src/devices.rs:387-400`). That contradicts the single-disk model (PLAN.md decision 6): data must live on the boot disk, and no other disk may be touched. | **S1:** the single-disk model (§2a). |
| G2 | **Blank detection checks only the first 4 KiB.** With whole-disk ownership this is no longer a data-safety question: foreign content is overwritten on purpose (PLAN.md decision 6). It still matters for *our own* disk: a urMQTT disk whose superblock was destroyed but whose regions still hold data must not be silently re-formatted as if new. | **S1:** classify each candidate as urMQTT (valid superblock), urMQTT-damaged (our magic or our size-table/telemetry magics present, superblock invalid: refuse, or restore in S5), or foreign/blank (claim, logged). |
| G3 | Regions are 4 KiB aligned from LBA 64 (32 KiB), not 1 MiB or the device's optimal I/O size. virtio-blk negotiates only `RO | BLK_SIZE | FLUSH`: no `TOPOLOGY`, `DISCARD` or `WRITE_ZEROES`. | S2 and S4. |
| G4 | Telemetry has a fixed `PARTITIONS = 8`. | With more than 8 cores (bare metal, X12 raises MAX_CPUS), cores have to share partitions. That is a format question for **S2** (partition count in the layout, not a constant). |
| G5 | **The host build is partial** (corrected during S0). SQLite and the VFS already build for the host with the same amalgamation and defines (`store/build.rs`), and `tests/sqlite.rs` runs them over `MemDisk`, which already has power-loss primitives (`crash`, `fail_after`). Missing: a VFS backend over a host file or block device, a `std` feature for the tooling, and the systematic fault runner. | S1 builds on what exists rather than splitting the crate from scratch. It also helps SECURITY-PLAN H5 (sanitizers on the VFS). |
| G6 | The cross-architecture disk test (X86-PLAN X8) needs a stable format. | **S2 comes before X8**, so the cross-arch tests are written against v2 and golden v1 images, and the two efforts do not diverge. |
| G7 | **A disk whose size is not a multiple of 4 KiB cannot be formatted**: the scratch region would start unaligned and `validate` refuses the plan (found during S0, tested in `disk_format_spec.rs`). | S2: round the formatted size down to 4 KiB (the `total_sectors` field already allows a device larger than the layout). |
| G8 | **Boot time grows with the telemetry region.** Recovery scans every record of every valid segment of every partition at boot (`telemetry.rs` `recover_partition` → `scan_segment` per segment), so it reads the whole region. That takes about 2 min for 250 GB on a fast NVMe and 15–40 min on a typical cloud volume (100–250 MB/s). | **S2:** only the newest segment per partition needs a full scan; record counts come from a per-segment summary written when a segment is closed, and full verification moves to the background scrubber (S6). Until then, keep data disks to tens of GB. |

## 2a. The single-disk model (PLAN.md decision 6)

```
LBA 0      protective MBR
LBA 1-33   primary GPT (header, 128 entries)
1 MiB      EFI system partition (Limine, kernels, limine.conf), from the image
…          urMQTT data partition, type GUID urmqtt-data, created on first boot,
           aligned to 1 MiB, up to the backup GPT
last 33    backup GPT
```

- **Finding the disk.** Limine reports the boot volume (media type, GPT disk UUID or MBR signature, partition index). The kernel reads LBA 1 of each disk it drives and picks the one whose GPT disk GUID (or MBR id) matches. No match, or more than one match: refuse to serve, listing what was found. Other disks are never written; the boot self-test and the store run only on the boot disk's data partition.
- **First boot, crash-safe and idempotent.** Each step re-checks the state, so a crash at any point resumes or repeats on the next boot:
  1. If the backup GPT is not at the last LBA (the image was written to a larger disk), write a new backup header and entries at the end, then rewrite the primary header with the new `AlternateLBA` and `LastUsableLBA`.
  2. Assign a random disk GUID, primary and backup. Every copy of the image starts with the same GUID.
  3. Add the data partition entry over the free space, 1 MiB aligned. This is primary and backup, entries CRC then header CRC.
  4. Zero the stale backup GPT the image left inside the new partition.
  5. Format the data layout inside the partition.

  Fault injection (§4) at every write of 1–5.
- **Contents of the data partition.** DISK-FORMAT.md's layout, with every LBA relative to the partition start. That is part of layout v2 (S2), together with 1 MiB alignment.
- **Growing** (S3) means the cloud volume got bigger: move the backup GPT to the new end, extend the partition entry, then grow the layout. These are the same primitives as the first boot.
- **Read-only boot media** (the ISO as a CD, or a write-protected disk): no data partition can exist. Production refuses to serve with `booted from read-only media: write the image to the machine's disk (DEPLOY.md)`; dev may run with an in-memory store.
- **Updating the kernel.** `urmqtt-disk update-boot <disk> <new image>` (offline) replaces the ESP contents and keeps the data partition. The next step, recorded but not planned yet: two boot entries (A/B) with automatic rollback when the new kernel does not reach `URMQTT READY`.
- **Testing** uses one disk everywhere. Smoke copies the image, extends it with `truncate`, and boots it as the only disk: virtio-blk, virtio-scsi and, from X13, NVMe and AHCI. Scenarios check:
  - first boot, and a crash at each first-boot step;
  - reboot, and growing the disk;
  - that a second attached disk is byte-identical afterwards;
  - booting the ISO as a CD (prod refuses).

## 2b. Self-installing ISO (PLAN.md decision 7)

**Boot menu** (`limine.conf`, hash-pinned like today, config hash enrolled by H8, editor off):

```
timeout: 5
default_entry: 1
/urMQTT                                        kernel: urmqtt-${ARCH}.elf#<blake2b>
/Install urMQTT on this machine's disk         kernel: urmqtt-${ARCH}.elf#<blake2b>
                                               cmdline: install
                                               module_path: boot():/esp.img#<blake2b>
```

- **Target selection.** Every disk the kernel drives, minus:
  - the boot medium (identified as in §2a);
  - optical devices (SCSI type 5);
  - write-protected devices;
  - disks smaller than the minimum (ESP plus 16 MiB of data).

  Exactly one disk left: that disk. Several: refuse and list them, unless `storage.install_target = { serial = "…" }` names one. On bare metal the USB stick the installer runs from is not even visible (there is no USB storage driver), which leaves the internal disk.
- **Confirmation without input.** The framebuffer and serial console show the target (bus, model, serial, size) and whether it holds a urMQTT data partition. Then a 30 s countdown follows, and the screen tells the operator to power off to cancel. A config option can shorten the countdown for automated VM tests only (dev builds).
- **Writing.** The module `esp.img`, loaded by Limine into memory and pinned by its hash, is the ESP. The kernel builds the protective MBR and GPT with the same rules as `scripts/mkraw.py` (shared specification, deterministic GUIDs), so the first 1 MiB plus the ESP are **byte-identical to the raw image**. The steps:
  1. Write the ESP.
  2. Write the GPT (backup at the image's end, as in the raw image).
  3. Write the MBR last.
  4. Flush, then read everything back and compare the blake2b hash.

  On x86 the BIOS stage of Limine is part of what the raw image contains (X10), so a BIOS boot of the installed disk works as well. A crash during writing leaves a disk that does not boot (no valid MBR or GPT yet), and the operator installs again.
- **Existing data partition.** The installer overwrites the target from the start; a previous urMQTT data partition is not kept. Reinstalling with data kept is `urmqtt-disk update-boot` (offline) and, later, an *Update* menu entry that replaces only the ESP.
- **Finish.** Log `install: done, remove the installation medium`, then power off. On the next boot from the disk, the single-disk first boot (§2a) moves the backup GPT, assigns a disk GUID, creates the data partition and formats it.
- **Production command line.** Still ignored, except the exact word `install` (ADR). A threat-model entry in SECURITY.md covers it.

### S1b — Self-installing ISO · M

**Work**
- The menu and `esp.img` module in `mkiso.sh`.
- `install` mode in the kernel: target selection, countdown, writing, read-back verification, power-off.
- A shared GPT writer used by first boot and install, specified in DISK-FORMAT.md, with a test that the installer's bytes equal `mkraw.py`'s for the same ESP.
- DEPLOY.md: install from CD/ISO in Proxmox or KVM, and from a USB stick on bare metal (UEFI, and BIOS on x86).

**Tests**
- Host: GPT writer against `mkraw.py` output (byte-identical); target selection rules.
- Smoke:
  - `install-vm`: the ISO as a CD plus an empty virtio-blk disk. Install, power-off, then boot from the disk alone: first boot, `URMQTT READY`, and the CD untouched;
  - `install-two-disks-refused`: nothing written, both listed;
  - `install-scsi`: the target is a virtio-scsi LUN;
  - `install-crash`: power cut while writing, so the disk does not boot, then a reinstall succeeds;
  - `install-prod-cmdline`: a prod image honours `install` and ignores every other word.
- **Bare metal (X12):** a USB stick on the Intel PC, by UEFI and by BIOS, onto its internal NVMe or SATA disk (after X13), followed by a boot from the internal disk.

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
- **Single-disk model, part 1 (§2a):**
  - boot-disk identification;
  - the first-boot GPT steps and the data partition (layout v1 inside the partition; v2 follows in S2);
  - classification of the data partition: valid, damaged (refused; S5 restores), or new (formatted);
  - the self-test only inside the data partition;
  - `urmqtt-disk info` shows the GPT, the partition and the layout.

**Tests**
- **Round trip:**
  1. Boot a VM, publish telemetry, create sessions, stop.
  2. `verify` is clean, and `export-db` opens in the host `sqlite3`.
  3. `export-telemetry` matches what was published.
  4. `import-devices`, then boot: the devices are present.
- **Single disk:**
  - smoke `first-boot` (image on a larger disk: backup GPT moved, GUID changed, partition created, formatted);
  - `first-boot-crash-N` (a crash after each write, then a clean recovery);
  - `second-disk-untouched` (an extra disk is byte-identical afterwards);
  - `iso-as-cd-refused` (prod, read-only media);
  - `own-damaged-refused`.
- A GPT fuzz target (headers and entries, primary/backup disagreement).
- Fuzz targets for the scanner and the host-side parsers (shared code, so the existing targets cover most of it).

**Status: done** (docs/PROGRESS.md, S1; ADR-051). Deviations from the work list:
- **No `std` feature needed:** `crates/store` builds for the host as it is. The host backend is `urmqtt-disk`'s file device under the same VFS, the same amalgamation and the same compile options.
- **`create` and `update-boot`:**
  - `create` writes a boot image (mkraw-identical) on a disk of the requested size, since under the single-disk model a blank data disk is never used.
  - `update-boot` (from §2a) is in S1 already, because `make run` and the KVM installer need it.
- **Host fault runner:** `scripts/fault-loop.sh` waits for its first procedure, the S2 migration. The fault device and a Rust test that cuts every first-boot write exist now.
- **Read-only media:** `iso-as-cd-refused` runs as `iso-as-cd`. A dev image runs memory-only and says why; the production refusal is the existing `storage.require_data_disk` rule.

**S1b status: done** (docs/PROGRESS.md, S1b; ADR-052). Deviations:
- **No `storage.install_target`:** with several candidates the installer refuses and lists them. Detach the others.
- **Write order hardened:** the backup at the disk's end is cleared first, and the primary header is written last. The first boot repairs a missing backup.
- **The SCSI target is tested next to the CD on the same virtio-scsi bus.**
- **Production command line:** a host test covers it instead of a separate production smoke image.
- **Bare metal:** UEFI and BIOS on the Intel PC remain X12.

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

**Status: done** (docs/PROGRESS.md, S2; ADR-140, ADR-141). Deviations from the work list:
- **Topology:** virtio-blk `F_TOPOLOGY` and the virtio-scsi READ CAPACITY (16) and Block Limits VPD are read. NVMe and ATA are deferred to X13.
- **4096/4096:** QEMU cannot boot the 512-byte GPT image through 4096-byte blocks, so that case is a host test on a strict 4Kn device; the kernel refuses a 4Kn boot disk with a message.
- **Migration:** the telemetry ring stays in place (4 KiB aligned, not 1 MiB) instead of being copied; the small live files move into aligned regions carved from the old database region's dead tail, so no free space beyond the old layout is needed (ADR-141).
- **Statsd reason:** the v1 refusal happens before the network is up; the reason is the log token `storage: refused reason=layout-v1`, not a datagram.
- **G8** (boot time grows with the telemetry region) is not done; it moves to S6.
- **Telemetry segments carry the layout UUID** (not in the plan; fixes stale segments surfacing after a reformat or a grow).
- **`scripts/fault-loop.sh`** exists now (`migrate` and `grow`), with `urmqtt-disk --fault` as its hook.

### S3 — Growing the disk · M

**Work**
- **Boot-time grow:** when capacity exceeds the layout size, grow. Online grow through a virtio-blk config-change interrupt, if QEMU `block_resize` delivers it (**to verify**); otherwise boot-time only, documented.
- **The update is crash-safe** (ADR: an A/B superblock pair vs a journaled superblock). New space is split by `grow_ratio_db` between the SQLite main region and telemetry; WAL and journal sizes stay. Data does not move unless unavoidable, and then only by copy-then-switch with recovery.
- **Never shrink automatically.**

**Tests:** grow 1 GiB → 4 GiB → 64 GiB with data present; fault injection at every write of the grow procedure always yields the old or the new layout, never a corrupt one.

**Status: done** (docs/PROGRESS.md, S3; ADR-142, ADR-143). Deviations:
- **Online grow works** on virtio-blk: QEMU's `block_resize` raises the configuration-change interrupt (verified on HVF and TCG, both architectures). A virtio-scsi LUN is not notified and is taken up at the next boot.
- **Crash safety** is the A/B superblock pair (ADR-142): the layout part of a grow is one block write; the partition table steps are the S1 primitives plus the extension of the data partition.
- Telemetry grows by **bands** (one per extent), the database by extents; nothing moves.

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

**Status: done** (docs/PROGRESS.md, S4; ADR-150, ADR-151). Deviations from the work list:
- **Commands:**
  - virtio-blk `F_DISCARD` and `F_WRITE_ZEROES`, and virtio-scsi UNMAP and WRITE SAME (16), are implemented. NVMe and AHCI stay with X13: the store's `BlockDevice::discard_caps` and `discard` are the seam.
  - DISCARD is used when present. Zeroing that may unmap is the fallback; zeroing that would write is never used.
- **"Space freed by rebalance"** does not exist (there is no rebalance); the three uses are retired telemetry segments, the logical tail of a truncated or deleted VFS file, and the space a grow adds.
- **Retention** did not free anything before S4 (expired records were only skipped on restore, the ring reused the oldest segment). It now retires whole expired segments (once a minute), which needs a wall clock.
- **Retirement zeroes the segment header first** (found by the smoke test: a qcow2 releases whole clusters only, so the first cluster of a range kept the old header).
- **The VFS zero-fills a gap** (a write past the end, a truncate to a larger size), so a file never exposes what the disk held there.
- **The check "by the file's allocated size"** is done on what the qcow2 maps as data (`qemu-img map`) and on the host file's allocated blocks (`st_blocks`): both shrink on aarch64 HVF and x86_64 TCG, with virtio-blk and virtio-scsi, on this macOS host (QEMU punches holes on APFS). A Linux host was not run.
- **Not covered by a smoke scenario:** `storage.discard = "off"` in a VM (the baked configuration is the dev one; the schema and the host tests cover "off").

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

**Status: done** (docs/PROGRESS.md, S5; ADR-160 to ADR-163). Deviations from the work list:
- **The backup region is not in the formatter's plan:** a disk formatted before S5 has no free space, so the region is carved from the database's unused tail by one superblock write at boot (layout v2.0 becomes v2.1, a minor version in the formerly reserved superblock word), for new and old disks alike (ADR-160).
- **`VACUUM INTO` was measured out:** this SQLite build has `SQLITE_MAX_ATTACHED=0` and it fails; the backup API in 16-page steps is used (ADR-161).
- **A restore mark** in a control block makes an interrupted restore finish at the next boot (not in the work list).
- **`auto_restore` defaults to true** (ADR-163).
- **Not covered by a smoke scenario:** `auto_restore = false` in a VM (host and schema tests only). Off-disk backup copies are the operator's (`urmqtt-disk backup-extract`).

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
