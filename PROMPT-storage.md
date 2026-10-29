# urMQTT — Storage tooling, disk layout v2, resize, discard, backup, scrub and encryption at rest

> This document extends `PROMPT.md` (and coexists with `PROMPT-x86_64.md`). Everything in `PROMPT.md` still
> applies: working method, code rules, ADRs, PROGRESS entries, "verify, don't assume", "never fake progress".
> Put this file in the repo root.

---

## 0. Context and working agreement

urMQTT keeps persistent state on a separate data disk **without a filesystem**: a superblock with a region
table, an A/B file-size table, fixed regions for the SQLite main DB, WAL and journal, per-core telemetry
partitions and a scratch area (see `README.md` → Persistence, `crates/store`, `docs/DECISIONS.md`).
This is the right design and stays. This work removes the practical downsides of a raw disk and hardens it.

Before writing code, read `crates/store` completely, the related ADRs and the crash tests (`test=db-crash`,
`test=log-crash`, `test=log-tear`).

Rules specific to this work:

- **Communicate with the user in Croatian.** Code, comments, commits and docs in English.
- Milestones **S0 … S8**, same discipline: `make check` + `make smoke` green, commit `S<n>: <summary>`,
  PROGRESS entry, ADRs, then stop and report.
- **Never format over a non-blank disk** (existing rule). Never lose data silently. Every on-disk format change
  bumps the layout version and comes with a migration path and tests.
- **The data-disk format is architecture independent** (explicit little-endian, fixed-width fields). If the x86_64
  work (`PROMPT-x86_64.md`) is in progress, keep the cross-architecture data-disk test green and coordinate
  format changes with it; do not let the two efforts diverge.
- **No new network attack surface.** Nothing in this document adds a port, a protocol or a remote command.
  Host-side tooling is offline only.
- **Crash safety is proven, not assumed.** Every multi-step on-disk update gets fault-injection tests (section 3).
- One parser per format: the kernel and the host tool share the same `store` code for layout, CRC and recovery.

---

## 1. Goals

1. A host-side tool to inspect, verify, export, import and create data disks (`urmqtt-disk`).
2. Layout v2: alignment to device topology, explicit and fully documented byte-level format.
3. Growing the disk (cloud volume resize) without losing data.
4. Discard / write-zeroes for thin-provisioned cloud volumes.
5. In-disk backup of the SQLite database with automatic restore on corruption (configurable).
6. Background scrubbing of telemetry and database integrity.
7. Optional encryption at rest with **measured** overhead.

---

## 2. Milestones

### S0 — Audit and specification (no format change)

- Write `docs/DISK-FORMAT.md`: byte-level specification of the current layout (every structure, field, offset,
  endianness, CRC coverage and salting, A/B rules, recovery algorithm, invariants).
- List gaps against the goals of this document in `PROGRESS.md`.
- Add golden test vectors: small disk images (or generators) of the current format checked by host tests.
- Accept: spec reviewed against code (every field in code appears in the spec and vice versa).

### S1 — Host-buildable store core + `urmqtt-disk`

- Split `crates/store` so layout, superblock, region table, file-size table, CRC-32C, telemetry record format and
  recovery compile for the host (`std` feature) as well as for the kernel. The SQLite VFS gets a second backend
  over a host file. The host build uses **the same vendored SQLite amalgamation and compile options** as the kernel
  (not a different system SQLite), so file formats and behaviour match.
- New crate `tools/urmqtt-disk` (std, offline, works on macOS and Linux, on raw images and block devices,
  read-only by default):

| Command | Does |
|---|---|
| `info <disk>` | layout version, uuid, region table, sizes, fill levels, last clean shutdown, encryption status |
| `verify <disk>` | superblock and A/B tables, CRC of every telemetry record, SQLite `integrity_check`; non-zero exit on errors |
| `create <file> --size <N>` | blank sparse image (same result as first boot would produce, or deliberately blank; document which) |
| `export-db <disk> <out.db>` | consistent copy of the SQLite DB (applies WAL) to a normal `.db` file |
| `export-telemetry <disk> --format csv\|jsonl [--from --to --topic]` | streams telemetry records out |
| `import-devices <disk> <devices.csv>` | offline provisioning of the device registry using the kernel's schema and migrations (requires `--write`) |
| `migrate <disk>` | offline layout migration (S2), requires `--write`, keeps a rollback copy of changed metadata |
| `backup-extract <disk> <out.db>` | extracts the in-disk backup (S5) |

  `--key <file>` for encrypted disks (S7). All writes need an explicit `--write` flag.
- Accept: round trips — boot VM, publish telemetry and create sessions, shut down, `verify` clean, `export-db`
  opens in `sqlite3`, `export-telemetry` matches what was published; `import-devices` then boot → devices
  present. Fuzz targets extended for any new parser.

### S2 — Layout v2: alignment and topology

- Read device topology: virtio-blk `blk_size` and `VIRTIO_BLK_F_TOPOLOGY` (physical block exponent, alignment
  offset, min/optimal I/O size); virtio-scsi block limits VPD where available.
- Align every region to 1 MiB and to the optimal I/O size; align telemetry segment writes to the physical block
  size (at least 4 KiB). No write may straddle a physical block unless unavoidable (document exceptions).
- Layout version 2 with a migration path from v1. Decide in an ADR between: kernel reads v1 and v2 and migrates in
  place crash-safely at boot, or kernel refuses v1 with a clear message and `urmqtt-disk migrate` converts offline.
  The project is pre-alpha, so the simpler correct option is acceptable; justify it.
- Accept: QEMU with `physical_block_size=4096,logical_block_size=512` and with 4096/4096 — no misaligned writes
  (add a debug counter that the smoke test checks); migration test from golden v1 images.

### S3 — Growing the disk

- At boot, detect `capacity > layout size`. Additionally handle virtio-blk **config-change notification** for online
  resize if feasible (verify QEMU `block_resize` support); otherwise boot-time only, documented.
- Grow by updating the region table crash-safely (A/B or journaled superblock; ADR). Policy (configurable): new
  space goes to the telemetry ring and the SQLite main region by ratio; WAL and journal keep their size unless
  configured. Existing data never moves if avoidable; if it must, use a copy-then-switch scheme with recovery.
- **Never shrink automatically.** Shrinking only offline via `urmqtt-disk` if implemented at all.
- Accept: grow from 1 GiB → 4 GiB → 64 GiB with data present; fault injection at every write of the grow
  procedure (section 3) always ends in either the old or the new layout, never in a corrupt one.

### S4 — Discard and write-zeroes

- Use `VIRTIO_BLK_F_DISCARD` / `VIRTIO_BLK_F_WRITE_ZEROES` (and SCSI UNMAP / WRITE SAME on the virtio-scsi path)
  when offered: on retired telemetry segments, on regions freed by grow/rebalance, and on the logical tail when the
  SQLite VFS truncates (`xTruncate`).
- Respect device limits (max discard sectors, segment count, alignment). Batch and rate-limit discards so they never
  delay commits. Config `storage.discard = "auto" | "off"`.
- Discarded ranges must read as "don't care": recovery must never trust their content (CRC + sequence salting
  already protect telemetry; verify for every region type).
- Accept: QEMU qcow2 backing file with `discard=unmap` shrinks on the host after telemetry retention runs (smoke
  checks the file's allocated size); no throughput regression in `db-bench`.

### S5 — In-disk backup of the database

- A backup region with two slots (A/B). The DB core periodically writes a consistent snapshot of the SQLite DB into
  the older slot (SQLite online backup API or `VACUUM INTO` through the VFS), then marks it valid with a header
  (sequence, timestamp, CRC/hash, schema version). Interval and enable flag in config.
- Snapshots must not stall the data plane: incremental backup steps between batches, bounded time per step.
- On boot, if `quick_check` fails on the main DB and a valid backup exists: if `storage.auto_restore = true`,
  restore it and log loudly what was lost (time window); otherwise refuse to serve as today.
- Document how this relates to provider volume snapshots (crash-consistent, already covered by the kill -9 tests).
- Accept: corrupt the main DB region deliberately (test mode) → restore from backup works and is logged; fault
  injection during backup never invalidates the previous good slot.

### S6 — Scrubbing

- Background scrubbing on the DB core when idle: re-read telemetry segments and verify CRCs; periodically run
  `PRAGMA quick_check` (bounded, incremental if possible); verify backup slot headers.
- Report via statsd (`urmqtt.scrub.*`) and syslog. Configurable interval and I/O budget so scrubbing never competes
  with commits.
- Accept: injected bit flips in telemetry and DB regions are detected and reported; scrubbing I/O stays within budget
  during a load test.

### S7 — Encryption at rest (optional, off by default)

- Config: `storage.encryption = "off" | "aes-256-xts"` and `storage.disk_key = "disk.key"` (file in `deploy/<env>/`,
  never committed, **separate from the TLS key**). The build fails if encryption is on and the key is missing or weak.
- Everything except the plaintext superblock is encrypted per physical block (4 KiB) with **AES-256-XTS**, tweak =
  block number. The superblock holds a key-check value (e.g. HMAC of a constant), never the key.
- Use the crypto dispatch framework (`PROMPT-x86_64.md` 6.2): ARMv8 AES on aarch64, AES-NI/VAES on x86_64. If no
  hardware AES is available, evaluate **Adiantum** (ChaCha12 + AES-256 single block + NH/Poly1305, designed for
  CPUs without AES instructions) as the fallback mode, or refuse encryption with a clear message; decide in an ADR.
  Never fall back silently to slow table-based AES.
- Encrypt in the I/O path of the DB core (batched commits, telemetry flush), never on data-plane cores.
- The SQLite page cache and the telemetry buffers stay plaintext in memory; only disk content is encrypted.
- Document limits in `SECURITY.md`: protects stolen volumes and volume snapshots, **not** a stolen ISO (the key is in
  it); XTS gives confidentiality, not integrity (existing CRCs detect accidental corruption, not tampering);
  key rotation = offline re-encryption with `urmqtt-disk rekey`.
- `urmqtt-disk` supports `--key` for all commands and adds `rekey` and `encrypt`/`decrypt` (offline, `--write`).
- **Measure and report** (aarch64 HVF, and x86_64 KVM when available): XTS throughput per core per implementation,
  `db-bench` commits/s, telemetry MB/s, `make bench` handshake/message numbers, boot time, with encryption off vs on.
- Accept: all storage smoke tests pass with encryption on; wrong key → clear refusal at boot; overhead on end-to-end
  throughput ≤ 5 % on hardware with AES instructions (if not met, report why and what dominates).

### S8 — Documentation and hardening

- `docs/DISK-FORMAT.md` final (v2, backup region, encryption), `docs/DEPLOY.md` (resize procedure per provider,
  snapshots, backup/restore, export), `docs/SECURITY.md` (encryption threat model), README features table.
- Fuzz targets: superblock and region table (v1 and v2), migration input, backup slot header, encrypted-block
  decoding with wrong keys. Golden images for every layout version in the test suite.
- Accept: docs match code; all fuzz targets run in CI.

---

## 3. Fault-injection framework (build it in S1, use it everywhere)

- A dev/test-only block-device wrapper in the kernel that can: stop the VM after the N-th write or flush, tear a write
  (persist only the first K sectors), drop a flush, or flip bits in a read. Controlled from the dev command line
  (e.g. `test=disk-fault:after-write=37`), compiled out of prod images.
- A host-side runner that loops N over every write of a procedure (grow, migrate, backup, rekey) and checks that the
  disk always recovers to a valid state with no committed data lost.
- The host tool's own writes use the same wrapper in tests.

---

## 4. Configuration additions (validated by `config-schema`)

```toml
[storage]
discard = "auto"            # "auto" | "off"
grow = "auto"               # "auto" | "off"
grow_ratio_db = 0.25        # share of new space for the SQLite main region (rest to telemetry)
backup_interval_min = 60    # 0 = off
auto_restore = false        # restore DB from in-disk backup on corruption
scrub_interval_h = 24       # 0 = off
scrub_io_budget_mb_s = 20
encryption = "off"          # "off" | "aes-256-xts"
disk_key = ""               # file in deploy/<env>/ when encryption is on
```

---

## 5. Definition of done

- `urmqtt-disk` can inspect, verify, export, import and migrate disks on macOS and Linux, sharing code with the kernel.
- Layout v2 aligned to device topology, fully specified in `DISK-FORMAT.md`, with migration from v1.
- Disks grow safely; discard works on thin-provisioned volumes; in-disk backup with optional auto-restore; scrubbing.
- Optional AES-256-XTS encryption at rest with measured overhead and documented limits.
- Every multi-step on-disk operation proven crash-safe by fault injection; data disks portable across architectures.

Start with **S0**. Before writing code, reply in Croatian with: your understanding in 5–8 bullet points, the current
layout as you read it from the code (short), risks you see, and the exact plan for S0–S1.
