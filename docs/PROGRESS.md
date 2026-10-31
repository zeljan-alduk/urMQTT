## H4 — Exploit mitigations (2026-10-31)

SECURITY-PLAN H4, in the order of the plan, one commit and one ADR per step. First release is VPS (KVM) only: **H4b (IOMMU) is deferred** (bare metal), recorded in ADR-176.

**Steps (one commit, one ADR each; steps 4 and 5 share a commit)**

1. Allocator hardening, key slab, zeroisation (ADR-170): poison on free (used part, up to 16 KiB in the buddy heap), checked on reuse; double/invalid-free detection (allocation bitmap, ancestor free bits, per-block tags in the per-CPU caches); XOR-obfuscated free-list links with safe unlinking; canary gap behind large allocations; `KeySlab` (volatile zero on free, generation-checked handles); `Csprng` wiped on drop; PAC key copy wiped. Boot seed from the bootloader's entropy, the CPU's RNG and the counter.
2. Stack protector (ADR-171): `-Zstack-protector=strong` (1315 protected functions), `-fstack-protector-strong` for SQLite, one `__stack_chk_guard` renewed from the seed and then from the CSPRNG inside `kmain_stage2`, `.got` placed in the data segment.
3. Fault policy (ADR-172): production reports have no registers, memory, absolute addresses or formatted panic messages; dev unchanged; `redact` word and open controls; hooks `selftest`-only, `scripts/check-prod-hooks.sh`.
4. KASLR (ADR-173): PIE kernel on both architectures slid by Limine (30/30 and 16/16 distinct slides, about 19 bits), random places for heap (12 bits), bookkeeping, stacks, page-table alias (21 each) and MMIO window (9); logs show bits, addresses in dev only.
5. MTE (ADR-174): heap mapped Normal Tagged, synchronous checking, random tags 1..14, free = tag 0; tested under TCG `mte=on` (`URMQTT_MTE=1`).
6. kCFI (ADR-175): evaluated, not adopted (rustc ICE on `der`/`spki`). H4b IOMMU deferred (ADR-176).

**Tests**

- `cargo test -p urmqtt-mm` 40 (was 12), `crates/tls/tests/zeroize.rs`.
- Smoke `SMOKE_ONLY=hardening` (see SECURITY-PLAN H4 status): aarch64 HVF and x86_64 TCG; MTE scenarios aarch64 TCG. The default suite ran on the PIE kernel: aarch64 HVF 43 passed and 1 stale pattern (`stack-overflow` faults on a read now; pattern fixed), x86_64 TCG 23 passed before it was stopped (TCG TLS scenarios take ~15 min each) and 1 stale pattern (`RIP=0xffffffff8`; fixed).
- Handshake path (`dp-bench`, aarch64 HVF, 1/2/4 cores): base 1941/3854/7620; allocator 1898/3768/7429; plus stack protector 1845/3672/7243; with PIE and the tagging code (loaded machine, noisy) about 1800/3480/6750.

**Not done**

- HHDM base randomisation; hardware heap guard pages; asynchronous MTE and a production switch; tagging of the SQLite arena and DMA buffers; kCFI; H4b. `make bench`'s network half, KVM and real hardware were not run.
- The nested worktree needs `RUSTFLAGS` set by hand to build the aarch64 kernel (two cargo configs); `make print-rustflags` prints the flags to add.

## S6 — Scrubbing, and G8 (2026-10-31)

PROMPT-storage.md S6, plan in docs/STORAGE-PLAN.md (status and deviations there). ADR-164 (what the scrubber reads, how it tells torn writes from rot, pacing), ADR-165 (bounded boot, G8, and the retention bound). No format change.

**Done**

- **Scrubber** (`crates/store/src/scrub.rs`, `telemetry.rs`): a pass over the database (`PRAGMA quick_check(table)` per table, after `shrink_memory` so the disk is read), the backup region (control block, headers, payload CRC of every snapshot) and every telemetry segment (every record against its CRC). Telemetry findings are classified: **damaged** (a bad record with valid records after it in the same segment: not a torn write), **bad tail** (nothing valid after: what a crash leaves, a warning), **bad header** (segment magic, failing checks: invisible to recovery). A segment reused during the read is not judged.
- **Pacing.** A token bucket (`Pacer`) at `storage.scrub_io_budget_mb_s`, charged with the bytes each step really read (SQLite's included), with debt after a whole-table check. The DB core runs steps only between transactions, never while a backup job runs, and, when busy, at most one 256 KiB step per 100 ms.
- **Config** `storage.scrub_interval_h` (default 24, 0 = off, at most 90 days; first pass 10 min after boot) and `storage.scrub_io_budget_mb_s` (default 8, 1 to 1024): schema, config crate, dev template (bench: off), schema tests, README. `deploy/prod/config.toml` untouched.
- **Reports.** One line per finding (error level, so console, `$SYS/console/out` and syslog), three summary lines per pass, `scrub: pass N FOUND K problem(s)`; statsd gauges `urmqtt.scrub.*` (`errors`, `errors_total`, `age_s`, counts); `urmqtt-disk scrub DISK`. Dev hooks `test=scrub`, `test=scrub-load`, `test=log-fill`.
- **G8.** `TelemetryLog::open` reads every segment header and scans only the newest segment of each partition; older segments are known by their header, with retention using the creation time of the following segment as an upper bound on their newest record, which the scrubber replaces by the exact timestamp. No summary block, no format change. Boot reads headers plus one segment per partition instead of the ring. `Recovery` has `scanned`; the boot log line and the smoke patterns say "in the K newest segment(s) read of S"; the host tool and grow tests count records by a full scan.

**Tests**

- `cargo test --workspace`: 689 passed, 0 failed, 8 ignored. New: `crates/store/tests/scrub.rs` (10): a clean ring counted at three step sizes; injected bit flips in a record payload, in a record's length field, in the last record of the active segment and in a segment header, each found and classified with its position; a torn write is a bad tail and not damage; **a flip on the read path only** (the fault injector, medium intact) is found; a clean disk scrubs clean and reads the database from the disk; structural damage to a table found; a flipped bit in a snapshot payload, a slot header and the control block found; **the budget under load**: a 20 MiB ring scrubbed while a writer appends at 2, 8 and 32 MB/s reads 2044, 8170 and 32630 KiB/s (whole pass and worst second within budget plus one step); **bounded boot**: 18 segments holding 5.8 MiB of records are opened by reading 1.1 MiB; retention from the headers and made exact by the scrub. Pacer unit tests.
- Smoke, final tree, `SMOKE_ONLY=storage`: **aarch64 HVF 79 passed, 0 failed; x86_64 TCG 79 passed, 0 failed** (the whole group: first-boot, first-boot-crash, scsi-boot, iso-as-cd, own-damaged, topology, layout-v1, grow, grow-online, discard-qcow2, db-backup, backup-upgrade, backup-scheduled, backup-bench, scrub-flip, scrub-load, disk-tool; ports 30111/30112).
- New smoke scenarios: `scrub-flip` (two bits flipped on the host in a `test=log-fill` ring: the kernel reports the damaged record and the damaged header with their positions and `FOUND 2 problem(s)`; the host tool reports the same bytes; clean before the flips), `scrub-load` (the telemetry writers of every data core while the first pass runs; the pass read about 7.7 MB in 4.4 s = 1.7 MB/s on HVF against a budget of 8 MB/s, since a busy broker is let through at 2.5 MB/s at most).
- `scripts/fault-loop.sh`: not extended (the scrubber writes nothing).

**Not done**

- Free-list and orphan-page checks of the database (boot only); flipped bits inside database values (SQLite has no page checksums here); a flip in a segment's magic bytes; any automatic repair of a damaged telemetry segment.
- A smoke scenario with a flipped bit in the database or in a backup slot in a VM (host tests only; same code).
- KVM, real hardware, fuzz targets, Miri, `make bench` not rerun. The aarch64 kernel builds in this nested worktree only with `RUSTFLAGS` set by hand (two cargo configs both set `-Zbranch-protection`).
