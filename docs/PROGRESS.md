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

## PERF - memcpy/memmove/memset on x86_64 (2026-10-31)

Diagnostic re-run on the Contabo VPS (169.58.184.193, KVM, AMD EPYC family 23 model 1), ADR-200 for the rest.

**Diagnostic, main at f0c1908 (nistz256, MULX/ADX X25519), against the first run (g4ecb512)**

| | g4ecb512 | f0c1908 run 1 | run 2 | run 3 |
|---|---|---|---|---|
| mutual-TLS handshake | 1.2 ms | 236.7 us | 224.7 us | 242.8 us |
| X25519 | 146 us | 47.3 us | 49.4 us | 44.1 us |
| ECDSA sign | 673 us | 35.0 us | 33.6 us | 33.9 us |
| ECDSA verify | 309 us | 89.1 us | 90.3 us | 85.4 us |
| AES-GCM | 930 MiB/s | 844 | 813 | 927 |
| memory copy / read / write MiB/s | 5380 / 10.9k / 8789 | 4387 / 9079 / 6884 | 537 / 7093 / 1221 | 2193 / 5713 / 5983 |

The memory figures vary by up to 10x between runs on this shared host and say nothing about the code; the crypto figures are stable to about 10%. A fourth run with the ADR-200 code: handshake 237.3 us, X25519 48.3, sign 33.7, verify 90.0, AES-GCM 915 MiB/s, copy 4649, read 9967, write 7228 MiB/s. The disk benchmark was skipped at the WIPE prompt each time (nothing typed). Video of a run: scratchpad `vps-diag.mkv` (1280x800, 20 fps, lossless H.264, 72 s; the VNC server sends an update only when the screen changes, so the 1440 frames hold 4 distinct pictures; the first seconds of boot are not in it, the VNC port refuses connections while Contabo reinstalls).

**Where memcpy/memset time went (before)**: see ADR-200. Server side, share of the time: handshake 7.1%, TLS records (rx+tx) 39% (64 B) to 13% (4 KiB), fan-out 17 to 34%.

**Done**: assembly `memcpy`/`memmove`/`memset` (`crates/arch-x86_64/src/mem.rs`), `memprof` build (`crates/kernel/src/memprof.rs`, `--features memprof`, `test=dp-bench`), differential tests.

**After (same boot, best of 15, old to new)**: handshake -17.7% (278.8 to 229.4 us server side); records 64/256/1024/4096 B -26/-20/-16/-7%; fan-out -7% to -34%. Per call, 1 to 64 bytes 55-75 cycles to 7-12.

**Tests**: `cargo test -p urmqtt-arch-x86_64 mem::` 3 passed on Rosetta (x86_64-apple-darwin) and on an AMD EPYC 9354P (Linux); `make check` rc=0 (fmt, typos, arch-leaks, clippy host + aarch64 + x86_64 kernels with and without selftest, `cargo test --workspace`), run in an out-of-tree copy because the aarch64 kernel does not build inside this nested worktree (two cargo configs both set `-Zbranch-protection`); the `memprof` feature itself is not linted. aarch64 untouched (the module is `cfg(target_arch = "x86_64")`).

**Not done**: non-temporal stores (no evidence they help; ADR-200); `make bench`/dp-bench throughput before and after (the memprof A/B stands in for it: the in-guest handshakes/s was not rerun); the aarch64 build was only compiled and linted, not run; the x86 smoke suite was not rerun; Miri cannot run the assembly.

## H9 — Supply chain and compliance readiness (2026-10-31)

docs/SECURITY-PLAN.md H9. ADR-190 (SBOM), ADR-191 (cargo-vet), ADR-192 (cargo-deny and the scheduled job), ADR-193 (vulnerability handling). No kernel or crate code touched; `deploy/prod/config.toml` untouched.

**Done**

- **SBOM** (`scripts/sbom.py`, `make sbom`): CycloneDX 1.5; 215 components at this commit (73 linked into a kernel, 26 build-time, 86 host-only, 29 workspace crates, Limine). Rust crates carry the `.crate` SHA-256 from `Cargo.lock`; SQLite 3.54.1, Limine 12.9.4 (every file), the nistz256 assembly (ring 0.17.14 ancestor) and the three patched crates (tree hash plus crates.io ancestor) carry hashes **recomputed from the files and compared** with `CHECKSUMS` / `vendor/README.md` (a mismatch aborts). Deterministic (two runs identical). `make dist` / `dist-universal` write it before `SHA256SUMS`; the release workflow attests it with `actions/attest-sbom` (pinned v4.1.0) next to the provenance.
- **cargo-vet** (`supply-chain/`, `cargo vet --locked` passes: 39 fully audited, 140 exempted): audits imported from Google, Mozilla, Bytecode Alliance, ISRG, Zcash, Embark (two further sources were tried and dropped: they covered nothing). `audit-as-crates-io = false` for the patched vendored crates. **Honest state:** of 67 kernel-linked third-party crate versions, 14 are covered by imported audits and **53 are exemptions** (mostly RustCrypto and rustls); no audit of ours was written. Listed by role in `docs/audit/vet-exemptions.md` (generated by `scripts/vet-exemptions.py`, checked in CI) and explained in `docs/SUPPLY-CHAIN.md`.
- **cargo-deny:** `deny.toml` now states `unmaintained = "all"`, `unsound = "all"`, an empty `ignore`; passes on the current tree (advisories, bans, licenses, sources; the fuzz lockfile for advisories). CI also checks the fuzz lockfile. New `.github/workflows/advisories.yml`: daily, opens one issue on failure. `make supply-chain` runs vet, deny and the SBOM check.
- **CI:** new job `supply-chain` (cargo-vet via `taiki-e/install-action`, exemption list check, `sbom.py --strict --check`).
- **Docs:** `docs/VULNERABILITY-HANDLING.md` (intake, triage with severity targets, fix, release, disclosure, supported versions, support period, CRA alignment, not legal advice, the reporting clock), `docs/SUPPLY-CHAIN.md`, links from SECURITY.md, AUDIT.md, DEPLOY.md, README, CHANGELOG, SECURITY-PLAN.

**Ran**

- `scripts/sbom.py` (output inspected; deterministic; `--strict --check`), `cargo vet --locked`, `cargo vet regenerate imports` and `prune`, `cargo deny check advisories bans licenses sources` and the fuzz lockfile (network), `actionlint` (clean), YAML parse of the three workflows, `typos`.
- `make check`: fmt, typos, fuzz fmt, arch-leaks, `cargo vet --locked`, host clippy ran as a whole. The two aarch64 kernel clippy runs and `make check-x86` and `cargo test --workspace` (689 passed, 0 failed) were run separately, the aarch64 ones with `RUSTFLAGS` set by hand: in this nested worktree the two cargo configs both set `-Zbranch-protection` (the known issue from S6).
- Installed: `cargo-vet` 0.10.3 (`cargo install --locked`). `cargo-cyclonedx` was not needed (ADR-190).

**Not run / not done**

- **Only on GitHub:** the `supply-chain` CI job, the scheduled `advisories.yml` (including its issue step), `actions/attest-sbom` and the release workflow's SBOM step, the `gh attestation verify` command in SUPPLY-CHAIN.md. None ran here; `actionlint` and a YAML parse are all the checking they have had. A real tag (`make dist` end to end, which needs xorriso and the ISO build) was not run: the SBOM line was only exercised through `make sbom` and `sbom.py`.
- The SBOM was not validated against the CycloneDX JSON schema (needs a download), only by the script's own checks.
- `scripts/audit-inventory.py --check` reports `docs/audit/inventory.md` and `unsafe.md` out of date in this worktree; this is not caused by H9 (no source changed), is not fixed here, and was not investigated further.
- No audit of our own was written for any crate; the 53 TCB exemptions stand. Audits of the fuzz workspace's dependencies were not made (not shipped).
- A negative test of the advisory gate (a lockfile with a known-vulnerable crate failing `cargo deny`) was not run; it relies on cargo-deny's documented behaviour.
- The vulnerability process has not been exercised on a real or seeded report. The CRA dates and reporting steps are the maintainers' reading from memory of the regulation, not checked against the text; the reporting platform details are explicitly left open. No support period is promised.
- `deploy/prod/config.toml` untouched; no prod image built.

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
