# Progress log

One entry per milestone: what was done, what was measured and the known gaps.
Milestones are defined in [PROMPT.md §9](../PROMPT.md#9-milestones-and-acceptance-criteria).

## M0 — Workspace and tooling (2026-10-28)

**Done**

- Cargo workspace with every crate from §4.2 (package names `urmqtt-*`, ADR-006), a pinned nightly (ADR-002), the shared release profile (fat LTO, `codegen-units = 1`, `panic = "abort"`, `opt-level = 3`) and a committed `Cargo.lock`.
- Lint policy:
  - `forbid(unsafe_code)` in `mqtt`, `broker`, `timer-wheel` and `config`; `deny(unsafe_code)` elsewhere.
  - `deny(unwrap_used, expect_used, indexing_slicing, panic)` in the data-path crates.
  - `undocumented_unsafe_blocks = deny` workspace-wide.
- `crates/config` with `crates/config-schema` (ADR-005), **fully implemented**:
  - `deploy/<env>/config.toml` is parsed, validated (every key from §12 plus `limits.max_topic_levels`), rendered to typed constants, and the certificates are embedded with `include_bytes!`.
  - Invalid configuration fails the build with every error listed by key path.
  - Plaintext MQTT is rejected outside `dev`.
- `scripts/gen-dev-certs.sh`: dev CA, server certificate, `device-001..003`, plus a rogue-CA device and an expired device for the M10 negative tests. The script self-verifies the chains.
- Makefile: every target from §3 exists. Targets that belong to later milestones exit with status 1 and name their milestone.
- Fuzz target `config_parse` (cargo-fuzz).
- CI on GitHub Actions (ADR-007):
  - lint (fmt, clippy for host and `aarch64-unknown-none`, typos, actionlint, shellcheck),
  - host tests on Linux arm64 and macOS arm64,
  - kernel build for the dev and prod configs,
  - cargo-deny and a 60 s fuzz smoke run,
  - scheduled 10-minute fuzzing, CodeQL and OpenSSF Scorecard,
  - Dependabot, and a tag-triggered release with SLSA provenance.

**Measured**

- `make check`: green on macOS 26.3 / Apple M4 Pro.
- Host tests: 27 (all in `urmqtt-config-schema`).
- `config_parse` fuzzing: 525 257 runs in 21 s, no crash.
- Kernel ELF (release, M0 skeleton): **1 360 bytes**. The number is not meaningful yet, because nothing is linked except the placeholder entry.

**Known gaps (explicit stubs)**

- All crates except `config` and `config-schema` are empty stubs whose docs name their milestone.
- `_start` in `crates/kernel` only parks the CPU. The Limine entry arrives in M1.
- `make iso`, `run`, `run-tcg`, `run-smp`, `debug`, `smoke` and `loadtest` are not implemented yet and exit with status 1.
- `make data-img` creates a blank sparse image only. The superblock/region layout arrives in M11.
- `tools/loadgen` exits with an explicit "not implemented" error. `tools/certgen` (optional) was not created, because `gen-dev-certs.sh` covers it.
- `vendor/limine` and `vendor/sqlite` are empty and get populated in M1 and M11.

## M1 — Boot (2026-10-29)

**Done**

- Vendored Limine v12.9.4 `BOOTAA64.EFI` (GPG-verified, SHA-256 pinned).
- `scripts/mkiso.sh` builds a UEFI-only ISO (ADR-015): no menu, no editor, kernel pinned by BLAKE2b, deterministic timestamps and FAT serial.
- Kernel entry (`crates/kernel/src/boot.rs`):
  - Limine base revision 6 requests (HHDM, memmap, MP, DTB, RSDP, framebuffer, cmdline, date at boot).
  - The asm stub enables FP/SIMD (ADR-003) and switches to SP_ELx.
  - Linker script with three PT_LOADs: RX, R and RW.
- `platform`: panic-free FDT parser and ACPI parser (RSDP, XSDT/RSDT, SPCR, FADT) with early discovery of the console UART and the PSCI conduit. Host tests run against real QEMU DTBs (HVF/TCG, GICv2/v3) and synthetic ACPI tables, including truncation and bit-flip robustness.
- Console:
  - PL011 output-only driver, mapped through an MMIO window (ADR-016), with a dev-only fallback to 0x0900_0000.
  - 8×8 framebuffer text console (ramfb in QEMU).
  - Global logger with uptime timestamps from the generic timer.
- `arch-aarch64`:
  - EL1 vector table that saves the full GPR and FP/SIMD state.
  - ESR decoding (exception class, fault status, WnR, imm16), host-tested.
  - Stage-1 descriptor encoding with W^X by construction, and a table walker/mapper, host-tested.
  - PSCI (version, SYSTEM_OFF, SYSTEM_RESET, CPU_ON), a ticket spinlock and system-register accessors.
- Fault handling:
  - Decoded exception reports (vector, EC, fault status, ESR/ELR/FAR/SPSR, x0–x30).
  - A panic handler that logs, then calls PSCI SYSTEM_RESET, or SYSTEM_OFF in smoke mode.
  - Nested-fault guard.
- `make iso`, `run`, `run-tcg`, `run-smp N=…`, `debug` and `smoke`. CI gains a smoke job (QEMU TCG on arm64 Linux) and the release workflow ships the ISO.

**Measured**

- HVF boot to `URMQTT READY` in about 5 s of wall time, most of it UEFI firmware. QEMU exits through PSCI SYSTEM_OFF.
- `make smoke`: 12/12 pass. Six scenarios run under both HVF and TCG: ACPI boot, DTB boot (`acpi=off`), data abort, undefined instruction, resumable `brk`, panic.
- Exception report sample (HVF):
  `EC=0x25 data abort (same EL), read, translation fault, level 2 … FAR=0xffff80003ffff000`.
- Kernel ELF: **79 280 bytes**. ISO: about 8.8 MB, mostly the FAT image that M17 will shrink.
- Host tests: 64.
- HVF/GIC findings: ADR-014.

**Known gaps**

- The bootloader's page tables are still active. Own W^X tables, guard pages and PAC/BTI arrive in M2.
- Exceptions run on the boot stack. A dedicated exception stack comes in M2, with guard pages.
- Entry at EL2 (VHE) is untested (ADR-018).
- `cpu=` comes from the Limine MP response. The application processors stay parked until M4.

## M2 — Memory (2026-10-29)

**Done**

- `mm` (host-tested, with proptest):
  - Bitmap frame allocator (single frames and aligned contiguous runs; double-free and foreign-address detection).
  - Binary buddy heap, headerless with per-order free bitmaps, behind a spinlock as the kernel `#[global_allocator]`.
- `arch-aarch64`:
  - 2 MiB block mappings, auto-sized ranges, a leaf walker, in-place permission changes.
  - CPU feature decoding (PAuth, FPAC, BTI, RNG, crypto, LSE, MTE, SVE).
  - PAC key programming and an assembly stack switch that enables PAC.
- `kernel/vm`:
  - Own TTBR1 tables with W^X, the HHDM alias of the kernel image read-only, the lower half disabled (EPD0) and WXN on (ADR-019).
  - Per-CPU stack slots with guard pages, exceptions on a separate SP_EL1 stack (ADR-020).
  - Heap mapped from `memory.kernel_heap_mb` (a new config key).
  - Page tables locked read-only at the end of boot, with no writable alias left.
- PAC and BTI enabled when present (ADR-021).
- Boot self-tests:
  - The frame allocator (1000 single frames plus a 16-frame contiguous run, all freed, accounting checked, double free refused).
  - The heap (coalesces back fully).
  - A full W^X audit of all leaf mappings after locking, plus spot checks: text RX, data/heap/stack RW-NX, guard unmapped, page-table alias gone, kernel alias read-only.
- Test switches (dev only): `test=write-text`, `exec-heap`, `stack-overflow`, `null`, `pac`, `bti`.

**Measured** (HVF, 512 MB)

- 45 page-table pages for the whole address space (2 MiB blocks for the HHDM). 442 MiB free after setup. 13 385 leaf mappings audited. Heap 32 MiB.
- CPU features under HVF on the M4 Pro: pauth, fpac, bti, aes, pmull, sha2, lse. No RNDR, no MTE, no SVE.
- `make smoke`: 24/24 (12 scenarios × HVF + TCG). Reports from those runs:
  - write to text: permission fault L3
  - executing heap memory: instruction abort, permission fault L3
  - stack overflow: data abort on the main stack guard page, reported on the exception stack
  - null pointer: translation fault L0
  - PAC forgery: EC 0x1c
  - BTI violation: EC 0x0d
- Kernel ELF: **113 240 bytes** (+34 KB: buddy heap, frame allocator, mapper, branch protection).
- Host tests: 80.

**Known gaps**

- Bootloader-reclaimable memory (about 30 MB at 512 MB) is not reclaimed yet. It still holds the DTB and memmap, which later milestones read.
- The page-table pool rounds up to 2 MiB (about 1.8 MB unused at 512 MB RAM).
- Only the boot CPU's stacks exist; M4 maps the others before the lock.
- MTE is not used (HVF does not expose it).

## M3 — Interrupts and time (2026-10-29)

**Done**

- `platform`: GICv3 and generic-timer discovery from the DTB (`arm,gic-v3`, ITS / GICv2m frames, `arm,armv8-timer` PPIs) and from ACPI (MADT GICD/GICC/GICR/ITS/MSI-frame, GTDT), with host tests on QEMU DTBs and synthetic tables (including zero-length MADT entries).
- `arch-aarch64`:
  - GICv3 driver: distributor, redistributor lookup by affinity (with VLPI stride), wake-up, SGI/PPI/SPI enable and routing, and the system-register CPU interface (IAR1/EOIR1/PMR/IGRPEN1/SGI1R).
  - Generic timer (CNTVCT with `isb`, CNTV deadline programming).
  - `OnceCell`; IRQ save/restore; `idle()` (WFI with IRQs on).
- `kernel`:
  - IRQ dispatch table (handlers only acknowledge and mark).
  - 10 ms periodic tick that re-arms from the previous deadline (no drift), with min/avg/max and log-histogram latency statistics.
  - The logger masks IRQs while it holds its lock, so a handler can never deadlock on it.
  - After `URMQTT READY` the boot CPU idles in WFI with the tick running.

**Measured**

- Under HVF, IRQ latency is 1.9 / 3.9 / 7.8 µs (min/avg/max) while busy-polling and about 1.8 ms average in WFI. Under TCG it is about 2.2 ms in both modes (ADR-022).
- `make smoke`: 24/24, with the boot scenarios checking GIC init, the tick and both latency reports.
- Kernel ELF: **127 784 bytes**.
- Host tests: 85.

**Known gaps**

- Only the boot CPU's redistributor is initialised; the other CPUs join in M4.
- SPIs and MSIs are not used yet (M6, M13).
- The tick is not yet used by the watchdog (M16).
