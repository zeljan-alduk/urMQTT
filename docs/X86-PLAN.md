# x86_64 port: implementation and test plan

Plan for [`PROMPT-x86_64.md`](../PROMPT-x86_64.md) (milestones X0–X11), plus
a bare-metal track (X12–X16). The ISO must also boot and serve **on real
hardware without a hypervisor**, a requirement the user added on 2026-10-29.
The first bare-metal target is the user's Intel x86_64 PC with 16 GB of RAM.
Written 2026-10-29 against commit `2c34019`, before any x86 code exists. It is
part of the overall plan in [PLAN.md](PLAN.md), next to
[SECURITY-PLAN.md](SECURITY-PLAN.md) and [STORAGE-PLAN.md](STORAGE-PLAN.md),
which also sets the order across the three tracks. Every
"verified" statement below was checked in this repository or its pinned
dependencies on that date. Everything else is marked **to verify** and has a
step in the milestone that needs it.

---

## 1. Findings that change the plan

These come from reading the code and the pinned crates. Two of them
contradict assumptions in PROMPT-x86_64.md.

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| F1 | **aarch64 has no hardware crypto path today.** AES-GCM, GHASH and SHA-256 run the portable software code. | `aes` 0.8.4 compiles its ARMv8 backend only with `--cfg aes_armv8` (`src/lib.rs:134`), and `polyval` 0.6.2 likewise needs `polyval_armv8`. Neither cfg is set (Makefile, `.cargo/config.toml`). `sha2` 0.11.1 autodetects through `cpufeatures`. | PROMPT §X0 assumes an "existing AES/PMULL path". There is none, so the dispatch framework gets its first real backends in X0b (below), and aarch64 gets faster in the process. |
| F2 | **RustCrypto runtime detection is disabled on `target_os = "none"`, on both architectures.** | `cpufeatures` 0.2.17: `aarch64.rs:158-166` returns `false` off Linux and Apple; `x86.rs:17-23` returns `false` on `target_os = "none"` ("Freestanding … targets do not support SIMD features with default compilation flags"). `cpufeatures` 0.3.1 behaves the same. | Hardware backends inside the crates are dead code in our kernel unless detection is replaced. Plan: a vendored, patched `cpufeatures` (D2). |
| F3 | `x86_64-unknown-none` is soft-float. | `--print target-spec-json`: `"features": "-mmx,-sse,…,-avx2,+soft-float"`. | FP/SIMD policy decision (D3). SQLite needs FP and the crypto needs SIMD. |
| F4 | Only aarch64 Limine is vendored, and PROMPT.md §2 forbids x86 binaries. | `vendor/limine/CHECKSUMS`: "Limine v12.9.4 … aarch64 UEFI only … no x86 binaries, PROMPT.md §2". | The x86 prompt overrides this. That needs an ADR and new vendored files: `BOOTX64.EFI`, `limine-bios.sys`, `limine-bios-cd.bin`, `limine-uefi-cd.bin`, and the `limine` host tool built from its C source, checksummed. |
| F5 | Limine's config has a built-in `${ARCH}` macro (`x86-64`, `ia-32`, `aarch64`, `riscv64`, `loongarch64`) and `${FW_TYPE}` (`UEFI`/`BIOS`). | Limine `CONFIG.md` (v12.x branch). | One `limine.conf` can select `urmqtt-${ARCH}.elf`. Must still be checked against the vendored v12.9.4 binary in X10. |
| F6 | Arch coupling outside `arch-aarch64` is small and mostly arch-neutral. | `mm`, `log`, `store` and `tls` use only `sync::{SpinLock, OnceCell}`, `paging::{FrameSource, PAGE_SIZE}` and `cpu::irq_save/restore`. Only `kernel` has assembly: `smp.rs` 15 sites, `boot.rs` 14, `vm.rs` 9, `jitter.rs` 8, `dataplane.rs` 6, `netproto`/`devices`/`db` 5 each, `trap.rs` 4, and others ≤ 3. | X0 is a contained refactor: about 20 kernel files plus 4 crates. |
| F7 | CRC-32C is a byte-wise table; Toeplitz is bit-serial. | `crates/store/src/crc.rs:29`, `crates/net/src/rss.rs`. | Both are dispatch candidates on both architectures. |
| F8 | The struct-size asserts are `const` asserts. | 10 `size_of` assertions in the crates. | They hold on x86_64 automatically if layouts match; X8 checks it by compiling, not by trust. |
| F10 | **The data disk is a separate disk today, chosen by "not partitioned".** | `kernel::devices::is_partitioned`. | Single-disk model (PLAN.md decision 6): data lives in a partition of the boot disk and no other disk is touched (STORAGE-PLAN S1, §2a). On the PC that means the image is on the internal disk, not on a USB stick next to it. |
| F11 | **GICv3 ITS (MSI on ARM servers) is not implemented.** Only GICv2m frames are driven. | `kernel/src/devices.rs:552` ("msi-x: not available … blk polled"). | ARM bare metal (Ampere servers) needs an ITS driver (X15). |
| F12 | **Only virtio devices have drivers.** | `crates/virtio`: net, blk, scsi, rng. | Bare metal needs native NIC and storage drivers (X13, X14) and a hardware inventory first (X12). |
| F9 | Local x86 tooling is present. | `qemu-system-x86_64` 11.1.2, `edk2-x86_64-code.fd`, SeaBIOS `bios-256k.bin`, CPU models `EPYC-Milan/Genoa`, `Icelake-Server`; Homebrew LLVM clang. | Bring-up and smoke can start on the M4 under TCG. |

---

## 2. Decisions to take (ADR-040 to ADR-047)

**D1 — Arch facade (ADR-040, X0).** A new crate `urmqtt-arch` re-exports
`arch-aarch64` or `arch-x86_64` per `target_arch`, behind one module list:
`cpu`, `irq`, `percpu`, `time`, `ipi`, `msi`, `paging`, `trap`, `barrier`,
`entropy`, `power`, `features`.

- The API is enforced by a contract file (`crates/arch/src/contract.rs`). It binds every facade item to an explicit function-pointer or type signature, so an architecture that lacks or changes one fails to compile.
- No traits: static dispatch with zero cost, and no generic parameters spread through the kernel.
- The arch-neutral parts of today's arch crate (`sync`, `spsc`, and the pure parts of `paging`'s `FrameSource`) move to a new crate `urmqtt-sync`, so host builds on any architecture get them without the facade.

**D2 — Feature detection and dispatch (ADR-041, X0/X0b).**
- `CpuFeatures` is filled once at boot from ID registers (aarch64) or CPUID/XGETBV (x86).
- The `[cpu] disable = [...]` config list is applied on top, then the result is **sealed**: written once, and the page is read-only once the tables lock.
- A patched `cpufeatures` (0.2.17 and 0.3.1, vendored under `vendor/cpufeatures-*`, wired in through `[patch.crates-io]`) replaces the `target_os = "none"` stub with a call to a kernel symbol, `urmqtt_cpu_has(feature) -> bool`, which reads the sealed set. All RustCrypto backends then obey our detection and the opt-out switch. Host and fuzz builds keep upstream behaviour (`cfg(not(target_os = "none"))`).
- Own primitives (`crc32c`, `toeplitz`) are selected in a neutral `urmqtt-dispatch` crate as `enum` choices fixed at seal time.
- **Alternatives:**
  - Forcing backends with compile-time cfgs (`aes_force_soft`, `sha2_backend`) gives one binary per CPU class. Rejected: PROMPT §6.1.2.
  - Own SIMD crypto. Only where measurement shows a crate is the bottleneck.

**D3 — x86 FP/SIMD policy (ADR-042, decided by the end of X1).** The
proposal mirrors ADR-003 (aarch64: FP/SIMD on kernel-wide, full state saved
on exception entry):
- **A custom target JSON** `targets/x86_64-urmqtt-none.json`. It is hard-float with the x86-64-v2 baseline (`+sse4.2,+popcnt,+ssse3,+cx16`), `disable-redzone`, `code-model: kernel`, static relocation and `panic: abort`. It builds with the `-Zbuild-std` we already use.
- **Boot:** set CR4.OSFXSR, OSXMMEXCPT and OSXSAVE. XCR0 = x87 | SSE | AVX, plus the AVX-512 components only if a dispatched kernel needs them.
- **Exception and IRQ entry:** XSAVEC into a per-CPU area sized from CPUID.0xD, with XSAVEOPT and then FXSAVE as fallbacks. The cost is measured in X4. A cheaper variant (xmm0-15 and MXCSR only, valid because v2-compiled handlers never touch the upper halves) comes only with its own test and ADR.
- **Fallback if the custom target is blocked:** option (b) of PROMPT §5.3, i.e. `x86_64-unknown-none` plus `#[target_feature]` islands. **To verify in X1:** does nightly-2026-10-20 accept `#[target_feature(enable = "sse2,aes")]` on the x86-softfloat ABI? Can SQLite be built soft-float at all?
- **Proof (both options):** a `test=simd-irq` scenario. It runs AES-GCM, ChaCha20-Poly1305, SHA-256 and CRC known-answer tests in a loop for 10 s, with a 10 kHz timer and an IPI storm from all cores, and compares every output.

**D4 — Universal image layout (ADR-043, X10).**
- **ISO:** El Torito BIOS entry (`limine-bios-cd.bin`) and UEFI entry (`limine-uefi-cd.bin`). The ESP holds `EFI/BOOT/BOOTAA64.EFI` and `BOOTX64.EFI`, and `limine bios-install` makes it hybrid.
- **Raw GPT image:** one ESP with both loaders and both kernels. BIOS boot on GPT through `limine bios-install` (**to verify:** does it need a BIOS boot partition, and is the result reproducible?).
- **Kernel names:** `urmqtt-<arch>.elf`, where `<arch>` is Limine's `${ARCH}` spelling. Each path is pinned by its blake2b hash, as today.

**D5 — x86 power control (ADR-044, X2).**
- Reset through the FADT reset register (q35 and pc use port 0xCF9), then the 8042 pulse, then a triple fault.
- Poweroff via ACPI S5 needs `SLP_TYPa` from `\_S5` in the DSDT, which is AML. A minimal, bounds-checked scanner finds the `_S5_` package, and it gets its own fuzz target.
- Smoke mode uses QEMU `isa-debug-exit` (exit code = status). This is a dev-only feature: prod images never write that port.

**D6 — Time (ADR-045, X4).**
- **TSC frequency,** in order of preference: kvmclock (KVM), CPUID 0x15/0x16, then calibration against the HPET, then the ACPI PM timer.
- **Invariant TSC:** if the CPU has none, use kvmclock or the HPET as the monotonic source and log it.
- **Timer:** LAPIC TSC-deadline, or LAPIC periodic as a fallback.

**D7 — CI with KVM (ADR-046, X1).**
- A probe job on `ubuntu-24.04` (x86_64) reports whether `/dev/kvm` exists and opens. GitHub enabled KVM on its Linux runners in 2024, behind a udev rule; this repository's plan is **to verify**.
- With KVM, x86 smoke runs under KVM with `-cpu host` (the runner's real CPU, so real AES-NI, SHA-NI, VAES and AVX2 paths). Without it, it runs under TCG.
- The runner's CPU model is logged in every run, so a number in the docs can always be traced to hardware.

**D8 — CET (ADR-047, X3, optional).**
- IBT via `-Zcf-protection=branch` (**to verify:** flag name and status on the pinned nightly, and that core/alloc built with `-Zbuild-std` get `endbr64`). Supervisor shadow stacks via `IA32_S_CET` and `PL0_SSP`, with shadow-stack PTEs.
- QEMU TCG does not emulate CET (**to verify in X2**), so this needs KVM on Tiger Lake+ or Zen 3+ with CET exposed. Scenarios without that hardware report "skipped".

---

## 3. Milestones

Each milestone ends as the prompt requires:
- `make check` and `make smoke`, for both architectures once x86 boots;
- an aarch64 non-regression report (smoke under HVF and TCG, `make bench` within noise, bytes per idle connection, ELF size before and after);
- commit `X<n>: …`, a PROGRESS entry and ADRs, then stop and report.

Relative size: S = a few days of work, M = a typical M-milestone, L = larger.

### X0 — Arch facade and dispatch (aarch64 only, no behaviour change) · M

**Work**
1. Create `crates/sync` (move `sync`, `spsc`) and `crates/arch` (the facade with `contract.rs`). Point `mm`, `log`, `store` and `tls` at `urmqtt-sync` and `urmqtt-arch`; they then no longer depend on `urmqtt-arch-aarch64`.
2. Kernel: move the assembly into `arch-aarch64`, then make the call sites use the facade. By file:

   | File | What changes |
   |---|---|
   | `boot.rs` | entry `global_asm!`, CPACR, PAC key |
   | `smp.rs` | AP trampoline and `ApBoot` become `arch::percpu::start_secondary(...)` |
   | `vm.rs`, `memory.rs` | TTBR/TCR/MAIR and the descriptor format go behind `arch::paging::{Builder, audit, lock}` |
   | `jitter.rs` | PMU clock becomes `arch::time::finest_clock()` |
   | `trap.rs` | ESR decode becomes `arch::trap::Report` with a `Display` impl; `brk`/`udf` move to `arch::trap::test_*` |
   | `irq.rs` | GIC code goes behind `arch::irq` |
   | `devices.rs` | GICv2m becomes `arch::msi::compose(cpu, vector) -> (addr, data)` |
   | `power.rs` | PSCI goes behind `arch::power` |
   | `dataplane.rs`, `db.rs`, `netproto.rs`, `mqtt_service.rs` | `cpu::wfi` becomes `arch::cpu::idle`, `timer::uptime_ns` becomes `arch::time::uptime_ns` |

3. `crates/dispatch` with `CpuFeatures` (aarch64: ID_AA64ISAR0/1, PFR0, DFR0) and the selection table. It includes the `[cpu] disable` config key with schema validation. Boot log line: `crypto: aes-gcm=soft ghash=soft chacha=soft sha256=soft crc32c=table toeplitz=bitwise`, which honestly reflects F1.
4. `scripts/check-arch-leaks.sh` in CI fails on `asm!`, `global_asm!`, `mrs`/`msr`, `_EL[0-3]`, `daif` or `tpidr` outside `crates/arch-aarch64`. Later it also covers `rdmsr`/`wrmsr`, `cr[0-4]`, `in`/`out` and `cpuid` outside `crates/arch-x86_64`.

**Tests**
- Every existing host test.
- New dispatch tests: selection for given feature masks, opt-out applied before selection, double seal rejected.
- A compile check of the contract.
- Leak-check script.
- All 79 smoke scenarios under HVF and TCG; `make repro`.
- `make bench` before and after, as a table.
- Bytes per idle connection at 10k (`tools/loadgen` as in M15).
- ELF size before and after.

**Accept**
- Smoke, bench, bytes per connection and reproducibility are unchanged, except that the ELF size changes by a reported amount.
- The leak check is green.

### X0b — aarch64 hardware crypto (new; proposed because of F1) · S–M

**Work**
- Vendor the patched `cpufeatures` (D2) and enable `--cfg aes_armv8 --cfg polyval_armv8` for the kernel target.
- Add the `crc32c` dispatch: ARMv8 `crc32c{b,h,w,x}` when FEAT_CRC32 is present (Cortex-A72 and Neoverse N1 have it), with an optional PMULL folding for long buffers.
- Log line: `crypto: aes-gcm=armv8-aes+pmull sha256=armv8-sha2 crc32c=armv8-crc …`.

**Tests**
- Known-answer tests (NIST GCM, FIPS 180-4, CRC-32C reference) at boot in dev (`test=crypto-kat`), on HVF (M4) and TCG `max`/`neoverse-n1`/`cortex-a72`.
- Differential fuzz targets `diff_aes_gcm`, `diff_sha256`, `diff_crc32c` comparing the soft and hardware paths on an aarch64 host (the CI arm runner and the M4).
- `test=simd-irq` on aarch64.
- Bench rows: AES-GCM MB/s, SHA-256 MB/s, CRC MB/s, handshakes/s and records/s.

**Accept:** each backend is on by default only if it is faster on HVF/M4 (real hardware) and every known-answer and differential test is equal. This step deliberately changes aarch64 numbers (upwards), which is why it is separate from X0.

### X1 — x86_64 builds · M

**Work**
- `crates/arch-x86_64` with every facade item as a `todo!`-style stub that fails loudly, and the target JSON (D3). The Makefile gets `ARCH=aarch64|x86_64`: `TARGET`, `KERNEL_FLAGS` and the remap rustflags env var derived per arch.
- SQLite via clang `--target=x86_64-unknown-none-elf -mno-red-zone -mcmodel=kernel -ffreestanding`, hard-float SSE per D3.
- CI builds both, and runs clippy on both.
- The KVM probe job (D7).
- Host tests on `ubuntu-24.04` x86_64 as well (today: macos-15 and ubuntu-24.04-arm).

**Tests:** `make check` on both targets; `make build ARCH=x86_64` gives an ELF; `nm`/`objdump` check that the ELF has no `xmm` use outside the policy (only with option b); the decision test for D3 (a tiny `#[target_feature]` function plus an SSE float function, compile and disassemble).

**Accept:** both ELFs build reproducibly (built twice, identical); the ADRs for D3 and D7 contain the measured or observed facts.

### X2 — Boot and exceptions · M

**Work**
- Limine x86 entry; the 16550 (SPCR or COM1) and framebuffer log; GDT, TSS, and an IDT with IST stacks for #DF, NMI, #MC and #PF.
- Decoded reports: vector name, error-code bits (#PF: P/W/U/RSVD/I/PK/SS), RIP, CR2, RSP, RFLAGS, all GPRs, and the stack guard explanation (as on aarch64).
- Panic handling: reset, or `isa-debug-exit` in smoke mode (D5).
- `URMQTT BOOT <ver> arch=x86_64 cpu=<n> mem=<MB>` plus a CPUID summary: vendor, family/model/stepping, hypervisor signature (KVMKVMKVM, TCGTCGTCG), and the section-6 features plus XCR0.
- The baseline-v2 check, with the message from PROMPT §1.
- **Feature census:** boot `-cpu max` under TCG and record which of these the guest really sees: AES-NI, PCLMULQDQ, SHA-NI, AVX2, VAES, VPCLMULQDQ, GFNI, AVX-512*, RDRAND/RDSEED, FSGSBASE, x2APIC, TSC-deadline, WAITPKG, CET. The table goes into ADR-046.
- `run-qemu.sh` gets arch support: q35/pc, OVMF/SeaBIOS, `--cpu`.
- **De-risk spike for X10:** boot one ISO containing `BOOTX64.EFI` with `${ARCH}` selection.

**Smoke (x86, TCG)**

| Scenario | What it checks |
|---|---|
| `x86-boot-q35-uefi`, `x86-boot-pc-bios` | boot line, CPUID summary, `URMQTT READY` |
| `x86-baseline-refuse` | `-cpu qemu64`: the exact message, then poweroff |
| `x86-fault-pf-null`, `x86-fault-ud`, `x86-fault-gp` | the decoded report for each fault |
| `x86-fault-df` | a stack overflow escalates to #DF, which is reported from its IST stack |

**Accept:** q35+OVMF and pc+SeaBIOS boot under TCG; the deliberate faults print decoded reports; the census is recorded.

### X3 — Memory protection · M

**Work**
- Own 4-level tables, NX via EFER.NXE, CR0.WP, CR4.SMEP/SMAP/UMIP (each only if CPUID has it, otherwise logged), guard pages, no lower-half mappings, null page unmapped.
- Tables become read-only after boot ("locked", like aarch64), with the W^X audit line in the same format (`selftest: W^X ok (N leaf mappings audited, 0 W+X)`).
- CET per D8.
- Kernel layout constants in `arch::layout`: canonical 48-bit addresses; `-mcmodel=kernel` needs the text in the top 2 GiB.

**Smoke:**
- `x86-wx-write-text`, `x86-nx-exec-heap`, `x86-guard-overflow`, `x86-null-deref`, `x86-smap-user-access` (a test page with U=1);
- `x86-cet-ibt` and `x86-cet-shstk` ("skipped (no CET)" under TCG).

**Accept:** every scenario gives the expected decoded report; skipped ones are counted as skipped, never as passed.

### X4 — Interrupts and time · M

**Work**
- 8259 remapped and fully masked.
- x2APIC, with xAPIC MMIO as the fallback.
- Vector map (ADR):
  - 0x20 timer;
  - 0x30–0x3f IPIs (ping, pong, wake);
  - 0x40–0xef MSI-X;
  - 0xfe error;
  - 0xff spurious.
- D6 timekeeping.
- KVM PV EOI when the CPUID KVM leaf offers it.
- IRQ latency measurement like M3 (busy-poll vs `hlt`).
- The cost of saving FP state at IRQ entry (D3) is measured: cycles per XSAVEC/XRSTOR.

**Tests**
- Host: vector allocation; TSC calibration maths, including CPUID 0x15 edge cases (crystal = 0).
- Smoke `x86-time`:
  - tick 10;
  - 5x ticks in ~500 ms against the HPET;
  - latency lines;
  - `clock monotonic across cores` (every core samples the clock under an IPI barrier; no core may go backwards);
  - `test=simd-irq` (D3).

**Accept:** per-core tick, measured latency logged, the monotonic test green, the XSAVE cost recorded.

### X5 — SMP · S–M

**Work:** Limine MP (with its x2APIC flag), per-CPU data via GS base (`wrgsbase` with FSGSBASE, else the MSR), IPIs through the ICR (or the KVM PV IPI hypercall when offered), `hlt` idle, ping-pong over every ordered pair, up to 64 CPUs.

**Tests:** smoke `x86-smp4` and `x86-smp8` (`make run-smp ARCH=x86_64 N=8`): the same output lines as aarch64 (`smp: 8/8 cpus online`, `ipi: 56/56 ordered pairs …`, `ticking on their own timer`).

**Accept:** output format identical to aarch64.

### X6 — Platform discovery (ACPI only on x86) · M

**Work**
- MADT: LAPIC, x2APIC, IOAPIC and interrupt source overrides.
- MCFG, FADT (reset register, PM1, `_S5` via D5), HPET, SPCR.
- All of it goes into the same `PlatformInfo`, with an x86 variant of the interrupt description.

**Tests**
- Host tests from real tables: dump QEMU q35 and pc ACPI tables (OVMF and SeaBIOS) into `crates/platform/tests/fixtures/` (the same approach as the DTB fixtures).
- The `acpi_parse` fuzz target gets those tables as seeds; new fuzz target `aml_s5`.
- Smoke: platform summary on q35 and pc, compared against the expected text.

**Accept:** summaries printed on q35 and pc; fuzz targets green in CI.

### X7 — PCI and virtio · M

**Work**
- ECAM via MCFG (q35); configuration mechanism #1 via 0xCF8/0xCFC (pc), behind the existing `pci` config-access trait.
- I/O BARs are read but MMIO is preferred.
- MSI-X via `arch::msi` (address 0xFEE00000 | APIC id, data = vector).
- The virtio rng, blk, scsi and net self-tests as in M6.
- Entropy: RDSEED/RDRAND mixed in and health-tested (stuck and repeat detection, failures logged), never the sole source; jitter via TSC.

**Tests:** for each of q35 and pc:
- smoke `x86-devices-{q35,pc}` (blk self-test, gratuitous ARP in the pcap via the existing `pcap_has_garp`, entropy seeded, MSI-X completions);
- `x86-scsi`;
- `x86-no-hw-rng` (`-cpu …,-rdrand,-rdseed` and no virtio-rng: jitter fallback).

**Accept:** all green on q35 and pc.

### X8 — Feature parity · L

**Work:** run every M7–M17 subsystem on x86_64. Nothing should be arch-specific beyond the facade by now; fix whatever is.

**Tests**
- The existing aarch64 smoke scenarios, parameterised by arch:

  | Area | Scenarios |
  |---|---|
  | network | net-echo |
  | MQTT | mqtt-plain, mqtt-tls with all rejections, mqtt-persist |
  | storage | db-bench, db-crash and verify, log-crash, log-tear and verify |
  | operations | storm, watchdog, observability |
  | boot media | raw-disk |
  | data plane | dp-bench |

- **Cross-arch data disk** (new):
  - `cross-arch-a2x`: an aarch64 VM (HVF) writes retained messages, sessions and telemetry, then is killed; an x86 VM (TCG) boots on the same disk and must print `db: restored 1 retained … 1 persistent session(s)` and the telemetry record count.
  - `cross-arch-x2a`: the same in the other direction.
- **Struct sizes:** the `const` asserts compile for x86, and a host test prints `size_of` for every connection and session struct on both architectures; the CI diff must be empty.

**Accept:** the full mqtt-scenarios set, the crash tests, storm and the cross-arch tests pass on x86_64.

### X9 — x86 optimisations · L

Order follows PROMPT §6.3. Each item ships with its implementation, known-answer tests, a differential fuzz target, a bench row and an end-to-end number.

1. AES-128-GCM: AES-NI and PCLMULQDQ, through `aes`/`polyval` with the patched detection. No own code unless the bench says so.
2. SHA-256: SHA-NI through `sha2`. Measure the M15 per-record key/IV derivation separately (records/s).
3. CRC-32C: SSE4.2 `crc32` (baseline v2, so always available on x86), plus PCLMULQDQ folding for ≥ 1 KiB buffers.
4. ChaCha20-Poly1305: the `chacha20`/`poly1305` AVX2 backends (`chacha20` 0.9 has an `avx2` backend; **to verify** how it selects it); SSE2 baseline.
5. Wide AES-GCM: VAES and VPCLMULQDQ, 256-bit. AVX-512 is opt-in only, in config.
6. Toeplitz: GFNI or PCLMULQDQ against a table-driven version. The table version is also tried on aarch64 first, because it may win everywhere.
7. Bit operations, MOVBE, prefetch and waiting (UMWAIT/MWAITX): measured; only kept if they show a gain.
8. FSGSBASE, RDSEED and kvmclock are already done in X4/X5/X7.

The cipher-preference rule (PROMPT §1): without AES-NI the server orders ChaCha20-Poly1305 first. This becomes a host test plus smoke `x86-cpu-v2-min` (no AES-NI, so the negotiated suite must be ChaCha).

**Tests**
- KATs: NIST GCM, RFC 8439, FIPS 180-4, RFC 8448 traces, CRC-32C vectors.
- Differential fuzz targets `diff_aes_gcm`, `diff_chacha`, `diff_sha256`, `diff_crc32c` and `diff_toeplitz`, with lengths 0..64 KiB and unaligned buffers. They run on the x86 CI runner and the KVM host.
- `test=crypto-kat` on every CPU model of the matrix (§4).
- `test=simd-irq` under load.

**Accept**
- The boot line lists the chosen implementations.
- `make bench ARCH=x86_64` has a table per implementation.
- Each optimisation is enabled by default only with a real-hardware number (KVM runner or the user's host) recorded in PROGRESS.

### X10 — One multi-arch ISO · M

**Work** per D4:
- `make dist` produces the universal ISO and raw image (plus optional single-arch images), `SHA256SUMS` and signatures.
- `make repro` checks both ELFs and both universal images bit for bit.
- The release workflow and SLSA provenance cover both architectures.

**Tests**
- Smoke `universal-iso-{aa64-hvf,aa64-tcg,x86-q35-uefi,x86-pc-bios}`, with the **same file** (checked by hash in the test).
- `universal-raw-{aa64,x86-uefi,x86-bios}`.
- The repro CI job runs on both architectures' images.

**Accept:** one ISO boots everywhere; repro green.

### X11 — Measurements and docs · M

**Work:** on a Linux x86_64 KVM host (Intel and AMD if available), measure:
- bytes per idle mTLS connection at 10k and beyond;
- handshakes/s per worker core;
- dp-bench scaling from 1 to 2 to 4 cores;
- micro-benchmarks per implementation;
- PV features on and off (kvmclock, PV IPI, PV EOI).

Then update README, DEPLOY (VM CPU types: Proxmox `host` / `x86-64-v2-AES` / `x86-64-v3`, and what happens on `kvm64`), ARCHITECTURE, SECURITY (x86 mitigations and why Spectre-class issues inside one image are out of scope), and `docs/X86-TESTING.md`.

**Accept:** every number in the docs has a source line in PROGRESS.

---

## 3b. Bare-metal track (X12–X16)

The VM milestones above give a kernel that runs on x86_64 and aarch64 with
virtio devices. On real hardware the firmware, console, storage and NIC are
different, and a mistake can destroy data on a real disk. Each step is first
built against a QEMU device model where one exists, then accepted only on real
hardware, starting with the user's Intel PC. Code paths that have never run on
real hardware stay marked experimental.

### X12 — Bare-metal foundation · M

**Work**
- **Boot media.** The universal ISO (X10) is hybrid, so the same file boots as a CD and, written with `dd` to a disk, by UEFI and, on x86, BIOS (Limine `bios-install`, `xorriso -isohybrid-gpt-basdat`, **to verify**). Written to a disk, the ISO is also the disk image: the GPT it carries gets the data partition on first boot (STORAGE-PLAN §2a), so there is one artifact for CD, USB, VM disk, cloud image and bare-metal disk.
- **Secure Boot.** Most PCs ship with it on and Limine is not Microsoft-signed. The signing and enrollment work is SECURITY-PLAN **H8**. X12 documents the interim path (turn Secure Boot off) and tests H8's signed loaders on the PC once they exist.
- **Console without serial.** Most PCs have no serial port, so the framebuffer is the primary console. It needs:
  - readable fonts at high resolutions;
  - a persistent last-screen summary (IP address, listener, errors) after the scrolling log;
  - syslog over UDP once the network is up.
- **`hwreport` boot mode** (`cmdline: hwreport`, safe: it reads only). On screen and over syslog it shows:
  - CPU and CPUID;
  - the firmware memory map;
  - the ACPI table list;
  - every PCI function with vendor:device, class and driver status (`driver: yes/no`);
  - disks with model, serial and size, plus the partition and signature scan.

  This is the first thing run on any new machine.
- **One disk** (F10, STORAGE-PLAN §2a), and **the ISO installs itself** (§2b, S1b). On the PC: boot the USB stick, choose *Install urMQTT on this machine's disk*, wait out the countdown, remove the stick, boot from the internal disk. X12 accepts this on the PC by UEFI and BIOS (once X13 drives its disk), plus first boot, a crash during first boot, and reboot. `dd` from another system remains documented as the fallback.
- **More CPUs.** MAX_CPUS goes from 64 to 256 (x2APIC; desktop SMT and hybrid P/E-core CPUs report many threads). Topology is logged; NUMA is logged and ignored for now.
- **Power.** ACPI reset and S5 (D5) become essential on real hardware.

**Tests**
- Smoke `hwreport` under QEMU (q35 and pc, aarch64 virt).
- S1's single-disk scenarios (`first-boot`, `first-boot-crash-N`, `second-disk-untouched`) also run with the bare-metal config.

**Real hardware (Intel PC)**
1. Boot from USB by UEFI (and BIOS if the firmware has CSM).
2. Run `hwreport` and record its output in `docs/HARDWARE.md`.
3. Confirm that no disk was written (hashes of the first and last MiB before and after, taken from a Linux live USB).

### X13 — Storage drivers: NVMe and AHCI · M

**Work**
- **NVMe:** admin queue plus one I/O queue pair, polled first and then MSI-X. Identify, namespace 1, Read/Write/Flush, and FUA for the telemetry log's sector writes. Controller reset and timeouts.
- **AHCI/SATA:** one port at a time, NCQ off at first, FLUSH CACHE EXT.
- Both plug in behind the existing `DataDisk` abstraction, next to virtio-blk and virtio-scsi.
- Write-cache semantics are checked against what the crash tests assume (flush = durable).

**Tests**
- QEMU `-device nvme` and `ich9-ahci` with the full storage set from the smoke suite: blk self-test, db-bench, db-crash and verify, log-crash, log-tear.
- A fuzz target for NVMe completion parsing (a malicious device must not corrupt memory).
- **Real hardware:** the Intel PC's NVMe or SATA disk, the one named in config. Run db-bench and the crash tests with a real power cut (pull the cable during telemetry writes, then verify on the next boot).

### X14 — NIC drivers for x86 hardware · L

Which drivers, and in what order, follows the Intel PC's `hwreport`; its
onboard NIC comes first.

| Family | Typical hardware | QEMU model | Plan |
|---|---|---|---|
| Intel `e1000e` | I217/I218/I219 onboard (desktops, laptops), 82574L | `e1000e` (82574L only) | first if the PC has an I219: develop on QEMU's 82574L, then adapt to the I219 PHY on the PC |
| Intel `igb` | I210/I211/I350 (mini PCs, servers) | `igb` (82576) | QEMU-testable end to end |
| Intel `igc` | I225/I226 2.5G (newer boards) | none | hardware only |
| Realtek `r8169`/`r8125` | RTL8111/8168, RTL8125 (very common on consumer boards) | none (QEMU's rtl8139 is a different chip) | hardware only; written from public datasheets and register documentation, not copied from GPL code |
| Intel `ixgbe`, Mellanox `mlx5` | 10/25G servers | none | later |

**Each driver:** RX/TX descriptor rings, MSI-X (MSI fallback), link state, MAC from EEPROM/NVM, checksum offload off at first. It sits behind the same NIC interface the data plane uses for virtio-net.

**Tests**
- QEMU models: every network and MQTT smoke scenario (net-echo, mqtt-plain, mqtt-tls, storm), with `e1000e` and `igb` instead of virtio-net.
- A fuzz target for RX descriptor handling.
- **Real hardware:** the Intel PC on the LAN: DHCP lease; the mqtt-scenarios set from the Mac; loadgen at 10k connections (bytes per connection); a 24 h soak with link down/up.

### X15 — aarch64 bare metal · L (optional, needs hardware)

**Work**
- **GICv3 ITS for MSI-X.** QEMU `virt` under TCG has an ITS, so this is testable now.
- **Ampere servers (Altra, AmpereOne):** UEFI and ACPI, the PCIe quirks, and the server NICs from X14 (Intel; Mellanox later).
- **Raspberry Pi 4 on bare metal** through the community UEFI firmware. It needs:
  - the GIC-400, already supported (ADR-039);
  - a GENET Ethernet driver;
  - SDHCI (EMMC2) for the SD card.

  The Pi 5 (RP1 behind PCIe) only after that.

**Tests:** the ITS under TCG with the full smoke suite; real hardware only if the user has a machine.

### X16 — Hardware validation and compatibility list · S (continuous)

**Work**
- `docs/HARDWARE.md` lists every machine tried with:
  - firmware version;
  - boot mode and Secure Boot state;
  - `hwreport` summary;
  - drivers used;
  - which scenarios passed;
  - measured numbers (bytes per connection, handshakes/s, db-bench).
- A written procedure for testing a new machine, so others can add rows.
- A `test=hw-acceptance` boot mode runs the in-guest self-tests that are safe on real hardware: crypto KATs, `simd-irq`, IPI pairs, timer, NIC loopback where supported, and blk self-test **only** on the configured data disk.

**Accept:** the Intel PC row is complete, every claim in the README about bare metal points to a row there, and anything not on the list is described as untested.

---

## 4. Test matrix

**x86 smoke matrix** (PROMPT §7; `make smoke ARCH=both`):

| Machine | Firmware | CPU | Under | Purpose |
|---|---|---|---|---|
| q35 | OVMF | `max` (TCG) / `host` (KVM) | TCG local, KVM in CI if D7 allows | full feature set |
| q35 | OVMF | `qemu64,+ssse3,+sse4.1,+sse4.2,+popcnt,+cx16` | TCG | baseline paths, ChaCha preference |
| pc | SeaBIOS | `max` / `host` | TCG, KVM | BIOS, port-I/O PCI |
| q35 | OVMF | `qemu64` | TCG | must refuse with the message |
| q35 | OVMF | `Icelake-Server`, `EPYC-Milan`, `EPYC-Genoa` | KVM only for meaningful results* | dispatch per model |

\* TCG silently drops the features it cannot emulate (e.g. AVX-512), so a named model under TCG only tests that the dispatch follows the *reported* CPUID. That is still useful, and is labelled as such.

**Test layers, in the order they catch problems:**

1. Host unit tests on three hosts (macOS arm64, Linux arm64, Linux x86_64). The x86_64 host runs the real AES-NI/SHA-NI/AVX2 backends natively.
2. Differential fuzzing: each primitive, soft against every hardware implementation, on both architecture hosts.
3. Known-answer tests in the guest at boot (`test=crypto-kat`) on every CPU model.
4. Smoke scenarios, which check serial logs as today.
5. Cross-arch data-disk tests.
6. Bench and repro.

aarch64 keeps all 79 scenarios at every milestone.

**Bare metal** (X12–X16). The QEMU device models listed below run in CI, and each driver is also accepted on real hardware:

| Hardware | QEMU model in CI | Real machine |
|---|---|---|
| NVMe, AHCI | `nvme`, `ich9-ahci` | Intel PC |
| NIC | `e1000e`, `igb` | Intel PC onboard NIC |
| GICv3 ITS | `virt` (TCG) | Ampere, if available |
| USB boot, framebuffer console, Secure Boot | — | Intel PC only |

---

## 5. Order and dependencies

This section covers the platform track only. The order across all three tracks (security, storage, platforms) is set in [PLAN.md](PLAN.md); there, S2 (disk format v2) comes before X8, and H4/H6/H8 sit between X8 and the bare-metal milestones.

```
X0 ─► X0b ─► X1 ─► X2 ─► X3 ─┐
                   │         ├─► X5 ─► X6 ─► X7 ─► X8 ─► X10 ─► X12 ─► X13 ─► X14 ─► X9 ─► X11
                   │   X4 ───┘                       ▲                                 │
                   └─(spike)─────────────────────────┘                    X15 (optional, after X12)
                                                         X16 runs alongside from X12 on
```

- X3 and X4 can be swapped; X5 needs X4 (IPIs, timer).
- Platform parsing for x86 ACPI (part of X6) is pulled forward into X2 as far as needed (MADT for the CPU count, SPCR for the UART).
- X10's boot-config spike happens in X2, so the riskiest image question is answered early.
- Proposed change to PROMPT-x86_64.md's order, because bare metal is a requirement:
  - X10 (the universal ISO) and the bare-metal track come **before** X9 (optimisations). A fast kernel that cannot drive the PC's NIC is not useful.
  - X9 measurements on the Intel PC then come from real hardware, not only from a VM.
- `hwreport` (part of X12) is useful as early as X7 and can be pulled forward. The Intel PC's NIC and disk models decide what X13/X14 build first.

---

## 6. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Patched `cpufeatures` (F2) is a fork to maintain across two versions | upgrades need a re-patch | a small patch (one macro arm), a CI check that the patch still applies, upstream issue offering a hook |
| Custom target JSON drifts between nightlies | build breaks on a toolchain bump | pinned nightly (as today); a target-spec check in `make check` |
| x86 under TCG on the M4 is slow, and possibly single-threaded for x86-on-arm | long smoke runs | measure MTTCG in X2; split smoke into fast/full sets; heavy runs in CI under KVM |
| TCG lacks AVX-512, CET, WAITPKG and maybe GFNI and SHA-NI (**to verify**) | those paths cannot be tested locally | KVM runner (AMD EPYC), the user's Intel host if there is one; otherwise off by default |
| ACPI poweroff needs AML | prod VMs cannot power off cleanly | `_S5` scanner plus fuzzing; reset always works via the FADT |
| BIOS boot on the GPT raw image | the universal raw image may not boot on BIOS | verify early (X2 spike); fall back to a hybrid MBR or document UEFI-only for the raw image |
| Reproducibility of `limine bios-install` and two kernels | repro job fails | run the step under `SOURCE_DATE_EPOCH`; compare bytes; remove any nondeterminism before X10 is accepted |
| The refactor regresses aarch64 | the primary platform breaks | X0 changes behaviour nowhere; full smoke, bench and bytes-per-connection checks at every milestone |
| No Intel hardware for measurements | X11 Intel numbers missing | resolved: the user's Intel PC (16 GB) is the bare-metal and measurement machine; AMD numbers come from the CI runner if it has KVM |
| A real disk gets formatted by mistake | data loss on the test PC or a user's machine | F10: signature scan, two-ended blank check, format only the disk named in config; `hwreport` never writes; the X12 hardware test checks hashes |
| The PC's NIC has no QEMU model (I219, Realtek, I225) | driver developed blind | `hwreport` first; register-level logging; develop against QEMU's 82574L where the family matches; the user runs test images and sends logs |
| Firmware quirks (ACPI tables, MSI-X, Secure Boot, no serial) | boot fails silently on hardware | framebuffer console with a persistent summary; ACPI parser fuzzed against real dumps; Secure Boot paths documented |
| Total size: roughly 10–12 milestone-sized steps | long project | stop and report after every milestone, as required |

---

## 7. Open questions for the user

1. **Answered:** an Intel x86_64 PC with 16 GB of RAM is the bare-metal test machine. Before X12, its inventory helps. From a Linux live USB (e.g. Ubuntu), send:
   - `lscpu`;
   - `lspci -nn`;
   - `lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE`;
   - `ls /sys/firmware/efi` (does it exist?);
   - `mokutil --sb-state`;
   - whether it has a serial port.

   The same machine, booted into that live Linux, can also serve as the KVM host for the X9/X11 measurements.
2. X0b: enable ARMv8 hardware crypto on aarch64 now (it changes aarch64 numbers, upwards) rather than in X9?
3. Is it OK to vendor x86 Limine binaries and build the `limine` host tool from its C source (overriding PROMPT.md §2, via ADR)?
