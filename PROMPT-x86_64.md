# urMQTT — x86_64 port, universal image and x86 CPU optimizations

> This document extends `PROMPT.md`. Everything in `PROMPT.md` still applies (working method, code rules,
> ADRs, PROGRESS entries, "verify, don't assume", "never fake progress"). Where this document is more
> specific, it wins for the x86_64 work. Put this file in the repo root next to `PROMPT.md`.

---

## 0. Context and working agreement

urMQTT is an aarch64 unikernel that is an MQTT broker. Milestones M0–M17 are complete (see `README.md`,
`docs/PROGRESS.md`, `docs/DECISIONS.md`). Read those three files and skim `crates/arch-aarch64`,
`crates/platform`, `crates/pci`, `crates/tls` (crypto provider and record layer), `crates/store`
(SQLite build, CRC-32C) and `crates/kernel` **before** writing any code.

The goal of this work is:

1. **x86_64 support with full feature parity** (everything M1–M17 delivers on aarch64 must work on x86_64).
2. **One universal image**: a single ISO (and a single raw GPT disk image) that boots on aarch64 UEFI,
   x86_64 UEFI and x86_64 legacy BIOS.
3. **Use Intel/AMD-specific instructions where they measurably help**, selected at boot by CPU feature
   detection, never by vendor name, with portable fallbacks and proof of equivalence.

Rules specific to this work:

- **Communicate with the user in Croatian.** Code, comments, commits and docs in English.
- **aarch64 is the primary platform and must not regress.** After every milestone: all aarch64 smoke
  scenarios green under HVF and TCG, `make bench` within noise of the previous numbers, bytes per idle
  connection unchanged. Report the aarch64 ELF size before/after.
- Milestones are named **X0 … X11**. Same discipline as before: `make check` + `make smoke` (both
  architectures once x86 boots), commit `X<n>: <summary>`, PROGRESS entry, ADRs, then stop and report.
- **Verify every platform assumption** (Limine x86 protocol details, QEMU machine types, TCG support for
  specific instructions, Rust target defaults, GitHub runner KVM availability) by reading current docs/source
  and by building/booting. Record findings in `docs/DECISIONS.md`.
- No x86 code may leak into protocol crates (`mqtt`, `broker`, `tcp`, `net`, `timer-wheel`, `config`).
  Architecture differences live behind the arch facade (X0) or in clearly separated, feature-dispatched
  kernels (X9).

---

## 1. Hard constraints

- Rust target `x86_64-unknown-none` (or a custom target JSON if required; justify in an ADR).
  Note: this target is soft-float with SSE disabled by default. Decide the FP/SIMD policy explicitly (see 5.3).
- Long mode only, 4-level paging (5-level not required), no 32-bit code beyond what Limine handles.
- **Baseline ISA: x86-64-v2** (SSE4.2, POPCNT, CMPXCHG16B, SSSE3). Check it at boot with CPUID; if missing,
  print a clear message naming the problem and the fix (e.g. "VM CPU type too old: use `host`,
  `x86-64-v2-AES` or newer in Proxmox/QEMU") and power off. Everything above v2 is optional and
  dispatched at runtime.
- **AES-NI is optional.** Without it, the TLS server must prefer ChaCha20-Poly1305 (constant-time software)
  over software AES-GCM. Document the cipher-preference logic.
- Devices: same virtio-pci set as aarch64 (net, blk, scsi, rng), 16550 UART, Limine framebuffer.
  No legacy devices beyond what is needed to boot, reset and keep the 8259 PIC masked.
- Supported VM machine types: QEMU/KVM **q35** (PCIe ECAM via MCFG) **and i440fx / `pc`** (no ECAM:
  needs PCI configuration mechanism #1 via ports 0xCF8/0xCFC). Proxmox and many KVM hosts default to i440fx.
- Firmware: UEFI (OVMF) and legacy BIOS (SeaBIOS) via Limine.
- Hardware discovery on x86_64 is **ACPI only** (MADT incl. LAPIC/x2APIC/IOAPIC entries, MCFG, FADT, HPET,
  SPCR when present). No DTB on x86.
- AWS (ENA/NVMe) and Azure (MANA/NetVSC) remain out of scope.

---

## 2. Development and test environment

- Primary dev host is an Apple M4 Pro: x86_64 runs there **only under TCG** (`qemu-system-x86_64 -accel tcg`).
  That is fine for bring-up and smoke tests, not for performance numbers.
- Performance and instruction-specific validation need a **Linux x86_64 host with KVM** (Intel and, if
  possible, AMD). Write `docs/X86-TESTING.md` explaining how to run the suite there.
- Check whether GitHub-hosted x86_64 Linux runners expose `/dev/kvm` for this repository's plan. If yes, run
  x86 smoke under KVM in CI; otherwise TCG. Record the result in an ADR.
- Verify which instructions QEMU TCG emulates (AES-NI, PCLMULQDQ, SHA-NI, AVX2, VAES, VPCLMULQDQ, GFNI,
  AVX-512 subsets, RDRAND/RDSEED, FSGSBASE, x2APIC, TSC-deadline, WAITPKG). Anything TCG lacks must be tested on
  real hardware before it can be enabled by default.
- Homebrew: `qemu` already installed; OVMF firmware for x86 is shipped with QEMU (`edk2-x86_64-code.fd`),
  locate via `brew --prefix qemu`.

### Makefile changes

All existing targets accept `ARCH=aarch64|x86_64` (default `aarch64` for build/run, both for `iso`/`dist`):

| Target | Behavior |
|---|---|
| `make build ARCH=x86_64` | builds `target/x86_64-unknown-none/release/urmqtt` |
| `make run ARCH=x86_64` | q35 + OVMF, TCG on macOS, KVM on Linux when available |
| `make run ARCH=x86_64 MACHINE=pc FW=bios` | i440fx + SeaBIOS |
| `make run ARCH=x86_64 CPU=<model>` | e.g. `qemu64,+sse4.2,+popcnt,+ssse3,+cx16` (minimal v2), `max`, `host`, `EPYC-Genoa`, `Icelake-Server` |
| `make smoke ARCH=both` | all scenarios on both architectures, including x86 CPU-model matrix (section 7) |
| `make iso` | **universal** ISO by default; `make iso ARCH=x86_64` for a single-arch ISO |
| `make bench ARCH=x86_64` | same tables as aarch64 plus crypto/CRC micro-benchmarks per implementation |

---

## 3. Mapping aarch64 → x86_64

| Concern | aarch64 (exists) | x86_64 (to build) |
|---|---|---|
| Entry / boot | Limine UEFI | Limine UEFI + BIOS, long mode set up by Limine |
| Exceptions | EL1 vectors, ESR/ELR/FAR decode | GDT, TSS, IDT, **IST stacks** for #DF, #NMI, #MC, #PF (separate exception stack as on aarch64); decode vector, error code, RIP, CR2, RSP, RFLAGS, GPRs |
| Paging / W^X | own tables, WXN, UXN/PXN, locked tables | own 4-level tables, NX (EFER.NXE), CR0.WP, **SMEP, SMAP, UMIP**, table pages mapped read-only after boot, W^X audit adapted to x86 PTE format |
| "Lower half disabled" | TCR EPD0 | no lower-half mappings at all, documented; null page unmapped; SMEP/SMAP on |
| CFI | PAC (`pac-ret`), BTI | **CET**: IBT (endbr64 landing pads) and supervisor shadow stacks if CPU and Rust/LLVM support allow; optional like PAC/BTI; verify toolchain flags |
| Interrupt controller | GICv3/v2, SGI IPIs | **x2APIC** (fallback xAPIC MMIO), IPIs via ICR; 8259 masked; IOAPIC only if something needs it (virtio uses MSI-X) |
| MSI-X | GICv2m frame | message address 0xFEE00000 \| dest APIC id, data = vector; arch hook used by `pci` |
| Timer | generic timer | LAPIC timer, **TSC-deadline** mode when available; TSC frequency from CPUID 0x15/0x16, **kvmclock** when under KVM, else calibrate vs HPET/ACPI PM timer; require or detect invariant TSC |
| SMP | PSCI CPU_ON / Limine MP | Limine MP; per-CPU via **GS base** (`FSGSBASE` instructions when available, MSR otherwise) |
| Idle | `WFI` | `HLT`; optionally MWAIT / UMWAIT / MWAITX when exposed (see X9) |
| Reset / off | PSCI SYSTEM_RESET/OFF | ACPI FADT reset register; ACPI S5 via PM1 control; QEMU `isa-debug-exit` in smoke mode only; triple fault as last resort |
| Console | PL011 | 16550 (SPCR or COM1 0x3F8), Limine framebuffer |
| Entropy | virtio-rng, RNDR, jitter | virtio-rng, **RDSEED/RDRAND** (health-tested, always mixed, never sole source), jitter |
| Crypto accel | AES + PMULL (ARMv8 CE) | AES-NI + PCLMULQDQ, optional VAES/VPCLMULQDQ, SHA-NI (section 6) |
| CRC-32C | (whatever aarch64 uses now) | SSE4.2 `crc32` instruction, PCLMULQDQ folding for long buffers |
| PCI config | ECAM | ECAM (q35) **and** port I/O mechanism #1 (i440fx) |

---

## 4. Milestones

### X0 — Arch facade (aarch64 only, no behavior change)

- Introduce one architecture facade used by `kernel`, `mm`, `pci`, `virtio`, `log`, `store` and `tls`:
  a cfg-selected module (`arch::` re-exporting `arch-aarch64` or `arch-x86_64`) with an identical API,
  or traits where static dispatch is free. Choose and justify in an ADR. It covers at least:
  CPU id and per-CPU pointer, interrupt enable/disable/save/restore, wait-for-interrupt, IPI send,
  monotonic time + deadline timer, MSI-X address/data composition, page-table builder and audit interface,
  exception report formatting, barriers/cache ops, entropy instructions, reset/poweroff, and a
  `CpuFeatures` struct filled once at boot.
- Remove every direct use of aarch64 registers/instructions from non-arch crates.
- Introduce the **implementation dispatch framework** used later by X9 (section 6.2), already used on
  aarch64 for its existing AES/PMULL path, so both architectures share the mechanism.
- Accept: aarch64 smoke, bench, bytes/connection, reproducibility all unchanged; `grep` shows no aarch64
  assembly or system-register names outside `arch-aarch64`.

### X1 — x86_64 builds

- Workspace builds and passes clippy for `x86_64-unknown-none`; `arch-x86_64` exists with stubs that fail
  loudly; CI builds both targets; SQLite compiles for x86_64 (clang `--target=x86_64-unknown-none-elf`,
  `-mno-red-zone`, `-mcmodel=kernel`, `-ffreestanding`, FP/SIMD flags per the policy in 5.3).
- Accept: `make build ARCH=x86_64` produces an ELF; `make check` covers both targets.

### X2 — Boot and exceptions

- Limine (UEFI and BIOS), 16550 + framebuffer logging, GDT/TSS/IDT with IST, decoded exception reports,
  panic handler → reset or, in smoke mode, `isa-debug-exit` / ACPI poweroff.
- Prints `URMQTT BOOT <version> arch=x86_64 cpu=<n> mem=<MB>` and the CPUID summary (vendor, family/model,
  hypervisor signature, feature list relevant to section 6).
- Baseline-ISA check with a clear failure message.
- Accept: boots on q35+OVMF and pc+SeaBIOS under TCG (and KVM on Linux); a deliberate fault prints a decoded report.

### X3 — Memory protection

- Own page tables, NX, W^X, guard pages, CR0.WP, SMEP/SMAP/UMIP, locked tables, W^X audit log line equivalent
  to aarch64. CET (IBT, and shadow stacks if feasible) when supported; log what is on.
- Accept: smoke scenarios — write to kernel text, execute heap, stack overflow into guard page, null pointer,
  and (when CET is available) a forged return / indirect branch to a non-`endbr64` target — each produce the
  expected decoded report. Scenarios that need unavailable hardware are reported as skipped, not passed.

### X4 — Interrupts and time

- x2APIC (xAPIC fallback), 8259 masked, LAPIC TSC-deadline timer (periodic fallback), TSC calibration
  hierarchy, kvmclock under KVM, monotonic clock, IRQ latency measurement like M3 (busy-poll vs HLT).
- Accept: per-core tick, measured latency logged, clock monotonic across cores (test).

### X5 — SMP

- Limine MP bring-up, GS-based per-CPU data, IPIs, HLT idle, IPI ping-pong between every ordered pair,
  up to 64 CPUs (raise if the aarch64 side supports more).
- Accept: `make run-smp ARCH=x86_64 N=8` matches the aarch64 output format.

### X6 — Platform discovery

- ACPI on x86: MADT (LAPIC, x2APIC, IOAPIC, interrupt overrides), MCFG, FADT, HPET, SPCR into the same
  `PlatformInfo`. Extend the `acpi_parse` fuzz target with x86 tables (use real QEMU q35/pc and OVMF tables as
  corpus seeds).
- Accept: platform summary printed on q35 and pc; fuzz target green.

### X7 — PCI and virtio

- ECAM via MCFG, port-I/O config mechanism #1 fallback, BARs (including I/O BARs where a device exposes them —
  prefer MMIO), MSI-X through the arch hook, virtio-rng/blk/scsi/net self-tests identical to M6.
- Accept: blk self-test, gratuitous ARP in pcap, entropy seeded, on q35 and pc.

### X8 — Feature parity

- Everything from M7–M17 runs on x86_64: DHCP, own TCP, TLS 1.3 mTLS, broker, SQLite on raw disk, telemetry
  log, multicore data plane, admission control, watchdog, syslog/statsd, DB/telemetry crash tests.
- Data-disk format is **architecture independent** (explicit little-endian everywhere): a data disk written by
  an aarch64 VM must boot and serve on x86_64 and vice versa. Add a cross-arch test.
- `size_of` assertions for all connection/session structs must give identical sizes on both architectures.
- Accept: `scripts/mqtt-scenarios.py` (plain dev and mTLS sets, including all rejections), db-crash/verify,
  log-crash/verify and the storm test pass on x86_64; cross-arch data-disk test passes.

### X9 — x86 optimizations (section 6)

- Implement the optimized kernels in the order of section 6.3, each behind feature detection, each with
  tests (6.4) and a benchmark row. Enable by default only what is proven faster on real hardware and correct.
- Accept: boot log line listing chosen implementations; `make bench ARCH=x86_64` table per implementation;
  differential fuzz targets green; numbers recorded in PROGRESS.

### X10 — One multi-arch ISO (the primary release artifact)

The release produces **one single multi-architecture ISO** (`urmqtt-<env>-<version>.iso`) that boots on
every supported architecture. Single-arch ISOs are optional extras, never the default. The image layout must
be extensible so a further architecture (section 9) is added by dropping in its EFI loader and kernel.

- ISO containing: `EFI/BOOT/BOOTAA64.EFI`, `EFI/BOOT/BOOTX64.EFI`, Limine BIOS CD boot, both kernels
  (`urmqtt-aarch64.elf`, `urmqtt-x86_64.elf`) and one `limine.conf` that selects the kernel for the running
  architecture. Verify how the vendored Limine version supports per-architecture selection (e.g. a built-in
  architecture macro) and record it.
- Raw GPT image with one ESP holding both EFI loaders and kernels, plus BIOS boot for x86 if Limine supports it
  on GPT (verify).
- `make dist` outputs universal ISO + universal raw image (and optional single-arch variants), `SHA256SUMS`,
  signatures; `make repro` checks **both** kernels and both universal images bit for bit; release workflow and
  SLSA provenance updated.
- Accept: the **same ISO file** boots on QEMU aarch64 (HVF and TCG), QEMU x86_64 q35+OVMF, pc+SeaBIOS; repro
  check green.

### X11 — Measurements and docs

- On a Linux x86_64 KVM host (Intel and AMD if available): bytes per idle mTLS connection at 10k (and more if
  the host allows), handshakes/s per worker core, in-guest dp-bench scaling 1→2→4 cores, crypto and CRC
  micro-benchmarks per implementation, effect of PV features (kvmclock, PV IPI, PV EOI).
- Update `README.md` (description, topics, badges, features table, deployment table: Proxmox x86 i440fx/q35,
  Vultr, Hetzner CX/CPX, generic KVM), `docs/DEPLOY.md` (recommended VM CPU types, e.g. Proxmox `host` or
  `x86-64-v3`, what happens on `kvm64`), `docs/ARCHITECTURE.md`, `docs/SECURITY.md` (x86 mitigations).
- Accept: docs reviewed for accuracy against actual measurements; no claim without a number behind it.

---

## 5. x86-specific design points

### 5.1 Interrupt path

Interrupt handlers stay tiny: acknowledge (x2APIC EOI MSR write), mark work, return — exactly like aarch64.
Use KVM **PV EOI** when the hypervisor offers it (fewer VM exits). Document vector allocation (spurious,
timer, IPI, MSI-X per queue, error).

### 5.2 Cross-core wakeups

SPSC rings wake an idle consumer with an IPI today. On x86 under KVM, use **PV send IPI** (hypercall) when
available to cut VM exits; measure. Where the guest exposes **UMWAIT/TPAUSE** (Intel WAITPKG) or
**MONITORX/MWAITX** (AMD), evaluate waiting on the ring's producer index instead of busy-polling or HLT
(aarch64 measured ~2 ms WFI wake-up under HVF; x86 behavior under KVM must be measured, not assumed).
Most VMs do not expose these; never require them.

### 5.3 FP/SIMD policy (decide in an ADR before X1 ends)

`x86_64-unknown-none` disables SSE by default. The crypto and CRC kernels need SSE/AVX. Options:

- (a) Enable SSE (and XSAVE/AVX state in CR4/XCR0) for the whole kernel; interrupt/exception entry must then
  not clobber vector state: either keep handlers in assembly that only touches GPRs, or save/restore with
  XSAVEOPT/XSAVEC to a per-CPU area (measure the cost).
- (b) Keep the kernel soft-float and use SIMD only inside `#[target_feature]` functions called from the data
  path with interrupts masked or with explicit state save.

Mirror whatever the aarch64 FP/SIMD ADR decided where sensible. SQLite needs FP on the DB core. Whatever
the choice: a test must prove that an interrupt during a SIMD crypto loop does not corrupt results
(e.g. run AES-GCM/ChaCha KATs in a loop with a high-frequency timer IRQ and IPIs, compare outputs).
Compiler-inserted `vzeroupper` handling: rely on `#[target_feature]` codegen, verify with disassembly.

### 5.4 Security parity

SMEP, SMAP, UMIP, NX, WP, locked tables, guard pages, CET when available. Spectre-class issues: there is
no user/kernel boundary inside the image, but document the reasoning in `SECURITY.md` (cross-VM isolation is
the hypervisor's job; which mitigations are irrelevant and why). RDRAND/RDSEED are **mixed** into the CSPRNG,
never trusted alone; health-test their output (stuck/repeat detection) and log failures.

### 5.5 PKS (optional, later)

Intel Protection Keys for Supervisor (where available) is an x86 option for isolating the SQLite heap,
analogous to the planned EL0 isolation on aarch64. Investigate only after X11; ADR first.

---

## 6. Using Intel/AMD-specific instructions

### 6.1 Principles

1. **Detect features, not vendors.** Use CPUID (and XGETBV for OS-enabled state) once at boot into
   `CpuFeatures`. AMD and Intel support overlapping sets (e.g. SHA-NI on AMD Zen since its first generation,
   on Intel only on newer cores; VAES on Intel Ice Lake+ and AMD Zen 3+; AVX-512 on Intel server parts and
   AMD Zen 4+). Hypervisors mask features: the guest CPUID is the truth.
2. **One binary.** Baseline x86-64-v2 code everywhere; optimized kernels are separate functions compiled with
   `#[target_feature(enable = "...")]` and selected at boot. No `-C target-cpu=native`.
   (`is_x86_feature_detected!` is std-only; use `core::arch::x86_64::__cpuid*` and your own detection.)
3. **Constant time for anything touching secrets.** No secret-dependent branches or memory indexing. No lookup
   table AES. Prefer audited RustCrypto implementations (`aes`, `ghash`/`polyval`, `chacha20`, `poly1305`,
   `sha2`) that already contain AES-NI/PCLMUL/SHA-NI/AVX2 backends, with their runtime detection hooked to
   `CpuFeatures` (check how each crate selects backends in `no_std` and whether it supports forced/own
   detection; record in ADR). Write own SIMD crypto only where measurement proves a crate path is the
   bottleneck, and then with exhaustive tests.
4. **Measure before enabling.** Every optimized path needs a micro-benchmark and an end-to-end number
   (handshakes/s, messages/s, telemetry MB/s). If it is not faster on real hardware, it stays off.
5. **Opt-out switch.** Build-time config `[cpu] disable = ["avx512", "vaes", ...]` lets an operator turn paths
   off (e.g. to work around a hypervisor bug). Validated by `config-schema`.

### 6.2 Dispatch mechanism

- A small `dispatch` module (shared by both architectures, introduced in X0) holds function pointers or
  `enum`-based selection per primitive: `aes_gcm_seal/open`, `chacha20poly1305_seal/open`, `sha256_*`
  (used by HKDF and the per-record key derivation), `crc32c`, `toeplitz_hash`, `memcpy_large` (only if measured).
- Selection happens once at boot, after `CpuFeatures` and before any core starts serving; tables are then
  read-only (lives in a page locked with the page tables).
- Boot log line, e.g.:
  `crypto: aes-gcm=vaes-avx2 chacha=avx2 sha256=sha-ni crc32c=sse42+pclmul toeplitz=gfni` and on aarch64 the
  equivalent names.

### 6.3 Candidate optimizations, in priority order

| # | Primitive | Instructions | Where it matters in urMQTT | Notes |
|---|---|---|---|---|
| 1 | AES-128-GCM | **AES-NI + PCLMULQDQ** | every TLS record, both directions, fan-out | interleave 4–8 blocks; must-have when available |
| 2 | SHA-256 | **SHA-NI** | TLS 1.3 handshake, HKDF, and the **per-record key/IV derivation** (README M15) | likely large win because per-record derivation hashes on every record; measure |
| 3 | CRC-32C | **SSE4.2 `crc32`** (+ PCLMULQDQ folding for long buffers) | superblock, file-size table, every telemetry record | baseline v2 already has SSE4.2 |
| 4 | ChaCha20-Poly1305 | **AVX2** (SSE2/SSSE3 baseline path) | clients that prefer ChaCha, CPUs without AES-NI | |
| 5 | AES-GCM, wide | **VAES + VPCLMULQDQ** (256-bit with AVX2) | large payloads, fan-out bursts, retained replay | 512-bit AVX-512 variant **opt-in only** (frequency effects on some Intel parts; validate on target hardware) |
| 6 | Toeplitz/RSS hash | **GFNI** or PCLMULQDQ | core-0 dispatcher, every packet | compare with the current table-based version |
| 7 | Bit operations | POPCNT (v2); LZCNT/TZCNT/BMI1/BMI2 (v3, dispatched only if it matters) | buddy allocator, slab bitmaps, timer wheel, trie | compiler intrinsics; beware TZCNT vs BSF semantics on old CPUs |
| 8 | Byte order | MOVBE | IPv4/TCP header parsing | only if measurable; usually not worth a dispatch |
| 9 | Prefetch | `prefetcht0` / PREFETCHW | TCP table lookup by 4-tuple, session lookup | measure under 100k+ connections |
| 10 | Waiting | UMWAIT/TPAUSE, MWAITX | ring consumers (5.2) | rarely exposed in VMs |
| 11 | Per-CPU access | FSGSBASE | per-CPU pointer reads | trivial, use when present |
| 12 | Entropy | RDSEED/RDRAND | CSPRNG reseeding | mixed, health-tested |
| 13 | Timekeeping | TSC-deadline, invariant TSC, kvmclock | timer wheel, watchdog | X4 |

Apply the same framework on aarch64 where an equivalent exists (ARMv8 SHA2 instructions for SHA-256,
`crc32c*` instructions for CRC-32C) so both architectures get the same class of speedup. Report both.

### 6.4 Correctness requirements for every optimized path

- Known-answer tests: NIST AES-GCM vectors, RFC 8439 (ChaCha20-Poly1305), FIPS 180-4 SHA-256 vectors,
  RFC 8446 / RFC 8448 TLS 1.3 traces for HKDF and record protection, CRC-32C reference vectors.
- **Differential fuzzing**: a fuzz target per primitive feeding identical random inputs (keys, nonces, AAD,
  lengths 0..64 KiB, unaligned buffers) to the portable and every optimized implementation; outputs and
  tag verification results must be identical.
- Run the host-side tests on an x86_64 machine with the features present (CI runner and the Linux KVM host);
  in-guest KATs run at boot in dev images (`test=crypto-kat`) on every CPU model of the smoke matrix.
- In-guest stress: KATs under heavy interrupt/IPI load (5.3).

---

## 7. Smoke matrix (x86_64)

| Machine | Firmware | CPU model | Purpose |
|---|---|---|---|
| q35 | OVMF | `max` (TCG) / `host` (KVM) | full feature set |
| q35 | OVMF | minimal v2: `qemu64,+ssse3,+sse4.1,+sse4.2,+popcnt,+cx16` | baseline paths, no AES-NI → ChaCha preference |
| pc (i440fx) | SeaBIOS | `max` / `host` | BIOS boot, port-I/O PCI config |
| q35 | OVMF | `qemu64` (no v2) | must refuse to boot with the clear message |
| q35 | OVMF | named models available in TCG/KVM (e.g. Intel Ice Lake / Sapphire Rapids, AMD EPYC Milan / Genoa) | dispatch selection per model |

All existing aarch64 scenarios keep running unchanged. `make smoke ARCH=both` runs everything.

---

## 8. Designing for more architectures (do this now, implement later)

The arch facade (X0), the dispatch framework (6.2), the build system (`ARCH=`), the smoke matrix and the
multi-arch image (X10) must be written for **N architectures**, not two. Concretely:

- No `if aarch64 { } else { x86 }` logic: use cfg-selected modules and per-arch tables.
- Kernel file names, Limine config entries and Makefile targets follow one pattern
  (`urmqtt-<arch>.elf`, `EFI/BOOT/BOOT<ARCH>.EFI`).
- Data-disk format and all protocol crates stay endian-explicit and pointer-width-agnostic.

## 9. Future milestone (not part of this work): riscv64

Only start after X11 and after the user confirms. Outline for a later prompt:

- Target `riscv64gc-unknown-none-elf`, S-mode kernel on OpenSBI (QEMU `virt`, UEFI via EDK2/U-Boot), Limine
  RISC-V UEFI loader (`BOOTRISCV64.EFI`) added to the same multi-arch ISO.
- Sv39/Sv48 paging with W^X; SBI for hart start (HSM), IPIs and timer (or the Sstc extension when present);
  interrupt controller PLIC, plus AIA (APLIC/IMSIC) for MSI-X; discovery via DTB and ACPI (RHCT/RINTC/MADT)
  where firmware provides it.
- Crypto via scalar crypto (Zkn) or vector crypto (Zvkned, Zvkg, Zvknh) when present, through the same
  dispatch framework; CFI via Zicfilp/Zicfiss when hardware supports it.
- Testing on QEMU TCG; real KVM-capable RISC-V hosts are still rare, so document limits honestly.

## 10. Definition of done

- One universal ISO and one universal raw image boot on aarch64 (UEFI) and x86_64 (UEFI and BIOS, q35 and pc).
- Full feature parity on x86_64; cross-arch data disks work.
- Bytes per idle mTLS connection on x86_64 ≤ aarch64 value (struct sizes identical, asserted).
- Optimized crypto/CRC paths selected at boot, proven equivalent by KATs and differential fuzzing, enabled by
  default only when measured faster on real hardware; opt-out via config.
- aarch64 numbers unchanged or better.
- Reproducible builds, signatures and release workflow cover both architectures.
- README and docs updated with measured numbers only.

Start with **X0**. Before writing code, reply in Croatian with: your understanding in 5–8 bullet points, the
current FP/SIMD policy on aarch64 and how you propose to handle 5.3, which RustCrypto crates (if any) the
project already uses and whether their x86 backends work in `no_std` with own feature detection, risks you see
in this plan, and the exact plan for X0.
