# Architecture Decision Records

Short ADRs: context, decision, alternatives, consequences. Status is
**Accepted** (in force, verified) or **Proposed** (direction agreed, must be
verified in the named milestone before it becomes Accepted).

---

## ADR-001 — Project name: urMQTT

- **Status:** Accepted (M0)
- **Context:** PROMPT.md uses the working name `ukmq` and allows renaming. The repository is `urMQTT`.
- **Decision:** Product name **urMQTT**. Lower-case identifier `urmqtt` for crates (`urmqtt-*`), the binary, ISO names (`build/urmqtt-<env>-<version>.iso`) and env vars (`URMQTT_ENV`). Serial markers become `URMQTT BOOT …` and `URMQTT READY`.
- **Consequences:** Wherever PROMPT.md says `ukmq`/`UKMQ`, read `urmqtt`/`URMQTT`.

## ADR-002 — Pinned nightly toolchain

- **Status:** Accepted (M0)
- **Context:** PAC/BTI must be compiled in (§4.3). Checked on 2026-10-28:
  - stable 1.97.1: `-C branch-protection` → `unknown codegen option`, `-Z` → `only accepted on the nightly compiler`.
  - nightly 2026-10-20: `-Zbranch-protection` is accepted, but rustc refuses to mix it with the precompiled `core` (`mixing -Zbranch-protection will cause an ABI mismatch`), so `-Zbuild-std` is needed as well, which is also nightly-only.
- **Decision:** Pin `nightly-2026-10-20` (rustc 1.101.0-nightly 07e526db9) in `rust-toolchain.toml`. Bump it on purpose, in its own commit, after `make check` and `make smoke` pass.
- **Alternatives:** Stable now and nightly at M2 (churn, and fuzzing needs nightly anyway). Stable without PAC/BTI (weaker security, which goes against the top priority).
- **Consequences:** Unstable flags are allowed only for branch protection, build-std and fuzzing. Host crates must not use `#![feature]`, so they stay stable-compatible.

## ADR-003 — FP/SIMD policy: enabled kernel-wide

- **Status:** Accepted (M0); implemented in M1 (CPACR_EL1.FPEN) and M3 (IRQ save/restore)
- **Context:** `aarch64-unknown-none` is a hard-float target (`"features": "+v8a,+strict-align,+neon"`, verified with `--print target-spec-json`), so the compiler may use SIMD registers anywhere, e.g. in `memcpy`. AES-GCM and ChaCha20 need SIMD/AES instructions to be fast, and SQLite uses floating point. PROMPT.md §8 suggests `-mgeneral-regs-only` for SQLite, which conflicts with this.
- **Decision:** Enable FP/SIMD on every core at boot. Exception entry from EL1 saves and restores the full FP state (q0–q31, FPCR, FPSR, about 528 B). IRQs are rare because of adaptive polling, so the cost is acceptable. Compile SQLite with FP and without `-mgeneral-regs-only`.
- **Alternatives:** `aarch64-unknown-none-softfloat` (several times slower crypto). Lazy FP trapping (complex, and the gain is small for a run-to-completion design).
- **Consequences:** Exception frames are larger. Kernel code must not assume the FP state survives a context switch unless it is saved.

## ADR-004 — Certificates and keys are never committed

- **Status:** Accepted (M0)
- **Context:** The repository is public. PROMPT.md §4.2 shows dev certificates inside `deploy/dev/`.
- **Decision:** `.gitignore` excludes every `*.pem` and `*.key`. `scripts/gen-dev-certs.sh` (and `make certs`, which `make check` and `make build` depend on) generates a dev CA, a server certificate, three device certificates and the negative-test certificates (rogue CA, expired). Production material is supplied by the operator.
- **Consequences:** A fresh clone needs `make certs` before `cargo build`. The build fails with a hint if the certificates are missing. Every developer has different dev certificates, which is fine. Release artifacts built by CI embed a throwaway dev key, so they are for evaluation only.

## ADR-005 — Configuration schema lives in a host crate

- **Status:** Accepted (M0)
- **Context:** `crates/config` must be `no_std` for the kernel, but parsing and validating TOML needs `std`, and the rules need host tests and fuzzing.
- **Decision:** `crates/config-schema` (`std`, `serde`, `toml`) holds the schema, validation and Rust code generation. It is used as a build-dependency of `crates/config` and by the `config_parse` fuzz target. `crates/config` holds only the `no_std` types and `include!`s the generated constants.
- **Consequences:** Adding a key touches three places: the schema, the `no_std` types and `render`. A type mismatch is caught at compile time because the generated code must type-check against `crates/config`.

## ADR-006 — Crate package names are prefixed `urmqtt-`

- **Status:** Accepted (M0)
- **Context:** Directory names such as `log`, `net`, `config` and `tls` clash with well-known crates.io packages.
- **Decision:** Directories follow PROMPT.md §4.2. Package names are `urmqtt-<dir>`, e.g. `cargo test -p urmqtt-mqtt`.

## ADR-007 — CI on GitHub-hosted arm64 runners; public releases are dev images

- **Status:** Accepted (M0)
- **Context:** The kernel is aarch64-only, and GitHub offers free arm64 Linux runners for public repositories.
- **Decision:**
  - Lint and kernel builds run on `ubuntu-24.04-arm`.
  - Host tests run on `ubuntu-24.04-arm` and `macos-15` (Apple Silicon, the dev platform).
  - `cargo-deny`, CodeQL, OpenSSF Scorecard and Dependabot cover supply chain.
  - Every third-party action is pinned by commit SHA.
  - Tagged releases publish only dev-environment artifacts with SHA256SUMS and SLSA build provenance.
- **Consequences:** QEMU smoke tests in CI will use TCG (from M1), because nested virtualization is not assumed on hosted runners.

## ADR-008 — SQLite heap sized to the VM, not fixed at 32 MB

- **Status:** Proposed (verify in M11)
- **Context:** §1 requires boot-and-serve in 64 MB RAM, while §8 defaults the SQLite heap to 32 MB.
- **Decision:** `storage.sqlite_heap_mb` stays configurable (dev: 32 MB for the 512 MB dev VM; prod template: 8 MB). At boot the kernel will refuse a heap larger than a fixed fraction of RAM (proposed: 25 %) and log the effective size.

## ADR-009 — Wall-clock time for certificate validity

- **Status:** Proposed (verify in M1/M10)
- **Context:** Rejecting expired certificates (M10) needs wall-clock time. The spec has no RTC driver and no NTP, and adding NTP would add attack surface.
- **Decision:** Use the Limine "date at boot" response (taken from the UEFI RTC) plus the monotonic generic timer. If the response is missing, the kernel will refuse TLS rather than accept certificates without a validity check.
- **Alternatives:** PL031 RTC (QEMU only). UEFI runtime `GetTime` (needs runtime services mapping). NTP.

## ADR-010 — MSI-X requires the GICv3 ITS; M6 starts with INTx/polling

- **Status:** Proposed (verify in M6); amended by ADR-014 (HVF exposes GICv2m, not an ITS)
- **Context:** On GICv3, MSI/MSI-X are delivered through the ITS (or a GICv2m frame). The spec makes ITS "optional later" but asks for MSI-X in M6.
- **Decision:** M6 uses legacy INTx (GIC SPIs) or polling for virtio. The ITS driver and per-queue MSI-X vectors land with multiqueue in M13.

## ADR-011 — Global session directory for cross-core reconnects

- **Status:** Proposed (design in M9, implement in M13)
- **Context:** A device that reconnects usually lands on a different core (new source port, so a new RSS hash). MQTT requires taking over the existing session with the same client ID and delivering its queued QoS 1 messages. Purely per-core session tables cannot do this.
- **Decision:** A directory sharded by `hash(device_id) mod data_cores`, reached through the SPSC rings, maps each device to its owning core. On CONNECT the connection's core asks the shard. If another core owns the session, it is migrated (serialized hot state plus queue) to the connection's core, and the old connection is closed (takeover). Topic node ids used in cross-core summaries must be global, for example hashes of the canonical topic or ids allocated by the directory.

## ADR-012 — TLS KeyUpdate after secret extraction

- **Status:** Proposed (verify in M10)
- **Context:** As far as is known, rustls `dangerous_extract_secrets()` returns AEAD key, IV and sequence numbers, but not the traffic secret needed to derive keys after a KeyUpdate. Newer rustls versions have a kernel-TLS API that may cover this. Not yet verified.
- **Decision:** Verify against the rustls version pinned in M10. If the traffic secrets are not available, a client KeyUpdate closes the connection, and the event is logged and counted. This is acceptable because IoT traffic volumes stay far below AES-GCM rekey limits. NewSessionTicket messages must be flushed before the secrets are extracted.

## ADR-013 — Watchdog "drop" acts only after the handler returns

- **Status:** Proposed (verify in M16)
- **Context:** With `panic = "abort"` and cooperative per-core loops, an IRQ cannot abort a running handler safely.
- **Decision:** `log` logs from the timer IRQ. `drop` marks the connection and closes it as soon as the handler returns to the core loop. `reset` calls PSCI `SYSTEM_RESET` from the IRQ when a handler is stuck beyond a hard limit (proposed: 10× budget).

## ADR-014 — QEMU/HVF findings: GICv3 works, GICv2 does not, MSI via GICv2m

- **Status:** Accepted (M1, verified 2026-10-29 on macOS 26.3, Apple M4 Pro, QEMU 11.1.2)
- **Findings:**
  - `-machine virt,gic-version=3 -accel hvf -cpu host` boots.
  - `gic-version=2` with HVF fails with `HVF does not support GICv2 emulation`.
  - Under HVF the DTB has **no GICv3 ITS**: MSIs go through a `arm,gic-v2m-frame` at 0x0802_0000. Under TCG there is an ITS at 0x0808_0000.
  - The high (64-bit) PCIe ECAM window at 0x40_1000_0000 is available under HVF.
- **Decision:** GICv3 only (PROMPT §3 allowed dropping GICv2). The MSI layer (M6/M13) must support **both** GICv2m frames and the ITS, chosen by discovery. ADR-010 is amended accordingly.

## ADR-015 — ISO layout: UEFI-only El Torito, boot files mirrored on ISO9660

- **Status:** Accepted (M1)
- **Context:** The first boot attempt left Limine at "Default entry is not valid": on CD boots Limine scans the ISO9660 volume, not the El Torito FAT image it was loaded from.
- **Decision:** `scripts/mkiso.sh` builds a FAT image (`/EFI/BOOT/BOOTAA64.EFI`, `/EFI/BOOT/limine.conf`, `/boot/urmqtt`) and copies the config and kernel onto the ISO9660 filesystem as well. The image is pure El Torito EFI, with no BIOS boot and no hybrid MBR or GPT. The same FAT image will become the ESP of the raw disk image (M17).
- **Hardening:** `limine.conf` sets `timeout: 0` and `editor_enabled: no`, so the image accepts no input, not even in the bootloader. The kernel path carries its BLAKE2b hash (`path: boot():/boot/urmqtt#<hash>`, `hash_mismatch_panic: yes`), so a swapped kernel does not boot. Only `BOOTAA64.EFI` is vendored, after its upstream GPG signature was checked (vendor/limine/CHECKSUMS).

## ADR-016 — Early MMIO mapping in the bootloader's tables (M1 only)

- **Status:** Accepted (M1), superseded by M2's own tables
- **Context:** With base revision ≥ 3, the HHDM covers only RAM-like memory map entries, so the PL011 is not mapped at entry.
- **Decision:** In M1 the kernel sets MAIR indices 2–4 (Device-nGnRE, Device-nGnRnE, Normal-NC), keeping indices 0 and 1, which Limine owns. It then claims a free level-0 slot of the TTBR1 tables as a 1 GiB MMIO window and maps device pages there. Table frames come from a bump allocator that takes 64 pages from the top of the largest usable region. M2 must exclude those frames from its frame allocator, or retire the bootloader tables entirely.

## ADR-017 — Kernel command line: test switches only in dev builds

- **Status:** Accepted (M1)
- **Decision:** `smoke` (power off instead of reset) and `test=data-abort|undef|brk|panic` are honoured only when `CONFIG.env == "dev"`. Other images count every word as ignored and log a warning. `make smoke` builds one ISO per scenario with its own command line.

## ADR-018 — Entry at EL2 (VHE)

- **Status:** Proposed (untested)
- **Context:** Limine base revision 6 may enter at EL2 with VHE on bare metal or under nested virtualization. QEMU `virt` (HVF/TCG) and KVM guests enter at EL1. The kernel logs `el=`.
- **Decision:** At EL2 an HVC would trap to the kernel itself, so a DTB/FADT HVC conduit is ignored there, and the kernel logs that the configuration is untested. Timers (CNTHP vs CNTP) and the GIC need attention before EL2 is supported. Until then it remains an explicit gap.

## ADR-019 — Kernel address space and page-table locking

- **Status:** Accepted (M2)
- **Decision:**
  - **Layout:** fixed upper-half slots, listed in `crates/kernel/src/layout.rs`: MMIO window, heap, heap metadata, per-CPU stacks, page-table alias and kernel image. The HHDM offset Limine chose is kept, so the bootloader's pointers (memmap, DTB, RSDP, framebuffer) stay valid. Boot fails if the HHDM would reach the fixed slots.
  - **W^X on four levels:**
    - Descriptor encoding cannot express W+X.
    - Text is RX and BTI-guarded, rodata R, data/bss RW-NX.
    - The HHDM alias of the kernel image and all firmware tables are read-only.
    - `SCTLR_EL1.WXN` is on.
    - A full walk after locking audits every leaf: no W+X, and nothing executable outside `.text`.
  - **Lower half disabled** (`TCR_EL1.EPD0`), so null and user pointers take a level-0 translation fault.
  - **Locking:** every page table comes from a 2 MiB-aligned pool that the HHDM maps read-only from the start. Before the lock, tables are edited only through a separate RW alias built from 2 MiB block mappings. `vm::lock()` removes that alias block by block, taking the block that holds the alias's own L2 table last, and then refuses every later mapping request. After boot no writable mapping of any page table exists.
- **Consequences:** The page-table pool costs at least 2 MiB (about 45 pages used at 512 MB RAM). Every mapping, including MMIO for devices found in M5/M6, must happen before the lock at the end of boot.

## ADR-020 — Stacks: SP_EL0 for code, SP_EL1 for exceptions, guard pages

- **Status:** Accepted (M2)
- **Decision:** After the switch, kernel code runs on SP_EL0 (main stack, 128 KiB) and exceptions arrive on SP_EL1 (exception stack, 32 KiB). Unmapped guard pages sit below both stacks, and above the main stack the slot stays unmapped. A main-stack overflow therefore faults into a handler that still has a valid stack, and the report names the guard page (`FAR is in: main stack guard page`).

## ADR-021 — PAC and BTI enablement

- **Status:** Accepted (M2), verified under HVF (Apple M4: PAuth + FPAC + BTI exposed to the guest) and TCG `-cpu max`
- **Build:** the kernel target is compiled with `-Zbranch-protection=bti,pac-ret` (`.cargo/config.toml`). `core`, `alloc` and `compiler_builtins` are rebuilt the same way with `-Zbuild-std` (Makefile `KERNEL_FLAGS`). The instructions are HINT-space NOPs on CPUs without the features, so the kernel still boots there.
- **PAC:** the IA key comes from the Limine Entropy feature: 8 values from EFI RNG or RNDR, mixed. Without bootloader entropy PAC stays off and a warning is logged. `SCTLR_EL1.EnIA` is set inside the assembly stack switch (`pac::switch_to`), never from Rust: a function compiled with `pac-ret` that enables PAC would fail to authenticate its own return. The continuation never returns.
- **BTI:** text pages carry the GP bit when FEAT_BTI is present. All indirect branch targets are compiler-generated landing pads, plus `bti c` at `_start`.
- **Verification:** `make smoke` forges a return address (EC 0x1c with FPAC) and branches to a non-landing pad (EC 0x0d) under both accelerators.

## ADR-022 — Timer-IRQ latency under QEMU: WFI costs about 2 ms on macOS hosts

- **Status:** Accepted (M3, measured 2026-10-29, Apple M4 Pro, macOS 26.3, QEMU 11.1.2)
- **Measurement:** the EL1 virtual timer (PPI 27) fires every 10 ms. Latency is the time from the programmed deadline (CNTV_CVAL) to the handler's first counter read. Both modes run at every boot:

  | Accelerator | Busy-poll (min / avg / max) | WFI (min / avg / max) |
  |---|---|---|
  | HVF | 1.9 / 3.9 / 7.8 µs | 110 µs / 1.81 ms / 2.3 ms |
  | TCG | 0.26 / 2.27 / 3.06 ms | 0.66 / 2.18 / 3.4 ms |

- **Interpretation:** under HVF, interrupt delivery to a running vCPU takes microseconds. A vCPU sleeping in WFI is descheduled on the host and woken late, presumably by macOS timer coalescing. TCG is limited by QEMU's timer emulation either way.
- **Decision:** confirms PROMPT §4.1. Data-plane cores busy-poll while there is work and drop to WFI only after an idle threshold (configurable, M13), accepting millisecond wake-up latency only when idle. Latency figures from macOS/QEMU are not representative of KVM on cloud hosts and must be re-measured there.
- **GIC findings** (see also ADR-014): GICD_TYPER reports 1020 lines under HVF and 288 under TCG. Both run the same distributor and redistributor code with affinity routing and group 1 non-secure interrupts.

## ADR-023 — SMP bring-up through Limine MP, mirrored CPU state

- **Status:** Accepted (M4, verified with 4 and 8 vCPUs under HVF and TCG)
- **Context:** Limine parks application processors and starts each one at a chosen address (`goto_address`) with its own stack. APs start in the bootloader's page tables, with FP disabled and SPSel = 0. PSCI `CPU_ON` would need an MMU-off entry path instead.
- **Decision:**
  - APs are released through Limine MP. A per-CPU `ApBoot` record carries the boot CPU's MAIR, TCR, TTBR1, SCTLR and VBAR, the PAC IA key, and the AP's two stack tops. The assembly entry `urmqtt_ap_entry` applies all of it before any compiled code runs: FP on, kernel tables plus local TLB invalidation, keys, VBAR, SCTLR with WXN/EnIA, SP_EL1 and SP_EL0. It then calls `ap_main` on the new stack.
  - Every core uses the same IA key. Return addresses are only ever authenticated on the core that signed them, so per-core keys would buy little.
  - The copy of the key in memory is dropped once all APs are up. The `ApBoot` records stay in `.data` and are zeroization candidates for M16.
  - `TPIDR_EL1` holds the logical CPU index (0 = boot CPU). Per-CPU data lives in a static array of 64 `PerCpu` slots; `MAX_CPUS = 64` also bounds the stack slots.
  - AP stacks are mapped before the page tables lock, and the APs start after the lock: they only read the tables.
  - IPIs use SGIs 1–3 (ping, pong, wake). `send_sgi` targets one MPIDR, using the ICC_SGI1R range selector for Aff0 ≥ 16, and issues `dsb ishst` first so data written before the IPI is visible to the handler.
- **Consequences:** PSCI `CPU_ON` (already implemented) remains the fallback for a bootloader without MP support. More than 64 CPUs are logged and ignored.

## ADR-024 — Platform description: one struct, firmware-assigned PCI BARs

- **Status:** Accepted (M5)
- **Decision:** `platform::PlatformInfo` holds UART, PSCI, GIC (GICD, GICR, ITS or GICv2m), timer PPIs, CPU MPIDRs and the PCIe ECAM window. It is filled either from the DTB or from ACPI (SPCR, FADT, MADT, GTDT, MCFG). Its `Display` form is the *platform summary*. `make smoke` boots `acpi=on` and `acpi=off` and requires the two summaries to match. A host test does the same for synthetic ACPI tables against the QEMU DTB.
- **PCI windows:** the summary has no BAR windows. With ACPI they live in AML (`_CRS` in the DSDT), and the kernel will not carry an AML interpreter. UEFI firmware (edk2 on QEMU, cloud firmware) has already enumerated PCI and assigned BARs on every target, so M6 uses the programmed BARs and does not allocate its own.
- **Found by fuzzing:** `fdt_parse` found an integer overflow in the timer PPI conversion within seconds. `bool::then_some` evaluates its argument eagerly, so `n + 16` ran even for invalid `n`. It is fixed by validating PPIs (< 16) with a lazy `then`. The input is kept as `fuzz/seeds/fdt_parse/regress-ppi-overflow`.

## ADR-025 — virtio drivers: polled by default, MSI-X via GICv2m; entropy policy

- **Status:** Accepted (M6)
- **Drivers:** virtio 1.x modern transport only (`VIRTIO_F_VERSION_1` required). Transitional IDs 0x1000–0x103f are accepted through their modern capabilities. Offloads, indirect descriptors and event-idx are not negotiated. Requests are synchronous and polled with bounded timeouts. Every value the device returns (used index distance, descriptor id, lengths) is validated: a misbehaving device gets `DeviceProtocol`, never an out-of-bounds access.
- **MSI-X:** with a GICv2m frame (QEMU under HVF), vector 0 of virtio-blk is pointed at a v2m SPI (`SETSPI_NS`), routed edge-triggered to the boot CPU, and completions do raise interrupts (3 per self-test). With only an ITS (TCG, KVM clouds) MSI-X stays off in M6 and the device is polled. The ITS backend arrives with multiqueue in M13. This amends ADR-010.
- **CSPRNG:** ChaCha20 (`rand_chacha`) seeded from a SHA-256 pool (`sha2`) with domain-separated inputs. The pool yields a generator only after at least 32 bytes from a *hardware* source: virtio-rng or `RNDR`. Bootloader entropy and timing jitter are mixed in but never sufficient alone. Without hardware entropy the kernel stops with `no hardware entropy source (virtio-rng or RNDR): refusing to run` (PROMPT §6). `Csprng::fork` derives per-core generators, and `reseed` adds fresh entropy with forward secrecy.
- **Data disk:** the last 8 sectors (4 KiB) are a scratch area for the boot self-test. The M11 layout must exclude them from every region.

## ADR-026 — Network prototype on smoltcp, single core, polled

- **Status:** Accepted (M7), to be replaced by the own stack (M14)
- **Decision:** smoltcp 0.14 (`alloc`, Ethernet, IPv4, DHCPv4, TCP, ICMP sockets) runs on the boot CPU behind a `phy::Device` adapter around `VirtioNet`. RX is polled; when idle the CPU sleeps in WFI and the 10 ms tick bounds wake-up latency. The other CPUs idle. After `URMQTT READY` the boot CPU runs the network service forever. In dev builds that includes a TCP echo service on port 7, used by smoke tests through `hostfwd`. The `serve` command-line switch keeps a smoke image alive after READY.
- **Ping from the host** is not possible: QEMU user networking does not deliver ICMP to the guest. Instead the guest pings the slirp gateway (10.0.2.2) after its DHCP lease, which exercises ARP, IPv4 and ICMP in both directions.
- **smoltcp interface seed** comes from the kernel CSPRNG.

## ADR-027 — MQTT codec strictness

- **Status:** Accepted (M8)
- **Decision:** the decoder is strict wherever MQTT 3.1.1 is normative, and adds canonical-form checks of its own:
  - Remaining length uses at most 4 bytes and must be minimally encoded; `0x80 0x00` is rejected. The declared packet size is checked against `limits.max_packet_size` *before* the body arrives, so a peer cannot make the broker buffer an oversized packet.
  - Fixed-header flags are exact (PUBREL, SUBSCRIBE and UNSUBSCRIBE need `0b0010`); DUP on QoS 0, QoS 3, packet id 0 and trailing bytes are all errors.
  - CONNECT: the protocol name must be `MQTT`. Level ≠ 4 (and `MQIsdp` 3.1) decodes to `UnsupportedProtocolLevel`, so the broker can answer CONNACK 0x01. The reserved flag, will flags without a will, and a password without a username are rejected.
  - Strings: valid UTF-8 without U+0000. Topic names have no wildcards. Topic filters put `#` only as the whole last level and `+` only as a whole level. Length and level count are checked against the limits.
  - Encoding is the inverse. The `mqtt_decode` fuzz target checks *decode → encode → decode* equality for every accepted packet, so parsing is never lossy or ambiguous.
- **Interop finding:** `mosquitto_pub` 2.1 (`-q 1`) may close TCP right after PUBACK without sending DISCONNECT. That is normal client behaviour. Because a will was set, the broker must treat it as an unclean disconnect and publish the will (M9).
