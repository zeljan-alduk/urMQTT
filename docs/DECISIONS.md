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

- **Status:** Superseded by ADR-033 (M14): smoltcp is gone from the image
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

## ADR-028 — Sans-IO broker core; service identities; v1 QoS policy

- **Status:** Accepted (M9)
- **Sans-IO:** `urmqtt-broker` takes bytes and milliseconds and produces bytes (`input`, `output`/`consumed`, `close_requested`, `closed`, `tick`). It knows nothing about sockets, so it is tested end to end on the host over an in-memory transport, and the transport can change (smoltcp now, the own TCP stack in M14, per-core loops in M13) without touching broker logic.
- **Identities and ACL:** the identity is the client id in dev plaintext mode and the certificate field from M10. An identity becomes a topic level through `{id}`, so it must be non-empty and contain no `/`, `+`, `#` or leading `$` (otherwise CONNACK 0x02). *Service identities* (`acl.service_ids`: exact ids or `prefix*`) get their own `service_publish` and `service_subscribe` patterns. That is how a backend talks to devices under the default device ACL. A subscription is allowed only if one pattern *covers* the filter: every topic the filter can match must be allowed, so `devices/+/cmd/#` is refused for a device. A will outside the device's publish rights is refused at CONNECT (0x05).
- **3.1.1 choices:**
  - An unauthorised or rate-limited PUBLISH is acknowledged and dropped (§3.3.5 allows ack-or-close).
  - QoS 2 publishes close the connection, and QoS 2 subscriptions are granted QoS 1 (QoS 2 is a "later" item).
    *Superseded by ADR-271 (2026-11-08): QoS 2 is supported, method B, granted at 2.*
  - Overlapping subscriptions of one session get one delivery at the highest QoS.
  - Retained messages go to new subscribers with RETAIN=1 and are routed live with RETAIN=0.
  - A will is published on any close except after DISCONNECT, including takeover and keepalive expiry (1.5 × interval).
  - Offline persistent sessions queue QoS 1 (bounded by `max_queued_per_offline_session`) and drop QoS 0.
  - Unacknowledged in-flight messages are resent with DUP on reconnect.
- **Plaintext port:** only in `dev` (build-time enforced), logged with a warning at boot.

## ADR-029 — TLS 1.3: rustls for the handshake, own provider and record layer

- **Status:** Accepted (M10)
- **Handshake:** `rustls` 0.23 (`no_std`, no default features) through `UnbufferedServerConnection`. TLS 1.3 only, with suites TLS13_CHACHA20_POLY1305_SHA256 and TLS13_AES_128_GCM_SHA256, groups X25519 then secp256r1, and server and client signatures ECDSA P-256/SHA-256 (the dev and recommended production profile; other key types fail at build-time validation).
- **Own crypto provider** (`crates/tls/src/provider`), built on RustCrypto: `aes-gcm`, `chacha20poly1305`, `p256` 0.14, `x25519-dalek`, `sha2`, `hmac`, `hkdf`. Randomness comes only from the kernel CSPRNG (ADR-025). Without it `start()` fails with `FailedToGetRandomBytes` and never falls back. ECDSA signing uses deterministic RFC 6979 nonces, so a signature does not depend on the RNG at signing time. P-256 ephemeral keys are rejection-sampled from CSPRNG bytes.
- **Dependency hygiene:** `p256` 0.13 pulled `crypto-bigint` 0.5.5, which is affected by RUSTSEC-2026-0387 (secret-dependent branches in constant-time arithmetic). We moved to the `p256` 0.14 / `sha2` 0.11 / `hmac` 0.13 / `hkdf` 0.13 / `x509-cert` 0.3 / `der` 0.8 generation instead of ignoring the advisory, which also removed most duplicate crates. The remaining duplicates are `rand_core` 0.6 (needed by `x25519-dalek` 2 and `rand_chacha` 0.3) and `crypto-common`/`cpufeatures` (needed by `aes-gcm`/`chacha20poly1305` 0.10).
- **Secret extraction:** rustls exposes the traffic secrets for kTLS-style offload only through `dangerous_into_kernel_connection()`, which hands over the *current* keys but no way to rekey from our side. We therefore capture the client and server application traffic secrets through a `KeyLog` keyed by the ClientHello random. After the handshake we convert to the kernel connection (to drain any post-handshake records rustls still owns, e.g. NewSessionTicket) and drop it at once.
- **Own record layer** (`record.rs`): TLS 1.3 records (RFC 8446 §5) with per-direction key, IV and 64-bit sequence numbers. It handles `KeyUpdate` in both directions (`update_requested` is answered), `close_notify`, inner content-type padding removal, the 2^14+256 ciphertext limit and the AES-GCM record limit (2^24 per key, then KeyUpdate). It is verified against RFC 8448 vectors and against a real rustls client (application data, KeyUpdate both ways).
- **Client authentication:** a `WebPkiClientVerifier` rooted at the embedded CA, wrapped by a revocation check. `tls.revocation_list` names a file in `deploy/<env>/` with one hex serial per line; serials are normalised by stripping leading zeros so `00ab` matches `ab`. This build-time list is a bridge until the SQLite revocation table (M11). Expiry is checked against a wall clock: the firmware date at boot (Limine) plus uptime. Without a date at boot every handshake is refused (ADR-009).
- **Identity:** the device id comes from the configured field. With `cn` it is the subject CN. With `san_uri` it is the rest of a `urn:urmqtt:device:` or `urn:urmqtt:service:` URI. The broker refuses a CONNECT whose client id differs from it (CONNACK 0x02, ADR-028), so the TLS layer authenticates and the broker authorises.
- **Resumption:** stateless PSK tickets sealed with ChaCha20-Poly1305 under a key from HKDF(server key, version string). Tickets survive a reboot of the same build and become invalid with a new version or key. Tickets are not bound to a revocation epoch: a revoked device may resume until its ticket expires. Ticket lifetime is 24 h, and M11 adds an epoch check.
- **Admission and timeouts:** a per-core token bucket (`limits.handshakes_per_core_per_sec`) gates new handshakes. Excess connections are closed before any crypto work and counted in one rate-limited log line. A whole handshake must finish within 10 s. Per-phase timeouts are left for the own TCP stack (M14), where the phases are visible.
- **Interop findings:**
  - OpenSSL clients (mosquitto) report `unexpected eof` (exit 4) unless the server sends `close_notify` before FIN. We now send it whenever the socket can still send, which includes `CloseWait`.
  - Aborting a socket in `TimeWait` sends an RST that some clients report as an error; we simply let it expire.
- **Known gaps** (tracked in PROGRESS): the kernel ELF is about 1.10 MB (target < 1 MB, M15/M17). Record-layer state is about 170 B per connection (two directions with expanded AES/ChaCha keys) against the 128 B target (M15: keep raw keys and expand per record, or share key schedules).

## ADR-030 — SQLite in the kernel: raw-disk VFS, DB core, persistence model

- **Status:** Accepted (M11)
- **Build:** the official 3.54.1 amalgamation is vendored in `vendor/sqlite`. `crates/store/build.rs` checks it against `CHECKSUMS` (SHA-256; the upstream zip's SHA3-256 is recorded) before compiling, so a modified file is never linked.
  - For `aarch64-unknown-none` it is built freestanding with clang (Homebrew LLVM if present, else `clang`/`clang-18`; override with `URMQTT_CLANG`) and archived with `llvm-ar` (`URMQTT_AR`). Apple's `ar` writes BSD archives with an empty symbol table for ELF members.
  - Flags match the kernel ABI: hard float (ADR-003; no `-mgeneral-regs-only`, SQLite uses FP), `-mbranch-protection=pac-ret+bti` (text pages are BTI-guarded, ADR-016), `-mstrict-align`, no PIC, no stack protector, `-Os`, and `-ffile-prefix-map` (no build paths in the objects).
  - Host builds (tests) use the host compiler and libc.
- **Compile options:** every option was verified against 3.54.1:
  - `OS_OTHER`, `THREADSAFE=0`, `ENABLE_MEMSYS5` + `ZERO_MALLOC` (no system allocator at all), `TEMP_STORE=3`, `DEFAULT_MEMSTATUS=0`, `DQS=0`.
  - Omitted: `LOAD_EXTENSION`, `SHARED_CACHE`, `DEPRECATED`, `LOCALTIME`, `PROGRESS_CALLBACK`, `AUTHORIZATION`, `AUTOINIT`, `JSON`, `UTF16`, `TRACE`, `COMPLETE`, `GET_TABLE`, `TCL_VARIABLE`, `DECLTYPE`.
  - Also: `UNTESTABLE`, `MAX_MMAP_SIZE=0`, page size 4096, exclusive locking and `synchronous=FULL` as defaults, foreign keys on, no worker threads.
  - `SQLITE_OMIT_ATTACH` does **not** work with the amalgamation (the generated parser still references `sqlite3Attach`, `sqlite3Detach` and `sqlite3Vacuum`), so `SQLITE_MAX_ATTACHED=0` is used instead.
  - `SQLITE_OMIT_DATETIME_FUNCS` is not used: its fallback needs `gmtime`/`strftime`.
  - Memory statistics are enabled at run time (`SQLITE_CONFIG_MEMSTATUS`) for the boot log and M15.
  - `SQLITE_USE_ALLOCA` is not used.
- **libc:**
  - The amalgamation's undefined symbols are exactly `memcmp`, `memcpy`, `memmove` and `memset` (from `compiler_builtins`), plus `strchr`, `strcmp`, `strcspn`, `strlen`, `strncmp`, `strrchr` and `strspn`. The `str*` functions are small Rust implementations in `crates/store/src/libc.rs`.
  - Minimal headers in `crates/store/csrc/include` declare only these. `assert` is a no-op, and `math.h` maps to compiler builtins.
- **Data disk:** no filesystem.
  - A 4 KiB superblock with magic, version, uuid, region table and CRC-32C, then a double-buffered *file-size table*, then 4 KiB-aligned regions: main DB (½), WAL (⅛, 2–64 MiB), rollback journal (1 MiB) and telemetry (the rest, M12). The last 8 sectors stay scratch for the boot self-test.
  - A blank (all-zero) disk is formatted at boot: size table first, superblock last. Anything else without our magic, with a bad CRC or with an inconsistent region table is **never formatted over**.
- **VFS (`urmqtt`):**
  - Three fixed files map onto the regions: `urmqtt.db`, `-wal` and `-journal`. Reads and writes are bounds-checked, with read-modify-write for partial sectors.
  - Logical file sizes live in the size table. `xSync` flushes the data, then writes the next size slot and flushes again, so a size never covers data that is not durable.
  - `xDelete` zeroes the logical size. Locks always succeed (single owner). `xRandomness` uses the kernel CSPRNG, `xCurrentTimeInt64` the boot wall clock, and the sector size is 512.
  - `xDeviceCharacteristics` = 0: no atomic writes and no powersafe overwrite, so SQLite assumes a torn sector can damage its neighbours and pads WAL commits accordingly. That is the right assumption for our read-modify-write.
  - `io_methods` is version 1 (no shared memory): WAL works because `PRAGMA locking_mode=EXCLUSIVE` is set *before* `journal_mode=WAL`. This is verified at open (`journal_mode` must return `wal`); failure refuses to start.
  - `wal_autocheckpoint` is sized to half the WAL region.
- **Durability policy:**
  - `synchronous=FULL`, so a commit is durable when it returns.
  - A device without `VIRTIO_BLK_F_FLUSH` is refused (`storage.require_flush`).
  - `PRAGMA quick_check` runs at every boot. On failure the kernel refuses to serve (`storage.refuse_on_corruption`).
  - No data disk means refusing to serve (`storage.require_data_disk`).
  - All three may be false only in `dev`, where the broker then runs memory-only with a loud log line.
  - `DBCONFIG_DEFENSIVE` is on and `TRUSTED_SCHEMA` off. All SQL is fixed and prepared once at open. Schema migrations are embedded and append-only, versioned by `user_version`, and a database from a newer build is refused.
- **Heap:** `storage.sqlite_heap_mb` of physically contiguous frames (HHDM, RW, NX) is given to `memsys5` once (`SQLITE_CONFIG_HEAP`). SQLite never touches the kernel heap.
- **DB core:**
  - With ≥ 2 CPUs the highest-numbered CPU becomes the DB core after SMP bring-up and runs only the worker. With one CPU the network loop runs it between iterations.
  - Data plane and DB core share only two SPSC rings, requests (4096) and responses (256), whose orderings are documented in `arch-aarch64/src/spsc.rs`. The data plane never blocks: a full ring spills into a local backlog that keeps order.
  - The DB core sleeps in `wfe`. It is woken by `sev` after pushes and by the generic-timer event stream (about every 0.5–1 ms), which bounds the batch delay.
  - Writes are grouped into one transaction per 5 ms or 512 operations. Each commit is reported on the response ring.
  - The store is opened, checked and loaded on the boot CPU *before* the other cores start, then handed over under a lock.
- **What is persisted:**
  - Retained messages (set or cleared on every retained PUBLISH and will).
  - Persistent sessions: the row is created when a `clean_session=0` session attaches, subscriptions on SUBSCRIBE/UNSUBSCRIBE, and the session is deleted on a clean reconnect.
  - Queued QoS 1 messages while the session is offline: a snapshot of in-flight + queue at disconnect, then one row per new message, cleared when the session reconnects.
  - The device registry (first and last seen, connect count), written when a TLS identity authenticates.
  - Revoked serials, seeded from `tls.revocation_list` at every boot.
  - The broker emits these as `PersistOp`s (sans-IO). On restore, stored subscriptions and topics are re-checked against the current ACL and limits, and whatever fails is dropped from the store.
- **Not persisted (v1):** in-flight state of *online* sessions. A broker crash loses unacknowledged QoS 1 deliveries to connected devices, though the publisher has already been acknowledged. Mosquitto has the same window between autosaves. Closing it means writing every QoS 1 delivery before sending it, which is a later trade-off. Persistent sessions never expire (MQTT 3.1.1 has no expiry), so their number is bounded only by the disk and the ACL.
- **Revocations at run time:** the TLS server reads the list from the store at boot. Revoking without a rebuild needs an operator path (M16) and the refresh control message from the DB core (PROMPT §6).
- **Testing:**
  - Host tests run real SQLite through the VFS on a `MemDisk` with a volatile write cache. Power loss is simulated by applying an arbitrary subset of the unflushed writes. They check: the store round-trip; uncommitted work rolled back; 12 crash rounds that must leave `integrity_check` = ok and keep every acknowledged commit; and foreign or damaged superblocks refused.
  - The smoke test kills QEMU with SIGKILL while the kernel commits in a loop and verifies on the next boot. The host page cache survives that, so this proves VM-crash consistency, not host power loss; the `MemDisk` tests cover reordering and loss.
  - `disk_layout` fuzz target.

## ADR-031 — Telemetry log: per-core partitions written by the DB core

- **Status:** Accepted (M12)
- **Placement:** inside the telemetry region of the data disk (ADR-030). A 4 KiB header (magic, version, geometry, CRC-32C) is followed by **8 partitions**; source core `c` uses partition `c % 8`.
  - Each partition is a ring of fixed-size segments (⅛ of the partition, 64 KiB – 8 MiB, 4 KiB aligned).
  - Each segment starts with a 512-byte header (magic, partition, sequence number, creation time, CRC), followed by records `len · crc · ts_ms · topic_len · topic · payload`.
  - A blank region is formatted on first use. Foreign data in it is refused (never formatted over).
- **Who writes:** the cores keep their own partitions, but the **DB core performs all disk I/O** (the virtio-blk device has one queue and one owner: ADR-030). The data plane hands batches of `(Unix ms, Arc<message>)` to the DB core over **one SPSC ring per source core**: zero copies before the final encoding, and no lock between cores. That is the "one ring per ordered core pair" of PROMPT §7.2.
  - The data plane batches 256 records or 1 ms. If the ring is full it keeps accumulating (up to 65 536 records, then drops and counts them), so it never blocks.
  - The DB core flushes every 5 ms or 256 KiB of pending records. A flush writes whole sectors, zero-padded after the last record, then syncs. A sector tail is kept in memory, so no read-modify-write is needed.
- **Record integrity:** each record's CRC-32C covers the **segment sequence number** and its bytes. Records left over from an earlier pass of the ring therefore never validate in a reused segment, so stale data needs no erasing. Records never span segments.
- **Recovery:** read every segment header and order the valid ones by sequence number. Scan each segment until the first `len == 0` (clean end) or the first record that fails its checks (a **torn tail**: counted and truncated).
  - After recovery, writing always continues in a **new segment**. Bytes after a recovered segment's last valid record may be valid records of an unacknowledged batch whose earlier sectors were lost (writes reach the medium in any order). Extending that segment could make them reappear behind newer records. The host test `lost_middle_of_a_batch_is_never_resurrected` covers this.
  - The cost is the unused rest of one segment per partition per boot.
- **Retention:**
  - By size: the ring reclaims the oldest segment when the newest is full.
  - By age (`storage.retention_days`): readers skip expired records, and recovery counts them. Expired data stays on disk until its segment is reused, so this is a visibility rule and not erasure. Erasure on demand belongs with ops (M16).
- **Not done (v1):** the time-series encodings and zstd dictionaries of PROMPT §7.4 (raw records only); an export/read API for operators (M16); per-core I/O queues (M13, with multiqueue virtio-blk).
- **Testing:**
  - Host tests on `MemDisk`: reopen, torn tail, ring wrap without resurrection of old generations, age retention, power loss mid-flush with an arbitrary subset of writes surviving, foreign data refused.
  - Smoke `log-crash`: three cores write until at least 1 M records are durable, then SIGKILL. The next boot must recover every durable record, with each core's sequence contiguous.
  - Smoke `log-tear`: a deliberately torn record is written through the real disk path. The next boot must truncate it, keep the 10 500 complete records, and report one torn tail.

## ADR-032 — Multicore data plane: dispatcher, worker cores, home shards

- **Status:** Accepted (M13)
- **Topology:** with storage and ≥ 2 CPUs the last CPU is the DB core (ADR-030). The others are **data cores** `0..n`. With one data core, core 0 does everything. Otherwise core 0 runs the NIC, the dispatcher, DHCP, ICMP and the dev echo port, and cores `1..n` are the **MQTT workers**. Running TLS handshakes on the dispatcher delayed the other cores' frames by milliseconds.
- **NIC: dispatcher mode only (v1).** Core 0 owns the single virtio-net queue pair.
  - It classifies each frame (`urmqtt-net::classify`). IPv4 TCP to an MQTT port goes to the worker given by the **Toeplitz hash** of the 4-tuple (Microsoft RSS key, verified against the RSS verification suite), so a later NIC with RSS and the same key would agree. ARP replies go to every core's stack; everything else stays on core 0.
  - Frames move as owned buffers through 0→c and c→0 SPSC rings: one copy out of the DMA ring, none after. Buffers circulate (RX buffers are reused for TX), so the steady state does not allocate.
  - virtio-net multiqueue + RSS is **not implemented**: QEMU user networking (the only backend on macOS without root) has no multiqueue, so the path could not be tested. That is a known gap; the hash already matches RSS.
- **Per-core stacks:** every data core runs its own interface and TCP stack (smoltcp in M13, the own stack since M14, ADR-033) with the same MAC and IP (core 0 forwards the DHCP lease as a control message), its own sockets, TLS server and MQTT service.
- **Sessions: home shards.** A session lives on the worker given by `fnv1a(client id) % workers`, stable across boots, so restored sessions find their shard. Takeover, wills, keepalive and persistence therefore stay core-local.
  - The TCP + TLS connection stays on its *transport* core (the flow's core).
  - If home ≠ transport, plaintext MQTT bytes are relayed: `Open`/`Input`/`Closed` one way, `Output`/`Close` back. The home core sends replies only within a **credit** (32 KiB) that the transport returns as it encrypts them. The transport stops reading the socket while its backlog to the home core is long, so TCP flow control pushes back on the client.
  - Relay ids carry a slot generation, so late messages never reach a reused slot.
  - Dev plaintext connections are held until their CONNECT names the client.
- **Fan-out:** every message a shard routes (PUBLISH, will) is offered to every other worker (`Broker::drain_routes` → `route_remote`). Each shard keeps a replica of the retained messages; only the origin persists them. QoS 0 fan-out to a peer whose backlog exceeds 16 384 messages is dropped and counted; QoS 1 is never dropped.
- **Per-CPU heap caches:** `urmqtt-mm::CachedHeap` keeps 7 size classes (32 B – 2 KiB, the buddy orders) per CPU, IRQs masked while touching them, and refills or drains 16 blocks per global-lock acquisition (≤ 32 KiB kept per class per CPU). That reduces the ticket-lock traffic (unfair to descheduled vCPUs) on the TLS-heavy path.
- **Adaptive polling:** a core busy-polls while it has work and for 100 µs after, then sleeps in **WFI**. Producers wake a sleeping peer with an SGI. A Dekker-style handshake (flag store + SeqCst fence on the sleeper, ring push + SeqCst fence + flag load on the producer) avoids lost wake-ups.
  - WFE is not used: under HVF, QEMU treats WFE as a no-op, so WFE-based idle loops spun at 100 % of a host CPU and made every added vCPU *slower*.
  - Core 0 has no RX interrupt yet (MSI-X for virtio-net is a later item), so the first packet after an idle period waits for the 10 ms tick. *Amended by ADR-224 (a 200 us poll while connections exist) and ADR-270 (the receive queue's MSI-X interrupt wakes core 0; the poll is the fallback).*
- **virtio-net transmit** is asynchronous: 256 descriptors with their own bounce buffers, lazy reclaim, one kick per loop pass and only if the device asks for one (`VIRTQ_USED_F_NO_NOTIFY`). Received buffers are recycled with one kick per burst. Before, every frame cost two VM exits and a synchronous wait.
- **smoltcp findings:**
  - In a simultaneous close smoltcp ignores the ACK carried by the peer's FIN and waits a full RTO (1 s) in CLOSING. TIME_WAIT lasts 10 s.
  - The session therefore now ends when we close our side, which also makes persistence snapshots timely. Sockets in TIME_WAIT/CLOSING are replaced by fresh listening sockets: no RST, so a late duplicate just gets a RST from the stack.
  - Both become moot with the own TCP stack (M14).
- **Logging at scale:** per-connection lines are `debug`. Every character on the emulated PL011 is a VM exit taken under QEMU's big lock, which serialised all vCPUs. The dev-only `log=` boot switch lowers the level for benchmarks.
- **Measuring scaling:**
  - `test=dp-bench` runs full TLS 1.3 + mTLS handshakes with CONNECT/CONNACK, client and server in the guest, on 1, 2 and 4 workers in parallel. It isolates the data plane from the host. Smoke requires ≥ 3.0× on 4 workers under HVF/KVM (measured 4.00×).
  - The network benchmark (`urmqtt-loadgen` through QEMU user networking) is capped by QEMU's single-threaded slirp and the userspace GIC: about 0.8–1.25 k conn/s whatever the worker count, falling as spinning vCPUs compete for host CPUs. Inside the guest the TLS cost per handshake stays constant (≈ 0.58 ms HVF, ≈ 3.3 ms TCG) and the workers are not saturated.

## ADR-033 — Own server-only TCP/IP stack

- **Status:** Accepted (M14); supersedes ADR-026. smoltcp is no longer a dependency.
- **Layering:** both new crates are sans-IO and host-tested.
  - `urmqtt-net`: Ethernet, ARP, IPv4, ICMP echo, UDP and an own DHCPv4 client, plus a per-core `Iface`.
  - `urmqtt-tcp`: segments in through `input` with an `App` that receives events synchronously, segments out through a callback, and time in milliseconds.
  - Every data core runs one `Iface` and one `TcpStack` with the same addresses (ADR-032).
- **IPv4 strictness:** IP options and fragments are dropped (MF or a non-zero offset; DF alone is fine), as are bad checksums, other protocols and non-IPv4 frames. ICMP echo replies are limited to 100/s, and RSTs to unknown connections to 200/s.
- **Neighbours:** replies need no ARP. The interface learns the sender's MAC from every IPv4 frame addressed to us, in a 32-entry LRU. Only the owner core answers ARP requests. It asks for the router's MAC before its boot-time ping.
- **DHCP:** DISCOVER → REQUEST → ACK, renewal at T1 and rebinding at T2 (both broadcast), expiry back to DISCOVER, retransmission 4 → 64 s. Static addressing comes from `network.mode = "static"` in the build-time configuration.
- **TCP, passive open only:**
  - **SYN cookies always on:** the ISN is a 5-bit 64 s counter, a 3-bit MSS index and a 24-bit SipHash-2-4 MAC over the 4-tuple, the client ISN and the counter, so a SYN creates no state.
    - Like Linux without timestamps, cookies cannot carry window scaling or SACK, so neither is negotiated: the window is at most 64 KiB, which is plenty for MQTT.
    - A data segment that fails the cookie check is dropped instead of reset: it may have overtaken a lost final ACK, and the client retransmits from its first byte.
  - **Table:** open addressing with linear probing on (remote address, remote port, local port), at most half full, with tombstones rebuilt when they pile up.
  - **Per-connection state:** about 120 bytes (96 since M15, ADR-034), with the send buffer separate. **No buffers while idle:** received data goes to the application straight from the segment, and the send buffer exists only while data is queued or unacknowledged.
  - **Timers:** one per connection (retransmission, persist or FIN-WAIT-2) in a 4-level × 64-slot hierarchical wheel (`urmqtt-timer-wheel`). Insert and cancel are O(1) with generation-tagged ids, and empty stretches are skipped.
  - **RTO** per RFC 6298 (initial 1 s, 200 ms – 60 s, Karn) with exponential backoff, giving up after 8 retries. **NewReno** (RFC 5681/6582, initial window 10 segments) sits behind a `Congestion` trait.
  - Go-back-N after a timeout, with `snd_max` so ACKs for data sent before the rollback stay valid. The simulated-loss tests found this deadlock.
  - Persist timer for zero windows. No TCP keepalive: MQTT keepalive is the liveness mechanism.
  - **ACK coalescing:** ACKs are deferred to `flush` at the end of the loop pass. A reply the application sends in the same pass (PUBACK, CONNACK, PINGRESP) carries the ACK, so one segment goes out instead of two.
  - **Windows:** the application sets a receive-space limit per connection (`set_recv_space`, its backpressure). The advertised window never retracts.
  - **Receive in order only:** out-of-order segments are dropped and answered with a duplicate ACK. That is simple, and the sender's fast retransmit repairs single losses.
  - **RFC 5961:** a RST must hit `rcv_nxt` exactly (in-window gets a challenge ACK), and a SYN on an established connection gets a challenge ACK. A pure ACK with a stale sequence number still has its acknowledgement processed.
  - **No TIME_WAIT (server-side RST policy):** after the final ACK the connection is forgotten, and a late duplicate gets a RST.
- **Event-driven MQTT service:** TCP delivers accept/data/peer-closed/closed events, and the broker reports connections with new output (`drain_ready`). Only blocked connections and pending handshakes are revisited, so no per-packet path scans every connection. Keepalive and handshake expiry run every 100 ms.
- **Testing:**
  - Unit tests per module: the cookie window and binding, the table against a HashMap under 200 k operations, SipHash reference vectors, checksum and option parsing, the timer wheel against a model.
  - Stack tests against a scripted client over a simulated link: lossless echo of 100 KB; 8 seeds with 10 % loss and 5 % duplication, including sequence-number wrap; 25 % loss; SYN floods holding no state; forged and expired cookies; RFC 5961 RST/SYN rules; retransmission timeout with backoff; zero window and persist probes; out-of-order data; ACK coalescing; refused connections.
  - The `tcp_segment` fuzz target drives segments relative to a live connection.

## ADR-034 — Memory per connection: exact accounting, compact state, no per-device trie nodes

- **Status:** Accepted (M15).
- **What is measured:** the heap keeps two exact counters per CPU, the bytes callers requested and the buddy blocks those requests occupy (each request rounded to its power-of-two block, as the heap really hands it out). Core 0 logs every 10 s while connections exist: heap above the idle baseline, minus the change in frame buffers, divided by the open connections. **The block figure is the one reported as "bytes per connection"**: it includes allocator rounding and slab slack. Frame buffers are a bounded pool (RX rings and per-core pools, about 2 MiB), independent of the connection count, and logged separately.
- **Layout of an idle mTLS connection** (inline sizes, all asserted in tests or at compile time):

  | Where | Size | How |
  |---|---:|---|
  | TCP `Conn` (`urmqtt-tcp`) | 96 B | flags in one byte, RTT/RTO in 16 bits (≤ 60 s), wrapping 32-bit RTT start, send buffer boxed and absent while idle |
  | TCP table | 4 B per slot | connection indices only; keys are compared through the connections, at most half full |
  | Service `Conn` (kernel) incl. TLS | 152 B | TLS record state inline (104 B): per direction only the traffic secret and sequence number (40 B) |
  | Broker `Conn` | 48 B | identity (until CONNECT) and Will in an optional box; buffers absent while empty |
  | Broker `Session` | 64 B | one subscription inline (`Small<Sub>`), token bucket flattened, connection id as `NonZeroU32` |
  | Subscription | 8 B | interned node id + QoS + scoped flag |
  | Client id | 1 block | the only per-device string; the index stores session ids, not strings |
  | Relay (sessions homed on another core) | 16 B + 16 B | `Remote` and the transport-id map entry |

- **Slabs sized to the heap:** the chunked slab (64 entries per chunk before) now fills one 8 KiB buddy block per chunk (`CHUNK_BYTES / size_of::<Option<T>>()` entries), so a 96-byte entry wastes under 1 % instead of a third (6 KiB rounded to 8 KiB).
- **TLS keys derived per record:** the AEAD key and IV are expanded from the traffic secret (HKDF-Expand-Label) for every record, on the stack, wiped after use. An idle connection holds 2 × 40 bytes of secrets and no expanded key schedule. The record state lives inline in the connection's slab entry instead of a separate heap block (this is the "key slab" of PROMPT §6: slab-resident, exactly sized, zeroized on drop). The cost is two HKDF expansions per record, a few microseconds; idle connections dominate the target workload.
- **Device-scoped subscriptions (PROMPT §7.3):** a filter `<scope>/<own client id>/<rest>` is stored as `rest`, interned once in a second trie shared by all devices. The scope is the first level of the device ACL's `<scope>/{id}/…` patterns (`devices` by default). A publish under `<scope>/<id>/…` looks up session `<id>` (one hash lookup) and matches its scoped filters against the remainder. Results are merged with the trie's, one delivery per session at the highest QoS. Devices therefore create no trie nodes of their own: 100 devices subscribing to `devices/<id>/cmd/#` leave the node count unchanged (tested). The full filter is rebuilt for the store and for unsubscribe matching, and restored sessions are scoped again.
- **Trade-offs:** subscription changes reallocate the list (rare by design); scoped matching is a linear scan of the session's few scoped filters.
- **Not done:**
  - Trie nodes for ordinary filters and retained topics are never freed (a node is 80 B).
  - The cold tier (compressing idle sessions) is not implemented: the measurement does not call for it.

## ADR-035 — Hardening and operations: admission, watchdog, health, syslog and statsd

- **Status:** Accepted (M16).
- **Admission (OOM protection):** a new connection is refused, before any crypto work, for the first reason that applies:
  1. free heap below `memory.min_free_mb`;
  2. the DB core more than 16 384 requests behind (durable changes are never dropped, so admission is the backpressure);
  3. `limits.max_handshakes_in_flight_per_core` handshakes in flight, or `limits.max_handshakes_in_flight_per_ip` from the same source address (a slow, unauthenticated peer cannot hold every slot);
  4. no handshake token (`limits.handshakes_per_core_per_sec`).

  Refusals are counted per reason (logged at 1, 2, 4, 8, … and pushed as statsd counters). Device-registry updates are skipped beyond 4 096 waiting DB requests: they are statistics.
- **Memory after a peak:** slabs hand out the lowest free id, so after a storm the remaining entries gather at the front. Every 10 s each core frees empty chunks at the end of its slabs and halves tables (TCP, client index) that are less than 1/8 full. Without this, the free-heap check would keep refusing after a storm that reached the limit, because the peak's chunks stay allocated. Measured: each worker returned about 1.1 MiB within 10 s of a 5 000-connection round.
- **Testing a storm on a small host:** `heap_limit_mb=N` (dev only) makes admission treat the heap as N MiB. The `storm` smoke scenario uses 8 MiB: 3 000 devices reconnect at once, 3 rounds; about 1 100–1 400 fit per round and the rest are refused. The checks are no allocation failure, no fault, memory refusals logged, and the memory back at 0 connections. On this host QEMU user networking cannot hold the 100k sockets the spec mentions (it stops near 10 240), so the heap is scaled down instead of the clients up.
- **Watchdog (PROMPT §4.1):**
  - Handlers mark their core with a phase and a connection (`watchdog::enter`, nested marks restore the outer one).
  - The per-core 10 ms tick checks the mark from its interrupt. Past `watchdog.handler_budget_ms` it logs core, phase and connection once, then applies `watchdog.action`: `log`, `drop` (abort the connection when the handler returns) or `reset`.
  - A handler still running after 100 budgets (at least 1 s) means a stuck core: the VM resets whatever the action.
  - Production uses `drop` with 20 ms: one slow handshake under steal time should cost one connection, not a million.
  - The DB core is not watched this way (a large commit can take hundreds of milliseconds); the health check covers it.
- **Health check (core 0, every 10 s):**
  - Every other core's loop-pass counter must advance; two checks without progress (a core spinning with interrupts masked, which its own watchdog cannot see) reset the VM.
  - A heap below the reserve marks the state degraded. State changes are logged, and the state goes to statsd as `urmqtt.health`.
- **Logging:**
  - Lines are rate-limited to 100/s with a burst of 300; what is suppressed is reported with the next line.
  - With `observability.syslog_udp` set, every line is also kept in a fixed ring (128 records × 200 bytes, no allocation, oldest overwritten and counted), from the first line of the boot on.
  - Core 0 sends one RFC 5424 message per datagram (RFC 5426) every 100 ms, once the collector's next hop is resolved: facility local0, the line's level as severity, wall-clock timestamp, our address as host, `cpuN` as PROCID, the subsystem prefix (`tls`, `mem`, …) as MSGID and `[meta sysUpTime=…]`.
- **Metrics:** with `observability.metrics_udp` set, core 0 pushes statsd lines every 10 s in datagrams of at most 1 400 bytes.
  - Gauges: connections, heap capacity/used/live bytes, frame buffers, health.
  - Counters: accepted connections, refusals by reason, watchdog reports, dropped frames, lost log records, unsent datagrams.
  - The dev configuration points both at the QEMU host (10.0.2.2:5514 and :8125), where the `observability` smoke scenario listens.
- **Revocation and resumption:** a resumption ticket outlives a revocation. Prod revocation lists are not in git, so a rebuilt image can carry the same version and hence the same ticket key. Resumed sessions therefore check the ticket's certificate against the list again.
- **Fuzzing:** 11 targets, each run for 60 s in CI.
  - New in M16: `net_frame`, `tls_record` (with a round-trip and tamper oracle), `x509_identity`, `broker_input` and `telemetry_recover`.
  - Earlier: `config_parse`, `fdt_parse`, `acpi_parse`, `mqtt_decode`, `disk_layout`, `tcp_segment`.
- **Not done:**
  - TLS for the observability sinks.
  - Limits on established connections per source address.
  - Revocation without a new image.
  - Per-core metrics.

## ADR-036 — Deployment: reproducible images, raw disk, minisign, dev code out of prod

- **Status:** Accepted (M17).
- **Reproducibility:**
  - All inputs are pinned (toolchain, `Cargo.lock`, vendored Limine and SQLite with checksums).
  - `SOURCE_DATE_EPOCH` is the commit time (ISO and FAT dates), and the FAT serial and the GPT GUIDs are derived from content.
  - Rust paths are remapped through `CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS`: the sysroot to `/rustc`, the cargo home to `/cargo`, the checkout to `/urmqtt`. Cargo merges these with the branch-protection flags of `.cargo/config.toml`.
  - C uses `-ffile-prefix-map`.
  - Before the remap, the kernel contained 76 strings with the builder's home directory (and so the user name). Now it contains none.
  - `scripts/repro.sh` (`make repro`) builds HEAD twice, in two worktrees at paths of different depth with separate target directories, and compares ELF, ISO and raw image. CI runs it for prod with throwaway certificates.
  - The first CI run of the check found what a single machine could not. On Ubuntu 24.04, mtools 4.0.43 gives `mmd` directories the current time, and `mformat` leaves uninitialised heap memory (pointers that differ per run) in an unused sector at the end of the FAT image. `scripts/fat-stamp.py` now sets every FAT timestamp to `SOURCE_DATE_EPOCH` and zeroes free clusters, so the ESP no longer depends on the mtools version or on chance.
    - The job had still reported success, because `| tee` hid the exit status; it now uses `pipefail`.
  - The claim: the same commit, inputs and toolchain give a bit-identical kernel ELF on any host, as long as paths are remapped. The ISO and the raw image are bit-identical for the same versions of xorriso and mtools; macOS (Homebrew) and Ubuntu versions lay out the ISO differently.
- **Raw disk image:**
  - `scripts/mkraw.py` wraps the ESP that `mkiso.sh` already builds in a GPT disk: protective MBR, one EFI system partition at 1 MiB, backup GPT, size rounded to whole MiBs (O_DIRECT hosts reject unaligned sizes).
  - Limine finds its config and the kernel on the ESP, as on the ISO.
  - Booting from a disk exposed a real hazard: the first virtio-blk device used to become the data disk, and the block self-test writes its last sectors (the backup GPT). Disks with an MBR signature or a GPT header are now skipped (`raw-disk` smoke scenario: the boot disk is byte-identical after boot).
- **Signatures:** minisign over `SHA256SUMS`, with version, environment and commit in the trusted comment (`make sign`).
  - The release workflow signs when the repository secret `MINISIGN_SECRET_KEY` holds a passwordless key, and keeps its SLSA provenance attestation.
  - The project key ([`minisign.pub`](../minisign.pub), `RWSOH9BS…`) is a **test** key, generated at the maintainer's request. Its secret is passwordless and in the CI secret `MINISIGN_SECRET_KEY`. Before a real release, replace it with an offline, password-protected key.
- **Dev code out of prod:**
  - The in-guest benchmark and the sans-IO TLS client sit behind the `selftest` kernel feature (`urmqtt-tls/client`), which the Makefile enables only for `ENV=dev`. CI lints both variants.
  - The dev certificates for self-tests were already empty in prod. Dev-only command-line switches were already ignored there.
  - The prod ELF is 2 214 352 bytes, against 2 399 120 for dev.
- **Production defaults changed:** `memory.kernel_heap_mb = 1024` (it was 8, which holds about ten thousand connections) and `min_free_mb = 64`.
- **Hetzner CAX:** the documented path is the raw image written from the rescue system. Until a virtio-scsi driver existed (ADR-037), it was likely blocked by the virtio-scsi disks.

## ADR-037 — virtio-scsi disks

- **Status:** Accepted (after M17).
- **Why:** aarch64 clouds (Hetzner CAX, Oracle A1 in paravirtualized mode) attach disks through virtio-scsi. Without a driver the kernel found no data disk there, and a production image would refuse to serve.
- **Design (`urmqtt-virtio::scsi`):**
  - A polled host adapter on the request queue only (the control and event queues stay unconfigured), with one command in flight and a 64 KiB bounce buffer, like virtio-blk.
  - A scan sends INQUIRY to targets 0–15 and LUNs 0–7. A bad-target response ends a target. Only direct-access devices (type 0) with 512-byte logical blocks count, so CD-ROMs (the ISO is one) and 4Kn disks are skipped.
  - Capacity comes from READ CAPACITY (10), or (16) beyond 2 TiB.
  - I/O uses READ/WRITE (10), or (16) when the LBA or the length needs it, and flush is SYNCHRONIZE CACHE (10). Unit attentions (after a reset) are retried up to 3 times.
  - The device's `max_sectors` caps the transfer size.
- **Selection:** the data disk is the first non-partitioned disk, whether virtio-blk or a SCSI LUN. A partitioned disk is a boot disk (ADR-036). The kernel sees both behind one `DataDisk` type, so the store and the self-test are unchanged.
- **Testing:**
  - Host tests for LUN addressing, CDBs, INQUIRY and capacity parsing, and sense keys.
  - The `scsi-disks` smoke scenario (HVF and TCG) boots the raw image from SCSI LUN 0 with the data disk on LUN 1. It checks the boot-disk skip, the self-test, formatting, a SQLite benchmark, the boot disk byte-identical afterwards, and reopening on a second boot.
- **Not done:** multiple queues, interrupts (polling suffices for the DB core's batched writes), hot-plug events, write-protect detection (a write-protected LUN fails the boot-time self-test instead).

## ADR-038 — Entropy without a hardware RNG; CPUs without PAC

- **Status:** Accepted (after M17).
- **Problem:** Ampere Altra (Neoverse N1, used by Hetzner CAX and Oracle A1) has no `RNDR`, and a cloud may offer no virtio-rng. The kernel refused to boot without a hardware source (PROMPT §6).
- **Fallback (`entropy.fallback = "jitter"`, the default in dev and prod; `"none"` keeps the strict refusal):**
  - With no hardware source, the boot CPU times a data-dependent read-modify-write walk over 32 KiB, as jitterentropy does. The duration varies with cache, TLB, predictor and pipeline state and with host interference.
  - The clock is the PMU cycle counter when the hypervisor exposes a PMU and it advances, else the generic timer.
  - The clock's granularity is learned (HVF's virtual cycle counter counts in steps of 128) and divided out.
  - The workload grows until a 256-sample probe shows at least 2 bits per sample.
  - Every delta goes into the SHA-256 pool. What is *credited* is decided by `JitterEstimator`, after NIST SP 800-90B and in integer arithmetic:
    - a repetition count test (32 equal samples fail);
    - an adaptive proportion test (more than 410 of 512 fail);
    - the most-common-value min-entropy estimate with a 3-sigma upper bound, rounded down to whole bits.
  - Only a quarter of the estimate is credited. Seeding needs 256 credited bits; otherwise the boot is refused as before.
  - Measured:
    - HVF (cycle counter, granularity 2^7): 1 024 samples, 512 bits credited, 85–166 ms.
    - TCG Neoverse N1: 618 bits in 275 ms.
    - TCG N1 without a PMU (generic timer): 512 bits in 112 ms.
  - The warning line records clock, granularity, samples, estimate, credit and the health-test result.
- **Why acceptable:** Linux has seeded from CPU jitter since 5.4 on machines without a hardware RNG. The pool still mixes the bootloader's (EFI RNG) values. The estimate is deliberately conservative (whole bits, upper bound, 1/4 credit). The kernel still refuses rather than run unseeded.
- **Found on the way: SMP did not start on CPUs without pointer authentication.** The AP trampoline wrote `APIAKey*_EL1` unconditionally; on Cortex-A72 and Neoverse N1 those registers are undefined and the APs died silently. The writes are now skipped when the CPU has no PAuth. Ampere Altra would have run on one core.
- **NIC:** urMQTT drives virtio-net only, and SR-IOV NICs (Mellanox ConnectX VFs on Oracle's native mode) would each need a large driver. Instead, at boot every network controller without a driver is named with its vendor, the fix is stated (Oracle: launch mode PARAVIRTUALIZED), and a production image stops (a dev image idles).
- **Amended by ADR-263:** the default stays `jitter`, but the weak path is an explicit, loud option (builder, `urmqtt-config pack`, boot log, `$SYS/broker/entropy/source`).
- **Testing:** the `no-hw-rng` smoke scenario boots with no virtio-rng: on HVF with the host CPU, and on TCG with `-cpu neoverse-n1` (no RNDR, no PAC/BTI). It checks the fallback's health tests, seeding and 4/4 CPUs online. Host tests cover the estimator and the pool policy.

## ADR-039 — GICv2 (Raspberry Pi and other GIC-400 hosts)

- **Status:** Accepted (after M17).
- **Problem:** the kernel drove only a GICv3. The Raspberry Pi 4 and 5 (and other GIC-400 boards) have a GICv2, and KVM can only give its guests the host's GIC version. urMQTT could not run as a KVM guest there, only under full emulation.
- **Design:**
  - **Discovery:** `GicCpu::V3 { gicr }` or `GicCpu::V2 { gicc }` in `urmqtt-platform::Gic`. From the device tree: `arm,gic-v3`, else `arm,cortex-a15-gic` / `arm,gic-400` / `arm,cortex-a9-gic` with the GICC frame as the second `reg`. From ACPI, by the MADT GICD version: redistributors mean v3, and the first GICC entry's physical base means v2. Version 0 (not stated) is decided by which of the two exists.
  - **Driver (`urmqtt_arch_aarch64::gic::Gicv2`):** the distributor and a memory-mapped CPU interface.
    - Interrupt groups stay as reset or firmware left them, as Linux does. Without the security extensions (QEMU, KVM) everything is group 0, and `GICC_IAR` acknowledges it. With them, firmware made everything group 1, which is what a non-secure `GICC_IAR` acknowledges. Bit 0 of both control registers enables that group in either view, and group 0 is signalled as IRQ (`FIQEn` = 0).
    - Each CPU reads its own target mask from the banked `GICD_ITARGETSR0`. SPIs are routed and SGIs sent (`GICD_SGIR`) with that mask, after a `dsb ishst` as on v3.
    - `GICC_EOIR` gets back the raw IAR value, which for an SGI includes the sender.
  - **Kernel:** `irq` hides the version. `irq::send_sgi(sgi, cpu)` and `irq::enable_spi(spi, cpu)` take logical CPU numbers, and a per-CPU `irq::Local` holds the redistributor (v3) or the mask (v2). The dispatch loop is unchanged on v3. On v2, at most 8 CPUs are started.
  - **MSI-X** works unchanged through the GICv2m frame (QEMU `virt` has one with both GIC versions).
- **Hosting:** `scripts/kvm-host/` holds a launcher (`virt,gic-version=host`, KVM, virtio devices), a systemd unit and an installer for Debian-family aarch64 hosts (docs/DEPLOY.md §7). The launcher works with a GICv2 or a GICv3 host.
- **Testing:**
  - Host tests: discovery from QEMU's GICv2 DTB and from GICv2 MADTs, including the contradictory case of version 2 with redistributors.
  - The `gicv2` smoke scenarios, under TCG because HVF cannot emulate a GICv2:
    - boot with ACPI and with DT, checking the tick, IRQ latency, 4/4 CPUs, 12/12 IPI pairs, MSI-X blk completions, virtio-net and SQLite;
    - the TLS broker scenarios against the GICv2 guest.
- **Not done:** more than 8 CPUs on a GICv2 (the architecture's limit); the GICv2 virtualization extensions (not needed by a guest); running directly on the Pi without Linux (no drivers for its Ethernet or SD card). Not yet tried on a real Pi.

## ADR-040 — Architecture facade (`urmqtt-arch`) and the arch-leak check

- **Status:** Accepted (X0).
- **Problem:** the x86-64 port (docs/X86-PLAN.md) needs one kernel over two architecture crates. Before X0 the kernel called `urmqtt-arch-aarch64` directly and held about 70 lines of AArch64 assembly and system-register code itself (boot entry, AP trampoline, PMU, RNDR, `brk`/`udf`, TTBR/TCR/SCTLR writes, GICv2m). Four library crates depended on the arch crate only for its spinlock.
- **Design:**
  - **`urmqtt-sync`:** the arch-neutral parts moved out of `arch-aarch64`: `sync` (spinlock, once-cell), `spsc`, and `frame` (`PAGE_SIZE`, `FrameSource`). `mm`, `store` and `tls` now depend only on it; `log` uses the facade only on bare metal (IRQ masking around the sink lock).
  - **`urmqtt-arch`:** one module list, `cpu`, `irq`, `ipi`, `msi`, `percpu`, `time`, `paging`, `trap`, `barrier`, `entropy`, `power`, `features`. Each module re-exports the target architecture's items under neutral names (for example `cpu::wait_for_interrupt`, `cpu::privilege_level`, `percpu::current`, `time::finest_clock`, `paging::activate`). Hardware items exist only for `target_os = "none"`; host builds get the pure parts, and `barrier::doorbell` falls back to a fence there.
  - **Contract:** `crates/arch/src/contract.rs` binds every item to an explicit function-pointer type or constant. An architecture that lacks an item or changes its shape fails to compile. Dispatch is static: no traits, no generics, no cost.
  - **Moved into `arch-aarch64`:**
    - `boot` (`_start`);
    - `percpu` (TPIDR index, MPIDR, `ApBoot` and the trampoline);
    - `mmu` (MAIR merge, TTBR1 root, activation with EPD0 and WXN);
    - `irq` (the v3/v2 `Controller` with `Local` and `Ack`; the kernel keeps the handler table and statistics);
    - `msi` (GICv2m frame: TYPER decode, SPI allocation, address/data composition; host-tested);
    - `power` (PSCI conduit state);
    - `entropy` (RNDR), `pmu` (cycle-counter clock), `faults` (test-mode `brk`, `udf`, PAC and BTI violations);
    - trap classification and the register dump (`TrapFrame::classify`, `cause`, `fault_address`, `registers`).
  - **`scripts/check-arch-leaks.sh`** (CI lint job and `make check`) fails on `asm!`, `global_asm!`, `mrs`/`msr`, `*_EL0..3` names, `daif` and `tpidr` outside `crates/arch-aarch64`, and on `rdmsr`/`wrmsr`, `cr0..4`, port I/O and `cpuid` outside `crates/arch-x86_64`. Comments are skipped. `--self-test` proves that each of its 10 rules fires on a sample, ignores the sample as a comment, and accepts it inside the arch crate.
- **Deliberate limits:**
  - The paging *builder* API stays the AArch64 `Mapper` with `PageAttrs`, re-exported as `arch::paging`. A neutral builder is designed in X1 against the x86 page-table format rather than guessed from one implementation.
  - Some facade items are AArch64 concepts with no x86 counterpart yet: the PAC key (`cpu::set_return_address_key`), the PSCI conduit, the GIC version, the exception level. X1 decides per item whether x86 gets an equivalent or the kernel call site becomes architecture-conditional.
- **Behaviour:** unchanged. The boot log, every smoke scenario and the benchmarks are the same. The trap path prints the register dump through one `emergency` call instead of one per field, with the same text.
- **Testing:** every host test, the contract (compiles for the kernel target), the leak check and its self-test, `msi` host tests, all smoke scenarios under HVF and TCG, `make repro`, and bench before and after (docs/PROGRESS.md, X0).

## ADR-041 — CPU feature dispatch (`urmqtt-dispatch`) and `[cpu] disable`

- **Status:** Accepted (X0). The AArch64 hardware backends, the `cpufeatures` patch and the read-only seal came in X0b (ADR-053); x86 follows in X9. The boot log line is now `cpu dispatch: detected <features>, disabled <features>` (configured plus dev command line).
- **Problem:** finding F1 (docs/X86-PLAN.md): AES-GCM, GHASH and SHA-256 run the portable code on AArch64 today, because RustCrypto's `cpufeatures` answers "no" on `target_os = "none"` and the `aes_armv8`/`polyval_armv8` cfgs are unset. Two architectures with several accelerators each need one place that decides what runs, and an operator needs a way to switch a faulty or slow accelerator off without a rebuild of the code.
- **Design:**
  - `CpuFeatures` is a set of `Feature`s that select code paths (AArch64 today: `aes`, `pmull`, `sha2`, `crc32`). `arch::features::Features::dispatch()` maps the decoded ID registers onto it.
  - `TABLE` lists, per primitive (`aes-gcm`, `ghash`, `chacha`, `sha256`, `crc32c`, `toeplitz`), its backends in preference order. Each has the features it needs and whether it is compiled into this image. The last backend of each row is the portable one and needs nothing (tested).
  - `select` takes the first built backend whose features are all usable.
  - **Opt-out:** `[cpu] disable = [...]` in `deploy/<env>/config.toml` (optional section; empty by default). The schema validates the names against `Feature::name` and rejects unknown names and duplicates. Security features (PAC, BTI, W^X, RNDR as an entropy source) are not in the list, so they cannot be switched off.
  - **Seal:** at boot, before any crypto runs, `CPU.seal(TABLE, detected, disable)` computes detected minus disabled, selects, and stores the result once. A second seal is refused and keeps the first result (tested). A failed seal stops the boot (fail closed).
  - **Boot log:** `cpu dispatch: detected <features>, disabled by config <features>` and `crypto: aes-gcm=soft ghash=soft chacha=soft sha256=soft crc32c=table toeplitz=bitwise`. Every hardware backend is listed in `TABLE` as not built, so the line reports F1 honestly whatever the CPU offers.
- **Not yet (X0b):**
  - the vendored `cpufeatures` patch that makes RustCrypto ask the sealed set (`urmqtt_cpu_has`);
  - the `aes_armv8`/`polyval_armv8` cfgs;
  - mapping the sealed state read-only once the page tables lock. The seal is write-once in X0, but its page is ordinary kernel data. Nothing reads it to choose code yet.
- **Testing:** host tests for selection by feature mask, opt-out before selection, double seal, name validation and the row invariant; schema tests for `[cpu] disable`; the smoke boot scenarios check both log lines.

## ADR-048 — Control channel: signed messages on `$urmqtt/control` (H1)

- **Status:** Accepted (H1). Threat model written first (docs/SECURITY.md, "Control channel").
- **Problem:** revoking a device needed a new image (M16 residual risk). PROMPT-security H1 requires runtime revocation and an allowlist, over the existing port, with no remote admin API, authenticated twice.
- **Design:**
  - **Transport:** a reserved topic namespace `$urmqtt/`.
    - The broker checks it before the ACL. Nobody may subscribe there, and MQTT's `$` rule keeps `#` from matching it.
    - Only an *operational* identity listed in `control.service_ids` may publish, and only to `$urmqtt/control`. Bootstrap certificates never qualify.
    - Such messages are never routed or retained. Everything else in the namespace is dropped and counted.
    - The schema rejects ACL patterns in the namespace.
  - **Message:** a fixed little-endian binary layout (`crates/control`), chosen over CBOR so the decoder stays tiny and exact.
    - Fields: magic, `seq`, `not_before`, `not_after`, command, and 1–64 length-prefixed unique items. Items are serials (1–20 bytes) or device ids (valid MQTT identities). Nothing may trail the 64-byte Ed25519 signature.
    - The signature covers `"urMQTT control message v1\0" || env || 0x00 || body`, so a message for one deployment never verifies in another.
    - Verification is `ed25519-dalek` 2.2 `verify_strict`. It rejects non-canonical encodings and small-order keys, and shares `curve25519-dalek` 4 with x25519.
  - **Processing on the DB core:** the data core forwards the payload unchanged.
    - The DB core re-checks the publisher, verifies, and checks the window (at most `control.max_message_age_s`), `seq > last` and the command policy.
    - Unrevoke must be allowed by `control.allow_unrevoke` (off in prod) and may not name an image-listed serial. Allow and disallow need `registry.mode = "allowlist"`.
    - The effect and the new `seq` commit in one SQLite transaction (schema v2: `control_state`, `allowlist`). Only then are the in-memory sets replaced, an epoch bumped and every core woken with an IPI.
  - **Live effect:** each data core compares the epoch on its next loop pass.
    - Transport cores close TLS connections whose certificate serial is now revoked. The per-connection tag is 32 bits and fits existing padding, so `Conn` stays at 152 B. A collision only closes an unrelated connection, which then reconnects and is verified in full.
    - Home shards close sessions whose identity left the allowlist.
    - Measured: 3–10 ms from commit to close under HVF and TCG.
  - **Fail closed:**
    - no wall clock, or a clock before the image's build time (ADR-050);
    - no durable storage: a revocation must not vanish at reboot;
    - malformed input, a bad signature, replay or an expired window.

    Every rejection has a statsd counter `urmqtt.control.rejected.<reason>` and a rate-limited log line naming only the publisher and the reason.
  - **Tool:** `tools/urmqtt-control` builds, signs (key file, or `--sign-cmd` for an HSM or KMS) and publishes, and can store and replay messages for tests. `seq` defaults to Unix milliseconds.
- **Alternatives rejected:**
  - A separate admin port or API: PROMPT forbids new ports.
  - CRL or OCSP fetching: the broker makes no outbound connections, and a fetch path would be new attack surface.
  - Signing with the mTLS key alone: one compromised service would then suffice.
- **Not done / limits:**
  - No acknowledgement channel back to the publisher; the outcome is in the log and the metrics.
  - No native PKCS#11 in the tool; the hook covers it.
  - An old data-disk snapshot restores old state (residual risk in SECURITY.md).
- **Testing:**
  - Host: RFC 8032 vectors; round trips; every flipped byte fails; environment and key binding; malformed bodies; the freshness, replay and permission rules; the store across power loss and the v1→v2 migration; broker tests for the namespace, control rights and the backlog bound (64).
  - Fuzz target `control_message`.
  - Smoke: `control` (revoke-live, unrevoke, forged, replay, expired, from-device), `control-persist` (a replay after a reboot is still rejected and the device still refused).

## ADR-049 — Trust anchors by role, bootstrap identities, registry modes, expiry safety (H1)

- **Status:** Accepted (H1).
- **Trust roles:** `[trust] operational = [...]` and `bootstrap = [...]` replace `tls.ca`.
  - The server builds one webpki verifier per role. Operational is tried first; the first that accepts decides the role.
  - The role is recorded during verification, keyed by the SHA-256 of the end-entity certificate, and bounded like the captured secrets.
  - A resumed session verified nothing, so its chain from the ticket is verified again against the *current* anchors. A CA removed from the image also ends resumption.
  - Two operational CAs side by side give rotation with overlap (procedure in docs/PROVISIONING.md). The schema forbids the same file in both roles.
- **Bootstrap identities** get the fixed ACL `provision/{id}/#`, for publishing and subscribing.
  - Their session key is `$bootstrap/<id>`, which no real client id can be, so they can neither take over nor read the operational session of the same id.
  - A persistent session is refused (CONNACK not authorised), and the registry does not record them.
- **Registry:** `registry.mode = "open" | "allowlist"`.
  - In allowlist mode an operational *device* identity that is not on the stored allowlist is refused right after the handshake (counter `urmqtt.registry.refused`, rate-limited log).
  - Identities named in the image (`acl.service_ids`, `control.service_ids`) and bootstrap identities are exempt.
  - The dev command line may switch an image to allowlist mode (`registry=allowlist`): it can only make the image stricter.
- **Expiry safety:**
  - The build fails if the server certificate expires within `tls.min_server_cert_days` (60) or any anchor within `trust.min_anchor_days` (365). The reference is the build machine's clock, never earlier than `SOURCE_DATE_EPOCH`.
  - The server certificate's notAfter is compiled in. At runtime there is a statsd gauge `urmqtt.tls.server_cert_days`, a boot line, and warnings at 60, 30, 7 and 1 days, plus an error once expired.
  - `tls.early_data = true` fails the build.
- **Limit:** cargo caches build-script results, so the expiry check runs again only when the configuration or certificates change and in every clean build (CI, `make repro`, releases). A long-lived local build directory can carry a stale "pass".
- **Testing:**
  - TLS host tests: roles with two operational CAs and a bootstrap CA, the resumed role, a removed CA refused even with a valid ticket, the bootstrap identity unknown without its anchor, and runtime revocation for full handshakes and resumption.
  - Broker tests for bootstrap isolation.
  - Schema tests for every new key and the `expiry_build_check`.
  - Smoke: `bootstrap-role`, `ca-rotation`, `registry-allowlist` (unknown refused; allowed then admitted; disallowed then disconnected live and refused).

## ADR-050 — The image's build time is the wall clock's lower bound (H7, moved into H1)

- **Status:** Accepted (H1). The rest of H7 (SNTP, NTS, jump handling) is still open.
- **Problem (H0-W5):** a dead CMOS battery or a restored VM snapshot gives a date in the past. Expired certificates would pass, and control-message windows would mean nothing.
- **Design:**
  - The Makefile exports `SOURCE_DATE_EPOCH`, the commit time, which is reproducible (M17), and the kernel embeds it.
  - A boot date before it means the time is unknown. The kernel logs "check the RTC battery or the hypervisor clock" and sets no wall clock. Every certificate check and control message then fails closed.
  - A build without the variable has no bound and says so at boot.
- **Testing:** smoke `time-before-build` boots with `-rtc base=2020-01-01`. It checks the warning and that a valid device's handshake is refused.

## ADR-051 — The single-disk model: the data partition of the boot disk (S1)

- **Status:** Accepted (S1). It implements PLAN.md decision 6 ("only the disk it boots from") and STORAGE-PLAN §2a, and supersedes the "first non-partitioned disk" rule of M11/M17.
- **Problem:**
  - The data disk was "the first disk that is not partitioned". On bare metal that could be a disk holding someone else's data, and the model needed two disks where hosts and clouds give one.
  - A damaged urMQTT disk had to be told apart from a foreign one by guesswork (H0-W12, W13; DISK-FORMAT G1, G2).
- **Design:**
  - **Identification.** Limine's executable-file response gives the boot volume's media type and GPT disk GUID. Every virtio-blk device and every virtio-scsi LUN is read at LBA 1..33. The one whose valid primary header carries that GUID is the boot disk. Others are logged as "not the boot disk, left untouched" and never written.
    - **A bug worked around:** the `limine` crate 0.6.5 omits the `unused` u32 after `media_type`, so its later fields are 4 bytes off. This was found from a memory dump under QEMU. The kernel reads the protocol's offsets (40 for the media type, 64 for the disk GUID) from the raw structure, and the reason is documented in `boot.rs`. To report upstream.
  - **First boot** (`urmqtt_store::gpt::prepare`, specified in DISK-FORMAT §0):
    - repair a torn primary from the backup;
    - move the backup to the end of a larger disk;
    - create the data partition: 1 MiB aligned, whole 4 KiB blocks, head zeroed first, fresh partition and disk GUIDs, backup copy before primary, entries before header.

    It is idempotent, and a power cut after any write is recovered on the next boot.
  - **The store works through a `Partition` window** (`urmqtt_store::part`), so the layout v1 is unchanged and relative to the partition. The block self-test writes the partition's last 8 sectors, never outside it.
  - **Classification:** blank → format; valid → open; anything else → refused and never written. Dev images then run memory-only; S5 brings restore.
  - **Read-only media.** Booting the ISO as a CD gives no data partition. The kernel says "booted from read-only media (CD/ISO): write the image to the machine's disk". Production refuses to serve (`storage.require_data_disk`); dev runs memory-only. The self-installing ISO (S1b) turns this into "install, then boot from the disk".
  - **Fault injection** (`urmqtt_store::fault`) wraps the boot disk in dev images with `test=disk-fault:<spec>`. It can stop after N writes or flushes, tear a write, drop a flush or flip a bit on read. A fired power cut powers the VM off, so smoke boots the disk again. Production never parses the option (command line ignored, H0-W11 test).
  - **Tools.**
    - `tools/urmqtt-disk` works on images and block devices, read-only unless `--write`. Its commands are `info`, `verify`, `export-db` (WAL applied in a copy-on-write overlay), `export-telemetry` (csv/jsonl with time and topic filters), `import-devices [--allowlist]`, `create` (the mkraw-identical writer) and `update-boot` (replace the ESP, keep the data).
    - `make run` uses one persistent `build/disk-<env>.img`, updated in place.
    - `scripts/kvm-host/install.sh` creates or updates one `disk.img`.
- **Consequences:**
  - Deployments attach one disk, larger than the image. The DEPLOY.md recipes changed: no separate data disk for libvirt, Proxmox, Hetzner, Oracle or the Pi.
  - Updating the kernel means replacing the ESP, not swapping a boot disk.
  - No image with the two-disk model was released, so nothing is migrated.
- **Testing:**
  - Host: 13 GPT tests, among them the crash at every write (cut and torn, cache kept or lost, 40 cases), byte identity with `mkraw.py`, idempotence, repair, shrink, too small, and the new partition formatting with the real layout code. Also partition-window and fault-device tests.
  - Fuzz target `gpt_parse`.
  - Smoke:
    - `first-boot` (with a second disk byte-identical afterwards) and `first-boot-again`;
    - `first-boot-crash` at four points, then recovery;
    - `scsi-boot` (format, bench, reopen, a second LUN untouched);
    - `iso-as-cd`;
    - `own-damaged-refused`;
    - `disk-tool-offline` and `disk-tool-import-in-force` (the tool's round trip, with the host `sqlite3`).

    Every older scenario now boots the single-disk image as well.

## ADR-052 — The self-installing ISO; `install` is the one honoured production word (S1b)

- **Status:** Accepted (S1b). It implements PLAN.md decision 7 and STORAGE-PLAN §2b. The threat-model entry is "Installer entry" in docs/SECURITY.md.
- **Problem:** bare metal and many hypervisors boot an ISO or a USB stick, not a pre-written disk. Under the single-disk model (ADR-051) a CD cannot hold the data. The ISO must therefore put urMQTT onto the machine's disk itself, with no other tool.
- **Design:**
  - **Menu** (the ISO9660 `limine.conf`; the ESP's own config, used by the installed disk, stays menu-less):
    - `/urMQTT`: the default, after 5 s;
    - `/Install urMQTT on this machine's disk`: `cmdline: install`, `module_path: boot():/esp.img#<blake2b>`.

    The editor is off and kernel and module are hash-pinned.
  - **Target** (`urmqtt_store::install::choose`): every disk driven in install mode, minus the installation medium (a disk whose GPT GUID is the boot GUID), read-only disks, and disks smaller than the image plus 17 MiB.
    - Exactly one remains: that disk.
    - None remain, or several: refuse, list them, write nothing.
    - `storage.install_target` (by serial) is **not** implemented: leave only the target attached. Bare metal sees no USB sticks anyway (no USB storage driver).
  - **Confirmation without input:** the target with its size, "ALL DATA … WILL BE ERASED" (naming an existing urMQTT data partition), and a 30 s countdown with "power off now to cancel" every 5 s. The dev-only `install-countdown=S` shortens it for tests.
  - **Writing** (`urmqtt_store::install::write_image`), the image built by `gpt::raw_image`, mkraw-identical:
    1. clear the disk's last 33 sectors, then LBA 0..33;
    2. the ESP and the image's backup table;
    3. the primary entries and the protective MBR;
    4. the primary header last.

    Then flush and a streaming SHA-256 read-back, so no second copy of the image is held: the dev heap is 32 MiB. Finally "remove the installation medium", flush the UART, power off.
  - **First boot from the disk** is the ordinary S1 first boot. It now also rewrites a missing or damaged backup from the primary, which an interrupted reinstall leaves.
  - **Production command line:** ignored as before, except the exact word `install`. A production ISO's install entry must work, and the word is harmless without the hash-pinned module.
- **Found on the way:**
  - The first version read the image back into a second 10 MiB buffer and panicked on the dev heap after the image was written. It is now streamed.
  - A power-off right after a log line cut that line off: `power::off` and the reset path now flush the UART first.
- **Not done:**
  - an *Update* entry (replace the ESP, keep the data) is planned;
  - BIOS boot of the installed disk comes with x86 (X10);
  - bare metal is X12.
- **Testing:**
  - Host: target selection; the installed disk equals the raw image and then first-boots; too small and bad images; a power cut at every write of a reinstall (cut, with and without the cache surviving) leaves the old install untouched or a disk that does not boot, never a mix, and installing again works; backup repair.
  - Kernel host tests for the production command line.
  - Smoke (HVF and TCG): `install-vm` and `install-vm-boots` (the ISO unchanged), `install-two-disks-refused` (both disks still all zero), `install-scsi` and `install-scsi-boots`, `install-crash` (the disk has no GPT afterwards, per `urmqtt-disk info`) and `install-crash-reinstalled`.

## ADR-053 — ARMv8 hardware crypto on AArch64; the sealed dispatch on a read-only page (X0b)

- **Status:** Accepted (X0b). Closes finding F1 (docs/X86-PLAN.md) on AArch64.
- **Problem:** RustCrypto compiles its ARMv8 AES and POLYVAL backends only with `--cfg aes_armv8` / `--cfg polyval_armv8`, and its runtime detection (`cpufeatures`) answers "no" on `target_os = "none"`. So the kernel ran portable AES-GCM, GHASH and SHA-256, and a table CRC-32C, on CPUs that have the instructions. The X0 dispatch (ADR-041) recorded the choice but nothing read it.
- **Design:**
  - **Build:** `.cargo/config.toml` sets `--cfg aes_armv8 --cfg polyval_armv8 --cfg chacha20_force_neon` (workspace `check-cfg` lists them). NEON is part of the AArch64 baseline, so ChaCha20 needs no detection.
  - **Detection hook:** `vendor/cpufeatures-{0.2.17,0.3.1}` (vendor/README.md) call the kernel's `urmqtt_cpu_has(name, len)` on `target_os = "none"`. It answers from the sealed dispatch (`Sealed::cpufeatures`):
    - `"aes"` means AES **and** PMULL, because `aes` and `polyval` both ask for `"aes"` and the kernel only runs them together;
    - `"sha2"` means SHA2;
    - every other name, and every name before the seal, gets "no".

    `cpufeatures` caches its first answer. A query before the seal therefore latches the portable code (safe), never a backend the opt-out would have refused.
  - **Table:** `aes-gcm=armv8-aes` (needs AES+PMULL), `ghash=armv8-pmull`, `chacha=neon`, `sha256=armv8-sha2`, `crc32c=armv8-crc` are built on the AArch64 kernel target. The portable rows stay last.
  - **CRC-32C:** `urmqtt_store::crc` gets a backend hook (`set_backend`). The kernel installs `arch::crc::crc32c_update` (the ARMv8 `crc32c{x,b}` instructions) only when the sealed selection says `armv8-crc`. The store and the host tool keep the table, which stays the reference.
  - **Read-only seal:** the `SealCell` lives in `.data.sealed`, a page-aligned section of its own (`linker.ld`). The boot CPU seals it through the bootloader's mapping. The kernel's own tables map that page read-only, and the W^X audit checks that. A later write faults (`test=sealed-write`).
  - **Known answers at boot, fail closed**, in every image right after the heap exists and before any TLS or storage work: AES-128-GCM (McGrew–Viega test case 4), ChaCha20-Poly1305 (RFC 8439 §2.8.2), SHA-256 (FIPS 180-2 "abc" and the 448-bit message, also streamed), HMAC-SHA-256 (RFC 4231 test case 2) and CRC-32C (`123456789`). A mismatch stops the boot. This covers whichever backend the dispatch chose.
  - **Opt-out:** `[cpu] disable` and, in dev images, `cpu-disable=aes,pmull,sha2,crc32` on the command line, to compare backends on the same machine.
- **Measured (QEMU HVF on an M4 Pro, `test=crypto-bench`, 64 KiB buffers, MiB/s):**

  | Primitive | Portable | ARMv8 |
  |---|---|---|
  | AES-128-GCM | 228 | 553 |
  | ChaCha20-Poly1305 | 596 | 763 (NEON) |
  | SHA-256 | 586 | 2663 |
  | CRC-32C | 497 | 9793 |

  Every hardware backend is faster, so each is on by default (the X0b acceptance rule).
- **Testing:**
  - Host: the `cpufeatures` answers follow the usable set; CSV parsing of the opt-out; the ARMv8 CRC against a bitwise reference; the KAT vectors.
  - Fuzz (aarch64 hosts, built with the kernel's cfgs): `diff_aes_gcm` and `diff_chacha20poly1305` against `ring` (ciphertext, tag, both directions open), `diff_sha256` (both `sha2` versions, one-shot and chunked) against `ring`, `diff_crc32c` hardware against the table.
  - Smoke (HVF and TCG): the boot scenarios expect the ARMv8 line and the KAT line; `crypto-soft`, `sealed-write` (a permission fault whose FAR is the sealed address), `simd-irq` (10 s of KATs on four cores under the tick and IPIs, 0 mismatches) and `crypto-bench`.
- **Not done:** PMULL folding for long CRC buffers (the plain instruction already gives ~10 GiB/s), and AES-GCM with the ARMv8.2 SHA3/EOR3 extensions. The x86 backends are X9.

## ADR-054 — Random, rotating session-ticket keys; fatal alerts; TLS assurance tooling (H2)

- **Status:** Accepted (H2). Implements PLAN.md decision 5; closes H0-W4. Details in docs/CRYPTO.md.
- **Problem:**
  - The ticket key was HKDF(server key, image version). Anyone with a copy of the image could forge a ticket for any device identity and resume as that device. Resumption re-checks revocation, but not possession of the device key.
  - The keys never rotated.
  - 0-RTT being off had no test.
  - The record layer had been checked only against itself.
  - Failures ended connections without an alert.
- **Design:**
  - **Ticket keys** (`urmqtt_tls::ticket::TicketKeys`, one instance shared by every core's server):
    - drawn from the CSPRNG when the first ticket is issued;
    - current for 12 h of uptime, previous for 12 h more, then zeroised in place. Two fixed slots, an index for "current", so a key is never moved or copied;
    - ticket lifetime 12 h;
    - ticket format `id (4) || nonce (12) || ChaCha20-Poly1305(state)`, with the id in the associated data;
    - the rotation is lazy: it runs at seal or open, under one spinlock. Handshakes are rare next to records, so the lock is not contended;
    - refusals are counted by reason (`expired`, `unknown_key`, `invalid`, `malformed`), logged at powers of two, and exported to statsd;
    - a CSPRNG failure issues no ticket;
    - dev `test=ticket-rotate:S` shortens the interval.
  - **Why uptime and not the wall clock:** rotation must work before and without a clock (H7), and a wrong clock must not stretch a key's life.
  - **0-RTT:** two independent locks. `max_early_data_size = 0`, with the build refusing `tls.early_data`. And rustls refuses early data with any stateless ticketer (RFC 8446 §8.1). A mutation test (setting `max_early_data_size` to 16 KiB) showed that the second lock alone keeps 0-RTT off. The test therefore asserts the outcome: no ticket allows early data, and none is accepted.
  - **Alerts** (RFC 8446 §6):
    - record-layer errors send a fatal alert under the current keys (`RecordError::alert`), then nothing more;
    - rustls's handshake alert, which the unbuffered API emits only on a second call, is now flushed;
    - close_notify is answered with close_notify;
    - the inner plaintext limit of 2^14 + 1 bytes is now enforced (`record_overflow`). Before, only the ciphertext length was checked, which let 2^14 + 2 … 2^14 + 240 bytes of inner plaintext through.
  - **Constant time:** `server::ct_eq` (`subtle`) for the one secret comparison of our own, plus dudect-style tests with a negative control (`make ct`, in CI).
  - **Differential fuzzing:** `diff_tls_record` compares our records with rustls's record layer, using rustls's key schedule and `ring`.
  - **Conformance:** tlsfuzzer probes for mutual TLS and MQTT (`make conformance`, in CI), and an interop matrix with OpenSSL 3/4, wolfSSL and Mbed TLS (`make interop`, in CI with the libraries Ubuntu ships).
- **Cost:** after a restart every device does one full handshake, the load the M16 storm scenario measures. A ticket open or seal is one ChaCha20-Poly1305 over about 200 bytes under a spinlock.
- **Not done:**
  - the plan put the keys "in the key slab": no key slab exists yet (H4). They live in a static, zeroised in place;
  - an embedded MQTT client on firmware;
  - tlsfuzzer's stock HTTP scripts (not applicable to an MQTT server with mutual TLS).
- **Testing:** see docs/CRYPTO.md. In short:
  - host tests for every rotation boundary, forgery, zeroisation, RNG failure, alerts and record overflow;
  - `ticket_from_another_boot_means_full_handshake`, `zero_rtt_is_never_offered`, `fatal_alerts_reach_the_peer`;
  - smoke `ticket-rotation` and `ticket-restart`;
  - fuzz `diff_tls_record`, 10 min clean;
  - 23 tlsfuzzer probes;
  - the interop table.


## ADR-044 — x86_64 boot, exceptions and power control (X2, D5)

- **Status:** Accepted (X2). ACPI S5 and the FADT reset register come with X6; they are not built yet.
- **Boot contract:** Limine enters in long mode, ring 0, interrupts off, with the kernel, the memory map and the framebuffer in its page tables (HHDM). `_start` (`crates/arch-x86_64/src/entry.rs`) runs before any Rust code:
  1. switches to a 128 KiB stack of the kernel's own (`.bss.boot_stack`, no guard page until X3), because the bootloader's memory is reclaimed later;
  2. checks the x86-64-v2 baseline (CPUID.1:ECX SSE3, SSSE3, CX16, SSE4.1, SSE4.2, POPCNT) **in assembly**, because the kernel is compiled for v2 and may fault anywhere on a CPU without it. A failing CPU gets the message of PROMPT-x86_64 section 1 on COM1, including which features are missing, then the QEMU/KVM power-off ports, then `hlt`. The refusal does not reach the framebuffer: only Rust can draw there, and it is compiled for the baseline;
  3. enables the hard-float kernel's state: CR0.MP/NE/WP set and EM clear, CR4.OSFXSR/OSXMMEXCPT, `fninit`, MXCSR default;
  4. calls the kernel's `urmqtt_kmain` (`crates/kernel/src/boot_x86.rs`).
  Rust then turns on XSAVE and sets XCR0 to x87 | SSE | AVX (AVX-512 only when a dispatched kernel needs it, ADR-042), reads CPUID and XGETBV (`features::detect()`), and logs `URMQTT BOOT <ver> arch=x86_64 cpu=<n> mem=<MB>`, the CPU identity (vendor, family, model, stepping, hypervisor signature, brand string) and the feature census.
- **Console:** COM1 (16550, 115200 8N1, FIFO on, polling, bounded waits, no input) and the Limine framebuffer through the existing `FbConsole`. The UART is found by writing the scratch register; without one only the framebuffer logs. SPCR/ACPI discovery of other ports is X6. `urmqtt-log` gained a `Uart` enum so the sink can be COM1 (port I/O in `arch-x86_64`) instead of a PL011; the emergency path uses it without the log lock.
- **Tables:** GDT with kernel code and data and the 16-byte TSS descriptor, loaded with `lgdt`, a far return and `ltr`. The IDT has 256 interrupt gates (IF cleared on entry) into 16-byte stubs; the TSS gives #DF, NMI, #MC and #PF their own 16 KiB IST stacks. All of this is boot-CPU-only static state for now; X5 (SMP) makes it per CPU. The legacy 8259 PICs are masked.
- **Exception path:** each stub pushes the error code (or a zero) and the vector; the common path saves CR2 and 15 GPRs (the `TrapFrame`, layout checked by a host test), runs FXSAVE (the handler is hard-float Rust; `int3` resumes), and calls the kernel's handler on the stack the exception arrived on. The report prints the vector name, the decoded error code (#PF: P/W/U/RSVD/I/PK/SS/SGX; #GP, #TS, #NP, #SS: selector index, table, EXT; #DF), RIP, RSP, RFLAGS, CR2, CS/SS, all GPRs, and which stack the frame sits on (`IST stack n` or `the interrupted stack`), so a #DF report shows that it ran on its own stack. XSAVE-sized state (AVX and later) is not saved on entry: v2-compiled kernel code never touches the upper halves, and X4 saves it when interrupts can reach dispatched AVX functions.
- **#PF has an IST stack** so that a stack overflow into a guard page (X3) is reported as a #PF with the faulting RSP in the guard, instead of escalating to a #DF with less information. The `test=df` self-test therefore does not overflow a stack: it marks the #GP gate not present and executes a non-canonical load, which delivers #GP, fails with #NP, and becomes #DF (two contributory exceptions).
- **Power (D5):**
  - reset: the PCI reset-control port 0xCF9 (0x02, then 0x06), then the 8042 pulse (0x64 <- 0xFE), then a triple fault (empty IDT, `int3`);
  - power-off: only under a hypervisor (CPUID.1:ECX bit 31), QEMU's ACPI PM1a control at 0x604 and 0xB004 (`0x2000`); on bare metal, until X6 reads `\_S5`, it halts. Writing unknown I/O ports on real hardware is not something to do blindly;
  - `isa-debug-exit` (port 0xF4): dev images in smoke mode only, as a last resort **after** the ACPI ports. D5 said smoke would use it for the exit code; it does not, because QEMU's debug-exit status is `(value << 1) | 1`, never 0, and the smoke harness (shared with aarch64) treats a non-zero QEMU status as a failure. The ACPI port exits with 0, as PSCI does. `run-qemu.sh` attaches the device on x86 anyway, for a machine type without the PM device (microvm). A production image never writes port 0xF4.
  - fatal errors: smoke mode powers off, otherwise reset (`power::fatal`, shared with aarch64).
- **Limine for x86 (lifts PROMPT.md section 2's "aarch64 only", see ADR-055).**
- **Not done here:** paging beyond what Limine hands over (X3); FP/SIMD save for interrupts, time, LAPIC (X4); APs (X5); ACPI, S5, SPCR (X6); devices (X7+). `URMQTT READY` on x86 currently means "the bring-up sequence finished", and a warning line says so.
- **Feature census** (`cpu features:` line, QEMU 11.1.2 under TCG; `-` = not exposed):

  | feature | `max` | EPYC-Milan | Icelake-Server | Skylake-Server | Haswell |
  |---|---|---|---|---|---|
  | AES-NI, PCLMULQDQ | yes | yes | yes | yes | yes |
  | SHA-NI | yes | yes | - | - | - |
  | AVX, AVX2 (XCR0=0x7) | yes | yes | yes | yes | yes |
  | VAES | yes | - | yes | - | - |
  | VPCLMULQDQ, GFNI, AVX-512*, WAITPKG, CET | - | - | - | - | - |
  | RDRAND, RDSEED | yes | yes | yes | yes | RDRAND only |
  | FSGSBASE | yes | yes | yes | yes | yes |
  | x2APIC | yes | - | yes | yes | yes |
  | TSC-deadline, invariant TSC | - | - | - | - | - |

  TCG implements no AVX-512, no CET and no WAITPKG, and does not offer TSC-deadline or an invariant TSC on any of these models (X4 must work without them under TCG). KVM on real CPUs will show more. The table belongs next to the CI/KVM decision (ADR-046).
- **Testing:** host tests for descriptor and gate encoding, the `TrapFrame` layout, vector and error-code decoding, the baseline mask and names, CPUID identity and census formatting. Smoke scenarios (TCG): `x86-boot-q35-uefi`, `x86-boot-pc-bios`, `x86-boot-v2-minimal`, `x86-baseline-refuse`, `x86-fault-pf-null`, `x86-fault-ud`, `x86-fault-gp`, `x86-fault-df`, `x86-brk-resume`, `x86-panic`. Not covered: KVM, real hardware, a CPU that really lacks the baseline other than `qemu64`.

## ADR-055 — Limine for x86_64: vendored binaries and the host tool

- **Status:** Accepted (X2). Lifts the "aarch64 only" rule of PROMPT.md section 2 for the bootloader, as PROMPT-x86_64.md requires.
- **Vendored** (`vendor/limine`, checksummed in `CHECKSUMS`, from the signed v12.9.4 binary release, tarball sha256 and GPG signature re-verified on 2026-10-30): `BOOTX64.EFI` (UEFI), `limine-bios.sys` and `limine-bios-cd.bin` (BIOS stage 2 and the El Torito boot image), and `limine.c` with `limine-bios-hdd.h` (the host tool's source). Not vendored: the 32-bit, RISC-V and LoongArch loaders, `limine-uefi-cd.bin` (3 MiB; the images carry their own FAT ESP), the PXE image.
- **The host tool is built, not vendored as a binary:** `scripts/mkiso.sh --arch x86_64` compiles `limine.c` with the host C compiler (`$CC`, default `cc`) into the temporary directory and runs `limine bios-install` on the finished ISO. This keeps a prebuilt executable out of the repository and the tool's source reviewable.
- **Image (X2, minimal):** a hybrid ISO. El Torito entry 1 is `limine-bios-cd.bin` (BIOS), entry 2 the FAT ESP image with `EFI/BOOT/BOOTX64.EFI` (UEFI); `limine.conf` has one entry and no menu; the kernel is pinned by blake2b as on aarch64. The ISO9660 tree repeats the loader, config and kernel because Limine reads the CD itself on a CD boot. The universal image (both architectures, the install menu, the raw GPT image) is X10. The aarch64 output of `mkiso.sh` is unchanged.
- **Verified:** the ISO boots under QEMU q35 with edk2 (UEFI) and pc with SeaBIOS (BIOS). Not verified: real hardware, other firmware, Secure Boot (Limine's binary is not signed for it).

## ADR-042 — x86_64 FP/SIMD policy and the custom target (X1, D3)

- **Status:** Accepted (X1).
- **Problem:** `x86_64-unknown-none` is soft-float (finding F3). SQLite needs floating point, and the crypto backends need SIMD registers; the kernel must keep that state intact across exceptions without a cost on every exception that nothing needs.
- **Decision:** option (a) of PROMPT-x86_64.md §5.3. A custom target, `targets/x86_64-urmqtt-none.json`: hard-float, x86-64-v2 baseline (`+sse4.2,+popcnt,+ssse3,+cx16`), no red zone, `code-model: kernel`, static relocation, `panic: abort`. It builds with the `-Zbuild-std` we already use and needs `-Zjson-target-spec`. A spike showed an `f64` multiply compiling to `mulsd`.
- **Consequences:**
  - The kernel itself uses only SSE-class registers. `_start` turns on the x87/SSE state before any Rust runs; Rust then enables XSAVE and sets XCR0 to x87 | SSE | AVX (AVX-512 only when a dispatched kernel needs it).
  - The exception entry saves x87/SSE state with FXSAVE (the handler is hard-float Rust; an `int3` resumes). It does **not** save AVX state: compiled kernel code never touches the upper halves. This is safe only while no AVX code runs in the kernel. Today none does (the vendored `cpufeatures` answers "no" for x86, ADR-041, so every RustCrypto backend is the portable one). X9 (AVX2/VAES backends) must switch the entry to XSAVE before it enables one; `test=simd-irq` is the check.
  - A CPU below x86-64-v2 cannot run the image: `_start` checks CPUID in assembly and refuses with the message of PROMPT-x86_64.md §1 (on COM1 and, since X10, on the framebuffer).
- **Alternatives:** `x86_64-unknown-none` plus `#[target_feature]` islands (rejected: SQLite would need a soft-float build, and every crate call crossing an island needs a wrapper); XSAVE on every exception (rejected until a backend needs it; the cost is measured in X9).

## ADR-043 — The universal image: one ISO for aarch64 UEFI, x86_64 UEFI and x86_64 BIOS (X10, D4)

- **Status:** Accepted (X10), verified under QEMU only (aarch64 UEFI under HVF and TCG, x86_64 q35+OVMF and pc+SeaBIOS under TCG). Not verified on KVM, on real hardware or with Secure Boot.
- **Layout (`scripts/mkiso.sh --universal`, `make universal`):**
  - **Kernels:** `/boot/urmqtt-aarch64.elf` and `/boot/urmqtt-x86-64.elf` (Limine's `${ARCH}` spelling). Each menu entry pins its own kernel by blake2b.
  - **One `limine.conf`, entries per architecture:** every entry carries `if_arch: aarch64|x86-64`, so a machine sees only its own. Checked against the vendored Limine 12.9.4: hidden entries are skipped, and `default_entry` counts the entries *visible* to the running architecture (1 = urMQTT, 2 = the installer). A macro for the hash (`${HASH_${ARCH}}`) does not work: macros do not nest.
  - **Installed disk image** (`disk.img`, also `--disk-out`): protective MBR with Limine's BIOS stage 1, a GPT with a **BIOS boot partition** (LBA 64..2047, where `limine bios-install` puts stage 1.5) and the **ESP** at 1 MiB with both UEFI loaders (`BOOTAA64.EFI`, `BOOTX64.EFI`), both kernels, the no-menu config at `/EFI/BOOT/limine.conf` and `/boot/limine/limine.conf`, and `limine-bios.sys` (stage 2, found on the ESP). One disk therefore boots on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS, and a VM's data partition can be read by a VM of the other architecture (smoke `cross-arch-*`).
  - **The ISO:** El Torito BIOS entry (`limine-bios-cd.bin`) and UEFI entry (the ISO's ESP), a GPT partition for that ESP and a protective MBR with Limine's BIOS code (`limine bios-install` on the ISO), so the file also boots when written to a USB stick. The ISO's ESP is the disk's ESP **plus `/disk.img` and the menu config**: UEFI firmware mounts that ESP, and Limine reads the config of the volume it was loaded from, so the menu and the install entry (`module_path: boot():/disk.img#<blake2b>`) have to be there. The ISO9660 tree (what a BIOS boot from the CD reads) has the same files. The ISO is about 48 MiB; the raw image 14 MiB.
  - **Installer:** the module may now be a finished disk image (`/disk.img`) as well as an ESP (`/esp.img`, the aarch64-only ISO). `urmqtt_store::install::write_boot_image` checks it (512-byte multiple, protective MBR signature, GPT header whose backup LBA is the image's last sector) and writes it in the same crash-safe order as before, including the BIOS boot code in sector 0 and the gap.
  - **First boot** is unchanged: it moves the backup GPT, gives the disk its GUID and creates the data partition after the ESP (the first usable LBA of this image is 34, because the BIOS boot partition lives below 1 MiB).
- **`make iso` and `make raw` are untouched** and byte for byte what they were: the universal artifacts are separate targets (`make universal`, `make dist-universal`, `scripts/repro.sh --universal`). Verified: two builds, and a build a second later, are identical (`limine bios-install` is deterministic).
- **First real-VPS finding (Proxmox/KVM, SeaBIOS, ISO as a virtual CD):** the default entry ran urMQTT from the CD, production refused to serve from read-only media and reset: an endless menu, kernel, reset loop with nothing readable. Now a fatal error in a production image leaves its message on the console for 60 s before resetting, and from optical media it prints `Booted from read-only media. Reboot and choose "Install ..."` and halts. The default stays urMQTT (an unattended wipe would be worse) but the menu countdown is 10 s. KVM facts seen there and handled: no TSC-deadline and a non-invariant TSC (one-shot LAPIC timer, a warning), kvmclock as the TSC source, no `_S5` and no reset register (power-off falls to the hypervisor's PM1a port, reset to port 0xCF9), no MCFG (configuration mechanism #1).
- **Menu look:** `wallpaper: boot():/boot/wallpaper.png#<blake2b>` (hash accepted by Limine 12.9.4), centered, `backdrop: 2c2c44`, empty `interface_branding`, `interface_help_hidden: yes`, in the menu configs only.
- **Alternatives:** separate per-architecture ISOs (kept, they are the aarch64-only default); `limine-uefi-cd.bin` (not vendored: the images carry their own FAT ESP); a per-entry hash through macros (does not nest); a BIOS stage 2 in a file only (`limine bios-install` on GPT refuses without a BIOS boot partition).
- **Known limits:** writing the ISO to a USB stick gives UEFI the menu (the ISO's ESP) and BIOS the stage-1 code of the ISO; the data partition of a *stick* used as the machine's disk is not a supported layout (install to the internal disk). Secure Boot is off-limits until H8 (Limine is not signed for it). Hybrid-ISO behaviour on real firmware is untested.

## ADR-045 — x86_64 interrupts and time (X4, D6)

- **Status:** Accepted (X4); verified under QEMU TCG (HPET calibration, one-shot LAPIC timer, MSI-X completions, IPIs between 8 CPUs). KVM paths (kvmclock, PV EOI, the TSC-deadline timer) are written and unit-tested but have not run.
- **Vector map** (`crates/arch-x86_64/src/vectors.rs`, tested for overlap): `0x20` local APIC timer; `0x21-0x3f` I/O APIC lines (`0x21 + GSI`); `0x40-0xdf` MSI/MSI-X, handed out by `msi::Frame`; `0xe0-0xef` the remapped 8259 (kept masked); `0xf1-0xf3` IPIs (ping, pong, wake); `0xfe` APIC error; `0xff` spurious. Vectors are per CPU, so one global handler table indexed by vector serves all CPUs.
- **Controllers:** the 8259s are masked first. x2APIC is used when the CPU has it (the request for Limine's MP feature asks for it, so every CPU starts in it), else xAPIC through an uncached mapping of the MADT's base. Every I/O APIC pin starts masked. `ack` reads the highest vector in service from the ISR (a local APIC has no acknowledge register), the spurious vector gets no EOI.
- **Time base (the TSC):** frequency from, in order, the hypervisor timing leaf, kvmclock's scale, CPUID 0x15, a measurement against the HPET (three 20 ms windows, median), the ACPI PM timer, then CPUID 0x16. One deliberate change from D6: a measured value beats CPUID 0x16, whose base MHz is nominal. `time::init` needs the HPET or PM timer addresses from the platform description, else `NoTscFrequency` and the boot stops with a message. A TSC without the invariant bit is used anyway (a hypervisor's virtual TSC is constant) and a warning says so. The log clock and the wall clock (date at boot plus uptime) are both derived from it.
- **Timer:** the local APIC in TSC-deadline mode when CPUID has it, else one-shot mode re-armed from the deadline with its rate measured once against the TSC. QEMU TCG offers no TSC-deadline, so TCG runs the one-shot path (`timer: ... (one-shot, calibrated)`); the interrupt latency figures under TCG say nothing about hardware.
- **`wait_for_interrupt` keeps the caller's interrupt flag.** The first version ended in `cli`, so the first idle wait turned interrupts off for the rest of the boot (found when no MSI-X completion ever arrived). It is `sti; hlt`, then `cli` only if interrupts were off on entry.
- **Per-CPU identity:** `GS` base points at a per-CPU block whose first word is the logical index (`percpu::current` is one `mov`). `set_current` must run on a CPU before anything calls `current()` on it.
- **Entropy:** RDSEED/RDRAND feed the pool as one source among others (virtio-rng, bootloader values, jitter); they are never the sole source (ADR-038).

## ADR-046 — x86_64 test matrix and the feature census (X1/X2, D7)

- **Status:** Partly accepted. Accepted: TCG is the local and CI-less baseline. Not done: the KVM CI job.
- **Decision:** the x86 smoke suite runs under TCG (q35+OVMF, pc+SeaBIOS) on any host and under KVM when `/dev/kvm` is writable on an x86_64 Linux host (`run-qemu.sh`, `smoke.sh --arch x86_64` choose by themselves). TCG implements no AVX-512, CET or WAITPKG and offers no TSC-deadline or invariant TSC, so it cannot test those paths; a named CPU model under TCG only tests that dispatch follows the *reported* CPUID.
- **Census** under TCG (QEMU 11.1.2): see ADR-044. The `max` model offers AES-NI, PCLMULQDQ, SHA-NI, AVX/AVX2, VAES, RDRAND/RDSEED, FSGSBASE and x2APIC.
- **Not verified:** whether GitHub's hosted Linux runners expose KVM to this repository's jobs (the probe job of D7 does not exist yet). Until it does, no number in the docs comes from KVM.

## ADR-047 — x86_64 control-flow integrity (CET) is not enabled (X3, D8)

- **Status:** Deferred. Nothing in the kernel uses IBT or supervisor shadow stacks.
- **Why:** QEMU TCG does not emulate CET, so the code cannot be tested locally, and untested control-flow enforcement on a kernel that cannot boot to report a violation is worse than none. The aarch64 equivalents (PAC, BTI) are on and tested.
- **Plan:** IBT through `-Zcf-protection=branch` and supervisor shadow stacks (`IA32_S_CET`, `PL0_SSP`) when a KVM host with CET exposed is available; the smoke scenarios `x86-cet-*` would report "skipped" without it. The page-table encoding has no shadow-stack type yet.

## ADR-056 — x86_64 memory protection and paging (X3)

- **Status:** Accepted (X3); verified under TCG (W^X audit over 15 000+ leaves, the five fault scenarios of smoke).
- **Tables:** 4-level, the kernel image and heap in the upper half. The root has no lower-half entries at all, so a null or user pointer faults (the audit counts lower-half leaves and must find none). No global pages (CR3 reloads flush everything), no PCID.
- **Types and PAT:** page attributes map to PAT indices WB, WC, UC-, UC at 0..3 (`pat.rs` programs the MSR on every CPU, the boot CPU before it edits the bootloader's tables, the others from the boot CPU's value in the AP entry stub). Device memory is UC- (an MTRR or a PAT entry can make it stronger, never weaker), the framebuffer write-combining.
- **Protections** (`paging::activate`): EFER.NXE first (the new tables carry NX bits), CR3, then CR4.SMEP/SMAP/UMIP where CPUID has them, then CR0.WP. The boot log line is `mm: protections nx=on wp=on smep=on smap=on umip=on`. A CPU without one reports it as `unavailable`; none is switched off silently.
- **Same security properties as aarch64:** text RX, rodata R, everything else RW+NX, the sealed dispatch page read-only, the HHDM alias of the kernel image read-only, stack guard pages unmapped, the page-table pool writable only through an alias that `vm::lock` removes, and then no mapping request succeeds. `selftest: W^X ok (... 0 W+X, text-only execute, guards unmapped, tables read-only)` has the aarch64 format.
- **No TLB shootdown.** After `lock` nothing is ever remapped, and everything mapped before it is mapped before the other CPUs start. `tlb_flush_va` therefore only has to flush the local CPU. This stops being true the day the kernel unmaps or remaps anything at run time; the day it does, it needs IPI shootdowns (ping/wake vectors exist).
- **Faults** are reported by the exception entry on IST stacks (#PF included), so a stack overflow into a guard page prints the faulting RSP and the guard explanation instead of becoming a #DF.

## ADR-057 — x86_64 platform discovery: ACPI only (X6)

- **Status:** Accepted (X6); verified on QEMU q35 and pc tables (host tests with captured tables, smoke boot lines).
- **Decision:** x86 has no device tree. Limine's RSDP (XSDT, or the RSDT when the XSDT is empty or corrupt) leads to the MADT (local APICs including x2APIC entries, I/O APICs, interrupt source overrides, NMIs, the 64-bit local APIC address override), the FADT (PM1 blocks, PM timer, SCI, reset register, DSDT), the HPET table, the MCFG (ECAM regions) and the SPCR. All of it goes into `PlatformInfo.x86` next to the aarch64-shaped fields, and the `platform summary:` line appends it.
- **Bounds:** fixed-capacity lists (64 CPUs, 8 I/O APICs, 32 overrides, 16 NMIs, 8 ECAM regions) with a `dropped` counter; every read is bounds-checked and the crate denies indexing, `unwrap` and panics.
- **`\_S5` without an interpreter:** a scanner finds the literal `Name (_S5, Package () { a, b })` encoding in the DSDT or an SSDT and nothing else; anything it does not understand yields `None`. It has a fuzz target (`aml_s5`), and `acpi_parse` is seeded with the QEMU tables.
- **Not done:** the kernel does not use the FADT reset register or `\_S5` for power control yet. Power-off is QEMU's ACPI ports under a hypervisor, reset is port 0xCF9 and the 8042 pulse (ADR-044). Real hardware needs the ACPI path (X12).

## ADR-058 — PCI and virtio on x86_64 (X7)

- **Status:** Accepted (X7); verified under TCG on q35 (ECAM) and, via the universal image, pc+SeaBIOS (configuration mechanism #1).
- **Config space:** ECAM from the MCFG when its window answers (the host bridge at 00:00.0 must read a vendor ID; some firmware lists a window that decodes nothing), else configuration mechanism #1 through ports 0xCF8/0xCFC behind the same `ConfigSpace` trait (`pci::PortConfig`). BARs are sized with decoding turned off, MMIO preferred.
- **virtio:** only virtio 1.0 devices (the modern capabilities). A transitional device that offers only the legacy I/O-port register block, or lacks the required capabilities, is logged as `unsupported legacy virtio device ... attach it as a modern device (disable-legacy=on)` and ignored. There is no legacy driver. A hypervisor that exposes nothing but legacy virtio gets a clear message and no network, not a half-working one.
- **MSI-X:** one vector per queue is composed by `msi::Frame` as `0xFEE00000 | apic_id << 12`, data = vector. The destination field is 8 bits wide, so a CPU with APIC ID above 0xFE cannot be targeted without interrupt remapping (checked, `Frame::reachable`). Vectors target the boot CPU.
- **Missing hardware** is said in the boot log, which the framebuffer shows: no virtio-rng and no RDRAND/RDSEED falls to the jitter fallback or to `no entropy source ... refusing to run`; no virtio-net names every network controller found without a driver (vendor and device ID).

## ADR-059 — One boot sequence for both architectures; x86_64 SMP (X8, X5)

- **Status:** Accepted (X8, X5); verified under QEMU (aarch64 HVF and TCG regression, x86_64 TCG, 2 to 8 CPUs).
- **Boot sequence:** `crates/kernel/src/boot.rs` is the only sequence. What differs is behind `boot_aarch64.rs` and `boot_x86.rs`: the console before the first log line (COM1 vs the PL011 mapped from the DTB/SPCR), the time base (the TSC calibrated against the HPET or PM timer vs the generic counter), the privilege label, CPU feature detection and its log, BTI/PAC, the interrupt controller bring-up and the timer interrupt number, and the test faults that exist on one architecture only. The old duplicate (`urmqtt_kmain_aarch64`, compiled but dead on x86) is gone. The aarch64 boot log is unchanged.
- **SMP (x86_64):** Limine's MP request asks for x2APIC. Each AP enters `urmqtt_ap_entry` in the bootloader's tables, mirrors the boot CPU's EFER.NXE, PAT, CR4, CR3 and CR0 (in that order: NX before the kernel's tables, WP last), initialises x87/SSE, switches to its kernel stack and calls `urmqtt_ap_prepare`, which loads its **own GDT/TSS** (the TSS descriptor is marked busy once loaded, so CPUs cannot share one), the shared IDT, sets the GS base (the GDT reload clears it) and enters the kernel's `ap_main`. Its four IST stacks are the top of its mapped exception stack, which is 64 KiB on x86 (`layout::EXC_STACK_SIZE`; 32 KiB on aarch64, where it holds the exception stack). `gdt::which_ist` knows every CPU's, so a fault report names the IST stack whichever CPU it came from.
- **IPIs and idle:** ICR through the x2APIC MSR (xAPIC: two MMIO writes with interrupts off); `hlt` idle; the same ping-pong over every ordered pair as aarch64 (`ipi: 56/56 ordered pairs ping-pong ok` with 8 CPUs).
- **Not done:** the KVM paravirtual IPI hypercall, more than 64 CPUs (`MAX_CPUS`), CPU hot-plug.

## ADR-060 — Remote operation over MQTT: `$SYS/`, the operator role and the console (O1, O2)

- **Status:** Accepted (O1, O2); verified by host tests, and by the `sys-operator` smoke scenario on aarch64 (HVF) and x86_64 (TCG).
- **Problem:** the only window into a running appliance was the serial console, or a VNC session on a VPS. There was no way to see load, memory or client counts, or to read the log or lower its level, without one.
- **Decision:**
  - **A fixed system namespace `$SYS/`** with its own role. `acl.operator_ids` (exact identities, required key, empty means none) gives the **operator** role. Only an operator subscribes to `$SYS/#` and publishes to `$SYS/console/in` and `$SYS/query/info`; everyone else is refused whatever their ACL patterns say (like `$urmqtt/`, enforced in `urmqtt_broker::acl`, not in the configuration). An operator reaches nothing outside `$SYS/`: it is not a superset of a service. The build rejects a `$SYS/` pattern in any ACL list, a wildcard or duplicate operator id, and an id that is also a service id (one role per identity).
  - **The role needs a certificate.** A connection without an authenticated identity (the dev plaintext port) that names an operator id is an ordinary device. A restored persistent session takes the role of the connection that resumes it, not the one it was restored with.
  - **What an operator publishes is a request, never a message.** `$SYS/console/in` and `$SYS/query/info` are not routed, not retained, not persisted and not offered to other shards: the broker queues them (at most 16, then dropped and counted) for the kernel to answer. Any other `$SYS/` topic is dropped, also for the operator. A will may not name `$SYS/` (it would run on disconnect).
  - **O1, retained topics.** Each data core publishes the topics of `urmqtt_broker::sys::topics` into its own shard every 10 s, from relaxed counters that every shard and the DB core keep for themselves. A subscriber meets the copy of its own shard, so there is no cross-core message and no lock. They are retained messages that live only in memory: not stored, not counted against `max_retained_per_device` or `max_retained_bytes`, and not in the `$SYS/broker/retained` figure. Topics: `version`, `uptime` (s), `arch`, `cpu/cores`, `cpu/busy/<core>` (% over the last 5 s window), `memory/{total,used}` (the kernel heap, bytes), `disk/{total,used}` (the data partition, and what SQLite's DB, WAL and journal use of it; the fixed telemetry ring is not "used", bytes), `clients/{connected,total}` (sessions attached / sessions including offline persistent ones), `subscriptions`, `retained` (device messages), `messages/{received,sent}` (accepted publishes / deliveries, `$SYS/` traffic included), `connections/refused` (admission), `tls/server_cert_days`, and `console/dropped`. Broker statistics are O(1) now (`Broker::stats` keeps counters for subscriptions and online connections), so reading them never walks a million sessions inside a data-plane pass.
  - **O1, the query.** An operator publishes anything to `$SYS/query/info`; the shard answers with one JSON document (the same numbers) on **`$SYS/query/info/response`**. **Deviation from the plan:** the plan said "MQTT 5 Response Topic". The broker speaks MQTT 3.1.1 only (5.0 is a later milestone), which has no such property, so the reply topic is fixed and every operator subscribed to it sees every reply.
  - **O2, the console.** The log crate keeps a second, numbered ring of the last 128 lines (`console_next`, `console_read`; a fixed array, no allocation, written under the same lock as the UART). Each data core reads it with its own cursor, 16 lines per pass, and publishes the lines (QoS 0, `[time] LEVEL text`) to `$SYS/console/out`; the shard keeps the last 64 and replays them to a new subscriber. Nothing waits for a reader: a subscriber that cannot take a line loses it (the broker's QoS 0 backpressure, `dropped_backpressure`), a core that falls more than the ring behind loses the oldest lines, and both are counted (`$SYS/broker/console/dropped`, plus a line on the console).
  - **O2, commands.** One command per message on `$SYS/console/in`: `help`, `status`, `log level <error|warn|info|debug|trace>` and `reboot`. The parser (`urmqtt_broker::sys::parse`, host-tested) accepts printable ASCII up to 64 bytes on one line; everything else is refused with a reason (`status; reboot` is an unknown command, not two). There is no shell, no variable, no path, no way to run operator-supplied code or read data. `log level` can only lower the level, never above the build-time maximum. `reboot` replies, waits 1 s and resets through the architecture's power-control seam (a request, not a flush: durable state is crash-safe).
  - **Rate limit and audit.** A burst of 5 commands, then one per 2 s per shard, on top of the session's own publish rate. Every command is audit-logged with the identity and the text, accepted or refused (`console: operator ran "status"`, `console: operator command refused (unknown command): "x"`), and a refusal for the rate limit is logged at powers of two. Audit lines are written whatever the log level is (`urmqtt_log::audit`; the log's own rate limit still applies), so lowering the level cannot hide what an operator did. Replies go to the console output of the shard the operator is on; the audit line goes through the log and so reaches every shard's console.
- **Consequences:**
  - An operator identity is as powerful as a device that can read the kernel log and reset the machine. A stolen operator certificate means a reboot loop (DoS) and a read of the log (no secrets or payloads are ever logged, a standing rule). Revoke it like any other certificate (control channel). Operators are exempt from the registry allowlist, like services, because the image names them.
  - The console exists on every build, production included, and cannot be switched off by the command line. It is off in effect when `acl.operator_ids` is empty. `deploy/prod/config.toml` lists `operator`; issue its certificate with `scripts/gen-operator-cert.sh deploy/prod`.
  - Memory: the log ring is 128 records of 216 bytes (27 KiB, in the kernel image), each shard's replay ring at most 64 messages.
- **Not done:** MQTT 5 Response Topic, a per-operator reply topic, per-core retained figures for `clients`, a command to change anything but the log level, console input as a stream (a command per message only).

## ADR-061 — The live entry is selected by the kernel command line and allowed by the configuration (O3)

- **Status:** Accepted (O3); verified under QEMU on aarch64 (HVF and TCG), x86_64 q35+OVMF and pc+SeaBIOS, and the universal ISO. Not run on KVM or hardware.
- **Question:** what makes a boot run the broker from RAM with no disk: the baked configuration (`storage.mode = "ram"`), or the boot menu entry?
- **Decision: both, and neither alone is enough for production.**
  - The ISO menu's first entry ("urMQTT") passes the word **`live`** on the kernel command line (`mkiso.sh`; `--no-live` leaves it out, the x86_64-only ISO without a menu takes it with `--live`). The installed disk's no-menu configuration never has it, so booting the disk is exactly what it was.
  - The word is honoured on production images like `install` (ADR-052), and by nothing else: the kernel cannot be talked into anything else by the command line.
  - The baked configuration must **allow** it. `storage.mode` is `"disk"` (the committed production template: `live` is refused loudly, "fatal: live mode ... but this image's storage.mode is \"disk\"", the screen stays readable), `"auto"` (the disk, but the live entry runs from RAM) or `"ram"` (always RAM, whatever the medium: a diskless appliance). Outside `dev` the key is **required** (the build fails without it), so an image never inherits a medium by default.
  - `storage.mode` x `live`: disk/no: disk; disk/yes: refuse; auto/no: disk; auto/yes: RAM; ram/either: RAM. `urmqtt_config::StorageMode::backing` is that table and is host-tested.
- **No silent fallback, either way.** With the disk path, a missing or read-only disk is still the fatal "no data partition" (production) and never turns into RAM; `live` is the only road to RAM, and it is explicit twice (the menu entry and the config). A production image whose operator never wrote `auto` or `ram` cannot become ephemeral by anyone's boot menu. `require_data_disk`, `require_flush` and `refuse_on_corruption` stay `true` outside dev, validated as before.
- **Why not the config alone** (`mode = "ram"` for the ISO, `"disk"` for the disk image): one build would need two configs, and the ISO's install entry installs the same kernel that then boots from the disk. **Why not the command line alone:** a menu typo or a bootloader substitution would then decide where production data goes, with no build-time evidence.
- **Consequences:** an ISO built from the committed production template shows the live entry, boots, and halts with the reason on screen until the template's `mode` is set to `"auto"`: opting in is one line in `deploy/prod/config.toml`. The install entry is unchanged.

## ADR-062 — The RAM store: a block device, a reservation and a loud banner (O3)

- **Status:** Accepted (O3).
- **Device, not a new storage layer.** `urmqtt_store::ram::RamDisk` implements the same `BlockDevice` as the virtio disks. The data layout (superblock, size table, SQLite regions, telemetry ring), the SQLite VFS and the telemetry log run on it unchanged; the kernel hands `db::init` a `BootDisk` whose partition is the whole device. The memory is zeroed frames in 2 MiB runs (`vm::dma_alloc`), one `'static` slice per run, because physical memory is rarely contiguous. No write cache: a write is complete when it returns and `flush` has nothing to do. The block self-test runs on it. No disk is read, written or formatted in live mode: the boot disk handle is dropped, the first-boot GPT steps are skipped (smoke `live-leaves-disks-alone`).
- **Size: `storage.ram_percent`** (default 10, validated 2..=50: the floor keeps the store above the layout's 16 MiB minimum on ordinary machines, the ceiling leaves most RAM to connections), applied to the RAM the memory map reports and rounded down to whole MiB. The kernel refuses (`live mode: the RAM store does not fit`) when the result is below 16 MiB, which is the layout's own minimum. The store's regions are the usual proportions (database half, WAL up to 64 MiB, telemetry the rest), so 10 % of a 4 GiB VPS is a 409 MiB store with 204 MiB of database.
- **Subtracted from the connection budget.** The kernel heap is a fixed buddy region (`memory.kernel_heap_mb`, a power of two, about 500 B per idle connection). Stage 1 plans `store + SQLite heap + 128 MiB kernel overhead + heap` against the memory map *before* the heap is mapped (`ram::plan`): if all fit, the heap keeps its size and the store comes out of what was spare; if not, the heap shrinks to the largest power of two that fits (never below twice `memory.min_free_mb`, at least 8 MiB), and the boot log says `live: kernel heap 512 MiB instead of the configured 1024 MiB ... about 1073741 connections instead of 2147483`. Connection capacity follows the heap, so a bigger `ram_percent` on a small machine costs connections. Example: 1 GiB, 10 %, heap 1024: 102 MiB store, 786 MiB left after SQLite (8) and overhead, heap 512 MiB.
- **Loud.** Before the broker serves: a framed banner written whatever the log level (`EPHEMERAL: data is lost on reboot`, how much RAM, what is lost, how to persist), the same words as a `WARN` line (syslog sees it), the storage and SQLite lines say `RAM store (EPHEMERAL ...)`, and the statsd gauges `urmqtt.storage.ephemeral` (1 in live mode) and `urmqtt.storage.ram_bytes` go out every 10 s. There is no `$SYS` tree in the broker, so the flag is a metric and the log, not a topic.
- **What ephemeral costs on the security side.** Revocations applied through the control channel and its replay-protection sequence number live in the store (H1): after a reboot only the image's own revocation list is seeded again, and an old, still-valid control message could be replayed. The kernel warns once at boot when the control channel is on in live mode. Sessions, retained messages and the telemetry log are gone, as intended. A fatal error in live mode resets the machine (the menu returns and boots live again) instead of halting: on the install entry a reset would loop, here it is the recovery.
- **Not done:** persisting a RAM store across a warm reboot (kexec-style), encrypting it (RAM is the trust boundary), a `$SYS` publication, hot-resizing.

## ADR-070 — x86_64 hardware crypto, and where a handshake's time goes (X9)

- **Status:** Accepted (X9). Extends ADR-041 (dispatch) and ADR-053 (aarch64 backends).
- **Context.** A real KVM VPS (AMD EPYC, 4 vCPU, software crypto) managed about 344 full TLS 1.3 + mTLS handshakes per second. X9 was planned as "AES-NI, SHA-NI, CRC". Before building more, we profiled the handshake (`urmqtt_tls::bench`, `cargo run --release -p urmqtt-tls --example profile`; the same code prints `crypto-profile:` at every boot).
- **The split** (x86_64 build under Rosetta on an Apple M4 Pro, which runs AES-NI and PCLMULQDQ but not SHA-NI; per operation): X25519 base multiplication 36 us, X25519 shared secret 36 us, ECDSA P-256 sign 199 us, verify 206 us, HMAC-SHA-256 0.7 us, AES-128-GCM 1 KiB 0.7 us (5.0 us in software). A server-side handshake does one X25519 key share, one signature and two verifications (the client certificate and its CertificateVerify): about 680 us of public-key math and about 70-85 us of hashing and records (48 HMACs, 160 SHA-256 blocks, 4 KiB of AEAD). **Public-key math is 89-91 % of the handshake.** AES-NI, PCLMULQDQ and SHA-NI therefore change a handshake by about 2 % (symmetric part 84 -> 68 us). They matter for records (AES-GCM 7.4x faster) and for the store's checksums (CRC-32C 24x), not for the handshake rate.
- **And the VPS number does not add up to crypto.** 680 us of public-key work per handshake on one core is about 1 400 handshakes/s/core, so more than 5 000/s on four cores, against the measured 344/s (about 11.6 ms of core time per handshake if all four cores were busy). Either the cores are mostly idle (load generator, network path, 20 ms stalls, admission refusals) or something else costs the time (steal, serial console logging, the 50-90 ms handler overruns). The boot line `crypto-profile:` on that VPS settles it in one read; the watchdog report now names the step (below).
- **Backends** (all behind the existing sealed dispatch, detected at boot, KATs at boot, software fallback, `[cpu] disable` honoured):
  - `aes-gcm=aesni ghash=pclmulqdq` (RustCrypto `aes`, `polyval` x86 intrinsics), `sha256=sha-ni` (`sha2` 0.10 and 0.11), `chacha=sse2` (the baseline; AVX2 is never granted because the kernel keeps no AVX state, ADR-042), `crc32c=sse4.2` (`arch-x86_64::crc`, `_mm_crc32_u64`, installed through the store's hook).
  - The vendored `cpufeatures` (0.2.17 and 0.3.1) gets the same patch on x86 as on aarch64: on `target_os = "none"` it asks the kernel's `urmqtt_cpu_has` instead of answering "no". Features the x86-64-v2 target enables at build time (SSE2 to SSE4.2) are answered true by `cfg!`. The dispatch grants `aes` (with PCLMULQDQ), `pclmulqdq` and `sha`; `avx*`, `bmi2`, `adx`, `vaes` are refused.
  - The feature names in `[cpu] disable` and in the log stay `aes`, `pmull`, `sha2`, `crc32` (AES-NI, PCLMULQDQ, SHA extensions, SSE4.2).
  - No hand-written assembly: RustCrypto's own intrinsics and one intrinsic in `arch-x86_64`. The arch-leak rule holds.
- **Tests.** Boot KATs gained long vectors (1000-byte AES-128-GCM with 37 bytes of AAD, from OpenSSL's AES-CTR plus an independent GHASH script; SHA-256 over 64, 128 and 1000 bytes; CRC-32C RFC 3720 vectors and an unaligned tail) so the wide paths run, and they run in `simd-irq` under interrupts. Differential: 20 000 random cases (lengths up to 70 KB, unaligned) of AES-GCM, ChaCha20-Poly1305, SHA-256 (both `sha2` versions, chunked) and CRC-32C against `ring` on the x86_64 build, no differences; `fuzz/diff_crc32c` has an x86 arm and the other `diff_*` targets run the hardware backends on x86 CI automatically. SHA-NI could only be exercised under QEMU TCG (KATs), because Rosetta has no SHA extensions: real-hardware differential for SHA-NI is open.
- **Public-key speed-ups.** Field arithmetic lives in `p256`/`primefield`/`crypto-bigint` (`forbid(unsafe_code)`, generic limbs); a BMI2/ADX multiplier would mean forking them, for at most 1.3-1.5x on 90 % of the handshake, and X25519 already uses the 51-bit backend. Not done. What was done is to **stop repeating work**: a successful certificate-signature verification is remembered by the SHA-256 of (key, message, signature) in a 512-entry direct-mapped memo (`provider/verify.rs`). A reconnecting device presents the same certificate, so its CA signature (one of the two verifications, about 30 % of the handshake's CPU) is not checked again. The result of a verification is a pure function of its three inputs, so a hit says what a fresh check says; failures are never stored, CertificateVerify messages (64 spaces first, fresh each handshake) bypass the memo, validity dates and revocation are checked elsewhere (webpki, the revocation list) and are unaffected. `$SYS`/statsd `tls.verify_memo_hits` counts hits. Session tickets (H2) skip all public-key math and stay the real answer for reconnect storms.
- **Boot cost.** The `crypto-profile` benchmark runs once at boot, on the boot core, before the data plane: about 0.25 s on a fast CPU (ten primitives, 20 ms each).
- **Not done:** VAES/VPCLMULQDQ and AVX2 backends (need AVX state), PCLMULQDQ folding for CRC-32C, Toeplitz, a BMI2/ADX P-256 field multiplier, fixed-base tables for signing (`p256`'s table needs `std` or `critical-section`).

## ADR-071 — The watchdog budget has classes; handshake steps get their own (WD)

- **Status:** Accepted (WD). Amends ADR-035.
- **What the 20 ms was for.** The data path is cooperative: a handler that runs long stalls every connection on its core (ADR-035, PROMPT 4.1). Production used 20 ms with `drop`, chosen when a full P-256 handshake took about 0.6 ms: "one slow handshake under steal time should cost one connection, not a million".
- **What `drop` does.** It aborts the *connection recorded in the handler's mark*, after the handler returns. For a TLS handshake step (an `Input` handler with that connection) it kills the handshake in progress: the peer sees a reset and counts an error. For the `Output` handler (`MqttService::poll`: timers, broker output, TCP hand-off, routes, control, DB and log pumps) no connection is recorded (`conn -`), so `drop` has no victim and aborts nothing; it only logs. The report `core N output handler for conn - over budget: 50-90 ms` from the VPS is therefore a core stall in `poll`, not a refused handshake. The stall itself delays every handshake in flight on that core (they pile up against `max_handshakes_in_flight_per_core`, which is what produces refusals). Which part of `poll` stalls is unknown; the report now names it (`step timers|shrink|sys|ready|tcp|routes|control|persist|telemetry`).
- **Decision.** Two classes. Ordinary handlers (`Input` for MQTT packets, `Output`, self-test) keep `watchdog.handler_budget_ms` (20 ms in production). A handshake step is a new `Phase::Handshake`, entered by the TCP data callback while the connection's TLS session is not yet established. Its budget is `watchdog.handshake_budget_ms`:
  - `0` (default, the key may be absent): **calibrated at boot** = 10 x the estimated handshake CPU time (the `crypto-profile` total), rounded up, within a floor of 50 ms and a cap of 500 ms (`urmqtt_tls::bench::handshake_budget_ms`, unit tested). 10x leaves room for steal time, interrupts and the second flight; the floor stops a fast CPU from being as tight as ordinary handlers; the cap keeps it far below the reset.
  - `1..=900`: pinned; never below `handler_budget_ms`. Above 900 is rejected at build time.
- **The hard cap.** A handler of any class still running after `max(1000 ms, 100 x handler_budget_ms)` means a stuck core and resets the VM, as before. The handshake budget does not move it (that is why 900 is the largest pinned value and 500 the calibrated cap), so a handler stuck forever still trips.
- **Numbers.** Fast x86 CPU, hardware-assisted: handshake 0.8 ms -> budget 50 ms (floor). QEMU TCG (smoke): 5.7-6.5 ms -> 57-65 ms. The VPS of the report, if it really spent 11.6 ms per handshake: 116 ms. A budget of 20 ms would be 1.7x that handshake; with the 50-90 ms stalls seen, ordinary handlers still report as before, which is the point: those are not handshake work and now say where they are.
- **Tests.** Host: budget function (floor, cap, rounding, configured wins), config bounds. Smoke: `watchdog` (ordinary class, now with the step in the report) and `watchdog-handshake` (`test=watchdog-handshake`: a handshake-class handler spends half its budget unreported although far over 10 ms, then overruns and is reported against the handshake budget). Boot prints `watchdog: handshake budget N ms (calibrated), other handlers 20 ms, stuck-core reset at 1000 ms`.
- **Not done:** a per-step split of the handshake (ClientHello flight vs client Finished flight), budgets for the DB core (still unwatched, ADR-035), drop for output handlers (needs a victim policy).

## ADR-063 — The diagnostic entry: detection, measurements and a guarded write test (O4)

- **Status:** Accepted (O4); verified under QEMU on aarch64 (HVF), x86_64 q35+OVMF (UEFI) and pc+SeaBIOS (BIOS), both under TCG. Not run on KVM or hardware.
- **Selection.** The ISO menu's third entry, *Diagnostic: hardware detection and benchmarks*, passes the word `diag` on the kernel command line (`mkiso.sh`: `--diag-cmdline`, `--diag-default`, `--no-diag`; the universal ISO and the aarch64 menu ISO carry it, the x86_64-only ISO has no menu and takes `--cmdline diag`). Like `install` and `live` it is honoured by production images and by nothing else new, and like `live` the baked configuration must allow it: `storage.diagnostic = true`. The key is optional and **false by default**; a production image built without it stops with a fatal message that names the key (the screen stays readable, the machine does not reset). `diag` never uses a data store: `storage.mode` is irrelevant to it and no disk is chosen, formatted or opened for the broker.
- **Shape.** Pure parts are the new crate `urmqtt-diag` (no dependencies, host-tested): statistics (nearest-rank percentiles), formatting, bar scaling (linear and log), the unallocated-space computation (`space`), the write guard (`guard`), the JSON writer and the report, the PS/2 scancode decoder and line editor, and the dashboard layout against a `Canvas` trait. The kernel side (`crates/kernel/src/diag.rs`) detects, measures and wires the canvas to the log crate's framebuffer console. Per-architecture facts (CPUID or MIDR_EL1, the time base, the keyboard) are behind the same `boot_x86.rs` / `boot_aarch64.rs` seams as the rest of the boot sequence. It runs in stage 2 after the self-tests, before any data-plane or storage step, on the boot CPU, with the install-mode device probe (every disk is kept as a candidate, none is chosen).
- **What it shows and measures.** CPU (vendor, model, identity, feature census, crypto units, and the backend the sealed dispatch selected), RAM (total, usable, reserved or MMIO ranges of the memory map), PCI functions, disks (bus, size, flags, contents), NICs (MAC, link), the time source (frequency source, invariant TSC, kvmclock, deadline timer, RTC date and whether it is plausible), firmware (BIOS or UEFI, bootloader, boot medium) and hypervisor (CPUID signature on x86; on Arm only the PSCI conduit can be said, because the CPU does not tell). Measurements: RAM read, write and copy MiB/s on a buffer of up to 128 MiB taken from the frame allocator (the dev heap is 32 MiB), a dependent-load pointer chase from 4 KiB to 64 MiB for the L1/L2/L3/DRAM curve, per disk the sequential read (up to 64 MiB or 2 s), random 4 KiB reads at queue depth 1 (up to 2000 or 2 s: IOPS and min/p50/p90/p99/max latency), a guarded sequential write, and a **TLS handshake estimate**: one server-side mutual handshake is two X25519 operations, one ECDSA P-256 signature and two verifications, timed from the real primitives (`urmqtt_tls::probe`, the same crates the server uses, so it exists on production images without the dev-only client), reported in microseconds and in ticks of the finest clock (the TSC; the PMU cycle counter on Arm if the hypervisor exposes it, else the generic counter), plus AES-GCM, ChaCha20-Poly1305, SHA-256 and CRC-32C throughput. It is an estimate: certificate chain parsing and the record layer are not in it.
- **The write test and the guard (`urmqtt_diag::space`, `guard`).** A disk is classified by reading only: the first and last MiB, the GPT (primary, else backup) and, for a urMQTT data partition, its superblock. `Installed` (a valid GPT with a urMQTT data partition), `Blank` (no GPT, zeros at both ends), `Foreign` (anything else, with or without a GPT), `Unreadable`. Free space is every sector covered by no partition and, inside the data partition, by neither the header nor any region of the superblock's table (an unreadable superblock takes the whole partition), minus the **first and the last MiB of the disk always** (boot sectors and the backup GPT), trimmed inward to 1 MiB. The rules, in order: the boot medium, a read-only device and an unreadable disk are never written; a disk with data but no partition table is never written (its free space cannot be known); an installed disk is written only inside free space and needs no confirmation because nothing it owns can be touched, and with no free window of at least 4 MiB the test is skipped with the reason ("no unallocated space: every sector belongs to a partition or a data region": the installer's layout leaves none); a blank disk, or a foreign one with a partition table, needs the word `WIPE` and Enter typed on the keyboard or the serial port before the first write (60 s, anything else, Escape or silence skips). The window is the start of the largest free extent, at most 64 MiB, and **every request is checked against the free extents again before it is sent**. The pattern is pseudo-random, read back and compared, then the area is zeroed, so a blank disk is blank afterwards. Nothing is ever written from the end of a disk. This is why the plan's "scratch region at the end of the disk the installer leaves" is not used: the installer leaves none, and the end of the disk holds the backup GPT. On an installed disk the test therefore skips today, which the dashboard says; it runs on a disk with real unallocated space (a larger disk than the installed image, a blank disk after confirmation).
- **Input.** The serial port (COM1 and the PL011 gained a polled receive path used only here) and, on x86, the PS/2 controller (scancode set 1, polled; the i8042 is what QEMU, VNC consoles and most PCs present). USB keyboards without PS/2 emulation are not read: use the serial console. Arm has no keyboard path. The dev-only words `diag-confirm=WIPE` and `diag-confirm-timeout=S` exist so the smoke suite can exercise the write path without typing; production ignores them.
- **Presentation.** The ALDO TECH look on the framebuffer: a dark navy page, panels with a 2 px border and an amber title, aligned label columns, bar graphs (amber on a dark track; the latency bars are logarithmic), white text, green and red for state. Two columns from 100 text cells wide, one below; panels that do not fit are cut with "... n more". The log crate's framebuffer sink is switched off while the dashboard owns the screen (log lines go on on the serial port), and `FbConsole` gained `fill_rect`, `text_at` and `cell_px` (no new dependency). The footer is a progress bar and the stage; at the end "Press any key to reboot": the screen stays, nothing resets or powers off. The one exception is a dev image in smoke mode, which powers off after the report so a test harness can end the run.
- **JSON.** The same figures as one compact line, `URMQTT-DIAG-JSON {...}`, written raw (so the log level cannot hide it) to the serial port, followed by `URMQTT DIAG DONE`; the stages also log ordinary `diag:` lines. `scripts/diag-check.py` validates the keys and sane values and is what the smoke scenario runs. Schema version 1 (`urmqtt_diag`): `cpu`, `memory`, `pci[]`, `disks[]` (with `seq_read`, `rand_read.latency_ns`, `seq_write.status`), `nics[]`, `time`, `firmware`, `hypervisor`, `ram` (`latency[]`), `crypto`.
- **Limits.** One LUN per virtio-scsi controller is measured (the driver hands the controller to a single disk; the others are listed as not measured). virtio gives no disk model, so it says "not reported". Disk figures are queue depth 1 on a virtio device; they measure the virtual disk as the guest sees it. The reserved figure includes MMIO windows the firmware lists (12 GiB on q35 for the 64-bit PCI window). The RAM figures run on one core. No TRIM, no fragmentation work (the layout has fixed regions and no filesystem). Hardware and KVM were not available.

## ADR-072 — The console reader never waits for the log sinks (O1, watchdog `step sys`)

- **Status:** Accepted. Amends ADR-060 (the console ring) and explains the "20 ms stalls" left open in ADR-070.
- **Report.** On the Contabo VPS (KVM, 4 vCPU) the output handler was reported over budget in step `sys`, 36 to 375 ms against 20 ms, at boot (375 ms at 2.6 s uptime) and in dozens during load tests, with an operator subscribed or not.
- **Cause.** Not the work of `Sys::poll`. Measured per part (worst pass, x86_64 TCG, every log line made 4 ms slow with `test=slow-log:4000`): `report` 1-53 us, retained publish of the ~20 topics 0.2-2.4 ms (the first pass at boot, 0.2-0.7 ms afterwards), request draining 1-123 us, but **`console()` 27-36 ms**. `console_read` took the log's sink lock (`SINKS`) with interrupts masked, and that lock is held by every other core's log line for as long as the serial port and the framebuffer take to show it. A real line is slow on a VPS: COM1 is port I/O the hypervisor traps per byte, and the VNC console scrolls a write-combining framebuffer. Every core was therefore queued behind the others' lines (and behind the watchdog's own report, which is a log line too), at boot most of all, when all cores log the boot sequence. `Sys::poll` is the one output step that takes the lock in nearly every pass whenever any core has logged (the console cursor is behind), so the wait was charged to `sys`; the cost was the log, not the sys code. The step label is correct; it names where the core was waiting.
- **Decision.** The console ring has a lock of its own (`CONSOLE`), held only for the copy of a record or of eight records; writers take it nested inside the sink lock for the push only, readers take it alone (interrupts masked, so the tick's watchdog report cannot spin on a lock its own core holds). A reader can never queue behind a slow sink again. Nothing else changed in `Sys::poll`: per-pass work was already capped (16 lines, one retained refresh per 10 s of ~20 small topics).
- **Numbers** (x86_64 TCG, 4 vCPU, operator subscribed, 4 ms per log line): `console()` worst pass 27 685-36 272 us before, 44-522 us after (the remainder is the copy and the broker's delivery); whole `Sys::poll` pass 25-39 ms before, 0.15-2.8 ms after; `step sys` reports over budget: 4 in 25 s before, 0 after. At 0 us per line (plain QEMU) nothing was over budget either way, which is why no smoke caught it.
- **Regression test.** Dev `test=slow-log:US` makes every log line hold the sink lock US microseconds longer (`urmqtt_log::set_sink_delay_us`; production ignores it like all test words). Smoke `sys-slow-log` boots with 4 ms per line, an operator subscribed to `$SYS/#` for 25 s, and fails on any `(step sys)` report. Host: `console_readers_do_not_wait_for_the_sinks` holds the sink lock and reads the ring (it hung before).
- **The other steps** (`timers|shrink|ready|tcp|routes|control|persist|telemetry`): none was reported on the VPS and none in the slow-log run. They log rarely (handshake timeouts, rate-limited refusal lines, the 10 s memory line), but any `info!` in a handler waits for the sink lock the same way, so a burst of lines from other cores can still show up under a different step. The remedy, a per-core log buffer drained by one writer outside the handlers, is ADR-090.
- **Not done:** the DB core's and core 0's own log calls (ADR-090 did the buffer); measuring on the VPS itself (this ISO is for that).

## ADR-090 — Per-core log rings, one writer for the sinks (PERF)

- **Status:** Accepted. Supersedes the remedy ADR-072 left open ("a per-core log buffer drained by one writer outside the handlers"); amends ADR-060 and ADR-072 (the console and syslog rings keep their own locks).
- **Problem.** On a KVM VPS a log line takes milliseconds to reach the sinks (COM1 is trapped port I/O per byte; the VNC console scrolls a write-combining framebuffer) and the global sink lock was held for all of it. Every other core's `info!`/`warn!`, including the watchdog's own report from the tick, queued behind it, so any handler that logged (and any code that took the sink lock: the syslog drain on core 0) was charged the wait: `watchdog: ... over budget 36-375 ms` under steps `sys`, `output`, whatever happened to log.
- **Decision.**
  - **Once the cores run** (`urmqtt_log::start`, called in `boot.rs` before the data cores start), a log call formats into **its own core's ring** (`ring::Ring`, 64 fixed slots of one `Record`, 256 B, in `.bss`; IRQs masked around the push so the tick's report cannot re-enter) and returns. Its cost is the formatting plus two atomic stores. It takes no lock another core can hold and never waits for a sink. The producer end is a try-flag: if it is somehow entered twice the line is dropped and counted, never corrupted.
  - **One consumer** drains all rings, **oldest timestamp first** (merging the heads of the rings that have lines; a bitmask of non-empty rings keeps the scan to the cores that logged), and is the only writer of the serial port, the framebuffer, the console ring (`$SYS`, ADR-072) and the syslog records. It is the **last CPU** (the DB core when there is storage and two or more CPUs; else the last data core; on one CPU, CPU 0): `urmqtt_log::service()` is called from `Idle::pass` (every core's loop, a no-op except on the consumer, between handlers, never inside one) and from the AP idle loop. A pass writes at most 16 lines or 2 ms (at least one), then goes back to its own work; it does not sleep while it has written something. The tick (10 ms) wakes a sleeping consumer, so a line reaches the sinks at most about 10 ms plus the queue behind it later; there is no IPI per line.
  - **Rate limit** per core (100 lines/s, burst 300, as before but one bucket per ring, so one flooding core cannot starve the others and nothing contends); the suppressed count is reported with the next line from that core. **Overflow drops the newest line** and counts it per ring; the drain writes `log: N line(s) dropped on cpu C (log ring full)` before the next lines. Information and below may fill only three quarters of a ring, so warnings and errors still find room in a flood of info lines.
  - **Audit lines** (`audit()`, every console command) are exempt from the rate limit and are **never dropped**: if their ring is full they are written synchronously, under the sink lock, by the caller (rare by construction: the console command rate limit, a full ring). They are not counted as dropped, since they are not lost.
  - **The fatal, flush and raw paths are synchronous and drain first.** `emergency` (traps, panic, `power::fatal`), `flush` (power-off, reboot) and `raw` (the `URMQTT READY` marker, diagnostic output) write up to 512 queued lines to the sinks, in order, before their own text; if a drain is already running they simply write. `emergency` keeps its try-lock and direct-UART fallback.
  - **Boot is unchanged**: before `start` every line goes straight to the sinks under their lock, as before (the cores that come up later log "cpu N online" through that path). Dev `test=log-sync` keeps that path after boot (the "before" of the numbers below); `test=dp-bench` and `test=log-crash` also keep it, since their cores never reach an idle pass.
  - **The syslog records have a lock of their own** (`RECORDS_RING`, like `CONSOLE`): `drain_records`, called from core 0's network loop, used to take the sink lock and so waited for the slowest line. It now takes only the records lock, held for a copy of eight records.
  - **Record text is 254 bytes** (was 200 in the records): a longer line queued by a core is cut with `...` at a character boundary (the longest line in the boot logs, `crypto-profile`, is 247). Lines written synchronously (boot) still reach the sinks whole; the console and syslog copies are cut.
- **Cost of a call** (`test=log-cost`, implied by `test=slow-log`: every call timed with the monotonic clock, reported by the consumer every 5 s as `log: cost: N call(s) in 5 s, mean .. ns, worst .. ns`). Smoke `log-slow-flood`, x86_64 TCG, 4 vCPU, every sink line 4 ms (`slow-log:4000`), every core logging one line every 50 ms from inside a watched handler (`test=log-flood:50`): **synchronous** mean 7.8-9.0 ms per call, worst 28-36 ms, **115 `over budget` reports in 16 s** (up to 18 ms against the 10 ms dev budget); **asynchronous** mean 5.3-5.7 us, worst 21-54 us (TCG emulation; the work is a format and two stores), **0 reports**. At `flood:25` (160 lines/s from four cores against a sink that takes 4 ms a line) the synchronous path also loses lines to its global rate limit (100/s for everyone); the asynchronous one wrote all 2 159 lines, none lost, none out of order (`scripts/log-flood-check.py`).
- **Ordering.** Lines come out in timestamp order of the rings' heads at the time of the pick. A line with an older timestamp can still arrive after a newer one from another core was written (the microseconds between reading the clock and publishing the slot); the smoke tolerates 2 ms and saw none.
- **Hot-path review.** Per-connection events were already `debug` (authenticated, disconnected, memory returned). What stays at `warn` on a per-connection basis are failures a scanner can cause (`tls: connection refused`, `tls: handshake timed out`, `mqtt: no CONNECT`): they are security events the operator relies on, now cost a ring push each and are bounded by the per-core rate limit with its count; the admission, registry, retained, route and control warnings were already logged at powers of two. The 5 s `dataplane:`/`tcp:` stats lines are formatted outside handlers (in the idle pass) and are now a ring push. Nothing was removed.
- **Not done / limits.** The consumer's 4 ms lines still occupy its core: a data core that is also the consumer (storage off, `live`) loses that time to its own connections (at most 2 ms per pass; with a DB core it costs the DB core only). The ring is 64 lines per core: a burst above that (a warning loop at 300 lines at once) drops the tail, counted. Not measured on the VPS.
- **The other steps** (`timers|shrink|ready|tcp|routes|control|persist|telemetry`): none was reported on the VPS and none in the slow-log run. They log rarely (handshake timeouts, rate-limited refusal lines, the 10 s memory line), but any `info!` in a handler waits for the sink lock the same way, so a burst of lines from other cores can still show up under a different step. The remedy would be a per-core log buffer drained by one writer outside the handlers; not done.
- **Not done:** that buffer; the DB core's and core 0's own log calls; measuring on the VPS itself (this ISO is for that).


## ADR-080 — Overload sheds load before it does work; handshakes are counted (PERF)

- **Status:** Accepted. Extends ADR-032 (admission) and the SYN-cookie design of H3 (ADR-033).
- **Report.** A real KVM VPS (Contabo, AMD EPYC, 4 vCPU, live RAM mode), loaded by `urmqtt-loadgen handshake` from one Mac (one source address, RTT 35 ms, mTLS): 128 clients 618 handshakes/s, 87 errors, mean 207 ms; 256 clients 393/s, 3 565 errors; 512 clients 67/s, 1 345 errors, mean 12.8 s. Cores 1..3 about 50 % busy, core 0 about 5 %. Not a plateau but a collapse.
- **What the numbers say before any code does.** (1) The plateau is not CPU. With the production limits and one source address the server admits at most `max_handshakes_in_flight_per_ip = 32` handshakes *per worker core*, 96 on three workers. A handshake is in flight from the final ACK to the end of TLS, two round trips plus the client's own work, about 150 ms on this path, so 96 / 0.15 s is about 640 handshakes/s: the 618/s, with the cores half idle. Past it every extra client is refused (87, 3 565, 1 345 errors). (2) Everything after that is what a refusal costs and what the refused client does next. (3) Mean latency of 12.8 s cannot come from CPU queueing (the in-flight limits bound that to about 256 x 2.4 ms per core); it is TCP retransmission, SYN retries at 1, 3, 7 s or a 10 s read timeout, so frames or SYNs are being lost somewhere between the client and the stack.
- **Mechanisms found in the code** (host tests and QEMU/HVF confirm the first two; none of this could be reproduced at 35 ms RTT without the VPS):
  1. **A refused flow was admitted by its own next segment.** SYN cookies keep no state, and a client sends its ClientHello right behind its ACK. After `accept()` refused the ACK (RST), the ClientHello still carried a valid cookie, went through `listen()` again, and was admitted whenever a slot had freed in between. The server then spent ECDHE and a signature (about 0.5 ms) and a handshake slot for a round trip on a socket the client had already closed. In an overload every refusal produced such a second chance, so a growing share of the free slots went to dead connections: goodput falls as offered load rises. In QEMU (limits shrunk to 4 per address) 18 of 26 refused flows on a core got exactly that second segment in one 5 s window.
  2. **Refusal told the client to retry at once.** A RST makes the client's `connect()`/handshake fail at once, and a load generator (50 ms sleep) or a device without backoff comes straight back: 400 refused clients make 3 000 or more attempts per second, each a SYN, a SYN-ACK, an ACK, an `accept()`, an allocation, a RST. Linux drops the SYN or the ACK when its accept queue is full for exactly this reason (`tcp_abort_on_overflow = 0`): the client's TCP then backs off by itself (1, 2, 4 s).
  3. **Admission was O(queue) and took a global lock per attempt.** `in_flight()` pruned the handshake queue with `retain` and `in_flight_from()` scanned it, up to 256 entries with a slab lookup each, twice per attempt; `heap_has_room()` took the allocator's global spinlock every time. Both are paid by exactly the connections that are refused.
  4. **A dead peer held a slot for 10 s.** A handshake whose client vanished (a reset that was lost, a client that gave up) kept one of the 32 (or 256) slots until the 10 s timeout, in an overload exactly when slots are the scarce thing.
  5. **Not seen, not countable:** frames dropped on a full ring (`DROPPED_FRAMES` was one number), the longest stall of a core, handshakes started/failed/timed out, how long a handshake took. The VPS log could not say which of the above happened.
- **Client side, not fixed in the server (a hypothesis to check first).** `urmqtt-loadgen` closed first (DISCONNECT, then `shutdown(Write)`), so *the client* kept the TIME_WAIT: 30 s on macOS (`net.inet.tcp.msl` 15 s) against 16 384 ephemeral ports (`net.inet.ip.portrange.first/last` 49152-65535). That caps one source at about 550 connections per second *whatever the server does*, and the three runs (128, 256, 512 clients) followed one another, each starting with the previous one's TIME_WAITs. 618/s, then 393/s, then 67/s with 12 s connects fits that picture at least as well as it fits the server. Check on the Mac during a run: `netstat -an | grep -c TIME_WAIT` (a number near 16 000 settles it) and the error text (`Can't assign requested address (os error 49)`). The load generator now lets the server close first (`--close server`, the default; the server keeps no TIME_WAIT, ADR-033), counts `os error 49/99` as its own error kind and says so.
- **Decision.**
  1. **A SYN gate** (`App::syn_ok`, `Admission::syn_check`): a SYN is answered only if a connection from that address would be admitted now (memory, DB backlog, per-core and per-address limits, a token left). Otherwise it is dropped without a SYN-ACK: no state, no packet, and the client's TCP retries after its own backoff (1 s, 2 s, ...). The check takes no token and no slot. A SYN that passes can still be refused at its ACK (a race); that path is unchanged: RST.
  2. **A memory of refused flows** (`tcp::refused`): 512 direct-mapped 32-bit tags with a 1 s lifetime and a per-stack seed. A segment of a refused flow gets one more RST (in case the first was lost), then nothing, and never reaches the application again. `Stats::refused_repeat` counts them; the second-chance admission of mechanism 1 cannot happen.
  3. **Admission in O(1)** (`urmqtt_net::admission::Admission`): the in-flight count and the per-address counts are kept at the transitions (admitted; handshake done, closed, timed out), the heap lookup is cached for 1 ms, and the queue that remains (it only serves the timeout) is pruned when it outgrows twice the limit. The pure logic is host-tested (9 tests).
  4. **A shorter timeout under pressure:** while three quarters of the in-flight limit are taken, a handshake older than 3 s (instead of 10 s) is dropped. Timeouts are logged at powers of two.
  5. **Counters and reports** (below).
- **What stays.** The limits and their defaults, the RST at the ACK, SYN cookies, the 10 s timeout when there is room, the rate bucket (2000/s per core).
- **Counters** (per core, published every 100 ms into `dataplane::HS`, summed for `$SYS` and statsd): handshakes started, done, failed, timed out; refused at the ACK and SYNs dropped, each by reason (rate, in_flight, per_ip, memory, storage); in flight now and the most in the last 5 s; sum and maximum of accept-to-done milliseconds and the number slower than 250 ms and 1 s; connections accepted per core since boot (`$SYS/broker/cpu/accepted/<core>`); frames dropped by site (steer ring, worker-to-dispatcher ring, NIC queue, NIC queue for core 0's own frames). The 5 s log has three lines per core: `handshakes:` (the above), `tcp:` (cookies, SYNs dropped, refused by the application, repeat segments, retransmissions split into fast and timeouts) and `dataplane:` (busy, *work by category*: rx, of it TLS, poll, tcp, mesh, nic; microseconds of work and of TLS per accepted connection; longest stall of the core). Names in docs/OPERATE.md.
- **Where a handshake's time goes** (`dataplane:` line, aarch64 under HVF on an Apple M-series, 2 worker cores, 128 clients, about 450 handshakes/s per worker; native speed, so the proportions carry): about 560 us of core time per accepted connection, of which TLS (`sess.input`) about 400 us; the other 150 us are TCP/IP/CONNECT/session setup and relay (about 50-90 us), the 100 ms timer step and the output pass (`poll`, `tcp`, `mesh`: 2-3 %, 1 %, 1 % of the window, mostly per-pass fixed cost of the polling loop, not per connection). Per handshake the DB core does one `DeviceSeen` upsert, batched (8 816 ops in 1 063 commits in 10 s, 3.7 ms per commit on the QEMU data disk: asynchronous, and not on the data path). Nothing outside the crypto is large enough to move the handshake rate by itself; the safe fixes are mechanisms 3 and 4 above (a lock and up to 512 slab lookups per refused attempt) and the second admission.
- **Not done / not known:** whether frames or SYNs are lost on the VPS (the new `frames dropped` line and the SYN counters will say); a CPU-time based admission (the in-flight cap bounds the queue to 256 x the handshake time per core, about 0.6 s at 2.4 ms); a larger virtio RX queue (the device decides, usually 256); the DB core reports 100 % busy because it polls without sleeping.
- **Tests.** Host: `tcp` (`syns_are_dropped_without_state_when_the_application_is_full`, `a_refused_flow_is_not_admitted_by_its_next_segment`, `refused::tests` x5), `net::admission` x9, `$SYS` topic list and JSON, `rss` spread. Smoke: the `storm` and `attack-app` checks accept either log form (`connection(s) refused` or `SYN(s) dropped without an answer`).

## ADR-081 — The dispatcher core can serve connections too, off by default (PERF)

- **Status:** Accepted as an option. Amends ADR-032 ("core 0 runs the NIC and the dispatcher, cores 1..n are the MQTT workers").
- **Question.** Core 0 owns the only virtio-net queue pair and steers frames to the workers; it accepts no connection, so with 4 vCPUs three do the TLS work (one is the DB core when storage is active). On the VPS it ran at about 5 %. Could it take a share?
- **Measured** (QEMU/HVF, 128 clients, about 900 handshakes/s through slirp, which is the limit here): core 0 busy 42-58 % of which `nic` 17-37 % of the window for 11-13 k frames/s (the notify to the emulated device is a trap: tens of microseconds per kick under HVF, a few under KVM with ioeventfd), `work` 25-43 %. With `dispatcher_serves = true` it took 1/3 of the connections, about 930-1 450 us of work per accepted connection including its NIC work, the longest stall of any core 1-6 ms (host preemption in this run, the same as on the workers) and accept-to-done stayed at 0-2 ms mean, 10-33 ms maximum. The rate stayed at slirp's 840-910/s either way. **It cannot show a gain here**: the workers are not the limit in QEMU (28-38 % busy).
- **Why it is not the default.** Every frame of every flow passes core 0 twice (receive, steer; transmit). Anything core 0 does for a connection delays all of them: one TLS step is 0.5-2.4 ms (the VPS: 2.4 ms of core time per handshake if all three workers were busy at 618/s), and a step cannot be cut. At 12 k frames/s the NIC's 256 RX buffers last 20 ms, so a stall of a few ms is survivable but it lands on *all* flows, and under steal time it can reach tens of ms. The workers' own stalls only delay their own flows. The gain, 4 workers instead of 3 (+33 % at the CPU limit, +100 % with two vCPUs), is real only when the workers are the limit, and on the VPS they were at 50 %.
- **Decision.** `[cpu] dispatcher_serves = false` (default; also in `deploy/prod`). `true`: core 0 is a worker too (`dataplane::workers` is `0..n`, so sessions, retained replicas and fan-out follow), its TCP stack listens on the MQTT ports, and the frames queued for its own connections are handled in slices of 200 us before it looks at the NIC again (`LOCAL_SLICE_NS`); the NIC burst, the mesh and the output pass run every pass as before. `deploy/bench/config.toml` carries the switch so that one ISO build family can be compared on the VPS: `scripts/mkbench.sh --serve-dispatcher`.
- **How to decide on the VPS.** Run the same load with both. Read `dataplane: core 0` (`nic`, longest stall), the workers' busy and `work`, `handshakes:` (accept to done, over 250 ms), `frames dropped` and the loadgen percentiles. Adopt it only if the rate rises at the CPU limit and neither the stall of core 0 nor `frames dropped` grows.
- **Not done:** a weighted share for core 0 (for example half a worker), and dedicating a second NIC queue (needs virtio-net multiqueue, F_MQ).

## ADR-082 — The bench profile: relaxed limits for single-source load tests, never the default (PERF)

- **Status:** Accepted.
- **Why.** The production limits (32 handshakes in flight per address and core, 256 per core, 2000/s per core) are the defence against one slow or abusive source. A load generator is one source, so against them it measures the limit. ADR-070's 344/s and the 618/s of the report are both in that regime.
- **Decision.** Two ways, both opt-in and loud. (1) `deploy/bench/config.toml`: the production template with `handshakes_per_core_per_sec = 100000`, `max_handshakes_in_flight_per_core = 4096`, `max_handshakes_in_flight_per_ip = 4096`, `storage.mode = "auto"` and the `dispatcher_serves` switch, header "BENCHMARK, never deploy". `scripts/mkbench.sh` (`make bench-iso`) copies the certificates from `deploy/prod`, writes the generated `deploy/bench-local/` (ignored by the repository: keys, address) and builds the universal ISO with `ENV=bench-local`; `--static ADDR/LEN GATEWAY` and `--serve-dispatcher`. (2) For QEMU, the dev command-line word `limits=bench` (`make bench BENCH_ARGS=--relaxed`, `scripts/bench.sh --relaxed`): the same numbers, honoured only by a dev image (a production image counts it as ignored, like every test word, H0-W11) and announced at boot (`limits: BENCH LIMITS on`).
- **Not changed:** the defaults of `deploy/dev` and `deploy/prod`, the schema bounds (there are none above zero), the 10 s timeout.
- **Memory:** 4096 handshakes in flight per core cost about 4096 x (TLS state, a few tens of KiB) of the 1 GiB production heap; `memory.min_free_mb` still refuses new connections first.

## ADR-100 — SNTP wall clock (T1)

- **Status:** Accepted. Amends ADR-009 (no NTP) and ADR-050 (the rest of H7: "SNTP, jump handling"); NTS stays out of scope. Uses the `$SYS` publisher of ADR-060.
- **Why.** The clock was the firmware RTC read once at boot plus uptime, floored at the image's build time. It was never corrected (the uptime counter drifts, a VM's RTC can be wrong) and a wrong RTC meant "unknown", so every certificate check and control message failed until the next reboot with a good RTC.
- **Decision.**
  - `urmqtt-sntp` (new, `no_std`, no I/O): request/response (RFC 4330, version 4 client packet), checks, per-server offset, consensus, bounds, and the query schedule as a state machine. The kernel (`time_sync.rs`) moves the datagrams on core 0 (the NIC owner) through `Iface::send_udp` and a new `Rx::Udp` (UDP for us that is not DHCP, checksum verified); nothing else listens on UDP. Source port 40123, destination port from the config (default 123).
  - **Servers are IPv4 literals.** There is no DNS resolver in the broker (DHCP hands over a resolver address that nothing uses), so `time.servers` takes `"a.b.c.d"` or `"a.b.c.d:port"`; names are rejected at build time with that explanation. At most four; no loopback, multicast, broadcast or 0.0.0.0; no duplicates.
  - **Config** `[time]` (optional section, so existing `deploy/*/config.toml` keep working): `servers = []` (none: no SNTP; the default everywhere, including `deploy/dev`), `interval_s = 3600` (60..=86400), `max_step_s = 600` (1..=86400). Schema tests cover defaults, accepted forms and each rejection. `deploy/prod` is untouched; an operator adds the section.
  - **Per response** the client checks: UDP source address and port are the ones asked and a request is outstanding for it; length >= 48; mode 4, version 3 or 4; leap indicator not 3; stratum 1..=15 (stratum 0 is a kiss-of-death: the server is not asked again for one interval; 16 and up is unsynchronised); the **origin timestamp equals our transmit timestamp**, whose low 32 bits are random (`rng::fill_global`; fail closed without randomness); root dispersion at most 5 s; receive and transmit timestamps nonzero, after 1970, transmit not before receive; round trip between 0 and 2 s. A wrong origin leaves the request outstanding, so a forgery does not cancel the real answer; an answer is used once.
  - **Consensus.** All servers are asked in one round (4 s limit). At least `min(2, servers)` usable answers are needed and the **median** offset counts if a strict majority of the answers lie within 1 s of it. One liar out of three cannot move the clock (the median is an honest value); two servers that disagree give nothing; with one configured server that server is trusted (documented).
  - **Bounds** (`Discipline`): the result may never be below the image's build time (`SOURCE_DATE_EPOCH`); the first correction after boot may move the clock forward by any amount (a dead RTC battery) or set an unknown clock, but a backward first step is limited to `max_step`; every later correction is limited to `max_step` and the sum of the later ones as well (the "drift budget"), so a man in the middle who controls all answers can move the clock by `max_step` in total after boot, not by `max_step` per interval. Corrections below 128 ms are applied as they are (a slew in effect: the clock is `base + uptime`, adjusting `base` is the whole mechanism; it never runs backwards inside a reading); larger ones are steps and are logged. Refused offsets are logged and shown in `time/offset_ms`, and the next round backs off (15 s doubling to the interval); rounds are never closer than 10 s whatever the configuration says.
  - **The clock.** `boot.rs` keeps `CLOCK_BASE_MS` and the source (`unknown`, `rtc`, `sntp`); `now_unix`/`now_unix_ms` are `base + uptime` and `None` while unknown, so TLS certificate validity, control-message windows, the certificate warnings, SQLite timestamps and the database all use the corrected time without further changes. Only core 0 writes; the source is stored last with release ordering.
  - **Published and logged.** `$SYS/broker/time/source` (`rtc|sntp|unknown`) and `$SYS/broker/time/offset_ms`, in the JSON query (`"time":{...}`) and `status`; `time:` lines at boot and at each round.
  - **Dev only.** The kernel command-line word `sntp=a.b.c.d[:port]` adds a server (ignored by production images like every test word) and `scripts/sntp-responder.py` plays the server for the smoke scenarios.
- **Not done.** NTS (RFC 8915) and SNTP authentication (symmetric keys); frequency discipline (the base is stepped, not slewed by rate); using the DHCP option 42 (NTP servers) because an unauthenticated DHCP answer should not choose the time source; DNS names for servers; a leap-second smear; using SNTP to correct the persisted control sequence (the sequence number is independent of the clock).
- **Testing.** Host: 17 tests in `urmqtt-sntp` (wrong origin, stratum 0/16/255, LI 3, wrong mode/version, truncated, zero and reversed timestamps, root dispersion, negative and 10 s round trips, extreme numbers without overflow, one liar of three on either side, no majority, 2 servers disagreeing, forged datagrams from a third address / wrong port / guessed origin / another server's origin, a kiss-of-death, retry and rate limit, unsent datagrams), the discipline rules (below the build time, unknown clock set once, backward at boot, per-step and total bounds, saturation), the era rollover of timestamps; schema tests; `Iface` UDP delivery; `$SYS` topic list. Smoke `time-sntp-{ok,past,kod,wrongorigin}` (`SMOKE_ONLY=time`, host responder over QEMU user net, RTC set to 2020): the clock is set once and a device handshake then succeeds; a 1970 answer, a kiss-of-death and a wrong origin leave the clock unknown and the handshake refused.

## ADR-110 — Fixed-base P-256 table for signing and key generation (PERF)

- **Status:** Accepted. Amends ADR-070 ("fixed-base tables for signing: not done").
- **Context.** After ADR-070 the handshake is about 90 % public-key math. `p256` 0.14 has a `precomputed-tables` feature (a radix-16 comb of the generator, 33 x 8 points, about 25 KiB) but it needs `std` or `critical-section` for its lazy initialisation, so the kernel (and the host build, which used `default-features = false`) ran every `k*G` as a variable-base multiplication: ECDSA sign 130-140 us and P-256 key generation 127-173 us on the host.
- **Decision.** Enable `p256/precomputed-tables` and vendor `primeorder` 0.14.0 (`vendor/primeorder-0.14.0`, wired with `[patch.crates-io]` in the root and `fuzz/` manifests, same policy as `cpufeatures`). The only change is in `src/tables/basepoint.rs`: the `std::sync::LazyLock` / `once_cell` + `critical-section` cell is replaced by a 60-line atomics-only once-cell (`EMPTY -> BUILDING -> READY`, Acquire/Release, concurrent first users spin for the build, about 1 ms), and the `compile_error!` that demanded `std` or `critical-section` is removed. No arithmetic is touched.
- **Security.** Secret scalars still go through `BasepointTable::mul`, which selects table entries with a constant-time lookup (`LookupTable::select`) and complete addition formulas; only the public-input paths (`mul_vartime`, verification) use the variable-time select. RFC 6979 deterministic nonces are unchanged. The table is built from the public generator, so it holds nothing secret.
- **Result** (host, Apple M4 Pro, `profile` example, quiet machine): ECDSA sign 130 -> 33 us, P-256 key generation 127 -> 29 us. X25519 stays preferred; P-256 `dh` (variable base, secret scalar, constant time) is unchanged at about 127 us.
- **Tests.** Boot KAT (`kat::run`, also every `cargo test`): RFC 6979 A.2.5 (P-256/SHA-256, "sample") public key, exact signature, and verification; host differential test of the table `k*G` (constant-time and vartime) against `GENERATOR * k` for 200 random scalars.
- **Cost.** 25 KiB of `.bss` and about 1 ms on the first use of any core (the boot KAT triggers it, before the data plane). Not done: a table build at boot that is not triggered by the KAT; wider windows (4x the memory for about 15 % fewer additions).

## ADR-111 — Trust-anchor tables for certificate verification (PERF)

- **Status:** Accepted. Extends ADR-070 (verification memo).
- **Context.** The verification memo (512 entries) skips the CA signature check of a *reconnecting* device, but a fleet larger than the memo, or a first connection, still pays a full ECDSA verification (140 us on the host, 295-309 us on the VPS) for the same CA key every time. The verifier's `u1*G + u2*Q` is a joint variable-base multiplication.
- **Decision.** `TlsServer::new` registers every trust anchor's P-256 key (`provider::register_issuer`, at most 8 keys, the anchors of the operational and bootstrap CA lists). Each gets its own `primeorder::BasepointTable` (added to the vendored `primeorder` as `BasepointTable::from_point`, an eager build, 33 x 8 points, 25 KiB, about 1 ms). `verify_signature` looks the issuer up by its exact SEC1 point and, if registered, verifies with `u1*G` (the generator table) plus `u2*Q` (the issuer table), both variable-time, which is fine because key, message and signature are public. Unregistered keys (client leaf keys in CertificateVerify, intermediates, a full table) take the stock `VerifyingKey::verify` path. Registration happens only from configuration, never from peer input, so a peer cannot make the server build tables or fill the slots. The memo, the CertificateVerify bypass and the "failures are never stored" rule are unchanged.
- **Verification** is SEC 1 4.1.4 written out (`Signature::from_der` rejects zero r/s and bad DER; z = SHA-256(message) reduced mod n; `s^-1` variable-time; accept iff x(R) mod n == r; the point at infinity gives x = 0 and r != 0, so it fails).
- **Result** (host): CA-signature verification 140 -> 52 us. Handshake estimate (`profile`) 465 -> 281-291 us (-39 %), counting X25519 key share and secret, one sign (140 -> 33 us), the client CertificateVerify verify (unchanged, 140 us) and the CA verify. In-guest `dp-bench` smoke on aarch64 HVF (client and server in one guest; the memo hits there, so this is mostly ADR-110 on both ends): 1 core 1268 -> 1812 handshakes/s, 2 cores 2520 -> 3609, 4 cores 5006 -> 7043 (+43 %, 3.9x scaling kept). The `crypto-profile` boot line gained `ecdsa-verify-ca=`, and the `diag` handshake estimate and the watchdog calibration use it.
- **Tests.** Differential test against the stock verifier on 40 random keys x 5 messages x 5 cases (valid, extended message, bit-flipped signature, garbage DER, other key's signature): 1000 verdicts, all equal; RFC 6979 vector through the issuer table (boot KAT); registration idempotence, rejection of a non-key, bound.
- **Dropped after measuring.** (1) Splitting verification into table `u1*G` + wNAF `u2*Q` for *unregistered* keys: 148 us against the stock 147 us, no gain (the shared-doubling Shamir loop in `lincomb_vartime` is already as cheap). (2) A per-device table for leaf keys (CertificateVerify): a table costs about ten verifications to build and 25 KiB, so it only pays for devices that reconnect many times, which session tickets and the memo already serve. (3) X25519 is already offered first and used by mosquitto/OpenSSL/mbedTLS/ESP32 clients; a client that sends only a secp256r1 share still pays 127 us of constant-time `dh`, which cannot use a table because the point is the peer's and the scalar is secret. (4) A hand-written BMI2/ADX 4x64 field multiplier: the field code is already a specialised Montgomery reduction (p256 `field64.rs`); a replacement is a large unsafe-free rewrite of the part everything depends on for an uncertain 1.2-1.4x, not a safe win here.
- **Not measured:** x86_64 numbers. QEMU TCG on this machine says nothing about EPYC; the expected effect on the VPS is the same shape (sign about 285-673 us -> about a quarter, CA verify about 2.5x faster) and should be read off the boot `crypto-profile:` line there.

## ADR-130 — P-256 on the OpenSSL/Intel `nistz256` assembly on x86_64 (PERF)

- **Status:** Accepted; extended to aarch64 by ADR-255. Supersedes item (4) of "Dropped after measuring" in ADR-111 (a BMI2/ADX field multiplier, then estimated at an uncertain 1.2-1.4x; measured here at 3-5x for the operations that matter) and extends ADR-110/111 on x86_64.
- **Context.** Measured natively on the build server (AMD EPYC 9354P, Zen 4, a loaded shared host, one pinned core, minimum of 11 runs): RustCrypto's constant-time P-256 took sign 80 us, verify 290 us, ECDH 263 us and CA verify (ADR-111 tables) 118 us, against OpenSSL 3.5.5 on the same core with 23.4 / 72.5 / 54-58 / 72.5 us. OpenSSL's advantage is hand-written Montgomery 4x64 assembly with MULX/ADCX/ADOX (Gueron-Krasnov `nistz256`) and a 150 KiB generator comb; the portable crates reduce with generic 64-bit code.
- **Decision.** New leaf crate `urmqtt-nistz256` (`crates/nistz256`, `no_std`, x86_64 on Linux or bare metal, not under Miri; empty elsewhere). It embeds `vendor/nistz256/p256-x86_64-asm.S` with `global_asm!` (Apache-2.0; provenance, hashes and the mechanical changes are in `vendor/README.md`) and has the logic around it in Rust, after ring's `p256-nistz.c`: signed Booth windows (5 bits for a variable base, 7 bits over the 37x64 generator comb), field inversion by a fixed addition chain, order-field inversion by a fixed 4-bit window over the public exponent N-2, ECDSA sign (SEC 1 with a caller-supplied RFC 6979 nonce), verify (without the final inversion: `X == r Z^2`, also for `r + N < P`), ECDH, public key, and `KeyTable`, a 148 KiB comb of one fixed public key. Each entry point picks the variant once: MULX/ADX if `cpufeatures` says `bmi2` and `adx` (on bare metal the sealed kernel dispatch: new feature `adx`, switchable in `[cpu] disable`, detected from CPUID leaf 7), else the plain-`mul` variant, which runs on any x86-64.
- **Wired in** through `crates/tls/src/provider/fastec.rs`: `ecdsa_sign` (RFC 6979 `KGenerator` from the `rfc6979` crate, so nonce and signature bytes are the stock ones), `ecdsa_verify` (keys without a table: the client's CertificateVerify), `p256_public`, `p256_dh`, and `IssuerTable` (registered trust anchors: a `KeyTable` on x86_64, primeorder's table elsewhere). On every other target, and for inputs the fast path does not take (compressed keys), the RustCrypto code runs unchanged. The probe, the profile and the diagnostic screen measure these production paths. The boot log gains `crypto: ecc=nistz256-adx|nistz256-mul|portable`.
- **Constant time.** Secret scalars (nonce, ECDH key, key generation) use constant-time table selection (`select_w5`/`select_w7` read every entry), branch-free conditional negation and the assembly's complete addition; the Rust code has no scalar-dependent branch or index. The one data-dependent branch in the assembly is `point_add`'s doubling case (equal inputs), unreachable for a scalar below the group order (the OpenSSL/ring argument). The order-field inversion exponent is public. Secret locals are zeroized. Verification is variable time on public data. Not measured with the dudect harness (`make ct` covers records and tickets only).
- **Result** (build server, `profile` example, min / median of 11, microseconds; OpenSSL 3.5.5 `speed` on the same core in the last column):

  | | before (9a5b19c) | after | OpenSSL |
  |---|---|---|---|
  | ECDSA sign | 80.4 / 89.7 | 25.3 / 28.3 | 23.4 |
  | ECDSA verify (unknown key) | 289.9 / 318.8 | 60.5 / 72.5 | 72.5 |
  | CA verify (registered issuer) | 117.6 / 143.5 | 19.5 / 23.4 | 72.5 (no tables) |
  | ECDH P-256 | 262.5 / 293.1 | 53.0 / 61.2 | 54-58 |
  | key generation | 68.3 / 78.7 | 15.9 / 16.5 | |

  Sign is at parity (OpenSSL 8 % ahead on the minimum): 12.5 of its 25 us are the two Fermat inversions (P-2: 5.5 us, N-2: 7.3 us), the comb is 9.2 us. Verify is 1.2x ahead with the same recipe because it skips the inversion; CA verify is 3.7x ahead because the issuer's own comb (20 us) replaces the 256 doublings (unknown-key verify: 46 us of 60 are the windowed multiplication, 7.3 us the inversion).
- **Tests.** `cargo test -p urmqtt-nistz256` (x86_64 only; both variants where the CPU has ADX): field and order-field multiplication, squaring and repeated squaring against a schoolbook double-and-add reference on edge values (0, 1, 2, p-1, p-2, half, single and multiple all-ones limbs, ...) and 300 random values; inversions; the whole generator table against RustCrypto `k*G` (2368 points); public keys for 310 scalars including 1, 2, 3, N-1, N-2; ECDH for 150 random pairs plus off-curve, out-of-range and zero inputs; **signatures bit-for-bit equal to RustCrypto's `sign_prehashed`** for 300 random (d, k, z) and the edges z = 0, N, N-1, 2^256-1; verification verdicts equal to the stock verifier for valid, bit-flipped, swapped and foreign-key inputs; point addition with equal, opposite and infinity operands; `KeyTable` entries against the portable arithmetic and its verdicts against the plain path. In `urmqtt-tls`: deterministic signatures equal to `SigningKey::try_sign` (200 random keys and messages), verification and key-exchange differential tests, both `IssuerTable` kinds against the stock verifier, and the boot KATs through the production paths: RFC 6979 A.2.5 (public key, signature, verification), RFC 5903 §8.1 ECDH, RFC 7748 (all in `kat::run`, so at every boot).
- **Boot check.** The x86_64 kernel builds and the `x86-disk-q35` smoke scenario passes under QEMU TCG (which implements MULX/ADX), KATs and profile line included. aarch64 is untouched by the P-256 change (cfg-gated).
- **Architecture rule.** `scripts/check-arch-leaks.sh` (ADR-040) now allows `asm!`/`global_asm!` also in `crates/nistz256` and `crates/x25519`: pure computation, no system register, privileged instruction or port, cfg-gated by `target_arch`.
- **Cost.** 148 KiB of heap per registered trust anchor (at most 8) and 1.3-1.6 ms to build each at configuration time (never from peer input); 150 KiB of read-only data in the image. The AVX2 selection functions were left out of the vendored assembly (the kernel keeps no AVX state, ADR-042).
- **Not done.** A wNAF for `u2*Q` of unknown keys (estimated 3-5 us of 60); Bernstein-Yang constant-time inversion (estimated -9 us on sign, -4 us on verify); overlapping the two inversions of a signature with the comb; AVX2 selection for host builds.

## ADR-131 — X25519 on four 64-bit limbs with MULX/ADX, and a table for key shares (PERF)

- **Status:** Accepted.
- **Context.** dalek's 51-bit-limb ladder took 64-80 us per X25519 on the build server (OpenSSL: 38.7 us). A handshake does two X25519 operations: the key share (base point) and the shared secret.
- **Decision.** New leaf crate `urmqtt-x25519` (`crates/x25519`): GF(2^255-19) in four loosely reduced limbs (any value below 2^256; 2^256 = 38), the RFC 7748 ladder with a branch-free swap, canonical encoding at the end. Multiplication and squaring have a portable `u128` form and, on x86_64, an assembly form written for this project (no third-party code): MULX with two carry chains (ADCX/ADOX) for the 4x4 product and the `lo + 38 hi` fold, the squaring with six cross products doubled. Chosen once by `cpufeatures` (`bmi2` + `adx`, the same sealed `adx` switch as ADR-130). On aarch64 the TLS provider keeps dalek's ladder: measured on an M4 core, 18.8 us against 29.3 us for the 4x64 code. The key share (`mul_base_clamped`) uses dalek's precomputed basepoint table (the `precomputed-tables` feature of `curve25519-dalek`, 30 KiB of read-only data), which the old `EphemeralSecret` path did not enable. The ephemeral secret is now 32 bytes from the kernel CSPRNG held in a `Zeroizing` buffer; the all-zero shared secret is still refused (RFC 7748 §6.1).
- **Result** (build server, min / median): key share 56.9 / 79.3 -> 20.0 / 24.2 us (aarch64 guest: 20.7 -> 8.7 us); shared secret 64.3 / 76.2 -> 34.2 / 40.6 us (OpenSSL 38.7 us: 1.13x ahead on the minimum; the plain-`mul` fallback takes 46-54 us).
- **Tests.** RFC 7748 §5.2 vectors, §6.1 Diffie-Hellman, the iterated 1-round and 1000-round vectors; both multiplications against each other on all pairs of 17 edge values (0, 1, 2, 38, p, p-1, 2^256-1, single all-ones limbs, ...) and 20000 random pairs biased towards all-ones and zero limbs (carry chains), squaring likewise; the whole X25519 against `x25519-dalek` on 12 scalars x 13 special u values (zero, one, values around p, 2^255-1, the top bit set, the small-order points) and 400 random pairs per backend; canonical encoding at p, 2p+37 and the folds. KATs in `kat::run`.
- **Not done.** A fused ladder step in assembly (the additions and subtractions are Rust, roughly a fifth of the time); an AVX2 ladder (no AVX state in the kernel).

## ADR-132 — The rest of the handshake: serial numbers, honest probes (PERF)

- **Status:** Accepted.
- **Context.** With `perf` on the build server (frame pointers, 2000 handshakes, only samples under the server's `input`/`accept`) the non-cryptographic share of a handshake was about 12 %, and most of it was decoding the client certificate up to four times: the revocation check, the "has a serial" check, the connection tag and the identity each called `Certificate::from_der`, which allocates names and extensions. The profile example and the boot profile also still measured the old primitives.
- **Decision.** `identity::serial` reads the serial straight out of the DER (certificate SEQUENCE, TBSCertificate SEQUENCE, optional `[0]` version, INTEGER: positive, minimal, at most 20 octets, definite lengths) without decoding the rest; the full decoder remains for the identity only. What the light reader does not accept still counts as revoked at the call sites; a certificate the full decoder would reject for some other reason is still refused by chain validation and by the identity extraction. The probe, the profile and the boot profile call the production routines (`fastec`, `kx`), the diagnostic's handshake estimate counts the key share as a fixed-base operation, and `kat::run` covers the key exchanges. A new ignored test, `server_side_handshake_cost` (`ROUNDS=300 cargo test --release -p urmqtt-tls --test handshake -- --ignored --nocapture server_side`), times full mTLS handshakes against a real rustls client and reports the time inside `accept` and `input` only.
- **Tests.** The light reader against the full decoder on every dev certificate and on 8 x 400 single-bit corruptions (whenever both answer, they agree), truncations, negative, padded, empty and over-long serials.
- **Result** (build server, in process, full handshakes with the CA signature memoised, server side only): minimum 440-495 us -> 150-162 us, median 497-566 us -> 194-206 us (five runs each). The sum of the primitives (key share, shared secret, signature, CertificateVerify verification, about 20 us of hashing and records) is 159 us at the minimum, so what remains outside the primitives is within the noise of the measurement. With the memo missing, add the CA verification: 20 us now (118 us before).
- **Dropped after measuring or by judgement.** A per-device table for the client's CertificateVerify key (ADR-111's argument stands: a table costs more than ten verifications). The 4x64 X25519 on aarch64 (slower than dalek there). OpenSSL's AVX2 point selection (the kernel cannot use it, so host figures would not be the production ones).
## ADR-120 — Kani: bounded proofs, scratch `rust-version`, a time cap (H5)

- **Status:** Accepted.
- **Context.** Kani 0.68 bundles a rustc one release behind the pinned nightly, and cargo refuses the workspace `rust-version = "1.101"` with it. CBMC also does not terminate on the timer wheel (slab + `Vec`): harnesses with 200, 72, 16 and 6 ticks ran 7 to 28 minutes at up to 17 GB and were killed.
- **Decision.** Harnesses live in `crates/*/src/proofs.rs` behind `#[cfg(kani)]` (`cfg(kani)` is declared in the workspace `check-cfg`). `scripts/kani.sh` lowers `rust-version` in `Cargo.toml` for the run and restores the file on exit; nothing else changes. Every harness has a 3 minute cap (`--harness-timeout`); a harness that hits it is reported as NOT PROVEN with the bound tried. Timer wheel: only the placement and skip arithmetic is proven; the behaviour stays with unit tests, the model test and Miri.
- **Result at the time of writing.** Proven: TLS `record_len`, TCP `parse`, the two timer-wheel arithmetic harnesses. Not proven (timed out): both MQTT decoder harnesses, both config harnesses, and the timer-wheel behaviour. The `kani` CI job is `continue-on-error` until those are reformulated.
- **Not claimed.** Unbounded correctness of any parser; the TLS record layer (AEAD) and the broker; anything beyond the bounds in `docs/VERIFICATION.md`.

## ADR-121 — Sanitizers on the host, C side included (H5)

- **Status:** Accepted.
- **Decision.** `scripts/sanitize.sh`: `-Zsanitizer=address` for Rust with an explicit `--target` (build scripts uninstrumented, own target dir `target/sanitize`), and `CFLAGS=-fsanitize=address,undefined -fsanitize-trap=undefined` for the SQLite amalgamation and the C shims compiled by `cc`. Trapping UBSan avoids linking a UBSan runtime (Apple clang's does not match rustc's). On macOS a no-op definition of Apple clang's `__asan_version_mismatch_check_*` is linked, because rustc's LLVM runtime does not define it. No LeakSanitizer on arm64 macOS; it stays on for Linux CI. Rust UB is Miri's job, there is no rustc UBSan.

## ADR-122 — The ACL fuzzer is a model-based test with an independent oracle (H5)

- **Status:** Accepted.
- **Decision.** `crates/broker/tests/acl_model.rs`, no new dependency (own xorshift generator, replayable by seed). Payload tags carry the oracle's verdict for each published message, so any output channel of the broker can be checked without tracking routing. The oracle restates the rules as prefix checks and does not call `acl.rs`. It runs 3 s inside `cargo test`, `make acl-fuzz` runs it for `ACL_FUZZ_SECS` (default 600), and the scheduled fuzz workflow runs it too. Scope and non-goals are in `docs/VERIFICATION.md`.

## ADR-123 — Miri runs a curated fast subset (H5)

- **Status:** Accepted.
- **Decision.** `scripts/miri.sh` runs the `--lib` tests of mqtt, timer-wheel, net, tcp, broker and tls with a skip list for tests that need minutes under Miri (the tcp stateful model and simulations, the broker's 60 000-step and 10 000-iteration loops, the RSS spread test). The list and the reason for each is in the script and in `docs/VERIFICATION.md`. The skipped tests still run natively on every `cargo test`. The `store` crate is not run under Miri (C code); ADR-121 covers it.

## ADR-140 — Layout v2: alignment, topology, partition count, A/B superblock, extents (S2)

- **Status:** Accepted (S2). Replaces layout v1 (ADR-030); the migration is ADR-141, the grow ADR-142. Byte-level spec: DISK-FORMAT.md, machine-checked by `crates/store/tests/disk_format_spec.rs`.
- **Problem:** v1 aligned regions to 4 KiB from LBA 64, wrote the telemetry in 512-byte sectors (a read-modify-write on every 4 KiB-physical device), fixed 8 telemetry partitions, kept one superblock (a torn write loses the disk) and could not grow without moving data.
- **Decision:**
  - **Topology.** The block sizes and I/O hints come from the device: virtio-blk `F_TOPOLOGY` (`physical_block_exp`, `alignment_offset`, `min_io_size`, `opt_io_size`), virtio-scsi READ CAPACITY (16) (physical block exponent, lowest aligned LBA) and the Block Limits VPD page B0h (optimal transfer length granularity and length). NVMe and ATA are deferred to X13 (the trait carries the same five numbers). Reading them is unconditional and harmless: a device that reports nothing is a plain 512-byte device.
  - **Alignment.** `align = lcm(1 MiB, physical block, optimal I/O)` in sectors, capped at 64 MiB (a larger value is ignored). Every region of a fresh layout starts on `align`; the first `align` sectors are the header area. The partition itself starts on a 1 MiB boundary (S1), so region alignment is disk alignment. The value is stored in the superblock and kept for life: a disk moved to another device is not re-laid-out.
  - **Writes.** `Disk` reads and writes in units of `max(physical block clamped to 512..4096, logical block)`; the edges of a smaller write are read first. So no SQLite write (a 4120-byte WAL frame at an odd offset, say) reaches the device off a physical block, and telemetry flushes pad to the physical block instead of the sector. A new telemetry segment's header goes out with its first records in one write. The counter `misaligned_writes` (requests that start or end off a physical block of the real disk, judged with the partition's offset) is in `DiskStats`; the kernel logs it after startup and after `db-bench`, and smoke requires 0 with 512/512, 4096/512 with optimal I/O 256 KiB, 1 MiB and 2 MiB (virtio-blk and virtio-scsi). Exceptions that are not counted, because they are not store writes: the GPT and MBR at the first boot and the installer (512-byte sectors by definition), and the boot self-test (a 4 KiB write at the partition's last 8 sectors, itself 4 KiB aligned).
  - **4Kn.** Not supported by the boot path: the GPT code is 512-byte based, and Limine cannot read the image's GPT through a 4096-byte-block device (QEMU's 4096/4096 does not boot it). The kernel refuses a boot disk whose logical block is not 512 bytes, with a message. The store layer is tested against a strict 4096/4096 device (`MemDisk::with_topology`) that rejects any request that is not whole logical blocks: zero misaligned writes, data round-trips. The plan's "QEMU 4096/4096" test is therefore a host test.
  - **Partition count in the layout** (G4): `partitions` in the superblock, 1 to 64, chosen at format time as the number of CPUs rounded up to a power of two, at least 8 (the kernel passes it); an existing layout keeps its own. Source core `c` writes partition `c mod P`.
  - **Superblock A/B.** Slots at LBA 0 and 24 with a `generation`. The higher valid generation wins, slot A on a tie. Every update is one 4 KiB write to the slot not in force, then a flush (ADR-142 and ADR-141 rely on it). The size table keeps its own pair (unchanged).
  - **Region table with extents.** Up to 128 entries; several entries of kind database or telemetry are extents of one logical region, concatenated in table order. The database is a flat file, so its extents just add up. The telemetry ring has one **band** per extent (segments per partition are laid out inside the extent), so growing never changes where an existing segment is.
  - **Segment headers carry the layout UUID** (bytes 32..48). A segment of an earlier incarnation of the disk, or stale bytes in space a grow claims, is not valid. This fixes a latent v1 problem: a reformat over a disk that held an older urMQTT ring could surface its segments. Only a ring kept from v1 (flag bit 0) accepts all-zero UUIDs, in band 0.
  - **Sizes.** The formatted size is rounded down to a multiple of 4 KiB (G7: the layout no longer refuses such disks).
- **Not done:** G8 (recovery reads the whole telemetry region at boot: a per-segment summary and a scan of only the newest segment) is S6's. NVMe/ATA topology is X13.
- **Alternatives rejected:** a header area that grows with the alignment (the first `align` sectors are reserved anyway, so nothing else is needed); region sizes as multiples of `align` for the migrated disk (its ring must stay in place, ADR-141).

## ADR-141 — Layout v1 is refused by the kernel and migrated offline by `urmqtt-disk migrate` (S2)

- **Status:** Accepted (S2). Settles PLAN.md decision 4 and the choice PROMPT-storage S2 leaves open (the kernel migrates at boot, or refuses v1).
- **Decision:** the kernel reads only layout v2. A valid v1 superblock is `LayoutError::OldVersion(1)` and the boot stops with `data disk is layout v1; this image needs v2: run urmqtt-disk migrate (docs/DEPLOY.md)` plus the stable token `storage: refused reason=layout-v1` in the log. Nothing is written first: the GPT steps find nothing to do on a disk that is the size of its partition table, and the boot self-test is skipped for any partition the store will refuse (the smoke scenario `layout-v1-refused` hashes the disk before and after). The migration is a host tool, offline, with a dry run by default. The project is pre-1.0, a copy of gigabytes at boot would be unattended and unbounded, and one parser (v2) stays in the kernel's TCB; the v1 parser lives in the same crate (`layout::v1`, `Disk::open_v1`) but only the tool calls it, so the kernel links none of it.
- **Statsd reason:** the plan asks for "a statsd reason". The refusal happens before the network stack exists, so no datagram is sent. The reason is the log token above, on the serial console and the screen (and syslog if one were up). A statsd counter would need a network bring-up in the failure path; not done.
- **What `migrate` does:**
  - **Plan** (`--write` absent, the default): old and new regions, bytes to copy, free space needed against available, the preconditions' findings. Nothing is changed.
  - **Preconditions:** a valid v1 superblock with slot B empty and no migration in progress; `verify` passes on a copy-on-write view (SQLite `integrity_check` with the WAL replayed in memory only, telemetry opens); the rollback journal is empty (a hot journal needs a boot of the old image first). A non-empty WAL is allowed and copied: it is position independent and the next boot replays it. A torn telemetry tail is allowed (the next boot truncates it, as before). "Clean last shutdown" cannot be read from the disk; the verify stands in for it.
  - **Where the data goes.** The live bytes of the database, WAL and journal (a few MB) are copied into new regions carved from the **dead tail of the old database region** (the live database sits at its head; the region is half the disk). So a source byte is never overwritten before the switch, and no free space beyond the old layout is needed. The telemetry ring is **not moved**: it stays where it is as extent 0 of the new layout (flag bit 0), 4 KiB aligned, not 1 MiB aligned. Copying up to hundreds of GB offline, and the exposure that goes with it, is not worth an alignment unit; its writes are whole physical blocks. The old database head, WAL and journal areas become database extents. This is the one place where the plan's "every region to 1 MiB" is not met, and it is documented in DISK-FORMAT §2a and §10. The alternative (a full relocation) needs either free space equal to the ring or an in-place shift with a progress journal; both rejected.
  - **Order of writes** (each flushed): rollback file on the host (`--rollback-file`, default `<disk>.urmqtt-migrate-rollback`, never overwritten); the v1 superblock saved at LBA 32 and state `planned` (LBA 40/48, alternating); the copies, read back and compared; state `copied`; **slot B := v2 generation 1** (LBA 24, free in v1; this single block write is the switch); state `switched`; slot A := v2 generation 2, so no v1 reader opens the disk; state `done`. Until slot B is complete and valid the disk is a valid v1 disk (slot A still holds v1); a torn slot B is invalid and ignored.
  - **`--resume`** finishes from the recorded state, re-deriving the plan from the saved superblock and refusing if its CRC differs from the record. If the switch was written but its record was not, it is recognised and the copies are not repeated. **`--rollback`** restores LBA 0, empties slot B and the migration blocks; after the switch it needs `--force`, because the disk was v2 and later changes would be lost. `--rollback-file` restores from the host copy when the on-disk copy is gone.
  - **Verification** after the run, from a read-only view: the v2 layout opens, the telemetry digest (records, order, content) equals the source's, the database and WAL bytes equal, `integrity_check` is ok and every table has the same row count as in the source.
- **Tests:** every golden v1 image is migrated and verified; a v1 disk with a real SQLite database and a ring (the tool's own fixture) is compared table by table; a power cut at every write (clean, torn, cache dropped or applied) always leaves a valid v1 or v2 disk with all data, and both `--resume` and `--rollback` finish from it, the latter byte-identical to the original LBA 0 (`tools/disk/tests/migrate.rs`); `scripts/fault-loop.sh migrate` does the same through the real binary on an image file; smoke `layout-v1-refused`, `layout-v1-migrate-tool`, `layout-v1-migrated-boots` boot the real kernel on the result.
- **Limits:** the golden v1 images hold no SQLite content (their size table declares a database of zeros); they are migrated with the database check off, which is a library option and not on the command line. The v1 writer exists for fixtures only; no v1 kernel is left to produce a disk, so the smoke fixtures come from `urmqtt-disk fixture-v1`.

## ADR-142 — Growing the disk: an A/B superblock pair, extents, and the GPT steps (S3)

- **Status:** Accepted (S3). Builds on ADR-140. Online grow is ADR-143.
- **Problem:** when a cloud volume is enlarged the data partition and the layout must follow, crash-safely, without moving data, never shrinking.
- **A/B pair or journaled superblock?** The A/B pair (already needed by ADR-141). A journal would add replay code to the kernel's TCB and a second structure to validate; the pair needs one comparison. A superblock update is one 4 KiB write to the slot not in force: if it tears, the slot's CRC fails and the other slot, the old layout, stays in force; if it completes, the new one is. There is no state in between to repair, and the fault tests have nothing to enumerate except "was the write complete". The cost is that the old layout is also on disk until the next update overwrites it, which is a feature.
- **Procedure at boot** (before the store opens): `gpt::prepare` (backup table to the new end, then the data partition's entry extended to the last whole 4 KiB block, backup copy before primary, entries before their header; a cut leaves the old table or the new one and the next boot repeats what is missing), then `Layout::grown` and one superblock write. The new space `[ceil_align(end of the last region), floor_align(device - 8))` is split by `storage.grow_ratio_db` (percent, default 50) between the database and the telemetry ring as new extents. The region that already ends the layout gets its share first, so a database extent that touches the previous one is merged into it; telemetry always gets a band of its own, because merging would change where the existing segments are. A telemetry share smaller than one row of segments (`P * segment_bytes`) goes to the database. WAL and journal keep their size. The scratch area moves to the new end. A device that is not larger by a whole alignment unit changes nothing, and a smaller device is never adopted (the superblock check refuses `total_sectors` above the device, `gpt::prepare` reports `Shrunk`).
- **Entries:** each grow adds at most two region entries; the table holds 128.
- **Telemetry:** new space is claimed by band, never written at grow time. Its stale bytes are harmless because segment headers carry the layout UUID (ADR-140). After a grow a ring whose active segment is not the last keeps overwriting the oldest segments next to it before reaching the new band: correct, and the new space is used from the next wrap.
- **Tests** (`crates/store/tests/grow.rs`): 1 GiB -> 4 GiB -> 64 GiB with SQLite state and a telemetry log (rows, retained messages, every record survive; layout, GPT and generations as expected; the database writable across the old end); a power cut at every write of the whole procedure (GPT and superblock, clean and torn, cache dropped or applied: always the old or the new layout with all data, and the next boot ends in the new one); the telemetry ring across a grow, with another UUID's ring planted where the new band lies (no stale record appears); slot alternation. On the real kernel: smoke `grow-boot`, `grow-again-noop` and `grow-crash` at eight writes (the nine GPT writes, the self-test write, the superblock write; clean and torn), on aarch64 (HVF) and x86_64 (TCG). `scripts/fault-loop.sh grow` runs the same through the tool binary.

## ADR-143 — Online grow through the virtio-blk configuration-change interrupt (S3)

- **Status:** Accepted (S3). Verified on QEMU 11 (HVF and TCG, virtio-blk on PCI with MSI-X).
- **Question (STORAGE-PLAN S3):** does QEMU's `block_resize` reach the guest, so a grow needs no reboot?
- **Finding:** yes. With the configuration vector set to the queue's MSI-X vector (`Transport::set_config_vector`), QEMU raises that interrupt when `block_resize` enlarges the drive and updates the capacity in the device configuration (`config_generation` guards the read). In the smoke scenario `grow-online` the host enlarges a running VM's disk over QMP and the guest logs `storage: grew the layout online from 54 MiB to 182 MiB (generation 3)` about a second later, with the telemetry ring taking up the new band without a reboot, on aarch64 HVF and x86_64 TCG. The guest logs `blk: resize notification (configuration-change interrupt): armed (online grow)` at boot. A virtio-scsi LUN has no such notification (and no vector: it is polled), so it is taken up at the next boot, which the boot log says.
- **Design:** the interrupt handler only counts (the vector is shared with request completions; it cannot read the device, which the DB core owns). The DB core, at most every 250 ms and only when the interrupt count moved, asks the device (`BlockDevice::refresh_size`, which re-reads the capacity under the config generation). If it grew: `Disk::grow_online` runs the same partition-table steps through the window's whole disk (`BlockDevice::whole_disk`), widens the window (`resize_window`) and calls `grow`; then the DB core tells the telemetry log to take up its new band (`TelemetryLog::refresh_geometry`). Everything runs on the DB core between its other work, so the disk has no concurrent user; a failure leaves the old layout in force (the update is the same single superblock write) and is logged. A smaller capacity is never adopted.
- **Tests:** `online_grow_while_the_store_runs` and `online_grow_survives_a_power_cut_at_every_write` (`crates/store/tests/grow.rs`: the store and a log open, the volume grows, the ring uses the new band; a cut at each of 12 writes); smoke `grow-online`, `grow-online-disk` and `grow-online-reboot` on both architectures.
- **Not done:** the window is resized only for virtio-blk; hot shrink is ignored by design; an online grow does not move `$SYS/broker/disk/total` until the DB core publishes it again (it is updated at grow time and every statistics interval).

## ADR-150 — Discard and write-zeroes: a queue behind a sync, within the device's limits, never in front of a commit (S4)

- **Status:** Accepted (S4). Builds on ADR-140 (topology, write granularity) and ADR-142 (grow). Recovery is ADR-151.
- **Problem:** a thin-provisioned disk (a qcow2 on a KVM host, a cloud volume, an SSD) only gets space back if the guest says what it no longer uses. The store has three such places: telemetry segments past `storage.retention_days`, the logical tail of a file SQLite truncated (the size table shrinks, the bytes stay), and the space a grow adds to the layout (it may hold what an earlier life of the volume left).
- **Commands:**

  | Device | Discard | Zeroing that may unmap |
  |---|---|---|
  | virtio-blk | `F_DISCARD` (13): `T_DISCARD`, an array of 16-byte segments | `F_WRITE_ZEROES` (14): `T_WRITE_ZEROES` with the unmap flag, only if `write_zeroes_may_unmap` |
  | virtio-scsi | UNMAP (0x42) with a parameter list; usable if READ CAPACITY (16) says LBPME, Block Limits B0h gives non-zero maximum counts and Logical Block Provisioning B2h says LBPU | WRITE SAME (16) with UNMAP and one zero block, if B2h says LBPWS |
  | NVMe, AHCI | Dataset Management Deallocate / TRIM | Write Zeroes | deferred to X13 |

  The seam is `BlockDevice::discard_caps()` and `discard(ranges)`; NVMe and AHCI implement the same two methods. DISCARD is used when the device has it; zeroing that may unmap is the fallback; zeroing that would write is never used (it burns I/O to release nothing). Both are advisory: a device may do nothing.
- **Limits, from the device:** virtio-blk reads `max_discard_sectors`, `max_discard_seg`, `discard_sector_alignment` (config offsets 36..56); SCSI reads maximum unmap LBA count, maximum unmap descriptor count and optimal unmap granularity (B0h). The store keeps every request inside them: a range is at most `min(max, 16 MiB)` (a longer discard blocks the device for a while), a request carries at most the device's range count (virtio-blk 256 at most, a 4 KiB bounce area), and **both the start and the length of a range are multiples of the granule**, judged on the physical disk (the partition window's offset is added) and rounded inwards to the physical write block as well. A range shrinks, never grows: a partial granule is not released. Hostile or absurd numbers are clamped (`UnmapLimits`, tested). The host `MemDisk` enforces the limits it advertises and counts violations (the tests require 0).
- **Ordering and safety.** `Disk::discard_region` only queues. A queued range is *staged* until the next `Disk::sync` (everything written before it is durable, including the size table that retired the range), then *ready*; if nothing is waiting to become durable it is ready at once. **A write to a queued range takes it back** (`write_dev` subtracts the written sectors from both lists), so a segment the ring reuses, or a file that grows again, is never discarded under its new data. Ranges are sent by `Disk::run_discards`, which only the DB core calls, **one request at a time, at most every 25 ms (about 640 MB/s), and only while no transaction is open, no data core has queued work and no telemetry is pending**: a discard is never in front of a commit. After the queue drains the DB core syncs once, so the device's discards are durable (a qcow2 records them on flush). A device that fails three requests in a row, or says the command is unsupported, is given up on for the boot (counters: `failed`, `unsupported`); the queue is capped at 512 ranges (`dropped`).
- **Config:** `storage.discard = "auto" | "off"`, optional, default `"auto"` (config schema and `config` crate, `deploy/dev` and `deploy/bench` say it explicitly; `deploy/prod` leaves it out). `"off"` never sends a command and queues nothing.
- **Counters** (`storage: discard: requests=… ranges=… released=… KiB (queued: telemetry …, truncate …, grow …) cancelled=… dropped=… failed=…`), logged once the queue is idle; the boot log says what the device offers (`storage: discard: auto, device discard (… per range at most, … range(s) per request, granularity … B)`). Smoke checks them.
- **Alternatives rejected:** discarding inside `xTruncate` (in front of the commit that made the truncate durable, and unsafe if SQLite writes the range again before the next sync); releasing individual SQLite pages (the VFS does not see SQLite's free list, and `auto_vacuum` is off); trimming a telemetry segment when the ring reuses it (it is overwritten at once, nothing to release); a background thread (the disk has one owner, the DB core).
- **Measured:** `db-bench` against the commit before S4 (HVF, virtio-blk, same machine, five runs each alternating): batched 53.3 k inserts/s on both (mean), one insert per transaction 1819 against 1766, the same 1572 device writes and 319 flushes: no measurable regression (the runs vary by more than the difference). The qcow2 scenario (`discard-qcow2`): 16 expired telemetry segments (48 MiB) written by one boot are released by the next; the qcow2 maps 62 MiB as data before and 15 MiB after, the host file occupies 62 MiB before and 16 MiB after, on aarch64 HVF and x86_64 TCG, virtio-blk and virtio-scsi.
- **Not done:** NVMe and AHCI (X13); no online `fstrim`-style sweep of free space inside the database file (SQLite's free pages stay allocated; the file only gives back its tail when it shrinks); the rate and chunk size are constants, not configuration.

## ADR-151 — Recovery never trusts the content of a released range (S4)

- **Status:** Accepted (S4). Builds on ADR-140 (segment headers carry the layout UUID, records a CRC salted by the segment sequence) and ADR-150.
- **Premise:** after a discard a sector may read back as zeros, as its old bytes, or as anything (virtio-blk leaves it undefined; SCSI says so unless LBPRZ; a thin disk releases only whole clusters, so the head and tail of a range keep their old bytes). The same is true of a range that was never written. Nothing may depend on it.
- **Rules, per region:**
  - *Database, WAL, journal:* the VFS never returns a byte beyond a file's logical size (`xRead` clips and zero-fills, as before); S4 adds the other half: **a write past the end and a truncate to a larger size zero-fill the gap** (`Disk::zero_fill`), so a file that grows without being written there reads zeros whatever the disk held. SQLite validates WAL frames by salt and checksum and never reads beyond the logical size.
  - *Telemetry:* a segment exists only if its header has the magic, this layout's UUID and a valid CRC, and a record only if its CRC (salted by the segment sequence) matches. **Retirement overwrites the segment's first block (the header) with zeros before queueing the discard.** The smoke test found why: a qcow2 frees whole 64 KiB clusters only, so the first, partial cluster of each released range kept its old header and records, and the old segment came back at the next boot (harmless to the data, which is expired, but it was counted, logged and retired again every boot). With the header zeroed the retirement is complete whatever the device does afterwards, and it is idempotent.
  - *Scratch:* never read as data.
  - *Superblocks, size table, telemetry header, GPT:* never inside a discarded range (ranges lie inside region extents and are shrunk inwards).
- **Retirement** needs a wall clock (`now_unix`; 0 retires nothing), skips the active segment of each partition and any segment whose newest record has no usable timestamp (0). It uses the clock the retention filter already uses; a clock that jumps far forward would retire data early, as it already hides it from `restored` after a restart. The in-memory table (`SegInfo`) is rebuilt by recovery, which already scans every segment; nothing new is stored.
- **Tests** (`crates/store/tests/discard.rs`): for each of three device behaviours (released ranges read zeros, pseudo-random garbage, or keep their old bytes) a store with SQLite state (committed rows and retained messages, a database and WAL grown to over 20 MiB and truncated by a checkpoint) and a telemetry log (old segments retired and released) is cut, then **every discarded range, the tail of each file beyond its logical size and the scratch area are filled with garbage**: the disk opens, `integrity_check` passes, the committed rows are exactly there, the telemetry log recovers exactly its live records and no garbage record, and the database grows again over the garbage with zeros in its holes. A power cut at every write and discard of a retirement (clean and torn, up to 40 cut points, zeroed or garbage-filled device) ends in a log that holds every live record. Unit tests for the queue: limits, ordering behind a sync, cancellation by a write, a failing device, "off", write-zeroes, a grow, a ring that reuses a queued segment.

## ADR-160 — The backup region: layout v2.1, carved from the database's tail (S5)

- **Status:** Accepted (S5). Builds on ADR-140 (layout v2, A/B superblock), ADR-141 (offline migration) and ADR-142 (grow).
- **Question (STORAGE-PLAN S5):** where does the in-disk backup live, and how does a disk formatted before S5 get it, without breaking v2 disks and within "every format change bumps the version and has a migration path"?
- **Decision:**
  - **A minor version.** The superblock word at offset 60, reserved and zero in every v2 disk so far, becomes `minor`: 0 is layout v2.0 (everything formatted up to S4), 1 is v2.1 (may carry a backup region). A new region kind 6 (`backup`) exists only with `minor` 1. A build that predates minors checks that word and refuses a non-zero one (`Inconsistent`), so **an older kernel never opens a v2.1 disk**; this build reads both and refuses a larger minor (`UnsupportedMinor`). This is the version bump, with a refusal in the direction that matters (a rollback to an older kernel must not misread the region as free space).
  - **The region is carved from the tail of the last database extent**, beyond the database file's logical end. A v2.0 disk has no free space (the formatter gives the database half and the telemetry ring the rest), and moving the telemetry ring is the one thing the format avoids. The database region is far larger than the database in practice (half the disk). `Layout::with_backup` takes `4 KiB + 2 × slot`, `slot = clamp(database region / 8, 1 MiB, 1 GiB)` (less if the last extent is small, as after a grow; never below 1 MiB), aligned to the alignment unit, and requires the database to keep **at least twice its file size plus 1 MiB**; otherwise the layout is left alone (`NoRoom`, logged: the broker runs without in-disk backups).
  - **The migration path is one superblock write**, in the kernel, at boot (`Disk::ensure_backup`): the control block and both slot headers of the new region are zeroed and flushed first (so whatever the bytes held reads as "no backup", ADR-151), then the new superblock goes to the slot not in force, then a flush. Same primitive and the same crash argument as the grow (ADR-142): a cut before it leaves the old layout, a torn write leaves an invalid slot and the old one in force, a complete write the new layout. No byte that is read moves. **This is not the unattended conversion ADR-141 refused:** nothing is copied, nothing is rewritten, the cost is four small writes, and a v2.0 disk keeps working if the carve does not happen (`backup_interval_min = 0` skips it; `NoRoom` skips it).
  - **A fresh disk is formatted as minor 0 and carved at its first boot by the same code**, so there is one path and the formatter's output is byte-for-byte what it was (the golden test below).
  - **Queued discards** (ADR-150) over the new region are cancelled by the carve; afterwards the database's extents no longer include the region, so a truncate of the database cannot discard it (tested).
- **Alternatives rejected:** a new layout version 3 (a copy of v2 with one region more: `urmqtt-disk migrate` for no data movement, and every disk offline); a region at the end of the disk (the scratch area and, since S1, the backup GPT live there; the partition's end moves with a grow); shrinking the telemetry ring (the ring's geometry is fixed by the first extent); a separate partition (a second table entry to keep consistent for no benefit; the layout already has the A/B superblock and fault-injection machinery).
- **Limits:** the slot is sized from the database region at carve time and is not resized by a later grow, so a database that outgrows 1/8 of its original region is no longer backed up (`backup: FAILED: the database (… KiB) does not fit a backup slot`; the previous snapshot stays). A broker database of that size is not what this appliance holds (retained messages, sessions, the device registry); a larger slot would be a second carve, not planned.
- **Tests** (`crates/store/tests/golden_v2.rs`, `backup.rs`, `disk_format_spec.rs`):
  - **Golden images** `v2-fresh` and `v2-data` were frozen from S4's tree before any change: the code still writes their bytes, and they open, are upgraded by `ensure_backup` (exactly four writes), keep every telemetry record, retained message and device, and take a backup.
  - **A power cut at every write of the upgrade** (cut or torn, cache dropped or applied): the old layout unchanged or the new one, data intact, the next boot finishes.
  - `NoRoom`; the minor in the superblock bytes (spec test, both new structures); a larger minor refused.
  - Smoke `backup-upgrade` on aarch64 HVF and x86_64 TCG: a populated v1 disk migrated by the tool to v2.0, then upgraded by the kernel's boot (generation 3, 40 devices, 600 telemetry records intact).

## ADR-161 — Snapshots by SQLite's online backup API through a fourth VFS file; `VACUUM INTO` is not available (S5)

- **Status:** Accepted (S5), by measurement.
- **Question:** how does the DB core write a consistent snapshot into the older slot without stalling commits: the online backup API in bounded steps, or `VACUUM INTO`?
- **Measured** (6000 rows of 3.8 KB, a database of about 24 MiB):
  - *Host, `MemDisk`, release build* (`backup_cost_against_vacuum_into`, ignored by default): the backup API in 646 steps of 16 pages has a longest step of **2.8 ms** (76 ms in all); the same copy in one call blocks **54 ms**.
  - *Guest, aarch64 HVF, virtio-blk* (`test=db-backup-bench`): steps of 16 pages, mean **0.9 ms**, longest **4.6 ms**; the same copy as one call **445 ms**. Commits of a writer running at about 1 kHz: max **2.2 ms** alone, **2.4 ms** during the backup (ADR-162). On x86_64 TCG: longest step 5.6 ms, one call 690 ms, commit max 3.1 ms alone and 3.0 ms during.
  - **`VACUUM INTO` does not run at all in this build:** `SQLITE_MAX_ATTACHED=0` (no `ATTACH`; the build trims everything the broker does not use), and `VACUUM INTO` needs an attachment inside, so it fails with `too many attached databases - max 0`. Even if enabled it is one call that cannot be split, which the single-call figure above bounds from below.
- **Decision:** the backup API, driven by the DB core 16 pages at a time (`sqlite3_backup_step`). Properties relied on: the source is read through its own connection (WAL included), so the snapshot is the committed state when a step reads it; **a change made through the same connection between steps is mirrored into the destination by SQLite itself**, so the finished copy is one consistent state (tested: a counter table and the rows it counts agree in a snapshot taken while transactions commit between steps).
- **The destination is a fourth file of the VFS**, `urmqtt-backup.db`, which exists only while a slot is attached (`vfs::backup_attach`): its bytes are the slot's payload area, its size lives in memory, it has no WAL or journal (the destination connection runs `journal_mode = OFF`, `synchronous = OFF`: its consistency does not matter, because the header that makes it a snapshot is written last, after a read-back). The VFS zero-fills gaps and bounds every access by the slot. The destination connection must outlive its backup handle (a handle finished after its connection closed is a use after free; the fault test found it, by killing the device mid-copy).
- **The write order is the safety argument** (docs/DISK-FORMAT.md section 12.3): the other slot's header is zeroed first; the previous good slot is never written; the payload is read back and its CRC computed; the header (sequence, time, schema, page geometry, payload CRC, layout UUID, own CRC) is one block written last. A newest slot whose payload fails its CRC is not trusted: the next backup overwrites *it* and keeps the older good one (tested). The first backup of a boot reads the newest snapshot back to know that (once; the result is remembered).
- **Tests:** a power cut at every write of a backup (148 cases over 36 writes, clean and torn, cache dropped or applied): the older slot's header and all its bytes unchanged, its payload CRC valid, the live database unharmed with its 20 rows, a restore afterwards picks an intact snapshot; `scripts/fault-loop.sh backup` through the real tool binary (26 cases); smoke `db-backup-cut` at two points inside a kernel backup with `test=disk-fault`, each followed by `urmqtt-disk verify` (first snapshot intact) and a boot that restores it; a bit flip in the newest payload; a database larger than a slot (refused before anything is written).

## ADR-162 — When and how the DB core takes a backup (S5)

- **Status:** Accepted (S5).
- **Config:** `storage.backup_interval_min` (default 60; 0 turns the backups off and skips the carve; at most one week). `deploy/dev` says 60, `deploy/bench` 0 (the benchmarks are not disturbed), `deploy/prod` leaves it out and gets the default.
- **Schedule:** the next backup is due `interval` after the newest snapshot on the disk (by its wall-clock time, so a reboot does not restart the clock), 10 s after boot at the earliest; a disk with no snapshot gets one 10 s after boot. With the clock unknown it counts from boot. A failure is retried after the shorter of the interval and 5 minutes.
- **Pacing:** one bounded step (16 pages = 64 KiB, or a 128 KiB read-back) at most every 2 ms, and **never inside a transaction**. A commit therefore waits for at most one step; the data cores only push into rings and do not wait at all. A 24 MiB database takes about 1.4 s while committing at 1 kHz.
- **Measured data-plane effect** (`test=db-backup-bench`, aarch64 HVF, virtio-blk, 24 MiB database, a commit every millisecond for 1 s alone, then for the length of a backup): commits alone **656 in 1 s, mean 523 us, max 2.2 ms**; commits during the backup **570 in 1.37 s, mean 496 us, max 2.4 ms**; backup steps mean 0.9 ms, longest 4.6 ms. The commit latency does not move. The closed-loop writer's commit *rate* falls (about 417/s) only because a step takes the DB thread between two of its commits, which is the design: the DB core is otherwise idle and no other core waits on it (the data cores push into rings). x86_64 TCG: 621 in 1 s, mean 610 us, max 3.1 ms alone; 570 in 1.8 s, mean 614 us, max 3.0 ms during; steps mean 1.5 ms, longest 5.6 ms.
- **Observability:** one line per snapshot (`backup: snapshot seq N written to slot S: P page(s), K KiB, schema vV, T step(s) over M ms, longest step U us`), `backup: FAILED: …` with the reason, and statsd gauges `urmqtt.backup.{enabled,snapshots_done,failed,restored,last_bytes,age_s}` (`age_s`, seconds since the newest snapshot on the disk, is the one to alert on).
- **Not done:** a backup while the database is larger than a slot (ADR-160); an on-demand backup through the control channel; off-disk copies (`urmqtt-disk backup-extract` writes the newest snapshot as a plain SQLite file for the operator to keep).

## ADR-163 — Restore at boot: when, with what default, and how it survives a cut (S5)

- **Status:** Accepted (S5).
- **When:** at boot, before the broker serves, if opening the database fails SQLite's own checks: `PRAGMA quick_check` not `ok`, or an error with code `SQLITE_CORRUPT`/`SQLITE_NOTADB` while opening (a damaged page 1 fails before `quick_check` runs). Anything else (an I/O error, a full disk, a newer schema) is not corruption and is not "mended". The same refuse-or-degrade rule as before applies when no restore happens (`storage.refuse_on_corruption`).
- **Config:** `storage.auto_restore`, default **true**. The appliance has no console, and "refuse to serve" means an offline broker until someone writes a disk image; a loudly logged restore of a recent snapshot is the better default for a fleet's broker. `false` restores the S4 behaviour exactly (`storage: the database is corrupt and storage.auto_restore is off: not restoring from a backup`). The loss is stated, not hidden: `storage: DATABASE RESTORED FROM BACKUP: snapshot seq N from slot S (K KiB, schema vV); T s of changes (since unix U) are LOST; reason: …` at error level (so it reaches the serial console, `$SYS/console/out` and syslog) and `urmqtt.backup.restored` = 1.
- **Which snapshot:** the newest whose header is valid for this disk and whose payload CRC matches, and whose schema this build can read (`user_version ≤ schema::VERSION`; a newer one is skipped and, if it is all there is, the reason says so: `open` would refuse it anyway). With none, the corruption is refused with `restoring from a backup failed: no valid backup`.
- **Crash safety:** the control block's `restoring` mark (snapshot slot and sequence) is written and flushed first; then the WAL and journal sizes are set to 0 (a stale frame must never be applied to the restored file); the payload is copied over the start of the database region and its CRC checked against the header; flush; the database size is set; the mark is cleared. The snapshot is only read, so a cut at any point leaves it intact and the next boot repeats the restore **whether or not the half-restored file passes `quick_check`** (the mark, not the check, decides). Tested at every write: 68 cases over 16 writes, 58 with the mark set, every one ends restored.
- **After the restore** `open` runs the schema migrations as usual, the lost window is the snapshot's age, and the next snapshot is taken as scheduled (the slots alternate, so the snapshot a restore came from is the last one overwritten).
- **Dev hooks:** `test=db-corrupt` checkpoints and closes the database, overwrites its first two pages with garbage and carries on to the open that must restore; `test=db-backup` fills 100 rows, takes a snapshot, writes 50 more. Smoke `db-backup`: snapshot, corrupt (the restored boot holds exactly the 100 rows), a plain boot afterwards restores nothing, `urmqtt-disk verify` clean.
- **Offline:** `urmqtt-disk backup-restore DISK --write`, `backup-extract DISK OUT [--slot N]`, `backup DISK [--write]`; `info` and `verify` show both slots and fail on a valid header whose payload does not match its CRC.
- **Not covered by a smoke scenario:** `auto_restore = false` in a VM (the baked configuration is the dev one; the host test `a_damaged_database_is_refused_without_auto_restore_and_restored_with_it` and the schema tests cover it).

## ADR-164 — The scrubber: what it reads, in what order, and how it is paced (S6)

- **Status:** Accepted (S6). Builds on ADR-031 (telemetry log), ADR-160 to ADR-163 (backups) and ADR-165 (bounded boot).
- **Problem:** the checks that run at boot (`quick_check`, telemetry recovery) only look at the newest data, and a bad sector or a flipped bit in data nobody reads goes unnoticed until the day it is needed. A background pass re-reads what is on the disk and says so while a good copy may still exist.
- **A pass** (`urmqtt_store::scrub::Scrubber`, driven by the DB core) visits, in this order:
  1. **The database**, one table at a time: `PRAGMA quick_check(table)` (which checks the table and its indexes), after `PRAGMA shrink_memory` has released the clean pages from SQLite's cache, so the check reads the disk and not a copy in RAM. A table is checked whole, so the step that does it can read more than it was granted; the pacer charges the debt (below). Indexes are checked with their table (`quick_check` takes table names). The structure that only the whole-database check sees (free list, orphan pages) is still checked at boot, not by the scrubber.
  2. **The backup region**: the control block, both slot headers and the payload CRC of every valid snapshot (the same `Verifier` that reads a snapshot back after writing it). A slot whose header has the magic and fails its checks, a payload that does not match its CRC, and a control block with its magic and a bad CRC are findings. A slot is re-read at the end of its check to see that a backup did not rewrite it meanwhile (and a scrub step never runs while a backup job does).
  3. **The telemetry ring**: every segment with a valid header is read in chunks of up to 256 KiB over several steps and its records are checked as they arrive (length bounds, topic length, CRC salted by the segment's sequence). The segment header is read again at the end: a segment that was reused or retired meanwhile is `Recycled`, not a finding.
- **What it finds, and how it tells torn writes from rot** (each segment ends in exactly one of these):
  - `Clean`: valid records up to a zero length or the segment's last byte.
  - `Damaged { at, resumes_at }`: a record that fails its checks and a **valid record after it** in the same segment. A torn write cannot do this (it leaves a prefix and nothing valid behind it); a flipped bit or a bad sector does. Found by trying every byte offset after the bad record whose length field is plausible (at most 64 KiB, at most 4 MiB of CRC work per segment).
  - `BadTail { at }`: a bad record and nothing valid after it. This is what a crash during a flush leaves, and it is also what a flipped bit in the *last* record looks like; the two cannot be told apart, so it is a warning, counted separately and not in `errors`.
  - `BadHeader`: the 512-byte block has the segment magic and fails its checks (a flipped bit in a header that recovery would otherwise treat as an unused slot, silently dropping the segment).
  A bit flipped in the magic itself, or in a block that is not a segment at all, cannot be told from a never-used slot and is not found.
- **What it cannot find, and why that is honest:** SQLite pages carry no checksum in this build, so `quick_check` finds structural damage (a broken tree, a bad page header, a bad cell pointer) and **not a flipped bit inside a row's value**. Telemetry records and backup payloads have CRCs, so any flipped bit in them is found. Page checksums would be a format change (reserved bytes per page: the `cksumvfs` shim) and are not part of S6.
- **Pacing** (`Pacer`): a token bucket at `storage.scrub_io_budget_mb_s` that holds at most one step (256 KiB), grants a step only when 64 KiB are available, and is charged what the step **really read** (the disk's `bytes_read` before and after, so SQLite's page reads for `quick_check` count). It may go into debt after a table check; the next step waits until the debt is repaid. Over any period the bytes read are at most the budget times the period plus one step (unit test: 1, 4, 8 and 64 MB/s over 20 s, with a step that overshoots by 5 KB every time; host test: a 20 MiB ring scrubbed under a writer appending all the time at 2, 8 and 32 MB/s, whole pass and worst second).
- **Scheduling** (in the DB core, `step_scrub`): the first pass ten minutes after boot (or the interval if shorter), then every `storage.scrub_interval_h` (default 24; 0 turns it off; at most 90 days). A step runs only between transactions, never while a backup job runs, and, when the broker is busy (requests queued for the DB core or telemetry pending), at most one step per 100 ms, so a pass always finishes (at most 2.5 MB/s whatever the budget) but never competes for more than a sliver of the disk. When it is idle the budget is the limit; the DB core wakes at least every 10 ms and takes what the bucket gives.
- **Reports:** every finding is one line, error level for data at risk (it reaches the serial console, `$SYS/console/out` and syslog), warning for a bad tail: `scrub: telemetry partition P segment S (seq N): DAMAGED record at byte B, valid records resume at byte R`, `… segment header DAMAGED …`, `scrub: database object T: DAMAGED: …`, `scrub: backup slot S (seq N): DAMAGED: the payload does not match the CRC in its header`. At most 24 findings per pass are logged in full. Three summary lines end a pass, and `scrub: pass N FOUND K problem(s)` at error level if there were any. statsd gauges: `urmqtt.scrub.{running,passes,last_ms,errors,errors_total,bytes_read,telemetry_segments,telemetry_records,telemetry_damaged,telemetry_bad_tails,telemetry_bad_headers,db_objects,db_errors,backup_slots_ok,backup_slots_bad,age_s}` (`errors` is the last pass's count and the one to alert on; `age_s` is the time since the last pass finished).
- **Offline:** `urmqtt-disk scrub DISK` runs one pass on the host over an overlay (the disk is not changed) and exits non-zero on any damage.
- **Tests:** host (`crates/store/tests/scrub.rs`): a clean ring with every record counted at three step sizes; bit flips in a record, in a record's length field, in the last record of the active segment and in a segment header, each classified as above; a torn write is a `BadTail`; a flip on the **read path only** (the fault injector, medium intact) is found, and the same medium through a clean device is clean; a clean disk (database, two snapshots, ring) has no finding and reads the database from the disk; structural damage to a table is found from the disk, not the cache; a flipped bit in a snapshot payload, in a slot header and in the control block are found; the budget under load. Smoke (aarch64 HVF and x86_64 TCG): `scrub-flip` (a bit flipped on the host in a record of partition 0 and in a header of partition 1; the kernel reports both with their positions and `FOUND 2 problem(s)`, the host tool reports the same bytes, the tool finds the clean disk clean before the flips), `scrub-load` (the telemetry writers of `log-crash` on every data core while the first pass runs; the pass's read rate against the budget).
- **Not done:** scrubbing the SQLite file's free pages and unused space; automatic repair (a damaged telemetry segment is reported, not rewritten; a damaged database is mended by the backup restore at the next boot only if `quick_check` fails there); rewriting a bad backup slot at once (the next scheduled backup replaces it).

## ADR-165 — Bounded boot: the newest segment of each partition, the rest by header; the retention bound (G8, S6)

- **Status:** Accepted (S6). Closes finding G8 of STORAGE-PLAN. No format change: the scrubber and the bounded boot add nothing to the disk (no region, field or version).
- **Problem:** recovery read every record of every segment at boot, so boot time grew with the telemetry region: about 2 minutes for 250 GB on fast NVMe, 15 to 40 minutes on a typical cloud volume.
- **Why a per-segment summary on disk is not needed:** STORAGE-PLAN S2 proposed a summary written when a segment is closed. It would be a format change and it is not necessary: recovery needs three things from the older segments and gets them without reading their records. (1) *Which segments exist and in what order:* the 512-byte header (sequence, UUID, partition, CRC) says. (2) *Where the ring continues:* only the newest segment's end (a torn tail is possible only there, because it is the only one a crash can interrupt). (3) *How old each segment is, for retention:* the bound below. The record counts that the boot log printed are a statistic.
- **Decision:** `TelemetryLog::open` reads the header of every segment slot (one block of the device's granule each) and scans only the newest segment of each partition. Boot I/O is therefore `segments × one block + partitions × one segment`, not the region. `Recovery` gains `scanned` (segments read) next to `segments` (segments found); `records` and `expired` now count the scanned segments only, and the boot log says so: `telemetry: log recovered in N ms: R record(s) in the K newest segment(s) read of S, T torn tail(s) truncated, E expired (the other segments are known by their headers and checked by the scrubber); P partitions of M MiB`.
- **Measured** (host, `boot_reads_the_headers_and_the_newest_segment_only`): a ring of 18 segments holding 5.8 MiB of records is opened by reading 1.1 MiB (64 headers of 512 B and 3 newest segments of 320 KiB); the bytes read fall from the size of the data to the size of the headers plus one segment per partition. For a 250 GB ring of 8 MiB segments that is 31 000 header reads and 8 segments, which at 0.1 to 1 ms per read is 3 to 30 seconds instead of 2 to 40 minutes; a smaller read per header would not help (the device block is the unit). The boot time of the real kernel for the 64 MiB test disks is dominated by other things (boot log: `log recovered in 3 ms`).
- **What changes for others:** `telemetry_digest` of the host tool, the migration check and the `verify` command use a full scan for record totals (they always did, through `scan`); the smoke recovery patterns say `in the K newest segment(s) read of S`; the grow tests count records with a full scan. Nothing on the disk changed; a disk written before S6 is read exactly as before.
- **The retention bound.** With boot no longer reading every segment, the age of an older segment is known only from its header until the scrubber has read it. The bound used is safe by construction: a segment's newest record is no younger than the creation time of the segment that followed it in the ring (the one with the next sequence number), because a segment is only left when the next is created, and records are stamped before they are written. Retention (ADR-150, ADR-151) retires a segment only when its bound is older than the cutoff, so it is never early; it can be late (a segment of old records followed by a segment created recently), and the scrubber, which reads the segment and sets the exact newest timestamp (`SegInfo::max_ts`, in memory), removes the lateness. The test `retention_works_from_the_headers_and_the_scrub_makes_it_exact` builds exactly that case (a segment created on day 30 whose records are from day 1): kept by the bound, retired after the scrub. A wall clock that steps backward could make a bound too small; that is the trust in the clock retention always had (ADR-151).
- **What the scrubber does with it:** a pass reads every older segment, checks every record and replaces the age bound by the exact newest timestamp. A segment with damage inside is reported there, not at boot: a bad record in an older segment shortens what `scan` returns for that segment and is not noticed by recovery any more.
- **Not done:** a hard bound on boot time for a very large ring of very many small segments (the header reads are still O(segments)); that would need the summary table, and 250 GB is already in seconds.

## ADR-190 — SBOM: CycloneDX 1.5 from a small script, with the vendored code and hashes (H9)

- **Status:** Accepted (H9).
- **Context:** the SBOM has to cover the Rust crates and the code that is not a crate: SQLite (C), Limine (binaries), the nistz256 assembly derived from ring, and three RustCrypto crates patched in `vendor/`. It has to be produced locally, offline once the registry is cached, and in the release workflow, and it must agree with the tree.
- **Decision:** `scripts/sbom.py` (Python 3 and cargo only) writes CycloneDX 1.5 JSON from `cargo metadata --locked --offline` and `Cargo.lock` (name, version, license, `.crate` SHA-256), then adds the vendored components with the hashes recorded in `vendor/*/CHECKSUMS` and `vendor/README.md`, **recomputed from the files and compared** (a mismatch aborts), the patched crates with a tree hash and the crates.io ancestor in `pedigree`, and the toolchain pin. Components carry `urmqtt:role` (`kernel`, `build-time`, `workspace`, `host-tool`, `boot-media`), taken from `cargo tree` for both kernel targets. Output is deterministic (UUIDv5 serial number, timestamp from `SOURCE_DATE_EPOCH`). `make sbom` writes it; `make dist` and `make dist-universal` put it in the release directory before `SHA256SUMS` is computed; the release workflow attests it with `actions/attest-sbom` next to the existing SLSA provenance; CI runs `--check`.
- **Alternatives:** `cargo-cyclonedx` (a tool to install and pin in CI and on every developer machine, no knowledge of `vendor/`, so the C code and patched crates would be merged in by a second script anyway; its output also differs by version); Syft on the ISO (cannot see inside a statically linked unikernel). Both remain usable as a cross-check.
- **Consequences:** one script to maintain, validated by its own checks and not against the CycloneDX JSON schema (needs a download; not done). Fuzz-workspace dependencies are not listed (not shipped). `urmqtt:role` of the vendored crates is assumed `kernel`.

## ADR-191 — cargo-vet: imports first, honest exemptions, patched crates are first-party (H9)

- **Status:** Accepted (H9).
- **Context:** H9 asks for audits of every TCB dependency. The project has no auditor and the TCB has 67 third-party crate versions, mostly RustCrypto and rustls. A self-audit by the integrator in one milestone would be a claim the evidence does not support.
- **Decision:** `supply-chain/` is initialised with the default criteria (`safe-to-deploy`). Published audits of Google, Mozilla, the Bytecode Alliance, ISRG, Zcash and Embark are imported (`imports.lock` pins what was imported). Everything not covered is an **exemption**, listed by role in `docs/audit/vet-exemptions.md` (generated and checked in CI): at H9, 53 of the 67 kernel-linked crate versions, 22 build-time and 65 host-only. **No audit entry of ours was written**: none was done. The vendored patched crates have `audit-as-crates-io = false` (cargo-vet otherwise demands that they be treated as the crates.io bytes, which they are not); they are reviewed as a diff against upstream. `cargo vet --locked` is a CI job and a step of `make check` when installed.
- **Alternatives:** write `certify` entries for the small crates after a skim (rejected: a skim is not an audit); exempt nothing and let CI fail (rejected: the check would be turned off); `audit-as-crates-io = true` for the patched crates (rejected: false statement).
- **Consequences:** the vet job proves that the dependency set cannot change without a visible diff, and that imported audits cover 14 TCB crates. It does **not** show that the TCB was audited; docs/SUPPLY-CHAIN.md and AUDIT say so, and the RustCrypto/rustls exemptions are the main input to the proposed external audit (H10).

## ADR-192 — cargo-deny: advisories are errors, with a scheduled run (H9)

- **Status:** Accepted (H9).
- **Decision:** `deny.toml` sets `yanked`, `unmaintained = "all"` and `unsound = "all"` explicitly next to vulnerabilities (always errors), with an empty `ignore` list whose use needs the advisory id, a reason and an expiry. The CI job also checks the fuzz workspace's lockfile. `.github/workflows/advisories.yml` runs the advisory check daily and on demand against a fresh database, and opens one issue when it fails. `make supply-chain` runs vet, deny and the SBOM check locally. Checked at H9: the current tree passes with the stricter settings.
- **Alternatives:** relying on Dependabot alerts only (GitHub's database, not RustSec, and it does not fail a build).
- **Consequences:** an advisory on a transitive crate can block CI on the day it is published. That is intended; the triage path is docs/VULNERABILITY-HANDLING.md.

## ADR-193 — Vulnerability handling: a written process, coordinated disclosure, no support period yet (H9)

- **Status:** Accepted (H9).
- **Decision:** `docs/VULNERABILITY-HANDLING.md` defines intake (private GitHub Security Advisory; 7 days to acknowledge), triage (3 working days; CVSS v4 and reachability from the SBOM), fix targets by severity (7, 30, 90 days), release (a new image; there is no in-place update), disclosure (coordinated, 90 days by default, CVE through GitHub), supported versions (the latest release and `main`) and the CRA alignment, stated not to be legal advice. **No support period is promised**, because the project is pre-1.0 and the CRA's minimum (five years for a commercial product) is a commitment the maintainers cannot make for a distributor; the document says what a manufacturer must add, and the table is to be completed before 1.0.
- **Consequences:** the targets are for a small team and are targets; the CRA reporting clock (24 h, 72 h, 14 days) is written down but its platform details were not verified and are marked for the first person who needs them. The process has not been exercised on a real report.
## ADR-170 — Allocator hardening: poison, free checks, obfuscated free lists, canary gaps, key slab (H4)

- **Status:** Accepted (H4 step 1). Code: `crates/mm/src/{buddy,cached,keyslab}.rs`, `crates/kernel/src/hardening.rs`.
- **Context:** the heap (a buddy allocator behind per-CPU size-class caches) trusted its callers and its own memory: a double free put one block on a list twice, a write after free could set a free-list link to an address of the attacker's choosing, a freed block kept its old contents (keys included), and nothing separated a large allocation from its neighbour. SECURITY-PLAN H4 asks for poison on free, double/invalid-free detection, obfuscated free-list pointers, guard gaps for large allocations, and a key slab that is zero on free.
- **Decision:**
  - **Poison on free.** A freed block is filled with `0xdf`. In the per-CPU caches (blocks of 32 B to 2 KiB, the hot path) the fill covers what the owner asked for (`layout.size()` rounded to 8) and the length is kept in the block's header: wiping what the owner can have written wipes every secret it held, and costs what it used, not the class size. In the buddy heap the fill covers the first `POISON_LIMIT` = 16 KiB of the block. When a freed block is handed out again its poison is checked (a branch-free word loop); a byte that changed is a **write after free** and the allocator stops. Memory that was never freed is not poisoned, so a first use reads whatever the page held (zero after boot); memory that was freed reads `0xdf`, never old data.
  - **Double free and invalid free.** The buddy heap keeps a second bitmap, one bit per 32-byte granule, set at the first granule of every live allocation. A free is refused (`DoubleFree`, or `InvalidFree`) if the pointer is outside the heap, misaligned for its size, not the start of a live allocation, or its size would span another live allocation; a block that is free, or inside a free block, is told apart as a double free by the free bits of all its ancestors (so it is also caught after the block has merged into a bigger one). The per-CPU caches check against the same bitmap without the lock (`AllocView`, atomic reads of the owner's own bit) and carry a state tag: freeing a block that already has the `FREED` or `FRESH` tag is a double free.
  - **Free-list integrity.** Every link and tag in a free block (buddy lists: next, prev, state; cache lists: next, state) is stored XOR a per-boot key and the address of the field itself, so a link read from a freed block is not a pointer, and one forged without the key decodes to an address outside the heap with overwhelming probability. Decoded links must be in the heap and 32-byte aligned (cache links must be live blocks of the class); unlinking from a buddy list checks that both neighbours point back ("safe unlinking"). A failure is `FreeListCorrupted`.
  - **Guard gaps for large allocations.** Allocations that do not fit a cache class (more than 2 KiB) are followed by a 32-byte canary derived from the key and the address, checked when they are freed (`RedZoneDamaged`). The canary sits in the slack of the buddy block when there is room (the block is rounded up to a power of two, so the common case costs no memory at all) and, for allocations of 32 KiB and more, always, at the price of a larger block when the size is an exact power of two. Below 32 KiB an exact power of two (the M15 slab chunks of 8 KiB, for example) keeps its block and has no gap.
  - **What a fault does.** The check finds the fault under the heap lock, the lock is released, and the allocator panics with a message that names the fault and nothing else (no address, no contents; ADR-172): `heap: double free`, `heap: write after free (poison overwritten)`, `heap: free list corrupted`, `heap: invalid free (...)`, `heap: heap overflow (red zone ... damaged)`. The kernel's panic handler resets in production (ADR-172).
  - **Key slab** (`urmqtt_mm::keyslab::KeySlab<BYTES, SLOTS>`; the kernel's instance is `hardtest::KEYS` in dev images, S7's disk key is the first production user): fixed slots in static memory, outside the heap, written once and read in place through a closure (no copy is handed out); a handle is a slot index plus a generation, so a handle to a slot that was freed is refused (double free, use after free) and cannot wipe the next occupant; freeing overwrites the slot with volatile zero writes and a fence. The ticket keys and the SYN-cookie key keep their own in-place storage, zeroised on rotation (tested in the TLS and TCP crates); moving them in would put `urmqtt-tls` and `urmqtt-tcp` on top of `urmqtt-mm`, and the property they need they already have.
  - **Zeroisation of secret-bearing types.** `Csprng` (the ChaCha20 key and buffered output) is overwritten when it is dropped, tested by looking at the memory a dropped generator occupied (`crates/tls/tests/zeroize.rs`); the PAC key copy in the boot state is wiped with volatile writes after the application processors have it (a plain `= None` would only have changed the discriminant). The traffic secrets, ticket keys, key-exchange secrets and P-256 scalars already used `zeroize` (H0 inventory).
  - **Keys.** `hardening::Seed` mixes the bootloader's entropy values (EFI RNG or `RNDR`), the CPU's own random instruction where it answers (`RNDR`/`RDRAND`) and the counter into 256 bits before the heap exists; the buddy key and the cache key are domain-separated derivations. The CSPRNG is seeded later, from the same and from virtio-rng, so the allocator keys cannot come from it; the boot log says how many bits were credited (`hardening: boot seed of N bit(s)`), never the key. The keys obfuscate and detect, they are not cryptographic: the point is that an overflow or a use after free which does not know them cannot forge a valid link.
- **Cost (measured, `dp-bench` full TLS 1.3 + mTLS + CONNECT handshakes inside the guest, aarch64 HVF, interleaved with the unhardened kernel, 3 runs, the figures are the same to within 0.5% between runs):** 1 core 1941 to 1898 handshakes/s (-2.2%), 2 cores 3854 to 3768 (-2.2%), 4 cores 7620 to 7429 (-2.5%). The first version poisoned the whole class block and checked it with a byte loop: -6.3%; poisoning what was used (-4.5%) and a branch-free word check (-2.2%) brought it down. The checks without poison cost about 1%; the rest is writing and reading the memory.
- **Not done, and why:**
  - **Hardware guard pages for the heap.** The page tables are locked read-only at boot (W^X, no writable alias; the property that makes the tables themselves safe), so a heap allocation cannot get an unmapped page next to it at run time. The canary is a software gap: it finds a linear overflow when the allocation is freed, not at the instruction that wrote it. MTE (ADR-174) would make that synchronous on aarch64 where it exists.
  - **Poison beyond 16 KiB** of a freed buddy block, and **slack beyond the used part** of a cached block: a freed 64 KiB buffer keeps its last 48 KiB (tested, `only_the_first_poison_limit_bytes_of_a_big_block_are_wiped`). Secrets are small and live in small blocks; the limit keeps a freed megabyte buffer from costing a megabyte of stores.
  - **A free with a smaller size than the allocation** leaks the rest of the block and is not detected (the allocator does not record sizes; a larger one is detected, see above).
  - **Detection is probabilistic against an attacker who can write a freed block's tag**: the tag is XOR a secret key and the address, so a write that does not know the key cannot make a block look freed or fresh, but a read primitive that leaks the key defeats it.
- **Tests:** host (`urmqtt-mm`, 39): poison content and wiped old contents, write after free found when the block is reused, a forged link and a forged tag found before they are followed, links are not stored as pointers and depend on the key, double free (also after coalescing), invalid frees (interior, misaligned, outside, never allocated, wrong size), the allocation map view, poison-limit behaviour with randomised workloads of 1 B to 140 kB, the same checks through the per-CPU caches (double free, invalid free, write after free, forged cache link), canary gaps, the key slab (zero on free, stale and double-freed handles, full and recovered). Smoke (`SMOKE_ONLY=hardening`, aarch64 HVF and x86_64 TCG): `double-free`, `heap-uaf`, `heap-overflow` (the VM panics with the fault named and no `URMQTT READY`), `keyslab-zero` (eight keys stored, read back in place, freed, all sixteen free slots zero, stale handles refused; a freed 1000-byte heap block reads back as poison with no byte of the old contents). The hooks are in the `selftest` feature (dev images) and are not in a production image (verified, see ADR-172).

## ADR-171 — Stack protector for the kernel and for SQLite (H4)

- **Status:** Accepted (H4 step 2). Code: `HARDEN` in the `Makefile`, `hardening::stack_guard`, `crates/store/build.rs`, `crates/kernel/linker*.ld`.
- **Context:** a stack buffer overflow in `unsafe` Rust or in SQLite (about 250 000 lines of C at EL1) would overwrite the saved return address. PAC (`pac-ret`) already signs return addresses on aarch64; the canary also stops the overflow *before* the corrupted frame is used, covers x86_64 (no PAC), and catches corruption of the locals between the buffer and the return address.
- **Decision:**
  - Rust: `-Zstack-protector=strong` for the kernel and for `core`/`alloc`/`compiler_builtins` rebuilt by `-Zbuild-std` (the flag is passed with the path remapping through `CARGO_TARGET_*_RUSTFLAGS`, like the other kernel-only flags). The pinned nightly (2026-10-20) accepts it and does not refuse to mix it with the precompiled `core` (unlike `-Zbranch-protection`, ADR-002). SQLite: `-fstack-protector-strong -mstack-protector-guard=global`. 1315 functions of the aarch64 dev kernel carry a canary (about 360 of them C); the text grew by 76 KB (3%).
  - **The guard is one global word** `__stack_chk_guard` (both compilers use a global guard on these targets; the x86_64 code was checked in the disassembly: `movq __stack_chk_guard(%rip)`), and `__stack_chk_fail` prints `STACK SMASHING DETECTED` and calls the fatal path (reset in production). Nothing about the frame is printed (ADR-172).
  - **The guard comes from the CSPRNG as early as that can be done safely.** A canary changed while a protected function is on the stack makes that function stop the machine when it returns, so the guard is only replaced from `kmain_stage2`, which never returns and is the root of the boot CPU's stack: first thing, from the boot seed (bootloader entropy and the CPU's random instruction; ADR-170), then again right after the CSPRNG is seeded (56 random bits; the low byte is zero, the usual terminator canary). The application processors start after both and use the final value; every core shares it. Before the first change, the build-time constant `0x0000_0aff_0d0a_0000` is in use (stage 1 and the code up to the first line of `kmain_stage2`).
  - **The linker scripts keep `.got` in the data segment.** On aarch64 LLVM reads the guard through the GOT; without a rule the linker put the GOT after `.bss`, outside the mapped image, and the first protected function faulted at `__kernel_end`. Both scripts now place `*(.got .got.*)` in `.data`; the entries are filled at link time (the kernel is not position independent until ADR-173).
- **Cost (measured, `dp-bench`, 1 to 4 cores, aarch64 HVF, interleaved):** the stack protector alone costs 2.7% of the handshake rate (1898 to 1845, 3764 to 3672, 7434 to 7243 handshakes/s); with ADR-170 the two together cost 4.9% (1939 to 1845 on one core, 7620 to 7243 on four). `-Zstack-protector=basic` costs the same (1847, 3670, 7248), so `strong` is kept; the cost is the check in the many small crypto and buffer functions, not the number of protected functions.
- **Tests:** smoke `stack-guard-boot` (the canary is renewed from the CSPRNG, the boot reaches `URMQTT READY` with every protected function returning through its check) and `stack-smash` (a dev hook overruns a 16-byte local by 48 bytes: `STACK SMASHING DETECTED`, no `URMQTT READY`; the hook also reports that the canary is no longer the build-time constant), aarch64 HVF and x86_64 TCG.
- **Not done / limits:** one guard for every core and every function (a leak of it, through an out-of-bounds read, defeats the check until the next boot); a canary protects the frame, not data above it; the exception-entry assembly stubs and the Limine entry are not compiled code and carry none.

## ADR-172 — Panic and fault policy: no secrets, no layout in a report; dev hooks are compiled out of production (H4)

- **Status:** Accepted (H4 step 3). Code: `hardening::fault_policy`, `trap.rs` (exception and panic reports), `mm::heap_fault`, `hardtest.rs`, `scripts/check-prod-hooks.sh`.
- **Context:** the exception report printed every general-purpose register and a panic printed its formatted message. At the moment of a fault the registers hold whatever the code was working on: a key, a plaintext, a Diffie-Hellman scalar. A panic message is formatted from the caller's data. The report goes to the serial console and the screen, which in a VPS is the provider's VNC console and whatever logs it, and it stays on the screen for 60 s before the machine resets. With KASLR (ADR-173) absolute addresses in it would also tell an attacker with a console where the kernel is.
- **Decision:**
  - **Production policy** (any image whose `[env]` is not `dev`; a dev image applies it with the test word `redact`): an exception report has the exception, its decoded cause (`EC=… data abort …, translation fault`), the class of the faulting address (`FAR is in: main stack guard page …`, no address), and `pc = kernel+0x6d3d8` (the offset into the image, readable against the build's symbols; `outside the kernel image` if it is not in it). It has no register, no stack and no memory dump and no absolute address. A panic has its source location and its message **only when the message is a fixed string**; a message with formatted arguments is replaced by `(message withheld: it has formatted arguments; production policy)`. The allocator's faults (`heap: double free`, …), `__stack_chk_fail` and the other panics with a literal message therefore stay readable; `expect("…")` and `assert!(…)` with arguments do not.
  - **Dev policy** is unchanged: the full register dump and the full message, because a developer needs them and the dev image holds no production secret.
  - **Reset in production** was already the rule (`power::fatal`: the message stays up for 60 s, then the machine resets, so a production VM comes back by itself; a smoke run powers off instead) and is not changed.
  - **The hooks of H4 are compiled out of production.** `hardtest.rs`, the `TestFault` variants (`HeapDoubleFree`, `HeapUaf`, `HeapOverflow`, `StackSmash`, `FaultSecrets`, `FaultSecretsOpen`, `PanicSecret`), their `test=` words and the `redact` word exist only with the `selftest` feature, which `make build` enables for `ENV=dev` only (as for `crypto_bench`). A production image's command line parser never sees the words (it ignores the whole line anyway). `scripts/check-prod-hooks.sh PROD_ELF [DEV_ELF]` checks it on the binary: seven strings that only the hooks print, and the 16 bytes of the test key, must not be in a kernel built without the feature and must be in the dev kernel (so the check cannot pass because a string was renamed). Run on a non-dev build of both architectures (`ENV=h4prod`, the bench template with the dev certificates, untracked) both pass: `prod-hooks-absent: 7 hook strings and the test key are not in h4prod-a64.elf (all present in the dev kernel)`, likewise `h4prod-x86.elf`.
- **Tests (smoke `SMOKE_ONLY=hardening`, aarch64 HVF and x86_64 TCG):**
  - `fault-secrets`: with `redact`, a data abort is taken with the test key in six registers (`x20`..`x25` / `r10`..`r15`), on the stack and on the heap. The serial log must not contain the key as hex or as text, any `xN=0x…`/`RNN=0x…` register value, `FAR=`, `CR2=`, `ESR=`, `RIP=` or `RSP=`, and must contain `pc = kernel+0x…; registers, stack and memory withheld (production policy)`.
  - `fault-secrets-open`: the same fault without `redact` must show the key words in the register dump: the control that proves the grep can see them.
  - `panic-secret` / `panic-secret-open`: a panic formatted from the key. Withheld with `redact` (no key bytes, no message text); printed in full without.
  - `double-free-prod`: the allocator's fault under the production policy is still named (`heap: double free`).
- **Not done / limits:** the report still says which function faulted (offset), what kind of fault, and the location of a panic; a core dump or a crash log kept across the reset does not exist (nothing is written to disk). The log ring that the console `$SYS/console/out` mirrors carries INFO lines, not fault reports, and log lines are written by code that decides what it formats (the secrets audit of H10 covers them). The x86 report additionally prints the vector and the IST stack number in the dev policy only.

## ADR-173 — KASLR: a position-independent kernel slid by Limine, and a random place for every region (H4)

- **Status:** Accepted (H4 step 4). Code: `Makefile` (`PIE_AARCH64`, `PIE_X86_64`), `crates/kernel/linker*.ld`, `crates/store/build.rs`, `scripts/mkiso.sh` (`kaslr: yes`), `layout.rs` (`randomise`), `hardening.rs` (`log_placement`).
- **Context:** the kernel was linked at a fixed address (`0xffffffff80000000`) and every region (heap, its bookkeeping, the per-CPU stacks, the page-table alias, the MMIO window) sat at a fixed virtual address. A memory-safety bug in `unsafe` Rust or in SQLite would have known addresses to aim at (gadgets in the image, the heap's free lists, a return address on a known stack).
- **Decision:**
  - **The image is position independent** on both architectures: `-Crelocation-model=pie -Clink-arg=-pie` for the kernel and for `core`/`alloc` (build-std), `-fPIE` for SQLite. The linker scripts gain what Limine needs from a relocatable kernel: a `PT_DYNAMIC` header, `.dynamic`, `.rela.dyn` and the dynamic symbol tables, and `.data.rel.ro` inside the read-only segment (Limine relocates before the kernel runs; the kernel then maps the segment read-only). The dev kernels carry 1573 (aarch64) and 1627 (x86_64) relocations, **all `RELATIVE`**, which is all Limine applies. `limine.conf` asks for `kaslr: yes` explicitly. The x86_64 kernel keeps the kernel code model of its target (ADR-042) and still links as PIE with RIP-relative addressing; nothing needed changing in the assembly.
  - **Limine slides the image.** Measured, from the `kaslr (dev only)` line of the boot log: aarch64 (HVF) 30 boots, 30 different slides, minimum `0x3d5000`, maximum `0x7cbef000`, every slide a multiple of 4 KiB and none of 2 MiB; x86_64 (TCG) 16 boots, 16 different slides, maximum `0x7a371000`, 4 KiB steps. So the slide is uniform-looking over about 2 GiB in 4 KiB steps: **about 19 bits** (log2 of 0x7cbef000/4096 = 19.0). 30 samples show the range and the step, not the uniformity; the claim is "about 19 bits" as an upper bound from the observed range, not a proof of the distribution.
  - **Every other region has its own random place, chosen from the boot seed (ADR-170) before anything is mapped**, inside its window: the heap by multiples of 1 GiB (the buddy heap needs its size as alignment; 1 GiB covers every size) in a 4 TiB window, **12 bits**; the heap bookkeeping, the per-CPU stacks and the page-table alias by 2 MiB in 4 TiB windows, **21 bits each**; the MMIO window by whole GiB inside its 512 GiB top-level slot, **9 bits**. The per-CPU data (the `PerCpu` array, the exception frames) is in `.bss` of the slid image; the per-CPU stacks are the randomised stack region. The boot log says how many bits each placement has (`kaslr: heap 12 bit(s), heap bookkeeping 21, stacks 21, page-table alias 21, mmio 9; kernel image slid by the bootloader (seed 256 bit(s))`) and **never an address**: the addresses are on one extra line printed only by a dev image (`kaslr (dev only): …`), and the other lines that carried virtual addresses (the console UART mapping, the stack top) now carry them in dev images only. Fault reports show the program counter as an offset into the image (ADR-172).
  - **What is not randomised, and why that is stated and not hidden:**
    - **The HHDM** (Limine's direct map of all RAM, at a fixed base) and everything reached through it: the DMA regions (virtio queues and packet buffers, the SQLite arena, the live-mode store) and the physical frames of the heap itself. An attacker who can read or write at a chosen address can reach the heap's data through the HHDM at a known address. Limine can randomise the HHDM base (`randomise_hhdm_base`); using it means placing the kernel's own windows around the HHDM's random position instead of at fixed windows, which is more than this step; it is the next KASLR item.
    - The page-table-pool size and the number of page tables are not secret and are not hidden.
    - The ordering of the regions (heap below stacks below alias) is fixed by the windows; only the places inside them move.
- **Cost (measured, `dp-bench`, aarch64 HVF, 3 interleaved runs, on a machine that other jobs were loading, so the noise was about 3%):** with the position-independent code and the tagging code present (inactive on HVF) the 4-core rate is a median 6740 handshakes/s against 6921 for the previous step (-2.6%) and 7107 for the unhardened kernel in the same session (-5%); the one-core figures overlap (1747 to 1825 against 1663 to 1840). Cumulative cost of ADR-170, 171 and 173 on the handshake path: **about 5% to 8%**, above the 'few percent' aim at its upper end; `db-bench` (disk bound) shows no difference beyond its run-to-run spread (base 45 to 57 k inserts/s, final 42 to 52 k). Booting takes the relocation pass of the bootloader (1.6 thousand 8-byte stores).
- **Tests:** smoke `kaslr-differs` (aarch64 HVF and x86_64 TCG): the same image booted three times must reach `URMQTT READY` each time and print a placement line where each of the six values (image, heap, bookkeeping, stacks, alias, mmio) takes at least two distinct values over the three boots (the narrowest placement is 9 bits, so three equal boots by chance are 1 in 262 144), and the production line with bit counts and no address must be present. The whole default smoke suite runs on the position-independent kernel with randomised regions on both architectures.
- **Not done:** the HHDM (above); the image is slid as a whole, not per section (function-granular randomisation is out of scope); the slide is chosen by Limine, whose generator is its own (it uses the same firmware entropy); the stack canary and the allocator keys come from the boot seed, not from the slide.

## ADR-174 — Memory tagging (MTE) for the heap on aarch64, tested under TCG (H4)

- **Status:** Accepted (H4 step 5). Code: `crates/arch-aarch64/src/mte.rs`, `paging.rs` (`MemType::NormalTagged`), `mmu.rs`, `esr.rs`, `mm::cached::Tagging`, `vm.rs`, `boot_aarch64.rs`, `smoke.sh` (`mte-*`), `run-qemu.sh` (`URMQTT_MTE=1`).
- **Feasibility, measured first:** QEMU's `virt` machine with `mte=on` under TCG (`-cpu max`) boots EDK2, Limine and the kernel and reports `FEAT_MTE2` (`cpu features: … mte=true`). HVF does not implement it (`mte=false`): on Apple Silicon and on every machine without FEAT_MTE2 the code stays off and the heap is mapped as before.
- **Decision:**
  - **Detection and mapping.** Stage 1 decides from `ID_AA64PFR1_EL1.MTE >= 2`. The heap (not the DMA regions, not the stacks, not the SQLite arena) is mapped **Normal Tagged** (`MAIR` index 5, `0xf0`, written only when the CPU has the feature, because the encoding is reserved without it).
  - **Checking.** On the boot CPU, before anything allocates with tags and before the other cores copy its registers: `TCR_EL1.TBI1` (translation ignores the tag byte), `TCR_EL1.TCMA1` (pointers whose tag is `0b1111` match every tag: all of the kernel's ordinary pointers, and the allocator's own headers, poison and canary accesses), `SCTLR_EL1.ATA` and `TCF = synchronous`. Each core sets `GCR_EL1` (tags 0 and 15 are never drawn) and the seed of `irg` (`RGSR_EL1`) from the boot seed. Synchronous in every build for now; asynchronous mode needs `TFSR_EL1` handling that is not written, so "configurable in production" is **not done**: the mode is a constant (`Mode::Sync`).
  - **Tagging.** A live allocation of up to 1 MiB gets one random tag from 1 to 14 over its bytes rounded up to 16 (`irg` + `stg` loop) and is returned as a pointer carrying it; freeing sets the tags back to 0 first. A stale pointer therefore faults at the instruction on every access, and a linear overflow faults at the first byte of the next 16-byte granule when that granule is free or untagged (always) or belongs to another allocation with a different tag (13 times in 14). The allocator keeps using the untagged address internally; the canary, poison and double-free checks of ADR-170 are unchanged and remain the defence where MTE is not available.
  - **Reporting.** A tag check fault is a data abort with `DFSC = 0b010001`; the report says `synchronous tag check fault (memory tagging)` (`esr.rs`) and follows the fault policy of ADR-172.
- **Tests:** host: `Tagging` bookkeeping in the cache tests, the fault status decoding. Smoke (aarch64 under TCG with `URMQTT_MTE=1`; skipped with a line saying why on HVF and x86_64): `mte-boot` (the boot reaches `READY` with the line `mte: synchronous tag checking on; …` and no tag fault), `mte-uaf` (a read through a freed pointer: `EC=0x25 data abort (same EL), read, synchronous tag check fault`), `mte-overflow` (a write in the last granule is accepted, the write one granule further faults), `mte-mqtt-tls` (the whole broker with TLS 1.3 handshakes, MQTT and the database under tag checking: pubsub, retained, QoS 1, wrong-CA and revoked-certificate refusals pass with no tag fault: no false positive in the workload).
- **Cost:** none where MTE is absent (HVF measurements are those of ADR-173; the only difference is a feature test at boot). Under TCG the tag stores are emulated; no number is quoted for them because TCG timing says nothing about hardware. On real MTE hardware the cost is the tag stores (one `stg` per 16 bytes of every allocation and again at free) and the synchronous check on every tagged access; it has not been measured here, there is no such machine in this setup.
- **Not done / limits:** only the Rust heap (up to 1 MiB per allocation) is tagged. The SQLite arena (`memsys5` over one DMA-region allocation), packet buffers (DMA regions) and the stacks are not. The granularity is 16 bytes and a tag collision is 1 in 14. Asynchronous mode and a production switch (`[hardening] mte`) are not implemented. No tested hardware other than QEMU TCG.

## ADR-175 — kCFI evaluated and not adopted (H4)

- **Status:** Accepted (H4 step 6): **not adopted**.
- **Context:** SECURITY-PLAN H4 asks to evaluate `-Zsanitizer=kcfi` (forward-edge control-flow integrity for indirect calls), including the callbacks SQLite makes into Rust and the other way round, and to adopt it only if it works cleanly.
- **Evaluation (2026-10-31, pinned nightly 2026-10-20, rustc 1.101.0-nightly 07e526db9):**
  1. `HARDEN += -Zsanitizer=kcfi -Zsanitizer-cfi-normalize-integers` (the second flag is required for type ids that agree with clang's `-fsanitize=kcfi -fsanitize-cfi-icall-experimental-normalize-integers`, which SQLite's side would need). The build of the dependencies stops with an **internal compiler error** in `rustc_middle::ty::normalize_erasing_regions` ("Failed to normalize Alias … `der::referenced::RefToOwned::Owned` … dyn …") while compiling `der` and `spki` (the X.509 and ASN.1 crates under the TLS stack).
  2. The same error without `-Zsanitizer-cfi-normalize-integers`: it is the sanitizer's type-id computation for trait objects with associated types, not the integer normalisation.
  3. The flags are restored; nothing is left in the tree.
- **Decision:** not adopted. A compiler that crashes on the dependency graph cannot be a build requirement of a security product (the reproducible build, M17, depends on a toolchain that builds). There is therefore **no measured cost**: no kernel was produced to measure. The evaluation is repeated when the pinned nightly is bumped (ADR-002), with the two commands above; if the ICE is gone the next obstacles are known: SQLite's function pointers need the C side built with `-fsanitize=kcfi` and the normalised-integer option, the Rust `extern "C"` callbacks given to SQLite need matching type ids, and the exception handler must decode the `brk` that kCFI raises on a mismatch.
- **What covers part of the ground meanwhile:** BTI (every indirect branch must land on a landing pad, aarch64), PAC on return addresses, W^X with locked page tables (no code injection), the randomised layout (ADR-173) and, with memory tagging, the heap objects that hold function pointers (ADR-174). On x86_64 there is no forward-edge protection beyond W^X and KASLR (Intel CET is the X-track's item).

## ADR-176 — H4b (IOMMU) deferred with bare metal (H4)

- **Status:** Accepted (deferral).
- **Context:** H4b adds DMA isolation (VT-d, AMD-Vi, SMMUv3) against a malicious or buggy device writing anywhere in RAM. The first release targets VPS (KVM) only (PLAN.md, 2026-10-31): the devices are the hypervisor's virtio devices, which are part of the trusted computing base the VM cannot defend against; there is no physical device whose firmware could be hostile, and a virtio-iommu in the guest would protect against nothing the host does not already control.
- **Decision:** H4b, its `iommu-dma-blocked` smoke scenario and the "refuse to run on bare metal without an IOMMU" rule move with Phase 10 (X12 to X16) after the first release. Nothing is implemented, measured or claimed here; the README and docs make no DMA-isolation claim, and `docs/SECURITY.md` lists it among the residual risks for bare metal.

## ADR-200 — x86_64 `memcpy`/`memmove`/`memset` in assembly, with a profile build (PERF)

- **Status:** Accepted (PERF).
- **Context.** The kernel took its mem functions from compiler_builtins (`compiler-builtins-mem`). On x86_64 without ERMSB those run three `rep` instructions (`movsb`, `movsq`, `movsb`) for every call, whatever the size. A `rep` costs 20 to 30 cycles before it moves a byte: measured on the Contabo VPS (AMD EPYC family 23 model 1, KVM), a 1-byte copy took 55 to 65 cycles, 17 to 64 bytes 60 to 75, 256 bytes 80 to 140. The `memprof` build (below) counted the calls of the server side of the real code paths: a handshake with CONNECT makes 766 mem calls (about 94% of them below 1 KiB, about 370 of 16 bytes or less), a 64-byte TLS record in and out 43, a publish to 16 subscribers 53. Share of the server-side time spent in them, before: handshake 7.1% (dev configuration), TLS records of 64/256/1024/4096 bytes 39/37/24/13%, fan-out to 1/16/128 subscribers 17 to 34%.
- **Decision.** `crates/arch-x86_64/src/mem.rs`: `copy` (memcpy and memmove) and `set` (memset) are naked assembly with a path per size. 0 to 3 bytes: first, middle and last byte. 4 to 7 and 8 to 16: two overlapping 4- or 8-byte moves. 17 to 128: two, four or eight overlapping 16-byte SSE2 moves (loaded before any store is made, so overlapping `memmove` is correct in both directions). Above 128: a 64-byte loop with an aligned destination that keeps the first 16 and last 64 bytes in registers and stores them last; backward (destination inside the source) the same from the end. From 2 KiB, `rep movsb`/`rep stosb` when CPUID reports ERMS (`mem::set_fast_rep`, called from `cpu_summary`; until then the SSE loop). `memcpy`, `memmove` and `memset` are `jmp` stubs into them (`#[no_mangle]`; compiler_builtins' are weak). aarch64 is unchanged. The `memprof` feature of the kernel (dev only, `test=dp-bench`) defines the symbols itself, counting calls by size bucket and timing them with `rdtsc` inside "server windows" of core 0, and runs every phase with the old code (`mem::baseline`, feature `mem-baseline`) and the new one in the same boot, 15 rounds each, reporting the best round.
- **SIMD state.** Only `xmm0` to `xmm8` (SSE2) are used. The target is hard-float with SSE (ADR-042), so compiled kernel code already uses them everywhere, and the exception entry saves them with FXSAVE. No AVX: the kernel keeps no AVX state (ADR-042), and AVX2 would be wrong here until the entry uses XSAVE. The direction flag stays clear (the old backward copy set it).
- **Alternatives.** `rep movsb` for everything (what `target_feature = "ermsb"` would give: still 25+ cycles per call; also unusable before CPUID is known). AVX2 loops (no AVX state). Non-temporal stores for very large blocks: not done. The only large copy in the product is the diagnostic's, which is limited by memory bandwidth: the new code gave 4649 MiB/s against 2193 to 5380 MiB/s with the old on the same VPS (the host varies run to run by more than that), read 9.97 GiB/s, so there is no evidence that it would help, and the stores would need alignment and a size threshold that cannot be set without the cache sizes of a VM.
- **Tests.** `crates/arch-x86_64/src/mem/tests.rs`, run on an x86_64 host (Linux, or macOS under Rosetta; not Miri, which cannot run assembly): `copy` against a Rust reference for every size to 300 and 23 sizes around every boundary up to 1,000,003, all 32 source and 32 destination alignments, guard bytes either side; overlapping moves for about 60 shifts (both signs, around 16/32/64/128/256 and n) at 16 base alignments (sizes to 4200 and 65,541); `set` for every size, alignment and 7 values; all with the `rep` paths on and off. A mutation (the backward branch removed) fails them. They pass on Rosetta and natively on an AMD EPYC 9354P (ERMS and FSRM).
- **Result (Contabo VPS, KVM, EPYC family 23 model 1, same boot, best of 15 rounds, server side, old to new).** Handshake with CONNECT (dev configuration, 766 calls): 779,209 to 641,099 cycles (278.8 to 229.4 us), -17.7%; mem calls 55,268 to 12,441 cycles (7.1% to 1.9%). TLS record in and out: 64 B -26.4%, 256 B -19.6%, 1024 B -16.1%, 4096 B -6.6%. Publish fan-out: 1 subscriber 64 B -6.9%, 1 x 1024 B -15.1%, 16 x 64 B -33.7%, 16 x 1024 B -25.4%, 128 x 256 B -24.6%. Per call (read from the screen, approximate): 1 to 8 bytes 50-65 to 7-12 cycles, 17 to 64 bytes 60-70 to 8-11, 129 to 256 bytes 85-135 to 13-53, 1025 to 2048 bytes 155-210 to 99-135.
- **Consequences.** `mem.rs` is 700 lines of assembly in a TCB crate, with the register set and the size paths documented in the file. A bug here corrupts memory anywhere: the differential tests are the guard, and any change to the file must re-run them on a real x86_64 host. The `memprof` build is a dev tool (its symbols replace the production ones; never in an image for use).

## ADR-210 — SQLite runs as an unprivileged component: the `dbworker` (H6)

- **Status:** Accepted (H6 step 1). Closes the design part of gap H0-W8; the sections "What is isolated" and "What is not" are the claim, and nothing else is.
- **Context.** SQLite (254,268 lines of C, ADR-030) parses the database, the WAL and the journal from the volume, which an attacker with write access to the disk image (a crafted or tampered volume) controls. It ran at EL1 / ring 0 with every kernel right. A memory-safety bug in it was a kernel compromise: keys in RAM (ticket keys, TLS state of other cores), page tables, every other core's state. SQLite already runs on exactly one core at a time (the DB core, ADR-032) and talks to the rest of the system through two narrow things: the `Db`/`Stmt` wrapper (`store/src/db.rs`, about 400 lines) and a VFS of fourteen callbacks that only call `Disk` (`store/src/vfs.rs`). That is a ready-made boundary.
- **Decision.** SQLite, its libc shims and its heap move into a separate program, the **dbworker**, that runs at **EL0 (aarch64) / ring 3 (x86_64)** in its own address space:
  1. **Separate image.** `crates/dbworker` is a `no_std` binary linked at a fixed low address with its own linker script and no symbol of the kernel (not PIE: it is a lower-half user program; the kernel keeps being slid). It contains the SQLite amalgamation (unchanged), `store/src/libc.rs`, a request dispatcher and a VFS shim whose callbacks are system calls. The kernel embeds the image and copies it into fresh frames at every start of the worker. The kernel no longer links SQLite at all.
  2. **Separate page tables, built once.** A worker space has: code (RX, user), read-only data, data and bss (RW, NX), a stack with a guard page, the SQLite heap (`storage.sqlite_heap_mb`, ADR-008; the frames the kernel used to give SQLite directly) and one **shared window** (request and response header plus an I/O area of 1 MiB). aarch64: the tables hang off `TTBR0_EL1` and the lower half stays disabled (`TCR_EL1.EPD0`) except while the worker runs. x86_64: a second PML4 whose upper half is the kernel's (same sub-tables) and whose lower half is the worker's, with `CR3` switched on entry and on leave. Every user page is non-executable for the kernel (`PXN` / `SMEP`) and unreadable and unwritable for it by accident (`PAN` / `SMAP` stay on during the whole life of the kernel; the kernel never dereferences a user address, see 4).
  3. **Entry and exit.** The kernel calls the worker synchronously, on whatever core owns the store (the boot CPU while it opens the store, then the DB core; one call at a time under a lock): it loads a fresh user context at the dispatcher's entry, with `ERET` / `IRETQ`, and the call ends when the worker executes the *exit* system call, when it faults, or when its time budget runs out. The kernel's callee-saved state is kept in a resume record, so every end of a call is an ordinary return into the caller (`enter_user() -> Exit`). Interrupts are taken in user mode like anywhere else (the handler runs on the kernel stack, then returns into the worker), so the worker never delays the timer, the NIC or the other cores.
  4. **The kernel never reads or writes a worker pointer.** Requests and responses are bytes in the shared window, which the kernel reaches through the direct map (its own alias of the same frames). Nothing is "copied from user" and so no `stac`/`clac`, no `LDTR`, no `PAN` toggling exists. Every length and offset that comes back is checked before use.
  5. **Fault containment.** A synchronous exception from user mode (data/instruction abort, undefined instruction, alignment, `BRK`, `#PF`, `#GP`, `#UD`, divide error ...) or a budget overrun ends the call with `Exit::Fault`, is logged (one line: kind, address, pc, call number, worker restart count), counted (statsd `urmqtt.dbworker.restarts`, `faults`, `calls`, `syscalls`, `us_inside`), and the worker is **restarted**: its writable frames are zeroed, the image is copied again, and the store is reopened from the WAL by the same path as a boot (`open_or_restore`). The in-flight operation fails with a storage error exactly as an I/O error would; the broker keeps serving from memory. A fault never reaches the kernel's fatal-exception path.
  6. **Budget.** A call may run for 30 s of wall time, checked on the timer tick (a constant of the kernel, not a setting: there is no configuration that makes a longer call right; the longest legitimate call is a `quick_check` of one table, which the scrubber paces, or a 64-page backup step); beyond it the worker is treated as stuck: fault, restart.
- **What is isolated.** After this change a bug in SQLite (or in the dispatcher, the VFS shim or the libc shims) can: corrupt the worker's own memory, return wrong data, ask for any I/O the VFS interface allows, and burn its budget. It **cannot**: read or write kernel memory, TLS keys, ticket keys, the CSPRNG state or other cores' data (not mapped; `PAN`/`SMAP`/`PXN`/`SMEP` and the page tables hold); run kernel code or inject code (W^X, user pages never kernel-executable); touch any device or MMIO; issue any I/O except the system calls below.
- **What is not.**
  1. **The kernel trusts what the worker returns, after validating it.** The worker still decides the content of what it reads and writes in the database: a compromised worker can lie to the broker (wrong retained messages, sessions, revocation list rows) and can write garbage to the database, WAL and journal regions. That is the same as a crafted volume could already do through SQLite's own parsing; the kernel's checks (lengths, UTF-8, handle ids, row shape) stop it from becoming a kernel bug, not from being a wrong answer. Revocation and the allow-list are read from the store at boot: a worker that returns an empty revocation list un-revokes certificates. This is stated in SECURITY.md.
  2. **The VFS interface is the attack surface** and is small (system calls below); each is validated against the volume layout: only the database, WAL, journal and backup *files* as the layout defines them, never the superblock, the backup headers, telemetry or other partitions, and never outside the region's current size limit.
  3. **Same CPU, no speculation barrier.** The worker shares the core with the kernel (it runs on the DB core, between its other duties) and there is no page-table isolation of the kernel half from the worker (no KPTI): Meltdown-class and Spectre-class leaks from the worker to kernel memory are **not** prevented by this change. KVM guests on current hosts get the host's mitigations; no claim is made.
  4. **Denial of service** of the storage path is possible (the worker can loop, fault repeatedly, or hammer the disk within its budget). The budget and the restart counter bound it per call; a worker that faults at every start is not restarted forever: after 5 restarts within a minute the store is declared failed (storage degraded exactly as an unreadable volume is today, `refuse_or_degrade`).
  5. **PAC key.** aarch64 PAC keys are shared by EL0 and EL1 in one translation regime. The worker is built with BTI but not with pointer authentication, and a compromised worker can execute `PACIA` as an oracle with the kernel's key for any pointer and modifier of its choice. It cannot see the key or any kernel stack value, so no signed kernel pointer can be forged from it by itself; the residual risk is recorded.
  6. **NMI on x86_64** arriving in the two instructions between a ring-3 entry's privilege test and `swapgs` would run on the wrong GS. The kernel enables no NMI source; QEMU raises none.
- **Alternatives.** (a) Run SQLite in a *Rust* sandbox (WASM or similar): a 254k-line C library compiled to WASM and interpreted in `no_std` is a port of a runtime we would then also have to trust; much slower. (b) Replace SQLite by a Rust store: abandons the one component whose reliability is the point of the product (ADR-030). (c) Split at the `Store` level (about 40 methods) instead of at the SQLite C API: fewer calls but the worker would have to contain the Rust store logic, the layout and the schema; the C API boundary keeps the fixed SQL in the kernel and the worker generic and small. (d) A per-connection process model with several workers: SQLite is single-writer here; one worker is the whole need. (e) Hypervisor-style isolation (EL2 / VMX): needs a feature the VPS guests do not have.
- **Increments** (each committed and verified): (1) this ADR, user/kernel mode on both architectures, a "hello" worker, the fault-containment test; (2) the protocol and the system calls, SQLite moved into the worker. There is no off switch: the direct-linked SQLite is not built into the kernel any more (a switch would have kept 254k lines of C in the privileged build and doubled the test matrix); the host tests still link SQLite directly and, with the `loopback` feature, through the protocol; (3) a fault-injection scenario on the real store path, documents, measured cost.

## ADR-211 — The worker interface: calls, system calls, validation (H6)

- **Status:** Accepted (H6 step 2).
- **Context.** ADR-210 puts SQLite at EL0 / ring 3. The boundary has to be small enough to audit and has to keep the store's behaviour identical.
- **Decision.**
  1. **Where the line is.** At the SQLite C API as `db.rs` uses it (`crates/store/src/remote.rs`, 32 functions with the names and signatures of the C ones) and at the VFS (`vfs::syscall`, 12 calls). `db.rs`, `store.rs`, `backup.rs`, `scrub.rs`, the schema and every fixed SQL string stay in the kernel and do not change; the worker is generic.
  2. **Calls into the worker** (`urmqtt_usys::proto::op`): `INIT`, `VERSION`, `OPEN`, `CLOSE`, `DBCONFIG`, `EXTENDED`, `EXEC`, `PREPARE`, `STEP`, `RESET`, `FINALIZE`, `ERRMSG`, `CHANGES`, `BACKUP_INIT`/`STEP`/`FINISH`, `STATUS`. A request is a header (operation, six words) and bytes in the I/O area of the shared window; the answer is two result words and bytes. Handles (`db`, `stmt`, `backup`) are small integers the worker picks; the kernel's `*mut sqlite3` is a box of its own bookkeeping holding that number and the worker's **epoch** (restart count), so a handle from before a restart is dead and answers `SQLITE_IOERR | 0x7f00` without entering the worker.
  3. **Fewer entries than calls.** Binds are queued and ride with the `STEP` (one entry for a record write: bind, bind, bind, step), a reset of a statement that is finished (done or failed) is queued too, a reset of a statement that is mid-row is immediate (SQLite holds its locks until then; a lazy reset there broke `DROP TABLE` in the tests), `extended_errcode` and `errmsg` share one entry, `sqlite3_errstr` is a table in the kernel, and a row comes back whole in the step that produced it (every column: type, `int64`, and the bytes of TEXT and BLOB), so `column_*` are local and the pointers they return stay valid until the next step, reset or finalize, as SQLite promises. Rows up to 4 KiB come back in the same entry; a bigger one is fetched by a second call (`FETCH`) at its exact size, so the kernel keeps no row-sized buffer (a first version kept 1 MiB in the kernel heap, a 2 MiB block with the allocator's rounding, and the `storm` scenario, which pretends the heap is 8 MiB, admitted 118 connections instead of the hundreds it expects).
  4. **System calls from the worker** (`proto::vfs`): `OPEN`, `DELETE`, `EXISTS`, `READ`, `WRITE`, `TRUNCATE`, `SYNC`, `SIZE`, `RANDOM`, `TIME`, `SLEEP`, `LOG`, plus `EXIT`. Files are numbers 0 to 3 (database, WAL, journal, backup slot); nothing else can be named. Data moves through the I/O area: the kernel reads from the disk into it and writes from it, so no kernel code ever dereferences an address the worker gave. Every offset is checked before it is added to a length (`checked_add`), lengths must fit the 1 MiB area, a truncate above 16 TiB is refused before the disk layer sees it, `SLEEP` is clamped to 100 ms (the worker must not be able to park the core), `LOG` text is cut at 400 bytes and printable ASCII only, and the backup file exists only while a slot is attached. The disk layer bounds every access to the region of that file.
  5. **What the kernel checks of what comes back.** Rows: `decode_row` checks the column count (at most 64), each type (SQLite's five), every length against the buffer; anything else is `SQLITE_CORRUPT` for that call. Error messages: cut at 255 bytes, printable ASCII. Handles are only compared and returned. The version string: printable ASCII, at most 32 bytes. Result words are narrowed (`as c_int`), so a wild value is a wrong result code, not a crash.
  6. **Size limit.** A request or a row larger than the I/O area (1 MiB) fails with `SQLITE_TOOBIG`. The largest legitimate item is a retained or queued payload, at most `limits.max_packet_size` (4,096 in every shipped configuration).
  7. **Restart.** After a worker fault the kernel's `Worker` (db.rs) sees the epoch change at the top of its next step, drops the backup job and the scrub pass (their handles are dead), tells the data cores the open transaction failed, and reopens the store with `open_or_restore`, the path a boot takes. If that fails (a volume that crashes the worker every time) it retries every 5 s until the worker is given up on (ADR-210, more than 5 restarts in a minute); then storage is unavailable until the next boot and the requests of the data cores are dropped and counted, so the rings keep flowing and the broker keeps serving from memory.
- **Alternatives.** Splitting at the `Store` level (about 40 methods, but the worker then contains the schema and the SQL); a general RPC for every SQLite call (more entries, no gain); shared memory for rows (the worker could change a row while the kernel reads it).
- **Consequences.** The store crate has four configurations: the kernel (no C library), the dbworker (`worker`: C library, dispatcher, VFS shim), the host tests (C library linked directly: unchanged) and the host tests through the protocol (`loopback`: the worker's code in process, calling the kernel's real `vfs::syscall` on the same shared window). The whole store suite (131 tests) passes in both host configurations.

## ADR-212 — How the worker is built and shipped (H6)

- **Status:** Accepted (H6 steps 1 and 2).
- **Decision.** `crates/dbworker` is a separate program: its own linker script (`PT_LOAD` per permission class at 0x400000), static, non-PIE, small code model, built by the kernel's `build.rs` with a nested `cargo build` into a target directory under the kernel's `OUT_DIR` (the outer cargo holds the lock of the workspace's own), with its own rustflags (path remapping from the outer build for reproducibility, `-Zstack-protector=strong`, aarch64 `-Zbranch-protection=bti` without pointer authentication) and its own C flags (`crates/store/build.rs`). The ELF is embedded in the kernel with `include_bytes!`; the loader parses the program headers and refuses a segment that is outside the window or both writable and executable. The worker has no allocator (a global allocator that always fails guards the unused code of the store crate it links), no symbol of the kernel, and its `libc.rs` shims (`strlen` and friends) moved with it. Binary size: aarch64 779 KB (SQLite -Os about 600 KB).
- **Why not `-Zbindeps` or a Makefile step.** Artifact dependencies are unstable and untested with `-Zbuild-std` and the custom x86_64 target; a Makefile step would leave `cargo clippy -p urmqtt-kernel`, `make check`, `make repro` and CI without the worker. Cargo does it in one place.
- **Consequences.** A kernel build takes one more `cargo` run and about 20 s of extra compilation once; a change under `crates/dbworker`, `crates/usys`, `crates/store` or `vendor/sqlite` rebuilds it (`rerun-if-changed`). `scripts/check-arch-leaks.sh` allows assembly in `crates/usys` (the system-call stub).

### Measured cost of ADR-210 to ADR-212 (aarch64 HVF; x86_64 not quotable)

Entering and leaving the worker: 1.1 us per round trip. `test=db-bench` (5 000 inserts in 50 transactions): best of six 54.7k ops/s against 61.9k with SQLite in the kernel (-11.6%), median 53.3k against 58.4k (-8.7%), one insert per transaction -1%; the I/O is identical (1 572 writes, 319 flushes). `backup-bench`: commit latency during a backup unchanged (mean 533 us against 532), a 16-page step 930 us against 1 081; copying the whole database in one call 635 ms against 514 ms. Details and conditions in docs/PROGRESS.md (H6). The x86_64 cost (a `CR3` write per entry and per exit, no PCID) was not measured on KVM; PCID would remove the TLB flushes and is an open item.

## ADR-213 — How the performance numbers are measured, and what they may be quoted for (X11)

- **Status:** Accepted.
- **Context.** X11 asks for numbers the project can quote and a reader can reproduce, with Mosquitto measured on the same VPS. Earlier numbers came from three kinds of setting that do not carry over: in-guest benchmarks (QEMU, no network), a Mac in front of QEMU's user-mode network (capped by slirp and by macOS's TIME_WAIT, ADR-080) and a Mac in front of the VPS (one source address, 35 ms, ADR-080). The Mac cannot reach the VPS at all now (its provider path resets port 8883).
- **Decision.**
  1. **The load comes from a Linux host that reaches the VPS** (the build server: 4 vCPU KVM guest, EPYC 9354P, about 15 ms from the VPS). The generator runs under `taskset` on two CPUs and `nice -n 19`, a run lasts about 10 s of measurement, and `scripts/x11-bench.sh` waits for the host's load to fall and checks the web server's response time before every run. The host is shared and noisy (CPU steal of 30-65 % was seen); every run records the host's steal and idle share, the generator's own CPU use and, for urMQTT, the busy percentage of its cores from `$SYS`. A figure at which the generator or the host is the limit is a lower bound and is labelled so.
  2. **`urmqtt-loadgen` gets a `pubsub` mode** (publishers, subscribers, topics, QoS 0/1, payload, fixed rate or flood, QoS 1 window) with end-to-end latency stamped in the payload and read in the same process (one clock), and a `RESULT` line for scripts. `handshake` and `hold` print the same kind of line and the generator's CPU. `hold` no longer waits for each close (20 000 connections took minutes). `hold` takes `--keepalive` (the suite uses 600 s: opening 20 000 connections takes longer than 1.5 x 60 s, and a broker that keeps its contract then closes the first ones). Host tests of the workspace are unchanged.
  3. **Two urMQTT images, nothing else different.** `prod` as shipped (limits that protect against one abusive address: they cap what one generator can show, and that cap is a result, not a fault) and `bench-x11` (`scripts/mkbench.sh --x11`: the ADR-082 bench limits, `publish_rate_per_device = 1000000/s`, and identities `svc-*` with the backend's `fleet/#` rights, so one generator can publish and subscribe at speed). It is never a release image.
  4. **Mosquitto is configured as close to the production endpoint as it can be** (`scripts/mosquitto/urmqtt-x11.conf`): the same CA, server certificate and key and client certificates, TLS 1.3 only, client certificates required, identity from the certificate, no anonymous clients, an ACL file, no persistence (urMQTT's live mode is RAM only), unlimited connections, `max_inflight_messages 16` (urMQTT's `max_inflight_qos1`), and the descriptor limit raised so that Mosquitto is not capped at 1024 connections by its unit file. Debian 13 packages, no tuning of the kernel on either side.
  5. **The order on the VPS** is: the production ISO as it stands (handshake figures with the production limits), the bench ISO, Debian 13 with Mosquitto, then **the production ISO again** (mandatory; the VPS is the project's live test instance). Images are created from the ISO served from a private URL and deleted afterwards. Raw files are kept in `docs/perf-results/`.
  6. **Every table in `docs/PERFORMANCE.md` has the repetitions behind it** (three, median and range), and a claim is made only where the ranges of the two brokers do not overlap and the generator was not the limit.
- **What the numbers may be quoted for.** One VPS model in one data centre, one source address, 15 ms away, TLS 1.3 with ECDSA P-256 and mutual authentication, small messages. Not for other CPUs, other paths or large payloads, and not as "faster than Mosquitto" in general: the two have different feature sets (Mosquitto has MQTT 5, bridges, plugins; urMQTT enforces an ACL per publish, SYN cookies and admission control) and Mosquitto is one thread against urMQTT's data cores.
- **Consequences.** The suite is repeatable by anyone with a Linux host in reach of a VPS (`scripts/x11-bench.sh`, `scripts/x11-report.py`). A new image or a new Mosquitto version means a new run, not an edit of the old tables.

## ADR-214 — `network.mode = "auto"`: DHCP first, static fallback

- **Status:** Accepted.
- **Context.** `dhcp` suits one ISO for many VMs, but providers such as Contabo give no DHCP to a custom ISO, so a VPS needed a different image from a lab VM.
- **Decision.** A third mode `auto` with `address`, `gateway` (both required) and `dhcp_timeout_s` (3..=120, default 15). The interface starts DHCP; when no lease is bound by the deadline, or when a lease is lost, the static settings are applied on every core (`netproto::apply_static`, also used by `static`). A lease that arrives later replaces the static address through the existing lease path. `dhcp_timeout_s` is rejected with the other modes.
- **Testing.** Schema tests (required fields, default and explicit timeout, range, other modes). Manual QEMU aarch64 with the prod config in `auto` mode: with slirp DHCP the lease 10.0.2.15 is used; with no network peer (`--dgram`) the log shows the fallback after 5 s and `net: static address 10.0.2.77/24`. No smoke scenario yet (a scenario needs its own image config).
- **Not done.** DNS/NTP from the lease are still unused (ADR-100), no IPv6.

## ADR-215 — Configuration is data: the `urmqtt-cfg` blob (C1a)

- **Status:** Accepted (C1a).
- **Context.** Until now `deploy/<env>/config.toml` and its PEM files were compiled into the kernel (`config-schema` rendered Rust constants, certificates were `include_bytes!`). Every customer therefore needed a toolchain, and the kernel differed per customer: no common hash to publish, no way for a browser to produce an image. The kernel pins itself in `limine.conf` by blake2b, so patching the kernel is not an option either.
- **Decision.**
  - A compact, versioned, canonical binary form of the *validated* configuration: the **`urmqtt-cfg` blob** (crate `urmqtt-cfg`, `no_std`). Layout, all little-endian: `"URMQCFG\0"`, format version `u16` (1), flags `u16` (must be 0), payload length `u32`, payload, **fingerprint** (32 bytes), signature kind `u8` (0 none, 1 Ed25519), and for kind 1 the signer's public key (32) and the signature (64). The payload is a sequence of records `tag u16, length u32, value`, tags strictly ascending, each at most once.
  - **Canonical.** A field equal to its default is not written and tags are sorted, so one configuration is one byte string. The **fingerprint** is SHA-256 over `"urmqtt-cfg-v1" ‖ header ‖ payload`. The optional **signature** is Ed25519 over `"urmqtt-cfg-sig-v1\0" ‖ fingerprint`; the fingerprint does not cover the signature, so signing never changes it.
  - **One field table**, `urmqtt_cfg::fields::FIELDS` (tag, TOML key, type, default, range, help text, `dev_only`). Tags are never reused. The decoder refuses an unknown tag, a duplicate or unordered record, a wrong size, an out-of-range value, a bad fingerprint or signature, an unknown version, and non-zero bytes after the blob. A new field gets a new tag and, if old kernels must refuse it, a new format version.
  - **Defaults live in the table.** An absent record means the default, so a newer kernel's defaults apply to fields the user never touched. The empty configuration is a valid blob (header and fingerprint only) and means "the documented defaults": no certificates, so a production kernel boots but refuses to serve (ADR-216).
  - **Validation.** For TOML input the authority stays `urmqtt-config-schema::parse`: `pack` completes the user's TOML with the table's defaults, runs `parse`, reads and checks the PEM files (structure, `min_server_cert_days`/`min_anchor_days` expiry rules, Ed25519 control key, revocation serials) and builds the blob. The kernel and `pack` then run `urmqtt_cfg::check::check`, a `no_std` implementation of the rules that span fields (network mode, ports, limits, retained bytes at most an eighth of the heap, ACL filters and roles, dev-only options, control key present, NTP servers, CPU features). Two implementations is a deliberate cost (the kernel cannot link `serde`/`toml`); the tests in `config-schema` compare their verdicts on every integer range and enum, on a list of cross-field cases, and run the shipped dev, prod and bench configurations through both.
  - **Slot.** The file the bootloader loads is a fixed 256 KiB *slot*: a 16-byte marker (`URMQTT-CFG-SLOT\0`), the blob, zero padding. Tools find slots in an image by the marker at a 512-byte boundary plus a parseable blob plus zero padding, so the marker constant inside the kernel is not mistaken for one. 256 KiB holds a certificate chain, eight CAs and thousands of revoked serials. A second marker, `URMQTT-CFG-DISK\0`, marks the unconfigured slot inside the installation image (ADR-217).
  - **Schema export.** `config_schema::pack::schema_json()` (CLI `urmqtt-config schema`) prints the field table as JSON: key, section, type, default, range, enum variants, list limits, help text, `dev_only`, `derived`. The web form is generated from it, so the form's defaults are the validator's. A test checks that every field has a default and help text and that an empty configuration packs to the blob of defaults.
- **Alternatives.** TOML in the module (needs `toml`/`serde` in the kernel; no canonical form, no cheap fingerprint). CBOR or postcard (a dependency, and still no canonical default omission). Rejected for the same reason: the kernel is the trust root and should parse the smallest grammar that does the job.
- **Consequences.** `config-schema` gains `pack` and `schema_json`; a fuzz target `cfg_blob` covers the decoder. BLAKE2b (RFC 7693) is implemented in the crate, tested against the RFC vector, for the host tool and the browser to compute the hashes Limine checks; the kernel does not use it.

## ADR-216 — The kernel reads its configuration from a Limine module (C1b)

- **Status:** Accepted (C1b).
- **Context.** ADR-215 makes the configuration data. The kernel needs it before its heap exists (`memory.kernel_heap_mb` sizes the heap), on aarch64 and x86_64, with the same code.
- **Decision.**
  - The ISO and the installed ESP carry the slot as `/boot/urmqtt.cfg`; every boot entry lists `module_path: boot():/boot/urmqtt.cfg#<blake2b of the 256 KiB slot>` (`hash_mismatch_panic` stops a corrupted slot in the ISO; the installed disk's `limine.conf` lists it without a hash, ADR-217). The kernel finds the module by its path suffix and decodes it in `urmqtt_kmain` before the console exists; the result is reported once the console is up.
  - `urmqtt-config` keeps the typed `BuildConfig`; `CONFIG` is now a handle that dereferences to the loaded configuration, or to the built-in defaults when none was loaded (host tests, no module). Strings and PEM files are not copied: they are slices of the module, which stays mapped and is never reclaimed. The tables behind the list slices are a static arena in `.bss` sized from the field table's documented maxima (at most 1488 strings in all: ACL 64 per list, 1024 revoked serials; 16 CA files; 4 time servers); no allocation, so it works before the heap. The only `unsafe` code is the initialise-once storage in `crates/config/src/store.rs` (nine justified sites; `scripts/audit-inventory.py` lists it when `docs/audit` is regenerated, which was already out of date before this work and is left to its own commit).
  - **One release kernel.** The only build switch left is `URMQTT_ENV=dev` (the `selftest` feature and the self-test client certificate); every other value builds the same kernel. A **release kernel refuses** a blob with `env = "dev"`, a plaintext port, or any other `dev_only` option set to a non-default value. A dev kernel accepts them only for `env = "dev"`. `BuildConfig::dev()` (dev kernel and `env = "dev"`) replaces the old `env == "dev"` tests for KASLR address printing, fault redaction, the semihosting exit, and so on.
  - **Fail closed.** A blob that fails a check (bad magic, version, fingerprint, signature, range, cross-field rule, dev option on a release kernel) stops the boot with the key and reason on the console. The kernel does not fall back to defaults when a configuration was present but wrong. No module, or an empty slot, means the documented defaults. Serving then needs a server certificate, its key and at least one operational CA; without them the kernel stops after the platform is up and before any disk is touched, saying what to do (`refusing to serve: no server certificate and key ...`). The installer and the diagnostic entry run without certificates.
  - Boot prints `config: fingerprint <sha-256> (<n> bytes, unsigned | signed by key <id>), env=<env>`, and warnings when the slot is empty, when no module was loaded and on a dev kernel.
  - `mkiso.sh` packs the environment's `config.toml` (default `deploy/$URMQTT_ENV`, via `urmqtt-config pack`) into the slot, or takes `--config FILE` (TOML, blob or slot) and `--empty-config`, so `make dist/iso ENV=...`, CI and the smoke suite keep working with exactly the blob the web builder will produce. `log::MAX_LEVEL` is now an atomic set at load (`set_max_level`).
- **Alternatives.** Appending the blob to the kernel ELF (changes the kernel hash and the reproducible-build story). Reading it from the ESP through a FAT driver at run time (a driver before the heap). A kernel command-line option (length limits, visible in the menu).
- **Testing.** Host: default and packed-blob decoding in `crates/config`, the arena bound. QEMU smoke (aarch64 HVF): the boot line, a packed non-default configuration (watchdog budget 37 ms, heap 16 MiB), the same signed, a slot with one flipped payload byte (fatal, no `READY`), the empty template (boots, refuses to serve).

## ADR-217 — The installed disk carries the configuration; an update keeps it (C1c)

- **Status:** Accepted (C1c).
- **Context.** An installed disk boots without the ISO, so its ESP needs the configuration. The installer image (the ISO's `disk.img` module, or `install/esp.img` on the aarch64-only ISO) is pinned by hash in the ISO's menus, and the image holds the keys of the customer, so it must not contain them a second time.
- **Decision.**
  - The installation image carries an **unconfigured slot** at `/boot/urmqtt.cfg` of its ESP, marked `URMQTT-CFG-DISK` and holding the *empty* configuration, whatever the ISO is configured with. The image, and its hash in the menus, therefore never depend on the configuration. Its `limine.conf` lists the module without a hash, so a configuration written later never trips the bootloader (a hash on the same writable ESP protects nothing an attacker with disk access could not rewrite; the blob has its own fingerprint and optional signature).
  - The installer finds that one unconfigured slot in the image (`urmqtt_cfg::blob::find_slots`), writes the image, then overwrites the slot with the boot slot it was started with (a Limine module, marker `SLOT`), flushes, and reads back everything: the comparison is against the image as it should be on the disk (step 2b of `write_boot_image_with`). An image without exactly one unconfigured slot is refused before anything is written (`InstallError::NoConfigSlot`). A power cut leaves a non-booting disk, as before.
  - The raw images a build keeps (`--disk-out`, `--esp-out`, so `make raw`, `make disk`, the release `.img`) carry the configuration directly; the copy inside the ISO is the template one. A slot still marked `DISK` on an installed disk is read as the empty configuration (boots, says so, does not serve).
  - `urmqtt-disk update-boot` **keeps the disk's configuration whenever it has a real one** (not the empty template), whatever the new ESP carries: an update with a release's `.img`, which holds the dev configuration, must not silently replace the customer's. A disk without a real configuration takes the new ESP's own. `--config BLOB|SLOT` sets one, `--replace-config` takes the new ESP's even over a real one, `--keep-config` keeps the disk's even if it is empty; `info` prints the installed fingerprint and `create` takes `--config`. Data-layout migration, grow and backup do not touch the ESP.
  - The aarch64-only ISO now has two ESP images: `esp.img` (configured; El Torito) and `install/esp.img` (the module).
- **Alternatives.** A configuration partition (a third partition; GPT, install and migration tools would all change). Patching `limine.conf` hashes at install time (needs a FAT writer in the kernel). Copying the whole ISO configuration into the image at build (the image and its hash would depend on the keys).
- **Testing.** Host: install writes and verifies the patched image, refuses an image without a slot; `urmqtt-disk` carry-over cases. QEMU: the installer on aarch64 (HVF), x86_64 UEFI and BIOS installs a signed non-default configuration and the disk boots on all three paths with the same fingerprint and setting; `install-vm-boots` on the aarch64-only ISO.

## ADR-218 — `urmqtt-config`, the template ISO and what the tool changes in an ISO (C1d)

- **Status:** Accepted (C1d).
- **Context.** The customer needs a configured ISO without building the kernel; the web builder (C1e) must produce the same bytes as an offline tool.
- **Decision.**
  - Host CLI `urmqtt-config` (`tools/config`): `pack` (TOML plus files to a blob, a slot, a copy of a template ISO or of a raw image), `show` (a blob, slot, ISO or raw image: fingerprint, signature, every non-default value; certificates are summarised, keys are never printed), `verify` (the checks of a release kernel, or with `--dev` a dev kernel; for an image also that every copy of the slot is the same and every module hash in a `limine.conf` is the slot's), `slot` (wrap a blob), `schema` (JSON, ADR-215), and `--sign KEY.pem`.
  - **In-place ISO patching.** The ISO holds the slot twice (the ISO 9660 file and the EFI system partition image) and each of the four `limine.conf` copies names it by blake2b in every entry (24 references). The tool finds slots by marker and structure and hashes by the text `urmqtt.cfg#<128 hex>`, replaces every slot copy and every hash with same-length data, and refuses an image where the copies of the slot differ, a hash is not the slot's, or there is no slot or no reference (it will not guess). No ISO 9660 record, FAT chain or El Torito entry is touched and the kernels keep their hashes. The unconfigured slots of the installation image are left alone.
  - **The result equals a direct build.** Packing configuration X into the template is byte for byte the ISO `mkiso.sh --universal --config X` builds (smoke `universal-config`). Output is deterministic; BLAKE2b is computed by the tool itself.
  - **Template ISO.** `make template` builds the universal ISO from the release kernels (any `ENV` but `dev` gives the same ones) with `--empty-config`; `make dist` and `make dist-universal` add it as `urmqtt-template-<version>-universal.iso`, so it is in `SHA256SUMS`, the SBOM attestation subjects and the minisign signature like the other artifacts. The `dev` ISO artifact stays.
  - Tests: unit and golden tests with fixtures in `tools/config/tests/fixtures` (a lab TOML, a broken TOML, a golden blob that pins the format), synthetic images (slot copies, template slots, hash references, inconsistencies), the dev configuration with its certificates.
- **Alternatives.** Rebuilding the ISO with xorriso on the customer's machine (needs xorriso, mtools and a Limine build; cannot run in a browser).
- **Consequences.** A patched ISO has no official hash (ADR-219). The browser builder (C1e) reimplements only the replace-slot-and-hashes step; `urmqtt-cfg` and `config-schema` compile to WebAssembly unchanged (no I/O in them).

## ADR-219 — Trust statement for a configured image (C1f)

- **Status:** Accepted (C1f).
- **Context.** The released kernel and the template ISO have published hashes and a minisign signature. A configured ISO is different bytes by construction.
- **Decision.** What is attested: the **template** (kernels, loader, installer) by `SHA256SUMS` and its signature, and the **configuration** by the fingerprint the packer prints and the kernel prints at every boot. The customer compares the fingerprint on the console with the one the tool or page showed. **Signing is optional and off by default:** `pack --sign KEY.pem` attaches an Ed25519 signature over the fingerprint; the kernel verifies it and prints the signer's key id. The signer key is the customer's own and is *not* a trust anchor in the kernel: nothing in the image says whose key to expect, so a signature proves only that the blob was not changed after the holder of that key signed it. Making it mandatory would need a place to pin the expected key, which an image the customer configures cannot offer without making the pin part of what the customer configures; and would put key management on people who asked not to have a toolchain. (The open question of the C1 plan, "sign by default?", is thereby answered no, with a pin as the later step.) A patched image also has a modified ISO 9660/FAT structure around unchanged kernel bytes; the kernel bytes still match the pinned hash that Limine checks at boot.
- **Consequences.** `docs/SECURITY.md` carries the statement ("Configured images"); the builder page repeats it.

## ADR-221 — The watchdog charges a handler for the time its core ran, not the time that passed (ROBUST)

- **Status:** Accepted. Amends ADR-013, ADR-035 and ADR-071.
- **Evidence (X11, Contabo KVM, 4 vCPU).** With the production `action = "drop"` the 20 ms handler budget aborted 1-8 live connections per run under load (`core N input handler over budget: 37-111 ms`), while the same sweeps with `action = "log"` lost none in 20 runs, and the data-plane line showed `longest stall` of 50-170 ms per core. The handlers did not run that long: a tick programmed for a deadline arrived tens of milliseconds late, which only happens when the virtual CPU is not running (the guest's counter kept going; nothing executed). Mosquitto has no such check and never dropped.
- **Causes considered.** Our own code: a long handler (the profile shows microseconds per packet and sub-millisecond timers), the allocator (small blocks come from per-core caches, the global ticket lock is taken once per 16 blocks; a descheduled lock holder is handled below), memcpy (ADR-200), log output (per-core rings, one writer, ADR-090; the console reader never waits for a sink, ADR-072), SQLite (an unprivileged component on the last core only, ADR-210), the timer wheel (O(expired)). None can take 50-170 ms. What can: the host taking the vCPU away (steal), and a core spinning for a lock whose holder lost its vCPU. Both are time in which the handler did nothing.
- **Decision.** The budget applies to **running time**, measured as elapsed time minus time the core was not running:
  1. **Late ticks.** The tick is programmed for a deadline; the tick handler knows how late it arrived. A tick later than 4 ms (`STALL_MIN_NS`; healthy delivery is tens of microseconds, the worst boot-time value on this VPS 2.3 ms) means the core was not running for at least that long, and for up to one more tick period before the deadline. Both are credited to the core (`late + period`, the conservative side) and subtracted from every handler that was running.
  2. **Lock waits.** `SpinLock::lock` times a wait that had to spin (a clock and a sink installed at boot, `urmqtt_sync::sync::set_contention_hooks`; the uncontended path is unchanged) and the wait is credited the same way: the holder may be a descheduled vCPU, and the waiter's own connection is not at fault.
  3. A handler that really runs past the budget with interrupts enabled earns no credit and is reported and dropped exactly as before. The **stuck-core reset** (1000 ms, `max(1000, 100 x budget)`) uses the same running time, so a host that pauses the VM for seconds does not reset it, while a loop that really spins is still reset; a core that spins with interrupts masked is still caught by the cross-core health check (ADR-035).
  4. **Confirmation at the next tick.** A stall that ends before the tick's deadline leaves no late tick (the tick only measures what happened after its deadline), so a handler that was over budget in elapsed time at one tick is only a suspect; it fires if it is still running, and still over budget in running time, at the next tick (10 ms later). A stalled handler finishes within microseconds of the core coming back; a handler that really overruns does not. The price is up to one tick period before a real overrun is dropped.
  5. **A wait that is still going on counts.** The wait for a spin lock is credited when it ends; a tick that looks in the middle of it (the holder is a virtual CPU the host has descheduled, so the wait can last tens of milliseconds, and the VPS showed up to 2.5 s of lock waiting per 5 s on a data core under flood) used to see an uncredited handler and, one tick later, drop its connection. The lock hooks now also report the start of a wait (`WAITING_SINCE`), and the tick counts the wait in progress.
  6. **Close-up ticks.** The late-tick measure sees only the part of a stall after the tick's deadline, and the host preempts a vCPU in slices of a few milliseconds. Once a handler has run for half its budget, the tick comes every 1 ms (and a tick 0.5 ms late counts as a stall) until it returns: handlers are microseconds long, so this costs nothing in practice, and the invisible part of a stall is then at most 1 ms per tick instead of 10.
  7. The report names both: `over budget: R ms > B ms (action: ...); W ms elapsed, S ms not running`. A handler that was over budget in elapsed time only is counted (`watchdog::EXCUSED`). Every core writes a `stalls:` line (late ticks, the worst, microseconds waiting for locks, host steal, the dispatcher's NIC backlog) at the end of a 5 s window in which it saw a stall of 20 ms or more, steal the host reports, 100 ms of lock waiting or a NIC backlog (a noisy VPS has late ticks in every window; a line per core per 5 s would be noise on a console that costs milliseconds a line).
- **What this cannot tell.** From inside the guest a stall that the host causes and an interrupt-masked section of our own code look the same (both: no tick, then a late tick). The kernel masks interrupts for short sections only (the per-core allocator cache, the log ring push); none runs inside a handler for milliseconds. Stalls shorter than 4 ms are charged to the handler (they cannot by themselves reach a 20 ms budget; at most a fraction of each tick period is invisible). The credit is one period larger than the proven lateness on purpose: a real overrun of a few ms during a stall can be excused once; the next tick charges it again.
- **Not changed.** The budget (20 ms ordinary, calibrated handshake class, ADR-071), the action (`drop` stays the production default), the hard reset. No knob was added.
- **Tests.** Smoke `watchdog` and `watchdog-handshake` unchanged and passing; new `watchdog-lockwait` (`test=watchdog-lockwait`: a handler that waits 50 ms for a lock is counted as not charged while it waits, one that runs 50 ms is reported); new `watchdog-stall` (`test=watchdog-stall`): a handler stalled for 45 ms with interrupts masked (the tick arrives late, as after a descheduled vCPU) is not reported, a handler that really runs 50 ms is. Measured on the real VPS: see PERFORMANCE.md section 7.

## ADR-222 — TCP keeps out-of-order data and negotiates window scaling, SACK and timestamps through the SYN cookie (PERF)

- **Status:** Accepted. Amends ADR-033 (the TCP stack) and the cookie description of H3.
- **Evidence (X11).** One TCP flow through urMQTT moved about 3 000 small messages/s (0-7 700 between runs) or 0.7 MB/s of 1 KiB messages over a 15 ms path; Mosquitto, on the same VPS and path, 22 700 and 1.4 MB/s. A local rig reproduces it (below) and shows two causes, one here and one in ADR-223:
  1. **Every segment after a loss was thrown away.** The receiver accepted in-order data only (`out-of-order data is dropped and answered with a duplicate ACK`). One lost segment in a window of 40 made the sender's fast retransmit resend the hole; the other 39 segments had been discarded, so each partial ACK uncovered the next hole and recovery took one round trip per discarded segment (NewReno without SACK against a receiver without a reassembly queue). With 15 ms per round trip that is hundreds of milliseconds to seconds per loss event, and a vCPU stall of tens of milliseconds, which makes the host drop a few thousand frames from a 256-entry virtio queue, is a loss event.
  2. **The window was 16 bit.** No window scaling: 64 KiB per round trip, 4.4 MB/s at 15 ms and 1.3 MB/s at 50 ms, at best, and the send queue of a connection (`tx_max`) was 64 KiB too: the subscriber leg had the same limit. A Linux sender (loadgen, any gateway) has MBs of window.
- **Decision.**
  1. **Out-of-order data is kept** (`crates/tcp/src/ooo.rs`): a sorted list of at most 16 non-overlapping ranges per connection, allocated by the first out-of-order segment and freed when the hole fills (an idle or healthy connection pays nothing: `Conn` grew by 16 bytes, 96 to 112, for this and the options). Only data inside the announced window is kept. **Bounded**: `ooo_conn_max` per connection (1 MiB) and `ooo_budget` per core (16 MiB); beyond them a segment is dropped as before and counted (`ooo_dropped`). A peer that sends only out-of-order data can therefore hold at most the per-core budget, whatever the number of connections. When a segment fills a hole, the contiguous ranges are handed to the application in slices of 16 KiB (each slice one watchdog-supervised handler) and the ACK is sent at once.
  2. **SACK blocks** (RFC 2018) are reported in the duplicate ACKs for the ranges held (up to three, the range with the latest segment first) when the peer negotiated SACK. We do not use SACK information on the sending side (a lost segment of ours is retransmitted per NewReno; the receivers that matter ACK every other segment).
  3. **Window scaling, SACK and timestamps through the cookie.** The ISN has no room (5 bit time, 3 bit MSS index, 24 bit MAC), so, as Linux does, the options the peer offered ride in the low six bits of our **timestamp value** in the SYN-ACK (`cookie::ts_encode`: SACK, window scale present, shift 0-14; the value is never above the clock, so later values cannot go backwards), and the peer echoes it in its final ACK, where `ts_decode` reads them back. The SYN-ACK carries the options only if the SYN carried timestamps; a peer that offers none gets the plain 16 bit window and no SACK, as before. The stack stays stateless until the final ACK; the MAC keeps its 24 bits. A forged echo can only change the options of the forger's own connection (shift clamped to 14).
  4. **Receive window**: 1 MiB when scaling was negotiated (shift 5), 64 KiB otherwise. The application consumes data synchronously, so the window is flow-control headroom, not a buffer.
  5. **Send side**: the peer's advertised window is read scaled. The send queue of a connection is no longer fixed at 64 KiB: it is twice the congestion window, between 64 KiB and 1 MiB (`tx_cap`), so memory is spent on connections that have shown they can carry it. Timestamps cost 12 bytes of every segment; the payload per segment is the MSS minus 12 on such connections.
  6. **The congestion window counts acknowledged bytes** (RFC 3465, ABC). NewReno grew the window by at most one MSS per ACK in slow start and by MSS squared over the window per ACK in congestion avoidance, which assumes an ACK per segment or per two. The VPS showed the other case: the receiver (the load generator on a host with 60-70 % steal, and any receiver with offload) acknowledges in batches, so one ACK covered tens of segments and the window of the subscriber leg grew by one or two segments per round trip, about 1 MB/s per flow at 15 ms. Slow start now adds what an ACK covers (at most 16 segments per ACK, a bound on a single stretch ACK) and congestion avoidance adds `MSS x acked / cwnd`.
  7. **Not done**: PAWS (no old duplicates can be accepted: the sequence checks stand), using the echoed timestamps for RTT (the existing timed segment stays), SACK-driven retransmission on our sending side, ECN.
- **Security properties kept.** SYN cookies are always on and a half-open connection holds no state; the cookie MAC is unchanged (24 bits); the RFC 5961 checks, the RST and challenge-ACK rules, strict flag checks and the small-MSS refusal are untouched; the receive window is never moved left; data outside the announced window is dropped, never kept; all memory a peer can make us hold is bounded per connection and per core. The fuzz target `tcp_segment` now opens its connection with timestamps, SACK and window scale and sends timestamped segments (2 million runs without a finding), the H3 stateful model test still passes, and 16 new unit tests cover the range list (merge, overlap, wrap, bound, SACK order), the cookie options, the stack (scaled windows, timestamps and segment size, one lost segment of 30 costs one retransmission, bounds per connection and per core, window edge, no options without timestamps) and the congestion window.
- **Numbers (local rig, ADR-223, 15 ms path, one publisher and one subscriber, QoS 0 flood).** See PERFORMANCE.md section 7.

## ADR-223 — A subscriber that stopped reading, the NIC queue, and QoS 0 loss that is counted (PERF, ROBUST)

- **Status:** Accepted.
- **Evidence.** X11: one flow stalled "for seconds"; QoS 0 flood: 18 300 of 24 300 messages delivered, loss not attributed; `frames dropped for a full NIC queue (39 in 5 s)`. Reproduced on a rig (below). Three separate causes:
  1. **A lost wake-up in the output loop (a bug).** `MqttService::poll` takes the `ready` list (`mem::take`), drains the broker's list into it and walks it; `local_output` and `remote_output` put a connection back on `self.ready` when they could not move all its output (the TLS buffer is at `TX_BUF`, or the relay has no credit left). After the walk the code assigned the drained list back (`self.ready = ready`), **overwriting those entries**. The broker marks a connection ready only when it sends to it, and a QoS 0 message is not sent to a connection whose output buffer is full, so a subscriber that fell behind once (a full TCP queue under overload) was never visited again: every later QoS 0 message to it was dropped, `delivered/s` fell to 0 for as long as nothing else woke it (a PINGRESP or a QoS 1 message), which is the keep-alive interval. On the rig: `delivered 0/s` in two runs out of three under flood. The fix keeps what the walk pushed (`append`).
  2. **Dropping frames the NIC could not take yet.** Core 0 moved frames from the workers' rings to the virtio-net queue (256 descriptors) and **dropped** any frame that did not fit. TCP recovers a dropped data frame, but at the price of ADR-222's round trips. Core 0 now holds them in a backlog of up to 4 096 frames and sends as descriptors free (it keeps polling while the backlog is not empty); beyond that the worker rings fill and the worker drops, counted. The rings between core 0 and the workers hold 2 048 frames (was 512): a 1 MiB window is about 720 segments, and a burst of it must fit while a worker is busy.
  3. **QoS 0 loss under overload is deliberate but was only partly counted and logged.** The designed behaviours stay: a QoS 0 message for a subscriber whose output buffer is full (32 KiB of broker buffer, 32 KiB of TLS output, up to 1 MiB of TCP queue) is dropped; so is one for a client that is not connected, and a fan-out to a core with more than 16 384 messages waiting. Now every cause has a counter and they are reported: `$SYS/broker/messages/dropped/{slow_subscriber,offline,cross_core,qos1_queue_full,publish_rate}` and `$SYS/broker/frames/dropped/{steer,worker_tx,nic}` (also in the `status` console command and the info query), and a warning line per core at most every 10 s with the counts of the interval. `dropped_backpressure` was split into "slow subscriber" and "offline".
- **Local rig (how the numbers were made).** Docker on the Mac gives a Linux VM with `tun`: `scripts/wan-bridge.c` joins the guest's `-netdev dgram` socket to a tap device in a container, delaying each direction (RTT 15 ms measured by ping through it), dropping a chosen share of frames and optionally limiting the rate, and `urmqtt-loadgen` runs in the same container (a real Linux TCP peer with SACK, timestamps and window scaling, not QEMU's slirp proxy, which terminates TCP itself). The guest is the production configuration (`mkbench.sh --x11 --static`) under HVF, 4 vCPU. The same container can run Mosquitto with netem on `lo` for the Linux baseline.
- **Not changed.** QoS 1 semantics; the drop policy (QoS 0 may be dropped under overload, QoS 1 is queued up to the session limits); the broker's per-connection buffer sizes.

## ADR-224 — A sleeping dispatcher polls the NIC every 200 us while connections exist (PERF)

- **Status:** Accepted. Amends ADR-032 (adaptive polling). Amended by ADR-270: the poll is now the fallback for a NIC or platform without a receive interrupt.
- **Evidence.** Rig, one idle MQTT connection open, ping through the bridge (RTT configured 4 ms plus the container's own path): **13.1 ms mean (6.8-21.0, deviation 3.3) before, 7.4 ms (5.3-10.3, deviation 1.2) after**. One flow, 1 KiB, QoS 0, same rig: 10 141 published and 4 297 delivered messages/s with 126 ms median latency before, 18 382 / 11 326 with 62 ms after. On the VPS, see PERFORMANCE.md section 7.
- **Cause.** The virtio-net queues are polled; the driver sets up no receive interrupt (ADR-032). Core 0, which owns the NIC, spins for 100 us after the last piece of work and then sleeps in `wfi`/`hlt`. Nothing wakes it for a frame that arrives while it sleeps except the next 10 ms tick, or an IPI from a worker that has something to send, which a worker only has after core 0 has delivered the input. A flow whose window lets the sender pause between bursts (every flow over a 15 ms path, and every flow at a few thousand packets per second) paid 0 to 10 ms, 5 ms on average, at each pause, and the sender's ACK-clocked window inflated with it (the VPS showed Linux measuring 66 ms round trips for a path of 15 ms). Mosquitto sleeps in `epoll` and is woken by the NIC's interrupt. This was the "interrupt versus poll latency" suspect of the task, and it is a cause.
- **Decision.** `Idle::poll_wake(ns)`: before sleeping, a core that asked for it programs the deadline timer to the earlier of the next tick and `now + ns`. The dispatcher asks for 200 us while any data core holds a connection (`dataplane::CONNECTIONS`), and for nothing otherwise (an empty broker still sleeps until the 10 ms tick). The timer interrupt that ends the sleep is the tick handler, which re-arms from the deadline, so the watchdog's lateness measure is unchanged. Cost: up to about 5 000 wake-ups a second on core 0 (a few percent of that core, which is otherwise idle at these rates) and none on the workers, which core 0 wakes by IPI.
- **Not done.** The proper fix is a receive interrupt (MSI-X vector on the virtio-net receive queue, then no polling wake-ups at all); it needs the interrupt plumbing of both architectures and a mode for hosts without MSI-X. The poll period is a constant, not a knob.

## ADR-225 — The builder's WebAssembly module: the command line tool's code, compiled (C1e)

- **Status:** Accepted (C1e).
- **Context.** The builder page must pack, validate and patch exactly as `urmqtt-config` does (ADR-218): a second implementation in JavaScript would drift, and the whole point of the page is that its result is the file the tool would have written. The page also needs what the tool never needed to show: the field schema, BLAKE2b and SHA-256 of a 60 MB image, the optional Ed25519 signature, the minisign check of a release, and what a certificate or key says.
- **Decision.**
  - **One module, `tools/builder/wasm` (`urmqtt-builder-wasm`), `crate-type = [cdylib, rlib]`**, built with `make builder` (`--profile wasm`: `opt-level = "s"`, fat LTO, `panic = "abort"`, `strip`; about 1.06 MB, 312 KB gzip; Caddy and nginx compress `application/wasm`). It has **no imports**: no clock, no random numbers, no I/O (the page passes the time and, for a new signing key, 32 bytes from `crypto.getRandomValues`). One module per configuration format version (`urmqtt-cfg<N>.wasm`); the page loads the one that matches the release's template and greys out the releases whose format it does not know.
  - **It calls the tool's code, it does not copy it.** What the browser needs and the file system never touched moved into the tool's library `urmqtt-config-tool` (`pack_text` with a file-reading closure, `sign_pem`, `image::configure_iso_in_place`, `image::probe`) or was added there (`minisign`, `release` for `SHA256SUMS`, `keys`, `certs`); `pack_blob`, `sign` and `configure_iso` are thin wrappers, so the command line did not change (one new subcommand, `check-release`, which makes the browser's release check available offline). The module adds only the release rule (a configuration the *release* kernel in the template would refuse is never packed or written into an image) and the glue.
  - **A plain C ABI on buffer handles, no `wasm-bindgen`.** The page asks the module for a buffer (`ub_buf_new`), writes into it through the exported memory, calls a function with handles and reads the answer from the returned handle. No pointer is ever an argument, so the module contains no `unsafe` block; the one unsafe-flavoured construct is `#[unsafe(no_mangle)]` on the exports (a documented `allow` on one module). Failures return handle 0 and `ub_error` says why; `pack` reports a JSON array of `{path, message}` with the *command line's* messages. The generator and JavaScript glue of `wasm-bindgen` would have been a second toolchain in the supply chain for 30 exported functions.
  - **No new third-party crate.** `base64ct` (already in the tree through `pem-rfc7468`), `sha2`, `p256` (ECDSA P-256 verify and key derivation, with the features `ecdsa`, `pem`), `x509-cert` are all in `Cargo.lock` already; `cargo vet` needed no new exemption. Certificate checks (subject, issuer, validity, names, key type, whether the private key belongs to the certificate, whether a CA signed it) are local computation for the import dialogs.
  - **The ISO is patched in place in the module's memory.** The page streams the download straight into a module buffer (one copy of the 63 MB template, no JavaScript copy), `configure_iso_in_place` replaces the slots and hashes there, SHA-256 is taken of the result and only then is a `Blob` made. Every check runs before the first byte changes.
- **Testing.** `tools/builder/test/wasm-vs-cli.test.mjs` (in `make check` and in CI when `node` and the wasm32 target are present): the module's schema equals `urmqtt-config schema` byte for byte; `pack` of the same TOML (lab fixture, a configuration with the development certificates, a control key and a deterministic signature) gives the identical blob; the same problems in the same words for the broken fixture; configuring a synthetic template and the real 63 MB template ISO gives the image the tool writes, with the same report and verdict, and configuring with the empty configuration restores the template byte for byte; the release check agrees with `minisign` on the real v0.1.0 signature and refuses every flipped bit; SHA-256 and BLAKE2b agree with Node's. Host unit tests of the module (13) and of the new library code (the real v0.1.0 `SHA256SUMS` and signature are fixtures).
- **Alternatives.** Re-implementing in JavaScript (drift, and the TOML/PEM/x509 rules are not small). `wasm-bindgen` or `wasm-pack` (generator in the supply chain, glue code to review). A server-side builder (keys would leave the browser: the one property the page promises).
- **Consequences.** `make builder` needs `rustup target add wasm32-unknown-unknown` and Node; `make check` runs the builder tests when both are there and says so when they are not. The module must be rebuilt with every change to the tool's library; the page and the kernel can therefore not disagree, because both are built from the same commit.

## ADR-226 — The builder page: one screen, defaults everywhere, nothing leaves the browser (C1e)

- **Status:** Accepted (C1e).
- **Context.** A customer who cannot or will not build the kernel needs to produce the same configured ISO as `urmqtt-config pack --iso` (ADR-218) from a browser, with their own certificates and keys. The page has to be usable on a phone, accessible, honest about what it does with a private key, and small enough to audit: it is the one place where this project's code runs next to a customer's key.
- **Decision.**
  - **One page, no navigation, dialogs for detail.** Release, presets, the form and a summary bar (status, name, Build, Download, Try in the emulator) sit on one scrolling screen; the summary is a card at the side on a desktop and a compact bar pinned to the bottom on a phone (status and Build; the rest opens with Details). Everything that is not the main flow is a native `<dialog>` opened with `showModal()`, so the page behind is inert, Tab stays inside, Escape closes and the focus returns to the opener: certificate and key import with the parsed result (subject, issuer, validity, names, key type, whether the key belongs to the certificate, whether a CA signed it, days left against the build's minimum), TOML import and export, the integrity report, the confirmation of risky combinations, the instructions after the build, the files-from-my-computer fallback, section reset and the emulator. Light and dark follow the system through the site's colour variables; `prefers-reduced-motion` stops animation; the controls have labels, descriptions (`aria-describedby` to the help and the error) and `aria-invalid`; Lighthouse accessibility 95 before the contrast fix, no remaining failure.
  - **The form is made from the exported schema** (the module's `ub_schema`, identical to `urmqtt-config schema`), so its defaults and ranges are the validator's. **Every field shows its default** (the placeholder of a text field, the selected choice of an enum, the state of a switch, the default list of a list field) and **an untouched field is not written**: the state holds only what the user changed (`core.js`), the TOML and the URL hash are made from that, and the packer's canonical form leaves a value equal to its default out in any case, so a newer kernel's defaults apply. A changed field carries a marker (text, not only a colour) and a reset link; a section has a count and a reset. Presets are three small sets of changed values (lab VM on DHCP, VPS with a fixed address, DHCP then fixed) plus "defaults". Fields that only exist in the other network mode are hidden and not written; development-only options are not offered (a release kernel refuses them).
  - **Validation is the command line's.** Every change re-packs through the module and shows the validator's own message at its field (`limits.max_packet_size: must be in 64..=268435455`), including the cross-field rules (`tls.cert and tls.key must be given together`); an input the TOML layer would reject as a type error (letters in a number) is caught by the page first and says so in the page's language. Pressing Build with a problem moves the focus to the first one. A configuration that cannot serve (no server certificate, key or operational CA) is a confirmation, not a block.
  - **State.** The address bar (`#s=` plus base64url JSON of the release, preset, name and changed values) and `sessionStorage` (the same, plus the public certificates and the control public key) survive a reload; **a private key and the signing key are held in memory only** and the page says so when a certificate is restored without its key. A test checks the address, `sessionStorage` and `localStorage` for key material and every network request of a build for key bytes.
  - **The build.** The page fetches `releases.json` (same origin; a failure is shown with Retry and "use files from my computer", never a silent fallback to GitHub), verifies `SHA256SUMS` against the embedded key when a release is chosen (the key is `minisign.pub` at build time; `BUILDER_PUBKEY_TEXT` replaces it for tests), streams the template straight into a buffer of the module with progress and Cancel (`AbortController`), compares its SHA-256 with the signed sums, writes the configuration in place, reads the image back (`verify`), hashes it and offers a `Blob` as `urmqtt-<version>-<name>-universal.iso` together with the fingerprint the kernel prints. A failed check opens a dialog that names it and blocks the build; the user may override it, and the integrity report then says so. Editing the form after a build marks the image out of date and disables Download until it is built again.
  - **No framework, no npm.** Plain ES modules, concatenated by `tools/builder/web/bundle.mjs` into one script (imports and exports stripped; the build fails on a form it does not handle); the DOM is built with a 30-line `h()` helper and updated in place. The page needs `'wasm-unsafe-eval'` in its script policy and nothing else beyond the site's (`connect-src 'self'`, no third-party origin).
  - **Languages.** Page texts are one JSON file per site language (`tools/builder/web/i18n`), English as the fallback; a test requires all 15 files to have exactly English's keys and placeholders. **Field labels are the TOML keys and the help texts come from the schema, in English; only the page's own words and the section names are translated** (the help is part of the validator's source and translating 70 sentences per language would fork it).
- **Testing.** `tools/builder/test`: form logic against the real module (defaults complete, nothing written for an untouched form, every field can be changed alone, hostile text cannot break the TOML, the hash holds no key); the page in headless Chrome driven over the DevTools protocol without a dependency (`cdp.mjs`): releases and greying, every placeholder equals the schema default, change, reset and section reset, validation text equals the module's, TOML import and export, certificate import, **a build in the browser (a real download) is byte-identical to `urmqtt-config pack --iso`**, privacy of requests and storage, the integrity failure and override, dialogs (Escape, focus stays inside, focus returns), phone width without overflow, dark mode, no request for emulator files before the click, the release list failing, a template from the computer.
- **Alternatives.** A framework (a build chain and a supply chain for 3000 lines). Web Workers for the build (the module hashes and patches 63 MB in about two seconds; a worker would add a second copy of the module and message passing for no visible gain). A wizard (the plan asks for one screen). Parsing the TOML in JavaScript (a second parser).
- **Consequences.** The page is as trustworthy as the site that serves it (docs/SECURITY.md, "The builder page"). The module is loaded once per page; the build holds the template (63 MB) and the `Blob` of the result at the same time (about 130 MB), which a phone may refuse: the error says so and the command line remains.

## ADR-227 — The release mirror, its web server and the pages on aldo.tech (C1e)

- **Status:** Accepted (C1e).
- **Context.** The page may only fetch from the site that serves it (`connect-src 'self'`, no third party; ADR-226), and it needs the template ISO (63 MB), `SHA256SUMS` and its signature. GitHub's release download addresses send no CORS headers, so a browser page cannot read them, and the API is rate limited for anonymous callers. The site (aldo.tech, 15 languages, a static generator behind Caddy 2.6.2 on a shared host) must not be disturbed by this: it also serves other customers' sites.
- **Decision.**
  - **GitHub Releases stays the one source of truth; a job mirrors it** (`scripts/mirror-releases.py`, Python standard library and the `minisign` tool, no other dependency). For a new or changed release it downloads `SHA256SUMS` and `.minisig`, verifies the signature against the release key, downloads the template, checks its size and SHA-256 against the *signed* sums and looks for the configuration slot; only then are the files moved under `<root>/<tag>/` by `os.replace` (the sums first, the ISO last), so a half-written file never has its final name. Anything that fails is not published, an earlier good edition of the tag stays, the release is listed as `unverified` with the reason and the exit status is 2 (the unit fails, `systemctl --failed` shows it). A release without a template is listed with `template: null` and costs two tiny downloads. The job is **not trusted**: the page verifies the signature again with the key embedded in it.
  - **`releases.json` (schema 1)** is what the page reads: the key id and the source, and per release `tag`, `published`, `prerelease`, `status` (`ok | unverified | removed`), `verified`, `edited`, `template` (`file`, `path`, `size`, `sha256`, `config_format`; null with a `reason` such as `no-template`), `sums` (the two paths), `assets` (every asset with its GitHub address and whether it is mirrored) and a top-level `templates` count (releases with a verified template: what the page's empty state and the status of the mirror look at). A release deleted upstream stays on disk and is marked `removed`. A failed listing of GitHub changes nothing.
  - **A systemd timer, as a guest on the machine.** `urmqtt-mirror.timer` runs hourly with five minutes of random delay (`Persistent=true`); the oneshot service runs as the unprivileged `urmqtt-mirror` user with `Nice=19`, idle I/O and CPU scheduling, `--limit-rate 2 MiB/s`, `MemoryMax=256M`, a one-hour timeout, `--min-free 256 MiB`, no capabilities, `ProtectSystem=strict` with one writable directory, and the usual `Protect*`/`Restrict*` set. `scripts/mirror/install.sh` creates the user and the units and is idempotent; nothing is installed by package.
  - **The web server is a small nginx in a container, behind Caddy.** The host's Caddy has no rate limiting, and rebuilding it with a module would put every site on this host on a custom binary. `urmqtt-mirror-web.service` runs `nginx-unprivileged` pinned by digest (read-only root, no capabilities, no new privileges, 64 MB, half a CPU, 64 processes) on `127.0.0.1:18089`, with the mirror directory mounted read-only. It serves only four shapes (`/releases.json`, `/<tag>/SHA256SUMS`, its `.minisig`, `/<tag>/urmqtt-template-<name>-universal.iso`), never the job's own `.tmp`, `.lock` or `meta.json`, and limits `releases.json` to 20 requests a minute per visitor (burst 30), the sums to 6 at a time, and templates to 3 at a time per visitor and 12 in all, at 12 MB/s after the first megabyte (the template is cached `immutable`: its name carries the version). Over a limit it answers 429; if the container is down only the list fails, the page says so and the rest of the site is untouched.
  - **Caddy** (`scripts/mirror/caddy-apply.py`): `/urmqtt/releases/*` and `/urmqtt/releases.json` are proxied to it (`header_down -Server`, so the response does not carry two `Server` headers), the builder pages get `Cross-Origin-Embedder-Policy: require-corp` (the site already sends COOP `same-origin`; the emulator's threads need both, ADR-228) and `/urmqtt/builder/emulator/*` is served from disk with its pre-compressed `.br`/`.gz` files, cached for good. The plain English `/products/` (every language has its own slug: `/proizvodi/`, `/en/products/`, `/de/produkte/`, ...) redirects to `/en/products/`. (A first version of that redirect had no matcher before the target, which Caddy reads as a path matcher, and answered an empty 200 for a few minutes; the unit test now pins the form.) The script edits two marked regions, removes what the first manual version left, is idempotent, keeps the first backup of the day and never reloads: `caddy validate` and `systemctl reload` stay with the operator.
  - **The pages come from the site's own generator.** `tools/builder/site/products.py` and `products_i18n.py` render the *Products* page (urMQTT is its first product, with the builder as a sub-section and a link to the source) and the *urMQTT builder* page in all 15 languages, in the site's layout; `apply_products.py` patches the generator's `build.py` with edits that must each match exactly once (a generator that changed is refused, not half edited; a second run changes nothing). The page's own script, style, module and texts are copied to `/urmqtt/builder/` with content hashes in their addresses (`?v=`), so they are cached `immutable` and a new build is picked up at once. The builder page carries **no analytics script** (the page promises there is no tracking and it handles keys) and its content policy gains `'wasm-unsafe-eval'` and nothing else.
  - **The mirror's directory survives a publish.** `publish.sh` copies the generated site into the web root with `rsync --delete`, which would delete the mirror; it now excludes `/urmqtt/releases/` and `/_x/` (the X11 test material, which lives in the same root).
  - **Listed from the start; the page is honest about what there is.** The first plan kept both pages unlisted (noindex, no link) until a release with a template existed, with a hook that published the site when the list changed. **The owner decided on 2026-11-01 to publish and link them at once**, so there is no hook (it was never installed and its files are gone): *Products* is in the header and the footer of every page in all 15 languages and in the sitemap (with `hreflang`), the Products page leads to urMQTT and to the builder, and the blog cards and the posts about urMQTT (a directory below `blog/` that starts with `urmqtt`, so the next one too) carry a short link, "Configure and download your own ISO", in the language of the page: under the card on the home page and the blog listing, and under the lead of the post. Linking is a switch of the generator (`URMQTT_PRODUCTS_LISTED=0` takes the links, the sitemap entries and the indexing away again). Because there is no release with a template yet (v0.1.0 predates the runtime configuration), **the builder page handles that state itself**: it says in plain words that no release with a configurable template has been published yet and why the existing release cannot be used, keeps the releases greyed out with their reasons and a link to the releases on GitHub, switches Build, Download and the emulator off with the same reason beside them (the status line reads "There is no release to build from yet."), and keeps what works: the form, presets, TOML import and export, and files from the computer. The page reads `releases.json` when it loads, so the first release with a template makes it usable without publishing the site again.
- **Testing.** `scripts/test-caddy-apply.py` (the Caddyfile edit: both anchors exactly once, one copy of each region, the old unmarked block removed whatever number its comment carried, a second run changes nothing, the first backup is the original) and `scripts/test-mirror-releases.py` (both in `make check`): the job against a fake GitHub API in a thread (pagination, redirects, rate limit, tokens, errors) with releases signed by throwaway minisign keys, never the real one: no template, a good one, a wrong hash, a wrong key (the ISO is never fetched), nothing changed (only the list request), deleted and edited upstream, a killed download, hostile tags and names, `--limit-rate`, `--dry-run`, free space. The builder's browser tests run against a local mirror of the same shape (`mirror-fixture.mjs`). On the server: the job ran against the real repository with the read-only API (v0.1.0 listed without a template); nginx's limits and its 404 for everything else are reached through the public address; `caddy validate` before every reload and the status of the 140 URLs of the sitemap before and after each change (identical); in a test build of the patched generator every existing page is byte for byte the page the unpatched generator writes (the pages are only added, unlisted); a browser test of the page against a mirror that lists only a release without a template (`no-release.test.mjs`: the message, the greyed release, the GitHub link, every button off with its reason, nothing requested from GitHub or for the emulator).
- **Alternatives.** Link to GitHub (no CORS, the page would need a third party). Serve the ISO from the generator's output (the generator would copy 63 MB per release into every build and `--delete` would race the mirror). A Caddy rate-limit module (custom web server binary on a shared host). A CDN (a third party that sees who downloads). A mirror inside the web server's process (a failure would take the site down). Polling every few minutes (the cost is GitHub's API for nothing; hourly is enough for releases).
- **Consequences.** The builder is visible now and **usable only when a release with `urmqtt-template-<ver>-universal.iso`, `SHA256SUMS` and `SHA256SUMS.minisig` is published** (the maintainer's key signs; nothing here creates a release); until then it is a page that explains and a form that exports a `config.toml`. Each template release costs about 63 MB on the host. Rolling back the site side is: restore `publish.sh` and the Caddyfile from their `.bak-<date>` copies, `systemctl disable --now urmqtt-mirror.timer urmqtt-mirror-web`, remove the units and `/usr/local/lib/urmqtt-mirror`, and `docker rm` the container (docs/DEPLOY.md).

## ADR-228 — "Try in the emulator": QEMU compiled to WebAssembly, optional, and what it may claim (C1g)

- **Status:** Accepted (C1g). The spike came first, as the plan asked.
- **Context.** After building an image a customer may want to see it boot before putting it on a VPS. A browser cannot give a page hardware virtualisation, so this is emulation. The kernel is an x86-64 long-mode kernel that needs x86-64-v2 and uses AES-NI, PCLMUL, SHA-NI and ADX when present, so a 32-bit emulator (v86) cannot run it. The plan also wanted an honest fallback, a recorded boot, if live emulation were infeasible.
- **Spike (what was measured).** `ktock/qemu-wasm` (QEMU 8.2.0 whose TCG backend emits WebAssembly, GPL-2.0), taking the prebuilt files of its demo repository, in headless Chrome driven over the DevTools protocol, fresh profile for each of three runs, on the development Mac. Times are since the call that starts the machine. **Template ISO** (512 MB guest, the boot menu's 10 s countdown): first serial byte of the kernel 12.5 s, crypto known-answer tests 13.1 s, the end state ("refusing to serve", an empty configuration) 14.1 to 14.3 s. **With the countdown skipped** (Enter sent at 3.2 s, 256 MB guest): first byte 4.4 to 4.6 s, end state 6.1 to 6.3 s. **A configured ISO with a NIC**: `URMQTT READY` 8.2 s with the countdown skipped, 16.1 s without. A reset boots again in the same time (no warm-up). The same kernel on native QEMU on the same Mac prints a boot of 0.82 s against 1.9 s here, and its crypto is about 58 times slower (a TLS handshake about 58 ms against about 1 ms), because the hardware instructions are emulated. The renderer holds 1.2 to 1.6 GB while it runs, 145 to 200 % of a core, and 33 threads. Two virtual CPUs work but are much slower (23 s instead of 14 s). **Not tested:** slower processors, Firefox, Safari, anything but BIOS.
- **Problems the spike found.** (a) *Blocking, and fixed:* the upstream wasm backend passes the wrong operands to the translation of x86 `POPCNT` (`tcg_out_op` calls `tcg_out_ctpop_*(s, opc, args[1], args[2])` where it must pass `args[0], args[1]`), so the kernel's own check `memory.kernel_heap_mb: must be a power of two` failed on the default 64. The fix is four bytes in the `.wasm` (`tools/builder/emulator/patch_ctpop.py`, which first checks the file's pinned SHA-256) and, as source, `qemu-wasm-ctpop-fix.patch`, which also fixes the 32-bit form; with it the serial log equals native QEMU's apart from CPU features QEMU 8.2 does not emulate. Everything else the kernel does ran: the crypto tests, APIC timer, HPET and PM-timer calibration, ACPI, PCI ECAM, virtio-scsi, -rng and -net, the in-RAM SQLite store, the TLS listener. (b) The build has no display, screenshot or VNC back end: the screen is read with the monitor's `pmemsave` about once a second. (c) UEFI does not work (OVMF dies in an Emscripten `longjmp` nobody catches): the emulator boots the ISO through BIOS only. (d) Memory comes back only when the whole worker is terminated.
- **Decision.**
  - **Integrated, optional, on demand.** The page has a second button, *Try in the emulator* (Croatian: *Isprobaj u emulatoru*), enabled once an ISO is built. **Nothing of the emulator is fetched, parsed or started before the click**: the page contains only the dialog; the click opens it with what the emulator is (size, about 3 MB the first time then cached, about 1.5 GB of memory, far slower than hardware, **no network**), and only *Start* loads `emulator/<hash>/` (a dynamic `import()` of the loader, which starts a Worker). Closing the dialog, Stop or Escape terminates the Worker, which frees everything. The boot menu's countdown is skipped by default (a switch undoes it).
  - **What the page checks while it runs.** The serial output is text in the dialog and is read for `config: fingerprint <64 hex>` (compared with the fingerprint the page computed when it built: the proof that the machine booted *this* configuration), `URMQTT READY`, `refusing to serve` (shown as a warning, e.g. no certificate) and fatal lines. The screen is a canvas. Reset restarts the machine.
  - **Where it is offered.** Only where it can run: the emulator's threads need `SharedArrayBuffer`, hence a cross-origin isolated page (COOP and COEP, ADR-227; every file the page loads is from the same origin, so nothing else changes); a phone or a device with under 4 GB is told it needs a desktop browser; an image whose `memory.kernel_heap_mb` does not fit in 1 GB is told why. Where it cannot run the button is replaced by a sentence saying why, and nothing is fetched either.
  - **No network.** The machine has a NIC without a back end: the broker starts and listens, and nothing can connect. A bridge to the outside would have to go through a relay, which would put the customer's traffic, and with it the property "nothing leaves the browser" (ADR-226), at risk.
  - **Files and licence.** The runtime is made by `tools/builder/emulator/make-runtime.sh` from the demo repository's prebuilt files at a pinned commit, each checked against a pinned SHA-256 before anything is changed, then patched (four bytes), stripped of the 28 MB of debug and name sections (40.8 MB to 12.4 MB; 2.3 MB with Brotli, 3.2 MB gzip, pre-compressed next to the file and served by Caddy) and split into its firmware files; it is a build output and is not committed. The directory is named after the wasm's hash, so everything in it is cached for good and a new version is a new address. The loader (`urmqtt-emulator.js`, `emu-worker.js`, `emu-core.js`) is this project's (MIT or Apache-2.0); the emulator is separate files under QEMU's GPL-2.0 (with LGPL, MIT and other licences of what is linked into it), not part of the page's script. `SOURCE.txt`, served next to the files and linked from the dialog, names the upstream source and commit, the licences, the pinned hashes, our change in source form and a written offer of the corresponding source (info@aldo.tech).
  - **What the project does not claim.** **Nothing seen in the emulator says anything about the broker's speed**: it runs at a fraction of hardware speed with emulated crypto instructions, and the page says so before it starts. The numbers above are engineering measurements of the emulator, not of urMQTT, and are not used anywhere else; performance figures come from a VPS (ADR-213). It is a check that the image boots and what its console says, not a test environment.
- **Testing.** No request for emulator files before the click, after a build, or when the dialog is open (a request log of the headless browser); without isolation there is no button and the page says why and requests nothing; the boot test (`make builder-test` with the runtime, a template ISO and the development certificates present, about 10 s) builds a configured image in the page, starts it and requires the kernel's fingerprint to equal the page's and `URMQTT READY`; runtime hashes are checked at build time.
- **Alternatives.** v86 (32-bit only). A recorded boot (kept as the fallback; not needed). Streaming a real VM from a server (the customer's configuration would leave the browser). Waiting for an upstream fix before shipping (the patch is four bytes and tested; an upstream report is still to be written).
- **Consequences.** The site carries about 36 MB of files (with the pre-compressed copies) that most visitors never fetch. The emulator's code is somebody else's, at a pinned commit, patched by us, under the GPL: updating it is a deliberate act (new hashes, repeat the spike's measurements for the worst case). The 1.5 GB of memory and the two busy cores mean the dialog tells the user to close it when done.

## ADR-229 — Plaintext MQTT for trusted networks: the `[plaintext]` section and blob format 2 (P1)

- **Status:** Accepted (P1). Amends ADR-215 (a format version bump) and ADR-216 (what a release kernel accepts). The listener itself is ADR-230, the password hashes and the builder page's part ADR-231.
- **Context.** Plain MQTT on TCP 1883 is what most of the IoT world speaks: Mosquitto's default, the default of Tasmota, ESPHome, Zigbee2MQTT and Home Assistant, the only thing a small microcontroller without a clock, flash for certificates or CPU for TLS can do, and normal inside a segmented plant network or behind a VPN. Over an untrusted network it is not acceptable: anyone on the path reads and changes the traffic, and a device has no identity worth the name. Until now `network.mqtt_plain_port` existed for development only (identity taken from the client id, no login, no address check) and a release kernel refused it, which is right and stays. P1 adds plaintext as an explicit, restricted opt-in that can be switched on from the configuration, the runtime blob and the builder page, with nothing compiled in.
- **Decision.**
  - **A new section, off by default**, with the keys and defaults of docs/PLAN.md P1 (`enabled = false`, `port = 1883`, `allow_from = []`, `allow_from_anywhere = false`, `auth = "password"`, `anonymous_identity = "lan"`, `users = []`, `ip_identities = []`, `max_connections = 1000`, `max_connections_per_ip = 16`, `max_packet_size = 1024`, `publish_rate_per_device = "5/s"`, `max_failed_auths_per_ip = 5`, `lockout_s = 300`, `acl_publish = ["devices/{id}/#"]`, `acl_subscribe = ["devices/{id}/cmd/#"]`, `retain = false`). No deviation from the plan's keys or defaults. The ranges are those of the field table (`urmqtt-config schema`).
  - **What is checked.** What is written is checked whether or not the listener is on: every network must be `a.b.c.d/len` with no host bits (`10.0.0.5/8` is an error, not `10.0.0.0/8`), no `0.0.0.0/0` (which is spelled `allow_from_anywhere`), no duplicates; accounts need a valid id and a password hash in the supported form; ACL filters are ordinary filters and none may start with `$`. A section that is **off** may not set `allow_from_anywhere` ("the file must not look more dangerous than it is"); the rest of an off section is inert. When it is **on**: `allow_from` or `allow_from_anywhere`, never both and never neither; `password` needs at least one account; `ip` needs at least one network, each inside `allow_from`; `anonymous` needs nothing; settings that belong to another mode are refused instead of ignored (`users` with `auth = "ip"`); the port differs from `network.mqtt_tls_port` and `network.mqtt_plain_port`; an identity (an account id, the anonymous identity, a network's id) may not be one of `acl.service_ids` (prefixes included), `acl.operator_ids` or `control.service_ids`, because a plaintext client never holds those roles and the same name on both sides would only confuse a reader of the logs. The rules live twice, as ADR-215 accepts: `urmqtt_cfg::check` for the blob (the kernel, at every boot) and `validate_plaintext` for TOML (messages that name the entry); a test compares their verdicts on a table of shapes of the section (off with leftovers, every mode, missing and clashing keys, roles, ports).
  - **A release kernel accepts it only through this section.** `network.mqtt_plain_port` stays a development option and is refused outside `env = "dev"` (smoke `release-kernel-refuses-plaintext-port`, whose hand-made version 1 blob still reads). The new section has no `dev_only` field. A dev kernel accepts both; they may not share a port.
  - **Blob format 2.** `FORMAT_VERSION` is 2 and the reader still reads 1 (`FORMAT_MIN`): an installed disk keeps its configuration across a kernel update (ADR-217), so a kernel that knows 2 must boot a disk that holds a 1. Tags 170 to 186 are new and each field carries `since`; a version 1 blob that holds a record of version 2 is refused, so a 1 means exactly what it meant. The writer always writes 2, including the empty configuration in a template ISO, which is how the release mirror and the builder page learn the format a template's kernel reads (`config_format`). A kernel that only knows 1 refuses a 2 by its version, before it reads a record. The price: re-packing an old TOML gives a different fingerprint (the version byte is in the hash). The golden blob `lab.blob` pins format 2; `lab-v1.blob`, the golden of the first release of the configuration, is kept to prove that format 1 still reads, checks and shows with the fingerprint it always had. A cheaper-looking rule ("the lowest version that holds the records", so unchanged configurations keep their bytes) was tried and dropped: it makes the empty blob in a template say 1 forever, which hides the format the kernel reads from the mirror and the page.
  - **How lists are stored.** The blob has no new value kinds. `allow_from`, `users` and `ip_identities` are lists of strings with a hint (`Item`) that the check, `show` and the builder read: `10.0.0.0/8`, `sensor-1 pbkdf2-sha256$...`, `10.0.1.0/24 plc`. No entry contains a space inside a part. In the TOML file the last two are arrays of tables (`{ id, password_hash }`, `{ from, id }`) as the plan has them; the packer joins the parts. The schema JSON gains `since` and `item` per field and `format_min`.
  - **Tooling.** `urmqtt-config hash-password [--id NAME] [--iterations N]` reads the password from standard input (never an argument, so it stays out of shell history and the process list) and prints the hash, or the table to paste. `show` prints accounts as `id (pbkdf2-sha256, N iterations)` and never the hash; `show`, `pack` and `verify` print a `warning:` line when plaintext is on (port, mode, number of accounts, networks, "NOT ENCRYPTED"). The WebAssembly module gains `ub_hash_password`, which overwrites its copy of the password before it returns (ABI version 2).
- **Alternatives.** Reusing `network.mqtt_plain_port` for the release kernel (it has no allow-list, no login and takes the identity from the client id: that is a development tool). A new blob value kind per list (three kinds, three decoders, and the builder would need each); strings with a hint cost one check function per list. Password hashes inside a separate file named by the TOML (another file for the browser to carry, and the point of the section is that the keys of the TOML are all there is).
- **Consequences.** The field table grows from 70 to 87 fields; `.bss` grows by the three typed arrays of the configuration (64 networks, 256 accounts, 64 network identities) and 32 string slots, about 10 KiB. The builder module is `urmqtt-cfg2.wasm`. An ISO configured before this change boots as before (version 1 blob, plaintext off); an ISO configured after it needs a kernel from this change on.

## ADR-230 — The plaintext listener: filtering at the SYN, three login modes, lock-out, session namespace (P1)

- **Status:** Accepted (P1). Builds on ADR-229 (the configuration) and ADR-231 (the password hashes).
- **Context.** A device that cannot do TLS needs a port it can talk to, on a network where the owner has decided the cost of plain TCP is acceptable. The same machine also serves TLS clients and the operator. A plaintext port is a way in for anything that can reach it, so the design question is what it may *never* give: its clients must not be able to become services, operators or the control channel, must not be able to take over a TLS device's session, and must not be a cheaper way to exhaust the broker than the TLS port is.
- **Decision.**
  - **Filtering happens at the SYN, and costs no state.** `App::syn_ok` for the plaintext port asks, in this order: is the source in `allow_from` (or is `allow_from_anywhere` set), is it locked out, does it hold its maximum of connections, is the listener full, is there a login-rate token and is memory free. Any "no" is **no SYN-ACK**: the peer sees silence, as for a closed firewall, and the kernel keeps no connection, no timer and no table entry for it. The checks run again at the final ACK (state may have changed since the cookie was sent), and only then is the connection counted. A scan of the allowed networks therefore costs the broker one comparison per SYN.
  - **One table of source addresses for all cores** (`urmqtt-plain::Sources`, behind a spin lock): per address, its connections, its failures in the current window and its lock-out. It is a fixed set of 8-way buckets, hashed under a per-boot random key (the generator must be up or boot stops), sized at twice `max_connections`. An address is entered only when it opens a connection that passed the allow-list or fails a login, never for a SYN; a full bucket drops an idle slot, never one with a live connection or an active lock-out, and when none can be dropped the new connection is refused rather than left untracked. One table, not one per core, because a client's connections spread over the cores by the hash of their 4-tuple, and a lock-out that one core knew would be a lock-out in name only.
  - **Three login modes** (`urmqtt-plain::Authenticator`). *password* (the default): the MQTT user name picks an account, the password must match its PBKDF2 hash, the user name is the identity. Every refusal (no credentials, unknown user, wrong password) is the same CONNACK 4 and **exactly one hash is computed on every path** (a decoy hash with the dearest account's iteration count stands in for an unknown user, the comparison is constant time), so neither the answer nor the time says whether a user exists. *anonymous*: every client is `anonymous_identity`; credentials sent are ignored. *ip*: the longest matching network of `ip_identities` names the identity; a source in none gets CONNACK 5. The configuration check refuses an identity that is also an `acl.service_ids`, `acl.operator_ids` or `control.service_ids` entry, and an identity may only use `A-Z a-z 0-9 - _ . :` (no `$`, `/`, `+` or `#`), and the broker gives every plaintext session the plaintext role whatever its name is.
  - **Lock-out.** A failed login (a CONNACK 4 or 5 from the checks above, an unreadable first packet, a first packet that is no CONNECT) counts against the **source address**; `max_failed_auths_per_ip` failures inside `lockout_s` lock the address out for `lockout_s`. A locked-out address gets no SYN-ACK (and the connections it already holds are not touched: they passed). A success clears the count. Failures are by address, not by user name, so a user name cannot be locked out by someone else, and a client behind one NAT shares its address's fate, which is the cost of the rule and is why the defaults (5 in 300 s) are generous for a legitimate typo.
  - **A login costs CPU, so it is admitted at a rate.** Plaintext has its own `Admission` instance per core, not the TLS one: the TLS path is untouched. In password mode each new connection takes a token from a bucket whose rate is `0.5 s / (cost of one hash)` per core, measured at boot (`plaintext: one password check costs about N us`), at least 20 and at most the TLS handshake rate (**amended by ADR-267:** at least 1, so the half-core rule holds at any cost). The watchdog's handshake budget is calibrated with the dearer of a TLS handshake and a password check, and a plaintext connection that has not sent its CONNECT counts as handshaking for it.
  - **The identity is the user name, and it is the ACL's `{id}`.** A plaintext session's ACL name is its identity; the patterns are `plaintext.acl_publish` and `acl_subscribe` (`{id}` is replaced), not the device ACL. Several devices may share an identity (anonymous and ip modes always do).
  - **The session namespace is separate.** The session key is `$plain/<identity>/<client id>`. `$` cannot start a certificate identity or a client id the TLS side accepts, so a plaintext client cannot collide with, take over or be taken over by a TLS session. The client id itself is free text (Mosquitto's tools send `mosqpub/<pid>` or, for MQTT 3.1.1 without `-i`, nothing): a non-empty id is used as sent, an empty one with a clean session is named `auto-N` by the broker. Plaintext sessions are **clean only**: a CONNECT with `clean_session = 0` is answered CONNACK 5 (2 if the id is also empty), so there is no stored session to be read by the next client with the same name and no offline queue to fill.
  - **What a plaintext connection never gets.** No service, operator or control role (the check is in the broker, not in the listener); no `$SYS` subscription and no `$urmqtt` topic; no console; no retained messages unless `retain = true` (a retained publish is delivered to current subscribers and not stored); a will is checked against the plaintext ACL like any publish. Its packets are limited to `plaintext.max_packet_size` (1024) from the first byte, its publishes to `publish_rate_per_device` (5/s) by a token bucket per session, and the broker's usual queue and in-flight limits apply.
  - **The registry applies.** When a device registry is installed, an identity must be in its allowlist to log in on the plaintext port (CONNACK 5, counted in `refused_registry`), so the signed control channel's `disallow` revokes a plaintext account's identity the same way it revokes a certificate. Adding or removing an account at run time is *not* done: a new password hash needs a signed control message type and a place to keep it across reboots, which is a second feature of the size of this one; accounts are changed by building a new image (the builder or `urmqtt-config pack`) and revoked at once by `disallow`. Documented as later.
  - **Counters, not log lines, are the record.** `$SYS/broker/plaintext/{enabled,port,auth,allow_from,accounts,connections,accepted,refused/source,refused/locked_out,refused/limit,refused/registry,refused/session,auth_ok,auth_failed,lockouts}` (one topic, `enabled`, while the listener is off), the same in the JSON object and in the status line, readable by the operator only. The log says a refusal kind at powers of two (1, 2, 4, 8, ...), so a scan does not flood the serial console. A lock-out is always logged, once, with the address.
  - **The boot report says what is on.** One `warn!` line with the port, the mode, the accounts, the allowed networks and all limits; a second when `allow_from_anywhere` is set; a third for anonymous and for ip mode saying what they do not prove; and a warning once the machine's own address is known and is public: a loud one when the allow-list admits public addresses (`Exposure::Open`), a milder one when only private networks are allowed (which holds only while nobody between can forge a source address).
- **Testing.** Host: `urmqtt-plain` (allow-list, table, authenticator: 25 tests, including lock-out windows, bucket pressure with live connections never dropped, decoy timing path, identity refusals), the broker (`Role::Plain` rules in `acl.rs`, session namespace, clean-only, empty id, retain, will, rate, packet size, no `$SYS`, no control) and a fuzz target for the parsers and the table against a model (`plain_input`; `broker_input` now opens plaintext connections). Smoke (`scripts/smoke.sh`, group `plaintext`, on aarch64 HVF and x86_64 TCG): password, lockout, refused, anonymous, ip, limits and registry modes, each against a real VM from the host (`scripts/plain-scenarios.py` and the Mosquitto tools), and TLS clients on the same VM in the password mode.
- **Alternatives.** Rate-limiting by user name (lets anyone lock out a user, and says whether a user exists). Per-core tables (an attacker gets `cores` times the guesses; a lock-out is partial). Answering a refused SYN with RST (it tells a scanner that something is there and costs a packet). Keeping stored sessions for plaintext clients (a session left behind by a device is readable by whoever uses its name next; the cost of clean-only is that a device that wants queued messages for when it was offline must use TLS). Accepting `clean_session = 0` and ignoring it (a client that expects its subscriptions to survive would be told yes and find them gone).
- **Consequences.** The plaintext listener adds one `Option<Box<PlainState>>` per core (None when off) and a few branches in code the TLS path passes (a port comparison at SYN and accept, an `Option` test in `is_handshaking` and `drop_conn`); measured, the TLS path does not change (docs/PERFORMANCE.md). `.bss` grows by the table of source addresses only when the listener is on (it is a heap allocation). Lock-outs are by IPv4 address: behind a NAT the clients share one, and the allow-list is the better tool there.

## ADR-231 — Password hashes, and where a password is never seen (P1)

- **Status:** Accepted (P1).
- **Context.** The password mode needs stored credentials. The image is a file anyone with the ISO can read, the config blob is not secret (its fingerprint is printed at boot and compared by customers), and the kernel is `no_std` with no password-hashing crate vetted for it. What is stored must make guessing expensive, and the page that makes it must not send the password anywhere.
- **Decision.**
  - **PBKDF2-HMAC-SHA-256**, 16 to 32 bytes of salt, 1000 to 200 000 iterations (default 10 000, a deliberate balance: about 2.5 ms on the HVF test machine, measured at boot and used to size the login admission rate, so a core that is admitting logins at its limit is not starved by them), 32-byte derived key. Text form `pbkdf2-sha256$<iterations>$<salt hex>$<key hex>`, stored in the blob as `<user> <hash>`. It is written on top of `sha2`, which the kernel already carries (HMAC is 30 lines on it; `subtle` is the one new dependency, for the comparison); it is checked against RFC 7914's PBKDF2-HMAC-SHA-256 vectors and published vectors for 1 and 4096 iterations, and against the host tool (`urmqtt-config hash-password`) in `tools/config/tests`. A memory-hard function (Argon2, scrypt) would be better against GPUs and is not in the kernel's dependency set; the iteration count is in the hash, so a stronger one can be added as a second scheme without a format change. The cost of this choice is stated in docs/SECURITY.md: a stolen image allows an offline guess at roughly the speed of a GPU's SHA-256, so passwords must be long and random, and the builder generates them.
  - **Comparison is constant time** (`subtle`), the length of a password is capped at 256 bytes (so a client cannot make a hash cost more than a field's worth of CPU), and the iteration count a client's account asks for is capped at 200 000 by the parser, so a hostile blob cannot make a login take seconds.
  - **No clear password anywhere persistent.** `urmqtt-config hash-password` reads the password from standard input only (not an argument: not in shell history or the process list), refuses an empty password, and prints the hash. The builder page hashes in the browser by the same module (`ub_hash_password`, ABI 2): the clear password is passed to WebAssembly in a buffer the module **wipes after use**, the field is cleared, and **only the hash is kept**: it is not written to the address bar (`#s=` carries the release, preset, name and changed *non-secret* values), nor to `sessionStorage`; a reload loses the accounts, and the page says so. The accounts editor can generate a random password (shown once, with a copy button), so the usual path never involves a person-chosen password at all.
  - **Salts are random per account** (`/dev/urandom` in the tool, `crypto.getRandomValues` in the browser). Two accounts with the same password have different hashes.
- **Testing.** Cfg: the vectors, parse round-trips, every malformed form; the tool: the same password hashed twice differs, verifies, an empty or 257-byte password is refused, the password never appears in an argument or output; builder: `password.test.mjs` (the hash equals the tool's for the same salt, the buffer is wiped, nothing in storage or the URL after entering accounts), `plaintext-page.test.mjs` (the accounts editor in a browser).
- **Alternatives.** A plain `user:password` list in the blob (the image would carry every device's password in the clear). Hashing in the kernel at boot from clear passwords in the config (same problem, and the clear password would sit in the ISO). bcrypt (not in the dependency set, and it truncates at 72 bytes). Argon2 (the memory cost on a core that also serves TLS needs its own admission, its own measurements and a vetted `no_std` implementation; left for later as a second scheme).
- **Consequences.** A hash is public once an image is. Anyone with the ISO can try to guess the passwords offline; the defence is a long random password, not the hash. Changing a password means building a new image.
- **Amended by ADR-267:** the default is 100 000 iterations (the range stays 1000 to 200 000; hashes carry their count, so those made with 10 000 keep working), and D-16 (Argon2) is answered "not now" with the reasons and the conditions to revisit.

## ADR-232 — The builder is simple by default and advanced when needed; the emulator's keyboard and boot entry (C1e, C1g)

- **Status:** Accepted. Amends ADR-226 (the page) and ADR-228 (the emulator).
- **Decision.**
  - **Two views over one state.** The default is a short page of three plain steps: *Where will it run?* (three cards: a server with a fixed address, a VM or lab machine on DHCP, DHCP first then a fixed address; a card that needs an address shows only address and gateway), *Your certificates* (one drop zone that takes the server certificate, its key and the CA together, sorts them by what they contain with the same checks as the import dialogs, lists what it found and what is still missing, and links to the docs for test certificates: generating X.509 in the browser would need a hand-built certificate encoder, which was not worth the risk) and *Name your image* (with the extras Diagnostics and plain MQTT, whose confirmation dialog stays). The release is chosen without a click, its signature is checked at once and shown as a small "Verified" chip with the report one click away; "change version" opens the list. The sticky bar names one next action ("Next: add your certificates") and then Build; after a build the focus goes to Download and the result card (file, size, SHA-256, fingerprint, what to do next) is on screen instead of a dialog. **Advanced** (a switch, remembered in `localStorage` and in the address as `a:1`, so it can be linked) is the whole form as before plus a search over names and help and an "only what I changed" filter. Both views read and write the same state (`app.state`), so switching loses nothing; the simple view's words are its own, the advanced view keeps key names and ranges. A problem in a field only the advanced view has opens that view.
  - **The template is fetched while the page is filled in.** When a release is chosen the template download starts at once (same origin, with the signature check running beside it) into a buffer of the module; Build uses it, shows MB and an estimate otherwise, and starts the next download after a build. Not on a phone or a device with under 4 GB. Nothing of the emulator is fetched before its click, as before.
  - **Emulator keyboard.** The screen takes the focus when the machine starts and on click; letters, digits, arrows, Enter, Escape and the function keys go to the guest through the monitor's `send-key` (Tab stays with the page, so the keyboard can leave). The cause of "keys do not arrive" was that nothing listened: the dialog had no key handling at all.
  - **Boot entry without keys.** The dialog offers *urMQTT* or *Diagnostic*; the choice (and the optional skip of the countdown) is written into the emulator's own copy of the image by changing, to the same width, the `timeout:` and `default_entry:` lines of every `limine.conf` in it. The file offered for download is not touched. Under emulation the diagnostic finishes its benchmarks in about 20 s (the kernel's own clock says 10 s), and the dialog says that its numbers describe the emulator.
- **Tests.** `simple.test.mjs` (the three steps, one-go certificates, build, result card, switching and back, the link), `emulator-entry.test.mjs` (the Diagnostic entry without keys, and with real key events), the existing page tests run in the advanced view, the 15-language parity test.

## ADR-233 — The two listeners are independent: `network.mqtt_tls_port = 0` turns TLS off, blob format 3 (C1e, P1)

- **Status:** Accepted. Amends ADR-215 (a format version), ADR-216 (what a release kernel needs to serve) and ADR-229 (plaintext MQTT).
- **Context.** Since P1 the plaintext listener runs beside the TLS one, but TLS could not be left out: `network.mqtt_tls_port` was 1 to 65535 and the kernel refused to serve without a server certificate, its key and an operational CA. A plant network that only wants plain MQTT on a trusted segment (the case P1 was made for) had to carry certificates it never used. The builder's simple view now asks the question directly: two checkboxes, TLS (mutual TLS, port 8883, on by default) and plain MQTT (port 1883, trusted networks only, off), at least one on.
- **Decision.**
  - **`network.mqtt_tls_port = 0` is the TLS listener off, and only with `plaintext.enabled = true`** (a broker needs a listener): in the field table (range 0 to 65535), in the strict TOML parser (`config-schema`) and in the kernel's blob check, which agree on it; the same error text everywhere. The two listeners may then share a port number (plain on 8883 is allowed when TLS is off). With TLS off **nothing of the TLS side is required**: no `tls.cert`, `tls.key` or `trust.operational` (`missing_to_serve` is empty), the certificate expiry watch is silent, and the builder neither asks for nor writes the `tls`, `trust` and `control` sections.
  - **What TLS off costs, stated where the user decides.** There are **no operator, service or control rights at all** (they exist only as certificate identities over mutual TLS), no `$SYS` topics and no console; a device's identity comes only from the plaintext login mode (accounts, one shared identity, or its network); nothing is encrypted. The kernel logs `mqtt: TLS listener off (plaintext only: ...)` at boot instead of the TLS line, answers no connection on the old port, and does not set up a TLS server at all. The simple view shows this next to the box, the build asks the same question as for any plaintext image (ADR-229) plus one about TLS being off, and the allowed-networks field is required as before.
  - **Blob format 3 and what stays valid.** `FORMAT_VERSION` is 3, `FORMAT_MIN` still 1, the records of 2 and 3 are the same. **The packer writes the lowest version that can hold the configuration**: 2 as before, and 3 only when the TLS port is 0, so every image that does not turn TLS off still boots on a v0.2.0 kernel (and an installed disk keeps reading its blob across a kernel update, ADR-217). A kernel that knows only 2 refuses a 3 by its version before it reads a record. The empty configuration of a **template ISO** is written in the newest version (`urmqtt-config pack --latest-format`, used by `scripts/mkiso.sh`), which is how the mirror's `config_format` says what a release's kernel reads: v0.2.0 says 2, v0.2.1 says 3. `configure_iso_in_place` refuses a configuration whose version is above what the template's own slot has (with the reason in words), so an image that an older kernel would refuse is never offered.
  - **The page chooses the release that can do what is asked.** While the release is the page's own choice (the user has not picked one), it is the newest stable release whose template can run the selected listeners; choosing TLS off moves to a release of format 3 and back when TLS is turned on again; releases that cannot are greyed out in the list ("too old for an image with TLS off: that needs v0.2.1 or newer") and the version line says so. Releases are accepted up to the module's own format (the module is `urmqtt-cfg3.wasm`), no longer only equal to it.
- **Testing.** Schema and packer (`tls_off_tests.rs`: refused without plaintext, packs without any certificate, format 3 only then, both listeners and TLS only stay 2, a lower version than needed is refused, the template's newest format), `cfg` tests, the module's tests; smoke scenario `plaintext-plainonly` (dev kernel: `mqtt: TLS listener off`, no TLS listener line, an anonymous plaintext client from the allowed network publishes and receives, a TLS client on the old port gets no handshake) on aarch64 under HVF and x86_64 under TCG, and the existing `plaintext-*` scenarios run TLS and plain together; browser tests for the combinations (`listeners.test.mjs`): TLS only, plain only (certificate step hidden, image verified by the tool, `mqtt_tls_port = 0` in it), both, at least one on, the release follows the choice.
- **Alternatives.** A separate boolean `network.tls_enabled` (two ways to say the same, and a port of 0 next to `enabled = true`); a format bump for every image (an older kernel could then not boot images that do not need it); letting the kernel serve plain-only with certificates present but unused (the point is to need none).
- **Consequences.** A plain-only image is the least safe thing this project builds, and says so; it exists because a trusted segment is a real place. The next release (v0.2.1) is the first that can run it; the live v0.2.0 keeps working for everything else.

## ADR-240 — Encryption at rest: AES-256-XTS under the disk layer, a key in the configuration, conversion offline (S7)

- **Status:** Accepted. Amends ADR-030 (the disk layout: one flag and a key check in the superblock) and ADR-215 (blob format 4).
- **Context.** The data partition holds the registry, retained messages, queued messages and the telemetry ring. On a VPS the cloud provider can snapshot the volume; on bare metal a disk can be taken out. STORAGE-PLAN S7 asks for optional encryption, off by default, with measured overhead.
- **Decision.**
  - **Where.** A `BlockDevice` wrapper, `urmqtt_store::crypt::CryptDev`, sits **below** `Disk`. The layout, the size table, the VFS, the telemetry ring, the backup region and the scrubber all work on plaintext and know nothing of it; the SQLite page cache and the telemetry buffers are plaintext in RAM, as before. `Disk::open_keyed` is the one place that decides (plain disk and no key, encrypted disk and the right key, blank disk and a key = formatted encrypted); every other combination is refused with its own error (`KeyRequired`, `NotEncrypted`, `WrongKey`, `ConversionPending`).
  - **Algorithm.** AES-256-XTS, IEEE 1619, from the RustCrypto `aes` crate (the hardware backends the TLS code already uses: ARMv8 AES through the sealed dispatch, AES-NI), the XTS mode written here (about 60 lines, checked against the first block of IEEE 1619 vector 10 and, over whole sectors, against a naive reference implementation; the tweak step is branch-free). **One 512-byte sector per data unit, tweak = sector number**, not one 4 KiB block as the plan said: the store writes in whole device sectors (a 512e disk takes 512-byte writes), and a 4 KiB data unit would turn each of them into a read-modify-write that a crash can tear.
  - **Holes.** An all-zero sector on the medium is read as zeros and not decrypted (`crypt` module). Without this, every never-written, discarded or zeroed sector (S4) would decrypt to noise and the telemetry ring's blank test, the grow code and the scrubber would see damage everywhere. Cost: the medium shows which sectors were never written (a thin-provisioned volume shows that anyway); the chance that real ciphertext is all zero is 2^-4096.
  - **The superblock.** `flags` bit 1 (encrypted) and a **key check** at offset 3136 (HMAC-SHA-256 keyed with the disk key over a label and the disk UUID). The two superblock slots stay plaintext; everything else in the partition is ciphertext. The unknown flag bit is what keeps a kernel that predates S7 from opening the disk, so **no minor version is spent**.
  - **Key and configuration.** `storage.encryption = "off" | "aes-256-xts"` and `storage.disk_key`, the name of a file with the key (64 raw bytes or 128 hex digits; two different halves; not one repeated byte), read by the packer into the blob (tag 86). **Blob format 4**: the packer writes 4 only when encryption is on, so every other image still boots on older kernels (the rule of ADR-233). The blob check in the kernel, the strict TOML parser and the packer agree (`encryption_tests.rs`); `Debug` of the key shows only its length.
  - **No hardware AES: refuse.** The kernel refuses `storage.encryption` on a CPU without AES instructions (or with `[cpu] disable` turning them off), with a message, instead of running XTS at a fraction of the speed. Adiantum was considered and not built: it is a second cipher, a second implementation to audit, for CPUs that no VPS offers.
  - **Never at boot.** The kernel does not encrypt, decrypt or rekey a disk. `urmqtt-disk encrypt | decrypt | rekey DISK --write` does it offline (§14.1 of DISK-FORMAT): a conversion record written first and cleared last, 1 MiB chunks with their old bytes journalled on the host, the superblock switched last, `--resume` after a cut. `--key FILE` opens an encrypted disk for every other command.
  - **The builder page does not offer it yet.** It needs a key dialog (generate, download, import); until then encryption is set with the TOML and `urmqtt-config pack`.
- **Testing.** XTS against IEEE 1619; the crypt layer (ciphertext on the medium, holes, superblock plain, wrong key, no key, a key for a plain disk, SQLite and the telemetry ring on an encrypted disk, no SQLite header on the medium); the conversion procedures (all three, with a power cut clean and torn, cache dropped and kept, at every write: the disk ends converted with its data); `disk_format_spec` with an encrypted superblock; configuration (`encryption_tests.rs`, `cfg`); smoke `storage-encrypted` on aarch64 (HVF, TCG) and x86_64 (TCG): first boot with the self-test and the backup, no plaintext in the data partition, second boot, another key refused, no configuration refused, the tool with and without a key, `decrypt` then a plain boot.
- **Alternatives.** Encryption inside SQLite (SQLCipher: not the telemetry ring, a second SQLite build); dm-crypt-style per-partition keys derived from a passphrase (nobody is there to type one; the key is in the ISO, see below); AES-GCM per block (integrity, but a tag per sector and nonce management that a crash can get wrong); a header-encrypted superblock (the kernel could not tell a wrong key from a damaged disk).
- **Consequences.** It protects a **stolen volume or snapshot** and nothing else: the key is in the ISO's configuration, so whoever has the ISO (or the running machine's memory) has the key. XTS gives no integrity: a flipped bit scrambles 16 bytes (the CRCs and the scrubber find it) and two snapshots can be mixed sector by sector. Rekeying and the first conversion are offline and take as long as the used part of the disk takes to read and write. A TPM-sealed key is H8's spike on bare metal.


## ADR-250 — The loaders' configuration is enrolled (`limine enroll-config`), and the tests that prove it (H8)

- **Status:** Accepted. Amends ADR-043 (the universal image) and ADR-217 (the installed disk's configuration).
- **Context.** `limine.conf` pins the kernel and the configuration module by blake2b, but the file itself was unprotected: whoever could rewrite one text file of the image could add an entry, change the command line (`install` on the first entry) or drop the hashes. SECURITY-PLAN H8 asks for the configuration to be enrolled into the loaders and for a test that a modified kernel or configuration does not boot.
- **Verified for Limine v12.9.4** (vendored `limine.c`, and by booting): `limine enroll-config <loader> <blake2b>` writes the 128 hex digits after the string `++CONFIG_B2SUM_SIGNATURE++`, which is present exactly once in **`BOOTAA64.EFI`, `BOOTX64.EFI` and `limine-bios.sys`** (the BIOS stage 2) and not in `limine-bios-cd.bin` (stage 1, which has no configuration). All three refuse a `limine.conf` that differs by one byte: the two EFI loaders print `!!! CHECKSUM MISMATCH FOR CONFIG FILE !!!` (read from the serial port in the tests); the BIOS stage refuses too, but prints before it has read `serial: yes`, so its refusal is on the screen only and the test asserts that the machine does not boot (with a control that does).
- **Decision.**
  - `scripts/mkiso.sh --universal` enrolls **two sets of loaders**, because the image has two configurations: the no-menu `limine.conf` of the installed disk's ESP (`--esp-out`, `--disk-out`, the installation image) and the menu of the ISO. Order: ESP config, then the ESP (so `disk.img` exists and can be hashed), then the menu with the installation image's hash, then the ISO's loaders enrolled with the menu's hash. The enrolled copies are made from the vendored binaries, which stay as upstream ships them (and as `vendor/limine/CHECKSUMS` records). `--no-enroll` builds the control for the tests.
  - Both configs end with the line `# end of limine.conf` and start with a known comment: tools find the copies by those markers, without parsing ISO 9660 or FAT.
  - **`urmqtt-config pack --iso`** changes the menu's module hashes, so it re-enrolls: every loader slot holding the old menu hash takes the new one (same length, in place, deterministic: a packed template equals the ISO built with that configuration, byte for byte; the smoke scenario `universal-config` compares them). `verify` now also refuses an image where a loader is enrolled with a hash that is no `limine.conf` of the image. The web builder uses the same code. **The builder's emulator** edits `timeout:` and `default_entry:` in its private copy of the ISO; it resets the enrolled hash in that copy (what `enroll-config --reset` does), the download is untouched.
  - The installed disk's configuration lists the configuration module without a hash (ADR-217) and so does not depend on the customer's configuration: its enrolled hash is the same for a given build. `urmqtt-disk update-boot` replaces the whole ESP, loaders included.
  - The aarch64-only and x86_64-only images of `mkiso.sh` (smoke tests; not released) are **not** enrolled.
  - `URMQTT_LIMINE_SERIAL=1` (tests only) adds `serial: yes` so Limine's messages reach the serial log.
- **Testing.** `SMOKE_ONLY=integrity` on the universal image, on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS: kernel (ISO and raw disk) and configuration module refused; an edited `limine.conf` refused in the ISO and in the raw disk; controls: the other architecture's kernel changed (boots), and the same `limine.conf` edit in an image built with `--no-enroll` (boots, so the refusal is the enrollment and nothing else). Rust: `configuring_the_template_enrolls_the_loaders_again` and `verify` of an inconsistent enrollment.
- **What it does not do.** Without Secure Boot (ADR-251) an attacker who can rewrite the **loader itself** (or `limine-bios.sys`, or the MBR/stage 1) replaces the check with it; enrollment stops edits of the configuration, not of the chain's first link. The BIOS path has no signature at all. The installed disk's module is not pinned (ADR-217), so a rewritten configuration slot there is caught only by the kernel's own checks (fingerprint, optional signature).
- **Alternatives.** Embedding the configuration in the loader (`limine.conf` inside the EFI binary: a second copy of everything, and the BIOS stage cannot); hashing the whole ISO in the firmware (not possible without Secure Boot).

## ADR-251 — Secure Boot: signed loaders, enrolled configuration, and the two limits that follow (H8)

- **Status:** Accepted for x86_64 and the build path; the Intel PC, Proxmox and aarch64 enforcement are **not done** (below). Builds on ADR-250.
- **Context.** SECURITY-PLAN H8: sign the EFI loaders with a project key, document enrollment, test OVMF with Secure Boot on. The chain that Secure Boot can protect is: the firmware verifies the loader's Authenticode signature; the loader verifies its enrolled `limine.conf` hash (ADR-250); `limine.conf` pins the kernel and the configuration module by blake2b. With Secure Boot active Limine additionally refuses any file with no hash.
- **Decision.**
  - **Signing** is `scripts/sign-loaders.sh sign` (`sbsign` when installed, else `osslsigncode`), called by `mkiso.sh --universal --sb-key KEY --sb-cert CERT` as the last step on the two EFI loaders, *after* enrolling (the signature covers the enrolled hash). Only the EFI loaders are signed: the kernel and the module are not PE files and are covered by hashes; `limine-bios.sys` is the BIOS path, which has no signatures. The signing time is `SOURCE_DATE_EPOCH`, RSA PKCS#1 v1.5 is deterministic, so the signed ISO is reproducible for a given key (tested).
  - **Keys.** `gen-keys` makes development keys under `build/` for tests. The release key is generated and kept offline by the maintainer (HSM or air-gapped machine) and is never in the repository. **No release signs with a project key yet:** the release workflow does not have one, so published template ISOs are unsigned and do not boot under an enforced Secure Boot. That is a decision for the maintainer (key custody, rotation, a `dbx` plan), not something the repository can settle.
  - **Enrollment** is documented for OVMF/QEMU (tested: `scripts/sign-loaders.sh ovmf-vars` builds a variable store with PK, KEK, db and Secure Boot on with `virt-fw-vars`; `run-qemu.sh --secure-vars` boots OVMF's SMM Secure Boot build), Proxmox (efidisk without pre-enrolled keys, or the firmware setup; **not tested**) and a physical PC (setup mode and `db.der`, or MOK through `shim`, **not tested**). Own keys in `db` are the documented path; MOK/shim is open: it needs a shim signed by Microsoft that this project would have to ship and rebuild-trust, and it moves the root of trust from the owner's key to Microsoft's.
  - **A CI test boots OVMF with Secure Boot enabled:** `SMOKE_ONLY=secureboot` (x86_64 q35, SMM): the signed ISO boots; unsigned, signed by another key, and changed after signing are `Access Denied`; under Secure Boot a modified kernel and a modified `limine.conf` are still refused by Limine. The scenario skips with a printed notice if a tool is missing and fails with `SMOKE_REQUIRE_SB=1`.
- **Limits found by testing, and recorded rather than hidden.**
  1. **The template ISO and signing do not compose.** The configuration lives in `limine.conf` as the module's hash, so configuring an ISO (`pack --iso`) re-enrolls the loaders and invalidates their signature (the firmware refuses it: tested as `configured-after-signing`). A signed image is therefore configured *and then* signed by whoever owns the key; the web builder cannot produce a Secure Boot image from the template. Making the template configurable while signed would need the enrolled hash outside the signed bytes, which Limine does not offer.
  2. **An installed disk does not boot under Secure Boot** (tested, asserted as `installed-disk-known-limit`). ADR-217 lists the configuration module without a hash on the installed disk, and Limine refuses a file without a hash when Secure Boot is active. The fix is a per-machine ESP whose module is pinned and whose loader is re-enrolled and re-signed by the key's owner at install time: **not done**.
  3. **aarch64:** the AArch64 edk2 build on the development machine does not enforce Secure Boot (an unsigned ISO boots with keys enrolled), and `run-qemu.sh` boots aarch64 with `-bios` (no variable store). The aarch64 loader is signed and its signature is checked offline; enforced booting of it is **not tested**.
  4. No rollback protection (no `dbx` entry for an older loader, no version counter), and the BIOS path is unprotected beyond ADR-250.
- **Alternatives.** Shipping shim and MOK enrollment (above); signing the kernel as a PE/UKI so that the firmware verifies it (the kernel is a Limine-protocol ELF; a UKI is a different boot path and loses Limine's multi-arch menu); a `pack --iso` that re-signs (needs the private key in the builder: refused).

## ADR-253 — What may start the installer: three production words, a module the loader pins, and an enrolled menu (H8)

- **Status:** Accepted. Corrects the wording of SECURITY-PLAN H8, amends ADR-052.
- **Context.** The installer erases a disk. H8 asked that "the prod kernel accepts exactly one command-line word, `install`, and only together with the hash-pinned `esp.img` module". Reading the code: a production kernel honours **three** words, `install`, `live` and `diag` (ADR-052, ADR-054, ADR-063); `live` and `diag` were added after the plan and neither writes to a disk the installer would (the diagnostic writes only in unallocated space after a typed confirmation). Everything else is ignored in production (`BootOptions::parse`, tests `production_ignores_every_option` and `production_honours_*`).
- **Decision.** Keep the three words. The rule that matters is the one about disk writes: **`install` writes nothing unless the installation image is present**, and the image is present only as a module that Limine has checked against the blake2b in the menu. The kernel does not hash the module again: it is the loader's check, and the loader's configuration is enrolled (ADR-250), so the pair (word, module hash) cannot be changed by editing the menu. No change to the kernel was needed.
- **Testing.** Host tests as above. Smoke `SMOKE_ONLY=install-rules` (aarch64 UEFI, x86_64 UEFI, x86_64 BIOS), each with a blank 64 MiB disk attached and its SHA-256 compared afterwards: (1) `cmdline: live smoke` edited to `install no` (same length) is refused by the enrolled loader (BIOS: no boot, message on the screen only); the control, the same edit with `--no-enroll`, reaches the kernel with `install`, which prints `install: no installation image` and writes nothing; (2) a flipped bit in the copy of `disk.img` that the install entry pins makes Limine panic with `Blake2b hash for URI boot():/disk.img does not match`, before the kernel runs. The honest path (`universal-install`, 12 scenarios) is unchanged.
- **Threat-model entry** (docs/SECURITY.md, "Installer entry"): whoever can use the boot menu can erase the target disk; that needs console or hypervisor access, which already allows it. Nothing here defends against that person.
- **Not enforced:** the kernel's own check of the module (it would not help: the same loader hands it the module), and a per-boot confirmation of the target other than the 30 s countdown that exists.

## ADR-252 — Image secrecy: a loud warning outside CI, and a scan of logs and comparison output for key bytes (H8)

- **Status:** Accepted.
- **Context.** The server's TLS private key (and, with encryption at rest, the 64-byte disk key) is in the configuration slot of the image (ADR-215, ADR-240). Two ways to lose it quietly: build a production image on a developer's machine, where the keys passed through disk, memory, history and backups; and let a log, a panic message or the output of the reproducibility check print them.
- **Decision.**
  - `scripts/mkiso.sh` prints a boxed WARNING to stderr when the packed configuration says `env` other than `dev` (read from the slot itself, so a `--config BLOB` is covered, not only `URMQTT_ENV`) and the `CI` variable is not set (GitHub Actions sets it). It is a warning, not an error: a deliberate local build of a private deployment is legitimate. `make iso|universal|raw|dist ENV=prod` all go through it; the key-less template (`--empty-config`) does not warn. It can be silenced only by setting `CI`, which is a bypass, not a control.
  - `scripts/secret-scan.py` derives the needles from the key files (the DER of the private key whole, its first 96 bytes, hex lower, upper, spaced, colon and `0x` forms, base64 at the three alignments, the PEM lines, the P-256 private scalar; for the disk key the 64 bytes and both halves) and searches the files given, with and without terminal escapes. `--found-in FILE` names a file that does hold the keys (the image) and **fails the scan if it finds nothing there**, so a blind scan cannot pass.
  - `SMOKE_ONLY=secrecy` (aarch64): an encrypted-at-rest first boot, the wrong-key refusal and the no-key refusal, on the dev kernel (the chattiest) and, with `SMOKE_RELEASE_KERNEL`, on a release kernel with the production configuration; all serial logs scanned. It also checks the warning appears for the production image and not in CI, nor for a dev image.
  - `scripts/repro.sh` keeps its own output and both build logs and scans them (control: the ISO it built) when `deploy/<ENV>/server.key` exists.
- **Not covered.** Panics and fault reports on paths no scenario reaches (ADR-172's redaction and the `fault-secrets`/`panic-secret` tests with their `-open` controls cover a planted secret); memory of the running system; the image itself. Secrets in a core dump do not exist (there are none).
- **Alternatives.** Making the warning an error unless `URMQTT_ALLOW_LOCAL_PROD=1` (a gate that people set once in their shell and forget, with the same effect as the warning); refusing prod images outside CI altogether (breaks private deployments, which the builder page and the template flow are for).

## ADR-254 — Sealing the server key to a TPM 2.0 or a vTPM: a research spike, not built (H8)

- **Status:** Proposed, **not implemented**. No code was written for it. Findings and a recommendation for the maintainer.
- **Question.** Can the server's private key (and the disk key) be bound to one machine, so that a copied image or disk does not work elsewhere?
- **What exists to build on** (checked, not assumed). Limine 12.9.4 measures into the TPM when the firmware offers one (its binary carries `tpm: HashLogExtendEvent for PCR %u failed` strings). The edk2 builds in use already speak to a TPM when present (they log `Tpm2SubmitCommand - Tcg2 - Not Found` without one). QEMU provides the devices on both architectures: `tpm-tis-device` (aarch64 `virt`), `tpm-tis` and `tpm-crb` (x86), backed by `swtpm` (not installed on the development machine; available as a package). The kernel has no TPM driver and no TPM 2.0 command layer.
- **What sealing would be.** At provisioning the secrets (TLS private key, disk key) are encrypted under a key that only this TPM can use, with a policy on PCRs (at least the firmware, the Secure Boot state, and the loader's measurement of the configuration and the kernel); at boot the kernel asks the TPM to unseal (`TPM2_CC_Unseal` in a policy session with `PolicyPCR`) and holds the key in RAM exactly as it does now. The key must be loaded into RAM: **signing inside the TPM is not an option on the hot path**. A TLS server at the project's target (`handshakes_per_core_per_sec = 2000` in deploy/prod/config.toml) needs one signature per handshake; a hardware TPM signs at tens of milliseconds, a vTPM at a few milliseconds, one at a time.
- **Why this is more than a driver.**
  1. **Where the plaintext is.** The key is in the ISO's configuration slot, copied byte for byte into the installed disk's ESP (ADR-217). Sealing helps only if the plaintext is *gone* from every copy that should not work elsewhere. The ISO that the user downloaded or built keeps it forever; so the protection would cover the **installed disk** (and its backups) and never the install medium. Removing the plaintext from the installed ESP needs a new configuration blob format (keys "sealed, in the TPM" instead of inline: a format 5, with a signature and fingerprint rules for a stripped slot) and a writer: the kernel has no FAT writer (ADR-217 rejected one), so the slot would be overwritten in place, which is possible (it is a fixed 256 KiB region) but is a new write path in a kernel that today never writes the ESP.
  2. **Updates.** A PCR policy on the loader and kernel measurements breaks at every kernel update; the Linux answer is a policy authorised by a signing key (`PolicyAuthorize`, signed PCR predictions), which here would be a *customer* key, not the project's. That is an operator workflow (generate, hold and use that key) the project does not have.
  3. **The TPM state is part of the machine.** On bare metal a discrete TPM stays when the disk is stolen: the threat is addressed. On a VPS a vTPM is software run by the hypervisor, and its state (swtpm on Proxmox: a file next to the disk, included in the VM backup) travels with the VM. Sealing then protects against a copy of the *ISO or the disk image alone*, and against nothing the hypervisor operator can do, and not against a whole-VM backup. Provider support was **not verified** for this spike; from general knowledge, many small VPS providers offer no vTPM, while the large clouds do on some products (Azure trusted launch, GCP Shielded VM, AWS Nitro TPM), and it should be checked per provider before relying on it.
  4. **Interposer.** A bus-attached TPM (SPI/LPC) can be sniffed; unsealing without parameter encryption and a bound session leaks the key. That needs HMAC sessions with salted/encrypted parameters (more commands, more code). Irrelevant for a vTPM.
  5. **Attack surface.** A TIS/CRB MMIO driver and a TPM2 marshaller are new parsers of device-controlled data. The hypervisor is trusted in a VM and the TPM is trusted by design, but the project fuzzes every parser (H5) and would fuzz this one.
- **Size, if built.** A TIS and a CRB driver (about 600 lines), a minimal TPM2 layer for `Startup`-less use: `GetCapability`, `CreatePrimary`, `Create` (sealed data object with a policy digest), `Load`, `StartAuthSession`, `PolicyPCR`, `Unseal`, `FlushContext`, with HMAC sessions on bare metal (about 1 000 lines), a provisioning boot entry that seals and strips the plaintext, blob format 5, DISK-FORMAT/ESP notes, a fuzz target for response parsing, and tests with `swtpm` under QEMU on both architectures (CI would install `swtpm`). Rough estimate: three to four weeks of work, then ongoing: PCR policy upgrades and the update workflow.
- **Alternatives considered.**
  - *Key release over the network at boot* (the node proves its identity with a TPM quote or a one-time token and a key server hands it the secrets over mTLS): moves the problem to a key server the project does not provide, and needs the network up before the broker.
  - *A passphrase typed at the console*: no one is there to type it on a headless VPS.
  - *Cloud KMS or instance metadata*: provider-specific, and the metadata service is reachable by whoever has the VM.
  - *Confidential VMs (SEV-SNP, TDX)*: seal to the VM's measurement; the right tool where the provider offers it, and a different boot path (no Limine hash chain as is).
  - *Do nothing and document* (today): the image is a secret; rotate the key with a new image. The cost is paid by anyone who copies an ISO.
- **Recommendation.** Do not build it for the VPS-first release: the threats it addresses (a copied disk on bare metal) are the bare-metal ones, which are out of scope for it (docs/PLAN.md, first release scope), and the VPS case is mostly unaddressed by a vTPM. Revisit with the bare-metal milestone, after Secure Boot (ADR-251) so that PCR 7 means something, and decide the update workflow (point 2) first. Meanwhile the residual risk stays listed (SECURITY.md, AUDIT.md section 6) and ADR-252's warning stays.
- **Open questions for the maintainer.** Is a bare-metal appliance with a discrete TPM a planned target? Would a customer-held PCR-policy signing key be acceptable operationally? Is a stripped, "keys in the TPM" configuration format an acceptable change to the signed-blob rules (ADR-215)?

## ADR-255 — P-256 on OpenSSL's ARMv8 `nistz256` assembly on aarch64 (PERF)

- **Status:** Accepted. Extends ADR-130 (the same crate, the same Rust around the assembly) from x86_64 to aarch64.
- **Context.** On aarch64 the kernel ran RustCrypto's portable P-256. Measured on a real aarch64 KVM guest (netcup VPS 500 ARM G12.5, Neoverse N1, about 3 GHz, at the H10/diag commits): ECDSA verify 508 us, sign 141 us, X25519 176 us, one mutual-TLS handshake 1.08 ms. A server handshake does one signature, two verifications (client certificate against the CA, CertificateVerify) and one key exchange, so P-256 is most of it. On x86_64 the OpenSSL assembly gave 3-5x for these operations (ADR-130).
- **Decision.** `crates/nistz256` gets an aarch64 module (`src/aarch64.rs`; the x86 primitives move to `src/x86_64.rs`, the scalar multiplication, ECDSA, ECDH, `KeyTable` and the generator comb stay shared in `src/lib.rs`). It embeds `vendor/nistz256/p256-armv8-asm.S` with `global_asm!`: ring 0.17.14's `pregenerated/p256-armv8-asm-linux64.S`, generated from BoringSSL's `p256-armv8-asm.pl` (OpenSSL's `ecp_nistz256-armv8.pl`, Andy Polyakov, Apache-2.0). Mechanical changes only, by `vendor/nistz256/derive.py` (provenance, hashes and the edits are in `vendor/README.md`). One variant runs on every ARMv8-A core (`mul`/`umulh`, `adds`/`adcs`), so there is no detection and no `[cpu] disable` switch. Gated like the x86 code: aarch64 on Linux or bare metal, not under Miri and now also not under Kani (neither executes foreign assembly; the Kani CI job runs on an arm64 runner and builds `urmqtt-tls`). macOS keeps the portable path (`FAST == false`, `ecc_backend() == "portable"`).
- **Integer registers only.** The vendored file uses x0-x17, x19-x30, `xzr` and `sp` and nothing else (no `x18`, no `v`/`q`/`d`/`s` register): checked by reading it and by a token count over the file. Upstream's two table-selection functions (`ecp_nistz256_select_w5`/`_w7`) are NEON (`ld1`, `bit`) and are **not** vendored; `select_w5`/`select_w7` are written in Rust instead (every entry read, a mask from `(i ^ index)` through `black_box`, OR-accumulated). Note for reviewers: this keeps the *vendored assembly* integer-only, but the kernel itself is hard-float (ADR-003: `aarch64-unknown-none` has `+neon`, FP/SIMD is enabled kernel-wide and the exception entry saves q0-q31), and LLVM vectorises the Rust scan with NEON `and`/`orr` exactly as it does for any other kernel code. That is safe under ADR-003; the choice was made for the reviewable property "the third-party assembly touches no SIMD state", not because NEON would be unsafe. Cost: `mul_base_ct` takes 4.46 us against 3.03 us for `mul_base_vartime` (direct indexing, no scans, no negation), so the scans cost at most 1.4 us of a 12 us signature (Docker, M4 Pro, see below).
- **BTI and PAC.** The kernel is built with `-Zbranch-protection=bti,pac-ret` and enforces BTI. ring's `AARCH64_*` macros (from `asm_base.h`, dropped with the preprocessor) are expanded by `derive.py` as for a build with both: `AARCH64_SIGN_LINK_REGISTER` becomes `bti c` + `paciasp` (hint #34, #25), `AARCH64_VALIDATE_LINK_REGISTER` becomes `autiasp` (#29), `AARCH64_VALID_CALL_TARGET` becomes `bti c`. So every one of the eight exported entry points starts with an explicit `bti c` (checked in the disassembly of the release kernel), whatever `SCTLR_EL1.BT` says about PACIASP as a landing pad. The six functions that save the link register sign it with the A key and authenticate it before `ret` (with the SP the prologue used; `point_add`'s doubling shortcut branches into `point_double`'s body after restoring the same frame, as upstream designed). `ord_mul_mont`/`ord_sqr_mont` are leaves: they store x30 but never reload it. There is no indirect branch in the file; the internal helpers (`__urmqtt_nistz256_*`) are reached by `bl` only. The `hint` encodings are NOPs on cores without BTI/PAuth.
- **The comb table is shared.** ring compiles the same `p256-nistz-table.h` into `p256-nistz.c` for both architectures; the layout is little-endian 64-bit Montgomery limbs, which aarch64 stores exactly as x86_64. `vendor/nistz256/p256-table.bin` is therefore used unchanged (`derive.py` reproduces it byte for byte, SHA-256 `e373124f...0d2`), and `the_generator_table_is_the_comb_of_the_generator` checks all 2368 entries against RustCrypto's `k*G` on aarch64 too.
- **Wired in.** `crates/tls/src/provider/fastec.rs` takes the fast path on aarch64 for `ecdsa_sign`, `ecdsa_verify`, `p256_public`, `p256_dh` and `IssuerTable` (a `KeyTable` per trust anchor), with the portable fallback for inputs the fast path does not take (compressed keys). `Ops::name()` gives the boot line `crypto: ecc=nistz256-armv8 (P-256 and X25519 field arithmetic)`; the diagnostic screen's crypto line now ends with `ecc=<backend>` as well (both architectures). X25519 is unchanged (dalek on aarch64, ADR-131).
- **Tests.** The whole `urmqtt-nistz256` suite now runs on aarch64 Linux (and so on the arm64 CI runners, which until now only compiled the crate empty): field and order-field multiplication, squaring and repeated squaring against the schoolbook reference on edge and 300 random values; inversions; all 2368 comb entries; public keys for 310 scalars incl. 1, 2, 3, N-1, N-2; ECDH incl. off-curve, out-of-range and zero inputs; signatures bit-for-bit equal to RustCrypto's `sign_prehashed` for 300 random and the edge inputs; verification verdicts equal to the stock verifier; point addition with equal, opposite and infinity operands; `KeyTable` against the portable arithmetic. New for both architectures: every index of both table scans (0 to 16, 0 to 64, and rows of the production comb); negation on edges and random values; mixed addition with infinity on either side, opposite points and agreement with full addition; variable-base multiplication by structured scalars (small, single bits, N-1, N-2, alternating); the backend name. In `urmqtt-tls`, the existing differential tests, both `IssuerTable` kinds and the boot KATs (`kat::run`: RFC 6979 A.2.5, RFC 5903 §8.1, RFC 7748) now run through the assembly on aarch64 Linux, and a test pins `ecc_backend()` per target.
- **Constant time.** As ADR-130: secret scalars use the constant-time scans, branch-free negation and the assembly's complete addition; the only secret-dependent branch in the assembly is `point_add`'s doubling case, unreachable for scalars below N. New: `make ct` has three P-256 cases (four since the amendment below) (`p256_key_generation_is_constant_time`, `p256_ecdh_is_constant_time`, `p256_signing_is_constant_time`, through the production `fastec` paths, a sparse fixed scalar against fresh random ones, 20 000 samples per class split) and a P-256-scale control (`harness_detects_a_variable_time_scalar_multiplication`, a textbook double-and-add with skipped additions). Results in docs/CRYPTO.md: six runs in Docker on the M4 Pro, |t| 0.8-5.5 (key generation), 0.2-2.1 (ECDH), 0.5-1.9 (sign), the control 482-749, bound 7. What this shows: no timing difference between a scalar with nearly all window digits zero and random scalars, at the resolution of one black-box test on one machine. What it does not show: absence of smaller leaks, cache-line or port contention side channels, behaviour on Neoverse N1 (the runs were in Docker on an Apple M4 Pro), or anything about the variable-time verification path (public inputs by design).
- **Result** (Docker `linux/arm64` on an Apple M4 Pro, image `urmqtt-ci`, the `profile` example of `urmqtt-tls`, release build, `main` at eb3a5d3 and this change built in the same container and run interleaved, 11 runs each, minimum / median in microseconds). **Not the target CPU:** an Apple core is not a Neoverse N1, and the ratios on the VPS may differ; the VPS has not been measured with this change.

  | | before (portable) | after (nistz256-armv8) | ratio (min) |
  |---|---|---|---|
  | key generation (`p256-base`) | 30.8 / 31.2 | 6.97 / 7.01 | 4.4x |
  | ECDH P-256 | 135.2 / 137.5 | 25.0 / 25.1 | 5.4x |
  | ECDSA sign | 34.7 / 35.4 | 11.6 / 12.1 | 3.0x |
  | ECDSA verify (unknown key) | 147.4 / 152.1 | 29.1 / 29.6 | 5.1x |
  | CA verify (registered issuer) | 54.2 / 55.7 | 9.6 / 10.0 | 5.6x |
  | X25519 (base / shared) | 7.4 / 20.4 | 7.5 / 20.1 | unchanged |
  | handshake estimate (`profile`) | 292 / 297 | 104 / 105 | 2.8x |

- **In the kernel** (boot profile under QEMU/HVF on the same M4 Pro, median of three boots each, before / after, us): sign 44.3 / 18.9, verify 164.3 / 32.8, ECDH 155.9 / 27.3, key generation 35.9 / 10.2, handshake estimate 347 / 141. Details in PERFORMANCE.md section 10.
- **Boot check.** `make build ARCH=aarch64` and `ARCH=x86_64` build; `make clippy-kernel` is clean on both. Smoke (`scripts/smoke.sh`, HVF and TCG) `boot-acpi`, `boot-dtb`, `crypto-soft`, `crypto-bench`, `simd-irq`, `sys-operator`, `sys-reboot`, `ticket-rotation`, `ticket-restart`, `dp-bench` and the related checks: 56 passed, 0 failed. The boot scenarios now require `crypto: ecc=nistz256-armv8` (aarch64) and `crypto: ecc=nistz256-(adx|mul)` (x86_64; that pattern was not run in this change). `simd-irq` ran 59 526 rounds of `kat::run` (P-256 KATs included, so the assembly) on four cores under IPIs and the tick with no mismatch.
- **Cost.** 180 KiB more in the aarch64 kernel ELF (3 481 296 -> 3 665 584 bytes, release, dev configuration: the 148 KiB comb, which aarch64 did not link before, and the code); 148 KiB of heap per registered trust anchor (at most 8), built at configuration time in about 0.5 ms each (Docker, M4 Pro).
- **Not done.** (Updated 2026-11-04: the netcup VPS, a Neoverse N1, was measured once, PERFORMANCE.md section 11: handshakes per second 1.55 to 1.7 times, the server's CPU per handshake 553 us against about 1.0 to 1.08 ms.) A measurement on any other real aarch64 server core, and a repeat on the N1; the NEON selection (upstream's), which would save part of the 1.4 us; the items of ADR-130's "Not done" list (wNAF for unknown keys, constant-time Bernstein-Yang inversion), which apply here equally.
- **Amendment (2026-11-04, branch `ct-dit`): the signing timing signal on the arm64 runner was the harness, not the key.** `p256_signing_is_constant_time` scored |t| = 8.3, 9.1 and 8.6 on the GitHub `ubuntu-24.04-arm` runner (Neoverse N2, MIDR part `0xd49`, 4 vCPUs), and 7.0 to 11.7 in every one of 24 attempts of the diagnosis there, so 87f45e1 raised its bound to 12 as an open finding (AUDIT.md A255-W1). Diagnosis on the runner (four jobs, each line measured six times per job in two groups of three, a throwaway test `ct_diag.rs` in the branch history; the second group ran inside a DIT guard that was a no-op on this runner, see below):
  - the case signed one fixed message. With the fixed key the RFC 6979 nonce and the **signature are then the same every time**, with random keys they differ each time, so the two classes differ in their *output*, which is public;
  - a **dense** fixed key (`0x5c` x 32) instead of d = 2 scored higher still, |t| = 14 to 23: the signal does not depend on the key being sparse;
  - with a fresh random message per measurement in both classes the same production call scored 0.3 to 4.4 (d = 2) and 0.2 to 3.5 (dense key), 24 attempts each;
  - the arithmetic alone (`nistz256::sign` with the nonce fixed and d = 2 or dense against random d; a fixed nonce or k = 2 against random nonces; `public_key` with d = 2) scored 0.1 to 4.8; the RFC 6979 nonce generation alone, d = 2 against random d, 1.1 to 5.7;
  - `Signature::to_der` alone (plus the `Vec`), the same signature every time against varying ones, scored |t| = 49 to 57 (medians 120 against 128 ns): the variable-length DER encoding is faster when it encodes the same value over and over. That is time spent on the public signature after the secret work is done.
  So the case measured the encoder's behaviour on a repeated output. It now signs a fresh random message per measurement in both classes (prepared untimed in the same slot), and the bound is 7 again. Because the production path derives the nonce inside `fastec`, a new case `p256_signing_nonce_is_constant_time` times the assembly's `sign` with the nonce as the secret (k = 2 against random nonces; key and message fixed; output two fixed-size arrays), on x86_64 and AArch64 Linux. On the runner after the change: signing 1.4 and 1.8, nonce 2.7 and 1.1 (first attempt each). The same pattern reproduced in Docker on the M4 Pro, weaker and more scattered (fixed message: 0.4 to 17; random message: 0.1 to 5.5; DER alone: 12 to 34; the medians there move in 41 ns timer steps, on the runner in about 8 ns steps), so the six earlier runs at 0.5 to 1.9 did not show that the effect was absent.
  - **PSTATE.DIT is not the cause on this runner:** its VM does not expose FEAT_DIT (no `dit` in `/proc/cpuinfo`, `HWCAP_DIT` clear in `AT_HWCAP`), so DIT could not be set there at all (the guard used in the diagnosis was a no-op), and the signal appeared and disappeared without DIT changing. In Docker on the M4 Pro (FEAT_DIT exposed, DIT read back as set inside the guard) setting DIT made no consistent difference to any case. Neither the kernel nor the host code sets DIT today (A255-W2): Arm guarantees data-independent timing of `mul`/`umulh` and the other listed instructions only with DIT = 1, and no measurement here shows what a core with FEAT_DIT does without it.

## ADR-256 — A virtio-gpu (2D) console for VMs whose display is dead after boot (`console.virtio_gpu`, NOW-6)

- **Status:** Accepted. Amends ADR-215 (blob format 5) and ADR-072 (a presenter after the framebuffer sink).
- **Context.** On netcup's ARM VPS (QEMU/KVM, edk2, a virtio-gpu PCI 1af4:1050 and no other display) the provider's console says "Display output is not active" as soon as the kernel runs. **Likely cause, not verified in the firmware's source on that host:** edk2's VirtioGpuDxe resets the device at ExitBootServices, so the scanout is disabled; the GOP framebuffer Limine hands over is guest RAM that nobody sends to the host. With virtio-gpu the guest must issue `TRANSFER_TO_HOST_2D` and `RESOURCE_FLUSH` after drawing. Until now a boot that fails before the network was invisible there, and the Diagnostic entry's dashboard could not be seen.
- **Decision: a driver, optional and off by default.** `crates/virtio/src/gpu.rs`: virtio 1.x §5.7, `VERSION_1` only (no virgl, EDID, blob, cursor queue, fences). The control queue (8 entries, polled) carries `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D` (one resource, B8G8R8X8, the console's pixel format), `RESOURCE_ATTACH_BACKING` (one entry), `SET_SCANOUT` (scanout 0), `TRANSFER_TO_HOST_2D` and `RESOURCE_FLUSH`; nothing is ever unreferenced or detached (the resource lives as long as the kernel). The mode is scanout 0's preferred size clamped to 640x480..1920x1080, or 1280x800 when the device prefers none; then the first of 1280x800, 1024x768, 800x600, 640x480 under an 8 MiB budget.
- **Memory.** The framebuffer is fresh, zeroed, physically contiguous DMA memory (`vm::dma_alloc`, HHDM-mapped) allocated for this purpose and attached as the resource's backing. **Limine's framebuffer is not reused:** whether it is RAM (edk2's GOP shadow) or a device BAR (VGA VRAM on virtio-vga, std VGA) cannot always be told apart, a BAR must never be attached as backing, and its geometry need not match the mode chosen. The console moves to the new memory (`urmqtt_log::replace_framebuffer`); the Limine path is unchanged when the driver is not used.
- **Lines from before.** `replace_framebuffer` redraws the newest lines of the console ring (the O2 ring, enabled from the first line of the boot, 128 lines) on the new console, as many as fit; raw markers (`URMQTT BOOT`) are not in that ring and are not redrawn.
- **Presenting.** Drawing only marks the framebuffer dirty. The log calls a presenter (`set_framebuffer_present`, implemented in `kernel/src/gpucon.rs`) after a synchronous line, after each drain pass and each idle pass of the consumer core, and after `raw`. It queues a transfer + flush of the whole screen **without waiting**, at most every 50 ms; the boot CPU's 10 ms tick calls it too, so the end of a burst follows within about 60 ms. `flush()` (power-off, reboot, `fatal`), `emergency()` (exceptions, panics) and every dashboard redraw (`with_framebuffer`, the Diagnostic entry and its final "press any key" screen) call it with `now`: queue, then wait for the device, bounded (250 ms). The device lock is only ever *tried* (for `now`: for at most 50 ms); a tick that interrupts a present on its own core, or a panic inside one, skips that frame instead of hanging, and the presenter never logs. No interrupt is needed (the used ring is polled against the counter clock).
- **Configuration.** `[console] virtio_gpu = "off" | "auto" | "on"`, an optional section, default **"off"** (and so in `deploy/prod`, `bench`, `demo`; `deploy/dev` says `"auto"`). Tag 190, **format 5**: "off" writes nothing (the blob stays at version 2 and boots on older kernels); "auto" and "on" need version 5, so a template of an older kernel refuses the configuration when it is packed (`urmqtt-config pack --iso`, the builder page) instead of the kernel refusing an unknown tag at boot. Allowed in production: it changes what is shown, not what is served.
- **What "auto" can detect.** The only fact available before the device is driven is where the bootloader's framebuffer lives. Inside a memory BAR of a PCI display controller (class 03: virtio-vga's VGA BAR, std VGA) it is scanned out by that device and live: the virtio-gpu is left alone. In RAM, with a virtio-gpu present, it is (as far as can be told) the shadow of edk2's driver and dead: the device is taken. No usable boot framebuffer at all: taken. Not detectable: a live RAM framebuffer of a non-PCI device (QEMU `ramfb`) next to a virtio-gpu; "auto" then takes the virtio-gpu and the `ramfb` picture freezes (A256-W2, accepted). "on" takes any virtio-gpu found. Every outcome is one boot line `console: virtio-gpu ...` with the reason; a device that fails to come up leaves the console where it was, with a warning (a display never stops the broker).
- **Threat model.** The device is the hypervisor: trusted for availability (it may show nothing), not for the memory safety of our parser. DMA goes only into memory allocated for it (the queue, one page of request/response slots, the framebuffer); no pointer or length the device returns is dereferenced; a response is copied out of its slot into a fixed 408-byte buffer, the length the device claims is capped at that buffer, and the type, the whole structure's length and (if one was sent) the fence are checked, unknown types refused; display values only feed a clamped mode. Every wait has a timeout. The driver and its presenter are TCB only when the key is not "off".
- **Tests.** Host tests of every command's encoding, of response parsing (short, overlong, error types, unexpected types, fences), of the mode choice and of the "auto" decision; config tests (parse, default, the three words, refusals, blob versions 2 and 5, a version 4 blob holding the record refused, decoding); log tests (the replay draws the earlier lines, dirty marking). Fuzz target `virtio_gpu_response`: in its first minute it found that a display info 4 bytes short (the last scanout's unread `flags`) was accepted (A256-W1); now the whole structure is required; 52 million runs clean afterwards. Smoke `virtio_gpu` (misc group): QEMU with `virtio-gpu-pci` instead of `ramfb`/VGA (`run-qemu.sh --gpu`), images with "on", "auto" and "off", a QMP `screendump` after `URMQTT READY`: with "on" and "auto" the first text row has lit pixels and the console's background fills most of the screen, with "off" the driver is not started and the console is not on that display; x86_64 also boots `virtio-vga` with "auto" (left alone: the framebuffer is its VGA BAR) and "on". Passed on aarch64 HVF and x86_64 TCG on the Mac.
- **Real machine.** netcup VPS 500 ARM G12.5 (QEMU/KVM, edk2, 1280x800), commit e86d2ca with `console.virtio_gpu = "on"` and the Diagnostic entry as the default: the owner saw the dashboard live in the provider's Screen tab, and the final "press any key" screen stays.
- **Not done / limits.** Only scanout 0; no resize or hotplug events; a full-screen transfer per present (8 MiB at most, 20 a second at most, only while something changes); Secure Boot interaction not tested (the driver is plain kernel code, nothing new is loaded); x86_64 not tried on a real machine; the 50 ms period is not configurable.

## ADR-257 — The virtio driver framework: one feature per driver, one table, `[devices]` keys (format 6)

- **Status:** Accepted. Amends ADR-215 (blob format 6) and ADR-256 (the gpu console is a row of the table and its own feature).
- **Context.** The owner's goal: every virtio device type gets a driver in the library (`crates/virtio`), but the MQTT image carries only those that make sense on a VPS. Until now every driver was compiled in, each had a path of its own in `kernel/src/devices.rs`, and a device without a driver was a bare `virtio (unused)` in the boot log. Other agents will add the remaining types: adding one must be a mechanical, uniform step.
- **Features.** Every driver module of `urmqtt-virtio` is behind its own Cargo feature: `net`, `blk`, `scsi`, `rng`, `gpu`, `console`, `balloon`, `input`, `vsock`. Umbrella features: `vps` (the set the MQTT image ships: all nine today) and `all` (every driver that exists; equal to `vps` until a driver that is not for a VPS lands). The crate's default is `all` so host tests, clippy and the fuzz targets see every driver. The transport, the queues, `bus` (the `Bus` trait, DMA copies, the byte ring) and `registry` are always built. The kernel depends on the crate with `default-features = false` and `net`, `blk`, `scsi`, `rng` always on (a broker without network, disk and entropy is not a product; those four keep their special paths), and exposes `virtio-gpu`, `virtio-console`, `virtio-balloon`, `virtio-input`, `virtio-vsock` with the umbrellas `virtio-vps` (**its default**: `make build`, `universal`, `template`, the release job and the builder's template build exactly that set without a flag) and `virtio-all` (`make build VIRTIO=all`). `make clippy-kernel` also checks `virtio-all` and `--no-default-features`.
- **The table.** `urmqtt_virtio::registry::KINDS` has one row per driver module: virtio type, transitional PCI ID (the modern ID is `0x1040 + type`), name, feature, whether this build compiled it, its `[devices]` key (none for net/blk/scsi/rng, which always run, and for gpu, whose key stays `console.virtio_gpu`) and whether it needs a device configuration. `registry::type_name` names every other type of the specification, so a device without a driver is still named. The kernel's table, `kernel/src/vdev/mod.rs::DRIVERS`, has one row per `KINDS` row, in the same order: `Builtin` (net, blk, rng, scsi, gpu: their code in `devices.rs`) or `Generic { init, max }` where `init` is `Some(fn)` exactly when the feature is compiled. A `const` assertion fails the build when a row is missing, out of order, or has an init function that does not match what was compiled.
- **States.** Every virtio function the PCI scan sees gets one final state, logged as `virtio: <name> at <bdf>: <state>[: detail]` and listed in the Diagnostic report: `driven`, `off` (the key says so), `no driver in this image` (the type has a module; this kernel was built without it), `no driver` (no module exists), `not used (another device of this type is driven)`, `legacy device`, `missing virtio 1.0 capabilities`, `not used` (the gpu console's "auto" decision, a disk that is not the boot disk) and `failed` (a warning). The first line of the scan says which drivers the image has: `virtio: drivers in this image: net,blk,...`.
- **Generic bring-up.** For a `Generic` type, `vdev::probe_generic` decides from the registry and the configuration first (not compiled, key "off"), then how many of the type are already driven (`max`, 4 for input, 1 for the others), then the capabilities (modern only), then enables memory and bus mastering and calls the init function, which maps the transport (`devices::transport`) and starts the driver. A failure is a warning and never stops the boot.
- **Configuration.** A `[devices]` section, optional, one key per optional driver: `virtio_console`, `virtio_balloon`, `virtio_input`, `virtio_vsock`, each `"off" | "auto" | "on"`, default **"off"** (and in `deploy/prod`, `bench`, `demo`; `deploy/dev` says "auto"). Tags 191..194, `since` 6: **configuration format 6**. As with ADR-256, "off" writes nothing, so a configuration that leaves every key off stays at the version it needed before (2 in most cases) and boots on an older kernel; "auto" or "on" need format 6, and a template of an older kernel refuses such a configuration when it is packed. A format bump was needed even though format 5 is not in a release: kernels of format 5 exist (the netcup images built from main) and would refuse the new tags only at boot. `urmqtt_cfg::build::Builder::lowest_version` became generic (the newest `since` of the records written, with the two value rules of formats 3 and 4 kept), so the next key needs no change there. "auto" starts the driver when the device is found; "on" does the same and a missing device is a warning.
- **Configured, not compiled.** A kernel carries a marker, `URMQTT-VIRTIO-DRIVERS:` and its compiled features (`registry::marker`, a `#[used]` static that the boot line also reads). `urmqtt-config pack --kernel ELF` (which `scripts/mkiso.sh` passes for every kernel of the image, so `make iso`, `make universal` and the smoke images check it) and `pack --iso`/`--image` (the template, and the builder page through the same function) refuse a key that is not "off" for a driver a kernel of the image lacks, naming the key and the kernel feature. Where that cannot be seen (a blob packed without a kernel), the kernel says so at boot with a warning: `virtio: devices.virtio_vsock = "on" but this image has no virtio-vsock driver ...`. Never a silent skip.
- **Fake device.** `Bus` (in `bus.rs`) is what the newer drivers need from the transport; `Transport` implements it, and `fake::FakeBus` (tests, and the `fake` feature for the fuzz targets) is an in-memory device configuration plus a device side that pops the driver's chains and completes them with any length or head, including ones it never had. Each driver of ADR-258 is generic over it and tested against it.
- **Diagnostic.** `urmqtt_diag::report::Report::virtio` (JSON key `virtio`: `bdf`, `type`, `name`, `state`, `detail`, after `pci`); the dashboard's PCI lines show `[name: state]` for a virtio function. `urmqtt-diag-png` reads the key (and still draws a report without it).
- **Image size.** The `vps` kernel (all nine drivers) against the kernels before this change, both `ENV=release`: see ADR-258.
- **Adding a driver.** The checklist is [docs/DEVELOPING-DRIVERS.md](DEVELOPING-DRIVERS.md).

## ADR-258 — virtio-console, virtio-balloon, virtio-input and virtio-vsock for a VPS (phase 1)

- **Status:** Accepted. Builds on ADR-257.
- **Common rules.** virtio 1.x modern only (`VERSION_1` required; a legacy-only device is listed, not driven), polled (no MSI-X: none of these needs latency, and the existing optional driver, the gpu, polls too), split queues of at most 8 entries (64 for input), DMA only into memory allocated for the driver, every buffer the device fills copied out with its length clamped to the buffer it was given, every completion's head checked against what was posted (`SplitQueue::pop_used` plus a slot map per driver), every loop bounded by the queue size, nothing that waits for the device. Each driver's state lives in a `SpinLock` that the log, the tick and the prompts only *try* (never wait for), and nothing logs while holding one. Each is off unless its `[devices]` key says otherwise.
- **virtio-console (type 3).** Port 0 only: `F_MULTIPORT` is not negotiated, so there is no control queue and QEMU marks port 0 open when the driver is ready; `F_SIZE` and `F_EMERG_WRITE` are not used. Output: a new sink beside the UART and the framebuffer (`urmqtt_log::set_extra_sink`), which gets every byte the UART gets. The log writes a line in pieces; the driver fills one 512-byte buffer and sends it when it is full, when a write ends a line, or on `flush`; 8 such buffers are in flight at most, and what does not fit (a host that does not read) is dropped and counted, never waited for. A line that meets the device lock held on another core is skipped and counted. Lines logged before the driver started are not replayed. Input: 8 receive buffers of 64 bytes, copied into a 256-byte ring (overflow dropped and counted) that the Diagnostic entry reads through the same `read_byte` as the serial port and PS/2.
- **virtio-balloon (type 5).** The policy: **never inflate**. The heap is sized once at boot and the allocator cannot hand whole pages to the device and take them back on use, so a host request (`num_pages`) is recorded, logged once per change (`virtio-balloon: the host asks for N page(s) ...; this kernel never inflates`) and `actual` stays 0; nothing is ever put on the inflate queue (set up, as the device expects, and unused). With `F_STATS_VQ` (the only feature taken) the host gets real numbers: total (usable RAM in the memory map), free and available (the heap's free bytes; the heap is all the kernel allocates from after boot), never more than the total. The boot CPU's tick looks once a second whether the device returned the statistics buffer and what it asks for; the heap's numbers are only *tried* (its lock may be held by the code the tick interrupted). `F_DEFLATE_ON_OOM`, `F_FREE_PAGE_HINT`, `F_PAGE_POISON` and `F_PAGE_REPORTING` are not negotiated: **free page reporting is not implemented** (it would need the allocator to report and reclaim whole pages).
- **virtio-input (type 18).** Up to 4 devices (a VNC console typically brings a keyboard and a tablet). The driver reads the name (`ID_NAME`, printable ASCII, 32 bytes at most) and the `EV_KEY`, `EV_REL`, `EV_ABS` bitmaps (keyboard: has KEY_A and Enter; pointer: axes), keeps 64 event buffers posted and turns key presses (value 1) and auto-repeats (2) into bytes for the prompts: letters, digits and the punctuation of a US layout, Space, Tab, Enter and keypad Enter (`\n`), Backspace (`\x08`), Escape (`\x1b`), with both Shift keys and Caps Lock. Pointer events are counted, other types too; the status queue (LEDs) is not used. The bytes go into the same `read_byte` path, so "press any key" and the `WIPE` confirmation work from a provider's VNC console that feeds a virtio keyboard.
- **virtio-vsock (type 19).** The stream transport only (`F_STREAM`; `F_SEQPACKET` is not taken and SEQPACKET packets are reset), for one consumer: a **read-only Diagnostic report service on vsock port 2883** (`urmqtt_virtio::vsock::DIAG_PORT`). A host (CID 2) that connects to it gets the JSON of `$SYS/diag/report` (after `diag-serve`, or from the Diagnostic entry once its measurements are done and it waits for a key) or, before that, a one-line JSON saying there is none; then the guest sends SHUTDOWN (both directions) and the connection ends with the host's reset, or ours after 2 s. The protocol is `vsock::Stack`, without I/O: requests to any other port, from any other CID, for unknown connections, or of the wrong type get a reset (a reset is never answered); at most 4 connections, more are refused; data is sent only within the peer's credit (`buf_alloc - (tx_cnt - fwd_cnt)`, never negative whatever the peer claims) and in packets of at most 1024 bytes; what the peer sends is counted (only what the device delivered, not the header's claim) and discarded, with credit updates so it is not stalled; a connection without progress for 10 s is reset. A `TRANSPORT_RESET` event drops every connection and re-reads the CID; a CID outside 3..0xffff_fffe refuses the device. Served from the boot CPU's 10 ms tick, one bounded pass (16 received packets, 8 sent). **Untested against a real device**: a vsock device needs vhost-vsock on a Linux host, and QEMU on the development Mac has none; the tests use the fake device. Connect from a Linux host with e.g. `socat - VSOCK-CONNECT:<guest cid>:2883`.
- **Threat model.** As ADR-256: the device is the hypervisor, trusted for availability, not for the memory safety of the parsers. Inputs and mitigations are in docs/AUDIT.md §2; none of the four drivers runs unless its key is not "off".
- **Tests.** Host tests against the fake device for each driver (posting, completions, clamped lengths, hostile heads and indices, missing features and queues, dropped output, the stats policy, key maps with Shift and Caps Lock, the vsock connection life cycle, credit, limits, timeouts, transport reset, CID checks). Fuzz targets `virtio_console_device` and `virtio_balloon_device` (the drivers against the fake device with fuzzer-chosen completions), `virtio_input_event` (events and the key map), `virtio_vsock_packet` (the stack with any packet sequence), with seeds. Smoke `virtio_devices` (misc group, next to `virtio_gpu`): a serving boot with `virtconsole` (to a file), `virtio-balloon-pci` and `virtio-keyboard-pci` (all driven; the console file has the log; QMP's `guest-stats` shows the totals; a QMP `balloon` request is refused with the log line and `query-balloon` still says the full size), the same with every key "off" (listed, not driven), and the Diagnostic entry's `WIPE` confirmation typed once as QMP `send-key` events into the virtio keyboard and once as bytes on the virtio-console (both confirm the write test on a blank disk; the report's `virtio` list shows the device driven).
- **Not done / limits.** No multiport console, no console resize; no balloon inflation, no free page reporting, no deflate-on-OOM; no input LEDs, no layouts other than US, pointer events unused; vsock: no outgoing connections, no SEQPACKET, no DGRAM, no service other than the read-only report, no interrupt (a 10 ms poll). None of the four has run on a real VPS yet; the console, balloon and keyboard ran in QEMU on the Mac (`virtio_devices`: aarch64 HVF and TCG, x86_64 TCG, all 4 checks passing on each).

## ADR-259 — The server handshake measured stage by stage; trust-anchor tables that were never used; X25519 and P-256 verification faster on AArch64 (PERF)

- **Status:** Accepted; amended by ADR-261 (the tables are built once at boot, 148 KiB each instead of a 256 KiB heap block, and counted in the heap sizing). Amends ADR-111 (the trust-anchor tables now really exist), ADR-131 (aarch64 no longer uses dalek's ladder for the shared secret) and ADR-130/ADR-255 (verification).
- **Context.** On the netcup VPS (Neoverse N1, 2 vCPU, PERFORMANCE.md section 11) one handshake cost the server 553 us after ADR-255, by the boot's `bench::run` (one run): ECDSA verify of an unknown key 192.5 us, sign 77.8 us, X25519 208.5 us. The handshake rate there is single-core bound. `bench::run` times primitives in isolation and *estimates* the rest (48 HMACs, 160 SHA-256 blocks, 4 KiB AEAD), so it cannot say what else a real handshake spends or whether the production code takes the paths it measures.
- **Measured first: a per-stage profile of real handshakes.** New host-only feature `stage-profile` of `urmqtt-tls` (`src/stages.rs`; never enabled by the kernel, where `timed(stage, f)` is just `f()`) and example `handshake_profile`: a stock rustls client with our provider runs full TLS 1.3 + mTLS handshakes against `TlsServer` with the dev certificates; only the server's `accept`/`input` calls are armed; every provider call (key share, shared secret, sign, both verifications, the verification memo, transcript hashing, HMAC/HKDF, AEAD, ticket sealing, RNG), webpki's path validation, our checks after it and `finish_handshake` are timed **exclusively** (nested stages subtracted), and the unattributed rest (rustls's state machine, encoding, copies, allocation) is the difference to the armed total. Three cases: a returning device (its certificate's signature in the memo), a first contact (memo cleared before each handshake), a resumed session. Allocations are counted.
- **Finding: no trust anchor ever had its table.** `register_issuer` parsed the anchor's key with `from_public_key_der`, but webpki's `TrustAnchor::subject_public_key_info` holds the *contents* of the SubjectPublicKeyInfo SEQUENCE (without `30 59`), so the parse failed silently for every anchor since ADR-111, and every first verification by a CA took the unknown-key path (29 us instead of 10 us in Docker; the first-contact profile showed two "unknown key" verifications and none by a table). `bench::run`, the probe and the boot KAT built their tables directly and so never noticed; the memo hid it for returning devices. Fix: `issuer_key` accepts both forms (wrapping the contents in a definite-length SEQUENCE header), `has_issuer_table` for tests; unit test with the webpki form, a handshake test that every dev anchor has its table, a property test (5 000 random byte strings, every truncation and every single-bit flip of a valid key: rejected, or the same key). No security effect: the variable-base path verifies the same signatures (ADR-130 differential tests).
- **X25519 on AArch64 (`crates/x25519/src/arm.rs`, `Backend::Armv8`).** Before: dalek's 51-bit serial ladder (`curve25519-dalek` 4, `u64` backend: 25 products per multiplication, 15 per squaring, plus the 19x precomputations). Our 4x64 portable ladder was slower (27.4 us against dalek's 18.5 us: no dedicated squaring, `u128` carry handling). Options, cheapest first: (1) a better portable Rust ladder: not tried separately, because the assembly below is small and the portable code's 12 ns per multiplication against 7 ns for the assembly left little hope; (2) **hand-written ARMv8 inline assembly** for multiplication (16 products and a `+ 38 * high` fold: 40 `mul`/`umulh`), squaring (10 products: 28), addition, subtraction and `* 121665`, in the shape of `adx.rs`; (3) vendored assembly: none with a usable licence was available offline, and (2) paid. Result (Docker linux/arm64, Apple M4 Pro, *not* the target CPU): one ladder 13.4 us against 18.0 us for dalek; with the multiplication and squaring alone in assembly it was 15.6 us, adding addition, subtraction and `* a24` gave the rest (the Rust subtraction took 4 ns). On a core with one multiply pipeline, such as the Neoverse N1, the 4x64 form issues about a quarter fewer multiplier instructions per ladder step than the 5x51 one (321 counted in our code against roughly 420 from dalek's algorithm: 25 products per multiplication, 15 per squaring, the 19x precomputations); whether that turns into more than the M4's 1.34x is **not measured**. The key share keeps dalek's fixed-base table (7.5 us, faster than any ladder).
  - **Correctness argument.** Operands are any 4-limb value below 2^256 (loosely reduced, as the rest of the crate). The product is formed row by row: row *i* adds the four low halves of `a * b[i]` at limbs *i..i+3* with one carry chain whose carry out becomes limb *i+4*, then the four high halves at *i+1..i+4* with a second chain. A limb never overflows: after row *i* the exact partial product is below 2^(64(i+5)), and every addition computes it exactly, so the top limb of the row holds it. The squaring adds the six cross products the same way, doubles limbs 1..6 with one chain (carry into limb 7) and adds the four squares. The fold is `t[0..4] + 38 t[4..8]` (low halves with one chain, high halves with a second, the carry *c* at most 38), then `+ 38 c` with a chain; if that carries, the low limb is below 2^11, so the final `+ 38` (`csel`, not a branch) cannot carry. Subtraction: a borrow subtracts 38, twice; after a second borrow the low limb is at least 2^64 - 38, so the last subtraction cannot borrow. These are exactly the portable functions' operations, so the results are **bit for bit** the portable ones (tested: all pairs of 17 edge values and 20 000 biased random pairs for multiplication and squaring; 209 values, all pairs, for addition, subtraction and `* a24`).
  - **Constant time.** No branch, no memory access (operands and results in registers, `options(pure, nomem, nostack)`), no address depending on a value. The release kernel's compiled `urmqtt_x25519::x25519` has five conditional branches: four loop back-edges on public counters (the ladder's 255 steps, the inversion's squaring runs) and the stack-protector check. `mul` and `umulh` are data-independent on the Arm cores whose manuals say so, and the architecture guarantees it only with PSTATE.DIT = 1, which urMQTT does not set anywhere (A255-W2 applies here too, unchanged). `make ct` gains `x25519_ladder_is_constant_time` (the production `urmqtt_x25519::x25519(Backend::detect(), ..)`, the all-zero scalar, clamped to 2^254, against random scalars): |t| = 1.0, 1.2, 2.0, 4.7, 1.4, 1.5 in six runs (bound 7), Docker linux/arm64 on the M4 Pro, while the P-256-scale control in the same runs scored 645.6. Not measured on a server core.
  - **Registers, BTI, PAC.** Inline assembly only (no `global_asm!`, no symbol, no entry point, no `ret`): the compiler allocates the registers from the `reg` class (in this kernel x18 is an ordinary register, used 5 475 times in the image; the compiler never allocates x19, x29 or sp to an operand) and the enclosing Rust function gets the compiler's `paciasp`/`autiasp` like all other code (checked in the disassembly of the release kernel). So there is no `bti c` to add and no return address in the assembly's hands. General-purpose registers only, no NEON or FP register. Not under Miri or Kani (`not(miri)`, `not(kani)`); there only the portable code exists.
  - **Tests.** The RFC 7748 §5.2 vectors, §6.1 Diffie-Hellman, the iterated 1 and 1 000 vectors and, new and `#[ignore]`d, the million-iteration vector (passed on the macOS host with `Armv8` in 15 s and in Docker linux/arm64), the dalek differential (random scalars and points, low-order points, non-canonical encodings, the top bit of u) over `Backend::Armv8`; the boot KAT (`kx_kat`, RFC 7748) now runs through it on aarch64. The handshake's refusal of an all-zero shared secret (`kx.rs`, RFC 7748 §6.1) is unchanged. The boot line is now `crypto: ecc=<p256> x25519=<ladder> (...)` (`armv8` on aarch64; `adx` or `portable` on x86_64), and the smoke patterns require it.
- **P-256 verification (both architectures, `crates/nistz256/src/lib.rs`).** Before: `u1 G` from the comb (37 mixed additions, 2.6 us), `u2 Q` for an unknown key by the *constant-time* signed-window multiplication (255 doublings, 51 additions, 52 full-table scans: 21.7 us; doublings are 15 of it), `s^-1` by the constant-time Fermat chain (3.9 us). Verification sees only public data, so:
  - `u2 Q` by a **width-5 NAF** over the Jacobian table Q, 3Q, ..., 15Q (`mul_var_vartime`): about 43 additions, no scans, nothing for the leading zero digits: 19.3 us. Wider windows were computed, not built: w = 6 saves about six additions (0.6 us) and costs eight more table additions (0.8 us); w = 4 costs about nine more additions. **Interleaving `u1 G` into the same doubling chain (Shamir/Straus) was not built:** the comb already computes `u1 G` without any doubling; interleaving would replace its 37 mixed additions by about 32 (reusing the comb's first row, the multiples 1G..64G), at most about 0.4 us, and the mixed addition of the assembly does not handle equal inputs, which an adversarial key could arrange in a shared chain. Not worth that hazard.
  - `s^-1` by RustCrypto's **variable-time** inversion (`p256::Scalar::invert_vartime`, safegcd in crypto-bigint, already in the image through `urmqtt-tls`; now a dependency of `urmqtt-nistz256` on the targets where it is not empty): 1.17 us. The KeyTable path (registered issuers) uses it too. Signing keeps `inv_n` (its nonce is secret).
  - **Tests.** wNAF digits reconstruct 2 000 scalars (with all-ones limbs, 0, N, P, 2^256 - 1) and have the NAF shape; the NAF multiplication equals the constant-time one and RustCrypto's on structured scalars (small, single bits, N-1, N-2, alternating) and 200 random ones, 0 and N give infinity; the inversion equals the Fermat chain on 504 values and refuses 0 and N; new corner cases against the stock verifier: keys G, 2G and -G (d = 1, 2, N-1, so `u1 G` and `u2 Q` can be equal or opposite and the sum infinity), z = 0 and z = N (u1 = 0), z = N-1, nonces 1, 2, N-1, r = s, r and s swapped, a flipped z, s = N-1. The existing differential tests (valid, bit-flipped, swapped, foreign key, r + N < P) pass unchanged. Verdicts are identical to the stock verifier in every case.
- **Other stages (item 4 of the brief).** Nothing else is above 5 % of a full handshake: HMAC/HKDF 3.7 us (45 calls, 4.7 %), AEAD 3.8 us (4.7 %), `finish_handshake` 2.5 us (identity, serial, record keys), SHA-256 transcript 1.6 us (23 calls), webpki's path validation 0.3 us, our serial/revocation/role checks 0.3 us, the memo 0.3 us, the ticket 1.1 us, the unattributed rest (rustls) 5.9 us; 164 allocations (48 KiB) per handshake. The transcript is not hashed twice, the certificate is decoded by webpki once and by our identity code at the end (ADR-132's state), and no `KeyTable` is built per handshake. Left alone.
- **Result (Docker linux/arm64 on an Apple M4 Pro, image `urmqtt-ci`, release, `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` as the kernel; NOT the target CPU, nothing measured on the Neoverse N1).** Server CPU per handshake (`handshake_profile`, median round of 9 x 200, three processes each, interleaved; "before" is v0.4.0's crypto with the profiler added): returning device 88.8 / 89.5 / 93.9 -> 80.3 / 80.5 / 80.5 us; first contact 118.6 / 118.6 / 123.8 -> 87.8 / 88.1 / 88.5 us. The primitive profile (`profile` example, v0.4.0 and this change interleaved, 7 runs, min / median): x25519-dh 20.0 / 20.3 -> 14.4 / 14.6, ecdsa-verify 28.3 / 29.0 -> 24.2 / 24.5, ecdsa-verify-ca 9.5 / 9.8 -> 7.1 / 7.2, the estimate 92.1 / 92.8 -> 79.8 / 80.8 us. Tables: PERFORMANCE.md section 12.
- **Boot check.** `make build ARCH=aarch64` and `ARCH=x86_64` build; `make clippy-kernel` is clean on both; `cargo clippy --workspace --all-targets -D warnings` on macOS and the three touched crates (with and without `stage-profile`) in linux/arm64 Docker are clean. aarch64 smoke (HVF and TCG): `boot-acpi`, `boot-dtb`, `crypto-soft`, `sealed-write`, `crypto-bench`, `simd-irq`, `sys-operator`, `sys-reboot`, `ticket-rotation`, `ticket-restart`, `dp-bench`, `mqtt-persist-*`, `watchdog-handshake` and the checks they pull in: 59 passed, 1 failed: `watchdog-handshake` under TCG, whose self-test spin loop was counted as 32-34 ms running of 52 ms elapsed (host stalls under TCG; no crypto in that loop, and its 50 ms budget is the floor in both trees); rerun alone it passed 2 of 3 times on this branch and once on v0.4.0. In-guest `dp-bench` (HVF): 4 376 / 8 394 / 15 583 handshakes/s on 1 / 2 / 4 worker cores (ADR-255's run: 4 008-4 018 on one core; not interleaved, so only indicative). x86_64 under TCG: the storage and control scenarios booted with `crypto: ecc=nistz256-adx x25519=adx` and the KATs passing (the filtered run then stopped at a `dp-bench` post-check that expects its log, a limitation of `SMOKE_SCENARIOS` filtering, as for `sealed-write` on aarch64). The x86_64 unit tests were not run (no x86_64 Linux host; the x25519 tests ran as an x86_64 macOS binary under Rosetta 2, where `nistz256` is empty and whether the ADX path ran is not known).
- **Not done.** A measurement on the Neoverse N1 (the owner's, with a benchmark image of this branch; PERFORMANCE.md section 12 names the command); PSTATE.DIT (A255-W2); the signing path (11.5 us: 3.9 us of it the constant-time `inv_n`, 2.4 us the affine conversion) is unchanged; ×38 by shifts instead of `mul`/`umulh` in the fold (fewer multiplier instructions, more ALU ones: only worth it if the N1 is multiplier bound, which needs the N1 to decide); a 4x64 fixed-base X25519 key share; x86_64 is built and its kernel type-checked, but its unit tests did not run here (no x86 Linux host): the verification change is shared code and runs there unmeasured.

## ADR-260 — Proposal, not enabled: a cache of verified client certificates (owner decision)

- **Status:** Proposed. No code. A security decision for the owner.
- **What exists today.** The verification memo (`provider/verify.rs`): a 512-entry direct-mapped set of SHA-256 digests of (key, message, signature) of *successful* certificate signature checks. A returning device's certificate signature is therefore not verified again (the profile's "returning device" case). Everything else of the path validation still runs on every full handshake: webpki parses the chain, builds the path to an anchor, checks validity periods against the wall clock, key usage, the name constraints; then our serial/revocation/role checks; CertificateVerify is always verified (fresh per handshake).
- **What a full certificate cache would add, measured.** On top of the memo it could skip only webpki's path validation (0.3 us), our checks (0.3 us) and part of `finish_handshake`'s certificate decoding (part of 2.5 us): **about 1 us of 80 us** per full handshake of a returning device (Docker linux/arm64, Apple M4 Pro, ADR-259). It cannot skip the CertificateVerify signature (25.7 us), the key exchange or the signature of our own CertificateVerify. The memo already takes the large part (the CA signature, 7-10 us). Session resumption (ADR-054) is the mechanism that saves the most for a returning device: 40.7 us per resumed handshake against 80.3 us for a full one (no signature, no verification; X25519 is still done, `psk_dhe_ke`).
- **What it would still have to check every time.** The validity period against the current wall clock (a cached "valid" expires with the certificate and must not outlive a clock correction); the revocation list at its current version (a revocation must take effect on the next handshake, so either the cache is flushed on every list change or each entry carries the list version it was checked against); the trust-anchor configuration (operational vs bootstrap role and the anchor set: an entry must carry the configuration's identity, and a removed anchor must invalidate it); the exact certificate bytes (keyed by a collision-resistant hash of the whole chain, as the memo is).
- **Risks.** A logic error in invalidation turns into accepting a revoked, expired or no-longer-trusted device; the cache is a new piece of state shared between cores (lock, bounds, eviction) on the authentication path; a cache keyed on anything less than the full chain is a confusion risk; the difference between a hit and a miss (about 1 us) would tell a remote observer whether a certificate was seen recently, which TLS 1.3 otherwise hides (the client certificate travels encrypted); low, but new.
- **Recommendation.** Do not build it: it saves about 1 % of a returning device's full handshake for a new trust decision. Keep the memo (pure function of its inputs, failures never cached) and rely on resumption for returning devices.

## ADR-261 — The `storm` hang: a FIN sent again on every ACK in FIN-WAIT-2 (since M14), exposed by the trust-anchor tables' heap (A261-W1, A259-W2)

- **Status:** Accepted. Amends ADR-033 (the own TCP stack: FIN-WAIT-2) and ADR-259 (where the anchor tables live and what they cost).
- **Symptom.** The smoke scenario `storm` (`scripts/smoke.sh`: `heap_limit_mb=8`, 3000 mTLS devices connect at once, three rounds) passed with the v0.4.0 kernel and hung on aarch64 HVF with every kernel containing 1fb37ba (ADR-259's anchor tables): round 1 stopped between 2,575 and 2,757 connections, the heap went below the free reserve, core 0 ran at 100 %, the loadgen never returned; CI's "Smoke misc" ran past 100 minutes (21 before).
- **Reproduced here** (Apple silicon, QEMU HVF, 4 vCPUs, dev image, `build/kernels/*` built from 6cc343b, 1fb37ba's descendant 51fabe2 and variants): 51fabe2 hung (round 1 at 2,741 connections after 190 s, `frame(s) dispatched` on core 0 rising from about 1,500 to 600,000 per 5 s at about 97 s, frame buffers 130 KiB -> 5.2 MiB, heap in blocks 3.6 -> 9.2 MiB); 6cc343b passed (rounds of 34, 64 and 71 s, 2,987 to 2,997 of 3,000).
- **Root cause: a TCP bug, in every release since M14 (93455a4).** `transmit` decided to send a FIN when `FIN_QUEUED` was set and `snd_nxt` stood at the end of the data. Once the peer acknowledged our FIN, the acknowledged data was gone (`tx_len() == 0`) and `snd_nxt == snd_una`, so the FIN looked unsent: the next pass sent a new FIN one sequence number further, and every ACK of it brought the next one. The retransmission timer armed for each "new" FIN also replaced the FIN-WAIT-2 timer, so the 60 s FIN-WAIT-2 bound never fired. It needs a peer that keeps its side open (CLOSE-WAIT) and acknowledges each FIN: QEMU's user-mode network (libslirp) does; a packet capture of one connection shows `F. seq=1584`, `. ack=1585`, `F. seq=1585`, ... 439,315 segments each way in about 40 s. How a Linux or lwIP device answers such a FIN was not tested; a peer that does not acknowledge it gets it again on the RTO back-off until the retries end the connection, which is slow, not a loop. Reproduced on the **v0.4.0 kernel** without any storm: `loadgen hold --clients 500 --keepalive 5` (the broker closes the idle connections after 7.5 s, the loadgen keeps its sockets): core 0 at 100 %, 3.7 million frames per 5 s, the 500 connections never released while the devices held them.
- **Why 1fb37ba exposed it: memory.** The anchor tables are real since ADR-259: 3 anchors in the dev image (`ca`, `ca-2`, `ca-bootstrap`), each a 151,552-byte vector, which the buddy heap rounds (power of two, and the canary gap of allocations of 32 KiB and more) to a 256 KiB block. Idle heap with one connection: 1,510 KiB in blocks on 6cc343b, 2,287 KiB on 51fabe2 (+778 KiB), 1,510 KiB on 51fabe2 with only the `register_issuer` call removed (`build/kernels/notables.elf`, the bisection inside 1fb37ba). `heap_limit_mb=8` with `min_free_mb = 4` leaves about 4 MiB in use before SYNs are dropped, about 2.5 MiB of it above the idle heap before; 778 KiB less made the kernel drop many more SYNs (each costs the device a 1 s SYN retransmission), so a round no longer finished before the first devices' keep-alive (1.5 x 60 s) expired. The broker closed those idle connections, the loadgen does not read, and the FIN loop above took core 0. v0.4.0 was close to the same edge (its rounds took up to 71 s).
- **What it was not.** The tables are not per core or per handshake: one registry (`verify.rs` `ISSUERS`, `Arc`), a key registered again finds its table (each core's `TlsServer::new` registers; the cost is a parse). The `stage-profile` wrappers are not in the kernel (`cargo tree -e features`: `urmqtt-tls` only with its default features; `timed` is `f()` without the feature). The X25519 and verification changes (f58ff7f, 663b5e9) are not involved (the kernel without registration behaves as v0.4.0). The heap reserve path did not stall: below the reserve SYNs are dropped and connections refused, as designed (ADR-080); with the TCP fix and the tables in place the storm passes (below).
- **Decision.**
  1. **TCP** (`crates/tcp/src/lib.rs`, `transmit`): no FIN once ours is acknowledged (`FIN_SENT && snd_una == snd_max`); a FIN is sent once and again only as a retransmission from `snd_una`. FIN-WAIT-2's timer then stays, and a half-open peer is let go 60 s after our FIN was acknowledged. Scripted tests (`scripts.rs`): `fin_wait_2_with_a_half_open_peer_sends_nothing_and_times_out`, `fin_after_data_is_sent_once` (both failed before: a second FIN at `seq=2` / `seq=26`).
  2. **Anchor tables** (`crates/nistz256`, `KeyTable`): each of the 37 rows is its own 4 KiB allocation (a compile-time check that a row is exactly 4096 bytes), so a table takes 148 KiB instead of a 256 KiB block. The boot builds them once, on the boot CPU, before it measures the heap the reserve is set against (`mqtt_service::prepare_trust_anchors`, `urmqtt_tls::server::prepare_trust_anchors`) and logs them: `tls: 3 trust-anchor verification table(s), 445 KiB of heap (445 KiB requested)`; the `mem: heap ... in use` line after it now includes them (1,793 KiB instead of 1,348 KiB). Idle heap with one connection: 1,964 KiB (+454 KiB against v0.4.0, -323 KiB against 51fabe2). The tables stay: they are the point of ADR-259 (a first contact's CA verification by table, 7.2 us against 24.5 us by the unknown-key path in Docker on an M4 Pro). Only in a heap of a few MiB with many anchors does their memory weigh (8 anchors, the maximum with a table: about 1.2 MiB); DEPLOY.md and README now count about 150 KiB per anchor in the heap sizing. A test (`trust_anchor_tables_are_built_once_and_shared`) checks one table per distinct key, at most 150 KiB each, and that four more servers add none.
  3. **Load generator** (`tools/loadgen`, `storm`): `--io-timeout-s` (default 10) is the read and write timeout of every step while a connection opens; the `--retry-s` deadline holds for each attempt, not only between passes (with SYNs dropped one pass over a thread's few hundred devices took many minutes past it); a round whose threads are still busy a connect timeout plus four I/O timeouts after the deadline fails with `storm round N: K of 8 thread(s) still in an attempt ...` instead of waiting. `smoke.sh` passes `--io-timeout-s 10` and bounds the loadgen at 15 minutes (`bounded`, since macOS has no `timeout(1)`).
  4. **Smoke** `fin_wait2` (in `SMOKE_ONLY=misc` and the default run): 50 devices with a 2 s keep-alive held for 90 s; `mem: 0 connection(s)` must be logged while they still hold their sockets (FIN-WAIT-2 ended them). On 51fabe2 it fails (`missing: mem: 0 connection(s)`), with the fix it passes.
- **Results (HVF, 4 vCPUs, `SMOKE_ONLY=misc SMOKE_GROUPS='^storm$'`).** See PERFORMANCE.md section 12.2. With only the TCP fix and the old loadgen the storm passed in 15 minutes (rounds of 259, 331 and 319 s: the dropped SYNs, not a stall; core 0 at 27 %); with all of the above it passed 3 of 3 in about two minutes each.
- **Consequences.** v0.4.0 and earlier releases have the FIN loop (A261-W1): a peer that keeps a connection half open after the broker closes it with a FIN (seen with keep-alive timeouts; a handshake timeout is a reset and not affected; the other graceful close paths were not audited one by one) and acknowledges each FIN makes the broker exchange segments with it at line rate for as long as it likes, and the connection slot is never freed. Fixed for the next release. Not verified: a real Linux or lwIP device as the peer, x86_64 (the code is shared), the netcup VPS (where the storm of ADR-259's bench image completed: its rounds ended before any keep-alive expired).

## ADR-262 — Miri in CI: one process per test (cargo-nextest), a result cache, a negative control

- **Status:** Accepted. Amends the Miri part of H5 (`scripts/miri.sh`, docs/VERIFICATION.md).
- **Problem.** The Miri jobs ran `cargo miri test` per crate: one process, the tests one after another on one of the
  runner's four vCPUs. Miri tls took about 50 to 90 minutes, Miri cfg about 70, and a release waited for them.
- **Measured (Apple M4 Pro, macOS, native Miri; nextest's per-test times).** tls: 27 tests, 2,042 s of Miri time, of
  which `server::capture_tests::the_bound_evicts_the_oldest_and_wipes_it` 1,100 s (4,096 inserts, each a linear scan of
  the table) and `identity::tests::the_light_serial_reader_agrees_with_the_full_decoder` 534 s (3,200 full X.509
  decodes); then the AEAD-heavy record tests (161 s, 123 s) and the ticket lifetime test (82 s). cfg: 41 tests, dominated
  by seven PBKDF2 tests that the script meant to skip: its patterns read `passwd::<name>`, the tests are
  `passwd::tests::<name>`, so they never matched (since ab5ac4e).
- **Decision.**
  1. **Runner.** `scripts/miri.sh` runs `cargo miri nextest run` (one Miri process per test, `MIRI_JOBS` at a time,
     default 2, CI 4) when cargo-nextest is installed; `MIRI_RUNNER=libtest` keeps the old runner. Same `MIRIFLAGS`,
     same skip lists (nextest takes libtest's `--skip` filters), same tests: the counts were compared per crate.
  2. **Two tests smaller under Miri only.** `MAX_CAPTURED` is 64 under `cfg(miri)` (4096 otherwise): the eviction test
     still fills the table and evicts through the same code. The serial-reader test runs 40 random corruptions per
     certificate under Miri instead of 400, on every certificate and with every truncation. Both crates' code is
     `forbid(unsafe_code)`; `cargo test` keeps the full sizes.
  3. **The cfg skips fixed** to `passwd::tests::<name>`, which is what the comment (ADR-229) always said Miri skips: 34
     tests run instead of 41; the seven run natively in `cargo test`.
  4. **Result cache.** `scripts/miri-cache-key.sh` hashes the tracked files of the crates and of every path package
     they build with, the workspace manifest, `Cargo.lock`, `.cargo/config.toml`, the toolchain file, the Miri scripts,
     the certificate generator, `rustc -vV`, the Miri and nextest versions, the flags and the OS and architecture. A job
     whose exact key has a marker reports "cached" and runs nothing; a marker is saved only after the Miri step and the
     negative control passed (`actions/cache` restore and save, exact key, no prefix match). `workflow_dispatch` with
     `miri-cache` off bypasses it.
  5. **Negative control.** `urmqtt-config` has a use-after-free test compiled only under Miri and `#[ignore]`d;
     `scripts/miri.sh --negative-control` fails unless Miri reports "Undefined Behavior" for it. Every Miri job runs it.
  6. `scripts/miri.sh` sets `CARGO_INCREMENTAL=0`: cargo-miri compiles the test crate again in every test process, and
     parallel processes raced on the incremental session directory (seen once in Docker: "failed to move dependency
     graph").
- **Results (Miri test time, build excluded; Apple M4 Pro native and Docker linux/arm64 with 4 vCPUs on it).**
  tls: 27 tests before and after; 2,042 s one after another before, 216 s (macOS) and 201 s (Docker) at `-j 2` after;
  the longest test is now `record::tests::roundtrip_and_fragmentation_both_suites` (136 to 145 s), the capture test takes
  0.8 s and the serial-reader test 52 to 57 s. cfg: 41 tests and 1,424 s before (the seven PBKDF2 tests 1,075 s of it),
  34 tests and 200 s (macOS) and 183 s (Docker) at `-j 2` after, bounded by `net::tests::contains_agrees_with_a_bitwise_reference`
  (199 s). protocol crates: 120 tests, 131 s wall before, 72 s at `-j 4` after; config: 11 tests, 40 s before, 31 s
  after. The GitHub runner was not measured: the old jobs' 50 to 90 minutes against 34 minutes here put it 1.5 to 2.6
  times slower, so the longest Miri job (cfg) should take about 5 to 9 minutes of tests plus its build, under 20 minutes.
- **Trade-offs.** The two shrunk tests check fewer cases under Miri (the full sizes run natively). The cache skips a
  run when the hashed inputs are unchanged; it cannot see the random development certificates (their generator is
  hashed), the runner image's system libraries, or new proptest seeds (Miri with isolation off takes host entropy), so
  a cached green never retries seeds. Per-test processes cost Miri's
  start-up (about 0.5 s) per test. Miri stays a gate on every push to main and every pull request: it is the only check
  of the memory model of the parsers, buffers and the one `unsafe` module that runs on every change; dropping it on
  main would leave a release depending on whichever pull request last ran it.

## ADR-263 — The weak entropy path is an explicit option, loud wherever a user decides (NOW-4, D-3)

- **Status:** Accepted (owner decision, 2026-11-06). Amends ADR-038 (the CPU-jitter fallback) and ADR-225 to ADR-228 and ADR-232 (the builder). Numbered 263: the highest on any branch at the time was ADR-262 (Miri in CI, already in main).
- **Problem.** On a real netcup ARM VPS (Neoverse N1) there was no virtio-rng and no `RNDR`: the generator ran on the jitter fallback alone, which the boot warning and the Diagnostic entry show, but nothing told the person who built the image, and nothing let them say "not on such a host" without reading the configuration reference. The key is `entropy.fallback` (`"jitter"` or `"none"`, not a boolean); the Diagnostic entry named it wrongly as `entropy.jitter_fallback` (that is the parsed field's name) and now uses the real one.
- **Decision.** The default stays `"jitter"`: such a VPS still boots. Nothing about the generator, the estimator or the credit changes. What changes is that the choice is visible and one click wide where it is made, and its result is stated where it is used:
  - **Builder, basic view:** a "Random numbers" group with two options. "Allow CPU-jitter fallback (default): boots on hosts without a hardware random number generator, seeding the generator from CPU timing jitter and the firmware's values; weaker than a hardware source." and "Require a hardware random number generator: the image refuses to boot without virtio-rng or a CPU instruction (RNDR, RDRAND/RDSEED) and says so on the console." A warning is shown while the first is chosen; the result card names the option built; the amber notes list "Random numbers may come from CPU jitter" while the fallback is allowed. The advanced form keeps the same key. 14 translations (AI, unreviewed).
  - **`urmqtt-config`:** `pack`, `verify` and `show` print `WARNING: entropy.fallback = "jitter": on a host without virtio-rng or RNDR/RDRAND the generator is seeded from CPU jitter and firmware values, which is weaker than a hardware source; set it to "none" to refuse such hosts` while it is allowed; `show` has an `entropy:` line either way. The schema's doc string says the same.
  - **Boot:** the warning line stays and gains "weaker than a hardware source (entropy.fallback = "none" refuses such hosts)". With `"none"` and no hardware source the fatal message names the key: `no entropy source (virtio-rng, RNDR) and entropy.fallback = "none" forbids the CPU-jitter fallback: refusing to run`. The old message stays for a fallback that ran and failed its health tests.
  - **`$SYS/broker/entropy/source`** (retained, next to the `time/` topics; also `"entropy":{"source":...}` in the info reply and an `entropy source` line in `status`): the hardware sources that delivered joined by `+` (`virtio-rng`, `rndr` or `rdrand`), else `jitter+firmware` (`jitter` if the firmware gave no non-zero value). The Diagnostic entry's RNG panel is unchanged.
- **Why not a stricter default.** A default that refuses would stop images from booting on the clouds that matter (Ampere Altra, the netcup finding) with a message nobody had a reason to expect; a default that is allowed and loud, with the strict choice a click away, keeps the first boot working and the decision informed. Revisit if a provider matrix shows hardware sources are the rule.
- **Tests.** Host: the `$SYS` topic, its JSON and status line, the source names (`urmqtt-broker`); the `pack`/`verify`/`show` output with both settings (`tools/config/tests/cli.rs`); the builder's form logic, the i18n completeness, and the page (the two options, the warning, the note, the hash, the result card). Smoke `entropy_option`: the `$SYS` value with no virtio-rng (`jitter+firmware`) and with it (`virtio-rng`), `fallback = "none"` refusing with the message above, and the same image booting with virtio-rng.
- **Not done.** Per-provider sources in DEPLOY.md section 6 (filled as providers are tried); the credited-bits figures on an Ampere cloud (TODO.md); a requirement that production images carry an explicit choice.

## ADR-264 — The link MTU: DHCP option 26, `network.mtu` (configuration format 7), the MSS follows it (NOW-19)

- **Status:** Accepted. Amends ADR-033 (the TCP stack: the announced MSS was a constant), ADR-222 (segment size), M7's
  DHCP client and the virtio-net transmit path. ADR-263 is the entropy-fallback decision; this is the next free number.
- **Context.** Every packet was sized for a 1500-byte MTU: `urmqtt_tcp::Config::mss` was 1460 from `netproto.rs`,
  the segment buffers were 1460 bytes, the SYN cookie's MSS table ends at 1460, the DHCP client neither asked for nor
  read option 26, and statsd datagrams were up to 1400 bytes "for any Ethernet MTU". Google Cloud's VPC networks use
  1460 by default (found 2026-11-05 while preparing that cloud's scripts): there a full segment is a 1500-byte IP
  packet, which the network drops without an ICMP error, so the handshake and small messages pass and a certificate
  flight or a 4 KiB publish stalls in retransmissions until a timeout. Other networks use 1500, jumbo frames (8896,
  9000) or less (tunnels).
- **Decision.**
  1. **Sources, in order:** `network.mtu` when set (576 to 9000, any network mode; with `mode = "static"` the only
     source; it also wins over DHCP, so an operator can correct a wrong lease); else DHCP option 26 when the lease
     carries it and it is 576 to 9000 (anything else is logged, `net: dhcp announced mtu N, outside 576..=9000:
     ignored`, and not used); else 1500. The DHCP request now lists option 26 among its parameters; a malformed
     option (length other than 2) is ignored. Core 0 applies the value to its interface and TCP stack and sends it to
     the other data cores in `CoreMsg::IpConfig`; one boot line `net: mtu N (static|dhcp|default)` (again when a
     renewal changes it), `$SYS/broker/net/mtu` and `net.mtu` in the info query.
  2. **Frames above 1500 bytes are never sent.** The driver's transmit buffers hold 1514 bytes and it does not
     negotiate `VIRTIO_NET_F_MTU` or larger frames. A jumbo MTU is used as 1500 (`net: mtu 1500 (dhcp; 9000 asked
     for, ...)`), which a jumbo network carries. The **receive** buffers are unchanged (2048 bytes per descriptor,
     independent of our MTU): what the device delivers is accepted as before.
  3. **TCP: MSS = MTU - 40** (`urmqtt_tcp::mss_for_mtu`, clamped to 536..=1460, the SYN-cookie table's range, which
     also bounds the segment buffers). It is what the SYN-ACK announces and the most a connection sends; the peer's
     MSS (through the cookie, rounded down to its table) and ours give the smaller. With timestamps the payload is the
     MSS minus 12 (ADR-222), so a segment is at most MTU bytes as an IP packet. `TcpStack::set_mss` applies a new
     value to new connections and lowers open ones (a DHCP renewal that announces less): their next segment and every
     retransmission are cut to it; the congestion window counts bytes (ADR-222), so it stays valid. ADR-222's send
     queue, cwnd and window logic is otherwise untouched.
  4. **UDP and ICMP, no fragmentation.** `Iface` holds the MTU; `send_udp` refuses a datagram larger than MTU - 28
     and `send_ip` drops any packet larger than the MTU (counted in `Stats::too_big`; in practice an echo request
     larger than our MTU gets no reply instead of a fragmented one). statsd packs its lines into datagrams of at most
     `min(1400, MTU - 28)`. The other datagrams are far below 548 (576 - 28), the smallest MTU allowed: DHCP about
     300 bytes, SNTP 48, a syslog line at most about 400 (254 bytes of record text plus the RFC 5424 header).
  5. **Configuration format 7.** `network.mtu` is a new tag (195), `uint(2, 0..=9000)`, default 0 ("not set"); the
     check refuses 1 to 575. 0 writes no record, so a configuration without the key keeps its lowest format and boots on
     an older kernel; a value needs format 7, so a v0.4.x template (format 6) refuses it when it is packed instead of
     booting a kernel that would ignore the record. The TOML form, the packer, the builder page (advanced view; the
     range text says what 0 means, in the 15 site languages, AI translations, unreviewed) and the schema follow the
     field table as usual. `default_toml` now groups a field added later to an existing section into that section.
- **Verification.** Host tests: option 26 present, absent, out of range and malformed (`urmqtt-net`); the MTU guard of
  the interface (TCP, UDP, an oversized echo); the MSS derivation and that no segment exceeds MTU - 40 of payload (and
  MTU as a packet) at 576, 1460, 1500 and 9000, with and without timestamps, first transmissions and a retransmission,
  the smaller-MSS rule, and a lowered MTU on an open connection (scripted segments, `urmqtt-tcp`); format 7 and the
  checks (`urmqtt-cfg`, `urmqtt-config-schema`, `urmqtt-config`, `tools/config`). Smoke group `net_mtu`: a static
  1460 configuration boots with `net: mtu 1460 (static)`, a 4 KiB QoS 1 message goes device -> broker -> backend over
  mutual TLS, `$SYS/broker/net/mtu` is 1460, and the capture shows no frame from the guest above 1474 bytes, full ones
  at 1474 and SYN-ACK MSS 1420; DHCP announcing 1460, 9000 and 300 on urmqtt-attack's raw transport (its DHCP server
  gained option 26 and the mode `mtu-probe`, which reads the SYN-ACK's MSS), because QEMU's user network has no `mtu`
  option and its DHCP server sends no option 26.
- **Not verified.** A network that really drops larger frames: QEMU's user network accepts 1500-byte frames, so the
  scenarios show what the broker sends, not that it survives a path that drops more. Google Cloud itself (the open
  edition's first boot there is planned on e2/n2 with virtio-net). Path MTU discovery is not done: a smaller MTU
  further along the path than on the link still depends on the peer's MSS or on ICMP "fragmentation needed", which we
  do not act on.
- **Not done.** `VIRTIO_NET_F_MTU` (the device's own MTU in its configuration space) is not negotiated: negotiating
  it obliges the driver to post receive buffers of that size, and the receive path stays at 2048-byte buffers. The
  Diagnostic report's NIC entry does not show the MTU: the Diagnostic boot runs no DHCP, so it could show only the
  configured value.

## ADR-265 — TCP recovers from the peer's SACK blocks, acknowledges every second segment on arrival, and grows its window only while it is used (NOW-13, PERF)

- **Status:** Accepted. Amends ADR-222 point 7 ("Not done: SACK-driven retransmission on our sending side") and
  ADR-033's NewReno. Written on 2026-11-01 on the unmerged branch `perf-nic-queues-tcp-sack` as "ADR-232", a number
  `main` has since used for the builder; rebased onto `main` (after ADR-261's FIN fix and ADR-264's MTU) on
  2026-11-07, when 265 was the next free number.
- **Context.** PERFORMANCE 7.5: one flow is not faster than Mosquitto's, and the subscriber leg (our sending side)
  is the slow one. A lost segment of a long subscriber stream was recovered NewReno-style: one retransmission per
  partial ACK, so a window with several holes took one round trip per hole, and a burst of ACKs after a vCPU stall
  (the host preempts the guest for tens of milliseconds) looked like a series of partial ACKs and resent segments
  that were not lost. Two more things held a sender back: the receiver acknowledged once per pass of the core (a
  batch of up to 64 frames, every 8 to 50 ms on a preempted VPS), so the peer's window waited for our ACK; and the
  congestion window grew while the application did not fill it (a quiet subscriber's window reached megabytes), so
  the first loss halved *what was in flight*, a few segments.
- **Decision.**
  1. **A scoreboard of the peer's SACK blocks** (`crates/tcp/src/sack.rs`, RFC 2018 / RFC 6675): at most 8 ascending,
     disjoint ranges above `snd_una`, boxed and allocated only while the peer reports holes (about 80 bytes; `None`
     otherwise), dropped on a full ACK, on a timeout and when the cumulative ACK covers it. A block is taken only if
     it lies within `(snd_una, snd_max]` and is not empty; its left edge is clamped to `snd_una`; a block that would
     need a ninth range is ignored (the peer repeats it). The blocks come from the existing option parser
     (`wire.rs`, at most 4 blocks, bounds-checked; unchanged).
  2. **Loss detection:** a hole is lost when more than two segments or three ranges are SACKed above it (RFC 6675
     `IsLost`, DupThresh 3) **and** the evidence has lasted a reordering window: an eighth of the smoothed RTT (at
     least 1 ms, at most one RTT), doubled each time the peer reports a duplicate (D-SACK, RFC 2883: a first block at
     or below the ACK, or inside the second), up to 7 doublings (kept in the high nibble of `retries`). Then
     `ssthresh` is cut and recovery starts with `cwnd = ssthresh`.
  3. **Recovery:** lost holes only are resent, each once (`next` is the frontier), one segment at a time, while the
     **pipe** (in flight, less SACKed, less lost and not yet resent) leaves room under `cwnd`; new data follows under
     the same pipe and the peer's window. A partial ACK no longer resends the next segment by itself when the peer
     does SACK. A peer that did not negotiate SACK gets NewReno exactly as before, and duplicate ACKs without blocks
     still start a classic fast retransmit.
  4. **ACK every second segment on arrival** (RFC 5681 §4.2), before the application sees the data; the rest at the
     end of the pass as before (an out-of-order segment is still answered at once, ADR-222).
  5. **Congestion window validation** (RFC 7661, Linux's `is_cwnd_limited`): the window grows only while the flight
     comes within two segments of it (congestion avoidance) or within half of it (slow start); a fast retransmit cuts
     to 70 % (Linux CUBIC's beta) of the smaller of the window and twice the recent peak flight, at least the flight;
     a timeout halves the same base. `ssthresh` and the peak are kept in 16 bits of 64-byte units (up to 4 MiB), so
     `Conn` stays at 112 bytes. The send queue limit follows `min(cwnd, peer window)`, so a reader that stops keeps
     only the base queued.
  6. `TcpStack::busiest_sender` exposes the connection with most data queued (for ADR-266's log line).
- **Security properties.** All new state is per connection and bounded (8 ranges, one box); a block outside what we
  sent is ignored. A peer that lies in its blocks (claims data it never received) can only slow itself: the data
  stays queued until the cumulative ACK covers it and a retransmission timeout clears the board and goes back to
  `snd_una`. Claiming SACKed data enlarges what may be sent by at most the flight, and is still bounded by the
  peer's window and `cwnd`, which an optimistic ACKer could already inflate. The RFC 5961 checks, SYN cookies and the
  receive side are untouched; ADR-261's "FIN once" holds (a hole never contains our FIN, which sits above every
  SACKed range).
- **Verification.** `cargo test -p urmqtt-tcp` (79 tests, 16 new): the board (merge, overlap, touch, trim, wrap,
  `IsLost`, frontier, a random-block model keeping it tidy), scripted connections (one loss resent once and nothing
  else, a reordered segment not resent, a burst of partial ACKs after a stall is not a loss, two holes repaired in
  one round trip, a peer without SACK gets NewReno, duplicate ACKs without blocks, a transfer over a lossy reordering
  link completes with few extra segments), the delayed-ACK change and the cwnd rules. The `tcp_segment` fuzz target
  now sends up to three SACK blocks (flag bit 6) with edges around the ACK: 5.1 million runs in 300 s on the M-series
  Mac, no finding. The H3 model tests, ADR-261's half-open scripts and ADR-264's MSS tests pass unchanged.
- **Numbers (local rig, ADR-223, `docs/perf-results/sack-rig-ab.txt`).** `main` against this change, one publisher
  and one subscriber, QoS 0 flood, 15 ms configured RTT, 3 runs per cell, medians of delivered/s (published/s
  changes little, inside the noise):

  | loss | 64 B: main | 64 B: ADR-265 | 1 KiB: main | 1 KiB: ADR-265 |
  |---|---|---|---|---|
  | 0 | 78.2k | 84.8k | 4.28k | 7.05k |
  | 0.1 % | 21.2k | 21.4k | 1.99k | 2.29k |
  | 0.5 % | 9.9k | 10.3k | 0.85k | 1.04k |
  | 1 % | 6.2k | 7.9k | 0.61k | 0.72k |

  The largest gain is at 1 KiB without loss (+65 %), where SACK recovery hardly runs: it is the per-arrival ACK and
  the validated window. Under loss the subscriber leg gains 0 to 27 %; the spread between runs is of the same order in
  several cells, so only the 1 KiB columns and the 1 % row are a claim. No run lost a connection.
- **Not verified.** Not measured on a VPS (netcup, Contabo) against Mosquitto, which is what NOW-13 asks for; the rig
  measures protocol behaviour, not capacity. No Kani harness for `sack.rs` (the existing TCP harnesses cover the
  parser, which is unchanged).
- **Not done.** RACK / tail-loss probes (a loss at the tail of a burst, with nothing SACKed above it, still waits for
  the retransmission timeout, as before); a partial ACK in a SACK recovery that leaves no blocks also waits for more
  evidence or the timeout. SACK reneging is handled only by the timeout (RFC 6675's rule). PAWS and ECN as in ADR-222.
  Pending a decision, not part of this change: the same branch's heap caches and TLS/broker copy reductions (its
  ADR-230 and ADR-231 drafts), see ROADMAP NOW-13.

## ADR-266 — virtio-net queues of up to 1024 descriptors and a receive-queue statistic (NOW-13, PERF)

- **Status:** Accepted. Amends ADR-223 (core 0's NIC backlog) and the virtio driver's `MAX_QUEUE`. Written on the
  same branch as ADR-265 as "ADR-233"; renumbered on rebase.
- **Context.** A vCPU that the host deschedules for some milliseconds cannot empty the receive queue; with 256
  descriptors a burst of a 1 MiB window (about 720 segments) overflows it and the host drops frames the guest never
  sees (the 0.3 % burst loss of the rig at loss 0, PERFORMANCE 7.3). Nothing in the guest showed how full the queue got.
- **Decision.**
  1. `VirtioNet` asks for 1024 receive and 1024 transmit descriptors and takes what the device offers (`queue_max`,
     which must be a power of two, as before). `MAX_QUEUE` is 1024 (the per-queue bookkeeping arrays grow from 1 to
     4 KiB per queue); the other drivers ask for their own sizes, unchanged. At 1024 the receive and transmit buffers
     take 2 MiB each of DMA memory (2048 bytes per descriptor), was 512 KiB each. Boot line `net: virtio-net with N
     receive and M transmit descriptor(s)`.
  2. Core 0 notes how many completed receive chains wait before each dispatch burst (`SplitQueue::used_pending`);
     the per-core `stalls:` line also appears when the peak of the window reaches three quarters of the queue and
     names it (`NIC receive queue peak P of N`; other cores print 0 of 0).
  3. Every 5 s with traffic each data core logs its busiest sender (`tcp: core C: busiest sender: ... KiB queued, ...
     in flight, cwnd, ssthresh, peer window, srtt, rto[, in loss recovery]`, ADR-265's `busiest_sender`).
  4. Tools: `scripts/x11-capture.sh` (one single-flow run with a 4 s `tcpdump` on the load host),
     `scripts/pcap-flows.py` (per-flow TCP dynamics from a pcap; Python standard library only), `SS=1` in
     `x11-bench.sh` (`ss -tin` of the generator's flows 8 s into each run), `QEMU_NIC_PROPS` in `run-qemu.sh`.
- **What the hosts offer decides.** QEMU's default is 256 and it refuses `tx_queue_size` above 256 without
  vhost-user; with `QEMU_NIC_PROPS=rx_queue_size=1024` the guest runs with 1024 receive and 256 transmit descriptors
  (checked on the rig). What netcup, Contabo and Google Cloud offer is not known yet: the boot line will say.
- **Numbers.** None that show a gain: on the rig at 0.5 % loss, 1024 receive descriptors gave 11.2k and 0.98k
  delivered/s against 10.3k and 1.04k with 256 (one run each). The change is kept for hosts that offer more and for
  the statistic, which tells whether queue overflow is a cause on a given host.
- **Verification.** `cargo test -p urmqtt-virtio` (the size test now refuses 2048); kernel builds for aarch64 and
  x86_64 (universal ISO); the rig boots with 256 and with 1024 receive descriptors.

## ADR-267 — Plaintext password hashes: PBKDF2 at 100 000 iterations by default, a login rate that keeps half the core, no Argon2 for now (D-16)

- **Status:** Accepted (2026-11-07). Amends ADR-231 (the default count, was 10 000) and ADR-230 (the login admission's
  floor, was 20 a second). Answers ROADMAP D-16. Numbered 267: ADR-265 (TCP SACK recovery) and ADR-266 (virtio-net queues) were merged to main while this was written.
- **Context.** Plaintext accounts (P1) store `pbkdf2-sha256$<iterations>$<salt>$<key>`; `urmqtt-config hash-password`
  and the builder page used 10 000 iterations. OWASP's current figure for PBKDF2-HMAC-SHA-256 is 600 000, and D-16
  asked whether a memory-hard function (Argon2) should be added. What bounds the count here is not the tool but the
  broker: the kernel verifies **every** password CONNECT, on the path before authentication, in **one handler on a
  data core** (run to completion: nothing else on that core runs meanwhile), and the decoy for an unknown user costs
  the same. The plaintext listener is off by default and, when on, answers only `plaintext.allow_from` (checked at the
  SYN); failed logins lock an address out (5 in 300 s by default); a core admits password logins through a token
  bucket sized at boot from a measured check (ADR-230); the watchdog's handshake budget is calibrated to the dearer of
  a TLS handshake and a check, capped at 500 ms, and a handler past 1 s resets the VM (ADR-071).
- **Measurements** (2026-11-07; kernel figures are the boot line `plaintext: one password check costs about N us`,
  which times 128 iterations three times and scales to the dearest account's count):

  | Where | per iteration | 10 000 | 100 000 | 200 000 | 600 000 |
  |---|---|---|---|---|---|
  | Kernel, aarch64, HVF on the M4 Pro (`sha256=armv8-sha2`) | 0.26 us | 2.56 ms | 25.7 ms | 50.9 ms | ~154 ms (scaled) |
  | Kernel, aarch64, QEMU TCG | 1.6 us | 16.2 ms | ~162 ms | ~323 ms | ~970 ms |
  | Kernel, x86_64, QEMU TCG (`sha256=sha-ni`) | 2.5-4.3 us | 42.7 ms | ~427 ms | 495 ms | ~1.5-2.6 s |
  | Host, macOS on the M4 Pro, this code (release) | 0.07-0.13 us | 1.31 ms | 9.1 ms | 14.0 ms | 41.0 ms |
  | Host, macOS on the M4 Pro, OpenSSL (`hashlib.pbkdf2_hmac`) | 0.076 us | 0.76 ms | 7.6 ms | - | 45.6 ms |
  | VPS vCPU, AMD EPYC 9354P (Hostinger KVM), OpenSSL | 0.15 us | 1.35 ms | 15.1 ms | - | 94.1 ms |

  The kernel on the VPS was not booted for this (its two KVM VPSes run broker images); scaling the HVF figure by the
  VPS/M4 ratio of the same OpenSSL code (about 2x) gives **about 0.5 us per iteration on a VPS vCPU: about 5 ms at
  10 000, 50 ms at 100 000, 100 ms at 200 000 and 300 ms at 600 000**, more on older vCPUs. The HVF figure varied
  between boots (25.7 and 60.8 ms at 100 000 with the host busy). The kernel is about 3.5x slower per iteration than
  the host on the same CPU under HVF; why (hypervisor, the hardware SHA path's call overhead) is not investigated here.
  For scale: a TLS 1.3 + mTLS handshake is estimated at 130 us of the same core under HVF (`crypto-profile`), so even
  10 000 iterations cost about 20 handshakes.
- **The DoS reasoning.**
  - **600 000 does not fit the design.** About 300 ms per login on a VPS vCPU holds a data core for that long, for every
    client on it, per login; the admission would allow 1-2 logins a second per core, so a fleet of 1000 devices
    reconnecting after a restart takes minutes on three data cores; an allowed address that only sends wrong
    passwords (each costs a full check) keeps that small bucket empty with very little traffic. Under TCG a check
    passes the 1 s stuck-core limit and resets the VM. OWASP's figure is for a server whose hashing runs on a pool
    of threads beside the request path, not for a run-to-completion core.
  - **The admission's floor was a lever.** ADR-230 admitted at least 20 logins a second per core. Above 25 ms per
    check (100 000 on a VPS vCPU, 200 000, the existing maximum, under HVF) that floor overrode the half-core rule: at
    200 000 on a VPS (~100 ms) it admitted 2 s of hashing per second, i.e. a whole core, to anyone in `allow_from`. The
    floor is now 1: admitted checks use at most half of each data core at any cost
    (`urmqtt_plain::auth::login_rate`, tested).
  - **What the count buys.** It only matters after an image (and its hashes) is copied: a guess costs `iterations` HMAC
    pairs on a GPU, so 10x the count is 10x the time for a given password. It does not save a short or human-chosen
    password at any count the broker can afford, and on this listener the password crosses the network in the clear
    on every CONNECT anyway. The builder generates 20 characters of a-zA-Z0-9 (about 119 bits), for which any count is
    enough.
- **Decision.**
  1. **Default 100 000 iterations** (`urmqtt_cfg::passwd::DEFAULT_ITERATIONS`, `urmqtt-config hash-password`, the
     builder's `PASSWORD_ITERATIONS`; a builder test compares the two). 10x the guessing cost of 10 000, for about 25 ms
     of a core per login under HVF and an estimated 50 ms on a VPS vCPU: at the watchdog's 50 ms handshake floor and a
     tenth of its 500 ms cap, and 10 to 20 new password logins a second per data core (a 1000-device reconnect in about
     20 to 35 s on three data cores).
  2. **The range stays 1000 to 200 000.** 200 000 is about 100 ms on a VPS vCPU, a 5x margin to the 500 ms budget cap.
     `hash-password --iterations N` documents OWASP's 600 000 and why it is refused here.
  3. **No migration.** A hash carries its own count, so hashes made with 10 000 (or any count in range) verify as
     before, side by side with new ones; the decoy costs what the dearest account costs (tests
     `a_hash_made_with_the_old_default_still_verifies`, against a vector made by Python's `hashlib`, and
     `old_and_new_default_hashes_work_together`). Nothing in the blob format changes. To get the new cost, hash again.
  4. **Login admission floor 20 -> 1** (above), the rest of ADR-230 unchanged.
  5. **A boot warning** when a check costs more than the handshake budget (calibrated or configured): `plaintext: one
     password check costs N ms, more than the watchdog's handshake budget of M ms: the watchdog acts on every password
     login (watchdog.action); hash the passwords with fewer iterations` (seen with a 20 ms configured budget and a
     100 000-iteration account).
- **D-16, Argon2: not now.** Argon2id is the better function against GPUs, but here: (a) its memory must be reserved
  per data core, since a check runs on the core (OWASP's minimum is m = 19 MiB, t = 2; three data cores would hold
  57 MiB, a fifth of a 256 MiB heap on a 512 MiB VM, or an allocation an unauthenticated client can trigger); (b) its
  time is of the same order as PBKDF2 at 100 000, so the core-holding problem stays; (c) it brings a new crate (`argon2`
  and `blake2`) into the TCB, with vetting, RFC 9106 vectors, Miri, fuzzing and the browser build; (d) it protects
  against cracking the hash of a password that this listener sends in the clear. It stays possible later as a second
  scheme (`argon2id$...`) without a format change. **Revisit** when accounts become changeable at run time (NOW-15),
  when a check can be split across handler runs or moved off the data cores, or if users need person-chosen passwords.
- **Tests.** `urmqtt-cfg`: the old-default compatibility vector (skipped under Miri, like the other hashing tests).
  `urmqtt-plain`: `the_login_rate_keeps_half_the_core`, `old_and_new_default_hashes_work_together`. Builder:
  `password.test.mjs` (the page's count is the tool's), `plaintext-page.test.mjs` (the hashes in the TOML carry
  100000 and are the PBKDF2 of the password). The smoke `plaintext` group hashes at 3000 explicitly and is unaffected;
  `scripts/plain-bench.sh` now labels its login row with the count it used.
- **Not done.** The kernel on a real VPS (the estimate above stands in for it); the load generator's login rate at
  100 000 (expected about 19 a second per data core under HVF); the 3.5x gap between kernel and host per iteration.

## ADR-268 — SACK loss detection counts the flow's own segments, and three duplicate ACKs with new blocks start a recovery (NOW-13, PERF)

- **Status:** Accepted. Amends ADR-265 point 2. Parts 3 to 5 of ADR-265 (recovery, ACK on arrival, window
  validation) stay as they are: the evidence below points at loss detection only.
- **Context.** PERFORMANCE §13.2/13.3 point 4: on the netcup ARM64 VPS (one data core) `main` 318f60b was 10-30 %
  behind v0.4.2 on QoS 1 (16 pairs 14.1k against 17.5k delivered/s, 64 pairs 42k against 52k, 16 x 1000/s 8.8k
  against 13.0k), while on the 4-vCPU x86 VPS it was ahead. The raw `.console` files say why:
  * the netcup path loses segments in both builds (thousands of retransmissions per QoS 1 run; Contabo's runs
    have a few dozen), so loss recovery decides the rate there and not on Contabo;
  * v0.4.2 repaired them with fast retransmits (16 x 1000/s: 2,024 of 2,088 retransmissions fast), the SACK
    build mostly without (355 of 3,256; 16 pairs flood: 1,235-3,071 of 10,189-21,975). The counter "timeouts"
    in that line counts connections given up, not timer expiries, which hid the rest: they were retransmission
    timeouts, and the busiest-sender line (ADR-266) showed what follows a timeout: `cwnd 1-4 KiB, ssthresh
    2 KiB, rto 200-400 ms` (the floor of `on_timeout`, the doubled RTO);
  * the CPU was not the limit (data core 40-46 % busy in those runs), and the NIC's transmit drops were 732 in
    the whole QoS 1 part of the suite: neither the per-segment ACK work nor the transmit ring.
  The cause is ADR-265's `IsLost`: "more than two segments SACKed above the hole" was counted as `> 2 * MSS`
  bytes. An MQTT flow sends segments of 60-300 bytes (a PUBLISH or a PUBACK in its TLS record) and holds a few
  of them in flight (QoS 1: the peer's receive maximum, the publisher waiting for its PUBACKs); 2 x 1448 bytes
  above a hole were some 25 such segments, which the flow seldom had, so the hole waited for the retransmission
  timer (200 ms after an RTT sample, doubling) and the window restarted from one segment. And because a SACK
  peer's duplicate ACKs no longer counted once it reported blocks, NewReno's three duplicate ACKs, which v0.4.2
  acted on, were gone too.
- **Decision.**
  1. **A segment is the flow's own.** The sender keeps a running average (weight 1/4) of the length of the data
     segments the application decided (full ones and those that sent all that was queued; a segment the window
     cut short says nothing about the flow) in its boxed `Sender` (`seg`, 2 bytes; `Conn` unchanged at 112
     bytes). `IsLost` counts "more than two segments" in that size, at most the MSS: three 120-byte segments
     above a hole make it lost, two do not. A bulk transfer's segments are full, so nothing changes for it.
  2. **DupThresh duplicate ACKs** (RFC 6675 §5, "DupAcks >= DupThresh"): a duplicate ACK from a SACK peer counts
     when its blocks report new data (RFC 6675 §2: one per segment that arrived above the hole); three of them
     with a hole at `snd_una` start the recovery as `IsLost` does, after the same reordering window. A duplicate
     ACK without blocks from a peer that reports blocks still does not count (ADR-265).
  3. The SACK recovery resends a hole while the pipe leaves room for one of the flow's segments (not a full MSS:
     a window cut to a few small segments still repairs them).
  4. A new counter, retransmission timer expiries (`Stats::rto_fired`), and a per-core log line every 5 s with
     retransmissions: `tcp: core N: retransmissions: R recoveries started, T by the timer, S segment(s) resent in
     recoveries`, so the next run on a VPS shows the split. (A first attempt put the count into the existing line;
     that line is near the console's record width and its end, `0 connection(s)`, which the `attack-*` smoke
     scenarios look for, was cut off.)
- **The 1 s handshake tail** (netcup, the SACK build only: `tcp connect` p99 1.02-1.05 s in all nine runs,
  v0.4.2 0.06-0.19 s) is not a retransmission timeout of ours: it is in the TCP connect time, i.e. the client
  sent its SYN again after Linux's 1 s, and the console shows 1.5-3 % of SYN-ACKs (cookies sent minus cookies
  validated) never answered against 0.1-0.2 % with v0.4.2. The SYN-ACK path is the same code in both builds.
  On the rig the handshake run shows no such tail for either build (TCP connect p99 20-22 ms without
  added loss; 1.04 s for all three builds at 1 % loss, where SYNs and SYN-ACKs are lost at random), so it is not
  reproduced and stays open: a capture on the VPS (`scripts/x11-capture.sh`) of the SYN-ACKs that go unanswered
  is the next step. Nothing in this change touches the SYN path.
- **Security properties.** No parser change (the SACK blocks come from the same `wire.rs` code). The segment size
  is our own sending history; a peer can only influence it by its window, and window-cut segments are not
  counted. A peer that lies in its blocks could already make holes count as lost (ADR-265); it now needs three
  small segments' worth of claims instead of three full ones, and what it gets is the same: our own data sent
  again, at most once per hole, inside `cwnd` and its own window.
- **Verification.** `cargo test -p urmqtt-tcp` (84 tests, 5 new). New: `small_segments_count_in_their_own_size`
  (board), `a_lost_small_segment_is_resent_after_three_segments_above_it`,
  `two_small_segments_above_a_hole_are_not_a_loss`, `two_small_holes_are_both_repaired_without_a_timeout`, and
  a model of a QoS 1 stream (`a_stream_of_small_messages_recovers_without_the_timer`: 120-byte messages, at most
  16 unacknowledged, 0.5-2 % loss). Against ADR-265's rule the first and third fail (no retransmission at all
  before the timer) and in the model every loss was a timeout (21 of 21 retransmissions, 6.4 s for what takes
  2.2 s now). ADR-265's tests pass unchanged; the lossy reordering bulk transfer showed why window-cut segments
  must not count (with them, 7 needless retransmissions under 4 ms of jitter).
  `tcp_segment` fuzzed 120 s on the M-series Mac (2.4 million runs, no finding). Smoke (`SMOKE_ONLY=misc`,
  groups `storm`, `fin_wait2`, `attack_raw`, `net_mtu`, `attack_app`) on aarch64 HVF and x86_64 TCG: 10 of 10
  each; the aarch64 core group (`SMOKE_NO_GROUPS=1`, MQTT end to end) 52 of 52.
- **Numbers (local rig).** Local WAN rig (PERFORMANCE 7.3: aarch64 HVF on the M-series Mac, `urmqtt-loadgen`
  in a Linux container behind `wan-bridge`, 12 ms RTT), `--smp 2` (boot log `dataplane: 1 data core(s)`, as on
  netcup) and `--smp 4` (3 data cores); v0.4.2 (tag), `main` cfe9fa1 (= 318f60b's code) and this change; 3 runs per
  cell, median (min-max) of delivered messages/s; "fast" counts recoveries started, of all retransmissions. The
  rig's own loss is about 0.3 % (bursts); "1 %" adds 1 % per direction at random, about what the netcup path loses.
  Raw: `docs/perf-results/adr268-rig.txt`.

  | one data core, 1 % loss | v0.4.2 | main | ADR-268 |
  |---|---|---|---|
  | 16 pairs, QoS 1, flood | 12.2k (12.2-12.3k) | 10.0k (9.9-10.2k) | **12.5k** (9.7-12.8k) |
  | 64 pairs, QoS 1, flood (main and ADR-268: 6 runs, 2 boots each, alternating) | 47.7k (47.6-48.6k) | 42.2k (40.3-42.8k) | **49.8k** (48.3-51.1k) |
  | 16 x 1000/s, QoS 1 | 13.0k (13.0-13.7k) | 9.0k (9.0-9.3k) | **13.4k** (12.3-13.7k) |
  | 16 x 1000/s: fast / all retransmissions | 1,021 / 1,225 | 3 / 591 | 1,015 / 1,270 |
  | handshakes/s, 128 threads (TCP connect p99) | 1,248 (1.04 s) | 1,218 (1.04 s) | 1,232 (1.04 s) |

  | one data core, no added loss | v0.4.2 | main | ADR-268 |
  |---|---|---|---|
  | 16 pairs, QoS 1, flood | 15.3k (15.3-15.5k) | 14.0k (13.9-14.1k) | **15.3k** (14.8-15.6k) |
  | 64 pairs, QoS 1, flood (main and ADR-268: 6 runs, 2 boots each, alternating; the core is saturated and the rig's noise is large) | 38.1k (34.8-40.9k) | 36.7k (29.7-43.2k) | 36.6k (32.9-48.2k) |
  | 16 x 1000/s, QoS 1 | 16.0k | 16.0k | 16.0k |
  | handshakes/s, 128 threads (TCP connect p99; main and ADR-268 alternating, 6 runs each) | 2,009 (22 ms) | 1,921 (22 ms) | 1,917 (22 ms) |

  | three data cores (`--smp 4`) | main, no added loss | ADR-268 | main, 1 % loss | ADR-268 |
  |---|---|---|---|---|
  | 16 pairs, QoS 1, flood | 16.1k (15.5-16.3k) | 16.4k (16.4-16.5k) | 10.2k (10.2-10.5k) | **12.8k** (12.7-12.8k) |
  | 64 pairs, QoS 1, flood | 40.6k (39.7-41.1k) | **43.7k** (42.4-44.9k) | 37.6k (37.4-39.3k) | **46.2k** (44.9-46.8k) |
  | 16 x 1000/s, QoS 1 | 16.0k | 16.0k | 9.3k (8.9-9.8k) | **13.6k** (13.5-13.7k) |
  | handshakes/s, 128 threads | 1,815 | 1,809 | 1,214 | 1,191 |

  With one data core and netcup's loss the rig shows the regression as the VPS did (16 x 1000/s: 9.0k against
  13.0k there, 8.8k against 13.0k on netcup) and this change removes it; on three cores it adds 0-8 % without loss
  and 23-46 % at 1 % loss, so the x86 VPS's gain is kept. The rig was shared with five other agents' builds and
  QEMU runs (timing-sensitive runs took a lock, builds did not): single boots vary, which is why the 64-pair cells
  were measured again alternating the two kernels.
- **Not verified.** The netcup VPS itself (the rig's loss is QEMU's and the bridge's, not netcup's host); the
  handshake tail there.

## ADR-269 — Publisher back-pressure: a QoS 0 message with one full subscriber pauses its publisher's TCP stream instead of being dropped (NOW-13, `limits.publisher_backpressure`, configuration format 8)

- **Status:** Accepted. Amends ADR-223 (QoS 0 to a full output buffer is dropped and counted: still the rule for
  fan-out, and the fallback), ADR-032/M13 (cross-shard routing carries the publisher; two new mesh messages), ADR-033 (the TCP stack's
  receive space, now closed and reopened by the application). Number reserved for this branch; ADR-268 and ADR-270 are
  parallel branches, format 8 is this branch's (9 to 12 are reserved for others).
- **Context.** PERFORMANCE §13: with one publisher and one subscriber flooding QoS 0, urMQTT accepted from the
  publisher as fast as its core allowed (150-195k msg/s on netcup's one ARM data core) while the subscriber's single
  TCP stream carried 12-22k/s; the rest was dropped (`messages/dropped/slow_subscriber`, hundreds of millions in the
  suite), and the publisher's input took the CPU the subscriber's output needed (1 KiB: 0.1-3k delivered/s).
  Mosquitto, single-threaded, in effect stops reading the publisher and delivers almost all it accepts (49k/s, 6.1k at
  1 KiB, on the same core). Both are legal for QoS 0. For a single consumer, not reading is better on both counts:
  nothing accepted is lost, and no cycles go into reading what will be dropped.
- **Decision.**
  1. **The signal and where it is evaluated.** The broker shard that owns the publisher's session decides, right
     after routing each PUBLISH (`Broker::after_publish`, `crates/broker/src/flow.rs`). It pauses the publisher when:
     the message went to exactly one session on this shard, at QoS 0 as delivered; that session's connection is not
     the publisher, not closing, and its own input is not held; its output buffer (`Conn::outbuf`, the bytes not yet
     taken by TLS/TCP) is at or above the **high-water mark, half of `max_outbound_bytes`** (16 KiB of the kernel's
     32 KiB); the publisher is not in cool-down; and, with several shards, no other shard has reported delivering
     this publisher's messages in the last second. The pause ends when that output buffer is at or below the
     **low-water mark, a quarter** (8 KiB), when the recipient is gone or closing, or after **500 ms**. Rejected
     signals: the relay credit (only exists for relayed connections, and measures the core-to-core hop, not the
     subscriber's TCP); the existing `dropped_backpressure` path (by the time it fires a message is already lost, and
     its rate says nothing about when to resume); the TCP send queue of the subscriber (on another core when relayed;
     the broker's buffer is the last stage and fills only once TLS and TCP are full, so it is the same signal, later
     and local).
  2. **Several shards.** Every routed message is offered to every other shard (`Config::fanout`), so the origin
     cannot see the whole recipient set by itself. Routes now carry the publishing connection
     (`CoreMsg::Route::origin`); a shard that delivers one to n >= 1 sessions tells the origin
     (`CoreMsg::Seen { conn, n }`, at most every 250 ms per publisher). The origin keeps, per publisher, which
     shards reported and how many sessions, for a second (`REMOTE_SEEN_MS`), and decides:
     - **subscriber here:** the single local recipient is full and no other shard reported in the last second;
     - **subscriber on shard B:** B, which owns that subscriber, finds the message went to exactly one session of its
       own, at QoS 0, whose input is not held and whose output is over the high-water mark; it records the wait and
       sends `CoreMsg::Hold { full: true }` to the origin. The origin pauses only if the publisher's last message had
       no recipient on the origin itself and no shard but B (and B with n = 1 only) reported in the last second. B
       sends `Hold { full: false }` when that subscriber is at or below the low-water mark, gone, closing, or after
       500 ms, so a lost or late message cannot hold the publisher longer than the origin's own bound.
     - **a learning second:** with several shards a publisher is not paused during the second after its first full
       recipient unless the other shards have already reported about it: the reports need a route and a message back,
       and a publisher with a remote consumer must not be paused for a local one before the first report arrives.
     The error goes one way: when in doubt (a report lost, a shard behind), the publisher is read and dropped for, as
     before. Messages the origin accepted while the request travelled (one message each way on the mesh, plus the
     routes already queued) are taken by B's subscriber beyond its 32 KiB buffer, up to **256 KiB more**
     (`OVERSHOOT`; 4 MiB per shard in all), instead of being dropped; beyond that they are dropped as before. Without
     this the first measurement on three data cores still dropped a quarter of a single flow: the pauses came, but
     a 16 KiB margin between the high-water mark and the drop is less than one 32 KiB slice of held input. A relayed publisher's window is on its
     transport core: the home shard sends `CoreMsg::Flow`. A late `Seen` or `Hold` naming a connection id that was
     reused can at worst keep a new publisher from pausing for a second, or pause it for at most 500 ms.
  3. **What is paused, and the head-of-line bound.** Parsing stops after the PUBLISH that caused it; the bytes that
     follow are held unparsed in the connection's input buffer, in order, and the TCP receive window is closed. So
     PINGREQ, DISCONNECT, PUBACK (for QoS 1 the broker sent to it), SUBSCRIBE and the next PUBLISH all wait, at most
     500 ms. A CONNECT is never behind a pause (only a PUBLISH starts one, after CONNACK). When the pause ends the held
     bytes are parsed in 32 KiB slices per loop pass (`DRAIN_SLICE`; one pass per slice keeps the watchdog's per-handler
     budget), and the window opens only when no complete packet is left in them; a slice can pause it again (the
     hysteresis between the marks). **Keep-alive** counts a paused connection as alive: `tick` skips it and the end of
     the hold sets its last-receive time (a PINGREQ held behind the pause is answered then).
  4. **No deadlock.** (a) A publisher is never paused for itself, nor for a recipient whose own input is held. No
     cycle of pauses can exist: take the edge of a cycle created last, P paused for R; R is on the cycle, so it has its
     own edge R -> S, created before and still there, so R was held when P -> R was created, which the rule forbids
     (tests: `two_publishers_for_each_other_never_both_pause` in both orders, `a_cycle_of_three_cannot_close`). (b)
     Waits outside the broker (a client that stops reading while its own write blocks, a subscriber that waits for
     something only the paused publisher will send) are cut by the time bound: after 500 ms the publisher is read again
     and is in **cool-down for 2 s** (read, its QoS 0 dropped as before), so a stuck subscriber costs its publisher at
     most a 500 ms stall per 2.5 s and never more than today's drops (`the_pause_is_bounded_and_counts_as_alive`).
     (c) Bounded memory: the window closes at the pause, so what arrives is what was already promised (at most
     the 1 MiB scaled window); a connection holding more than 2 MiB plus a packet (a transport that does not close a
     window) is released into cool-down; no new pause starts while a shard holds 16 MiB
     (`held_input_is_bounded_without_a_window`).
  5. **QoS 1 and QoS 2 are not paused for.** Only a delivery at QoS 0 (the publish's QoS and the subscription's, the
     lower) can pause. QoS 2 (ADR-271) shares the in-flight window with QoS 1 and is left to it the same way. A
     paused publisher's own QoS 2 control packets (its PUBREL for a message it published, its PUBREC or PUBCOMP for one
     it was sent) wait in the held bytes like PINGREQ, at most 500 ms, and complete after the pause
     (`qos2_flows_of_a_paused_publisher_complete_after_the_pause`, `qos2_deliveries_are_not_paused_for`). A QoS 2
     publish to a QoS 0 subscription is a QoS 0 delivery and can pause its publisher, whose PUBREC then comes when
     the PUBLISH is parsed. A QoS 1 delivery already waits in the session's in-flight window (`limits.max_inflight_qos1`) and queue,
     and the publisher's own window waits for our PUBACKs, which go out as each PUBLISH is parsed; adding a pause would
     throttle twice (`qos1_deliveries_are_not_paused_for`). A QoS 1 publish to a QoS 0 subscription is a QoS 0
     delivery and can pause its publisher: its PUBACKs then come later, which is the back-pressure it should feel.
  6. **WebSocket publishers (ADR-272).** A WebSocket connection is a TCP connection whose TLS plaintext goes through
     the frame decoder (`crates/kernel/src/mqtt_service/ws.rs`) before the broker sees MQTT bytes. The pause closes
     that TCP connection's window like any other, so the client stops sending frames; what was promised still arrives
     and is decoded. The broker holds **decoded MQTT bytes**, not raw frames: the decoder has no reassembly buffer and
     unmasks in place, so holding raw frames would mean a second buffer and a second decoder state per connection,
     while decoded bytes are what the broker's parser and its bounds already work on (frame headers only make the
     held amount smaller than the window). The frame layer keeps answering PING with PONG and a CLOSE ends the
     session while the MQTT input is held, so a browser's WebSocket keep-alive is unaffected. A login connection (the
     CONNECT not yet decided) is never paused: only a PUBLISH after CONNACK starts a pause.
  7. **Fan-out keeps dropping.** Two or more recipients (on this shard, or any on another) never pause: one slow
     subscriber must not slow the others (`fan_out_keeps_dropping`).
  8. **TCP.** `TcpStack::set_recv_space(c, 0)` on pause; the advertised right edge is never moved left (RFC 9293
     §3.8.6.2.1), so the window shrinks as the promised bytes arrive and reads 0 after them; a segment beyond it is
     not taken and is answered with the current window, and the peer's persist timer probes. On resume the new
     `TcpStack::reset_recv_space(c)` gives back the space the handshake gave (the 1 MiB scaled window, or 65 535)
     in one window update: the window is all or nothing, so no small openings are announced (receiver-side
     silly-window avoidance, RFC 1122 §4.2.3.3). A lost update is recovered by the peer's probe. Script test
     `the_application_closes_and_reopens_the_window`; the H3 model tests and the other scripts are unchanged.
  9. **Configuration.** `limits.publisher_backpressure = "single" | "off"`, tag 53 (the free tag after the other
     `limits.*` keys), **default `"single"`**, justified by the measurements below. "single" writes no record, so a
     configuration that keeps the default stays readable by every older kernel; "off" needs **format 8**: an older
     kernel would refuse the unknown tag at boot, and the version moves that refusal to build time (the template check
     of `urmqtt-config` and the builder page, as for ADR-256/257/264). The TOML form, the packer, the builder (choice
     hints in the 15 site languages, AI translations, unreviewed) and the schema follow the field table.
  10. **Observability.** `$SYS/broker/messages/backpressure/mode`, `paused` (pauses started), `paused_ms` (time
     paused, ended pauses), `timeouts` (pauses that ran out), `holding` (publishers held now), the same under
     `"backpressure"` in the info reply, a `status` line, the boot line `mqtt: publisher back-pressure single|off`,
     and at most every 10 s per core `mqtt: core N paused P publisher(s) for a full single subscriber since the last
     report, M ms in all, K ran out`.
- **Measurements** (local rig only, PERFORMANCE §13.5, raw files in `perf-results/backpressure-2026-11-08/`; "off"
  is the same kernel with the policy off, i.e. the behaviour before). One data core (`--smp 2`, like netcup): one
  64 B flow delivered 119-165k/s with "single" against 130-157k with "off", 1 KiB 9.2-12.1k against 8.9-11.4k; with
  "single" published equals delivered and nothing is dropped (off: 3-21k dropped per 10 s run). Three data cores
  (`--smp 4`): 143-146k against 113-134k (64 B), 9.3-12.1k against 7.6-8.2k (1 KiB), 0 dropped against 160-500k per
  run. 16 pairs, QoS 1, the 16 x 1000/s latency sweep and fan-out 1 -> 100 / 1 -> 1000 are within the run-to-run
  range (fan-out is never paused). A flooded single flow's latency rises (messages wait in the publisher's socket
  instead of being dropped). **The default is "single"**: fan-out, many pairs, QoS 1 and steady rates did not move beyond
  the rig's noise, and one flow no longer loses what it accepted. The one cost measured is on the target case itself:
  a 64 B flood on one fast core delivers about 10 % less after ADR-268 (below). "off" stays for a deployment that
  prefers the most messages per second, or the newest message, over every message (the behaviour of v0.4.x); the
  default is to be confirmed or reversed by the netcup measurement.
- **Verification.** Broker: 19 scripted tests (`crates/broker/src/flow_tests.rs`: two and three connections on one
  shard, and two shards wired as the kernel wires them: pause and resume across shards, refusals with a local or a
  third-shard consumer, a leaving subscriber, the overshoot bound, publishers on two shards for each other), the
  `$SYS` topic list, JSON and status line; the `broker_input` fuzz target runs with "single", `poll_flow`,
  `drain_flow` and remote notes; the ACL oracle (`acl_invariants`, `broker_acl`) and `acl_model` run with "single"
  and `poll_flow` and stay green. TCP: the window script. Configuration: format 8 and the checks (`urmqtt-cfg`,
  `urmqtt-config`, `urmqtt-config-schema`, `tools/config`, the builder module). Parsing now decodes a held buffer in
  place and consumes it once, instead of moving the rest of the buffer after every packet (a held megabyte of 64-byte
  packets would have cost gigabytes of copying). The fuzz targets `broker_input` (now also cross-shard notes,
  requests and routes fed back with their publisher), `plain_input` and `broker_acl` ran 60 s each without a finding.
  Miri runs the flow tests except the two that hold megabytes on purpose (skip list in `scripts/miri.sh`). Smoke:
  `mqtt-plain`, `mqtt-tls` and `sys-operator` (which now checks `messages/backpressure/mode` and `paused` and the
  info reply's `backpressure`) pass on aarch64 (HVF) and x86_64 (TCG).
- **Rejected.** Pausing for "all recipients full" (fan-out where every subscriber is slow): it would make the policy
  depend on the slowest of many consumers; fan-out keeps dropping. A per-topic global subscriber count shared by the
  shards: a structure every SUBSCRIBE would have to update on every core, for a decision the shards can make from the
  routes they already exchange. Closing the window without holding input in the broker (stop the TCP stack from
  delivering): the stack has no receive buffer (data is consumed as it arrives, ADR-033), and the bytes already
  promised must go somewhere.
- **After the rebase onto ADR-268, ADR-271 and ADR-272** (configuration formats: 8 is this ADR's, 9 the WebSocket
  section's; 10 was allocated to QoS 2 and is unused, 11 to the receive-interrupt branch, 12 to MQTT 5, so 10 and 11
  stay unknown to this tree). The rig numbers above ran without ADR-268's change of the TCP sender's loss detection;
  one flow was measured again after the rebase (PERFORMANCE §13.5): 0 dropped with "single" as before; 1 KiB the same
  as "off" (9.9-10.4k against 9.8-10.6k delivered); 64 B 116-145k against 144-151k, about 10 % less on this fast
  core, where "off" loses only 5-15 % of the flood. That is the price of the pacing when the subscriber almost keeps
  up; where it does not (netcup's §13.2: 85-90 % dropped) the measurement is still to be made, and "off" restores
  the old behaviour.
- **Not verified.** The real VPS pair: the numbers above are the local rig's, where one data core is a vCPU of an
  Apple-silicon Mac under HVF behind a container bridge, not netcup's Neoverse N1; the expected effect on §13.2's
  single-flow rows has to be measured there (same suite, `limits.publisher_backpressure` "single" against "off").
  The cross-shard path is measured only on the rig's three data cores (point 2). A relayed publisher (transport core
  other than its home shard, `CoreMsg::Flow`) is exercised by the `--smp 4` runs whenever the RSS hash and the
  identity hash disagree, but no test isolates it.

## ADR-270 — virtio-net's receive interrupt wakes the dispatcher; ADR-224's polling is the fallback (NOW-13, PERF)

- **Status:** Accepted. Amends ADR-032 ("Core 0 has no RX interrupt") and ADR-224 (the 200 us poll is now the
  fallback only). Configuration format 11 (8 is ADR-269's, 9 ADR-272's, 10 is unused, 12 is reserved for MQTT 5).
- **Context.** Core 0 owns the NIC. It spins 100 us after its last piece of work and then sleeps in `wfi`/`hlt`;
  since ADR-224 it programs the deadline timer at most 200 us ahead while connections exist, because nothing else
  wakes it for a received frame. That costs up to 200 us of receive latency when idle, about 5 000 wake-ups a second
  with idle connections (host CPU and power), and on a one-data-core machine the polling competes with the work.
  Without connections it slept until the 10 ms tick, so even the first SYN of an idle broker waited for it.
- **What the platforms allow.**
  - x86_64: MSI-X to the boot CPU's local APIC (physical destination, fixed delivery, edge), as the boot disk already
    used (X4): always available with a virtio-net that has MSI-X.
  - aarch64, GICv2m frame: QEMU under HVF (GICv3 without an ITS) and every GICv2 guest (the Raspberry Pi path,
    ADR-039) have one; an MSI is a write of the SPI number to the frame, the SPI is routed to core 0.
  - aarch64, GICv3 ITS: QEMU under TCG and KVM's in-kernel vITS (the netcup ARM VPS: QEMU `virt` with
    pcie-root-ports, its NIC at 07:00.0) have only an ITS. Until now no MSI at all there. New: a minimal ITS driver
    (`crates/arch-aarch64/src/its.rs`), used **for the NIC only**.
  - Neither (an aarch64 platform with no v2m frame and no usable ITS, a NIC without MSI-X): polling as before.
- **Decision.**
  1. **Vector.** At probe the NIC's MSI-X vector 0 gets a GICv2m SPI, an x86 vector or (no v2m frame, an ITS) an
     LPI, with the handler `on_net_irq` (a counter, nothing else; the interrupt itself ended the `wfi`/`hlt`). Only
     the receive queue signals it (`VirtioNet::new_with_msix`; a device that refuses the vector gets a polled queue:
     the queue is set up again before it is enabled). The transmit queue never asks for one: its descriptors are
     reclaimed lazily and a dispatcher with frames waiting for descriptors does not sleep (`moved |= !nic_q.is_empty()`,
     ADR-223). The SPI is routed to core 0 when the dispatcher starts; LPIs go to collection 0, the boot CPU.
  2. **Suppression protocol (virtio 1.x §2.7.7, §2.7.10, without `VIRTIO_F_EVENT_IDX`).** Both queues start with
     `VIRTQ_AVAIL_F_NO_INTERRUPT` set. The dispatcher clears it only on its way to sleep (`SplitQueue::enable_interrupts`:
     flag store, full fence, used-index load) and sets it again as soon as it is awake (`suppress_interrupts`). Either
     the re-check sees the frame (then it does not sleep), or the device, which stores its used index before it reads
     the flag, sees the flag clear and interrupts. While the dispatcher works the flag is set, so a flood is polled and
     costs no interrupts (measured below); the flag is a hint the device may ignore, so a stray interrupt costs one
     counter increment and an EOI.
  3. **No lost wake-up in the CPU either.** `Idle::pass_armed` (and `pass`, for every core) now masks the CPU's
     interrupts from the sleep announcement to the wait: an interrupt that fires after the last check (the NIC's, or a
     wake SGI from a worker, which had the same window since ADR-032) stays pending and ends the `wfi` (AArch64 wakes on
     a pending IRQ whatever PSTATE.I says) or is taken inside `sti; hlt` (x86), instead of being consumed by its
     handler just before the core sleeps until the next tick.
  4. **Mode machine (`urmqtt_virtio::wake::RxWake`, pure).** `Interrupt`: while the NIC moved a frame in the last
     **2 ms** (`HOLD_NS`) and connections exist, the dispatcher polls exactly as ADR-224 did (200 us deadline, interrupt
     not armed); once the NIC has been quiet for 2 ms, or without connections, it arms the interrupt and sleeps with no
     deadline at all. `Polling(why)`: ADR-224's 200 us while connections exist. The hold is measured, not a guess: the
     first version armed the interrupt at every idle gap, and on the rig with one data core a steady stream then woke
     the dispatcher by an MSI once per gap, which cost a fifth of the QoS 0 flood rate and raised the 99th percentile at
     16 000 messages/s (Evidence). A hypervisor that accepts the vector and
     never delivers it would leave the dispatcher on the 10 ms tick: after **8 sleeps in a row** that ended with a
     received frame waiting and the interrupt counter unchanged since the queue was armed, the mode falls back to
     polling for good with a warning (`net: receive wake-up: 8 frames waited after a sleep without the receive
     interrupt; polling every 200 us ...`). One such sleep is possible with a working interrupt (a frame landing between
     the counter read and the ring read); eight in a row are not.
  5. **Timers are untouched.** The interrupt only replaces the 200 us deadline; the 10 ms tick keeps running on every
     core in both modes, so everything driven by time rather than by a frame (TCP retransmission and delayed ACKs,
     keep-alives, ADR-269's 500 ms limit on a paused publisher, ADR-272's WebSocket upgrade timeout) is served within
     one tick of its deadline, as it always was on a core without connections. A back-pressure resume is driven
     by frames (the subscriber's ACKs: the receive interrupt) or by another shard's `CoreMsg::Hold` (the wake SGI,
     which the masked wait no longer loses).
  6. **Configuration.** `[devices] virtio_net_interrupt = "auto" | "off"` (tag 211, format 11). `"auto"`, the default,
     writes nothing, so a configuration that does not set it keeps its format and boots on an older kernel; `"off"`
     forces polling (a hypervisor whose interrupt misbehaves) and needs format 11.
  7. **Boot line**, next to `net: virtio-net with N receive ...`: `net: receive wake-up: interrupt (MSI-X via GICv2m SPI
     80 | GICv3 ITS LPI 8192 | local APIC vector 65, to core 0); polling only within 2 ms of NIC traffic`, or `net: receive wake-up:
     polling every 200 us while connections exist (<reason>)` with the reason (`devices.virtio_net_interrupt = "off"`,
     the device has no MSI-X, no MSI target, the ITS could not be set up, no free vector, the device refused it). The
     dispatcher's 5 s statistics line counts `receive interrupt(s)`.
- **The ITS driver.** On first use (the NIC, on a GICv3 with an ITS and no v2m frame): the boot CPU's redistributor
  gets an LPI configuration table (8 KiB, LPIs 8192..16383) and a zeroed pending table (64 KiB aligned) and its LPIs
  are enabled; the ITS, quiescent, gets a flat device table sized for the highest requester ID the PCI scan saw (4 KiB
  pages first; an ITS with a fixed page size reads back its own and the table is sized again), a one-page collection
  table, a one-page command queue, then `MAPC` (collection 0 to the boot CPU, by processor number or by address as
  `GITS_TYPER.PTA` says) and `SYNC`. Per device `MAPD` (an ITT for two events), `MAPTI` (event 0 to the next LPI),
  `INV`, `SYNC`; the message is `GITS_TRANSLATER` with data 0. Tables are declared inner shareable write-back; where
  the ITS or redistributor reads back non-shareable, the configuration byte, the ITT and every command are cleaned to
  the point of coherency. Every register wait is bounded; a stalled command fails the setup and the NIC is polled.
  The **device ID is assumed to be the PCI requester ID** (QEMU `virt`'s `msi-map` and IORT are the identity); a
  platform that maps it otherwise gets no interrupt, and point 4 falls back. That is why the boot disk does not use
  the ITS: its self-test requires its completion interrupts and would fail the boot instead of falling back. The
  kernel's handler table gained 16 LPI slots; the GIC's `Ack` no longer takes INTIDs from 8192 for "nothing pending".
  9 new `unsafe` sites (register accessors, cache clean, command and configuration writes, the kernel's `init` call),
  all justified (docs/audit/unsafe.md).
- **Evidence.** Local rig (PERFORMANCE 7.3, RTT 4 ms configured, aarch64 HVF, the bench image with the default
  configuration against the same image with `"off"`, two rounds per cell, `docs/perf-results/now13b-rx-irq-rig.txt`):
  host CPU of the QEMU process with 100 idle mTLS connections **2.9 % against 28-29 %** of one host CPU on 2 vCPU and
  **4.8-5.0 % against 31 %** on 4 vCPU (without connections both 2.6-5.1 %); ping without any MQTT connection 7.8-8.7 ms
  mean against 12.7-14.8 ms (the 10 ms tick is gone); with one idle connection (ADR-224's method) 7.8-9.1 ms against
  8.1-8.6 ms, unchanged; 16 x 1000 msg/s QoS 0 p50 6.0-6.2 ms and p99 11.4-12.2 ms against 6.1-6.2 and 11.0-12.3 ms;
  16-pair QoS 0 flood 341k/346k against 338k/297k delivered/s on 2 vCPU, 306k/335k against 342k/345k on 4 vCPU (the
  flood's spread between runs is that wide in both modes); 150-730 receive interrupts per 5 s window under the flood (no
  storm). The first version without the hold (`now13b-rx-irq-rig-v1.txt`): the same idle gains, but on 2 vCPU the flood
  delivered 261k/263k/s against 325k/340k/s and the p99 at 16 x 1000/s was 20-21 ms against 12-14 ms, with 1 000 to
  2 000 receive interrupts a second; on 4 vCPU no difference. Again after the rebase onto ADR-268/269 (`now13b-rx-irq-rig-v3.txt`):
  100 idle connections 2.8-2.9 % against 29 % (2 vCPU) and 5.4-5.5 % against 32-35 % (4 vCPU); one 64 B flow
  240k-249k against 231k-249k delivered/s, one 1 KiB flow 17.7k-18.9k against 18.1k-19.9k, 16 x 1000/s p99
  10.6-11.3 ms against 10.3-11.5 ms, the 16-pair flood 343k-353k against 346k-355k.
- **Verification.** Host tests: the suppression and re-check protocol against the queue's toy device
  (`interrupt_suppression_and_recheck`, `interrupt_flag_leaves_the_ring_alone`), the mode machine (a working
  interrupt keeps the mode over 10 000 sleeps, occasional races do not fall back, a silent one falls back exactly once
  after 8, polling with and without connections), the ITS's `GITS_TYPER` decoding, table sizing (netcup's 07:00.0),
  register values and the five command encodings against the architecture specification, format 11 and the key in
  `urmqtt-cfg`, `urmqtt-config`, `urmqtt-config-schema`, `urmqtt-config` (tool) and the builder module. Smoke group
  `net_irq` (`SMOKE_ONLY=misc`): the serving image with the default configuration says it uses the interrupt (aarch64
  HVF: GICv2m SPI; aarch64 TCG: GICv3 ITS LPI, with the ITS line; x86_64 TCG: local APIC vector), carries three QoS 1
  round trips over mutual TLS and its statistics count receive interrupts; the same with `virtio_net_interrupt =
  "off"` says polling with that reason, carries the traffic and counts none. The `gicv2` group's TLS run now also
  asserts the interrupt line (GICv2m SPI). The full MQTT scenario script passed by hand over the ITS (TCG) and the
  local APIC (x86_64 TCG).
- **Not verified / limits.** No real KVM host: the netcup ARM VPS (KVM vITS, NIC behind a root port at bus 7) and the
  Contabo x86 VPS are the targets, and only a boot there shows whether the vITS maps the requester ID as QEMU does
  and how the hypervisor's interrupt delivery and halt polling change latency and steal. HVF does not offer an ITS,
  so the ITS ran under TCG only. `VIRTIO_F_EVENT_IDX` is not negotiated (the flag is only a hint; with event indices
  the device could not interrupt at all while suppressed). The ITS serves one CPU (collection 0), one event per
  device, LPIs 8192..16383, flat tables only (a device table needing more than 256 pages fails the setup), no
  `msi-map`/IORT parsing.
- **Amendment (after the merge, the CI failure of `attack-app [tcg]`).** CI's aarch64 misc job (Ubuntu 24.04,
  QEMU 8.2.2, TCG, the GICv3 ITS) failed `attack-app` twice after this ADR merged: the admission line ("too many
  handshakes in flight") was missing. Reproduced in Docker with Ubuntu's QEMU 8.2.2 (scripts and raw numbers in
  `docs/perf-results/rx-irq-fix-qemu82/`), and the cause is **not** a lost or late receive interrupt:
  - Interrupt delivery works on QEMU 8.2.2: 0 of 39 050 armed sleeps in six attack runs ended with a frame waiting
    and no interrupt (a new statistic, below); a TCP echo round trip with 50 ms gaps 0.89-0.99 ms median with the interrupt against
    0.74-0.85 ms polled and 0.84 ms on the kernel before this ADR; sequential mutual-TLS handshakes 2.4-2.6 ms median
    against 3.4-3.7 ms polled.
  - The scenario's slowloris stages opened their 200 connections **one after the other**, and QEMU's user network
    under TCG accepted a waiting forwarded connection only when QEMU's main loop ran: the guest saw the SYNs in
    batches of two or three about once a second (pcap), so a 200-connection stage took 45-57 s polled and 55-69 s with
    the interrupt. Under TCG the guest's timer is a QEMU timer served by that main loop, so the 200 us deadline of
    ADR-224 woke it 5 000 times a second; without it (the interrupt) the accept pace fell by about a fifth. A kernel
    with the interrupt **and** the 200 us deadline (a test build) was as fast as polling (51 s, 12 and 9 refusals).
    The assertion needs more than 32 handshakes in flight from one address on a core within the 10 s handshake
    timeout; at one accepted connection every 225-345 ms it was marginal in every mode: at least one refusal in 3
    of 3 runs of the kernel before this ADR, 5 of 6 polled, 4 of 7 with the interrupt (CI: 0 of 2).
  - **Fix of the test, not a weaker one:** `urmqtt-attack slowloris` opens its TCP and TLS stage connections from
    32 threads at once, as a real slowloris does; the stages then take 7-11 s on QEMU 8.2.2 and the per-address cap
    refuses 14-20 times in every mode (interrupt three runs, polled, the kernel before this ADR). No kernel
    behaviour depends on QEMU's main loop on KVM or HVF, where the guest's timer does not run through it.
- **Probation and a windowed miss rule (part of the amendment).** Whatever the cause there, a fallback that only
  counted 8 misses *in a row* would not have caught an interrupt that arrives for some frames only (any hit resets
  it). Now: the interrupt starts **on probation**: armed before every sleep, with a 1 ms poll deadline while
  connections exist (longer than 200 us so that an emulated interrupt controller's late delivery is not counted as
  a miss), until 3 sleeps were ended by it (the boot's DHCP, ARP and ICMP replies do that within its first
  seconds): `net: receive interrupt verified: 3 frames woke core 0 by it (N ms after boot); no polling while the
  NIC is quiet`. 8 misses before that, or 8 misses among any 32 armed sleeps that ended with a frame afterwards,
  fall back to polling for good with a warning (`net: receive wake-up: 8 frames waited after sleeps without the
  receive interrupt; polling every 200 us ...`). Before verification a broken delivery costs at most 1 ms per frame;
  after it, a frame waits for the 10 ms tick at most until the fallback, which needs at most 8 such frames among 32.
  The dispatcher's statistics line counts the armed sleeps and the misses (`N receive interrupt(s) (M armed
  sleep(s), K ended with a frame and no interrupt)`). Host tests: probation and its deadline, verification, a
  silent interrupt on probation, an interrupt that works for one frame in five on probation and for three in four
  after verification (both fall back), one race in eight never falling back. Smoke `net_irq` asserts the
  probation and the verification lines; `gicv2` the verification.

## ADR-271 — QoS 2, exactly once: method B, the in-flight window for both QoS, packet ids in the store (NEXT-2)

- **Status:** Accepted (2026-11-08). Amends ADR-028 ("QoS 2 publishes close the connection, and QoS 2 subscriptions
  are granted QoS 1") and ADR-030 (what the store holds of a persistent session). Answers ROADMAP NEXT-2. The number was
  reserved for this branch: 268 to 270 are performance work, 272 WebSocket, 273 and later MQTT 5.
- **Context.** A device that published at QoS 2 was disconnected on every publish, and a QoS 2 subscription was
  granted QoS 1, so the receiver had to be idempotent. MQTT 3.1.1 4.3.3 defines the four-packet flow and leaves the
  receiver two methods (its Table 4.3 / Figure 4.3): **A** stores the message, answers PUBREC, and delivers it onwards
  only when PUBREL arrives; **B** stores the packet identifier, delivers the message onwards at once, answers PUBREC,
  and forgets the identifier at PUBREL; until then any PUBLISH with that identifier is a duplicate.
- **Decision.**
  1. **Inbound: method B.** A QoS 2 PUBLISH with a new packet id is answered with PUBREC, the id is added to the
     session's held ids, and the message then takes exactly the QoS 1 path (reserved namespace, `$SYS/` requests, ACL,
     rate, telemetry, retain, routing and fan-out). A PUBLISH with a held id, DUP set or not, is answered with PUBREC
     and nothing else: not routed, not counted as published, not charged to the rate, not looked at by the ACL again
     (`qos2_duplicates`). PUBREL removes the id and is answered with PUBCOMP, also for an id not held (our PUBCOMP was
     lost and the client sends PUBREL again; 4.3.3 requires the answer). After PUBREL the id starts a new message.
     Why B and not A:
     - **Memory.** B holds 2 bytes per unfinished flow; A holds the message (up to `limits.max_packet_size`, 4 KiB in
       production) from PUBLISH to PUBREL, per flow and per session, i.e. memory that an authenticated client fills
       by never sending PUBREL. With B that client fills at most the id bound below.
     - **One path.** The message is routed when it arrives, like QoS 1: retained messages, wills, telemetry, the
       control channel and the cross-core fan-out need no second entry point fed from PUBREL, and delivery latency is
       one packet shorter.
     - **The cross-core question disappears.** Deduplication happens on the session's home core before the message
       is routed, so what crosses to other shards is an ordinary routed message (`CoreMsg::Route { msg, qos, retain }`
       with `qos = 2`); no QoS 2 state is ever on another core. Each shard delivers it to its own sessions with its
       own outbound flows.
     B's cost is the one 4.3.3 states: the message goes onwards before the sender knows it was received. That is
     the same exposure as QoS 1 and is what "exactly once" means between two parties: the receiver's duplicates are
     suppressed by the id.
  2. **A refused QoS 2 publish completes its handshake** like an accepted one: PUBREC, the id held, PUBREL ->
     PUBCOMP, the message dropped and counted (`dropped_acl`, `dropped_rate`, `dropped_control`). This is ADR-028's
     "acknowledged and dropped" for QoS 1 (3.1.1 has no negative acknowledgement); its duplicate is not judged again,
     so it is neither counted twice nor accepted later when the rate bucket has refilled.
  3. **Outbound.** Subscriptions are granted the QoS asked for (0, 1 or 2) when the ACL allows the filter. A message
     is delivered at min(publish QoS, granted QoS) (one delivery per session at the highest matching grant, as before);
     wills keep their QoS; retained messages keep theirs and are replayed at min(retained QoS, granted QoS) with RETAIN
     set. A QoS 2 delivery is a *flight* in the session's in-flight list:

     ```
       outbound (the broker sends)                   inbound (the client sends), method B
       ---------------------------                   ------------------------------------
                 deliver / pump                        PUBLISH id (new) --> PUBREC id; route once;
                       |                                                     hold id
                       v                               PUBLISH id (held) -> PUBREC id; nothing else
       [Pubrec] PUBLISH id sent (DUP on resend)        PUBREL id ---------> PUBCOMP id; forget id
          |  PUBREC id --> PUBREL id                    (held ids > bound) -> close the connection
          v                                            reconnect (persistent): held ids kept
       [Pubcomp] PUBREL id sent (msg released)
          |  PUBREC id again --> PUBREL id again
          |  PUBCOMP id --> flight done, pump the queue
          v
        (free)
       PUBACK for a QoS 2 flight, PUBCOMP before PUBREC: ignored
       PUBREC for an unknown id: PUBREL id (the client may hold state we lost)
       reconnect (persistent): every flight re-sent in the order first sent,
         [Pubrec] as PUBLISH with DUP and its id, [Pubcomp] as PUBREL with its id
       clean session or takeover by a clean CONNECT: everything discarded
     ```

     QoS 1 keeps its one state (`Puback`): a PUBACK ends only a QoS 1 flight, a PUBREC or PUBCOMP never does.
  4. **Bounds, no new configuration key.** `limits.max_inflight_qos1` is the in-flight window of a session for QoS 1
     and QoS 2 together; a QoS 2 flight counts until its PUBCOMP (a PUBREC does not free the slot). The offline queue
     (`limits.max_queued_per_offline_session`) holds QoS 1 and QoS 2 messages, each with its QoS. The ids a session may
     hold awaiting PUBREL are `max(max_inflight_qos1, 64)` (`Broker::qos2_id_limit`, `MIN_QOS2_IDS`): 64 covers the
     common clients' default windows (mosquitto and paho Python pipeline up to 20), and a larger window raises it. One
     id more closes the connection (`qos2_inbound_full`; a persistent session keeps its ids, and the client sends the
     PUBLISH again after it reconnects). A held id costs 2 bytes: at most 128 bytes per session at the default. So
     no `limits.*` key is added and the configuration format does not change (format 10, reserved for it, stays unused). The
     key's name says QoS 1; its documentation now says both.
     Memory: an in-flight entry stays 16 bytes (`Flight { pid: u16, flow, msg: Option<Msg> }`, as the `(u16, Msg)` it
     replaces); a queued entry grows from 8 to 16 bytes (its QoS); the held ids live in the same boxed `Pending` as
     the queues, freed when all are empty. `Session` (64 B) and `Conn` (48 B) are unchanged (`hot_state_stays_small`).
  5. **Persistence: database schema 3.** As for QoS 1 (ADR-030), what a session has in flight lives in RAM while it is
     online and is written as a snapshot when it goes offline. The snapshot now holds each in-flight message **with
     its packet id and QoS** (`queued.pid`, 0 for not sent), the queue with each message's QoS, and the QoS 2 ids:
     `qos2_ids (client_id, released, pid)`, `released` 0 for an id received and awaiting PUBREL, 1 for an id released
     to the client and awaiting PUBCOMP. `PersistOp::QueuePush` carries `qos` and `pid`, `PersistOp::Qos2` records an
     id, `QueueClear` clears both. At boot, `restore_session` puts released ids back first (their PUBLISH went out
     before anything still in flight), then the in-flight messages with their ids (up to the window; beyond it, or on
     an id already taken, they are queued), then the queue, and the held ids (up to the bound; id 0 and duplicates
     skipped). So a restart while a device is offline resumes each flow where it stood: PUBREL and PUBLISH with DUP
     and the original id, and a held inbound id still suppresses its duplicate.
     **QoS 1 changes with it:** an unacknowledged QoS 1 message used to come back after a restart as a new message
     with a new id; it now comes back with its id and DUP (4.4 asks for exactly that).
     Schema 3 rebuilds `retained`, `subscriptions` and `queued` (their `CHECK (qos IN (0, 1))` becomes `(0, 1, 2)`;
     SQLite cannot alter a CHECK) inside the migration's transaction, copying every row (a schema 2 queued row reads
     as not in flight), and creates `qos2_ids`. It runs when the store opens a schema 2 database, in the kernel and
     in `urmqtt-disk` (which opens the store for `verify`, `export` and `migrate --verify`). A kernel before this one
     refuses a schema 3 database (`schema version 3 is newer than this build`), as it would any newer schema; a backup
     snapshot records its schema and is restored only by a build that can read it (S5).
- **Not exactly once across a broker crash while the client is connected.** The online state is not written until
  the session goes offline (unchanged from QoS 1). If the VM dies while a device is connected, the session comes back
  as it was at its last disconnect: messages in flight or queued since then are lost (as for QoS 1), an inbound flow
  whose PUBREC the client never saw is routed a second time when the client sends the PUBLISH again, and a client that
  holds an id we released may treat our next PUBLISH with that id as a duplicate. Writing each id and flight through
  the DB core before answering would make every QoS 2 publish wait for a commit (5 ms batches today) and is not
  done; KNOWN-ISSUES section 5 says so.
- **Counters.** `Stats::{qos2_received, qos2_duplicates, qos2_completed, qos2_inbound_full}`, summed over the shards
  into `$SYS/broker/messages/qos2/{received,duplicates,completed,inbound_full}`, the info reply (`"qos2":{...}`) and
  a line of the console's `status`.
- **Verification.**
  - Host: `crates/broker/src/qos2_tests.rs`, 18 tests: every transition of both machines, duplicates with and without
    DUP, acknowledgements of the wrong kind or out of order, QoS 1 and 2 ids of one client independent, the id wrap
    skipping a released id, a reconnect in the middle of both directions, a takeover in the middle, clean sessions,
    a QoS 2 will (retained), retained replay at the lower QoS, ACL and rate refusal completing once, a control message
    sent twice handled once, the id bound and its floor, the fan-out across shards, the offline queue at QoS 2, the
    snapshot and a restart through a model store, and the bounds `restore_session` applies to what the store returns.
  - Model: `crates/broker/tests/qos2_model.rs`, a proptest (400 cases, fixed seed) that runs random sequences of a
    persistent device (publishes with chosen ids and DUP, PUBREL, every acknowledgement for any id, drops, clean and
    persistent reconnects) and of the system (a backend commanding at each QoS, a restart from the store while the
    device is away) against a reference model written from 4.3.3 and 4.4, and compares every packet both clients
    receive after every step; every device publish must reach the backend exactly once. Mutants checked by hand
    (no deduplication, no release at PUBREC, no PUBREL on resend, PUBREL forgetting the wrong id, a snapshot that
    loses a held id or an in-flight id) all fail it.
  - The `broker_acl` oracle (H5) models the held ids per session (across reconnects, takeovers and `restore_session`)
    and checks that a duplicate is answered and neither routed nor counted, that one id too many closes, that every
    PUBREC answers a held id and every PUBREL is answered, that a message reaches a session in one flow only (sent
    again only with DUP and its id, never after our PUBREC) and that a PUBREL comes only after our PUBREC; new
    operations `Release` and `Dup`, QoS 2 subscriptions and restores with held ids; 6 new seeds; a directed test.
    After garbage on a connection the broker may read any packet in what follows (a PUBREL among them), so the
    oracle stops judging that session's QoS 2 ids from then on (two of its own false positives, now seeds). 120 s
    runs: `broker_acl` 468 968 executions and `broker_input` 2 733 499, clean. Its first 120 s found a bug older than
    QoS 2: a retained message replayed for a SUBSCRIBE while the in-flight
    window was full went to the queue and came out with RETAIN 0 (QoS 1 since M9; 3.3.1.3 requires 1). Queue entries
    and flights now carry the flag (still 16 bytes), resends keep it; the oracle's RETAIN rule was widened to such
    queued replays and tightened to messages that were published, willed or restored retained.
  - `broker_input`: the harness moved to `crates/broker/tests/input_harness/` (the fuzz target includes it), its
    seeds (`fuzz/seeds/broker_input/`, new: duplicates, a resume after a drop, a QoS 2 will and retained message)
    replay in `cargo test`, and a test checks that they reach the QoS 2 counters.
  - Store: `golden_schema3.rs` (the frozen schema 2 database of `v2-data` migrates and keeps every row; the rebuilt
    tables' QoS checks and index; QoS 2 rows written, cleared and cascaded; a power cut at every write of the migration,
    cut or torn, cache kept or dropped, leaves schema 2 or 3 with every row), `golden_schema3_bytes.rs` (a schema 3
    database with QoS 2 state is written byte for byte as `schema3-qos2.txt`), `golden_v2.rs` (`v2-data` stays the
    frozen schema 2 image; the same steps now write `v2-data-schema3`).
  - Smoke, both architectures: `mqtt-scenarios.py` (run by `mqtt-plain`, `mqtt-tls` and the plaintext and GICv2
    groups) gains `qos2-pubsub-exactly-once`, `qos2-after-reconnect` and `qos2-retained` with mosquitto `-q 2 -V
    mqttv311`; the group `mqtt_qos2` (also in `SMOKE_ONLY=misc`) speaks MQTT itself (`scripts/qos2-scenarios.py`):
    the same PUBLISH three times before PUBREL is delivered once, an inbound and an outbound flow survive a kill of
    the client at both points, paho-mqtt (through `uv`, when installed) pipelines 40 QoS 2 publishes and drains an
    offline queue of 24 at QoS 2, each exactly once; then a session is left in the middle of every flow, the client
    and the VM are killed, and the next boot resumes every flow from the store.
- **Not done.** Exactly once across a crash of the broker while the client is connected (above). MQTT 5's receive
  maximum (the client's own bound on our window) comes with NEXT-3. The id bound is not configurable on its own.

## ADR-272 — MQTT over secure WebSocket in the kernel: one bounded upgrade, a streaming frame codec, mtls or a password inside TLS (NEXT-5, D-5)

- **Status:** Accepted (2026-11-08). Answers D-5 (the owner: in the kernel, not an external bridge). Configuration
  format 9 (format 8 is another branch's). Builds on ADR-080 (handshake admission), ADR-221..224 (watchdog
  classes), ADR-229..231 and ADR-267 (password hashes, lock-out, login rate), ADR-233 (independent listeners).
- **Context.** Browsers and many web stacks speak MQTT only as WebSocket (`wss://host:port/mqtt`, subprotocol `mqtt`,
  RFC 6455 binary frames, MQTT 3.1.1 section 6). Until now the only way was the demo's external bridge
  (`deploy/demo-bridge/`), not a product. A WebSocket listener puts an HTTP request parser and a frame codec into the
  TCB, which is new attack surface; the design question is how little of HTTP and WebSocket the kernel has to accept,
  and how a browser, which cannot practically present a client certificate, proves who it is.
- **Decision.**
  - **A new `no_std` crate, `urmqtt-ws`, holds all of the protocol** and nothing of the kernel: `forbid(unsafe_code)`,
    no allocation, clippy's `unwrap`/`expect`/`indexing`/`panic` denials, host-tested. Two pieces:
    - **The upgrade** (`upgrade.rs`): one request of at most **4 KiB and 32 header lines**, delimited first (`scan`),
      then read in one pass. Only `GET <path> HTTP/1.1` with the configured path (byte for byte; no query, no absolute
      form), CRLF line ends only, no folding, token header names, no control characters in values; `Host` once and
      not empty; `Upgrade` lists `websocket`, `Connection` lists `Upgrade` (case-insensitive lists: Firefox sends
      `keep-alive, Upgrade`); `Sec-WebSocket-Key` the canonical base64 of 16 bytes; `Sec-WebSocket-Version: 13`
      (anything else 426 naming 13); `Sec-WebSocket-Protocol` offers `mqtt` (preferred) or `mqttv3.1`; no
      `Transfer-Encoding`, `Content-Length` absent or 0; a second `Host`, `Upgrade`, `Connection`, key, version, origin
      or length header is a refusal, not "the last one wins". Everything else is ignored, including
      `Sec-WebSocket-Extensions`: **no extension is ever agreed on (no permessage-deflate)**. The answers are fixed:
      101 with the accept value and the subprotocol, or 400, 403 (origin), 404 (path), 426 (version), each with
      `Connection: close` and nothing the client sent. No body, no keep-alive, no second request, no static files, no
      CORS preflight, no redirect. `Sec-WebSocket-Accept` needs SHA-1 (RFC 6455 4.2.2); the crate has a 60-line
      private SHA-1 checked against RFC 3174's vectors, used for nothing else, because the accept value is a protocol
      handshake, not a security property (no vetted `sha1` crate is in the dependency set and one call does not
      justify adding one).
    - **The frames** (`frame.rs`): a streaming decoder that unmasks each payload byte in place and hands it on at once.
      **MQTT needs no message boundaries** ("the receiver MUST NOT assume that MQTT Control Packets are aligned on
      WebSocket frame boundaries", 3.1.1 section 6), so there is **no reassembly buffer**: the decoder keeps a frame
      header (at most 14 bytes) and one control frame's payload (at most 125). Nothing is sized by an attacker's
      length. A message's announced length is checked against the message limit at the header, before any payload is
      accepted (64-bit lengths with the top bit set and non-minimal encodings are refused); the limit is the MQTT
      packet limit in force plus 4 KiB for small packets sent along, a sanity bound rather than a memory bound (the
      broker's parser bounds each packet). Every server-side rule of RFC 6455 with its close code: unmasked client
      frame, reserved bits, unknown opcode, a control frame fragmented or over 125 bytes, a continuation without a
      message or a data frame inside one, a bad close payload (1002); a text frame (1003: MQTT is binary); a close
      reason that is not UTF-8 (1007); a message over the limit (1009). Close codes accepted from a peer: 1000-1003,
      1007-1014, 3000-4999.
  - **The kernel's side is a transport adapter.** A listener on `websocket.port` beside the TLS one, sharing its
    certificate and key (so `websocket.enabled` needs `network.mqtt_tls_port` set). The connection glue lives in a
    child module of the MQTT service (`mqtt_service/ws.rs`) and the listener's state in `websocket.rs`; the service's
    shared paths call in at accept, TLS established, decrypted bytes, output and close. The MQTT bytes the broker
    sees are exactly the binary frames' payloads, parsed by the **same parser with the same limits** as on the TLS
    port; server output is one binary frame per broker output chunk, nothing is sent after our close frame. Core 0
    steers the port's flows to the workers like the other MQTT ports.
  - **Admission and the slow client.** A WebSocket connection is a TLS connection: the core's TLS admission (in-flight
    per core and per address, the handshake rate, the heap reserve, the DB backlog) applies at the SYN and the ACK,
    and the listener adds its own: connections in all (`max_connections`) and per address (`max_connections_per_ip`)
    in a source table (the plaintext listener's type, its own instance, hashed under a boot key), lock-outs, and in
    password mode a login token bucket at half a core (ADR-267). Until the upgrade (with mtls) or the login (with
    passwords) the connection counts as a handshake in flight, so its slot is held only as long as a handshake's.
    The request must be complete within `upgrade_timeout_s` (1-10 s, default 5) **of the accept, TLS included**, and
    within 4 KiB; a slower client is reset and counted (`refused/timeout`). The handshake timeout of ADR-080 (10 s,
    3 s under pressure) still applies on top.
  - **Two authentication modes, chosen per image (`websocket.auth`):**
    - **`mtls` (the default).** The TLS port's server: a client certificate, the same identity, roles (device,
      service, operator, bootstrap), registry and revocation (a revoked serial's WebSocket connections close like its
      TLS ones). The session attaches at the upgrade. Works for every non-browser WebSocket client and for browsers
      that hold a certificate.
    - **`password`.** Browsers cannot practically present client certificates, so the TLS server is built without a
      client-certificate request (`TlsServer::new_server_only`: same certificate, key, suites and record layer, no
      session tickets so that nothing of it can resume on the mutual-TLS server) and the first MQTT packet is decided
      before the broker sees it: a CONNECT whose user name and password match an account of `websocket.users`
      (PBKDF2-HMAC-SHA-256 as `plaintext.users`, the same checker, decoy and constant-time comparison, one hash on
      every path). A refusal is CONNACK 4 (5 for the registry or a stored-session request) in a frame, then close 1008;
      failed logins count toward the source address's lock-out (`max_failed_auths_per_ip` in `lockout_s`). **The
      password only ever travels inside TLS.** The session is a new broker role, `Role::Web`, with the section's own
      ACL (`acl_publish`, `acl_subscribe`, `{id}` = the account id, default `web/{id}/#`), packet limit, publish rate
      and retain flag; it never holds the service, operator or control role, never reaches `$SYS` or `$urmqtt`, is
      **clean only**, and is named `$ws/<id>/<client id>`, so it meets neither a certificate's session nor a
      plaintext one. The registry allowlist applies. The broker change is limited to the policy lookup per role; its
      parser is untouched.
  - **Origins.** Browsers send `Origin` on every WebSocket request, and cross-site WebSocket hijacking (a page on
    another site opening a connection with the user's ambient credentials) is the classic attack. `websocket.origins`
    is a list of exact origins (`https://app.example.com`; the check refuses `null`, wildcards, paths, trailing
    slashes, upper case and the scheme's default port, which browsers never send); a request whose `Origin` is not
    listed gets 403. **Required with `password`**; with `mtls` an empty list admits any origin, since only a browser
    that holds a client certificate gets past TLS. A request **without** `Origin` is accepted: it comes from a device
    or a script, not a browser, so it cannot be a cross-site request. An origin refusal does **not** count toward the
    lock-out: a hostile page could otherwise lock out its visitors' addresses.
  - **Answers on the wire.** Pings are answered with pongs while the connection's output buffer has room (RFC 6455
    allows answering only the latest; a client that pings without reading does not grow our buffers); a client's
    close is echoed with its code and the MQTT session ends as on a lost connection (the will is published unless it
    sent DISCONNECT); a violation is closed with its code; the broker's own close (DISCONNECT, keep-alive, takeover)
    sends 1000; then TLS close_notify and FIN.
  - **Watchdog (ADR-221..224).** A WebSocket connection's input runs in the handshake class until the upgrade (and in
    password mode the login, a password check) is done; boot calibrates that budget with the dearer of a TLS
    handshake and either listener's password check (`websocket: one password check costs about N us`). The upgrade
    deadline is checked in the 100 ms timer step with the handshake timeouts.
  - **Observability.** `$SYS/broker/websocket/{enabled, port, path, auth, origins, accounts, connections, accepted,
    upgrades, refused/{request, method, path, version, protocol, origin, too_large, timeout, limit, locked_out},
    auth_ok, auth_failed, lockouts, frames/{in,out}, bytes/{in,out}, close/client/<code>, close/server/<code>,
    close/abrupt}` (one topic while off), the same as a `websocket` object of the info query and a status line. One
    boot line names the port, path, mode, origins and limits; refusals and protocol violations are logged at powers
    of two per kind, a lock-out always, once, with the address.
  - **Configuration (format 9).** `[websocket]`: `enabled` (false), `port` (8084), `path` (`/mqtt`), `auth` (`mtls` |
    `password`), `origins`, `users`, `upgrade_timeout_s` (5), `max_connections` (1000), `max_connections_per_ip`
    (16), and for `password` `max_packet_size` (16 384), `publish_rate_per_device` (10/s), `max_failed_auths_per_ip`
    (5), `lockout_s` (300), `acl_publish`, `acl_subscribe` (`web/{id}/#`), `retain` (false). Tags 230-245, each
    `since 9`; a section left at its defaults writes no record, so the blob keeps its older format. The blob check
    (`urmqtt_cfg::check`) and the TOML validator agree (a table of 27 section shapes); entries are well formed whether
    or not the listener is on; when on: the TLS listener on, a port of its own, accounts and origins with `password`,
    no accounts with `mtls`, no account id that is a service, operator or control identity.
- **Conformance and testing.** Host: RFC 6455's accept and masking examples, RFC 3174's vectors, every refusal and
  violation, split invariance and no-panic properties (proptest), Kani (`scan` on any 8 bytes and every header length
  proven; the decoder and `parse` harnesses do not finish within the cap even at 6 and 2 symbolic bytes and are listed
  as not proven), Miri. Fuzz: `ws_upgrade` (any request and policy; what is accepted is a
  complete request for the path with a well-formed 101 — it found that the `mqttv3.1` response did not fit its
  160-byte buffer, now 192 with a test) and `ws_frames` (the decoder against itself under arbitrary cuts: same
  events, same verdict, no message over its limit), 180 s each with no finding after the fix; `broker_input` now
  opens web sessions. **Autobahn|Testsuite 25.10.1** (fuzzingclient, all 517 cases, against `examples/echo.rs`,
  which shares the parser and the decoder): 298 OK, 3 informational, 216 unimplemented (12.x/13.x, permessage-deflate,
  which is not negotiated, so the client falls back cleanly), 0 failed, 0 non-strict (docs/audit/ws-autobahn.md).
  End to end (smoke group `websocket`, both architectures): paho-mqtt over wss and a raw client against the real
  kernel in QEMU; QoS 0/1, a packet at the size limit and one over, a fragmented message with a ping inside, clean and
  abrupt close, every refusal, the violations, a slowloris request cut at the deadline, no certificate refused,
  two rounds of 10 000 upgraded idle connections and the heap after each, password logins, the ACL, clean sessions,
  the lock-out. A real browser: headless Chrome 156 with MQTT.js 5.10.1 (`scripts/ws-browser-test.mjs`, by hand)
  logs in from an allowed origin, publishes and receives at QoS 0 and 1, gets CONNACK 4 for a wrong password, and
  gets no connection from another origin.
- **Alternatives.** The external bridge as a product (no TCB change, but a second process to deploy and secure, and
  the broker sees the bridge's address and identity, not the client's). Reassembling messages before the broker
  (a buffer per connection sized by the client, for nothing MQTT needs). Accepting `permessage-deflate` (a
  decompressor in the TCB and compression oracles inside TLS). A password over plain `ws://` (the password in the
  clear; never). Cookie or token authentication on the HTTP upgrade (a second credential system; browsers' WebSocket
  API cannot set headers anyway, so the MQTT CONNECT is the natural place). Reusing `plaintext.users` (a LAN
  account would become a web account by accident; the two lists are separate and may share ids, in separate session
  namespaces).
- **Consequences.** The TCB grows by the crate `urmqtt-ws` (1 766 lines in docs/audit/inventory.md, of which about
  1 000 are the upgrade, the frames and SHA-1 and the rest tests and proofs) and about 1 250 lines of kernel (the
  listener's state and the connection glue). An idle WebSocket connection costs 734 bytes of heap
  (HVF, 10 000 upgraded connections, TLS session, WebSocket state and the broker's connection together; an idle TLS
  connection is 494, M15), and two rounds of 10 000 leave the heap where one round did (5 655 and 5 671 KiB). Not done: run-time accounts (NOW-15, as for plaintext), stored
  sessions for password logins, compression, HTTP/2 or HTTP/3 WebSocket (RFC 8441/9220), `ws://` without TLS.

## ADR-273 — MQTT 5.0: a strict zero-copy codec now, broker semantics in two phases (NEXT-3, D-13)

- **Status:** Accepted for the codec (part 1, implemented: `crates/mqtt/src/v5/`); **proposed** for the broker
  (parts 2 and 3, below). Answers the design half of ROADMAP NEXT-3; D-13 was answered by the owner as "full MQTT
  5.0, in phases". Numbers 273 to 278 are reserved for MQTT 5.0: parts 2 and 3 record what they change against this
  ADR in ADR-274 onwards. 268 to 270 are performance, 271 QoS 2 (NEXT-2, a dependency: part 2 starts after it is
  merged), 272 WebSocket.
- **Context.** The broker speaks MQTT 3.1.1 only; a CONNECT with protocol level 5 is refused (KNOWN-ISSUES §2). The
  3.1.1 codec is zero-copy, `no_std`, `forbid(unsafe_code)`, streaming and bounded (M8, ADR-028), the broker
  sans-IO with home shards per client id (ADR-032) and about 494 B per idle mTLS connection (M15, ADR-034). MQTT 5.0
  adds a property block to most packets, reason codes on every acknowledgement and on DISCONNECT, AUTH, and new
  session, flow-control and subscription semantics. On this branch the broker is unchanged: a 5.0 CONNECT is still
  refused at run time.

### Part 1: the codec (done)

- **Where.** `urmqtt_mqtt::v5` (new files only; the crate root gained `pub mod v5;`). Same contract as the 3.1.1
  codec: `decode(buf, &Limits) -> (Packet, used)` with `Error::Incomplete(n)` for streaming, `encode(&Packet, out)`
  into a caller buffer, `encoded_len`. Re-uses the 3.1.1 string and topic rules (`validate.rs`: valid UTF-8, hence
  no surrogates, no U+0000, 65 535 bytes by the prefix; topic names without wildcards; `#` last, `+` whole level).
- **All 15 packet types**, AUTH included. Strict, per the OASIS text: fixed-header flags (§2.1.3), Remaining Length
  and every Variable Byte Integer at most 4 bytes and minimal (§1.5.5), CONNECT flags (reserved bit, Will QoS 3,
  Will QoS/Retain without Will; a password without a user name is legal in 5.0), Will Properties, the property
  matrix of Table 2-4 (27 identifiers × 14 places, the Will counted as a place), duplicates (only User Property
  repeats, and Subscription Identifier in PUBLISH), value ranges (0/1 flags, zero Receive Maximum, Topic Alias,
  Maximum Packet Size and Subscription Identifier are protocol errors, Response Topic is a Topic Name),
  Authentication Data only with an Authentication Method, the reason codes of Table 2-6 per packet, the short forms
  (PUBACK and friends with Remaining Length 2 or 3, DISCONNECT 0 or 1, AUTH 0), CONNACK Session Present only with
  0x00, the Subscription Options byte (QoS 3 and reserved bits malformed, Retain Handling 3 a protocol error),
  shared-subscription syntax (`$share/{non-empty name without + #}/{non-empty filter}`) and No Local on a shared
  subscription (protocol error), an empty Topic Name only with a Topic Alias, empty SUBSCRIBE/UNSUBSCRIBE and empty
  SUBACK/UNSUBACK lists refused.
- **Allocation.** None. A property block, a topic list and a reason-code list are kept as the borrowed bytes after
  one validating pass and are iterated lazily (`Properties::Raw`, `SubscribeTopics::Raw`, ...). Duplicate detection
  uses a 64-bit mask of the identifiers seen. The two lists the specification leaves open have documented bounds in
  `v5::Limits`: `max_user_properties` per block and `max_subscription_identifiers` per PUBLISH; everything else is
  bounded by `base.max_packet_size` (the Maximum Packet Size this side announces), which is checked from the fixed
  header before the body is awaited, as in 3.1.1.
- **Symmetric encoder.** `encode` refuses with `EncodeError::Invalid(e)` every packet the decoder would refuse under
  `Limits::PROTOCOL_MAX` (it validates the property block it has just written with the decoder's own validator), so
  whatever it writes decodes to an equal packet. It writes the shortest form (an acknowledgement with 0x00 and no
  properties is 2 bytes). `Properties::Forward { raw, drop, extra }` encodes a received block minus some
  identifiers plus appended properties without copying it first: the broker's fan-out primitive (drop Topic Alias
  and Message Expiry Interval, append the subscriber's Subscription Identifiers and the remaining expiry); a block
  that is wrong for the target packet (a Will's Will Delay Interval in a PUBLISH) is refused, never emitted.
- **Errors carry their reason code.** `Error::reason_code()` maps each refusal to what a server answers (CONNACK for
  the CONNECT, DISCONNECT afterwards): the specification's Malformed Packet (0x81) and Protocol Error (0x82)
  classification, 0x84 for the protocol name and level, 0x85 for the client id bound, 0x90/0x8F for topic names
  and filters, 0x95 for the packet size, and 0x83 for our own bounds (topic length and levels, filters, User
  Properties, Subscription Identifiers). Tested: every code is one a CONNACK or a DISCONNECT may carry.
- **Dispatch helper.** `v5::connect_protocol_level(buf)` reads the level of a CONNECT from its first bytes (streaming)
  so that the broker can pick the decoder before parsing the rest.
- **Deliberately left to the broker** (they need connection state): Topic Alias above the announced maximum, a
  client sending a Subscription Identifier in PUBLISH [MQTT-3.3.4-6], Receive Maximum overrun, a DISCONNECT that
  raises Session Expiry from 0, Payload Format Indicator 1 with a payload that is not UTF-8 (the receiver MAY check;
  §3 below), Retain when Retain Available is 0. Nothing that can be checked on one packet is deliberately accepted.
- **Verification.** Unit tests straight from Table 2-4 (every identifier × every place, accepted iff the table says
  so; every byte that is not an identifier refused in every place; duplicates per place) and Table 2-6 (every
  value × every packet, accepted iff the table says so), byte vectors per packet, a negative corpus (truncations,
  flags, duplicates, not-allowed properties, bad UTF-8 including surrogates and overlong NUL, five-byte and
  non-minimal varints, trailing bytes), round-trip proptests (random packets, "careful sender" packets that must
  always encode, random bytes), interop fixtures captured from Mosquitto 2.x clients and paho-mqtt 2.x
  (`crates/mqtt/tests/mqtt5_interop.rs`, `scripts/mqtt5-capture.sh`), fuzz targets `mqtt5_packet` and
  `mqtt5_props`, Kani harnesses for the varint and the property-block length arithmetic
  (`crates/mqtt/src/v5/proofs.rs`), Miri with the crate's other tests.

### Part 2 and 3: broker semantics (proposed, decided here)

1. **Version negotiation.** Both versions on every listener (TLS, plaintext, and the WebSocket listener of ADR-272
   when it exists). The broker reads the first packet's level with `v5::connect_protocol_level`: 4 goes to the 3.1.1
   decoder as today, 5 to `v5::decode` (when `mqtt5.enabled`), 3 (`MQIsdp`) gets the 3.1.1 CONNACK 0x01 as today,
   anything else is closed. With `mqtt5.enabled = false` a 5.0 CONNECT gets a 5.0 CONNACK 0x84 (the client can
   parse it, §3.1.4) and the connection is closed. The connection keeps `protocol_level` in its flags byte; every
   later packet uses that version's codec, both ways. The broker's logic moves onto version-neutral internal
   events (inbound PUBLISH = topic, payload, QoS, retain, and an optional borrowed property block); a thin per-
   connection shim decodes into them and encodes out of them. 3.1.1 behaviour and its tests stay byte-identical.
   The relay between transport and home core (ADR-032) carries bytes and is version-agnostic; the code that peeks
   at a CONNECT before the broker (the dev plaintext hold and `kernel/src/plain.rs` credentials) learns the level
   first, then uses the matching decoder.
2. **Mixed-version fan-out.** A stored message (`MsgInner`) gains `props: Option<Box<[u8]>>`: the validated
   PUBLISH block **minus** Topic Alias and Subscription Identifier (connection-specific) and with Message Expiry
   Interval kept as an absolute deadline beside it, not in the bytes. A 5.0 subscriber gets the block through
   `Properties::Forward` plus its Subscription Identifiers and the remaining expiry; a 3.1.1 subscriber gets topic
   and payload only (properties stripped); a message from a 3.1.1 publisher has no block. A Will from a 5.0 client
   is published with its Will Properties minus Will Delay Interval. Forwarded unchanged and unread: Payload Format
   Indicator, Content Type, Response Topic, Correlation Data, User Properties (request/response is just forwarding).
   Retained messages and persisted queues keep the block (new `props BLOB` columns).
3. **Payload Format Indicator** is forwarded, not checked (checking is O(payload) on the publisher's core and the
   specification lets the receiver choose). A later key `mqtt5.check_payload_format` could answer 0x99.
4. **Session Expiry Interval, and NEXT-4.** Sessions get an expiry in both versions; this replaces NEXT-4's separate
   design. 5.0: the CONNECT's interval (absent = 0), lowered to `limits.max_session_expiry_s` and then announced in
   CONNACK; Clean Start only decides whether an existing session is discarded. 3.1.1: `clean_session=1` is expiry 0,
   `clean_session=0` is `limits.max_session_expiry_s` (3.1.1 persistent sessions stop being eternal; the default
   below is long enough that no current deployment should notice, and 0xFFFFFFFF ("never") is only granted when
   the configured maximum is 0xFFFFFFFF). DISCONNECT may change the interval, except from 0 to non-zero (0x82).
   Store: migration adds `expiry_s` and `offline_since` (wall-clock seconds, the boot clock of ADR-009) to the
   session row; each home shard keeps offline sessions with a finite expiry in its timer wheel
   (`urmqtt-timer-wheel`, seconds resolution) and on restore re-arms from `offline_since + expiry_s` (already past:
   dropped at boot, counted). Expiry deletes the session, its subscriptions and its queue, and publishes a pending
   Will (rule 6). Bootstrap and plaintext sessions stay never-persistent (ADR-230): their expiry is forced to 0
   and a 5.0 client that asks for more is told 0 in CONNACK, instead of the 3.1.1 refusal.
5. **Message Expiry Interval.** The absolute deadline (monotonic ms while online; wall-clock seconds in the store) is
   kept beside the message; each delivery sends the remaining seconds, and a message whose deadline passed is
   dropped instead of delivered from a queue, the retained store or a resend (counted). Retained messages expire
   the same way, lazily on read and in the periodic compaction. `limits.max_message_expiry_s` (0 = no cap) bounds
   what a publisher can ask for, so a retained message cannot outlive the operator's policy.
6. **Will Delay Interval.** On a close that publishes the Will, the Will is armed for `min(will delay, session
   expiry)` in the home shard's timer wheel; a CONNECT that takes over the session first cancels it. The armed
   Will lives in the session (it does today in the connection's extra box), so delay costs nothing while unused.
   DISCONNECT 0x04 (Disconnect with Will Message) publishes it; a normal DISCONNECT discards it, as in 3.1.1.
7. **Receive Maximum (flow control).** Server to client: the in-flight window of a 5.0 connection is
   `min(client Receive Maximum, limits.max_inflight_qos1)` (QoS 1 and 2 together), the rest queues as today.
   Client to server: the broker announces `mqtt5.receive_maximum` (default 32); QoS 1 is acknowledged on receipt,
   so only QoS 2 publications between PUBREC and PUBREL count; one above the announced value is DISCONNECT 0x93.
8. **Maximum Packet Size.** Server side: CONNACK announces the effective `limits.max_packet_size` (or
   `plaintext.max_packet_size` on that listener); a larger packet is DISCONNECT 0x95 (the codec refuses it from the
   fixed header). Client side: the client's value is kept per connection (default: the protocol maximum); a
   delivery whose `encoded_len` exceeds it is dropped "as if sent" [MQTT-3.1.2-25] and counted, and a reason
   string or user properties that would push an acknowledgement over it are left out first.
9. **Topic aliases.** Client to server only. The broker announces `mqtt5.topic_alias_maximum` (default 10, 0
   disables); the table is allocated on the first alias (`Box<[Option<Box<str>>]>` of that length), so a client
   that does not use aliases pays nothing; its worst case is `topic_alias_maximum × (max_topic_len + 16)` bytes
   (2.7 KiB with the defaults), counted against the connection in the M15 accounting. An alias above the maximum,
   0, or unknown with an empty topic is DISCONNECT 0x94. Server to client: the broker never sends aliases (the
   client's Topic Alias Maximum is honoured by not using any), so no per-subscriber state.
10. **Server Keep Alive.** `mqtt5.max_keep_alive_s` (default 0 = accept the client's). When set and the client asks
    for 0 or more, CONNACK carries Server Keep Alive with the maximum and the broker enforces it (1.5 × as today).
11. **Assigned Client Identifier.** An empty client id from a 5.0 client: on TLS the broker assigns the certificate
    identity (the only id it would accept anyway) and returns it; on plaintext it assigns `auto-N` as it does for
    3.1.1 today (that rule already exists for clean sessions) and returns it.
12. **Subscription options.** Stored in the spare bits of the 8-byte `Sub` (QoS 2 bits, No Local, Retain As
    Published, Retain Handling 2 bits; persisted as one `options` column). No Local: a route carries its origin
    session (shard, id) and a delivery to the same session is skipped. Retain As Published keeps the RETAIN flag on
    live delivery (3.1.1 clears it). Retain Handling 1 sends retained messages only if the subscription is new, 2
    never. 3.1.1 subscriptions are options = QoS only.
13. **Reason codes and reason strings.** Acknowledgements carry codes the broker can know on its own core: PUBACK/
    PUBREC 0x00, 0x87 when the ACL refused the publish (3.1.1 keeps ack-and-drop), 0x97 when the publish rate
    refused it, 0x90 for a topic the broker does not accept; never 0x10 "No matching subscribers" (fan-out to other
    shards is asynchronous, the home core cannot know). SUBACK per filter: granted QoS, 0x87 refused by the ACL,
    0x8F not accepted, 0x97 subscription limit, 0x9E/0xA1 until part 3 implements shared subscriptions and
    subscription identifiers. UNSUBACK 0x00 or 0x11. Reason strings only on CONNACK and DISCONNECT, short and fixed
    (no client data echoed), and not at all when the client set Request Problem Information 0.
14. **Server-initiated DISCONNECT** (5.0 connections only; 3.1.1 keeps closing): codec errors with
    `Error::reason_code()`, 0x8E session taken over, 0x8D keep alive timeout, 0x8B server shutting down, 0x93, 0x94,
    0x95 as above, 0x96 when the publish rate closes a connection, 0x98 for the control channel's
    `disconnect_identity`, 0x87 for an ACL refusal that closes, 0x9A Retain when Retain Available is 0 (plaintext
    without `retain`; 3.1.1 keeps "delivered, not retained"), 0x82 for a client AUTH. CONNACK refusals map the 3.1.1
    codes: 0x02 -> 0x85, 0x04 -> 0x86, 0x05 -> 0x87, admission -> 0x89 Server busy, a locked-out plaintext address ->
    0x8A Banned, the plaintext login rate -> 0x9F.
15. **Enhanced authentication (AUTH): refused for now.** A CONNECT with Authentication Method gets CONNACK 0x8C Bad
    authentication method; an AUTH packet on a connection that did not negotiate a method is DISCONNECT 0x82.
    Identity stays where it is: on TLS the certificate authenticates (the 5.0 user name and password are ignored,
    as in 3.1.1 today); on plaintext and WebSocket the P1 account rules apply to the 5.0 user name and password (a
    password without a user name, legal in 5.0, is 0x86 in the account modes). **Later**: a method would be a
    configured list (`mqtt5.auth_methods`, empty today), with SCRAM-SHA-256 over the plaintext accounts as the
    candidate (it stops sending the password in clear); its steps run under the same login admission and lock-out
    as a password check (ADR-230, ADR-267), and re-authentication (0x19) would be refused until there is a reason.
    Its own ADR when someone needs it.
16. **Shared subscriptions (part 3).** `$share/{group}/{filter}`. **Owner shard:** a group lives on the worker
    `fnv1a(role class, group, filter) % workers`; joining and leaving are messages to it (the member's home shard
    sends them), and only the owner matches shared filters, so every message, which is already offered to every
    shard (ADR-032), is delivered to one member exactly once. **Which member:** round robin over the group's
    *online* members (offline persistent members are skipped while another is online; with none online, QoS 1 goes
    to the queue of the next member in turn, QoS 0 is dropped). A delivery to a member on another shard is a
    "deliver to session" route message; if that member is gone when it arrives, the owner picks the next one (QoS 1
    only). A message already handed to a member stays with it (the specification allows this on disconnect).
    **ACL:** a share is checked against the inner filter with the subscribe rules, and the group's identity
    includes the role class (device, service, operator, plaintext), so a device can never join a service's group
    and take messages from the backend; between devices allowed the same filter, a device can join another's
    group, which only takes deliveries away from them (it could subscribe without sharing and see all of them
    anyway). Retained messages are not sent on a shared subscribe (§4.8.2).
17. **Subscription identifiers (part 3).** One per SUBSCRIBE, kept per subscription in a side list of the session
    (only sessions that use them pay), persisted with the subscription; a delivery carries the identifiers of every
    matching subscription of that session (one delivery per session, as today), bounded by
    `max_subscriptions_per_session`. CONNACK announces availability per phase.
18. **User properties** are forwarded with the message and bounded by `mqtt5.max_user_properties` (default 16 per
    block, the codec's limit) and by the packet size; the broker never adds any.
19. **Memory.** 3.1.1 connections keep their M15 layout. A 5.0 connection adds one boxed `V5State` (client Receive
    Maximum, Maximum Packet Size, Topic Alias Maximum, Request Problem Information, the alias table pointer: one
    32 B block) and the alias table only once used. Part 2 re-measures bytes per idle connection for both versions
    (NEXT-3's "494 B must be re-established").
20. **$SYS, statsd and limits.** New: `$SYS/broker/clients/mqtt5` (connected 5.0 clients), `messages/expired`,
    `messages/dropped/too_large` (client Maximum Packet Size), `sessions/expired`, `wills/delayed`,
    `disconnects/sent/<reason>` for the server-initiated reasons, `connections/refused/auth_method`. The ACL oracle
    (`fuzz/fuzz_targets/broker_acl.rs`, `crates/broker/tests/acl_oracle/`) extends to: mixed versions on one
    broker, `$share/` judged on the inner filter and never across role classes, No Local, Retain Handling and
    Retain As Published, and "no delivery after expiry". `broker_input` gets 5.0 sequences (seeds from the
    interop fixtures).
21. **Configuration (format 12, reserved).** New keys and defaults:

    | Key | Default | Meaning |
    |---|---|---|
    | `mqtt5.enabled` | `true` | accept protocol level 5 (false: CONNACK 0x84) |
    | `mqtt5.receive_maximum` | 32 | announced; QoS 2 publications awaiting PUBREL |
    | `mqtt5.topic_alias_maximum` | 10 | announced; 0 disables aliases |
    | `mqtt5.max_user_properties` | 16 | per property block, larger blocks are refused (0x83) |
    | `mqtt5.max_keep_alive_s` | 0 | 0: accept the client's; otherwise Server Keep Alive |
    | `mqtt5.shared_subscriptions` | `true` | part 3; announced as Shared Subscription Available |
    | `mqtt5.subscription_identifiers` | `true` | part 3; announced as Subscription Identifier Available |
    | `limits.max_session_expiry_s` | 2 592 000 (30 days) | both versions (NEXT-4); 4 294 967 295 = never |
    | `limits.max_message_expiry_s` | 0 | 0: no cap on a publisher's Message Expiry Interval |

    `mqtt5.auth_methods` is reserved (empty, rule 15). The builder page gets the same keys.
22. **Phases.** Part 2 (after QoS 2): rules 1 to 14 and 18 to 21 except the part 3 rows: version negotiation,
    CONNACK and acknowledgement reason codes, server DISCONNECT, session expiry (NEXT-4 closes with it), message
    expiry, will delay, Receive Maximum, Maximum Packet Size, topic aliases, Server Keep Alive, assigned id,
    subscription options, user properties, AUTH refused. Part 3: shared subscriptions, subscription identifiers,
    the conformance suite run to its expected-failure list, the README/KNOWN-ISSUES/PERFORMANCE updates, and any
    enhanced-auth method if wanted then.
23. **Conformance plan.** `docs/MQTT5-CONFORMANCE.md`: the Eclipse Paho interoperability suite (`client_test5.py`)
    against the broker with a checked-in expected-failure list, Mosquitto clients with `-V mqttv5`, and the codec's
    interop fixtures; `scripts/mqtt5-conformance.sh` is the harness (a stub until part 2).

- **For the owner.** (a) Shared-subscription distribution: round robin over online members on an owner shard
  (rule 16), against the alternatives "random" (no state, uneven) or "least in flight" (needs the members' load on
  the owner). (b) Groups scoped by role class (rule 16). (c) Enhanced auth refused (0x8C) until a method is wanted;
  SCRAM over plaintext accounts is the candidate. (d) The 30-day default session expiry, which also ends 3.1.1's
  never-expiring persistent sessions (NEXT-4). (e) `mqtt5.enabled` on by default.
- **Not done here.** Any broker or kernel change. The kernel does not call the 5.0 codec, so the image does not
  grow: release kernels with and without `pub mod v5;` are the same size (aarch64 3 573 176 B, `.text` +4 B of
  layout noise; x86_64 3 732 016 B, identical sections).

## ADR-274 — MQTT 5.0 part 2: broker semantics as built, and where they differ from ADR-273 (NEXT-3, NEXT-4)

- **Status:** Accepted (part 2 of NEXT-3; NEXT-4 closes with it). Implements ADR-273 rules 1 to 15 and 18 to 21 except
  the part-3 rows (shared subscriptions, subscription identifiers, enhanced authentication), and records every
  departure from it. ADR-275 to 278 stay reserved for part 3.
- **Context.** ADR-273 decided the broker side of MQTT 5.0 and left it to part 2 to build. This ADR is what was
  built, the decisions ADR-273 left open (marked *decided*) and what differs from its text (marked *deviation*).

### What is built

1. **Version-neutral core.** `crates/broker/src/v5.rs` holds the 5.0 shim: `ConnectIn`, `WillIn`, `PublishIn` (the
   version-neutral events of rule 1), the 5.0-only handlers (`on_connect5`, `on_publish5`, `handle5`,
   `on_disconnect5`, `reject5`, `send5`, `close5`) and `V5State` (24 B: client Receive Maximum, Maximum Packet Size,
   Request Problem Information, whether the CONNECT asked for expiry 0, the alias table pointer). The first packet's
   protocol level picks the decoder; a connection that negotiated 5.0 keeps its `V5State` in the connection's
   `Extra` box and uses the 5.0 codec both ways. 3.1.1 is byte-identical: its tests are unchanged except one that
   sent a level-5 CONNECT (now levels 3, 6 and 255), and `qos01_allocs` still counts 9 allocations per QoS 0 and 15
   per QoS 1 message.
2. **Mixed fan-out** (rule 2). `MsgInner` gains `props: Option<Box<[u8]>>` (the PUBLISH block minus Topic Alias,
   Subscription Identifier and Message Expiry Interval) and `expires_ms: u64`; the cross-core route carries the same
   `Arc`, so a 3.1.1 message costs no allocation and no copy (`MsgInner` is 56 B instead of 32, inside the same `Arc`
   allocation). A 5.0 subscriber gets `Properties::Forward` plus the remaining expiry; a 3.1.1 one topic and payload.
3. **Session expiry** (rule 4, NEXT-4). `Session.clean: bool` became `expiry_s: u32` (the session stays 64 B).
   0 ends the session at close; `u32::MAX` never expires and is granted only when `limits.max_session_expiry_s` is
   `u32::MAX`; 3.1.1 `clean_session = 0` gets `limits.default_session_expiry_s` (*deviation*: a key of its own, both
   default 30 days, the default at most the maximum; ADR-273 used the maximum). Bootstrap, plaintext and WebSocket
   password sessions: a 5.0 client is granted 0 and told so in CONNACK, a 3.1.1 one is refused as before. A
   DISCONNECT may change the interval, from 0 to non-zero is 0x82.
4. **Expiry deadlines** (*deviation*: not the timer wheel). Offline sessions with a finite expiry and Wills armed
   with a delay are kept in two ordered sets of (deadline, session) with the reverse map (`crates/broker/src/expiry.rs`):
   a session that comes back cancels its deadline by its id, so the 64-byte session needs no `TimerId` (it has no room
   left), and only waiting sessions pay (two tree entries each). `Broker::tick` (every 100 ms) ends at most 64 of each
   (`SWEEP_PER_TICK`), so an expiry storm is spread over ticks within the watchdog's budget.
5. **Expired while the broker was down** (*decided*: at boot, not at first touch). The store records the wall-clock
   time a session went offline (`SessionOffline`, cleared by `SessionUpsert` when it is back); at restore a session
   whose interval has run is deleted from the store and not loaded (counted, `mqtt: shard N/M ready: ... (K expired
   while down, dropped)`). Reasons: memory and the store are freed at once, no lazily-expired state needs a check on
   every lookup, and boot is the one moment without traffic and watchdog pressure. A session stored before schema 4
   has no recorded expiry: the 3.1.1 default applies from the restore. Without a wall clock the downtime is not
   counted (the latest recorded offline time stands for "now").
6. **Message expiry** (rule 5). An absolute deadline on the broker's ms clock beside the message; each delivery
   states the remaining seconds (rounded up, never 0); a message past it is dropped from queues, retained replays and
   restores (counted). An interval of 0 means "no expiry" (*decided*, as Mosquitto). `limits.max_message_expiry_s`
   caps an explicit interval only (*decided*: a message without one, and every 3.1.1 message, never expires). Retained
   messages expire lazily on read (an expired one found by a replay is cleared there and in the store) and at restore
   (*deviation*: no periodic sweep; an expired retained message nobody reads keeps its bytes until it is replaced or
   the broker restarts). The store keeps the deadline in wall-clock seconds.
7. **Will delay** (rule 6). An armed Will lives in a side map keyed by session (*deviation*: not in the session),
   published at `min(delay, session expiry)` or when the session ends (expiry, a clean-start takeover). A reconnect
   within the delay cancels it; on a takeover that resumes the session the old connection's delayed Will is dropped
   at the takeover. DISCONNECT 0x00 discards the Will; every other code keeps it (0x04 asks for it, §3.1.2.5). The
   Will's Message Expiry runs from its publication. Wills are not persisted (as in 3.1.1).
8. **Flow control** (rules 7, 8). The window to a 5.0 client is `min(max_inflight, its Receive Maximum)`, QoS 1 and 2
   together; *deviation found by the ACL oracle*: after a reconnect the flights owed a resend are marked unsent and
   resent only as the new connection's Receive Maximum allows (`Flight.sent`, in the padding of the 16-byte flight);
   a 3.1.1 client gets them all at once as before. Inbound, only QoS 2 ids awaiting PUBREL count (QoS 1 is
   acknowledged on receipt): one above `mqtt5.receive_maximum` is DISCONNECT 0x93; a QoS 2 PUBLISH refused with a
   failure code (0x87, 0x97) ends its flow and holds no id (§4.3.3). A delivery above the client's Maximum Packet
   Size is dropped as if sent (also an in-flight one at resend), counted `dropped_too_large`; a reason string that
   would not fit a CONNACK or DISCONNECT is left out.
9. **Topic aliases** (rule 9), client to server only; the table (`Box<[Option<Box<str>>]>`, 16 B per slot plus the
   topics) is allocated on the first alias; an aliased PUBLISH takes its topic out of the table while it is handled,
   so no copy. 0x94 for an alias above the maximum or unknown. *Deviation*: the table is not counted in the kernel's
   per-connection accounting (memprof); its bound is documented instead (`topic_alias_maximum` × (16 + topic)).
10. **Subscription options** (rule 12) in the byte the trie keeps per subscriber (the `SubOpts` of the 5.0 Options
    byte; 3.1.1 is QoS only), persisted in `subscriptions.options`. *Decided*: overlapping subscriptions of one
    session give one delivery with the options merged (highest QoS, No Local only if every matching subscription has
    it, Retain As Published if any has it). No Local compares the publisher's session on the shard that routes it
    (where that session lives); a Will has no publisher session. Retain As Published keeps RETAIN when the shard
    retained the message (*deviation*: a retained publish the limits refused to retain is delivered with RETAIN 0).
11. **Reason codes** (rules 13, 14). PUBACK/PUBREC 0x87 (ACL, the reserved namespace, `$SYS/` without the operator
    role), 0x97 (publish rate, a full control or `$SYS` backlog); SUBACK 0x87, 0x97 (subscription limit), 0x9E,
    0xA1; UNSUBACK 0x00/0x11; PUBREL/PUBCOMP always 0x00 (an unknown id is answered as in 3.1.1). Server DISCONNECT
    for 5.0 connections: decoder errors with their code (0x81, 0x82, 0x83, 0x8F, 0x90, 0x95), 0x8D, 0x8E, 0x93, 0x94,
    0x98 (allowlist), 0x9A (Retain without Retain Available), 0x82 (AUTH, a client Subscription Identifier in
    PUBLISH, a second CONNECT, DISCONNECT raising expiry from 0). CONNACK refusals: 0x84 (`mqtt5.enabled` off),
    0x85, 0x86, 0x87, 0x88, 0x8C (Authentication Method), 0x9A (retained Will without Retain Available), a decoder
    error's code. Reason strings are fixed text, only on CONNACK and DISCONNECT, only with Request Problem Information.
    *Not used* (deviation, no path for them): 0x8B (no orderly shutdown path; `reboot` stops the machine), 0x96 (no
    rate path closes a connection: over the rate a publish is refused with 0x97 and the connection stays), 0x89, 0x8A
    and 0x9F (admission, lock-out and the login rate refuse at the SYN, before there is a CONNECT to answer).
    Revoked certificates are cut at the transport without a DISCONNECT (nothing more is sent to a revoked identity);
    an identity that leaves the allowlist gets 0x98.
12. **CONNACK properties.** Receive Maximum, Maximum Packet Size (the listener's), Topic Alias Maximum (when > 0),
    Retain Available 0 (login roles without `retain`), Subscription Identifier and Shared Subscription Available 0,
    Session Expiry Interval when it differs from the request, Server Keep Alive when `mqtt5.max_keep_alive_s` holds a
    client to less (or to it, for keep alive 0), Assigned Client Identifier (TLS: the certificate's identity; a login:
    the generated tail; the development port: `auto-N`). Maximum QoS, Wildcard Subscription Available and Response
    Information are not sent (QoS 2 and wildcards are available; no response information).
13. **Store schema 4** (`crates/store/src/schema.rs`): columns added, no table rebuilt (the CHECK constraints of schema 3 stay
    right): `sessions.expiry_s` (NULL for older rows), `sessions.offline_since`, `subscriptions.options` (older rows:
    their QoS), `retained.props`, `retained.expires_at`, `queued.props`, `queued.expires_at`. A stored property block is
    validated again at restore (dropped if it does not validate; the message is kept).
14. **Kernel.** `crates/kernel/src/mqtt5.rs`: the login paths (plaintext, WebSocket password, development port) peek
    at the CONNECT with the decoder its level picks and answer a refused 5.0 login with a 5.0 CONNACK; the restore;
    the per-shard `$SYS` counters. `$SYS/broker/clients/connected/v311` and `/v5` (*deviation* from the name
    `clients/mqtt5`), `messages/expired`, `messages/dropped/too_large`, `sessions/expired` and `/expiring`,
    `wills/delayed` and `/pending`, `disconnects/sent/0xNN` and `connections/refused/v5/0xNN` (fixed lists, `other`
    for the rest), the same in the info query and two `status` lines.
15. **Configuration format 12**: the `[mqtt5]` keys of rule 21 and `limits.max_session_expiry_s`,
    `limits.default_session_expiry_s`, `limits.max_message_expiry_s`. `mqtt5.shared_subscriptions` and
    `mqtt5.subscription_identifiers` are accepted and reserved: part 3 gives them effect (no format bump then).
    Formats 8 (ADR-269), 9 (ADR-272), 11 (ADR-270) and 12 are valid; 10, which no format ever had, is refused like
    an unknown version (`urmqtt_cfg::blob::UNUSED_VERSION`), by the parser and by `finish_as`.
16. **A broker-closed connection ends its session at once** (*found by the Paho suite*, both versions). When the
    broker asks to close a connection (keep alive, a protocol error, a takeover, a 5.0 DISCONNECT), the kernel used
    to end the broker session, and so publish the Will, only when TCP was done; a client that never closes its socket
    held that back until the FIN_WAIT2 timeout. Now the session ends when its last bytes are handed to TCP (locally,
    and on the home core of a relayed connection, whose transport core then finds no relay when TCP is done).
17. **With publisher back-pressure** (ADR-269, merged before this part). The held input of a paused publisher goes
    through the same version dispatch as live input (`Broker::parse` picks the codec per connection), so a paused
    5.0 publisher's PINGREQ, PUBREL, PUBCOMP and QoS 2 PUBLISHes wait at most 500 ms and are then parsed as 5.0; the
    Receive Maximum counts them as without the pause (`v5_tests::a_paused_5_0_publisher_is_answered_within_the_bound`).
    No Local skips are not recipients: a message whose only other match is its publisher's own No Local subscription
    has none and never pauses anyone. A held connection is exempt from the keep alive for both versions (no
    DISCONNECT 0x8D while held). `Conn` keeps its 48 B with the back-pressure bytes and the 5.0 refusal code by
    storing the keep alive in seconds (`u16`) instead of milliseconds.

### Memory

`Conn` stays 48 B and `Session` 64 B. A 3.1.1 connection pays nothing new at rest; with a Will its `Extra` box is 72 B
instead of 56 (the Will's delay and expiry, the `V5State` pointer). A 5.0 connection keeps an `Extra` (72 B) and a
`V5State` (24 B) for its life, about 96 B of heap more than an idle 3.1.1 one, plus the alias table once used. Each
session waiting for its expiry or an armed Will costs two B-tree entries. `MsgInner` is 24 B larger per message.
Measured (HVF, 4 vCPU, 2000 mTLS connections each with one QoS 1 subscription, `urmqtt-loadgen hold --subscribe 1`,
`--mqtt5 1` for 5.0, the first full `mem:` report): the previous kernel 494 B per connection in heap blocks (468 B
requested), this one 509 B (477 B) for 3.1.1 and 670 B (573 B) for 5.0. The 3.1.1 difference is no per-connection
cost: it is the new retained `$SYS` topics, about 18 KiB over three shards whatever the connection count; 5.0 adds
96 B requested (161 B in blocks) per connection.

### Verification

Unit tests per rule and reason-code path (`crates/broker/src/v5_tests.rs`, 35), `qos2_model` with half its cases a
5.0 device (Receive Maximum both ways, session expiry with time and restarts), `acl_model` with mixed versions, the
ACL oracle (`broker_acl`) with 5.0 operations and checks for No Local, Retain As Published, Retain Handling, message
and session expiry and the 5.0 window (mutation-checked against broken broker variants), new seeds for `broker_input`
and `broker_acl`, store golden files and power-cut tests for schema 3 to 4, the smoke group `mqtt5` (paho-mqtt 2.x
and mosquitto clients over mTLS, a restart on the same disk, an image with `mqtt5.enabled = false`), a schema 3 disk
written by the previous kernel booted by this one (`scripts/mqtt5-migration-check.sh`), and the Paho interoperability
suite over the plaintext listener and the development port (`scripts/mqtt5-conformance.sh`, results in
docs/MQTT5-CONFORMANCE.md).

## ADR-275 — MQTT 5.0 part 3: shared subscriptions, subscription identifiers, and what part 2 left open (NEXT-3)

- **Status:** Accepted (part 3 of NEXT-3; NEXT-3 is done with it). Implements ADR-273 rules 15 to 17 and the part-3
  rows of rule 21, closes the "not done" list of ADR-274, and records every departure (marked *deviation*) and every
  question ADR-273 left open (marked *decided*). ADR-276 to 278 stay free.
- **Context.** After part 2 a `$share/` filter got SUBACK 0x9E, a Subscription Identifier 0xA1, and CONNACK said
  both were unavailable. ADR-274 also left: retained messages expiring only when read, Wills not persisted, a revoked
  certificate cut without a DISCONNECT, five reason codes never sent, the topic-alias tables outside the memory
  accounting, and the cross-core ordering of a SUBACK against another client's PUBLISH.

### Shared subscriptions (ADR-273 rule 16)

1. **As decided.** `$share/{group}/{filter}`: a group is (role class, group, filter), the role class being device,
   service, operator, bootstrap, plaintext or WebSocket login, so a device can never join a service's group (a
   device group and a service group of the same name and filter are two groups and each gets every message). The
   group lives on its **owner**, the worker shard `first + fnv1a(class, group, filter) % workers`
   (`crates/broker/src/shared.rs`, `Broker::set_shards`). Every message is offered to every shard already (ADR-032),
   so the owner sees each one once and hands it to one member: round robin over the members that are online. The
   member's own shard delivers it, with the QoS and options of that member's subscription: a
   `SharedMsg::Deliver` over the mesh (`CoreMsg::Shared`) carries the message's `Arc`, so a delivery costs no copy;
   the owner keeps 12 bytes per member and one entry per group. A shard that owns no group pays one branch per message.
   The mesh is bounded as for routes: a QoS 0 delivery to a core whose backlog is over the QoS 0 route limit is
   dropped and counted with the dropped routes; joins, leaves and QoS 1 and 2 deliveries are always sent (QoS 1 and
   2 routes are not dropped either).
2. **Joining waits for the owner** (*decided*). A SUBSCRIBE whose group is owned by another shard sends a
   `Join` and parks its SUBACK until the owner's `Joined`; the connection's input is held meanwhile (a flow bit,
   `flow::WAIT_SUBACK`, beside ADR-269's), so the client's next packets keep their order. Two things follow: a limit
   refuses the join with SUBACK 0x97 instead of failing silently, and a message published after the SUBACK reached
   the subscriber finds the member at the owner (point 13). A SUBACK that got no answer in 2 s reports 0x80 for the
   open joins (the mesh does not lose messages: a bound, not a path that is taken). A group owned by the
   subscriber's own shard answers at once.
3. **QoS and redelivery** (*decided*). Delivered QoS = min(publish, the member's subscription). With no member online,
   QoS 0 is dropped (counted, `$SYS/broker/shared/messages/dropped`) and QoS 1 and 2 go to the queue of the next
   member in turn, which then can only be an offline persistent session (ADR-273 rule 16; the task text said
   "dropped" for both: the accepted ADR loses nothing a non-shared persistent subscription would keep, so it
   stands). A message handed to a member stays with it while its session lives (a persistent member gets it again
   with DUP after reconnecting). When a member's session **ends** (clean session closed, session expiry, a clean
   start) its QoS 1 messages in flight and everything still queued for it go back to the owner for another member
   (§4.8.2, SHOULD; `Redispatch`); QoS 2 in flight never [MQTT-4.8.2-5]. A delivery that finds its member gone (it
   left while the delivery was on the mesh) comes back (`Bounce`): the owner forgets that member and, for QoS 1 and
   2, picks another, at most `MAX_TRIES` = 4 times; QoS 0 is dropped (counted). The tag that ties a queued or
   in-flight message to its share is 4 bytes in the padding of `Flight` (still 16 B: RETAIN and the resend flag
   share a byte) and of the queue entry (16 B, a struct instead of the tuple); it is not stored, so a message of a
   queue restored at boot is not handed on if its session then ends.
4. **What else holds.** No retained message on a shared SUBSCRIBE (§4.8.2), whatever Retain Handling says (the
   other filters of the same SUBSCRIBE get theirs after the SUBACK). No Local on a share is a protocol error (the
   codec's, DISCONNECT 0x82). The ACL judges the filter after `$share/{group}/` with the subscribe rules (the group
   name is not a topic: `$share/devices/fleet/#` is the filter `fleet/#`). UNSUBSCRIBE leaves the group; a session
   that ends leaves all its groups; a takeover that resumes the session keeps its memberships; a session going
   offline or coming back tells the owners (`Presence`). A Will is routed like any message and reaches one member
   per group. A group whose last member left is deleted (its id is never reused, so a late `Bounce` cannot reach
   another group).
5. **Both protocol versions** (*deviation*: ADR-273 spoke of 5.0). A 3.1.1 client may use `$share/` too, as
   Mosquitto, EMQX and HiveMQ allow; a malformed share from a 3.1.1 client (empty group or filter, a wildcard in the
   group) gets 0x80. With `mqtt5.shared_subscriptions = false` a 5.0 client gets 0x9E, a 3.1.1 one 0x80.
6. **Limits** (format 13): `limits.max_shared_groups` (groups one shard may own) and
   `limits.max_shared_group_members` (members per group), 1 to 65 535, 1024 by default: a join over either gets
   SUBACK 0x97 (`$SYS/broker/shared/joins/refused`). A shared subscription also counts against
   `limits.max_subscriptions_per_session`. Worst case per owner shard: about 120 B and the name and filter twice per
   group, 12 B per member.
7. **Persistence.** A shared subscription of a persistent session is a row of `subscriptions` like any other (its
   filter `$share/...`); at boot it is restored (ACL and limits checked again, and dropped with its identifier
   when the configuration turned the feature off) and joins its group offline.
8. **Announced.** CONNACK leaves Shared Subscription Available and Subscription Identifier Available out (they mean 1
   then) unless configured off, when it says 0.
9. **`$SYS`.** `shared/groups`, `shared/members` (on their owners), `shared/messages/delivered`, `/dropped`,
   `/redispatched`, `shared/joins/refused`; the same in the info query and a `status` line. A share of `$SYS/...`
   (operators) sees only the `$SYS` messages of its owner shard: every shard publishes its own (O1), only the
   owner's reach the group.

### Subscription identifiers (ADR-273 rule 17)

10. **One per subscription, in a side map** (`Broker::sub_ids`, keyed by session, trie and node; only sessions that
    use identifiers have entries). A SUBSCRIBE's identifier applies to each of its filters; re-subscribing replaces
    it, re-subscribing without one removes it. The identifiers are looked up when the PUBLISH is written: one
    PUBLISH per message and session carries the identifiers of **all** its matching ordinary subscriptions (the
    form the Paho suite expects, `test_subscribe_identifiers`; Mosquitto sends one PUBLISH per subscription
    instead); a delivery through a shared subscription carries that subscription's identifier alone; a retained
    replay, a queued message and a resend carry the identifiers the session's subscriptions have when it is
    written; a 3.1.1 subscriber never sees one. They count against the client's Maximum Packet Size (a delivery
    they push over it is dropped as if sent, as in ADR-274). *Decided*: no key of their own; the number per client
    is bounded by `limits.max_subscriptions_per_session`, each at most 268 435 455 (0 is the codec's protocol
    error). The common path does not change: a session without identifiers costs one empty-map test per PUBLISH,
    and the QoS 0 and 1 routing of 3.1.1 traffic still makes 9 and 15 allocations per message
    (`tests/qos01_allocs.rs`).
11. **Persistence:** the new column `subscriptions.sub_id` (schema 5, point 15).

### Enhanced authentication (ADR-273 rule 15): final

12. Refused, as decided by the owner. A CONNECT with an Authentication Method (with or without Authentication Data)
    gets CONNACK 0x8C "enhanced authentication is not supported" and is closed; an AUTH after a CONNECT without a
    method is DISCONNECT 0x82; an AUTH as the first packet is closed without an answer (no CONNECT, so no CONNACK).
    `mqtt5.auth_methods` stays unimplemented (no key): SCRAM-SHA-256 over the plaintext accounts remains the
    candidate when someone needs it, with its own ADR.

### What part 2 left open

13. **Cross-core ordering** (*decided*). For an ordinary subscription nothing is missed in the order that matters:
    the SUBACK is written after the subscription is in its shard's trie, and every message reaches that shard after
    it was published, so a message published after the SUBACK reached the subscriber's client (or anyone it told)
    is delivered. What the broker does not order is two connections that do not wait for each other: a client that
    publishes right after sending another connection's SUBSCRIBE, without waiting for that SUBACK, can be routed
    before the SUBSCRIBE is read on a different core (the Paho suite does this in two tests, docs/MQTT5-CONFORMANCE.md
    "Ordering"); MQTT promises no order between connections. Shared subscriptions are the one place where a SUBACK
    could come before the subscription is in effect (the member is installed on another shard), and there the SUBACK
    waits for the owner (point 2). KNOWN-ISSUES says this.
14. **Retained-message expiry** (*decided*: both). A sweep in `Broker::tick` (every 100 ms): retained messages with
    a Message Expiry Interval are kept in a deadline set by topic (`expiry::TopicDeadlines`, one entry per topic: a
    topic republished often costs one), and at most `SWEEP_PER_TICK` = 64 due ones are cleared per tick, so an
    expiry storm stays within the watchdog's budget; the check on read stays. Every shard clears its replica; the
    first worker shard alone tells the store (one deletion per expiry, not one per shard).
    `$SYS/broker/retained/expiring` (the largest count of a shard: each holds a replica).
15. **Wills across a restart** (*decided*: documented, not built). A Will, armed or waiting for its delay, lives in
    RAM; a broker restart loses it (KNOWN-ISSUES). Storing it would add a store write to every CONNECT with a Will
    and a deletion to every clean DISCONNECT, for the case of a broker that dies while the client also does; after a
    restart the clients reconnect and their sessions are found again.
16. **A revoked certificate gets DISCONNECT 0x98** (Administrative action) from the broker that holds its session,
    then the close: the transport core asks the home core (`CoreMsg::Revoked`) or the local broker
    (`Broker::disconnect_conn`), and cuts the connection itself after 1 s whatever happens (`REVOKE_GRACE_MS`). A
    connection still in its handshake or before its CONNECT is cut at once, as before.
17. **The reason codes part 2 never sent.**
    - 0x8B Server shutting down: sent. The console's `reboot` sets a flag every shard sees within its next pass;
      each tells its 5.0 clients DISCONNECT 0x8B and closes them during the 1 s the reboot waits
      (`Broker::shut_down`, logged per core). *Decided*: from then on no Will is published or armed: the reboot is
      not the clients' failure, a reset broker never sent them either, and a persistent session is found again
      after the restart. 3.1.1 has no way to say it; its connections end with the reset.
    - 0x96 Message rate too high: not sent, by design: no rate limit closes a connection. Over the per-session rate a
      PUBLISH is refused with 0x97 (Quota exceeded) in its PUBACK or PUBREC and the connection stays.
    - 0x89 Server busy, 0x8A Banned, 0x9F Connection rate exceeded: not sent, by design. Admission (memory, the
      handshake and connection limits), the plaintext lock-out and the login rate act on the SYN or the accept
      (ADR-080, ADR-230, ADR-267), before there is a CONNECT to answer; reading a CONNECT first would spend what
      they protect (a TLS handshake, a buffer). A refused password is 0x86 and an allowlist refusal 0x87 at
      CONNECT, as in part 2.
18. **Topic-alias tables are counted** (ADR-274 point 9's deviation removed). `Stats::alias_bytes` follows each
    table (16 B per slot, allocated on the first alias, plus the topics) and is released when the connection
    closes; `$SYS/broker/memory/topic_aliases`. Per connection it is at most `mqtt5.topic_alias_maximum` × (16 +
    `limits.max_topic_len`), 2 720 B with the defaults; the heap admission (M16) sees it like every other
    allocation.

### Store, configuration, kernel

19. **Store schema 5** (`crates/store/src/schema.rs`): `subscriptions.sub_id INTEGER NOT NULL DEFAULT 0 CHECK (sub_id
    BETWEEN 0 AND 268435455)`, added in the migration's transaction (no rebuild). `Store::subscribe_v5`;
    `SessionRecord.sub_ids`. Golden files: `schema4-mqtt5` is frozen (the input of the 4 to 5 migration),
    `schema5-shared` is what the code writes now, `v2-data-schema5` likewise; tests: schema 4 migrates keeping every
    row, the CHECK holds, a power cut at every write of the migration leaves schema 4 or 5 with every row, the
    frozen schema 5 image reads back; the 2 to 5 and 3 to 5 paths see every intermediate version.
20. **Configuration format 13** (`crates/cfg`, tags 260 and 261): `limits.max_shared_groups`,
    `limits.max_shared_group_members`; formats 8, 9, 11, 12 and 13 are valid, 10 is refused. The part-3 keys of
    format 12, `mqtt5.shared_subscriptions` and `mqtt5.subscription_identifiers`, now take effect (no format
    change). The builder page has both limits (shown while shared subscriptions are on) and keeps
    `mqtt5.shared_subscriptions` shown with MQTT 5.0 off, since 3.1.1 clients share too.
21. **Kernel.** `CoreMsg::Shared` and `CoreMsg::Revoked`; each worker shard is named before the restore
    (`set_shards`), so restored shared subscriptions join their groups; the store gets and restores the
    identifiers; the part-3 counters per shard in `$SYS`.

### Verification

Unit tests in `crates/broker/src/shared_tests.rs` (20: identifiers per rule, shares on one shard and across three,
the SUBACK and next packet held until the owner answers, a refused join, members gone, clean and persistent members
that leave with unacknowledged messages, 0x8B, 0x98, enhanced authentication in every form, the alias accounting, the
retained sweep); a new reference-model proptest `tests/shared_model.rs` (three shards, devices and services, every
delivery attributed by its identifier: each group exactly once through one member, never across roles; ordinary
subscriptions one copy with all identifiers; mutation-checked); the ACL oracle (`broker_acl`) with shares and
identifiers, `acl_model` with shared filters, `qos2_model` with a shared backend; new fuzz seeds; store golden and
power-cut tests; the smoke group `mqtt5` extended (part-3 scenarios over mTLS, the restart, a four-vCPU image with a
group of paho and mosquitto workers on the development port); the Paho suite (docs/MQTT5-CONFORMANCE.md). The
results of the runs are in docs/MQTT5-CONFORMANCE.md and in the branch report.

### For the owner

(a) No Will at `reboot` (point 17). (b) Shared subscriptions for 3.1.1 clients (point 5). (c) No member online:
QoS 1/2 queued for an offline persistent member rather than dropped (point 3). (d) `limits.max_shared_groups` per
shard rather than per broker (point 6). (e) Wills are not persisted (point 15).

## ADR-305 — DMA remapping: VT-d, AMD-Vi and SMMUv3 behind `devices.iommu` (LATER-5, H4b)

- **Status:** Accepted (LATER-5). Supersedes the deferral of ADR-176 for the code; bare metal itself stays
  deferred (LATER-4). ADR-306 is the fault path, ADR-307 the verification and what is not done. ADR-308 and
  ADR-309 stay free.
- **Context.** Every device the kernel drives could write anywhere in RAM: a buggy or hostile device (on bare
  metal its firmware; in a VM a device model of a hypervisor that is not trusted) reaches the page tables, the
  key slab and the code. The firmware describes the machine's IOMMUs in ACPI (DMAR for Intel VT-d, IVRS for
  AMD-Vi, IORT for Arm SMMUv3) or in the device tree (`arm,smmu-v3` and the PCIe host's `iommu-map`). QEMU
  emulates all three (`intel-iommu`, `amd-iommu,dma-remap=on`, `virt,iommu=smmuv3`).

### Decisions

1. **One key, three words, `off` by default.** `devices.iommu = "off" | "auto" | "require"` (configuration
   format 18, tag 318). `off` leaves the IOMMU exactly as the firmware left it (in practice: translation off)
   and only names it in the log: the behaviour of v0.5.0. `auto` brings up every unit the firmware describes
   and goes on, with a warning, where it cannot (no IOMMU, a unit that fails, a device outside every unit's
   scope or bypassing it). `require` turns each of those into a refusal to boot with the reason.
   *Decided* (the owner was away): the default is `off`, not `auto`. The release targets KVM VPSes, whose
   devices are the hypervisor's (trusted, ADR-176); an emulated IOMMU costs every DMA a table walk in the
   device model, which would silently slow a host that happens to expose one; and an existing configuration
   must behave as before. Bare metal, or a host whose device models are not trusted, should say `require`
   (OPERATE.md). When bare metal is supported (LATER-4) the default for a bare-metal image is the owner's
   call; this ADR recommends `require` there.
2. **Where it sits in the boot.** After the PCI scan and before the first driver: `iommu::init` brings every
   unit up with translation on and **nothing mapped**, so from that moment every device's DMA (including one a
   firmware left running) is blocked. A unit that was already enabled by the firmware is turned off first and
   reprogrammed. The register frames are mapped like any MMIO, before the page tables lock.
3. **A domain per device, identity mapped, only its own pages.** Every DMA allocation of a driver goes through
   `devices::KernelEnv`, which now knows the device it allocates for (`KernelEnv::device(bdf)`); the first
   allocation creates the device's domain (VT-d context entry and domain ID, AMD-Vi device table entry and
   domain, SMMUv3 stream table entry, context descriptor and ASID) and each allocation maps exactly its pages,
   read-write, at I/O virtual address = physical address. Nothing is ever unmapped: the kernel's DMA memory
   lives as long as the device. Work after bring-up uses `KernelEnv::RUNTIME`, which allocates nothing; an
   allocation for no named device is mapped nowhere and warned about once. Identity mapping keeps every driver
   unchanged (the address a driver gives the device is the same with and without translation) and makes the
   choice of `off` safe at any time.
4. **Page tables.** One radix builder for three encodings (`crates/iommu/src/pt.rs`): VT-d second-level
   tables (R/W on every level), AMD-Vi v1 host tables (PR, next level, IR/IW on every level), Arm VMSAv8-64
   stage 1 with a 4 KiB granule (AF set, never executable, inner-shareable write-back; MAIR index 1 device
   memory for the doorbell). 4 levels (48 bits) where the unit supports them, else 3 (39 bits); an address
   beyond is refused. 4 KiB pages only (no large pages: the mappings are small and exact).
5. **The drivers.** VT-d in legacy mode (root and context tables), register-based invalidation (global context
   cache and IOTLB after every change, which caching mode needs), the write-buffer flush where CAP asks;
   a unit whose firmware enabled interrupt remapping is refused (`auto` goes on without it) because taking it
   over needs the queued invalidation this driver does not implement. AMD-Vi with a device table for all 65 536
   IDs, every entry "valid, translation valid, mode 0, no read, no write" (blocked) until attached, a one-page
   command buffer (INVALIDATE_DEVTAB_ENTRY, INVALIDATE_IOMMU_PAGES, COMPLETION_WAIT with a store) and a
   one-page event log. SMMUv3 with a linear stream table sized for the highest stream ID the scan found, every
   entry invalid (abort) until attached, stage 1 through one context descriptor per stream (stage 2 is not
   in QEMU's default model and not needed), a 256-entry command queue (CFGI_STE, CFGI_ALL, TLBI_NH_ASID,
   TLBI_NSNH_ALL, CMD_SYNC with its error checked) and a 128-entry event queue. Every wait for a unit is
   bounded (100 ms) and a timeout is a bring-up failure. The drivers have no `unsafe`: registers are a
   `Regs` trait and the memory the unit reads an `Env` trait, implemented by `kernel/src/iommu.rs`.
6. **Coherency.** VT-d reports it (ECAP.C), SMMUv3 too (IDR0.COHACC); for a unit that does not snoop, every
   table and queue write is cleaned to the point of coherency (`urmqtt_arch::cache::clean_to_device`: `clflush`
   and `mfence`, or `dc cvac` and `dsb sy`). AMD-Vi walks are declared coherent (Control.Coherent).
7. **MSIs.** Interrupt remapping is not enabled on any unit (VT-d, AMD-Vi): with it off an MSI is an interrupt
   request, not a DMA, and passes as before. On a GIC an MSI is a write to the ITS's translation page or the
   GICv2m frame, which the SMMU translates like any DMA: that one page is mapped into every domain as device
   memory. With the ITS the device can only signal events of its own device ID; with a GICv2m frame it can
   raise any SPI of the frame (as without an IOMMU).
8. **virtio and VIRTIO_F_ACCESS_PLATFORM.** A virtio device that does not offer this feature uses physical
   addresses *around* the IOMMU (virtio 1.x §6; QEMU's devices do so unless `iommu_platform=on`). The transport
   now accepts the feature whenever it is offered (harmless without translation: the addresses are identity)
   and tells the environment; with translation active a device without it is a device without isolation:
   refused by `require`, warned about by `auto`.
9. **Scope from the firmware.** `crates/platform/src/iommu.rs` reduces DMAR, IVRS, IORT and the device tree to
   units (kind, register base, segment) with the requester IDs each translates and the ID it sees for them
   (the stream ID of an SMMU, the device ID of AMD-Vi, an alias where IVRS says so). An explicit scope wins over
   a unit that takes "all the rest". What a parser cannot represent is counted and never guessed: a DMAR scope
   behind a bridge, a variable-length IVRS entry it does not know (the rest of that block is not read), an IORT
   mapping flagged single. Nor is the catch-all unit guessed for an ID another unit may claim through such an
   entry (a bridge's scope: every bus above the bridge's; an unknown, truncated or dropped entry, or a dropped
   unit: every ID): such a device gets no unit, which `require` refuses, instead of a domain on the catch-all
   that its DMA never goes through (it would be blocked, or not translated at all behind a dropped unit, while
   the kernel counted it as isolated). Two functions the unit sees with the same ID (an IVRS alias) share one
   domain, said in the log and the summary line: the unit cannot tell them apart. Reserved regions the firmware asks to keep mapped (RMRR, IVMD, RMR) are counted and
   logged, not mapped: the kernel drives only virtio devices, which have none. At most 4 units and 32 ID ranges
   per unit (QEMU 11.1 lists every device of the root bus in DMAR and IVRS one by one). A table that fails its
   checksum means no IOMMU, and does not stop the rest of the discovery.
10. **What an operator sees.** At boot: the description (`iommu: VT-d@0xfed90000/0:... (devices.iommu =
   "require")`), each unit's bring-up, each device's domain, and one summary line (units, domains, pages
   mapped, KiB of tables, devices without isolation). `$SYS/broker/iommu/{mode,state,units,domains,pages,
   faults,overflows}`, an `iommu` object in the info query and a `status` line when the key is not `off`.
11. **Configuration format 18.** The only key of the format; `off` writes nothing, so every existing
   configuration keeps its format number and boots on v0.5.0. A blob of format 18 is refused by an older kernel
   by its version (it would run without the isolation it was told to require). Formats 14 to 17 belong to the
   other items of v0.6.0 and are unknown to this branch until the release merge (`blob::UNUSED_VERSIONS`).
   The tag is 318, away from the tags the other items take, so the merge does not collide.

### For the owner

(a) The default `off` (point 1). (b) `require` refuses a unit with firmware-enabled interrupt remapping
(point 5). (c) Reserved regions are not honoured (point 9): a real machine whose firmware lists an RMRR for a
device the kernel does not drive is unaffected; one for a driven device would be (none exists today).

## ADR-306 — IOMMU faults are polled, bounded, counted and logged; no fault interrupt (LATER-5, H4b)

- **Status:** Accepted (LATER-5).
- **Context.** A blocked DMA is recorded by the unit (VT-d fault recording registers, the AMD-Vi event log, the
  SMMUv3 event queue). A hostile device can produce faults as fast as it can issue requests; a fault must
  never be silently ignored and its handling must not be a way to stall a core.

1. **Polling, not interrupts.** Core 0's tick reads the fault logs every 100 ms (every tenth of core 0's own
   10 ms ticks: the global tick count interleaves every core's, so core 0 could see the same residue each time),
   trying the IOMMU lock only (a poll that meets the bring-up or a mapping is skipped). The fault-event
   interrupts stay masked (VT-d FECTL.IM, AMD-Vi EventIntEn off, SMMUv3 IRQ_CTRL 0). *Decided*: an interrupt
   would add an interrupt route per unit (an MSI of its own, which on aarch64 would itself go through the
   ITS) to tell the kernel something it only counts and logs; polling bounds the cost by construction.
2. **Bounded.** At most 16 records per unit per poll (the next poll continues), so a fault storm costs core 0
   at most 160 register or memory reads per unit per second. Indices from the unit are masked to its ring
   (AMD-Vi head and tail, SMMUv3 producer and consumer) and a garbage index reads nothing.
3. **Counted and logged.** Every record read is counted (`$SYS/broker/iommu/faults`) and acknowledged (VT-d
   F bit and PFO, AMD-Vi head and the overflow bit, which also restarts the stopped log, SMMUv3 consumer with
   the overflow flag acknowledged). The first 16 faults are logged one line each (`iommu: fault N: <unit>
   <base>: pci <bdf> write to|access to <address> blocked (reason <code>)`), then only every power of two, so
   a storm costs the log a few lines. A log overflow (faults lost) is counted
   (`$SYS/broker/iommu/overflows`) and logged.
4. **No action on a fault.** The device is not reset or detached: its DMA already did not happen, and the
   driver's own timeouts handle a device that stops answering. `require` does not stop the broker for a
   fault at run time: the isolation did its job.

## ADR-307 — IOMMU verification, and what LATER-5 does not do (LATER-5, H4b)

- **Status:** Accepted (LATER-5).

1. **Host tests.** `crates/platform/src/iommu_tests.rs` (DMAR, IVRS, IORT with QEMU's shapes, ranges,
   aliases, RMRR/IVMD, malformed and truncated tables, every prefix of every table), the QEMU `virt` DTB with
   an SMMUv3 (`tests/fixtures/qemu-virt-smmuv3.dtb`, `dumpdtb` of QEMU 11.1). `crates/iommu`: each driver
   against a model of its unit that walks the in-memory tables as the hardware would and answers DMA: only an
   attached device reaches only its pages (and on SMMUv3 the doorbell); unattached devices, other devices'
   pages, IDs beyond the tables are refused; bring-up with the firmware's state left on; a unit that never
   answers times out; fault and event decoding, bounds and overflow; domain and ASID limits. Configuration:
   format 18 written only for `auto` and `require`, refused by format 13 and by the unknown 17; the CLI's
   template check (a v0.5.0 template refuses a `devices.iommu` configuration with the reason); the builder
   page's model (`tools/builder/test/iommu.test.mjs`).
2. **Fuzzing.** `iommu_tables`: arbitrary bytes as DMAR, IVRS, IORT, a device tree, or unit fault records;
   ranges must stay inside the requester-ID space; seeds from QEMU's shapes. Two minutes: 14.6 million runs,
   no finding.
3. **QEMU smoke, `SMOKE_ONLY=iommu`.** Per IOMMU (aarch64: SMMUv3 under HVF and TCG, ACPI and device tree;
   x86_64: VT-d and AMD-Vi under TCG): `iommu-dma` with `require` and `test=iommu-dma` (dev only), which makes
   the entropy device write 64 bytes into a page outside its domain: the page must stay untouched, at least
   one fault counted, by core 0's tick alone within a second (the test runs after the tick starts, and reads
   the logs itself only after that second), the fault line name the device; `iommu-off control`, the same request with
   `devices.iommu = "off"`: the page is written (so the test can see a write); `iommu-mqtt`, the full MQTT
   round trip over mutual TLS (`mqtt-scenarios.py`) with every device translated and no fault. Then:
   `require` on a machine without an IOMMU and with a virtio device that bypasses it (no `iommu_platform`)
   refuses to boot with the reason; `auto` without one boots and warns. `scripts/run-qemu.sh --iommu
   intel|amd|smmuv3` adds the unit and `iommu_platform=on,disable-legacy=on` to every virtio device.
4. **Not done (listed, not hidden).**
   - No real hardware: VT-d, AMD-Vi and SMMUv3 ran only as QEMU 11.1 models. Bare metal stays LATER-4.
   - Interrupt remapping is not enabled (point 7 of ADR-305); a unit whose firmware enabled it is refused.
   - VT-d: no queued invalidation, no scalable mode, no 5-level tables, no device-TLB (ATS); AMD-Vi: no
     interrupt remapping, no exclusion range, no IOTLB (ATS); SMMUv3: no two-level stream table, no stage 2,
     no PRI or ATS, no stall model, and a non-coherent unit's cache maintenance is untested (QEMU's are
     coherent).
   - RMRR, IVMD and RMR are counted, not mapped; DMAR scopes behind a bridge are not followed.
   - At most 4 units and 32 ID ranges per unit; more are counted and their devices are not translated, nor
     given to the catch-all unit, so `require` refuses them.
   - QEMU's AMD-Vi model writes its IO_PAGE_FAULT events in a layout where this decoder reads address 0 and
     no write flag; the device and the event type are right. Checked against the specification only.
   - The cost of translation is not measured: an emulated IOMMU makes every DMA a table walk in QEMU, real
     hardware has IOTLBs; `make bench` was not run with an IOMMU.
   - intel-iommu under KVM needs the split irqchip (`run-qemu.sh` adds it); not run here (no KVM host).
   - Fault interrupts (ADR-306) and unmapping are deliberately absent.
