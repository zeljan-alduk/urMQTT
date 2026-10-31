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
  - Core 0 has no RX interrupt yet (MSI-X for virtio-net is a later item), so the first packet after an idle period waits for the 10 ms tick.
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

- **Status:** Accepted. Supersedes item (4) of "Dropped after measuring" in ADR-111 (a BMI2/ADX field multiplier, then estimated at an uncertain 1.2-1.4x; measured here at 3-5x for the operations that matter) and extends ADR-110/111 on x86_64.
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
