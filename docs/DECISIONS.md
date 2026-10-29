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

- **Status:** Accepted (X0); the hardware backends follow in X0b (AArch64) and X9 (x86).
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
