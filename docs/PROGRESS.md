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

## M4 — SMP (2026-10-29)

**Done**

- `kernel/smp`:
  - Per-CPU data indexed by `TPIDR_EL1`.
  - AP bring-up through Limine MP with an assembly entry that mirrors the boot CPU's MMU, PAC, vector and stack configuration (ADR-023).
  - Per-core redistributor and CPU interface.
  - Per-core tick on each core's own virtual timer.
  - Per-core idle loop (WFI, or busy-poll during tests) that runs work posted by the boot CPU.
- SGI IPIs (ping, pong, wake) and an IPI self-test. Every core pings every other core and waits for the pong, covering all ordered pairs, with round-trip times measured.
- `gic::send_sgi` targets a single MPIDR (with the range selector), and `dsb ishst` orders data before the IPI.
- `vm::map_stacks` maps every AP's stacks (with guard pages) before the page tables lock.
- `make run-smp N=8` boots eight cores. Smoke covers 4 CPUs in every boot scenario plus a dedicated 8-CPU scenario.

**Measured**

- HVF, 8 vCPUs: 8/8 online, **56/56 ordered pairs ok**, IPI round trip avg 12–13 µs (max 29–66 µs).
- TCG, 8 vCPUs: 56/56, avg 23 µs.
- HVF, 4 vCPUs: 12/12, avg 11 µs.
- Every core ticks on its own timer (checked over 5 ticks).
- `make smoke`: 26/26.
- Kernel ELF: **144 400 bytes**.

**Known gaps**

- The per-CPU log rings described in §4.2 are not in yet; all cores share the IRQ-safe global logger. The per-core loop arrives with the data plane (M13).
- APs only idle. Data-plane work starts in M13; the DB core assignment (highest-numbered CPU) lands with SQLite in M11.

## M5 — Platform discovery (2026-10-29)

**Done**

- `platform::PlatformInfo` (ADR-024): UART, PSCI, GICv3 (GICD, GICR, ITS / GICv2m), timer PPIs, CPU list (MPIDR, up to 64) and PCIe ECAM (segment, bus range).
  - DTB path: `/cpus` nodes, `pci-host-ecam-generic` with `bus-range`.
  - ACPI path: MADT GICC MPIDRs (enabled and online-capable only), MCFG.
- Source-independent `Display` summary, logged at boot as `platform summary: …`. The kernel warns if the firmware's CPU list and the bootloader's MP list disagree.
- Fuzz targets `fdt_parse` and `acpi_parse` (ACPI over an arbitrary memory blob). The first found an integer overflow, now fixed and kept as a regression seed.
- Smoke compares the acpi=on and acpi=off summaries for every accelerator.

**Measured**

- Summary under both HVF and TCG, identical for acpi=on and acpi=off:
  `uart=0x9000000 psci=hvc gicd=0x8000000 gicr=0x80a0000 msi=v2m@0x8020000 timer=27/30 cpus=4[0x0,0x1,0x2,0x3] pcie=0x4010000000/0:0-255` (under TCG `msi=its@0x8080000`).
- Fuzzing after the fix: `fdt_parse` 2.6 M runs in 2 min, `acpi_parse` 100 M runs in 1 min, no crash.
- `make smoke`: 28/28.

**Known gaps**

- ACPI-only cloud validation (Hetzner, Oracle) is deferred (PROMPT §9 "later").
- PCI BAR windows are not discovered by design (ADR-024).

## M6 — PCIe and virtio (2026-10-29)

**Done**

- `pci` (host-tested against a simulated bus):
  - ECAM addressing, enumeration through bridges (bounded, loop-safe), multifunction devices, BAR decoding (32/64-bit, I/O).
  - Bounded capability-list walk, MSI-X table location, enable and entries.
- `virtio` (host-tested, including a simulated device and hostile used-ring values):
  - Modern virtio-pci capability discovery, feature negotiation, queue setup and notification with `dsb st`.
  - Split virtqueue with bounds-checked ring access.
  - Drivers: virtio-rng, virtio-blk (read/write/flush, FLUSH, RO and BLK_SIZE features), virtio-net (one queue pair, MAC, link status).
- `tls::rng`: ChaCha20 CSPRNG behind a SHA-256 entropy pool that requires a hardware source (ADR-025).
- `kernel/devices`:
  - The 256 MiB ECAM is mapped with 2 MiB device blocks; enumeration is logged per function.
  - Virtio regions mapped from firmware-assigned BARs; DMA from contiguous frames.
  - GICv2m MSI-X for virtio-blk.
  - Entropy pool fed from virtio-rng, RNDR and the bootloader.
  - Boot self-tests:
    - blk: 4 KiB random pattern written, flushed, read back, compared.
    - net: gratuitous ARP, plus an ARP request for 10.0.2.2 whose reply must arrive.
- `run-qemu.sh --fwd`. Every smoke boot gets a fresh 64 MiB data disk and a pcap, and a Python pcap check looks for the gratuitous ARP from 52:54:00:12:34:56.

**Measured**

- QEMU `virt` enumerates 5 functions (host bridge, virtio-scsi CD, rng, blk, net), identically under HVF and TCG.
- Under HVF: MSI-X via GICv2m SPIs 80..144, 3 blk completion interrupts per self-test. Under TCG (ITS only) blk is polled.
- Under TCG both virtio-rng and RNDR contribute; under HVF only virtio-rng.
- `make smoke`: 30/30 (13 scenarios × 2 accelerators + pcap ARP check + summary comparison, each per accelerator).
- Kernel ELF: about **212 KB**: sha2, ChaCha, pci, virtio and the drivers.

**Known gaps**

- No ITS driver yet, so no MSI-X on KVM or TCG (M13).
- virtio-net has one queue pair and no interrupts; multiqueue and RSS come in M13.
- Requests are synchronous. Batched, asynchronous blk I/O for SQLite and the telemetry log comes in M11/M12.

## M7 — Network prototype on smoltcp (2026-10-29)

**Done**

- `kernel/netproto`: smoltcp interface over virtio-net (ADR-026).
  - DHCPv4 client: lease, router and DNS are logged; a lost lease is handled.
  - ARP and ICMP: an echo request goes to the router and the reply round trip is logged.
  - TCP echo service on port 7 (dev only, 4 sockets), closing cleanly when the peer half-closes.
- `smoke.sh` `service` scenarios: boot without powering off, wait for a ready pattern, run a host client through the QEMU port forward, stop QEMU, check the serial log plus the client output. `scripts/echo-client.py` echoes 1, 3000 and 60 000 random bytes.

**Measured**

- DHCP lease `10.0.2.15/24 router 10.0.2.2 dns [10.0.2.3]` about 10 ms after the service starts.
- ICMP RTT to the slirp gateway: about 9 ms under HVF. That is dominated by the polled RX path while the core sleeps in WFI (ADR-022).
- Echo of 1, 3000 and 60 000 bytes byte-exact under HVF and TCG.
- `make smoke`: 32/32.
- Kernel ELF: **294 000 bytes** (smoltcp adds about 80 KB).

**Known gaps**

- No RX interrupts (still polled), one core, one queue: by design for this phase (PROMPT §5.1).
- The prototype stack is not fuzzed; the own stack gets fuzz targets in M14.

## M8 — MQTT 3.1.1 codec (2026-10-29)

**Done**

- `crates/mqtt`: complete MQTT 3.1.1 decoder and encoder covering all 14 packet types (ADR-027).
  - `no_std`, `forbid(unsafe_code)`, clippy-denied unwrap/indexing/panic, no allocation.
  - Zero-copy: packets borrow from the input; SUBSCRIBE/UNSUBSCRIBE keep validated raw payloads with iterators.
  - Streaming: `Incomplete(n)` gives the exact total size needed.
  - Limits: packet size (checked before the body arrives), topic length and levels, client-id length, topics per packet.
  - `topic_matches` implements §4.7 including the `$`-topic rule.
- Tests:
  - 20 unit tests built from spec byte vectors and edge cases. Every prefix of a valid packet returns `Incomplete`, and back-to-back packets are split correctly.
  - Property tests: PUBLISH/CONNECT/SUBSCRIBE/UNSUBSCRIBE round trips, plus arbitrary and mutated bytes never panicking.
  - Interop tests (`tests/interop.rs`) run real `mosquitto_pub` and `mosquitto_sub` against an in-test server built only on this crate: CONNECT with will, credentials and keepalive; PUBLISH QoS 1 with retain → PUBACK; SUBSCRIBE with two filters → SUBACK; server PUBLISH QoS 1 → client PUBACK and the message printed. CI installs the mosquitto clients on Linux and macOS.
- Fuzz target `mqtt_decode` with seeds: stream decoding plus a round-trip assertion.

**Measured**

- `make fuzz T=mqtt_decode FUZZ_TIME=600`: **33 621 279 runs in 601 s** (about 56 k/s), coverage 678 edges, corpus 448 inputs. No crash.
- Host tests: 128.

## M9 — Broker over plain TCP, dev only (2026-10-29)

**Done**

- `crates/broker` (sans-IO, `no_std` + `alloc`, `forbid(unsafe_code)`, ADR-028):
  - Topic trie with interned `NodeId`s, holding subscriptions and retained messages, with the `$` rule.
  - Sessions, clean or persistent, with QoS 1 in-flight windows, bounded offline queues and DUP redelivery.
  - Last Will, keepalive, session takeover.
  - ACL with `{id}` and coverage checks for subscriptions; service identities.
  - Per-session token-bucket rate limit, plus limits on packet size, topic length, levels, subscriptions, in-flight, queue, connections and output backpressure.
  - Payloads stored once and shared through `Arc`.
- 20 end-to-end host tests over an in-memory transport, feeding byte by byte where the length allows: CONNECT rules and CONNACK codes, protocol violations, pub/sub with wildcards and ACL, retained set/deliver/clear, `$` topics, will vs DISCONNECT, keepalive expiry, QoS 1 redelivery with DUP after reconnect, window and queue bounds, subscription limit and unsubscribe, takeover, rate limit, QoS 2 refusal, oversized packets, 200 concurrent sessions.
- New config keys `acl.service_ids`, `acl.service_publish`, `acl.service_subscribe` (dev and prod: `backend`).
- `kernel/mqtt_plain`: 32 smoltcp sockets on `network.mqtt_plain_port` (dev only) pumping the broker, with clean versus unclean close detection and per-disconnect logs.
- `scripts/mqtt-scenarios.py`: real `mosquitto_pub`/`mosquitto_sub` scenarios, also used by M10 with `--tls`.

**Measured**

- `make smoke`: 34/34. `mqtt-plain` passes under HVF and TCG: pub/sub through a wildcard, retained, LWT after `SIGKILL`ing the client, QoS 1 delivered after reconnect to a persistent session, ACL-denied subscribe ("All subscription requests were denied.").
- Kernel ELF: **358 400 bytes**.

**Known gaps**

- Topic nodes are never pruned (memory grows with distinct topics; M15).
- Retained messages and persistent sessions live in RAM only until SQLite arrives (M11).
- One core (M13).

## M10 — TLS 1.3 with mutual TLS (2026-10-29)

**Done**

- `crates/tls` (`no_std` + `alloc`, ADR-029):
  - rustls 0.23 unbuffered server handshake with our own RustCrypto provider (X25519/P-256 key exchange, AES-128-GCM and ChaCha20-Poly1305, ECDSA P-256 signatures). All randomness comes from the kernel CSPRNG.
  - Traffic secrets captured through `KeyLog`, then the rustls connection is dropped.
  - Own record layer with sequence numbers, KeyUpdate in both directions and `close_notify`.
  - Client certificates verified against the embedded CA, plus a build-time revocation list (`tls.revocation_list`) and expiry against the boot wall clock.
  - Identity from CN or SAN URI (`urn:urmqtt:device:` / `urn:urmqtt:service:`).
  - Stateless resumption tickets; key derived from the server key and version.
- `kernel/mqtt_service` (replaces `mqtt_plain`):
  - 32 TLS slots on `network.mqtt_tls_port`, plus 16 plaintext slots in dev builds only.
  - Handshake admission control (token bucket), a 10 s handshake timeout, and the identity handed to the broker before CONNECT.
  - Clean `close_notify` + FIN.
  - Logs `tls: <id> authenticated (<suite>[, resumed])` and `tls: connection refused: <reason>`.
- Config:
  - `tls.revocation_list` (dev: `revoked.txt` from `make certs`, prod: empty).
  - Validation of the identity pattern.
  - The plaintext port stays build-time forbidden outside dev.
- `scripts/gen-dev-certs.sh`:
  - SAN URIs on device and service certificates, and a `services/backend` certificate.
  - A revoked device (`device-004`) whose serial goes to `revoked.txt`.
  - Requires OpenSSL ≥ 3, since LibreSSL cannot verify `urn:` SANs.
- Tests:
  - Unit: record layer against RFC 8448, identity extraction, serial normalisation.
  - Host interop (`tests/handshake.rs`), where a real rustls client drives our server:
    - mTLS, application data both ways, KeyUpdate and resumption all work.
    - The rogue CA, expired and revoked certificates are rejected, and garbage is rejected as not-TLS.
- Smoke scenario `mqtt-tls` (HVF and TCG). The real `mosquitto_pub` and `mosquitto_sub` (OpenSSL) run all five broker scenarios over mTLS. Then the four required rejections are each tested: wrong CA, expired certificate, client-id ≠ certificate identity, and revoked certificate.

**Measured**

- `make smoke`: **36/36** (new: `mqtt-tls` under HVF and TCG).
- 50 sequential `mosquitto_pub -q 1` runs over mTLS (process start, TCP, full handshake with client certificate, CONNECT, PUBLISH/PUBACK, close) under HVF on Apple silicon: **≈ 50 ms each**, end to end and single core. Negotiated suite: TLS13_CHACHA20_POLY1305_SHA256 (OpenSSL prefers it without AES hardware detection in the guest).
- Kernel ELF: **1 101 008 bytes** (M9: 358 400). Nearly all of the growth is rustls, webpki and the crypto crates.
- `cargo deny`: clean after moving to `p256` 0.14 (RUSTSEC-2026-0387 in `crypto-bigint` 0.5).

**Known gaps**

- Kernel ELF > 1 MB target (M15/M17: `opt-level = "s"` for crypto crates, dropping unused rustls paths).
- Record state ≈ 170 B per connection against the 128 B target (M15).
- Revocation is build-time only until the SQLite table (M11). Resumed sessions are not re-checked against revocations made after the ticket was issued.
- One handshake timeout instead of one per phase (M14).
- Handshakes run on the boot core only (M13).

## M11 — SQLite in the kernel (2026-10-29)

**Done**

- `vendor/sqlite`: SQLite 3.54.1 amalgamation. Checksums are verified by the build, and the upstream SHA3-256 is recorded.
- `crates/store` (ADR-030):
  - `build.rs`: the freestanding clang build matching the kernel ABI (FP, BTI/PAC, strict alignment) with the option set of ADR-030.
  - `libc.rs`: the seven `str*` symbols SQLite needs, in Rust.
  - `layout`: superblock + region table + double-buffered file-size table, CRC-32C (`crc`).
  - `disk`: byte-addressed region I/O with read-modify-write; sizes persisted at sync. `MemDisk` is a test device with a volatile cache and power-loss simulation.
  - `vfs`: the `urmqtt` VFS (three fixed files, no shared memory, conservative device characteristics).
  - `db`: a safe `Db`/`Stmt` wrapper.
  - `schema`: embedded migrations, now v1 with devices, revoked, retained, sessions, subscriptions, queued and selftest tables.
  - `store`: exclusive + WAL, verified; defensive mode; quick_check; migrations; and the prepared statements for the broker state.
- `crates/broker`: `PersistOp` events (retained, persistent sessions, subscriptions, offline queue) and `restore_retained` / `restore_session` with ACL and limit re-checks.
- `crates/arch-aarch64::spsc`: bounded lock-free SPSC ring with documented orderings, tested across two threads.
- `kernel/db`:
  - The store opens on the boot CPU before SMP (format if blank, quick_check, migrations), seeds revocations from the config, and loads the state for the broker and the TLS revocation set.
  - After SMP bring-up the worker moves to the DB core (the highest CPU) and batches into one transaction per 5 ms or 512 ops. It sleeps in `wfe` with `sev` and the generic-timer event stream, and reports to the data plane over the response ring.
  - Self-tests: `test=db-bench`, `test=db-crash`, `test=db-verify`.
- `kernel/mqtt_service`:
  - Restores the broker at boot and forwards `PersistOp`s and device sightings over the request ring, with a backlog that keeps order when the ring is full.
  - The TLS revocation set now comes from the store.
- Config: `storage.require_data_disk` and `storage.refuse_on_corruption`. They (and `require_flush`) may be false only in dev.
- CI: clang and llvm are installed for every job that builds the kernel. New fuzz target `disk_layout`.

**Measured**

- `make smoke`: **48/48**. New checks, under HVF and TCG:
  - `db-bench`.
  - `db-crash-writer` → SIGKILL → `db-crash-recovery`: quick_check ok, every row consistent, and **every acknowledged commit present** (HVF 15 900 rows ≥ 15 000 logged; TCG 8 000 ≥ 7 000).
  - `mqtt-persist`: mosquitto over mTLS. A retained message and a QoS 1 command queued for an offline persistent session are delivered after SIGKILL and reboot; 3 devices are in the registry.
- Batched writes (`db-bench`, 200-byte rows, `synchronous=FULL`, 64 MiB data disk):

  | | 100 inserts per transaction | 1 insert per transaction |
  |---|---|---|
  | HVF (Apple M4) | **49 431 ops/s** (2.0 ms per commit) | 1 844 ops/s |
  | TCG | 40 221 ops/s (2.5 ms per commit) | 1 679 ops/s |

- `quick_check` at boot on the fresh or small database: 1–4 ms (HVF), 42 ms (TCG).
- Host crash tests: 12 rounds with an arbitrary subset of unflushed writes applied, then `integrity_check` = ok and no acknowledged commit lost.
- `make fuzz T=disk_layout FUZZ_TIME=30`: 4.57 M runs, no crash.
- SQLite object code: 654 KB text (`-Os`). Kernel ELF 1 938 432 bytes (M10: 1 101 008).
- Host tests: 180.

**Known gaps**

- In-flight QoS 1 state of online sessions is RAM-only (ADR-030).
- No session expiry.
- Runtime revocation (M16).
- Partial-sector writes cost a read per WAL frame (a VFS write cache would remove it; M15).
- The telemetry region is reserved but unused until M12.
- SQLite runs at EL1 (EL0 isolation is a later item).

## M12 — Telemetry log (2026-10-29)

**Done**

- `crates/store/telemetry` (ADR-031):
  - Header and 8 partitions of segment rings in the telemetry region.
  - Records with a CRC-32C salted by the segment sequence.
  - Batched, sector-aligned, zero-padded writes without read-modify-write.
  - Recovery with torn-tail truncation and a roll-over to a fresh segment.
  - Retention by size (ring) and age (`retention_days`).
  - `scan` for readers.
- `crates/broker`: PUBLISHes matching `storage.telemetry_topics` are handed out as `Arc` messages (`drain_telemetry`), after ACL and rate limits.
- `kernel/db`:
  - One telemetry SPSC ring per core to the DB core, which appends to the source core's partition and flushes every 5 ms or 256 KiB.
  - Durability reported on the response ring.
  - Self-tests: `test=log-crash` (every core but the DB core writes forever), `test=log-verify`, `test=log-tear`.
- `kernel/mqtt_service`: batches telemetry (256 records or 1 ms) into its core's ring and never blocks (bounded backlog, counted drops).
- Smoke:
  - `log-crash`: a 1 GiB sparse disk; SIGKILL after ≥ 1 M durable records.
  - `log-tear`.
  - `mqtt-persist` now also checks that a telemetry PUBLISH over mTLS is in the log after the restart.

**Measured**

- `make smoke`: **58/58**.
- `log-crash`, 3 writer cores + DB core, 42-byte records:
  - HVF: about **2.4 M records/s** (1.5 M durable 0.6 s after the writers started). Recovery found 1 480 704 ≥ 1 400 832 durable, in 0.14 s for about 1.6 M records.
  - TCG: 1 005 568 ≥ 1 005 568 durable.
  - Every core's sequence was contiguous.
  - No torn tail in the SIGKILL runs so far: the kill fell between flushes. Torn-tail truncation is shown by `log-tear` (10 500 complete records kept, 1 torn tail truncated, under HVF and TCG) and by the host tests.
- Kernel ELF: 1 976 424 bytes.

**Known gaps**

- No time-series or zstd encoding.
- No export/read API (M16).
- Age retention hides expired records but does not erase them before their segment is reused.
- With more than 8 cores, cores share partitions (the DB core still serialises the writes).

## M13 — Multicore data plane (2026-10-29)

**Done**

- `kernel/dataplane` + `netproto` (ADR-032):
  - Per-core smoltcp stacks, TLS servers and MQTT services.
  - Core 0 dispatches frames by Toeplitz hash to workers 1..n over SPSC frame rings (buffers move, no copy after the DMA ring), copies ARP replies to every core, and forwards the DHCP lease.
  - Adaptive polling with WFI and wake SGIs.
- `kernel/mqtt_service`:
  - Broker shards with sessions on their home core (`fnv1a(client id)`).
  - Relayed connections with credit flow control and generation-tagged ids.
  - Fan-out of every routed message to the other shards (retained replicas, origin persists).
  - Restore distributes sessions to their homes.
  - Sessions end when we close (not after smoltcp's CLOSING/TIME_WAIT); TIME_WAIT/CLOSING sockets are replaced.
- `crates/broker`: `fanout`, `drain_routes`, `route_remote` (+ shard test).
- `crates/net`: `classify` and `rss::ipv4_tcp` (Microsoft RSS verification suite).
- `crates/arch-aarch64::spsc::new_boxed`: large rings built on the heap.
- `crates/mm::CachedHeap`: per-CPU size-class caches in front of the buddy heap.
- `crates/virtio::net`: asynchronous TX (256 descriptors with own buffers), batched kicks with notification suppression, `rx_pending`.
- `kernel/db`: one request/response ring pair per data core.
- `crates/tls::client`: an unbuffered TLS 1.3 client with a client certificate (host test against our server), used by `test=dp-bench`.
- `tools/loadgen` (real now):
  - `handshake` mode: full TLS 1.3 + mTLS + CONNECT churn, device certificates generated from the dev CA, no resumption.
  - `hold` mode: N connections with PINGREQ and optional QoS 0 publishes.
  - `make loadtest ARGS=…`; `make bench` / `scripts/bench.sh` prints the table below.
- Logging: per-connection events at `debug`; dev-only `log=<level>` boot switch.
- Smoke: `dp-bench` (SMP 6) with a ≥ 3.0× check on 4 workers under HVF. All MQTT scenarios now run across 3 data cores, with sessions relayed between cores.

**Measured** (`make bench`, Apple M4 Pro, HVF)

| Worker cores | dp-bench (handshakes/s, in guest) | scaling | network via QEMU user net (conn/s, 32 clients) | scaling |
|---|---|---|---|---|
| 1 | 862 | 1.00x | 789 | 1.00x |
| 2 | 1 724 | 2.00x | 636 | 0.81x |
| 4 | 3 438 | 3.99x | 536 | 0.68x |

- **The shared-nothing data plane scales linearly** in the guest (TCG: 163 → 341 → 681, 4.18×).
- Through QEMU user networking the rate is capped by the host side: single-threaded slirp and the userspace GIC, with a best of 1 265 conn/s on one core. It falls as more vCPUs compete for host CPUs. Inside the guest the TLS cost per handshake stays constant (0.58 ms) and the workers are 20–40 % busy. A host with KVM, an in-kernel vGIC and a tap or vhost backend is needed for a network-level scaling number.
- Fixes found on the way, all measured:
  - Synchronous virtio TX (2 VM exits per frame): 1 → 1.27 k conn/s on one core.
  - UART logging per connection: about 2× on the network benchmark.
  - Clean disconnects took 1 s (smoltcp simultaneous close); now 1–4 ms.
  - TIME_WAIT slots capped churn at ~400 conn/s.
- `make smoke`: **62/62**. Kernel ELF 2 227 176 bytes; the TLS client for the dev self-test is still linked in prod (M15/M17: gate it).

**Known gaps**

- **virtio-net multiqueue/RSS not implemented**: dispatcher mode only, so "fallback tested by disabling mq" does not apply. QEMU user networking has no multiqueue; it needs tap/vhost and root (CI could do it later).
- No RX interrupt for core 0 (idle → first packet waits ≤ 10 ms).
- Fan-out goes to every shard rather than to the shards with subscribers.
- Relayed connections cost one extra copy per message between cores.

## M14 — Own TCP stack (2026-10-29)

**Done**

- `crates/timer-wheel`: hierarchical wheel, 4 × 64 slots, O(1) insert/cancel with generation ids, empty-range skipping. Tested against a reference model over 20 000 random operations.
- `crates/tcp` (ADR-033): server-only TCP.
  - SYN cookies (SipHash-2-4) always on; open-addressing table; RFC 6298 RTO; NewReno behind a trait; persist timer.
  - Go-back-N with `snd_max`; RFC 5961 RST/SYN handling.
  - ACK coalescing with application replies; no TIME_WAIT; application-controlled receive window.
  - The send buffer exists only while data is pending.
- `crates/net`:
  - Ethernet/ARP/IPv4 (options and fragments dropped), rate-limited ICMP echo, UDP, an own DHCPv4 client (renew/rebind/expiry).
  - A per-core `Iface` with a neighbour cache learned from incoming frames; ARP is answered only on the NIC-owning core.
- Kernel:
  - smoltcp removed. Core 0 runs `Iface` + `TcpStack` for ARP/ICMP/DHCP/echo; every worker runs its own for its MQTT flows.
  - The MQTT service is rewritten as event driven: TCP events plus the broker's new `drain_ready`. Only blocked connections are revisited; keepalive and handshake expiry run every 100 ms.
  - Static addressing (`network.mode = "static"`) is wired up.
- Fuzz target `tcp_segment`: a live connection driven by fuzzed segments, sends, closes and raw bytes, with invariants checked.

**Measured**

- `make smoke`: **62/62**: every earlier test, unchanged, now on the own stack (DHCP, ping, echo, mTLS and plaintext MQTT, persistence, crash tests, dp-bench).
- `urmqtt-tcp` host tests: 16, including 8 lossy seeds (10 % loss + 5 % duplication, sequence wrap) and 25 % loss.
- `make fuzz T=tcp_segment FUZZ_TIME=60`: 2 164 095 runs, no crash or invariant violation.
- Kernel ELF: 2 339 672 bytes (M13: 2 227 176; smoltcp out, own stack in).

**Known gaps**

- No window scaling or SACK (cookies cannot carry them): 64 KiB windows.
- In-order receive only.
- No IPv6 (a later item).
- One timer per connection: a connection waiting in FIN-WAIT-2 has no retransmission timer to restart.

## M15 — Memory per connection (2026-10-29)

**Done** (ADR-034)

- **Exact accounting:** the per-CPU heap counts requested bytes and the buddy blocks they occupy. Core 0 reports every 10 s: heap above the idle baseline per open connection, frame-buffer pool apart. The block figure, allocator rounding included, is the one quoted.
- **TCP:**
  - `Conn` 112 → 96 B: one flags byte, 16-bit RTT/RTO, a 32-bit wrapping RTT start.
  - The table stores 4-byte connection indices and compares keys through the connections (24 → 4 B per slot).
- **TLS:**
  - Per direction only the traffic secret and sequence number (56 → 40 B): the AEAD key *and* IV are derived per record and wiped.
  - The record state lives inline in the connection's slab entry (no separate 128-byte block).
- **Broker:**
  - `Conn` 80 → 48 B: identity and Will in an optional box.
  - `Session` 80 → 64 B (PROMPT §7.3 target): one subscription inline, flattened token bucket, `NonZeroU32` connection id.
  - Subscriptions are 8-byte interned node ids; filters are kept once, in the trie node.
- **Device-scoped subscriptions:** `devices/<own id>/…` filters are stored relative to the session's id and shared by all devices, so devices add no trie nodes. Matching, retained delivery, persistence, restore and unsubscribe are covered by a new test.
- **Slab:** chunks are sized to one 8 KiB heap block (less than 1 % slack instead of up to a third).
- **Kernel:** relay entry 32 → 16 B.
- **Regression guards:** `size_of` assertions as host tests (TCP, TLS, broker) and as compile-time asserts in the kernel.
- **Load generator:** `--subscribe 1` makes every simulated device subscribe to `devices/<id>/cmd/#` at QoS 1.

**Measured** (HVF, 4 vCPU, 3 worker cores, 1 GiB; `urmqtt-loadgen hold --subscribe 1`; each device holds an mTLS connection with one subscription)

| Connections | Heap blocks per connection | Requested bytes per connection |
|---:|---:|---:|
| 960 | 531 B | 504 B |
| 9 922 | **494 B** | 469 B |
| 10 197 | **474 B** | 449 B |

- Before M15: 762 B with frame buffers and 604–610 B requested without them, at 10k without subscriptions (4 099 B at the start of the work). With honest block accounting, the M14 layout was 682 B.
- Frame-buffer pool: a fixed ~2 MiB, reported apart (≈ 200 B per connection at 10k, ≈ 2 B at 1M).
- **100k / 1M not measurable on this host:**
  - QEMU user networking on macOS stopped accepting at 10 197 connections (about the 10 240-descriptor `OPEN_MAX` of the QEMU process); the rest were reset by QEMU.
  - The loopback address also has only 16 384 ephemeral ports, and adding addresses needs root.
  - The per-connection figure falls with the count (fixed chunks amortize), and none of the structures grows superlinearly.
- `make check` green; `make smoke`: **62/62**. Host tests: 75 in tcp/broker/tls/mm. Kernel ELF 2 294 992 bytes.

**Known gaps**

- 100k / 1M measurements need a Linux/KVM host with tap networking (M16/M17 tooling).
- Trie nodes of ordinary filters and retained topics are never freed.
- Under a 10k connect storm the DB core's commits slowed from 15 ms to 600 ms on average (device-registry `DeviceSeen` upserts, about 10 ms each). Not a correctness problem, but M16's reconnect-storm test must look at it.
- The loadgen's first ~80 connects time out (QEMU's listen backlog under 48 parallel connectors).

## M16 — Hardening and operations (2026-10-29)

**Done** (ADR-035, threat model in [SECURITY.md](SECURITY.md))

- **Admission:** new connections are refused before any crypto work when one of these holds:
  - free heap is below `memory.min_free_mb` (new key);
  - the DB core is more than 16 384 requests behind;
  - too many handshakes are in flight per core or per source address (`limits.max_handshakes_in_flight_per_core` / `_per_ip`, new keys);
  - the handshake rate is exceeded.

  Refusals are counted per reason and logged rate-limited. Device-registry updates are skipped when the DB core is far behind (the backlog was unbounded before).
- **Memory after peaks:**
  - Slabs hand out the lowest free id and free empty tail chunks.
  - TCP and client-id tables shrink.
  - Every core does this every 10 s. Without it, admission would have kept refusing forever after a storm that reached the limit (found by the storm test).
- **Watchdog:**
  - Handlers on the data path mark core, phase and connection.
  - The 10 ms tick reports overruns and applies log / drop / reset.
  - A core stuck for 100 budgets (≥ 1 s) resets the VM.
  - Production now uses `drop` with a 20 ms budget.
- **Health check** every 10 s on core 0:
  - every core's loop must progress, or the VM resets after 20 s;
  - a heap below the reserve marks the state degraded.
- **Logs:** rate-limited (100/s, burst 300; suppressions counted). A fixed ring keeps records from the first boot line for syslog.
- **Syslog** (RFC 5424 over UDP) and **statsd** metrics go to the configured collectors from core 0.
  - Gauges: connections, heap, frames, health.
  - Counters: accepts, refusals by reason, watchdog, drops, lost logs.
  - Dev points both at the QEMU host.
- **Security fix:** resumed TLS sessions are checked against the revocation list. Before this, a ticket issued before a revocation still resumed: prod revocation lists are not in git, so a rebuilt image can keep the version and the ticket key.
- **Fuzzing:** 5 new targets (`net_frame`, `tls_record` with a round-trip and tamper oracle, `x509_identity`, `broker_input`, `telemetry_recover`), 11 in all, each run for 60 s in CI.
- **Load generator:** `storm` mode (rounds of simultaneous reconnects with retry and backoff, `--min-connected`). Dev command line `heap_limit_mb=`.
- **docs/SECURITY.md:** a full threat model with assets, trust boundaries, attackers, the input surface (each parser with its verification), a limits table and residual risks.

**Measured**

- `make smoke`: **68/68**. New scenarios:
  - `watchdog`: a 50 ms self-test handler is reported at 14 ms.
  - `storm`: 3 × 3 000 devices against an 8 MiB admission heap.
    - HVF: 1 378 / 1 163 / 1 068 connected per round.
    - TCG: 1 283 / 1 078 / 1 158.
    - Every other attempt was refused cleanly; no allocation failure; memory back at 0 connections.
  - `observability`: the full boot log arrives as RFC 5424 records, and statsd gauges and counters arrive every 10 s.
- Without the heap limit, storms of 8 000 devices × 3 rounds all connected (HVF). The limit there was QEMU's ~10 240 sockets, not the guest.
- Fuzzing, 30–60 s each, no findings after one harness fix:
  - `net_frame`: 3.0 M runs;
  - `tls_record`: 1.4 M;
  - `x509_identity`: 4.0 M;
  - `broker_input`: 1.9 M;
  - `telemetry_recover`: 14 k (each run clones a 16 MiB image).
- Host tests: 232 across the workspace. Kernel ELF 2 399 352 bytes (M15: 2 294 992).

**Known gaps**

- 100k-client storms cannot be generated on this host (QEMU user networking stops near 10 240 sockets), so the heap is scaled down instead.
- Syslog and statsd are plain UDP (private collectors only).
- There is no limit on established connections per source address.
- Revocations still need a new image (now enforced for resumed sessions too).
- M14's CI run failed on `cargo fmt` (an import order in `kernel/src/main.rs`); fixed in the M15 commit.

## M17 — Deployment (2026-10-29)

**Done** (ADR-036, [DEPLOY.md](DEPLOY.md))

- **Reproducible images:**
  - Toolchain, crate-cache and checkout paths are remapped in kernel builds. The ELF used to contain 76 strings with the builder's home directory; it now contains none.
  - `scripts/repro.sh` / `make repro` builds HEAD twice, in two fresh worktrees at paths of different depth with separate target directories, and compares the kernel ELF, the ISO and the raw image.
  - A new CI job runs it for prod with throwaway certificates.
- **Raw GPT disk image** (`make raw`, `scripts/mkraw.py`) with the EFI system partition from `mkiso.sh`; GUIDs derived from content, size in whole MiBs. `run-qemu.sh --disk` boots it from virtio-blk.
- **Data-disk selection fix:** disks with an MBR or GPT are never used as the data disk. Before, the first virtio-blk disk was taken, and its self-test overwrote the last sectors of what would be the boot disk.
- **Signing:**
  - `make sign` (minisign over `SHA256SUMS`, trusted comment with version, environment and commit).
  - The release workflow signs when `MINISIGN_SECRET_KEY` is set, and keeps its SLSA provenance.
  - `make dist` now ships ELF, ISO and raw image.
- **Dev code out of prod:** the dp-bench and the TLS client sit behind the `selftest` feature, which only dev builds enable. CI lints both variants.
- **Production defaults:**
  - heap 1024 MiB (it was 8 MiB, about ten thousand connections), `min_free_mb = 64`;
  - watchdog `drop` at 20 ms (since M16).
- **docs/DEPLOY.md:** inputs and sizing, build, verification (repro and minisign), virtual hardware requirements, libvirt/virt-install and Proxmox steps, the Hetzner CAX path with its caveat, operations (logs, metrics, failure handling, revocation, key rotation, backups).

**Measured**

- `make repro` on macOS (prod, the code of this commit): ELF, ISO and raw image identical in both builds (47 s).
- The CI job's first run on Ubuntu showed the ISO and the raw image differing (ELF identical). Two causes, both in mtools: directory timestamps, and uninitialised memory that `mformat` writes into an unused sector. The fix is `scripts/fat-stamp.py`.
  - Afterwards, three Ubuntu 24.04 builds in a container gave identical ISO and raw images.
  - The job also passed despite the mismatch (`| tee` without `pipefail`); fixed.
- `make smoke`: **70/70**, including `raw-disk` (HVF and TCG): the boot disk is skipped, the data disk is formatted, the boot disk is byte-identical afterwards.
- `make dist` + `make sign` + `minisign -Vm` + `shasum -c` checked end to end with a throwaway key.
- Kernel ELF: prod 2 214 352 bytes, dev 2 399 120 bytes.

**Known gaps**

- Not validated on real cloud hardware. Hetzner CAX likely exposes virtio-scsi disks, and urMQTT drives only virtio-blk.
- The signing key is a test key (`minisign.pub`; the passwordless secret is in the CI secret `MINISIGN_SECRET_KEY`). Replace it with an offline key before a real release.
- A local test PKI exists in `deploy/prod/` (test CA, server, `device-001`; git-ignored). The prod image built from it was checked end to end on the raw disk image:
  - mTLS publish at QoS 1 and the `cmd/#` subscription work;
  - plaintext, a foreign CA, a client id that differs from the CN, and subscriptions outside the ACL are all refused.
- The ISO and the raw image are identical only for the same xorriso and mtools versions; macOS (Homebrew) and Ubuntu builds differ there. The ELF does not.
- Oracle Cloud and ACPI-only validation on real ARM servers remain future work.

## After M17 — virtio-scsi disks (2026-10-29)

**Done** (ADR-037)

- virtio-scsi host adapter driver: INQUIRY/READ CAPACITY scan, READ/WRITE 10/16, SYNCHRONIZE CACHE, unit-attention retry. Only 512-byte direct-access disks are used.
- Kernel: a `DataDisk` type covers virtio-blk and SCSI LUNs. The first non-partitioned disk becomes the data disk.
- `run-qemu.sh --bus scsi`: the boot disk and the data disk become scsi-hd LUNs, as on clouds.
- docs/DEPLOY.md: Hetzner CAX and Oracle Cloud Always Free A1 steps (QCOW2 import), and what to check first (virtio-rng, virtio NIC).

**Measured**

- `scsi-disks` smoke (HVF, TCG): the boot disk on LUN 0 is skipped and byte-identical afterwards; the data disk on LUN 1 is formatted and passes its self-test; db-bench shows 43 524 ops/s batched and 2 021 ops/s with one insert per transaction; a second boot reopens the disk.

**Known gaps**

- Still not tried on Hetzner or Oracle hardware.
- Both need virtio-rng: Ampere Altra has no `RNDR`, and the kernel will not boot without a hardware entropy source. (Resolved by the jitter fallback below.)

## After M17 — entropy fallback, CPUs without PAC (2026-10-29)

**Done** (ADR-038)

- CPU-jitter entropy fallback (`entropy.fallback = "jitter"`):
  - PMU cycle counter or generic timer, granularity learned, workload calibrated;
  - SP 800-90B-style health tests and a conservative min-entropy estimate (1/4 credited, 256 bits required).
- **Bug fix:** the APs wrote PAC key registers that CPUs without PAuth do not have. On Cortex-A72 and Neoverse N1 (Ampere Altra) SMP failed, with 1 of 4 CPUs online. Found by booting `-cpu neoverse-n1`.
- Missing virtio-net: every unsupported NIC is named with its vendor plus the fix; production stops instead of idling silently.
- `run-qemu.sh --cpu MODEL --no-rng`; smoke scenario `no-hw-rng` (HVF host CPU; TCG Neoverse N1).

**Measured**

- Jitter fallback:
  - HVF cycle counter (steps of 128): 512 bits credited in 85–166 ms.
  - TCG Neoverse N1: 618 bits in 275 ms.
  - TCG N1 without a PMU (generic timer): 512 bits in 112 ms.
- Health tests passed in all three cases.
- SMP: 4/4 CPUs online on Cortex-A72, Neoverse N1 and `max` (TCG).

**Known gaps**

- The jitter source has only been measured under QEMU, not on Altra hardware. Its warning line reports the figures, so the first cloud boot shows them.
- No driver for SR-IOV NICs.

## After M17 — GICv2 for Raspberry Pi KVM hosts (2026-10-29)

**Done** (ADR-039)

- GICv2 discovery from DT (`arm,cortex-a15-gic`, `arm,gic-400`, `arm,cortex-a9-gic`) and ACPI (MADT GICD version, GICC base).
- A `Gicv2` driver: distributor, MMIO CPU interface, target-mask routing, `GICD_SGIR` IPIs, raw-IAR EOI. The kernel's IRQ and SGI layer now takes logical CPUs and works with either GIC version; a GICv2 starts at most 8 CPUs.
- `run-qemu.sh --gic 2`. The `gicv2` smoke scenarios run under TCG (HVF cannot emulate a GICv2): boot with ACPI and DT, and the mTLS broker scenarios.
- `scripts/kvm-host/` with `install.sh`, `urmqtt-vm.sh` (`gic-version=host`, KVM, virtio devices, `--dry-run`) and `urmqtt.service`. docs/DEPLOY.md §7 covers the Raspberry Pi 4/5 and other aarch64 Linux KVM hosts.

**Measured (TCG, `gic-version=2`, 4 vCPUs)**

- 4/4 CPUs online and 12/12 IPI pairs, with an average round trip of about 46–50 µs under TCG.
- MSI-X blk completions through GICv2m, SQLite, virtio-net, and the TLS broker scenarios all pass.

**Known gaps**

- Not yet run on a real Raspberry Pi with KVM.
- The launcher's QEMU command line was checked under TCG on macOS, not with KVM.

## H0 — Security baseline and inventory (2026-10-29)

PROMPT-security.md, plan in docs/SECURITY-PLAN.md. No behaviour change.

**Done**

- `docs/AUDIT.md` contains:
  - the TCB summary;
  - every external input with its parser, bound and fuzz target;
  - the mitigation matrix (protection, implementation, proving test);
  - the nine H0 questions answered from the code with file references;
  - 14 weaknesses.
- `scripts/audit-inventory.py` (`make audit`) generates `docs/audit/inventory.md` (crates, vendored code, the kernel's third-party crates by kind, fuzz targets) and `docs/audit/unsafe.md` (every `unsafe` site in non-test code, with or without a written justification). It is deterministic; CI fails when it is out of date (`--check` in the lint job).
- `urmqtt-store` now denies `unsafe_code` except in its FFI modules. Before, nothing enforced the boundary its docs described (H0-W7).

**Measured**

| Part | Size |
|---|---|
| Own Rust | 30 773 lines in 17 crates |
| Third-party Rust linked into the kernel | 65 crates, 290 278 lines |
| SQLite | 254 268 lines of C |
| `unsafe` in non-test code | 308 sites, 278 with a written justification |

**Answers to the H0 questions:** gaps in 1 (no runtime revocation), 2 (open registry), 3 (no lower time bound), 4 (no KASLR), 5 (0-RTT is off, but untested), 6 (captured traffic secrets are not wiped), 7 (the cookie/ISN key never rotates), 8 (retained messages unbounded) and 9 (no expiry checks).

**Weaknesses** (AUDIT.md §5; each has a planned milestone):

- **High:**
  - H0-W1: retained messages are unbounded per device (authenticated DoS on memory and DB).
  - H0-W4: the ticket key is derived from the image's server key, so tickets can be forged from a copy of the image.
  - H0-W5: no lower bound on the wall clock.
  - H0-W13: a whole-disk filesystem can be taken for a blank disk on bare metal.
- **Medium:**
  - H0-W2: captured TLS traffic secrets are not wiped.
  - H0-W8: SQLite parses a volume-controlled database without fuzzing.
  - H0-W9: no fuzzing of PCI and virtio parsing.
  - H0-W12: the boot self-test writes to unidentified disks.
- **Low:**
  - H0-W3: cookie key rotation.
  - H0-W6: random-number failures ignored in two places.
  - H0-W10: no proof that the page tables are read-only.
  - H0-W11: no test that prod ignores the command line.
  - H0-W14: 30 unjustified `unsafe` sites.
- **Fixed:** H0-W7.

**Correction to SECURITY-PLAN §1:** revocation on resumption is tested (`tls/tests/handshake.rs` `revoked_device_cannot_resume`).

## S0 — Disk format specification (2026-10-29)

PROMPT-storage.md, plan in docs/STORAGE-PLAN.md. No format or behaviour change; the disk stays raw, without a filesystem.

**Done**

- `docs/DISK-FORMAT.md`: the byte-level specification of layout v1. It covers:
  - conventions (little-endian, CRC-32C with its check value);
  - the disk map and the region-sizing formula;
  - the superblock and region entries, the A/B size table and its ordering rules;
  - the SQLite regions and their settings;
  - the telemetry log (header, geometry formula, segment header, record, write and recovery rules, why stale data never resurrects, retention);
  - scratch, the format procedure, invariants and known gaps.
- `crates/store/tests/disk_format_spec.rs` reads the spec's field tables and checks them against the real encoders in both directions. Every listed field must be at its offset with the expected bytes, and every byte the code writes must belong to a listed field. It also checks the region-sizing formula on four disk sizes, the telemetry geometry formula, the size-table slot rules and the CRC check value. Mutation check: moving a field or deleting one from the spec makes it fail.
- `crates/store/tests/golden_v1.rs` and `tests/golden/v1-{fresh,telemetry,torn}.txt` freeze the bytes of three deterministic 16 MiB v1 disks (non-zero sectors only, 6–18 KB each):
  - a fresh format;
  - 40 telemetry records in three partitions plus a size-table update;
  - a torn tail.

  Each is also recovered: 0, 40 and 40 records, with 0, 0 and 1 torn tails. These are the inputs of S2's migration tests. SQLite's own files are checked semantically by `tests/sqlite.rs`, not frozen.

**Gaps found** (STORAGE-PLAN §2):

| Gap | Description |
|---|---|
| G1 | the data disk is chosen by "not partitioned" instead of by identity |
| G2 | a damaged urMQTT disk must not be taken for a blank one |
| G3 | 4 KiB region alignment and 512 B telemetry writes |
| G4 | 8 fixed telemetry partitions |
| G5 | no host-file VFS backend yet |
| G6 | the cross-arch test must use v2 |
| G7 | a disk whose size is not a multiple of 4 KiB cannot be formatted |
| G8 | recovery reads the whole telemetry region at boot, so boot time grows with the disk |

**Decisions (user, 2026-10-29):**
- **The data disk belongs to urMQTT entirely**, and previous content does not matter.
- Refined the same day: **there is one disk, the one urMQTT boots from.** The data moves into a partition of the boot disk, created on first boot, and no other disk is ever touched (PLAN.md decision 6, STORAGE-PLAN §2a, implemented in S1).

This turns G1/G2 into:
- identify the boot disk exactly;
- never re-format our own damaged partition.

**Corrections to earlier planning text, found while writing the spec:**
- Blank detection reads the whole first 4 KiB, so ext4, XFS, LVM, LUKS and swap disks are refused today. The formats at risk are the ones with an empty first 4 KiB (fixed in X86-PLAN, STORAGE-PLAN, SECURITY-PLAN and AUDIT.md).
- SQLite already builds and runs on the host over `MemDisk`, which has crash primitives (G5).

## X0 — Architecture facade and CPU dispatch (2026-10-29)

PROMPT-x86_64.md, plan in docs/X86-PLAN.md. AArch64 only; no behaviour change (ADR-040, ADR-041).

**Done**

- **`urmqtt-sync`:** the spinlock, once-cell, SPSC ring and the frame-source trait moved out of the arch crate. `mm`, `store` and `tls` depend only on it now. `log` uses the facade, and only on bare metal.
- **`urmqtt-arch` facade:** 12 modules (`cpu`, `irq`, `ipi`, `msi`, `percpu`, `time`, `paging`, `trap`, `barrier`, `entropy`, `power`, `features`). `contract.rs` binds 63 items to explicit signatures.
- **All assembly and system-register code is now in `arch-aarch64`.** That covers the boot entry, the AP trampoline with `ApBoot`, per-CPU id, MMU activation, the GIC v3/v2 controller, the GICv2m MSI frame (now host-tested), PSCI conduit, RNDR, the PMU clock, the test faults, and trap classification with the register dump. The kernel went from 63 to 51 `unsafe` sites. The virtio doorbell barrier goes through `arch::barrier`.
- **`scripts/check-arch-leaks.sh`** runs in CI and `make check`. It has 10 rules for AArch64 and future x86 code, plus `--self-test`. The tree is clean.
- **`urmqtt-dispatch`:**
  - `CpuFeatures`, the per-primitive backend table and `select`;
  - the optional `[cpu] disable = [...]` config key, validated by the schema against the same names, with security features not switchable;
  - a write-once seal (a second seal is refused).
- **Boot log:** `cpu dispatch: detected aes pmull sha2 crc32, disabled by config none` (HVF, M4 Pro) and `crypto: aes-gcm=soft ghash=soft chacha=soft sha256=soft crc32c=table toeplitz=bitwise`. That is F1, stated honestly: no hardware backend is built before X0b.
- **Tests:**
  - 7 dispatch host tests (selection by mask, opt-out before selection, double seal, name validation, every row ends in portable code), a schema test and 2 MSI tests;
  - the boot-acpi and boot-dtb smoke scenarios check both dispatch lines.
- `docs/audit/` regenerated, and AUDIT.md updated: 20 crates, 31 905 lines, 316 `unsafe` sites with 289 justified (was 308/278). Three extern blocks got their missing justification.

**aarch64 non-regression** (Apple M4 Pro, HVF)

- `make check` green (257 host tests). `make smoke`: **79/79** (HVF and TCG, including GICv2 and all fault scenarios), both after the facade step and after dispatch.
- `make bench`, before → after:

| Worker cores | dp-bench handshakes/s | network conn/s (32 clients) |
|---:|---:|---:|
| 1 | 865 → 877 | 658 → 638 |
| 2 | 1 730 → 1 724 | 815 → 846 |
| 4 | 3 431 → 3 452 | 896 → 864 |

  The differences are within run-to-run noise. The network column moves by a few percent between runs in both directions.
- **Bytes per idle connection** (dev image, 32 MiB heap, 4 vCPU, `urmqtt-loadgen hold --clients 10000 --subscribe 1`, mTLS with one subscription each), steady state: **512 B → 511 B** in heap blocks (487 → 486 B requested) at 9 936 / 9 937 connections. Both images were measured back to back under the same conditions.
- **Kernel ELF size:** dev 2 417 968 → 2 423 608 B (+5 640), prod 2 249 504 → 2 255 192 B (+5 688). The facade step alone added 176 B; the rest is the dispatch table, its formatting and the seal.
- `make repro` (prod, c92b912): kernel ELF, ISO and raw image identical across two builds (ELF sha256 `203a8ef9…`).

**Deviations from the plan** (X86-PLAN X0 status):
- The paging builder stays the AArch64 `Mapper` behind `arch::paging`. A neutral one is designed in X1 against the x86 format.
- The sealed dispatch state is write-once but not yet on a read-only page. That is moved to X0b, where it starts choosing code.

## H1 — Identity lifecycle without new images (2026-10-29)

PROMPT-security.md H1, plan in docs/SECURITY-PLAN.md (status and deviations there). ADR-048, ADR-049, ADR-050. The threat model of the control channel came first (docs/SECURITY.md, "Control channel").

**Done**

- **Control channel** (`crates/control`, kernel `control.rs`):
  - signed messages on `$urmqtt/control`, accepted only from an operational identity in `control.service_ids` and only with a valid Ed25519 signature by the offline key (`control.pub` in the image);
  - a fixed, bounded binary layout, domain-separated and bound to the environment, verified with `verify_strict`;
  - checks: `seq` strictly increasing, a validity window of at most `control.max_message_age_s`, and fail closed without a trustworthy clock or without durable storage;
  - commands: revoke and unrevoke serials (unrevoke only with `control.allow_unrevoke`, never an image-listed serial), and allow and disallow device ids;
  - processing on the DB core: the effect and the new `seq` commit in one transaction (schema v2), then the shared sets are replaced, an epoch is bumped and every core is woken;
  - each core closes its live connections whose serial is now revoked or whose identity left the allowlist.
- **Reserved namespace in the broker:** no subscriptions, nothing routed or retained, unauthorised publishes dropped and counted, backlog bounded at 64. The schema refuses ACL patterns there.
- **Trust anchors by role** (`[trust]` replaces `tls.ca`):
  - operational CAs, two side by side for rotation with overlap;
  - bootstrap CAs, which give only `provision/{id}/#`, in a separate session namespace and never persistently;
  - the role is decided at verification; a resumed session re-verifies against the current anchors.
- **Registry:** `registry.mode = "open" | "allowlist"`. In allowlist mode an unknown device identity is refused after the handshake and counted. Image-named services and bootstrap identities are exempt. The dev command line can switch an image to allowlist mode (stricter only).
- **Expiry safety:**
  - the build fails below `tls.min_server_cert_days` (60) and `trust.min_anchor_days` (365);
  - at runtime: a boot line, the gauge `urmqtt.tls.server_cert_days`, and warnings at 60, 30, 7 and 1 days;
  - `tls.early_data = true` fails the build.
- **Clock lower bound (H7 part, ADR-050):** the image's `SOURCE_DATE_EPOCH` is embedded. An earlier boot date means unknown time, so every certificate check and control message is refused.
- **`tools/urmqtt-control`:** revoke, unrevoke, allow, disallow (by `--cert`, `--serial` or `--id`), `publish-file`, `show`. Signing with a key file or `--sign-cmd` (HSM/KMS hook); `seq` defaults to Unix milliseconds.
- **Metrics:**
  - `urmqtt.control.applied`;
  - `urmqtt.control.rejected.<reason>` (13 reasons);
  - `urmqtt.registry.refused`;
  - `urmqtt.revocation.live_closed`;
  - `urmqtt.tls.server_cert_days`.

  Every rejection is also logged rate-limited, with the reason and the publisher only.
- `docs/PROVISIONING.md`: keys born on the device, enrollment outside the broker with the CAs in an HSM/KMS, CA rotation, runtime revocation, the signing hook.
- `make certs` adds, without touching an existing dev CA:
  - a second operational CA with device-005;
  - a bootstrap CA with bootstrap/device-006;
  - the control service identity `operator`;
  - the Ed25519 control key pair.
- **Fixed from H0:** W5 (clock lower bound); W6 (random-number failures for the SYN-cookie key and the DHCP xid are fatal); W11 (the kernel binary has host tests; `production_ignores_every_option`).

**Tests**

- **Host:**
  - control crate: 9 tests (RFC 8032 vectors, round trip, every flipped byte, environment and key binding, malformed input, freshness/replay/permission rules, PEM keys);
  - TLS: runtime revocation for full handshakes and resumption; roles with two operational CAs and a bootstrap CA, including resumed roles and a removed CA refused even with a valid ticket;
  - broker: 5 new tests (namespace, control rights, bootstrap isolation, disconnects);
  - store: control state across power loss and the v1→v2 migration;
  - schema: 4 new tests, including `expiry_build_check`; kernel: 2 command-line tests.

  282 host tests in all.
- **Fuzz:** new target `control_message` (structured and raw; 238k runs in 60 s, coverage 929). `broker_input` now also drives bootstrap identities.
- **Smoke: 87/87** (HVF and TCG). New scenarios:
  - `control`: control-revoke-live (closed 8–10 ms after the commit, refused on reconnect), unrevoke, forged, replay, expired, from-device, bootstrap-role, ca-rotation;
  - `registry-allowlist`: unknown refused, allowed then admitted, disallowed then closed live in 3–4 ms and refused;
  - `control-persist`: after a power cut the revocation and `seq` remain; the replayed message is rejected and the device is still refused;
  - `time-before-build`: RTC in 2020; the date is refused and the handshake fails.

**Measurements** (M4 Pro, HVF)

- **Bytes per idle connection** (10k mTLS connections with one subscription each, dev image, 32 MiB heap), with the pre-X0 kernel measured again back to back:
  - idle phase: **476–477 B before and after**;
  - keepalive phase: 516–527 B before and 516–550 B after, overlapping and noisy.

  `Conn` stays at 152 B: the 32-bit serial tag fits its padding.
- **`make bench` dp-bench** (handshakes/s, 1/2/4 workers): 872 / 1 716 / 3 385, against 877 / 1 724 / 3 452 at X0, so −1.9 % at 4 workers, near noise. Each full handshake now hashes the client certificate twice and takes a global lock to record the role.
- **Found and fixed while measuring:** the first version read the broker's full `stats()` (a walk over every session) on every loop pass. It now reads a single counter.
- Dev ELF 2 403 536 B (X0: 2 423 608 B).

**Weaknesses found** (AUDIT.md, H1-W1 to W4):
- W1: the publisher gets no outcome back.
- W2: a data-disk rollback restores old revocations and `seq`.
- W3: the build's expiry check is cached until the inputs change.
- W4: allowlist mode without storage refuses every device.

**Deviations** (SECURITY-PLAN H1 status):
- a fixed binary layout instead of CBOR;
- the `--sign-cmd` hook instead of a linked PKCS#11 library;
- an epoch plus IPI instead of ring messages;
- removal of an old CA proven by a host test with two servers instead of a second image in smoke.

## S1 — Single-disk model, `urmqtt-disk`, fault injection (2026-10-30)

PROMPT-storage.md S1, plan in docs/STORAGE-PLAN.md (status and deviations there). ADR-051. Specification in DISK-FORMAT.md §0.

**Done**

- **One disk.** The kernel finds the disk it booted from by the GPT disk GUID in Limine's executable-file response. It keeps its data in a partition of that disk and never writes any other disk.
  - Found on the way: the `limine` crate 0.6.5's `File` lacks the protocol's `unused` field, so its UUIDs are 4 bytes off. The kernel reads the protocol offsets from the raw structure.
- **First boot** (`urmqtt_store::gpt`):
  - a torn primary is repaired from the backup;
  - the backup moves to the end of a larger disk;
  - the data partition is created: type `58D3F720-BDF5-4DB7-99EC-DE26C8B8850F`, 1 MiB aligned, whole 4 KiB blocks, head zeroed first, fresh partition and disk GUIDs, backup copy before primary;
  - every step is idempotent and survives a power cut.
- **The store through a partition window** (`urmqtt_store::part`), with layout v1 unchanged. The block self-test writes only inside the partition.
- **Classification:** blank → format, valid → open, damaged → refused and never written.
- **Booting the ISO as a CD** gives no data partition, with a clear message. Dev runs memory-only; prod refuses.
- **Fault injection** (`urmqtt_store::fault`): stop after N writes or flushes, a torn write, a dropped flush, a bit flip on read. On the host it wraps `MemDisk`; in dev kernels it is enabled with `test=disk-fault:<spec>`, and an injected power cut powers the VM off.
- **The GPT writer** `gpt::raw_image` is byte-identical to `scripts/mkraw.py` (test with five ESP sizes). S1b's installer will use it.
- **`tools/urmqtt-disk`** (host, images and block devices, read-only unless `--write`):
  - `info`, `verify`;
  - `export-db` (WAL applied in a copy-on-write overlay; the output opens in the host's `sqlite3`);
  - `export-telemetry` (csv/jsonl, time and topic filters);
  - `import-devices [--allowlist]`, which seeds the H1 allowlist offline;
  - `create` (the mkraw-identical image on a disk of any size);
  - `update-boot` (new kernel, data kept).
- **Single disk everywhere:**
  - `make run` uses one persistent `build/disk-<env>.img` (`make disk` creates it, or updates its kernel in place);
  - `scripts/bench.sh` and every smoke scenario boot one disk;
  - `scripts/kvm-host/install.sh` creates and updates one `disk.img`;
  - DEPLOY.md lost every "separate data disk" step (libvirt, Proxmox, Hetzner, Oracle, Pi).
- **Fixed:** H0-W12 and W13; DISK-FORMAT G1 and G2.

**Tests**

- **Host:**
  - 13 GPT tests, among them a power cut at every one of the 10 first-boot writes (cut and torn, with and without the volatile cache surviving: 40 cases), repair, shrink, too small, old data under the new partition, and the real layout formatting the new partition;
  - a partition-window test; fault-device tests;
  - the mkraw identity test.

  299 host tests in all.
- **Fuzz:** new target `gpt_parse`. It patches a valid image, optionally with the CRCs fixed up, and runs the first boot on the result. 150k runs in 120 s reached coverage 422 with no failure.
- **Smoke: 113 checks, all passing** (HVF and TCG), with every earlier scenario now on a single disk. New:
  - `first-boot` (a second virtio-blk disk with random data is byte-identical afterwards) and `first-boot-again`;
  - `first-boot-crash` at four points (stop after write 2, 6, 8; write 9 torn), each followed by a recovery boot;
  - `scsi-boot`: the boot disk as a virtio-scsi LUN, formatted, db-bench, reopened, a second LUN untouched;
  - `iso-as-cd`;
  - `own-damaged-refused`: one flipped byte in the superblock; refused, the partition head unchanged;
  - `disk-tool-offline`:
    - `verify` passes;
    - the exported database passes `integrity_check` in `sqlite3` and holds 1 retained message and 1 session;
    - the 3 published telemetry values come out of `export-telemetry`;
    - the read-only commands leave the image unchanged;
    - import without `--write` is refused;
  - `disk-tool-import-in-force`: the next boot in allowlist mode admits the imported device-002 and refuses device-003.

  The full run had 107 passing and 6 failing checks, all caused by the new scenarios themselves:
  - `own-damaged` expected a memory-only fallback, but dev refuses on corruption;
  - client lines were written into the serial log while QEMU was still writing it.

  The same race was then also fixed in `control-persist` and `time-before-build`, where a lost line could have hidden a failure. The fixed scenarios passed, 10/10 on HVF and TCG.
- db-bench on the data partition (HVF): 62 610 ops/s batched and 2 378 ops/s with one insert per transaction (virtio-scsi); 56 696 and 2 094 on virtio-blk (M11 baseline: 43 524 / 2 021).

**Not done (as planned for later):**
- `migrate` and `backup-extract` (S2, S5);
- `scripts/fault-loop.sh`, which comes with its first procedure, the S2 migration.

**Not re-measured:** `make bench` and bytes per connection. S1 changed only the storage path and boot-time disk handling, not the data plane.

## S1b — Self-installing ISO (2026-10-30)

PROMPT-storage.md and PLAN.md decision 7; plan in STORAGE-PLAN §2b (status and deviations there). ADR-052; threat model "Installer entry" in docs/SECURITY.md.

**Done**

- **ISO menu** (`scripts/mkiso.sh`): the ISO9660 `limine.conf` lists *urMQTT* (the default, after 5 s) and *Install urMQTT on this machine's disk*. The second entry passes `cmdline: install` and loads the ESP as `module_path: boot():/esp.img#<blake2b>`. The editor is off. The ESP's own config, used by the installed disk, stays menu-less. The options `--install-cmdline` and `--install-default` serve the tests.
- **Install mode in the kernel** (`install.rs`):
  - every driven disk becomes a candidate (virtio-blk, and virtio-scsi LUNs, also next to the CD on the same bus);
  - exactly one qualifies: writable, not the installation medium, at least the image plus 17 MiB;
  - the screen shows each disk and the warning, then counts down 30 s ("power off now to cancel");
  - the image is written (mkraw-identical), read back with a streaming SHA-256, and the machine powers off with "remove the installation medium".
- **The write order** (`urmqtt_store::install`) leaves an interrupted install either untouched or unbootable, never half-new:
  1. clear the backup at the end, then the primary;
  2. write the ESP and the image's backup;
  3. write the entries and the MBR;
  4. write the primary header last.

  The S1 first boot now also rewrites a missing or damaged backup.
- **Production command line:** still ignored, except the exact word `install`.
- **Fixed on the way:**
  - the read-back first used a second 10 MiB buffer and panicked on the 32 MiB dev heap after the image was written;
  - a power-off cut off the last log line: `power::off` and the reset path now flush the UART first.
- DEPLOY.md "Installing from the ISO"; the README feature and roadmap rows.

**Tests**

- **Host:**
  - target selection;
  - the installed disk equals the raw image and first-boots;
  - too-small and bad images;
  - a power cut at every write of a reinstall (with and without the cache surviving) leaves the old install untouched or a non-booting disk, and installing again works;
  - backup repair;
  - the production command line (`production_honours_install_and_nothing_else`).

  305 host tests pass.
- **Smoke: 127/127** (HVF and TCG). New, each on both:
  - `install-vm`: the ISO itself unchanged afterwards;
  - `install-vm-boots`: first boot, data partition, `URMQTT READY` from the disk alone;
  - `install-two-disks-refused`: both disks still all zero;
  - `install-scsi` and `install-scsi-boots`;
  - `install-crash`: `urmqtt-disk info` finds no GPT on the target;
  - `install-crash-reinstalled`.

  Installing 10 MiB takes 70 ms under HVF.

**Not done:**
- an *Update* menu entry (ESP only, data kept);
- selecting a target by serial (`storage.install_target`);
- BIOS boot of the installed disk (x86, X10);
- the real USB stick on the Intel PC (X12).

## X0b — aarch64 hardware crypto (2026-10-30)

PROMPT-x86_64.md and PLAN.md phase 4; plan in docs/X86-PLAN.md (X0b status there). ADR-053, ADR-041 updated. Closes finding F1 on AArch64.

**Done**

- **Build:** `--cfg aes_armv8 --cfg polyval_armv8 --cfg chacha20_force_neon` for every target (`.cargo/config.toml`, workspace `check-cfg`).
- **`cpufeatures` vendored** (0.2.17 and 0.3.1, vendor/README.md): on `target_os = "none"` RustCrypto asks the kernel's `urmqtt_cpu_has`, which answers from the sealed dispatch and says "no" before the seal. On the hosts the code is the upstream code.
- **Dispatch table:** `aes-gcm=armv8-aes`, `ghash=armv8-pmull`, `chacha=neon`, `sha256=armv8-sha2`, `crc32c=armv8-crc` on the AArch64 kernel, with the portable backends last. `"aes"` is granted only with AES and PMULL together.
- **CRC-32C:** the ARMv8 `crc32c` instructions in `arch-aarch64` (`arch::crc`), installed into `urmqtt_store::crc` through a new backend hook only when selected. The table stays as the reference and in the host tool.
- **Read-only seal:** the dispatch state lives in `.data.sealed`, a page of its own, mapped read-only by the kernel's tables. The W^X audit checks it.
- **Known-answer tests on every boot, fail closed** (`urmqtt_tls::kat`), right after the heap is up: AES-128-GCM, ChaCha20-Poly1305, SHA-256 (one-shot and streamed), HMAC-SHA-256, CRC-32C. Log: `crypto: known-answer tests passed (…)`.
- **Dev tools:**
  - `cpu-disable=aes,pmull,sha2,crc32` takes features out on the command line;
  - `test=crypto-bench` reports throughput;
  - `test=simd-irq` runs 10 s of KATs on every core under the tick and a storm of IPIs;
  - `test=sealed-write` writes the sealed page;
  - `scripts/bench.sh --cmdline WORDS`.
- **Fuzz:** `diff_aes_gcm`, `diff_chacha20poly1305`, `diff_sha256` (both `sha2` versions, one-shot and chunked) against `ring`, and `diff_crc32c` (hardware against the table). `make fuzz` builds with the kernel's cfgs, so CI's fuzz smoke compares the backends the kernel runs.

**Tests**

- `make check` green: **308 host tests**, plus the new ones for the `cpufeatures` answers, the opt-out CSV, ARMv8 CRC against a bitwise reference, and the KAT vectors.
- Fuzz on the M4 (20 s each, before CI's 60 s): `diff_aes_gcm` 3.55 M runs, `diff_chacha20poly1305` 3.39 M, `diff_sha256` 3.43 M, `diff_crc32c` 17.6 M. **No differences.**
- **Smoke: 137/137** (HVF and TCG). The boot scenarios now expect the ARMv8 selection and the KAT line. New, each on both accelerators:
  - `crypto-soft`: the portable selection, with the KATs passing on it;
  - `sealed-write`: a level-3 write permission fault, whose FAR equals the logged sealed address (`0xffffffff801f2000`);
  - `simd-irq`: HVF 1 854 758 rounds with 5 564 274 IPIs, TCG 497 686 rounds with 1 493 058 IPIs, **0 mismatches**;
  - `crypto-bench`.

**Measured** (Apple M4 Pro, QEMU HVF)

`test=crypto-bench`, 64 KiB buffers, MiB/s. The portable column comes from `cpu-disable=aes,pmull,sha2,crc32`. ChaCha20's portable figure needs a build without `chacha20_force_neon`; it was measured once and the build was then restored.

| Primitive | Portable | ARMv8 | Factor |
|---|---:|---:|---:|
| AES-128-GCM | 228 | 553–559 | 2.4× |
| ChaCha20-Poly1305 | 596 | 758–763 | 1.3× |
| SHA-256 | 586 | 2 632–2 663 | 4.5× |
| CRC-32C | 497 | 9 793 | 20× |

Under TCG (smoke) the ARMv8 figures are 106 / 148 / 224 / 429 MiB/s. That is emulation, so it is not a basis for any decision.

`make bench` with the portable crypto (`--cmdline cpu-disable=…`) → the ARMv8 crypto, back to back:

| Worker cores | dp-bench handshakes/s | network conn/s (32 clients) |
|---:|---:|---:|
| 1 | 853 → 894 | 628 → 632 |
| 2 | 1 700 → 1 774 | 845 → 836 |
| 4 | 3 381 → 3 532 | 769 → 823 |

Handshakes gain about 4–5 %. A full mTLS handshake is dominated by ECDSA P-256 and X25519, which X0b does not touch. The symmetric part gets much faster, so records/s and the store's checksums gain more than handshakes. The network column moves by a few percent from run to run, as in X0. Every backend is faster on the M4, so each is on by default (the X0b acceptance rule).

- **Kernel ELF (dev):** 2 462 624 → 2 520 232 B (+57 608). The ARMv8 code paths are compiled in next to the portable ones, along with the KAT vectors and the selftest tools.

**Deviations and not done** (X86-PLAN X0b status):
- The KATs run on every boot, not only under a dev `test=crypto-kat`.
- No PMULL folding for CRC-32C.
- TCG `cortex-a72` (the Raspberry Pi 4 core) and `neoverse-n1` (Ampere Altra) were booted by hand, not in the smoke. Both select all ARMv8 backends, pass the KATs and reach `URMQTT READY`.
- Records/s are not measured separately yet; `make bench` measures handshakes only.
- Bytes per connection were not re-measured: X0b changes no data structures.
- The real Raspberry Pi (Cortex-A72 has AES, PMULL, SHA2 and CRC32) is still open.

## H2 — TLS assurance (2026-10-30)

PROMPT-security.md §H2 and PLAN.md decision 5; plan in SECURITY-PLAN (H2 status and deviations there). ADR-054; the cryptography as a whole in the new docs/CRYPTO.md.

**Done**

- **Session-ticket keys** (`urmqtt_tls::ticket`) replace the key derived from the server key (H0-W4, high if an image leaks):
  - random per boot, current for 12 h of uptime, previous for 12 h more, then zeroised in place (two fixed slots, never moved);
  - ticket lifetime 12 h;
  - format `key id || nonce || ChaCha20-Poly1305` with the id in the associated data;
  - one set shared by every core's server;
  - refusals are counted by reason (statsd `urmqtt.tls.resume_refused.*`, plus issued, resumed, rotated, not issued) and logged at powers of two; key rotations are logged;
  - dev `test=ticket-rotate:S`.
- **0-RTT:** `zero_rtt_is_never_offered` (a client that wants early data gets tickets without it). The `tls.early_data` build refusal already existed. A mutation (16 KiB early data configured) showed that rustls alone already refuses early data with stateless tickets (RFC 8446 §8.1), so 0-RTT is locked twice. The test checks the outcome.
- **Found and fixed (conformance):**
  - **No fatal alerts were sent.** Record-layer errors now send `bad_record_mac`, `record_overflow`, `unexpected_message` or `internal_error` under the current keys. rustls's handshake alert, which its unbuffered API emits only on a second call, is now flushed. Before, peers saw only a close.
  - **close_notify was not answered;** now it is (RFC 8446 §6.1).
  - **The inner-plaintext limit of 2^14 + 1 bytes was not enforced.** Only the ciphertext length was, which let up to 239 extra bytes through (an inner plaintext of up to 2^14 + 240). Now it is `record_overflow`.
- **Constant time:** the one secret comparison of our own (captured vs rustls record keys) goes through `subtle` (`server::ct_eq`). `make ct` runs dudect-style tests with a negative control, also in CI. The review list is in docs/CRYPTO.md.
- **Differential fuzzing:** `diff_tls_record` against rustls's record layer, with rustls's key schedule and `ring`'s AEAD: sealing byte-identical, and opening of padded or tampered records of every content type agreeing.
- **Conformance:** `scripts/tlsfuzzer/urmqtt_tls13.py`, 23 probes on tlsfuzzer's machinery for mutual TLS and MQTT (`make conformance`; tlsfuzzer and tlslite-ng pinned by commit). The stock scripts expect HTTP without client authentication (the reasons are in CRYPTO.md).
- **Interop:** `tools/interop/client.c` built against OpenSSL, wolfSSL and Mbed TLS (`make interop`). It covers handshake, resumption, KeyUpdate, 1-byte records and one 16 KiB record. Resumption is also confirmed in the server log.
- **CI:** a new job "TLS conformance (tlsfuzzer) and interop" (TCG, Ubuntu's OpenSSL and wolfSSL); `make ct` in the host-test job.

**Tests**

- `make check` green: **324 host tests**. New:
  - 11 ticket tests;
  - `ticket_from_another_boot_means_full_handshake`, `zero_rtt_is_never_offered`, `fatal_alerts_reach_the_peer`;
  - `inner_plaintext_over_the_limit_is_record_overflow`, `errors_map_to_their_alerts`;
  - the `test=ticket-rotate` command line.
- `make ct` (M4 Pro, release, six runs): the control (early-exit comparison) at |t| = 4352–5601; `ct_eq` 0.3–4.0, AES-128-GCM bad tag 0.3–2.2, ChaCha20-Poly1305 0.7–2.1, ticket 0.6–4.3 (bound 7).
  - **CI found a flaw in the first harness:** on the arm64 runner `ct_eq` showed |t| = 8.1 and AES-GCM 16. Each class had its own input buffer, and the input copy was timed. Now the inputs are prepared untimed in one buffer, both classes write the same bytes, and a case fails only if three runs all exceed the bound. Locally `ct_eq` went from 5–10 to 0.3–4.
- `diff_tls_record`: **10 min, 24 552 413 runs, clean** (aarch64, M4).
- tlsfuzzer: **23/23** (HVF).
- Interop (HVF): OpenSSL 3.6.3 and 4.1.0, wolfSSL 5.9.4 all ✅. Mbed TLS 4.2.0 ✅, except KeyUpdate: Mbed TLS has no API for it.
- **Smoke: 141/141** (HVF and TCG). New:
  - `ticket-rotation`: 20 s keys; a ticket issued late in the first interval resumes after the rotation;
  - `ticket-restart`: a ticket from before a reboot gives a full handshake, logged as `unknown key 1`.

**Not done** (SECURITY-PLAN H2 status):
- the x86 half of the 10-minute differential run (with X1–X8);
- an embedded MQTT client on firmware;
- tlsfuzzer's stock HTTP scripts;
- the ticket keys in a key slab, which does not exist yet (H4).

## H3 — TCP/IP assurance and DoS resistance (2026-10-30)

PROMPT-security.md §H3 and PLAN.md decision 5; plan and status in SECURITY-PLAN (H3). ADRs for the rotation and bounds live with parts 1–2. This entry is **part 3**: the adversarial attack tool. Parts 1–2 (earlier commits) added bounded retained messages with freed trie nodes (H0-W1), SYN-cookie key rotation (H0-W3), the packetdrill-style scripted tests and the stateful RFC 9293 model test.

**Done (part 3)**

- **`tools/attack/`** — host-side adversarial clients, dev only, `publish = false`, never shipped. It drives a running dev VM and prints what it sent and saw; the *expected* outcome (memory within limits, per-core CPU bounded, counters correct) is asserted in `scripts/smoke.sh` against the kernel's own serial log. Two transports:
  - the usernet TCP port forward, for application-level attacks;
  - a **raw layer-2 datagram socket** (`scripts/run-qemu.sh --dgram LOCAL:REMOTE`, a QEMU `dgram` netdev): the tool becomes the guest's entire network — a tiny ARP responder and fixed DHCP lease bring the broker up, then it injects crafted Ethernet/IPv4/TCP frames. `tools/attack/src/wire.rs` re-states just enough wire format to be an adversary, so a bug there cannot flatter the broker.
- **TCP floods** (raw L2): `syn-flood`, `ack-flood`, `rst-flood`, each 20 000 segments from pseudo-random on-subnet sources at a paced rate.
- **Application attacks** (TLS port): `slowloris` at three stages (`--stage tcp|tls|mqtt`); `half-records` (TLS flights and the CONNECT delivered in 4-byte fragments with gaps, so each record spans many TCP segments); `max-packets` (PUBLISHes at the size limit, then one well over it); `topic-flood` (retained messages on many distinct topics, paced under the device rate to reach the retained cap); `sub-flood` (one over-long SUBSCRIBE); `keepalive-abuse` (a PINGREQ flood); `identities` (many distinct device certificates from one address).
- **Kernel-side evidence:** a per-core TCP-stats log line every 5 s while counters move (`crates/kernel/src/netproto.rs`): segments in, SYN cookies sent/ok/bad, full-table refusals, RSTs sent and rate-limited, bad segments, live connections. This is what the smoke scenarios grep.
- **Smoke scenarios** `attack_raw` (one dgram boot per flood) and `attack_app` (one usernet boot, all application attacks in sequence).

**Observed** (M4 Pro, HVF; mirrored under TCG in CI)

- **SYN flood:** 20 000 SYNs → ~20 000 SYN cookies issued across the worker cores, `0 connection(s)` — no per-connection state — `0 bad`, heap flat, `NOT:memory allocation of`.
- **ACK flood:** bare ACKs for unknown connections → `cookies … bad` and the RFC 5961 rate cap plainly visible: `RST 600 sent (9402 rate-limited)` per core at 8 000 ACK/s (`rst_per_sec = 200` × the ~3 s window), `0 connection(s)`.
- **RST flood:** RSTs for unknown connections dropped — `RST 0 sent (0 rate-limited)`, 0 RSTs back, 0 state.
- **slowloris:** `admission: … refused: too many handshakes in flight` climbs by powers of two; per-core live connections ceil at the per-IP in-flight cap (32) and fall back to 0 once the attacker drops. (On loopback the attacker and any probe share one source address, so the per-IP cap is what bounds them — exactly the intended behaviour.)
- **half-records:** the fragmented handshake and CONNECT complete, CONNACK received (≈0.3 s), proving record reassembly without unbounded buffering.
- **max-packets:** the oversize packet is a `ProtocolError` close.
- **topic-flood:** `broker: … retained message(s) not retained … over an identity's limit of 32`.
- **sub-flood:** the over-long SUBSCRIBE closes the session.
- **keepalive-abuse / identities:** absorbed, heap flat.

**Tests**

- `make check` green (host + bare-metal clippy, host tests).
- `make smoke` green (HVF and TCG): new `attack-syn-flood`, `attack-ack-flood`, `attack-rst-flood` and `attack-app` scenarios pass alongside the existing suite.

**Not done / deviations** (SECURITY-PLAN H3 status)

- Reconnect storms stay in `tools/loadgen` (the `storm` scenario, M16); not duplicated here.
- The raw-L2 floods exercise the aarch64 VM only; the x86 half follows the X-track port.
- The full unbounded-work audit table is written up under H10, not re-listed here.

## X1 — x86_64 builds (2026-10-30)

X86-PLAN §X1. `make build ARCH=x86_64` links an ELF; `make check` is green on both targets.

**Done**

- **`crates/arch-x86_64`:** every facade item exists with the contract's signature and stops with "not implemented until X<n>" when called. Pure parts already work and are tested: CPUID decoding (`features`), MSI composition (`msi`).
- **Facade split:** `crates/arch/src/{aarch64,x86_64}.rs` re-export the per-architecture crate under the same module names; `contract.rs` now binds both.
- **Target:** `targets/x86_64-urmqtt-none.json` — hard-float, x86-64-v2 (`sse4.2,popcnt,cx16`), no red zone, kernel code model, static relocation. Needs `-Zjson-target-spec` with `-Zbuild-std`. **D3 decided: option (a), the custom target** — spike: an `f64` multiply compiles to `mulsd`.
- **SQLite:** `crates/store/build.rs` picks clang flags per architecture (`-march=x86-64-v2 -mcmodel=kernel -mno-red-zone` on x86).
- **Linker:** `crates/kernel/linker-x86_64.ld`; the entry `_start` is a stub that calls `urmqtt_kmain` and halts.
- **Kernel:** Limine MP identity (`mpidr` / `lapic_id`) behind `smp::hw_id_of`; PSCI conduit only on aarch64.
- **Makefile:** `ARCH=aarch64|x86_64`, `make check-x86` (clippy for the x86 kernel) inside `make check`.

**Not done**

- CI jobs (x86 build, KVM probe, x86 host tests): follow with X2's smoke jobs.
- The reproducibility double-build of the x86 ELF, and the `xmm` audit: meaningful once the ELF contains the kernel (X2).

## X2–X7 — x86_64 bring-up, written as separate pieces and first booted in X8 (2026-10-30)

X2 (boot, exceptions), X3 (paging), X4 (interrupts, time), X6 (ACPI) and X7 (PCI, virtio) were written by separate agents against the facade contract. Only X2 had ever booted when they merged; X3, X4, X6 and X7 existed as compiled, host-tested code. The first complete boot happened in X8 (below), so this entry records what each piece looks like **now that it runs**, under **QEMU 11.1.2 TCG on an Apple M-series host**. Nothing here ran on KVM or on real hardware. ADRs: 042, 044–047, 055–058.

**X2 — boot and exceptions.** Limine x86 (UEFI and BIOS), COM1 and framebuffer log, GDT/TSS/IDT with IST stacks, decoded fault reports, power-off by QEMU's ACPI port, the x86-64-v2 baseline refusal. Smoke (TCG): `x86-boot-q35-uefi`, `x86-boot-pc-bios`, `x86-boot-v2-minimal`, `x86-baseline-refuse`, `x86-fault-{pf-null,ud,gp,df}`, `x86-brk-resume`, `x86-panic`: all pass. Added in X10: the refusal message is also drawn on the framebuffer (below).

**X3 — memory protection.** 4-level tables, PAT, EFER.NXE, CR0.WP, CR4.SMEP/SMAP/UMIP (`mm: protections nx=on wp=on smep=on smap=on umip=on` under `-cpu max`), locked page tables, the aarch64 W^X audit line (`selftest: W^X ok (15 729 leaf mappings audited, 0 W+X, ...)`). Smoke: `x86-wx-write-text`, `x86-nx-exec-heap`, `x86-guard-overflow`, `x86-sealed-write` (CR2 equals the sealed address), `x86-fault-unmapped-mmio`. **Not done:** CET (ADR-047), `x86-smap-user-access` (there is no user mapping to test with).

**X4 — interrupts and time.** x2APIC, I/O APIC, 8259 masked, TSC frequency from the HPET under TCG (`time: tsc 999 850 000 Hz from Hpet`), one-shot LAPIC timer calibrated against the TSC (TCG has no TSC-deadline), 10 ms tick on every CPU, MSI-X completions through the local APIC (`msi-x: 3 blk completion interrupt(s) via the local APIC`). **Not verified:** kvmclock, KVM PV EOI, the TSC-deadline timer, an invariant TSC (all absent under TCG). The IRQ latency lines under TCG (`avg` about 2 ms) measure TCG's timer, not hardware. `x86-time`'s "clock monotonic across cores" check was not written.

**X6 — platform discovery.** MADT, FADT, HPET, MCFG and `\_S5` parsed from the real tables of QEMU q35 (`acpi: lapic=0xfee00000 ioapic=1[0@0xfec00000+0] ovr=5 hpet=0xfed00000 pmtmr=0x608 reset=io:0xcf9=0xf s5=0/0 sci=9`). The kernel now also uses the FADT for power control (PM1a_CNT with the `_S5` type, the reset register; X10).

**X7 — PCI and virtio.** ECAM on q35, configuration mechanism #1 on pc (`pci: ports 0xcf8/0xcfc (mechanism #1) buses 0-255`), virtio-blk, -scsi, -net and -rng with MSI-X, RDSEED/RDRAND mixed into the entropy pool. Smoke: `x86-disk-q35`, `scsi-boot-*`, `first-boot*`, `no-hw-rng` (`-cpu max,-rdrand,-rdseed`, no virtio-rng: the jitter fallback seeds the CSPRNG and its health tests pass), and the pc machine through the universal-image scenarios.

**Bugs found while booting this code** (all fixed in X8/X5):

- `cpu::wait_for_interrupt` was `sti; hlt; cli`: after the first idle wait interrupts stayed off for the rest of the boot (no MSI-X completion ever arrived, the blk self-test failed). It now keeps the caller's interrupt flag.
- `cpu::switch_to` took its arguments in a different order from the contract (the AArch64 shape: main stack, exception stack, argument), which handed the exception stack top to the continuation as its argument. Harmless by luck.
- The power-off in smoke mode raced QEMU's handling of the ACPI request against the `isa-debug-exit` fallback, which always exits with status 1: `scsi-boot-reopen` failed once in 68. It waits 200 ms now.
- `ApBoot::capture` and the AP entry were `unimplemented!`, and the GDT/TSS/IDT were boot-CPU statics: both are X5's work and are done below.

## X5 — x86_64 SMP (2026-10-30)

X86-PLAN §X5; ADR-059. QEMU TCG only.

**Done**

- Limine's MP request with the x2APIC flag. Each AP enters `urmqtt_ap_entry` (assembly) in the bootloader's tables, copies the boot CPU's EFER.NXE, PAT, CR4, CR3 and CR0, sets up x87/SSE, switches to its kernel stack and calls `urmqtt_ap_prepare`: its own GDT and TSS, the shared IDT, GS base, XSAVE state, then the kernel's `ap_main`.
- Per-CPU GDT/TSS (a TSS can be loaded once). The IST stacks of an AP are the top of its mapped exception stack, 64 KiB on x86; `which_ist` covers every CPU.
- IPIs through the ICR (x2APIC MSR; xAPIC two-write path), `hlt` idle, the same bring-up checks as aarch64.
- **No TLB shootdown** is implemented, on purpose (ADR-056): after the tables lock nothing is remapped.

**Tests**

- `make check` green; smoke `x86-disk-q35` (4 CPUs: `smp: 4/4 cpus online (3 application processors started)`, `ipi: 12/12 ordered pairs ping-pong ok`, `smp: 4/4 cpus ticking on their own timer`) and `x86-smp8` (`ipi: 56/56 ordered pairs ping-pong ok`).
- `dp-bench` and `log-crash` run on 3 to 5 CPUs on x86 and pass.

**Not done**

- `make run-smp ARCH=x86_64`: `run-qemu.sh --smp N` works, the Makefile target is aarch64-shaped.
- KVM PV IPI, more than 64 CPUs, hot-plug.
- Not run on KVM or hardware: AP start timing, x2APIC IDs above 255 and AMD or hybrid-core topologies are untested.

## X8 — x86_64 feature parity (2026-10-30)

X86-PLAN §X8; ADR-059 and the entries above. **QEMU 11.1.2 under TCG on an Apple M-series host. Never run on KVM or real hardware.**

**Done**

- **One boot sequence for both architectures** (`crates/kernel/src/boot.rs`). The x86 path used to stop after the CPU summary, and the aarch64 sequence was compiled on x86 as a dead copy. Now the sequence (platform discovery, memory and `vm::build`/`activate`, time, interrupts, PCI and devices, entropy, crypto dispatch, storage, SQLite, SMP, the MQTT service, the data plane) is one code path with seams in `boot_aarch64.rs` and `boot_x86.rs`: console, time base, privilege label, feature detection, BTI/PAC, the interrupt controller and its timer vector, the stack-switch log text, and the faults that exist on one architecture only. The aarch64 boot log is unchanged, and `make iso` and `make raw` produce the same bytes as before for the same kernel (compared against the pre-X10 scripts).
- **Everything the earlier agents wrote booted on the first attempt, after one bug fix** (`wait_for_interrupt`, see X2–X7). The first full boot to `URMQTT READY` on one CPU, then SMP (X5).
- **Shared code changes** (small): `irq::init_apic` next to the GIC path; the `Image` of the installer; the log line `irq: N interrupt(s) without handler (last: V)` names the vector; the entropy log lines name RDRAND/RDSEED on x86; unused virtio-blk disks get a no-op MSI-X handler.
- **`scripts/run-qemu.sh --arch x86_64`** now takes `--disk`, `--bus scsi`, `--data`, `--fwd`, `--pcap`, `--dgram` like the aarch64 path; `URMQTT_ARCH` selects the architecture for the scripts that call it (`smoke.sh` sets it).
- **`scripts/smoke.sh --arch x86_64`** (disk-based, q35+OVMF, 4 CPUs unless stated): `x86-disk-q35`, `x86-smp8`, the memory-protection faults, `x86-crypto-soft`, `x86-simd-irq`, `net-echo`, `mqtt-plain`, `mqtt-tls` (all four rejections), `ticket-rotation`, `ticket-restart`, `control`, `registry-allowlist`, `control-persist`, `time-before-build`, `db-bench`, `watchdog`, `db-crash` (every acknowledged commit survived SIGKILL), `log-crash` (1 114 112 flushed records recovered), `log-tear`, `dp-bench`, `mqtt-persist`, `storm`, `attack-{syn,ack,rst}-flood`, `attack-app`, `observability`, `first-boot`, `first-boot-crash` (four fault points), `scsi-boot`, `iso-as-cd`, `own-damaged`, `disk-tool`, `no-hw-rng`, and the gratuitous-ARP pcap check. Together with the X2 scenarios the final run is **67 passed, 0 failed** (`scripts/smoke.sh --arch x86_64 --accels tcg`); an earlier run failed `scsi-boot-reopen` once, the power-off race fixed above. **aarch64 non-regression: `scripts/smoke.sh` (HVF and TCG) 149 passed, 0 failed**; `make check` green with 452 host tests.
- **Cross-architecture data disks** (`scripts/smoke.sh --arch universal`, with the universal raw disk, X10): a VM of one architecture writes a retained message, a persistent session with a queued command and a telemetry record, is killed, and a VM of the other architecture on the same disk prints `db: restored 1 retained message(s), 1 persistent session(s) with 1 queued message(s), 1 revoked serial(s), 3 known device(s)` and `telemetry: log recovered ... 1 record(s)` and serves both messages to the real mosquitto clients. All four directions pass: aarch64 (HVF) to and from x86 UEFI (TCG), aarch64 to and from x86 BIOS.

**Observed under TCG** (not hardware numbers): `dp-bench` scaling with 4 worker cores 4.39x (reported only under TCG); `smp: 8/8 cpus online`, `ipi: 56/56 ordered pairs ping-pong ok` (round trip about 76 µs); interrupt latency in the milliseconds (TCG's timer).

**Not done**

- The x86 `install-iso` scenario inside `--arch x86_64` (the installer is covered by `--arch universal`), `gicv2` (no GIC on x86), the `x86-time` scenario, `x86-smap-user-access`, `x86-cet-*`, `x86-devices-*`/`x86-scsi` as separate scenarios.
- Struct sizes compared across architectures by a host test (only the `const` asserts compile).
- `make bench ARCH=x86_64`, bytes per idle connection on x86, ELF size table: not measured.
- The aarch64 non-regression numbers (`make bench`, bytes per connection) were not re-measured; the aarch64 smoke, the host tests and the byte-identical images are the evidence.
- KVM, real hardware, hybrid-core or AMD topologies.

## X10 — One multi-platform ISO (2026-10-30)

X86-PLAN §X10; ADR-043. **QEMU only: aarch64 UEFI under HVF and TCG, x86_64 q35+OVMF and pc+SeaBIOS under TCG. Not run on KVM, on a real VPS or on real hardware; Secure Boot is not supported.**

**Done**

- **`scripts/mkiso.sh --universal`** (`make universal ENV=...`) builds both kernels' ISO and a raw disk image (`...-universal.iso`, 48 MiB; `...-universal.img`, 14 MiB). Layout, Limine 12.9.4 findings and alternatives in ADR-043. In short: `if_arch` entries pin each architecture's kernel by blake2b, an ESP with both UEFI loaders and both kernels, a BIOS boot partition with `limine bios-install`, an ISO whose own ESP carries the menu and `/disk.img`, El Torito BIOS and UEFI entries and a hybrid GPT.
- **The installer writes a finished disk image** (`urmqtt_store::install::write_boot_image`, host-tested, including refusal of malformed images before any write); the aarch64-only ISO's ESP module path is unchanged.
- **`make raw` and the ESP unchanged**, byte for byte (compared against the pre-X10 `mkiso.sh` and `mkraw.py` for the same kernel; so was `make iso` before the wallpaper below); `mkraw.py` gained `--bios-boot` and is unchanged without it.
- **Boot menu look:** the ISO menus (aarch64 `make iso` and the universal ISO; the no-menu ESP config shows nothing) show `assets/boot/wallpaper.png` (ALDO TECH mark and `https://aldo.tech`), `wallpaper_style: centered`, backdrop `2c2c44`, an empty `interface_branding` and `interface_help_hidden: yes`: no `Limine 12.9.4` header and no key-help lines; the keyboard still works and the countdown text stays. The wallpaper is pinned `#<blake2b>` like the kernels (Limine 12.9.4 accepts it) and sits on every volume Limine boots the menu from (ISO tree, the ISO's ESP). Screenshots checked under aarch64 UEFI (HVF), q35+OVMF and pc+SeaBIOS: logo and URL below the entries; on 800x600 (aarch64 ramfb) the countdown line touches the URL. `URMQTT_MENU_TIMEOUT` (dev) lengthens the menu for screenshots. This changes the aarch64 ISO bytes (new file) but not its reproducibility.
- **Reproducible:** two builds, and one a second later, give identical ISO and raw image bytes. `scripts/repro.sh prod --universal` builds from two worktrees and compares both ELFs, the ISO and the raw image (result in the rerun below).
- **`make dist-universal`:** both ELFs, ISO, raw image, `SHA256SUMS`.
- **Framebuffer console on x86:** the boot log was already drawn on the Limine framebuffer; the baseline-refusal message (a CPU below x86-64-v2, `-cpu qemu64`) was COM1 only, and is now also drawn there: white text on black, doubled 8x8 font, from assembly without SSE (the CPU is below the baseline the compiler assumes). Checked by screenshot (`screendump`) under UEFI and under BIOS. Missing hardware is named in the log, which the framebuffer shows: legacy-only virtio, NICs without a driver, no entropy source (ADR-058; table in docs/DEPLOY.md §5b).
- **x86 power control from ACPI** (FADT PM1 control blocks with the DSDT's `_S5` type, the FADT reset register) before QEMU's ports.

**Smoke** (`scripts/smoke.sh --arch universal`: 27 scenarios, 0 failed)

- `universal-iso-{aa64-hvf,aa64-tcg,x86-q35-uefi,x86-pc-bios}`: **the same file** (its sha256 is in the scenario name and re-checked after every boot) boots on all four machines.
- `universal-raw-{aa64,x86-uefi,x86-bios}`: the raw image boots on all three paths and creates its data partition.
- `universal-install via {aa64,x86-uefi,x86-bios}`: the installer entry runs on each machine, writes 14 MiB and verifies it; **each installed disk then boots on all three paths** (9 combinations).
- `cross-arch-*`: four directions (X8).
- By hand: the ISO written to a 64 MiB "disk" boots under q35+OVMF and pc+SeaBIOS (it runs the broker without persistence; the hybrid ISO is not a supported data layout, ADR-043).

**Not done**

- The release workflow and SLSA provenance for both architectures; `make dist` (aarch64) is unchanged and does not include the universal files.
- Secure Boot (H8), KVM, a real VPS (Contabo or another), real firmware, USB sticks.
- A BIOS-boot scenario with a CD **and** a disk under SeaBIOS at once beyond the installer scenarios.

**Try it on a VPS** (docs/DEPLOY.md §5b): `make universal ENV=prod`, upload `build/urmqtt-prod-<version>-universal.iso`, boot the VPS from it, pick *Install urMQTT on this machine's disk*, detach the ISO, boot again. On the VNC console look for `URMQTT BOOT ... arch=x86_64`, `cpu: ... hypervisor=KVMKVMKVM`, `pci:`, `blk: boot disk is virtio-...`, `net: mac ..., link up`, `URMQTT READY`.

## O1 — `$SYS/` introspection and the operator role (2026-10-30)

PLAN.md "O1, O2"; ADR-060. **QEMU only (aarch64 under HVF and TCG, x86_64 under TCG); not run on KVM or real hardware.**

**Done**

- **The operator role.** `acl.operator_ids` (exact identities, a required key, empty means none) in the config schema, validated at build time: exact ids only, no duplicates, never also a service id, and no ACL pattern may name `$SYS/` (the build says so). Dev lists `operator` (the existing `make certs` identity), `deploy/prod/config.toml` lists `operator` too. `urmqtt_broker::acl` has `Role::Operator`: only it subscribes to `$SYS/#` and publishes `$SYS/console/in` and `$SYS/query/info`; devices, services and bootstrap identities are refused whatever their patterns say. The role needs an authenticated (TLS) identity: an operator id on the dev plaintext port is a device. Operators are exempt from the registry allowlist, like services.
- **What an operator publishes is a request.** Not routed, not retained, not persisted, not offered to other shards; bounded queue of 16; any other `$SYS/` topic is dropped, also for the operator; a will naming `$SYS/` refuses the CONNECT.
- **Retained `$SYS/broker/...` every 10 s**, from each data core into its own shard: `version`, `uptime`, `arch`, `cpu/cores`, `cpu/busy/<core>`, `memory/{total,used}`, `disk/{total,used}`, `clients/{connected,total}`, `subscriptions`, `retained`, `messages/{received,sent}`, `connections/refused`, `tls/server_cert_days`, `console/dropped`. They are in memory only and outside the device retained budgets. The numbers are relaxed counters each shard (and the DB core, for the disk) keeps for itself; `Broker::stats` is O(1) now (counters for subscriptions and online connections), and `Idle` keeps the per-core busy percentage.
- **`$SYS/query/info`:** any payload, answered with one JSON document on `$SYS/query/info/response`. **Deviation:** the plan said MQTT 5 Response Topic; the broker speaks 3.1.1 only, so the reply topic is fixed (ADR-060).
- `scripts/gen-operator-cert.sh DIR [ID] [DAYS]` issues an operator certificate from a deploy directory's CA (subject CN and `URI:urn:urmqtt:service:<id>`, like the dev operator and the production device-001). `deploy/prod/services/operator.{pem,key}` was issued with it from the production test CA; the key is git-ignored.

**Tests**

- Host: broker (the role in `acl.rs`; an operator with a certificate subscribes, a device, the service and a plaintext "operator" are refused; retained `$SYS/` topics outside the budgets and not stored or replicated; requests reach the kernel and nothing else; bounded; wills; counters), `sys.rs` (the fixed topic list, the JSON), config-schema (`operator_ids` rules, `$SYS/` patterns).
- Smoke `sys-operator` (mutual TLS, the real operator certificate): every topic of the list arrives and is plausible, uptime refreshes, per-core busy, retained flag, the query's JSON, a device and the backend service are refused `$SYS/#`, the operator cannot forge a `$SYS/` topic.

**Not done**

- MQTT 5 Response Topic, a per-operator reply topic.
- `memory` is the kernel heap, not the machine's RAM; `disk/used` counts SQLite's files, not the telemetry ring.

## O2 — The console over MQTT (2026-10-30)

PLAN.md "O1, O2"; ADR-060; docs/OPERATE.md. **QEMU only (aarch64 under HVF and TCG, x86_64 under TCG); not run on KVM or real hardware.**

**Done**

- **`$SYS/console/out`:** every kernel log line, `[time] LEVEL text`, QoS 0. The log crate keeps a numbered ring of the last 128 lines (a fixed array under the sink lock, no allocation) that every data core reads with its own cursor, 16 lines per pass; a shard keeps the last 64 and replays them to a new subscriber. Nothing waits for a reader: a slow subscriber loses lines (the broker's QoS 0 backpressure), a core that falls more than the ring behind loses the oldest; both are counted (`$SYS/broker/console/dropped`, and a line on the console).
- **`$SYS/console/in`:** one command per message, a closed set: `help`, `status`, `log level <error|warn|info|debug|trace>` (never above the build-time maximum), `reboot` (reply, 1 s, reset). The parser accepts one line of printable ASCII up to 64 bytes; `status; reboot` is an unknown command. No shell, no code, no data. **Rate limit:** a burst of 5, then one per 2 s per shard, on top of the session's publish rate. **Audit:** every command, accepted or refused, is logged with identity and text (`console: operator ran "status"`), whatever the log level (`urmqtt_log::audit`).
- Replies go to the console of the shard the operator is on; the audit line goes through the log and so reaches every shard's console.
- docs/OPERATE.md: how an operator connects (certificate, client id, MQTTX and mosquitto settings), the topics, the commands, issuing and revoking certificates. ADR-060, a SECURITY.md entry (threat model).

**Tests**

- Host: log crate (independent readers, bounded reads, lost count, the audit line at level `error`), `sys.rs` (the closed command set with refusals, the status text, the limiter), broker (replay from the bounded ring, a reader that never reads cannot block).
- Smoke `sys-operator` (adds to O1's): the ring is replayed to a new subscriber, `help`, `status`, `log level` (and the level is restored), refusal of unknown and malformed commands, no command chaining, the audit lines on the console and on the serial log, the rate limit (9 of 12 refused in the burst), a device and the backend service refused `$SYS/console/out` and unable to run `reboot` or lower the level, the operator cannot publish to `$SYS/console/out`. `sys-reboot` runs `reboot` as the operator and checks that the VM resets (QEMU runs with `-no-reboot`, so the reset ends it) and that the command was audit-logged: aarch64 under HVF and TCG, x86_64 under TCG.

**Not done**

- MQTT 5, a streaming console input (a command per message only), an operator reply topic of its own.

**Final runs (both milestones):** `cargo test --workspace` green (broker 53, config-schema 41, log 6 tests); the steps of `make check` run by hand (fmt, typos, check-arch-leaks, clippy for the host and both kernels with and without `selftest`); the full `scripts/smoke.sh`: **151 passed, 0 failed** (aarch64, HVF and TCG); the full `scripts/smoke.sh --arch x86_64`: **68 passed, 0 failed** (TCG). `sys-reboot` was run on all three accelerator and architecture pairs after those runs. (Building from a worktree under the main checkout needs `RUSTFLAGS` set explicitly: cargo also reads the parent's `.cargo/config.toml` and the duplicated `-Zbranch-protection` breaks rustc.)
