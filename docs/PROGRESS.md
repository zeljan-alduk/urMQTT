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
