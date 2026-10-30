# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- X2–X8: x86_64. The same kernel boots and serves on x86_64 under QEMU TCG (q35 with OVMF, pc with SeaBIOS): boot and decoded exceptions, 4-level paging with NX/WP/SMEP/SMAP/UMIP and the same W^X audit, ACPI platform discovery, x2APIC/I/O APIC/HPET-calibrated TSC, SMP (8 CPUs tested), PCI by ECAM or port I/O, virtio with MSI-X, RDSEED/RDRAND entropy, ACPI power-off. `scripts/smoke.sh --arch x86_64` runs the MQTT, TLS, storage, crash, storm and attack scenarios. **Not run on KVM or real hardware.** The crypto backends are the portable ones until X9 (ADR-042, ADR-045, ADR-056–059).
- X10: one universal ISO (`make universal`) that boots on aarch64 UEFI, x86_64 UEFI and x86_64 legacy BIOS, installs itself on the machine's disk, and whose installed disk boots by all three paths; data disks are portable between the architectures. The x86_64 refusal message for a CPU below x86-64-v2 is also drawn on the framebuffer (ADR-043).

- O3: **live mode.** The ISO's first menu entry runs the broker from RAM with no disk: the data layout, SQLite and the telemetry log sit on an in-memory block device (`storage.ram_percent` of RAM, default 10), loudly ephemeral (`EPHEMERAL: data is lost on reboot`, banner, `urmqtt.storage.ephemeral`). `storage.mode = "disk" | "auto" | "ram"` is required outside dev; the committed production template stays `"disk"` (live refused). The install entry and disk boots are unchanged (ADR-061, ADR-062).

### Changed

- The boot sequence is shared by both architectures (`boot.rs`; ADR-059). The aarch64 boot log is unchanged.

## [0.1.0] - 2026-10-30

The first release: urMQTT as an aarch64 VM image, pre-alpha. The release
assets are a **dev** build with throwaway certificates, for evaluation only;
production images embed the operator's own keys and are built with
`make dist ENV=prod` (docs/DEPLOY.md).

### Added

- S1b: the ISO installs itself. A boot menu entry *Install urMQTT on this machine's disk* writes the raw image (mkraw-identical) onto the one qualifying disk after a 30 s on-screen countdown, verifies it and powers off. An interrupted install never leaves a disk that boots half-written. `install` is the only command-line word production honours (ADR-052).
- S1: single-disk model (ADR-051). The data lives in a partition of the boot disk, which is found by its GPT disk GUID and created crash-safely on the first boot; no other disk is ever written, and a damaged data partition is refused, never reformatted. Also new: `tools/urmqtt-disk` (info, verify, export-db, export-telemetry, import-devices, create, update-boot); fault injection (`test=disk-fault:`); fuzz target `gpt_parse`.
- H1: identity lifecycle without new images (ADR-048–050). Ed25519-signed control messages on `$urmqtt/control` (offline key, persisted sequence numbers, validity windows) revoke and unrevoke certificates and maintain an allowlist at runtime; live connections of a revoked or disallowed identity close within milliseconds. Also new:
  - trust anchors by role: operational, with CA rotation; bootstrap, limited to `provision/{id}/#`;
  - `registry.mode = "allowlist"`;
  - expiry checks at build time and at runtime;
  - the image's build time as the clock's lower bound;
  - `tools/urmqtt-control`; fuzz target `control_message`.
- X0: architecture facade `urmqtt-arch` with an API contract, all assembly confined to `arch-aarch64` (checked by `scripts/check-arch-leaks.sh`), CPU feature dispatch with a `[cpu] disable` opt-out (ADR-040, ADR-041).
- S0: byte-level specification of the data disk format (docs/DISK-FORMAT.md) with a spec-vs-code test and frozen golden images.
- H0: security baseline: TCB and `unsafe` inventory (docs/AUDIT.md, `make audit`), parser and mitigation tables, weaknesses list.

- M0: Cargo workspace with all crates, pinned nightly toolchain and Makefile.
- M0: Validated build-time configuration (`deploy/<env>/config.toml`) compiled into typed constants.
- M0: Dev certificate generator, including negative-test certificates.
- GICv2 support (ADR-039), so urMQTT runs as a KVM guest on GIC-400 hosts such as the Raspberry Pi 4/5: discovery from DT and ACPI, `Gicv2` driver, version-neutral IRQ/SGI layer, `run-qemu.sh --gic 2`, `gicv2` smoke scenarios (boot and mTLS broker under TCG), `scripts/kvm-host/` (installer, launcher, systemd unit) and the Raspberry Pi section in docs/DEPLOY.md.
- Entropy fallback for clouds without a hardware RNG (`entropy.fallback = "jitter"`: health-tested CPU jitter, conservative estimate); SMP fixed on CPUs without pointer authentication (Neoverse N1 / Ampere Altra, Cortex-A72); unsupported NICs named at boot; `run-qemu.sh --cpu/--no-rng`; `no-hw-rng` smoke scenario.
- virtio-scsi data disks (clouds attach disks that way): polled driver, `DataDisk` abstraction, `run-qemu.sh --bus scsi`, `scsi-disks` smoke scenario; Hetzner and Oracle Always Free deployment steps.
- M17: Deployment: reproducible images (paths remapped, `make repro` builds HEAD twice in separate worktrees, CI job), raw GPT disk image (`make raw`, `scripts/mkraw.py`), deterministic FAT images independent of the mtools version (`scripts/fat-stamp.py`), minisign signing (`make sign`, optional in the release workflow), dev-only benchmark and TLS client behind the `selftest` feature (prod ELF 180 KiB smaller), partitioned disks never used as the data disk, prod heap 1024 MiB, `raw-disk` smoke scenario, docs/DEPLOY.md for KVM/Proxmox and Hetzner.
- M16: Hardening and operations: admission refusing new connections on a low heap (`memory.min_free_mb`), a DB core that is behind, too many handshakes in flight per core or per source address (new config keys), or the handshake rate; memory returned after peaks (lowest-id-first slabs, shrinking tables); handler watchdog with log/drop/reset and stuck-core reset; health check; rate-limited logs; RFC 5424 syslog and statsd over UDP; revocation re-checked on TLS resumption; loadgen `storm`; smoke scenarios `storm`, `watchdog`, `observability`; fuzz targets `net_frame`, `tls_record`, `x509_identity`, `broker_input`, `telemetry_recover`; threat model in docs/SECURITY.md.
- M15: Memory per connection: exact heap accounting (requested and block bytes) with a per-connection report; compact TCP, TLS, connection and session state with size assertions; index-only TCP table; TLS key and IV derived per record; record state inline; slab chunks sized to heap blocks; device-scoped subscriptions without per-device trie nodes; loadgen `--subscribe`. 494 B per idle mTLS connection at 10k.
- M14: Own server-only TCP/IP stack replacing smoltcp: SYN cookies (SipHash), open-addressing connection table, hierarchical timing wheel, RFC 6298 RTO, NewReno, persist timer, RFC 5961 checks, ACK coalescing with replies, no TIME_WAIT; own Ethernet/ARP/IPv4/ICMP/UDP and DHCPv4 client; event-driven MQTT service; loss-simulation tests and tcp_segment fuzz target.
- M13: Multicore data plane: per-core smoltcp stacks, TLS and broker shards; core 0 dispatcher with Toeplitz/RSS steering; sessions on home shards with relayed connections and credit flow control; cross-core fan-out with retained replicas; per-CPU heap caches; asynchronous virtio-net TX; adaptive polling with WFI and wake SGIs; in-guest dp-bench (linear to 4 cores) and a real load generator.
- M12: Telemetry log: per-core partitions of segment rings on the data disk, CRC per record salted by segment sequence, batched sector-aligned writes by the DB core fed through per-core SPSC rings, crash recovery with torn-tail truncation, size and age retention; million-record SIGKILL test and torn-write test in smoke.
- M11: SQLite 3.54.1 inside the kernel: freestanding build, raw-disk VFS with superblock and region table, WAL + exclusive locking, quick_check at boot, embedded migrations; DB core fed by SPSC rings with 5 ms / 512-op batching; persisted device registry, revocations, retained messages and persistent sessions; crash-consistency tests (host power-loss model, SIGKILL in smoke); disk_layout fuzz target.
- M10: TLS 1.3 with mutual TLS on port 8883: rustls handshake with an own RustCrypto provider, own record layer (AES-128-GCM, ChaCha20-Poly1305, KeyUpdate), identity from CN or SAN URI, revocation list, stateless resumption, handshake admission control; mosquitto mTLS scenarios with all four rejections.
- M9: Sans-IO broker core (QoS 0/1, wildcards, retained, LWT, persistent sessions, ACL with service identities, limits) on plain TCP in dev builds; mosquitto acceptance scenarios.
- M8: Zero-copy MQTT 3.1.1 codec (no_std, no unsafe, streaming, bounded), property tests, mosquitto interop tests, mqtt_decode fuzz target.
- M7: smoltcp network prototype: DHCPv4, ARP, ICMP echo to the gateway, dev TCP echo service; service-style smoke tests.
- M6: PCIe enumeration, virtio-pci (rng, blk, net), MSI-X via GICv2m, ChaCha20 CSPRNG with hardware-entropy requirement, blk/net self-tests.
- M5: Unified platform description from DTB or ACPI (CPUs, GIC, timer, UART, PSCI, PCIe ECAM); DTB/ACPI fuzz targets.
- M4: SMP bring-up (Limine MP), per-CPU data, per-core GIC + timer, SGI IPIs with all-pairs ping-pong test.
- M3: GICv3 driver, generic timer, 10 ms tick, IRQ dispatch, measured IRQ latency (busy-poll vs WFI).
- M2: Kernel page tables with enforced W^X, locked tables, guard pages, frame allocator, buddy heap, PAC/BTI.
- M1: Bootable UEFI ISO, console, decoded exception reports, PSCI, `make run`/`smoke`, CI smoke job.
- M0: CI and CD: lint, host tests, kernel build, cargo-deny, fuzzing, CodeQL, Scorecard, Dependabot and a release workflow with provenance.

[Unreleased]: https://github.com/zeljan-alduk/urMQTT/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.1.0
