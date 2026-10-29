# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- M0: Cargo workspace with all crates, pinned nightly toolchain and Makefile.
- M0: Validated build-time configuration (`deploy/<env>/config.toml`) compiled into typed constants.
- M0: Dev certificate generator, including negative-test certificates.
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
