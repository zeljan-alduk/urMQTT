# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.3.0] - 2026-11-02

The first release with a runtime configuration, an optional plaintext listener, an x86_64 port, a storage track
(layout v2, growth, discard, in-disk backups, scrubbing, encryption at rest) and an audit package. It also covers
everything that was tagged as v0.2.0 and v0.2.1 without release notes (the template ISO and the builder page; TLS
off, configuration format 3).

**Compatibility.** Nothing here breaks an existing image or disk. A configuration blob of format 1, 2 or 3 is still
read, and format 4 is written only when disk encryption is switched on, so every other image still boots on a kernel
of v0.2.1. A layout-v2.0 data disk opens and is upgraded to v2.1 by one superblock write at boot (an older kernel then
refuses it). A layout-v1 disk is refused by the kernel and converted offline with `urmqtt-disk migrate`, as before.
The builder page picks the newest release whose template can do what the form asks.

**Limits, stated plainly.** The first supported target is a VPS or VM under KVM. The smoke suites run on aarch64 under Apple HVF and TCG and on x86_64 under QEMU TCG; **x86_64 has also been run on a real KVM VPS** (Contabo, 4 vCPU AMD EPYC: boot, mutual TLS under load and a comparison with Mosquitto, X11, at the H7 commit), but not the later code (disk encryption, boot integrity) and not on physical hardware. Secure Boot is only partly done (H8: the loaders'
configuration is enrolled and the signing path works under OVMF on x86_64, but release images are not signed and
no physical machine was tried), and there is no IOMMU. Encryption at rest is not on the builder page yet (use `urmqtt-config pack` with
`storage.encryption`). 53 of the 67 kernel-linked crates are `cargo-vet` exemptions, not audits. The release assets are
**dev** builds with throwaway keys, for evaluation; production images are built by the operator (docs/DEPLOY.md).

### Added

- **Runtime configuration (C1).** The kernel is built once; limits, ACLs, network, TLS certificate and key, trust anchors and control key are a versioned, canonical `urmqtt-cfg` blob in a 256 KiB slot that the bootloader hands to the kernel and that is re-validated at every boot (fail closed; a release kernel refuses development options). `urmqtt-config pack | show | verify | schema` builds the blob from a TOML and PEM files and writes it into a copy of the new `urmqtt-template-<version>-universal.iso`, published with every release, without a toolchain. The kernel prints the configuration fingerprint at every boot. ADR-215 to ADR-219.
- **The urMQTT builder (C1e, C1g).** A web page that does what `urmqtt-config pack --iso` does, in the browser: the tool compiled to WebAssembly (tested byte for byte against the command line), a simple and an advanced view, presets, TOML import and export, certificate and key import with checks, minisign and SHA-256 verification of the release against a key built into the page, 15 languages. Certificates and keys never leave the browser. "Try in the emulator" boots the image in QEMU compiled to WebAssembly (GPL-2.0, source offer). `scripts/mirror-releases.py` mirrors the GitHub releases to the site after verifying them. ADR-225 to ADR-228, ADR-232.
- **Optional plaintext MQTT for trusted networks (P1).** A `[plaintext]` section, off by default, opens TCP 1883 without TLS. `allow_from` is mandatory and enforced at the SYN; login by `password` (PBKDF2-HMAC-SHA-256), `anonymous` or `ip`; lock-out after failed logins; a narrow ACL, small packets and a low publish rate by default; never an operator, service or control right. Blob format 2. `network.mqtt_tls_port = 0` turns TLS off when plaintext is on (format 3, v0.2.1 or newer). See docs/SECURITY.md for what plaintext gives up. ADR-229 to ADR-231, ADR-233.
- **x86_64 (X2 to X10).** The same kernel boots and serves on x86_64 under QEMU TCG (UEFI and legacy BIOS): paging with NX/WP/SMEP/SMAP/UMIP, ACPI, x2APIC, SMP, PCI, virtio with MSI-X, RDSEED/RDRAND, hardware AES, PCLMULQDQ, SHA-NI and SSE4.2 CRC (X9). One universal ISO (`make universal`) boots on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS, installs itself on the machine's disk, and its installed disk boots by all three paths; data disks are portable between the architectures. **Not run on KVM or real hardware.**
- **Live mode (O3).** The ISO's first menu entry runs the broker from RAM with no disk (`storage.mode = "disk" | "auto" | "ram"`), loudly marked ephemeral.
- **Storage track (S2 to S8).** Layout v2 with aligned regions and an A/B superblock; `urmqtt-disk migrate` converts a v1 disk offline (ADR-140, ADR-141). The disk grows into a larger volume at boot and, on virtio-blk, while running (`urmqtt-disk grow`; ADR-142, ADR-143). Space is given back with DISCARD or UNMAP, only while idle (`storage.discard`; ADR-150, ADR-151). Two in-disk database backup slots written by SQLite's online backup API, automatic restore of a corrupt database at boot, `urmqtt-disk backup | backup-extract | backup-restore` (layout v2.1; ADR-160 to ADR-163). An idle scrubber checks the database, the backups and every telemetry record, and boot no longer reads the whole telemetry ring (`urmqtt-disk scrub`; ADR-164, ADR-165). Fuzz targets for the backup headers and encrypted disks, golden images for every layout version, and the data-disk format spec (docs/DISK-FORMAT.md).
- **Encryption at rest (S7), optional and off by default.** `storage.encryption = "aes-256-xts"` and `storage.disk_key` encrypt the data partition (hardware AES required; configuration format 4). `urmqtt-disk encrypt | decrypt | rekey` convert a disk offline and resume after a power cut; `--key FILE` opens an encrypted disk for every other command. Protects a stolen volume or snapshot, not a stolen ISO; XTS has no integrity. ADR-240.
- **SQLite as an unprivileged component (H6).** The database engine runs as a separate program at EL0 / ring 3 with its own address space and 12 checked system calls; a fault or an overrun restarts the worker and the broker keeps serving. ADR-210 to ADR-212.
- **Kernel hardening (H4, H5).** Allocator hardening and zeroisation, stack protector, KASLR on both architectures, MTE heap tagging on aarch64, a panic and fault policy with test hooks compiled out of production (ADR-170 to ADR-176). Miri, Kani proofs, sanitizer runs and a stateful ACL fuzzer (`make miri | kani | sanitize | acl-fuzz`).
- **Supply chain (H9).** A CycloneDX SBOM with every release, listed in `SHA256SUMS` and attested; `cargo-vet` and `cargo-deny` in CI (ADR-190 to ADR-193). `docs/VULNERABILITY-HANDLING.md`: intake, triage, fix, disclosure and supported versions, aligned with the EU Cyber Resilience Act (not legal advice; no support period promised yet).
- **Audit package (H10).** `docs/AUDIT.md` (TCB and `unsafe` inventory with every site justified, mitigation matrix, bounds table, proposed external audit scope, red-team checklist), a STRIDE table per component in `docs/SECURITY.md`, and the encryption section of `docs/CRYPTO.md`.
- **Performance measurement (X11).** A load generator mode for publish/subscribe and a measured comparison with Mosquitto on a 4 vCPU KVM VPS (docs/PERFORMANCE.md).
- **Boot integrity (H8)** (ADR-250 to ADR-254). The loaders' configuration is enrolled (`limine enroll-config` on `BOOTAA64.EFI`, `BOOTX64.EFI` and the BIOS stage), so a modified `limine.conf` is refused as a modified kernel or configuration module already was; `SMOKE_ONLY=integrity` flips bytes in a built ISO and raw disk image on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS and shows the refusal, with controls that boot. `urmqtt-config pack --iso` re-enrolls. **Secure Boot signing path**: `scripts/sign-loaders.sh` (development keys, signing, verifying, an OVMF variable store with the keys), `mkiso.sh --sb-key`, `run-qemu.sh --secure-vars`, an OVMF Secure Boot scenario (x86_64) and the enrollment procedures in DEPLOY.md; no project key exists and release images are not signed. The installer entry's rules are tested (`install-rules`). A production image built outside CI warns loudly; the key bytes are scanned for in serial logs and `make repro` output. A TPM sealing spike is an ADR. Limits: a signed ISO cannot be configured afterwards, an installed disk does not boot under Secure Boot, aarch64 enforcement, Proxmox and a physical PC are untested.
- **A public demo broker (D1), built and not deployed.** A public demo broker, built and not deployed** (needs the owner's go-ahead). `deploy/demo/config.toml` (live mode, `demo/{id}/#`, plaintext only for a bridge host), `scripts/demo-certs.sh` (a published throwaway client CA, a separate broker CA whose key is deleted), `demo-pack.sh`, `demo-smoke.sh`; a stdlib Python WebSocket-to-TCP bridge with caps, rate limits and an Origin allow-list (`deploy/demo-bridge/`); the page "Try urMQTT live" with an MQTT client in plain JS (`tools/builder/demo/`, English and Croatian); the runbook in `docs/DEPLOY.md` section 11 and the threat model in `docs/SECURITY.md`.

### Fixed

- A subscriber whose output buffer filled was never served again until a keep-alive woke it (lost wake-up in the output loop). One TCP flow was slow because the stack dropped every segment after a loss, had a 16 bit window and counted ACKs instead of bytes; TCP gains an out-of-order queue, SACK, window scaling and timestamps. The 20 ms handler watchdog dropped healthy connections when the host stalled a vCPU; its budget is now running time. QoS 0 loss is counted per cause in `$SYS` (ADR-221 to ADR-224).
- H0-W2: captured TLS traffic secrets are wiped in place when taken, dropped or evicted. The AES-XTS tweak step is branch-free.

### Changed

- The boot sequence is shared by both architectures (ADR-059). The aarch64 boot log is unchanged.
- `make dist` also builds the template ISO and the SBOM; the release workflow lists both in `SHA256SUMS`.

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

[Unreleased]: https://github.com/zeljan-alduk/urMQTT/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.2.1...v0.3.0
[0.1.0]: https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.1.0
