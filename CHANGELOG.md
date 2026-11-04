# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Fixed
- **The trust anchors' verification tables were never built** (ADR-111, ADR-259, AUDIT.md A259-W1): webpki stores an
  anchor's SubjectPublicKeyInfo without its outer SEQUENCE, which `register_issuer` did not parse, so a device's
  first handshake verified its certificate on the slower unknown-key path. Both forms are accepted now. No effect on
  verdicts; about 20 us less for a first contact (Docker linux/arm64 on an Apple M4 Pro).

### Changed
- **X25519 on AArch64**: the shared secret uses `urmqtt-x25519` with new `mul`/`umulh` inline assembly
  (`Backend::Armv8`, ADR-259) instead of dalek's 51-bit ladder; 14.6 us against 20.3 us in the profile (Docker on an
  M4 Pro, not measured on a server core). The boot line reads `crypto: ecc=... x25519=armv8|adx|portable (...)`.
- **P-256 verification** (both architectures): a width-5 NAF for the key's multiple and a variable-time scalar
  inversion (public inputs only; signing and ECDH stay constant time): unknown key 29.0 -> 24.5 us, by a CA table
  9.8 -> 7.2 us (Docker on an M4 Pro).
- Server CPU per full mutual-TLS handshake, measured stage by stage (Docker on an M4 Pro, PERFORMANCE.md section
  12): returning device 88.8 -> 80.3 us, first contact 118.6 -> 87.8 us. Nothing was measured on the Neoverse N1.
- **Measured on the netcup Neoverse N1 VPS** (PERFORMANCE.md section 12.1, one run each, shared hosts): the server's
  CPU per handshake 461 us (553 us with the assembly alone, about 1.0 to 1.08 ms with the portable code; the CPU clock
  differed between the runs); X25519 128 us, ECDSA verify 124 us; full mTLS handshakes per second 1,451 / 1,624 / 1,599
  at 32 / 64 / 128 threads against 1,317 / 1,398 / 1,316 with the assembly alone and 848 / 827 / 778 with the portable
  code (0 errors).

### Added
- `stage-profile` feature and `handshake_profile` example of `urmqtt-tls` (host only): the server's handshake time
  per stage. `make ct` case `x25519_ladder_is_constant_time`; the RFC 7748 million-iteration vector (ignored test).
- ADR-260: a proposal, not built, for a cache of verified client certificates (it would save about 1 us per
  returning device's full handshake on top of the existing memo; recommended against).

## [0.4.0] - 2026-11-04

A release of what was built after v0.3.0: optional virtio drivers for the consoles and devices that VPS providers
attach (a virtio-gpu console, virtio-console, -balloon, -input and -vsock) behind one driver framework, P-256 on
the ARMv8 assembly, the Diagnostic entry's measurements over the network, and the first records of a real aarch64
KVM guest. Its main purpose: the builder page only offers published templates, and v0.3.0's template reads
configuration format 4, so the new keys (`console.virtio_gpu`, `[devices]`) can be used from the page only with a
release whose template reads format 6.

**Compatibility.** Nothing here breaks an existing image or disk. The kernel reads configuration formats 1 to 6. The
packer still writes the lowest format that can hold the configuration, so an image whose new keys are all `"off"`
(the default) is written in format 2, 3 or 4 exactly as before and boots on the kernels that boot it today (2:
v0.2.0 or newer, 3: v0.2.1 or newer, 4: v0.3.0 or newer). A configuration with `console.virtio_gpu` not "off" is
format 5, one with any `[devices]` key not "off" is format 6; only a v0.4.0 kernel reads them, an older kernel
refuses them at boot by the version, and `urmqtt-config pack --iso` (and the builder page) refuses to write them into
an older template, naming the reason ("use a newer release"). Format 5 was never in a release; a v0.4.0 template
declares format 6. The data-disk layout is unchanged (v2.1). The golden blobs of formats 1 and 2 are unchanged and
still valid; the builder page must be redeployed before the mirror lists this release (docs/RELEASE.md section 4).

**Limits, stated plainly.** The signing key is still a test key, and the release assets are **dev** builds with
throwaway certificates, for evaluation (as for v0.3.0); production images are built by the operator
(docs/DEPLOY.md). The only real-machine results are one netcup VPS 500 ARM G12.5 (Neoverse N1, 2 vCPU, aarch64 KVM)
and, for x86_64, the Contabo run at the H7 commit (PERFORMANCE.md 3 and 7). On the netcup machine the Diagnostic
entry, the measurements and load runs below, and the virtio-gpu console were run; install, boot from the installed disk and a retained message that survived a power cut are recorded in PROGRESS and PERFORMANCE (one run each). That machine has no virtio-rng and no `RNDR`: its generator was seeded from the
CPU-jitter fallback and the bootloader's EFI RNG only, the weakest seeding the kernel accepts (ADR-038). The P-256 speed-up of ADR-255 was measured on the Neoverse N1 once (and on an Apple M4 Pro). The virtio-console, -balloon, -input and
-vsock drivers have not run on a real VPS; vsock has run only against the fake device of the tests (it needs
vhost-vsock on a Linux host). The x86_64 and universal-ISO smoke suites are not in CI; for this release only the
x86_64 `virtio_gpu` and `virtio_devices` groups were run, under QEMU TCG on the Mac (PROGRESS, "Release candidate
v0.4.0"), not the full x86_64 or universal suites and nothing on KVM; the code after H7 (disk encryption, boot integrity, everything in this release) has not run
on an x86_64 KVM guest or on physical hardware. Secure Boot, IOMMU and the rest of v0.3.0's limits are unchanged.

### Added

- **A virtio driver framework** (ADR-257): every driver of `crates/virtio` behind its own Cargo feature, the umbrellas
  `vps` (the MQTT image's set) and `all`; the kernel's default is `virtio-vps` (`make build VIRTIO=all` for every
  driver). One table (`registry::KINDS` and the kernel's `vdev::DRIVERS`, kept in step by a build-time check); every
  virtio device found is listed in the boot log (`virtio: <name> at <bdf>: <state>`) and in the Diagnostic report's
  new `virtio` list, also those without a driver (`no driver in this image`). A `[devices]` section with one
  `"off" | "auto" | "on"` key per optional driver, all off by default: configuration **format 6** only when a key is
  not "off". `urmqtt-config pack --iso`/`--image`/`--kernel` refuses a key for a driver the image's kernel lacks (the
  kernel carries a `URMQTT-VIRTIO-DRIVERS:` marker); the boot warns where that could not be checked.
  docs/DEVELOPING-DRIVERS.md is the checklist for the next driver.
- **virtio-console, virtio-balloon, virtio-input and virtio-vsock drivers** (ADR-258), each off unless configured:
  the log on a virtio-console's port 0 and the Diagnostic prompts' keys from it; memory statistics for the host from
  a balloon that never inflates (fixed heap; a host request is logged and refused); virtio keyboards for "press any
  key" and `WIPE` from a provider's VNC console; the Diagnostic report, read-only, on vsock port 2883. Fuzz targets
  `virtio_console_device`, `virtio_balloon_device`, `virtio_input_event`, `virtio_vsock_packet`; smoke
  `virtio_devices` (QEMU HVF: console, balloon with QMP statistics, `WIPE` typed as QMP key events and on the
  console). **vsock is untested against a real device** (needs vhost-vsock on a Linux host); none of the four has
  run on a real VPS yet. The release kernels grow by about 80 KiB (aarch64, 2.3 %) and 67 KiB (x86_64, 1.9 %).
- **A virtio-gpu (2D) console, optional and off by default** (ADR-256, NOW-6): `[console] virtio_gpu = "off" |
  "auto" | "on"`. For VMs whose firmware display goes dark after boot (netcup ARM: "Display output is not active").
  The kernel gives the device a framebuffer of its own on scanout 0, moves the log's console onto it (the lines
  logged before are redrawn) and presents changes at most every 50 ms, and at once before a fatal stop, a panic, a
  power-off and after every Diagnostic dashboard redraw. "auto" takes the device when the boot framebuffer is
  missing or is RAM nothing shows; "on" whenever one is found. **Verified on a real machine:** netcup VPS 500 ARM
  G12.5, 1280x800, the Diagnostic dashboard visible live in the provider's Screen tab and the final "press any key"
  screen staying. Configuration format 5 when the key is not "off" (an "off" image stays format 2 and boots on older
  kernels); format 5 was never released on its own, a v0.4.0 template declares format 6. New fuzz target
  `virtio_gpu_response`; smoke `virtio_gpu` (QMP screendump checked); `run-qemu.sh --gpu virtio|virtio-vga`.
- **Configuration format 6** and the builder page for it: the page's WebAssembly module is `urmqtt-cfg6.wasm`; its
  advanced view offers `console.virtio_gpu` and the four `[devices]` keys. With a template of v0.2.0 to v0.3.0 the
  page and `urmqtt-config pack --iso` write every configuration that template's kernel reads and refuse the rest with
  the reason (new test `templates_of_earlier_releases_take_what_their_kernel_reads`).
- P-256 on aarch64 through OpenSSL's ARMv8 `nistz256` assembly (ADR-255), vendored from ring 0.17.14 like the
  x86_64 code (ADR-130): ECDSA sign and verify, ECDH, key generation and the trust-anchor tables. Boot line
  `crypto: ecc=nistz256-armv8`; the diagnostic screen's crypto line names the backend too. Measured in Docker on an
  Apple M4 Pro (not the target CPU), production paths, minimum of 11 runs: sign 34.7 -> 11.6 us, verify 147 -> 29 us,
  ECDH 135 -> 25 us, handshake estimate 292 -> 104 us (PERFORMANCE.md section 10). On the netcup Neoverse N1 VPS (PERFORMANCE.md section 11): full mTLS handshakes per second 848 -> 1317 at 32 threads, 827 -> 1398 at 64 and 778 -> 1316 at 128 (1.55 to 1.7x, 0 errors), the server's CPU per handshake 553 us (one run) against about 1.0 to 1.08 ms before; two vCPUs, so single-core broker figures. The vendored assembly uses integer registers only (upstream's two NEON selection
  functions are replaced by constant-time Rust) and starts every entry point with `bti c`. macOS, Miri and Kani keep
  the portable code.
- `make ct`: P-256 key generation, ECDH and signing (key and nonce) through the production paths (sparse fixed
  against random scalars), with a P-256-scale positive control (a variable-time double-and-add).
- `diag-serve` boot word: the Diagnostic entry's measurements (detection, RAM, crypto incl. AES-XTS, disk reads),
  then a normal live boot that serves MQTT with the report as the retained `$SYS/diag/report` (operator certificate).
  For machines whose console cannot be seen (written for the netcup ARM VPS before the virtio-gpu console existed;
  its serial port is not exposed). Use it with `mkiso.sh --diag-default --diag-cmdline diag-serve`.
- Diagnostic entry: the **CPU clock** (the PMU cycle counter, or the TSC rate on x86_64, measured against the time
  base; "not measurable" where only a fixed-rate timer is readable) and a **random number generator** panel: which
  sources seeded it (virtio-rng, RNDR or RDRAND/RDSEED, the bootloader's EFI RNG, the CPU-jitter fallback with its
  samples, credited bits and health tests), a sanity test of fresh bytes from each hardware source (share of ones,
  longest run; not a certification), the generator's throughput and a test of its output. `scripts/diag-check.py`
  checks the new keys.
- `tools/diag-png` (`urmqtt-diag-png`): draws that JSON (or the `URMQTT-DIAG-JSON` serial line) as the PNG of the
  dashboard, with the kernel's own `dash::draw` and framebuffer font, disks included.
- First measurement on a real aarch64 KVM guest (netcup VPS 500 ARM G12.5, Neoverse N1, 2 vCPU, before ADR-255):
  hardware AES-XTS 241 MiB/s per core, AES-GCM 314 MiB/s, ECDSA verify 508 us, sign 141 us, one mutual-TLS handshake
  1.08 ms; TLS 1.3 + mTLS, QoS 1 publish/subscribe, 500 held connections and three 1000-client reconnect storms ran
  over the Internet without an error.
- docs/ROADMAP.md: a proposal for the work after v0.3.0 (what is missing, why, effort, how each item would be
  verified). Nothing in it is decided.

### Changed

- The template ISO's empty configuration declares format 6 (`FORMAT_VERSION`), so the release mirror reports
  `config_format` 6 and a builder page built before this release greys the release out.
- `make clippy-kernel` also checks the kernel with `virtio-all` and with `--no-default-features`.
- The aldo.tech site patch (`tools/builder/site/apply_products.py`): Products goes first in the header and the footer
  wherever the site's own links sit.

### Fixed

- `urmqtt-diag-png` left the disks of the report out (the picture said "no disks found").
- The mm poison-on-free test looked at the obfuscated free-list header and failed about one run in eight.
- Tests: the P-256 timing cases retry (fail only if every attempt is over the bound); the ECDSA signing case signs a
  fresh random message per measurement in both classes (A255-W1: the signal on the arm64 runner came from the DER
  encoding of a repeated signature, not from the key) and its bound is 7 again; the install smoke patterns no longer
  depend on the image size; `virtio_devices` boots the x86_64-only ISO with the diag words on its one entry.
- CI: Miri runs as three parallel jobs (protocol crates, tls, cfg) with the development certificates and a 120 minute
  timeout, and skips the heavy P-256 table, known-answer and benchmark tests of `urmqtt-tls` (they run natively);
  Kani is a real gate (the documented NOT PROVEN harnesses are listed by name, any other failure fails); typos;
  `qemu-utils` for the discard scenario; three attempts and a 25 ms handler budget for the two slow-log watchdog
  scenarios on a slow TCG runner; the scheduled fuzz workflow makes the development certificates first (every target
  failed to build without them).
- docs/PROGRESS.md: the entries M0 to S6, lost when commit 85605d2 replaced the file, are restored from the history.

### Security

- A256-W1, fixed before merge: a virtio-gpu display-info response 4 bytes short of the structure was accepted (found
  by the new `virtio_gpu_response` fuzz target in its first minute; low, nothing past the buffer was read).
- A255-W1 closed: the ECDSA signing timing signal was the harness (see Fixed). A255-W2 stays open: PSTATE.DIT is never
  set, so Arm's data-independent-timing guarantee for the instructions the nistz256 assembly uses is not requested
  (docs/AUDIT.md).
- New device inputs, each with a fuzz target and AUDIT.md rows: virtio-gpu responses, virtio-console data, balloon
  requests, input events, vsock packets. All of them are off unless configured. The balloon never gives memory back;
  vsock serves only the read-only Diagnostic report.

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

[Unreleased]: https://github.com/zeljan-alduk/urMQTT/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.2.1...v0.3.0
[0.1.0]: https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.1.0
