# Threat model

> Status: H1 (control channel and identity lifecycle added before their
> implementation, as PROMPT-security requires). To report a vulnerability, see [../SECURITY.md](../SECURITY.md).
> Every mitigation below names the test, fuzz target or smoke scenario that
> checks it. A claim without one is listed under [residual risks](#residual-risks).

urMQTT is a single-purpose appliance: one ARM64 VM, one public port (TCP 8883,
TLS 1.3 with client certificates), no shell, no console input, no remote
administration. Configuration changes mean a new image. The one exception is the
identity lifecycle (revocation and the device allowlist, H1): it changes at
runtime through signed control messages on the same MQTT/TLS port. See
[Control channel](#control-channel-h1).

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Server TLS private key | Embedded in the image (`include_bytes!`) | Impersonating the broker; decrypting nothing (TLS 1.3 is forward secret), but accepting devices. |
| Session-ticket key | Derived at boot: HKDF(server key, image version) | Forging resumption tickets. Never stored. |
| Traffic secrets | Per connection, in RAM, zeroized on drop | Reading or injecting one device's traffic. |
| Device identities and the revocation list | CA embedded; revocations embedded and in SQLite | Who may connect. |
| Control signing key (Ed25519) | **Offline**, never in the image: a file on an operator machine (dev) or an HSM/KMS behind `urmqtt-control --sign-cmd` (prod). The image holds only the public key (`deploy/<env>/control.pub`). | Revoking, unrevoking and allowlisting devices at runtime. |
| Trust anchors by role | `[trust] operational` and `bootstrap` CA lists, embedded | Which CA grants which rights; rotation with overlap. |
| Messages | In flight (RAM), retained and offline queues (SQLite), telemetry (log on the data disk) | Confidentiality and integrity of device data. |
| Availability | — | The broker's purpose; the main target of a remote attacker. |

## Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| Network (TCP 8883, and the L2 segment) | **Untrusted** | Every byte is hostile until TLS client authentication completes, and stays untrusted as MQTT input afterwards. |
| Authenticated device | Partially | Restricted by the ACL and every limit below. A device can only harm itself and its own topics. |
| Backend/service identity | More trusted | Wider ACL (`acl.service_*`). Still no query interface and no code execution. |
| Data disk | Integrity-checked | Treated as corruptible (torn writes, bit rot), not as malicious: the hypervisor owns it. |
| Boot image (kernel, command line, configuration) | Trusted | Built reproducibly (M17); dev-only switches are ignored by non-dev builds. |
| Hypervisor / cloud provider | Trusted | It can read memory and disks. urMQTT cannot defend against its host. |
| Build machine and CI | Trusted | Pinned toolchain and dependencies; provenance attestations let others check builds. |

## Attackers

1. **Remote, unauthenticated:** anyone who can reach port 8883. Goals: code
   execution, bypassing authentication, denial of service.
2. **Authenticated device:** holds a valid certificate (possibly a stolen one).
   Goals: other devices' data, denial of service, persistence after revocation.
3. **On-link attacker:** on the same L2 segment as the VM (a shared cloud
   network). Goals: redirecting traffic, spoofing DHCP.
4. **Damaged storage:** not an attacker, but the disk content after a crash or
   corruption is untrusted input at boot.

## Attack surface: everything that parses untrusted input

| Input | Parser | Verification |
|---|---|---|
| Ethernet, ARP, IPv4, ICMP, UDP | `urmqtt-net` (own) | unit tests; fuzz `net_frame` |
| DHCP replies | `urmqtt-net::dhcp` (own) | unit tests; fuzz `net_frame` |
| TCP segments | `urmqtt-tcp` (own) | 17 host tests incl. loss/duplication; fuzz `tcp_segment` |
| TLS handshake | rustls (no_std, own RustCrypto provider) | upstream fuzzing; mTLS scenarios in smoke (wrong CA, expired, mismatch, revoked) |
| TLS records after the handshake | `urmqtt-tls::record` (own) | unit tests; fuzz `tls_record` (garbage rejected, sealed records round-trip, any changed byte fails) |
| Client certificate identity and serial | `urmqtt-tls::identity` (x509-cert) | fuzz `x509_identity` |
| MQTT packets | `urmqtt-mqtt` (own, `forbid(unsafe_code)`) | spec and property tests; mosquitto interop; fuzz `mqtt_decode` |
| MQTT session behaviour | `urmqtt-broker` (own, `forbid(unsafe_code)`) | 30 host tests; fuzz `broker_input` |
| Disk superblock and size table | `urmqtt-store::layout` | fuzz `disk_layout` |
| Telemetry log on the disk | `urmqtt-store::telemetry` | crash and torn-write tests; fuzz `telemetry_recover` |
| SQLite database file | SQLite 3.54.1 (vendored) | `quick_check` at boot, `SQLITE_DBCONFIG_DEFENSIVE`; upstream fuzzing |
| Firmware tables (DTB, ACPI) | `urmqtt-platform` | fuzz `fdt_parse`, `acpi_parse` (trusted source, fuzzed anyway) |
| Control messages (`$urmqtt/control`, H1) | `urmqtt-control` (own, `forbid(unsafe_code)`, fixed layout) + `ed25519-dalek` `verify_strict` | RFC 8032 vectors, round trip, every flipped byte fails; fuzz `control_message`; smoke `control-*` |
| Build-time configuration | `urmqtt-config-schema` | 38 tests; fuzz `config_parse`; invalid configuration fails the build |

CI runs every fuzz target on every push (60 s each), and longer in the
scheduled fuzz workflow.

## Control channel (H1)

Written before the implementation. The control channel changes who may
connect, at runtime and without a new image. It is the only path that
changes state without a new image, so it gets its own model.

**What it is.**
- Reserved topic namespace `$urmqtt/`. A message to the exact topic
  `$urmqtt/control` is not routed to anyone. It is handed to the control
  handler on the DB core.
- Commands: `revoke` and `unrevoke` certificate serials (unrevoke only with
  `control.allow_unrevoke`), and `allow` and `disallow` device ids for
  `registry.mode = "allowlist"`.
- No other effect exists. A control message cannot change configuration, run
  code, read data or open a port.

**Authenticated twice.**
1. *mTLS identity:* the publisher must be an operational (not bootstrap)
   identity listed in `control.service_ids`. Every other identity's publish to
   `$urmqtt/…` is dropped and counted (`control.dropped_unauthorized`).
   Subscribing to any `$urmqtt/…` filter is refused for every identity. MQTT's
   wildcard rule keeps `#` and `+` from matching `$` topics.
2. *Offline signature:* an Ed25519 signature (RFC 8032, strict verification)
   over a domain-separated, fixed binary encoding of the whole message. The
   signing key is offline. A compromised service identity alone cannot issue
   a command, and neither can the signing key alone.

**Freshness and replay.**
- Each message carries a 64-bit `seq`, which must be strictly greater than the
  last accepted one. The value is persisted in the same SQLite transaction as
  the effect.
- The validity window `not_before`/`not_after` must contain the broker's
  wall clock. It may not be longer than `control.max_message_age_s`.
- Without a trustworthy wall clock (unknown, or before the image's build time,
  H7) every control message is refused.
- Without durable storage every control message is refused, because a
  revocation that disappears at the next boot is worse than none.

**Effect.**
- The handler commits first, then applies the change to the in-memory sets
  that all cores read, then wakes every data core.
- Each core closes its live connections whose certificate serial is newly
  revoked, or whose identity left the allowlist.
- A revoked device is refused at its next full handshake and at its next
  resumption.

**Attackers and what stops them.**

| Attacker | Attempt | Stopped by | Test |
|---|---|---|---|
| Any device | publish to `$urmqtt/control` | reserved namespace before the ACL | broker test; smoke `control-from-device` |
| Any device | subscribe to `$urmqtt/#`, `#` | reserved namespace; `$` rule | broker tests |
| Compromised service identity | forge a command | Ed25519 signature | host vectors; smoke `control-forged` |
| Network attacker who recorded a message | replay it | persisted `seq` | host test; smoke `control-replay` |
| Anyone with an old message | delay it | validity window | host test; smoke `control-expired` |
| Malformed message | crash or confuse the decoder | bounded, fixed layout; fuzz `control_message` | fuzz |
| Bootstrap identity | act as a device or service | bootstrap role: only `provision/{id}/#`, its own session namespace, never persistent | broker tests; smoke `bootstrap-role` |
| Unknown device (allowlist mode) | connect | refused after the handshake, counted | smoke `registry-allowlist` |

**Residual risks of the control channel** (also in the table below):
- **Signing-key theft.** Theft of the signing key together with a service
  identity allows arbitrary revocation (denial of service) and, with
  `allow_unrevoke`, un-revoking a stolen device. Keep the key in an HSM or
  KMS. `allow_unrevoke` is off by default.
- **Disk rollback.** Restoring an old snapshot of the data disk restores old
  revocations and an old `seq`. Revocations that must survive anything belong
  in the image's `tls.revoked` list as well. The validity window limits what
  an old message can do after a rollback.
- **Dead service.** Revocation is only as timely as the service that publishes
  it.

## Installer entry (S1b)

Written with the implementation. The ISO's boot menu has a second entry,
"Install urMQTT on this machine's disk". It boots the same hash-pinned kernel
with the command-line word `install` and the ESP as a hash-pinned module, and
writes the raw boot image onto the machine's disk.

- **What it can do:**
  - erase exactly one disk (the only writable disk large enough that is not
    the installation medium) and write the release image onto it;
  - with several candidates it refuses and writes nothing.
- **Who can trigger it:** anyone at the console of a machine booting the ISO
  (keyboard at the Limine menu), or who can set the VM's boot medium. That
  attacker already has physical or hypervisor access and could erase the
  disk anyway.
- **Mitigations:**
  - the menu editor is off;
  - the kernel and the image are pinned by blake2b in the menu file
    (`hash_mismatch_panic`), H8 will add the config hash to the enrolled loader;
  - the target, its size and a warning are on screen, followed by a 30 s
    countdown during which a power-off cancels; dev tests may shorten it,
    production cannot;
  - the write leaves a non-booting disk if interrupted, never a half-new one
    that boots (host test `an_interrupted_install_never_boots_and_can_be_redone`,
    smoke `install-crash`);
  - the result is verified by reading it back.
- **Production command line:** still ignored, except the exact word `install`
  (ADR-052; test `production_honours_install_and_nothing_else`). Without the
  installation module, `install` only prints a message and powers off.
- **Residual risk:** the installer erases the previous data partition. There
  is no "keep data" mode yet; an offline kernel update keeps data
  (`urmqtt-disk update-boot`).

## Mitigations

### Code execution

- Rust everywhere except vendored SQLite and Limine. `forbid(unsafe_code)` in
  `mqtt`, `broker`, `timer-wheel` and `config`; elsewhere `unsafe` is confined
  to `arch`, `mm`, `pci`, `virtio`, `store` (FFI) and minimal kernel glue, each
  block with a `// SAFETY:` comment (lint-enforced).
- No panics on input: clippy denies `unwrap`, `expect`, indexing and `panic!` in
  data-path crates; fuzzing checks it.
- W^X with locked page tables, guard pages, PAC and BTI when the CPU has them,
  no dynamic code (smoke: `wx-write-text`, `wx-exec-heap`, `stack-overflow`,
  `pac-forgery`, `bti-violation`, `null-deref`).
- SQLite: statements are fixed at compile time; defensive mode on; extensions
  and ATTACH compiled out. There is no network-reachable SQL.

### Authentication and authorisation

- TLS 1.3 only, mutual TLS against the embedded trust anchors, the client id
  must equal the certificate's device id (smoke: `mqtt-tls`).
- **Trust anchors by role (H1, ADR-049):**
  - Operational CAs give device and service rights. Two side by side allow
    rotation with overlap (smoke `ca-rotation`).
  - Bootstrap CAs give only `provision/{id}/#`, in a separate session
    namespace and never persistently (broker tests; smoke `bootstrap-role`).
  - A resumed session re-verifies its chain against the current anchors (test
    `trust_roles_and_ca_rotation`).
- Revocation by serial, checked in memory at every full handshake **and at
  every resumption** (M16: a ticket issued before a revocation does not resume
  after it; test `revoked_device_cannot_resume`).
- **Since H1, revocations also change at runtime:** signed control messages
  close the live connections of a revoked certificate within milliseconds
  (smoke `control-revoke-live`) and survive reboots (smoke `control-persist`).
- **Registry (H1):** `registry.mode = "allowlist"` refuses unknown device
  identities after the handshake (smoke `registry-allowlist`).
- **Time (H7 lower bound, ADR-050):** a clock before the image's build time is
  treated as unknown, and certificate checks then refuse (smoke
  `time-before-build`).
- **Expiry safety (H1):** the build fails for a server certificate or trust
  anchor that is about to expire (test `expiry_build_check`). At runtime there
  is a gauge and warnings at 60, 30, 7 and 1 days.
- ACL compiled in and evaluated without the database: by default a device may
  publish to `devices/{id}/#` and subscribe to `devices/{id}/cmd/#`.
- The plaintext port can only exist in the `dev` environment; the build rejects
  it elsewhere.

### Denial of service

Every resource is bounded. What happens at the limit is part of the design:

| Resource | Limit (configuration) | At the limit |
|---|---|---|
| Half-open connections | none kept: SYN cookies always | — |
| RSTs to unknown connections | 200/s | not sent |
| ICMP echo replies | 100/s | not sent |
| New TLS handshakes per core | `limits.handshakes_per_core_per_sec` | refused before any crypto |
| Handshakes in flight per core | `limits.max_handshakes_in_flight_per_core` | refused |
| … of those from one source address | `limits.max_handshakes_in_flight_per_ip` | refused (an unauthenticated peer cannot take every slot) |
| Time to finish a handshake and CONNECT | 10 s | connection aborted |
| Free heap | `memory.min_free_mb` | new connections refused (smoke: `storm`) |
| DB core backlog | 16 384 requests | new connections refused; registry updates skipped beyond 4 096 |
| Connections per core | `limits.max_connections_per_core` | refused |
| Packet size, topic length and levels, client id, topics per packet | `limits.*` | protocol error, connection closed |
| Subscriptions per session | `limits.max_subscriptions_per_session` | SUBACK failure |
| QoS 1 in flight, offline queue | `limits.max_inflight_qos1`, `limits.max_queued_per_offline_session` | queued; beyond the queue, new messages are dropped and counted |
| Publish rate per device | `limits.publish_rate_per_device` | dropped and counted |
| Output buffered per connection | 32 KiB | QoS 0 dropped, QoS 1 queued |
| Receive window | broker backpressure | TCP window closes |
| Cross-core fan-out | 16 384 messages per core pair | QoS 0 dropped, QoS 1 kept |
| Telemetry backlog | 65 536 records per core | dropped and counted |
| Log lines | 100/s, burst 300 | suppressed and counted |
| A handler hogging its core | `watchdog.handler_budget_ms` | `watchdog.action` (log, drop the connection, reset); a core stuck for 100 budgets (≥ 1 s) resets the VM (smoke: `watchdog`) |
| A core that stops making progress | 2 health checks (20 s) | VM reset (a fresh boot is the recovery) |

Memory left by a peak is returned within 10 s (slab chunks, tables), so the
free-heap admission recovers after a storm instead of refusing forever. The
`storm` smoke scenario checks this with 3 rounds of 3 000 devices reconnecting
at once against an 8 MiB admission limit.

### Data integrity

- Telemetry: CRC-32C per record salted with the segment sequence, torn tails
  truncated on recovery, a new segment after recovery (smoke: `log-crash`,
  `log-tear`).
- SQLite: WAL with `synchronous=FULL`, `quick_check` at boot, refuse to serve on
  corruption in production (smoke: `db-crash`).
- Disk layout: CRC on the superblock and the double-buffered size table.

### Confidentiality

- Logs never contain secrets, keys, full certificates or payloads.
- Traffic secrets, record keys and handshake buffers are zeroized when dropped;
  record keys exist only on the stack while a record is sealed or opened.
- Observability goes to private collectors named in the build-time
  configuration. It is plain UDP and carries no payloads or secrets.

### Supply chain

Pinned nightly toolchain and `Cargo.lock`; `--locked` builds; cargo-deny
(advisories, licenses, sources); vendored and checksummed Limine and SQLite;
SHA-pinned CI actions; OpenSSF Scorecard; SLSA provenance on releases.

## Residual risks

| Risk | Why it remains | Mitigation available today |
|---|---|---|
| The image contains the server key. | No secure key storage in the VM. | Treat the ISO as a secret; rotate the key with a new image. |
| Theft of the control signing key **and** a control service identity. | Both are needed; then arbitrary revocation (DoS) or, with `allow_unrevoke`, unrevocation. | Offline key in an HSM/KMS (`--sign-cmd`); `allow_unrevoke = false` (default); revocations that must survive anything also in the image. |
| A restored old data-disk snapshot brings back old revocations and `seq`. | The disk is trusted not to be maliciously rolled back. | Image-listed revocations are re-applied at every boot; validity windows bound old messages. |
| DHCP and ARP are unauthenticated. | IPv4 on a shared L2 segment has no defence against on-link spoofing. | Static addressing (`network.mode = "static"`) and a private network for the VM. |
| Many source addresses defeat the per-address handshake limit. | A botnet can use the per-core in-flight and rate limits up. | Upstream filtering; the limits keep the broker alive for connected devices. |
| Syslog and statsd are plain UDP. | No TLS sink in the kernel. | Collectors on a private network only. |
| No hardware RNG on the cloud (Ampere Altra has no `RNDR`; virtio-rng may be absent). | Then the CSPRNG is seeded from CPU timing jitter, which is weaker evidence than a hardware source. | Health tests and a conservative estimate gate it (ADR-038), and it is logged at boot. Prefer clouds with virtio-rng; `entropy.fallback = "none"` refuses to boot without one. |
| Side channels in the crypto. | RustCrypto implementations are designed to be constant-time; that is not verified here. | ChaCha20-Poly1305 is offered alongside AES-128-GCM. |
| The hypervisor sees everything. | Out of scope. | Choose the host. |
| 100k and 1M connections are not measured on the development host. | QEMU user networking on macOS stops near 10 240 sockets. | The per-connection footprint is flat from 1k to 10k (ADR-034); the storm test scales the heap down instead of the clients up. |
