# Threat model

> Status: M16. To report a vulnerability, see [../SECURITY.md](../SECURITY.md).
> Every mitigation below names the test, fuzz target or smoke scenario that
> checks it. A claim without one is listed under [residual risks](#residual-risks).

urMQTT is a single-purpose appliance: one ARM64 VM, one public port (TCP 8883,
TLS 1.3 with client certificates), no shell, no console input, no remote
administration. Changing anything, including the revocation list, means building
and deploying a new image.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Server TLS private key | Embedded in the image (`include_bytes!`) | Impersonating the broker; decrypting nothing (TLS 1.3 is forward secret), but accepting devices. |
| Session-ticket key | Derived at boot: HKDF(server key, image version) | Forging resumption tickets. Never stored. |
| Traffic secrets | Per connection, in RAM, zeroized on drop | Reading or injecting one device's traffic. |
| Device identities and the revocation list | CA embedded; revocations embedded and in SQLite | Who may connect. |
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
| Build-time configuration | `urmqtt-config-schema` | 32 tests; fuzz `config_parse`; invalid configuration fails the build |

CI runs every fuzz target on every push (60 s each), and longer in the
scheduled fuzz workflow.

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

- TLS 1.3 only, mutual TLS against the embedded CA, the client id must equal
  the certificate's device id (smoke: `mqtt-tls`).
- Revocation by serial, checked in memory at every full handshake **and at
  every resumption** (M16: a ticket issued before a revocation does not resume
  after it; test `revoked_device_cannot_resume`).
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
| Revocations need a new image. | No administration path, by design. | Rebuild with the updated list; tickets are re-checked, so a revoked device is refused at once. |
| DHCP and ARP are unauthenticated. | IPv4 on a shared L2 segment has no defence against on-link spoofing. | Static addressing (`network.mode = "static"`) and a private network for the VM. |
| Many source addresses defeat the per-address handshake limit. | A botnet can use the per-core in-flight and rate limits up. | Upstream filtering; the limits keep the broker alive for connected devices. |
| Syslog and statsd are plain UDP. | No TLS sink in the kernel. | Collectors on a private network only. |
| Side channels in the crypto. | RustCrypto implementations are designed to be constant-time; that is not verified here. | ChaCha20-Poly1305 is offered alongside AES-128-GCM. |
| The hypervisor sees everything. | Out of scope. | Choose the host. |
| 100k and 1M connections are not measured on the development host. | QEMU user networking on macOS stops near 10 240 sockets. | The per-connection footprint is flat from 1k to 10k (ADR-034); the storm test scales the heap down instead of the clients up. |
