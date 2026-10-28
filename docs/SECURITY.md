# Threat model (draft)

> Draft from M0. The full threat model and its verification are part of M16.
> To report a vulnerability, see [../SECURITY.md](../SECURITY.md).

## Assets

- The server TLS private key and the session-ticket key, both embedded in the image.
- Device identities and the revocation list.
- Messages in flight, retained messages and persisted telemetry.
- Availability of the broker for legitimate devices.

## Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| Network (TCP 8883) | **Untrusted** | The only exposed surface. Every byte is hostile until TLS client authentication completes, and stays untrusted as MQTT input afterwards. |
| Authenticated device | Partially | Restricted by ACL, rate limits and packet/queue limits. A device can only harm itself and its own topics. |
| Backend/service identity | More trusted | Wider ACL. Still no query interface and no code execution. |
| Data disk | Integrity-checked | CRC per telemetry record, SQLite `quick_check`, bounds-checked VFS. Treated as corruptible, not as malicious (the hypervisor owns it). |
| Hypervisor / cloud provider | Trusted | It can read memory and disks. urMQTT cannot defend against its host. |
| Build machine and CI | Trusted | Reproducible builds (M17) and provenance attestations let others check this. |

## Attacker capabilities and mitigations

| Threat | Mitigation |
|---|---|
| Remote code execution through parser bugs | Rust; `forbid(unsafe_code)` in `mqtt`, `broker`, `timer-wheel` and `config`; no panics on input (clippy denies unwrap, expect, indexing, panic); every parser fuzzed; W^X and locked page tables; PAC/BTI when available; no dynamic code loading. |
| Unauthenticated access | TLS 1.3 only; mutual TLS against the embedded CA; client id must equal the certificate device id; revocation checked from an in-memory set. |
| Plaintext exposure | Port 1883 can only be enabled in the `dev` environment, rejected at build time. |
| SYN floods and handshake storms | SYN cookies always on (no half-open state); per-core handshake token bucket; a timeout on every handshake phase. |
| Resource exhaustion by an authenticated device | Limits on packet size, topic length and levels, subscriptions, in-flight messages, offline queue depth and publish rate; TCP window tied to broker backpressure; allocation failure closes the connection, never panics. |
| Cross-device data access | ACL compiled in, default `devices/{id}/#` publish and `devices/{id}/cmd/#` subscribe; the check never touches the DB. |
| Key disclosure through logs | Logs never contain secrets, keys, full certificates or payloads. Payload logging exists only behind a dev-only flag. |
| SQL injection | There is no network-reachable SQL: statements are fixed at compile time, `SQLITE_DBCONFIG_DEFENSIVE` is on, and extensions and ATTACH are compiled out. |
| Tampered disk or torn writes | Superblock CRC; telemetry record CRC with tail truncation; `quick_check` on boot with refuse-to-serve. |
| Supply chain | Pinned toolchain and `Cargo.lock`; `--locked`; cargo-deny (advisories, licenses, sources); vendored and checksummed Limine and SQLite; SHA-pinned CI actions; SLSA provenance on releases. |

## Explicit non-goals

- Protection against a malicious hypervisor or physical access.
- Confidentiality of the image contents against anyone who can read the ISO. The image embeds the server key, so treat the ISO as a secret.
- Remote administration of any kind. Changing anything means building and deploying a new image.
