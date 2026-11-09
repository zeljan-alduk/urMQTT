# Security audit package

Status: **H10, the audit package** (docs/SECURITY-PLAN.md), 2026-11-02, at the
commit this file is part of. It grew from the H0 baseline of 2026-10-29. It
records:

- what the trusted computing base is and what the system is made of;
- which inputs reach which parser, and what bounds each;
- which protection is proven by which test, and which are not proven;
- every weakness found, fixed or open, and the risks accepted;
- how to build, boot and test everything without asking anyone;
- the scope we propose for an external audit, and an internal red-team
  checklist with its results.

Weaknesses are listed even when they are not fixed. Where a protection has no
test, that is listed as a gap too: an untested protection does not count.

**What this release does not claim.** It targets a **VPS (KVM)**. Bare metal is
not claimed: no IOMMU (H4b), no Secure Boot enforced for release images (the loaders are
unsigned by any project key; the signing path exists and is tested on x86_64 OVMF only, H8), no TPM
sealing (a spike, ADR-254), no native NIC or disk drivers (X12 to X16). The `unsafe` and
inventory tables below include the code that exists for bare metal (x86_64
platform code, PCI) because it is built into the image, but nothing here
audits it against a hostile device.

Regenerate the inventory with `make audit` (`scripts/audit-inventory.py`). CI fails if it is
out of date (`--check`).

## 0. Reading order for an auditor

| Read | For |
|---|---|
| This file, §1 to §3 | the system, the trusted base, the inputs, what is proven |
| [ARCHITECTURE.md](ARCHITECTURE.md) | boot sequence, per-core run-to-completion design, the database worker |
| [SECURITY.md](SECURITY.md) | assets, trust boundaries, attackers, **STRIDE per component**, mitigations, residual risks |
| [CRYPTO.md](CRYPTO.md) | the TLS 1.3 record layer and key schedule, entropy, constant-time evidence |
| [PROVISIONING.md](PROVISIONING.md) | the identity lifecycle: certificates, revocation, the signed control channel |
| [DISK-FORMAT.md](DISK-FORMAT.md) | the byte-level format of the data disk, the encryption at rest |
| [DECISIONS.md](DECISIONS.md) | every design decision with its reasons (ADR-nnn); the numbers in this file point there |
| [VERIFICATION.md](VERIFICATION.md), [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md), [VULNERABILITY-HANDLING.md](VULNERABILITY-HANDLING.md) | the verification tools, the SBOM and vet setup, how a report is handled |
| This file, §7 to §9 | build and test instructions, the proposed scope, the red-team results |

---

## 0b. The system in one page

urMQTT is a unikernel MQTT 3.1.1 broker: one statically linked ELF (aarch64 and
x86_64) in EL1 / ring 0, started by Limine, with no scheduler, no processes,
no filesystem, no shell and no console input. Each core owns its connections
and runs a packet from the NIC through TCP, TLS decrypt-in-place, the MQTT
codec and routing to the reply without queues between stages. The one listening
service is **TCP 8883, mutual TLS 1.3**. The owner can add a plaintext
listener when the image is made (P1, off by default, answering only listed
networks); development images also accept test words on the kernel command
line, which production images ignore. SQLite (C, 254k lines) runs **outside the kernel**, as an
unprivileged program in its own address space (EL0 / ring 3, ADR-210), called
synchronously through twelve checked system calls. The image carries its
configuration as a validated binary blob (`urmqtt-cfg`, ADR-215), including the
server certificate and key; the kernel validates it again at every boot and
refuses to serve on any problem.

```
 network ──► virtio-net ──► Ethernet/ARP/IPv4/TCP (own, SYN cookies) ──► TLS 1.3
          (hostile)                                                     (rustls handshake,
                                                                         own record layer)
                                                                              │
 operator ◄── $SYS / console (certificate role) ◄── broker (sessions, ACL, ◄──┘
 control msgs (signed) ──────────────────────────►  retained, QoS, limits)
                                                          │ requests
                                              store (layout, VFS, telemetry) ──► virtio-blk
                                                          │ 12 system calls      (data partition,
                                                          ▼                       optionally AES-XTS)
                                                  dbworker: SQLite at EL0
```

Trust boundaries, in order of exposure: the network (everything), the data
volume (a snapshot or a stolen disk), the image and its configuration (a
secret: it holds the server key), the hypervisor (trusted in a VM), the
build host and the dependencies (supply chain). SECURITY.md has the full table.

---

## 1. Trusted computing base

The full tables are generated: [audit/inventory.md](audit/inventory.md)
(crates, vendored code, dependencies, fuzz targets) and
[audit/unsafe.md](audit/unsafe.md) (every `unsafe` site). The summary is taken
from them at the H10 commit (H0 baseline: 30 773 lines, 65 linked crates, 308
`unsafe` sites with 278 justified).

| Part | Size | Notes |
|---|---|---|
| Own Rust in the image (29 workspace crates, `src/` incl. inline tests) | 89 612 lines | both architectures; `tools/*` (6 host tools, 8 300 lines) are not in the image |
| Third-party Rust built for the kernel target | 80 crates from crates.io (494 628 lines), **67 of them linked** (294 797 lines on aarch64), plus the two vendored `cpufeatures` below | RustCrypto, rustls, webpki, p256, x25519-dalek, ed25519-dalek, aes, hmac, … ([list](audit/inventory.md)) |
| Third-party Rust at build time only | proc-macros and build scripts (syn, toml, cc, …) | they run on the build host, so they are a supply-chain risk, not runtime TCB; cargo-vet exemptions, SBOM and advisory checks: [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md), [vet-exemptions.md](audit/vet-exemptions.md) |
| SQLite 3.54.1 (C), linked into the dbworker, **not** the kernel | 254 268 lines | the largest component; it runs at EL0 / ring 3 in an address space of its own (ADR-210): a memory-corruption bug in it no longer reaches kernel memory, keys or other connections |
| `dbworker`, `usys` (H6) | 2 crates, about 650 lines of Rust | the worker's entry, panic and syscall stub, and the kernel/worker contract; the dispatcher and VFS shim are `store/src/worker.rs`, the kernel's side `store/src/remote.rs` |
| Own C headers for SQLite | 53 lines in 7 headers | the libc surface SQLite sees (functions implemented in Rust, `store/src/libc.rs`) |
| OpenSSL `nistz256` P-256 assembly, vendored from ring 0.17.14 (ADR-130, ADR-255) | 3 795 lines for x86_64, 1 332 lines for aarch64, plus the 148 KiB generator comb (`p256-table.bin`, shared) | Apache-2.0; mechanical changes only, regenerated by `vendor/nistz256/derive.py` and reviewable with `diff` ([vendor/README.md](../vendor/README.md)). The aarch64 file is integer-only and starts each entry with `bti c`; the x86 one has no AVX. Differential tests against RustCrypto run on both architectures |
| RustCrypto `cpufeatures` 0.2.17 and 0.3.1, vendored (X0b) | 675 + 598 lines | upstream sources plus one hunk each: on bare metal they ask the kernel's sealed dispatch (`urmqtt_cpu_has`). Reviewable with `diff -r` against the crates.io files ([vendor/README.md](../vendor/README.md)) |
| Limine v12.9.4 (binary) | `BOOTAA64.EFI`, 331 776 bytes (and the x86_64 and BIOS loaders in the universal ISO) | pre-kernel; its configuration is enrolled (ADR-250), signing path ADR-251; **no project signing key exists**, so release loaders are unsigned |

**`unsafe` in non-test code of the workspace:** 924 sites, **all 924 with a
`// SAFETY:` comment or a `# Safety` section** (the tool crate `builder-wasm`
accounts for 29 of them and the fake virtio device of the tests and fuzz targets,
`virtio/src/fake.rs`, behind the `fake` feature, for 6; neither is in the image). In
the image: 889 (889 and 860 at H10; the 9 added by ADR-255 are the aarch64 calls into
the assembly; the 3 added by ADR-256 are the virtio-gpu driver's request slots and
framebuffer, and the console's slice of that framebuffer; the 3 added by ADR-257 are
the shared queue allocation and the two bounds-checked DMA copies of `virtio/src/bus.rs`;
the 5 added by ADR-259 are the AArch64 X25519 inline-assembly blocks, register-only,
`options(pure, nomem, nostack)`; the 9 added by ADR-270 are the GICv3 ITS driver's register
accessors, its cache clean, its command-queue and LPI-configuration writes, and the kernel's call
of its `init`).

| Crate | Sites (justified) | Crate lint |
|---|---|---|
| `urmqtt-store` | 302 (302) | deny, with `allow` on the FFI modules (`db`, `ffi`, `libc`, `vfs`, `init`, the log callback, the worker's half) |
| `urmqtt-arch-x86_64` | 155 (155) | deny; port I/O, MSRs, control registers, interrupt entry |
| `urmqtt-kernel` | 119 (119) | deny; `cpu_dispatch.rs` (the sealed section, the `urmqtt_cpu_has` export), boot requests, user mode |
| `urmqtt-arch-aarch64` | 109 (109) | deny; all assembly and system registers, the ARMv8 CRC-32C intrinsics, the GICv3 ITS (ADR-270) |
| `urmqtt-mm` | 74 (74) | deny; frames, heap, slabs, key slab |
| `urmqtt-dbworker` | 22 (22) | default; the worker's entry and syscall stub |
| `urmqtt-nistz256` | 28 (28) | allow; the calls into the vendored P-256 assembly (x86_64 and aarch64) and the comb table's reinterpretation (ADR-130, ADR-255) |
| `urmqtt-sync` | 19 (19) | deny; spinlock, once-cell, SPSC ring |
| `urmqtt-virtio` | 30 (30) | deny; 6 of them in the fake device (tests, fuzzing; not in the image) |
| `urmqtt-log` | 12 (12) | deny |
| `urmqtt-config` | 9 (9) | deny; the typed `CONFIG` in `.bss` |
| `urmqtt-usys` | 8 (8) | default; the kernel and worker's shared formats |
| `urmqtt-x25519` | 8 (8) | default; the MULX/ADX assembly (x86_64, ADR-131) and the `mul`/`umulh` inline assembly (AArch64, ADR-259; written for this project, no third-party code) |

`mqtt`, `broker`, `tls`, `timer-wheel`, `cfg`, `config-schema`, `control`,
`plain`, `sntp` and `dispatch` are `forbid(unsafe_code)`. `tcp`, `net`, `pci`,
`platform`, `diag` and the `arch` facade are `deny` and contain none. A new
`unsafe` site without a `// SAFETY:` comment shows up in the generated
inventory as **no**; the CI check fails on a stale inventory, and the count
above is 0 unjustified at this commit. A justification is a claim to review,
not a proof: reviewing them is item 5 of the proposed scope (§8).

---

## 2. External inputs and their parsers

Who controls the input decides how hostile it can be. **Network** means
anyone who can reach port 8883 (the only open port), or the LAN for
ARP/DHCP. **Volume** means anyone with access to the data disk (a cloud
snapshot, a stolen disk). **Firmware/hypervisor** is trusted in a VM, but
not on bare metal for devices (DMA, see H4b).

| Input | Who controls it | Parser | Bounded by | Fuzz target |
|---|---|---|---|---|
| Ethernet, ARP, IPv4 (no fragments), ICMP, UDP | network/LAN | `net/src/iface.rs`, `net/src/ipv4.rs` | frame size; ARP cache size | `net_frame` |
| DHCP replies | LAN | `net/src/dhcp.rs` | packet size; xid match | `net_frame` (via `Iface`) |
| TCP segments and the state machine | network | `tcp/src/wire.rs`, `tcp/src/lib.rs`, `tcp/src/sack.rs` (the sender's SACK scoreboard, ADR-265) | `max_conns`, `tx_max`, window, SYN cookies, `rst_per_sec`; SACK: at most 4 blocks parsed, 8 ranges kept per connection, blocks outside `(snd_una, snd_max]` ignored | `tcp_segment` (wire + stack; sends SACK blocks since ADR-265) |
| TLS records (application, KeyUpdate, alerts) | network | `tls/src/record.rs` (own) | 2^14+256 ciphertext, 2^14+1 inner plaintext | `tls_record`; `diff_tls_record` against rustls + ring (H2); 23 tlsfuzzer probes |
| Session tickets (on resumption) | network | `tls/src/ticket.rs` (own) | AEAD under per-boot keys; length checked first | host tests (every bit flipped) |
| TLS handshake messages | network | rustls 0.23.46 (third party) | handshake timeout 10 s; in-flight limits | none of our own (upstream fuzzes rustls) |
| Client X.509 certificates | network (signed by the CA) | rustls-webpki (third party), `tls/src/identity.rs` (own: CN/SAN URI) | certificate size from rustls | `x509_identity` |
| MQTT 3.1.1 packets | network (authenticated devices) | `mqtt/src/decode.rs`, `validate.rs` | `max_packet_size` 4096, topic length 256 and levels 16 | `mqtt_decode` |
| MQTT 5.0 packets and property blocks (ADR-273; reachable since NEXT-3 part 2, ADR-274, on every listener while `mqtt5.enabled`) | network (authenticated devices; the CONNECT of a plaintext or WebSocket login before the login is decided) | `mqtt/src/v5/{decode,props,reason,encode}.rs`, the 3.1.1 `validate.rs` | Maximum Packet Size = `max_packet_size`, checked from the fixed header; topic length and levels; User Properties per block and Subscription Identifiers per PUBLISH (`v5::Limits`); no allocation, duplicates found with a 64-bit mask; varints at most 4 bytes and minimal | `mqtt5_packet`, `mqtt5_props`; Kani `v5::proofs` |
| MQTT sequences (sessions, ACL, retained, LWT, QoS 2 flows: PUBREC, PUBREL, PUBCOMP and duplicate PUBLISHes, ADR-271; MQTT 5.0: session and message expiry, will delay, topic aliases, subscription options, Receive Maximum, Maximum Packet Size, property forwarding, ADR-274; shared subscriptions across shards, Subscription Identifiers, the retained-expiry sweep, ADR-275) | authenticated devices; for a shared group also the members' shards (`CoreMsg::Shared` over the mesh) | `broker/src/lib.rs`, `broker/src/v5.rs`, `broker/src/expiry.rs`, `broker/src/shared.rs` | limits section of config; retained messages per identity and per byte budget (H3, was unbounded: H0-W1); QoS 2 ids held per session (`max(limits.max_inflight_qos1, 64)`; a 5.0 client `mqtt5.receive_maximum`, 32, then DISCONNECT 0x93); topic aliases per connection (`mqtt5.topic_alias_maximum`, 10, table allocated on first use); session expiry at most `limits.max_session_expiry_s`; expiries ended at most 64 per tick; shared groups per shard `limits.max_shared_groups` and members per group `limits.max_shared_group_members` (1024 each), a message handed on at most 4 times, a SUBACK waiting for another shard at most 2 s; one Subscription Identifier per subscription (bounded by `limits.max_subscriptions_per_session`) | `broker_input`, `broker_acl` (both with QoS 2, MQTT 5.0 and shared-subscription seeds) |
| Control messages `set-account` and `remove-account` (NOW-15, ADR-285; only after the mTLS service identity and the Ed25519 signature, and only when `limits.max_runtime_accounts` > 0): the items, the account id and the PBKDF2 hash text | a holder of the control signing key and a service identity | `control/src/lib.rs` (`parse_account`, `decode_body`), reusing `cfg/src/{plain,passwd}.rs`; `kernel/src/control.rs` (the glue) | fixed layout, at most 8 items of at most 216 bytes, ids of 1 to 64 identity characters, hashes of 1 000 to 100 000 iterations and 150 bytes, one id once per message; at most `limits.max_runtime_accounts` rows | `control_account`, `control_message` |
| Plaintext listener (P1, only when `plaintext.enabled`): source addresses, the first packet and CONNECT credentials, the `[plaintext]` entries | network (only addresses in `plaintext.allow_from`); the image's configuration | `cfg/src/net.rs`, `passwd.rs`, `plain.rs`; `plain/src/{allow,sources,auth}.rs`; `kernel/src/plain.rs` (the glue) | SYN-time allow-list, connections (total, per address), login rate, lock-out; packets 1 KiB from the first byte; password 256 bytes, PBKDF2 iterations at most 200 000; the broker's plaintext role (no service, operator or control rights) | `plain_input`, `broker_input`, `mqtt_decode` |
| The source address of a TLS connection, as the key of the per-address table (ADR-280) | network (any address; spoofed SYNs leave no trace, the table is entered only at the final ACK) | `net/src/source_limit.rs` (own); `kernel/src/conn_limit.rs` | hashed under a per-boot random key into eight-slot buckets; `limits.max_connections_per_ip` per address; 32 768 slots; a full bucket lets the address through uncounted | `source_limit` |
| WebSocket listener (ADR-272, only when `websocket.enabled`): the HTTP Upgrade request, RFC 6455 frames, the password CONNECT in `password` mode, the `[websocket]` entries | network (after TLS; with `mtls` only clients with a certificate) | `ws/src/{upgrade,frame,sha1}.rs` (own, `no_std`, no allocation); `cfg/src/ws.rs`; `kernel/src/websocket.rs`, `kernel/src/mqtt_service/ws.rs` (the glue) | request 4 KiB and 32 header lines, within `upgrade_timeout_s` (5 s) of the accept; no reassembly (14 bytes of header and 125 of control payload kept); a message at most the packet limit + 4 KiB, checked at the header; connections total and per address, login rate, lock-out; the MQTT bytes go to the broker's parser with its limits | `ws_upgrade`, `ws_frames`, `mqtt_decode`, `broker_input` (web sessions); Kani; Autobahn\|Testsuite |
| Superblock, region table, size table | volume | `store/src/layout.rs` | fixed 4 KiB blocks, region count ≤ 128 | `disk_layout` |
| Backup slot headers and control block (S5) | volume | `store/src/backup.rs` | magic, disk UUID, CRC-32C, page size and count against the slot's capacity | `disk_backup` |
| Encrypted disk: key files, sectors under a wrong key, a damaged medium (S7) | the key file (operator); the volume | `store/src/crypt.rs`, `cfg/src/diskkey.rs`, `Disk::open_keyed` | key length and shape, key check in the superblock before any other read, hardware AES only | `disk_crypt` |
| Telemetry segments and records | volume | `store/src/telemetry.rs` | segment header checks, CRC salted by sequence | `telemetry_recover` |
| SQLite database, WAL, journal | volume | SQLite (C), **at EL0 / ring 3** (H6) | `quick_check` at boot, `DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`, no extensions; address-space isolation, checked system calls, restart | no fuzzing (gap H0-W8, narrowed); isolation: smoke `worker-contain`, `worker-fault` |
| Worker protocol: rows, handles, messages, VFS system calls | the worker (untrusted) | `store/src/remote.rs`, `store/src/vfs.rs::syscall`, `usys/src/proto.rs` | bounds-checked readers, type checks, file numbers 0 to 3, offsets and lengths checked, sleep clamped | `usys` host tests; the whole store suite through the protocol (`loopback`, 131 tests) |
| Device tree | firmware | `platform/src/fdt.rs` | blob size, node depth | `fdt_parse` |
| ACPI tables | firmware | `platform/src/acpi.rs` | table lengths, MADT entry lengths | `acpi_parse` |
| PCI configuration space, capabilities | firmware/devices | `pci/src/lib.rs` | capability list walk | **none** (gap H0-W9) |
| virtio rings, config space, SCSI sense/INQUIRY | hypervisor/devices | `virtio/src/{queue,blk,net,scsi,transport}.rs` | ring sizes, descriptor ids | **none** (gap H0-W9) |
| virtio-net's receive interrupt (ADR-270; MSI-X through the GICv2m frame, the GICv3 ITS or the local APIC; `devices.virtio_net_interrupt = "off"` turns it off) and the ITS's command-queue progress | hypervisor | `kernel/src/devices.rs` (`on_net_irq`: a counter only), `virtio/src/wake.rs`, `arch-aarch64/src/its.rs` | the queue asks for interrupts only while the dispatcher sleeps; the interrupt is on probation (a 1 ms deadline kept) until 3 frames verify it, and 8 frames that waited without it fall back to polling; a device that interrupts anyway costs a counter increment and an EOI per interrupt; every ITS register wait is bounded (10^7 polls), a stalled command fails the setup and the NIC is polled | host tests of the protocol, the mode machine and the ITS encodings; no fuzz target (no parser) |
| virtio-gpu control-queue responses (ADR-256; only with `console.virtio_gpu` not `"off"`, the default) | hypervisor | `virtio/src/gpu.rs` (`parse_response`, `choose_mode`, `auto_choice`) | fixed-size copy of the response (at most 408 bytes); the device's written length is capped at the buffer; type, length and fence checked; a display info only whole; no device value is used as a pointer or an index; the mode is clamped to 640x480..1920x1080 and an 8 MiB budget; every wait has a timeout | `virtio_gpu_response` (narrows H0-W9 for this parser only) |
| virtio-console port 0 receive buffers and transmit completions (ADR-258; only with `devices.virtio_console` not `"off"`, the default) | hypervisor | `virtio/src/console.rs`, `kernel/src/vdev/console.rs` | length clamped to the 64-byte buffer; heads checked against a slot map; received bytes into a fixed 256-byte ring (overflow dropped, counted); output never waits (full buffers drop, counted); the log only tries the device lock | `virtio_console_device` (the driver against a fake device with hostile completions) |
| virtio-balloon `num_pages` and statistics completions (ADR-258; only with `devices.virtio_balloon` not `"off"`) | hypervisor | `virtio/src/balloon.rs`, `kernel/src/vdev/balloon.rs` | the request is only logged (never inflates, `actual` stays 0); statistics never claim more than the total; a completion for a head never posted is counted; the heap's numbers only tried from the tick | `virtio_balloon_device` |
| virtio-input configuration (name, event bitmaps) and events (ADR-258; only with `devices.virtio_input` not `"off"`) | hypervisor (fed by the provider's VNC console) | `virtio/src/input.rs`, `kernel/src/vdev/input.rs` | the configuration's size clamped to the 128-byte union, the name to 32 printable bytes; an event only whole (8 bytes); key codes through a fixed table; at most 4 devices; typed bytes into a 256-byte ring | `virtio_input_event` |
| virtio-vsock packets, credit and transport events (ADR-258; only with `devices.virtio_vsock` not `"off"`) | hypervisor and host processes (any CID the host routes) | `virtio/src/vsock.rs` (`Hdr::parse`, `Stack`), `kernel/src/vdev/vsock.rs` | one listening port (2883), only from CID 2, at most 4 connections, read-only (peer data counted and dropped), sends only within the peer's credit (never negative), payload counted from what the device delivered, 10 s idle and 2 s close timeouts, a reset never answered with a reset; **untested on a real device** | `virtio_vsock_packet` |
| Limine responses (memory map, MP, date) | bootloader | `kernel/src/boot.rs` via the `limine` crate | — | none (trusted) |
| Configuration (`deploy/<env>/config.toml`, PEMs, packed into the `urmqtt-cfg` blob of the image's slot; ADR-215, ADR-216) | operator, when the image is made | `config-schema` at pack time, `urmqtt-cfg` at every boot | fail closed: the kernel refuses a blob it does not understand, a dev option on a release kernel, a bad fingerprint or signature | `config_parse`, `cfg_blob` |
| Kernel command line | operator (`limine.conf`) | `kernel/src/cmdline.rs` | **prod ignores every option** (dev only) | none (fixed words) |

---

## 3. Mitigation matrix

Every protection, where it lives, and what proves it. *Test* is a smoke
scenario (`scripts/smoke.sh`), a host test or a CI job. "**none**" is a gap.

| Protection | Implementation | Proving test | Arch |
|---|---|---|---|
| W^X: no page writable and executable | `kernel/src/vm.rs`, `arch-aarch64/src/paging.rs` | boot audit line `selftest: W^X ok (… 0 W+X)`; `wx-write-text`, `wx-exec-heap` | aarch64 |
| Page tables locked (read-only after boot) | `vm::lock` | `page tables locked` line; **no test writes a table after the lock** (gap H0-W10) | aarch64 |
| Guard pages around every stack; separate exception stack | `kernel/src/layout.rs`, `vm.rs` | `stack-overflow` (decoded report names the guard page) | aarch64 |
| Lower half unmapped, null page unmapped | TCR EPD0, `vm.rs` | `null-deref` | aarch64 |
| PAC (return addresses) | `-Zbranch-protection=pac-ret`, `arch-aarch64/src/pac.rs` | `pac-forgery` | aarch64 (when the CPU has PAuth) |
| BTI (indirect branch targets) | `-Zbranch-protection=bti`, guarded pages | `bti-violation` | aarch64 (when the CPU has BTI) |
| FP/SIMD state saved on exceptions | ADR-003, exception entry | smoke `simd-irq` (X0b: 10 s of crypto known answers on four cores under the tick and an IPI storm, 0 mismatches) | aarch64 |
| Boot refuses without a seeded CSPRNG | `tls/src/rng.rs`, `kernel/src/devices.rs` | host tests (pool policy); `no-hw-rng` (jitter fallback with health tests) | aarch64 |
| TLS 1.3 only, mutual TLS, identity from the certificate | `tls/src/server.rs` | `mqtt-tls`: `tls-wrong-ca-rejected`, `tls-expired-rejected`, `tls-client-id-mismatch-rejected` | all |
| Revocation (build-time list, persisted in SQLite) | `server.rs` (verifier wrapper), `db.rs:470` | `tls-revoked-rejected`; `mqtt-persist` (1 revoked serial restored) | all |
| Revocation re-checked on resumption | `server.rs:574-585` | `tls/tests/handshake.rs` `revoked_device_cannot_resume` | all |
| 0-RTT off | `server.rs` (`max_early_data_size = 0`; rustls refuses early data with stateless tickets) and config-schema (`tls.early_data` fails the build) | `zero_rtt_is_never_offered`, `early_data_fails_the_build`; tlsfuzzer `early_data offered without a PSK` (H2) | all |
| Session tickets under random, rotating, per-boot keys | `tls/src/ticket.rs` (ADR-054) | `ticket::tests` (11), `ticket_from_another_boot_means_full_handshake`; smoke `ticket-rotation`, `ticket-restart` | all |
| Fatal alerts on TLS errors; inner plaintext ≤ 2^14 + 1 | `tls/src/record.rs`, `server.rs` (`flush_alert`) | `fatal_alerts_reach_the_peer`, `inner_plaintext_over_the_limit_is_record_overflow`; 23 tlsfuzzer probes (`make conformance`) | all |
| Constant-time tag checks and secret comparison | RustCrypto (`subtle`), `server::ct_eq` | `make ct` (dudect-style, with a negative control) | all |
| Constant-time P-256 secret-scalar operations (key generation, ECDH, signing) | `nistz256` (scans, branch-free negation, complete addition; ADR-130, ADR-255) | `make ct`: four P-256 cases (key generation, ECDH, signing key, signing nonce) and a P-256-scale positive control (black-box; Docker on an M4 Pro and the Neoverse N2 CI runner) | all |
| Handshake admission (rate, in flight per core and per IP, heap reserve, DB backlog) | `kernel/src/mqtt_service.rs` (`admit`) | `storm` (3 × 3000 devices against an 8 MiB heap) | all |
| Established TLS connections per source address (`limits.max_connections_per_ip`, ADR-280): one table for all cores behind a spin lock, checked at the SYN, counted at the ACK, released in `drop_conn` | `net/src/source_limit.rs` (own, `no_std`, no `unsafe`), `kernel/src/conn_limit.rs`, `kernel/src/mqtt_service.rs` (`syn_ok`, `admit`, `drop_conn`) | `source_limit` unit tests and model, `source_limit` fuzz, smoke `conn-limit` (a limit of 6 on four vCPUs, `established-flood`) | both |
| MQTT limits (packet, topic, subscriptions, inflight, queue, publish rate) | `mqtt/src/validate.rs`, `broker/src/lib.rs` | broker host tests; `broker_input` fuzzing | all |
| ACL (device and service rights, device-scoped subscriptions) | `broker/src/lib.rs` | `mqtt-plain`/`mqtt-tls`: `acl-subscribe-denied`; broker host tests | all |
| SYN cookies (SipHash, random key at boot) | `tcp/src/cookie.rs`, `netproto.rs:50-62` | tcp host tests | all |
| RFC 5961 checks (challenge ACK, RST/SYN in window) | `tcp/src/lib.rs` | tcp host tests (`tests.rs`) | all |
| RST rate limit | `tcp` `rst_per_sec = 200` | tcp host tests | all |
| Handler watchdog, stuck-core reset | `kernel/src/watchdog.rs` | `watchdog` | all |
| Rate-limited logs | `crates/log` | log host tests | all |
| No secrets in logs, fault reports or panics | `crates/log`, `kernel/src/hardening.rs` (fault and panic policy, ADR-172); `redact` word | `fault-secrets` and `panic-secret` (a planted secret must not appear), each with an `-open` control that proves the planted secret *would* appear without redaction; `scripts/log-flood-check.py` | aarch64 (x86_64: the same code, not in the hardening group) |
| Production ignores the kernel command line | `kernel/src/cmdline.rs` | host test `production_ignores_every_option` (H0-W11, fixed in H1) | all |
| SQLite hardening (`DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`, `OMIT_LOAD_EXTENSION`, fixed prepared statements) | `store/src/store.rs`, `store/build.rs` | `the_connection_hardening_is_in_force` (H10: the flags are read back from the open connection; `DEFENSIVE` through its effect on `writable_schema`) | all |
| Integrity check at boot, refuse on corruption | `store`, `kernel/src/db.rs` | `db-crash`, `log-crash`, `log-tear` | all |
| A partitioned disk is never the data disk | `kernel/src/devices.rs:510` | `raw-disk` (boot disk byte-identical afterwards) | all |
| Kernel and configuration module pinned by blake2b in `limine.conf`; the `limine.conf` itself enrolled into the loaders (`limine enroll-config`, ADR-250) | `scripts/mkiso.sh`, `tools/config/src/image.rs` | `integrity-*` (H8; universal group `SMOKE_ONLY=integrity`, aarch64 UEFI, x86_64 UEFI, x86_64 BIOS): one flipped bit in the kernel or in the configuration module, in the ISO or in the raw disk image, and one edited byte of `limine.conf` in the ISO or in the raw disk: the loader refuses and nothing boots (Limine's message is read from the serial port, except for the BIOS configuration refusal, which is on the screen only: there the test asserts that the machine does not boot); each has a control that boots (the other architecture's kernel changed; the same edit with `--no-enroll`). Also `config-tampered-refused`, `universal-config` (a packed template equals the direct build, loaders re-enrolled). **Without Secure Boot the loader itself is not protected**: whoever can rewrite `BOOTX64.EFI`, `limine-bios.sys` or the MBR defeats the pin and the enrollment (see 3b, H8 Secure Boot) | all |
| Reproducible images | `make repro` | CI "Reproducible prod image (built twice)" | aarch64 |
| Signed releases, provenance | `make sign`, release workflow | release workflow (minisign verify, SLSA attestation) | all |
| Config validated when the image is made and again at every boot | `config-schema`, `urmqtt-cfg` | config tests; `config_parse` fuzzing | all |

### 3b. Protections added after H0

| Protection | Implementation | Proving test | Arch |
|---|---|---|---|
| Revocation at run time, allowlist mode, signed control channel (Ed25519, per-message sequence number and validity window) | `control` crate, `broker`, `kernel` (H1, ADR-048 to ADR-050) | `scripts/control-scenarios.py` against a dev VM (`control-forged`, `control-replay`, `control-expired`, `control-from-device`, `control-revoke-live`, `control-unrevoke`, `registry-allowlist`, `bootstrap-role`, `ca-rotation`); host tests in `control` | all |
| Password accounts at run time: only a hash is signed, stored and logged; an account never shadows the image's or a service identity; a class only narrows; a removed or changed account's live logins are cut; the limit bounds the table | `control` (`parse_account`), `plain` (`Authenticator::set_runtime`), `broker` (`set_login_class`), `store` (schema 6), `kernel/src/control.rs` (NOW-15, ADR-285 to ADR-287) | host tests in `control`, `plain`, `broker` and `store` (`golden_schema6.rs`, a power cut at every write of the migration); fuzz `control_account`; smoke `accounts-run-time` and `accounts-persist` (both listeners, class, limit, shadowing, replay after a power cut, no password or hash in the serial log) | all (aarch64 smoke group `accounts`) |
| Lower bound on the wall clock; SNTP with median consensus and a drift budget | `kernel` time code, `sntp` crate (H1, T1, H7, ADR-050, ADR-100) | `SMOKE_ONLY=time` (incl. `time-before-build`); `sntp` host tests | all |
| Expiring certificates refused at build and watched at run time | `config-schema`, `kernel` (H1) | config tests (`config-schema`); `tls-expired-rejected` for a device certificate | all |
| TLS 1.3 conformance and interoperability | `tls` | 23 tlsfuzzer probes (`make conformance`); OpenSSL, wolfSSL and mbedTLS clients (`make interop`); `diff_tls_record` against rustls and ring | all |
| Hardware crypto selected at run time, differential-tested | `dispatch`, vendored `cpufeatures` (X0b, ADR-041) | `diff_aes_gcm`, `diff_chacha20poly1305`, `diff_sha256`, `diff_crc32c` against ring; known-answer tests at every boot | aarch64; x86_64 selects ADX/BMI2 only |
| SYN, ACK and RST floods; slowloris; oversize and over-long packets | `tcp`, `kernel` admission (H3) | `tools/attack` clients asserted in `scripts/smoke.sh` (observed: 20 000 SYNs, 0 connections, heap flat) | aarch64 (raw layer-2 floods) |
| Retained messages bounded per identity and per byte | `broker` (H0-W1, H3) | `retained_per_device_limit_at_the_bound`, `retained_byte_budget_at_the_bound`, smoke `retained-limit` | all |
| SYN-cookie key rotation | `tcp/src/cookie.rs` (H0-W3, H3) | `valid_within_two_periods_and_bound_to_the_flow` | all |
| Allocator hardening: poison on free, double and invalid free refused, obfuscated free lists, guard gaps, key slab | `mm` (H4, ADR-170) | `double-free`, `heap-uaf`, `heap-overflow`, `keyslab-zero`, `double-free-prod` | aarch64 |
| Stack protector, canary from the CSPRNG | `-Zstack-protector`, `kernel/src/hardening.rs` (ADR-171) | `stack-guard-boot`, `stack-smash` | aarch64 |
| KASLR: about 19 bits for the image plus random heap, stacks, bookkeeping, page-table alias and MMIO window | `kernel` (ADR-173) | `kaslr-differs` (three boots, every region elsewhere) | both |
| MTE heap tagging | `mm` (ADR-174) | `mte-boot`, `mte-uaf`, `mte-overflow`, `mte-mqtt-tls` (TCG `mte=on` only; no hardware or HVF) | aarch64 TCG |
| SQLite in an unprivileged address space, twelve checked system calls, restart on fault or 30 s overrun | `dbworker`, `usys`, `store/src/{worker,remote}.rs`, `kernel/src/dbsandbox.rs` (H6, ADR-210 to ADR-212) | `worker-contain` (kernel read, write, jump, privileged instruction, write to own code, jump into data, null, endless loop: all contained, kernel word intact), `worker-fault`; the whole store suite through the protocol (`--features loopback`) | both |
| Stateful ACL invariants | `broker` | the stateful ACL fuzzer (`make acl-fuzz ACL_FUZZ_SECS=600`; the H5 acceptance is a clean 10-minute run, re-run it for the audit); the second, coverage-guided oracle (`make fuzz T=broker_acl`, and `acl_invariants` in `cargo test`) | host |
| Bounded proofs of the parsers | `mqtt`, `tcp`, `tls`, `cfg`, `timer-wheel` (H5) | `make kani` (a harness that hits its cap is *not proven*) | host |
| Undefined behaviour, memory errors | host builds (H5) | `make miri` (subset, VERIFICATION.md lists what is excluded), `make sanitize` (ASan Rust and C, trapping UBSan on C) | host |
| Plaintext listener: filtering at the SYN, three login modes, lock-out, a narrower role | `plain` crate, `kernel/src/plain.rs` (P1, ADR-229 to ADR-231) | `plain-scenarios.py`, `plain_input` and `broker_input` fuzzing, the `plaintext-*` smoke scenarios | both |
| WebSocket listener: one bounded upgrade, a streaming codec, `mtls` or a password inside TLS, origin allowlist, upgrade deadline, `Role::Web` | `ws` crate, `kernel/src/websocket.rs`, `kernel/src/mqtt_service/ws.rs`, `tls::TlsServer::new_server_only` (ADR-272) | host tests with RFC 6455 and RFC 3174 vectors, Kani, Miri, `ws_upgrade` and `ws_frames` fuzzing, Autobahn\|Testsuite (docs/audit/ws-autobahn.md), `ws-scenarios.py` and the `websocket-*` smoke scenarios | both |
| Operator role: `$SYS/` and the console only for listed identities over mutual TLS | `broker`, `kernel` (O1, O2) | `sys-scenarios.py` | both |
| Signed configuration, refused when tampered; empty template refuses to serve | `urmqtt-cfg`, `kernel` (C1, ADR-215 to ADR-219) | `config-packed-*`, `config-tampered-refused`, `config-empty-refuses-to-serve`; `cfg_blob` and `config_parse` fuzzing | both |
| Data disk: a damaged partition is refused and never re-formatted; crash safety of every multi-step update; scrubbing; in-disk backup with automatic restore | `store`, `kernel/src/db.rs` (S1 to S6) | the fault-injection loops (`tools/disk/tests`, `crates/store/tests`, `scripts/fault-loop.sh`), the storage smoke group (86 scenarios on aarch64 HVF at S7), `disk_layout`, `disk_backup`, `telemetry_recover` fuzzing, golden images of every layout version | both |
| Encryption at rest (optional): AES-256-XTS, hardware AES required, key check, never converted at boot | `store/src/crypt.rs`, `kernel/src/db.rs` (S7, ADR-240) | IEEE 1619 vector, the conversion procedures under a power cut at every write, smoke `storage-encrypted`, `disk_crypt` fuzzing | both |
| UEFI Secure Boot path: loaders signed with an owner key (`sbsign` or `osslsigncode`), keys enrolled in OVMF's variable store | `scripts/sign-loaders.sh`, `mkiso.sh --sb-key`, `run-qemu.sh --secure-vars` (H8, ADR-251) | `SMOKE_ONLY=secureboot` (x86_64 q35, OVMF with SMM): signed ISO boots; unsigned, other key, and changed-after-signing are `Access Denied`; a modified kernel or `limine.conf` is still refused by Limine under Secure Boot; the signed ISO is reproducible. **Not tested:** aarch64 enforcement (the firmware here does not enforce), Proxmox, a physical PC, the CI wiring (the group skips when its tools are missing; `SMOKE_REQUIRE_SB=1` makes that a failure). Limits: a signed ISO cannot be configured afterwards (`pack --iso` breaks the signature); an installed disk does not boot under Secure Boot (ADR-217's module has no hash) | x86_64 |
| What may start the installer: three production words, a module the loader pins, an enrolled menu | `cmdline.rs`, `install.rs`, `mkiso.sh` (H8, ADR-253) | `production_honours_*` (host), `SMOKE_ONLY=install-rules` (a word added to the menu refused; with no module `install` writes nothing; a changed installation image refused; the target disk's SHA-256 unchanged; three machines) | all |
| Image secrecy: a warning for a production image built outside CI; no key bytes in logs or repro output | `mkiso.sh`, `scripts/secret-scan.py`, `scripts/repro.sh` (H8, ADR-252) | `SMOKE_ONLY=secrecy` (server key and disk key scanned for in the serial logs of an encrypted boot and both refusals, dev and release kernels; the scan must find them in the image), the scan in `make repro` | aarch64 (repro: the image it builds) |
| SBOM, vet, advisory job, vulnerability process | `scripts/sbom.py`, `supply-chain/`, CI (H9, ADR-190 to ADR-193) | CI jobs; 53 of 67 kernel-linked crate versions are cargo-vet *exemptions*, not audits ([audit/vet-exemptions.md](audit/vet-exemptions.md)) | n/a |
| Static analysis: CodeQL (Rust, Actions) and OpenSSF Scorecard, every alert triaged | `.github/workflows/codeql.yml`, `.github/codeql/codeql-config.yml` (tests and fuzz targets excluded), `scorecard.yml` | [audit/codeql-triage.md](audit/codeql-triage.md): 137 alerts read on 2026-11-07; no hard-coded secret in production code; 1 fixed (base image pinned), 132 dismissed with a named reason, 4 repository-posture alerts left to the owner ([CSV](audit/codeql-triage-2026-11-07.csv)) | n/a |
| virtio-gpu console (optional, off by default): DMA only into memory allocated for it, the device lock only tried, every wait bounded | `virtio/src/gpu.rs`, `kernel/src/gpucon.rs`, `log` presenter hooks (ADR-256) | host tests (encoding, parsing, mode, `auto`), `virtio_gpu_response` fuzzing, smoke `virtio-gpu-*` (QMP screendump checked; `off`: not started); real machine: netcup VPS 500 ARM G12.5 | both |
| The optional virtio drivers (console, balloon, input, vsock; each off by default): a driver configured but not compiled in is refused at pack time and warned about at boot; every device listed with its state | `virtio/src/registry.rs`, `kernel/src/vdev/`, `cfg/src/drivers.rs`, `config/tools image.rs` (ADR-257) | host tests (the table's const check, registry and key tables equal, marker found, `pack --kernel` refusal), smoke `virtio-devices: every key off, listed and not driven` | both |
| virtio-console, -balloon, -input, -vsock: lengths clamped, heads checked, loops bounded, nothing waits for the device, locks only tried from the log, the tick and the prompts; the balloon never inflates | `virtio/src/{console,balloon,input,vsock}.rs`, `kernel/src/vdev/` (ADR-258) | host tests against `fake::FakeBus`, fuzz `virtio_console_device`, `virtio_balloon_device`, `virtio_input_event`, `virtio_vsock_packet`, smoke `virtio-devices: *` (QMP stats, balloon request refused, `WIPE` typed on the virtio keyboard and on the virtio-console); vsock: host tests and fuzzing only | aarch64 (smoke); both (build) |

---

## 4. The nine questions of PROMPT-security H0

1. **Can a device certificate be revoked at runtime without a new image?** **No.** The list comes from `tls.revocation_list` when the image is configured and is seeded into SQLite at boot (`kernel/src/db.rs:470`); nothing changes it at runtime. Gap → H1. **At H10: yes.** The signed control channel (Ed25519, sequence number, validity window) revokes and unrevokes at run time and persists the list; `allow_unrevoke` is off by default (SECURITY.md, PROVISIONING.md).
2. **Is the registry an allowlist?** **No.** It is a record filled on first connect: `DbReq::DeviceSeen` is an upsert (`mqtt_service.rs:281`, `db.rs:699`). Any certificate from the CA connects. Gap → H1 (`registry.mode`). **At H10: both.** `registry.mode` is `open` (the default, as before) or `allowlist` (a certificate from the CA also needs its identity on the allowlist, which the control channel edits).
3. **Where does wall-clock time come from, and what if it is wrong?** From the firmware RTC through Limine, plus uptime (`boot.rs:226-233`, `now_unix` at `boot.rs:608-625`). An unknown date refuses every handshake (fail closed, ADR-009). A **wrong** date used to be believed; since H1 a clock before the image's build time is unknown (ADR-050), and since T1/H7 an SNTP client (ADR-100: several IPv4 servers, median consensus, a drift budget of `max_step`) can correct it. Not authenticated: NTS is out of scope, so a man in the middle who controls every answer can move the clock by `max_step` in total after boot. *H7 closed: lower bound, SNTP, bounded jumps.*
4. **KASLR?** **No.** The kernel is linked statically at a fixed address (`crates/kernel/linker.ld`); the heap, stacks and per-CPU regions are at fixed virtual addresses (`kernel/src/layout.rs`). Gap → H4. **At H10: yes**, on both architectures (ADR-173): the image is position independent and slid about 19 bits by Limine, and the heap, stacks, bookkeeping, page-table alias and MMIO window get random places; `kaslr-differs`. The direct map of RAM (HHDM) keeps its base (residual risk in SECURITY.md).
5. **0-RTT disabled?** **Yes** (`tls/src/server.rs:348`), but untested and not refused by config. Gap (test) → H2. *H2: tested (`zero_rtt_is_never_offered`, tlsfuzzer); the config refusal already existed (`early_data_fails_the_build`).*
6. **Secrets zeroised?** **Partly:**
   - Per-direction record secrets and per-record keys are wiped on drop (`tls/src/record.rs:106-128`).
   - The X25519 scalar is in `Zeroizing` (`provider/kx.rs:68`).
   - **Not** wiped: traffic secrets captured for KeyUpdate (`server.rs:84-150`). They sit in a global `Vec`; `remove(0)` and `swap_remove` drop them without wiping, and reallocations leave copies in freed heap memory (H0-W2).
   - Not established: whether rustls's own handshake secrets, P-256 keys and CSPRNG state are wiped when retired, or that freed slab memory is clear. → H4. **At H10:** the captured traffic secrets are wiped in place when taken, dropped or evicted, and the table never moves an entry (H0-W2, fixed in H10, unit tests `capture_tests`); a reallocation of the table frees the old buffer, and the allocator poisons freed blocks (ADR-170); `Csprng`, the PAC key copy, ticket keys, key-exchange secrets and P-256 scalars are wiped; the disk key of S7 is wiped after the cipher is built and its round keys on drop. **Not controlled:** copies of a secret on a stack that a callee returned by value (the 32-byte arrays handed to the record layer) and whatever rustls keeps for its own handshake until it drops it.
7. **RFC 5961 and RFC 6528?** RFC 5961: **yes** (`tcp/src/lib.rs`, tests in `tcp/src/tests.rs`). RFC 6528: ISNs are SYN cookies (SipHash-2-4 MAC over the 4-tuple under a 16-byte key from the CSPRNG at boot, `tcp/src/cookie.rs`, `netproto.rs:50-62`), so they are keyed. **The key never rotated** (H0-W3). → H3. **At H10:** it rotates every 10 minutes with the previous key valid for the cookie lifetime.
8. **Network-reachable unbounded memory or loops?** Mostly bounded by config limits and admission (M16). One case is **not** bounded: retained messages. A device may publish retained messages to any number of distinct topics under its own `devices/{id}/#`, at up to `publish_rate_per_device` (10/s, about 864 000 topics a day). Each is stored in SQLite and replicated on every core (H0-W1). There is no per-loop bound documentation yet. → H3. **At H10:** retained messages are bounded (H0-W1, fixed in H3) and §6b lists every network-reachable loop and allocation with its bound.
9. **Expiring server certificate refused at build, monitored at runtime?** **No** and **no**: `config-schema` has no expiry check and there is no expiry gauge. Gap → H1. **At H10: yes and yes** (H1): the build refuses a certificate that expires within `tls.min_server_cert_days`, and the kernel watches the server certificate's expiry.

---

## 5. Weaknesses found

Severity is for the current deployment model: a VM with a virtio data disk,
mutual TLS devices, and the image treated as a secret.

| Id | Weakness | Severity | Where | Plan |
|---|---|---|---|---|
| H0-W1 | ~~**Retained messages are unbounded per device**, in count and in total bytes. An authenticated device can exhaust memory on every core (each core keeps a replica) and fill the database. Even clearing a retained topic (empty payload) creates its trie nodes first~~ | **high** (authenticated DoS) | `broker/src/lib.rs`, `broker/src/topics.rs`, `db.rs` | **fixed in H3:** `limits.max_retained_per_device` and `max_retained_bytes` (checked at the origin shard, replicas follow it; refusals counted and logged); clearing creates no nodes and removes unused ones, as does unsubscribing (`retained_*_at_the_bound`, `clearing_retained_messages_leaves_no_nodes_behind`, `unsubscribed_filters_leave_no_nodes_behind`; smoke `retained-limit`). Residual: counts per identity start empty after a restart (the store keeps no owner), so an identity can hold up to twice its limit across a reboot; the byte budget still holds |
| H0-W2 | ~~**Captured TLS traffic secrets are not wiped** (global `Vec`, `remove`/`swap_remove`, reallocation copies)~~ | medium (needs a memory disclosure to exploit) | `tls/src/server.rs` | **fixed in H10:** slots wiped in place (no `remove`, no `swap_remove`), a vacated slot is reused, the bound evicts the oldest after wiping it; reallocation copies are covered by the allocator's poison on free (ADR-170); `capture_tests`. Residual: stack copies of the two 32-byte secrets while the record layer is built |
| H0-W3 | ~~**The SYN-cookie/ISN key never rotates**~~ | low | `netproto.rs`, `tcp/src/cookie.rs` | **fixed in H3:** rotation every 10 minutes, the previous key valid for the cookie lifetime (`valid_within_two_periods_and_bound_to_the_flow`) |
| H0-W4 | ~~**Session-ticket key derived from the server key** (in the image): a copy of the image lets anyone forge tickets for any device identity~~ | **high** if the image leaks | `tls/src/server.rs` | **fixed in H2** (ADR-054): random per-boot keys, rotated by uptime, zeroised; smoke `ticket-restart` |
| H0-W5 | ~~**No lower bound on the wall clock**: an RTC in the past accepts expired certificates~~ | **high** on bare metal (dead CMOS battery) and after VM snapshot restores | `boot.rs` | **fixed in H1** (ADR-050): build time is the lower bound; smoke `time-before-build` |
| H0-W6 | ~~**Random-number failures ignored** in two places: `let _ = fill_global(...)` for the cookie key and the DHCP xid~~ | low | `netproto.rs` | **fixed in H1:** both are fatal now. The generator's `Err` without a source is already host-tested; the kernel paths cannot be reached in a test because boot refuses earlier |
| H0-W7 | ~~`urmqtt-store` had no `unsafe_code` lint.~~ Its docs confined unsafe to the FFI modules, but nothing enforced it | low | `store/src/lib.rs` | **fixed in H0:** `#![deny(unsafe_code)]`, `allow` only on `db`, `ffi`, `libc`, `vfs`, `init` and the log callback |
| H0-W8 | **SQLite parses a database from the volume without fuzzing of crafted images** | ~~medium (a crafted volume reaches 254k lines of C at EL1)~~ **low after H6**: a bug is contained in an unprivileged worker (ADR-210); the remaining harm is wrong answers (an empty revocation list), a restart storm (storage unavailable), and speculative leaks (no KPTI) | SQLite | **narrowed in H6** (EL0 / ring 3, restart, `worker-contain`, `worker-fault`); still open: no fuzz run of crafted database images under ASan (the `sanitize` job runs the store suites, not crafted files) |
| H0-W9 | **No fuzzing of PCI and virtio parsing** (hostile or buggy devices: on bare metal, and virtio under a hostile hypervisor) | medium on bare metal, low in a VM (the hypervisor is trusted) | `pci`, `virtio` | **open.** H5 did not add targets for them; with H4b (IOMMU) deferred to bare metal. Proposed for the external audit (§8) |
| H0-W10 | **No test proves page tables are read-only after the lock** | low (the lock exists; the proof is missing) | `vm::lock` | **open.** The boot audit line `selftest: W^X ok (… tables read-only)` checks the mappings, and `sealed-write` covers the sealed section, but no scenario writes to a table and expects a fault |
| H0-W11 | ~~**No test for "prod ignores the command line"**~~ | low | `cmdline.rs` | **fixed in H1:** the kernel binary runs host tests; `production_ignores_every_option` |
| H0-W12 | ~~**The data disk is chosen by "not partitioned" instead of by identity**~~ | medium on bare metal | `kernel/src/devices.rs` | **fixed in S1** (ADR-051): the boot disk by its GPT disk GUID; other disks only read (smoke `first-boot`, `scsi-boot` check a second disk is byte-identical) |
| H0-W13 | ~~Foreign disks taken for blank; a damaged urMQTT partition re-formatted~~ | low | `store/src/layout.rs` | **fixed in S1:** a damaged data partition is refused and left unwritten (smoke `own-damaged-refused`) |
| H0-W14 | ~~**30 `unsafe` sites have no written justification**~~ | low | [audit/unsafe.md](audit/unsafe.md) | **fixed in H10:** every one of the 889 sites carries a `// SAFETY:` comment or a `# Safety` section (the 108 that lacked one, mostly `#[unsafe(no_mangle)]` and `link_section` attributes, now say who calls the symbol and what the layout contract is); the CI inventory keeps the count visible |

Found while doing H1 (kept here so the list stays in one place):

| Id | Weakness | Severity | Where | Plan |
|---|---|---|---|---|
| H1-W1 | **A publisher learns nothing about the outcome** of a control message. A PUBACK only means "received"; the result is in the broker's log and metrics | low (operations) | `control.rs` | later: a signed status topic readable only by control identities, with its own threat-model entry |
| H1-W2 | **Rolling back the data disk** to an old snapshot restores old revocations and an old `seq` | medium (needs disk access) | store | documented residual risk; image-listed revocations are re-applied at every boot |
| H1-W3 | **The build's expiry check is cached** by cargo until the configuration or certificates change | low | `config/build.rs` | clean builds (CI, repro, release) always run it; optional: a `make` target that forces it |
| H1-W4 | **Allowlist mode without durable storage** means an empty, frozen allowlist: every device is refused | low (fails closed, logged at boot) | `boot.rs` | intended; documented |

Found while doing H8:

| Id | Weakness | Severity | Where | Plan |
|---|---|---|---|---|
| H8-W1 | **An installed disk does not boot under Secure Boot**: its `limine.conf` names the configuration module without a hash (ADR-217) and Limine refuses a file with no hash when Secure Boot is active (asserted by `secureboot: installed-disk-known-limit`) | low (Secure Boot is not used on the VPS target) | `scripts/mkiso.sh`, ADR-217 | **open:** a per-machine ESP with the module pinned and the loader re-enrolled and re-signed by the key's owner; not built |
| H8-W2 | **A signed image cannot be configured afterwards**: `urmqtt-config pack --iso` changes the enrolled hash, which breaks the loader's signature (tested: `configured-after-signing` is refused). The builder page cannot make a Secure Boot image from the template | low | ADR-251 | documented: configure, then sign, with the owner's key |
| H8-W3 | **The BIOS path has no signature**, and its stage 1 and `limine-bios.sys` are not covered by the enrolled hash | accepted (BIOS has no Secure Boot) | ADR-250 | none |
| H8-W4 | **Aarch64 Secure Boot enforcement is untested** (the AArch64 edk2 on the development machine does not enforce it), as are Proxmox and a physical PC; the CI job for the x86_64 test is not wired | medium for the claim, low for a VPS | ADR-251 | open |
| H8-W5 | SECURITY-PLAN said "exactly one command-line word, `install`"; production honours three (`install`, `live`, `diag`) | low (wording) | `cmdline.rs` | **fixed in H8:** the documents say so (ADR-253) |
| H8-W6 | **No downgrade protection**: an older, correctly pinned and signed image boots | low | ADR-251 | open (no version counter, no `dbx` plan) |
| A255-W1 | **ECDSA signing with the ARMv8 assembly showed a repeatable timing difference between a sparse and a random secret key on the GitHub arm64 runner** (`make ct`: \|t\| = 8.6, 9.1, 8.3 in three attempts and 8.6 the run before; the bound was raised to 12 in 87f45e1 while open). **Cause: the harness.** The case signed one fixed message, so the fixed key produced the same signature every time and the random keys a different one each time; DER-encoding a repeated signature is faster (\|t\| = 49 to 57 for `to_der` alone). A dense fixed key scored higher (14 to 23), a random message per measurement in both classes removed it (below 4.5), and the arithmetic and nonce generation alone showed nothing (at most 5.7). Measured on the runner (Neoverse N2), ADR-255 amendment, CRYPTO.md | none (public output) | `crates/tls/tests/constant_time.rs`, ADR-255 | **fixed in ct-dit:** random message per measurement for both classes, bound back to 7, a separate nonce case (`p256_signing_nonce_is_constant_time`); after: 1.4, 1.8 (sign), 2.7, 1.1 (nonce) on the runner |
| A255-W2 | **PSTATE.DIT is never set** (neither by the kernel on its CPUs nor around the host-side calls). Arm guarantees data-independent timing of `mul`, `umulh` and the other listed instructions only with DIT = 1 on cores that implement FEAT_DIT; the nistz256 assembly is built from them, and since ADR-259 so is the AArch64 X25519 field arithmetic (secret scalar). No measurement here shows a difference: the CI runner's VM does not expose FEAT_DIT at all, and in Docker on an M4 Pro (DIT exposed and set by a test guard) it changed nothing measurable | unknown (depends on the core; no leak observed) | ADR-255 amendment | open: set DIT at boot on every CPU where ID_AA64PFR0_EL1.DIT >= 1 and keep it set across the EL0 worker's entry and exit (`user.rs` erets with SPSR = 0 and `leave` returns without an eret) |
| A259-W1 | ~~**No trust anchor ever had its verification table** (ADR-111): `register_issuer` parsed the key with `from_public_key_der`, but webpki's `TrustAnchor::subject_public_key_info` holds the SubjectPublicKeyInfo *without* its outer SEQUENCE, so every registration failed silently and every first verification by a CA took the variable-base path. The benchmarks, the probe and the boot KAT build their tables directly and never showed it~~ | none for security (the variable-base path gives the same verdicts); performance: a device's first handshake cost about 20 us more in Docker on the M4 Pro | `tls/src/provider/verify.rs` | **fixed in ADR-259:** both forms accepted, `has_issuer_table`, a handshake test that every dev anchor has its table, a property test of the parser |
| A261-W1 | ~~**TCP sent a new FIN on every acknowledgement in FIN-WAIT-2** (since M14, every release up to v0.4.0): once our FIN was acknowledged the acknowledged data was gone and `transmit` saw a FIN not yet sent, so a peer that keeps its side open and acknowledges each segment made the broker exchange segments with it at line rate; the retransmission timer armed for each FIN replaced the FIN-WAIT-2 timer, so the connection was never released while the peer held it. Found by the `storm` smoke hang (QEMU's user-mode network acknowledges each FIN; core 0 at 100 %, frame buffers growing, the heap below its reserve)~~ | medium (availability: a peer the broker closes with a FIN (seen with keep-alive timeouts, which need a connected, authenticated session; a handshake timeout is a reset and is not affected; the other close paths were not audited one by one) can hold the connection slot as long as it likes and make the broker answer each of its ACKs, a 1:1 exchange without amplification; per-address and per-core limits still bound how many; no data exposure) | `tcp/src/lib.rs` `transmit` | **fixed in ADR-261:** the FIN is sent once and retransmitted only while unacknowledged; scripted tests for the half-open peer, smoke `fin_wait2` |
| A259-W2 | ~~**The trust-anchor tables cost more heap than counted**: each 148 KiB table was one vector, which the buddy heap rounds to a 256 KiB block (778 KiB for the 3 dev anchors), built by whichever core's server came first after the boot had logged the heap in use, and absent from the heap sizing rule; with a small heap (the `storm` smoke's 8 MiB pretence) admission refused noticeably earlier than in v0.4.0~~ | low (only small heaps notice; no correctness effect) | `nistz256` `KeyTable`, `kernel/src/mqtt_service.rs` | **fixed in ADR-261:** one 4 KiB allocation per row (445 KiB for 3 anchors), built once at boot and logged before the heap reserve line, 150 KiB per anchor in DEPLOY.md and README; test that the tables are shared and bounded |
| A256-W1 | ~~A virtio-gpu display info **4 bytes short** of the structure (the last scanout's unread `flags`) was accepted~~ | low (the hypervisor is trusted; nothing past the buffer was read) | `virtio/src/gpu.rs` | **fixed in ADR-256** before merge: found by the new `virtio_gpu_response` fuzz target in its first minute; the whole 408 bytes are required, with a regression test |
| A256-W2 | **`console.virtio_gpu = "auto"` cannot tell a live RAM framebuffer (QEMU `ramfb`) from the dead GOP shadow of edk2's virtio-gpu driver**: with both devices it takes the virtio-gpu, and the `ramfb` picture freezes | low (a display, opt-in, logged with its reason) | `kernel/src/devices.rs`, `auto_choice` | accepted, documented (ADR-256); `"on"`/`"off"` decide explicitly |
| A271-W1 | **Exactly once does not survive a crash of the broker while the client is connected.** As for QoS 1, a session's in-flight state is written to the store only when it goes offline (ADR-030); after a crash or power cut the session is back as it was at its last disconnect. A QoS 2 PUBLISH whose PUBREC the client never saw is routed a second time when the client sends it again, and a client that still holds an id the broker released may take the broker's next PUBLISH with that id for a duplicate | low (integrity of delivery, not of access: needs a crash of the VM at the wrong moment; the client is authenticated) | `broker/src/lib.rs` `closed` (the snapshot), ADR-271 | open: writing each flow through the DB core before answering would make every QoS 2 publish wait for a commit; documented in KNOWN-ISSUES section 5 |

Untested protections (from §3) count as gaps as well: FP-state save, 0-RTT,
the page-table lock and the SQLite flags (the last is tested since H10). The kernel hash in
`limine.conf`, the secrecy of the logs and prod ignoring the command line are tested
(`integrity-*`, `secrecy`, `production_ignores_every_option`).

---

## 6. Known limits and accepted risks

The owner-facing list, with the reasons and what to do about each, is the
**Residual risks** table of [SECURITY.md](SECURITY.md); it is part of this
package. The ones an auditor should weigh first:

| Limit | Why it stands | Where recorded |
|---|---|---|
| **The image holds the server private key and, with encryption at rest, the disk key.** A copy of the ISO is a copy of both. | No secure key store in a VM. TPM or vTPM sealing was studied (ADR-254) and not built: it needs a TPM driver and a new configuration format, protects a copied disk but not the install ISO, and a vTPM's state travels with the VM. A production image built outside CI warns (ADR-252). | SECURITY.md residual risks; ADR-240, ADR-252, ADR-254 |
| **No Secure Boot for release images, no measured boot, BIOS path unprotected.** The configuration is enrolled into the loaders and the kernel and module are pinned (H8, ADR-250), but nothing signs the loaders: whoever can rewrite `BOOTX64.EFI`, `limine-bios.sys` or the MBR defeats both. The signing path exists (ADR-251) and has no project key; a signed ISO cannot be configured afterwards and an installed disk does not boot under Secure Boot. | The release targets a VPS, whose firmware and loader are the host's. | PLAN.md (first release scope); §3b; ADR-250, ADR-251 |
| **No IOMMU (H4b), and no fuzzing of PCI and virtio parsing (H0-W9).** | VM devices are the hypervisor's, which is trusted; both matter on bare metal. | SECURITY.md; H0-W9 |
| **SQLite is 254k lines of C.** Contained (EL0 / ring 3, restart on fault), not eliminated: the kernel trusts the worker's *answers* (an empty revocation list from a compromised worker un-revokes certificates), there is no KPTI and no PCID, and PAC keys are shared on aarch64. | ADR-210; the remaining cost of isolation. | PROGRESS.md H6, "Not done / honest limits" |
| **No forward-edge CFI (kCFI crashes the pinned compiler), no MTE on x86_64, on HVF or on most clouds; the HHDM base is fixed.** | ADR-174, ADR-175. | SECURITY.md residual risks |
| **Constant-time evidence covers the tag checks, our one secret comparison, since ADR-255 P-256 key generation, ECDH and signing (key and nonce), and since ADR-259 the X25519 ladder of the shared secret (Docker on the M4 Pro only)** (`make ct`, dudect-style, measured in Docker on an Apple M4 Pro and on the GitHub arm64 runner, a Neoverse N2 VM; not on the Neoverse N1 VPS, and never with PSTATE.DIT set on a server core, A255-W2); the X25519 key share (dalek's table) and Ed25519 are not measured here. | A black-box test bounds only what it can resolve at its sample size, on the machine it ran on; the code is designed for constant time (upstream's argument for the assembly; ADR-259's for the X25519 field arithmetic). | CRYPTO.md, ADR-255, ADR-259 |
| **Third-party code dominates the trusted base** (rustls, webpki, RustCrypto, dalek). 53 of 67 kernel-linked crate versions are cargo-vet *exemptions*, not audits. | An audit of that code is a project of its own; the RustCrypto and rustls families are inputs to §8. | SUPPLY-CHAIN.md; audit/vet-exemptions.md |
| **Rollback of the data volume** restores old revocations and an old sequence number (H1-W2). XTS gives no integrity: sectors can be swapped or rolled back between snapshots. | The disk is trusted not to be maliciously rolled back; image-listed revocations are re-applied at every boot. | SECURITY.md; ADR-240 |
| **TLS handshake messages are parsed by rustls** (third party); we fuzz our own record layer, identity extraction and ticket code, and run tlsfuzzer against the whole. | Upstream fuzzes rustls. | §2 |
| **Plaintext MQTT, when the owner turns it on, is plaintext**, and `auth = "ip"` trusts a source address. | That is what the option means; it is off by default, narrow by default and says so at every step. | SECURITY.md (P1 sections) |
| **Not measured on real hardware:** x86_64 on bare metal, x86_64 on KVM for anything added after the H7 commit (X11 ran the production image on a real KVM VPS, Contabo AMD EPYC, at that commit: boot, mutual TLS under load, a comparison with Mosquitto), 100k and 1M connections, MTE on silicon. | No physical x86 machine was available; the VPS run predates the later changes. | PERFORMANCE.md, PROGRESS.md |

### 6b. Network-reachable loops and allocations, and their bounds (H3 deliverable)

Every place where an unauthenticated or authenticated peer can make the
broker spend memory or time, the bound that stops it, and the test at the
bound. "Smoke" means a scenario in `scripts/smoke.sh`.

| What a peer can drive | Bound (config key and default) | Test at the bound |
|---|---|---|
| Open TCP connections | `limits.max_connections_per_core` (2 000 000, in practice the heap); SYN cookies hold no state before the handshake completes | `syn_flood_holds_no_state_and_forged_acks_are_refused`; smoke `syn-flood` (20 000 SYNs, 0 connections) |
| Half-open and idle TLS handshakes | `limits.max_handshakes_in_flight_per_core` (256), `..._per_ip` (32), `limits.handshakes_per_core_per_sec` (2000), `memory.min_free_mb` (8); handshake timeout 10 s | `admission_limits`; smoke `storm` (3 × 3000 devices against an 8 MiB heap), slowloris in `tools/attack` |
| Established TLS connections from one source address | `limits.max_connections_per_ip` (1024; 0 off), table of 32 768 addresses (768 KiB), the bound of one address held exactly, a full bucket lets a new address through uncounted and counted | `source_limit` tests (`thousands_from_one_address`, the model), fuzz `source_limit`, `established-flood` in `tools/attack`, smoke `conn-limit` |
| RST and challenge-ACK responses | `rst_per_sec` (200) and the RFC 5961 cap | `tcp` host tests; the ACK flood in `tools/attack` (`RST 600 sent (9402 rate-limited)` per core) |
| An MQTT packet | `limits.max_packet_size` (4096; plaintext: `plaintext.max_packet_size`, 1024) | `mqtt_limits`; `mqtt_decode` fuzzing; an oversize packet closes the connection |
| A topic name or filter | `limits.max_topic_len` (256), `limits.max_topic_levels` (16) | `mqtt_limits`; `broker_input` fuzzing |
| MQTT 5.0 property lists | `mqtt5.max_user_properties` (16) per block (more: refused, 0x83); one Subscription Identifier per packet from a client (a PUBLISH with one: 0x82); every other property at most once; the block within the packet size | `v5::tests::list_bounds`, `duplicate_property_rules`; `mqtt5_props` fuzzing; `v5_tests::server_disconnects_carry_their_reason` |
| MQTT 5.0 per-connection state | one `V5State` box (24 B) and the alias table once used: `mqtt5.topic_alias_maximum` × (16 B + a topic of at most `limits.max_topic_len`), 2 720 B with the defaults; counted since ADR-275 (`$SYS/broker/memory/topic_aliases`) | `v5_tests::the_5_0_state_is_one_small_box_and_aliases_cost_nothing_until_used`, `topic_aliases_from_the_client_are_resolved_and_bounded`, `shared_tests::topic_alias_tables_are_counted` |
| Offline sessions and armed Wills | each until its Session Expiry Interval (at most `limits.max_session_expiry_s`, 30 days) or Will Delay; ended at most 64 per 100 ms tick; expired while the broker was down: dropped at boot | `v5_tests::session_expiry_*`, `restore_drops_sessions_that_expired_while_the_broker_was_down`; `qos2_model` with time and restarts |
| Subscriptions of one session | `limits.max_subscriptions_per_session` (8) | `subscription_limit_and_unsubscribe` |
| Shared-subscription groups and members (ADR-275) | `limits.max_shared_groups` (1024 per owner shard: about 120 B and the name and filter twice each), `limits.max_shared_group_members` (1024 per group, 12 B each); a shared subscription also counts in `limits.max_subscriptions_per_session`; one more: SUBACK 0x97 / 0x80 | `shared_tests::across_shards_a_limit_refuses_the_join_in_the_suback`, `takeover_will_limits_and_a_3_1_1_member` |
| A shared message whose member is gone, a SUBACK waiting for the owner shard | handed on at most `MAX_TRIES` = 4 times, then dropped (counted); a QoS 0 delivery to a core more than 16 384 messages behind dropped like a QoS 0 route (`messages/dropped/cross_core`); the SUBACK and the connection's input held at most 2 s, then 0x80 | `shared_tests::across_shards_a_member_that_is_gone_hands_the_message_on`, `across_shards_the_owner_decides_and_the_members_shards_deliver` |
| Retained messages with a Message Expiry Interval | one deadline per topic; at most 64 cleared per 100 ms tick (ADR-275) | `shared_tests::expired_retained_messages_are_swept_even_if_nobody_reads_them` |
| QoS 1 and QoS 2 in flight, queued for an offline session | `limits.max_inflight_qos1` (16, both QoS; a QoS 2 delivery until its PUBCOMP), `limits.max_queued_per_offline_session` (64) | `inflight_window_and_queue_bounds`, `the_window_counts_qos2_flights_until_pubcomp` |
| QoS 2 packet ids a client holds awaiting PUBREL (2 bytes each) | `max(limits.max_inflight_qos1, 64)` per session; one more closes the connection (ADR-271) | `too_many_ids_awaiting_pubrel_close_the_connection`, `restore_bounds_what_the_store_hands_back` |
| Retained messages | `limits.max_retained_per_device` (32), `limits.max_retained_bytes` (1 MiB per core, at most an eighth of the heap) | `retained_per_device_limit_at_the_bound`, `retained_byte_budget_at_the_bound`; smoke `retained-limit` |
| Publish rate | `limits.publish_rate_per_device` (10/s) | `rate_limit_drops_excess`, `the_limiter_allows_a_burst_then_the_rate` |
| Bytes held for a slow reader | per connection and per core | `held_bytes_are_bounded_per_connection_and_per_core` |
| Input held unparsed while a publisher is paused for its only subscriber (ADR-269) | the TCP window it was promised (closed on pause, at most 1 MiB), 2 MiB plus a packet per connection without a window, 16 MiB per core before no new pause; a pause lasts 500 ms at most, then 2 s of cool-down; a subscriber whose publisher on another shard was asked to pause takes at most 256 KiB beyond its output buffer, 4 MiB per core in all; `limits.publisher_backpressure` (`single`) | `held_input_is_bounded_without_a_window`, `the_overshoot_of_a_waited_subscriber_is_bounded`, `across_shards_two_publishers_for_each_other_never_both_pause`, `the_pause_is_bounded_and_counts_as_alive`, `two_publishers_for_each_other_never_both_pause`, `a_cycle_of_three_cannot_close`; `broker_input` fuzzing |
| Client identifier length | fixed | `client_id_limit` |
| Plaintext connections, per address, failed logins, password length, PBKDF2 iterations | `plaintext.max_connections` (1000), `..._per_ip` (16), `max_failed_auths_per_ip` (5), password 256 bytes, iterations at most 200 000 | `the_plaintext_limits_are_its_own`, `a_very_long_password_is_refused_without_a_long_computation`, `plain_input` fuzzing, `plain-scenarios.py` |
| WebSocket upgrade size, header lines, deadline, message length, connections, failed logins | 4 KiB and 32 lines (fixed), `websocket.upgrade_timeout_s` (5, at most 10), packet limit + 4 KiB per message, `websocket.max_connections` (1000), `..._per_ip` (16), `max_failed_auths_per_ip` (5), `max_packet_size` (16 384, password mode) | `size_and_header_count_are_bounded`, `the_message_limit_is_checked_at_the_header`, `ws_upgrade`, `ws_frames`, `wss-slowloris-upgrade-cut-at-the-deadline`, `wss-password-lockout` |
| Handler run time | `watchdog.handler_budget_ms` (20), `watchdog.handshake_budget_ms` (calibrated at boot), `watchdog.action` | smoke `watchdog`, `watchdog-handshake`, `watchdog-stall`, `watchdog-lockwait` |
| Log volume | per-CPU rate-limited rings | `crates/log` host tests; `scripts/log-flood-check.py` |
| Telemetry written to disk | `storage.telemetry_topics`, ring size, `storage.retention_days`; the ring overwrites its oldest segment | `log-crash`, `log-tear`, the storage group |
| Database work | fixed prepared statements; the worker's 30 s overrun restarts it | `worker-fault` |
| Control messages | signature, sequence number and validity window checked before any work; only listed service identities may publish to the reserved namespace | `control-forged`, `control-replay`, `control-expired`, `control-from-device` |

A loop or allocation not in this table that a peer can drive is a finding.

---

## 7. Build, run and test

An auditor needs a Mac (Apple silicon) or a Linux machine, QEMU, and about
20 GB of disk. Everything below is in the repository; nothing needs a network
except `cargo fetch` and the tools' own downloads.

**Prerequisites** (README "Prerequisites"): a Rust toolchain through `rustup`
(the pinned nightly, `nightly-2026-10-20`, installs itself from
`rust-toolchain.toml`; the PAC/BTI flags and `-Zbuild-std` need nightly),
QEMU (`qemu-system-aarch64`, `qemu-system-x86_64`), `xorriso`, `clang` and
`llvm` (SQLite's C), `openssl` 3, `mosquitto` clients. macOS:
`brew install qemu xorriso llvm mosquitto openssl@3`. Linux:
`sudo apt install qemu-system-arm qemu-system-x86 qemu-efi-aarch64 ovmf xorriso clang llvm mosquitto-clients openssl`.
Optional: `cargo install cargo-fuzz --locked`, `cargo-vet`, `cargo-deny`,
`kani-verifier`, `node` (the builder page's tests).

| To | Run |
|---|---|
| Make development certificates | `make certs` |
| Build the development kernel (aarch64, with the in-kernel selftests) | `make build ENV=dev` |
| Build the x86_64 kernel | `make build ENV=dev ARCH=x86_64` |
| Build a bootable ISO of the development configuration | `make iso ENV=dev` |
| Build the one universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) | `make universal ENV=dev` |
| Boot it and look | `make run` (HVF on macOS), `make run-tcg` elsewhere; serial on stdio |
| **Everything the project checks in one go** | `make check` (fmt, typos, clippy `-D warnings` for the host and both kernels, `cargo test --workspace`, the release-mirror and builder tests) |
| The boot and behaviour scenarios | `make smoke` (aarch64: HVF and TCG on a Mac; `scripts/smoke.sh --arch x86_64`; `--arch universal` for the ISO on four machines) |
| One group of scenarios | `SMOKE_ONLY=hardening` (the H4 scenarios), `storage`, `time`, `live`, `config`, `diag`, `install`, `template`, `migrated`, with `SMOKE_SCENARIOS=<regex>` to pick by name |
| TLS conformance and interoperability | `make conformance`, `make interop` |
| Constant-time tests | `make ct` |
| Fuzz a target (60 s in CI) | `make fuzz T=<target> FUZZ_TIME=600`; `cargo fuzz list` (29 targets) |
| Stateful ACL fuzzer | `make acl-fuzz ACL_FUZZ_SECS=600`; the coverage-guided one: `make fuzz T=broker_acl FUZZ_TIME=600` |
| Miri, Kani, sanitizers, coverage | `make miri`, `make kani`, `make sanitize`, `make coverage` (VERIFICATION.md says what each leaves out) |
| Reproducible build check | `make repro` (builds HEAD twice in separate worktrees and compares the ELF and the ISO) |
| Release artifacts, signature | `make dist`, `make sign` (minisign) |
| Regenerate the inventory | `make audit` (CI runs `--check`) |
| SBOM, vet, advisories | `make sbom`, `make supply-chain` |
| Attack a running VM | `tools/attack` (SYN, ACK and RST floods, slowloris, oversize packets; the smoke scenarios drive it) |
| The offline disk and configuration tools | `cargo build -p urmqtt-disk-tool -p urmqtt-config-tool -p urmqtt-control-tool` |

A production image is built with `make iso ENV=prod`; it ignores the kernel
command line and refuses development options (`network.mqtt_plain_port`,
durability shortcuts, test words). The configuration that goes into an image,
its limits and the builder page are in [DEPLOY.md](DEPLOY.md) and
[PROVISIONING.md](PROVISIONING.md).

---

## 8. Proposed scope of the external audit

Ordered by how much a defect would cost. File names are the entry points.

| # | Area | Entry points | Why, and what we would like answered |
|---|---|---|---|
| 1 | **TLS 1.3 record layer and key schedule** | `crates/tls/src/record.rs`, `server.rs` (the hand-over from rustls: secret capture, KeyUpdate, ticket handling), `ticket.rs`, `provider/` (fast P-256 tables, `nistz256`, `x25519`) | We replaced rustls's record layer and parts of its crypto provider for speed and memory. Nonce and sequence handling, KeyUpdate limits, alert behaviour, the per-record key derivation, the hand-written assembly and fixed-base tables, constant-time claims |
| 2 | **TCP/IP stack** | `crates/tcp`, `crates/net` | Own implementation: SYN cookies, RFC 5961 checks, the state machine under loss and reordering, fragment and option handling |
| 3 | **MQTT codec, ACL, sessions and the control channel** | `crates/mqtt`, `crates/broker`, `crates/control`, `crates/plain` | Parsing without panics or out-of-bounds, ACL correctness (device-scoped `{id}` rights, the reserved namespace), the signed-message checks, replay and window logic, plaintext login and lock-out |
| 4 | **Admission, limits and the watchdog** | `crates/kernel/src/mqtt_service.rs` (`admit`), `watchdog.rs`, §6b | Whether any network-reachable work is unbounded |
| 5 | **`unsafe` in the kernel's own crates** | `crates/mm`, `crates/arch-aarch64`, `crates/arch-x86_64`, `crates/virtio`, `crates/pci`, `crates/sync`, `crates/kernel` ([audit/unsafe.md](audit/unsafe.md)) | Every site has a written justification; are they right. Page-table code, the W^X and lock claims, the allocator hardening (ADR-170), user mode and the system-call boundary (H6) |
| 6 | **SQLite FFI, VFS and the worker protocol** | `crates/store/src/{ffi,csqlite,vfs,libc,worker,remote}.rs`, `crates/dbworker`, `crates/usys`, `crates/kernel/src/dbsandbox.rs` | The 12 system calls and their argument checks, the libc surface SQLite sees, containment of a compromised worker, what the kernel still trusts in its answers |
| 7 | **Data-disk code and encryption at rest** | `crates/store/src/{layout,disk,crypt,backup,scrub,telemetry}.rs`, `tools/disk` | The format parsers, crash safety of each multi-step update, the XTS mode written here (it is about 60 lines over the `aes` crate), key handling, the conversion procedure |
| 8 | **Boot chain, image and configuration** | `scripts/mkiso.sh`, `scripts/mkraw.py`, `crates/cfg`, `crates/config`, `crates/config-schema`, `tools/config`, the installer entry | What is pinned by hash and what is not, the configuration blob's validation at every boot, the installer's refusal rules, what a modified ISO can do |
| 9 | **The builder page** (browser WebAssembly packing the same configuration) | `tools/builder` | Not in the image; it handles private keys in the user's browser. Network behaviour (none but the release files), the module's handling of keys |
| 10 | **Third-party code on the data path** | rustls, rustls-webpki, RustCrypto (`aes-gcm`, `chacha20poly1305`, `sha2`, `hmac`, `aes`), `p256`, `ed25519-dalek`, `x25519-dalek` | The inputs of §1; the exemption list in [audit/vet-exemptions.md](audit/vet-exemptions.md) says what nobody has audited yet |

**Out of scope:** the hypervisor and the cloud provider; the build host (a supply-chain
topic: SUPPLY-CHAIN.md); bare-metal drivers and Secure Boot (not built).

**What we hand over:** this package, the repository at a tagged commit, the
signed release artifacts and their SHA256SUMS, the SBOM, the reproducible-build
check, and the ability to rebuild and re-run everything in §7 without help.

---

## 9. Internal red-team checklist and results

What we tried against the system ourselves, what happened, and what was
fixed. "Result" is what the cited test or tool reported when it last ran;
the date of the run is in PROGRESS.md for the milestone named.

| # | Attack | Done with | Result |
|---|---|---|---|
| 1 | SYN flood | `tools/attack`, 20 000 segments | ~20 000 cookies issued, **0 connections**, heap flat (H3) |
| 2 | ACK flood, forged ACKs | `tools/attack` at 8 000 ACK/s | the RFC 5961 cap holds (`RST 600 sent (9402 rate-limited)` per core), 0 connections (H3) |
| 3 | RST injection | `tools/attack` | dropped, no RST back, no state (H3) |
| 4 | Slowloris over TCP, TLS and MQTT | `tools/attack` | trips the per-address in-flight cap, connections ceiling at the cap and back to 0 after the drop (H3) |
| 5 | Oversize and over-long packets, over-long SUBSCRIBE | `tools/attack` | protocol-error close; the retained store caps at 32 per identity (H3) |
| 6 | Retained-message flood to exhaust memory | paced topic flood | **found: unbounded (H0-W1). Fixed in H3**, tests at the bound |
| 7 | Forge a session ticket from a copy of the image | review, `ticket_from_another_boot_means_full_handshake` | **found: the ticket key was derived from the server key (H0-W4). Fixed in H2**: random per-boot keys, rotated |
| 8 | Wall clock in the past to accept an expired certificate | `time-before-build` | **found (H0-W5). Fixed in H1**: the build time is a lower bound; SNTP is bounded (H7) |
| 9 | Expired, wrong-CA, revoked and mismatched-identity device certificates | `mqtt-tls` scenarios | all rejected |
| 10 | Early data (0-RTT) | `zero_rtt_is_never_offered`, tlsfuzzer | never offered; the configuration refuses it |
| 11 | Malformed and truncated TLS records, KeyUpdate abuse | `tls_record`, `diff_tls_record`, 23 tlsfuzzer probes | no panic, same verdict as rustls and ring, fatal alerts reach the peer |
| 12 | Device reads or writes another device's topics, the control namespace, `$SYS` | the stateful ACL fuzzers (`make acl-fuzz`, `broker_acl`), `acl-subscribe-denied` | no violation found at the H5 acceptance run, nor by `broker_acl` (10 min on 2026-10-30, 60 s on v0.4.2); re-run for the audit |
| 13 | Forged, replayed, expired or device-sent control messages | `control-forged`, `control-replay`, `control-expired`, `control-from-device` | all ignored; the legitimate ones apply |
| 14 | Heap double free, use after free, overflow | `double-free`, `heap-uaf`, `heap-overflow` (and `-prod`) | each stops the machine with a message that names the fault and nothing else |
| 15 | Stack smashing, stack overflow into the guard | `stack-smash`, `stack-overflow` | canary or guard page catches it |
| 16 | Write to text, execute from the heap, null dereference, forged return address, bad branch target | `wx-write-text`, `wx-exec-heap`, `null-deref`, `pac-forgery`, `bti-violation` (and the x86_64 equivalents) | each faults with a decoded report |
| 17 | A compromised SQLite worker: read, write and jump into the kernel, privileged instruction, write to its own code, jump into data, null, endless loop | `worker-contain` | all contained, the kernel word intact; an endless loop is cut at 30 s and the worker restarts (`worker-fault`) |
| 18 | A secret in a log line, a fault report or a panic message | `fault-secrets`, `panic-secret`, each with an `-open` control | nothing planted appears with redaction on; the controls show it would otherwise |
| 19 | A corrupted database | `db-corrupt` (storage group) | detected at boot, restored from the in-disk backup, the loss reported |
| 20 | Power cut, torn write or dropped flush at every write of grow, migrate, backup and the encryption conversions | the fault loops (`tools/disk/tests`, `crates/store/tests`) | always a valid disk with all its data after the documented resume |
| 21 | Open an encrypted disk with a wrong key, with none, or a plain disk with a key; damage random sectors of an encrypted disk | `storage-encrypted`, `disk_crypt` fuzzing | refused with a reason; never opened; no panic |
| 22 | A modified configuration module | `config-tampered-refused` | the loader refuses; the kernel never defaults |
| 23 | An empty or unsigned configuration | `config-empty-refuses-to-serve` | boots, says why, serves nothing |
| 24 | Plaintext login guessing, source-address forging, lock-out abuse | `plain-scenarios.py`, `plain_input` fuzzing | lock-out by address works; the limits hold; `auth = "ip"` is documented as forgeable on a shared segment |
| 25 | A hostile `unsafe` claim: a site with no written justification | `scripts/audit-inventory.py` | see §1: every site now carries one, and CI fails if a new one does not |
| 26 | A vulnerable or unreviewed dependency | `cargo deny`, the scheduled advisory job, cargo-vet | clean at H9; 53 of 67 versions are exemptions (§6) |
| 27 | **A hostile virtio or PCI device** | none | **not tested** (H0-W9); the hypervisor is trusted in a VM |
| 28 | A modified kernel image, configuration module or `limine.conf` (**a downgrade and a replaced loader are not tested**) | `integrity-kernel-*`, `integrity-module-iso-*`, `integrity-conf-*` | refused by the loader on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS (H8, ADR-250). **A loader replaced by the attacker is not refused without Secure Boot**; under Secure Boot (x86_64 OVMF only, ADR-251) an unsigned or other-signed loader is refused; **a downgrade to an older correctly pinned image is not detected** (H8-W6) |
| 32 | An unsigned, foreign-signed or post-signing-modified loader under Secure Boot | `secureboot-*` (`SMOKE_ONLY=secureboot`) | `Access Denied` on x86_64 OVMF; **aarch64, Proxmox and a physical PC not tested** (H8-W4) |
| 33 | Key bytes in a log, panic or the repro output | `secrecy`, the scan in `make repro` | none found; the scan sees the keys in the image (the control) |
| 34 | The installer started by an added word, or with a replaced installation image | `install-rules-*` | refused; the target disk unchanged |
| 35 | Malformed, short, mistyped or wrongly fenced virtio-gpu responses (a hostile hypervisor's display device) | `virtio_gpu_response` (52 million runs on the Mac at ADR-256), parser host tests | **found: a display info 4 bytes short was accepted (A256-W1), fixed**; nothing else; the rest of virtio (rings, blk, net, scsi) is still item 27 |
| 36 | A hostile virtio-console, -balloon, -input or -vsock device (completions for heads never posted, lengths past the buffer, indices far ahead, floods, a host that never reads, any vsock packet sequence) | host tests against the fake device; `virtio_console_device`, `virtio_balloon_device`, `virtio_input_event`, `virtio_vsock_packet` (one minute each on the Mac at ADR-258) | nothing found in the drivers (the first runs found three bugs of the fuzz harness and the fake device, fixed); vsock never ran against a real device |
| 37 | A hostile WebSocket client: malformed, oversized, duplicated-header, wrong-version, wrong-origin or slow upgrades; unmasked, reserved-bit, text, oversized, interleaved and fragmented-control frames; ping floods; cross-site pages | `ws_upgrade`, `ws_frames` (180 s each at ADR-272), Autobahn\|Testsuite fuzzingclient (517 cases), `ws-scenarios.py` against the kernel | `ws_upgrade` found that the 101 answer for `mqttv3.1` (163 bytes) did not fit its 160-byte buffer (fixed, a test added); Autobahn 0 failed, 0 non-strict; the scenarios pass on both architectures |
| 29 | **A write to a page table after the lock** | none | **not tested** (H0-W10) |
| 30 | **Timing of P-256, X25519, Ed25519** | `make ct`: `p256_*_is_constant_time` (ADR-255), `x25519_ladder_is_constant_time` (ADR-259) | P-256 key generation, ECDH, signing key and nonce: no class dependence found (\|t\| below the bound of 7, control far above it; Docker on an M4 Pro and the Neoverse N2 CI runner, CRYPTO.md; the earlier signing signal was the harness, A255-W1); the X25519 ladder (shared secret): \|t\| 1.0 to 4.7 in six runs, Docker on the M4 Pro only; **the X25519 key share and Ed25519 not measured** (§6) |
| 31 | **A crafted SQLite database file under ASan** | none | **not fuzzed** (H0-W8, contained by H6) |

Items 27 and 29 to 31 are the open findings of this review (28 is closed for modified
files and open for a replaced loader and for downgrade, H8-W6); they are repeated in §5
and, for the first four, are part of the scope in §8.

