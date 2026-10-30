# Security audit baseline

Status: **H0 baseline** (PROMPT-security.md, docs/SECURITY-PLAN.md), 2026-10-29.
This file grows into the audit package of H10. It records:

- what the trusted computing base is;
- which inputs reach which parser;
- which protection is proven by which test;
- every weakness found.

Weaknesses are listed even when they are not fixed yet. Where a protection has
no test, that is listed as a gap too: an untested protection does not count.

Regenerate the inventory with `make audit` (`scripts/audit-inventory.py`). CI fails if it is
out of date (`--check`).

---

## 1. Trusted computing base

The full tables are generated: [audit/inventory.md](audit/inventory.md)
(crates, vendored code, dependencies) and [audit/unsafe.md](audit/unsafe.md)
(every `unsafe` site). The summary below is taken from them at the H2 commit (H0: 30 773 lines,
65 linked crates, 308 `unsafe` sites with 278 justified; X0: 31 905 lines;
H1: 34 538 lines, 316/289; S1: 36 573 lines, 318/290; S1b: 37 240 lines, 319/290; X0b: 37 789 lines, 326/297).

| Part | Size | Notes |
|---|---|---|
| Own Rust (23 workspace crates, `src/` incl. inline tests) | 38 488 lines | `tools/loadgen`, `tools/control` and `tools/disk` are host tools, not in the image |
| Third-party Rust linked into the kernel | 69 crates from crates.io, 297 675 lines, plus the two vendored `cpufeatures` below | RustCrypto, rustls, webpki, p256, x25519-dalek, ed25519-dalek (H1), … ([list](audit/inventory.md)). `ed25519-dalek` 2.2 brings `sha2` 0.10, `digest` 0.10 and `signature` 2 alongside the 0.11/3 versions (about 4 500 duplicate lines, H9) |
| Third-party Rust at build time only | proc-macros and build scripts (syn, toml, cc, …) | they run on the build host, so they are a supply-chain risk (H9), not runtime TCB |
| SQLite 3.54.1 (C), linked | 254 268 lines | the largest component; runs at EL1 with full kernel rights (H6) |
| Own C headers for SQLite | 53 lines in 7 headers | the libc surface SQLite sees (functions implemented in Rust, `store/src/libc.rs`) |
| RustCrypto `cpufeatures` 0.2.17 and 0.3.1, vendored (X0b) | 642 + 565 lines | upstream sources plus one hunk each: on bare metal they ask the kernel's sealed dispatch (`urmqtt_cpu_has`). Reviewable with `diff -r` against the crates.io files ([vendor/README.md](../vendor/README.md)) |
| Limine v12.9.4 (binary) | `BOOTAA64.EFI`, 331 776 bytes | pre-kernel; integrity is H8 |

**`unsafe` in non-test code:** 326 sites; 297 have a `// SAFETY:` comment or a `# Safety` section.

| Crate | Sites (justified) | Crate lint |
|---|---|---|
| `urmqtt-store` | 119 (107) | deny, with `allow` on the FFI modules (since H0, was none) |
| `urmqtt-arch-aarch64` | 73 (73) | deny; all assembly and system registers since X0; the ARMv8 CRC-32C intrinsics (X0b) |
| `urmqtt-kernel` | 59 (42) | deny; `cpu_dispatch.rs` (X0b): the sealed section, the `urmqtt_cpu_has` export |
| `urmqtt-mm` | 35 (35) | deny |
| `urmqtt-virtio` | 19 (19) | deny |
| `urmqtt-sync` | 16 (16) | deny; spinlock, once-cell, SPSC ring (moved out of the arch crate in X0) |
| `urmqtt-log` | 5 (5) | deny |

The protocol crates (`mqtt`, `broker`, `tls`, `timer-wheel`, `config`,
`config-schema`, `dispatch`) are `forbid(unsafe_code)`. `tcp`, `net`, `pci`,
`platform` and the `arch` facade are `deny` and contain none. The 29
unjustified sites:

| Where | Sites |
|---|---|
| `kernel/src/boot.rs`: `#[unsafe(link_section)]` on Limine requests | 16 |
| `store/src/vfs.rs`: SQLite VFS callbacks | 9 |
| `store/src/libc.rs` | 2 |
| `unsafe extern` blocks in `kernel/src/vm.rs`, `store/src/ffi.rs` | 2 |

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
| TCP segments and the state machine | network | `tcp/src/wire.rs`, `tcp/src/lib.rs` | `max_conns`, `tx_max`, window, SYN cookies, `rst_per_sec` | `tcp_segment` (wire + stack) |
| TLS records (application, KeyUpdate, alerts) | network | `tls/src/record.rs` (own) | 2^14+256 ciphertext, 2^14+1 inner plaintext | `tls_record`; `diff_tls_record` against rustls + ring (H2); 23 tlsfuzzer probes |
| Session tickets (on resumption) | network | `tls/src/ticket.rs` (own) | AEAD under per-boot keys; length checked first | host tests (every bit flipped) |
| TLS handshake messages | network | rustls 0.23.46 (third party) | handshake timeout 10 s; in-flight limits | none of our own (upstream fuzzes rustls) |
| Client X.509 certificates | network (signed by the CA) | rustls-webpki (third party), `tls/src/identity.rs` (own: CN/SAN URI) | certificate size from rustls | `x509_identity` |
| MQTT 3.1.1 packets | network (authenticated devices) | `mqtt/src/decode.rs`, `validate.rs` | `max_packet_size` 4096, topic length 256 and levels 16 | `mqtt_decode` |
| MQTT sequences (sessions, ACL, retained, LWT) | authenticated devices | `broker/src/lib.rs` | limits section of config; **retained count unbounded** (H0-W1) | `broker_input` |
| Superblock, region table, size table | volume | `store/src/layout.rs` | fixed 4 KiB blocks, region count ≤ 16 | `disk_layout` |
| Telemetry segments and records | volume | `store/src/telemetry.rs` | segment header checks, CRC salted by sequence | `telemetry_recover` |
| SQLite database, WAL, journal | volume | SQLite (C) | `quick_check` at boot, `DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`, no extensions | **none** (gap H0-W8) |
| Device tree | firmware | `platform/src/fdt.rs` | blob size, node depth | `fdt_parse` |
| ACPI tables | firmware | `platform/src/acpi.rs` | table lengths, MADT entry lengths | `acpi_parse` |
| PCI configuration space, capabilities | firmware/devices | `pci/src/lib.rs` | capability list walk | **none** (gap H0-W9) |
| virtio rings, config space, SCSI sense/INQUIRY | hypervisor/devices | `virtio/src/{queue,blk,net,scsi,transport}.rs` | ring sizes, descriptor ids | **none** (gap H0-W9) |
| Limine responses (memory map, MP, date) | bootloader | `kernel/src/boot.rs` via the `limine` crate | — | none (trusted) |
| Build configuration (`deploy/<env>/config.toml`, PEMs) | operator, at build time | `config-schema` | validated at build | `config_parse` |
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
| Handshake admission (rate, in flight per core and per IP, heap reserve, DB backlog) | `kernel/src/mqtt_service.rs` (`admit`) | `storm` (3 × 3000 devices against an 8 MiB heap) | all |
| MQTT limits (packet, topic, subscriptions, inflight, queue, publish rate) | `mqtt/src/validate.rs`, `broker/src/lib.rs` | broker host tests; `broker_input` fuzzing | all |
| ACL (device and service rights, device-scoped subscriptions) | `broker/src/lib.rs` | `mqtt-plain`/`mqtt-tls`: `acl-subscribe-denied`; broker host tests | all |
| SYN cookies (SipHash, random key at boot) | `tcp/src/cookie.rs`, `netproto.rs:50-62` | tcp host tests | all |
| RFC 5961 checks (challenge ACK, RST/SYN in window) | `tcp/src/lib.rs` | tcp host tests (`tests.rs`) | all |
| RST rate limit | `tcp` `rst_per_sec = 200` | tcp host tests | all |
| Handler watchdog, stuck-core reset | `kernel/src/watchdog.rs` | `watchdog` | all |
| Rate-limited logs | `crates/log` | log host tests | all |
| No secrets in logs or fault reports | by convention | **none** (gap, H4) | all |
| Production ignores the kernel command line | `kernel/src/cmdline.rs:73-78` | **none** (no test with `dev_build = false`, gap H0-W11) | all |
| SQLite hardening (`DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`, `OMIT_LOAD_EXTENSION`, fixed prepared statements) | `store/src/store.rs:129-141`, `store/build.rs:22` | **none** asserts the flags (gap, H6) | all |
| Integrity check at boot, refuse on corruption | `store`, `kernel/src/db.rs` | `db-crash`, `log-crash`, `log-tear` | all |
| A partitioned disk is never the data disk | `kernel/src/devices.rs:510` | `raw-disk` (boot disk byte-identical afterwards) | all |
| Kernel pinned by blake2b in `limine.conf` | `scripts/mkiso.sh` | **none** tampers with the kernel (gap, H8) | all |
| Reproducible images | `make repro` | CI "Reproducible prod image (built twice)" | aarch64 |
| Signed releases, provenance | `make sign`, release workflow | release workflow (minisign verify, SLSA attestation) | all |
| Config validated at build time | `config-schema` | config tests; `config_parse` fuzzing | all |

---

## 4. The nine questions of PROMPT-security H0

1. **Can a device certificate be revoked at runtime without a new image?** **No.** The list comes from `tls.revocation_list` at build time and is seeded into SQLite at boot (`kernel/src/db.rs:470`); nothing changes it at runtime. Gap → H1.
2. **Is the registry an allowlist?** **No.** It is a record filled on first connect: `DbReq::DeviceSeen` is an upsert (`mqtt_service.rs:281`, `db.rs:699`). Any certificate from the CA connects. Gap → H1 (`registry.mode`).
3. **Where does wall-clock time come from, and what if it is wrong?** From the firmware RTC through Limine, plus uptime (`boot.rs:226-233`, `now_unix` at `boot.rs:608-625`). An unknown date refuses every handshake (fail closed, ADR-009). A **wrong** date is believed: there is no lower bound, so an RTC in the past makes expired certificates look valid. Gap → H7 (lower bound with H1).
4. **KASLR?** **No.** The kernel is linked statically at a fixed address (`crates/kernel/linker.ld`); the heap, stacks and per-CPU regions are at fixed virtual addresses (`kernel/src/layout.rs`). Gap → H4.
5. **0-RTT disabled?** **Yes** (`tls/src/server.rs:348`), but untested and not refused by config. Gap (test) → H2. *H2: tested (`zero_rtt_is_never_offered`, tlsfuzzer); the config refusal already existed (`early_data_fails_the_build`).*
6. **Secrets zeroised?** **Partly:**
   - Per-direction record secrets and per-record keys are wiped on drop (`tls/src/record.rs:106-128`).
   - The X25519 scalar is in `Zeroizing` (`provider/kx.rs:80`).
   - **Not** wiped: traffic secrets captured for KeyUpdate (`server.rs:84-150`). They sit in a global `Vec`; `remove(0)` and `swap_remove` drop them without wiping, and reallocations leave copies in freed heap memory (H0-W2).
   - Not established: whether rustls's own handshake secrets, P-256 keys and CSPRNG state are wiped when retired, or that freed slab memory is clear. → H4.
7. **RFC 5961 and RFC 6528?** RFC 5961: **yes** (`tcp/src/lib.rs`, tests in `tcp/src/tests.rs`). RFC 6528: ISNs are SYN cookies (SipHash-2-4 MAC over the 4-tuple under a 16-byte key from the CSPRNG at boot, `tcp/src/cookie.rs`, `netproto.rs:50-62`), so they are keyed. **The key never rotates** (H0-W3). → H3.
8. **Network-reachable unbounded memory or loops?** Mostly bounded by config limits and admission (M16). One case is **not** bounded: retained messages. A device may publish retained messages to any number of distinct topics under its own `devices/{id}/#`, at up to `publish_rate_per_device` (10/s, about 864 000 topics a day). Each is stored in SQLite and replicated on every core (H0-W1). There is no per-loop bound documentation yet. → H3.
9. **Expiring server certificate refused at build, monitored at runtime?** **No** and **no**: `config-schema` has no expiry check and there is no expiry gauge. Gap → H1.

---

## 5. Weaknesses found

Severity is for the current deployment model: a VM with a virtio data disk,
mutual TLS devices, and the image treated as a secret.

| Id | Weakness | Severity | Where | Plan |
|---|---|---|---|---|
| H0-W1 | **Retained messages are unbounded per device**, in count and in total bytes. An authenticated device can exhaust memory on every core (each core keeps a replica) and fill the database. Even clearing a retained topic (empty payload) creates its trie nodes first | **high** (authenticated DoS) | `broker/src/lib.rs:1102-1110`, `broker/src/topics.rs:147-162` (`set_retained` → `intern`), `db.rs` | H3: `limits.max_retained_per_device` and a global byte budget, refusal counted; tested at the bound |
| H0-W2 | **Captured TLS traffic secrets are not wiped** (global `Vec`, `remove`/`swap_remove`, reallocation copies) | medium (needs a memory disclosure to exploit) | `tls/src/server.rs:84-150` | H4 (or earlier): fixed-capacity array, explicit wipe on take and on eviction, test |
| H0-W3 | **The SYN-cookie/ISN key never rotates** | low | `netproto.rs:50-62` | H3: two keys, rotation |
| H0-W4 | ~~**Session-ticket key derived from the server key** (in the image): a copy of the image lets anyone forge tickets for any device identity~~ | **high** if the image leaks | `tls/src/server.rs` | **fixed in H2** (ADR-054): random per-boot keys, rotated by uptime, zeroised; smoke `ticket-restart` |
| H0-W5 | ~~**No lower bound on the wall clock**: an RTC in the past accepts expired certificates~~ | **high** on bare metal (dead CMOS battery) and after VM snapshot restores | `boot.rs` | **fixed in H1** (ADR-050): build time is the lower bound; smoke `time-before-build` |
| H0-W6 | ~~**Random-number failures ignored** in two places: `let _ = fill_global(...)` for the cookie key and the DHCP xid~~ | low | `netproto.rs` | **fixed in H1:** both are fatal now. The generator's `Err` without a source is already host-tested; the kernel paths cannot be reached in a test because boot refuses earlier |
| H0-W7 | ~~`urmqtt-store` had no `unsafe_code` lint.~~ Its docs confined unsafe to the FFI modules, but nothing enforced it | low | `store/src/lib.rs` | **fixed in H0:** `#![deny(unsafe_code)]`, `allow` only on `db`, `ffi`, `libc`, `vfs`, `init` and the log callback |
| H0-W8 | **SQLite parses a database from the volume without fuzzing** | medium (a crafted volume reaches 254k lines of C at EL1) | SQLite | H5 (fuzz the VFS with crafted images under ASan), H6 (EL0) |
| H0-W9 | **No fuzzing of PCI and virtio parsing** (hostile or buggy devices: on bare metal, and virtio under a hostile hypervisor) | medium on bare metal | `pci`, `virtio` | H5: fuzz targets with a fake config space and rings; H4b IOMMU |
| H0-W10 | **No test proves page tables are read-only after the lock** | low (the lock exists; the proof is missing) | `vm::lock` | H4: `test=write-table` must fault |
| H0-W11 | ~~**No test for "prod ignores the command line"**~~ | low | `cmdline.rs` | **fixed in H1:** the kernel binary runs host tests; `production_ignores_every_option` |
| H0-W12 | ~~**The data disk is chosen by "not partitioned" instead of by identity**~~ | medium on bare metal | `kernel/src/devices.rs` | **fixed in S1** (ADR-051): the boot disk by its GPT disk GUID; other disks only read (smoke `first-boot`, `scsi-boot` check a second disk is byte-identical) |
| H0-W13 | ~~Foreign disks taken for blank; a damaged urMQTT partition re-formatted~~ | low | `store/src/layout.rs` | **fixed in S1:** a damaged data partition is refused and left unwritten (smoke `own-damaged-refused`) |
| H0-W14 | **30 `unsafe` sites have no written justification** (§1) | low | [audit/unsafe.md](audit/unsafe.md) | H10 review; the CI inventory keeps the count visible |

Found while doing H1 (kept here so the list stays in one place):

| Id | Weakness | Severity | Where | Plan |
|---|---|---|---|---|
| H1-W1 | **A publisher learns nothing about the outcome** of a control message. A PUBACK only means "received"; the result is in the broker's log and metrics | low (operations) | `control.rs` | later: a signed status topic readable only by control identities, with its own threat-model entry |
| H1-W2 | **Rolling back the data disk** to an old snapshot restores old revocations and an old `seq` | medium (needs disk access) | store | documented residual risk; image-listed revocations are re-applied at every boot |
| H1-W3 | **The build's expiry check is cached** by cargo until the configuration or certificates change | low | `config/build.rs` | clean builds (CI, repro, release) always run it; optional: a `make` target that forces it |
| H1-W4 | **Allowlist mode without durable storage** means an empty, frozen allowlist: every device is refused | low (fails closed, logged at boot) | `boot.rs` | intended; documented |

Untested protections (from §3) count as gaps as well: FP-state save, 0-RTT,
the page-table lock, no secrets in logs, the SQLite flags, the kernel hash in
`limine.conf`, and prod ignoring the command line.
