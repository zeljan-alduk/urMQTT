# Security assurance: implementation and test plan (H0–H10)

Plan for [`PROMPT-security.md`](../PROMPT-security.md). Written 2026-10-29
against commit `8186a61`. It is part of the overall plan in
[PLAN.md](PLAN.md), next to [X86-PLAN.md](X86-PLAN.md) and
[STORAGE-PLAN.md](STORAGE-PLAN.md). Security is the project's first
priority: where these plans conflict, this one wins unless an ADR approved by
the user says otherwise.

---

## 1. Quick answers to the H0 questions (from reading the code; H0 confirms them)

| # | Question | Answer today | Evidence | Gap? |
|---|---|---|---|---|
| 1 | Runtime revocation without a new image? | **No.** `tls.revoked_serials` is built into the image and seeded into SQLite at boot. There is no runtime path. | `kernel/src/db.rs:470`, `store.rs` `revoked_add` | **yes** (H1) |
| 2 | Is the device registry an allowlist? | **No.** It is a record filled on first connect (`DbReq::DeviceSeen` upsert); any certificate from the CA connects. | `mqtt_service.rs:281`, `db.rs:699` | **yes** (H1, `registry.mode`) |
| 3 | Where does wall-clock time come from? | Firmware RTC via Limine plus uptime. No date means every handshake is refused (fail closed, ADR-009). There is **no lower bound**: an RTC set in the past is believed, so an expired certificate looks valid. | `boot.rs:226-233, 608-625` | **yes** (H7: build time as the lower bound) |
| 4 | KASLR? Heap, slab, stack placement randomised? | **No.** The kernel is linked statically (`linker.ld`) and the regions sit at fixed virtual addresses (`layout.rs`). | `crates/kernel/linker.ld`, `layout.rs` | **yes** (H4) |
| 5 | 0-RTT disabled? | **Yes.** `config.max_early_data_size = 0`. There is not yet a regression test or a config refusal. | `tls/src/server.rs:348` | test missing (H2) |
| 6 | Secrets zeroised? | **Partly.** `zeroize` is used in 6 places. Whether the key slab is zero-on-free, and what happens to traffic secrets after KeyUpdate and to CSPRNG state, has not been checked across the board. | `grep zeroize` | **to verify** (H0/H4) |
| 7 | RFC 5961 and RFC 6528? | RFC 5961 checks are implemented (M14, tested). ISNs come from SipHash SYN cookies under `cookie_key`, which is effectively a keyed ISN. **No key rotation** was found. | `tcp/src/lib.rs`, `siphash.rs` | rotation (H3) |
| 8 | Network-reachable unbounded memory or loops? | Bounded by design (limits, admission, M16 storms), but there is **no documented bound per loop and allocation**. | M16 | audit (H3) |
| 9 | Build refuses a soon-to-expire server certificate? Runtime expiry monitoring? | **No** and **no.** `config-schema` has no expiry check. | `crates/config-schema` | **yes** (H1) |

Further findings while reading:
- **Session-ticket keys are derived from the server key** (`ticket_key(&key, setup.version)`), so they never rotate while an image runs. They are the same on every boot and every replica of the image. Not insecure by itself (resumption re-checks revocation, ADR-034), but against PROMPT-security §H2 (rotation, lifetime limits). **Gap (H2).**
- **Bare metal adds attack surface the hypervisor used to absorb** (see X86-PLAN §3b):
  - physical access;
  - DMA from real devices: a malicious or buggy NIC or NVMe controller can write anywhere without an IOMMU;
  - firmware state left behind;
  - Secure Boot. **New item H4b** (IOMMU) and H8 (Secure Boot, here not optional).
- **The data disk can be mistaken for blank** (X86-PLAN F10: e.g. btrfs or mdraid 1.2 without a partition table). That is a data-loss bug on bare metal, not a security bug, and it is handled by STORAGE-PLAN S1.

---

## 2. Most serious risks right now

1. **No runtime revocation (H0 Q1).** A stolen device certificate stays valid until a new image is built and deployed. This is the largest operational security gap.
2. **No lower time bound (Q3).** With a wrong RTC (VM restored from an old snapshot, empty CMOS battery on bare metal) the broker accepts expired certificates. It fails closed only when there is no date at all.
3. **Open registry (Q2).** Every certificate from the CA is admitted; a CA compromise or a wrongly issued certificate gives immediate access.
4. **Custom security-critical code without differential testing:** the TLS record layer, the TCP stack and the MQTT ACL. They are fuzzed for crashes, but not proven equivalent to a reference or checked for invariants.
5. **No KASLR, no stack protector, no allocator hardening.** W^X, PAC/BTI and guard pages exist, but a memory-safety bug in `unsafe` code or in SQLite (C) would have fixed addresses to aim at.
6. **SQLite (≈ 250k lines of C) runs at EL1** with full kernel rights (H6).
7. **On bare metal: no IOMMU** (DMA from devices) and Secure Boot not yet supported.

---

## 3. Milestones

Every milestone ends with:
- `make check` and `make smoke`;
- commit `H<n>: …`, a PROGRESS entry and ADRs;
- a report of **every weakness found**, fixed or not.

**Rules for all milestones:**
- Every protection gets a regression test that fails when the protection is lost.
- Every refusal has a statsd counter and a rate-limited log line without secrets.
- No new port, and no new control path without an entry in `SECURITY.md` first.

**x86_64:** each item is done for both architectures if x86 already exists by then; otherwise an x86 follow-up is recorded.

### H0 — Security baseline and inventory · M (no behaviour change)

**Work**
- `scripts/audit-inventory.sh` (reproducible output) generates the inventory part of `docs/AUDIT.md`:
  - lines of code per crate, per vendored component (SQLite, Limine) and per dependency (`cargo metadata` plus `tokei` or a simple counter);
  - the `unsafe` inventory (an own scan of `unsafe {`, `unsafe fn` and `unsafe impl` with file:line and the adjacent `// SAFETY:`; `cargo-geiger` as a cross-check if it works with `-Zbuild-std`). Today's raw count is 372 lines mentioning `unsafe` outside attributes, and 7 crates with `forbid(unsafe_code)`;
  - the C code (SQLite, libc shims);
  - every parser of external input: the network (Ethernet, ARP, IPv4, ICMP, UDP, DHCP, TCP, TLS records, X.509, MQTT), the disk (superblock, size table, telemetry, SQLite), firmware tables (DTB, ACPI) and config (build time).
- **Mitigation matrix:** protection → implementation (file) → proving test (smoke scenario or host test) → architectures. Missing tests are listed as gaps.
- The 9 questions answered with file references (confirming §1).

**Tests:** the inventory script runs in CI and the output must be up to date (a diff check). **Accept:** AUDIT.md exists; gaps are in PROGRESS.

### H1 — Identity lifecycle without new images · L

**Work**
- **Control channel.** The topic namespace `$urmqtt/control/#` is reserved:
  - the ACL never lets device identities publish or subscribe there (checked before any other ACL rule);
  - only `control.service_ids` may publish;
  - each message carries `{seq, not_before, not_after, command, args}` in a canonical encoding (CBOR or a fixed binary layout; ADR) plus an **Ed25519 signature** by the offline key whose public half is `deploy/<env>/control.pub`, embedded at build time;
  - the persisted `seq` must strictly increase (anti-replay), and the validity window is checked against the time policy (H7 lower bound);
  - commands: `revoke`, `unrevoke` (only if `allow_unrevoke`), `allowlist add/remove`;
  - effects are written to SQLite, then propagated to all cores by a broadcast over the existing SPSC rings. **Live connections whose certificate serial is newly revoked are closed at once:** every core scans its connections for the serial, using the serial index that the TLS session keeps (sizes checked: bytes per connection must not grow, or the growth is reported).
- **`tools/urmqtt-control`** (host, std): build, sign and publish (with a service identity over mTLS). The key comes from a file in dev, or through a PKCS#11 hook (`--pkcs11-uri`) or a KMS command hook (`--sign-cmd`) in prod.
- **`registry.mode = "open" | "allowlist"`.** In `allowlist` mode an unknown identity is refused after the handshake with a statsd reason counter. The list can be seeded offline (STORAGE-PLAN S1 `urmqtt-disk import-devices`) or set through the control channel.
- **Trust anchors with roles** (`[trust]`):
  - `operational` and `bootstrap`, each a list of CA files, with at least two CAs per role for rotation with overlap;
  - a bootstrap identity gets only `provision/{id}/#`.
  - `docs/PROVISIONING.md` describes key generation on the device (secure element), CSR, an enrollment service outside the broker with the CA in an HSM/KMS, and no central store of device keys.
- **Expiry safety:**
  - `config-schema` fails the build below `tls.min_server_cert_days` (60) and `trust.min_anchor_days` (365);
  - at runtime a statsd gauge `urmqtt.tls.server_cert_days`, plus warnings at 60, 30, 7 and 1 days;
  - `early_data = true` fails the build.
- `SECURITY.md` threat-model entry for the control channel, written **before** the code.

**Tests**
- Host: canonical encoding round trip; signature verify with RFC 8032 vectors; seq and window rules; ACL precedence of the reserved namespace; config-schema refusals.
- Fuzz target `control_message`.
- Smoke scenarios:
  - `control-revoke-live`: a connected device is revoked, disconnected within 1 s, and refused on reconnect;
  - `control-forged`, `control-replay`, `control-expired`, `control-from-device`: each is ignored and counted;
  - `registry-allowlist`: unknown refused, added then admitted, removed then refused;
  - `bootstrap-role`: only `provision/{id}/#`;
  - `ca-rotation`: devices from both operational CAs work, and an old CA removed in a new image is refused;
  - `expiry-build-check` (in `make check`).

**Status: done** (docs/PROGRESS.md, H1; ADR-048, ADR-049, ADR-050). Deviations from the work list above:
- **Fixed binary encoding instead of CBOR:** the plan allowed either.
- **Signing hook:** the tool offers the generic `--sign-cmd` hook (HSM through `pkcs11-tool`, cloud KMS CLIs) instead of a linked PKCS#11 library behind `--pkcs11-uri`.
- **Broadcast:** propagation to the cores is an epoch counter plus a wake-up IPI rather than ring messages. Each core rescans its own connections, so nothing extra is queued per change.
- **Serial index:** the per-connection serial index is a 32-bit tag in existing padding (bytes per connection unchanged).
- **CA removal:** removing an old CA "in a new image" is proven by a host test that runs two servers with different anchors, including a resumption attempt with a valid ticket. The smoke `ca-rotation` scenario covers the overlap phase.
- **Fixed on the way:** H0-W5 (clock lower bound), H0-W6 (random failures fatal) and H0-W11 (command-line host test).

### H2 — TLS assurance · L

**Work**
- 0-RTT: config refusal (H1) plus a test with an early-data ClientHello (rustls client with `enable_early_data`), which the server must refuse.
- `docs/CRYPTO.md`: traffic-secret storage, per-record key/IV derivation (M15), nonce, sequence numbers, KeyUpdate, limits, padding, alerts, `close_notify`, with RFC 8448 vectors.
- **Session-ticket keys** (decided 2026-10-29, PLAN.md decision 5). Today the key is derived from the server key, which is inside the image, so anyone with a copy of the image could forge a ticket for any device identity and bypass mTLS. The new scheme:
  - **Keys:** random (CSPRNG at boot), never derived from anything in the image, never written to disk. They live in the key slab, zeroised when retired.
  - **Rotation:** a new key every 12 h; the previous key decrypts for 12 h more; tickets get `lifetime = 12 h`. Every ticket therefore expires before its key is dropped (RFC 8446 §4.6.1 allows up to 7 days; short-lived keys follow common practice for STEK rotation).
  - **Ticket format:** the ticket carries a key id; an unknown or retired key id is a quiet full handshake, counted (`urmqtt.tls.resume_refused.{expired,unknown_key}`). Encryption stays AEAD (ChaCha20-Poly1305), with a fresh random nonce per ticket and the key id as associated data.
  - **Cores:** all cores share the current and previous key through one sealed, read-mostly structure, swapped atomically at rotation.
  - **Kept as today:** revocation is re-checked on resumption, 0-RTT stays off, and resumption keeps (EC)DHE (`psk_dhe_ke`), so resumed sessions keep forward secrecy.
  - **Cost:** after a broker restart every device does one full handshake. A test measures this: the M16 storm scenario after a restart, refused and retried within the admission limits.
  - **Tests:**
    - host: rotation boundaries (issue just before rotation, resume just before and after the previous key expires), forged tickets (wrong key, flipped bit, foreign key id), zeroisation of retired keys;
    - smoke `ticket-rotation` with a dev-only short interval (`test=ticket-rotate:60s`);
    - smoke `ticket-forged`: a ticket made with the old image-derived key is refused.
- **Differential testing:** for random secrets, sequence numbers, content types and lengths, our record layer must produce byte-identical records to rustls's own record layer (a host dev-dependency), and accept exactly what it accepts. Fuzz target `diff_tls_record`; OpenSSL via a host-only test is optional.
- **Constant time:**
  - dudect-style timing tests (host) for tag verification, decryption failure paths and comparisons;
  - every secret comparison goes through `subtle`;
  - a grep-plus-review list in AUDIT.md.
- **Conformance:** tlsfuzzer against the running VM in CI, with the scripts that apply to a TLS 1.3, client-auth-required server. The list of chosen scripts and results goes in docs.
- **Interop matrix:**
  - OpenSSL (mosquitto), mbedTLS, wolfSSL and one embedded MQTT client (e.g. ESP-IDF's or Paho Embedded over mbedTLS);
  - for each: resumption, KeyUpdate, minimum and maximum record sizes.

**Accept:** the differential fuzz target runs 10 min clean per architecture; tlsfuzzer and interop tables are in docs; no non-constant-time secret comparison is left.

### H3 — TCP/IP assurance and DoS resistance · L

**Work**
- RFC 5961 re-verified against tests. SYN-cookie/ISN key rotation (two keys, the previous one still accepted for the cookie lifetime).
- **Scripted TCP tests:** a packetdrill-style DSL in the `tcp` crate's host tests. Coverage:
  - handshake edge cases, simultaneous close;
  - zero window and persist, window shrinking;
  - out-of-window segments, overlapping retransmissions;
  - URG, malformed options, MSS extremes.
- **Stateful model test:** `proptest-state-machine` against a reduced RFC 9293 model.
- **`tools/attack/`** (dev only, never shipped), each with an automatically checked expected outcome (memory within limits, CPU per core bounded, counters correct):
  - TCP: SYN flood, ACK flood, RST injection;
  - slowloris at three stages (TCP, TLS handshake, MQTT CONNECT); half records; maximum-size packets;
  - MQTT: topic and subscription explosion, keepalive abuse;
  - many identities from one IP; reconnect storms.
- **Unbounded-work audit:** every loop and allocation reachable from the network gets a documented bound from config, and a test at that bound.

**Accept:** all scripted and adversarial tests pass; memory stays within configured limits; findings are documented.

### H4 — Exploit mitigations · L

**KASLR**
- A PIE kernel (`relocation-model=pie`, linker script with a dynamic section).
- Limine KASLR for the Limine protocol (**to verify** in v12.9.4: config option and how it handles our higher-half layout).
- The heap, slab, packet-pool, per-CPU and stack bases are randomised within their regions from the CSPRNG.
- The log reports entropy bits, never addresses (except in dev).
- x86: KASLR inside the `-mcmodel=kernel` 2 GiB window.

**Stack protector:** `-Zstack-protector=strong` (provide `__stack_chk_guard` and `__stack_chk_fail`, the guard from the CSPRNG before any compiled code that uses it). SQLite with `-fstack-protector-strong`.

**kCFI:** evaluate `-Zsanitizer=kcfi`, including indirect calls into SQLite callbacks. ADR with the measured cost.

**MTE (aarch64):** tagged heap, packet buffers and SQLite heap; synchronous in dev, configurable in prod. Tested under TCG `mte=on`; HVF has no MTE (**to verify**).

**Allocator hardening:** poison on free; double-free and invalid-free detection; freelist integrity (obfuscated pointers); guard gaps for large allocations; the key slab zero-on-free, proven by a test.

**Zeroisation:** `zeroize` on every secret-bearing type, with a test that freed key-slab memory is zero.

**Panic and fault policy:** no secrets in reports (a test greps the fault output for known test-key bytes); reset in prod.

**H4b (new, bare metal): IOMMU.**
- Intel VT-d / AMD-Vi / Arm SMMUv3: map only the DMA buffers each device needs; refuse to run on bare metal without an IOMMU unless config allows it.
- Under a VM: a virtio-iommu is optional.
- The x86 bare-metal part comes after X12–X14.

**Tests:** smoke scenarios `kaslr-differs` (two boots, different bases, dev log only), `stack-smash`, `mte-uaf`, `mte-overflow`, `double-free`, `keyslab-zero`, `fault-no-secrets`, and `iommu-dma-blocked` (QEMU `intel-iommu` / `smmuv3` with a test device). Costs go in `make bench`.

### H5 — Verification tooling · M (CI jobs; can start right after H0)

**Work**
- Miri on the host crates (`mqtt`, `broker`, `tcp`, `net`, `timer-wheel`, `store` layout, `tls` record).
- **Kani proofs:**
  - the MQTT decoder never panics and never reads out of bounds up to a bound;
  - the TCP segment parser and the TLS record header;
  - config validation;
  - timer-wheel invariants.
- ASan and UBSan host builds, including the SQLite VFS and the libc shims compiled for the host (shared with STORAGE-PLAN S1, which needs the host build of `store` anyway).
- **Stateful broker fuzzing** with ACL invariants: no device receives another device's topics; no publish outside its rights; control topics unreachable.
- Coverage reports for fuzz targets; seeds for uncovered branches.

**Accept:** CI jobs for Miri, Kani and sanitizers; the ACL fuzzer runs 10 min clean; coverage in PROGRESS.

### H6 — SQLite isolation · L

**Work**
- **SQLite at EL0 on the DB core** (aarch64). Its own TTBR0 table maps only:
  - the memsys5 heap and its rings;
  - the VFS bounce buffers;
  - SQLite code (read-only, executable at EL0 only).

  There are no syscalls: requests and responses go only through the rings. An exception at EL0 is fatal for the DB core and goes through the existing failure policy. Cost measured with db-bench.
- **Interim fallback if EL0 is too large:** MTE plus page permissions, with an ADR.
- **x86:** ring 3, or PKS later; recorded as a follow-up.
- **Hardening flags verified by a test:** `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`, no mmap, no extensions, only fixed prepared statements.

**Accept:** a deliberate out-of-bounds write from SQLite context (test hook) faults without touching kernel memory; db-bench within an agreed cost.

### H7 — Time security · M (the lower bound moves forward into H1)

**Work**
- **Lower bound:** the image build time (`SOURCE_DATE_EPOCH`) is a hard lower bound. A clock before it counts as an unknown date, so the system fails closed. This lands **together with H1**, because control-message windows depend on it.
- **Optional SNTP** to configured private servers, with a maximum step and agreement between sources. An NTS (RFC 8915) evaluation and decision in an ADR.
- **Unknown or implausible time:** fail closed; config can only make it stricter.
- **Bare metal:** an empty CMOS battery gives a date in the past, so the lower bound catches it. A logged warning says to check the battery or the RTC.

**Tests:** clock before build time, large forward and backward jumps, SNTP disagreement. Certificate validity is correct in every case.

### H8 — Boot integrity and secret protection · M (essential for bare metal)

**Work**
- Kernel hashes pinned in `limine.conf` (as today). The config checksum is enrolled into the Limine EFI binaries (`limine enroll-config`, **to verify** for v12.9.4 on every loader in the multi-arch ISO).
- **UEFI Secure Boot:**
  - the EFI loaders are signed with a project key (`sbsign`);
  - enrollment documented for OVMF/QEMU, Proxmox and **the Intel test PC** (own keys in `db`, or MOK via shim; ADR);
  - a CI test boots OVMF with Secure Boot enabled.
- **Installer entry** (PLAN.md decision 7, STORAGE-PLAN S1b):
  - The prod kernel accepts exactly one command-line word, `install`, and only together with the hash-pinned `esp.img` module.
  - The threat-model entry: whoever can use the boot menu can erase the target disk. That requires physical or console access, which already allows that.
  - The menu editor stays disabled, and the enrolled config hash (above) prevents adding entries or arguments.
- **Image secrecy:**
  - a loud build warning when a prod image is built outside CI;
  - secrets never appear in logs, panics or the repro comparison artifacts (a test greps them for key bytes).
- **Research spike** (ADR only): seal the server key to a vTPM or TPM 2.0 (on bare metal a real TPM) so that a copied image does not work elsewhere.

**Accept:** a modified kernel or config does not boot; the Secure Boot CI test passes; Secure Boot works on the Intel PC.

### H9 — Supply chain and compliance readiness · M

**Work**
- **SBOM:** CycloneDX for every release, covering the Rust dependencies and the vendored C and binaries (SQLite, Limine) with versions and hashes, attached next to the SLSA provenance.
- **Dependencies:** `cargo-vet` audits for every TCB dependency, plus a check of the `cargo-deny` configuration (advisories fail CI) and a scheduled advisory job.
- **`docs/VULNERABILITY-HANDLING.md`:** intake, triage, fix, release, disclosure, supported versions and support period, and alignment with the EU Cyber Resilience Act's expectations for manufacturers, stated not to be legal advice.

**Accept:** the SBOM is in the release workflow; vet audits are complete; the process document exists.

### H10 — Audit package · M (last)

**Work:** finalise `docs/AUDIT.md` with:
- the architecture summary, TCB inventory and the `unsafe` inventory with justifications;
- `CRYPTO.md`, the trust and provisioning model, and STRIDE per component (into `SECURITY.md`);
- every mitigation with its test;
- known limits and accepted risks;
- build, run and test instructions;
- the proposed external audit scope: record layer and key schedule; TCP; MQTT codec, ACL and control channel; admission and limits; `unsafe` in `mm`, `arch-*`, `virtio`, `pci`, the native drivers (X13/X14) and the SQLite FFI/VFS; boot chain and image.

Plus an internal red-team checklist with results and fixes.

**Accept:** an external auditor can build, boot and test everything without asking.

---

## 4. Configuration additions

Exactly as in PROMPT-security.md §2 (`[tls] min_server_cert_days, early_data`, `[trust]`, `[registry]`,
`[control]`, `[time]`). All of it is validated by `config-schema`, and each key has a refusal test.

## 5. Exact plan for H0 and H1

1. **H0:**
   - inventory script and AUDIT.md skeleton;
   - `unsafe` scan;
   - parser list;
   - mitigation matrix with test references;
   - the 9 answers;
   - gaps into PROGRESS.

   No behaviour change; smoke must stay at 79/79.
2. **H1 (with H7's lower bound):**
   - threat-model entries for the control channel and the allowlist (SECURITY.md) first;
   - config keys and refusals;
   - Ed25519 verify (the `ed25519-dalek` crate, no_std, constant time; vetted in H9);
   - the reserved namespace in the ACL;
   - control-message decoder and fuzz target;
   - seq persistence (new SQLite table, migration v2);
   - core broadcast and live disconnect;
   - registry modes;
   - trust roles;
   - expiry checks and gauge;
   - `tools/urmqtt-control`;
   - `docs/PROVISIONING.md`;
   - the smoke scenarios from H1.

Each step is tested before the next.
