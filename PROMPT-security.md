# urMQTT — Security assurance and hardening

> This document extends `PROMPT.md` and coexists with `PROMPT-x86_64.md` and `PROMPT-storage.md`.
> Everything in `PROMPT.md` still applies (working method, code rules, ADRs, PROGRESS entries,
> "verify, don't assume", "never fake progress"). Put this file in the repo root.
>
> **Security is the project's first priority.** When this document conflicts with performance, footprint or
> convenience goals elsewhere, security wins unless the user explicitly decides otherwise in an ADR.

---

## 0. Context and working agreement

urMQTT already has strong foundations: one exposed port (8883, TLS 1.3 + mTLS), no shell or remote management,
Rust with `forbid(unsafe_code)` in protocol crates, W^X with locked page tables, guard pages, PAC/BTI, admission
control, 11 fuzz targets in CI, reproducible signed builds and a threat model (`docs/SECURITY.md`).

The goal of this work is to turn "designed to be secure" into **"demonstrably secure and ready for an external
audit"**: find and close gaps, prove properties with tests and tools, make the identity lifecycle operable without
new images, and produce an audit package.

Read `README.md`, `docs/SECURITY.md`, `docs/DECISIONS.md`, `docs/PROGRESS.md`, `crates/tls`, `crates/tcp`,
`crates/broker`, `crates/mm`, `crates/arch-aarch64` and `crates/store` before starting.

Rules specific to this work:

- **Communicate with the user in Croatian.** Code, comments, commits and docs in English.
- Milestones **H0 … H10**, same discipline: `make check` + `make smoke` green, commit `H<n>: <summary>`,
  PROGRESS entry, ADRs, then stop and report — including **every weakness found**, even if not fixed yet.
- **Fail closed.** On doubt (unknown time, failed self-test, invalid signature, unexpected state) refuse rather than
  continue.
- **No new attack surface without a threat-model entry.** No new ports, no remote shell or admin API. Any new
  control path (e.g. runtime revocation) goes over the existing MQTT/TLS port, is authenticated twice
  (mTLS identity **and** an offline-key signature) and is added to `SECURITY.md` before implementation.
- **Every security property gets a regression test** that fails if the property is lost (e.g. a deliberate
  W^X violation must fault; a revoked certificate must be rejected; a forged control message must be ignored).
- **Every rejection is observable**: a statsd counter per reason and a rate-limited log line, never containing
  secrets, keys, full certificates or payloads.
- Do not weaken an existing protection for performance without an ADR approved by the user.
- If the x86_64 work is in progress, implement each item for both architectures or record the x86 follow-up
  explicitly.

---

## 1. Milestones (in priority order)

### H0 — Security baseline and inventory

- **TCB inventory** (`docs/AUDIT.md`, generated where possible by a script in `scripts/`): lines of code per crate,
  per vendored component (SQLite, Limine) and per dependency; count and location of `unsafe` blocks
  (e.g. `cargo-geiger` or own scan); list of C code; list of every external input parser.
- **Mitigation matrix**: each protection (W^X, locked tables, guard pages, PAC/BTI, admission, limits, …) with
  where it is implemented and which test proves it.
- **Answer these questions from the code**, with file references, and list them as gaps if the answer is "no":
  1. Can a device certificate be revoked **at runtime** without a new image?
  2. Is the device registry an allowlist (unknown devices refused) or a record filled on first connect?
  3. Where does wall-clock time come from, and what happens to certificate validation if it is wrong or unknown?
  4. Is the kernel base address randomized (KASLR)? Heap, slabs, per-CPU areas, stacks?
  5. Is TLS 1.3 0-RTT (early data) disabled? (It must be.)
  6. Are all secrets (server key, ticket keys, traffic secrets, CSPRNG state) zeroized when no longer needed?
  7. Does the TCP stack implement RFC 5961 (blind in-window RST/SYN/data injection) and RFC 6528 (keyed ISN)?
  8. Is there any code path reachable from the network that can allocate unbounded memory or loop unboundedly?
  9. Does the build refuse a server certificate that expires soon, and is expiry monitored at runtime?
- Accept: `docs/AUDIT.md` exists with the inventory, matrix and answers; gaps listed in PROGRESS.

### H1 — Identity lifecycle without new images

- **Runtime revocation**: a reserved topic namespace (e.g. `$urmqtt/control/...`) that devices can never publish
  to or subscribe to. Only configured service identities may publish there, and every control message must carry
  an **Ed25519 signature** by an offline *control signing key* whose public key is baked into the image
  (`deploy/<env>/control.pub`). Messages carry a monotonic sequence number (persisted) to prevent replay, and a
  validity window. Supported commands: revoke serial(s), unrevoke (if allowed by config), allowlist add/remove
  (if registry mode is allowlist). Effects persist in SQLite, propagate to all cores, and **existing connections
  using a newly revoked certificate are closed immediately**.
- `tools/urmqtt-control` (host, std): builds and signs control messages with the offline key (file for dev,
  PKCS#11 / cloud KMS hook for prod), and publishes them via a service identity.
- **Registry mode** in config: `registry.mode = "open" | "allowlist"`, documented and tested both ways.
- **Multiple trust anchors with roles** in config: e.g. `operational` (normal device rights) and `bootstrap`
  (only `provision/{id}/#` rights), each with its own CA certificate(s); at least two CAs per role to allow
  **CA rotation with overlap**. Document the provisioning flow in `docs/PROVISIONING.md` (keys generated on the
  device, ideally in a secure element; CSR; enrollment service outside the broker with the CA key in an HSM/KMS;
  no central store of device private keys).
- **Expiry safety**: build fails if the server certificate expires in less than `tls.min_server_cert_days`
  (default 60) or any trust anchor in less than a configured threshold; at runtime a statsd gauge for days
  remaining and log warnings at 60/30/7/1 days.
- Accept: scenario tests — revoke a connected device → disconnected and refused on reconnect; forged signature,
  replayed sequence, expired control message, control message from a device identity → all ignored and counted;
  bootstrap identity limited to its topics; CA rotation with two operational CAs; expiry build check works.

### H2 — TLS assurance

- **0-RTT disabled** and tested; TLS 1.3 only; cipher suites and groups as configured, documented rationale
  (prefer X25519 and ECDSA P-256/Ed25519 certificates; document RSA cost if allowed at all).
- **Record layer and key schedule review**: write `docs/CRYPTO.md` specifying exactly how traffic secrets are stored,
  how key/IV are derived per record (the M15 memory optimization), nonce construction, sequence handling, KeyUpdate,
  record size limits, padding, alerts and close_notify. Include RFC 8448 test vectors.
- **Differential testing** (host): for random secrets, sequence numbers, content types and lengths, the own record
  layer must produce byte-identical records to a reference (rustls's record layer and, if practical, OpenSSL via a
  host-only test dependency), and must accept exactly the records the reference accepts. Add as a fuzz target.
- **Constant-time checks**: dudect-style statistical timing tests (host) for tag verification, record decryption
  failure paths, HMAC/PSK binder comparisons and any secret-dependent comparison. Use constant-time primitives
  (`subtle`) everywhere secrets are compared.
- **Conformance and negative testing** against the running VM: run a TLS conformance suite such as tlsfuzzer
  (select applicable scripts for a TLS 1.3, client-auth-required server) in CI; record which scripts apply and pass.
- **Interop matrix** with the TLS stacks devices actually use: OpenSSL (mosquitto), mbedTLS, wolfSSL, and at least
  one embedded MQTT client; including resumption, KeyUpdate and large/small records.
- Ticket keys: generation, rotation interval, lifetime limits, zeroization; resumption must re-check revocation.
- Accept: differential fuzz target green for 10 min per architecture; tlsfuzzer results recorded; interop matrix
  table in docs; no non-constant-time comparison of secret data (grep + review list in AUDIT.md).

### H3 — TCP/IP assurance and DoS resistance

- Implement and test **RFC 5961** (challenge ACK for in-window RST/SYN, data injection checks) and **RFC 6528**
  (keyed-hash ISN with a secret rotated periodically) if missing; SYN-cookie secret rotation.
- **Scripted TCP tests** (packetdrill-style harness in host tests over the `tcp` crate): handshake edge cases,
  simultaneous close, zero window and persist, window shrinking, out-of-window segments, overlapping
  retransmissions, urgent pointer, malformed options, MSS extremes.
- **Stateful model test**: `proptest-state-machine` (or equivalent) comparing the TCP implementation against a
  simplified reference model of RFC 9293 states.
- **Adversarial suite in QEMU** (dev tool, `tools/attack/`, never shipped): SYN flood, ACK flood, RST injection,
  slowloris at TCP, TLS handshake and MQTT CONNECT stages, half-sent records, maximum-size packets, topic and
  subscription explosion attempts, keepalive abuse, many identities from one IP, reconnect storms. Each scenario has
  an expected outcome (bounded memory, bounded CPU per core, correct counters) checked automatically.
- **Unbounded work audit**: every loop and allocation reachable from network input has a documented bound coming
  from config; add tests at the bound.
- Accept: all scripted and adversarial tests pass; memory stays within configured limits in every scenario;
  findings documented.

### H4 — Exploit mitigations

- **KASLR**: build the kernel position-independent and randomize its base (verify Limine's KASLR support for the
  vendored version) on every boot; also randomize heap, slab, packet-pool, per-CPU and stack placement. Log entropy
  bits, never the addresses (except in dev builds).
- **Stack protection**: evaluate `-Z stack-protector=strong|all` (the toolchain is nightly) and enable if it works
  in the freestanding environment; also compile SQLite with `-fstack-protector-strong` providing the guard symbols.
- **Forward-edge CFI**: evaluate kCFI (`-Zsanitizer=kcfi`) for indirect calls in addition to BTI; ADR with
  measured cost.
- **MTE (aarch64)**: where the CPU supports it (testable under QEMU TCG with `mte=on`), tag the heap, packet
  buffers and the SQLite heap; synchronous mode in dev, configurable in prod. Smoke scenario for use-after-free and
  overflow detection.
- **Allocator hardening**: poison on free (dev and optionally prod), double-free and invalid-free detection,
  freelist pointer obfuscation/integrity, guard gaps between large allocations; separate slabs for secrets (exists)
  with zero-on-free verified by a test.
- **Zeroization**: use `zeroize` for all secret-bearing types; test that freed key-slab memory is zero.
- **Panic and fault policy**: a panic or fatal exception never prints secrets, then resets (prod) — verify.
- Accept: smoke scenarios for each mitigation (KASLR differs across boots, stack smash detected, MTE fault,
  double free detected); costs measured in `make bench` and recorded.

### H5 — Verification tooling

- **Miri** for all host-testable crates in CI (where Miri supports the code).
- **Kani** (bounded model checking) proofs for: MQTT decoder never panics and never reads out of bounds for inputs up
  to a bound; TCP segment parser; TLS record header parsing; config validation; timer wheel invariants.
- **Sanitizers** for host tests: AddressSanitizer and UndefinedBehaviorSanitizer builds, including the SQLite VFS and
  libc shims compiled for the host.
- **Stateful fuzzing** of the broker (sequences of CONNECT/SUBSCRIBE/PUBLISH/DISCONNECT across many sessions,
  checking ACL invariants: a device never receives another device's topics, never publishes outside its rights).
- Coverage reports for fuzz targets; add seeds for uncovered branches.
- Accept: CI jobs for Miri, Kani and sanitizers; ACL invariant fuzzer runs 10 min clean; coverage numbers in PROGRESS.

### H6 — SQLite isolation

- Run SQLite on the DB core at **EL0** (aarch64) with its own translation table mapping only: its memsys5 heap,
  its request/response rings, VFS bounce buffers and its code (read-only, executable at EL0 only). No syscalls:
  communication only through the rings; any exception from EL0 is fatal for the DB core and handled by the
  existing failure policy. Measure the cost.
- If EL0 is not feasible in a reasonable scope, use MTE plus page-permission isolation as an interim, with an ADR.
- x86_64 follow-up: ring 3 equivalent (or PKS later), recorded.
- SQLite hardening flags verified: `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check=ON`,
  no mmap, no extensions, fixed prepared statements only.
- Accept: a deliberate out-of-bounds write from SQLite context (test hook) faults without touching kernel memory;
  DB benchmarks within an agreed cost.

### H7 — Time security

- Define the time source hierarchy: hypervisor clock (generic timer / kvmclock) + RTC, with the **image build time
  (`SOURCE_DATE_EPOCH`) as a hard lower bound**; optional SNTP to configured private servers with sanity limits
  (maximum step, agreement between sources); evaluate NTS (RFC 8915) and document the decision.
- Certificate validation policy when time is unknown or implausible: fail closed by default; configurable only
  towards stricter behavior.
- Accept: tests for clock before build time, large forward/backward jumps, SNTP disagreement; certificate validity
  enforced correctly in each case.

### H8 — Boot integrity and secret protection

- **Limine integrity**: pin kernel hashes in `limine.conf` and enroll the config checksum into the Limine EFI binary
  (verify the mechanism for the vendored version) so a modified kernel or config does not boot.
- **UEFI Secure Boot**: sign the EFI loaders with a project key; document key enrollment for OVMF/QEMU and Proxmox;
  CI test booting with Secure Boot enabled in OVMF.
- **Embedded secrets**: document that the image is a secret; make the build warn loudly when producing a prod image
  outside CI; ensure secrets never appear in logs, panic output, crash paths or the reproducibility comparison
  artifacts.
- Research spike (ADR only, not default): sealing the server key to a vTPM so a copied image does not work elsewhere.
- Accept: tampered kernel or config refuses to boot; Secure Boot test in CI.

### H9 — Supply chain and compliance readiness

- **SBOM** (CycloneDX or SPDX) generated for every release, including Rust dependencies and vendored C components
  with versions and hashes; attached to releases next to provenance.
- Dependency review: `cargo-vet` (or equivalent) audits for every dependency in the TCB; RUSTSEC advisories fail CI
  (cargo-deny exists — verify configuration); scheduled job that alerts on new advisories.
- `docs/VULNERABILITY-HANDLING.md`: intake, triage, fix, release and disclosure process, supported versions and
  support period, security update policy, contact; align with the EU Cyber Resilience Act's expectations for
  manufacturers (vulnerability handling and reporting). State clearly that this is not legal advice.
- Accept: SBOM in release workflow; vet audits complete for TCB dependencies; process document reviewed.

### H10 — Audit package

- `docs/AUDIT.md` final: architecture summary, TCB inventory, `unsafe` inventory with justifications, crypto design
  (`CRYPTO.md`), trust model and provisioning, threat model (STRIDE per component; update `SECURITY.md`), all
  mitigations with their tests, known limitations and accepted risks, how to build, run and test everything,
  and a **proposed scope for an external audit** in priority order:
  1. TLS record layer and key schedule (custom code),
  2. TCP stack (custom code),
  3. MQTT codec, broker ACL and control channel,
  4. admission control and resource limits,
  5. `unsafe` code in `mm`, `arch-*`, `virtio`, `pci`, and the SQLite FFI/VFS,
  6. boot chain and image build.
- Internal red-team checklist executed by you, with results and fixes.
- Accept: the package lets an external auditor build, boot and test the system without asking questions.

---

## 2. Configuration additions (validated by `config-schema`)

```toml
[tls]
min_server_cert_days = 60
early_data = false            # must stay false; build fails if true

[trust]
# role -> CA files in deploy/<env>/
operational = ["ca-ops-2026.pem", "ca-ops-2031.pem"]
bootstrap   = ["ca-bootstrap.pem"]
min_anchor_days = 365

[registry]
mode = "open"                 # "open" | "allowlist"

[control]
public_key = "control.pub"    # Ed25519, offline private key
service_ids = ["backend"]
allow_unrevoke = false
max_message_age_s = 600

[time]
sntp = []                     # private servers, optional
max_step_s = 300
```

---

## 3. Definition of done

- All H0 questions answered "yes" (or a documented, user-approved exception).
- Runtime revocation, allowlist and CA rotation work without new images, authenticated twice.
- Own TLS record layer proven equivalent to a reference by differential fuzzing; conformance and interop recorded.
- TCP stack resists the adversarial suite with bounded resources; RFC 5961/6528 implemented.
- KASLR, allocator hardening, zeroization, MTE (where available) and SQLite isolation in place with tests.
- Miri, Kani, sanitizers and stateful fuzzing in CI.
- Boot chain integrity and Secure Boot tested; SBOM and vulnerability process published.
- Audit package complete and usable by an external auditor.

Start with **H0**. Before writing code, reply in Croatian with: your understanding in 5–8 bullet points, a first
quick answer to each H0 question from your reading of the code (to be confirmed in H0), the risks you consider most
serious right now, and the exact plan for H0–H1.
