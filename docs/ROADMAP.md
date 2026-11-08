# Roadmap proposal after v0.3.0

Status: proposal, 2026-11-04, written against `8f6c059` (v0.3.0 plus 24 commits). Nothing here is decided or
scheduled. It lists what is still missing, why (with the document, ADR or finding that says so), a rough effort
and how each item would be verified, so the owner can pick the next work. The milestone plan that produced
v0.3.0 is [PLAN.md](PLAN.md). Where this file and an older plan disagree, the older plan was written first and
this file says why.

Effort: **S** up to a few days, **M** one to three weeks, **L** more than three weeks. Rough guesses, not
commitments. Risk is the risk to the project (regression, new attack surface, a claim we cannot back), not to
the schedule.

## 1. Where we are

- **Release.** v0.3.0 is tagged (`git tag`: v0.1.0, v0.2.0, v0.2.1, v0.3.0). Scope: a VPS or VM under KVM only
  (PLAN.md, "First release scope"); bare metal (X12 to X16) and the hardware part of H8 come after it. The release
  assets are dev builds with throwaway keys (CHANGELOG 0.3.0, "Limits, stated plainly").
- **CI.** The owner reports `main` green on `68d4820`; not re-checked from this checkout (no network was used).
  At the release candidate: 934 workspace tests, smoke aarch64 HVF+TCG 308/0, universal 59/0, x86_64 TCG 150/1
  (`log-slow-flood`, fixed afterwards), `make repro` identical (PROGRESS, "Release candidate v0.3.0").
- **Real machines.**
  - Contabo VPS, 4 vCPU AMD EPYC, KVM, x86_64, at the H7 commit: mTLS handshakes 185/262/333 per second at
    32/64/128 clients with the shipped limits, 0.50 to 0.66 KB of heap per idle connection at 19 975 held, one
    64 B flow 23.7k published/s against Mosquitto's 29.3k after the ADR-221 to ADR-224 fixes (PERFORMANCE.md 3, 7).
  - netcup VPS 500 ARM G12.5, Neoverse N1, 2 vCPU, aarch64 KVM: AES-XTS 241 MiB/s per core, AES-GCM 314 MiB/s,
    one mutual-TLS handshake 1.08 ms; TLS 1.3 + mTLS, QoS 1, 500 held connections and three 1000-client
    reconnect storms over the Internet without an error (CHANGELOG, Unreleased). The owner also reports install,
    boot from the installed disk and a retained message that survived a power cut on that machine; those three
    are **not yet recorded** in PROGRESS or PERFORMANCE.
  - Entropy on that machine (owner's measurement, reported by the new Diagnostic RNG panel): no virtio-rng and
    no `RNDR`, so the CSPRNG was seeded from the CPU-jitter fallback (768 bits credited) plus the bootloader's EFI
    RNG only. This is the ADR-038 path working as designed, and also the weakest seeding the kernel accepts.
    Not yet recorded in PROGRESS either.
- **What is not claimed** (AUDIT.md "What this release does not claim", §6): bare metal, IOMMU, Secure Boot for
  release images, TPM sealing, x86_64 on KVM for the code after H7 (disk encryption, boot integrity), 100k and
  1M connections.

## 2. Principles and constraints

These come from PLAN.md, ADR-213 and the way every milestone so far was closed; each item below keeps them.

1. **A small trusted base.** A feature that adds a parser of network or device input adds a fuzz target and a
   row in AUDIT.md §2 and §6b in the same change. A feature that needs a large new component (an HTTP server, an
   outbound client, a cluster protocol) is an owner decision first (section 4), not a default.
2. **No silent fallbacks.** The kernel refuses rather than degrades quietly: no unseeded CSPRNG (ADR-038), no
   software XTS (ADR-240), no default configuration over an invalid one (ADR-216). New fallbacks follow the
   same rule: logged at boot, visible in `$SYS`, and switchable off.
3. **Claims only as strong as the tests.** A number is quoted only with its source line and machine (ADR-213).
   "Done on QEMU" and "done on a real VPS" stay separate statements. An untested protection counts as a gap
   (AUDIT.md §5).
4. **aarch64 must not regress** (PLAN.md): smoke, `make bench`, bytes per idle connection and `make repro` after
   every item.
5. **One disk, and it is ours** (PLAN.md decision 6), and the appliance model: no shell, no login, no
   configuration after boot except the signed control channel.

## 3. Phases

**Editions (owner decision, 2026-11-05).** urMQTT has an open edition (this repository: everything that runs on
virtio devices, and all protocol, security and storage features) and a commercial edition (a private repository
that adds drivers for devices that are not virtio, bare metal, and support). The line, the promise that it never
moves backwards and how the two relate are in [EDITIONS.md](EDITIONS.md). For this roadmap that means: the
device drivers of LATER-2 and LATER-3 and the bare-metal work of LATER-4 and LATER-8 (X12 to X16) are
commercial-edition work; every other item stays here, including the security items that bare metal motivated
(LATER-5, LATER-6, LATER-7). It also answers part of D-11: **Google Cloud is the next real-machine target**,
first on its instance types that offer virtio-net and a virtio-scsi disk (e2, n2), which the open edition should
run on unchanged; gVNIC and NVMe for the newer types are the first commercial target. Nothing has run on Google
Cloud yet.

### Now: v0.4, hardening and operability of what exists (19 items)

The goal of v0.4 would be: a release an operator can run in production on a KVM VPS, with a real signing key,
the open audit findings that need no hardware closed, and the gaps the netcup run showed fixed.

**NOW-1. Restore PROGRESS.md and record the netcup run.** S.
- What: bring back the entries lost from `docs/PROGRESS.md` and add the netcup measurements (install, disk boot,
  power cut, entropy, crypto) as a PROGRESS entry and a PERFORMANCE section.
- Why: commit `85605d2` (S6) replaced the 1 763-line file with the 26-line S6 entry; every entry from M0 to S5
  (H0 to H5, X0 to X10, O1 to O4, T1, X9 + WD) is gone from the current file while README, PLAN.md and X86-PLAN.md
  still cite them ("PROGRESS.md is the source of truth"). The netcup run exists only in CHANGELOG.
- Risk: none (docs). Dependency: none.
- Verify: `git show 0723ec8:docs/PROGRESS.md` merged with the current file; every "PROGRESS ..." reference in
  docs/ resolves to a heading (a small script, or by hand).

**NOW-2. A real release signing key.** S (work), owner decision (custody). **Done on `main` (2026-11-06); the first
release signed with it is v0.4.2.**
- What: an offline-generated minisign key replaces `minisign.pub` and the CI secret; the builder page's
  embedded key, SECURITY.md and the mirror follow.
- Done (branch `release-key`, merged in b47c0ff): a key ring (`keys/release-keys.json`): the release key (`minisign.pub`, tags from v0.4.2 on) and
  the former test key (`keys/minisign-test-9229E05252D01F8E.pub`, v0.1.0 to v0.4.1 only). The builder page embeds it,
  verifies each release with the key its signature names, refuses an unknown key and a key outside its range, and marks
  the old releases "signed with the project's former test key" (15 languages). The mirror takes `--keyring` (same rules,
  `signed_by` and `keys` in `releases.json`; tests for two keys, an unknown key id, the test key on a newer tag, the
  placeholder, the switch from `--pubkey`). `urmqtt-config check-release` takes several `--pubkey`.
  `minisign.pub` is the release key `721316B961DCB94B` (generated by the owner on 2026-11-06, 685bb21);
  `scripts/check-release-key.sh` makes the Release workflow, `make sign`, `scripts/mirror/install.sh` and
  `scripts/deploy-builder-site.sh` refuse a placeholder or test-key `minisign.pub`. Releases
  ship the release environment only (`urmqtt-<tag>.elf/.iso/.img`, the template, SBOM; no dev build with throwaway
  certificates), trusted comment `urMQTT <tag> release <commit>`; `make repro ENV=release`.
- Done by the owner (docs/release-key-rotation.md steps 1 to 6): the key generated, the secret set, `minisign.pub`
  committed, the key id in SECURITY.md; the builder page on aldo.tech redeployed with the key ring and configuration
  format 7 on 2026-11-06 (its live manifest names format 7 and both keys), and the release mirror switched to
  `--keyring` by `scripts/mirror/install.sh` on 2026-11-06 at 22:23 UTC (`releases.json` lists both keys; `signed_by`
  is the test key for v0.2.0 to v0.4.1; v0.1.0 shows none, cause not investigated).
- What remains: cut v0.4.2 (docs/release-day-v0.4.2.md) and verify it with the new key on the page and the mirror.
  The release `.elf` asset is the aarch64 kernel only; the x86_64 release kernel ships inside the universal ISO and
  raw image, not as a file of its own.
- Risk: a page or mirror that does not know the new key refuses the first release signed with it (hence the order of
  the checklist). A forged `SHA256SUMS` signed with the compromised test key for an old tag is refused: the six
  test-key releases are pinned by the SHA-256 of their published `SHA256SUMS` (page, mirror, `check-release --keyring`).
- Verify: `scripts/test-mirror-releases.py` and `make builder-test` (two keys); `scripts/check-release-key.sh` with the
  real key (done); RELEASE.md §3 on v0.4.2 (open); the page shows v0.4.1 with the test-key note and the new release without.

**NOW-3. Production PKI tooling and guidance.** M. **Built, on `main` (merged in b47c0ff); the end-to-end run below is open.**
- What: a documented, scripted way for an operator to run the device CA, the server certificate and the control
  key offline (rotation, revocation, the bootstrap role), replacing the local test CA in `deploy/prod/`.
- Done: `scripts/pki.sh` (OpenSSL 3: `init` CA + server + control key + revocation list, `device`,
  `service`, `sign-csr` for keys born on devices, `server` rotation, `ca` for a second or bootstrap CA, `revoke`,
  `check` through `urmqtt-config pack`), docs/PKI.md (threat model, custody, rotation, revocation, the builder page,
  issuing at scale), `scripts/test-pki.sh` (host test: issues, revokes, checks the negative cases and packs the
  result into the release ISO and raw image; boots nothing).
- What the owner must do: nothing for the release; operators run it on their offline machine. Review the guide.
- Risk: low. Dependency: NOW-2 for the release side only.
- Verify (still open): a scripted end-to-end run on a VM (issue, connect, rotate CA with overlap, revoke over the
  control channel) with `pki.sh` output, as `scripts/control-scenarios.py` does with the dev PKI.

**NOW-4. Entropy: make the weak path visible and decide its default.** S. **Done (2026-11-06, ADR-263).**
- What: publish the seeding sources and credited bits under `$SYS/broker/` and in `$SYS/query/info` (today only
  the boot warning and the Diagnostic report show them); state per tested provider which source it gives
  (DEPLOY.md §6); decide whether production images should default to `entropy.fallback = "none"` with an explicit
  opt-in (section 4, D-3).
- Why: the netcup run (section 1); SECURITY.md residual risks "No hardware RNG on the cloud"; ADR-038 measured the
  jitter credit under QEMU only, and TODO.md asks for the figures on an Ampere cloud.
- Risk: a stricter default stops images from booting on such clouds; it must fail with a message naming the key.
- Outcome: the default stays `jitter` (such a VPS still boots); the weak path is an explicit choice, loud where a user
  decides: the builder's basic view (two options, a warning, the result card, a note), `urmqtt-config pack` / `verify` /
  `show`, the boot log and `$SYS/broker/entropy/source`; `fallback = "none"` is one click in the builder and refuses
  with a message naming the key (smoke scenario `entropy_option`). Per-provider sources (DEPLOY.md §6) stay to be filled
  as providers are tried; the credited-bits figures on an Ampere cloud remain open (TODO.md).
- Verify: smoke `no-hw-rng` checks the new topics; the jitter figures from netcup and one more provider recorded
  in PROGRESS.

**NOW-5. Document `diag-serve` and the fourth production word.** S.
- What: an ADR for `diag-serve`, a DEPLOY/OPERATE section for `$SYS/diag/report`, and the "three production
  words" statements corrected.
- Why: `crates/kernel/src/cmdline.rs` honours `install`, `live`, `diag` and `diag-serve` in production, while
  ADR-253, AUDIT.md §3b and SECURITY.md "Installer entry" say three; `diag-serve` is described only in CHANGELOG.
- Risk: none. Verify: the host tests `production_honours_*` cover the fourth word (`cmdline.rs` has a test
  for it); the threat-model entry names it.

**NOW-6. A console for VPSes without a visible framebuffer.** M.
- What: a minimal virtio-gpu 2D driver for the boot log, so the provider's web console shows the kernel's
  output; until then, `diag-serve` and `$SYS/console/out` remain the only views.
- Why: on netcup the VNC console shows "Display output is not active" (virtio-gpu has no driver) and no serial
  port is exposed (CHANGELOG, Unreleased); a boot that fails before the network is up is invisible there.
- Risk: a new device parser (virtio-gpu config and responses) in the TCB; it would join H0-W9's fuzz gap.
- Dependency: none. Verify: QEMU `-device virtio-gpu-pci` without a GOP framebuffer shows the log in a smoke
  screenshot; the netcup console shows the boot.
- Status: addressed on branch `virtio-gpu` (ADR-256, `console.virtio_gpu`, off by default): smoke screenshots on
  aarch64 HVF and x86_64 TCG, and the Diagnostic dashboard seen on the netcup console.

**NOW-7. H0-W10: prove the page tables are read-only after the lock.** S.
- What: a smoke scenario that writes to a page-table page after `vm::lock` and expects a decoded fault, on both
  architectures.
- Why: AUDIT.md §5 H0-W10 and §9 item 29 ("not tested").
- Risk: none. Verify: the scenario itself, with an `-open` style control as the H4 scenarios have.

**NOW-8. H0-W9: fuzz the PCI and virtio parsers.** M.
- What: fuzz targets for `pci` capability walks and for `virtio` rings, config space and SCSI sense/INQUIRY
  (`virtio/src/{queue,blk,net,scsi,transport}.rs`).
- Why: AUDIT.md §2 ("none (gap H0-W9)"), §9 item 27; it becomes a prerequisite once a hostile device is in scope
  (bare metal, LATER-4).
- Risk: refactoring drivers into host-testable parsers can change timing-sensitive code; keep the smoke suite on.
- Verify: the targets in CI's fuzz matrix (it builds from `fuzz/fuzz_targets`), a clean 10-minute nightly run.

**NOW-9. Constant-time evidence for P-256, X25519 and Ed25519.** M.
- What: extend `make ct` (dudect-style) to the asymmetric operations the server performs per handshake,
  including the own `nistz256` and `x25519` code.
- Why: AUDIT.md §6 and §9 item 30 ("not measured"); CRYPTO.md; the project carries hand-written assembly and
  fixed-base tables for these (ADR-110, ADR-130, ADR-131).
- Risk: a black-box test may be inconclusive at a feasible sample size (AUDIT.md §6 says so); report it as such.
- Verify: `make ct` output with a negative control per primitive, recorded in CRYPTO.md.
- Progress (ADR-255): P-256 key generation, ECDH and signing are in `make ct`, with a P-256 positive control;
  X25519 and Ed25519 are still open, and the P-256 runs so far are Docker on an Apple M4 Pro, not a server core.

**NOW-10. H0-W8: fuzz crafted SQLite files.** M.
- What: a fuzz target that opens mutated database, WAL and journal images through the worker's VFS under ASan.
- Why: AUDIT.md §5 H0-W8 (narrowed by H6, still open), §9 item 31.
- Risk: low (host only). Verify: the target in CI; findings, if any, upstream to SQLite.

**NOW-11. Reduce the cargo-vet exemptions.** L, ongoing.
- What: the order of SUPPLY-CHAIN.md "Where it stands": regenerate imports, delta-audit the small crates, then
  the RustCrypto and rustls families by external audit.
- Why: 53 of 67 kernel-linked crate versions are exemptions (AUDIT.md §6, SUPPLY-CHAIN.md).
- Risk: none. Verify: the exemption count in `docs/audit/vet-exemptions.md` per release.

**NOW-12. Re-run x86_64 on a real KVM VPS for the code after H7.** S to M.
- What: the smoke groups that matter (storage including `storage-encrypted`, hardening, secrecy, config) and an
  X11 subset on the Contabo VPS, plus AES-NI XTS throughput and `db-bench` with encryption on.
- Why: AUDIT.md §6 "Not measured on real hardware"; PROGRESS S7 "Not measured on x86_64 hardware"; H6 "x86_64
  CR3 switch without PCID not measured on KVM".
- Risk: uses the production VPS; needs the owner's go-ahead and a restore of the production ISO afterwards, as in X11.
- Verify: results in PROGRESS with commit, machine and raw files in `docs/perf-results/`.

**NOW-13. Single-flow throughput, the rest of PERFORMANCE §7.5.** M.
- What: per-CPU heap caches for blocks up to 16 KiB (the lock wait), SACK-driven recovery on the sending side, a
  virtio-net receive interrupt instead of ADR-224's 200 us polling.
- Why: PERFORMANCE.md 7.5 ("One flow is still not faster than Mosquitto's"); ADR-032 "Core 0 has no RX interrupt".
- Risk: TCP changes touch the H3 model tests and the `tcp_segment` fuzz target; idle power and latency change.
- Verify: the local rig (PERFORMANCE 7.3) and a same-session VPS run against Mosquitto.
- Status (2026-11-07): SACK-driven recovery on the sending side is in (ADR-265, rig numbers only) with deeper NIC
  queues and a receive-queue statistic (ADR-266). Open: the VPS run, the receive interrupt, and the per-CPU heap
  caches; the unmerged branch `perf-nic-queues-tcp-sack` (624a4fb, a5b9627) has a draft of the caches (up to 128 KiB,
  depots, trim) and of fewer copies per message (TLS records sealed in place, relay credit 256 KiB, 128 KiB output
  buffer per connection) without ADR, audit rows, Miri run or numbers.
- Status (2026-11-08): the VPS run is done (PERFORMANCE §13: two VPSes, each measured from the other, against
  Mosquitto 2.0.21). On 4 vCPU the SACK build leads Mosquitto in every row but 1 KiB on one flow (inside its range);
  on one ARM core Mosquitto keeps QoS 0 throughput and the SACK build is 10-30 % behind v0.4.2 on QoS 1 (a regression
  to resolve before v0.5.0). Next: publisher back-pressure when the subscriber is the only consumer, the receive
  interrupt, the per-CPU heap cache, the QoS 1 regression on one core.

**NOW-14. A limit on established TLS connections per source address.** S.
- What: a per-address cap for established connections, like `plaintext.max_connections_per_ip` already has.
- Why: TODO.md "Known limits": today only handshakes in flight are limited per address
  (`limits.max_handshakes_in_flight_per_ip`, AUDIT.md §6b).
- Risk: devices behind one NAT share an address; the default must be generous and the refusal counted.
- Verify: host test at the bound; a `tools/attack` scenario that opens many connections from one address.

**NOW-15. Plaintext accounts at run time.** M.
- What: a signed control message type that adds and removes `[plaintext]` password accounts, with the hashes
  kept on the data disk.
- Why: PROGRESS P1 "Not done / open"; SECURITY.md residual risk "Plaintext accounts cannot be added or removed at
  run time" (ADR-230).
- Risk: the control channel's replay and window logic gets a new message type; it needs its own fuzz input.
- Verify: `control-scenarios.py` cases (add, login, remove, replay refused), `control_message` fuzzing.

**NOW-16. Encryption at rest on the builder page.** M.
- What: the key dialog ADR-240 asks for (generate in the browser, download, import), so the page can write
  configuration format 4.
- Why: ADR-240 "The builder page does not offer it yet"; CHANGELOG 0.3.0 limits.
- Risk: a key generated in a browser must come from `crypto.getRandomValues` and never enter `sessionStorage`
  (ADR-226 rules).
- Verify: the page's headless tests (the produced blob equals `urmqtt-config pack` byte for byte; no key in
  storage or requests), as for the TLS key today.

**NOW-17. CI gaps that hide regressions.** S.
- What: wire `SMOKE_ONLY=secureboot` into CI on an x86_64 runner with `SMOKE_REQUIRE_SB=1`; the X1 "CI KVM
  probe"; `make builder-test` without the emulator runtime (PROGRESS, "Found, not fixed").
- Why: H8-W4 ("the CI job for the x86_64 test is not wired"); README X1 "CI KVM probe not done".
- Risk: none. Verify: the jobs run on a pull request.

**NOW-18. Kernel as a library.** M.
- What: a driver registration API for out-of-tree drivers, generic PCI ID binding, and a reserved configuration
  tag range; the open kernel's behaviour unchanged, `make repro` identical.
- Why: [EDITIONS.md](EDITIONS.md) §5. The driver framework's tables (`virtio::registry::KINDS`,
  `kernel/src/vdev/mod.rs::DRIVERS`) and the configuration tags (`crates/cfg/src/fields.rs`) are closed lists
  inside this repository (ADR-257), so a driver that lives elsewhere needs a patched kernel crate today.
- Risk: the registration path is code in the TCB that every image carries; a driver registered from outside must
  not be able to change how the open drivers bind, and the const checks of `vdev/mod.rs` must keep working.
- Verify: `make repro` identical before and after; smoke and host tests unchanged; a test driver registered from
  a crate outside the workspace binds a QEMU device by PCI ID and reads a key from the reserved range.

**NOW-19. Honour the MTU the network announces.** S. **Done (ADR-264).**
- What: use the MTU from DHCP (option 26) or the interface's configured value instead of assuming 1500 bytes for
  every segment; clamp the TCP MSS accordingly.
- Why: Google Cloud's default VPC network uses an MTU of 1460 and others use 1500 or jumbo frames; a kernel that
  sends 1500-byte frames into a 1460-byte network loses the large segments silently (found while preparing the
  Google Cloud scripts of the commercial edition, 2026-11-05).
- Risk: low; a wrong MTU today is a connectivity failure, not a safety one.
- Verify: a QEMU smoke scenario with a DHCP server that announces 1460 and a tap/user network that drops larger
  frames; the handshake and a 4 KiB publish complete; `$SYS` or the boot log shows the MTU in use.
- Done: DHCP option 26 and `network.mtu` (format 7), MSS = MTU - 40 for new and open connections, UDP and ICMP bounded,
  frames above 1500 never sent; boot line and `$SYS/broker/net/mtu`; host tests (option 26, MSS, segment sizes at 576,
  1460, 1500, 9000) and the smoke group `net_mtu` (static 1460 with a 4 KiB QoS 1 round trip and the capture checked;
  DHCP 1460/9000/300 on urmqtt-attack's raw transport, as QEMU's user network cannot announce an MTU). Not verified: a
  network that really drops larger frames (QEMU's user network accepts them), and Google Cloud itself.

### Next: protocol and network features (11 items)

These change what devices can do. Each is larger than the Now items and most add input parsing; sizes assume the
same test standard as M8 to M16 (codec fuzzing, Kani harnesses, mosquitto interop).

**NEXT-1. IPv6 with SLAAC and static addresses.** L.
- What: Ethernet type 0x86DD, ICMPv6 with Neighbour Discovery, SLAAC and a static address/prefix, dual stack in
  the per-core `Iface`, TCP and SYN cookies over IPv6, the Toeplitz steering for IPv6 tuples, IPv6 CIDRs in
  `plaintext.allow_from`, SNTP to IPv6 servers.
- Why: README features "IPv6 + SLAAC 📋 later", PROMPT.md §5.2 ("IPv6 + SLAAC as a later milestone"); the owner
  reports that VPS providers such as netcup hand out a /64; `crates/net` classifies IPv6 as "everything else".
- Risk: high parsing surface (extension headers, Neighbour Discovery options); needs the `net_frame` fuzzer extended and the
  RFC 5961 tests duplicated for IPv6. Memory per connection grows with 128-bit addresses (M15 budget).
- Verify: QEMU user networking supports IPv6; smoke scenarios for SLAAC, static, dual stack; mosquitto over IPv6.

**NEXT-2. QoS 2.** M.
- What: PUBREC/PUBREL/PUBCOMP with the packet-id state persisted per session; QoS 2 subscriptions granted at 2.
- Why: ADR-028 ("QoS 2 publishes close the connection, and QoS 2 subscriptions are granted QoS 1 (QoS 2 is a
  'later' item)"); `broker/src/lib.rs` closes on a QoS 2 PUBLISH; README "MQTT 5.0, QoS 2 📋 later".
- Risk: the persisted state is new SQLite schema and new crash-consistency cases.
- Verify: mosquitto `-q 2` interop, kill -9 between PUBREC and PUBCOMP (as `mqtt-persist` does for QoS 1),
  `broker_input` fuzzing with QoS 2 sequences.

**NEXT-3. MQTT 5.0.** L.
- Status: **part 1: codec + design done** (`urmqtt_mqtt::v5`, ADR-273, `docs/MQTT5-CONFORMANCE.md`); part 2 (version
  negotiation, reason codes, session/message expiry, will delay, flow control, packet size, topic aliases, keep alive,
  assigned id, subscription options) after NEXT-2; part 3 (shared subscriptions, subscription identifiers,
  conformance suite). D-13 answered: full 5.0 in phases.
- What: protocol level 5 alongside 3.1.1: properties, reason codes, session and message expiry, topic aliases,
  response topic and correlation data, user properties, flow control (receive maximum); shared subscriptions as a
  separate decision.
- Why: README features; PERFORMANCE §5 lists MQTT 5 as a difference from Mosquitto; OPERATE.md has to use a fixed
  reply topic because "MQTT 3.1.1 has no Response Topic property". Today `decode.rs` refuses any level but 4.
- Risk: the largest change to the codec and broker since M9: Kani harnesses, fuzz corpora and the 494 B
  per-connection figure (M15) must be re-established. Dependency: NEXT-2 (QoS 2 is part of the 5.0 spec).
- Verify: an MQTT 5 conformance suite (to be chosen), mosquitto 5 clients, re-measured bytes per idle connection.

**NEXT-4. Expiry of offline persistent sessions.** S to M.
- Status: designed into NEXT-3 part 2 (ADR-273 rule 4: `limits.max_session_expiry_s` for both versions, the
  session row gains `expiry_s` and `offline_since`).
- What: a configured maximum age for an offline persistent session and its queue (3.1.1 has none; 5.0 brings
  Session Expiry Interval).
- Why: I found no expiry in the broker (`Broker::tick` handles keepalive only); sessions are bounded by the number
  of identities the CA issues, not by time, so the store grows with every identity ever seen.
- Risk: dropping a session a device expects. Verify: host test at the bound; a smoke scenario across a restart.

**NEXT-5. MQTT over WebSocket.** M (in-kernel) or S (keep the external bridge).
- What: either a WebSocket listener in the kernel (HTTP upgrade, framing, masking) or a supported, documented
  version of the D1 bridge (`deploy/demo-bridge/`) for operators.
- Why: PLAN.md D1b ("urMQTT does not speak MQTT over WebSocket"); browser clients cannot connect otherwise.
- Risk: an HTTP request parser in the TCB is new attack surface; the bridge keeps it out. Owner decision (D-5).
- Verify: in-kernel: fuzz target for the upgrade and frame parser, `mqtt.js` interop; bridge: its 26 tests and a
  hardened deployment test.

**NEXT-6. virtio-net multiqueue and RSS.** M.
- What: one queue pair per data core with the device's RSS, so core 0 stops copying every frame.
- Why: ADR-032 ("virtio-net multiqueue + RSS is not implemented ... the hash already matches RSS"); README features
  "📋 later (needs tap/vhost to test)".
- Risk: needs a Linux KVM host with tap/vhost for tests (QEMU user networking has no multiqueue).
- Dependency: a test host (the Contabo VPS cannot nest; see D-9). Verify: smoke on tap with `mq=on`, dp-bench and
  the X11 rows re-measured.

**NEXT-7. An outbound TCP client.** L.
- What: active open in `urmqtt-tcp` (today passive open only, ADR-033), with connection state, ISN generation
  without cookies, and a TLS client path.
- Why: it is the prerequisite of bridging, webhooks, syslog over TLS, NTS and any cluster protocol; PROMPT.md §7.4
  names an export bridge as a later milestone.
- Risk: high. It changes the server-only design of ADR-033 and the threat model (the broker starts connections).
  Owner decision (D-6).
- Verify: the H3 model tests extended to active open; a loss-simulation test for the client side.

**NEXT-8. Export bridge.** M (after NEXT-7).
- What: forward selected topics to an upstream broker or HTTP endpoint with a service identity, bounded queues
  and backpressure.
- Why: PROMPT.md §7.4 ("a later milestone defines how data leaves the box ... Do not add a general query interface
  over the network"); README "Later: ... an export bridge".
- Risk: unbounded queues are the obvious failure; AUDIT.md §6b needs a new row. Dependency: NEXT-7.
- Verify: an upstream Mosquitto in the smoke rig; a stalled upstream must not grow the heap.

**NEXT-9. Observability beyond statsd and syslog over UDP.** S (exporter) to M (in-kernel).
- What: either an OpenMetrics/Prometheus exporter outside the image that reads `$SYS` over MQTT or statsd, or an
  in-kernel HTTP endpoint; and TLS for log shipping once NEXT-7 exists.
- Why: SECURITY.md residual risk "Syslog and statsd are plain UDP"; there is no Prometheus support in the repo.
- Risk: an in-kernel HTTP listener contradicts "TCP 8883 only" (README); the exporter keeps the image unchanged.
  Owner decision (D-7).
- Verify: the exporter's output against `$SYS/query/info` in a smoke scenario.

**NEXT-10. A DNS resolver for configured names.** S to M.
- What: a small stub resolver (UDP, the DHCP-supplied server) for SNTP and future upstream names.
- Why: OPERATE.md "IPv4 literals, at most four: the broker has no DNS"; `time_sync.rs` says the same.
- Risk: DNS answers are attacker-influenced input; needs a fuzz target. Verify: smoke with a QEMU DNS server.

**NEXT-11. Updates and rollback: A/B boot entries.** M to L.
- What: two kernel/configuration sets on the ESP with a boot counter and automatic fallback, so an update is not
  only the offline `urmqtt-disk update-boot`; a rollback-protection rule alongside (H8-W6).
- Why: PLAN.md decision 6 ("A/B boot entries with rollback as a later step"); AUDIT.md H8-W6 ("No downgrade
  protection").
- Risk: the kernel never writes the ESP today (ADR-217, ADR-254); a boot counter needs a write path or a
  firmware variable. Verify: power cut during an update in the fault loop; a deliberately broken new kernel falls
  back.

### Later: scale-out, more clouds, bare metal (12 items)

**LATER-1. Clustering or high availability.** L. Nothing exists. Needs NEXT-7, a session and retained-state
replication design, and a decision whether HA means "a warm standby with the same disk snapshot" or "several
active brokers" (D-8). Verify: a failover test with a defined loss bound for QoS 0 and none for QoS 1.

**LATER-2. AWS: ENA and NVMe drivers.** L. TODO.md "no driver for ... NVMe, AWS ENA ... so AWS and Google Cloud
are not supported"; PROMPT-x86_64.md §1 keeps AWS (and Azure) out of scope. Verify: smoke on QEMU's NVMe model, then a real
instance.

**LATER-3. Google Cloud gVNIC, Azure MANA/NetVSC, SR-IOV VFs.** L each. Same TODO.md line and ADR-038 (unsupported
NICs are named at boot and a production image stops). Each is a large driver and a new device parser.

**LATER-4. Bare metal, X12 to X16.** L. USB boot, `hwreport`, NVMe and AHCI (X13; also DISK-FORMAT §2a "NVMe, ATA
deferred to X13"), e1000e/igb and the test PC's NIC (X14), `docs/HARDWARE.md` (X16). Blocked on the Intel PC's
inventory (TODO.md). Prerequisites: H4b IOMMU (ADR-176) and NOW-8.

**LATER-5. H4b: IOMMU (VT-d, AMD-Vi, SMMUv3).** M to L. ADR-176 deferred it with bare metal; SECURITY.md residual
risks. Verify: the planned `iommu-dma-blocked` scenario.

**LATER-6. Secure Boot completed.** M. H8-W1 (installed disk does not boot under Secure Boot), H8-W2 (a signed
image cannot be configured afterwards), H8-W4 (aarch64 enforcement, Proxmox, a physical PC untested), H8-W6
(downgrade). Needs a project key (D-2) and, for W1, a per-machine ESP re-signed by the key owner (ADR-251).

**LATER-7. A disk key that is not in the image.** L. Today the key comes only from the configuration in the ISO
(ADR-240), so a stolen ISO defeats encryption at rest. ADR-254 estimates three to four weeks for TPM sealing and
recommends doing it with bare metal, after Secure Boot; the alternatives it lists (network key release, a
confidential VM) are owner decisions (D-10).

**LATER-8. aarch64 bare metal and other ARM hosts, X15.** L. GICv3 ITS for MSI (X86-PLAN F11), Ampere servers,
Raspberry Pi; the Pi-under-KVM and Hetzner CAX runs in TODO.md are S each and could move to Now if hardware is at hand.

**LATER-9. x86 control-flow integrity and other mitigations.** M. CET when a KVM host exposes it (ADR-047); kCFI
re-evaluated at the next toolchain bump (ADR-175); HHDM randomisation and KPTI/PCID for the worker (SECURITY.md
residual risks, PROGRESS H6).

**LATER-10. The rest of X9.** M. AVX2 ChaCha20, VAES, GFNI Toeplitz (X86-PLAN X9 items 4 to 7), enabled by default
only with a real-hardware number (X9 acceptance).

**LATER-11. 4Kn disks.** S to M. DISK-FORMAT.md §1 ("4Kn devices are not supported by the boot path (G3)"); likely
to matter with NVMe (LATER-2, LATER-4).

**LATER-12. riscv64.** L. PROMPT-x86_64.md §9, "only start after X11 and after the user confirms".

### Not technical, but blocking adoption (listed for completeness)

- **D1, the public demo broker:** built, not deployed (PROGRESS D1); needs its own VPS (one VM runs one image),
  DNS, and the owner's approval for public exposure. Also untested: its x86_64 boot, the container build, the
  real site's `build.py`.
- **The web builder and emulator:** 13 of 15 languages are machine translations not checked by native speakers;
  the emulator boots BIOS only, has no network and was tested in Chrome only (PROGRESS C1e/C1g).
- **Support period:** VULNERABILITY-HANDLING.md §6 promises none yet; the CRA expects one for a commercial product.
- **The "adapt your service to a unikernel" offer on aldo.tech:** not mentioned anywhere in this repository (the
  site texts here only describe urMQTT). If it should point at this project as a reference, the claims it can
  cite are the measured ones in section 1.

### Community readiness (owner decision, 2026-11-06)

Goal: someone from the open-source community can try urMQTT, deploy it and report what they find without help
from the maintainers. Four items, done on branch `community-docs`:

1. **A first-hour guide**, [FIRST-HOUR.md](FIRST-HOUR.md): from nothing to a first message over mutual TLS (test PKI,
   builder page or `urmqtt-config pack`, QEMU on a laptop or a KVM VPS, `mosquitto_pub`/`mosquitto_sub`, the five
   most likely failures with their log lines), with what was run for it.
2. **Issue and pull-request templates**: the forms `bug`, `boot-failure` and `question` in `.github/ISSUE_TEMPLATE/`
   (blank issues off, vulnerabilities pointed to SECURITY.md), checked by `scripts/check-issue-forms.py`; the pull
   request template with the DCO sign-off, `make check` and the edition rule for drivers that are not virtio.
3. **One page of known problems**, [KNOWN-ISSUES.md](KNOWN-ISSUES.md): what affects a user from AUDIT.md sections 5
   and 6, the "Limits" of v0.4.0 and v0.4.1, and the protocol, network, platform and entropy limits, each with a
   workaround and its tracking reference; `scripts/check-known-issues.py` (CI Lint job) fails when a cited AUDIT id,
   ROADMAP item or ADR no longer exists or an AUDIT weakness it cites is marked fixed.
4. **Consistent status wording**: README's title, badges, banners, "Why urMQTT" table and milestone tables brought
   in line with section 6 below and the documents; the status word stays "pre-alpha".

**Definition of "alpha".** The status word changes from "pre-alpha" to "alpha" (README badge and banner, SECURITY.md,
KNOWN-ISSUES.md) when all three of these have landed on `main`: a real release signing key (NOW-2), the entropy
option, that is the weak seeding made visible and its production default decided (NOW-4, D-3), and the MTU the
network announces honoured (NOW-19). The owner makes the change. **Done 2026-11-07:** all three are in v0.4.2 and
the status word is "alpha" (README badge and banner, SECURITY.md, KNOWN-ISSUES.md, FIRST-HOUR.md).

## 4. Candidate items that need an owner decision

Questions, not assumptions. Each blocks one or more items above.

| # | Question | Blocks |
|---|---|---|
| D-1 | Is v0.4 the "production on a KVM VPS" release (Now phase), or should a protocol feature (IPv6, QoS 2) be in it? | phase order |
| D-2 | Who holds the minisign key and a Secure Boot project key, where (HSM, air-gapped machine), and how are they rotated? A `dbx`/version-counter plan? (ADR-251 says this is the maintainer's decision.) | NOW-2, LATER-6 |
| D-3 | Should production images refuse to boot without a hardware RNG (`entropy.fallback = "none"`) unless the operator opts in, given the netcup finding? **Answered (owner, 2026-11-06): the default stays allowed; the choice is explicit in the builder; the hard requirement is one click** (ADR-263). | NOW-4 |
| D-4 | May the production VPS (Contabo) be used again for KVM runs, or is a separate test VPS bought? | NOW-12, NEXT-6 |
| D-5 | WebSocket: in the kernel (new HTTP parser in the TCB) or a supported external bridge? | NEXT-5 |
| D-6 | Is an outbound TCP client acceptable at all? It ends the server-only design (ADR-033) and opens bridging, TLS log shipping, NTS and clustering. | NEXT-7, NEXT-8, LATER-1 |
| D-7 | Metrics: an external exporter, or an HTTP port on the broker? | NEXT-9 |
| D-8 | Is HA a goal for 1.0? If so, standby or active-active? | LATER-1 |
| D-9 | Which test host gives KVM with tap/vhost and nested virtualisation for multiqueue and CI? | NEXT-6, NOW-17 |
| D-10 | Disk key outside the image: TPM sealing (ADR-254), network key release, confidential VMs, or "the ISO is a secret" for good? | LATER-7 |
| D-11 | Which clouds after KVM VPSes, if any: AWS, GCP, Azure? Each is at least one large driver. | LATER-2, LATER-3 |
| D-12 | Is bare metal still a goal before 1.0, and is the Intel PC available for the inventory? | LATER-4, LATER-5 |
| D-13 | MQTT 5.0: full, or a subset (properties, reason codes, session expiry) first? Shared subscriptions in or out? **Answered by the owner: full MQTT 5.0, in phases (ADR-273: codec and design done; broker in parts 2 and 3; shared subscriptions in part 3).** | NEXT-3 |
| D-14 | D1: deploy the demo broker, on which machine and name? | D1 |
| D-15 | A support period (CRA) and an LTS line, before or at 1.0? | VULNERABILITY-HANDLING §6 |
| D-16 | Should a stricter, memory-hard password hash (Argon2) be added for plaintext accounts? (PROGRESS P1, open.) **Answered 2026-11-07 (ADR-267): not now.** PBKDF2 stays; its default goes from 10 000 to 100 000 iterations (at most 200 000, below OWASP's 600 000 because a check runs in one go on a data core for every login); the login admission keeps half of each core whatever a check costs. Argon2id would reserve its memory per data core (OWASP's minimum is 19 MiB) and add a vetted `no_std` crate to the TCB, for passwords that plaintext MQTT sends in the clear anyway. Revisit with run-time accounts (NOW-15), or once a check can be split across handler runs. | plaintext |
| D-17 | When to migrate the TCB's crypto crates to the next RustCrypto generation (aes 0.9, aes-gcm and chacha20poly1305 0.11, `hybrid-array` instead of `generic-array`, `digest`/`sha2` 0.11), `curve25519`/`x25519`/`ed25519-dalek` 5/3 and `rand_core` 0.10 (its `RngCore` and `TryCryptoRng` traits replace ours)? Dependabot's PR #1 (2026-11-05) bundled all eight majors and broke every crate of the TLS stack; closed, Dependabot now sends majors singly. Each is a migration with its own ADR, KATs re-run, Miri and the differential tests, not a bot merge. | H9, SBOM freshness |

## 5. Explicitly out of scope

Recorded so they are not proposed again without a new reason.

- **A shell, a login, or configuration after boot** other than the signed control channel (README "Why urMQTT",
  PLAN.md "The result").
- **A filesystem** on the data disk (PLAN.md "The result" item 2).
- **A general query interface over the network** (PROMPT.md §7.4, export).
- **NTS** for the wall clock (PLAN.md T1, H7 closed, SECURITY.md); reconsider only after NEXT-7.
- **Software XTS or Adiantum** for CPUs without AES instructions (ADR-240).
- **Signing inside a TPM on the handshake path** (ADR-254: tens of milliseconds per signature).
- **A builder page that re-signs a configured ISO** (it would need the private key in the browser; ADR-251).
- **v86 for the in-browser emulator** (32-bit only; PLAN.md C1g).
- **Spectre-class isolation inside one image** (X86-PLAN X11) and **defence against the hypervisor**
  (SECURITY.md residual risks).
- **The emulator instance as a public broker** (PLAN.md D1).

## 6. README drift corrections

README's milestone tables and banners were not updated after several milestones closed. Proposed corrections,
for a separate change (README is not edited here). **Status (2026-11-06): applied** (the H, X9 and X11 rows and
the NOTE banner earlier, the rest on branch `community-docs`: title, badges, WARNING banner, "Why urMQTT" table,
Features Build row, M11, the O1 to D1 rows and the order list), as far as the documents back each statement:

| Where in README | README says | State per the docs |
|---|---|---|
| Roadmap, H3 TCP/IP & DoS | 📋 planned | done: AUDIT.md §6b ("the H3 deliverable"), H0-W1 and H0-W3 fixed in H3, `tools/attack` results (AUDIT.md §9) |
| Roadmap, H4 Exploit mitigations | 📋 planned | done except the deferred parts: ADR-170 to ADR-176 (kCFI not adopted, ADR-175; IOMMU deferred, ADR-176); CHANGELOG 0.3.0 |
| Roadmap, H5 Verification tooling | 📋 planned | done: ADR-120 to ADR-123, `make miri / kani / sanitize / acl-fuzz`, VERIFICATION.md |
| Roadmap, H7 Time security | 📋 planned | closed 2026-11-01 (PROGRESS H7; ADR-050, ADR-100) |
| Roadmap, H8 Boot integrity | 📋 planned | done for the VPS scope: ADR-250 to ADR-254, PROGRESS H8; open: H8-W1 to H8-W6, physical PC, aarch64 enforcement |
| Roadmap, H10 Audit package | 📋 planned | done: AUDIT.md is the H10 package (PROGRESS H10) |
| Roadmap, X9 x86 CPU optimisations | 📋 planned | partly done: items 1 to 3 under QEMU (ADR-070, X86-PLAN X9 status); items 4 to 7 and hardware numbers open |
| Roadmap, X11 Measurements & docs | 📋 planned | done on a KVM VPS (Contabo, PERFORMANCE.md, ADR-213); real x86 hardware and PV on/off not measured |
| Roadmap tables | no rows | O1, O2 (ADR-060), O3 (ADR-061, ADR-062), O4 (ADR-063), T1 (ADR-100), C1 (ADR-215 to ADR-228), P1 (ADR-229 to ADR-231), D1 (built, not deployed) are missing |
| "Next: ..." section | "Nothing below is implemented yet" | most of it is implemented (S0 to S8, H0 to H10 for the VPS scope, X0 to X10) |
| NOTE banner | "planned, not yet built": the multi-platform ISO, one disk, the audit work | built (X10, S1, S1b, H10); bare metal is the part that is not |
| WARNING banner | completed milestones listed up to M17; "plain TCP in dev builds only" | the later milestones are missing; release images can open a plaintext listener (P1) |
| Title and badges | "An ARM64 unikernel"; badge "pre-alpha (M17)"; target badge aarch64 only | aarch64 and x86_64; the status after v0.3.0 |
| "Why urMQTT" table | "TCP 8883 only"; remote management "None" | plus the optional plaintext listener (P1); the signed control channel (H1) and the console over MQTT (O2) exist |
| Features, Build | "Bootable UEFI ISO (Limine) for aarch64" | the universal ISO: aarch64 UEFI, x86_64 UEFI and BIOS (X10) |
| Roadmap, M11 | "SQLite in the kernel" | since H6 SQLite runs as an unprivileged worker (the Features row already says so) |
| Order list | phases 1 to 12 | misses 11b to 11e (O1/O2, O3, O4, T1) and the first-release scope of 2026-10-31 (PLAN.md) |

Other documents with stale statements found while writing this (also for separate changes):

- `docs/PROGRESS.md`: entries before S6 lost in `85605d2` (NOW-1).
- `docs/PLAN.md` line 11: "Nothing here is implemented yet."; its O1 text promises "an MQTT 5 Response Topic",
  which OPERATE.md correctly says 3.1.1 cannot carry (a fixed reply topic is used).
- ADR-253, AUDIT.md §3b, SECURITY.md "Installer entry": three production words; the code has four (NOW-5).
- ADR-063: "Not run on KVM or hardware"; the Diagnostic has since run on the netcup KVM guest (CHANGELOG).
- AUDIT.md §9: rows numbered 28, 32, 33, 34, 29 out of order (cosmetic).
- TODO.md "Milestones H0–H10, S0–S8 and X0–X16 in the order of docs/PLAN.md": all but X12 to X16 and the hardware
  parts of H8 are done.
