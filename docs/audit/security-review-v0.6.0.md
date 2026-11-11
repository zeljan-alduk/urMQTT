# Internal security review of urMQTT v0.6.0

Date: 2026-11-10 to 2026-11-11. Code reviewed: `main` at `5e4dc67` (v0.6.0). Fixes merged at `de98c6f`
(merge of `sec/integration`).

## 1. Purpose and scope

This is an internal, AI-assisted pre-audit package. It records what an internal review of v0.6.0 looked for, what it
found, what was fixed and what it did not look at, so that an external auditor can start from it instead of from
zero.

It is **not** an independent external audit.

- No independence: the reviewers and the fixers worked for the authors, and the same AI-assisted process found,
  fixed and verified the findings.
- No accreditation, no certificate, no attestation of any standard.
- No liability is taken or implied.
- No real hardware: everything ran on the host (cargo tests, fuzzers, Miri) and in local QEMU (HVF on aarch64, TCG on
  x86_64). Bare metal, real NICs, real IOMMUs and real clocks were not involved.
- No specialist cryptanalysis: the TLS and key-handling code was read for protocol and implementation errors. The
  primitives and rustls itself were assumed upstream-correct.
- Everything was tested locally against the project's own code. No production system, key, server or third-party
  service was touched.

Scope: the code in this repository at v0.6.0: kernel, network and TLS stacks, broker, authorisation, boot and
update tooling, storage, parsers, release pipeline and vendored code. See section 6 for what was left out.

## 2. Method

1. **Nine lenses**, each a separate pass over a part of the system with its own questions: supply chain and release
   signing (`supply`), TLS 1.3 and cryptography (`crypto`), authentication and authorisation (`authz`), the MQTT
   broker (`broker`), boot, A/B slots and the offline tools (`boot`), `unsafe` code and device handling (`unsafe`),
   disk and database storage (`storage`), network denial of service (`netdos`) and wire parsers (`parsers`).
2. **Proof per finding.** A candidate counted only with a reproduction: a failing test, a proof-of-concept or a
   precise code path.
3. **Independent skeptics.** Each finding was challenged by three independent skeptics with different angles
   (reachability, reproduction, impact); a finding stood when the majority confirmed it.
4. **Fixes with regression tests.** Each fix was made in its own branch with a regression test that fails on v0.6.0
   and passes after the fix, or, where the change is documentation only, with a statement that none exists. Fixes
   were merged and checked by CI (fmt, clippy for host and kernel targets, typos, shellcheck, actionlint,
   `cargo test --workspace`, the QEMU smoke groups, the release-pipeline and PKI script tests).
5. **Fuzzing alongside.** The committed fuzz targets ran in this review (for example all 42 for 300 s each in the
   parsers lens, `tls_record`, `broker_acl`, `broker_input`, `disk_keyslot`, `disk_layout`, `tcp_segment`,
   `ipv6_nd`, `source_limit`). No crash was found other than the findings below.

## 3. Results

Counts are the candidates each lens reported ("found"), those that survived the skeptics ("confirmed") and those
that were fixed. A finding found while fixing another one is included in "found" for the lens.

| Lens | Found | Confirmed | Refuted | Fixed | Open |
|---|---|---|---|---|---|
| supply | 5 | 4 | 0 recorded | 4 | 0 |
| crypto | 5 | 3 | 0 recorded | 2 | 1 |
| authz | 11 | 9 | 0 recorded | 6 | 3 |
| broker | 6 | 5 | 0 recorded | 3 | 2 |
| boot | 5 | 5 | 0 recorded | 5 | 0 |
| unsafe | 4 | 3 | 0 recorded | 3 | see below |
| storage | 8 | 6 | 0 recorded | 5 | 1 |
| netdos | 2 | 2 | 0 recorded | 2 | 0 |
| parsers | 2 | 1 | 0 recorded | 1 | 0 |
| **Total** | **48** | **38** | **0 recorded** | **31** | **8** |

Notes on the table.

- "Refuted" is 0 because the review's record lists no finding as refuted. The difference between found and
  confirmed (10 candidates) is made of information-level observations (hardening, documentation mismatches, a
  fuzzing gap, a debug-build-only assertion, a reproducibility note) that were recorded but not rated as
  vulnerabilities. See section 5.
- "Open" is the number of findings not fixed on `main` at the time of writing. It includes one extra finding made
  while fixing another one, which is in the `unsafe` row and is not part of "found". Of the 8, 7 are confirmed
  findings (38 confirmed = 31 fixed + 7 open); the eighth is that residual finding.
- Two findings (SUPPLY-2 and BOOT-1) are the same flaw reported by two lenses; the fix was unified, and both are
  counted.
- Fixed by severity: 3 high, 11 medium, 17 low. Some low findings were closed by documentation or a warning
  rather than a behaviour change; the table in section 4 says which.

### Open findings

There are **8 open findings, all low severity** (0 high, 0 medium). Details are withheld under
[VULNERABILITY-HANDLING.md](../VULNERABILITY-HANDLING.md) until each is fixed on `main`. Nothing about them is in
this repository. Their impact is limited by the severity above.

## 4. Fixed findings

Severity is the review's rating. ADR numbers are in [DECISIONS.md](../DECISIONS.md); release notes per lens are in
`docs/v0.6.1-notes/`. Changes to the configuration format number or the store schema: none.

### 4.1 supply (release pipeline and signing)

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| SUPPLY-1 | medium | `.github/workflows/release.yml` | The release signing key was reachable by third-party build code running in the same job, and any `v*` tag ran the workflow | Three jobs. `build` has no secret and read-only permissions, and first runs `scripts/check-release-tag.sh` (release tag, names `$GITHUB_SHA`, ancestor of `origin/main`). `sign` runs in a protected environment, checks out only `minisign.pub`, signs with the key on a pipe and verifies, building nothing. `publish` holds the write permissions and builds nothing. `scripts/check-release-workflow.py` enforces the shape in CI | `scripts/test-release-pipeline.sh`: 7 tag cases, the real workflow passes, 10 mutants refused | ADR-380 |
| SUPPLY-2 | medium | `release.js`, `scripts/mirror-releases.py`, `keyring.rs` | The tag claimed by the mirror was not bound to the signed trusted comment, so an older signed release could be offered under a newer tag | The tag in the trusted comment must equal the claimed tag in the builder page, the mirror and `keyring::verify`. A local file takes its tag from the signed comment | Rust `a_signed_older_release_under_a_newer_tag_is_refused`; Node `release-binding.test.mjs`; Python `test_d_a_signed_older_release_under_a_newer_tag_is_not_published` | ADR-381 |
| SUPPLY-3 | low | `urmqtt-disk slots stage` | It ignored the key ring (no tag ranges, no pins for the former test key) | `--keyring` applies ring, ranges and pins; `--pubkey` alone prints a warning; the two are exclusive | `tools/disk/tests/slots.rs` `stage_with_the_key_ring_refuses_the_former_test_key_for_a_new_tag` | ADR-382 |
| SUPPLY-4 | low | builder page `release.js` | Link URLs from the untrusted `releases.json` became hrefs unchecked | A link is kept only if it is the GitHub release or attestation page of that repository and tag; otherwise it is empty | `release-binding.test.mjs` "release links are shown only when they are the release's GitHub pages" | ADR-383 |

### 4.2 crypto (TLS 1.3 and key handling)

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| CRYPTO-1 | high | `crates/tls` server | The table of captured traffic secrets, keyed by the ClientHello random, leaked a slot per abandoned handshake; after 4096 live slots overlapping handshakes evicted each other until reboot | The global table is removed. Each session holds its own `Arc<SecretCapture>` that wipes itself on every exit path. Handshake cost unchanged (median 235/236 us after, 237/239 us before) | `crates/tls/tests/secret_capture.rs::abandoned_handshakes_do_not_break_later_overlapping_ones` (fails on v0.6.0) plus two unit tests | ADR-340 |
| CRYPTO-2 | low | `crates/tls` server | A ClientHello fragmented over several records never completed | The client random is no longer read from the raw buffer; non-TLS is decided after 6 bytes | `secret_capture.rs::a_fragmented_client_hello_completes`, `::not_a_client_hello_is_refused_after_six_bytes` | ADR-340 |

### 4.3 authz (identity, revocation, lock-out)

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| AUTHZ-1 | high | `tls/identity.rs`, `scripts/pki.sh` | The broker took the first CN of type UTF8String/PrintableString while `sign-csr` checked the first CN of any type and copied the CSR subject, so a certificate could carry another identity | A subject with more than one CN, or a CN of another string type, has no identity; so does a SAN with more than one identity URI. `sign-csr` signs its own subject and refuses CSRs without exactly one CN; `check` fails certificates with more than one CN or identity URI | `identity::tests::a_subject_with_two_cns_or_a_cn_of_another_string_type_has_no_identity`, `scripts/test-pki.sh`, fuzz seeds | ADR-360, `51610da` |
| AUTHZ-8 | medium | `tls/server.rs` | A revocation applied between the client's Certificate and Finished was not enforced on that connection | The revocation list is checked again at Finished for every handshake | `tests/handshake.rs::a_revocation_during_the_clients_flight_refuses_the_handshake` | ADR-361, `7a60b06` |
| AUTHZ-9 | medium | `crates/broker` | `disallow` did not close a TLS connection that had not sent CONNECT, and there was no CONNECT deadline | Such connections are judged too; new 60 s CONNECT deadline from open | `v5_tests::disallowing_an_identity_closes_its_connection_that_has_not_sent_connect`, `::a_connection_without_connect_is_closed_after_the_connect_timeout` | ADR-362 |
| AUTHZ-2 | medium | `crates/plain`, kernel `plain.rs`/`websocket.rs` | A successful login cleared the address's failure count, and connections opened before a lock-out were still judged, so an account holder could guess other passwords without being locked out | A login no longer touches the count; a CONNECT from a locked-out address is refused without hashing and without a new failure | `sources::tests::logins_between_failures_do_not_save_an_address_from_the_lockout`; smoke plaintext lock-out scenario | ADR-363 |
| AUTHZ-4 | low | `crates/broker` | The Will of a connection closed because its identity was revoked, disallowed or its account narrowed or removed was still published | That Will is dropped, delayed or not (the cases the kernel reports as a disallow close) | `v5_tests::a_revoked_devices_delayed_will_is_dropped`, `::a_narrowed_accounts_will_is_dropped_with_its_login` | ADR-364 |
| AUTHZ-3 | low | `crates/plain/src/auth.rs` | User enumeration by time when account hashes have different iteration counts | Every path costs the dearest count (the difference is spent on a throwaway derivation) | `auth::tests::a_cheaper_account_takes_as_long_as_an_unknown_user` | ADR-364 |

Related residual behaviour of Will handling and of the authz lens is counted in the open totals of section 3.

### 4.4 broker

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| BROKER-1 | medium | `crates/broker` flow control | A peer that never reads made the broker's own answers (PINGRESP, PUBACK, ...) grow its output buffer without bound, exhausting the heap | Parsing stops when the connection's output passes `max_outbound_bytes + max_packet_size + 4 KiB`, the window is closed, held bytes drain when it reads again; nothing is dropped; a transport that ignores the closed window is cut off | `flow_tests::a_client_that_never_reads_cannot_grow_its_output_without_bound`, `::a_held_reader_gets_every_answer_once_it_reads_again` | ADR-375 |
| BROKER-5 | medium | `topics.rs` | Device-scoped subscription filters were never freed; subscribe/unsubscribe churn grew the heap without bound | Trie nodes carry a hold count, released at unsubscribe and at session end, pruned at zero. Heap growth over 20,000 pairs: 0 B (was about 89.6 MB) | `tests.rs::scoped_filters_leave_no_nodes_behind` | ADR-376 |
| BROKER-2 | low | `crates/cfg`, `crates/config-schema`, broker | `limits.max_inflight_qos1` at 65535 or above was accepted and `alloc_pid` then looped forever | Range 1..=65535 in the schema and the validator; the broker clamps to `MAX_INFLIGHT` | `the_inflight_window_fits_the_packet_id_space`, `inflight_window_fits_the_packet_ids` | ADR-377 |

### 4.5 boot (A/B slots, offline tools, release verification)

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| BOOT-1 | medium | `keyring::verify`, builder `verifyWithKeys` | Same flaw as SUPPLY-2 (tag not bound to the signed release) reproduced in the Rust tool | Tag taken from the signed trusted comment and compared | `tools/config/tests/release_tag.rs::an_old_signed_release_is_refused_under_a_newer_tag`; `key-rotation.test.mjs` | ADR-365 |
| BOOT-2 | low | `check-release`, `slots stage` `--pubkey` | `--pubkey` trusted the former, compromised test key for any tag and content | The repository key ring is built into the tool; ring ranges and pins apply to any key in the ring | `release_tag.rs::the_former_test_key_is_held_to_the_ring_in_pubkey_mode`, `::the_built_in_ring_is_the_repository_ring` | ADR-366 |
| BOOT-3 | low | `urmqtt-disk update-boot --in-place` | On an A/B disk it skipped downgrade, schema and format rules, then resealed the slot | The new ESP's build note is required on A/B disks and the same rules as `slots stage` apply before any write; `--allow-downgrade` added | `tools/disk/tests/slots.rs::an_in_place_update_keeps_the_downgrade_rules` | ADR-368 |
| BOOT-5 | low | `configure_iso` | The configuration-format rule was skipped when an already configured template was configured again | The kernels' build note, else the unconfigured slot, else the format already in the image decides | `cli.rs::reconfiguring_a_configured_old_template_keeps_the_format_rule`; `slots.rs::the_config_tool_reads_the_build_note_like_the_store` | ADR-367 |
| BOOT-6 | low | `urmqtt-config pack --image` | The raw-image path applied no configuration-format rule | It uses the same check as BOOT-5 | `release_tag.rs::a_raw_image_is_not_configured_with_a_format_its_kernel_cannot_read` | ADR-367 |

### 4.6 unsafe (device handling, limits)

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| UNSAFE-1 | medium | `crates/pci`, kernel `devices.rs`, `memory.rs` | The MSI-X table offset was not checked against its BAR, so the kernel could map device-chosen physical memory and write MSI entries there, outside IOMMU control | `pci::msix_table` accepts only a table inside an assigned memory BAR (otherwise the device is polled); `map_mmio` refuses any range overlapping RAM-like memory-map entries | `urmqtt-pci tests::msix_table_outside_its_bar_is_refused`; QEMU `iommu` groups (aarch64 6/6, x86_64 9/9) and `mq` 2/2 pass | ADR-345 |
| UNSAFE-2 | low | config limits, kernel | `limits.max_topic_levels` was accepted up to `u32::MAX` and truncated with `as u16`; deep topics overflowed the 128 KiB data-core stack in recursive walks | Capped at 128 in the binary config and the schema; saturating narrowing of u32 limits in the kernel | `tests::topic_levels_are_capped` (cfg and schema), `topic_depth_stack.rs::deepest_allowed_topic_fits_a_data_core_stack` | ADR-346 |
| UNSAFE-3 | low | `KEnv::va` (kernel) | The safe IOMMU crate got a read-write pointer to any 8-byte-aligned physical address | `OwnedFrames` records the frames lent to each unit; any access outside them reads 0 or is dropped. `unsafe` count unchanged (937) | `owned_frames::tests::only_lent_frames_are_reachable`; IOMMU smoke groups | ADR-347 |

### 4.7 storage

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| STORAGE-1 (R060-S1) | low | `crates/store/src/disk.rs` | A torn superblock write during the first format left the data partition refused for good | The exact state a torn format leaves is treated as blank and formatted again; any other damaged superblock is still refused. Bytes written by a format are unchanged (golden image still matches) | `wrapped.rs::a_torn_superblock_write_during_the_format_is_formatted_again`, `::a_damaged_superblock_of_a_used_disk_is_still_refused` | ADR-370 |
| STORAGE-2 (R060-S2) | low | `urmqtt-disk` | Plaintext copies of an encrypted disk (conversion journal, `export-db`, `backup-extract`) were world-readable | Files are created 0600 and fsynced | `convert.rs::the_conversion_journal_file_is_owner_only`, `keys.rs::plaintext_copies_of_an_encrypted_disk_are_owner_only` | ADR-371 |
| STORAGE-3 (R060-S3) | low | key-slot change messages, docs | A passphrase change does not lock out someone holding an earlier copy of the header and the old passphrase (rewrap by design) | Documentation and messages: the disk key is unchanged; after a leak run `rekey`, then `keys add`. Accepted behaviour, not a code change | none (messages and docs); `SMOKE_ONLY=unlock` 8/8 | ADR-372 |
| STORAGE-4 (R060-S4) | low | `urmqtt-disk keys` | Low floor for offline guessing of a disk passphrase (12 characters, 300 000 PBKDF2 rounds by default, 10 000 accepted) | Mitigated by a warning for new slots below the default rounds or under 20 characters; documented in KNOWN-ISSUES. Defaults not raised, format not changed | `keys.rs::a_weak_new_slot_is_warned_about` | ADR-374 |
| STORAGE-7 (R060-S7) | low | SECURITY.md, DEPLOY.md | The docs said an image key protects a snapshot of a single-disk VPS volume; it does not | Docs reworded; `disk_key_source = "console"` recommended for that case | none (documentation) | ADR-373 |

### 4.8 netdos and parsers

| ID | Sev | Component | What was wrong | Fix | Regression test | Record |
|---|---|---|---|---|---|---|
| NETDOS-1 | high | `crates/kernel` mqtt service, `crates/tcp` | A TLS handshake refused under a zero window left a connection that was never freed; the heap filled and every new connection was refused | A 5 s close deadline (`urmqtt_net::linger::Linger`) after which the connection is dropped, its counts released and a RST sent; and, once FIN is queued, zero-window probes count toward the retry limit | `tcp` `zero_window_after_close_is_given_up` and `..._with_answered_probes_...`; `linger::tests`; QEMU `attack-zero-window-close`: 2000 handshakes, 2000 RSTs, every connection freed (unfixed kernel: 0 RSTs) | ADR-355 |
| NETDOS-2 | medium | same | The same never-finished close on the plaintext, WebSocket and metrics listeners and after any close the broker starts | Covered by the same deadline, which sits in `push_to_tcp`, the one path every close takes | shared with NETDOS-1; the QEMU scenario covers the TLS listener only, the other listeners reach the same code | ADR-355 |
| PARSERS-1 | medium | `crates/tls/src/record.rs` | TLS KeyUpdate(update_requested) answers were queued without bound; a peer that never reads exhausted the heap | One answer per silent period (RFC 8446 section 4.6.3); the receive keys still follow every request | `record::tests::key_update_requests_while_silent_get_one_answer`; `handshake.rs::many_key_update_requests_while_silent_queue_one_answer` (fails on v0.6.0 with 54000 vs 27 bytes) | ADR-350 |

## 5. Refuted and unconfirmed candidates

No candidate was recorded as refuted by a skeptic, so there are no refuted ids to list here; this document does
not invent any. The lenses reported 48 candidates and 38 were confirmed. The other 10 are information-level
observations: hardening ideas, documentation or code mismatches, a fuzzing gap, a debug-build-only assertion and a
reproducibility note (one of them, SUPPLY-5, the unpinned host clang that affects the ELF hash of a rebuild, is
already stated openly in [RELEASE.md](../RELEASE.md)). They are not counted as findings, and the ones that are
still unaddressed are withheld with the open findings until handled. An external auditor should ask for the skeptic
notes and the full candidate list: a filter whose rejects cannot be audited is weaker evidence than one whose rejects
can, and no skeptic ever refuting a candidate is itself a reason to be cautious about how hard the skeptics pushed.

## 6. Checked and found fine

Each item was read or tested and no defect found. "Checked" means what the lens did; it is not a proof.

**Supply chain and release.** Vendored `cpufeatures` and `primeorder` match upstream hashes plus the documented
hunks; the `nistz256` assembly differs from ring 0.17.14 only by the documented mechanical changes; SQLite and Limine
checksums are verified at build; `deny.toml` denies advisories, unknown sources and wildcards with an empty ignore
list; every third-party action is pinned by commit SHA; checkout never persists credentials; no `pull_request_target`
or `workflow_run`; PR-controlled values go through `env`; the Miri cache key covers path dependencies, lock file,
toolchain and flags; the key-ring handling is strict in the page and the mirror; the release workflow verifies its
signature against the committed key and checks assets for PEM keys; the builder vault (PBKDF2-SHA256 600k rounds,
non-extractable AES-256-GCM key) and the builder page's sinks and CSP; the SBOM covers vendored code.

**TLS and cryptography.** Record layer (nonce, AAD, limits, padding, sequence exhaustion, KeyUpdate), HKDF labels,
session tickets (random per-boot keys, rotation, resumption re-checks revocation), refusal of 0-RTT, TLS 1.3 only,
X25519 and P-256 input validation, ECDSA verify against RustCrypto (including 23 520 adversarial cases on aarch64),
the verification memo, RFC 6979 signing, client-certificate extended key usage, the outbound TLS client, revocation
serial handling, SYN cookies, the CSPRNG seeding rules; `tls_record` and the server-handshake fuzz targets clean.

**Authorisation.** ACL matching and `{id}` substitution, the reserved `$urmqtt` and `$SYS` namespaces, shared
subscriptions, topic aliases, session namespaces and takeover, client id equals certificate identity, restored
sessions re-checked, the control channel (strict Ed25519 over a domain-separated body, monotonic sequence, validity
window, fail closed on storage errors), run-time account rules, one PBKDF2 per attempt on every path, the lock-out
table, WebSocket origin check, retained-message ACLs.

**Broker.** The full broker test suite and the `broker_acl` and `broker_input` fuzzers; topic aliases, subscription
identifiers, outbound maximum packet size, shared and service subscription churn, inbound QoS 2 bounds, retained
byte budget.

**Boot and update.** The slot state machine and GPT validation, the kernel's trial and rollback logic, the installer
(single candidate disk, seal checked before any write), the seal pin scanner, minisign verification, `SHA256SUMS`
parsing, the key ring, the builder page's binding of verification to the selected release, loader signing refusing an
un-enrolled configuration, the boot-menu configuration. QEMU: A/B group 10/10 and installer group 4/4 pass.

**Unsafe and devices.** The `unsafe` inventory regenerates unchanged (937 sites, all justified); virtio split-queue
and driver bounds; virtio capability regions; whole-page DMA allocations; the IOMMU drivers' ring and stream-ID
bounds; kernel stack guard pages and stack probes; the panic policy; the dbworker sandbox's length clamps and
checked arithmetic; the buddy allocator.

**Storage.** Key-slot decoding, unlock and constant-time wrap check, KDF binding to disk UUID, key-slot write
ordering, XTS tweak, kernel refusal on every key/disk mismatch, schema migrations, backup restore, VFS call
surface confinement, redaction of reports and logs, console unlock; `disk_keyslot` and `disk_layout` fuzzers and the
full store suite clean.

**Network and parsers.** SYN cookies; per-address limit; out-of-order and SACK bounds; Neighbour Discovery and MLD
validation; no echo to multicast; MQTT 3.1.1 and 5.0 decoders; WebSocket upgrade and frames; HTTP request parser;
control-message decoder; TLS record limits; IPv6 extension walk; TCP options; DHCP and SNTP arithmetic; FDT and AML
scanners; metrics label escaping. All 42 committed fuzz targets ran 300 s each with no crash, timeout or out-of-memory.

On-link spoofing (ARP, Neighbour Discovery, DHCP) is possible by design and is documented in SECURITY.md; it was not
re-reported.

## 7. What was not covered, and what an external audit should look at first

Prioritised, with reasons.

1. **Everything on real hardware and real hypervisors.** No bare metal, no real NIC, IOMMU, TPM or Secure Boot chain.
   The Secure Boot group could not run locally (tools missing), so enforcement claims come from documents and tests
   not re-executed. Reason: the highest-impact boundaries (DMA, boot trust) depend on hardware behaviour that
   emulators model only partly.
2. **Live repository and site settings.** Branch and tag rulesets, the release environment and its reviewers, secret
   scopes and the live HTTP headers of the site. The release-key protection of SUPPLY-1 is only as good as those
   settings. Reason: they are configuration outside the repository and cannot be reviewed offline.
3. **Cryptography beyond the project's own glue.** Constant-time behaviour (`make ct` was not re-run), x86_64
   assembly paths of the P-256 and X25519 code (only aarch64 was exercised), rustls 0.23 and webpki internals,
   the dalek and RustCrypto crates (53 of 67 kernel-linked crate versions are cargo-vet exemptions, not audits).
   Reason: this is third-party code that dominates the trusted base.
4. **Kernel and QEMU reproductions.** Several fixes (UNSAFE-1, AUTHZ-8, AUTHZ-9, BROKER-1, BROKER-5, PARSERS-1)
   are proved at the library level and by code path, not in a running kernel with a hostile device model or
   hostile network peer. Reason: the interaction between layers is where such bugs hide.
5. **`unsafe` and architecture code in depth.** Page-table, exception and SMP code was only skimmed; Kani proofs and
   `cargo-geiger` were not run; Miri was not run on the log, IOMMU and store crates or on the slow mm tests.
   Reason: 937 `unsafe` sites with written justifications are claims to review.
6. **Fuzz gaps.** PCI configuration space, virtio-blk and SCSI parsers and crafted SQLite database files against
   the worker remain unfuzzed or unreviewed (known as H0-W8 and H0-W9 in AUDIT.md).
7. **Conformance and interop.** The tlsfuzzer run, the Paho conformance suite and line-by-line comparison with
   MQTT5-CONFORMANCE.md were not repeated; the x86 and BIOS installers and multiqueue configurations were not run
   in the QEMU groups.
8. **Load behaviour.** Shard steering and the mesh between cores under load, cost of `$SYS` and metrics rendering,
   watchdog behaviour under load, memory limits under many authenticated devices, publisher back-pressure and
   queue limits were not measured. Slowloris against each listener was not re-run.
9. **Tooling and release process.** The cargo-vet audit content beyond the policy files, the SQLite compile flags
   and libc shim surface, the emulator bundle and demo-site generator, the install scripts under `deploy/`
   (excluded by rule), and a reproducible-build run (`make repro`).
10. **The review process itself.** Section 5: the 10 information-level candidates and the skeptics' notes.

## 8. Verification of this document

The counts come from the structured results of the nine lenses and the integration step, which merged the nine fix
branches into `main` at `de98c6f`. The CI run on the integration branch head was green; the run on the merge
commit itself had started but not finished when this was written. ADR numbers and regression-test names were taken
from those results and from `docs/DECISIONS.md`; they should be re-checked with `cargo test` and CI before this
document is cited elsewhere.
