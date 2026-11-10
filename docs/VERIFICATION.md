# Verification tooling (H5)

What each tool covers, how to run it, and what it leaves out. Results of the
runs at the time of writing are in `docs/PROGRESS.md` (entry H5).

| Tool | Command | CI job | Covers |
|---|---|---|---|
| Miri | `make miri` (`scripts/miri.sh [crate...]`) | `miri` | Undefined behaviour and aliasing in the host unit tests of mqtt, timer-wheel, net, tcp (subset), broker (subset), ws (the WebSocket codec), tls, cfg (the configuration blob decoder) and config (the write-once `.bss` arena of the loaded configuration: its one `unsafe` module) |
| Kani | `make kani` (`scripts/kani.sh`) | `kani` | Bounded proofs: MQTT decoder, MQTT 5.0 varint and property-block lengths, TCP segment parser, TLS record header, config checks, timer-wheel arithmetic, WebSocket frame decoder and upgrade parser |
| Sanitizers | `make sanitize` (`scripts/sanitize.sh`) | `sanitize` | ASan on Rust and on the C SQLite amalgamation, trapping UBSan on the C side, over the host test suites |
| ACL fuzzer | `make acl-fuzz ACL_FUZZ_SECS=600` | `fuzz` (scheduled) | Stateful, model-checked access rules of the broker |
| ACL fuzzer, coverage-guided | `make fuzz T=broker_acl` | `fuzz` (scheduled), fuzz smoke | A second, independent ACL oracle under libFuzzer, with the QoS 2 exactly-once rules and MQTT 5.0 sessions (No Local, Retain As Published, Retain Handling, session and message expiry, the 5.0 window, 0x93; ADR-274), shared subscriptions judged on their inner filter and Subscription Identifiers (only the ones a session was given; ADR-275); also proptests in `cargo test` (one structured over 5.0 operations) |
| QoS 2 reference model | `cargo test -p urmqtt-broker --test qos2_model` | `test` | The QoS 2 state machines (both directions, reconnects, restarts through the store) against a model of MQTT 3.1.1 4.3.3 and 4.4; half the cases a 5.0 device (its Receive Maximum, the broker's, DISCONNECT 0x93) with time passing (session expiry, also across restarts); half the cases the backend receives through a shared group of one member and must see exactly the same (ADR-275) |
| Shared subscriptions reference model | `cargo test -p urmqtt-broker --test shared_model` | `test` | ADR-275: three shards wired as the kernel runs them, devices and services (5.0), every SUBSCRIBE with a fresh identifier; after each publish every shared group gets the message exactly once through one member at that member's QoS with its identifier alone, never across role classes, each session with ordinary matching subscriptions one copy with all their identifiers, a share granted iff its inner filter is allowed, the round robin even. Mutation-checked (a doubled dispatch, a class-blind group key) |
| Shared subscriptions and identifiers, unit | `cargo test -p urmqtt-broker --lib shared_tests` | `test` | ADR-275 (20 tests): identifiers per rule (one PUBLISH, retained replays, queues, persistence, turned off), groups on one shard and across three (round robin, offline members, no retained, No Local refused, the ACL on the inner filter, roles never crossed, the SUBACK and next packet held until the owner answers, a join refused by a limit, a member gone, clean and persistent members leaving with unacknowledged messages), the retained sweep, DISCONNECT 0x8B at shutdown and 0x98 on revocation, enhanced authentication refused in every form, the topic-alias accounting |
| Publisher back-pressure | `cargo test -p urmqtt-broker --lib flow_tests` | `test`, `miri` (three megabyte tests skipped) | ADR-269: pause and resume on one shard and across two wired shards, the deadlock cases (each other, a cycle of three, across shards), the bounds (500 ms, held input, overshoot), QoS 1 and 2 never paused for, a paused publisher's QoS 2 flows completing; the `broker_input` fuzz harness drives the pause, the remote notes and requests, and routes fed back with their publisher |
| The NIC's receive interrupt | `cargo test -p urmqtt-virtio --lib wake queue::tests::interrupt`, `cargo test -p urmqtt-arch-aarch64 --lib its` | `test` | ADR-270: the suppression flag and the re-check after enabling against the queue's toy device (a completion before arming is found, one after it interrupts, a flood is suppressed), the mode machine (probation with a 1 ms deadline until 3 frames verify the interrupt, polling while traffic is recent, a working interrupt kept over 10 000 sleeps, a silent one and one that works for some frames only falling back), the ITS's register values, table sizing and command encodings; on QEMU the smoke group `net_irq` (interrupt and forced polling with traffic, aarch64 HVF/TCG and x86_64 TCG) |
| virtio-net multiqueue with RSS | `cargo test -p urmqtt-virtio --lib net::`, `cargo test -p urmqtt-net --lib rss`; `make fuzz T=virtio_net_mq`; `SMOKE_ONLY=mq scripts/smoke.sh` (and `--arch x86_64`; the tap part on Linux as root or with sudo, or with `URMQTT_MQ_DOCKER=<image>`) | `test`, `fuzz`, smoke group `mq` where it runs | ADR-310 to ADR-314: negotiation only with MQ, the control queue and RSS, every device field checked, the RSS command's layout, pairs handed out only after the device's OK, refusals and silence leaving one pair, hostile completions on a taken pair; the kernel's table and the device's agree for every hash; in QEMU (multi-queue tap, software RSS, TCG) each worker receives its flows on its own pair with none forwarded, the receive interrupt verified per pair on x86_64 and on aarch64 with a GICv2m frame, and the fallback to one pair on QEMU's user network and with one data core. Not covered: a KVM host, vhost with eBPF RSS |
| MQTT 5.0 interoperability | `scripts/mqtt5-conformance.sh --boot` | by hand (MQTT5-CONFORMANCE.md); `mqtt5-conformance` (optional, `workflow_dispatch`, development port under TCG) | The Eclipse Paho interoperability suite (`client_test5.py`, `client_test.py`) against a booted broker, each test in its own process, against an expected-failure list |
| A/B boot slots under power cuts | `cargo test -p urmqtt-store --lib slots`, `cargo test -p urmqtt-disk-tool --test slots`; `make fuzz T=boot_slots`; `SMOKE_ONLY=ab scripts/smoke.sh` (and `--arch x86_64`, `--arch universal`) | `test`, `fuzz`, smoke group `ab` | ADR-295 to ADR-299: the first boot that reserves the standby, staging, activation, the kernel's trial count, confirmation, the automatic switch back and the operator's rollback, each cut at every write (clean and torn, the volatile cache lost and kept); the state read by firmware afterwards is the old one or the new one. In QEMU (edk2 aarch64, OVMF x86_64): the offline switch cut after writes 1 to 3, the trial count after writes 1 and 3, a bad update rolling back, the control messages; the universal image's staged slot booted on x86_64 BIOS and UEFI and aarch64. Not covered: power cuts on the BIOS path, a real VPS |
| Key slots: a disk key that is not in the image | `cargo test -p urmqtt-store --lib keyslot`, `cargo test -p urmqtt-store --test wrapped`, `cargo test -p urmqtt-disk-tool --test keys`; `make fuzz T=disk_keyslot`; `SMOKE_ONLY=unlock scripts/smoke.sh` (and `--arch x86_64`) | `test`, `fuzz`, smoke group `unlock` | ADR-325 to ADR-329: RFC 3394 key wrap vectors, every edit of the header (with and without a valid CRC) refused or yielding the disk's own key, a passphrase change cut at every write (clean and torn, the cache lost and kept) leaving the old or the new passphrase, never neither, and no superblock with the old wrap once the next open scrubs it. In QEMU (aarch64 HVF and TCG, x86_64 TCG): the passphrase typed twice on the serial console at the first boot, nothing listening before it, a wrong one, `change` at the prompt, an edited header refused. Not covered: the VNC keyboard path with a passphrase, a real VPS console |
| Coverage | `make coverage` (`scripts/fuzz-coverage.sh`) | none | Line coverage of fuzz targets |

## Miri

`scripts/miri.sh` runs the lib tests of mqtt, timer-wheel, net, tcp, broker,
ws, tls, cfg and config under Miri with `-Zmiri-strict-provenance
-Zmiri-disable-isolation` (config adds `-Zmiri-ignore-leaks`) and
`PROPTEST_CASES=6`.

**Runner (ADR-262).** `MIRI_RUNNER=nextest` (the default when cargo-nextest
is installed) runs `cargo miri nextest run`: one Miri process per test,
`MIRI_JOBS` at a time (default 2; CI sets 4, the runner's vCPUs), every test
printed with its time. `MIRI_RUNNER=libtest` is the old runner (`cargo miri
test`, one process per crate, the tests one after another on one core) for a
machine without nextest. Both take the same skip lists and run the same tests.
`MIRI_PARTITION=count:K/N` (nextest only) runs a share of each crate's tests.

**One test under Miri:** `MIRI_JOBS=1 scripts/miri.sh urmqtt-tls` runs a
crate; for a single test, `cargo miri nextest run -p urmqtt-tls --lib -E
'test(=record::tests::alerts)'` or `cargo miri test -p urmqtt-tls --lib --
--exact record::tests::alerts` with the `MIRIFLAGS` above.

**Negative control.** `scripts/miri.sh --negative-control` runs
`urmqtt-config`'s `miri_negative_control::deliberate_use_after_free_must_be_reported`
(compiled only under Miri, `#[ignore]`d) and fails unless Miri reports
"Undefined Behavior" for it. Every CI Miri job runs it after its crates, with
the same runner and toolchain.

**Result cache (CI only).** Each Miri job computes `scripts/miri-cache-key.sh
<crates>`: a SHA-256 over the tracked files of the crates and of every path
package they build with (normal, build and dev dependencies, transitively, the
vendored crates included), the workspace `Cargo.toml`, `Cargo.lock`,
`.cargo/config.toml`, `rust-toolchain.toml`, `scripts/miri.sh`, the key script,
`scripts/gen-dev-certs.sh`, `rustc -vV`, `cargo miri --version`, the nextest
version, `MIRIFLAGS`, `PROPTEST_CASES`, `MIRI_RUNNER`, `MIRI_PARTITION` and the
OS and architecture. A job that finds a marker saved under exactly that key
(`actions/cache`, no prefix match) reports "cached" with the run that wrote it
and runs nothing. The marker is saved only by a job whose Miri step and
negative control both passed. What the key cannot see: the generated
development certificates (the generator is hashed, its random output is
not), the runner image (system libraries), and proptest's random seeds (a
cached green does not retry new seeds; the fuzzers and `cargo test` do).
Bypass: run the CI workflow by hand (`workflow_dispatch`) with `miri-cache`
off, or delete the `miri-ok-*` caches (`gh cache delete`).

**Shrunk under Miri only** (same code, fewer iterations; `cargo test` runs the
full size): tls `server::capture_tests::the_bound_evicts_the_oldest_and_wipes_it`
(`MAX_CAPTURED` is 64 under Miri instead of 4096: the table fills through a
linear scan per insert, more than 10 minutes under Miri on an Apple M4 Pro at
4096) and tls `identity::tests::the_light_serial_reader_agrees_with_the_full_decoder`
(40 random corruptions per certificate instead of 400; 534 s under Miri).

Excluded, and why:

- `store` (SQLite, VFS, libc shims): Miri cannot execute C. `make sanitize`
  covers it.
- `kernel`, `arch-*`, `virtio`, `pci`, `platform`: bare-metal code (inline
  asm, MMIO); no host test target.
- tcp `model::` (stateful proptest) and `tests::` (loss, flood, retransmission
  simulations) and `table::behaves_like_a_map_under_churn`: each ran for more
  than 25 minutes under Miri without finishing. Only `cookie::`, `refused::`,
  `scripts::`, `seq::`, `siphash::` run.
- net `rss::one_source_address_spreads_over_the_workers`: 750 000 Toeplitz
  hashes (`cfg_attr(miri, ignore)`).
- broker: `compact::` (60 000-step loop) and the tests with hundreds of
  retained messages or 10 000 iterations (see the skip list in the script).
- All integration tests under `tests/`: they read files, start processes or
  need minutes of CPU. The ACL fuzzer is one of them.
- tls `provider::`, `kat::`, `bench::`, `probe::`: P-256 and X25519 arithmetic
  and known-answer vectors (`provider::` alone ran 55 minutes under Miri). The
  crate is `forbid(unsafe_code)`; the assembly is in urmqtt-nistz256 and
  x25519. They run natively in `cargo test`.
- cfg: the `passwd::tests::` hashing tests and the tests that hash an account
  password (PBKDF2, at least 1000 iterations per hash, ADR-229) and
  `garbage_never_panics` (20 000 cases, the fuzz target's job): 13 of 47, see
  the list in the script; Miri keeps `long_keys_are_hashed_first` and
  `hmac_matches_rfc_4231_case_2`. They run natively in `cargo test`. Until
  ADR-262 seven of these skips were written `passwd::<name>`, matched nothing,
  and those seven PBKDF2 tests ran under Miri.

## Kani

Install: `cargo install --locked kani-verifier && cargo kani setup` (Kani
0.68.0, CBMC 6.11.0 here). The harnesses are in `crates/*/src/proofs.rs`
behind `#[cfg(kani)]`. `scripts/kani.sh` caps every harness (`KANI_TIMEOUT`,
default 3 minutes). **A harness that hits the cap is NOT PROVEN, not passed.**
The script keeps a list of the harnesses documented below as NOT PROVEN (`KNOWN_NOT_PROVEN` in `scripts/kani.sh`): they are reported with their name on every run and do not fail it; any other harness that fails, and any failure with a counterexample, does. `tcp::parse_any_segment` is proven on an Apple M-series machine but does not finish within 3 minutes on the 4-core CI runner, so it is on that list too (a fifth NOT PROVEN, in CI only).

Bounds are part of the claim. Each is stated in the harness file. Status
at the time of writing (Kani 0.68.0, Apple M-series, 3 minute cap):

| Harness | Bound | Status |
|---|---|---|
| tls `record_len_any_prefix` | any prefix of up to 6 bytes | PROVEN |
| tcp `parse_any_segment` | any segment of up to 28 bytes, any addresses | PROVEN: no panic or out-of-bounds, accepted data offset inside the segment |
| timer-wheel `slot_of_is_always_a_valid_slot` | every `now` below 2^62, every deadline | PROVEN |
| timer-wheel `skip_target_moves_forward_within_limit` | same | PROVEN |
| mqtt `decode_any_short_input` | 6 bytes, any limits | NOT PROVEN: CBMC timed out (also at 10 bytes, 3 min) |
| mqtt `v5::proofs::varint_round_trip` | every u32 | PROVEN: values up to 268 435 455 encode in `varint_len` bytes and decode back, larger ones are refused |
| mqtt `v5::proofs::read_varint_any_bytes` | any 5 bytes, any prefix | PROVEN: an accepted varint is in range, 1 to 4 bytes, inside the input, minimal |
| mqtt `v5::proofs::property_length_arithmetic` | one property, up to 5 bytes, every identifier | PROVEN (34 s) with the UTF-8 and topic-name checks stubbed (`-Z stubbing`; they keep the length): parsing never panics and consumes exactly `encoded_len`. A whole 6-byte block in any context timed out at 8 min, with or without the string identifiers |
| mqtt `decode_typed_packets` | CONNECT/PUBLISH/SUBSCRIBE/UNSUBSCRIBE, 6-byte body | NOT PROVEN: timed out (also at a 14-byte body, 3 min) |
| config `parse_rate_any_short_string` | 5 bytes | NOT PROVEN: timed out at 2 min |
| config `check_topic_filter` | 5 bytes | NOT PROVEN: timed out at 2 min |
| timer-wheel behaviour (fires once, not early, cancel, slot reuse) | 6 to 200 ticks | NOT PROVEN: no result after 7 to 28 min, up to 17 GB; harness dropped |

The NOT PROVEN harnesses stay in the tree as a starting point (the mqtt and
config ones); they fail the `kani` CI job until a cheaper formulation
(stubbing the UTF-8 and `format!` paths, smaller bounds, `kani::unwind` per
loop) lets CBMC finish. The TLS record layer proper needs the AEAD code and
is out of reach for bounded model checking.

Kani ships its own `rustc`, older than the pinned nightly. `scripts/kani.sh`
lowers the workspace `rust-version` for the run and restores `Cargo.toml` on
exit (ADR-120).

## Sanitizers

`scripts/sanitize.sh` builds the host test suites with `-Zsanitizer=address`
and an explicit `--target` (build scripts stay uninstrumented), and compiles
the SQLite amalgamation with `-fsanitize=address,undefined
-fsanitize-trap=undefined` through `CFLAGS`. rustc has no UBSan, so UBSan
covers C only; Miri covers Rust UB. On macOS the LeakSanitizer is not
available (`detect_leaks=0`); on Linux it is on. Apple clang references an
ASan version-check symbol that rustc's LLVM runtime lacks; the script
defines it as a no-op.

## ACL fuzzer

`crates/broker/tests/acl_model.rs`. Random operation sequences (connect with
and without a TLS identity, bootstrap identities, wills, publish, subscribe,
unsubscribe, close, tick, QoS 1 acknowledgements) drive a `Broker` with
fan-out and persistence on. Every message carries a tag that names publisher,
topic and the oracle's verdict, and everything the broker hands out is
checked: deliveries, routes to other shards, telemetry, persist operations,
control messages, `$SYS` requests. Invariants:

1. a device receives only `devices/<own id>/cmd/...`; only an authenticated
   operator receives `$SYS/...`; nobody receives `$urmqtt/...`;
2. a message the oracle forbids appears nowhere;
3. control messages come only from a control identity, `$SYS` requests only
   from an authenticated operator;
4. a TLS identity cannot connect under another client id; a will the
   publisher could not publish is refused; persisted subscriptions never
   cover `$urmqtt` or give `$SYS` to a non-operator.

The oracle does not use `acl.rs`. It was checked to be live by a deliberate
mutation (`reserved()` made to match nothing): it failed within the first
seeds. A failure prints its seed; replay with `ACL_FUZZ_SEED=<n>
ACL_FUZZ_SECS=0`. It runs for 3 s in `cargo test`.

Not modelled: byte-level mutation (the `broker_input` fuzz target does that),
QoS 2 (`broker_acl` and `qos2_model.rs` do), retained delivery order, ACL changes at runtime, sharding beyond the
route hand-out.

### The second oracle: `broker_acl`

`crates/broker/tests/acl_oracle/`, written apart from `acl.rs` and from
`acl_model.rs`. It decodes bytes into a structured operation sequence over
four connection slots and ten identities (two devices, a control service, a
service without control rights, a `*`-prefix service and the device next to
it, bootstrap certificates named like a device and like the control service,
the invalid ids `+` and `a/b`): connect (spoofed client id, clean or
persistent, will), publish (QoS 0/1/2, retain, empty), subscribe,
unsubscribe, ack, DISCONNECT, abrupt drop, tick, ping, garbage bytes,
`restore_session`, `restore_retained`, `disconnect_identity` and
`route_remote`. Two drivers share it: the cargo-fuzz target
`fuzz/fuzz_targets/broker_acl.rs` and the proptest
`crates/broker/tests/acl_invariants.rs` (fixed seed, in `cargo test`, which
also replays every file of `fuzz/seeds/broker_acl/`), so a fuzz finding
replays as a unit test.

The rights are restated as predicates over topic levels, and a filter is
judged by enumerating every topic of up to four levels over a 13-symbol
alphabet rather than by `covers`. The test ACL grants `$urmqtt/#` and
`$SYS/#` in every rule list on purpose; no operator is configured, so `$SYS/`
must stay closed to all. Checked after every step: the exact counter deltas of
each publish (`published`, `dropped_acl`, `control_received`,
`dropped_control`); control messages only from `svc` on the exact topic and
never from a bootstrap session of that name; no `$SYS` request; every
delivery (live, queued, retained replay, will, remote, restored) inside the
receiver's rights and a granted filter, never reserved, never `$SYS`, never
another device's topic, and from an allowed publisher; a SUBACK grant only
for a filter wholly inside the rights; CONNACK codes and `session_present`
against a session model; RETAIN only on a replay for the receiver's own
SUBSCRIBE (during it, or at QoS 1 and 2 later from the queue or again after a
reconnect) and only on a message published, willed or restored retained; unacknowledged QoS 1 and QoS 2 within `max_inflight`; retained count and
bytes within the limits. QoS 2 (ADR-271): the oracle holds each session's QoS 2
ids (across reconnects, takeovers and restores, with the operations `Release`
and `Dup`) and checks that a PUBLISH with a held id is answered and neither
routed nor counted, that one id too many closes, that every PUBREC answers a
held id and every PUBREL is answered, that a message reaches a session in one
flow only (again only with DUP and its id, never after our PUBREC) and that a
broker PUBREL follows our PUBREC. Garbage on a connection ends those checks
for its session: from then on the broker may read any packet, a PUBREL among
them, in what the connection sends. Likewise, after garbage on a connection the
oracle no longer judges the broker's PUBREL against its own PUBRECs, its PUBCOMP
against its own PUBRELs, or that connection's window: the garbage may itself be a
well-formed PUBREC, PUBREL, PUBACK or PUBCOMP that the broker answers as 4.3.3
requires (seeds `qos2_pubrec_inside_garbage`, `qos2_pubrel_inside_garbage`,
2026-11-08; and a PUBREC in garbage for an id not in flight, answered with
PUBREL while the id stays free: `qos2_pubrec_for_a_free_id_in_garbage`); and a `Dup` sent while the session's ids are not known may be a new
message to the broker, so its payload is then judged by the publisher's rights
(seed `qos2_dup_of_an_unknown_id`). Garbage never starts with a SUBSCRIBE either:
the oracle pairs every SUBACK with its own SUBSCRIBE.

### QoS 2 against a reference model

`crates/broker/tests/qos2_model.rs` (proptest, 400 cases, fixed seed, in
`cargo test`): random sequences of a persistent device (QoS 2 publishes with
chosen ids and DUP, PUBREL, PUBACK, PUBREC and PUBCOMP for any id, drops, clean
and persistent reconnects) and of the system (a backend commanding at QoS 0, 1
and 2, a restart from a model of the store while the device is away) run
against the broker and a small model written from 4.3.3 and 4.4. After every
step the packets both clients received must be the model's, exactly, and every
device publish must reach the backend once. Checked to be live with six
hand-made mutants of the broker (no deduplication; no release at PUBREC; no
PUBREL on a resend; PUBREL forgetting the wrong id; a snapshot that loses a
held id; one that loses an in-flight id): each fails it at once. Not modelled:
several devices, the ACL, retained messages and wills (the unit tests and
`broker_acl` cover them).

Not modelled: the operator role and `$SYS` requests (`acl_model.rs` has
them), the plaintext role, queue contents (only their bounds), the rate
limiter (`rate_tokens` is set out of reach), a retained replica from another
shard (`route_remote` is sent without retain).

## Coverage

`scripts/fuzz-coverage.sh` grows a corpus per target for `FUZZ_SECS` (default
20) from `fuzz/seeds`, replays it with `cargo fuzz coverage` and reports the
lines of the source files the target is about (`llvm-cov export`). The
corpus lives in a temp directory.

## MQTT over WebSocket (ADR-272)

The `urmqtt-ws` crate is checked five ways, each for something the others miss:

- **Host tests** (`cargo test -p urmqtt-ws`): RFC 6455's examples (the `Sec-WebSocket-Accept` of section 1.3, the
  masked frames and length encodings of section 5.7), RFC 3174's SHA-1 vectors and padding boundaries, every refusal
  of the upgrade and every violation of the framing with its close code, and three properties: any split of a valid
  stream gives the same events, no input panics, any accepted request has a well-formed answer.
- **Fuzzing**: `make fuzz T=ws_upgrade` (any request under three paths and three origin lists; what is accepted is a
  complete request for the configured path and gets a well-formed 101) and `make fuzz T=ws_frames` (the decoder
  against itself: the same events and verdict however the stream is cut, no message over its limit, no payload it
  was not fed). Seeds in `fuzz/seeds/ws_*`. At ADR-272: 180 s each; `ws_upgrade` found the `mqttv3.1` response
  overflowing its buffer (fixed), then ran clean; `ws_frames` 21.8 million runs, clean.
- **Kani** (`scripts/kani.sh urmqtt-ws`): proven: `scan` on any 8 bytes, every server header length. **Not proven**
  (listed in `KNOWN_NOT_PROVEN`): the decoder on any 6-byte stream in two feeds and `parse` with a 2-byte symbolic
  header line; CBMC does not finish them within the 3-minute cap (larger bounds were tried first). The fuzz targets
  are what covers those two parsers.
- **Miri**: the lib tests (the long-frame test runs two sizes under Miri).
- **Autobahn|Testsuite** (conformance of the codec): `cargo run --release -p urmqtt-ws --example echo -- 0.0.0.0:19301`
  and `docker run --rm -v $PWD/docs/audit/ws-autobahn:/config -v /tmp/reports:/reports
  crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json` (the URL in the spec is
  `ws://host.docker.internal:19301`). Results and every deviation: [audit/ws-autobahn.md](audit/ws-autobahn.md).

End to end, the smoke group `websocket` (`SMOKE_ONLY=websocket scripts/smoke.sh [--arch x86_64]`) runs
`scripts/ws-scenarios.py` (paho-mqtt over wss and a raw client) against the kernel in QEMU.

### The Prometheus endpoint (NEXT-9, ADR-290 to ADR-294)

`urmqtt-http` (the request reader) and `urmqtt_broker::metrics` (the exposition) are checked four ways:

- **Host tests** (`cargo test -p urmqtt-http`, `cargo test -p urmqtt-broker metrics`): every refusal of the request
  reader (405, 505, 400 for a body, chunking, bare LF, folding, a second `Content-Length`, 431), the negotiation of the
  format by quality value (Prometheus 2 and 3 headers, malformed values), the bounds, `scan` over every prefix, properties
  over arbitrary and mutated bytes; for the exposition: **every `$SYS` topic has exactly one metric or a stated reason**
  (with both listeners on, at 1, 4 and 64 cores) and every rule matches a topic; the rules are well formed (names,
  `_total` on exactly the counters, base units, bounded label names, no family split in two runs, no duplicate
  series); a strict reader of both text formats accepts the output and finds the same series in both; the numbers
  are the `$SYS` numbers (spot checks of every family); unknown values are absent; label values are escaped; the series do not
  depend on the traffic; the size is bounded.
- **Configuration** (`cargo test -p urmqtt-cfg -p urmqtt-config -p urmqtt-config-schema -p urmqtt-config-tool`, `make builder-test`):
  defaults write nothing and keep the old format; any key set is format 16; ranges, the required allow-list, the port
  collisions; the TOML path and the blob check agree over a grid; templates of earlier releases refuse the section.
- **Fuzzing**: `make fuzz T=http_request` (any bytes: `scan` and `parse` agree on what a request is, whatever is
  accepted is a GET or HEAD for an ASCII target with no bare LF and no `Transfer-Encoding`, every refusal is a fixed
  answer, the same prefix gives the same `scan`) and `make fuzz T=metrics_render` (arbitrary numbers and text in every
  `Info` field: every line is a comment or a sample, label values never split a line). Seeds in
  `fuzz/seeds/http_request` (25) and `fuzz/seeds/metrics_render`. At ADR-290: 120 s each; `http_request` found the
  bare-LF delimiter disagreement (fixed) and then ran 15.4 million executions clean; `metrics_render` found an unchecked
  addition in `sys::by_code` (now saturating) and then ran 125 000 executions clean (each renders twice).
- **End to end**, the smoke group `metrics` (`SMOKE_ONLY=metrics scripts/smoke.sh [--arch x86_64]`) runs
  `scripts/metrics-scenarios.py` (standard library only) against the kernel in QEMU: the text, OpenMetrics by `Accept`,
  `HEAD`, nine refusals, one answer for two pipelined requests, a request in five pieces, a slowloris cut at the
  deadline, the per-address limit, the endpoint's own counters, the numbers against the info query and a retained
  `$SYS` topic read by the operator, counters that follow 25 real publishes, and a second image whose allow-list does
  not cover the host and gets not one byte.

