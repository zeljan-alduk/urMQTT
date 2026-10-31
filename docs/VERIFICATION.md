# Verification tooling (H5)

What each tool covers, how to run it, and what it leaves out. Results of the
runs at the time of writing are in `docs/PROGRESS.md` (entry H5).

| Tool | Command | CI job | Covers |
|---|---|---|---|
| Miri | `make miri` (`scripts/miri.sh [crate...]`) | `miri` | Undefined behaviour and aliasing in the host unit tests of mqtt, timer-wheel, net, tcp (subset), broker (subset), tls |
| Kani | `make kani` (`scripts/kani.sh`) | `kani` | Bounded proofs: MQTT decoder, TCP segment parser, TLS record header, config checks, timer-wheel arithmetic |
| Sanitizers | `make sanitize` (`scripts/sanitize.sh`) | `sanitize` | ASan on Rust and on the C SQLite amalgamation, trapping UBSan on the C side, over the host test suites |
| ACL fuzzer | `make acl-fuzz ACL_FUZZ_SECS=600` | `fuzz` (scheduled) | Stateful, model-checked access rules of the broker |
| Coverage | `make coverage` (`scripts/fuzz-coverage.sh`) | none | Line coverage of fuzz targets |

## Miri

`scripts/miri.sh` runs `cargo miri test --lib` with `-Zmiri-strict-provenance
-Zmiri-disable-isolation` and `PROPTEST_CASES=6`. Excluded, and why:

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

## Kani

Install: `cargo install --locked kani-verifier && cargo kani setup` (Kani
0.68.0, CBMC 6.11.0 here). The harnesses are in `crates/*/src/proofs.rs`
behind `#[cfg(kani)]`. `scripts/kani.sh` caps every harness (`KANI_TIMEOUT`,
default 3 minutes). **A harness that hits the cap is NOT PROVEN, not passed.**

Bounds are part of the claim. Each is stated in the harness file. Status
at the time of writing (Kani 0.68.0, Apple M-series, 3 minute cap):

| Harness | Bound | Status |
|---|---|---|
| tls `record_len_any_prefix` | any prefix of up to 6 bytes | PROVEN |
| tcp `parse_any_segment` | any segment of up to 28 bytes, any addresses | PROVEN: no panic or out-of-bounds, accepted data offset inside the segment |
| timer-wheel `slot_of_is_always_a_valid_slot` | every `now` below 2^62, every deadline | PROVEN |
| timer-wheel `skip_target_moves_forward_within_limit` | same | PROVEN |
| mqtt `decode_any_short_input` | 6 bytes, any limits | NOT PROVEN: CBMC timed out (also at 10 bytes, 3 min) |
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
QoS 2, retained delivery order, ACL changes at runtime, sharding beyond the
route hand-out.

## Coverage

`scripts/fuzz-coverage.sh` grows a corpus per target for `FUZZ_SECS` (default
20) from `fuzz/seeds`, replays it with `cargo fuzz coverage` and reports the
lines of the source files the target is about (`llvm-cov export`). The
corpus lives in a temp directory.
