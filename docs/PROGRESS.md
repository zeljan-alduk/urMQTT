# Progress log

One entry per milestone: what was done, what was measured and the known gaps.
Milestones are defined in [PROMPT.md §9](../PROMPT.md#9-milestones-and-acceptance-criteria).

## M0 — Workspace and tooling (2026-10-28)

**Done**

- Cargo workspace with every crate from §4.2 (package names `urmqtt-*`, ADR-006), a pinned nightly (ADR-002), the shared release profile (fat LTO, `codegen-units = 1`, `panic = "abort"`, `opt-level = 3`) and a committed `Cargo.lock`.
- Lint policy:
  - `forbid(unsafe_code)` in `mqtt`, `broker`, `timer-wheel` and `config`; `deny(unsafe_code)` elsewhere.
  - `deny(unwrap_used, expect_used, indexing_slicing, panic)` in the data-path crates.
  - `undocumented_unsafe_blocks = deny` workspace-wide.
- `crates/config` with `crates/config-schema` (ADR-005), **fully implemented**:
  - `deploy/<env>/config.toml` is parsed, validated (every key from §12 plus `limits.max_topic_levels`), rendered to typed constants, and the certificates are embedded with `include_bytes!`.
  - Invalid configuration fails the build with every error listed by key path.
  - Plaintext MQTT is rejected outside `dev`.
- `scripts/gen-dev-certs.sh`: dev CA, server certificate, `device-001..003`, plus a rogue-CA device and an expired device for the M10 negative tests. The script self-verifies the chains.
- Makefile: every target from §3 exists. Targets that belong to later milestones exit with status 1 and name their milestone.
- Fuzz target `config_parse` (cargo-fuzz).
- CI on GitHub Actions (ADR-007):
  - lint (fmt, clippy for host and `aarch64-unknown-none`, typos, actionlint, shellcheck),
  - host tests on Linux arm64 and macOS arm64,
  - kernel build for the dev and prod configs,
  - cargo-deny and a 60 s fuzz smoke run,
  - scheduled 10-minute fuzzing, CodeQL and OpenSSF Scorecard,
  - Dependabot, and a tag-triggered release with SLSA provenance.

**Measured**

- `make check`: green on macOS 26.3 / Apple M4 Pro.
- Host tests: 27 (all in `urmqtt-config-schema`).
- `config_parse` fuzzing: 525 257 runs in 21 s, no crash.
- Kernel ELF (release, M0 skeleton): **1 360 bytes**. The number is not meaningful yet, because nothing is linked except the placeholder entry.

**Known gaps (explicit stubs)**

- All crates except `config` and `config-schema` are empty stubs whose docs name their milestone.
- `_start` in `crates/kernel` only parks the CPU. The Limine entry arrives in M1.
- `make iso`, `run`, `run-tcg`, `run-smp`, `debug`, `smoke` and `loadtest` are not implemented yet and exit with status 1.
- `make data-img` creates a blank sparse image only. The superblock/region layout arrives in M11.
- `tools/loadgen` exits with an explicit "not implemented" error. `tools/certgen` (optional) was not created, because `gen-dev-certs.sh` covers it.
- `vendor/limine` and `vendor/sqlite` are empty and get populated in M1 and M11.
