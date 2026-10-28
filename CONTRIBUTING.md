# Contributing to urMQTT

Thanks for your interest! urMQTT follows the specification in
[PROMPT.md](PROMPT.md) milestone by milestone. Please read it, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), before proposing larger changes.

## Setup

```bash
brew install qemu xorriso llvm mosquitto     # macOS; Linux: qemu-system-arm xorriso clang mosquitto-clients
rustup toolchain install                     # installs the pinned toolchain from rust-toolchain.toml
make certs                                   # dev certificates (git-ignored)
make check                                   # fmt, clippy (host + bare metal), tests
```

## Rules that reviews enforce

- **No panics on external input.** No `unwrap`, `expect`, unchecked indexing or `panic!` on data from the network or disk. Clippy denies these in data-path crates.
- **`unsafe` is allowed only** in `arch-aarch64`, `mm`, `pci`, `virtio`, `store` and minimal `kernel` glue. Every block needs a `// SAFETY:` comment.
- **No allocation in the hot path** after a connection is established, except from per-core slabs and pools. Allocation failure closes the connection.
- **Every atomic `Ordering`** gets a comment explaining why it is correct on a weakly ordered CPU.
- **No magic numbers.** Limits come from `urmqtt-config`.
- **No fake progress.** Intentional stubs return explicit errors and are listed in `docs/PROGRESS.md`.
- Non-obvious decisions get an ADR in `docs/DECISIONS.md`.
- New parsers come with a fuzz target in `fuzz/`.

## Commits and pull requests

- Small, reviewable commits. Do not reformat unrelated code.
- Milestone commits use `M<n>: <summary>`. Other commits use a short imperative subject.
- CI must be green: lint, host tests (Linux and macOS arm64), kernel build, cargo-deny and fuzz smoke.

## License

By contributing you agree that your work is dual-licensed under MIT OR Apache-2.0, like the rest of the project.
