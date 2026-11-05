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

## Developer Certificate of Origin

Every commit in a pull request must be signed off. The sign-off certifies that you wrote the change, or
otherwise have the right to submit it under the project's licence, as stated in the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) (DCO).

Sign off with `git commit -s`, which adds a trailer with the name and e-mail of your git configuration:

```text
Signed-off-by: Your Name <you@example.com>
```

The rule: **every commit of a pull request carries a `Signed-off-by:` line of a real person, and that person is the
one who can make the certification.** Sign off only for yourself; never add a sign-off for someone else, and a
tool or an AI assistant does not sign off on your behalf. A commit you forgot to sign off is fixed with
`git commit --amend -s` (the last commit) or `git rebase --signoff main` (all of them), then a force-push of
your branch.

CI checks this: the Lint job fails on a pull request in which a commit has no `Signed-off-by:` trailer. The
check covers the pull request's own commits only, not the history already on `main`.

The edition boundary (which drivers belong in this repository and which may be declined) is in
[docs/EDITIONS.md](docs/EDITIONS.md).

## License

By contributing you agree that your work is dual-licensed under MIT OR Apache-2.0, like the rest of the project.
