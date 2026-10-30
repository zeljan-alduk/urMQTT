# Vendored third-party artifacts

Every artifact here is pinned to an exact version and verified against
`CHECKSUMS` before it is used.

| Directory | Content | Pinned in |
|---|---|---|
| `limine/` | Limine bootloader binaries for aarch64 UEFI (`BOOTAA64.EFI`) | M1 |
| `sqlite/` | Official SQLite amalgamation (`sqlite3.c`, `sqlite3.h`) | M11 |
| `cpufeatures-0.2.17/`, `cpufeatures-0.3.1/` | RustCrypto `cpufeatures`, patched for `target_os = "none"` (below) | X0b |

## `cpufeatures` (X0b, ADR-041 and ADR-053)

RustCrypto's `aes`, `polyval` and `sha2` ask `cpufeatures` whether a CPU
feature may be used. Upstream answers "no" on every target it cannot query
through the OS, which includes `target_os = "none"`, so the kernel ran the
portable code on every CPU (finding F1, docs/X86-PLAN.md).

Both versions in the dependency graph (0.2.17 for `aes`/`polyval`/`sha2`
0.10, 0.3.1 for `sha2` 0.11) are the crates.io sources with one change each,
in `src/aarch64.rs` only: on `target_os = "none"` the detection macro calls
the kernel symbol `urmqtt_cpu_has(name, len)`, which answers from the sealed
CPU dispatch (`crates/kernel/src/cpu_dispatch.rs`). That honours the
`[cpu] disable` opt-out and answers "no" until the dispatch is sealed. Every
other target, the hosts included, compiles exactly the upstream code.
`Cargo.toml.orig`, `.cargo-ok` and `.cargo_vcs_info.json` are not copied.

Wired in with `[patch.crates-io]` in the root `Cargo.toml` and in
`fuzz/Cargo.toml`. Upstream `.crate` SHA-256 (the files before the patch):

| Crate | SHA-256 of the `.crate` |
|---|---|
| cpufeatures 0.2.17 | `59ed5838eebb26a2bb2e58f6d5b5316989ae9d08bab10e0e6d103e656d1b0280` |
| cpufeatures 0.3.1 | `5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566` |

To review the patch: unpack the upstream crate and `diff -r` it against the
directory here. To update: copy the new version from the registry, reapply
the two hunks (the `target_os = "none"` macro and `mod urmqtt`, and the
exclusion of `target_os = "none"` from the "other targets" fallback), and
rerun the boot KATs and the `diff_*` fuzz targets.

