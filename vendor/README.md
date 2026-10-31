# Vendored third-party artifacts

Every artifact here is pinned to an exact version and verified against
`CHECKSUMS` before it is used.

| Directory | Content | Pinned in |
|---|---|---|
| `limine/` | Limine bootloader binaries for aarch64 UEFI (`BOOTAA64.EFI`) | M1 |
| `sqlite/` | Official SQLite amalgamation (`sqlite3.c`, `sqlite3.h`) | M11 |
| `cpufeatures-0.2.17/`, `cpufeatures-0.3.1/` | RustCrypto `cpufeatures`, patched for `target_os = "none"` (below) | X0b |
| `primeorder-0.14.0/` | RustCrypto `primeorder`, fixed-base table without `std` (below) | PERF |
| `nistz256/` | P-256 assembly for x86_64 (OpenSSL/Intel `nistz256`, via ring) and the generator's comb table (below) | PERF |

## `cpufeatures` (X0b, X9; ADR-041, ADR-053, ADR-070)

X9 adds the same patch for x86 (`src/x86.rs`, `src/lib.rs`): on `target_os = "none"` the detection macro takes the runtime path and answers from the kernel (`urmqtt_cpu_has`), except for features the target enables at build time, which are true. `mod x86` is `pub` so the macros can reach `x86::urmqtt`.

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


## `primeorder` 0.14.0 (PERF; ADR-110, ADR-111)

`vendor/primeorder-0.14.0` is the crates.io source with one file changed, `src/tables/basepoint.rs`: the basepoint table's lazy cell is an atomics-only once-cell instead of `std::sync::LazyLock` / `once_cell` + `critical-section` (the `compile_error!` that required one of them is removed), and `BasepointTable::from_point` builds the table of an arbitrary point eagerly (trust-anchor keys). No arithmetic changed. `Cargo.toml.orig`, `.cargo-ok`, `.cargo_vcs_info.json` and `Cargo.lock` are not copied. Wired in with `[patch.crates-io]` in the root and `fuzz/` manifests. Upstream `.crate` SHA-256: `5c9f42978c78a00e3d68f69fc03e57a234debae69da4020a4fb588fcdcd07b06`. To review: unpack the upstream crate and `diff -r` against the directory. To update: copy the new version and reapply the two hunks, then rerun the boot KATs and `cargo test -p urmqtt-tls`.


## `nistz256` (PERF; ADR-130)

Source: the pregenerated GNU-assembler output `pregenerated/p256-x86_64-asm-elf.S` and the table `crypto/fipsmodule/ec/p256-nistz-table.h` of **ring 0.17.14** (crates.io `.crate` SHA-256 `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`). ring generates the assembly from BoringSSL's `p256-x86_64-asm.pl`, which is OpenSSL's `ecp_nistz256-x86_64.pl`: Copyright 2014-2016 The OpenSSL Project Authors, Copyright (c) 2014 Intel Corporation, Copyright (c) 2015 CloudFlare, Inc.; originally by Shay Gueron and Vlad Krasnov. **License: Apache-2.0** (the header of every file says so; the text is `vendor/nistz256/LICENSE-BoringSSL`, which is ring's copy of BoringSSL's license file and begins with the Apache License 2.0). Apache-2.0 is the license of this workspace's own dual license, so redistribution needs only this notice and the preserved headers.

| File | Content | SHA-256 |
|---|---|---|
| `p256-x86_64-asm.S` | Montgomery 4x64 field multiplication/squaring (MULX/ADX and plain `mul`), order-field multiplication/squaring, point doubling/addition/mixed addition, constant-time table selection | `24476bdfe4332ec153aad78ddc38e3d987cf80ad6efc6ee1fc188a328d36eafe` |
| `p256-table.bin` | the generator's comb: 37 rows x 64 affine points x 64 bytes, little-endian Montgomery limbs (ring's `TOBN` table, byte for byte) | `e373124f67e14a9deeb7a334cf17b3f0bcc262499061a3377788a357570e70d2` |
| `derive.py` | regenerates both from the unpacked ring crate | |

Changes to the assembly, all mechanical: the `#include`/`#if` lines and the `_CET_ENDBR` markers are removed, the two AVX2 select functions are removed (the kernel keeps no AVX state, ADR-042), `//` comment lines become `#`, and every symbol is renamed `ecp_nistz256_*` -> `urmqtt_nistz256_*` (so it cannot clash with another copy in a binary). Nothing is edited by hand. The assembler (LLVM's, through `global_asm!`) accepts MULX/ADCX/ADOX whatever the target features say. To review: run `derive.py` on the pristine crate and `diff`; the table is also checked entry by entry against RustCrypto's `k*G` in `cargo test -p urmqtt-nistz256`. Used by `crates/nistz256` (the only user), x86_64 on Linux and bare metal only.
