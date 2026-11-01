//! Compiles the vendored SQLite amalgamation (ADR-030).
//!
//! The source is verified against `vendor/sqlite/CHECKSUMS` first, so a
//! modified amalgamation never gets linked. It is linked into exactly two
//! kinds of program: the host tests (host C compiler and libc) and the
//! unprivileged dbworker (ADR-210), the bare-metal build with the `worker`
//! feature: freestanding with clang as a *user* program (hard float
//! (ADR-003), BTI on aarch64 but no pointer authentication, strict
//! alignment, static non-PIE at a fixed low address, the strong stack
//! protector with a global guard the worker sets). The kernel itself links
//! no SQLite: without `worker`, a bare-metal build compiles nothing here.
//!
//! This script also sets two cfgs for the crate:
//! - `sandboxed`: SQLite is reached through the worker (`remote.rs`): the
//!   kernel, and the host tests with the `loopback` feature;
//! - `direct_vfs`: the VFS callbacks of `vfs.rs` are SQLite's own (the host
//!   tests without `loopback`).

use std::path::Path;

use sha2::{Digest, Sha256};

/// Compile-time options; each is checked against SQLite 3.54.1.
const DEFINES: &[(&str, &str)] = &[
    ("SQLITE_OS_OTHER", "1"),
    ("SQLITE_THREADSAFE", "0"),
    ("SQLITE_ENABLE_MEMSYS5", "1"),
    ("SQLITE_ZERO_MALLOC", "1"),
    ("SQLITE_TEMP_STORE", "3"),
    ("SQLITE_DEFAULT_MEMSTATUS", "0"),
    ("SQLITE_DQS", "0"),
    ("SQLITE_OMIT_LOAD_EXTENSION", "1"),
    ("SQLITE_OMIT_SHARED_CACHE", "1"),
    ("SQLITE_OMIT_DEPRECATED", "1"),
    ("SQLITE_OMIT_LOCALTIME", "1"),
    ("SQLITE_OMIT_PROGRESS_CALLBACK", "1"),
    ("SQLITE_OMIT_AUTHORIZATION", "1"),
    ("SQLITE_OMIT_AUTOINIT", "1"),
    ("SQLITE_OMIT_JSON", "1"),
    ("SQLITE_OMIT_UTF16", "1"),
    ("SQLITE_OMIT_TRACE", "1"),
    ("SQLITE_OMIT_COMPLETE", "1"),
    ("SQLITE_OMIT_GET_TABLE", "1"),
    ("SQLITE_OMIT_TCL_VARIABLE", "1"),
    ("SQLITE_OMIT_DECLTYPE", "1"),
    ("SQLITE_UNTESTABLE", "1"),
    ("SQLITE_MAX_MMAP_SIZE", "0"),
    ("SQLITE_MAX_ATTACHED", "0"),
    ("SQLITE_DEFAULT_PAGE_SIZE", "4096"),
    ("SQLITE_DEFAULT_LOCKING_MODE", "1"),
    ("SQLITE_DEFAULT_SYNCHRONOUS", "2"),
    ("SQLITE_DEFAULT_WAL_SYNCHRONOUS", "2"),
    ("SQLITE_DEFAULT_FOREIGN_KEYS", "1"),
    ("SQLITE_DEFAULT_WORKER_THREADS", "0"),
    ("SQLITE_MAX_WORKER_THREADS", "0"),
    ("SQLITE_LIKE_DOESNT_MATCH_BLOBS", "1"),
    ("NDEBUG", "1"),
];

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let vendor = root.join("vendor/sqlite");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc/include");
    for f in ["sqlite3.c", "sqlite3.h", "CHECKSUMS"] {
        println!("cargo:rerun-if-changed={}", vendor.join(f).display());
    }
    println!("cargo:rerun-if-env-changed=URMQTT_CLANG");
    println!("cargo:rerun-if-env-changed=URMQTT_AR");
    verify_checksums(&vendor);

    let bare_metal = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none");
    let worker = std::env::var("CARGO_FEATURE_WORKER").is_ok();
    let loopback = std::env::var("CARGO_FEATURE_LOOPBACK").is_ok();
    let sandboxed = (bare_metal && !worker) || loopback;
    println!("cargo::rustc-check-cfg=cfg(sandboxed)");
    println!("cargo::rustc-check-cfg=cfg(direct_vfs)");
    if sandboxed {
        println!("cargo::rustc-cfg=sandboxed");
    }
    if !sandboxed && !worker {
        println!("cargo::rustc-cfg=direct_vfs");
    }
    // The C library is needed by whoever calls it directly.
    if bare_metal && !worker {
        return;
    }

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let mut b = cc::Build::new();
    b.file(vendor.join("sqlite3.c"))
        .include(&vendor)
        .warnings(false)
        .opt_level_str("s");
    for (k, v) in DEFINES {
        b.define(k, Some(*v));
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        let clang = tool(
            "URMQTT_CLANG",
            &[
                "/opt/homebrew/opt/llvm/bin/clang",
                "clang",
                "clang-19",
                "clang-18",
            ],
        );
        // ELF archives need LLVM's archiver (Apple's `ar` writes BSD
        // archives with an empty symbol table for ELF members).
        let ar = tool(
            "URMQTT_AR",
            &[
                "/opt/homebrew/opt/llvm/bin/llvm-ar",
                "llvm-ar",
                "llvm-ar-19",
                "llvm-ar-18",
            ],
        );
        b.compiler(clang)
            .archiver(ar)
            .no_default_flags(true)
            .include(Path::new(env!("CARGO_MANIFEST_DIR")).join("csrc/include"));
        // The worker's ABI per architecture: aarch64 is strict-alignment with
        // BTI (no pointer authentication: the keys are the kernel's);
        // x86_64 is hard-float SSE at the x86-64-v2 baseline. Both are
        // static code at a fixed low address: small code model, no PIC.
        let arch_flags: &[&str] = match arch.as_str() {
            "aarch64" => &[
                "--target=aarch64-unknown-none-elf",
                "-mcmodel=small",
                "-mstrict-align",
                "-mbranch-protection=bti",
                "-fno-pic",
                "-fno-pie",
            ],
            "x86_64" => &[
                "--target=x86_64-unknown-none-elf",
                "-mcmodel=small",
                "-mno-red-zone",
                "-march=x86-64-v2",
                "-fno-pic",
                "-fno-pie",
            ],
            other => panic!("unsupported architecture {other}"),
        };
        for flag in arch_flags.iter().chain(&[
            "-ffreestanding",
            "-nostdlibinc",
            "-fno-builtin",
            "-fstack-protector-strong",
            "-mstack-protector-guard=global",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-Os",
        ]) {
            b.flag(flag);
        }
    }
    // No absolute build paths in the objects (reproducible builds, M17).
    b.flag(format!("-ffile-prefix-map={}=.", root.display()));
    b.compile("sqlite3");
}

/// The tool named by `env`, else the first candidate that runs.
fn tool(env: &str, candidates: &[&str]) -> String {
    if let Ok(t) = std::env::var(env) {
        return t;
    }
    candidates
        .iter()
        .find(|c| {
            std::process::Command::new(c)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .map(|c| (*c).to_string())
        .unwrap_or_else(|| panic!("none of {candidates:?} found; set {env}"))
}

fn verify_checksums(vendor: &Path) {
    let sums = std::fs::read_to_string(vendor.join("CHECKSUMS")).expect("vendor/sqlite/CHECKSUMS");
    let mut checked = 0;
    for line in sums
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let mut it = line.split_whitespace();
        let (Some(want), Some(name)) = (it.next(), it.next()) else {
            panic!("malformed CHECKSUMS line: {line}");
        };
        let data = std::fs::read(vendor.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let got: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, want, "vendor/sqlite/{name} does not match CHECKSUMS");
        checked += 1;
    }
    assert!(checked >= 2, "CHECKSUMS must cover sqlite3.c and sqlite3.h");
}
