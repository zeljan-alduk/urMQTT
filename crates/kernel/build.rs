//! Links the bare-metal kernel with its own linker script, and builds the
//! unprivileged database worker the kernel embeds (ADR-210, ADR-212).

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=linker.ld");
    println!("cargo::rerun-if-changed=linker-x86_64.ld");
    println!("cargo::rerun-if-env-changed=URMQTT_VERSION");
    // The wall clock's lower bound (H7), read with `option_env!`.
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let script = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("x86_64") => "linker-x86_64.ld",
            _ => "linker.ld",
        };
        println!("cargo::rustc-link-arg-bins=-T{dir}/{script}");
        println!("cargo::rustc-link-arg-bins=--no-dynamic-linker");
        println!("cargo::rustc-link-arg-bins=-zmax-page-size=4096");
        // The same for the kernel binary of another crate (an edition's
        // image, ADR-335): its build script reads DEP_URMQTT_KERNEL_* and
        // passes them on (examples/edition/build.rs).
        println!("cargo::metadata=linker_script={dir}/{script}");
        println!("cargo::metadata=link_args=--no-dynamic-linker -zmax-page-size=4096");
        build_worker();
    }
}

/// Builds `crates/dbworker` for the kernel's target in a target directory
/// of its own (the outer cargo holds the lock of the workspace's) and
/// leaves the ELF where `include_bytes!` finds it.
///
/// The worker is a different program: static, non-PIE, small code model, no
/// PAC (its keys would be the kernel's), linked at a low address (its own
/// linker script). Only the flags that must match (path remapping for
/// reproducible builds) are taken from the outer build.
fn build_worker() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let root = manifest.join("../..");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    for dir in ["crates/dbworker", "crates/usys", "crates/store"] {
        println!("cargo::rerun-if-changed={}", root.join(dir).display());
    }
    println!(
        "cargo::rerun-if-changed={}",
        root.join("vendor/sqlite").display()
    );
    println!(
        "cargo::rerun-if-changed={}",
        root.join("Cargo.lock").display()
    );
    println!("cargo::rerun-if-env-changed=URMQTT_CLANG");
    println!("cargo::rerun-if-env-changed=URMQTT_AR");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_dir = out.join("dbworker-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let mut flags: Vec<String> = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .split('\x1f')
        .filter(|f| f.starts_with("--remap-path-prefix"))
        .map(str::to_string)
        .collect();
    flags.extend(
        [
            "-Crelocation-model=static",
            "-Zstack-protector=strong",
            "-Cforce-frame-pointers=no",
        ]
        .map(str::to_string),
    );
    match arch.as_str() {
        // Branch targets are checked at EL0 (SCTLR_EL1.BT0); no PAC.
        "aarch64" => flags.push("-Zbranch-protection=bti".into()),
        "x86_64" => flags.push("-Ccode-model=small".into()),
        other => panic!("unsupported kernel architecture {other}"),
    }

    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        .args(["--release", "--locked", "-p", "urmqtt-dbworker"])
        .args([
            "-Zbuild-std=core,compiler_builtins,alloc",
            "-Zbuild-std-features=compiler-builtins-mem",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(&root);
    let (target_arg, target_name) = if arch == "x86_64" {
        cmd.arg("-Zjson-target-spec");
        (
            root.join("targets/x86_64-urmqtt-none.json")
                .canonicalize()
                .unwrap_or_default()
                .display()
                .to_string(),
            "x86_64-urmqtt-none".to_string(),
        )
    } else {
        (
            "aarch64-unknown-none".to_string(),
            "aarch64-unknown-none".to_string(),
        )
    };
    cmd.arg("--target").arg(&target_arg);
    // The self-test operations (fault injection) are in dev images only.
    if std::env::var("CARGO_FEATURE_SELFTEST").is_ok() {
        cmd.args(["--features", "selftest"]);
    }
    cmd.env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"));
    for var in [
        "RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    let status = cmd.status().expect("running cargo for the dbworker");
    assert!(status.success(), "building the dbworker failed");

    let elf = target_dir
        .join(&target_name)
        .join("release/urmqtt-dbworker");
    copy(&elf, &out.join("dbworker.elf"));
}

fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to).unwrap_or_else(|e| panic!("copy {}: {e}", from.display()));
}
