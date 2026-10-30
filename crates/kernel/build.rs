//! Links the bare-metal kernel with its own linker script.

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
    }
}
