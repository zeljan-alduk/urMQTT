//! Links the worker with its own linker script (a user program at a fixed
//! low address; it shares no symbol with the kernel).

fn main() {
    println!("cargo::rerun-if-changed=linker.ld");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        println!("cargo::rustc-link-arg-bins=-T{dir}/linker.ld");
        println!("cargo::rustc-link-arg-bins=--no-dynamic-linker");
        println!("cargo::rustc-link-arg-bins=-zmax-page-size=4096");
        println!("cargo::rustc-link-arg-bins=--gc-sections");
    }
}
