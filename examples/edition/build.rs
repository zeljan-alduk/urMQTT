//! Links the kernel image with the kernel library's linker script and flags,
//! which its build script hands to dependents (`links = "urmqtt-kernel"`,
//! DEP_URMQTT_KERNEL_*; ADR-335). Every edition's image needs these lines.

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_URMQTT_KERNEL_LINKER_SCRIPT");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    let script = std::env::var("DEP_URMQTT_KERNEL_LINKER_SCRIPT")
        .expect("urmqtt-kernel hands its linker script to dependents");
    println!("cargo::rustc-link-arg-bin=urmqtt-example=-T{script}");
    let args = std::env::var("DEP_URMQTT_KERNEL_LINK_ARGS").unwrap_or_default();
    for a in args.split_whitespace() {
        println!("cargo::rustc-link-arg-bin=urmqtt-example={a}");
    }
}
