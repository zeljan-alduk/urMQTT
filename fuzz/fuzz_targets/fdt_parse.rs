//! Arbitrary bytes as a device tree: discovery must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_platform::fdt::{Fdt, Visit};

fuzz_target!(|data: &[u8]| {
    if let Ok(fdt) = Fdt::new(data) {
        let _ = urmqtt_platform::early_from_fdt(&fdt);
        let _ = fdt.find_path("/cpus/cpu@0");
        let _ = fdt.for_each_node(|n| {
            let _ = n.reg(0);
            let _ = n.prop_strings("compatible").map(Iterator::count);
            Visit::Continue
        });
    }
});
