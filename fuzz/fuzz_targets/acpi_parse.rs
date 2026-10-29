//! Arbitrary bytes as physical memory holding an RSDP at address 0 and
//! tables anywhere inside: discovery must never panic or read out of bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_platform::acpi::{Acpi, PhysMemory};

struct Blob<'a>(&'a [u8]);

impl PhysMemory for Blob<'_> {
    fn bytes(&self, pa: u64, len: usize) -> Option<&[u8]> {
        let start = usize::try_from(pa).ok()?;
        self.0.get(start..start.checked_add(len)?)
    }
}

fuzz_target!(|data: &[u8]| {
    let mem = Blob(data);
    if let Ok(acpi) = Acpi::new(&mem, 0) {
        let _ = urmqtt_platform::early_from_acpi(&acpi);
    }
});
