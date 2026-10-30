//! Arbitrary bytes as a DSDT/SSDT body: the `_S5_` scanner must never panic
//! or read out of bounds, and any answer it gives must be a valid SLP_TYP.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(s) = urmqtt_platform::aml::find_s5(data) {
        assert!(s.a <= 7 && s.b <= 7);
    }
});
