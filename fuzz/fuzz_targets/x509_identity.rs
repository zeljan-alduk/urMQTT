//! Device identity and serial extraction from client certificates (M10).
//! rustls has verified the chain before these run, but the parsing is our
//! own and must hold for any DER.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_tls::IdentityField;
use urmqtt_tls::identity::{identity, serial};

fuzz_target!(|data: &[u8]| {
    let _ = serial(data);
    for f in [IdentityField::Cn, IdentityField::SanUri] {
        if let Some(id) = identity(data, f) {
            assert!(!id.is_empty());
        }
    }
});
