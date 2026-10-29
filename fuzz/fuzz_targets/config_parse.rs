//! Arbitrary bytes into the build-time config parser: it must return
//! `Ok`/`Err`, never panic, and anything it accepts must render.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_config_schema::{EmbeddedFiles, parse, render};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for env in ["dev", "prod"] {
        if let Ok(cfg) = parse(env, text) {
            let files = EmbeddedFiles {
                ca: "/ca.pem".into(),
                cert: "/server.pem".into(),
                key: "/server.key".into(),
                revoked: Vec::new(),
            };
            let _ = render(&cfg, &files);
        }
    }
});
