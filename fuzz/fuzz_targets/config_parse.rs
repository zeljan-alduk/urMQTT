//! Arbitrary bytes into the configuration parser: it must return `Ok`/`Err`,
//! never panic, and anything it accepts must pack into a blob (the files it
//! names are stand-ins) that the kernel-side decoder and checks accept
//! (the two validators must agree, ADR-215).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_config_schema::pack::{PackOptions, pack};
use urmqtt_config_schema::parse;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for env in ["dev", "prod"] {
        let _ = parse(env, text);
    }
    // Packing completes missing keys with the defaults and refuses files it
    // cannot read; whatever it produces must pass the kernel's checks.
    let mut read = |_: &str| Err("no files".to_owned());
    if let Ok(blob) = pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
        },
    ) {
        let b = urmqtt_cfg::Blob::parse(&blob).expect("a packed blob parses");
        let dev = b.str(urmqtt_cfg::fields::tag::ENV) == "dev";
        urmqtt_cfg::check::check(&b, dev).expect("a packed blob passes the kernel checks");
    }
});
