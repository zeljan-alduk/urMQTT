//! NOW-13, ADR-269: `limits.publisher_backpressure`. Optional; absent or
//! "single" writes nothing (the blob keeps its version), "off" needs format
//! 8; the strict parser, the packer and the blob validator agree.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack};
use crate::{ConfigError, PublisherBackpressure, parse};

const DEV: &str = include_str!("../../../deploy/dev/config.toml");
const PROD: &str = include_str!("../../../deploy/prod/config.toml");
const BENCH: &str = include_str!("../../../deploy/bench/config.toml");
const DEMO: &str = include_str!("../../../deploy/demo/config.toml");

fn run(text: &str) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: 1_800_000_000,
            env: None,
        },
    )
}

fn dev_with(v: &str) -> String {
    DEV.replacen(
        "[limits]\n",
        &format!("[limits]\npublisher_backpressure = {v}\n"),
        1,
    )
}

#[test]
fn the_templates_leave_it_at_single_and_mention_it() {
    for (env, t) in [("dev", DEV), ("prod", PROD)] {
        assert_eq!(
            parse(env, t).unwrap().limits.publisher_backpressure,
            PublisherBackpressure::Single,
            "{env}"
        );
    }
    for t in [DEV, PROD, BENCH, DEMO] {
        assert!(t.contains("\n# publisher_backpressure = \"single\""));
    }
}

#[test]
fn single_writes_nothing_and_off_needs_format_8() {
    let none = run("").unwrap();
    let single = run("[limits]\npublisher_backpressure = \"single\"\n").unwrap();
    assert_eq!(none, single, "the default writes no record");
    assert_eq!(Blob::parse(&none).unwrap().version(), 2);
    let off = run("[limits]\npublisher_backpressure = \"off\"\n").unwrap();
    let blob = Blob::parse(&off).unwrap();
    assert_eq!(blob.version(), 8);
    assert_eq!(blob.variant(tag::LIM_PUBLISHER_BACKPRESSURE), 1);
    assert_eq!(
        parse("dev", &dev_with("\"off\""))
            .unwrap()
            .limits
            .publisher_backpressure,
        PublisherBackpressure::Off
    );
}

#[test]
fn anything_else_is_refused_by_name() {
    for bad in ["\"on\"", "\"all\"", "1", "true"] {
        let e = parse("dev", &dev_with(bad)).unwrap_err();
        assert!(
            e.iter()
                .any(|e| format!("{e:?}").contains("publisher_backpressure")),
            "{bad}: {e:?}"
        );
    }
}
