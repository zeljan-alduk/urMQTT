//! NOW-19, ADR-264: `network.mtu`. Optional; absent or 0 takes the MTU from
//! DHCP option 26, else 1500, and writes nothing (the blob keeps its
//! version); a value in 576..=9000 needs format 7, in every network mode;
//! the strict parser, the packer and the blob validator agree.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack};
use crate::{ConfigError, parse};

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

/// The dev template with `mtu = <v>` added to `[network]`.
fn dev_with_mtu(v: &str) -> String {
    DEV.replacen("[network]\n", &format!("[network]\nmtu = {v}\n"), 1)
}

#[test]
fn the_templates_leave_it_unset_and_mention_it() {
    for (env, t) in [("dev", DEV), ("prod", PROD)] {
        assert_eq!(parse(env, t).unwrap().network.mtu, None, "{env}");
    }
    for t in [DEV, PROD, BENCH, DEMO] {
        assert!(t.contains("\n# mtu = 1460 "), "the commented example");
    }
}

#[test]
fn parse_accepts_0_and_576_to_9000() {
    for (v, want) in [
        ("0", None),
        ("576", Some(576)),
        ("1460", Some(1460)),
        ("9000", Some(9000)),
    ] {
        let c = parse("dev", &dev_with_mtu(v)).unwrap();
        assert_eq!(c.network.mtu, want, "{v}");
    }
    for v in ["1", "575", "9001", "65535"] {
        let e = parse("dev", &dev_with_mtu(v)).unwrap_err();
        assert!(e.iter().any(|e| e.path == "network.mtu"), "{v}: {e:?}");
    }
    // Not an integer: the TOML layer refuses it.
    assert!(parse("dev", &dev_with_mtu("\"1460\"")).is_err());
    assert!(parse("dev", &dev_with_mtu("-1")).is_err());
}

#[test]
fn absent_writes_nothing_and_a_value_needs_format_7() {
    let none = run("").unwrap();
    let zero = run("[network]\nmtu = 0\n").unwrap();
    assert_eq!(none, zero, "0 is the default: no record");
    assert_eq!(Blob::parse(&none).unwrap().version(), 2);
    let b = run("[network]\nmtu = 1460\n").unwrap();
    let p = Blob::parse(&b).unwrap();
    assert_eq!((p.version(), p.uint(tag::NET_MTU)), (7, 1460));
    // A static address with its MTU (Google Cloud, a static configuration).
    let b = run(
        "[network]\nmode = \"static\"\naddress = \"10.128.0.5/32\"\ngateway = \"10.128.0.1\"\nmtu = 1460\n",
    )
    .unwrap();
    let p = Blob::parse(&b).unwrap();
    assert_eq!((p.variant(tag::NET_MODE), p.uint(tag::NET_MTU)), (1, 1460));
    for v in ["575", "9001"] {
        let e = run(&format!("[network]\nmtu = {v}\n")).unwrap_err();
        assert!(e.iter().any(|e| e.path == "network.mtu"), "{v}: {e:?}");
    }
}
