//! ADR-334: `network.ipv6*` and IPv6 networks in the allow-lists through the
//! TOML path. A configuration that does not touch them is the blob it always
//! was; slaac and static need format 23; the strict parser and the kernel's
//! blob check accept and refuse the same configurations.

use urmqtt_cfg::blob::Blob;
use urmqtt_cfg::build::Builder;
use urmqtt_cfg::fields::tag;

use crate::pack::{PackOptions, pack};
use crate::{ConfigError, Ipv6Mode, parse};

const NOW: u64 = 1_800_000_000;

fn pack_toml(text: &str) -> Result<Vec<u8>, Vec<ConfigError>> {
    let mut read = |_: &str| Err("no files in this test".to_owned());
    pack(
        text,
        PackOptions {
            read: &mut read,
            now_unix: NOW,
            env: None,
        },
    )
}

fn v6(s: &str) -> [u8; 16] {
    urmqtt_cfg::net::parse_ipv6(s).unwrap()
}

#[test]
fn off_by_default_and_writes_nothing() {
    let c = parse("dev", include_str!("../../../deploy/dev/config.toml")).unwrap();
    assert_eq!(c.network.ipv6, Ipv6Mode::Off);
    let blob = pack_toml("[network]\nipv6 = \"off\"\n").unwrap();
    assert_eq!(blob, Builder::new().finish(false).unwrap());
}

#[test]
fn slaac_and_static_need_format_23_and_come_back() {
    let blob = pack_toml("[network]\nipv6 = \"slaac\"\n").unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!((b.version(), b.variant(tag::NET_IPV6)), (23, 1));
    let text = "[network]\nipv6 = \"static\"\nipv6_address = \"2001:DB8:1:0::10/64\"\nipv6_gateway = \"fe80::1\"\n";
    // The dev configuration with the keys added (a full file, as `parse` takes).
    let dev = include_str!("../../../deploy/dev/config.toml").replace(
        "[network]\n",
        "[network]\nipv6 = \"static\"\nipv6_address = \"2001:DB8:1:0::10/64\"\nipv6_gateway = \"fe80::1\"\n",
    );
    let c = parse("dev", &dev).unwrap();
    assert_eq!(
        c.network.ipv6,
        Ipv6Mode::Static {
            address: v6("2001:db8:1::10"),
            prefix_len: 64,
            gateway: v6("fe80::1")
        }
    );
    let blob = pack_toml(text).unwrap();
    let b = Blob::parse(&blob).unwrap();
    assert_eq!(b.version(), 23);
    // Written in the canonical form.
    assert_eq!(b.str(tag::NET_IPV6_ADDRESS), "2001:db8:1::10/64");
    assert_eq!(b.str(tag::NET_IPV6_GATEWAY), "fe80::1");
}

/// The TOML path and the kernel's check refuse the same configurations.
#[test]
fn the_toml_path_and_the_blob_check_agree() {
    let cases: [(&str, &str, &str, bool); 9] = [
        ("static", "2001:db8:1::10/64", "fe80::1", true),
        ("static", "2001:db8:1::10/64", "2001:db8:1::1", true),
        ("static", "2001:db8:1::10/64", "2001:db8:2::1", false),
        ("static", "fe80::10/64", "fe80::1", false),
        ("static", "2001:db8:1::10", "fe80::1", false),
        ("static", "2001:db8:1::10/64", "", false),
        ("static", "", "fe80::1", false),
        ("slaac", "2001:db8:1::10/64", "", false),
        ("off", "", "fe80::1", false),
    ];
    for (mode, addr, gw, ok) in cases {
        let mut text = format!("[network]\nipv6 = \"{mode}\"\n");
        if !addr.is_empty() {
            text.push_str(&format!("ipv6_address = \"{addr}\"\n"));
        }
        if !gw.is_empty() {
            text.push_str(&format!("ipv6_gateway = \"{gw}\"\n"));
        }
        assert_eq!(pack_toml(&text).is_ok(), ok, "{text}");
        let mut b = Builder::new();
        let i = match mode {
            "off" => 0,
            "slaac" => 1,
            _ => 2,
        };
        b.variant(tag::NET_IPV6, i).unwrap();
        if !addr.is_empty() {
            b.str(tag::NET_IPV6_ADDRESS, addr).unwrap();
        }
        if !gw.is_empty() {
            b.str(tag::NET_IPV6_GATEWAY, gw).unwrap();
        }
        assert_eq!(b.finish(false).is_ok(), ok, "blob: {text}");
    }
}

#[test]
fn ipv6_networks_in_the_allow_lists() {
    let text = "[metrics]\nenabled = true\nallow_from = [\"10.0.0.0/8\", \"2001:db8::/32\"]\n";
    let blob = pack_toml(text).unwrap();
    assert_eq!(Blob::parse(&blob).unwrap().version(), 23);
    // IPv4 only: the format the metrics endpoint needs (16).
    let blob = pack_toml("[metrics]\nenabled = true\nallow_from = [\"10.0.0.0/8\"]\n").unwrap();
    assert_eq!(Blob::parse(&blob).unwrap().version(), 16);
    for bad in ["::/0", "2001:db8::1/32", "2001:db8::/129", "2001:db8::"] {
        let t = format!("[metrics]\nenabled = true\nallow_from = [\"{bad}\"]\n");
        assert!(pack_toml(&t).is_err(), "{bad}");
    }
    let twice = "[metrics]\nenabled = true\nallow_from = [\"2001:db8::/32\", \"2001:DB8::/32\"]\n";
    assert!(pack_toml(twice).is_err());
    let plain = "[network]\nmqtt_tls_port = 8883\n[plaintext]\nenabled = true\nallow_from = [\"fd00::/8\"]\nauth = \"anonymous\"\n";
    let blob = pack_toml(plain).unwrap();
    assert_eq!(Blob::parse(&blob).unwrap().version(), 23);
}
