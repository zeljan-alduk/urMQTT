//! IPv6 from the network (NEXT-1, ADR-330, ADR-331): the header and its
//! extension headers, ICMPv6 and Neighbour Discovery, the steering
//! classifier, and the interface's SLAAC/DAD state machine fed with frames
//! and time; and the configuration's IPv6 text forms. Every byte comes from
//! the network (or an operator's file), so nothing may panic, and:
//!
//! - an accepted packet's payload lies within the input, its source is not
//!   multicast or IPv4-mapped, its upper layer is TCP, UDP or ICMPv6, and at
//!   most `MAX_EXT` extension headers were skipped;
//! - the classifier steers by TCP only what the interface's parser accepts
//!   as TCP, with the same addresses;
//! - the interface's addresses in use are its own (the link-local one from
//!   the MAC, a global one with the MAC's interface identifier or the static
//!   one), its IPv6 MTU stays within 1280 and the link's, and every frame it
//!   sends parses;
//! - an IPv6 address or network the text parser accepts is written back in a
//!   form that parses to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_net::iface::Iface;
use urmqtt_net::ipv6::{
    self, ETHERTYPE_IPV6, IPV6_HDR, MAX_EXT, NH_ICMPV6, eui64, link_local_of, parse_icmp6,
    parse_ipv6, pseudo6,
};
use urmqtt_net::nd::Mode6;
use urmqtt_net::{Class, addr::Addr, classify, ipv4};

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const STATIC: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
const GW: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn check_packet(p: &[u8]) {
    if let Ok(ip) = parse_ipv6(p) {
        let base = p.as_ptr() as usize;
        let at = ip.payload.as_ptr() as usize;
        assert!(at >= base + IPV6_HDR && at + ip.payload.len() <= base + p.len());
        assert!(ip.src[0] != 0xff && !urmqtt_net::addr::is_mapped(&ip.src));
        assert!(!urmqtt_net::addr::is_mapped(&ip.dst));
        assert!(matches!(ip.next, 6 | 17 | 58));
        assert!(usize::from(ip.ext) <= MAX_EXT);
        if ip.next == NH_ICMPV6
            && let Ok(ipv6::Icmp6::RouterAdvert(ra)) = parse_icmp6(&ip)
        {
            assert!(ra.prefixes().len() <= ipv6::MAX_PREFIXES);
        }
    }
    // The classifier and the parser agree.
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    f.extend_from_slice(p);
    if let Class::Tcp { src, dst, .. } = classify(&f) {
        let ip = parse_ipv6(p).expect("a frame steered by TCP parses");
        assert_eq!(ip.next, ipv6::NH_TCP);
        assert_eq!((src, dst), (Addr::v6(ip.src), Addr::v6(ip.dst)));
    }
}

/// With `fix`, an ICMPv6 packet gets its length and checksum made right, so
/// that the fuzzer reaches Neighbour Discovery rather than the checksum.
fn fixed(p: &mut [u8]) {
    if p.len() < IPV6_HDR + 4 || p[6] != NH_ICMPV6 {
        return;
    }
    let len = (p.len() - IPV6_HDR) as u16;
    p[4..6].copy_from_slice(&len.to_be_bytes());
    p[0] = 0x60 | (p[0] & 0x0f);
    let (src, dst): ([u8; 16], [u8; 16]) =
        (p[8..24].try_into().unwrap(), p[24..40].try_into().unwrap());
    p[IPV6_HDR + 2] = 0;
    p[IPV6_HDR + 3] = 0;
    let c = ipv4::csum(
        pseudo6(&src, &dst, NH_ICMPV6, usize::from(len)),
        &p[IPV6_HDR..],
    );
    p[IPV6_HDR + 2..IPV6_HDR + 4].copy_from_slice(&c.to_be_bytes());
}

fuzz_target!(|data: &[u8]| {
    check_packet(data);
    if let Ok(s) = core::str::from_utf8(data) {
        if let Some(a) = urmqtt_cfg::net::parse_ipv6(s) {
            let mut t = String::new();
            urmqtt_cfg::net::write_ipv6(&mut t, &a).unwrap();
            assert_eq!(urmqtt_cfg::net::parse_ipv6(&t), Some(a), "{s:?} -> {t}");
            // `Addr` writes an IPv4-mapped address (::ffff:a.b.c.d) as the
            // dotted quad it stands for, by design; every other address is
            // written the way the configuration writes it.
            if !(a[..10].iter().all(|b| *b == 0) && a[10] == 0xff && a[11] == 0xff) {
                assert_eq!(
                    format!("{}", Addr::v6(a)),
                    t,
                    "the kernel writes it the same way"
                );
            }
        }
        if let Ok(c) = urmqtt_cfg::net::Cidr6::parse(s) {
            assert_eq!(urmqtt_cfg::net::Cidr6::parse(&c.to_string()), Ok(c));
        }
        let _ = urmqtt_cfg::net::parse_ipv6_address(s);
        let _ = urmqtt_cfg::net::parse_ipv6_gateway(s);
    }
    // The interface: the first byte picks SLAAC or static; then frames, each
    // `[len, flags, bytes...]`: flags bit 0 fixes an ICMPv6 checksum, bits 1-7
    // advance the clock (in 100 ms steps).
    let Some((&mode, mut rest)) = data.split_first() else {
        return;
    };
    let mut i = Iface::new(MAC, true, None, 0);
    i.set_addr(Some(([10, 0, 2, 15], 24)), Some([10, 0, 2, 2]));
    let static_mode = mode & 1 == 1;
    i.v6.start(
        0,
        if static_mode {
            Mode6::Static {
                addr: STATIC,
                prefix_len: 64,
                gateway: GW,
            }
        } else {
            Mode6::Slaac
        },
    );
    if mode & 2 != 0 {
        i.set_mtu(1280 + u16::from(mode >> 2) * 4);
    }
    let mut now = 0u64;
    let check_out = |f: &[u8]| {
        let e = ipv4::parse_eth(f).expect("frames we send have an Ethernet header");
        if e.ethertype == ETHERTYPE_IPV6 {
            let ip = parse_ipv6(e.payload).expect("frames we send parse");
            assert!(e.payload.len() <= usize::from(i_mtu_bound()));
            if ip.next == NH_ICMPV6 {
                if let Err(e) = parse_icmp6(&ip) {
                    panic!("our ICMPv6 parses: {e:?} {:02x?}", f);
                }
            }
        }
    };
    while let Some((&len, tail)) = rest.split_first() {
        let Some((&flags, tail)) = tail.split_first() else {
            break;
        };
        let len = usize::from(len).min(tail.len());
        let (body, tail) = tail.split_at(len);
        rest = tail;
        now += u64::from(flags >> 1) * 100;
        let mut pkt = body.to_vec();
        if flags & 1 == 1 {
            fixed(&mut pkt);
        }
        let mut frame = Vec::with_capacity(14 + pkt.len());
        // To us, or to the all-nodes group.
        frame.extend_from_slice(if flags & 0x80 != 0 {
            &[0x33, 0x33, 0, 0, 0, 1]
        } else {
            &MAC
        });
        frame.extend_from_slice(&[0x52, 0x55, 0, 0, 0, 1]);
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend_from_slice(&pkt);
        let _ = i.receive(now, &frame, &mut |f| check_out(f));
        while i.poll(now, &mut |f| check_out(f)).is_some() {}
        // A segment to a peer the stack would answer.
        let peer = Addr::v6([0x20, 1, 0xd, 0xb8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        i.send_tcp(peer, &body[..body.len().min(64)], &mut |f| check_out(f));
        let c = i.v6.config();
        assert!(c.mtu >= ipv6::MIN_MTU && c.mtu <= i.mtu().max(ipv6::MIN_MTU));
        if let Some(ll) = c.locals.link_local {
            assert_eq!(ll, link_local_of(MAC));
        }
        if let Some(g) = c.locals.global {
            if static_mode {
                assert_eq!(g, STATIC);
            } else {
                assert_eq!(g[8..], eui64(MAC));
            }
        }
    }
});

/// The largest IPv6 packet the interface may send (its link MTU is at most
/// 1500).
fn i_mtu_bound() -> u16 {
    urmqtt_net::iface::MAX_SEND_MTU
}
