//! NEXT-1, ADR-330, ADR-331: the stack over IPv6 beside IPv4. The scripted
//! edge cases run over IPv6 too (`scripts.rs`); these cover what only a
//! second family brings: the local address picked per peer, a peer with no
//! address of ours to answer from, the MSS per family, and both families
//! in one table.

use super::*;
use crate::script::{CLIENT6, SERVER6, cfg, segment_between};
use urmqtt_net::addr::V6Locals;

const LL: [u8; 16] = [
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
];
const LL_PEER: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

#[derive(Default)]
struct Rec {
    accepted: Vec<Endpoint>,
    syns: Vec<Addr>,
}

impl App for Rec {
    fn syn_ok(&mut self, _p: u16, r: Addr) -> bool {
        self.syns.push(r);
        true
    }
    fn accept(&mut self, _c: ConnId, _p: u16, r: Endpoint) -> bool {
        self.accepted.push(r);
        true
    }
    fn data(&mut self, _c: ConnId, _d: &[u8]) {}
    fn peer_closed(&mut self, _c: ConnId) {}
    fn closed(&mut self, _c: ConnId, _w: CloseReason) {}
}

fn syn(client: Addr, server: Addr, port: u16) -> Vec<u8> {
    segment_between(
        client,
        server,
        port,
        7,
        0,
        wire::SYN,
        65535,
        0,
        &[2, 4, 5, 0xb4],
        &[],
    )
}

/// The SYN-ACK to `client`, parsed with the pseudo-header of `server`.
fn syn_ack(
    s: &mut TcpStack,
    app: &mut Rec,
    client: Addr,
    server: Addr,
    port: u16,
) -> Option<wire::Header> {
    let mut out = Vec::new();
    s.input(0, client, &syn(client, server, port), app, &mut |d, b| {
        assert_eq!(d, client);
        out.push(b.to_vec())
    });
    let b = out.first()?;
    Some(wire::parse(server, client, b).expect("checksum over the right pseudo-header"))
}

fn finish(
    s: &mut TcpStack,
    app: &mut Rec,
    client: Addr,
    server: Addr,
    port: u16,
    h: &wire::Header,
) {
    let ack = segment_between(
        client,
        server,
        port,
        8,
        h.seq.wrapping_add(1),
        wire::ACK,
        65535,
        0,
        &[],
        &[],
    );
    s.input(0, client, &ack, app, &mut |_, _| {});
}

#[test]
fn each_peer_is_answered_from_the_address_of_its_scope() {
    let mut s = TcpStack::new(cfg(), 0);
    s.set_local6(V6Locals {
        link_local: Some(LL),
        global: Some(SERVER6),
    });
    let mut app = Rec::default();
    let g = syn_ack(
        &mut s,
        &mut app,
        Addr::v6(CLIENT6),
        Addr::v6(SERVER6),
        40000,
    )
    .unwrap();
    assert_eq!(g.mss, Some(1440));
    let l = syn_ack(&mut s, &mut app, Addr::v6(LL_PEER), Addr::v6(LL), 40001).unwrap();
    assert_eq!(l.flags, wire::SYN | wire::ACK);
    // A segment summed for the other local address does not check out.
    let mut out = Vec::new();
    let wrong = syn(Addr::v6(LL_PEER), Addr::v6(SERVER6), 40002);
    s.input(0, Addr::v6(LL_PEER), &wrong, &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    assert!(out.is_empty());
    assert_eq!(s.stats.bad_segments, 1);
    assert_eq!(app.syns, [Addr::v6(CLIENT6), Addr::v6(LL_PEER)]);
}

#[test]
fn without_an_address_of_ours_nothing_is_taken_or_sent() {
    let mut s = TcpStack::new(cfg(), 0);
    let mut app = Rec::default();
    // IPv6 off: no SYN-ACK, no RST, the application never asked.
    assert!(
        syn_ack(
            &mut s,
            &mut app,
            Addr::v6(CLIENT6),
            Addr::v6(SERVER6),
            40000
        )
        .is_none()
    );
    assert!(app.syns.is_empty());
    assert_eq!(s.stats.no_local, 1);
    // Only a link-local address: a global peer is not answered.
    s.set_local6(V6Locals {
        link_local: Some(LL),
        global: None,
    });
    assert!(
        syn_ack(
            &mut s,
            &mut app,
            Addr::v6(CLIENT6),
            Addr::v6(SERVER6),
            40000
        )
        .is_none()
    );
    assert_eq!(s.stats.no_local, 2);
}

#[test]
fn both_families_share_the_table_and_keep_their_mss() {
    let mut s = TcpStack::new(cfg(), 0);
    s.set_local6(V6Locals {
        link_local: None,
        global: Some(SERVER6),
    });
    let mut app = Rec::default();
    let v4c = Addr::v4(crate::script::CLIENT);
    let v4s = Addr::v4(crate::script::SERVER);
    // The same port from both families: two connections.
    let h4 = syn_ack(&mut s, &mut app, v4c, v4s, 40000).unwrap();
    assert_eq!(h4.mss, Some(1460));
    finish(&mut s, &mut app, v4c, v4s, 40000, &h4);
    let h6 = syn_ack(
        &mut s,
        &mut app,
        Addr::v6(CLIENT6),
        Addr::v6(SERVER6),
        40000,
    )
    .unwrap();
    finish(
        &mut s,
        &mut app,
        Addr::v6(CLIENT6),
        Addr::v6(SERVER6),
        40000,
        &h6,
    );
    assert_eq!(s.connections(), 2);
    assert_eq!(
        app.accepted.iter().map(|e| e.addr).collect::<Vec<_>>(),
        [v4c, Addr::v6(CLIENT6)]
    );
    // A smaller IPv6 path MTU lowers only the IPv6 connection.
    s.set_mss6(mss6_for_mtu(1280));
    let mss: Vec<u16> = s.conns.iter().map(|(_, k)| k.mss).collect();
    assert!(mss.contains(&1460) && mss.contains(&1220), "{mss:?}");
    assert_eq!(
        (mss6_for_mtu(1500), mss6_for_mtu(9000), mss6_for_mtu(100)),
        (1440, 1440, MIN_MSS)
    );
}

#[test]
fn the_ipv6_checksum_agrees_with_the_ip_layers() {
    let seg = segment_between(
        Addr::v6(CLIENT6),
        Addr::v6(SERVER6),
        40000,
        1,
        2,
        wire::ACK,
        100,
        0,
        &[],
        b"odd",
    );
    // The IP layer's own pseudo-header and sum (independent code) verify it.
    let acc = urmqtt_net::ipv6::pseudo6(&CLIENT6, &SERVER6, 6, seg.len());
    assert_eq!(urmqtt_net::ipv4::csum(acc, &seg), 0);
    // And IPv4 still sums as before.
    let seg4 = crate::script::segment(40000, 1, 2, wire::ACK, 100, 0, &[], b"odd");
    let mut pseudo = 0u32;
    for p in crate::script::CLIENT
        .chunks(2)
        .chain(crate::script::SERVER.chunks(2))
    {
        pseudo += u32::from(u16::from_be_bytes([p[0], p[1]]));
    }
    assert_eq!(
        urmqtt_net::ipv4::csum(pseudo + 6 + seg4.len() as u32, &seg4),
        0
    );
}
