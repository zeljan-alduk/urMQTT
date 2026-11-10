//! TCP segment processing (M14): a real connection is established through
//! the SYN-cookie handshake, then every fuzz chunk becomes a segment whose
//! flags, sequence/ack offsets (relative to the live connection), window
//! and payload come from the input, interleaved with timer runs, sends and
//! closes. The stack must never panic and its invariants must hold. Every
//! input runs twice: over IPv4 and over IPv6 (NEXT-1, ADR-330: the
//! pseudo-header, the IPv6 MSS, the local address picked per peer).
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_net::addr::{Addr, V6Locals};
use urmqtt_tcp::wire::{self, ACK, Ext, Out, SYN};
use urmqtt_tcp::{App, CloseReason, Config, ConnId, Endpoint, TcpStack};

const S4: [u8; 4] = [10, 0, 2, 15];
const C4: [u8; 4] = [10, 0, 2, 2];
const S6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
const C6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

#[derive(Default)]
struct Sink {
    conns: Vec<ConnId>,
    received: usize,
}

impl App for Sink {
    fn accept(&mut self, c: ConnId, _: u16, _: Endpoint) -> bool {
        self.conns.push(c);
        true
    }
    fn data(&mut self, _: ConnId, d: &[u8]) {
        self.received += d.len();
    }
    fn peer_closed(&mut self, _: ConnId) {}
    fn closed(&mut self, c: ConnId, _: CloseReason) {
        self.conns.retain(|&x| x != c);
    }
}

#[allow(clippy::too_many_arguments)]
fn seg_x(
    (c, s): (Addr, Addr),
    sport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    x: &Ext,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    wire::emit_ext(
        c,
        s,
        &Out {
            sport,
            dport: 8883,
            seq,
            ack,
            flags,
            window,
            mss: (flags & SYN != 0).then_some(1460),
        },
        x,
        payload,
        &mut b,
    );
    b
}

fuzz_target!(|data: &[u8]| {
    run(data, (Addr::v4(C4), Addr::v4(S4)));
    run(data, (Addr::v6(C6), Addr::v6(S6)));
});

fn run(data: &[u8], pair: (Addr, Addr)) {
    let (cli, srv) = pair;
    let mut s = TcpStack::new(
        Config {
            local_addr: S4,
            ports: vec![8883],
            mss: 1460,
            rcv_wnd: 65535,
            rcv_wnd_scaled: 512 * 1024,
            max_conns: 64,
            tx_max: 64 * 1024,
            tx_cap: 1 << 20,
            ooo_budget: 1 << 20,
            ooo_conn_max: 256 * 1024,
            cookie_key: [3; 16],
            rst_per_sec: 1000,
        },
        0,
    );
    s.set_local6(V6Locals {
        link_local: None,
        global: Some(S6),
    });
    let mut app = Sink::default();
    let mut out: Vec<Vec<u8>> = Vec::new();
    // Handshake: SYN, then the ACK echoing the cookie.
    let client_isn = 1000u32;
    s.input(
        0,
        cli,
        &seg_x(
            pair,
            5555,
            client_isn,
            0,
            SYN,
            65535,
            &Ext {
                sack_perm: true,
                wscale: Some(7),
                ts: Some((1000, 0)),
                ..Ext::NONE
            },
            &[],
        ),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    let Some(synack) = out.pop() else { return };
    let h = wire::parse(srv, cli, &synack).expect("our own SYN-ACK parses");
    let server_isn = h.seq;
    s.input(
        0,
        cli,
        &seg_x(
            pair,
            5555,
            client_isn + 1,
            server_isn.wrapping_add(1),
            ACK,
            65535,
            &Ext {
                ts: Some((1001, h.ts.map_or(0, |t| t.0))),
                ..Ext::NONE
            },
            &[],
        ),
        &mut app,
        &mut |_, _| {},
    );
    assert_eq!(s.connections(), 1);
    let mut cseq = client_isn + 1;
    let mut now = 0u64;
    for chunk in data.chunks(64) {
        let [op, flags, sd0, sd1, ad0, ad1, w0, w1, rest @ ..] = chunk else {
            break;
        };
        now += u64::from(*op & 0x3f) * 25;
        match op >> 6 {
            0 => {
                let seq = cseq.wrapping_add(i16::from_le_bytes([*sd0, *sd1]) as i32 as u32);
                let ack = server_isn.wrapping_add(i16::from_le_bytes([*ad0, *ad1]) as i32 as u32);
                // With bit 6 of the flags set the segment carries SACK blocks
                // (up to three, edges relative to the ACK) taken from the data:
                // what the sender's scoreboard and loss recovery do with them
                // must never break it (ADR-265).
                let (mut sacks, mut nsack, mut payload) = ([(0u32, 0u32); 3], 0u8, rest);
                if flags & 0x40 != 0 {
                    let n = usize::from(rest.first().copied().unwrap_or(0) % 4);
                    let blocks = rest.get(1..).unwrap_or(&[]);
                    for (slot, b) in sacks.iter_mut().zip(blocks.chunks_exact(4)).take(n) {
                        let l = i16::from_le_bytes([b[0], b[1]]) as i32 as u32;
                        let r = i16::from_le_bytes([b[2], b[3]]) as i32 as u32;
                        *slot = (ack.wrapping_add(l), ack.wrapping_add(r));
                        nsack += 1;
                    }
                    payload = &[];
                }
                let b = seg_x(
                    pair,
                    5555,
                    seq,
                    ack,
                    flags & 0x3f,
                    u16::from_le_bytes([*w0, *w1]),
                    &Ext {
                        ts: Some((1002 + now as u32, 0)),
                        sacks,
                        nsack,
                        ..Ext::NONE
                    },
                    payload,
                );
                s.input(now, cli, &b, &mut app, &mut |_, _| {});
                if seq == cseq {
                    cseq = cseq.wrapping_add(rest.len() as u32);
                }
            }
            1 => {
                if let Some(&c) = app.conns.first() {
                    s.send(c, rest);
                }
            }
            2 => {
                if let Some(&c) = app.conns.first() {
                    s.close(c);
                }
            }
            _ => {
                // Raw bytes as a segment (checksum mostly wrong, sometimes right).
                s.input(now, cli, chunk, &mut app, &mut |_, _| {});
            }
        }
        s.poll(now, &mut app, &mut |_, b| {
            wire::parse(srv, cli, b).expect("every segment we emit parses");
        });
        s.flush(now, &mut |_, b| {
            wire::parse(srv, cli, b).expect("every segment we emit parses");
        });
        assert!(s.connections() <= 1);
        assert_eq!(s.connections(), app.conns.len());
    }
}
