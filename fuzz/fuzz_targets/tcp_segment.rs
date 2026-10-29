//! TCP segment processing (M14): a real connection is established through
//! the SYN-cookie handshake, then every fuzz chunk becomes a segment whose
//! flags, sequence/ack offsets (relative to the live connection), window
//! and payload come from the input, interleaved with timer runs, sends and
//! closes. The stack must never panic and its invariants must hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_tcp::wire::{self, ACK, Out, SYN};
use urmqtt_tcp::{App, CloseReason, Config, ConnId, Endpoint, TcpStack};

const S: [u8; 4] = [10, 0, 2, 15];
const C: [u8; 4] = [10, 0, 2, 2];

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

fn seg(sport: u16, seq: u32, ack: u32, flags: u8, window: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    wire::emit(
        C,
        S,
        &Out {
            sport,
            dport: 8883,
            seq,
            ack,
            flags,
            window,
            mss: (flags & SYN != 0).then_some(1460),
        },
        payload,
        &mut b,
    );
    b
}

fuzz_target!(|data: &[u8]| {
    let mut s = TcpStack::new(
        Config {
            local_addr: S,
            ports: vec![8883],
            mss: 1460,
            rcv_wnd: 65535,
            max_conns: 64,
            tx_max: 64 * 1024,
            cookie_key: [3; 16],
            rst_per_sec: 1000,
        },
        0,
    );
    let mut app = Sink::default();
    let mut out: Vec<Vec<u8>> = Vec::new();
    // Handshake: SYN, then the ACK echoing the cookie.
    let client_isn = 1000u32;
    s.input(
        0,
        C,
        &seg(5555, client_isn, 0, SYN, 65535, &[]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    let Some(synack) = out.pop() else { return };
    let h = wire::parse(S, C, &synack).expect("our own SYN-ACK parses");
    let server_isn = h.seq;
    s.input(
        0,
        C,
        &seg(
            5555,
            client_isn + 1,
            server_isn.wrapping_add(1),
            ACK,
            65535,
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
                let b = seg(
                    5555,
                    seq,
                    ack,
                    flags & 0x3f,
                    u16::from_le_bytes([*w0, *w1]),
                    rest,
                );
                s.input(now, C, &b, &mut app, &mut |_, _| {});
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
                s.input(now, C, chunk, &mut app, &mut |_, _| {});
            }
        }
        s.poll(now, &mut app, &mut |_, b| {
            wire::parse(S, C, b).expect("every segment we emit parses");
        });
        s.flush(now, &mut |_, b| {
            wire::parse(S, C, b).expect("every segment we emit parses");
        });
        assert!(s.connections() <= 1);
        assert_eq!(s.connections(), app.conns.len());
    }
});
