//! The active open (NEXT-7, ADR-315): the stack opens a connection, and
//! every fuzz chunk becomes a segment from the far end (flags, sequence and
//! acknowledgement offsets relative to the connection, window, options from
//! the input; SYN-ACKs while in SYN-SENT), a raw segment, a clock step (SYN
//! retransmissions and the give-up, data retransmissions), an application
//! send, close or abort, or a new connection. The stack must never panic and
//! its invariants must hold: no more than one active connection, nothing
//! but active connections, `connected` at most once per connection and
//! only for one that exists, a segment the stack sends always parses.
#![no_main]

use libfuzzer_sys::fuzz_target;
use urmqtt_tcp::wire::{self, ACK, Ext, Out, RST, SYN};
use urmqtt_tcp::{App, CloseReason, Config, ConnId, Endpoint, TcpStack};

const ME: [u8; 4] = [10, 0, 2, 15];
const PEER: [u8; 4] = [10, 0, 2, 2];
const SINK: u16 = 6514;

#[derive(Default)]
struct Rec {
    connected: Vec<ConnId>,
    closed: Vec<ConnId>,
    received: usize,
}

impl App for Rec {
    fn accept(&mut self, _: ConnId, _: u16, _: Endpoint) -> bool {
        panic!("no listener: nothing is accepted");
    }
    fn data(&mut self, _: ConnId, d: &[u8]) {
        self.received += d.len();
    }
    fn peer_closed(&mut self, _: ConnId) {}
    fn closed(&mut self, c: ConnId, _: CloseReason) {
        self.closed.push(c);
    }
    fn connected(&mut self, c: ConnId) {
        assert!(
            !self.connected.contains(&c) || self.closed.contains(&c),
            "connected twice"
        );
        self.connected.push(c);
    }
}

struct Peer {
    /// Our ISS (from the SYN) and what the peer has received of ours.
    iss: u32,
    rcv_nxt: u32,
    /// The peer's next sequence number.
    snd_nxt: u32,
    lport: u16,
}

fn emit(
    p: &Peer,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    x: &Ext,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    wire::emit_ext(
        PEER,
        ME,
        &Out {
            sport: SINK,
            dport: p.lport,
            seq,
            ack,
            flags,
            window,
            mss,
        },
        x,
        payload,
        &mut b,
    );
    b
}

fn take(data: &mut &[u8], n: usize) -> Vec<u8> {
    let k = n.min(data.len());
    let (a, b) = data.split_at(k);
    *data = b;
    a.to_vec()
}

fn byte(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

fn u16_of(data: &mut &[u8]) -> u16 {
    let b = take(data, 2);
    u16::from_le_bytes([
        b.first().copied().unwrap_or(0),
        b.get(1).copied().unwrap_or(0),
    ])
}

fn u32_of(data: &mut &[u8]) -> u32 {
    (u32::from(u16_of(data)) << 16) | u32::from(u16_of(data))
}

fuzz_target!(|input: &[u8]| {
    let mut s = TcpStack::new(
        Config {
            local_addr: ME,
            ports: vec![8883],
            mss: 1460,
            rcv_wnd: 65535,
            rcv_wnd_scaled: 512 * 1024,
            max_conns: 64,
            tx_max: 64 * 1024,
            tx_cap: 1 << 20,
            ooo_budget: 1 << 20,
            ooo_conn_max: 256 * 1024,
            cookie_key: [7; 16],
            rst_per_sec: 100,
        },
        0,
    );
    s.set_max_active(1);
    let mut app = Rec::default();
    let mut now = 0u64;
    let mut data = input;
    let mut peer = Peer {
        iss: 0,
        rcv_nxt: 0,
        snd_nxt: 0x1000_0000,
        lport: 0,
    };
    let mut conn: Option<ConnId> = None;
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut steps = 0;
    while !data.is_empty() && steps < 256 {
        steps += 1;
        let op = byte(&mut data) % 9;
        match op {
            // A new connection when there is none.
            0 => {
                if conn.is_none_or(|c| app.closed.contains(&c)) {
                    let remote = Endpoint {
                        addr: PEER,
                        port: SINK,
                    };
                    if let Some(p) = s.ephemeral_port(remote, |p| p % 3 == 0) {
                        assert!(p % 3 != 0 && p != 8883);
                        if let Ok(c) = s.connect(now, remote, p, &mut |_, b| out.push(b.to_vec())) {
                            conn = Some(c);
                            peer.lport = p;
                        }
                    }
                }
            }
            // A SYN-ACK, acknowledging our SYN or an offset from it, with options.
            1 => {
                let off = u32::from(byte(&mut data) % 4);
                let o = byte(&mut data);
                let x = Ext {
                    sack_perm: o & 1 != 0,
                    wscale: (o & 2 != 0).then_some(o >> 4),
                    ts: (o & 4 != 0).then_some((0x55, 0x66)),
                    ..Ext::NONE
                };
                let mss = (o & 8 != 0).then(|| u16_of(&mut data));
                let win = u16_of(&mut data);
                let seg = emit(
                    &peer,
                    peer.snd_nxt,
                    peer.iss.wrapping_add(off),
                    SYN | ACK,
                    win,
                    &x,
                    mss,
                    &[],
                );
                s.input(now, PEER, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
                if off == 1 {
                    peer.snd_nxt = peer.snd_nxt.wrapping_add(1);
                    peer.rcv_nxt = peer.iss.wrapping_add(1);
                }
            }
            // A segment relative to the connection.
            2 => {
                let flags = byte(&mut data) & 0x1f;
                let dseq = u16_of(&mut data);
                let dack = u16_of(&mut data);
                let win = u16_of(&mut data);
                let len = usize::from(byte(&mut data)) * 8;
                let payload = take(&mut data, len);
                let seq = peer
                    .snd_nxt
                    .wrapping_add(u32::from(dseq))
                    .wrapping_sub(1000);
                let ack = peer
                    .rcv_nxt
                    .wrapping_add(u32::from(dack))
                    .wrapping_sub(1000);
                let seg = emit(&peer, seq, ack, flags, win, &Ext::NONE, None, &payload);
                s.input(now, PEER, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
                if seq == peer.snd_nxt && flags & RST == 0 {
                    peer.snd_nxt = peer.snd_nxt.wrapping_add(payload.len() as u32);
                }
            }
            // Raw bytes as a segment (the parser and every path behind it).
            3 => {
                let len = usize::from(byte(&mut data));
                let raw = take(&mut data, len);
                s.input(now, PEER, &raw, &mut app, &mut |_, b| out.push(b.to_vec()));
            }
            // The clock.
            4 => {
                now += u64::from(u16_of(&mut data)) * 4;
                s.poll(now, &mut app, &mut |_, b| out.push(b.to_vec()));
            }
            5 => {
                if let Some(c) = conn {
                    let n = usize::from(u16_of(&mut data));
                    s.send(c, &vec![0x5a; n]);
                }
            }
            6 => {
                if let Some(c) = conn {
                    s.close(c);
                }
            }
            7 => {
                if let Some(c) = conn.take() {
                    s.abort(c, &mut |_, b| out.push(b.to_vec()));
                    app.closed.push(c);
                }
            }
            // An arbitrary ACK number for the peer's view (a peer that lost track).
            _ => peer.rcv_nxt = u32_of(&mut data),
        }
        s.flush(now, &mut |_, b| out.push(b.to_vec()));
        for b in out.drain(..) {
            let h = wire::parse(ME, PEER, &b).expect("the stack sends valid segments");
            if h.flags & SYN != 0 {
                assert_eq!(h.flags, SYN, "our SYN carries no other flag");
                peer.iss = h.seq;
            } else if h.flags & ACK != 0 && h.flags & RST == 0 {
                peer.rcv_nxt = h.seq.wrapping_add((b.len() - h.data_off) as u32);
            }
        }
        assert!(s.active_connections() <= 1);
        assert_eq!(
            s.connections(),
            s.active_connections(),
            "only active connections exist"
        );
        for c in &app.connected {
            assert!(
                app.closed.contains(c) || s.remote(*c).is_some(),
                "a connected connection vanished without `closed`"
            );
        }
    }
});
