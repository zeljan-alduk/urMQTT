//! Options and loss recovery (ADR-222): window scaling, SACK and timestamps
//! negotiated through the SYN cookie, and what a receiver does with data that
//! arrives beyond a hole.

use alloc::vec::Vec;

use super::*;
use crate::wire::Ext;

const SERVER: [u8; 4] = [10, 0, 2, 15];
const CLIENT: [u8; 4] = [10, 0, 2, 2];
const CPORT: u16 = 41000;
const C_ISN: u32 = 5_000;

fn cfg(ooo_budget: usize, ooo_conn_max: usize) -> Config {
    Config {
        local_addr: SERVER,
        ports: alloc::vec![8883],
        mss: 1460,
        rcv_wnd: 65535,
        rcv_wnd_scaled: 1 << 20,
        max_conns: 64,
        tx_max: 64 * 1024,
        tx_cap: 1 << 20,
        ooo_budget,
        ooo_conn_max,
        cookie_key: [4; 16],
        rst_per_sec: 1000,
    }
}

#[derive(Default)]
struct Sink {
    data: Vec<u8>,
    conns: Vec<ConnId>,
}

impl App for Sink {
    fn accept(&mut self, c: ConnId, _p: u16, _r: Endpoint) -> bool {
        self.conns.push(c);
        true
    }
    fn data(&mut self, _c: ConnId, d: &[u8]) {
        self.data.extend_from_slice(d);
    }
    fn peer_closed(&mut self, _c: ConnId) {}
    fn closed(&mut self, _c: ConnId, _why: CloseReason) {}
}

/// What the client side of a connection knows.
struct Peer {
    srv_next: u32,
    ts: bool,
    shift: u8,
    now_ts: u32,
    tsecr: u32,
}

fn segment(
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    x: &Ext,
    mss: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    wire::emit_ext(
        CLIENT,
        SERVER,
        &Out {
            sport: CPORT,
            dport: 8883,
            seq,
            ack,
            flags,
            window,
            mss: mss.then_some(1460),
        },
        x,
        payload,
        &mut b,
    );
    b
}

/// SYN with the options asked for, then the final ACK echoing what the
/// SYN-ACK said; returns the SYN-ACK's header too.
fn open(
    s: &mut TcpStack,
    app: &mut Sink,
    wscale: Option<u8>,
    sack: bool,
    ts: bool,
) -> (Peer, Header) {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let syn = Ext {
        sack_perm: sack,
        wscale,
        ts: ts.then_some((1000, 0)),
        ..Ext::NONE
    };
    s.input(
        0,
        CLIENT,
        &segment(SYN, C_ISN, 0, 65535, &syn, true, &[]),
        app,
        &mut |_, b| out.push(b.to_vec()),
    );
    let synack = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    let echoed = synack.ts.map_or(0, |(v, _)| v);
    let ack = Ext {
        ts: ts.then_some((1001, echoed)),
        ..Ext::NONE
    };
    s.input(
        1,
        CLIENT,
        &segment(
            ACK,
            C_ISN + 1,
            synack.seq.wrapping_add(1),
            65535,
            &ack,
            false,
            &[],
        ),
        app,
        &mut |_, _| {},
    );
    let peer = Peer {
        srv_next: synack.seq.wrapping_add(1),
        ts,
        shift: wscale.unwrap_or(0),
        now_ts: 1002,
        tsecr: echoed,
    };
    (peer, synack)
}

impl Peer {
    /// A data segment at stream offset `off` (0 = the first byte after the handshake).
    fn data(&mut self, off: u32, payload: &[u8]) -> Vec<u8> {
        self.now_ts += 1;
        let x = Ext {
            ts: self.ts.then_some((self.now_ts, self.tsecr)),
            ..Ext::NONE
        };
        let window = (1u32 << 20 >> self.shift).min(65535) as u16;
        segment(
            ACK | PSH,
            C_ISN + 1 + off,
            self.srv_next,
            window,
            &x,
            false,
            payload,
        )
    }
}

fn stream(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn last_ack(out: &[Vec<u8>]) -> Header {
    wire::parse(SERVER, CLIENT, out.last().unwrap()).unwrap()
}

#[test]
fn a_peer_without_timestamps_gets_no_options() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (_, synack) = open(&mut s, &mut app, Some(7), true, false);
    assert_eq!(synack.ts, None);
    assert_eq!(synack.wscale, None);
    assert!(!synack.sack_ok);
    assert_eq!(synack.window, 65535);
    assert_eq!(s.stats.scaled, 0);
    assert_eq!(s.stats.sack_neg, 0);
}

#[test]
fn window_scale_sack_and_timestamps_ride_in_the_cookie() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (_, synack) = open(&mut s, &mut app, Some(7), true, true);
    // 1 MiB needs a shift of 5 to fit 16 bits.
    assert_eq!(synack.wscale, Some(5));
    assert!(synack.sack_ok);
    let (tsval, tsecr) = synack.ts.unwrap();
    assert_eq!(tsecr, 1000);
    let o = cookie::ts_decode(tsval);
    assert_eq!((o.sack_ok, o.wscale), (true, Some(7)));
    // The SYN-ACK window is never scaled.
    assert_eq!(synack.window, 65535);
    assert_eq!((s.stats.scaled, s.stats.sack_neg), (1, 1));
    assert_eq!(app.conns.len(), 1);
    // The state needed no memory before the final ACK: the stack holds only
    // the accepted connection.
    assert_eq!(s.connections(), 1);
}

#[test]
fn the_announced_window_is_scaled_and_the_peers_is_read_scaled() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    let mut out = Vec::new();
    let d = stream(1000);
    s.input(5, CLIENT, &p.data(0, &d), &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    s.flush(5, &mut |_, b| out.push(b.to_vec()));
    let h = last_ack(&out);
    assert_eq!(h.ack, C_ISN + 1 + 1000);
    // About 1 MiB announced as a 16-bit field of 32-byte units.
    let announced = u32::from(h.window) << 5;
    assert!(
        announced > (1 << 20) - 64 * 1024 && announced <= 1 << 20,
        "{announced}"
    );
    // Timestamps: echoed, with ours not ahead of the clock.
    let (_, tsecr) = h.ts.unwrap();
    assert_eq!(tsecr, p.now_ts);
    // The peer's window of 1 MiB >> 7 = 8192 units read as 1 MiB: the server
    // may now queue far more than 64 KiB.
    let k = s.conn(app.conns[0]).unwrap();
    assert_eq!(k.snd_shift, 7);
    assert_eq!(k.snd_wnd, 8192 << 7);
}

#[test]
fn segments_are_shorter_by_the_timestamp_option() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    let c = app.conns[0];
    s.input(5, CLIENT, &p.data(0, &stream(10)), &mut app, &mut |_, _| {});
    s.send(c, &stream(5000));
    let mut out = Vec::new();
    s.flush(6, &mut |_, b| out.push(b.to_vec()));
    assert!(out.len() >= 3);
    for seg in &out {
        let h = wire::parse(SERVER, CLIENT, seg).unwrap();
        assert!(h.ts.is_some());
        // 32 header bytes and at most 1448 of payload: the IP packet stays
        // within 1500.
        assert!(seg.len() <= 1480, "{}", seg.len());
        assert!(seg.len() - h.data_off <= 1448);
    }
}

#[test]
fn one_lost_segment_costs_one_retransmission() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    let data = stream(30 * 1000);
    let mut out = Vec::new();
    // 30 segments of 1000 bytes; the 3rd (offset 2000) is lost.
    for i in 0..30u32 {
        if i == 2 {
            continue;
        }
        let seg = p.data(
            i * 1000,
            &data[(i * 1000) as usize..((i + 1) * 1000) as usize],
        );
        s.input(10, CLIENT, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
    }
    // Only the first two arrived in order.
    assert_eq!(app.data.len(), 2000);
    assert_eq!(s.stats.ooo_buffered, 27);
    assert_eq!(s.stats.ooo_bytes, 27_000);
    // The two in-order segments were answered by one ACK (every second one is),
    // every out-of-order segment at once with the same ACK, and the SACK blocks
    // name the single range beyond the hole.
    let acks: Vec<Header> = out
        .iter()
        .map(|b| wire::parse(SERVER, CLIENT, b).unwrap())
        .collect();
    assert_eq!(acks.len(), 1 + 27);
    assert_eq!(acks[0].ack, C_ISN + 1 + 2000);
    assert_eq!(acks[0].nsack, 0);
    let h = acks.last().unwrap();
    assert_eq!(h.ack, C_ISN + 1 + 2000);
    assert_eq!(h.nsack, 1);
    assert_eq!(h.sack[0], (C_ISN + 1 + 3000, C_ISN + 1 + 30_000));
    // The retransmission is the only thing the sender must do.
    out.clear();
    let seg = p.data(2000, &data[2000..3000]);
    s.input(20, CLIENT, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(app.data, data);
    assert_eq!(last_ack(&out).ack, C_ISN + 1 + 30_000);
    assert_eq!(s.stats.ooo_bytes, 0);
}

#[test]
fn every_second_segment_is_acknowledged_when_it_arrives() {
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 18), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    let data = stream(9 * 1000);
    let mut out = Vec::new();
    // Nine segments arrive in one pass, no flush between them: the ACKs of a
    // batch do not wait for its end (a sender of a long batch was held up by
    // the one ACK per pass, ADR-232).
    for i in 0..9u32 {
        let seg = p.data(
            i * 1000,
            &data[(i * 1000) as usize..((i + 1) * 1000) as usize],
        );
        s.input(10, CLIENT, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
    }
    let acks: Vec<u32> = out
        .iter()
        .map(|b| wire::parse(SERVER, CLIENT, b).unwrap().ack)
        .collect();
    assert_eq!(
        acks,
        [2000, 4000, 6000, 8000].map(|n| C_ISN + 1 + n),
        "one ACK for every two segments"
    );
    // The ninth is acknowledged at the end of the pass.
    out.clear();
    s.flush(11, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(out.len(), 1);
    assert_eq!(last_ack(&out).ack, C_ISN + 1 + 9000);
    // Nothing is owed after that.
    out.clear();
    s.flush(12, &mut |_, b| out.push(b.to_vec()));
    assert!(out.is_empty());
    assert_eq!(app.data, data);
}

#[test]
fn without_a_budget_the_old_behaviour_remains() {
    let mut s = TcpStack::new(cfg(0, 0), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    let data = stream(3000);
    let mut out = Vec::new();
    s.input(
        10,
        CLIENT,
        &p.data(1000, &data[1000..2000]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    assert!(app.data.is_empty());
    assert_eq!((s.stats.ooo_buffered, s.stats.ooo_dropped), (0, 1));
    assert_eq!(last_ack(&out).nsack, 0);
}

#[test]
fn held_bytes_are_bounded_per_connection_and_per_core() {
    // Per connection: 5 000 bytes.
    let mut s = TcpStack::new(cfg(1 << 20, 5_000), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, Some(7), true, true);
    for i in 1..20u32 {
        s.input(
            10,
            CLIENT,
            &p.data(i * 1000, &stream(1000)),
            &mut app,
            &mut |_, _| {},
        );
    }
    assert_eq!(s.stats.ooo_bytes, 5_000);
    assert_eq!(s.stats.ooo_buffered, 5);
    assert_eq!(s.stats.ooo_dropped, 14);
    // The connection ends: what it held is released.
    let c = app.conns[0];
    let mut out = Vec::new();
    s.abort(c, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(s.stats.ooo_bytes, 0);
    assert_eq!(s.ooo_used, 0);

    // Per core: two connections share 8 000 bytes.
    let mut s = TcpStack::new(cfg(8_000, 1 << 20), 0);
    let mut app = Sink::default();
    let (mut p1, _) = open(&mut s, &mut app, Some(7), true, true);
    for i in 1..6u32 {
        s.input(
            10,
            CLIENT,
            &p1.data(i * 1000, &stream(1000)),
            &mut app,
            &mut |_, _| {},
        );
    }
    assert_eq!(s.stats.ooo_bytes, 5_000);
    // A second connection finds only 3 000 left.
    let mut other = Vec::new();
    let syn = Ext {
        ts: Some((7, 0)),
        ..Ext::NONE
    };
    let mk = |sport: u16, flags: u8, seq: u32, ack: u32, x: &Ext, pl: &[u8]| {
        let mut b = Vec::new();
        wire::emit_ext(
            CLIENT,
            SERVER,
            &Out {
                sport,
                dport: 8883,
                seq,
                ack,
                flags,
                window: 65535,
                mss: (flags & SYN != 0).then_some(1460),
            },
            x,
            pl,
            &mut b,
        );
        b
    };
    s.input(
        11,
        CLIENT,
        &mk(42000, SYN, 100, 0, &syn, &[]),
        &mut app,
        &mut |_, b| other.push(b.to_vec()),
    );
    let sa = wire::parse(SERVER, CLIENT, &other[0]).unwrap();
    let ackx = Ext {
        ts: Some((8, sa.ts.unwrap().0)),
        ..Ext::NONE
    };
    s.input(
        12,
        CLIENT,
        &mk(42000, ACK, 101, sa.seq.wrapping_add(1), &ackx, &[]),
        &mut app,
        &mut |_, _| {},
    );
    for i in 1..6u32 {
        s.input(
            13,
            CLIENT,
            &mk(
                42000,
                ACK | PSH,
                101 + i * 1000,
                sa.seq.wrapping_add(1),
                &ackx,
                &stream(1000),
            ),
            &mut app,
            &mut |_, _| {},
        );
    }
    assert_eq!(s.stats.ooo_bytes, 8_000);
    assert!(s.stats.ooo_dropped >= 2);
}

#[test]
fn a_window_beyond_what_was_announced_is_not_kept() {
    // No scaling: the window is 65535; data 100 000 bytes ahead is not kept.
    let mut s = TcpStack::new(cfg(1 << 20, 1 << 20), 0);
    let mut app = Sink::default();
    let (mut p, _) = open(&mut s, &mut app, None, false, false);
    s.input(
        10,
        CLIENT,
        &p.data(100_000, &stream(1000)),
        &mut app,
        &mut |_, _| {},
    );
    assert_eq!(s.stats.ooo_bytes, 0);
    // A segment that straddles the right edge is cut at it.
    s.input(
        11,
        CLIENT,
        &p.data(65_000, &stream(2000)),
        &mut app,
        &mut |_, _| {},
    );
    assert_eq!(s.stats.ooo_bytes, 535);
}
