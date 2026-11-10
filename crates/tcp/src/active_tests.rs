//! NEXT-7 (ADR-315): host tests of the active open. A hand-driven peer
//! checks the SYN-SENT rules segment by segment; then the stack's client
//! side talks to its own server side over a link that drops, duplicates and
//! reorders segments (the client-side loss simulation of ROADMAP NEXT-7).

use super::*;
use std::collections::{BTreeMap, VecDeque as Dq};

const ME: [u8; 4] = [10, 0, 2, 15];
const PEER: [u8; 4] = [10, 0, 2, 2];
const LISTEN: u16 = 8883;
const SINK: u16 = 6514;

fn cfg(addr: [u8; 4], ports: Vec<u16>) -> Config {
    Config {
        local_addr: addr,
        ports,
        mss: 1460,
        rcv_wnd: 65535,
        rcv_wnd_scaled: 512 * 1024,
        tx_cap: 1 << 20,
        ooo_budget: 1 << 20,
        ooo_conn_max: 256 * 1024,
        max_conns: 64,
        tx_max: 256 * 1024,
        cookie_key: [9; 16],
        rst_per_sec: 1000,
    }
}

fn client() -> TcpStack {
    let mut s = TcpStack::new(cfg(ME, alloc::vec![LISTEN]), 0);
    s.set_max_active(4);
    s
}

#[derive(Default)]
struct Rec {
    connected: Vec<ConnId>,
    data: BTreeMap<ConnId, Vec<u8>>,
    peer_closed: Vec<ConnId>,
    closed: Vec<(ConnId, CloseReason)>,
    accepted: Vec<ConnId>,
}

impl App for Rec {
    fn accept(&mut self, c: ConnId, _p: u16, _r: Endpoint) -> bool {
        self.accepted.push(c);
        true
    }
    fn data(&mut self, c: ConnId, d: &[u8]) {
        self.data.entry(c).or_default().extend_from_slice(d);
    }
    fn peer_closed(&mut self, c: ConnId) {
        self.peer_closed.push(c);
    }
    fn closed(&mut self, c: ConnId, why: CloseReason) {
        self.closed.push((c, why));
    }
    fn connected(&mut self, c: ConnId) {
        self.connected.push(c);
    }
}

/// A segment from the peer to us, with raw options.
#[allow(clippy::too_many_arguments)]
fn from_peer(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
    x: &wire::Ext,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let o = wire::Out {
        sport,
        dport,
        seq,
        ack,
        flags,
        window: win,
        mss,
    };
    let mut b = Vec::new();
    wire::emit_ext(PEER, ME, &o, x, payload, &mut b);
    b
}

fn parse(seg: &[u8]) -> wire::Header {
    wire::parse(ME, PEER, seg).expect("the stack sends valid segments")
}

/// Connects to PEER:SINK and returns the connection, its port and the SYN.
fn open(s: &mut TcpStack, now: u64) -> (ConnId, u16, wire::Header) {
    let remote = Endpoint {
        addr: Addr::v4(PEER),
        port: SINK,
    };
    let lport = s.ephemeral_port(remote, |_| false).unwrap();
    let mut q = Vec::new();
    let c = s
        .connect(now, remote, lport, &mut |d, b| {
            assert_eq!(d, Addr::v4(PEER));
            q.push(b.to_vec())
        })
        .unwrap();
    assert_eq!(q.len(), 1);
    let h = parse(&q[0]);
    (c, lport, h)
}

fn input(s: &mut TcpStack, now: u64, seg: &[u8], app: &mut Rec) -> Vec<wire::Header> {
    let mut q = Vec::new();
    s.input(now, PEER, seg, app, &mut |_, b| q.push(b.to_vec()));
    s.flush(now, &mut |_, b| q.push(b.to_vec()));
    q.iter().map(|b| parse(b)).collect()
}

fn tick(s: &mut TcpStack, now: u64, app: &mut Rec) -> Vec<wire::Header> {
    let mut q = Vec::new();
    s.poll(now, app, &mut |_, b| q.push(b.to_vec()));
    s.flush(now, &mut |_, b| q.push(b.to_vec()));
    q.iter().map(|b| parse(b)).collect()
}

const FULL: wire::Ext = wire::Ext {
    sack_perm: true,
    wscale: Some(7),
    ts: Some((5000, 0)),
    sacks: [(0, 0); 3],
    nsack: 0,
};

#[test]
fn the_syn_offers_the_options_and_the_handshake_negotiates_them() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    assert!((EPHEMERAL_FIRST..=EPHEMERAL_LAST).contains(&lport));
    assert_eq!(syn.flags, wire::SYN);
    assert_eq!(syn.mss, Some(1460));
    assert!(syn.sack_ok);
    assert_eq!(syn.wscale, Some(4), "512 KiB needs a shift of 4");
    assert!(syn.ts.is_some());
    assert_eq!((syn.dport, syn.sport), (SINK, lport));
    assert!(!s.is_established(c));
    assert_eq!(
        s.send(c, b"early"),
        0,
        "nothing is queued before the handshake"
    );
    let mut x = FULL;
    x.ts = Some((5000, syn.ts.unwrap().0));
    let synack = from_peer(
        SINK,
        lport,
        7000,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        1000,
        &x,
        Some(1400),
        &[],
    );
    let out = input(&mut s, 40, &synack, &mut app);
    assert_eq!(app.connected, alloc::vec![c]);
    assert!(s.is_established(c));
    assert_eq!(out.len(), 1);
    let ack = out[0];
    assert_eq!(ack.flags, wire::ACK);
    assert_eq!((ack.seq, ack.ack), (syn.seq.wrapping_add(1), 7001));
    assert_eq!(
        ack.ts.map(|t| t.1),
        Some(5000),
        "the peer's TSval is echoed"
    );
    // The windows: the peer's SYN window is unscaled; ours is scaled by 4.
    assert_eq!(ack.window, ((512 * 1024) >> 4) as u16);
    let k = s.conn(c).unwrap();
    assert_eq!(
        (k.snd_shift, k.rcv_shift, k.mss, k.snd_wnd),
        (7, 4, 1400, 1000)
    );
    assert!(k.has(TS_OK) && k.has(SACK_OK));
    assert_eq!(k.srtt, 40, "the SYN's round trip is the first sample");
    assert_eq!(s.stats.active_established, 1);
    // Data both ways, then our FIN.
    assert_eq!(s.send(c, b"hello"), 5);
    let out = tick(&mut s, 41, &mut app);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].seq, syn.seq.wrapping_add(1));
    let d = from_peer(
        SINK,
        lport,
        7001,
        syn.seq.wrapping_add(6),
        wire::ACK | wire::PSH,
        1000,
        &wire::Ext {
            ts: Some((5001, 0)),
            ..wire::Ext::NONE
        },
        None,
        b"world",
    );
    input(&mut s, 50, &d, &mut app);
    assert_eq!(app.data[&c], b"world");
    s.close(c);
    let out = tick(&mut s, 60, &mut app);
    assert!(out.iter().any(|h| h.flags & wire::FIN != 0));
    let fin_ack = from_peer(
        SINK,
        lport,
        7006,
        syn.seq.wrapping_add(7),
        wire::ACK | wire::FIN,
        1000,
        &wire::Ext {
            ts: Some((5002, 0)),
            ..wire::Ext::NONE
        },
        None,
        &[],
    );
    input(&mut s, 70, &fin_ack, &mut app);
    assert_eq!(app.closed, alloc::vec![(c, CloseReason::Normal)]);
    assert_eq!((s.connections(), s.active_connections()), (0, 0));
}

#[test]
fn a_peer_without_options_gets_a_plain_connection() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    let synack = from_peer(
        SINK,
        lport,
        1,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        None,
        &[],
    );
    let out = input(&mut s, 5, &synack, &mut app);
    assert_eq!(out[0].ts, None);
    let k = s.conn(c).unwrap();
    assert_eq!(
        (k.snd_shift, k.rcv_shift, k.mss, k.flags & (TS_OK | SACK_OK)),
        (0, 0, 536, 0)
    );
    assert_eq!(out[0].window, 65535);
}

#[test]
fn the_syn_is_retransmitted_with_backoff_then_given_up() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, _, syn) = open(&mut s, 0);
    let mut sent_at = Vec::new();
    for now in (0..70_000).step_by(100) {
        for h in tick(&mut s, now, &mut app) {
            assert_eq!(h.flags, wire::SYN);
            assert_eq!(h.seq, syn.seq, "the same ISS every time");
            sent_at.push(now);
        }
    }
    assert_eq!(sent_at, alloc::vec![1000, 3000, 7000, 15_000, 31_000]);
    assert_eq!(app.closed, alloc::vec![(c, CloseReason::Timeout)]);
    assert_eq!(s.stats.syn_retransmits, 5);
    assert_eq!(s.stats.active_timeouts, 1);
    assert_eq!((s.connections(), s.active_connections()), (0, 0));
    // Fewer retries when asked.
    let mut s = client();
    s.set_syn_retries(1);
    let (c, _, _) = open(&mut s, 0);
    let mut app = Rec::default();
    for now in (0..5_000).step_by(100) {
        tick(&mut s, now, &mut app);
    }
    assert_eq!(app.closed, alloc::vec![(c, CloseReason::Timeout)]);
}

#[test]
fn a_late_syn_ack_after_a_retransmission_gives_no_rtt_sample() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    tick(&mut s, 1000, &mut app);
    let synack = from_peer(
        SINK,
        lport,
        1,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    input(&mut s, 1050, &synack, &mut app);
    let k = s.conn(c).unwrap();
    assert_eq!((k.srtt, k.rto), (0, 3000));
    assert!(k.timer.is_none(), "nothing in flight, no timer");
}

#[test]
fn syn_sent_rules() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    let iss = syn.seq;
    // An ACK that does not acknowledge our SYN: a RST for it, state kept.
    for bad in [iss, iss.wrapping_add(2), iss.wrapping_sub(100)] {
        let seg = from_peer(
            SINK,
            lport,
            1,
            bad,
            wire::SYN | wire::ACK,
            8192,
            &wire::Ext::NONE,
            Some(1460),
            &[],
        );
        let out = input(&mut s, 1, &seg, &mut app);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].flags, out[0].seq), (wire::RST, bad));
        assert!(!s.is_established(c));
    }
    // ... and a RST that does not acknowledge it changes nothing.
    let seg = from_peer(
        SINK,
        lport,
        1,
        iss,
        wire::RST | wire::ACK,
        0,
        &wire::Ext::NONE,
        None,
        &[],
    );
    assert!(input(&mut s, 1, &seg, &mut app).is_empty());
    // A RST without an ACK cannot be told from a blind one: ignored.
    let seg = from_peer(SINK, lport, 1, 0, wire::RST, 0, &wire::Ext::NONE, None, &[]);
    assert!(input(&mut s, 1, &seg, &mut app).is_empty());
    // A bare SYN (simultaneous open) and a bare ACK are dropped.
    let seg = from_peer(
        SINK,
        lport,
        1,
        0,
        wire::SYN,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    assert!(input(&mut s, 1, &seg, &mut app).is_empty());
    let seg = from_peer(
        SINK,
        lport,
        1,
        iss.wrapping_add(1),
        wire::ACK,
        8192,
        &wire::Ext::NONE,
        None,
        &[],
    );
    assert!(input(&mut s, 1, &seg, &mut app).is_empty());
    assert!(app.closed.is_empty() && app.connected.is_empty());
    assert_eq!(s.connections(), 1);
    // The RST that acknowledges the SYN: refused.
    let seg = from_peer(
        SINK,
        lport,
        0,
        iss.wrapping_add(1),
        wire::RST | wire::ACK,
        0,
        &wire::Ext::NONE,
        None,
        &[],
    );
    assert!(input(&mut s, 2, &seg, &mut app).is_empty());
    assert_eq!(app.closed, alloc::vec![(c, CloseReason::Refused)]);
    assert_eq!(s.stats.active_refused, 1);
    assert_eq!((s.connections(), s.active_connections()), (0, 0));
}

#[test]
fn a_tiny_mss_is_refused_with_a_reset() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    let seg = from_peer(
        SINK,
        lport,
        1,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        Some(100),
        &[],
    );
    let out = input(&mut s, 1, &seg, &mut app);
    assert_eq!(out.len(), 1);
    assert_eq!(
        (out[0].flags, out[0].seq),
        (wire::RST, syn.seq.wrapping_add(1))
    );
    assert_eq!(app.closed, alloc::vec![(c, CloseReason::Refused)]);
    assert_eq!(s.connections(), 0);
}

#[test]
fn data_on_the_syn_ack_is_delivered_and_syn_fin_is_not_a_segment() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    // SYN and FIN together: refused by the parser, like on the server side.
    let seg = from_peer(
        SINK,
        lport,
        99,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK | wire::FIN,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        b"banner",
    );
    assert!(input(&mut s, 1, &seg, &mut app).is_empty());
    assert!(!s.is_established(c));
    let seg = from_peer(
        SINK,
        lport,
        99,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK | wire::PSH,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        b"banner",
    );
    let out = input(&mut s, 1, &seg, &mut app);
    assert_eq!(app.data[&c], b"banner");
    assert!(
        out.iter().any(|h| h.ack == 99 + 1 + 6),
        "the data is acknowledged: {out:?}"
    );
}

#[test]
fn close_before_the_handshake_sends_the_fin_after_it_and_abort_resets() {
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    s.close(c);
    assert!(
        tick(&mut s, 1, &mut app).is_empty(),
        "no FIN before the SYN-ACK"
    );
    let seg = from_peer(
        SINK,
        lport,
        1,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    let out = input(&mut s, 2, &seg, &mut app);
    assert!(out.iter().any(|h| h.flags & wire::FIN != 0), "{out:?}");
    // Abort in SYN-SENT: a bare RST, no `closed`.
    let (c2, _, syn2) = open(&mut s, 3);
    let mut q = Vec::new();
    s.abort(c2, &mut |_, b| q.push(b.to_vec()));
    let h = parse(&q[0]);
    assert_eq!(
        (h.flags, h.seq, h.ack),
        (wire::RST, syn2.seq.wrapping_add(1), 0)
    );
    assert_eq!(s.active_connections(), 1);
    assert!(app.closed.iter().all(|&(x, _)| x != c2));
}

#[test]
fn connect_refuses_what_it_must() {
    let remote = Endpoint {
        addr: Addr::v4(PEER),
        port: SINK,
    };
    let mut q = |_: Addr, _: &[u8]| {};
    // Off by default: a server stack never opens a connection.
    let mut s = TcpStack::new(cfg(ME, alloc::vec![LISTEN]), 0);
    assert_eq!(
        s.connect(0, remote, 50000, &mut q),
        Err(ConnectError::NotAllowed)
    );
    s.set_max_active(1);
    assert_eq!(
        s.connect(0, remote, LISTEN, &mut q),
        Err(ConnectError::PortInUse)
    );
    assert_eq!(
        s.connect(0, remote, 0, &mut q),
        Err(ConnectError::PortInUse)
    );
    for bad in [
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [255, 255, 255, 255],
        ME,
    ] {
        let r = Endpoint {
            addr: bad.into(),
            port: SINK,
        };
        assert_eq!(
            s.connect(0, r, 50000, &mut q),
            Err(ConnectError::BadDestination),
            "{bad:?}"
        );
    }
    assert_eq!(
        s.connect(
            0,
            Endpoint {
                addr: Addr::v4(PEER),
                port: 0
            },
            50000,
            &mut q
        ),
        Err(ConnectError::BadDestination)
    );
    assert!(s.connect(0, remote, 50000, &mut q).is_ok());
    assert_eq!(
        s.connect(0, remote, 50001, &mut q),
        Err(ConnectError::NotAllowed),
        "the limit"
    );
    s.set_max_active(2);
    assert_eq!(
        s.connect(0, remote, 50000, &mut q),
        Err(ConnectError::PortInUse),
        "the same 4-tuple"
    );
    assert!(s.connect(0, remote, 50001, &mut q).is_ok());
    // No address yet.
    let mut s = TcpStack::new(cfg([0; 4], alloc::vec![]), 0);
    s.set_max_active(1);
    assert_eq!(
        s.connect(0, remote, 50000, &mut q),
        Err(ConnectError::NoAddress)
    );
    // A full table.
    let mut c = cfg(ME, alloc::vec![]);
    c.max_conns = 1;
    let mut s = TcpStack::new(c, 0);
    s.set_max_active(4);
    assert!(s.connect(0, remote, 50000, &mut q).is_ok());
    assert_eq!(
        s.connect(0, remote, 50001, &mut q),
        Err(ConnectError::TableFull)
    );
    assert_eq!(MAX_ACTIVE_LIMIT, 64);
    s.set_max_active(1000);
    assert_eq!(s.max_active, MAX_ACTIVE_LIMIT);
}

#[test]
fn ephemeral_ports_avoid_listeners_reserved_ports_and_used_tuples() {
    let mut s = TcpStack::new(cfg(ME, alloc::vec![LISTEN, 50000, 60000]), 0);
    s.set_max_active(MAX_ACTIVE_LIMIT);
    let remote = Endpoint {
        addr: Addr::v4(PEER),
        port: SINK,
    };
    let reserved = |p: u16| p % 2 == 1;
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..MAX_ACTIVE_LIMIT {
        let p = s.ephemeral_port(remote, reserved).unwrap();
        assert!((EPHEMERAL_FIRST..=EPHEMERAL_LAST).contains(&p));
        assert!(p % 2 == 0 && p != 50000 && p != 60000, "{p}");
        assert!(seen.insert(p), "port {p} given twice ({i})");
        s.connect(0, remote, p, &mut |_, _| {}).unwrap();
    }
    // Spread out: not 64 neighbours.
    let span = seen.last().unwrap() - seen.first().unwrap();
    assert!(span > 1000, "{span}");
    // Only one port left: found, then none.
    let mut s = TcpStack::new(cfg(ME, alloc::vec![]), 0);
    s.set_max_active(4);
    let only = |p: u16| p != 51234;
    let p = s.ephemeral_port(remote, only).unwrap();
    assert_eq!(p, 51234);
    s.connect(0, remote, p, &mut |_, _| {}).unwrap();
    assert_eq!(s.ephemeral_port(remote, only), None);
    // ... but the same port to another destination is a different tuple.
    let other = Endpoint {
        addr: Addr::v4([10, 0, 2, 3]),
        port: SINK,
    };
    assert_eq!(s.ephemeral_port(other, only), Some(51234));
}

#[test]
fn initial_sequence_numbers_are_keyed_and_move_with_the_clock() {
    let a = TcpStack::new(cfg(ME, alloc::vec![]), 0);
    let mut c2 = cfg(ME, alloc::vec![]);
    c2.cookie_key = [10; 16];
    let b = TcpStack::new(c2, 0);
    let k = Key {
        addr: Addr::v4(PEER),
        rport: SINK,
        lport: 50000,
    };
    let k2 = Key { lport: 50001, ..k };
    assert_ne!(a.isn(&k, 0), b.isn(&k, 0), "another key, another ISN");
    assert_ne!(a.isn(&k, 0), a.isn(&k2, 0));
    assert_eq!(a.isn(&k, 1).wrapping_sub(a.isn(&k, 0)), 250, "4 µs ticks");
    assert_ne!(a.isn_key, [9; 16]);
}

#[test]
fn server_and_client_sides_share_the_table_without_confusion() {
    // A listener's connection and an outbound one on the same stack.
    let mut s = client();
    let mut app = Rec::default();
    let (c, lport, syn) = open(&mut s, 0);
    // A SYN from the peer to the listener gets a cookie SYN-ACK, ...
    let seg = from_peer(
        40000,
        LISTEN,
        5,
        0,
        wire::SYN,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    let out = input(&mut s, 1, &seg, &mut app);
    assert_eq!(out[0].flags, wire::SYN | wire::ACK);
    // ... a segment for an unused ephemeral port gets a RST ...
    let seg = from_peer(
        SINK,
        lport.wrapping_add(1).max(EPHEMERAL_FIRST),
        5,
        0,
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    let out = input(&mut s, 1, &seg, &mut app);
    assert_eq!(out[0].flags & wire::RST, wire::RST);
    // ... and the outbound one still completes.
    let seg = from_peer(
        SINK,
        lport,
        1,
        syn.seq.wrapping_add(1),
        wire::SYN | wire::ACK,
        8192,
        &wire::Ext::NONE,
        Some(1460),
        &[],
    );
    input(&mut s, 2, &seg, &mut app);
    assert_eq!(app.connected, alloc::vec![c]);
    assert!(app.accepted.is_empty());
}

// --- our client against our server over a bad link ---------------------------

struct Link {
    rng: u64,
    loss: u32,
    dup: u32,
    reorder: u32,
    /// In flight: (due ms, destination is the server, bytes).
    q: Dq<(u64, bool, Vec<u8>)>,
}

impl Link {
    fn rand(&mut self) -> u32 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 32) as u32
    }

    fn send(&mut self, now: u64, to_server: bool, b: &[u8]) {
        if self.rand() % 100 < self.loss {
            return;
        }
        let delay = 5 + u64::from(if self.rand() % 100 < self.reorder {
            self.rand() % 30
        } else {
            0
        });
        self.q.push_back((now + delay, to_server, b.to_vec()));
        if self.rand() % 100 < self.dup {
            self.q.push_back((now + delay + 1, to_server, b.to_vec()));
        }
    }
}

fn pattern(i: usize, salt: u8) -> u8 {
    (i as u8).wrapping_mul(31).wrapping_add(salt)
}

/// Returns (bytes the server got, bytes the client got, the client's close).
fn transfer(
    seed: u64,
    loss: u32,
    n_up: usize,
    n_down: usize,
) -> (usize, usize, Option<CloseReason>) {
    const SRV: [u8; 4] = [10, 0, 2, 2];
    let mut cli = TcpStack::new(cfg(ME, alloc::vec![]), 0);
    cli.set_max_active(1);
    let mut scfg = cfg(SRV, alloc::vec![SINK]);
    scfg.cookie_key = [3; 16];
    let mut srv = TcpStack::new(scfg, 0);
    let mut link = Link {
        rng: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
        loss,
        dup: 3,
        reorder: 10,
        q: Dq::new(),
    };
    let (mut ca, mut sa) = (Rec::default(), Rec::default());
    let remote = Endpoint {
        addr: Addr::v4(SRV),
        port: SINK,
    };
    let lport = cli.ephemeral_port(remote, |_| false).unwrap();
    let mut out = Vec::new();
    let c = cli
        .connect(0, remote, lport, &mut |_, b| out.push(b.to_vec()))
        .unwrap();
    for b in out {
        link.send(0, true, &b);
    }
    let up: Vec<u8> = (0..n_up).map(|i| pattern(i, 1)).collect();
    let down: Vec<u8> = (0..n_down).map(|i| pattern(i, 2)).collect();
    let (mut sent_up, mut sent_down) = (0usize, 0usize);
    let mut closed_down = false;
    let mut now = 0u64;
    while now < 600_000 {
        now += 1;
        let mut c2s: Vec<Vec<u8>> = Vec::new();
        let mut s2c: Vec<Vec<u8>> = Vec::new();
        // Deliver what is due.
        let mut i = 0;
        while i < link.q.len() {
            if link.q[i].0 <= now {
                let (_, to_server, b) = link.q.remove(i).unwrap();
                if to_server {
                    srv.input(now, ME, &b, &mut sa, &mut |_, o| s2c.push(o.to_vec()));
                } else {
                    cli.input(now, SRV, &b, &mut ca, &mut |_, o| c2s.push(o.to_vec()));
                }
            } else {
                i += 1;
            }
        }
        // The client writes once connected, then closes.
        if ca.connected.contains(&c) && sent_up < up.len() {
            sent_up += cli.send(c, &up[sent_up..]);
            if sent_up == up.len() {
                cli.close(c);
            }
        }
        // The server echoes a stream of its own back to every connection.
        if let Some(&sc) = sa.accepted.first() {
            if sent_down < down.len() {
                sent_down += srv.send(sc, &down[sent_down..]);
            } else if !closed_down && sa.peer_closed.contains(&sc) {
                srv.close(sc);
                closed_down = true;
            }
        }
        cli.poll(now, &mut ca, &mut |_, o| c2s.push(o.to_vec()));
        cli.flush(now, &mut |_, o| c2s.push(o.to_vec()));
        srv.poll(now, &mut sa, &mut |_, o| s2c.push(o.to_vec()));
        srv.flush(now, &mut |_, o| s2c.push(o.to_vec()));
        for b in c2s {
            link.send(now, true, &b);
        }
        for b in s2c {
            link.send(now, false, &b);
        }
        if !ca.closed.is_empty() && !sa.closed.is_empty() && link.q.is_empty() {
            break;
        }
    }
    let got_up = sa.data.values().next().map_or(0, Vec::len);
    let got_down = ca.data.get(&c).map_or(0, Vec::len);
    if let Some(d) = sa.data.values().next() {
        assert_eq!(
            d[..],
            up[..d.len()],
            "seed {seed}: the server's stream differs"
        );
    }
    if let Some(d) = ca.data.get(&c) {
        assert_eq!(
            d[..],
            down[..d.len()],
            "seed {seed}: the client's stream differs"
        );
    }
    assert!(ca.connected.len() <= 1);
    (got_up, got_down, ca.closed.first().map(|x| x.1))
}

#[test]
fn client_side_transfer_survives_loss_duplication_and_reordering() {
    for seed in 0..40 {
        let loss = [0, 2, 5, 10][seed as usize % 4];
        let (up, down, why) = transfer(seed, loss, 200_000, 50_000);
        assert_eq!((up, down), (200_000, 50_000), "seed {seed}, loss {loss}%");
        assert_eq!(why, Some(CloseReason::Normal), "seed {seed}");
    }
}

#[test]
fn a_dead_link_ends_in_a_timeout_not_a_hang() {
    let (up, down, why) = transfer(1, 100, 1000, 1000);
    assert_eq!((up, down, why), (0, 0, Some(CloseReason::Timeout)));
}
