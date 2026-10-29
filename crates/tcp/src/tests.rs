//! Host tests: a scripted TCP client talks to the stack over a simulated
//! link that can drop, duplicate and delay segments in both directions.

use super::*;
use std::collections::{BTreeMap, VecDeque as Dq};

const SERVER: [u8; 4] = [10, 0, 2, 15];
const CLIENT: [u8; 4] = [10, 0, 2, 2];
const PORT: u16 = 8883;

fn cfg() -> Config {
    Config {
        local_addr: SERVER,
        ports: alloc::vec![PORT, 1883],
        mss: 1460,
        rcv_wnd: 65535,
        max_conns: 1024,
        tx_max: 256 * 1024,
        cookie_key: [9; 16],
        rst_per_sec: 1000,
    }
}

/// Server application: echoes everything back and closes after the peer.
#[derive(Default)]
struct Echo {
    accepted: Vec<ConnId>,
    received: BTreeMap<ConnId, Vec<u8>>,
    /// Bytes still to echo.
    pending: BTreeMap<ConnId, Vec<u8>>,
    peer_closed: Vec<ConnId>,
    closed: Vec<(ConnId, CloseReason)>,
    refuse: bool,
}

impl App for Echo {
    fn accept(&mut self, c: ConnId, port: u16, _r: Endpoint) -> bool {
        assert_eq!(port, PORT);
        self.accepted.push(c);
        !self.refuse
    }
    fn data(&mut self, c: ConnId, d: &[u8]) {
        self.received.entry(c).or_default().extend_from_slice(d);
        self.pending.entry(c).or_default().extend_from_slice(d);
    }
    fn peer_closed(&mut self, c: ConnId) {
        self.peer_closed.push(c);
    }
    fn closed(&mut self, c: ConnId, why: CloseReason) {
        self.closed.push((c, why));
    }
}

impl Echo {
    /// What the kernel loop does after input: reply, close when done.
    fn reply(&mut self, s: &mut TcpStack) {
        for (&c, buf) in self.pending.iter_mut() {
            let n = s.send(c, buf);
            buf.drain(..n);
        }
        for &c in &self.peer_closed {
            if self.pending.get(&c).is_none_or(Vec::is_empty) {
                s.close(c);
            }
        }
    }
}

struct Seg {
    at: u64,
    to_server: bool,
    bytes: Vec<u8>,
    src: [u8; 4],
}

/// Deterministic xorshift.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// A minimal TCP client: go-back-N on a fixed timeout, in-order receive.
struct Client {
    port: u16,
    isn: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    established: bool,
    data: Vec<u8>,
    rx: Vec<u8>,
    fin_sent: bool,
    fin_acked: bool,
    peer_fin: bool,
    last_progress: u64,
    window: u16,
    reset: bool,
}

impl Client {
    fn new(port: u16, isn: u32, data: Vec<u8>) -> Self {
        Self {
            port,
            isn,
            snd_una: isn,
            snd_nxt: isn,
            rcv_nxt: 0,
            established: false,
            data,
            rx: Vec::new(),
            fin_sent: false,
            fin_acked: false,
            peer_fin: false,
            last_progress: 0,
            window: 65535,
            reset: false,
        }
    }

    fn seg(&self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        wire::emit(
            CLIENT,
            SERVER,
            &Out {
                sport: self.port,
                dport: PORT,
                seq,
                ack: if flags & ACK != 0 { self.rcv_nxt } else { 0 },
                flags,
                window: self.window,
                mss: (flags & SYN != 0).then_some(1460),
            },
            payload,
            &mut b,
        );
        b
    }

    fn sent_all(&self) -> bool {
        self.snd_una.wrapping_sub(self.isn + 1) as usize >= self.data.len()
    }

    /// Segments to send now.
    fn outgoing(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.reset {
            return out;
        }
        if !self.established {
            if self.snd_nxt == self.isn || now.saturating_sub(self.last_progress) > 300 {
                self.snd_nxt = self.isn + 1;
                self.last_progress = now;
                out.push(self.seg(self.isn, SYN, &[]));
            }
            return out;
        }
        // Go back to the first unacknowledged byte after a timeout.
        if now.saturating_sub(self.last_progress) > 300 && self.snd_nxt != self.snd_una {
            self.snd_nxt = self.snd_una;
            if self.fin_sent && !self.fin_acked {
                self.fin_sent = false;
            }
            self.last_progress = now;
        }
        let base = self.isn + 1;
        loop {
            let off = self.snd_nxt.wrapping_sub(base) as usize;
            if off >= self.data.len() {
                break;
            }
            let end = (off + 1000).min(self.data.len());
            let s = self.seg(self.snd_nxt, ACK | PSH, &self.data[off..end]);
            self.snd_nxt = self.snd_nxt.wrapping_add((end - off) as u32);
            out.push(s);
            if self.snd_nxt.wrapping_sub(self.snd_una) > 32_000 {
                break;
            }
        }
        if self.sent_all() && !self.fin_sent && self.rx_done() {
            out.push(self.seg(self.snd_nxt, ACK | FIN, &[]));
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_sent = true;
        }
        out
    }

    fn rx_done(&self) -> bool {
        self.rx.len() >= self.data.len()
    }

    /// Handles a segment from the server; returns an immediate reply.
    fn input(&mut self, now: u64, b: &[u8]) -> Option<Vec<u8>> {
        let h = wire::parse(SERVER, CLIENT, b).unwrap();
        let payload = &b[h.data_off..];
        if h.flags & RST != 0 {
            self.reset = true;
            return None;
        }
        if h.flags & SYN != 0 {
            self.rcv_nxt = h.seq.wrapping_add(1);
            self.snd_una = h.ack;
            self.established = true;
            self.last_progress = now;
            return Some(self.seg(self.snd_una, ACK, &[]));
        }
        if seq::gt(h.ack, self.snd_una) {
            self.snd_una = h.ack;
            self.last_progress = now;
            if self.fin_sent && h.ack == self.snd_nxt {
                self.fin_acked = true;
            }
        }
        let mut reply = false;
        if !payload.is_empty() {
            if h.seq == self.rcv_nxt {
                self.rx.extend_from_slice(payload);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            }
            reply = true;
        }
        if h.flags & FIN != 0 && h.seq.wrapping_add(payload.len() as u32) == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.peer_fin = true;
            reply = true;
        }
        reply.then(|| self.seg(self.snd_nxt, ACK, &[]))
    }
}

/// Runs client(s) against the stack until done or `limit_ms`.
fn run(
    clients: &mut [Client],
    loss_pct: u64,
    dup_pct: u64,
    seed: u64,
    limit_ms: u64,
) -> (TcpStack, Echo) {
    let mut s = TcpStack::new(cfg(), 0);
    let mut app = Echo::default();
    let mut rng = Rng(seed);
    let mut wire_q: Dq<Seg> = Dq::new();
    let mut now = 0u64;
    while now < limit_ms {
        // Clients send.
        for c in clients.iter_mut() {
            for b in c.outgoing(now) {
                wire_q.push_back(Seg {
                    at: now + 1,
                    to_server: true,
                    bytes: b,
                    src: CLIENT,
                });
            }
        }
        // Deliver due segments (with loss and duplication).
        let mut later = Dq::new();
        while let Some(seg) = wire_q.pop_front() {
            if seg.at > now {
                later.push_back(seg);
                continue;
            }
            if rng.chance(loss_pct) {
                continue;
            }
            let copies = if rng.chance(dup_pct) { 2 } else { 1 };
            for _ in 0..copies {
                if seg.to_server {
                    let mut outq = Vec::new();
                    s.input(now, seg.src, &seg.bytes, &mut app, &mut |_, b| {
                        outq.push(b.to_vec())
                    });
                    for b in outq {
                        later.push_back(Seg {
                            at: now + 1,
                            to_server: false,
                            bytes: b,
                            src: SERVER,
                        });
                    }
                } else {
                    let h = wire::parse(SERVER, CLIENT, &seg.bytes).unwrap();
                    if let Some(c) = clients.iter_mut().find(|c| c.port == h.dport)
                        && let Some(r) = c.input(now, &seg.bytes)
                    {
                        later.push_back(Seg {
                            at: now + 1,
                            to_server: true,
                            bytes: r,
                            src: CLIENT,
                        });
                    }
                }
            }
        }
        wire_q = later;
        // The server's loop: reply, timers, flush.
        app.reply(&mut s);
        let mut outq = Vec::new();
        s.poll(now, &mut app, &mut |_, b| outq.push(b.to_vec()));
        s.flush(now, &mut |_, b| outq.push(b.to_vec()));
        for b in outq {
            wire_q.push_back(Seg {
                at: now + 1,
                to_server: false,
                bytes: b,
                src: SERVER,
            });
        }
        let done = clients
            .iter()
            .all(|c| (c.rx_done() && c.fin_acked && c.peer_fin) || c.reset)
            && s.connections() == 0;
        if done && wire_q.is_empty() {
            break;
        }
        now += 1;
    }
    (s, app)
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn lossless_echo_and_clean_close() {
    let data = payload(100_000, 1);
    let mut c = [Client::new(40000, 1000, data.clone())];
    let (s, app) = run(&mut c, 0, 0, 1, 20_000);
    assert_eq!(
        c[0].rx.len(),
        data.len(),
        "received {} of {} (stats {:?}, closed {:?})",
        c[0].rx.len(),
        data.len(),
        s.stats,
        app.closed
    );
    assert!(c[0].rx == data);
    assert!(c[0].fin_acked && c[0].peer_fin);
    assert_eq!(app.closed, [(0, CloseReason::Normal)]);
    assert_eq!(s.connections(), 0);
    assert_eq!(s.stats.retransmits, 0);
    assert_eq!(s.stats.cookies_ok, 1);
}

#[test]
fn delivers_everything_under_loss_and_duplication() {
    for seed in 1..=8u64 {
        let data = payload(60_000, seed as u8);
        let mut cs = [
            Client::new(40001, 7, data.clone()),
            Client::new(40002, u32::MAX - 500, payload(30_000, 9)),
        ];
        let (s, app) = run(&mut cs, 10, 5, seed * 7919, 600_000);
        assert_eq!(cs[0].rx.len(), data.len(), "seed {seed}: {:?}", s.stats);
        assert!(cs[0].rx == data, "seed {seed}");
        assert!(
            cs[1].rx == payload(30_000, 9),
            "seed {seed} (sequence wrap)"
        );
        assert!(cs.iter().all(|c| c.fin_acked && c.peer_fin), "seed {seed}");
        assert_eq!(s.connections(), 0, "seed {seed}");
        assert!(
            s.stats.retransmits > 0,
            "seed {seed}: loss must cause retransmissions"
        );
        assert_eq!(app.closed.len(), 2);
    }
}

#[test]
fn syn_flood_holds_no_state_and_forged_acks_are_refused() {
    let mut s = TcpStack::new(cfg(), 0);
    let mut app = Echo::default();
    let mut out = Vec::new();
    for port in 0..5000u16 {
        let c = Client::new(port.wrapping_add(10_000), u32::from(port) * 77, Vec::new());
        s.input(0, CLIENT, &c.seg(c.isn, SYN, &[]), &mut app, &mut |_, b| {
            out.push(b.to_vec())
        });
    }
    assert_eq!(s.connections(), 0);
    assert_eq!(s.stats.cookies_sent, 5000);
    assert_eq!(out.len(), 5000);
    // A forged final ACK (guessed ISN) gets RST and no connection.
    let mut c = Client::new(30_000, 5, Vec::new());
    c.rcv_nxt = 0x1234_5678;
    out.clear();
    s.input(0, CLIENT, &c.seg(6, ACK, &[]), &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    assert_eq!(s.connections(), 0);
    assert_eq!(s.stats.cookies_bad, 1);
    let h = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    assert_eq!(h.flags & RST, RST);
    // A SYN to a closed port gets RST|ACK.
    out.clear();
    let mut seg = Vec::new();
    wire::emit(
        CLIENT,
        SERVER,
        &Out {
            sport: 1,
            dport: 25,
            seq: 9,
            ack: 0,
            flags: SYN,
            window: 100,
            mss: None,
        },
        &[],
        &mut seg,
    );
    s.input(0, CLIENT, &seg, &mut app, &mut |_, b| out.push(b.to_vec()));
    let h = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    assert_eq!((h.flags, h.ack), (RST | ACK, 10));
    // A cookie older than two periods is refused.
    let mut c = Client::new(30_001, 5, Vec::new());
    out.clear();
    s.input(0, CLIENT, &c.seg(c.isn, SYN, &[]), &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    c.input(0, &out[0]);
    out.clear();
    s.input(
        300_000,
        CLIENT,
        &c.seg(c.snd_una, ACK, &[]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    assert_eq!(s.connections(), 0);
}

/// Establishes one connection; returns (stack, app, client, id).
fn established() -> (TcpStack, Echo, Client, ConnId) {
    let mut s = TcpStack::new(cfg(), 0);
    let mut app = Echo::default();
    let mut c = Client::new(41000, 100, Vec::new());
    let mut out = Vec::new();
    s.input(0, CLIENT, &c.seg(c.isn, SYN, &[]), &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    let ack = c.input(0, &out[0]).unwrap();
    c.snd_nxt = c.snd_una;
    s.input(0, CLIENT, &ack, &mut app, &mut |_, _| {});
    assert_eq!(s.connections(), 1);
    let id = app_id(&app);
    (s, app, c, id)
}

fn app_id(app: &Echo) -> ConnId {
    app.accepted[0]
}

#[test]
fn rst_rules_rfc5961() {
    let (mut s, mut app, c, id) = established();
    let mut out = Vec::new();
    // In window but not exact: challenge ACK, connection stays.
    let rst = c.seg(c.snd_nxt.wrapping_add(10), RST, &[]);
    let bad = {
        let mut b = rst.clone();
        // seq must be in *our* receive window: rcv_nxt + 10
        let h = wire::parse(CLIENT, SERVER, &b).unwrap();
        assert_eq!(h.flags, RST);
        b.clear();
        wire::emit(
            CLIENT,
            SERVER,
            &Out {
                sport: c.port,
                dport: PORT,
                seq: c.snd_una.wrapping_add(10),
                ack: 0,
                flags: RST,
                window: 0,
                mss: None,
            },
            &[],
            &mut b,
        );
        b
    };
    s.input(0, CLIENT, &bad, &mut app, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(s.connections(), 1);
    assert_eq!(wire::parse(SERVER, CLIENT, &out[0]).unwrap().flags, ACK);
    // A SYN on an established connection: challenge ACK too.
    out.clear();
    s.input(
        0,
        CLIENT,
        &c.seg(c.snd_una, SYN, &[]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    assert_eq!(s.connections(), 1);
    // Exact sequence number: the connection is reset.
    let mut exact = Vec::new();
    wire::emit(
        CLIENT,
        SERVER,
        &Out {
            sport: c.port,
            dport: PORT,
            seq: c.snd_una,
            ack: 0,
            flags: RST,
            window: 0,
            mss: None,
        },
        &[],
        &mut exact,
    );
    s.input(0, CLIENT, &exact, &mut app, &mut |_, _| {});
    assert_eq!(s.connections(), 0);
    assert_eq!(app.closed, [(id, CloseReason::Reset)]);
}

#[test]
fn retransmission_gives_up_after_backoff() {
    let (mut s, mut app, _c, id) = established();
    assert_eq!(s.send(id, &[1u8; 5000]), 5000);
    let mut sent = 0;
    s.flush(0, &mut |_, _| sent += 1);
    assert!(sent >= 4);
    // The peer vanished: nothing is ever acknowledged.
    let mut now = 0;
    let mut retx = 0;
    while s.connections() == 1 && now < 3_600_000 {
        now += 100;
        s.poll(now, &mut app, &mut |_, _| retx += 1);
    }
    assert_eq!(app.closed, [(id, CloseReason::Timeout)]);
    assert!(retx >= usize::from(MAX_RETRIES));
    // Exponential backoff: 1 + 2 + 4 + ... seconds before giving up.
    assert!(now > 200_000, "gave up after {now} ms");
}

#[test]
fn zero_window_is_probed_then_resumes() {
    let (mut s, mut app, mut c, id) = established();
    // The client closes its window.
    c.window = 0;
    let mut out = Vec::new();
    s.input(
        1,
        CLIENT,
        &c.seg(c.snd_nxt, ACK, &[]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    s.send(id, b"hello world");
    s.flush(2, &mut |_, b| out.push(b.to_vec()));
    assert!(
        out.iter()
            .all(|b| wire::parse(SERVER, CLIENT, b).unwrap().data_off == b.len()),
        "no data into a zero window"
    );
    // Persist timer: a one-byte probe after the RTO.
    out.clear();
    s.poll(2000, &mut app, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(out.len(), 1);
    let h = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    assert_eq!(out[0].len() - h.data_off, 1);
    // Window reopens: the rest follows.
    c.window = 65535;
    c.rcv_nxt = h.seq.wrapping_add(1);
    out.clear();
    s.input(
        2001,
        CLIENT,
        &c.seg(c.snd_nxt, ACK, &[]),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    s.flush(2001, &mut |_, b| out.push(b.to_vec()));
    let total: usize = out
        .iter()
        .map(|b| b.len() - wire::parse(SERVER, CLIENT, b).unwrap().data_off)
        .sum();
    assert_eq!(total, 10);
}

#[test]
fn out_of_order_data_gets_a_duplicate_ack_and_waits() {
    let (mut s, mut app, c, id) = established();
    let mut out = Vec::new();
    let base = c.snd_una;
    s.input(
        1,
        CLIENT,
        &c.seg(base.wrapping_add(5), ACK | PSH, b"world"),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    assert!(!app.received.contains_key(&id));
    let h = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    assert_eq!(h.ack, base);
    assert_eq!(s.stats.out_of_order, 1);
    s.input(
        2,
        CLIENT,
        &c.seg(base, ACK | PSH, b"hello"),
        &mut app,
        &mut |_, _| {},
    );
    assert_eq!(app.received[&id], b"hello");
    // A retransmission overlapping old data delivers only the new part.
    s.input(
        3,
        CLIENT,
        &c.seg(base.wrapping_add(3), ACK | PSH, b"loworld"),
        &mut app,
        &mut |_, _| {},
    );
    assert_eq!(app.received[&id], b"helloworld");
}

#[test]
fn reply_carries_the_ack_coalescing() {
    let (mut s, mut app, c, id) = established();
    let mut out = Vec::new();
    s.input(
        1,
        CLIENT,
        &c.seg(c.snd_una, ACK | PSH, b"PINGREQ"),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    assert!(out.is_empty(), "the ACK waits for the end of the pass");
    s.send(id, b"PINGRESP");
    s.flush(1, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(out.len(), 1, "one segment: reply + ACK");
    let h = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
    assert_eq!(h.ack, c.snd_una.wrapping_add(7));
    assert_eq!(&out[0][h.data_off..], b"PINGRESP");
    // Without a reply, flush sends a pure ACK.
    out.clear();
    s.input(
        2,
        CLIENT,
        &c.seg(c.snd_una.wrapping_add(7), ACK | PSH, b"x"),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    s.flush(2, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(out.len(), 1);
    assert_eq!(
        wire::parse(SERVER, CLIENT, &out[0]).unwrap().data_off,
        out[0].len()
    );
}

#[test]
fn refused_and_window_controlled_connections() {
    let mut s = TcpStack::new(cfg(), 0);
    let mut app = Echo {
        refuse: true,
        ..Echo::default()
    };
    let mut c = Client::new(42000, 1, Vec::new());
    let mut out = Vec::new();
    s.input(0, CLIENT, &c.seg(c.isn, SYN, &[]), &mut app, &mut |_, b| {
        out.push(b.to_vec())
    });
    let ack = c.input(0, &out[0]).unwrap();
    out.clear();
    s.input(0, CLIENT, &ack, &mut app, &mut |_, b| out.push(b.to_vec()));
    assert_eq!(s.connections(), 0);
    assert_eq!(
        wire::parse(SERVER, CLIENT, &out[0]).unwrap().flags & RST,
        RST
    );

    let (mut s, mut app, c, id) = established();
    s.set_recv_space(id, 4);
    let mut out = Vec::new();
    s.input(
        1,
        CLIENT,
        &c.seg(c.snd_una, ACK | PSH, b"0123456789"),
        &mut app,
        &mut |_, b| out.push(b.to_vec()),
    );
    // The advertised window was 65535 before shrinking, so it is honoured
    // (a window is never retracted), but the application gets backpressure.
    assert_eq!(app.received[&id].len(), 10);
    s.flush(1, &mut |_, b| out.push(b.to_vec()));
    let w = wire::parse(SERVER, CLIENT, out.last().unwrap())
        .unwrap()
        .window;
    assert!(w < 65535);
}

#[test]
fn survives_heavy_loss() {
    for seed in [3u64, 11, 29] {
        let data = payload(20_000, 4);
        let mut cs = [Client::new(43000, 99, data.clone())];
        let (s, _app) = run(&mut cs, 25, 0, seed, 3_600_000);
        assert!(
            cs[0].rx == data,
            "seed {seed}: got {} bytes",
            cs[0].rx.len()
        );
        assert_eq!(s.connections(), 0, "seed {seed}");
    }
}
