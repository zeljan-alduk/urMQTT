//! NEXT-7 (ADR-315): the H3 model test extended to the active open. The
//! stack opens a connection to a well-behaved peer server that tracks
//! sequence numbers exactly, answers the SYN only when told to (a SYN it
//! does not answer is a lost one), receives everything the stack sends and
//! acknowledges only when told to. Random sequences of peer actions,
//! application calls, clock steps and hostile segments (the RFC 9293
//! SYN-SENT cases and the RFC 5961 ones once open) are applied, and after
//! every step:
//!
//! - in SYN-SENT the stack holds one connection, sent nothing but SYNs (all
//!   with the same ISS, at most `SYN_RETRIES + 1` of them) and told the
//!   application nothing; at 63 s without an answer it is gone with
//!   [`CloseReason::Timeout`];
//! - `connected` is reported once, only after a SYN-ACK that acknowledged
//!   the SYN;
//! - the application received exactly the bytes the peer sent while the
//!   connection was open, in order; the peer received a prefix of what the
//!   application sent, in order, never past the window it advertised;
//! - hostile segments never closed the connection or moved its state, except
//!   a RST that acknowledges the SYN (refused) or one at `rcv_nxt`;
//! - a connection the model says is gone holds no state in the stack.

use alloc::vec::Vec;

use proptest::prelude::*;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

use super::*;

const ME: [u8; 4] = [10, 0, 2, 15];
const PEER: [u8; 4] = [10, 0, 2, 2];
const SINK: u16 = 6514;
const P_ISN: u32 = 0xfff0_0000;
/// When an unanswered active open is given up (1 + 2 + 4 + 8 + 16 + 32 s).
const SYN_GIVE_UP_MS: u64 = 63_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    SynSent,
    Open,
    Gone,
}

#[derive(Debug, Clone)]
pub struct Model {
    phase: Phase,
    /// Time spent in SYN-SENT, ms.
    syn_ms: u64,
    peer_fin: bool,
    app_closed: bool,
}

#[derive(Debug, Clone)]
pub enum Step {
    Connect,
    /// The peer answers the SYN; with all options or none.
    SynAck(bool),
    /// The peer refuses: RST|ACK for the SYN.
    Refuse,
    /// SYN-SENT: a SYN-ACK whose ACK does not cover our SYN.
    BadAck(u32),
    /// SYN-SENT: a RST without an ACK.
    BlindRst,
    /// SYN-SENT: a bare SYN (simultaneous open).
    BareSyn,
    PeerData(u16),
    PeerFin,
    PeerAck,
    PeerWindow(u16),
    AppSend(u16),
    AppClose,
    Tick(u16),
    RstInWindow(u16),
    RstExact,
    SynOnOpen,
    AckUnsent,
    FarFutureData,
}

pub struct RefModel;

impl ReferenceStateMachine for RefModel {
    type State = Model;
    type Transition = Step;

    fn init_state() -> BoxedStrategy<Model> {
        Just(Model {
            phase: Phase::Idle,
            syn_ms: 0,
            peer_fin: false,
            app_closed: false,
        })
        .boxed()
    }

    fn transitions(m: &Model) -> BoxedStrategy<Step> {
        match m.phase {
            Phase::Idle | Phase::Gone => {
                prop_oneof![Just(Step::Connect), (1u16..2000).prop_map(Step::Tick)].boxed()
            }
            Phase::SynSent => prop_oneof![
                4 => any::<bool>().prop_map(Step::SynAck),
                1 => Just(Step::Refuse),
                1 => prop_oneof![Just(0u32), Just(2), Just(1000), Just(u32::MAX / 2)].prop_map(Step::BadAck),
                1 => Just(Step::BlindRst),
                1 => Just(Step::BareSyn),
                1 => (1u16..5000).prop_map(Step::AppSend),
                1 => Just(Step::AppClose),
                3 => prop_oneof![Just(10u16), Just(900), Just(4000), Just(20_000)].prop_map(Step::Tick),
            ]
            .boxed(),
            Phase::Open => prop_oneof![
                4 => (1u16..3000).prop_map(Step::PeerData),
                1 => Just(Step::PeerFin),
                4 => Just(Step::PeerAck),
                1 => prop_oneof![Just(0u16), Just(1000u16), Just(65535u16)].prop_map(Step::PeerWindow),
                4 => (1u16..5000).prop_map(Step::AppSend),
                1 => Just(Step::AppClose),
                3 => prop_oneof![Just(10u16), Just(250), Just(1100), Just(4000)].prop_map(Step::Tick),
                1 => (1u16..30000).prop_map(Step::RstInWindow),
                1 => Just(Step::RstExact),
                1 => Just(Step::SynOnOpen),
                1 => Just(Step::AckUnsent),
                1 => Just(Step::FarFutureData),
            ]
            .boxed(),
        }
    }

    fn preconditions(m: &Model, s: &Step) -> bool {
        match s {
            Step::Connect => matches!(m.phase, Phase::Idle | Phase::Gone),
            Step::SynAck(_) | Step::Refuse | Step::BadAck(_) | Step::BlindRst | Step::BareSyn => {
                m.phase == Phase::SynSent
            }
            Step::AppSend(_) | Step::AppClose => {
                matches!(m.phase, Phase::SynSent | Phase::Open) && !m.app_closed
            }
            Step::PeerData(_) | Step::PeerFin => m.phase == Phase::Open && !m.peer_fin,
            Step::Tick(_) => true,
            _ => m.phase == Phase::Open,
        }
    }

    fn apply(mut m: Model, s: &Step) -> Model {
        match s {
            Step::Connect => {
                m = Model {
                    phase: Phase::SynSent,
                    syn_ms: 0,
                    peer_fin: false,
                    app_closed: false,
                };
            }
            Step::SynAck(_) => m.phase = Phase::Open,
            Step::Refuse | Step::RstExact => m.phase = Phase::Gone,
            Step::PeerFin => m.peer_fin = true,
            Step::AppClose => m.app_closed = true,
            Step::Tick(ms) if m.phase == Phase::SynSent => {
                m.syn_ms += u64::from(*ms);
                if m.syn_ms >= SYN_GIVE_UP_MS {
                    m.phase = Phase::Gone;
                }
            }
            _ => {}
        }
        m
    }
}

#[derive(Default)]
struct App2 {
    connected: Vec<ConnId>,
    received: Vec<u8>,
    closed: Vec<(ConnId, CloseReason)>,
    peer_closed: bool,
}

impl App for App2 {
    fn accept(&mut self, _c: ConnId, _p: u16, _r: Endpoint) -> bool {
        panic!("the client stack has no listener");
    }
    fn data(&mut self, _c: ConnId, d: &[u8]) {
        self.received.extend_from_slice(d);
    }
    fn peer_closed(&mut self, _c: ConnId) {
        self.peer_closed = true;
    }
    fn closed(&mut self, c: ConnId, why: CloseReason) {
        self.closed.push((c, why));
    }
    fn connected(&mut self, c: ConnId) {
        self.connected.push(c);
    }
}

fn byte(i: usize, salt: u8) -> u8 {
    (i as u8).wrapping_mul(37).wrapping_add(salt)
}

pub struct Sut {
    s: TcpStack,
    app: App2,
    now: u64,
    conn: Option<ConnId>,
    lport: u16,
    /// Our ISS, from the first SYN; how many SYNs the peer saw.
    iss: Option<u32>,
    syns: usize,
    /// The handshake completed (the peer sent its SYN-ACK).
    synced: bool,
    // The peer, absolute sequence numbers.
    p_nxt: u32,
    p_sent: usize,
    p_fin: bool,
    /// Next byte of ours the peer expects; what it has acknowledged.
    rcv_nxt: u32,
    acked: u32,
    win: u16,
    /// The window edge the peer last advertised (ack + window, scaled).
    edge: u32,
    /// The peer's window shift (it offered 0 or 2).
    shift: u8,
    rx: Vec<u8>,
    s_fin: bool,
    a_sent: usize,
    gone: bool,
}

impl Sut {
    fn new() -> Self {
        let cfg = Config {
            local_addr: ME,
            ports: alloc::vec![8883],
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
        };
        let mut s = TcpStack::new(cfg, 0);
        s.set_max_active(1);
        Self {
            s,
            app: App2::default(),
            now: 0,
            conn: None,
            lport: 0,
            iss: None,
            syns: 0,
            synced: false,
            p_nxt: P_ISN,
            p_sent: 0,
            p_fin: false,
            rcv_nxt: 0,
            acked: 0,
            win: 65535,
            edge: 0,
            shift: 0,
            rx: Vec::new(),
            s_fin: false,
            a_sent: 0,
            gone: true,
        }
    }

    fn deliver(&mut self, seg: &[u8]) {
        let mut q = Vec::new();
        self.s
            .input(self.now, PEER, seg, &mut self.app, &mut |d, b| {
                assert_eq!(d, PEER);
                q.push(b.to_vec())
            });
        self.service(q);
    }

    fn service(&mut self, mut q: Vec<Vec<u8>>) {
        self.s
            .poll(self.now, &mut self.app, &mut |_, b| q.push(b.to_vec()));
        self.s.flush(self.now, &mut |_, b| q.push(b.to_vec()));
        for b in q {
            self.receive(&b);
        }
        if let Some(c) = self.conn
            && self.app.closed.iter().any(|&(x, _)| x == c)
        {
            self.gone = true;
        }
    }

    /// The peer takes in a segment of ours and checks the stack's side of
    /// the invariants.
    fn receive(&mut self, b: &[u8]) {
        let h = wire::parse(ME, PEER, b).expect("the stack sends valid segments");
        assert_eq!(h.sport, self.lport, "a segment from another port");
        assert!((EPHEMERAL_FIRST..=EPHEMERAL_LAST).contains(&h.sport));
        let payload = &b[h.data_off..];
        if h.flags & wire::RST != 0 {
            return;
        }
        if h.flags & wire::SYN != 0 {
            assert!(!self.synced, "a SYN after the handshake");
            assert_eq!(h.flags, wire::SYN, "our SYN carries no other flag");
            assert!(payload.is_empty(), "no data on our SYN");
            match self.iss {
                None => self.iss = Some(h.seq),
                Some(i) => assert_eq!(i, h.seq, "a retransmitted SYN changed the ISS"),
            }
            self.syns += 1;
            assert!(
                self.syns <= usize::from(SYN_RETRIES) + 1,
                "{} SYNs",
                self.syns
            );
            return;
        }
        assert!(
            self.synced,
            "a segment other than a SYN before the SYN-ACK: {h:?}"
        );
        if h.flags & wire::ACK != 0 {
            assert!(
                seq::le(h.ack, self.p_nxt),
                "the stack acknowledged unsent data: ack {} > {}",
                h.ack,
                self.p_nxt
            );
        }
        if !payload.is_empty() {
            let end = h.seq.wrapping_add(payload.len() as u32);
            let slack = if self.edge == self.acked { 1 } else { 0 };
            assert!(
                seq::le(end, self.edge.wrapping_add(slack)),
                "sent past the window: end {end} > edge {} (+{slack})",
                self.edge
            );
            if h.seq == self.rcv_nxt {
                self.rx.extend_from_slice(payload);
                self.rcv_nxt = end;
            } else if seq::lt(h.seq, self.rcv_nxt) && seq::gt(end, self.rcv_nxt) {
                let skip = self.rcv_nxt.wrapping_sub(h.seq) as usize;
                self.rx.extend_from_slice(&payload[skip..]);
                self.rcv_nxt = end;
            }
        }
        if h.flags & wire::FIN != 0
            && h.seq.wrapping_add(payload.len() as u32) == self.rcv_nxt
            && !self.s_fin
        {
            self.s_fin = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn raw(
        &self,
        seq: u32,
        ack: u32,
        flags: u8,
        win: u16,
        x: &wire::Ext,
        mss: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let o = wire::Out {
            sport: SINK,
            dport: self.lport,
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

    /// A peer segment acknowledging what it received, with its window.
    fn seg(&mut self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        if flags & wire::ACK != 0 {
            self.acked = self.rcv_nxt;
            self.edge = self.rcv_nxt.wrapping_add(u32::from(self.win) << self.shift);
        }
        self.raw(
            seq,
            self.rcv_nxt,
            flags,
            self.win,
            &wire::Ext::NONE,
            None,
            payload,
        )
    }

    fn data(&self, n: usize) -> Vec<u8> {
        (0..n).map(|i| byte(self.p_sent + i, 1)).collect()
    }

    fn ack(&mut self) {
        let s = self.seg(self.p_nxt, wire::ACK, &[]);
        self.deliver(&s);
    }

    fn in_syn_sent(&self) -> bool {
        !self.gone && !self.synced
    }
}

pub struct ActiveModelTest;

impl StateMachineTest for ActiveModelTest {
    type SystemUnderTest = Sut;
    type Reference = RefModel;

    fn init_test(_m: &Model) -> Sut {
        Sut::new()
    }

    fn apply(mut t: Sut, _m: &Model, s: Step) -> Sut {
        let before = t.s.connections();
        match s {
            Step::Connect => {
                let remote = Endpoint {
                    addr: PEER,
                    port: SINK,
                };
                t.lport = t.s.ephemeral_port(remote, |p| p == 8883).unwrap();
                t.iss = None;
                t.syns = 0;
                t.synced = false;
                t.p_nxt = P_ISN;
                t.p_sent = 0;
                t.p_fin = false;
                t.rx.clear();
                t.s_fin = false;
                t.a_sent = 0;
                // Connection ids are reused: the records start over.
                t.app = App2::default();
                t.win = 65535;
                t.shift = 0;
                let mut q = Vec::new();
                let c =
                    t.s.connect(t.now, remote, t.lport, &mut |_, b| q.push(b.to_vec()))
                        .expect("a connection is allowed");
                t.conn = Some(c);
                t.gone = false;
                t.service(q);
                assert_eq!(t.syns, 1, "connect sends one SYN");
            }
            Step::SynAck(full) => {
                if t.in_syn_sent() {
                    let iss = t.iss.expect("a SYN was seen");
                    let x = if full {
                        wire::Ext {
                            sack_perm: true,
                            wscale: Some(2),
                            ts: Some((77, 1)),
                            ..wire::Ext::NONE
                        }
                    } else {
                        wire::Ext::NONE
                    };
                    let mss = full.then_some(1400);
                    t.rcv_nxt = iss.wrapping_add(1);
                    t.p_nxt = P_ISN.wrapping_add(1);
                    t.synced = true;
                    // The SYN-ACK's own window is not scaled.
                    t.acked = t.rcv_nxt;
                    t.edge = t.rcv_nxt.wrapping_add(u32::from(t.win));
                    let seg = t.raw(P_ISN, t.rcv_nxt, wire::SYN | wire::ACK, t.win, &x, mss, &[]);
                    if full {
                        t.shift = 2;
                    }
                    let n = t.app.connected.len();
                    t.deliver(&seg);
                    assert_eq!(
                        t.app.connected.len(),
                        n + 1,
                        "the handshake did not complete"
                    );
                    assert_eq!(t.app.connected.last().copied(), t.conn);
                    assert!(t.s.is_established(t.conn.unwrap()));
                }
            }
            Step::Refuse => {
                if t.in_syn_sent() {
                    let iss = t.iss.unwrap();
                    let seg = t.raw(
                        0,
                        iss.wrapping_add(1),
                        wire::RST | wire::ACK,
                        0,
                        &wire::Ext::NONE,
                        None,
                        &[],
                    );
                    t.deliver(&seg);
                    assert_eq!(
                        t.app.closed.last().copied(),
                        Some((t.conn.unwrap(), CloseReason::Refused))
                    );
                    assert!(t.gone);
                }
            }
            Step::BadAck(off) => {
                if t.in_syn_sent() {
                    let iss = t.iss.unwrap();
                    // 0 is the ISS itself: no SYN is acknowledged by it.
                    let bad = iss.wrapping_add(if off == 1 { 2 } else { off });
                    let seg = t.raw(
                        P_ISN,
                        bad,
                        wire::SYN | wire::ACK,
                        1000,
                        &wire::Ext::NONE,
                        Some(1460),
                        &[],
                    );
                    t.deliver(&seg);
                    assert!(!t.s.is_established(t.conn.unwrap()));
                    assert_eq!(t.s.connections(), before);
                }
            }
            Step::BlindRst => {
                if t.in_syn_sent() {
                    let seg = t.raw(0, 0, wire::RST, 0, &wire::Ext::NONE, None, &[]);
                    t.deliver(&seg);
                    assert_eq!(t.s.connections(), before, "a RST without an ACK closed it");
                }
            }
            Step::BareSyn => {
                if t.in_syn_sent() {
                    let seg = t.raw(P_ISN, 0, wire::SYN, 1000, &wire::Ext::NONE, Some(1460), &[]);
                    t.deliver(&seg);
                    assert!(!t.s.is_established(t.conn.unwrap()));
                    assert_eq!(t.s.connections(), before);
                }
            }
            Step::PeerData(n) => {
                if !t.gone {
                    let n = usize::from(n);
                    let d = t.data(n);
                    let seg = t.seg(t.p_nxt, wire::ACK | wire::PSH, &d);
                    t.p_nxt = t.p_nxt.wrapping_add(n as u32);
                    t.p_sent += n;
                    t.deliver(&seg);
                }
            }
            Step::PeerFin => {
                if !t.gone {
                    let seg = t.seg(t.p_nxt, wire::ACK | wire::FIN, &[]);
                    t.p_nxt = t.p_nxt.wrapping_add(1);
                    t.p_fin = true;
                    t.deliver(&seg);
                }
            }
            Step::PeerAck => {
                if !t.gone {
                    t.ack();
                }
            }
            Step::PeerWindow(w) => {
                if !t.gone {
                    t.win = w;
                    t.ack();
                }
            }
            Step::AppSend(n) => {
                if let Some(c) = t.conn
                    && !t.gone
                {
                    let n = usize::from(n);
                    let data: Vec<u8> = (0..n).map(|i| byte(t.a_sent + i, 2)).collect();
                    let k = t.s.send(c, &data);
                    if !t.synced {
                        assert_eq!(k, 0, "data accepted before the handshake");
                    }
                    t.a_sent += k;
                    t.service(Vec::new());
                }
            }
            Step::AppClose => {
                if let Some(c) = t.conn
                    && !t.gone
                {
                    t.s.close(c);
                    t.service(Vec::new());
                }
            }
            Step::Tick(ms) => {
                // The kernel's loop polls the stack every few milliseconds:
                // the clock moves in steps of at most 100 ms, so a timer runs
                // when it is due and not at the end of a long jump.
                let end = t.now + u64::from(ms);
                while t.now < end {
                    t.now = (t.now + 100).min(end);
                    t.service(Vec::new());
                }
            }
            Step::RstInWindow(off) => {
                if !t.gone {
                    let seq = t.p_nxt.wrapping_add(u32::from(off).max(1));
                    let seg = t.seg(seq, wire::RST, &[]);
                    t.deliver(&seg);
                    assert_eq!(t.s.connections(), before, "an in-window RST closed it");
                }
            }
            Step::RstExact => {
                if !t.gone {
                    let seg = t.seg(t.p_nxt, wire::RST, &[]);
                    t.deliver(&seg);
                    assert!(t.gone, "a RST at rcv_nxt did not close it");
                }
            }
            Step::SynOnOpen => {
                if !t.gone {
                    let seg = t.raw(
                        t.p_nxt.wrapping_add(7),
                        0,
                        wire::SYN,
                        1000,
                        &wire::Ext::NONE,
                        None,
                        &[],
                    );
                    t.deliver(&seg);
                    assert_eq!(
                        t.s.connections(),
                        before,
                        "a SYN on an open connection closed it"
                    );
                }
            }
            Step::AckUnsent => {
                if !t.gone {
                    let ack = t.rcv_nxt.wrapping_add(100_000);
                    let seg = t.raw(t.p_nxt, ack, wire::ACK, t.win, &wire::Ext::NONE, None, &[]);
                    t.deliver(&seg);
                    assert_eq!(t.s.connections(), before);
                }
            }
            Step::FarFutureData => {
                if !t.gone {
                    let received = t.app.received.len();
                    let d = t.data(100);
                    let seg = t.seg(t.p_nxt.wrapping_add(2_000_000), wire::ACK | wire::PSH, &d);
                    t.deliver(&seg);
                    assert_eq!(
                        t.app.received.len(),
                        received,
                        "data beyond the window delivered"
                    );
                }
            }
        }
        t
    }

    fn check_invariants(t: &Sut, m: &Model) {
        match m.phase {
            Phase::SynSent => {
                // The model's clock says whether the SYN was given up.
                assert!(!t.gone, "gone after {} ms in SYN-SENT", m.syn_ms);
                assert!(!t.synced);
                assert_eq!(t.s.connections(), 1);
                assert_eq!(t.s.active_connections(), 1);
                assert!(t.app.connected.is_empty(), "connected before the SYN-ACK");
            }
            Phase::Open if !t.gone => {
                let want: Vec<u8> = (0..t.p_sent).map(|i| byte(i, 1)).collect();
                assert_eq!(t.app.received, want, "application stream differs");
                assert_eq!(t.s.connections(), 1);
            }
            _ => {}
        }
        if m.phase == Phase::Gone
            && let Some(c) = t.conn
        {
            assert!(t.gone, "the model says gone, the stack kept it");
            if m.syn_ms >= SYN_GIVE_UP_MS {
                assert_eq!(
                    t.app.closed.last().copied(),
                    Some((c, CloseReason::Timeout))
                );
            }
        }
        // The peer holds an exact prefix of what the application sent.
        let want: Vec<u8> = (0..t.rx.len()).map(|i| byte(i, 2)).collect();
        assert_eq!(t.rx, want, "peer stream differs");
        assert!(t.rx.len() <= t.a_sent);
        // Each connection is reported connected at most once.
        let mut c = t.app.connected.clone();
        c.dedup();
        assert_eq!(c.len(), t.app.connected.len());
        if t.gone || matches!(m.phase, Phase::Idle | Phase::Gone) {
            assert_eq!(t.s.connections(), 0, "a gone connection left state behind");
            assert_eq!(t.s.active_connections(), 0);
        }
    }
}

prop_state_machine! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 256 },
        failure_persistence: None,
        .. ProptestConfig::default()
    })]
    #[test]
    fn active_open_against_the_model(sequential 1..60 => ActiveModelTest);
}
