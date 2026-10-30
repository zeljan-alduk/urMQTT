//! H3: a stateful model test (proptest-state-machine) against a reduced
//! RFC 9293 model of one server-side connection.
//!
//! The reference model knows the connection's phase and how many bytes
//! each side has sent. The system under test is the real stack and a
//! well-behaved client that tracks sequence numbers exactly, receives
//! everything the server sends and acknowledges only when told to. Random
//! sequences of client actions, application calls, clock steps and hostile
//! segments (RFC 5961 cases, out-of-window and old data) are applied, and
//! after every step:
//!
//! - the application received exactly the bytes the client sent while the
//!   connection was open, in order;
//! - the client received a prefix of the bytes the application sent, in
//!   order, never one twice;
//! - the server never sent past the window the client advertised, nor
//!   acknowledged a byte the client did not send;
//! - hostile segments never closed the connection or moved its state;
//! - a connection the model says is gone holds no state in the stack.

use alloc::vec::Vec;

use proptest::prelude::*;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

use super::*;
use crate::script::{C_ISN, CLIENT, CPORT, SERVER, cfg as script_cfg, segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No connection.
    Listen,
    Open,
    /// The connection ended (both FINs acknowledged, a reset, a timeout).
    Gone,
}

#[derive(Debug, Clone)]
pub struct Model {
    phase: Phase,
    client_fin: bool,
    app_closed: bool,
    /// Connections opened so far (each gets a new client port).
    opened: u16,
}

#[derive(Debug, Clone)]
pub enum Step {
    Connect,
    ClientData(u16),
    ClientFin,
    ClientAck,
    /// The client's receive window: 0 closes it.
    ClientWindow(u16),
    AppSend(u16),
    AppClose,
    Tick(u16),
    /// RFC 5961 §3: in-window RST, not at rcv_nxt.
    RstInWindow(u16),
    RstExact,
    /// RFC 5961 §4.
    SynOnOpen,
    /// RFC 5961 §5.
    AckUnsent,
    FarFutureData,
    OldData,
}

pub struct RefModel;

impl ReferenceStateMachine for RefModel {
    type State = Model;
    type Transition = Step;

    fn init_state() -> BoxedStrategy<Model> {
        Just(Model {
            phase: Phase::Listen,
            client_fin: false,
            app_closed: false,
            opened: 0,
        })
        .boxed()
    }

    fn transitions(m: &Model) -> BoxedStrategy<Step> {
        if m.phase != Phase::Open {
            return prop_oneof![Just(Step::Connect), (1u16..2000).prop_map(Step::Tick)].boxed();
        }
        prop_oneof![
            4 => (1u16..3000).prop_map(Step::ClientData),
            1 => Just(Step::ClientFin),
            4 => Just(Step::ClientAck),
            1 => prop_oneof![Just(0u16), Just(1000u16), Just(65535u16)].prop_map(Step::ClientWindow),
            4 => (1u16..5000).prop_map(Step::AppSend),
            1 => Just(Step::AppClose),
            3 => prop_oneof![Just(10u16), Just(250), Just(1100), Just(4000)].prop_map(Step::Tick),
            1 => (1u16..30000).prop_map(Step::RstInWindow),
            1 => Just(Step::RstExact),
            1 => Just(Step::SynOnOpen),
            1 => Just(Step::AckUnsent),
            1 => Just(Step::FarFutureData),
            1 => Just(Step::OldData),
        ]
        .boxed()
    }

    fn preconditions(m: &Model, s: &Step) -> bool {
        match s {
            Step::Connect => m.phase != Phase::Open,
            Step::ClientData(_) | Step::ClientFin => m.phase == Phase::Open && !m.client_fin,
            Step::AppSend(_) | Step::AppClose => m.phase == Phase::Open && !m.app_closed,
            Step::Tick(_) => true,
            _ => m.phase == Phase::Open,
        }
    }

    fn apply(mut m: Model, s: &Step) -> Model {
        match s {
            Step::Connect => {
                m = Model {
                    phase: Phase::Open,
                    client_fin: false,
                    app_closed: false,
                    opened: m.opened + 1,
                };
            }
            Step::ClientFin => m.client_fin = true,
            Step::AppClose => m.app_closed = true,
            Step::RstExact => m.phase = Phase::Gone,
            _ => {}
        }
        m
    }
}

#[derive(Default)]
struct App2 {
    conns: Vec<ConnId>,
    received: Vec<u8>,
    closed: Vec<CloseReason>,
    peer_closed: bool,
}

impl App for App2 {
    fn accept(&mut self, c: ConnId, _p: u16, _r: Endpoint) -> bool {
        self.conns.push(c);
        true
    }
    fn data(&mut self, _c: ConnId, d: &[u8]) {
        self.received.extend_from_slice(d);
    }
    fn peer_closed(&mut self, _c: ConnId) {
        self.peer_closed = true;
    }
    fn closed(&mut self, _c: ConnId, why: CloseReason) {
        self.closed.push(why);
    }
}

fn byte(i: usize, salt: u8) -> u8 {
    (i as u8).wrapping_mul(37).wrapping_add(salt)
}

pub struct Sut {
    s: TcpStack,
    app: App2,
    now: u64,
    port: u16,
    conn: Option<ConnId>,
    // Client side, absolute sequence numbers.
    c_nxt: u32,
    c_sent: usize,
    c_fin: bool,
    s_isn: u32,
    /// Next server byte the client expects; what it has acknowledged.
    rcv_nxt: u32,
    acked: u32,
    win: u16,
    /// The window edge the client last advertised (ack + window).
    edge: u32,
    rx: Vec<u8>,
    s_fin: bool,
    // Server application.
    a_sent: usize,
    /// The connection is gone in the stack.
    gone: bool,
}

impl Sut {
    fn new() -> Self {
        Self {
            s: TcpStack::new(script_cfg(), 0),
            app: App2::default(),
            now: 0,
            port: CPORT,
            conn: None,
            c_nxt: C_ISN,
            c_sent: 0,
            c_fin: false,
            s_isn: 0,
            rcv_nxt: 0,
            acked: 0,
            win: 65535,
            edge: 0,
            rx: Vec::new(),
            s_fin: false,
            a_sent: 0,
            gone: true,
        }
    }

    fn deliver(&mut self, seg: &[u8]) {
        let mut q = Vec::new();
        self.s
            .input(self.now, CLIENT, seg, &mut self.app, &mut |_, b| {
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
            && self.app.closed.len() >= self.app.conns.len()
            && self.app.conns.last() == Some(&c)
        {
            self.gone = true;
        }
    }

    /// The client takes in a server segment and checks the server's side
    /// of the invariants.
    fn receive(&mut self, b: &[u8]) {
        let h = wire::parse(SERVER, CLIENT, b).expect("the server sends valid segments");
        if h.dport != self.port {
            return;
        }
        let payload = &b[h.data_off..];
        if h.flags & wire::RST != 0 {
            return;
        }
        if h.flags & wire::SYN != 0 {
            self.s_isn = h.seq;
            self.rcv_nxt = h.seq.wrapping_add(1);
            return;
        }
        if h.flags & wire::ACK != 0 {
            assert!(
                seq::le(h.ack, self.c_nxt),
                "the server acknowledged unsent data: ack {} > {}",
                h.ack,
                self.c_nxt
            );
        }
        if !payload.is_empty() {
            let end = h.seq.wrapping_add(payload.len() as u32);
            // Probes may send one byte past a closed window (RFC 9293).
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

    /// A client segment acknowledging what it received, with its window
    /// (which the server may then use: the edge moves).
    fn seg(&mut self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        if flags & wire::ACK != 0 {
            self.acked = self.rcv_nxt;
            self.edge = self.rcv_nxt.wrapping_add(u32::from(self.win));
        }
        segment(
            self.port,
            seq,
            self.rcv_nxt,
            flags,
            self.win,
            0,
            &[],
            payload,
        )
    }

    /// The client's next `n` payload bytes.
    fn data(&self, n: usize) -> Vec<u8> {
        (0..n).map(|i| byte(self.c_sent + i, 1)).collect()
    }

    fn ack(&mut self) {
        let s = self.seg(self.c_nxt, wire::ACK, &[]);
        self.deliver(&s);
    }
}

pub struct TcpModelTest;

impl StateMachineTest for TcpModelTest {
    type SystemUnderTest = Sut;
    type Reference = RefModel;

    fn init_test(_m: &Model) -> Sut {
        Sut::new()
    }

    fn apply(mut t: Sut, m: &Model, s: Step) -> Sut {
        let before = t.s.connections();
        match s {
            Step::Connect => {
                t.port = CPORT + m.opened;
                t.c_nxt = C_ISN;
                t.c_sent = 0;
                t.c_fin = false;
                t.rx.clear();
                t.s_fin = false;
                t.a_sent = 0;
                t.app.received.clear();
                t.app.peer_closed = false;
                t.win = 65535;
                let syn = segment(
                    t.port,
                    C_ISN,
                    0,
                    wire::SYN,
                    65535,
                    0,
                    &[2, 4, 0x05, 0xb4],
                    &[],
                );
                t.deliver(&syn);
                t.c_nxt = C_ISN.wrapping_add(1);
                t.acked = t.rcv_nxt;
                t.edge = t.rcv_nxt.wrapping_add(65535);
                let n_before = t.app.conns.len();
                t.ack();
                assert_eq!(
                    t.app.conns.len(),
                    n_before + 1,
                    "the handshake did not complete"
                );
                t.conn = t.app.conns.last().copied();
                t.gone = false;
            }
            Step::ClientData(n) => {
                let n = usize::from(n);
                let d = t.data(n);
                let seg = t.seg(t.c_nxt, wire::ACK | wire::PSH, &d);
                t.c_nxt = t.c_nxt.wrapping_add(n as u32);
                t.c_sent += n;
                t.deliver(&seg);
            }
            Step::ClientFin => {
                let seg = t.seg(t.c_nxt, wire::ACK | wire::FIN, &[]);
                t.c_nxt = t.c_nxt.wrapping_add(1);
                t.c_fin = true;
                t.deliver(&seg);
            }
            Step::ClientAck => t.ack(),
            Step::ClientWindow(w) => {
                t.win = w;
                t.ack();
            }
            Step::AppSend(n) => {
                if let Some(c) = t.conn
                    && !t.gone
                {
                    let n = usize::from(n);
                    let data: Vec<u8> = (0..n).map(|i| byte(t.a_sent + i, 2)).collect();
                    let k = t.s.send(c, &data);
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
                t.now += u64::from(ms);
                t.service(Vec::new());
            }
            Step::RstInWindow(off) => {
                let seq = t.c_nxt.wrapping_add(u32::from(off).max(1));
                let seg = t.seg(seq, wire::RST, &[]);
                t.deliver(&seg);
                assert_eq!(
                    t.s.connections(),
                    before,
                    "an in-window RST closed the connection"
                );
            }
            Step::RstExact => {
                let seg = t.seg(t.c_nxt, wire::RST, &[]);
                t.deliver(&seg);
                t.gone = true;
            }
            Step::SynOnOpen => {
                let seg = segment(
                    t.port,
                    t.c_nxt.wrapping_add(7),
                    0,
                    wire::SYN,
                    65535,
                    0,
                    &[],
                    &[],
                );
                t.deliver(&seg);
                assert_eq!(
                    t.s.connections(),
                    before,
                    "a SYN on an open connection closed it"
                );
            }
            Step::AckUnsent => {
                let ack = t.rcv_nxt.wrapping_add(100_000);
                let seg = segment(t.port, t.c_nxt, ack, wire::ACK, t.win, 0, &[], &[]);
                t.deliver(&seg);
                assert_eq!(t.s.connections(), before);
            }
            Step::FarFutureData => {
                let received = t.app.received.len();
                let d = t.data(100);
                let seg = t.seg(t.c_nxt.wrapping_add(200_000), wire::ACK | wire::PSH, &d);
                t.deliver(&seg);
                assert_eq!(
                    t.app.received.len(),
                    received,
                    "data beyond the window delivered"
                );
            }
            Step::OldData => {
                let received = t.app.received.len();
                let seq = t.c_nxt.wrapping_sub(50);
                if t.c_sent >= 50 {
                    // A retransmission of the last 50 bytes: nothing new.
                    let payload: Vec<u8> = (0..50).map(|i| byte(t.c_sent - 50 + i, 1)).collect();
                    let seg = t.seg(seq, wire::ACK, &payload);
                    t.deliver(&seg);
                    assert_eq!(t.app.received.len(), received, "old data delivered twice");
                }
            }
        }
        t
    }

    fn check_invariants(t: &Sut, m: &Model) {
        if m.phase == Phase::Open && !t.gone {
            // Everything the client sent arrived, in order, exactly once.
            let want: Vec<u8> = (0..t.c_sent).map(|i| byte(i, 1)).collect();
            assert_eq!(t.app.received, want, "application stream differs");
            assert_eq!(t.s.connections(), 1);
        }
        // The client holds an exact prefix of what the application sent.
        let want: Vec<u8> = (0..t.rx.len()).map(|i| byte(i, 2)).collect();
        assert_eq!(t.rx, want, "client stream differs");
        assert!(t.rx.len() <= t.a_sent);
        if t.gone || m.phase != Phase::Open {
            assert_eq!(t.s.connections(), 0, "a gone connection left state behind");
        }
    }
}

prop_state_machine! {
    #![proptest_config(ProptestConfig {
        // Miri is for the memory model; the full run stays in the normal suite.
        cases: if cfg!(miri) { 3 } else { 256 },
        failure_persistence: None,
        .. ProptestConfig::default()
    })]
    #[test]
    fn tcp_against_the_model(sequential 1..60 => TcpModelTest);
}
