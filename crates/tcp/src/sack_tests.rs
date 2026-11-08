//! The sending side's loss recovery with the peer's SACK blocks (ADR-265):
//! what a burst of acknowledgements after a stall, a reordered segment and a
//! real loss each cost.

use alloc::vec::Vec;

use super::*;
use crate::wire::Ext;

const SERVER: [u8; 4] = [10, 0, 2, 15];
const CLIENT: [u8; 4] = [10, 0, 2, 2];
const CPORT: u16 = 41500;
const C_ISN: u32 = 9_000;
/// Payload of a full segment when timestamps are on (1460 - 12).
const SEG: usize = 1448;

fn cfg() -> Config {
    Config {
        local_addr: SERVER,
        ports: alloc::vec![8883],
        mss: 1460,
        rcv_wnd: 65535,
        rcv_wnd_scaled: 1 << 20,
        max_conns: 64,
        tx_max: 1 << 20,
        tx_cap: 1 << 20,
        ooo_budget: 1 << 20,
        ooo_conn_max: 1 << 18,
        cookie_key: [4; 16],
        rst_per_sec: 1000,
    }
}

#[derive(Default)]
struct Sink {
    conns: Vec<ConnId>,
}

impl App for Sink {
    fn accept(&mut self, c: ConnId, _p: u16, _r: Endpoint) -> bool {
        self.conns.push(c);
        true
    }
    fn data(&mut self, _c: ConnId, _d: &[u8]) {}
    fn peer_closed(&mut self, _c: ConnId) {}
    fn closed(&mut self, _c: ConnId, _why: CloseReason) {}
}

/// A segment the server sent: where it starts and how long it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sent {
    seq: u32,
    len: u32,
    tsval: u32,
}

struct Rig {
    s: TcpStack,
    app: Sink,
    c: ConnId,
    /// The server's first data byte.
    base: u32,
    now: u64,
    ts: u32,
}

impl Rig {
    /// A connection with SACK and timestamps negotiated, `n` bytes queued.
    fn new(sack: bool, n: usize) -> Self {
        let mut s = TcpStack::new(cfg(), 0);
        let mut app = Sink::default();
        let mut out: Vec<Vec<u8>> = Vec::new();
        let syn = Ext {
            sack_perm: sack,
            wscale: Some(7),
            ts: Some((1000, 0)),
            ..Ext::NONE
        };
        s.input(
            0,
            CLIENT,
            &seg(SYN, C_ISN, 0, 65535, &syn, true, &[]),
            &mut app,
            &mut |_, b| out.push(b.to_vec()),
        );
        let synack = wire::parse(SERVER, CLIENT, &out[0]).unwrap();
        let echoed = synack.ts.map_or(0, |(v, _)| v);
        let ack = Ext {
            ts: Some((1001, echoed)),
            ..Ext::NONE
        };
        let base = synack.seq.wrapping_add(1);
        s.input(
            1,
            CLIENT,
            &seg(ACK, C_ISN + 1, base, 65535, &ack, false, &[]),
            &mut app,
            &mut |_, _| {},
        );
        let c = app.conns[0];
        let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        assert_eq!(s.send(c, &data), n);
        Self {
            s,
            app,
            c,
            base,
            now: 10,
            ts: 1002,
        }
    }

    /// Lets time pass and collects what the server sends in its next pass.
    fn flush(&mut self, dt: u64) -> Vec<Sent> {
        self.now += dt;
        let mut out: Vec<Vec<u8>> = Vec::new();
        self.s.flush(self.now, &mut |_, b| out.push(b.to_vec()));
        Self::data_of(&out)
    }

    /// An ACK from the client: cumulative `ack` (a stream offset), SACK blocks (offsets).
    fn ack(&mut self, dt: u64, ack: u32, blocks: &[(u32, u32)], tsecr: u32) -> Vec<Sent> {
        self.now += dt;
        self.ts += 1;
        let mut sacks = [(0, 0); 3];
        for (slot, &(l, r)) in sacks.iter_mut().zip(blocks) {
            *slot = (self.base + l, self.base + r);
        }
        let x = Ext {
            ts: Some((self.ts, tsecr)),
            sacks,
            nsack: blocks.len().min(3) as u8,
            ..Ext::NONE
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        self.s.input(
            self.now,
            CLIENT,
            &seg(ACK, C_ISN + 1, self.base + ack, 65535, &x, false, &[]),
            &mut self.app,
            &mut |_, b| out.push(b.to_vec()),
        );
        let mut sent = Self::data_of(&out);
        sent.extend(self.flush(0));
        sent
    }

    fn data_of(out: &[Vec<u8>]) -> Vec<Sent> {
        out.iter()
            .filter_map(|b| {
                let h = wire::parse(SERVER, CLIENT, b).unwrap();
                let len = (b.len() - h.data_off) as u32;
                (len > 0).then(|| Sent {
                    seq: h.seq,
                    len,
                    tsval: h.ts.map_or(0, |(v, _)| v),
                })
            })
            .collect()
    }
}

fn seg(flags: u8, seq: u32, ack: u32, window: u16, x: &Ext, mss: bool, payload: &[u8]) -> Vec<u8> {
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

impl Rig {
    /// Gets the first window acknowledged and returns the next flight.
    fn warm_up(&mut self) -> Vec<Sent> {
        let first = self.flush(1);
        // Ten segments of the window's 14 600 bytes and a short one.
        assert_eq!(first.len(), 11, "the initial window");
        let last = *first.last().unwrap();
        let end = self.top(last);
        self.ack(15, end, &[], last.tsval)
    }

    fn off(&self, s: Sent) -> u32 {
        s.seq.wrapping_sub(self.base)
    }

    /// The offset after the segment.
    fn top(&self, s: Sent) -> u32 {
        self.off(s) + s.len
    }
}

/// The server sends 10 segments, they are acknowledged, 20 follow; the third of
/// them is lost and the client reports the rest.
#[test]
fn a_lost_segment_is_sent_again_once_and_nothing_else() {
    let mut r = Rig::new(true, 200_000);
    let flight = r.warm_up();
    assert!(flight.len() >= 15, "{}", flight.len());
    let lost = flight[2];
    let lost_off = r.off(lost);
    let after = r.off(flight[3]);
    let end = r.top(*flight.last().unwrap());
    let mut resent = Vec::new();
    // Each later segment arrives and is reported; the hole stays.
    for (i, f) in flight.iter().enumerate().skip(3) {
        let top = r.top(*f);
        let got = r.ack(1, lost_off, &[(after, top)], f.tsval);
        resent.extend(
            got.into_iter()
                .filter(|x| r.off(*x) < end && x.seq == lost.seq),
        );
        assert!(i < 100);
    }
    // Time passes beyond the reordering window with the hole still open.
    resent.extend(
        r.ack(10, lost_off, &[(after, end)], flight.last().unwrap().tsval)
            .into_iter()
            .filter(|x| x.seq == lost.seq),
    );
    assert_eq!(resent.len(), 1, "the hole once: {resent:?}");
    assert_eq!(resent[0].len as usize, SEG);
    assert_eq!(r.s.stats.fast_retransmits, 1);
    assert_eq!(r.s.stats.retransmits, 1, "and nothing else");
    // The retransmission arrives: everything is acknowledged, the recovery ends.
    let k = r.s.conn(r.c).unwrap();
    assert!(k.has(IN_RECOVERY));
    let ssthresh = k.cc.ssthresh();
    // The recovery ends when everything sent before it started is acknowledged
    // (the server went on sending new data meanwhile, as far as the pipe allowed).
    let recover = k.recover.wrapping_sub(r.base);
    assert!(recover >= end);
    r.ack(15, recover, &[], resent[0].tsval);
    let k = r.s.conn(r.c).unwrap();
    assert!(
        !k.has(IN_RECOVERY),
        "recover {} snd_max {} snd_una {} end {end}",
        k.recover.wrapping_sub(r.base),
        k.snd_max.wrapping_sub(r.base),
        k.snd_una.wrapping_sub(r.base)
    );
    assert_eq!(k.cc.window(), ssthresh, "the window is the reduced one");
    assert!(k.tx.as_ref().is_none_or(|t| t.board.is_none()));
    assert_eq!(r.s.stats.retransmits, 1);
}

/// A segment that only arrives late (the network reordered it by a few places)
/// costs nothing: the hole fills before the reordering window is over.
#[test]
fn a_reordered_segment_is_not_sent_again() {
    let mut r = Rig::new(true, 200_000);
    let flight = r.warm_up();
    let late = flight[2];
    let late_off = r.off(late);
    let after = r.off(flight[3]);
    // Four segments overtake it ...
    let mut sent = Vec::new();
    for f in flight.iter().skip(3).take(4) {
        let top = r.top(*f);
        sent.extend(r.ack(0, late_off, &[(after, top)], f.tsval));
    }
    // ... and it arrives in the same moment: one ACK for all of them.
    let top = r.top(flight[6]);
    sent.extend(r.ack(0, top, &[], late.tsval));
    assert_eq!(r.s.stats.retransmits, 0, "{sent:?}");
    assert_eq!(r.s.stats.fast_retransmits, 0);
    assert!(!r.s.conn(r.c).unwrap().has(IN_RECOVERY));
    // The window did not shrink.
    assert!(r.s.conn(r.c).unwrap().cc.window() >= 20 * SEG as u32);
}

/// The acknowledgements a stalled receiver sends in a burst afterwards are
/// partial ACKs; they are not holes. NewReno sent a segment per ACK (a dozen
/// segments that were not lost, on the VPS).
#[test]
fn a_burst_of_partial_acks_is_not_a_loss() {
    let mut r = Rig::new(true, 200_000);
    let flight = r.warm_up();
    let mut sent = Vec::new();
    // First an ACK for the first segment alone, then for every second
    // segment, all in the same millisecond.
    sent.extend(r.ack(0, r.top(flight[0]), &[], flight[0].tsval));
    for (i, f) in flight.iter().enumerate().skip(1) {
        if i % 2 == 1 {
            let top = r.top(*f);
            sent.extend(r.ack(0, top, &[], f.tsval));
        }
    }
    assert_eq!(r.s.stats.retransmits, 0, "{sent:?}");
    assert!(!r.s.conn(r.c).unwrap().has(IN_RECOVERY));
}

/// A peer that negotiated SACK but reports no blocks still gets the classic
/// fast retransmit after three duplicate ACKs (a receiver that drops
/// out-of-order data it has no room for says nothing more).
#[test]
fn duplicate_acks_without_blocks_still_start_a_classic_recovery() {
    let mut r = Rig::new(true, 200_000);
    let flight = r.warm_up();
    let una = r.off(flight[0]);
    let mut sent = Vec::new();
    for _ in 0..3 {
        sent.extend(r.ack(0, una, &[], flight[0].tsval));
    }
    assert_eq!(r.s.stats.fast_retransmits, 1);
    assert!(sent.iter().any(|x| x.seq == flight[0].seq), "{sent:?}");
}

/// What a receiver that got the segments flagged in `got` reports: the cumulative
/// ACK (offset of the first one missing) and its SACK blocks, the range of the segment
/// that arrived last first (RFC 2018).
fn report(r: &Rig, flight: &[Sent], got: &[bool], last: usize) -> (u32, Vec<(u32, u32)>) {
    let first_missing = got.iter().position(|g| !g).unwrap_or(got.len());
    let cum = if first_missing < flight.len() {
        r.off(flight[first_missing])
    } else {
        r.top(flight[flight.len() - 1])
    };
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i = first_missing;
    while i < got.len() {
        if got[i] {
            let start = i;
            while i < got.len() && got[i] {
                i += 1;
            }
            ranges.push((start, i));
        } else {
            i += 1;
        }
    }
    ranges.sort_by_key(|&(a, e)| !(a <= last && last < e));
    let blocks = ranges
        .iter()
        .take(3)
        .map(|&(a, e)| (r.off(flight[a]), r.top(flight[e - 1])))
        .collect();
    (cum, blocks)
}

/// Two holes in one window are both repaired in the recovery that the first starts.
#[test]
fn two_holes_are_repaired_in_one_round_trip() {
    let mut r = Rig::new(true, 400_000);
    let flight = r.warm_up();
    assert!(flight.len() >= 12, "{}", flight.len());
    let (a, b) = (2usize, 7usize);
    let mut got = alloc::vec![false; flight.len()];
    let mut resent: Vec<Sent> = Vec::new();
    // The segments that did arrive are reported one by one, a millisecond
    // apart; the first two arrived before the hole.
    got[0] = true;
    got[1] = true;
    for k in 3..flight.len() {
        if k == b {
            continue;
        }
        got[k] = true;
        let (cum, blocks) = report(&r, &flight, &got, k);
        resent.extend(r.ack(1, cum, &blocks, flight[k].tsval));
    }
    // And a little later, with nothing new, the board is looked at again.
    let (cum, blocks) = report(&r, &flight, &got, flight.len() - 1);
    resent.extend(r.ack(10, cum, &blocks, flight[flight.len() - 1].tsval));
    let mut holes: Vec<u32> = resent
        .iter()
        .filter(|x| x.seq == flight[a].seq || x.seq == flight[b].seq)
        .map(|x| x.seq)
        .collect();
    holes.sort_unstable();
    assert_eq!(holes.len(), 2, "each hole once: {resent:?}");
    assert_ne!(holes[0], holes[1]);
    assert_eq!(r.s.stats.fast_retransmits, 1, "one recovery for both");
    assert_eq!(r.s.stats.retransmits, 2);
}

/// Without SACK the old NewReno rules stand.
#[test]
fn a_peer_without_sack_gets_newreno() {
    let mut r = Rig::new(false, 200_000);
    let flight = r.warm_up();
    let una = r.off(flight[0]);
    let mut sent = Vec::new();
    for _ in 0..3 {
        sent.extend(r.ack(0, una, &[], flight[0].tsval));
    }
    assert_eq!(r.s.stats.fast_retransmits, 1);
    assert!(sent.iter().any(|x| x.seq == flight[0].seq), "{sent:?}");
}

// ---- a whole transfer over a lossy, reordering link ------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// True with probability `per_mille / 1000`.
    fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }
}

/// The receiving end: acknowledges what it holds in order, reports the rest as
/// SACK blocks (the latest range first) and echoes timestamps.
struct Receiver {
    base: u32,
    next: u32,
    /// Out-of-order ranges (start, end) as offsets, ascending.
    ranges: Vec<(u32, u32)>,
    latest: u32,
    got: Vec<u8>,
    tsval: u32,
    /// The duplicate the next ACK reports first (RFC 2883).
    dsack: Option<(u32, u32)>,
}

impl Receiver {
    fn segment(&mut self, seq: u32, tsval: u32, payload: &[u8]) {
        self.tsval = tsval;
        let off = seq.wrapping_sub(self.base);
        let end = off + payload.len() as u32;
        if end <= self.next || self.ranges.iter().any(|&(a, e)| a <= off && end <= e) {
            self.dsack = Some((off, end));
            if end <= self.next {
                return;
            }
        }
        if off <= self.next {
            let skip = (self.next - off) as usize;
            self.got.extend_from_slice(&payload[skip..]);
            self.next = end;
            // Pull in the ranges that now touch.
            while let Some(&(a, e)) = self.ranges.first() {
                if a > self.next {
                    break;
                }
                // The bytes of a held range are not kept here: the test sender's
                // data is a function of the offset, see `byte_at`.
                if e > self.next {
                    for o in self.next..e {
                        self.got.push(byte_at(o));
                    }
                    self.next = e;
                }
                self.ranges.remove(0);
            }
            return;
        }
        // Out of order: merge into the ranges.
        let (mut lo, mut hi) = (off, end);
        self.ranges.retain(|&(a, e)| {
            if a <= hi && e >= lo {
                lo = lo.min(a);
                hi = hi.max(e);
                false
            } else {
                true
            }
        });
        let at = self
            .ranges
            .iter()
            .position(|&(a, _)| a > lo)
            .unwrap_or(self.ranges.len());
        self.ranges.insert(at, (lo, hi));
        self.latest = lo;
    }

    fn ack(&mut self, r: &mut Rig) -> Vec<u8> {
        let mut blocks: Vec<(u32, u32)> = self.ranges.clone();
        blocks.sort_by_key(|&(a, e)| !(a <= self.latest && self.latest < e));
        if let Some(d) = self.dsack {
            blocks.insert(0, d);
        }
        let mut sacks = [(0, 0); 3];
        for (slot, &(a, e)) in sacks.iter_mut().zip(&blocks) {
            *slot = (r.base + a, r.base + e);
        }
        r.ts += 1;
        let x = Ext {
            ts: Some((r.ts, self.tsval)),
            sacks,
            nsack: blocks.len().min(3) as u8,
            ..Ext::NONE
        };
        self.dsack = None;
        seg(ACK, C_ISN + 1, self.base + self.next, 65535, &x, false, &[])
    }
}

fn byte_at(off: u32) -> u8 {
    (off.wrapping_mul(7)) as u8
}

/// Sends `total` bytes through a link that drops `loss` per mille of the data
/// segments (and `ack_loss` of the ACKs) and delays each by 5 ms plus up to
/// `jitter` ms (which reorders). Returns (the stack, the receiver, milliseconds).
fn transfer(
    total: usize,
    loss: u64,
    ack_loss: u64,
    jitter: u64,
    seed: u64,
) -> (TcpStack, Receiver, u64) {
    let mut r = Rig::new(true, 0);
    let mut rng = Rng(seed | 1);
    let mut rx = Receiver {
        base: r.base,
        next: 0,
        ranges: Vec::new(),
        latest: 0,
        got: Vec::new(),
        tsval: 0,
        dsack: None,
    };
    // (due, to_server, bytes)
    let mut link: Vec<(u64, bool, Vec<u8>)> = Vec::new();
    let mut queued = 0usize;
    let mut now = 10u64;
    while now < 120_000 && rx.got.len() < total {
        // The application keeps the queue full.
        while queued < total {
            let room = r.s.send_space(r.c).min(total - queued);
            if room == 0 {
                break;
            }
            let chunk: Vec<u8> = (queued..queued + room).map(|o| byte_at(o as u32)).collect();
            let n = r.s.send(r.c, &chunk);
            queued += n;
            if n == 0 {
                break;
            }
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        r.s.poll(now, &mut r.app, &mut |_, b| out.push(b.to_vec()));
        r.s.flush(now, &mut |_, b| out.push(b.to_vec()));
        for b in out {
            if rng.chance(loss) {
                continue;
            }
            let delay = 5 + if jitter > 0 {
                rng.next() % (jitter + 1)
            } else {
                0
            };
            link.push((now + delay, false, b));
        }
        // Deliver what is due, in due order.
        link.sort_by_key(|(due, _, _)| *due);
        let split = link.partition_point(|(due, _, _)| *due <= now);
        let due: Vec<(u64, bool, Vec<u8>)> = link.drain(..split).collect();
        for (_, to_server, bytes) in due {
            if to_server {
                let mut out: Vec<Vec<u8>> = Vec::new();
                r.s.input(now, CLIENT, &bytes, &mut r.app, &mut |_, b| {
                    out.push(b.to_vec())
                });
                for b in out {
                    link.push((now + 5, false, b));
                }
            } else {
                let h = wire::parse(SERVER, CLIENT, &bytes).unwrap();
                let len = bytes.len() - h.data_off;
                if len > 0 {
                    rx.segment(h.seq, h.ts.map_or(0, |(v, _)| v), &bytes[h.data_off..]);
                    if !rng.chance(ack_loss) {
                        link.push((now + 5, true, rx.ack(&mut r)));
                    }
                }
            }
        }
        now += 1;
    }
    let elapsed = now;
    (r.s, rx, elapsed)
}

#[test]
fn a_transfer_over_a_lossy_reordering_link_completes_with_few_extra_segments() {
    for (seed, loss, jitter) in [
        (1, 10, 0),
        (2, 20, 3),
        (3, 20, 12),
        (4, 50, 6),
        (5, 5, 20),
        (6, 0, 4),
        (7, 0, 15),
    ] {
        let total = 400_000;
        let (s, rx, ms) = transfer(total, loss, loss / 2, jitter, seed);
        assert_eq!(rx.got.len(), total, "seed {seed}: complete");
        assert!(
            rx.got
                .iter()
                .enumerate()
                .all(|(o, &b)| b == byte_at(o as u32)),
            "seed {seed}: the bytes are right"
        );
        assert!(ms < 60_000, "seed {seed}: {ms} ms");
        // Without loss or with reordering only, almost nothing is sent twice.
        let st = &s.stats;
        if loss == 0 && jitter <= 4 {
            assert!(
                st.retransmits <= 3,
                "seed {seed}: {} retransmissions for pure reordering (jitter {jitter} ms)",
                st.retransmits
            );
        }
        if loss == 0 {
            // Reordering by more than a round trip: some segments are sent
            // again before the window has grown, a few percent, not more.
            assert!(
                st.retransmits <= 276 / 10,
                "seed {seed}: {}",
                st.retransmits
            );
        }
        assert!(
            st.retransmits < 400_000 / 1448 / 2,
            "seed {seed}: {} retransmissions of {} segments",
            st.retransmits,
            total / 1448
        );
    }
}

// ---- small segments: what an MQTT stream sends (ADR-268) -------------------

impl Rig {
    /// The application hands over `n` bytes and the pass ends: one segment of
    /// `n` bytes goes out (a QoS 1 PUBLISH or a PUBACK in its TLS record).
    fn message(&mut self, n: usize) -> Vec<Sent> {
        let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
        assert_eq!(self.s.send(self.c, &data), n);
        self.flush(0)
    }

    /// `count` messages of `size` bytes, one segment each.
    fn messages(&mut self, count: usize, size: usize) -> Vec<Sent> {
        let mut sent = Vec::new();
        for _ in 0..count {
            let s = self.message(size);
            assert_eq!(s.len(), 1, "one segment per message: {s:?}");
            sent.extend(s);
        }
        sent
    }
}

/// A lost segment among small ones (120 bytes, a QoS 1 message in its TLS record) is
/// repaired by a fast retransmit once three segments are reported above it, as
/// NewReno's three duplicate ACKs did: RFC 6675's "more than two segments" counted
/// in bytes of a full MSS needed some 25 such segments, which an MQTT flow seldom
/// has in flight, and the hole waited for the retransmission timer (200 ms or more,
/// 1 s before the first RTT sample) instead. On the netcup VPS 90 % of the
/// retransmissions of the SACK build were such timeouts (ADR-268).
#[test]
fn a_lost_small_segment_is_resent_after_three_segments_above_it() {
    let mut r = Rig::new(true, 0);
    let flight = r.messages(8, 120);
    let lost = flight[1];
    let lost_off = r.off(lost);
    let after = r.off(flight[2]);
    let mut resent = Vec::new();
    // The first arrives, then the receiver reports each one above the hole.
    resent.extend(r.ack(1, r.top(flight[0]), &[], flight[0].tsval));
    for f in flight.iter().skip(2).take(3) {
        let top = r.top(*f);
        resent.extend(r.ack(1, lost_off, &[(after, top)], f.tsval));
    }
    // The reordering window passes (well short of any retransmission timeout).
    resent.extend(r.ack(5, lost_off, &[(after, r.top(flight[4]))], flight[4].tsval));
    resent.extend(r.flush(5));
    let again: Vec<Sent> = resent.into_iter().filter(|x| x.seq == lost.seq).collect();
    assert_eq!(
        again.len(),
        1,
        "the hole, once, without a timeout: {again:?}"
    );
    assert_eq!(again[0].len, 120);
    assert_eq!(r.s.stats.fast_retransmits, 1);
    assert_eq!(r.s.stats.retransmits, 1);
}

/// Two segments above a small hole are still reordering, not loss.
#[test]
fn two_small_segments_above_a_hole_are_not_a_loss() {
    let mut r = Rig::new(true, 0);
    let flight = r.messages(8, 120);
    let lost_off = r.off(flight[1]);
    let after = r.off(flight[2]);
    r.ack(1, r.top(flight[0]), &[], flight[0].tsval);
    for f in flight.iter().skip(2).take(2) {
        let top = r.top(*f);
        r.ack(1, lost_off, &[(after, top)], f.tsval);
    }
    r.ack(5, lost_off, &[(after, r.top(flight[3]))], flight[3].tsval);
    r.flush(5);
    assert_eq!(r.s.stats.retransmits, 0);
    assert!(!r.s.conn(r.c).unwrap().has(IN_RECOVERY));
}

/// The second of two small holes in one flight is repaired in the same recovery,
/// not by a timeout.
#[test]
fn two_small_holes_are_both_repaired_without_a_timeout() {
    let mut r = Rig::new(true, 0);
    let flight = r.messages(12, 120);
    let (a, b) = (1usize, 6usize);
    let mut got = alloc::vec![false; flight.len()];
    let mut resent: Vec<Sent> = Vec::new();
    got[0] = true;
    for k in 2..flight.len() {
        if k == b {
            continue;
        }
        got[k] = true;
        let (cum, blocks) = report(&r, &flight, &got, k);
        resent.extend(r.ack(1, cum, &blocks, flight[k].tsval));
    }
    let (cum, blocks) = report(&r, &flight, &got, flight.len() - 1);
    resent.extend(r.ack(5, cum, &blocks, flight[flight.len() - 1].tsval));
    resent.extend(r.flush(5));
    let mut holes: Vec<u32> = resent
        .iter()
        .filter(|x| x.seq == flight[a].seq || x.seq == flight[b].seq)
        .map(|x| x.seq)
        .collect();
    holes.sort_unstable();
    holes.dedup();
    assert_eq!(holes.len(), 2, "both holes: {resent:?}");
    assert_eq!(r.s.stats.fast_retransmits, 1, "one recovery for both");
    assert_eq!(r.s.stats.retransmits, 2);
}

/// An MQTT-like stream over a link that drops `loss` per mille of the segments:
/// up to `per_ms` messages of `size` bytes every millisecond, each its own
/// segment, while fewer than `inflight` messages are unacknowledged (QoS 1: the
/// peer's receive maximum, a publisher waiting for its PUBACKs). Returns the
/// stack, how many bytes arrived and the milliseconds it took.
fn stream(
    total: usize,
    size: usize,
    per_ms: usize,
    inflight: usize,
    loss: u64,
    seed: u64,
) -> (TcpStack, usize, u64) {
    let mut r = Rig::new(true, 0);
    let mut rng = Rng(seed | 1);
    let mut rx = Receiver {
        base: r.base,
        next: 0,
        ranges: Vec::new(),
        latest: 0,
        got: Vec::new(),
        tsval: 0,
        dsack: None,
    };
    let mut link: Vec<(u64, bool, Vec<u8>)> = Vec::new();
    let mut queued = 0usize;
    let mut now = 10u64;
    while now < 120_000 && rx.got.len() < total {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for _ in 0..per_ms {
            let held = r.s.conn(r.c).map_or(0, |k| k.tx_len());
            if queued >= total || r.s.send_space(r.c) < size || held + size > inflight * size {
                break;
            }
            let chunk: Vec<u8> = (queued..queued + size).map(|o| byte_at(o as u32)).collect();
            queued += r.s.send(r.c, &chunk);
            r.s.flush(now, &mut |_, b| out.push(b.to_vec()));
        }
        r.s.poll(now, &mut r.app, &mut |_, b| out.push(b.to_vec()));
        r.s.flush(now, &mut |_, b| out.push(b.to_vec()));
        for b in out {
            if !rng.chance(loss) {
                link.push((now + 5, false, b));
            }
        }
        link.sort_by_key(|(due, _, _)| *due);
        let split = link.partition_point(|(due, _, _)| *due <= now);
        let due: Vec<(u64, bool, Vec<u8>)> = link.drain(..split).collect();
        for (_, to_server, bytes) in due {
            if to_server {
                let mut out: Vec<Vec<u8>> = Vec::new();
                r.s.input(now, CLIENT, &bytes, &mut r.app, &mut |_, b| {
                    out.push(b.to_vec())
                });
                for b in out {
                    link.push((now + 5, false, b));
                }
            } else {
                let h = wire::parse(SERVER, CLIENT, &bytes).unwrap();
                let len = bytes.len() - h.data_off;
                if len > 0 {
                    rx.segment(h.seq, h.ts.map_or(0, |(v, _)| v), &bytes[h.data_off..]);
                    link.push((now + 5, true, rx.ack(&mut r)));
                }
            }
        }
        now += 1;
    }
    assert!(
        rx.got
            .iter()
            .enumerate()
            .all(|(o, &b)| b == byte_at(o as u32)),
        "the bytes are right"
    );
    (r.s, rx.got.len(), now)
}

/// A stream of small messages over a lossy link repairs its losses with fast
/// retransmits, not with the retransmission timer: on one core of the netcup VPS
/// the timer's 200 ms (doubling) and the window cut to one segment after it were
/// the QoS 1 regression of the SACK build (ADR-268).
#[test]
fn a_stream_of_small_messages_recovers_without_the_timer() {
    for (seed, loss) in [(11, 10), (12, 20), (13, 5)] {
        // At most 16 messages of 120 bytes unacknowledged (1 920 bytes, less
        // than "more than two" full segments), as fast as they are acknowledged.
        let total = 120 * 3000;
        let (s, got, ms) = stream(total, 120, 16, 16, loss, seed);
        assert_eq!(got, total, "seed {seed}: complete");
        let st = &s.stats;
        assert!(st.fast_retransmits > 0, "seed {seed}: {st:?}");
        assert!(
            st.rto_fired * 5 <= st.retransmits,
            "seed {seed}: {} of {} retransmissions on the timer ({} fast)",
            st.rto_fired,
            st.retransmits,
            st.fast_retransmits
        );
        // Each timeout costs at least 200 ms with nothing else to send: with
        // them, the 3 000 messages took 2.8x as long (6.4 s against 2.2 s).
        assert!(ms < 3_000, "seed {seed}: {ms} ms");
    }
}
