//! Congestion control: a pluggable interface with NewReno (RFC 5681,
//! RFC 6582) as the implementation, initial window 10 segments (RFC 6928),
//! a window that only grows while it is used (RFC 7661) and a reduction of 30 %
//! on a fast retransmit, as Linux's CUBIC does (ADR-232).

pub trait Congestion {
    /// `flight` bytes are in flight after a send.
    fn on_sent(&mut self, flight: u32);
    /// Bytes acknowledged by a cumulative ACK outside recovery; `flight` is
    /// what is still in flight, `round` whether the ACK ends a round trip
    /// (the one the RTT is timed over).
    fn on_ack(&mut self, acked: u32, mss: u32, flight: u32, round: bool);
    /// Third duplicate ACK: entering fast recovery with `flight` bytes out.
    fn on_fast_retransmit(&mut self, flight: u32, mss: u32);
    /// A partial or full ACK during recovery.
    fn on_recovery_ack(&mut self, acked: u32, mss: u32, full: bool);
    /// Further duplicate ACK in recovery (window inflation).
    fn on_dupack_in_recovery(&mut self, mss: u32);
    /// Retransmission timeout with `flight` bytes out.
    fn on_timeout(&mut self, flight: u32, mss: u32);
    fn window(&self) -> u32;
}

/// Segments one ACK may add to the window in slow start.
const SS_BURST: u32 = 16;

/// `ssthresh` and the peak are kept in units of 64 bytes in 16 bits (up to
/// 4 MiB), so that the state of a connection stays within its budget (M15).
const UNIT_SHIFT: u32 = 6;

#[derive(Debug, Clone, Copy)]
pub struct NewReno {
    pub cwnd: u32,
    /// Slow start threshold in units of 64 bytes; the maximum is "none".
    ssthresh64: u16,
    /// The most bytes in flight in the current round trip or the one before
    /// (cwnd validation, RFC 7661), in units of 64 bytes. A window that
    /// nothing fills is not grown: a flow that sends less than it may (the
    /// application's pace, a quiet subscriber) used to grow it to megabytes,
    /// and the first loss then cut *what was in flight*, a few segments, so
    /// the next burst of messages was let out a few segments per round trip.
    peak64: u16,
}

fn to_units(bytes: u32) -> u16 {
    (bytes.div_ceil(1 << UNIT_SHIFT)).min(u32::from(u16::MAX) - 1) as u16
}

impl NewReno {
    pub fn new(mss: u32) -> Self {
        Self {
            cwnd: 10 * mss,
            ssthresh64: u16::MAX,
            peak64: 0,
        }
    }

    /// The slow start threshold in bytes (`u32::MAX`: none yet).
    pub fn ssthresh(&self) -> u32 {
        if self.ssthresh64 == u16::MAX {
            u32::MAX
        } else {
            u32::from(self.ssthresh64) << UNIT_SHIFT
        }
    }

    /// Sets the threshold (rounded to 64 bytes, at most 4 MiB).
    pub fn set_ssthresh(&mut self, bytes: u32) {
        self.ssthresh64 = to_units(bytes);
    }

    /// The most bytes in flight lately.
    fn peak(&self) -> u32 {
        u32::from(self.peak64) << UNIT_SHIFT
    }

    /// What the window is worth after a loss: the smaller of the window and
    /// twice the lately used flight, but at least what is in flight now.
    fn demand(&self, flight: u32, mss: u32) -> u32 {
        self.cwnd
            .min(self.peak().saturating_mul(2).max(10 * mss))
            .max(flight)
    }
}

impl Congestion for NewReno {
    fn on_sent(&mut self, flight: u32) {
        self.peak64 = self.peak64.max(to_units(flight));
    }

    fn on_ack(&mut self, acked: u32, mss: u32, flight: u32, round: bool) {
        let slow_start = self.cwnd < self.ssthresh();
        // Grown while the flow uses it: in slow start up to twice the largest
        // flight, in congestion avoidance while the flight comes within two
        // segments of the window (Linux: `is_cwnd_limited`).
        let used = if slow_start {
            self.cwnd < self.peak().saturating_mul(2).max(10 * mss)
        } else {
            self.peak().saturating_add(2 * mss) >= self.cwnd
        };
        if round {
            // A round trip is over: from here on the peak is what is still out.
            self.peak64 = to_units(flight);
        }
        if !used {
            return;
        }
        if slow_start {
            // Slow start counts the bytes an ACK covers (RFC 3465, ABC), up to
            // `SS_BURST` segments per ACK. The limit L=2 of the RFC is too low
            // against a receiver whose ACKs arrive in batches (a virtual CPU the
            // host keeps preempting, receive offload): one ACK for 40 segments
            // then grew the window by two. Linux counts every acknowledged byte.
            self.cwnd = self
                .cwnd
                .saturating_add(acked.min(SS_BURST.saturating_mul(mss)));
        } else {
            // Congestion avoidance: about one MSS per round trip, counted in bytes
            // as well (an ACK for many segments is many increments).
            let inc =
                (u64::from(mss) * u64::from(acked) / u64::from(self.cwnd.max(1))).max(1) as u32;
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    fn on_fast_retransmit(&mut self, flight: u32, mss: u32) {
        // 70 % of what the flow was using (Linux's CUBIC; Reno's 50 % is for a
        // path whose only loss is congestion).
        let base = self.demand(flight, mss);
        self.set_ssthresh(((u64::from(base) * 7 / 10) as u32).max(2 * mss));
        self.cwnd = self.ssthresh() + 3 * mss;
    }

    fn on_recovery_ack(&mut self, acked: u32, mss: u32, full: bool) {
        if full {
            self.cwnd = self.ssthresh();
        } else {
            // Partial ACK: deflate by the amount acked, add back one MSS.
            self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(mss);
        }
    }

    fn on_dupack_in_recovery(&mut self, mss: u32) {
        self.cwnd = self.cwnd.saturating_add(mss);
    }

    fn on_timeout(&mut self, flight: u32, mss: u32) {
        let base = self.demand(flight, mss);
        self.set_ssthresh((base / 2).max(2 * mss));
        self.cwnd = mss;
        self.peak64 = 0;
    }

    fn window(&self) -> u32 {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ACK for `acked` bytes that leaves `flight` out; it ends the round when nothing is.
    fn ack(c: &mut NewReno, acked: u32, mss: u32, flight: u32) {
        c.on_ack(acked, mss, flight, flight == 0);
    }

    #[test]
    fn slow_start_doubles_per_round_trip_with_delayed_acks() {
        let mss = 1448;
        let mut c = NewReno::new(mss);
        // One round trip: 10 segments sent and in flight, acknowledged two at a time.
        c.on_sent(10 * mss);
        let start = c.window();
        for i in 0..5 {
            c.on_ack(2 * mss, mss, (8 - 2 * i) * mss, false);
        }
        assert_eq!(c.window(), 2 * start);
        // A stretch ACK (a whole burst at once) counts for what it covers, up to
        // 16 segments.
        c.on_sent(40 * mss);
        let before = c.window();
        ack(&mut c, 40 * mss, mss, 20 * mss);
        assert_eq!(c.window(), before + 16 * mss);
        // In congestion avoidance an ACK for many segments is many increments.
        let mut c = NewReno::new(mss);
        c.on_sent(40 * mss);
        c.on_fast_retransmit(40 * mss, mss);
        c.on_recovery_ack(mss, mss, true);
        let w = c.window();
        c.on_sent(w);
        ack(&mut c, 10 * mss, mss, w - 10 * mss);
        assert_eq!(c.window(), w + 10 * mss * mss / w);
    }

    #[test]
    fn a_window_nothing_fills_does_not_grow() {
        let mss = 1448;
        let mut c = NewReno::new(mss);
        // 2 segments in flight at a time, for a long while, the window is 10.
        for _ in 0..1000 {
            c.on_sent(2 * mss);
            ack(&mut c, 2 * mss, mss, 0);
        }
        assert_eq!(
            c.window(),
            10 * mss,
            "an idle flow keeps its initial window"
        );
        // The same in congestion avoidance.
        c.set_ssthresh(5 * mss);
        for _ in 0..1000 {
            c.on_sent(2 * mss);
            ack(&mut c, 2 * mss, mss, 0);
        }
        assert_eq!(c.window(), 10 * mss);
        // A flow that fills it grows it.
        let mut c = NewReno::new(mss);
        for _ in 0..20 {
            let w = c.window();
            c.on_sent(w);
            ack(&mut c, w, mss, 0);
        }
        assert!(c.window() > 100 * mss, "{}", c.window());
    }

    #[test]
    fn loss_cuts_what_the_flow_was_using_not_a_stale_window() {
        let mss = 1024;
        let mut c = NewReno::new(mss);
        c.on_sent(40 * mss);
        // 40 segments in flight and a window that has grown to 400: the reduction is
        // 70 % of the (validated) window, bounded by twice the flight.
        c.cwnd = 400 * mss;
        c.on_fast_retransmit(40 * mss, mss);
        assert_eq!(
            c.ssthresh(),
            56 * mss,
            "70 % of twice the flight, not of 400"
        );
        c.on_recovery_ack(mss, mss, true);
        assert_eq!(c.window(), 56 * mss);
        // The same when everything is in use: 70 % of 40.
        let mut c = NewReno::new(mss);
        c.on_sent(40 * mss);
        c.cwnd = 40 * mss;
        c.on_fast_retransmit(40 * mss, mss);
        assert_eq!(c.ssthresh(), 28 * mss);
        c.on_recovery_ack(mss, mss, true);
        // A timeout halves and restarts.
        c.on_timeout(28 * mss, mss);
        assert_eq!((c.window(), c.ssthresh()), (mss, 14 * mss));
    }
}
