//! Congestion control: a pluggable interface with NewReno (RFC 5681,
//! RFC 6582) as the implementation, initial window 10 segments (RFC 6928).

pub trait Congestion {
    /// Bytes acknowledged by a cumulative ACK outside recovery.
    fn on_ack(&mut self, acked: u32, mss: u32);
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

#[derive(Debug, Clone, Copy)]
pub struct NewReno {
    pub cwnd: u32,
    pub ssthresh: u32,
}

impl NewReno {
    pub fn new(mss: u32) -> Self {
        Self {
            cwnd: 10 * mss,
            ssthresh: u32::MAX,
        }
    }
}

impl Congestion for NewReno {
    fn on_ack(&mut self, acked: u32, mss: u32) {
        if self.cwnd < self.ssthresh {
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
        self.ssthresh = (flight / 2).max(2 * mss);
        self.cwnd = self.ssthresh + 3 * mss;
    }

    fn on_recovery_ack(&mut self, acked: u32, mss: u32, full: bool) {
        if full {
            self.cwnd = self.ssthresh;
        } else {
            // Partial ACK: deflate by the amount acked, add back one MSS.
            self.cwnd = self.cwnd.saturating_sub(acked).saturating_add(mss);
        }
    }

    fn on_dupack_in_recovery(&mut self, mss: u32) {
        self.cwnd = self.cwnd.saturating_add(mss);
    }

    fn on_timeout(&mut self, flight: u32, mss: u32) {
        self.ssthresh = (flight / 2).max(2 * mss);
        self.cwnd = mss;
    }

    fn window(&self) -> u32 {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_doubles_per_round_trip_with_delayed_acks() {
        let mss = 1448;
        let mut c = NewReno::new(mss);
        // One round trip: 10 segments in flight, acknowledged two at a time.
        let start = c.window();
        for _ in 0..5 {
            c.on_ack(2 * mss, mss);
        }
        assert_eq!(c.window(), 2 * start);
        // A stretch ACK (a whole burst at once) counts for what it covers, up to
        // 16 segments.
        let before = c.window();
        c.on_ack(40 * mss, mss);
        assert_eq!(c.window(), before + 16 * mss);
        // In congestion avoidance an ACK for many segments is many increments.
        let mut c = NewReno::new(mss);
        c.on_fast_retransmit(40 * mss, mss);
        c.on_recovery_ack(mss, mss, true);
        let w = c.window();
        c.on_ack(10 * mss, mss);
        assert_eq!(c.window(), w + 10 * mss * mss / w);
    }

    #[test]
    fn loss_halves_the_window_and_a_timeout_restarts() {
        let mss = 1000;
        let mut c = NewReno::new(mss);
        c.on_fast_retransmit(40 * mss, mss);
        assert_eq!(c.ssthresh, 20 * mss);
        c.on_recovery_ack(mss, mss, true);
        assert_eq!(c.window(), 20 * mss);
        c.on_timeout(20 * mss, mss);
        assert_eq!((c.window(), c.ssthresh), (mss, 10 * mss));
    }
}
