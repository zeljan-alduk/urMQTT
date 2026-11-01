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
            // Slow start: at most two MSS per ACK (RFC 3465 §2.3, ABC with L=2,
            // the value that lets a window double per round trip when the peer
            // acknowledges every second segment).
            self.cwnd = self.cwnd.saturating_add(acked.min(2 * mss));
        } else {
            // Congestion avoidance: about one MSS per RTT.
            let inc = (u64::from(mss) * u64::from(mss) / u64::from(self.cwnd.max(1))).max(1) as u32;
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
        // A stretch ACK (a whole burst at once) counts for two segments only.
        let before = c.window();
        c.on_ack(20 * mss, mss);
        assert_eq!(c.window(), before + 2 * mss);
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
