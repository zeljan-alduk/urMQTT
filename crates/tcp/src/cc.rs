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
            // Slow start: at most one MSS per ACK (RFC 5681 §3.1, ABC L=1).
            self.cwnd = self.cwnd.saturating_add(acked.min(mss));
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
