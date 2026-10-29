//! SYN cookies (always on, PROMPT §5.2): the initial sequence number
//! carries a 5-bit time counter, a 3-bit MSS index and a 24-bit SipHash
//! MAC over the 4-tuple, the client's ISN and the counter. Half-open
//! connections therefore need no state at all.
//!
//! Like Linux without timestamps, cookies cannot carry window scaling or
//! SACK, so the stack negotiates neither (ADR-033).

use crate::siphash::SipHasher;

/// MSS values a cookie can encode (largest ≤ the peer's MSS is used).
pub const MSS_TABLE: [u16; 8] = [536, 1024, 1200, 1300, 1360, 1400, 1440, 1460];
/// The time counter advances every 64 s; a cookie is valid for the
/// current and the previous period (64–128 s).
pub const PERIOD_S: u64 = 64;

pub struct Cookies {
    key: [u8; 16],
}

/// The connection a cookie is bound to (as seen by the server).
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub src: [u8; 4],
    pub sport: u16,
    pub dst: [u8; 4],
    pub dport: u16,
}

impl Cookies {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    fn mac(&self, t: u32, f: &Flow, client_isn: u32) -> u32 {
        let mut h = SipHasher::new(&self.key);
        h.write(&f.src);
        h.write(&f.sport.to_be_bytes());
        h.write(&f.dst);
        h.write(&f.dport.to_be_bytes());
        h.write(&client_isn.to_be_bytes());
        h.write(&t.to_be_bytes());
        (h.finish() & 0x00ff_ffff) as u32
    }

    fn counter(now_s: u64) -> u32 {
        ((now_s / PERIOD_S) & 0x1f) as u32
    }

    /// Our ISN for a SYN from `src:sport` to `dst:dport`.
    pub fn make(&self, now_s: u64, f: &Flow, client_isn: u32, peer_mss: u16) -> u32 {
        let t = Self::counter(now_s);
        let idx = MSS_TABLE.iter().rposition(|&m| m <= peer_mss).unwrap_or(0) as u32;
        (t << 27) | (idx << 24) | self.mac(t, f, client_isn)
    }

    /// Validates the cookie echoed in the handshake's final ACK
    /// (`our_isn = ack - 1`, `client_isn = seq - 1`). Returns the MSS.
    pub fn check(&self, now_s: u64, f: &Flow, client_isn: u32, our_isn: u32) -> Option<u16> {
        let t = our_isn >> 27;
        let now_t = Self::counter(now_s);
        if t != now_t && t != (now_t + 31) & 0x1f {
            return None;
        }
        if our_isn & 0x00ff_ffff != self.mac(t, f, client_isn) {
            return None;
        }
        MSS_TABLE.get(((our_isn >> 24) & 7) as usize).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_within_two_periods_and_bound_to_the_flow() {
        let c = Cookies::new([7; 16]);
        let (a, b) = ([10, 0, 2, 2], [10, 0, 2, 15]);
        let fl = |sport| Flow {
            src: a,
            sport,
            dst: b,
            dport: 8883,
        };
        let isn = c.make(1000, &fl(40000), 12345, 1460);
        assert_eq!(c.check(1000, &fl(40000), 12345, isn), Some(1460));
        assert_eq!(c.check(1000 + 64, &fl(40000), 12345, isn), Some(1460));
        assert_eq!(c.check(1000 + 200, &fl(40000), 12345, isn), None);
        assert_eq!(c.check(1000, &fl(40001), 12345, isn), None);
        assert_eq!(c.check(1000, &fl(40000), 12346, isn), None);
        assert_eq!(c.check(1000, &fl(40000), 12345, isn ^ 1), None);
        let small = c.make(1000, &fl(1), 0, 1000);
        assert_eq!(c.check(1000, &fl(1), 0, small), Some(536));
        // A different key never validates.
        assert_eq!(
            Cookies::new([8; 16]).check(1000, &fl(40000), 12345, isn),
            None
        );
    }
}
