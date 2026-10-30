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

/// How long the previous key still validates after a rotation: the
/// longest a cookie can be valid (two periods).
pub const PREVIOUS_KEY_S: u64 = 2 * PERIOD_S;

pub struct Cookies {
    key: [u8; 16],
    /// The key before the last rotation, accepted until `previous_until_s`
    /// (H3): a handshake in flight across a rotation still completes.
    previous: Option<[u8; 16]>,
    previous_until_s: u64,
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
        Self {
            key,
            previous: None,
            previous_until_s: 0,
        }
    }

    /// Replaces the key; the old one validates for [`PREVIOUS_KEY_S`] more.
    pub fn rotate(&mut self, key: [u8; 16], now_s: u64) {
        self.previous = Some(core::mem::replace(&mut self.key, key));
        self.previous_until_s = now_s + PREVIOUS_KEY_S;
    }

    fn mac(&self, t: u32, f: &Flow, client_isn: u32) -> u32 {
        Self::mac_with(&self.key, t, f, client_isn)
    }

    fn mac_with(key: &[u8; 16], t: u32, f: &Flow, client_isn: u32) -> u32 {
        let mut h = SipHasher::new(key);
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
        let mac = our_isn & 0x00ff_ffff;
        let current = mac == self.mac(t, f, client_isn);
        let previous = !current
            && now_s < self.previous_until_s
            && self
                .previous
                .is_some_and(|k| mac == Self::mac_with(&k, t, f, client_isn));
        if !current && !previous {
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

    /// H3 (H0-W3): after a rotation new cookies use the new key, cookies
    /// made just before still validate for their lifetime, and never after.
    #[test]
    fn rotation_keeps_cookies_in_flight_valid() {
        let mut c = Cookies::new([7; 16]);
        let f = Flow {
            src: [10, 0, 2, 2],
            sport: 40000,
            dst: [10, 0, 2, 15],
            dport: 8883,
        };
        let before = c.make(1000, &f, 1, 1460);
        c.rotate([9; 16], 1001);
        let after = c.make(1001, &f, 1, 1460);
        assert_ne!(before, after, "new cookies come from the new key");
        assert_eq!(c.check(1001, &f, 1, before), Some(1460));
        assert_eq!(c.check(1001 + 63, &f, 1, before), Some(1460));
        assert_eq!(c.check(1001, &f, 1, after), Some(1460));
        // The window outlasts every cookie the old key made (rotation
        // comes after `make`, the window is a cookie's longest life), so
        // the old key never cuts a valid cookie short; after it, nothing.
        assert_eq!(c.check(1001 + PREVIOUS_KEY_S, &f, 1, before), None);
        // Two rotations: only the latest previous key is kept.
        c.rotate([11; 16], 1010);
        assert_eq!(c.check(1010, &f, 1, before), None);
        assert_eq!(c.check(1010, &f, 1, after), Some(1460));
    }
}
