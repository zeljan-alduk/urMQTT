//! Toeplitz hash (Microsoft RSS) over the IPv4 TCP 4-tuple: the same flow
//! always lands on the same core, in software dispatch and (with the same
//! key) when a NIC does RSS itself.

/// The default key from the Microsoft RSS specification (40 bytes).
pub const DEFAULT_KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

/// Toeplitz hash of `input` under `key` (`key` must be at least
/// `input.len() + 4` bytes long; extra input is ignored).
pub fn toeplitz(key: &[u8], input: &[u8]) -> u32 {
    let mut result = 0u32;
    // The 32-bit window of the key that lines up with the current bit.
    let mut window = u32::from_be_bytes([
        key.first().copied().unwrap_or(0),
        key.get(1).copied().unwrap_or(0),
        key.get(2).copied().unwrap_or(0),
        key.get(3).copied().unwrap_or(0),
    ]);
    for (i, &byte) in input.iter().enumerate() {
        let next = key.get(i + 4).copied().unwrap_or(0);
        for bit in (0..8).rev() {
            if byte >> bit & 1 == 1 {
                result ^= window;
            }
            window = (window << 1) | u32::from(next >> bit & 1);
        }
    }
    result
}

/// RSS hash of an IPv4 TCP flow, as seen on receive (source = the peer).
pub fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    let mut input = [0u8; 12];
    input[..4].copy_from_slice(&src);
    input[4..8].copy_from_slice(&dst);
    input[8..10].copy_from_slice(&sport.to_be_bytes());
    input[10..].copy_from_slice(&dport.to_be_bytes());
    toeplitz(&DEFAULT_KEY, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One source address (a load generator, a NAT gateway) must still
    /// spread over the worker cores: only the source port varies, and the
    /// hash modulo the worker count must be even for the port ranges
    /// operating systems use (PERF, ADR-080).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "750 000 Toeplitz hashes: minutes under Miri, pure integer arithmetic"
    )]
    fn one_source_address_spreads_over_the_workers() {
        for (lo, hi) in [(32768u16, 60999u16), (49152, 65535), (1024, 65535)] {
            for workers in 2usize..=8 {
                let mut count = alloc::vec![0usize; workers];
                for sport in lo..=hi {
                    let h = ipv4_tcp([10, 0, 2, 2], [169, 58, 184, 193], sport, 8883);
                    count[h as usize % workers] += 1;
                }
                let total = usize::from(hi - lo) + 1;
                let fair = total / workers;
                for (core, &n) in count.iter().enumerate() {
                    // Within 4 % of a fair share.
                    assert!(
                        n.abs_diff(fair) * 100 <= fair * 4,
                        "ports {lo}..={hi}, {workers} workers: core {core} got {n} of {total}"
                    );
                }
            }
        }
    }

    /// Verification suite from the Microsoft RSS specification (IPv4 with
    /// TCP ports).
    #[test]
    fn microsoft_verification_suite() {
        let cases = [
            (
                [66, 9, 149, 187],
                2794,
                [161, 142, 100, 80],
                1766,
                0x51cc_c178u32,
            ),
            (
                [199, 92, 111, 2],
                14230,
                [65, 69, 140, 83],
                4739,
                0xc626_b0ea,
            ),
            (
                [24, 19, 198, 95],
                12898,
                [12, 22, 207, 184],
                38024,
                0x5c2b_394a,
            ),
            (
                [38, 27, 205, 30],
                48228,
                [209, 142, 163, 6],
                2217,
                0xafc7_327f,
            ),
            (
                [153, 39, 163, 191],
                44251,
                [202, 188, 127, 2],
                1303,
                0x10e8_28a2,
            ),
        ];
        for (src, sport, dst, dport, want) in cases {
            assert_eq!(
                ipv4_tcp(src, dst, sport, dport),
                want,
                "{src:?}:{sport} -> {dst:?}:{dport}"
            );
        }
    }
}
