//! Toeplitz hash (Microsoft RSS) over the TCP 4-tuple of IPv4 and IPv6: the
//! same flow always lands on the same core, in software dispatch and (with
//! the same key) when a NIC does RSS itself (IPv6: NEXT-1, ADR-333).

use crate::addr::Addr;

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

/// Entries of the indirection table that the kernel's steering and the
/// device's RSS share when the NIC steers flows itself (virtio-net
/// multiqueue, NEXT-6, ADR-311). A power of two: the device indexes the
/// table with the hash's low bits. virtio-net devices that offer RSS accept
/// 128 (QEMU's maximum); a device that cannot take it is not used for
/// steering.
pub const TABLE_LEN: usize = 128;

/// The core of a flow with hash `h` among `count` cores from `first`, by
/// the indirection table ([`table`]): `first + (h mod TABLE_LEN) mod
/// count`. The device's RSS computes the same by looking up `table`, so a
/// frame lands on the queue of the core that owns its flow.
pub const fn core_by_table(h: u32, first: usize, count: usize) -> usize {
    let count = if count == 0 { 1 } else { count };
    first + (h as usize % TABLE_LEN) % count
}

/// The indirection table of [`core_by_table`]: entry `i` names core
/// `first + i mod count`.
pub fn table(first: usize, count: usize) -> [usize; TABLE_LEN] {
    core::array::from_fn(|i| core_by_table(i as u32, first, count))
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

/// RSS hash of an IPv6 TCP flow, as seen on receive: the addresses of the
/// IPv6 header (not those of a Home Address option or a Routing header, the
/// `_EX` hash types this stack never asks a device for), then the ports.
pub fn ipv6_tcp(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> u32 {
    let mut input = [0u8; 36];
    input[..16].copy_from_slice(&src);
    input[16..32].copy_from_slice(&dst);
    input[32..34].copy_from_slice(&sport.to_be_bytes());
    input[34..].copy_from_slice(&dport.to_be_bytes());
    toeplitz(&DEFAULT_KEY, &input)
}

/// RSS hash of a TCP flow of either family.
pub fn tcp(src: Addr, dst: Addr, sport: u16, dport: u16) -> u32 {
    match (src.as_v4(), dst.as_v4()) {
        (Some(s), Some(d)) => ipv4_tcp(s, d, sport, dport),
        _ => ipv6_tcp(src.octets(), dst.octets(), sport, dport),
    }
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

    /// The table and the hash agree for every hash (ADR-311): what the
    /// device looks up is what the kernel computes.
    #[test]
    fn the_table_and_the_computation_agree() {
        for (first, count) in [(1usize, 1usize), (1, 2), (1, 3), (0, 4), (1, 7), (0, 16)] {
            let t = table(first, count);
            let mut h = 0x9e37_79b9u32;
            for _ in 0..20_000 {
                h = h.wrapping_mul(0x0100_0193) ^ (h >> 13);
                assert_eq!(
                    t[h as usize & (TABLE_LEN - 1)],
                    core_by_table(h, first, count)
                );
            }
            for (i, c) in t.iter().enumerate() {
                assert!((first..first + count).contains(c), "entry {i}");
            }
        }
        assert_eq!(core_by_table(5, 1, 0), 1, "no cores: the first");
    }

    /// One source address still spreads over the workers through the table.
    /// A 128-entry table cannot split evenly over 3, 5, 6 or 7 cores: some
    /// get one entry more (7 cores: 19 or 18 entries, +3.9 % and -1.6 % of a
    /// fair share), which is the bound here with the hash's own spread.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "450 000 Toeplitz hashes: minutes under Miri, pure integer arithmetic"
    )]
    fn one_source_address_spreads_over_the_workers_by_the_table() {
        for (lo, hi) in [(32768u16, 60999u16), (49152, 65535), (1024, 65535)] {
            for workers in 2usize..=8 {
                let mut count = alloc::vec![0usize; workers];
                for sport in lo..=hi {
                    let h = ipv4_tcp([10, 0, 2, 2], [169, 58, 184, 193], sport, 8883);
                    count[core_by_table(h, 0, workers)] += 1;
                }
                let total = usize::from(hi - lo) + 1;
                let fair = total / workers;
                for (core, &n) in count.iter().enumerate() {
                    assert!(
                        n.abs_diff(fair) * 100 <= fair * 6,
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

    /// Verification suite from the Microsoft RSS specification (IPv6 with
    /// TCP ports): the 40-byte key covers the 36 bytes of input.
    #[test]
    fn microsoft_verification_suite_ipv6() {
        fn a(g: [u16; 8]) -> [u8; 16] {
            let mut x = [0u8; 16];
            for (i, v) in g.iter().enumerate() {
                x[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
            }
            x
        }
        let cases = [
            (
                a([0x3ffe, 0x2501, 0x200, 0x1fff, 0, 0, 0, 7]),
                2794,
                a([0x3ffe, 0x2501, 0x200, 3, 0, 0, 0, 1]),
                1766,
                0x4020_7d3du32,
            ),
            (
                a([0x3ffe, 0x501, 8, 0, 0x260, 0x97ff, 0xfe40, 0xefab]),
                14230,
                a([0xff02, 0, 0, 0, 0, 0, 0, 1]),
                4739,
                0xdde5_1bbf,
            ),
            (
                a([0x3ffe, 0x1900, 0x4545, 3, 0x200, 0xf8ff, 0xfe21, 0x67cf]),
                44251,
                a([0xfe80, 0, 0, 0, 0x200, 0xf8ff, 0xfe21, 0x67cf]),
                38024,
                0x02d1_feef,
            ),
        ];
        for (src, sport, dst, dport, want) in cases {
            assert_eq!(ipv6_tcp(src, dst, sport, dport), want);
            assert_eq!(tcp(Addr::v6(src), Addr::v6(dst), sport, dport), want);
        }
        // The family-neutral hash is the IPv4 one for IPv4 flows.
        assert_eq!(
            tcp(
                Addr::v4([66, 9, 149, 187]),
                Addr::v4([161, 142, 100, 80]),
                2794,
                1766
            ),
            0x51cc_c178
        );
    }
}
