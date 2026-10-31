//! Ethernet, ARP, IPv4, ICMP and DHCPv4 handling with dispatch to TCP.
//!
//! - [`classify`] and [`rss`]: receive-side steering for the dispatcher (M13).
//! - [`ipv4`], [`dhcp`], [`iface`]: the own IPv4 layer with ARP, ICMP echo,
//!   UDP for DHCP and a DHCPv4 client (M14, replacing smoltcp).

#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)
)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

pub mod admission;
pub mod dhcp;
pub mod iface;
pub mod ipv4;
pub mod rss;

/// What the dispatcher needs to know about a received Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// ARP request (only the owner of the NIC answers) or reply (every
    /// core's stack learns from it).
    Arp { reply: bool },
    /// IPv4 TCP: the 4-tuple, in network byte order.
    Tcp {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    },
    /// Everything else (DHCP, ICMP, UDP, IPv6, malformed).
    Other,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Classifies an Ethernet II frame without validating checksums (the
/// stack that receives it does).
pub fn classify(frame: &[u8]) -> Class {
    const ETH: usize = 14;
    match be16(frame, 12) {
        Some(0x0806) => match be16(frame, ETH + 6) {
            Some(2) => Class::Arp { reply: true },
            Some(1) => Class::Arp { reply: false },
            _ => Class::Other,
        },
        Some(0x0800) => {
            let Some(&vihl) = frame.get(ETH) else {
                return Class::Other;
            };
            let ihl = usize::from(vihl & 0x0f) * 4;
            let frag = be16(frame, ETH + 6).unwrap_or(0);
            // Version 4, a sane header length, TCP, and not a non-first
            // fragment (which carries no ports).
            if vihl >> 4 != 4 || ihl < 20 || frame.get(ETH + 9) != Some(&6) || frag & 0x1fff != 0 {
                return Class::Other;
            }
            let ip = |at: usize| -> Option<[u8; 4]> { frame.get(at..at + 4)?.try_into().ok() };
            let t = ETH + ihl;
            match (
                ip(ETH + 12),
                ip(ETH + 16),
                be16(frame, t),
                be16(frame, t + 2),
            ) {
                (Some(src), Some(dst), Some(sport), Some(dport)) => Class::Tcp {
                    src,
                    dst,
                    sport,
                    dport,
                },
                _ => Class::Other,
            }
        }
        _ => Class::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[14 + 9] = 6;
        f[14 + 12..14 + 16].copy_from_slice(&src);
        f[14 + 16..14 + 20].copy_from_slice(&dst);
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f
    }

    #[test]
    fn classifies_tcp_arp_and_others() {
        let f = tcp_frame([10, 0, 2, 2], [10, 0, 2, 15], 51000, 8883);
        assert_eq!(
            classify(&f),
            Class::Tcp {
                src: [10, 0, 2, 2],
                dst: [10, 0, 2, 15],
                sport: 51000,
                dport: 8883
            }
        );
        let mut frag = f.clone();
        frag[14 + 6..14 + 8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert_eq!(classify(&frag), Class::Other);
        let mut udp = f.clone();
        udp[14 + 9] = 17;
        assert_eq!(classify(&udp), Class::Other);
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        arp[20..22].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(classify(&arp), Class::Arp { reply: true });
        arp[21] = 1;
        assert_eq!(classify(&arp), Class::Arp { reply: false });
        assert_eq!(classify(&[]), Class::Other);
        assert_eq!(classify(&f[..30]), Class::Other);
    }
}
