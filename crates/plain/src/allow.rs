//! The allow-list: which source addresses may start a connection to the
//! plaintext port. It is part of the image's configuration and never changes
//! at run time; a lookup is a handful of mask-and-compare operations, cheap
//! enough to run on every SYN.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use urmqtt_cfg::net::Cidr;

/// Networks whose addresses may connect, or every address.
#[derive(Debug, Clone)]
pub struct AllowList {
    nets: Vec<Cidr>,
    anywhere: bool,
}

/// How exposed a listener is, from the broker's own address and its allow-list
/// (only for a warning at boot; never an access decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// The broker's address is private (or not known yet).
    Private,
    /// The address is public, but only private networks are allowed to connect.
    PublicAddressPrivateAllowList,
    /// The address is public and public addresses may connect (or all may).
    Open,
}

impl AllowList {
    pub fn new(nets: &[Cidr], anywhere: bool) -> Self {
        Self {
            nets: nets.to_vec(),
            anywhere,
        }
    }

    /// Whether a SYN from `ip` (as on the wire) may be answered.
    pub fn allows(&self, ip: [u8; 4]) -> bool {
        if self.anywhere {
            return true;
        }
        let ip = u32::from_be_bytes(ip);
        self.nets.iter().any(|n| n.contains(ip))
    }

    /// Every address is allowed (`allow_from_anywhere`).
    pub fn anywhere(&self) -> bool {
        self.anywhere
    }

    pub fn networks(&self) -> &[Cidr] {
        &self.nets
    }

    /// For the log and `$SYS`: `10.0.0.0/8, 192.168.0.0/16`, or `anywhere`.
    pub fn describe(&self) -> String {
        if self.anywhere {
            return "anywhere".into();
        }
        let mut s = String::new();
        for (i, n) in self.nets.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            let _ = write!(s, "{n}");
        }
        s
    }

    /// Whether some allowed address is outside the private ranges.
    pub fn reaches_public(&self) -> bool {
        if self.anywhere {
            return true;
        }
        self.nets.iter().any(|n| !within_private(n))
    }

    /// The exposure for a broker with the address `local` (all zero: none yet).
    pub fn exposure(&self, local: [u8; 4]) -> Exposure {
        if local == [0; 4] || urmqtt_cfg::net::is_private(local) {
            Exposure::Private
        } else if self.reaches_public() {
            Exposure::Open
        } else {
            Exposure::PublicAddressPrivateAllowList
        }
    }
}

/// The private ranges as networks (RFC 1918, RFC 6598, link-local, loopback).
const PRIVATE: [(u32, u8); 6] = [
    (0x0a00_0000, 8),
    (0xac10_0000, 12),
    (0xc0a8_0000, 16),
    (0x6440_0000, 10),
    (0xa9fe_0000, 16),
    (0x7f00_0000, 8),
];

fn within_private(n: &Cidr) -> bool {
    PRIVATE
        .iter()
        .filter_map(|(a, p)| Cidr::new(*a, *p))
        .any(|p| p.contains_net(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(nets: &[&str], anywhere: bool) -> AllowList {
        let nets: Vec<Cidr> = nets.iter().map(|s| Cidr::parse(s).unwrap()).collect();
        AllowList::new(&nets, anywhere)
    }

    #[test]
    fn only_listed_networks_are_allowed() {
        let a = list(&["10.0.0.0/8", "192.168.1.0/24", "203.0.113.7/32"], false);
        for ip in [
            [10, 0, 0, 0],
            [10, 255, 255, 255],
            [192, 168, 1, 0],
            [192, 168, 1, 255],
            [203, 0, 113, 7],
        ] {
            assert!(a.allows(ip), "{ip:?}");
        }
        for ip in [
            [9, 255, 255, 255],
            [11, 0, 0, 0],
            [192, 168, 0, 255],
            [192, 168, 2, 0],
            [203, 0, 113, 6],
            [203, 0, 113, 8],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            [8, 8, 8, 8],
        ] {
            assert!(!a.allows(ip), "{ip:?}");
        }
    }

    #[test]
    fn an_empty_list_allows_nothing_and_anywhere_allows_everything() {
        let none = list(&[], false);
        assert!(!none.allows([10, 0, 0, 1]) && !none.allows([0, 0, 0, 0]));
        let all = list(&[], true);
        for ip in [
            [0, 0, 0, 0],
            [10, 0, 0, 1],
            [255, 255, 255, 255],
            [8, 8, 8, 8],
        ] {
            assert!(all.allows(ip));
        }
        assert!(all.anywhere() && !none.anywhere());
    }

    #[test]
    fn edge_prefixes() {
        let a = list(&["10.0.0.2/31", "172.16.0.0/12"], false);
        assert!(a.allows([10, 0, 0, 2]) && a.allows([10, 0, 0, 3]));
        assert!(!a.allows([10, 0, 0, 1]) && !a.allows([10, 0, 0, 4]));
        assert!(a.allows([172, 16, 0, 0]) && a.allows([172, 31, 255, 255]));
        assert!(!a.allows([172, 15, 255, 255]) && !a.allows([172, 32, 0, 0]));
        let half = list(&["128.0.0.0/1"], false);
        assert!(half.allows([128, 0, 0, 0]) && half.allows([255, 255, 255, 254]));
        assert!(!half.allows([127, 255, 255, 255]) && !half.allows([0, 0, 0, 0]));
        // The widest accepted prefix, a /32 that is the whole space's last address.
        let b = list(&["255.255.255.255/32"], false);
        assert!(b.allows([255, 255, 255, 255]) && !b.allows([255, 255, 255, 254]));
    }

    #[test]
    fn it_agrees_with_a_bytewise_reference() {
        let mut x = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 8) as u32
        };
        for _ in 0..300 {
            let nets: Vec<Cidr> = (0..(next() % 5))
                .map(|_| {
                    let p = (next() % 33) as u8;
                    Cidr::new(next() & Cidr::mask(p), p).unwrap()
                })
                .collect();
            let a = AllowList::new(&nets, false);
            for _ in 0..200 {
                let ip = if next() % 2 == 0 {
                    next()
                } else {
                    nets.first()
                        .map_or(next(), |n| n.addr | (next() & !Cidr::mask(n.prefix)))
                };
                let want = nets.iter().any(|n| {
                    let (ipb, nb) = (ip.to_be_bytes(), n.addr.to_be_bytes());
                    let mut bits = n.prefix;
                    let mut ok = true;
                    for (x, y) in ipb.iter().zip(nb.iter()) {
                        let take = bits.min(8);
                        bits -= take;
                        let mask = if take == 0 { 0 } else { 0xffu8 << (8 - take) };
                        ok &= x & mask == y & mask;
                    }
                    ok
                });
                assert_eq!(a.allows(ip.to_be_bytes()), want, "{nets:?} {ip:#x}");
            }
        }
    }

    #[test]
    fn it_describes_itself() {
        assert_eq!(
            list(&["10.0.0.0/8", "192.168.0.0/16"], false).describe(),
            "10.0.0.0/8, 192.168.0.0/16"
        );
        assert_eq!(list(&[], true).describe(), "anywhere");
        assert_eq!(list(&[], false).describe(), "");
    }

    #[test]
    fn exposure_for_the_boot_warning() {
        let private = list(&["10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/10"], false);
        let mixed = list(&["10.0.0.0/8", "203.0.113.0/24"], false);
        let wide = list(&["0.0.0.0/1"], false);
        let any = list(&[], true);
        assert!(!private.reaches_public() && mixed.reaches_public() && wide.reaches_public());
        let (home, public) = ([192, 168, 1, 5], [203, 0, 113, 9]);
        for l in [&private, &mixed, &wide, &any] {
            assert_eq!(l.exposure(home), Exposure::Private);
            assert_eq!(l.exposure([0; 4]), Exposure::Private, "no address yet");
        }
        assert_eq!(
            private.exposure(public),
            Exposure::PublicAddressPrivateAllowList
        );
        assert_eq!(mixed.exposure(public), Exposure::Open);
        assert_eq!(wide.exposure(public), Exposure::Open);
        assert_eq!(any.exposure(public), Exposure::Open);
        // A network that straddles a private range is not private.
        assert!(list(&["10.0.0.0/7"], false).reaches_public());
        assert!(!list(&["172.20.0.0/16"], false).reaches_public());
    }
}
