//! IPv4 prefixes ("CIDRs") for the plaintext MQTT allow-list and the
//! per-network identities (P1, ADR-229).
//!
//! The text form is strict on purpose: `a.b.c.d/len`, four decimal octets
//! without leading zeros (a leading zero reads as octal in some tools), a
//! prefix length of 0 to 32, and **no host bits** below the prefix (so
//! `10.0.0.5/8` is a mistake, not `10.0.0.0/8`). The same parser runs in the
//! kernel at boot, in the packer, in the web builder and in the tests.

use core::fmt;

/// An IPv4 network. `addr` is in host byte order and has no bits set below
/// the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: u32,
    pub prefix: u8,
}

/// Why a CIDR was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrError {
    /// Not of the form `a.b.c.d/len`.
    Syntax,
    /// An octet above 255, empty, or written with a leading zero.
    Octet,
    /// A prefix length above 32, empty, or written with a leading zero.
    Prefix,
    /// Bits below the prefix are set, as in `10.0.0.5/8`.
    HostBits,
}

impl CidrError {
    pub const fn msg(self) -> &'static str {
        match self {
            Self::Syntax => "must look like a.b.c.d/len (for example 10.0.0.0/8)",
            Self::Octet => {
                "an address part must be a decimal number up to 255 without leading zeros"
            }
            Self::Prefix => "the prefix length must be a decimal number from 0 to 32",
            Self::HostBits => {
                "has bits set below the prefix length (write the network address, for example 10.0.0.0/8)"
            }
        }
    }
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg())
    }
}

impl Cidr {
    /// The netmask of a prefix length (0 to 32; larger counts as 32).
    pub const fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix as u32)
        }
    }

    /// The network `addr`/`prefix`; `None` if the prefix is above 32 or
    /// `addr` has host bits set.
    pub const fn new(addr: u32, prefix: u8) -> Option<Self> {
        if prefix > 32 || addr & !Self::mask(prefix) != 0 {
            None
        } else {
            Some(Self { addr, prefix })
        }
    }

    /// The network of `octets`/`prefix` (the blob's form).
    pub const fn from_octets(octets: [u8; 4], prefix: u8) -> Option<Self> {
        Self::new(u32::from_be_bytes(octets), prefix)
    }

    /// Whether `ip` (host byte order) is in the network.
    pub const fn contains(&self, ip: u32) -> bool {
        ip & Self::mask(self.prefix) == self.addr
    }

    /// Whether `ip` (network byte order, as on the wire) is in the network.
    pub const fn contains_octets(&self, ip: [u8; 4]) -> bool {
        self.contains(u32::from_be_bytes(ip))
    }

    /// Whether every address of `other` is in this network.
    pub const fn contains_net(&self, other: &Cidr) -> bool {
        other.prefix >= self.prefix && self.contains(other.addr)
    }

    pub const fn octets(&self) -> [u8; 4] {
        self.addr.to_be_bytes()
    }

    /// Parses `a.b.c.d/len` strictly (see the module documentation).
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let (a, p) = s.split_once('/').ok_or(CidrError::Syntax)?;
        let mut octets = [0u8; 4];
        let mut parts = a.split('.');
        for o in &mut octets {
            *o = decimal(parts.next().ok_or(CidrError::Syntax)?, 255).ok_or(CidrError::Octet)?;
        }
        if parts.next().is_some() {
            return Err(CidrError::Syntax);
        }
        let prefix = decimal(p, 32).ok_or(CidrError::Prefix)?;
        Self::from_octets(octets, prefix).ok_or(CidrError::HostBits)
    }
}

/// A decimal number of at most three digits, no sign, no leading zero (but
/// `0` itself), not above `max`.
fn decimal(s: &str, max: u8) -> Option<u8> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 3 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if b.len() > 1 && b.first() == Some(&b'0') {
        return None;
    }
    s.parse::<u8>().ok().filter(|v| *v <= max)
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}/{}", self.prefix)
    }
}

/// Whether an IPv4 address (as on the wire) is one a private network, the
/// loopback or the link uses: RFC 1918, RFC 6598 (carrier-grade NAT, used by
/// some clouds and VPNs), link-local, loopback. Used only for a warning, never
/// for access control.
pub const fn is_private(ip: [u8; 4]) -> bool {
    matches!(
        ip,
        [10, ..]
            | [172, 16..=31, ..]
            | [192, 168, ..]
            | [100, 64..=127, ..]
            | [169, 254, ..]
            | [127, ..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    fn ip(s: &str) -> u32 {
        let o: Vec<u8> = s.split('.').map(|x| x.parse().unwrap()).collect();
        u32::from_be_bytes([o[0], o[1], o[2], o[3]])
    }

    #[test]
    fn masks_at_the_edges() {
        assert_eq!(Cidr::mask(0), 0);
        assert_eq!(Cidr::mask(1), 0x8000_0000);
        assert_eq!(Cidr::mask(8), 0xff00_0000);
        assert_eq!(Cidr::mask(24), 0xffff_ff00);
        assert_eq!(Cidr::mask(31), 0xffff_fffe);
        assert_eq!(Cidr::mask(32), u32::MAX);
        assert_eq!(Cidr::mask(33), u32::MAX);
    }

    #[test]
    fn membership_at_the_boundaries() {
        let n = p("10.0.0.0/8");
        for yes in ["10.0.0.0", "10.0.0.1", "10.255.255.255", "10.1.2.3"] {
            assert!(n.contains(ip(yes)), "{yes}");
        }
        for no in [
            "9.255.255.255",
            "11.0.0.0",
            "0.0.0.0",
            "255.255.255.255",
            "110.0.0.1",
        ] {
            assert!(!n.contains(ip(no)), "{no}");
        }
        let n = p("192.168.1.128/25");
        assert!(n.contains(ip("192.168.1.128")) && n.contains(ip("192.168.1.255")));
        assert!(!n.contains(ip("192.168.1.127")) && !n.contains(ip("192.168.2.128")));
        let n = p("203.0.113.7/32");
        assert!(n.contains(ip("203.0.113.7")));
        assert!(!n.contains(ip("203.0.113.6")) && !n.contains(ip("203.0.113.8")));
        let n = p("172.16.0.0/12");
        assert!(n.contains(ip("172.16.0.0")) && n.contains(ip("172.31.255.255")));
        assert!(!n.contains(ip("172.15.255.255")) && !n.contains(ip("172.32.0.0")));
        let n = p("0.0.0.0/0");
        assert!(n.contains(0) && n.contains(u32::MAX) && n.contains(ip("8.8.8.8")));
        let n = p("128.0.0.0/1");
        assert!(n.contains(ip("128.0.0.0")) && n.contains(ip("255.255.255.255")));
        assert!(!n.contains(ip("127.255.255.255")));
        let n = p("255.255.255.255/32");
        assert!(n.contains(u32::MAX) && !n.contains(u32::MAX - 1));
        let n = p("10.0.0.2/31");
        assert!(n.contains(ip("10.0.0.2")) && n.contains(ip("10.0.0.3")));
        assert!(!n.contains(ip("10.0.0.1")) && !n.contains(ip("10.0.0.4")));
    }

    #[test]
    fn octets_are_in_wire_order() {
        let n = p("10.1.0.0/16");
        assert!(n.contains_octets([10, 1, 200, 3]));
        assert!(!n.contains_octets([10, 2, 0, 0]));
        assert_eq!(n.octets(), [10, 1, 0, 0]);
    }

    #[test]
    fn a_network_inside_another() {
        let big = p("10.0.0.0/8");
        assert!(big.contains_net(&p("10.4.0.0/16")));
        assert!(big.contains_net(&p("10.0.0.0/8")));
        assert!(big.contains_net(&p("10.9.9.9/32")));
        assert!(!big.contains_net(&p("0.0.0.0/0")));
        assert!(!big.contains_net(&p("10.0.0.0/7")));
        assert!(!big.contains_net(&p("11.0.0.0/16")));
        assert!(p("0.0.0.0/0").contains_net(&p("8.8.8.8/32")));
    }

    #[test]
    fn parsing_is_strict() {
        assert_eq!(
            p("10.0.0.0/8"),
            Cidr {
                addr: 0x0a00_0000,
                prefix: 8
            }
        );
        assert_eq!(p("0.0.0.0/0").prefix, 0);
        assert_eq!(p("255.255.255.255/32").addr, u32::MAX);
        assert_eq!(Cidr::parse("10.0.0.0"), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse("10.0.0/8"), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse("10.0.0.0.0/8"), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse(""), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse("/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse("10.0.0.0/"), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("10.0.0.0/33"), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("10.0.0.0/08"), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("10.0.0.0/-1"), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("10.0.0.0/+8"), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("256.0.0.0/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse("010.0.0.0/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse("10.0.0.x/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse("10..0.0/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse(" 10.0.0.0/8"), Err(CidrError::Octet));
        assert_eq!(Cidr::parse("10.0.0.0/8 "), Err(CidrError::Prefix));
        assert_eq!(Cidr::parse("10.0.0.5/8"), Err(CidrError::HostBits));
        assert_eq!(Cidr::parse("192.168.1.1/24"), Err(CidrError::HostBits));
        assert_eq!(Cidr::parse("1.2.3.4/0"), Err(CidrError::HostBits));
        assert!(Cidr::parse("1.2.3.4/32").is_ok());
        assert_eq!(Cidr::parse("1.2.3.5/31"), Err(CidrError::HostBits));
        assert!(Cidr::parse("1.2.3.4/31").is_ok());
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "10.0.0.0/8",
            "0.0.0.0/0",
            "192.168.1.0/24",
            "203.0.113.7/32",
            "172.16.0.0/12",
        ] {
            assert_eq!(p(s).to_string(), s);
        }
    }

    #[test]
    fn private_ranges_for_the_warning() {
        for s in [
            [10, 0, 0, 1],
            [10, 255, 255, 255],
            [172, 16, 0, 1],
            [172, 31, 255, 255],
            [192, 168, 0, 1],
            [100, 64, 0, 1],
            [100, 127, 255, 255],
            [169, 254, 1, 1],
            [127, 0, 0, 1],
        ] {
            assert!(is_private(s), "{s:?}");
        }
        for s in [
            [8, 8, 8, 8],
            [172, 15, 0, 1],
            [172, 32, 0, 1],
            [192, 169, 0, 1],
            [100, 63, 0, 1],
            [100, 128, 0, 1],
            [203, 0, 113, 5],
            [11, 0, 0, 1],
            [0, 0, 0, 0],
        ] {
            assert!(!is_private(s), "{s:?}");
        }
    }

    /// Every CIDR the parser accepts round-trips, and `contains` agrees with a
    /// bit-by-bit comparison (a reference without the mask arithmetic).
    #[test]
    fn contains_agrees_with_a_bitwise_reference() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 16) as u32
        };
        for _ in 0..20_000 {
            let prefix = (next() % 33) as u8;
            let net = Cidr::new(next() & Cidr::mask(prefix), prefix).unwrap();
            let probe = if next() % 2 == 0 {
                next()
            } else {
                net.addr | (next() & !Cidr::mask(prefix))
            };
            let reference = (0..prefix as u32).all(|bit| {
                let m = 1u32 << (31 - bit);
                (probe & m) == (net.addr & m)
            });
            assert_eq!(net.contains(probe), reference, "{net} {probe:#x}");
            assert_eq!(Cidr::parse(&net.to_string()), Ok(net));
        }
    }
}
