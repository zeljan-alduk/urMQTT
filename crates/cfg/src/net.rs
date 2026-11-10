//! IPv4 prefixes ("CIDRs") for the plaintext MQTT allow-list and the
//! per-network identities (P1, ADR-229), and IPv6 ones for the allow-lists
//! and the static IPv6 address (NEXT-1, ADR-334).
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
    /// IPv6: not of the form `addr/len` (NEXT-1).
    Syntax6,
    /// IPv6: the address part is not an IPv6 address.
    Address6,
    /// IPv6: a prefix length above 128, empty, or with a leading zero.
    Prefix6,
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
                "has bits set below the prefix length (write the network address, for example 10.0.0.0/8 or 2001:db8::/32)"
            }
            Self::Syntax6 => "must look like 2001:db8::/32 (an IPv6 network and its prefix length)",
            Self::Address6 => {
                "is not an IPv6 address (eight hexadecimal groups, or fewer with one ::; no zone, no dotted part)"
            }
            Self::Prefix6 => "the prefix length must be a decimal number from 0 to 128",
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

/// Parses an IPv6 address in the RFC 4291 §2.2 text form: eight groups of
/// one to four hexadecimal digits, or fewer with one `::`. No zone index
/// (`%eth0`), no embedded dotted IPv4 part, no surrounding brackets: what a
/// configuration needs, and nothing that reads two ways.
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    if s.is_empty() || s.len() > 39 {
        return None;
    }
    let group = |g: &str| -> Option<u16> {
        if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(g, 16).ok()
    };
    let mut out = [0u16; 8];
    match s.split_once("::") {
        None => {
            let mut n = 0;
            for g in s.split(':') {
                *out.get_mut(n)? = group(g)?;
                n += 1;
            }
            if n != 8 {
                return None;
            }
        }
        Some((head, tail)) => {
            if tail.contains("::") {
                return None;
            }
            let parts = |x: &str| -> Option<([u16; 8], usize)> {
                let mut v = [0u16; 8];
                let mut n = 0;
                if !x.is_empty() {
                    for g in x.split(':') {
                        *v.get_mut(n)? = group(g)?;
                        n += 1;
                    }
                }
                Some((v, n))
            };
            let (h, hn) = parts(head)?;
            let (t, tn) = parts(tail)?;
            // `::` stands for at least one group.
            if hn + tn > 7 {
                return None;
            }
            for (d, v) in out.iter_mut().zip(h.iter().take(hn)) {
                *d = *v;
            }
            for (d, v) in out.iter_mut().skip(8 - tn).zip(t.iter().take(tn)) {
                *d = *v;
            }
        }
    }
    let mut a = [0u8; 16];
    for (d, g) in a.as_chunks_mut::<2>().0.iter_mut().zip(out) {
        *d = g.to_be_bytes();
    }
    Some(a)
}

/// Writes an IPv6 address in the RFC 5952 form (lower case, no leading
/// zeros, the longest run of two or more zero groups as `::`).
pub fn write_ipv6(f: &mut impl fmt::Write, a: &[u8; 16]) -> fmt::Result {
    let mut g = [0u16; 8];
    for (d, p) in g.iter_mut().zip(a.as_chunks::<2>().0) {
        *d = u16::from_be_bytes(*p);
    }
    let (mut best, mut run) = (None::<(usize, usize)>, None::<usize>);
    for (i, &x) in g.iter().enumerate() {
        if x == 0 {
            let start = *run.get_or_insert(i);
            let len = i + 1 - start;
            if len >= 2 && best.is_none_or(|(_, l)| len > l) {
                best = Some((start, len));
            }
        } else {
            run = None;
        }
    }
    let mut first = true;
    for (i, x) in g.iter().enumerate() {
        match best {
            Some((s, _)) if i == s => {
                f.write_str("::")?;
                first = true;
                continue;
            }
            Some((s, l)) if i > s && i < s + l => continue,
            _ => {}
        }
        if !first {
            f.write_str(":")?;
        }
        first = false;
        write!(f, "{x:x}")?;
    }
    Ok(())
}

/// Whether `a` and `b` share their first `len` bits.
pub fn same_prefix6(a: &[u8; 16], b: &[u8; 16], len: u8) -> bool {
    let len = u32::from(len.min(128));
    let (x, y) = (u128::from_be_bytes(*a), u128::from_be_bytes(*b));
    len == 0 || (x ^ y) >> (128 - len) == 0
}

/// Whether `a` can be a unicast address of a host: not `::`, `::1`,
/// multicast or IPv4-mapped.
pub fn is_unicast6(a: &[u8; 16]) -> bool {
    let v = u128::from_be_bytes(*a);
    v > 1 && a[0] != 0xff && (v >> 32) != 0xffff
}

/// `fe80::/10`.
pub const fn is_link_local6(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

/// An IPv6 network: no bits set below the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr6 {
    pub addr: [u8; 16],
    pub prefix: u8,
}

impl Cidr6 {
    pub fn new(addr: [u8; 16], prefix: u8) -> Option<Self> {
        let host_bits_clear = prefix == 0 && addr == [0; 16]
            || prefix >= 128
            || prefix > 0 && u128::from_be_bytes(addr) << prefix == 0;
        (prefix <= 128 && host_bits_clear).then_some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: &[u8; 16]) -> bool {
        same_prefix6(&self.addr, ip, self.prefix)
    }

    pub fn contains_net(&self, other: &Cidr6) -> bool {
        other.prefix >= self.prefix && self.contains(&other.addr)
    }

    /// Parses `addr/len` (len 0 to 128 in decimal, no leading zero, no host
    /// bits).
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let (a, p) = s.split_once('/').ok_or(CidrError::Syntax6)?;
        let addr = parse_ipv6(a).ok_or(CidrError::Address6)?;
        let prefix = prefix_len(p, 128).ok_or(CidrError::Prefix6)?;
        Self::new(addr, prefix).ok_or(CidrError::HostBits)
    }
}

/// A decimal prefix length up to `max` (three digits at most, no leading zero).
fn prefix_len(s: &str, max: u8) -> Option<u8> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 3 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if b.len() > 1 && b.first() == Some(&b'0') {
        return None;
    }
    s.parse::<u8>().ok().filter(|v| *v <= max)
}

impl fmt::Display for Cidr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_ipv6(f, &self.addr)?;
        write!(f, "/{}", self.prefix)
    }
}

/// An allow-list entry of either family (NEXT-1, ADR-334).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Net {
    V4(Cidr),
    V6(Cidr6),
}

impl Net {
    /// IPv6 if the text has a colon, IPv4 otherwise.
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        if s.contains(':') {
            Cidr6::parse(s).map(Self::V6)
        } else {
            Cidr::parse(s).map(Self::V4)
        }
    }

    pub const fn prefix(&self) -> u8 {
        match self {
            Self::V4(c) => c.prefix,
            Self::V6(c) => c.prefix,
        }
    }

    pub const fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    /// Whether the IPv4 address `ip` (wire order) is in the network.
    pub const fn contains_v4(&self, ip: [u8; 4]) -> bool {
        match self {
            Self::V4(c) => c.contains_octets(ip),
            Self::V6(_) => false,
        }
    }

    /// Whether the IPv6 address `ip` is in the network.
    pub fn contains_v6(&self, ip: &[u8; 16]) -> bool {
        match self {
            Self::V4(_) => false,
            Self::V6(c) => c.contains(ip),
        }
    }

    pub fn contains_net(&self, other: &Net) -> bool {
        match (self, other) {
            (Self::V4(a), Self::V4(b)) => a.contains_net(b),
            (Self::V6(a), Self::V6(b)) => a.contains_net(b),
            _ => false,
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(c) => c.fmt(f),
            Self::V6(c) => c.fmt(f),
        }
    }
}

/// `network.ipv6_address`: an IPv6 address of this host with the length of
/// its on-link prefix, `2001:db8:1::10/64` (host bits are the point here).
/// A global unicast address: not link-local (the host makes that one
/// itself), not multicast, `::`, `::1` or IPv4-mapped.
pub fn parse_ipv6_address(s: &str) -> Result<([u8; 16], u8), &'static str> {
    let (a, p) = s
        .split_once('/')
        .ok_or("must look like 2001:db8::10/64 (an IPv6 address and its prefix length)")?;
    let addr = parse_ipv6(a)
        .ok_or("is not an IPv6 address (eight hexadecimal groups, or fewer with one ::)")?;
    let prefix = prefix_len(p, 128)
        .filter(|p| *p >= 1)
        .ok_or("the prefix length must be a decimal number from 1 to 128")?;
    if !is_unicast6(&addr) || is_link_local6(&addr) {
        return Err(
            "must be a global unicast address: not ::, ::1, multicast, IPv4-mapped or link-local (fe80::/10, made from the MAC by itself)",
        );
    }
    Ok((addr, prefix))
}

/// `network.ipv6_gateway`: the default router, usually link-local
/// (`fe80::1`) on a VPS, or an address within `network.ipv6_address`'s
/// prefix (checked by the caller with [`same_prefix6`]).
pub fn parse_ipv6_gateway(s: &str) -> Result<[u8; 16], &'static str> {
    let a = parse_ipv6(s)
        .ok_or("is not an IPv6 address (eight hexadecimal groups, or fewer with one ::)")?;
    if !is_unicast6(&a) {
        return Err("must be a unicast address: not ::, ::1, multicast or IPv4-mapped");
    }
    Ok(a)
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

    #[test]
    fn ipv6_text_is_parsed_strictly_and_written_canonically() {
        let ok = [
            ("::", "::"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("fe80::5054:ff:fe12:3456", "fe80::5054:ff:fe12:3456"),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("1::", "1::"),
            ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
            ("2001:0:0:1::1", "2001:0:0:1::1"),
            ("0:0:0:0:0:0:0:0", "::"),
        ];
        for (inp, out) in ok {
            let a = parse_ipv6(inp).unwrap_or_else(|| panic!("{inp}"));
            let mut s = String::new();
            write_ipv6(&mut s, &a).unwrap();
            assert_eq!(s, out, "{inp}");
            assert_eq!(parse_ipv6(&s), Some(a));
        }
        for bad in [
            "",
            ":",
            ":::",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "12345::",
            "g::1",
            "::ffff:1.2.3.4",
            "fe80::1%eth0",
            "[::1]",
            " ::1",
            "1:2:3:4:5:6:7::8",
            "1:2:3:4::5:6:7:8",
            ":1::",
            "1:::2",
        ] {
            assert_eq!(parse_ipv6(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ipv6_networks() {
        let n = Cidr6::parse("2001:db8::/32").unwrap();
        assert!(n.contains(&parse_ipv6("2001:db8:ffff::1").unwrap()));
        assert!(!n.contains(&parse_ipv6("2001:db9::1").unwrap()));
        assert_eq!(n.to_string(), "2001:db8::/32");
        assert_eq!(Cidr6::parse("2001:db8::1/32"), Err(CidrError::HostBits));
        assert_eq!(Cidr6::parse("2001:db8::/129"), Err(CidrError::Prefix6));
        assert_eq!(Cidr6::parse("2001:db8::/032"), Err(CidrError::Prefix6));
        assert_eq!(Cidr6::parse("2001:db8::"), Err(CidrError::Syntax6));
        assert_eq!(Cidr6::parse("2001:dg8::/32"), Err(CidrError::Address6));
        assert!(Cidr6::parse("::/0").is_ok());
        assert!(
            Cidr6::parse("2001:db8::1/128")
                .unwrap()
                .contains(&parse_ipv6("2001:db8::1").unwrap())
        );
        let n8 = Cidr6::parse("2001:db8:1:fe00::/56").unwrap();
        assert!(n8.contains(&parse_ipv6("2001:db8:1:fe00::1").unwrap()));
        assert!(n8.contains(&parse_ipv6("2001:db8:1:feff::1").unwrap()));
        assert!(!n8.contains(&parse_ipv6("2001:db8:1:ff00::").unwrap()));
        assert!(!n8.contains(&parse_ipv6("2001:db8:1:fd00::").unwrap()));
        assert_eq!(
            Cidr6::parse("2001:db8:1:fe80::/56"),
            Err(CidrError::HostBits)
        );
        // Net picks the family by the colon and never mixes them.
        let v4 = Net::parse("10.0.0.0/8").unwrap();
        let v6 = Net::parse("2001:db8::/32").unwrap();
        assert!(v4.contains_v4([10, 1, 2, 3]) && !v6.contains_v4([10, 1, 2, 3]));
        let a = parse_ipv6("2001:db8::7").unwrap();
        assert!(v6.contains_v6(&a) && !v4.contains_v6(&a));
        assert!(!v4.contains_net(&v6) && v6.contains_net(&Net::parse("2001:db8:1::/48").unwrap()));
        assert_eq!((v4.prefix(), v6.prefix(), v6.is_v6()), (8, 32, true));
        assert_eq!(v6.to_string(), "2001:db8::/32");
    }

    #[test]
    fn the_static_ipv6_address_and_gateway() {
        let (a, p) = parse_ipv6_address("2001:db8:1::10/64").unwrap();
        assert_eq!((a, p), (parse_ipv6("2001:db8:1::10").unwrap(), 64));
        for bad in [
            "2001:db8::10",
            "2001:db8::10/0",
            "2001:db8::10/129",
            "fe80::1/64",
            "ff02::1/64",
            "::/64",
            "::1/128",
            "::ffff:a00:1/96",
            "x/64",
        ] {
            assert!(parse_ipv6_address(bad).is_err(), "{bad}");
        }
        assert!(parse_ipv6_gateway("fe80::1").is_ok());
        assert!(parse_ipv6_gateway("2001:db8:1::1").is_ok());
        for bad in ["::", "::1", "ff02::2", "fe80::1/64", "10.0.0.1"] {
            assert!(parse_ipv6_gateway(bad).is_err(), "{bad}");
        }
        assert!(same_prefix6(&a, &parse_ipv6("2001:db8:1::1").unwrap(), 64));
        assert!(!same_prefix6(&a, &parse_ipv6("2001:db8:2::1").unwrap(), 64));
        assert!(same_prefix6(&a, &[0; 16], 0));
    }

    /// Random networks: `contains` agrees with a bit-by-bit reference and the
    /// text round-trips.
    #[test]
    fn ipv6_contains_agrees_with_a_bitwise_reference() {
        let mut seed = 0x0bad_cafe_1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..10_000 {
            let prefix = (next() % 129) as u8;
            let raw = (u128::from(next()) << 64) | u128::from(next());
            let net = if prefix == 0 {
                0
            } else {
                raw & (u128::MAX << (128 - u32::from(prefix)))
            };
            let c = Cidr6::new(net.to_be_bytes(), prefix).unwrap();
            let probe = if next() % 2 == 0 {
                (u128::from(next()) << 64) | u128::from(next())
            } else {
                net | (raw
                    & !(if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - u32::from(prefix))
                    }))
            };
            let reference = (0..u32::from(prefix)).all(|bit| {
                let m = 1u128 << (127 - bit);
                (probe & m) == (net & m)
            });
            assert_eq!(c.contains(&probe.to_be_bytes()), reference, "{c}");
            assert_eq!(Cidr6::parse(&c.to_string()), Ok(c));
        }
    }
}
