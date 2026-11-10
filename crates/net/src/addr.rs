//! IP addresses of both families in one type (NEXT-1, ADR-330).
//!
//! [`Addr`] holds 16 bytes. An IPv4 address is stored IPv4-mapped
//! (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2); an IPv6 address as itself. The two
//! never overlap because the IPv6 layer drops every packet whose source or
//! destination is IPv4-mapped ([`crate::ipv6::parse_ipv6`]): such a packet is
//! not valid on the wire, and accepting one would let an IPv6 peer pose as an
//! IPv4 address in an allow-list or a per-address limit.
//!
//! [`V6Locals`] is the source address rule that the interface (which writes
//! the IPv6 header) and the TCP stack (which writes the checksum over the
//! pseudo-header) share: a link-local peer is answered from the link-local
//! address, every other peer from the one global address.

use core::fmt;

/// An IPv4 or IPv6 address (IPv4 stored IPv4-mapped).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Addr([u8; 16]);

/// Whether `a` lies in `::ffff:0:0/96` (an IPv4-mapped address).
pub const fn is_mapped(a: &[u8; 16]) -> bool {
    matches!(a, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ..])
}

impl Addr {
    /// `0.0.0.0` (IPv4-mapped): the IPv4 stack's "no address".
    pub const UNSPECIFIED_V4: Self = Self::v4([0; 4]);

    /// An IPv4 address.
    pub const fn v4(a: [u8; 4]) -> Self {
        let [w, x, y, z] = a;
        Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, w, x, y, z])
    }

    /// An IPv6 address as it is on the wire. An IPv4-mapped one becomes the
    /// IPv4 address it maps (the IPv6 layer never hands one out).
    pub const fn v6(a: [u8; 16]) -> Self {
        Self(a)
    }

    /// The 16 bytes (IPv4 mapped).
    pub const fn octets(self) -> [u8; 16] {
        self.0
    }

    pub const fn is_v4(self) -> bool {
        is_mapped(&self.0)
    }

    /// The IPv4 address, if this is one.
    pub const fn as_v4(self) -> Option<[u8; 4]> {
        if self.is_v4() {
            let [.., w, x, y, z] = self.0;
            Some([w, x, y, z])
        } else {
            None
        }
    }

    /// The IPv6 address, if this is not an IPv4 one.
    pub const fn as_v6(self) -> Option<[u8; 16]> {
        if self.is_v4() { None } else { Some(self.0) }
    }

    /// The address as it is on the wire: 4 bytes for IPv4, 16 for IPv6.
    pub fn wire(&self) -> &[u8] {
        if self.is_v4() {
            self.0.get(12..).unwrap_or(&self.0)
        } else {
            &self.0
        }
    }

    /// `0.0.0.0` or `::`.
    pub fn is_unspecified(self) -> bool {
        self == Self::UNSPECIFIED_V4 || self.0 == [0; 16]
    }

    /// `fe80::/10`.
    pub const fn is_link_local(self) -> bool {
        is_link_local(&self.0)
    }

    /// `224.0.0.0/4` or `ff00::/8`.
    pub const fn is_multicast(self) -> bool {
        match self.as_v4() {
            Some([a, ..]) => a >> 4 == 14,
            None => self.0[0] == 0xff,
        }
    }
}

/// `fe80::/10`.
pub const fn is_link_local(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

impl From<[u8; 4]> for Addr {
    fn from(a: [u8; 4]) -> Self {
        Self::v4(a)
    }
}

/// Writes an IPv6 address in the RFC 5952 form: lower-case hexadecimal
/// without leading zeros, the longest run of two or more zero groups (the
/// first of equal ones) as `::`.
pub fn write_v6(f: &mut impl fmt::Write, a: &[u8; 16]) -> fmt::Result {
    let (pairs, _) = a.as_chunks::<2>();
    let mut g = [0u16; 8];
    for (d, p) in g.iter_mut().zip(pairs) {
        *d = u16::from_be_bytes(*p);
    }
    // The longest run of zero groups (at least two): (start, length).
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

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_v4() {
            Some([a, b, c, d]) => write!(f, "{a}.{b}.{c}.{d}"),
            None => write_v6(f, &self.0),
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The IPv6 addresses a host answers from (ADR-331): the link-local one and
/// at most one global one, each only once Duplicate Address Detection
/// accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct V6Locals {
    pub link_local: Option<[u8; 16]>,
    pub global: Option<[u8; 16]>,
}

impl V6Locals {
    pub const NONE: Self = Self {
        link_local: None,
        global: None,
    };

    /// The source address for a packet to `remote`: the link-local one for a
    /// link-local (or link-scope multicast) peer, the global one otherwise.
    pub fn for_peer(&self, remote: &[u8; 16]) -> Option<[u8; 16]> {
        let link_scope = is_link_local(remote) || (remote[0] == 0xff && remote[1] & 0x0f == 2);
        if link_scope {
            self.link_local
        } else {
            self.global
        }
    }

    /// Whether `a` is one of these addresses.
    pub fn holds(&self, a: &[u8; 16]) -> bool {
        self.link_local.as_ref() == Some(a) || self.global.as_ref() == Some(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn v6(s: [u16; 8]) -> [u8; 16] {
        let mut a = [0u8; 16];
        for (i, g) in s.iter().enumerate() {
            a[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
        }
        a
    }

    #[test]
    fn families_do_not_overlap_and_round_trip() {
        let a = Addr::v4([10, 0, 2, 15]);
        assert!(a.is_v4());
        assert_eq!(a.as_v4(), Some([10, 0, 2, 15]));
        assert_eq!(a.as_v6(), None);
        let b = Addr::v6(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
        assert!(!b.is_v4());
        assert_eq!(b.as_v4(), None);
        assert_ne!(a, b);
        assert!(Addr::UNSPECIFIED_V4.is_unspecified());
        assert!(Addr::v6([0; 16]).is_unspecified());
        assert!(!a.is_unspecified());
        assert!(Addr::v4([239, 1, 1, 1]).is_multicast());
        assert!(Addr::v6(v6([0xff02, 0, 0, 0, 0, 0, 0, 1])).is_multicast());
        assert!(!b.is_multicast());
        assert!(Addr::v6(v6([0xfe80, 0, 0, 0, 0, 0, 0, 2])).is_link_local());
        assert!(Addr::v6(v6([0xfebf, 0, 0, 0, 0, 0, 0, 2])).is_link_local());
        assert!(!Addr::v6(v6([0xfec0, 0, 0, 0, 0, 0, 0, 2])).is_link_local());
    }

    #[test]
    fn rfc_5952_text() {
        let cases: [([u16; 8], &str); 9] = [
            ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], "2001:db8::1"),
            ([0, 0, 0, 0, 0, 0, 0, 0], "::"),
            ([0, 0, 0, 0, 0, 0, 0, 1], "::1"),
            (
                [0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456],
                "fe80::5054:ff:fe12:3456",
            ),
            // One zero group is not compressed.
            ([0x2001, 0xdb8, 0, 1, 1, 1, 1, 1], "2001:db8:0:1:1:1:1:1"),
            // The longest run wins; of equal ones the first.
            ([0x2001, 0, 0, 1, 0, 0, 0, 1], "2001:0:0:1::1"),
            ([0x2001, 0xdb8, 0, 0, 1, 0, 0, 1], "2001:db8::1:0:0:1"),
            ([1, 0, 0, 0, 0, 0, 0, 0], "1::"),
            ([0xABCD, 0xEF01, 2, 3, 4, 5, 6, 7], "abcd:ef01:2:3:4:5:6:7"),
        ];
        for (g, want) in cases {
            assert_eq!(format!("{}", Addr::v6(v6(g))), want);
        }
        assert_eq!(format!("{}", Addr::v4([192, 0, 2, 1])), "192.0.2.1");
    }

    #[test]
    fn the_source_follows_the_peers_scope() {
        let ll = v6([0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let g = v6([0x2001, 0xdb8, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456]);
        let l = V6Locals {
            link_local: Some(ll),
            global: Some(g),
        };
        assert_eq!(l.for_peer(&v6([0xfe80, 0, 0, 0, 0, 0, 0, 2])), Some(ll));
        assert_eq!(l.for_peer(&v6([0xff02, 0, 0, 0, 0, 0, 0, 1])), Some(ll));
        assert_eq!(l.for_peer(&v6([0x2001, 0xdb8, 1, 0, 0, 0, 0, 2])), Some(g));
        assert!(l.holds(&ll) && l.holds(&g) && !l.holds(&[0; 16]));
        let only_ll = V6Locals {
            link_local: Some(ll),
            global: None,
        };
        assert_eq!(
            only_ll.for_peer(&v6([0x2001, 0xdb8, 1, 0, 0, 0, 0, 2])),
            None
        );
    }
}
