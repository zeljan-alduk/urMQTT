//! IPv6 (RFC 8200) and ICMPv6 with Neighbour Discovery (RFC 4443, RFC 4861):
//! parsing with strict validation, and emission (NEXT-1, ADR-330).
//!
//! Policy, as for IPv4 (PROMPT §5.2): what the broker does not need is
//! dropped and counted, never half-handled.
//!
//! - The header must say version 6, the payload length must fit the frame
//!   (Ethernet padding beyond it is cut off), the source must not be
//!   multicast, the loopback or IPv4-mapped, and the destination must not be
//!   the loopback or IPv4-mapped (an IPv4-mapped address would alias an IPv4
//!   one in [`crate::addr::Addr`]).
//! - Extension headers are walked with hard bounds ([`MAX_EXT`] headers,
//!   [`MAX_EXT_BYTES`] bytes): Hop-by-Hop and Destination Options are skipped
//!   when every option in them may be skipped (Pad1, PadN, Router Alert, or
//!   an unknown one whose action bits are 00); a Routing header is skipped
//!   only with Segments Left 0 (this host is no router). A Fragment header
//!   drops the packet ([`V6Error::Fragment`], counted): no reassembly (a TCP
//!   peer follows the MSS, and ICMPv6 here is small). ESP, AH, No Next Header
//!   and anything unknown drop it too.
//! - ICMPv6 needs a correct checksum over the pseudo-header. Neighbour
//!   Discovery messages need hop limit 255 (so they come from the link), code
//!   0, their minimum length, and options that each have a non-zero length
//!   within the message (RFC 4861 §6.1, §7.1); anything else drops the whole
//!   message.

use alloc::vec::Vec;

use crate::addr::{is_link_local, is_mapped};
use crate::ipv4::{Mac, csum};

pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const IPV6_HDR: usize = 40;
pub const NH_HOP: u8 = 0;
pub const NH_TCP: u8 = 6;
pub const NH_UDP: u8 = 17;
pub const NH_ROUTING: u8 = 43;
pub const NH_FRAGMENT: u8 = 44;
pub const NH_ICMPV6: u8 = 58;
pub const NH_DSTOPTS: u8 = 60;
/// The smallest MTU every IPv6 link has (RFC 8200 §5).
pub const MIN_MTU: u16 = 1280;
/// Extension headers walked at most, and their bytes at most.
pub const MAX_EXT: usize = 4;
pub const MAX_EXT_BYTES: usize = 256;

pub type Ip6 = [u8; 16];

/// `::`.
pub const UNSPECIFIED: Ip6 = [0; 16];
/// `ff02::1`, all nodes on the link.
pub const ALL_NODES: Ip6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// `ff02::2`, all routers on the link.
pub const ALL_ROUTERS: Ip6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// `ff02::16`, MLDv2-capable routers.
pub const MLDV2_ROUTERS: Ip6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16];

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn arr<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at + N)?.try_into().ok()
}

/// The solicited-node multicast address of `a` (`ff02::1:ffXX:XXXX`).
pub fn solicited_node(a: &Ip6) -> Ip6 {
    let mut m = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
    m[13..].copy_from_slice(&a[13..]);
    m
}

/// The Ethernet address of an IPv6 multicast group (RFC 2464 §7).
pub fn multicast_mac(a: &Ip6) -> Mac {
    [0x33, 0x33, a[12], a[13], a[14], a[15]]
}

/// The modified EUI-64 interface identifier of a MAC (RFC 4291 App. A).
pub fn eui64(mac: Mac) -> [u8; 8] {
    [
        mac[0] ^ 2,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// `prefix`'s first 64 bits followed by `iid`.
pub fn with_iid(prefix: &Ip6, iid: [u8; 8]) -> Ip6 {
    let mut a = *prefix;
    a[8..].copy_from_slice(&iid);
    a
}

/// `fe80::` + the EUI-64 of `mac`.
pub fn link_local_of(mac: Mac) -> Ip6 {
    let mut p = [0u8; 16];
    p[0] = 0xfe;
    p[1] = 0x80;
    with_iid(&p, eui64(mac))
}

/// Whether `a` and `b` share their first `len` bits.
pub fn same_prefix(a: &Ip6, b: &Ip6, len: u8) -> bool {
    let len = usize::from(len.min(128));
    let (bytes, bits) = (len / 8, len % 8);
    if a.get(..bytes) != b.get(..bytes) {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    match (a.get(bytes), b.get(bytes)) {
        (Some(x), Some(y)) => x & mask == y & mask,
        _ => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6<'a> {
    pub src: Ip6,
    pub dst: Ip6,
    /// The upper-layer protocol after the extension headers.
    pub next: u8,
    pub hop_limit: u8,
    /// Extension headers skipped.
    pub ext: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Error {
    Truncated,
    NotV6,
    BadLength,
    /// Multicast, loopback or unspecified-where-forbidden source; loopback
    /// destination.
    BadAddress,
    /// An IPv4-mapped source or destination (ADR-330).
    Mapped,
    /// A Fragment header: no reassembly (counted).
    Fragment,
    /// Too many or too long extension headers, a Routing header with segments
    /// left, an option that must not be skipped, ESP/AH, or No Next Header.
    ExtHeader,
}

/// Walks the options of a Hop-by-Hop or Destination Options header: whether
/// every one may be skipped.
fn options_skippable(opts: &[u8]) -> bool {
    let mut i = 0;
    let mut n = 0;
    while i < opts.len() {
        n += 1;
        if n > 32 {
            return false;
        }
        let Some(&t) = opts.get(i) else { return false };
        if t == 0 {
            // Pad1.
            i += 1;
            continue;
        }
        let Some(&len) = opts.get(i + 1) else {
            return false;
        };
        let end = i + 2 + usize::from(len);
        if end > opts.len() {
            return false;
        }
        // PadN (1) and Router Alert (5) are known; an unknown option may be
        // skipped only if its two high bits are 00 (RFC 8200 §4.2).
        if t != 1 && t != 5 && t >> 6 != 0 {
            return false;
        }
        i = end;
    }
    true
}

/// Parses an IPv6 packet (the Ethernet payload) under the policy above.
pub fn parse_ipv6(p: &[u8]) -> Result<Ipv6<'_>, V6Error> {
    let v = *p.first().ok_or(V6Error::Truncated)?;
    if v >> 4 != 6 {
        return Err(V6Error::NotV6);
    }
    if p.len() < IPV6_HDR {
        return Err(V6Error::Truncated);
    }
    let plen = usize::from(be16(p, 4).ok_or(V6Error::Truncated)?);
    if IPV6_HDR + plen > p.len() {
        return Err(V6Error::BadLength);
    }
    let src: Ip6 = arr(p, 8).ok_or(V6Error::Truncated)?;
    let dst: Ip6 = arr(p, 24).ok_or(V6Error::Truncated)?;
    if is_mapped(&src) || is_mapped(&dst) {
        return Err(V6Error::Mapped);
    }
    let mut loopback = [0u8; 16];
    loopback[15] = 1;
    // `::/64` holds no unicast source but `::` (DAD) on a link: refusing the
    // rest keeps every source's /64 key non-zero (ADR-332).
    let zero_prefix = src.get(..8) == Some(&[0u8; 8][..]) && src != UNSPECIFIED;
    if src[0] == 0xff || zero_prefix || dst == loopback || dst == UNSPECIFIED {
        return Err(V6Error::BadAddress);
    }
    let mut next = *p.get(6).ok_or(V6Error::Truncated)?;
    let hop_limit = *p.get(7).ok_or(V6Error::Truncated)?;
    // Ethernet padding beyond the payload length is cut off.
    let mut rest = p.get(IPV6_HDR..IPV6_HDR + plen).ok_or(V6Error::Truncated)?;
    let (mut ext, mut ext_bytes) = (0u8, 0usize);
    loop {
        match next {
            NH_HOP | NH_DSTOPTS | NH_ROUTING => {
                // Hop-by-Hop must be the first (RFC 8200 §4.3).
                if next == NH_HOP && ext != 0 {
                    return Err(V6Error::ExtHeader);
                }
                let len = 8 * (usize::from(*rest.get(1).ok_or(V6Error::Truncated)?) + 1);
                ext += 1;
                ext_bytes += len;
                if usize::from(ext) > MAX_EXT || ext_bytes > MAX_EXT_BYTES {
                    return Err(V6Error::ExtHeader);
                }
                let h = rest.get(..len).ok_or(V6Error::Truncated)?;
                let ok = if next == NH_ROUTING {
                    // Segments Left 0: ignore the header (RFC 8200 §4.4).
                    h.get(3) == Some(&0)
                } else {
                    options_skippable(h.get(2..).unwrap_or(&[]))
                };
                if !ok {
                    return Err(V6Error::ExtHeader);
                }
                next = *h.first().ok_or(V6Error::Truncated)?;
                rest = rest.get(len..).ok_or(V6Error::Truncated)?;
            }
            NH_FRAGMENT => return Err(V6Error::Fragment),
            NH_TCP | NH_UDP | NH_ICMPV6 => break,
            _ => return Err(V6Error::ExtHeader),
        }
    }
    if src == UNSPECIFIED && next != NH_ICMPV6 {
        // Only Neighbour Discovery may come from `::` (DAD).
        return Err(V6Error::BadAddress);
    }
    Ok(Ipv6 {
        src,
        dst,
        next,
        hop_limit,
        ext,
        payload: rest,
    })
}

/// The pseudo-header sum (RFC 8200 §8.1) for an upper-layer packet of `len`
/// bytes.
pub fn pseudo6(src: &Ip6, dst: &Ip6, next: u8, len: usize) -> u32 {
    let mut acc = 0u32;
    for p in src.as_chunks::<2>().0.iter().chain(dst.as_chunks::<2>().0) {
        acc += u32::from(u16::from_be_bytes(*p));
    }
    let len = len as u32;
    acc + (len >> 16) + (len & 0xffff) + u32::from(next)
}

/// Appends an IPv6 header for `len` payload bytes.
pub fn push_ipv6(buf: &mut Vec<u8>, src: &Ip6, dst: &Ip6, next: u8, hop_limit: u8, len: usize) {
    buf.extend_from_slice(&[0x60, 0, 0, 0]);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.push(next);
    buf.push(hop_limit);
    buf.extend_from_slice(src);
    buf.extend_from_slice(dst);
}

/// Sets the IPv6 payload length of the header at `at` to what follows it.
pub fn fix_len(buf: &mut [u8], at: usize) {
    let len = buf.len().saturating_sub(at + IPV6_HDR) as u16;
    if let Some(l) = buf.get_mut(at + 4..at + 6) {
        l.copy_from_slice(&len.to_be_bytes());
    }
}

// ICMPv6 types.
pub const ICMP6_ECHO_REQUEST: u8 = 128;
pub const ICMP6_ECHO_REPLY: u8 = 129;
pub const ICMP6_MLD_QUERY: u8 = 130;
pub const ICMP6_RS: u8 = 133;
pub const ICMP6_RA: u8 = 134;
pub const ICMP6_NS: u8 = 135;
pub const ICMP6_NA: u8 = 136;
pub const ICMP6_REDIRECT: u8 = 137;
pub const ICMP6_MLDV2_REPORT: u8 = 143;

// Neighbour Discovery options.
const OPT_SLLA: u8 = 1;
const OPT_TLLA: u8 = 2;
const OPT_PREFIX: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;

/// Prefix Information options taken from one Router Advertisement.
pub const MAX_PREFIXES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefixInfo {
    pub prefix: Ip6,
    pub len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    /// Seconds; `u32::MAX` is infinity.
    pub valid_s: u32,
    pub preferred_s: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouterAdvert {
    pub cur_hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    pub router_lifetime_s: u16,
    pub reachable_ms: u32,
    pub retrans_ms: u32,
    pub slla: Option<Mac>,
    pub mtu: Option<u32>,
    pub prefixes: [PrefixInfo; MAX_PREFIXES],
    pub n_prefixes: u8,
    /// Prefix options beyond [`MAX_PREFIXES`] (ignored, counted).
    pub prefixes_dropped: u8,
    /// RDNSS options seen (not used: the broker resolves no names, ADR-332).
    pub rdnss: u8,
}

impl RouterAdvert {
    pub fn prefixes(&self) -> &[PrefixInfo] {
        self.prefixes
            .get(..usize::from(self.n_prefixes))
            .unwrap_or(&[])
    }
}

/// An ICMPv6 message for this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmp6<'a> {
    Echo {
        request: bool,
        ident: u16,
        seq: u16,
        data: &'a [u8],
    },
    RouterSolicit,
    /// Boxed: the prefixes make it large and RAs are rare.
    RouterAdvert(alloc::boxed::Box<RouterAdvert>),
    NeighbourSolicit {
        target: Ip6,
        slla: Option<Mac>,
    },
    NeighbourAdvert {
        target: Ip6,
        router: bool,
        solicited: bool,
        override_: bool,
        tlla: Option<Mac>,
    },
    /// A valid message of a type this host does not act on (MLD queries,
    /// Redirects, errors).
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmp6Error {
    Truncated,
    BadChecksum,
    /// A Neighbour Discovery message that RFC 4861 says to discard: hop
    /// limit, code, length, an option of length 0 or beyond the end, a
    /// multicast target, `::` where it is not allowed.
    BadNd,
}

/// The options of an ND message: calls `f(type, body)` for each, `body`
/// being the option without its two-byte header. Fails if an option has
/// length 0 or runs past the end (the message is then discarded).
fn nd_options(mut o: &[u8], mut f: impl FnMut(u8, &[u8])) -> Result<(), Icmp6Error> {
    while !o.is_empty() {
        let t = *o.first().ok_or(Icmp6Error::BadNd)?;
        let len = 8 * usize::from(*o.get(1).ok_or(Icmp6Error::BadNd)?);
        if len == 0 {
            return Err(Icmp6Error::BadNd);
        }
        let body = o.get(2..len).ok_or(Icmp6Error::BadNd)?;
        f(t, body);
        o = o.get(len..).ok_or(Icmp6Error::BadNd)?;
    }
    Ok(())
}

fn lla(body: &[u8]) -> Option<Mac> {
    // An Ethernet link-layer address option is 8 bytes: 6 of address.
    if body.len() == 6 { arr(body, 0) } else { None }
}

/// Parses an ICMPv6 message of the packet `ip` (whose `next` is ICMPv6).
pub fn parse_icmp6<'a>(ip: &Ipv6<'a>) -> Result<Icmp6<'a>, Icmp6Error> {
    let p = ip.payload;
    if p.len() < 4 {
        return Err(Icmp6Error::Truncated);
    }
    if csum(pseudo6(&ip.src, &ip.dst, NH_ICMPV6, p.len()), p) != 0 {
        return Err(Icmp6Error::BadChecksum);
    }
    let (t, code) = (
        *p.first().ok_or(Icmp6Error::Truncated)?,
        *p.get(1).ok_or(Icmp6Error::Truncated)?,
    );
    let nd = matches!(
        t,
        ICMP6_RS | ICMP6_RA | ICMP6_NS | ICMP6_NA | ICMP6_REDIRECT
    );
    if nd && (ip.hop_limit != 255 || code != 0 || ip.ext != 0) {
        return Err(Icmp6Error::BadNd);
    }
    if ip.src == UNSPECIFIED && t != ICMP6_NS && t != ICMP6_RS {
        return Err(Icmp6Error::BadNd);
    }
    match t {
        ICMP6_ECHO_REQUEST | ICMP6_ECHO_REPLY => {
            if code != 0 {
                return Ok(Icmp6::Other(t));
            }
            Ok(Icmp6::Echo {
                request: t == ICMP6_ECHO_REQUEST,
                ident: be16(p, 4).ok_or(Icmp6Error::Truncated)?,
                seq: be16(p, 6).ok_or(Icmp6Error::Truncated)?,
                data: p.get(8..).ok_or(Icmp6Error::Truncated)?,
            })
        }
        ICMP6_RS => {
            let mut slla = false;
            nd_options(p.get(8..).ok_or(Icmp6Error::BadNd)?, |t, _| {
                slla |= t == OPT_SLLA;
            })?;
            // From `::` there must be no source link-layer address (§6.1.1).
            if ip.src == UNSPECIFIED && slla {
                return Err(Icmp6Error::BadNd);
            }
            Ok(Icmp6::RouterSolicit)
        }
        ICMP6_RA => {
            if !is_link_local(&ip.src) || p.len() < 16 {
                return Err(Icmp6Error::BadNd);
            }
            let flags = *p.get(5).ok_or(Icmp6Error::Truncated)?;
            let mut ra = RouterAdvert {
                cur_hop_limit: *p.get(4).ok_or(Icmp6Error::Truncated)?,
                managed: flags & 0x80 != 0,
                other: flags & 0x40 != 0,
                router_lifetime_s: be16(p, 6).ok_or(Icmp6Error::Truncated)?,
                reachable_ms: be32(p, 8).ok_or(Icmp6Error::Truncated)?,
                retrans_ms: be32(p, 12).ok_or(Icmp6Error::Truncated)?,
                ..RouterAdvert::default()
            };
            let mut bad = false;
            nd_options(p.get(16..).ok_or(Icmp6Error::BadNd)?, |t, b| match t {
                OPT_SLLA => ra.slla = lla(b).or(ra.slla),
                OPT_MTU => {
                    if b.len() == 6 {
                        ra.mtu = be32(b, 2);
                    } else {
                        bad = true;
                    }
                }
                OPT_PREFIX => {
                    // 32 bytes in all: 30 after the option header.
                    let parsed = (b.len() == 30)
                        .then(|| {
                            Some(PrefixInfo {
                                len: *b.first()?,
                                on_link: b.get(1)? & 0x80 != 0,
                                autonomous: b.get(1)? & 0x40 != 0,
                                valid_s: be32(b, 2)?,
                                preferred_s: be32(b, 6)?,
                                prefix: arr(b, 14)?,
                            })
                        })
                        .flatten();
                    match parsed {
                        Some(pi) if usize::from(ra.n_prefixes) < MAX_PREFIXES => {
                            if let Some(s) = ra.prefixes.get_mut(usize::from(ra.n_prefixes)) {
                                *s = pi;
                            }
                            ra.n_prefixes += 1;
                        }
                        Some(_) => ra.prefixes_dropped = ra.prefixes_dropped.saturating_add(1),
                        None => bad = true,
                    }
                }
                OPT_RDNSS => ra.rdnss = ra.rdnss.saturating_add(1),
                _ => {}
            })?;
            if bad {
                return Err(Icmp6Error::BadNd);
            }
            Ok(Icmp6::RouterAdvert(alloc::boxed::Box::new(ra)))
        }
        ICMP6_NS => {
            let target: Ip6 = arr(p, 8).ok_or(Icmp6Error::BadNd)?;
            if target[0] == 0xff {
                return Err(Icmp6Error::BadNd);
            }
            let mut slla = None;
            nd_options(p.get(24..).ok_or(Icmp6Error::BadNd)?, |t, b| {
                if t == OPT_SLLA {
                    slla = lla(b).or(slla);
                }
            })?;
            // DAD (§7.1.1): from `::` only to a solicited-node group, and
            // without a source link-layer address.
            if ip.src == UNSPECIFIED
                && (slla.is_some() || ip.dst.get(..13) != solicited_node(&target).get(..13))
            {
                return Err(Icmp6Error::BadNd);
            }
            Ok(Icmp6::NeighbourSolicit { target, slla })
        }
        ICMP6_NA => {
            let flags = *p.get(4).ok_or(Icmp6Error::Truncated)?;
            let target: Ip6 = arr(p, 8).ok_or(Icmp6Error::BadNd)?;
            let solicited = flags & 0x40 != 0;
            if target[0] == 0xff || (ip.dst[0] == 0xff && solicited) {
                return Err(Icmp6Error::BadNd);
            }
            let mut tlla = None;
            nd_options(p.get(24..).ok_or(Icmp6Error::BadNd)?, |t, b| {
                if t == OPT_TLLA {
                    tlla = lla(b).or(tlla);
                }
            })?;
            Ok(Icmp6::NeighbourAdvert {
                target,
                router: flags & 0x80 != 0,
                solicited,
                override_: flags & 0x20 != 0,
                tlla,
            })
        }
        _ => Ok(Icmp6::Other(t)),
    }
}

/// Appends an ICMPv6 message (type, code, the four bytes after the
/// checksum, then `body`) with its checksum.
pub fn push_icmp6(
    buf: &mut Vec<u8>,
    src: &Ip6,
    dst: &Ip6,
    t: u8,
    code: u8,
    word: [u8; 4],
    body: &[u8],
) {
    let start = buf.len();
    buf.push(t);
    buf.push(code);
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&word);
    buf.extend_from_slice(body);
    let seg = buf.get(start..).unwrap_or(&[]);
    let c = csum(pseudo6(src, dst, NH_ICMPV6, seg.len()), seg);
    if let Some(d) = buf.get_mut(start + 2..start + 4) {
        d.copy_from_slice(&c.to_be_bytes());
    }
}

/// The body of a Neighbour Solicitation for `target` (with our link-layer
/// address unless the source is `::`).
pub fn ns_body(target: &Ip6, slla: Option<Mac>) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(target);
    if let Some(m) = slla {
        b.extend_from_slice(&[OPT_SLLA, 1]);
        b.extend_from_slice(&m);
    }
    b
}

/// The flags word and body of a Neighbour Advertisement.
pub fn na_parts(target: &Ip6, solicited: bool, tlla: Mac) -> ([u8; 4], Vec<u8>) {
    let flags = if solicited { 0x60 } else { 0x20 };
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(target);
    b.extend_from_slice(&[OPT_TLLA, 1]);
    b.extend_from_slice(&tlla);
    ([flags, 0, 0, 0], b)
}

/// The body of a Router Solicitation (with our link-layer address).
pub fn rs_body(slla: Option<Mac>) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(m) = slla {
        b.extend_from_slice(&[OPT_SLLA, 1]);
        b.extend_from_slice(&m);
    }
    b
}

/// An MLDv2 report (RFC 3810 §5.2) that joins `groups` (exclude-mode with no
/// sources): the IPv6 header with a Hop-by-Hop Router Alert, then the
/// report, appended to `buf` after its Ethernet header. Switches that snoop
/// MLD then deliver the solicited-node groups to this port.
pub fn push_mld_report(buf: &mut Vec<u8>, src: &Ip6, groups: &[Ip6]) {
    let at = buf.len();
    push_ipv6(buf, src, &MLDV2_ROUTERS, NH_HOP, 1, 0);
    // Hop-by-Hop: next header ICMPv6, length 0 (8 bytes), Router Alert
    // (MLD, value 0), PadN of 2 bytes... RFC 2711: type 5, length 2.
    buf.extend_from_slice(&[NH_ICMPV6, 0, 5, 2, 0, 0, 1, 0]);
    let mut body = Vec::with_capacity(groups.len() * 20);
    for g in groups {
        // Record type 4 (CHANGE_TO_EXCLUDE_MODE), no aux data, no sources.
        body.extend_from_slice(&[4, 0, 0, 0]);
        body.extend_from_slice(g);
    }
    let n = (groups.len() as u16).to_be_bytes();
    push_icmp6(
        buf,
        src,
        &MLDV2_ROUTERS,
        ICMP6_MLDV2_REPORT,
        0,
        [0, 0, n[0], n[1]],
        &body,
    );
    fix_len(buf, at);
}

#[cfg(test)]
mod tests {
    use super::*;

    const LL: Ip6 = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
    ];
    const RTR: Ip6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

    pub(crate) fn icmp_packet(
        src: &Ip6,
        dst: &Ip6,
        hop: u8,
        t: u8,
        word: [u8; 4],
        body: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        push_ipv6(&mut b, src, dst, NH_ICMPV6, hop, 0);
        push_icmp6(&mut b, src, dst, t, 0, word, body);
        fix_len(&mut b, 0);
        b
    }

    #[test]
    fn addresses_of_a_mac() {
        assert_eq!(eui64(MAC), [0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56]);
        assert_eq!(link_local_of(MAC), LL);
        let sn = solicited_node(&LL);
        assert_eq!(&sn[..13], &[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]);
        assert_eq!(&sn[13..], &[0x12, 0x34, 0x56]);
        assert_eq!(multicast_mac(&sn), [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
        assert!(same_prefix(&LL, &RTR, 64));
        assert!(same_prefix(&LL, &RTR, 65));
        assert!(!same_prefix(&LL, &RTR, 66));
        assert!(same_prefix(
            &LL,
            &[0xfe, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            15
        ));
        assert!(!same_prefix(
            &LL,
            &[0xfe, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            16
        ));
        assert!(same_prefix(&LL, &[0; 16], 0));
    }

    #[test]
    fn the_header_is_strict() {
        let mut b = Vec::new();
        push_ipv6(&mut b, &RTR, &LL, NH_TCP, 64, 20);
        b.extend_from_slice(&[0; 20]);
        let ip = parse_ipv6(&b).unwrap();
        assert_eq!(
            (ip.src, ip.dst, ip.next, ip.payload.len()),
            (RTR, LL, NH_TCP, 20)
        );
        // Padding is cut off; a length beyond the frame is refused.
        let mut padded = b.clone();
        padded.extend_from_slice(&[0; 6]);
        assert_eq!(parse_ipv6(&padded).unwrap().payload.len(), 20);
        assert_eq!(parse_ipv6(&b[..50]), Err(V6Error::BadLength));
        assert_eq!(parse_ipv6(&b[..30]), Err(V6Error::Truncated));
        let mut v4 = b.clone();
        v4[0] = 0x45;
        assert_eq!(parse_ipv6(&v4), Err(V6Error::NotV6));
        // Mapped, multicast source, loopback.
        let mut m = b.clone();
        m[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
        assert_eq!(parse_ipv6(&m), Err(V6Error::Mapped));
        let mut m = b.clone();
        m[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
        assert_eq!(parse_ipv6(&m), Err(V6Error::Mapped));
        let mut mc = b.clone();
        mc[8] = 0xff;
        assert_eq!(parse_ipv6(&mc), Err(V6Error::BadAddress));
        let mut lo = b.clone();
        lo[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(parse_ipv6(&lo), Err(V6Error::BadAddress));
        // TCP from `::` is refused.
        let mut un = b.clone();
        un[8..24].copy_from_slice(&[0; 16]);
        assert_eq!(parse_ipv6(&un), Err(V6Error::BadAddress));
        // Unknown upper layer.
        let mut u = b.clone();
        u[6] = 99;
        assert_eq!(parse_ipv6(&u), Err(V6Error::ExtHeader));
    }

    fn with_ext(exts: &[(u8, Vec<u8>)], last: u8) -> Vec<u8> {
        let mut b = Vec::new();
        let first = exts.first().map_or(last, |e| e.0);
        push_ipv6(&mut b, &RTR, &LL, first, 64, 0);
        for (i, (_, body)) in exts.iter().enumerate() {
            let next = exts.get(i + 1).map_or(last, |e| e.0);
            b.push(next);
            b.extend_from_slice(body);
        }
        b.extend_from_slice(&[0; 20]);
        fix_len(&mut b, 0);
        b
    }

    #[test]
    fn extension_headers_are_walked_within_bounds() {
        // HBH with PadN, a routing header with segments left 0, DstOpts with
        // an unknown skippable option.
        let hbh = alloc::vec![0u8, 1, 4, 0, 0, 0, 0];
        let rt = alloc::vec![0u8, 0, 0, 0, 0, 0, 0];
        let dst = alloc::vec![0u8, 0x1e, 4, 0, 0, 0, 0];
        let p = with_ext(
            &[
                (NH_HOP, hbh.clone()),
                (NH_ROUTING, rt.clone()),
                (NH_DSTOPTS, dst),
            ],
            NH_TCP,
        );
        let ip = parse_ipv6(&p).unwrap();
        assert_eq!((ip.next, ip.ext, ip.payload.len()), (NH_TCP, 3, 20));
        // Segments left: dropped.
        let mut rt1 = rt.clone();
        rt1[2] = 1;
        assert_eq!(
            parse_ipv6(&with_ext(&[(NH_ROUTING, rt1)], NH_TCP)),
            Err(V6Error::ExtHeader)
        );
        // An option whose action bits say discard.
        let bad = alloc::vec![0u8, 0x80, 4, 0, 0, 0, 0];
        assert_eq!(
            parse_ipv6(&with_ext(&[(NH_DSTOPTS, bad)], NH_TCP)),
            Err(V6Error::ExtHeader)
        );
        // HBH not first.
        assert_eq!(
            parse_ipv6(&with_ext(
                &[(NH_DSTOPTS, hbh.clone()), (NH_HOP, hbh.clone())],
                NH_TCP
            )),
            Err(V6Error::ExtHeader)
        );
        // Five headers: over the bound.
        let five: Vec<(u8, Vec<u8>)> = (0..5).map(|_| (NH_DSTOPTS, hbh.clone())).collect();
        assert_eq!(
            parse_ipv6(&with_ext(&five, NH_TCP)),
            Err(V6Error::ExtHeader)
        );
        // A fragment header.
        assert_eq!(
            parse_ipv6(&with_ext(&[(NH_FRAGMENT, alloc::vec![0; 7])], NH_TCP)),
            Err(V6Error::Fragment)
        );
        // An option that runs past its header.
        let over = alloc::vec![0u8, 1, 9, 0, 0, 0, 0];
        assert_eq!(
            parse_ipv6(&with_ext(&[(NH_HOP, over)], NH_TCP)),
            Err(V6Error::ExtHeader)
        );
        // A header longer than the packet.
        let mut long = with_ext(&[(NH_HOP, hbh)], NH_TCP);
        long[41] = 5;
        assert_eq!(parse_ipv6(&long), Err(V6Error::Truncated));
        long[41] = 200;
        assert_eq!(parse_ipv6(&long), Err(V6Error::ExtHeader));
    }

    #[test]
    fn neighbour_discovery_round_trips_and_is_strict() {
        let target = LL;
        // NS from a neighbour with its link-layer address.
        let ns = icmp_packet(
            &RTR,
            &solicited_node(&target),
            255,
            ICMP6_NS,
            [0; 4],
            &ns_body(&target, Some([2; 6])),
        );
        let ip = parse_ipv6(&ns).unwrap();
        assert_eq!(
            parse_icmp6(&ip),
            Ok(Icmp6::NeighbourSolicit {
                target,
                slla: Some([2; 6])
            })
        );
        // Hop limit below 255: from off the link.
        let off = icmp_packet(
            &RTR,
            &solicited_node(&target),
            254,
            ICMP6_NS,
            [0; 4],
            &ns_body(&target, None),
        );
        assert_eq!(
            parse_icmp6(&parse_ipv6(&off).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        // DAD from `::` with an SLLA, or to a unicast address: refused.
        let dad_bad = icmp_packet(
            &UNSPECIFIED,
            &solicited_node(&target),
            255,
            ICMP6_NS,
            [0; 4],
            &ns_body(&target, Some([2; 6])),
        );
        assert_eq!(
            parse_icmp6(&parse_ipv6(&dad_bad).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        let dad_uni = icmp_packet(
            &UNSPECIFIED,
            &LL,
            255,
            ICMP6_NS,
            [0; 4],
            &ns_body(&target, None),
        );
        assert_eq!(
            parse_icmp6(&parse_ipv6(&dad_uni).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        let dad = icmp_packet(
            &UNSPECIFIED,
            &solicited_node(&target),
            255,
            ICMP6_NS,
            [0; 4],
            &ns_body(&target, None),
        );
        assert!(matches!(
            parse_icmp6(&parse_ipv6(&dad).unwrap()),
            Ok(Icmp6::NeighbourSolicit { slla: None, .. })
        ));
        // An option of length 0.
        let mut zero = ns_body(&target, Some([2; 6]));
        zero[17] = 0;
        let z = icmp_packet(&RTR, &solicited_node(&target), 255, ICMP6_NS, [0; 4], &zero);
        assert_eq!(
            parse_icmp6(&parse_ipv6(&z).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        // NA.
        let (w, body) = na_parts(&target, true, MAC);
        let na = icmp_packet(&LL, &RTR, 255, ICMP6_NA, w, &body);
        assert_eq!(
            parse_icmp6(&parse_ipv6(&na).unwrap()),
            Ok(Icmp6::NeighbourAdvert {
                target,
                router: false,
                solicited: true,
                override_: true,
                tlla: Some(MAC)
            })
        );
        // A solicited NA to a multicast address is refused.
        let na_mc = icmp_packet(&LL, &ALL_NODES, 255, ICMP6_NA, w, &body);
        assert_eq!(
            parse_icmp6(&parse_ipv6(&na_mc).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        // A bad checksum.
        let mut bad = na.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            parse_icmp6(&parse_ipv6(&bad).unwrap()),
            Err(Icmp6Error::BadChecksum)
        );
    }

    pub(crate) fn ra_body(
        prefixes: &[([u8; 16], u8, u8, u32, u32)],
        mtu: Option<u32>,
        slla: Option<Mac>,
    ) -> Vec<u8> {
        // Reachable and retrans times, then options.
        let mut b = alloc::vec![0u8; 8];
        if let Some(m) = slla {
            b.extend_from_slice(&[OPT_SLLA, 1]);
            b.extend_from_slice(&m);
        }
        if let Some(m) = mtu {
            b.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
            b.extend_from_slice(&m.to_be_bytes());
        }
        for (p, len, flags, valid, pref) in prefixes {
            b.extend_from_slice(&[OPT_PREFIX, 4, *len, *flags]);
            b.extend_from_slice(&valid.to_be_bytes());
            b.extend_from_slice(&pref.to_be_bytes());
            b.extend_from_slice(&[0; 4]);
            b.extend_from_slice(p);
        }
        // An RDNSS option (ignored).
        b.extend_from_slice(&[OPT_RDNSS, 3, 0, 0, 0, 0, 0, 60]);
        b.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        b
    }

    #[test]
    fn router_advertisements_parse() {
        let p: Ip6 = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let body = ra_body(&[(p, 64, 0xc0, 86400, 14400)], Some(1480), Some([2; 6]));
        let ra = icmp_packet(&RTR, &ALL_NODES, 255, ICMP6_RA, [64, 0, 0x07, 0x08], &body);
        let Ok(Icmp6::RouterAdvert(r)) = parse_icmp6(&parse_ipv6(&ra).unwrap()) else {
            panic!("not an RA");
        };
        assert_eq!(
            (r.cur_hop_limit, r.router_lifetime_s, r.mtu, r.slla, r.rdnss),
            (64, 1800, Some(1480), Some([2; 6]), 1)
        );
        assert_eq!(
            r.prefixes(),
            &[PrefixInfo {
                prefix: p,
                len: 64,
                on_link: true,
                autonomous: true,
                valid_s: 86400,
                preferred_s: 14400
            }]
        );
        // From a global source: refused.
        let g = icmp_packet(&p, &ALL_NODES, 255, ICMP6_RA, [64, 0, 0x07, 0x08], &body);
        assert_eq!(
            parse_icmp6(&parse_ipv6(&g).unwrap()),
            Err(Icmp6Error::BadNd)
        );
        // A prefix option of the wrong length.
        let mut short = body.clone();
        let at = short.iter().position(|&x| x == OPT_PREFIX).unwrap();
        short[at + 1] = 3;
        let s = icmp_packet(&RTR, &ALL_NODES, 255, ICMP6_RA, [64, 0, 0x07, 0x08], &short);
        assert!(parse_icmp6(&parse_ipv6(&s).unwrap()).is_err());
        // More prefixes than kept: the rest counted.
        let many: Vec<_> = (0..10u8)
            .map(|i| {
                let mut q = p;
                q[5] = i;
                (q, 64u8, 0xc0u8, 100u32, 50u32)
            })
            .collect();
        let m = icmp_packet(
            &RTR,
            &ALL_NODES,
            255,
            ICMP6_RA,
            [64, 0, 0, 0],
            &ra_body(&many, None, None),
        );
        let Ok(Icmp6::RouterAdvert(r)) = parse_icmp6(&parse_ipv6(&m).unwrap()) else {
            panic!("not an RA");
        };
        assert_eq!((r.n_prefixes, r.prefixes_dropped), (8, 2));
    }

    #[test]
    fn echo_and_the_mld_report() {
        let e = icmp_packet(&RTR, &LL, 64, ICMP6_ECHO_REQUEST, [0, 9, 0, 1], b"ping");
        assert_eq!(
            parse_icmp6(&parse_ipv6(&e).unwrap()),
            Ok(Icmp6::Echo {
                request: true,
                ident: 9,
                seq: 1,
                data: b"ping"
            })
        );
        let mut b = Vec::new();
        push_mld_report(&mut b, &LL, &[solicited_node(&LL)]);
        let ip = parse_ipv6(&b).unwrap();
        assert_eq!(
            (ip.next, ip.ext, ip.hop_limit, ip.dst),
            (NH_ICMPV6, 1, 1, MLDV2_ROUTERS)
        );
        assert_eq!(parse_icmp6(&ip), Ok(Icmp6::Other(ICMP6_MLDV2_REPORT)));
    }
}
