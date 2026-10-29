//! Ethernet II, ARP, IPv4, ICMP echo and UDP: parsing with strict
//! validation, and emission (PROMPT §5.2: IP options, fragments, unknown
//! protocols and malformed headers are dropped).

use alloc::vec::Vec;

pub const ETH_HDR: usize = 14;
pub const IP_HDR: usize = 20;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

pub type Mac = [u8; 6];
pub type Ip = [u8; 4];

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn arr<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at + N)?.try_into().ok()
}

/// Internet checksum (RFC 1071) of `data`, starting from `acc`.
pub fn csum(mut acc: u32, data: &[u8]) -> u16 {
    let (pairs, rest) = data.as_chunks::<2>();
    for p in pairs {
        acc += u32::from(u16::from_be_bytes(*p));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthFrame<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(f: &[u8]) -> Option<EthFrame<'_>> {
    Some(EthFrame {
        dst: arr(f, 0)?,
        src: arr(f, 6)?,
        ethertype: be16(f, 12)?,
        payload: f.get(ETH_HDR..)?,
    })
}

pub fn push_eth(buf: &mut Vec<u8>, dst: Mac, src: Mac, ethertype: u16) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&ethertype.to_be_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sha: Mac,
    pub spa: Ip,
    pub tha: Mac,
    pub tpa: Ip,
}

pub fn parse_arp(p: &[u8]) -> Option<Arp> {
    // Ethernet + IPv4 only.
    if be16(p, 0)? != 1 || be16(p, 2)? != ETHERTYPE_IPV4 || p.get(4)? != &6 || p.get(5)? != &4 {
        return None;
    }
    Some(Arp {
        op: be16(p, 6)?,
        sha: arr(p, 8)?,
        spa: arr(p, 14)?,
        tha: arr(p, 18)?,
        tpa: arr(p, 24)?,
    })
}

pub fn emit_arp(buf: &mut Vec<u8>, our_mac: Mac, a: &Arp) {
    buf.clear();
    let dst = if a.op == 1 { BROADCAST_MAC } else { a.tha };
    push_eth(buf, dst, our_mac, ETHERTYPE_ARP);
    buf.extend_from_slice(&[0, 1, 0x08, 0, 6, 4]);
    buf.extend_from_slice(&a.op.to_be_bytes());
    buf.extend_from_slice(&a.sha);
    buf.extend_from_slice(&a.spa);
    buf.extend_from_slice(&a.tha);
    buf.extend_from_slice(&a.tpa);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    pub src: Ip,
    pub dst: Ip,
    pub proto: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpError {
    Truncated,
    NotV4,
    /// IP options present (dropped by policy).
    Options,
    Fragment,
    BadLength,
    BadChecksum,
}

/// Parses an IPv4 header; drops options, fragments and bad checksums.
pub fn parse_ipv4(p: &[u8]) -> Result<Ipv4<'_>, IpError> {
    let vihl = *p.first().ok_or(IpError::Truncated)?;
    if vihl >> 4 != 4 {
        return Err(IpError::NotV4);
    }
    if vihl & 0x0f != 5 {
        return Err(IpError::Options);
    }
    if p.len() < IP_HDR {
        return Err(IpError::Truncated);
    }
    let total = usize::from(be16(p, 2).ok_or(IpError::Truncated)?);
    if total < IP_HDR || total > p.len() {
        return Err(IpError::BadLength);
    }
    let frag = be16(p, 6).ok_or(IpError::Truncated)?;
    if frag & 0x3fff != 0 {
        // MF set or a non-zero offset (DF alone is fine).
        return Err(IpError::Fragment);
    }
    if csum(0, p.get(..IP_HDR).ok_or(IpError::Truncated)?) != 0 {
        return Err(IpError::BadChecksum);
    }
    Ok(Ipv4 {
        src: arr(p, 12).ok_or(IpError::Truncated)?,
        dst: arr(p, 16).ok_or(IpError::Truncated)?,
        proto: *p.get(9).ok_or(IpError::Truncated)?,
        ttl: *p.get(8).ok_or(IpError::Truncated)?,
        // Ethernet padding beyond the IP length is cut off.
        payload: p.get(IP_HDR..total).ok_or(IpError::Truncated)?,
    })
}

/// Appends an IPv4 header (DF, TTL 64, no options) for `len` payload bytes.
pub fn push_ipv4(buf: &mut Vec<u8>, src: Ip, dst: Ip, proto: u8, id: u16, len: usize) {
    let start = buf.len();
    buf.push(0x45);
    buf.push(0);
    buf.extend_from_slice(&((IP_HDR + len) as u16).to_be_bytes());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x4000u16.to_be_bytes());
    buf.push(64);
    buf.push(proto);
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    let c = csum(0, buf.get(start..).unwrap_or(&[]));
    if let Some(d) = buf.get_mut(start + 10..start + 12) {
        d.copy_from_slice(&c.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp<'a> {
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(src: Ip, dst: Ip, p: &[u8]) -> Option<Udp<'_>> {
    let len = usize::from(be16(p, 4)?);
    if len < 8 || len > p.len() {
        return None;
    }
    let body = p.get(..len)?;
    if be16(p, 6)? != 0 && udp_sum(src, dst, body) != 0 {
        return None;
    }
    Some(Udp {
        sport: be16(p, 0)?,
        dport: be16(p, 2)?,
        payload: p.get(8..len)?,
    })
}

fn pseudo(src: Ip, dst: Ip, proto: u8, len: usize) -> u32 {
    let mut acc = 0u32;
    for p in src.as_chunks::<2>().0.iter().chain(dst.as_chunks::<2>().0) {
        acc += u32::from(u16::from_be_bytes(*p));
    }
    acc + u32::from(proto) + len as u32
}

fn udp_sum(src: Ip, dst: Ip, seg: &[u8]) -> u16 {
    csum(pseudo(src, dst, PROTO_UDP, seg.len()), seg)
}

/// Appends a UDP header + payload (with checksum).
pub fn push_udp(buf: &mut Vec<u8>, src: Ip, dst: Ip, sport: u16, dport: u16, payload: &[u8]) {
    let start = buf.len();
    buf.extend_from_slice(&sport.to_be_bytes());
    buf.extend_from_slice(&dport.to_be_bytes());
    buf.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(payload);
    let mut c = udp_sum(src, dst, buf.get(start..).unwrap_or(&[]));
    if c == 0 {
        c = 0xffff;
    }
    if let Some(d) = buf.get_mut(start + 6..start + 8) {
        d.copy_from_slice(&c.to_be_bytes());
    }
}

/// An ICMP echo request or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo<'a> {
    pub request: bool,
    pub ident: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

pub fn parse_icmp_echo(p: &[u8]) -> Option<Echo<'_>> {
    if csum(0, p) != 0 {
        return None;
    }
    let request = match p.first()? {
        8 => true,
        0 => false,
        _ => return None,
    };
    if *p.get(1)? != 0 {
        return None;
    }
    Some(Echo {
        request,
        ident: be16(p, 4)?,
        seq: be16(p, 6)?,
        data: p.get(8..)?,
    })
}

pub fn push_icmp_echo(buf: &mut Vec<u8>, e: &Echo<'_>) {
    let start = buf.len();
    buf.push(if e.request { 8 } else { 0 });
    buf.push(0);
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&e.ident.to_be_bytes());
    buf.extend_from_slice(&e.seq.to_be_bytes());
    buf.extend_from_slice(e.data);
    let c = csum(0, buf.get(start..).unwrap_or(&[]));
    if let Some(d) = buf.get_mut(start + 2..start + 4) {
        d.copy_from_slice(&c.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_udp_icmp_round_trips_and_strictness() {
        let (a, b) = ([10, 0, 2, 15], [10, 0, 2, 2]);
        let mut buf = Vec::new();
        push_ipv4(&mut buf, a, b, PROTO_UDP, 7, 8 + 5);
        push_udp(&mut buf, a, b, 68, 67, b"hello");
        let ip = parse_ipv4(&buf).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (a, b, PROTO_UDP));
        let u = parse_udp(ip.src, ip.dst, ip.payload).unwrap();
        assert_eq!((u.sport, u.dport, u.payload), (68, 67, &b"hello"[..]));
        // Padding after the IP length is ignored.
        let mut padded = buf.clone();
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(parse_ipv4(&padded).unwrap().payload.len(), 13);
        let mut bad = buf.clone();
        bad[0] = 0x46;
        assert_eq!(parse_ipv4(&bad), Err(IpError::Options));
        let mut frag = buf.clone();
        frag[6] |= 0x20;
        assert_eq!(parse_ipv4(&frag), Err(IpError::Fragment));
        let mut sum = buf.clone();
        sum[15] ^= 1;
        assert_eq!(parse_ipv4(&sum), Err(IpError::BadChecksum));
        let mut udp = buf.clone();
        udp[30] ^= 1;
        assert!(parse_udp(a, b, parse_ipv4(&udp).unwrap().payload).is_none());

        let mut icmp = Vec::new();
        push_icmp_echo(
            &mut icmp,
            &Echo {
                request: true,
                ident: 9,
                seq: 1,
                data: b"ping",
            },
        );
        let e = parse_icmp_echo(&icmp).unwrap();
        assert!(e.request && e.ident == 9 && e.data == b"ping");
        icmp[9] ^= 1;
        assert!(parse_icmp_echo(&icmp).is_none());
    }

    #[test]
    fn arp_round_trip() {
        let mut buf = Vec::new();
        let a = Arp {
            op: 1,
            sha: [1; 6],
            spa: [10, 0, 2, 15],
            tha: [0; 6],
            tpa: [10, 0, 2, 2],
        };
        emit_arp(&mut buf, [1; 6], &a);
        let f = parse_eth(&buf).unwrap();
        assert_eq!((f.dst, f.ethertype), (BROADCAST_MAC, ETHERTYPE_ARP));
        assert_eq!(parse_arp(f.payload), Some(a));
    }
}
