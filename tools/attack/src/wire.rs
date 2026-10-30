//! Minimal Ethernet/IPv4/TCP/UDP builders for the raw-L2 attacks. The
//! kernel's own `urmqtt-net`/`urmqtt-tcp` crates are `no_std` and bound to
//! the appliance; this host tool re-states just enough wire format to be an
//! adversarial peer, so a bug here cannot flatter the broker.

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

pub type Mac = [u8; 6];
pub type Ip = [u8; 4];

/// The one's-complement sum used by the internet checksum.
fn sum(mut acc: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        acc += u32::from(data[i]) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn eth(buf: &mut Vec<u8>, dst: Mac, src: Mac, ethertype: u16) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&ethertype.to_be_bytes());
}

/// An IPv4 header with the total length and header checksum filled in.
pub fn ipv4(buf: &mut Vec<u8>, src: Ip, dst: Ip, proto: u8, id: u16, payload_len: usize) {
    let total = 20 + payload_len;
    let start = buf.len();
    buf.extend_from_slice(&[0x45, 0x00]);
    buf.extend_from_slice(&(total as u16).to_be_bytes());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x40, 0x00]); // DF, no fragment offset
    buf.extend_from_slice(&[64, proto, 0, 0]); // TTL, proto, checksum=0
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    let csum = fold(sum(0, &buf[start..start + 20]));
    buf[start + 10..start + 12].copy_from_slice(&csum.to_be_bytes());
}

/// A full Ethernet frame carrying a TCP segment (no options except an MSS
/// on SYN), checksums computed.
#[allow(clippy::too_many_arguments)]
pub fn tcp_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: Ip,
    dst_ip: Ip,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    let off: u8 = if mss.is_some() { 6 } else { 5 };
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(off << 4);
    seg.push(flags);
    seg.extend_from_slice(&window.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    if let Some(m) = mss {
        seg.extend_from_slice(&[2, 4]);
        seg.extend_from_slice(&m.to_be_bytes());
    }
    seg.extend_from_slice(payload);
    // TCP checksum over the pseudo-header and the segment.
    let mut acc = sum(0, &src_ip);
    acc = sum(acc, &dst_ip);
    acc += u32::from(PROTO_TCP);
    acc += seg.len() as u32;
    let csum = fold(sum(acc, &seg));
    seg[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut frame = Vec::with_capacity(ETH_HDR + 20 + seg.len());
    eth(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4);
    ipv4(
        &mut frame,
        src_ip,
        dst_ip,
        PROTO_TCP,
        (seq & 0xffff) as u16,
        seg.len(),
    );
    frame.extend_from_slice(&seg);
    frame
}

/// A full Ethernet frame carrying a UDP datagram.
pub fn udp_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: Ip,
    dst_ip: Ip,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);
    let mut acc = sum(0, &src_ip);
    acc = sum(acc, &dst_ip);
    acc += u32::from(PROTO_UDP);
    acc += udp.len() as u32;
    let csum = fold(sum(acc, &udp));
    // A zero UDP checksum means "not computed"; 0xffff stands in for it.
    udp[6..8].copy_from_slice(&(if csum == 0 { 0xffff } else { csum }).to_be_bytes());

    let mut frame = Vec::with_capacity(ETH_HDR + 20 + udp.len());
    eth(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4);
    ipv4(&mut frame, src_ip, dst_ip, PROTO_UDP, 0, udp.len());
    frame.extend_from_slice(&udp);
    frame
}

/// The parsed shape of a received frame, enough to run the mini stack.
pub struct Parsed {
    pub src_mac: Mac,
    pub proto: u8,
    pub src_ip: Ip,
    pub dst_ip: Ip,
    /// For TCP: (sport, dport, seq, ack, flags). For UDP: (sport, dport, 0, 0, 0).
    pub l4: (u16, u16, u32, u32, u8),
    pub payload: Vec<u8>,
    pub arp: Option<ArpReq>,
}

pub struct ArpReq {
    pub sender_mac: Mac,
    pub sender_ip: Ip,
    pub target_ip: Ip,
    pub is_request: bool,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub fn parse(frame: &[u8]) -> Option<Parsed> {
    if frame.len() < ETH_HDR {
        return None;
    }
    let src_mac: Mac = frame[6..12].try_into().ok()?;
    let ethertype = be16(frame, 12)?;
    let body = &frame[ETH_HDR..];
    let mut p = Parsed {
        src_mac,
        proto: 0,
        src_ip: [0; 4],
        dst_ip: [0; 4],
        l4: (0, 0, 0, 0, 0),
        payload: Vec::new(),
        arp: None,
    };
    match ethertype {
        ETHERTYPE_ARP => {
            if be16(body, 0)? == 1 && be16(body, 2)? == ETHERTYPE_IPV4 {
                let op = be16(body, 6)?;
                p.arp = Some(ArpReq {
                    sender_mac: body.get(8..14)?.try_into().ok()?,
                    sender_ip: body.get(14..18)?.try_into().ok()?,
                    target_ip: body.get(24..28)?.try_into().ok()?,
                    is_request: op == 1,
                });
            }
        }
        ETHERTYPE_IPV4 => {
            let ihl = usize::from(body.first()? & 0x0f) * 4;
            p.proto = *body.get(9)?;
            p.src_ip = body.get(12..16)?.try_into().ok()?;
            p.dst_ip = body.get(16..20)?.try_into().ok()?;
            let l4 = body.get(ihl..)?;
            match p.proto {
                PROTO_TCP => {
                    let data_off = usize::from(l4.get(12)? >> 4) * 4;
                    p.l4 = (
                        be16(l4, 0)?,
                        be16(l4, 2)?,
                        be32(l4, 4)?,
                        be32(l4, 8)?,
                        *l4.get(13)? & 0x3f,
                    );
                    p.payload = l4.get(data_off..)?.to_vec();
                }
                PROTO_UDP => {
                    p.l4 = (be16(l4, 0)?, be16(l4, 2)?, 0, 0, 0);
                    p.payload = l4.get(8..)?.to_vec();
                }
                _ => {}
            }
        }
        _ => {}
    }
    Some(p)
}

/// An ARP reply frame: `our_mac` claims `our_ip` to `req.sender`.
pub fn arp_reply(our_mac: Mac, our_ip: Ip, req: &ArpReq) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_HDR + 28);
    eth(&mut f, req.sender_mac, our_mac, ETHERTYPE_ARP);
    f.extend_from_slice(&[0, 1]); // Ethernet
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f.extend_from_slice(&[6, 4, 0, 2]); // reply
    f.extend_from_slice(&our_mac);
    f.extend_from_slice(&our_ip);
    f.extend_from_slice(&req.sender_mac);
    f.extend_from_slice(&req.sender_ip);
    f
}
