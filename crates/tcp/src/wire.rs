//! TCP header parsing and emission with the IPv4 pseudo-header checksum.

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
pub const HEADER: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// MSS option, if present (only meaningful on SYN).
    pub mss: Option<u16>,
    /// Offset of the payload in the segment.
    pub data_off: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadOffset,
    BadChecksum,
    BadFlags,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// One's-complement sum used by the internet checksum.
fn sum(mut acc: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for p in pairs {
        acc += u32::from(u16::from_be_bytes(*p));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The TCP checksum over the IPv4 pseudo-header and `segment` (with its
/// checksum field as it is).
pub fn checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut acc = sum(0, &src);
    acc = sum(acc, &dst);
    acc += 6;
    acc += segment.len() as u32;
    fold(sum(acc, segment))
}

/// Parses and validates a TCP segment received from `src` for `dst`.
pub fn parse(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> Result<Header, WireError> {
    if seg.len() < HEADER {
        return Err(WireError::Truncated);
    }
    let off = usize::from(seg.get(12).copied().unwrap_or(0) >> 4) * 4;
    if off < HEADER || off > seg.len() {
        return Err(WireError::BadOffset);
    }
    if checksum(src, dst, seg) != 0 {
        return Err(WireError::BadChecksum);
    }
    let flags = seg.get(13).copied().unwrap_or(0) & 0x3f;
    // Nonsense combinations are dropped (PROMPT §5.2 strict input).
    if (flags & SYN != 0 && flags & (FIN | RST) != 0) || flags & URG != 0 || flags == 0 {
        return Err(WireError::BadFlags);
    }
    let mut mss = None;
    let mut i = HEADER;
    while i < off {
        match seg.get(i).copied() {
            Some(0) | None => break,
            Some(1) => i += 1,
            Some(kind) => {
                let len = usize::from(seg.get(i + 1).copied().unwrap_or(0));
                if len < 2 || i + len > off {
                    return Err(WireError::BadOffset);
                }
                if kind == 2 && len == 4 {
                    mss = be16(seg, i + 2);
                }
                i += len;
            }
        }
    }
    Ok(Header {
        sport: be16(seg, 0).ok_or(WireError::Truncated)?,
        dport: be16(seg, 2).ok_or(WireError::Truncated)?,
        seq: be32(seg, 4).ok_or(WireError::Truncated)?,
        ack: be32(seg, 8).ok_or(WireError::Truncated)?,
        flags,
        window: be16(seg, 14).ok_or(WireError::Truncated)?,
        mss,
        data_off: off,
    })
}

/// Fields of an outgoing segment.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
}

/// Writes header (+ MSS option) and `payload` into `buf` (cleared first)
/// and fills in the checksum.
pub fn emit(src: [u8; 4], dst: [u8; 4], o: &Out, payload: &[u8], buf: &mut alloc::vec::Vec<u8>) {
    buf.clear();
    let hlen = if o.mss.is_some() { HEADER + 4 } else { HEADER };
    buf.extend_from_slice(&o.sport.to_be_bytes());
    buf.extend_from_slice(&o.dport.to_be_bytes());
    buf.extend_from_slice(&o.seq.to_be_bytes());
    buf.extend_from_slice(&o.ack.to_be_bytes());
    buf.push(((hlen / 4) as u8) << 4);
    buf.push(o.flags);
    buf.extend_from_slice(&o.window.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(m) = o.mss {
        buf.extend_from_slice(&[2, 4]);
        buf.extend_from_slice(&m.to_be_bytes());
    }
    buf.extend_from_slice(payload);
    let c = checksum(src, dst, buf);
    if let Some(d) = buf.get_mut(16..18) {
        d.copy_from_slice(&c.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn emit_parse_round_trip_and_checksum() {
        let (a, b) = ([10, 0, 2, 2], [10, 0, 2, 15]);
        let mut buf = Vec::new();
        let o = Out {
            sport: 51000,
            dport: 8883,
            seq: 0xdead_beef,
            ack: 7,
            flags: SYN | ACK,
            window: 65535,
            mss: Some(1460),
        };
        emit(a, b, &o, b"hi", &mut buf);
        let h = parse(a, b, &buf).unwrap();
        assert_eq!(
            (h.sport, h.dport, h.seq, h.ack, h.flags, h.window, h.mss),
            (51000, 8883, 0xdead_beef, 7, SYN | ACK, 65535, Some(1460))
        );
        assert_eq!(&buf[h.data_off..], b"hi");
        // One flipped bit anywhere breaks the checksum.
        let mut bad = buf.clone();
        bad[22] ^= 1;
        assert_eq!(parse(a, b, &bad), Err(WireError::BadChecksum));
        assert_eq!(parse([1, 2, 3, 4], b, &buf), Err(WireError::BadChecksum));
        // Odd-length payloads are padded in the sum.
        emit(
            a,
            b,
            &Out {
                mss: None,
                flags: ACK,
                ..o
            },
            b"odd",
            &mut buf,
        );
        assert!(parse(a, b, &buf).is_ok());
    }

    #[test]
    fn rejects_bad_offsets_and_flags() {
        let (a, b) = ([1, 1, 1, 1], [2, 2, 2, 2]);
        let mut buf = Vec::new();
        emit(
            a,
            b,
            &Out {
                sport: 1,
                dport: 2,
                seq: 0,
                ack: 0,
                flags: SYN | FIN,
                window: 0,
                mss: None,
            },
            &[],
            &mut buf,
        );
        assert_eq!(parse(a, b, &buf), Err(WireError::BadFlags));
        assert_eq!(parse(a, b, &buf[..10]), Err(WireError::Truncated));
        emit(
            a,
            b,
            &Out {
                sport: 1,
                dport: 2,
                seq: 0,
                ack: 0,
                flags: ACK,
                window: 0,
                mss: None,
            },
            &[],
            &mut buf,
        );
        buf[12] = 0xf0;
        assert_eq!(parse(a, b, &buf), Err(WireError::BadOffset));
    }
}
