//! Encoder into caller-provided buffers (no allocation).

use crate::{MAX_REMAINING_LENGTH, Packet, QoS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
    /// A field exceeds what MQTT can represent (string > 65535 bytes,
    /// packet > 268 435 455 bytes).
    TooLarge,
    /// QoS > 0 publish without a packet id, or the reverse.
    InconsistentPacketId,
}

struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let end = self.pos + b.len();
        self.out
            .get_mut(self.pos..end)
            .ok_or(EncodeError::BufferTooSmall)?
            .copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    fn u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> Result<(), EncodeError> {
        self.bytes(&v.to_be_bytes())
    }

    fn binary(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let n = u16::try_from(b.len()).map_err(|_| EncodeError::TooLarge)?;
        self.u16(n)?;
        self.bytes(b)
    }

    fn varint(&mut self, mut v: u32) -> Result<(), EncodeError> {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v > 0 {
                b |= 0x80;
            }
            self.u8(b)?;
            if v == 0 {
                return Ok(());
            }
        }
    }
}

const fn str_len(s: &[u8]) -> usize {
    2 + s.len()
}

/// Remaining length (body size) of `p`.
fn body_len(p: &Packet<'_>) -> usize {
    match p {
        Packet::Connect(c) => {
            let mut n = str_len(b"MQTT") + 1 + 1 + 2 + str_len(c.client_id.as_bytes());
            if let Some(w) = &c.will {
                n += str_len(w.topic.as_bytes()) + str_len(w.payload);
            }
            if let Some(u) = c.username {
                n += str_len(u.as_bytes());
            }
            if let Some(pw) = c.password {
                n += str_len(pw);
            }
            n
        }
        Packet::ConnAck(_) => 2,
        Packet::Publish(p) => {
            str_len(p.topic.as_bytes())
                + if p.qos == QoS::AtMostOnce { 0 } else { 2 }
                + p.payload.len()
        }
        Packet::PubAck(_)
        | Packet::PubRec(_)
        | Packet::PubRel(_)
        | Packet::PubComp(_)
        | Packet::UnsubAck(_) => 2,
        Packet::Subscribe(s) => {
            2 + s
                .topics
                .iter()
                .map(|(f, _)| str_len(f.as_bytes()) + 1)
                .sum::<usize>()
        }
        Packet::SubAck(s) => 2 + s.return_codes.len(),
        Packet::Unsubscribe(u) => {
            2 + u
                .topics
                .iter()
                .map(|f| str_len(f.as_bytes()))
                .sum::<usize>()
        }
        Packet::PingReq | Packet::PingResp | Packet::Disconnect => 0,
    }
}

const fn varint_len(v: usize) -> usize {
    match v {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

/// Total encoded size of `p`.
pub fn encoded_len(p: &Packet<'_>) -> usize {
    let body = body_len(p);
    1 + varint_len(body) + body
}

fn first_byte(p: &Packet<'_>) -> u8 {
    match p {
        Packet::Connect(_) => 0x10,
        Packet::ConnAck(_) => 0x20,
        Packet::Publish(p) => {
            0x30 | (u8::from(p.dup) << 3) | ((p.qos as u8) << 1) | u8::from(p.retain)
        }
        Packet::PubAck(_) => 0x40,
        Packet::PubRec(_) => 0x50,
        Packet::PubRel(_) => 0x62,
        Packet::PubComp(_) => 0x70,
        Packet::Subscribe(_) => 0x82,
        Packet::SubAck(_) => 0x90,
        Packet::Unsubscribe(_) => 0xa2,
        Packet::UnsubAck(_) => 0xb0,
        Packet::PingReq => 0xc0,
        Packet::PingResp => 0xd0,
        Packet::Disconnect => 0xe0,
    }
}

/// Encodes `p` into `out`; returns the number of bytes written.
pub fn encode(p: &Packet<'_>, out: &mut [u8]) -> Result<usize, EncodeError> {
    let body = body_len(p);
    if body > MAX_REMAINING_LENGTH as usize {
        return Err(EncodeError::TooLarge);
    }
    let mut w = Writer { out, pos: 0 };
    w.u8(first_byte(p))?;
    w.varint(body as u32)?;
    match p {
        Packet::Connect(c) => {
            w.binary(b"MQTT")?;
            w.u8(c.protocol_level)?;
            let mut flags = 0u8;
            if c.clean_session {
                flags |= 0x02;
            }
            if let Some(will) = &c.will {
                flags |= 0x04 | ((will.qos as u8) << 3);
                if will.retain {
                    flags |= 0x20;
                }
            }
            if c.password.is_some() {
                flags |= 0x40;
            }
            if c.username.is_some() {
                flags |= 0x80;
            }
            w.u8(flags)?;
            w.u16(c.keep_alive)?;
            w.binary(c.client_id.as_bytes())?;
            if let Some(will) = &c.will {
                w.binary(will.topic.as_bytes())?;
                w.binary(will.payload)?;
            }
            if let Some(u) = c.username {
                w.binary(u.as_bytes())?;
            }
            if let Some(pw) = c.password {
                w.binary(pw)?;
            }
        }
        Packet::ConnAck(a) => {
            w.u8(u8::from(a.session_present))?;
            w.u8(a.code as u8)?;
        }
        Packet::Publish(pb) => {
            w.binary(pb.topic.as_bytes())?;
            match (pb.qos, pb.packet_id) {
                (QoS::AtMostOnce, None) => {}
                (QoS::AtMostOnce, Some(_)) | (_, None) => {
                    return Err(EncodeError::InconsistentPacketId);
                }
                (_, Some(id)) => w.u16(id)?,
            }
            w.bytes(pb.payload)?;
        }
        Packet::PubAck(id)
        | Packet::PubRec(id)
        | Packet::PubRel(id)
        | Packet::PubComp(id)
        | Packet::UnsubAck(id) => w.u16(*id)?,
        Packet::Subscribe(s) => {
            w.u16(s.packet_id)?;
            for (f, q) in s.topics.iter() {
                w.binary(f.as_bytes())?;
                w.u8(q as u8)?;
            }
        }
        Packet::SubAck(s) => {
            w.u16(s.packet_id)?;
            w.bytes(s.return_codes)?;
        }
        Packet::Unsubscribe(u) => {
            w.u16(u.packet_id)?;
            for f in u.topics.iter() {
                w.binary(f.as_bytes())?;
            }
        }
        Packet::PingReq | Packet::PingResp | Packet::Disconnect => {}
    }
    Ok(w.pos)
}
