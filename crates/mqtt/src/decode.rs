//! Streaming, zero-copy decoder.

use crate::validate::{topic_filter, topic_name, utf8};
use crate::{
    ConnAck, Connect, ConnectReturnCode, Error, Limits, PROTOCOL_LEVEL_3_1_1, Packet, Publish, QoS,
    SUBACK_FAILURE, SubAck, Subscribe, SubscribeTopics, Unsubscribe, UnsubscribeTopics, Will,
};

/// Cursor over a packet body; every read is bounds-checked.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedPacket)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::MalformedPacket)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        self.bytes(1)?
            .first()
            .copied()
            .ok_or(Error::MalformedPacket)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?;
        match b {
            [h, l] => Ok(u16::from_be_bytes([*h, *l])),
            _ => Err(Error::MalformedPacket),
        }
    }

    /// Length-prefixed binary data (§1.5.3).
    fn binary(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        s
    }

    fn packet_id(&mut self) -> Result<u16, Error> {
        match self.u16()? {
            0 => Err(Error::ZeroPacketId),
            id => Ok(id),
        }
    }

    fn finish(&self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::MalformedPacket)
        }
    }
}

/// Decodes the remaining length varint starting at `buf[1]`.
/// Returns (value, bytes used by the varint).
fn remaining_length(buf: &[u8]) -> Result<(u32, usize), Error> {
    let mut value = 0u32;
    for i in 0..4 {
        let Some(&b) = buf.get(1 + i) else {
            return Err(Error::Incomplete(2 + i));
        };
        value |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            // Reject non-minimal encodings (trailing zero groups).
            if i > 0 && b == 0 {
                return Err(Error::MalformedRemainingLength);
            }
            return Ok((value, i + 1));
        }
    }
    Err(Error::MalformedRemainingLength)
}

/// Decodes one packet from the start of `buf`. Returns the packet and the
/// number of bytes it occupied.
pub fn decode<'a>(buf: &'a [u8], limits: &Limits) -> Result<(Packet<'a>, usize), Error> {
    let Some(&first) = buf.first() else {
        return Err(Error::Incomplete(2));
    };
    let ptype = first >> 4;
    let flags = first & 0x0f;
    if ptype == 0 || ptype == 15 {
        return Err(Error::InvalidPacketType(ptype));
    }
    let (rem, varint) = remaining_length(buf)?;
    let total = 1 + varint + rem as usize;
    if total as u64 > u64::from(limits.max_packet_size) {
        return Err(Error::PacketTooLarge);
    }
    let Some(body) = buf.get(1 + varint..total) else {
        return Err(Error::Incomplete(total));
    };
    let expect_flags = |want: u8| {
        if flags == want {
            Ok(())
        } else {
            Err(Error::InvalidFixedHeaderFlags)
        }
    };
    let mut r = Reader::new(body);
    let packet = match ptype {
        1 => {
            expect_flags(0)?;
            Packet::Connect(connect(&mut r, limits)?)
        }
        2 => {
            expect_flags(0)?;
            let ack_flags = r.u8()?;
            if ack_flags & 0xfe != 0 {
                return Err(Error::MalformedPacket);
            }
            let code = ConnectReturnCode::from_u8(r.u8()?).ok_or(Error::InvalidReturnCode)?;
            r.finish()?;
            Packet::ConnAck(ConnAck {
                session_present: ack_flags & 1 != 0,
                code,
            })
        }
        3 => Packet::Publish(publish(flags, &mut r, limits)?),
        4 | 5 | 7 | 11 => {
            expect_flags(0)?;
            let id = r.packet_id()?;
            r.finish()?;
            match ptype {
                4 => Packet::PubAck(id),
                5 => Packet::PubRec(id),
                7 => Packet::PubComp(id),
                _ => Packet::UnsubAck(id),
            }
        }
        6 => {
            expect_flags(0b0010)?;
            let id = r.packet_id()?;
            r.finish()?;
            Packet::PubRel(id)
        }
        8 => {
            expect_flags(0b0010)?;
            let packet_id = r.packet_id()?;
            let raw = r.rest();
            let mut n = 0u32;
            for t in RawTopics::new(raw) {
                let (f, opts) = t?;
                topic_filter(f.as_bytes(), limits)?;
                if opts & 0xfc != 0 || QoS::from_bits(opts).is_none() {
                    return Err(Error::InvalidQos);
                }
                n += 1;
            }
            check_topic_count(n, limits)?;
            Packet::Subscribe(Subscribe {
                packet_id,
                topics: SubscribeTopics::Raw(raw),
            })
        }
        9 => {
            expect_flags(0)?;
            let packet_id = r.packet_id()?;
            let return_codes = r.rest();
            if return_codes.is_empty() || return_codes.iter().any(|&c| c > 2 && c != SUBACK_FAILURE)
            {
                return Err(Error::InvalidReturnCode);
            }
            Packet::SubAck(SubAck {
                packet_id,
                return_codes,
            })
        }
        10 => {
            expect_flags(0b0010)?;
            let packet_id = r.packet_id()?;
            let raw = r.rest();
            let mut n = 0u32;
            for t in RawStrings::new(raw) {
                topic_filter(t?.as_bytes(), limits)?;
                n += 1;
            }
            check_topic_count(n, limits)?;
            Packet::Unsubscribe(Unsubscribe {
                packet_id,
                topics: UnsubscribeTopics::Raw(raw),
            })
        }
        12..=14 => {
            expect_flags(0)?;
            r.finish()?;
            match ptype {
                12 => Packet::PingReq,
                13 => Packet::PingResp,
                _ => Packet::Disconnect,
            }
        }
        other => return Err(Error::InvalidPacketType(other)),
    };
    Ok((packet, total))
}

fn check_topic_count(n: u32, limits: &Limits) -> Result<(), Error> {
    if n == 0 {
        return Err(Error::EmptySubscription);
    }
    if n > u32::from(limits.max_topics_per_packet) {
        return Err(Error::TooManyTopics);
    }
    Ok(())
}

fn connect<'a>(r: &mut Reader<'a>, limits: &Limits) -> Result<Connect<'a>, Error> {
    let name = r.binary()?;
    if name != b"MQTT" {
        return Err(if name == b"MQIsdp" {
            // MQTT 3.1: well-formed but unsupported; answer CONNACK 0x01.
            Error::UnsupportedProtocolLevel(r.u8().unwrap_or(3))
        } else {
            Error::InvalidProtocolName
        });
    }
    let level = r.u8()?;
    if level != PROTOCOL_LEVEL_3_1_1 {
        return Err(Error::UnsupportedProtocolLevel(level));
    }
    let f = r.u8()?;
    let reserved = f & 0x01 != 0;
    let clean_session = f & 0x02 != 0;
    let will_flag = f & 0x04 != 0;
    let will_qos = (f >> 3) & 0x03;
    let will_retain = f & 0x20 != 0;
    let password_flag = f & 0x40 != 0;
    let username_flag = f & 0x80 != 0;
    if reserved
        || (!will_flag && (will_qos != 0 || will_retain))
        || (password_flag && !username_flag)
    {
        return Err(Error::InvalidConnectFlags);
    }
    let will_qos = QoS::from_bits(will_qos).ok_or(Error::InvalidQos)?;
    let keep_alive = r.u16()?;
    let client_id = utf8(r.binary()?)?;
    if client_id.len() > usize::from(limits.max_client_id_len) {
        return Err(Error::ClientIdTooLong);
    }
    let will = if will_flag {
        let topic = topic_name(r.binary()?, limits)?;
        let payload = r.binary()?;
        Some(Will {
            topic,
            payload,
            qos: will_qos,
            retain: will_retain,
        })
    } else {
        None
    };
    let username = if username_flag {
        Some(utf8(r.binary()?)?)
    } else {
        None
    };
    let password = if password_flag {
        Some(r.binary()?)
    } else {
        None
    };
    r.finish()?;
    Ok(Connect {
        protocol_level: level,
        clean_session,
        keep_alive,
        client_id,
        will,
        username,
        password,
    })
}

fn publish<'a>(flags: u8, r: &mut Reader<'a>, limits: &Limits) -> Result<Publish<'a>, Error> {
    let dup = flags & 0x08 != 0;
    let qos = QoS::from_bits((flags >> 1) & 0x03).ok_or(Error::InvalidQos)?;
    let retain = flags & 0x01 != 0;
    if dup && qos == QoS::AtMostOnce {
        return Err(Error::InvalidFixedHeaderFlags);
    }
    let topic = topic_name(r.binary()?, limits)?;
    let packet_id = if qos == QoS::AtMostOnce {
        None
    } else {
        Some(r.packet_id()?)
    };
    Ok(Publish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        payload: r.rest(),
    })
}

/// Iterates (filter, options byte) pairs of a SUBSCRIBE payload.
pub(crate) struct RawTopics<'a>(Reader<'a>);

impl<'a> RawTopics<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self(Reader::new(raw))
    }
}

impl<'a> Iterator for RawTopics<'a> {
    type Item = Result<(&'a str, u8), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            return None;
        }
        let item = (|| {
            let f = utf8(self.0.binary()?)?;
            let opts = self.0.u8()?;
            Ok((f, opts))
        })();
        if item.is_err() {
            // Stop after the first error.
            self.0.pos = self.0.buf.len();
        }
        Some(item)
    }
}

/// Iterates the strings of an UNSUBSCRIBE payload.
pub(crate) struct RawStrings<'a>(Reader<'a>);

impl<'a> RawStrings<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self(Reader::new(raw))
    }
}

impl<'a> Iterator for RawStrings<'a> {
    type Item = Result<&'a str, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            return None;
        }
        let item = self.0.binary().and_then(utf8);
        if item.is_err() {
            self.0.pos = self.0.buf.len();
        }
        Some(item)
    }
}
