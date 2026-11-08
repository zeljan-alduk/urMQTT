//! Streaming, zero-copy MQTT 5.0 decoder.

use super::props::validate_properties;
use super::{
    Ack, Auth, ConnAck, Connect, Disconnect, Error, Limits, MAX_VARINT, PROTOCOL_LEVEL_5, Packet,
    Properties, PropertyContext, PropertyId, Publish, QoS, ReasonCode, ReasonTable, SubAck,
    Subscribe, SubscribeTopics, SubscriptionOptions, UnsubAck, Unsubscribe, UnsubscribeTopics,
    Will,
};
use crate::validate;

/// The 3.1.1 string rule (§1.5.4): valid UTF-8 (so no surrogates), no
/// U+0000; the length prefix bounds it to 65 535 bytes.
pub(crate) fn utf8(bytes: &[u8]) -> Result<&str, Error> {
    Ok(validate::utf8(bytes)?)
}

/// Decodes a Variable Byte Integer (§1.5.5) at the start of `buf`: at most
/// 4 bytes, minimal. Returns (value, bytes used). Truncated, too long or
/// non-minimal input is [`Error::MalformedVarint`].
pub fn read_varint(buf: &[u8]) -> Result<(u32, usize), Error> {
    let mut value = 0u32;
    for i in 0..4 {
        let Some(&b) = buf.get(i) else {
            return Err(Error::MalformedVarint);
        };
        value |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return Err(Error::MalformedVarint);
            }
            return Ok((value, i + 1));
        }
    }
    Err(Error::MalformedVarint)
}

/// The Remaining Length at `buf[1..]`, with the streaming contract: a
/// truncated varint asks for one more byte.
fn remaining_length(buf: &[u8]) -> Result<(u32, usize), Error> {
    let tail = buf.get(1..).unwrap_or(&[]);
    match read_varint(tail) {
        Ok(v) => Ok(v),
        // Truncated if every byte present so far has the continuation bit.
        Err(_) if tail.len() < 4 && tail.iter().all(|b| b & 0x80 != 0) => {
            Err(Error::Incomplete(tail.len() + 2))
        }
        Err(_) => Err(Error::MalformedRemainingLength),
    }
}

/// Cursor over a packet body; every read is bounds-checked.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn skip_to_end(&mut self) {
        self.pos = self.buf.len();
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedPacket)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::MalformedPacket)?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        match self.bytes(1)? {
            [b] => Ok(*b),
            _ => Err(Error::MalformedPacket),
        }
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        match self.bytes(2)? {
            [h, l] => Ok(u16::from_be_bytes([*h, *l])),
            _ => Err(Error::MalformedPacket),
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        match self.bytes(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Error::MalformedPacket),
        }
    }

    pub(crate) fn varint(&mut self) -> Result<u32, Error> {
        let (v, n) = read_varint(self.buf.get(self.pos..).unwrap_or(&[]))?;
        self.pos += n;
        Ok(v)
    }

    /// Binary Data (§1.5.6).
    pub(crate) fn binary(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }

    /// UTF-8 Encoded String (§1.5.4).
    pub(crate) fn string(&mut self) -> Result<&'a str, Error> {
        utf8(self.binary()?)
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

    /// Property Length and the block (§2.2.2.1), validated for `ctx`.
    fn properties(
        &mut self,
        ctx: PropertyContext,
        limits: &Limits,
    ) -> Result<Properties<'a>, Error> {
        let len = self.varint()?;
        let raw = self.bytes(len as usize)?;
        validate_properties(raw, ctx, limits)?;
        Ok(Properties::Raw(raw))
    }

    fn reason(&mut self, table: ReasonTable) -> Result<ReasonCode, Error> {
        let b = self.u8()?;
        ReasonCode::for_packet(b, table).ok_or(Error::InvalidReasonCode(b))
    }

    fn finish(&self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::MalformedPacket)
        }
    }
}

/// The protocol level of the CONNECT at the start of `buf`, to choose
/// between the 3.1.1 decoder and this one (ADR-273 §1). Needs only the
/// fixed header, the protocol name and the level byte; asks for more with
/// [`Error::Incomplete`] like [`decode`]. Not a CONNECT, or a protocol name
/// other than `MQTT` (or 3.1's `MQIsdp`), is an error.
pub fn connect_protocol_level(buf: &[u8]) -> Result<u8, Error> {
    let Some(&first) = buf.first() else {
        return Err(Error::Incomplete(2));
    };
    if first >> 4 != 1 {
        return Err(Error::InvalidPacketType(first >> 4));
    }
    if first & 0x0f != 0 {
        return Err(Error::InvalidFixedHeaderFlags);
    }
    let (rem, varint) = remaining_length(buf)?;
    let start = 1 + varint;
    let body_end = start + rem as usize;
    let need = |n: usize| -> Result<(), Error> {
        if n > body_end {
            Err(Error::MalformedPacket)
        } else if n > buf.len() {
            Err(Error::Incomplete(n))
        } else {
            Ok(())
        }
    };
    need(start + 2)?;
    let len = match buf.get(start..start + 2) {
        Some(&[h, l]) => usize::from(u16::from_be_bytes([h, l])),
        _ => return Err(Error::MalformedPacket),
    };
    need(start + 2 + len + 1)?;
    let name = buf.get(start + 2..start + 2 + len).unwrap_or(&[]);
    if name != b"MQTT" && name != b"MQIsdp" {
        return Err(Error::InvalidProtocolName);
    }
    buf.get(start + 2 + len)
        .copied()
        .ok_or(Error::MalformedPacket)
}

/// Splits a shared subscription `$share/{ShareName}/{filter}` (§4.8.2).
/// `None` if `f` does not start with `$share/` or is not well formed: the
/// share name must be non-empty without `+` or `#`, the filter non-empty.
pub fn split_shared(f: &str) -> Option<(&str, &str)> {
    let rest = f.strip_prefix("$share/")?;
    let (name, filter) = rest.split_once('/')?;
    if name.is_empty() || name.contains(['+', '#']) || filter.is_empty() {
        return None;
    }
    Some((name, filter))
}

/// A topic filter of SUBSCRIBE/UNSUBSCRIBE: the 3.1.1 rules and limits,
/// and a well-formed `$share/` prefix. Returns whether it is shared.
fn filter(bytes: &[u8], limits: &Limits) -> Result<bool, Error> {
    let f = validate::topic_filter(bytes, &limits.base)?;
    if f.starts_with("$share/") {
        if split_shared(f).is_none() {
            return Err(Error::InvalidTopicFilter);
        }
        return Ok(true);
    }
    Ok(false)
}

/// Decodes one packet from the start of `buf`. Returns the packet and the
/// number of bytes it occupied.
pub fn decode<'a>(buf: &'a [u8], limits: &Limits) -> Result<(Packet<'a>, usize), Error> {
    let Some(&first) = buf.first() else {
        return Err(Error::Incomplete(2));
    };
    let ptype = first >> 4;
    let flags = first & 0x0f;
    if ptype == 0 {
        return Err(Error::InvalidPacketType(ptype));
    }
    let (rem, varint) = remaining_length(buf)?;
    let total = 1 + varint + rem as usize;
    if total as u64 > u64::from(limits.base.max_packet_size) {
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
            let session_present = ack_flags & 1 != 0;
            let reason = r.reason(ReasonTable::ConnAck)?;
            if session_present && reason != ReasonCode::Success {
                return Err(Error::SessionPresentWithError);
            }
            let properties = r.properties(PropertyContext::ConnAck, limits)?;
            r.finish()?;
            Packet::ConnAck(ConnAck {
                session_present,
                reason,
                properties,
            })
        }
        3 => Packet::Publish(publish(flags, &mut r, limits)?),
        4..=7 => {
            let (table, ctx) = match ptype {
                4 => (ReasonTable::PubAck, PropertyContext::PubAck),
                5 => (ReasonTable::PubRec, PropertyContext::PubRec),
                6 => (ReasonTable::PubRel, PropertyContext::PubRel),
                _ => (ReasonTable::PubComp, PropertyContext::PubComp),
            };
            expect_flags(if ptype == 6 { 0b0010 } else { 0 })?;
            let packet_id = r.packet_id()?;
            // §3.4.2.1: Remaining Length 2 means 0x00 and no properties,
            // 3 means no properties.
            let reason = if r.remaining() == 0 {
                ReasonCode::Success
            } else {
                r.reason(table)?
            };
            let properties = if r.remaining() == 0 {
                Properties::EMPTY
            } else {
                r.properties(ctx, limits)?
            };
            r.finish()?;
            let ack = Ack {
                packet_id,
                reason,
                properties,
            };
            match ptype {
                4 => Packet::PubAck(ack),
                5 => Packet::PubRec(ack),
                6 => Packet::PubRel(ack),
                _ => Packet::PubComp(ack),
            }
        }
        8 => {
            expect_flags(0b0010)?;
            let packet_id = r.packet_id()?;
            let properties = r.properties(PropertyContext::Subscribe, limits)?;
            let raw = r.rest();
            let mut n = 0u32;
            for t in RawPairs::new(raw) {
                let (f, opts) = t?;
                let shared = filter(f.as_bytes(), limits)?;
                let opts = SubscriptionOptions::from_byte(opts)?;
                if shared && opts.no_local {
                    return Err(Error::SharedNoLocal);
                }
                n += 1;
            }
            check_topic_count(n, limits)?;
            Packet::Subscribe(Subscribe {
                packet_id,
                properties,
                topics: SubscribeTopics::Raw(raw),
            })
        }
        9 | 11 => {
            expect_flags(0)?;
            let (table, ctx) = if ptype == 9 {
                (ReasonTable::SubAck, PropertyContext::SubAck)
            } else {
                (ReasonTable::UnsubAck, PropertyContext::UnsubAck)
            };
            let packet_id = r.packet_id()?;
            let properties = r.properties(ctx, limits)?;
            let reason_codes = r.rest();
            if reason_codes.is_empty() {
                return Err(Error::MalformedPacket);
            }
            if let Some(&c) = reason_codes
                .iter()
                .find(|&&c| ReasonCode::for_packet(c, table).is_none())
            {
                return Err(Error::InvalidReasonCode(c));
            }
            if ptype == 9 {
                Packet::SubAck(SubAck {
                    packet_id,
                    properties,
                    reason_codes,
                })
            } else {
                Packet::UnsubAck(UnsubAck {
                    packet_id,
                    properties,
                    reason_codes,
                })
            }
        }
        10 => {
            expect_flags(0b0010)?;
            let packet_id = r.packet_id()?;
            let properties = r.properties(PropertyContext::Unsubscribe, limits)?;
            let raw = r.rest();
            let mut n = 0u32;
            for t in RawStrings::new(raw) {
                filter(t?.as_bytes(), limits)?;
                n += 1;
            }
            check_topic_count(n, limits)?;
            Packet::Unsubscribe(Unsubscribe {
                packet_id,
                properties,
                topics: UnsubscribeTopics::Raw(raw),
            })
        }
        12 | 13 => {
            expect_flags(0)?;
            r.finish()?;
            if ptype == 12 {
                Packet::PingReq
            } else {
                Packet::PingResp
            }
        }
        14 => {
            expect_flags(0)?;
            // §3.14.2.1: Remaining Length 0 means 0x00; 1 means no properties.
            let reason = if r.remaining() == 0 {
                ReasonCode::Success
            } else {
                r.reason(ReasonTable::Disconnect)?
            };
            let properties = if r.remaining() == 0 {
                Properties::EMPTY
            } else {
                r.properties(PropertyContext::Disconnect, limits)?
            };
            r.finish()?;
            Packet::Disconnect(Disconnect { reason, properties })
        }
        15 => {
            expect_flags(0)?;
            // §3.15.2.1: Remaining Length 0 means 0x00 and no properties;
            // otherwise both are present and the Authentication Method is
            // required (§3.15.2.2.2).
            if r.remaining() == 0 {
                Packet::Auth(Auth {
                    reason: ReasonCode::Success,
                    properties: Properties::EMPTY,
                })
            } else {
                let reason = r.reason(ReasonTable::Auth)?;
                let properties = r.properties(PropertyContext::Auth, limits)?;
                r.finish()?;
                if properties.authentication_method().is_none() {
                    return Err(Error::MissingAuthenticationMethod);
                }
                Packet::Auth(Auth { reason, properties })
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
    if n > u32::from(limits.base.max_topics_per_packet) {
        return Err(Error::TooManyTopics);
    }
    Ok(())
}

fn connect<'a>(r: &mut Reader<'a>, limits: &Limits) -> Result<Connect<'a>, Error> {
    let name = r.binary()?;
    if name != b"MQTT" {
        return Err(if name == b"MQIsdp" {
            Error::UnsupportedProtocolLevel(r.u8().unwrap_or(3))
        } else {
            Error::InvalidProtocolName
        });
    }
    let level = r.u8()?;
    if level != PROTOCOL_LEVEL_5 {
        return Err(Error::UnsupportedProtocolLevel(level));
    }
    // §3.1.2.3. Unlike 3.1.1, a password without a user name is allowed.
    let f = r.u8()?;
    let reserved = f & 0x01 != 0;
    let clean_start = f & 0x02 != 0;
    let will_flag = f & 0x04 != 0;
    let will_qos = (f >> 3) & 0x03;
    let will_retain = f & 0x20 != 0;
    let password_flag = f & 0x40 != 0;
    let username_flag = f & 0x80 != 0;
    if reserved || (!will_flag && (will_qos != 0 || will_retain)) {
        return Err(Error::InvalidConnectFlags);
    }
    let will_qos = QoS::from_bits(will_qos).ok_or(Error::InvalidQos)?;
    let keep_alive = r.u16()?;
    let properties = r.properties(PropertyContext::Connect, limits)?;
    let client_id = r.string()?;
    if client_id.len() > usize::from(limits.base.max_client_id_len) {
        return Err(Error::ClientIdTooLong);
    }
    let will = if will_flag {
        let properties = r.properties(PropertyContext::Will, limits)?;
        let topic = validate::topic_name(r.binary()?, &limits.base)?;
        let payload = r.binary()?;
        Some(Will {
            properties,
            topic,
            payload,
            qos: will_qos,
            retain: will_retain,
        })
    } else {
        None
    };
    let username = if username_flag {
        Some(r.string()?)
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
        clean_start,
        keep_alive,
        properties,
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
    let topic_bytes = r.binary()?;
    // An empty Topic Name needs a Topic Alias (checked below, §3.3.2.1).
    let topic = if topic_bytes.is_empty() {
        ""
    } else {
        validate::topic_name(topic_bytes, &limits.base)?
    };
    let packet_id = if qos == QoS::AtMostOnce {
        None
    } else {
        Some(r.packet_id()?)
    };
    let properties = r.properties(PropertyContext::Publish, limits)?;
    if topic.is_empty() && properties.get(PropertyId::TopicAlias).is_none() {
        return Err(Error::InvalidTopicName);
    }
    Ok(Publish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        properties,
        payload: r.rest(),
    })
}

/// Iterates (filter, options byte) pairs of a SUBSCRIBE payload.
pub(crate) struct RawPairs<'a>(Reader<'a>);

impl<'a> RawPairs<'a> {
    pub(crate) const fn new(raw: &'a [u8]) -> Self {
        Self(Reader::new(raw))
    }
}

impl<'a> Iterator for RawPairs<'a> {
    type Item = Result<(&'a str, u8), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            return None;
        }
        let item = self.0.string().and_then(|f| Ok((f, self.0.u8()?)));
        if item.is_err() {
            self.0.skip_to_end();
        }
        Some(item)
    }
}

/// Iterates the strings of an UNSUBSCRIBE payload.
pub(crate) struct RawStrings<'a>(Reader<'a>);

impl<'a> RawStrings<'a> {
    pub(crate) const fn new(raw: &'a [u8]) -> Self {
        Self(Reader::new(raw))
    }
}

impl<'a> Iterator for RawStrings<'a> {
    type Item = Result<&'a str, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            return None;
        }
        let item = self.0.string();
        if item.is_err() {
            self.0.skip_to_end();
        }
        Some(item)
    }
}

const _: () = assert!(MAX_VARINT == 0x0fff_ffff);
