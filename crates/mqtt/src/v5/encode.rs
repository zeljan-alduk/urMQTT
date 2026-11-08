//! MQTT 5.0 encoder into caller-provided buffers (no allocation).
//!
//! Every rule the decoder checks on one packet is checked here too, so
//! `encode` either refuses or writes bytes that [`super::decode`] accepts
//! (under [`Limits::PROTOCOL_MAX`]) and that decode to an equal packet.
//! Property blocks are checked by running the decoder's validator over the
//! bytes just written.

use super::decode::split_shared;
use super::props::validate_properties;
use super::{
    Ack, Error, Limits, MAX_VARINT, Packet, Properties, Property, PropertyContext, PropertyId, QoS,
    ReasonCode, ReasonTable,
};
use crate::validate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall,
    /// A field exceeds what MQTT can represent (string or binary > 65 535
    /// bytes, packet or property block > 268 435 455 bytes).
    TooLarge,
    /// QoS > 0 PUBLISH without a packet id, or the reverse.
    InconsistentPacketId,
    /// The packet breaks a rule the decoder enforces (the decoder's error).
    Invalid(Error),
}

impl From<Error> for EncodeError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}

/// Bytes a Variable Byte Integer takes (values above the maximum count 4;
/// [`write_varint`] refuses them).
pub const fn varint_len(v: u32) -> usize {
    match v {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

/// Writes `v` as a minimal Variable Byte Integer; returns the bytes used.
pub fn write_varint(mut v: u32, out: &mut [u8]) -> Result<usize, EncodeError> {
    if v > MAX_VARINT {
        return Err(EncodeError::TooLarge);
    }
    let mut n = 0;
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        *out.get_mut(n).ok_or(EncodeError::BufferTooSmall)? = b;
        n += 1;
        if v == 0 {
            return Ok(n);
        }
    }
}

struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .pos
            .checked_add(b.len())
            .ok_or(EncodeError::BufferTooSmall)?;
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

    fn u32(&mut self, v: u32) -> Result<(), EncodeError> {
        self.bytes(&v.to_be_bytes())
    }

    fn varint(&mut self, v: u32) -> Result<(), EncodeError> {
        let n = write_varint(v, self.out.get_mut(self.pos..).unwrap_or(&mut []))?;
        self.pos += n;
        Ok(())
    }

    fn binary(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let n = u16::try_from(b.len()).map_err(|_| EncodeError::TooLarge)?;
        self.u16(n)?;
        self.bytes(b)
    }

    fn property(&mut self, p: &Property<'_>) -> Result<(), EncodeError> {
        self.u8(p.id() as u8)?;
        match *p {
            Property::PayloadFormatIndicator(v)
            | Property::RequestProblemInformation(v)
            | Property::RequestResponseInformation(v)
            | Property::MaximumQos(v)
            | Property::RetainAvailable(v)
            | Property::WildcardSubscriptionAvailable(v)
            | Property::SubscriptionIdentifierAvailable(v)
            | Property::SharedSubscriptionAvailable(v) => self.u8(v),
            Property::ServerKeepAlive(v)
            | Property::ReceiveMaximum(v)
            | Property::TopicAliasMaximum(v)
            | Property::TopicAlias(v) => self.u16(v),
            Property::MessageExpiryInterval(v)
            | Property::SessionExpiryInterval(v)
            | Property::WillDelayInterval(v)
            | Property::MaximumPacketSize(v) => self.u32(v),
            Property::SubscriptionIdentifier(v) => self.varint(v),
            Property::ContentType(s)
            | Property::ResponseTopic(s)
            | Property::AssignedClientIdentifier(s)
            | Property::AuthenticationMethod(s)
            | Property::ResponseInformation(s)
            | Property::ServerReference(s)
            | Property::ReasonString(s) => self.binary(s.as_bytes()),
            Property::CorrelationData(b) | Property::AuthenticationData(b) => self.binary(b),
            Property::UserProperty(k, v) => {
                self.binary(k.as_bytes())?;
                self.binary(v.as_bytes())
            }
        }
    }

    /// Property Length and block, then the decoder's check of what was
    /// written.
    fn properties(&mut self, p: &Properties<'_>, ctx: PropertyContext) -> Result<(), EncodeError> {
        self.varint(props_len(p)?)?;
        let start = self.pos;
        match *p {
            Properties::Raw(raw) => self.bytes(raw)?,
            _ => {
                for q in p.iter() {
                    self.property(&q)?;
                }
            }
        }
        let written = self.out.get(start..self.pos).unwrap_or(&[]);
        validate_properties(written, ctx, &Limits::PROTOCOL_MAX)?;
        Ok(())
    }
}

fn props_len(p: &Properties<'_>) -> Result<u32, EncodeError> {
    u32::try_from(p.encoded_len())
        .ok()
        .filter(|&n| n <= MAX_VARINT)
        .ok_or(EncodeError::TooLarge)
}

/// Property Length plus the block.
fn props_block(p: &Properties<'_>) -> Result<usize, EncodeError> {
    let n = props_len(p)?;
    Ok(varint_len(n) + n as usize)
}

fn str_len(s: &[u8]) -> Result<usize, EncodeError> {
    if s.len() > usize::from(u16::MAX) {
        return Err(EncodeError::TooLarge);
    }
    Ok(2 + s.len())
}

struct Sum(Result<usize, EncodeError>);

impl Sum {
    fn add(self, n: Result<usize, EncodeError>) -> Self {
        Self(
            self.0
                .and_then(|a| n.and_then(|b| a.checked_add(b).ok_or(EncodeError::TooLarge))),
        )
    }
}

/// Form of an acknowledgement: 0 = no reason and no properties, 1 = reason
/// only, 2 = both (the shortest form that keeps the values).
fn ack_form(reason: ReasonCode, p: &Properties<'_>) -> u8 {
    match (reason == ReasonCode::Success, p.encoded_len() == 0) {
        (true, true) => 0,
        (_, true) => 1,
        _ => 2,
    }
}

/// Remaining length (body size) of `p`.
fn body_len(p: &Packet<'_>) -> Result<usize, EncodeError> {
    let s = Sum(Ok(0));
    let s = match p {
        Packet::Connect(c) => {
            let mut s = s
                .add(Ok(6 + 1 + 1 + 2))
                .add(props_block(&c.properties))
                .add(str_len(c.client_id.as_bytes()));
            if let Some(w) = &c.will {
                s = s
                    .add(props_block(&w.properties))
                    .add(str_len(w.topic.as_bytes()))
                    .add(str_len(w.payload));
            }
            if let Some(u) = c.username {
                s = s.add(str_len(u.as_bytes()));
            }
            if let Some(pw) = c.password {
                s = s.add(str_len(pw));
            }
            s
        }
        Packet::ConnAck(a) => s.add(Ok(2)).add(props_block(&a.properties)),
        Packet::Publish(pb) => s
            .add(str_len(pb.topic.as_bytes()))
            .add(Ok(if pb.qos == QoS::AtMostOnce { 0 } else { 2 }))
            .add(props_block(&pb.properties))
            .add(Ok(pb.payload.len())),
        Packet::PubAck(a) | Packet::PubRec(a) | Packet::PubRel(a) | Packet::PubComp(a) => {
            match ack_form(a.reason, &a.properties) {
                0 => s.add(Ok(2)),
                1 => s.add(Ok(3)),
                _ => s.add(Ok(3)).add(props_block(&a.properties)),
            }
        }
        Packet::Subscribe(sb) => sb.topics.iter().fold(
            s.add(Ok(2)).add(props_block(&sb.properties)),
            |s, (f, _)| s.add(str_len(f.as_bytes())).add(Ok(1)),
        ),
        Packet::SubAck(a) => s
            .add(Ok(2))
            .add(props_block(&a.properties))
            .add(Ok(a.reason_codes.len())),
        Packet::UnsubAck(a) => s
            .add(Ok(2))
            .add(props_block(&a.properties))
            .add(Ok(a.reason_codes.len())),
        Packet::Unsubscribe(u) => u
            .topics
            .iter()
            .fold(s.add(Ok(2)).add(props_block(&u.properties)), |s, f| {
                s.add(str_len(f.as_bytes()))
            }),
        Packet::PingReq | Packet::PingResp => s,
        Packet::Disconnect(d) => match ack_form(d.reason, &d.properties) {
            0 => s,
            1 => s.add(Ok(1)),
            _ => s.add(Ok(1)).add(props_block(&d.properties)),
        },
        Packet::Auth(a) => match ack_form(a.reason, &a.properties) {
            0 => s,
            _ => s.add(Ok(1)).add(props_block(&a.properties)),
        },
    };
    let n = s.0?;
    if n > MAX_VARINT as usize {
        return Err(EncodeError::TooLarge);
    }
    Ok(n)
}

/// Total encoded size of `p` (the size a peer's Maximum Packet Size is
/// compared with, §3.1.2.11.4).
pub fn encoded_len(p: &Packet<'_>) -> Result<usize, EncodeError> {
    let body = body_len(p)?;
    Ok(1 + varint_len(body as u32) + body)
}

fn first_byte(p: &Packet<'_>) -> u8 {
    let t = p.packet_type();
    let flags = match p {
        Packet::Publish(p) => (u8::from(p.dup) << 3) | ((p.qos as u8) << 1) | u8::from(p.retain),
        _ => t.fixed_flags(),
    };
    ((t as u8) << 4) | flags
}

fn nonzero(id: u16) -> Result<u16, EncodeError> {
    if id == 0 {
        Err(Error::ZeroPacketId.into())
    } else {
        Ok(id)
    }
}

fn reason(c: ReasonCode, table: ReasonTable) -> Result<u8, EncodeError> {
    if c.allowed_in(table) {
        Ok(c as u8)
    } else {
        Err(Error::InvalidReasonCode(c as u8).into())
    }
}

fn string(s: &str) -> Result<&[u8], EncodeError> {
    Ok(validate::utf8(s.as_bytes())
        .map_err(Error::from)?
        .as_bytes())
}

fn filter(f: &str) -> Result<bool, EncodeError> {
    validate::topic_filter(f.as_bytes(), &crate::Limits::PROTOCOL_MAX).map_err(Error::from)?;
    if f.starts_with("$share/") {
        if split_shared(f).is_none() {
            return Err(Error::InvalidTopicFilter.into());
        }
        return Ok(true);
    }
    Ok(false)
}

fn topic_count(n: usize) -> Result<(), EncodeError> {
    if n == 0 {
        return Err(Error::EmptySubscription.into());
    }
    if n > usize::from(u16::MAX) {
        return Err(Error::TooManyTopics.into());
    }
    Ok(())
}

fn codes(c: &[u8], table: ReasonTable) -> Result<(), EncodeError> {
    if c.is_empty() {
        return Err(Error::MalformedPacket.into());
    }
    match c
        .iter()
        .find(|&&b| ReasonCode::for_packet(b, table).is_none())
    {
        Some(&b) => Err(Error::InvalidReasonCode(b).into()),
        None => Ok(()),
    }
}

fn ack(
    w: &mut Writer<'_>,
    a: &Ack<'_>,
    table: ReasonTable,
    ctx: PropertyContext,
) -> Result<(), EncodeError> {
    w.u16(nonzero(a.packet_id)?)?;
    let form = ack_form(a.reason, &a.properties);
    if form >= 1 {
        w.u8(reason(a.reason, table)?)?;
    }
    if form == 2 {
        w.properties(&a.properties, ctx)?;
    }
    Ok(())
}

/// Encodes `p` into `out`; returns the number of bytes written.
pub fn encode(p: &Packet<'_>, out: &mut [u8]) -> Result<usize, EncodeError> {
    let body = body_len(p)?;
    let mut w = Writer { out, pos: 0 };
    w.u8(first_byte(p))?;
    w.varint(body as u32)?;
    let start = w.pos;
    match p {
        Packet::Connect(c) => {
            w.binary(b"MQTT")?;
            w.u8(super::PROTOCOL_LEVEL_5)?;
            let mut flags = 0u8;
            if c.clean_start {
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
            w.properties(&c.properties, PropertyContext::Connect)?;
            w.binary(string(c.client_id)?)?;
            if let Some(will) = &c.will {
                w.properties(&will.properties, PropertyContext::Will)?;
                let t = validate::topic_name(will.topic.as_bytes(), &crate::Limits::PROTOCOL_MAX)
                    .map_err(Error::from)?;
                w.binary(t.as_bytes())?;
                w.binary(will.payload)?;
            }
            if let Some(u) = c.username {
                w.binary(string(u)?)?;
            }
            if let Some(pw) = c.password {
                w.binary(pw)?;
            }
        }
        Packet::ConnAck(a) => {
            if a.session_present && a.reason != ReasonCode::Success {
                return Err(Error::SessionPresentWithError.into());
            }
            w.u8(u8::from(a.session_present))?;
            w.u8(reason(a.reason, ReasonTable::ConnAck)?)?;
            w.properties(&a.properties, PropertyContext::ConnAck)?;
        }
        Packet::Publish(pb) => {
            if pb.dup && pb.qos == QoS::AtMostOnce {
                return Err(Error::InvalidFixedHeaderFlags.into());
            }
            if pb.topic.is_empty() {
                if pb.properties.get(PropertyId::TopicAlias).is_none() {
                    return Err(Error::InvalidTopicName.into());
                }
            } else {
                validate::topic_name(pb.topic.as_bytes(), &crate::Limits::PROTOCOL_MAX)
                    .map_err(Error::from)?;
            }
            w.binary(pb.topic.as_bytes())?;
            match (pb.qos, pb.packet_id) {
                (QoS::AtMostOnce, None) => {}
                (QoS::AtMostOnce, Some(_)) | (_, None) => {
                    return Err(EncodeError::InconsistentPacketId);
                }
                (_, Some(id)) => w.u16(nonzero(id)?)?,
            }
            w.properties(&pb.properties, PropertyContext::Publish)?;
            w.bytes(pb.payload)?;
        }
        Packet::PubAck(a) => ack(&mut w, a, ReasonTable::PubAck, PropertyContext::PubAck)?,
        Packet::PubRec(a) => ack(&mut w, a, ReasonTable::PubRec, PropertyContext::PubRec)?,
        Packet::PubRel(a) => ack(&mut w, a, ReasonTable::PubRel, PropertyContext::PubRel)?,
        Packet::PubComp(a) => ack(&mut w, a, ReasonTable::PubComp, PropertyContext::PubComp)?,
        Packet::Subscribe(s) => {
            w.u16(nonzero(s.packet_id)?)?;
            w.properties(&s.properties, PropertyContext::Subscribe)?;
            topic_count(s.topics.len())?;
            for (f, o) in s.topics.iter() {
                if filter(f)? && o.no_local {
                    return Err(Error::SharedNoLocal.into());
                }
                w.binary(f.as_bytes())?;
                w.u8(o.to_byte())?;
            }
        }
        Packet::SubAck(a) => {
            w.u16(nonzero(a.packet_id)?)?;
            w.properties(&a.properties, PropertyContext::SubAck)?;
            codes(a.reason_codes, ReasonTable::SubAck)?;
            w.bytes(a.reason_codes)?;
        }
        Packet::Unsubscribe(u) => {
            w.u16(nonzero(u.packet_id)?)?;
            w.properties(&u.properties, PropertyContext::Unsubscribe)?;
            topic_count(u.topics.len())?;
            for f in u.topics.iter() {
                filter(f)?;
                w.binary(f.as_bytes())?;
            }
        }
        Packet::UnsubAck(a) => {
            w.u16(nonzero(a.packet_id)?)?;
            w.properties(&a.properties, PropertyContext::UnsubAck)?;
            codes(a.reason_codes, ReasonTable::UnsubAck)?;
            w.bytes(a.reason_codes)?;
        }
        Packet::PingReq | Packet::PingResp => {}
        Packet::Disconnect(d) => {
            let form = ack_form(d.reason, &d.properties);
            if form >= 1 {
                w.u8(reason(d.reason, ReasonTable::Disconnect)?)?;
            }
            if form == 2 {
                w.properties(&d.properties, PropertyContext::Disconnect)?;
            }
        }
        Packet::Auth(a) => {
            if ack_form(a.reason, &a.properties) != 0 {
                if a.properties.authentication_method().is_none() {
                    return Err(Error::MissingAuthenticationMethod.into());
                }
                w.u8(reason(a.reason, ReasonTable::Auth)?)?;
                w.properties(&a.properties, PropertyContext::Auth)?;
            }
        }
    }
    // The body must be exactly what body_len promised (a mismatch would be
    // a bug here, not bad input: refuse rather than emit a corrupt packet).
    if w.pos - start != body {
        return Err(Error::MalformedPacket.into());
    }
    Ok(w.pos)
}
