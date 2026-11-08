//! Zero-copy MQTT 5.0 packet decoder and encoder (OASIS MQTT Version 5.0,
//! 7 March 2019). Part 1 of NEXT-3 (ADR-273): the codec only; the broker
//! still refuses a 5.0 CONNECT.
//!
//! The same contract as the 3.1.1 codec in the crate root:
//!
//! - `no_std`, `forbid(unsafe_code)`, no allocation. Decoded packets borrow
//!   from the input; property blocks, topic lists and reason-code lists stay
//!   borrowed byte slices that were validated once and are iterated later.
//!   Nothing is allocated in proportion to an attacker-chosen length.
//! - Streaming: [`decode`] returns [`Error::Incomplete`] with the number of
//!   bytes the packet needs.
//! - Strict: every rule of the specification that can be checked on one
//!   packet is checked (property matrix §2.2.2, duplicates, value ranges,
//!   reason codes per packet §2.4, CONNECT flags §3.1.2.3, subscription
//!   options §3.8.3.1, shared-subscription syntax §4.8.2). Rules that need
//!   connection state (Topic Alias Maximum, Receive Maximum, a client
//!   sending a Subscription Identifier) are the broker's (ADR-273).
//! - Bounded: the documented maxima are [`Limits`]: the packet size
//!   (Maximum Packet Size), topic length and levels, client id length,
//!   filters per packet, and two lists the specification leaves open:
//!   User Properties per property block and Subscription Identifiers per
//!   PUBLISH.
//! - Symmetric: [`encode`] refuses (with [`EncodeError::Invalid`]) every
//!   packet [`decode`] would refuse under [`Limits::PROTOCOL_MAX`], so what
//!   it writes always decodes to an equal packet (fuzzed: `mqtt5_packet`).

mod decode;
mod encode;
mod props;
mod reason;

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;

pub use decode::{connect_protocol_level, decode, read_varint, split_shared};
pub use encode::{EncodeError, encode, encoded_len, varint_len, write_varint};
pub use props::{
    Properties, Property, PropertyContext, PropertyId, PropertyMask, PropertyType,
    validate_properties,
};
pub use reason::{ReasonCode, ReasonTable};

pub use crate::QoS;

/// Protocol level of MQTT 5.0.
pub const PROTOCOL_LEVEL_5: u8 = 5;
/// Largest value of a Variable Byte Integer (§1.5.5).
pub const MAX_VARINT: u32 = 268_435_455;

/// Bounds applied while decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Packet size, topic and client-id bounds shared with 3.1.1.
    /// `base.max_packet_size` is the Maximum Packet Size this side accepts
    /// (§3.1.2.11.4, §3.2.2.3.6): a larger packet is
    /// [`Error::PacketTooLarge`] before its body is waited for.
    pub base: crate::Limits,
    /// User Properties in one property block (CONNECT, Will, PUBLISH, ...).
    pub max_user_properties: u16,
    /// Subscription Identifiers in one PUBLISH (one per matching
    /// subscription, §3.3.4).
    pub max_subscription_identifiers: u16,
}

impl Limits {
    /// The protocol's own maxima.
    pub const PROTOCOL_MAX: Self = Self {
        base: crate::Limits::PROTOCOL_MAX,
        max_user_properties: u16::MAX,
        max_subscription_identifiers: u16::MAX,
    };
}

/// Why a packet was refused. [`Error::reason_code`] gives the code a
/// CONNACK or DISCONNECT answers it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// At least this many bytes (counted from the start of the packet) are
    /// needed; call again once they have arrived.
    Incomplete(usize),
    /// The Remaining Length is longer than 4 bytes or not minimal.
    MalformedRemainingLength,
    /// A Variable Byte Integer inside the packet (Property Length,
    /// Subscription Identifier) is truncated, longer than 4 bytes or not
    /// minimal.
    MalformedVarint,
    PacketTooLarge,
    InvalidPacketType(u8),
    InvalidFixedHeaderFlags,
    InvalidProtocolName,
    /// Protocol level other than 5.
    UnsupportedProtocolLevel(u8),
    InvalidConnectFlags,
    InvalidQos,
    InvalidUtf8,
    InvalidTopicName,
    InvalidTopicFilter,
    TopicTooLong,
    TooManyTopicLevels,
    ClientIdTooLong,
    EmptySubscription,
    TooManyTopics,
    ZeroPacketId,
    /// A reason code that does not exist, or is not allowed in this packet.
    InvalidReasonCode(u8),
    /// Reserved bits of the Subscription Options byte set (§3.8.3.1).
    InvalidSubscriptionOptions,
    /// Retain Handling 3 (§3.8.3.1).
    InvalidRetainHandling,
    /// No Local on a shared subscription (§3.8.3.1).
    SharedNoLocal,
    /// A property identifier that does not exist.
    UnknownProperty(u8),
    /// A property this packet (or the Will) may not carry (§2.2.2.2).
    PropertyNotAllowed(u8),
    /// A property that may appear once appears again.
    DuplicateProperty(u8),
    /// A property value out of its range (0 where 0 is a protocol error,
    /// a byte that must be 0 or 1, a Response Topic with wildcards).
    InvalidPropertyValue(u8),
    /// Authentication Data without Authentication Method, or an AUTH
    /// packet with properties but no Authentication Method.
    MissingAuthenticationMethod,
    TooManyUserProperties,
    TooManySubscriptionIdentifiers,
    /// CONNACK with Session Present and a non-zero reason code
    /// [MQTT-3.2.2-6].
    SessionPresentWithError,
    /// Lengths inside the packet disagree with the remaining length, or a
    /// field is truncated.
    MalformedPacket,
}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Incomplete(n) => Self::Incomplete(n),
            crate::Error::MalformedRemainingLength => Self::MalformedRemainingLength,
            crate::Error::PacketTooLarge => Self::PacketTooLarge,
            crate::Error::InvalidPacketType(t) => Self::InvalidPacketType(t),
            crate::Error::InvalidFixedHeaderFlags => Self::InvalidFixedHeaderFlags,
            crate::Error::InvalidProtocolName => Self::InvalidProtocolName,
            crate::Error::UnsupportedProtocolLevel(l) => Self::UnsupportedProtocolLevel(l),
            crate::Error::InvalidConnectFlags => Self::InvalidConnectFlags,
            crate::Error::InvalidQos => Self::InvalidQos,
            crate::Error::InvalidUtf8 => Self::InvalidUtf8,
            crate::Error::InvalidTopicName => Self::InvalidTopicName,
            crate::Error::InvalidTopicFilter => Self::InvalidTopicFilter,
            crate::Error::TopicTooLong => Self::TopicTooLong,
            crate::Error::TooManyTopicLevels => Self::TooManyTopicLevels,
            crate::Error::ClientIdTooLong => Self::ClientIdTooLong,
            crate::Error::EmptySubscription => Self::EmptySubscription,
            crate::Error::TooManyTopics => Self::TooManyTopics,
            crate::Error::ZeroPacketId => Self::ZeroPacketId,
            crate::Error::InvalidReturnCode => Self::InvalidReasonCode(0xff),
            crate::Error::MalformedPacket => Self::MalformedPacket,
        }
    }
}

impl Error {
    /// The reason code a server answers this error with: in a CONNACK when
    /// the error is in the CONNECT, otherwise in a DISCONNECT (ADR-273 §4).
    /// 0x81 Malformed Packet and 0x82 Protocol Error follow the
    /// specification's classification (§1.5, §2.2.2.2, §3.x, §4.13); our
    /// own bounds answer 0x83 Implementation specific error, the packet
    /// size 0x95. `Incomplete` is not an error to answer and maps to 0x81.
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::Incomplete(_)
            | Self::MalformedRemainingLength
            | Self::MalformedVarint
            | Self::InvalidPacketType(_)
            | Self::InvalidFixedHeaderFlags
            | Self::InvalidConnectFlags
            | Self::InvalidQos
            | Self::InvalidUtf8
            | Self::InvalidReasonCode(_)
            | Self::InvalidSubscriptionOptions
            | Self::UnknownProperty(_)
            | Self::PropertyNotAllowed(_)
            | Self::MalformedPacket => ReasonCode::MalformedPacket,
            Self::EmptySubscription
            | Self::ZeroPacketId
            | Self::InvalidRetainHandling
            | Self::SharedNoLocal
            | Self::DuplicateProperty(_)
            | Self::InvalidPropertyValue(_)
            | Self::MissingAuthenticationMethod
            | Self::SessionPresentWithError => ReasonCode::ProtocolError,
            Self::PacketTooLarge => ReasonCode::PacketTooLarge,
            Self::InvalidProtocolName | Self::UnsupportedProtocolLevel(_) => {
                ReasonCode::UnsupportedProtocolVersion
            }
            Self::ClientIdTooLong => ReasonCode::ClientIdentifierNotValid,
            Self::InvalidTopicName => ReasonCode::TopicNameInvalid,
            Self::InvalidTopicFilter => ReasonCode::TopicFilterInvalid,
            Self::TopicTooLong
            | Self::TooManyTopicLevels
            | Self::TooManyTopics
            | Self::TooManyUserProperties
            | Self::TooManySubscriptionIdentifiers => ReasonCode::ImplementationSpecificError,
        }
    }
}

/// The 15 control packet types (§2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect = 1,
    ConnAck = 2,
    Publish = 3,
    PubAck = 4,
    PubRec = 5,
    PubRel = 6,
    PubComp = 7,
    Subscribe = 8,
    SubAck = 9,
    Unsubscribe = 10,
    UnsubAck = 11,
    PingReq = 12,
    PingResp = 13,
    Disconnect = 14,
    Auth = 15,
}

impl PacketType {
    pub const ALL: [Self; 15] = [
        Self::Connect,
        Self::ConnAck,
        Self::Publish,
        Self::PubAck,
        Self::PubRec,
        Self::PubRel,
        Self::PubComp,
        Self::Subscribe,
        Self::SubAck,
        Self::Unsubscribe,
        Self::UnsubAck,
        Self::PingReq,
        Self::PingResp,
        Self::Disconnect,
        Self::Auth,
    ];

    pub const fn from_u8(t: u8) -> Option<Self> {
        Some(match t {
            1 => Self::Connect,
            2 => Self::ConnAck,
            3 => Self::Publish,
            4 => Self::PubAck,
            5 => Self::PubRec,
            6 => Self::PubRel,
            7 => Self::PubComp,
            8 => Self::Subscribe,
            9 => Self::SubAck,
            10 => Self::Unsubscribe,
            11 => Self::UnsubAck,
            12 => Self::PingReq,
            13 => Self::PingResp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            _ => return None,
        })
    }

    /// The fixed-header flags every packet but PUBLISH must carry (§2.1.3).
    pub const fn fixed_flags(self) -> u8 {
        match self {
            Self::PubRel | Self::Subscribe | Self::Unsubscribe => 0b0010,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Will<'a> {
    /// Will Properties (§3.1.3.2).
    pub properties: Properties<'a>,
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub qos: QoS,
    pub retain: bool,
}

/// CONNECT (§3.1). Unlike 3.1.1, a password without a user name is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect<'a> {
    pub clean_start: bool,
    pub keep_alive: u16,
    pub properties: Properties<'a>,
    pub client_id: &'a str,
    pub will: Option<Will<'a>>,
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnAck<'a> {
    pub session_present: bool,
    pub reason: ReasonCode,
    pub properties: Properties<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publish<'a> {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    /// Empty only when the properties carry a Topic Alias (§3.3.2.1).
    pub topic: &'a str,
    /// Present (and non-zero) exactly when `qos > 0`.
    pub packet_id: Option<u16>,
    pub properties: Properties<'a>,
    pub payload: &'a [u8],
}

/// PUBACK, PUBREC, PUBREL, PUBCOMP (§3.4-§3.7). A short packet (Remaining
/// Length 2 or 3) decodes to reason 0x00 and/or no properties; the encoder
/// writes the shortest form that carries the same values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack<'a> {
    pub packet_id: u16,
    pub reason: ReasonCode,
    pub properties: Properties<'a>,
}

/// Retain Handling of a subscription (§3.8.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainHandling {
    /// 0: send retained messages at the time of the subscribe.
    SendOnSubscribe = 0,
    /// 1: send them only if the subscription did not exist.
    SendIfNew = 1,
    /// 2: do not send them.
    DoNotSend = 2,
}

/// The Subscription Options byte (§3.8.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionOptions {
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

impl SubscriptionOptions {
    /// Decodes the byte: QoS 3 and reserved bits are malformed, Retain
    /// Handling 3 a protocol error.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        if b & 0xc0 != 0 {
            return Err(Error::InvalidSubscriptionOptions);
        }
        let Some(qos) = QoS::from_bits(b & 0x03) else {
            return Err(Error::InvalidQos);
        };
        let retain_handling = match (b >> 4) & 0x03 {
            0 => RetainHandling::SendOnSubscribe,
            1 => RetainHandling::SendIfNew,
            2 => RetainHandling::DoNotSend,
            _ => return Err(Error::InvalidRetainHandling),
        };
        Ok(Self {
            qos,
            no_local: b & 0x04 != 0,
            retain_as_published: b & 0x08 != 0,
            retain_handling,
        })
    }

    pub const fn to_byte(self) -> u8 {
        (self.qos as u8)
            | ((self.no_local as u8) << 2)
            | ((self.retain_as_published as u8) << 3)
            | ((self.retain_handling as u8) << 4)
    }

    /// QoS only, every flag off: what a 3.1.1 subscription means.
    pub const fn qos(qos: QoS) -> Self {
        Self {
            qos,
            no_local: false,
            retain_as_published: false,
            retain_handling: RetainHandling::SendOnSubscribe,
        }
    }
}

/// SUBSCRIBE topic list: the borrowed, validated payload after decoding,
/// or a list when building a packet to encode.
#[derive(Debug, Clone, Copy)]
pub enum SubscribeTopics<'a> {
    Raw(&'a [u8]),
    List(&'a [(&'a str, SubscriptionOptions)]),
}

impl<'a> SubscribeTopics<'a> {
    /// The (filter, options) pairs. A raw payload was validated by
    /// `decode`, so iteration cannot fail; on unvalidated bytes it stops at
    /// the first malformed entry.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, SubscriptionOptions)> + 'a {
        let (raw, list): (&'a [u8], &'a [(&'a str, SubscriptionOptions)]) = match *self {
            Self::Raw(r) => (r, &[]),
            Self::List(l) => (&[], l),
        };
        decode::RawPairs::new(raw)
            .map_while(Result::ok)
            .map_while(|(f, b)| SubscriptionOptions::from_byte(b).ok().map(|o| (f, o)))
            .chain(list.iter().copied())
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for SubscribeTopics<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for SubscribeTopics<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscribe<'a> {
    pub packet_id: u16,
    pub properties: Properties<'a>,
    pub topics: SubscribeTopics<'a>,
}

/// SUBACK (§3.9) and UNSUBACK (§3.11): one reason code per filter, kept as
/// the borrowed bytes (each checked against the packet's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAck<'a> {
    pub packet_id: u16,
    pub properties: Properties<'a>,
    pub reason_codes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsubAck<'a> {
    pub packet_id: u16,
    pub properties: Properties<'a>,
    pub reason_codes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum UnsubscribeTopics<'a> {
    Raw(&'a [u8]),
    List(&'a [&'a str]),
}

impl<'a> UnsubscribeTopics<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &'a str> + 'a {
        let (raw, list): (&'a [u8], &'a [&'a str]) = match *self {
            Self::Raw(r) => (r, &[]),
            Self::List(l) => (&[], l),
        };
        decode::RawStrings::new(raw)
            .map_while(Result::ok)
            .chain(list.iter().copied())
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PartialEq for UnsubscribeTopics<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for UnsubscribeTopics<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsubscribe<'a> {
    pub packet_id: u16,
    pub properties: Properties<'a>,
    pub topics: UnsubscribeTopics<'a>,
}

/// DISCONNECT (§3.14). Remaining Length 0 decodes to 0x00 and no
/// properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnect<'a> {
    pub reason: ReasonCode,
    pub properties: Properties<'a>,
}

/// AUTH (§3.15). Remaining Length 0 decodes to 0x00 and no properties;
/// otherwise the properties must carry an Authentication Method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth<'a> {
    pub reason: ReasonCode,
    pub properties: Properties<'a>,
}

/// Every MQTT 5.0 control packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    Connect(Connect<'a>),
    ConnAck(ConnAck<'a>),
    Publish(Publish<'a>),
    PubAck(Ack<'a>),
    PubRec(Ack<'a>),
    PubRel(Ack<'a>),
    PubComp(Ack<'a>),
    Subscribe(Subscribe<'a>),
    SubAck(SubAck<'a>),
    Unsubscribe(Unsubscribe<'a>),
    UnsubAck(UnsubAck<'a>),
    PingReq,
    PingResp,
    Disconnect(Disconnect<'a>),
    Auth(Auth<'a>),
}

impl Packet<'_> {
    pub const fn packet_type(&self) -> PacketType {
        match self {
            Self::Connect(_) => PacketType::Connect,
            Self::ConnAck(_) => PacketType::ConnAck,
            Self::Publish(_) => PacketType::Publish,
            Self::PubAck(_) => PacketType::PubAck,
            Self::PubRec(_) => PacketType::PubRec,
            Self::PubRel(_) => PacketType::PubRel,
            Self::PubComp(_) => PacketType::PubComp,
            Self::Subscribe(_) => PacketType::Subscribe,
            Self::SubAck(_) => PacketType::SubAck,
            Self::Unsubscribe(_) => PacketType::Unsubscribe,
            Self::UnsubAck(_) => PacketType::UnsubAck,
            Self::PingReq => PacketType::PingReq,
            Self::PingResp => PacketType::PingResp,
            Self::Disconnect(_) => PacketType::Disconnect,
            Self::Auth(_) => PacketType::Auth,
        }
    }
}
