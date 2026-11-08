//! Properties (§2.2.2, the table in §2.2.2.2 and each packet's section).
//!
//! A property block is kept as the borrowed bytes after one validating
//! pass ([`validate_properties`]); iteration parses lazily and cannot fail
//! on validated bytes. Duplicates are found with a 64-bit mask of the ids
//! seen (every id is below 64), so validation needs no storage at all.

use super::decode::Reader;
use super::{Error, Limits, MAX_VARINT};

/// Data type of a property value (§1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyType {
    Byte,
    TwoByteInteger,
    FourByteInteger,
    VariableByteInteger,
    Utf8String,
    BinaryData,
    Utf8StringPair,
}

/// Where a property block sits: a packet, or the Will Properties of a
/// CONNECT (§3.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyContext {
    Connect,
    ConnAck,
    Publish,
    Will,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    Disconnect,
    Auth,
}

impl PropertyContext {
    pub const ALL: [Self; 14] = [
        Self::Connect,
        Self::ConnAck,
        Self::Publish,
        Self::Will,
        Self::PubAck,
        Self::PubRec,
        Self::PubRel,
        Self::PubComp,
        Self::Subscribe,
        Self::SubAck,
        Self::Unsubscribe,
        Self::UnsubAck,
        Self::Disconnect,
        Self::Auth,
    ];

    /// Bit of the context: the packet type's value, bit 0 for the Will.
    const fn bit(self) -> u16 {
        1 << match self {
            Self::Will => 0,
            Self::Connect => 1,
            Self::ConnAck => 2,
            Self::Publish => 3,
            Self::PubAck => 4,
            Self::PubRec => 5,
            Self::PubRel => 6,
            Self::PubComp => 7,
            Self::Subscribe => 8,
            Self::SubAck => 9,
            Self::Unsubscribe => 10,
            Self::UnsubAck => 11,
            Self::Disconnect => 14,
            Self::Auth => 15,
        }
    }
}

const WI: u16 = 1 << 0;
const CN: u16 = 1 << 1;
const CA: u16 = 1 << 2;
const PB: u16 = 1 << 3;
const PA: u16 = 1 << 4;
const PR: u16 = 1 << 5;
const PL: u16 = 1 << 6;
const PC: u16 = 1 << 7;
const SB: u16 = 1 << 8;
const SA: u16 = 1 << 9;
const UB: u16 = 1 << 10;
const UA: u16 = 1 << 11;
const DI: u16 = 1 << 14;
const AU: u16 = 1 << 15;

/// The 27 property identifiers of MQTT 5.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PropertyId {
    PayloadFormatIndicator = 0x01,
    MessageExpiryInterval = 0x02,
    ContentType = 0x03,
    ResponseTopic = 0x08,
    CorrelationData = 0x09,
    SubscriptionIdentifier = 0x0b,
    SessionExpiryInterval = 0x11,
    AssignedClientIdentifier = 0x12,
    ServerKeepAlive = 0x13,
    AuthenticationMethod = 0x15,
    AuthenticationData = 0x16,
    RequestProblemInformation = 0x17,
    WillDelayInterval = 0x18,
    RequestResponseInformation = 0x19,
    ResponseInformation = 0x1a,
    ServerReference = 0x1c,
    ReasonString = 0x1f,
    ReceiveMaximum = 0x21,
    TopicAliasMaximum = 0x22,
    TopicAlias = 0x23,
    MaximumQos = 0x24,
    RetainAvailable = 0x25,
    UserProperty = 0x26,
    MaximumPacketSize = 0x27,
    WildcardSubscriptionAvailable = 0x28,
    SubscriptionIdentifierAvailable = 0x29,
    SharedSubscriptionAvailable = 0x2a,
}

impl PropertyId {
    pub const ALL: [Self; 27] = [
        Self::PayloadFormatIndicator,
        Self::MessageExpiryInterval,
        Self::ContentType,
        Self::ResponseTopic,
        Self::CorrelationData,
        Self::SubscriptionIdentifier,
        Self::SessionExpiryInterval,
        Self::AssignedClientIdentifier,
        Self::ServerKeepAlive,
        Self::AuthenticationMethod,
        Self::AuthenticationData,
        Self::RequestProblemInformation,
        Self::WillDelayInterval,
        Self::RequestResponseInformation,
        Self::ResponseInformation,
        Self::ServerReference,
        Self::ReasonString,
        Self::ReceiveMaximum,
        Self::TopicAliasMaximum,
        Self::TopicAlias,
        Self::MaximumQos,
        Self::RetainAvailable,
        Self::UserProperty,
        Self::MaximumPacketSize,
        Self::WildcardSubscriptionAvailable,
        Self::SubscriptionIdentifierAvailable,
        Self::SharedSubscriptionAvailable,
    ];

    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::PayloadFormatIndicator,
            0x02 => Self::MessageExpiryInterval,
            0x03 => Self::ContentType,
            0x08 => Self::ResponseTopic,
            0x09 => Self::CorrelationData,
            0x0b => Self::SubscriptionIdentifier,
            0x11 => Self::SessionExpiryInterval,
            0x12 => Self::AssignedClientIdentifier,
            0x13 => Self::ServerKeepAlive,
            0x15 => Self::AuthenticationMethod,
            0x16 => Self::AuthenticationData,
            0x17 => Self::RequestProblemInformation,
            0x18 => Self::WillDelayInterval,
            0x19 => Self::RequestResponseInformation,
            0x1a => Self::ResponseInformation,
            0x1c => Self::ServerReference,
            0x1f => Self::ReasonString,
            0x21 => Self::ReceiveMaximum,
            0x22 => Self::TopicAliasMaximum,
            0x23 => Self::TopicAlias,
            0x24 => Self::MaximumQos,
            0x25 => Self::RetainAvailable,
            0x26 => Self::UserProperty,
            0x27 => Self::MaximumPacketSize,
            0x28 => Self::WildcardSubscriptionAvailable,
            0x29 => Self::SubscriptionIdentifierAvailable,
            0x2a => Self::SharedSubscriptionAvailable,
            _ => return None,
        })
    }

    /// The value's data type (§2.2.2.2, Table 2-4).
    pub const fn ty(self) -> PropertyType {
        use PropertyType::*;
        match self {
            Self::PayloadFormatIndicator
            | Self::RequestProblemInformation
            | Self::RequestResponseInformation
            | Self::MaximumQos
            | Self::RetainAvailable
            | Self::WildcardSubscriptionAvailable
            | Self::SubscriptionIdentifierAvailable
            | Self::SharedSubscriptionAvailable => Byte,
            Self::ServerKeepAlive
            | Self::ReceiveMaximum
            | Self::TopicAliasMaximum
            | Self::TopicAlias => TwoByteInteger,
            Self::MessageExpiryInterval
            | Self::SessionExpiryInterval
            | Self::WillDelayInterval
            | Self::MaximumPacketSize => FourByteInteger,
            Self::SubscriptionIdentifier => VariableByteInteger,
            Self::ContentType
            | Self::ResponseTopic
            | Self::AssignedClientIdentifier
            | Self::AuthenticationMethod
            | Self::ResponseInformation
            | Self::ServerReference
            | Self::ReasonString => Utf8String,
            Self::CorrelationData | Self::AuthenticationData => BinaryData,
            Self::UserProperty => Utf8StringPair,
        }
    }

    /// The packets (and the Will) that may carry it (Table 2-4).
    const fn contexts(self) -> u16 {
        match self {
            Self::PayloadFormatIndicator
            | Self::MessageExpiryInterval
            | Self::ContentType
            | Self::ResponseTopic
            | Self::CorrelationData => PB | WI,
            Self::SubscriptionIdentifier => PB | SB,
            Self::SessionExpiryInterval => CN | CA | DI,
            Self::AssignedClientIdentifier
            | Self::ServerKeepAlive
            | Self::ResponseInformation
            | Self::MaximumQos
            | Self::RetainAvailable
            | Self::WildcardSubscriptionAvailable
            | Self::SubscriptionIdentifierAvailable
            | Self::SharedSubscriptionAvailable => CA,
            Self::AuthenticationMethod | Self::AuthenticationData => CN | CA | AU,
            Self::RequestProblemInformation | Self::RequestResponseInformation => CN,
            Self::WillDelayInterval => WI,
            Self::ServerReference => CA | DI,
            Self::ReasonString => CA | PA | PR | PL | PC | SA | UA | DI | AU,
            Self::ReceiveMaximum | Self::TopicAliasMaximum | Self::MaximumPacketSize => CN | CA,
            Self::TopicAlias => PB,
            Self::UserProperty => {
                CN | CA | PB | WI | PA | PR | PL | PC | SB | SA | UB | UA | DI | AU
            }
        }
    }

    pub const fn allowed_in(self, ctx: PropertyContext) -> bool {
        self.contexts() & ctx.bit() != 0
    }

    /// User Property may repeat anywhere; Subscription Identifier may
    /// repeat in PUBLISH (one per matching subscription, §3.3.2.3.8).
    /// Every other property at most once.
    pub const fn may_repeat(self, ctx: PropertyContext) -> bool {
        matches!(self, Self::UserProperty)
            || (matches!(self, Self::SubscriptionIdentifier)
                && matches!(ctx, PropertyContext::Publish))
    }
}

/// A set of property identifiers (bit `id`; every id is below 64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PropertyMask(pub u64);

impl PropertyMask {
    pub const EMPTY: Self = Self(0);

    pub const fn with(self, id: PropertyId) -> Self {
        Self(self.0 | 1 << (id as u8))
    }

    pub const fn contains(self, id: PropertyId) -> bool {
        self.0 & (1 << (id as u8)) != 0
    }
}

/// One property and its value. Byte-valued flags keep the byte (0 or 1 for
/// the boolean ones, checked) so that what decodes encodes back the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Property<'a> {
    PayloadFormatIndicator(u8),
    MessageExpiryInterval(u32),
    ContentType(&'a str),
    ResponseTopic(&'a str),
    CorrelationData(&'a [u8]),
    SubscriptionIdentifier(u32),
    SessionExpiryInterval(u32),
    AssignedClientIdentifier(&'a str),
    ServerKeepAlive(u16),
    AuthenticationMethod(&'a str),
    AuthenticationData(&'a [u8]),
    RequestProblemInformation(u8),
    WillDelayInterval(u32),
    RequestResponseInformation(u8),
    ResponseInformation(&'a str),
    ServerReference(&'a str),
    ReasonString(&'a str),
    ReceiveMaximum(u16),
    TopicAliasMaximum(u16),
    TopicAlias(u16),
    MaximumQos(u8),
    RetainAvailable(u8),
    UserProperty(&'a str, &'a str),
    MaximumPacketSize(u32),
    WildcardSubscriptionAvailable(u8),
    SubscriptionIdentifierAvailable(u8),
    SharedSubscriptionAvailable(u8),
}

impl<'a> Property<'a> {
    pub const fn id(&self) -> PropertyId {
        match self {
            Self::PayloadFormatIndicator(_) => PropertyId::PayloadFormatIndicator,
            Self::MessageExpiryInterval(_) => PropertyId::MessageExpiryInterval,
            Self::ContentType(_) => PropertyId::ContentType,
            Self::ResponseTopic(_) => PropertyId::ResponseTopic,
            Self::CorrelationData(_) => PropertyId::CorrelationData,
            Self::SubscriptionIdentifier(_) => PropertyId::SubscriptionIdentifier,
            Self::SessionExpiryInterval(_) => PropertyId::SessionExpiryInterval,
            Self::AssignedClientIdentifier(_) => PropertyId::AssignedClientIdentifier,
            Self::ServerKeepAlive(_) => PropertyId::ServerKeepAlive,
            Self::AuthenticationMethod(_) => PropertyId::AuthenticationMethod,
            Self::AuthenticationData(_) => PropertyId::AuthenticationData,
            Self::RequestProblemInformation(_) => PropertyId::RequestProblemInformation,
            Self::WillDelayInterval(_) => PropertyId::WillDelayInterval,
            Self::RequestResponseInformation(_) => PropertyId::RequestResponseInformation,
            Self::ResponseInformation(_) => PropertyId::ResponseInformation,
            Self::ServerReference(_) => PropertyId::ServerReference,
            Self::ReasonString(_) => PropertyId::ReasonString,
            Self::ReceiveMaximum(_) => PropertyId::ReceiveMaximum,
            Self::TopicAliasMaximum(_) => PropertyId::TopicAliasMaximum,
            Self::TopicAlias(_) => PropertyId::TopicAlias,
            Self::MaximumQos(_) => PropertyId::MaximumQos,
            Self::RetainAvailable(_) => PropertyId::RetainAvailable,
            Self::UserProperty(..) => PropertyId::UserProperty,
            Self::MaximumPacketSize(_) => PropertyId::MaximumPacketSize,
            Self::WildcardSubscriptionAvailable(_) => PropertyId::WildcardSubscriptionAvailable,
            Self::SubscriptionIdentifierAvailable(_) => PropertyId::SubscriptionIdentifierAvailable,
            Self::SharedSubscriptionAvailable(_) => PropertyId::SharedSubscriptionAvailable,
        }
    }

    /// Parses one property (identifier and value) and checks the value's
    /// own range. Context, duplicates and counts are [`validate_properties`].
    pub(crate) fn parse(r: &mut Reader<'a>) -> Result<Self, Error> {
        let raw_id = r.u8()?;
        // The identifier is a Variable Byte Integer; every defined one is a
        // single byte, so a continuation bit means an unknown identifier.
        let id = PropertyId::from_u8(raw_id).ok_or(Error::UnknownProperty(raw_id))?;
        let bad = Error::InvalidPropertyValue(raw_id);
        let flag = |v: u8| if v <= 1 { Ok(v) } else { Err(bad) };
        let nonzero16 = |v: u16| if v != 0 { Ok(v) } else { Err(bad) };
        Ok(match id {
            PropertyId::PayloadFormatIndicator => Self::PayloadFormatIndicator(flag(r.u8()?)?),
            PropertyId::MessageExpiryInterval => Self::MessageExpiryInterval(r.u32()?),
            PropertyId::ContentType => Self::ContentType(r.string()?),
            PropertyId::ResponseTopic => {
                // A Topic Name: no wildcards, not empty [MQTT-3.3.2-14].
                let t = r.string()?;
                if !crate::is_valid_topic_name(t) {
                    return Err(bad);
                }
                Self::ResponseTopic(t)
            }
            PropertyId::CorrelationData => Self::CorrelationData(r.binary()?),
            PropertyId::SubscriptionIdentifier => match r.varint()? {
                0 => return Err(bad),
                v => Self::SubscriptionIdentifier(v),
            },
            PropertyId::SessionExpiryInterval => Self::SessionExpiryInterval(r.u32()?),
            PropertyId::AssignedClientIdentifier => Self::AssignedClientIdentifier(r.string()?),
            PropertyId::ServerKeepAlive => Self::ServerKeepAlive(r.u16()?),
            PropertyId::AuthenticationMethod => Self::AuthenticationMethod(r.string()?),
            PropertyId::AuthenticationData => Self::AuthenticationData(r.binary()?),
            PropertyId::RequestProblemInformation => {
                Self::RequestProblemInformation(flag(r.u8()?)?)
            }
            PropertyId::WillDelayInterval => Self::WillDelayInterval(r.u32()?),
            PropertyId::RequestResponseInformation => {
                Self::RequestResponseInformation(flag(r.u8()?)?)
            }
            PropertyId::ResponseInformation => Self::ResponseInformation(r.string()?),
            PropertyId::ServerReference => Self::ServerReference(r.string()?),
            PropertyId::ReasonString => Self::ReasonString(r.string()?),
            PropertyId::ReceiveMaximum => Self::ReceiveMaximum(nonzero16(r.u16()?)?),
            PropertyId::TopicAliasMaximum => Self::TopicAliasMaximum(r.u16()?),
            PropertyId::TopicAlias => Self::TopicAlias(nonzero16(r.u16()?)?),
            PropertyId::MaximumQos => Self::MaximumQos(flag(r.u8()?)?),
            PropertyId::RetainAvailable => Self::RetainAvailable(flag(r.u8()?)?),
            PropertyId::UserProperty => {
                let k = r.string()?;
                let v = r.string()?;
                Self::UserProperty(k, v)
            }
            PropertyId::MaximumPacketSize => match r.u32()? {
                0 => return Err(bad),
                v => Self::MaximumPacketSize(v),
            },
            PropertyId::WildcardSubscriptionAvailable => {
                Self::WildcardSubscriptionAvailable(flag(r.u8()?)?)
            }
            PropertyId::SubscriptionIdentifierAvailable => {
                Self::SubscriptionIdentifierAvailable(flag(r.u8()?)?)
            }
            PropertyId::SharedSubscriptionAvailable => {
                Self::SharedSubscriptionAvailable(flag(r.u8()?)?)
            }
        })
    }

    /// Bytes this property takes when encoded (identifier included).
    pub const fn encoded_len(&self) -> usize {
        1 + match self {
            Self::PayloadFormatIndicator(_)
            | Self::RequestProblemInformation(_)
            | Self::RequestResponseInformation(_)
            | Self::MaximumQos(_)
            | Self::RetainAvailable(_)
            | Self::WildcardSubscriptionAvailable(_)
            | Self::SubscriptionIdentifierAvailable(_)
            | Self::SharedSubscriptionAvailable(_) => 1,
            Self::ServerKeepAlive(_)
            | Self::ReceiveMaximum(_)
            | Self::TopicAliasMaximum(_)
            | Self::TopicAlias(_) => 2,
            Self::MessageExpiryInterval(_)
            | Self::SessionExpiryInterval(_)
            | Self::WillDelayInterval(_)
            | Self::MaximumPacketSize(_) => 4,
            Self::SubscriptionIdentifier(v) => super::varint_len(*v),
            Self::ContentType(s)
            | Self::ResponseTopic(s)
            | Self::AssignedClientIdentifier(s)
            | Self::AuthenticationMethod(s)
            | Self::ResponseInformation(s)
            | Self::ServerReference(s)
            | Self::ReasonString(s) => 2 + s.len(),
            Self::CorrelationData(b) | Self::AuthenticationData(b) => 2 + b.len(),
            Self::UserProperty(k, v) => 4 + k.len() + v.len(),
        }
    }
}

/// Checks a property block (the bytes after the Property Length) for
/// `ctx`: every identifier known and allowed there, every value of its type
/// and range, no forbidden repetition, Authentication Data only with an
/// Authentication Method, and the list bounds of `limits`.
pub fn validate_properties(raw: &[u8], ctx: PropertyContext, limits: &Limits) -> Result<(), Error> {
    let mut r = Reader::new(raw);
    let mut seen = PropertyMask::EMPTY;
    let mut user = 0u32;
    let mut sub_ids = 0u32;
    while r.remaining() > 0 {
        let p = Property::parse(&mut r)?;
        let id = p.id();
        if !id.allowed_in(ctx) {
            return Err(Error::PropertyNotAllowed(id as u8));
        }
        if seen.contains(id) && !id.may_repeat(ctx) {
            return Err(Error::DuplicateProperty(id as u8));
        }
        seen = seen.with(id);
        match id {
            PropertyId::UserProperty => {
                user += 1;
                if user > u32::from(limits.max_user_properties) {
                    return Err(Error::TooManyUserProperties);
                }
            }
            PropertyId::SubscriptionIdentifier => {
                sub_ids += 1;
                if sub_ids > u32::from(limits.max_subscription_identifiers) {
                    return Err(Error::TooManySubscriptionIdentifiers);
                }
            }
            _ => {}
        }
    }
    if seen.contains(PropertyId::AuthenticationData)
        && !seen.contains(PropertyId::AuthenticationMethod)
    {
        return Err(Error::MissingAuthenticationMethod);
    }
    Ok(())
}

/// Lazily parses validated property bytes; stops at the first error (which
/// validated bytes never have).
#[derive(Debug, Clone)]
pub(crate) struct RawProps<'a>(Reader<'a>);

impl<'a> RawProps<'a> {
    pub(crate) const fn new(raw: &'a [u8]) -> Self {
        Self(Reader::new(raw))
    }
}

impl<'a> Iterator for RawProps<'a> {
    type Item = Property<'a>;

    fn next(&mut self) -> Option<Property<'a>> {
        if self.0.remaining() == 0 {
            return None;
        }
        match Property::parse(&mut self.0) {
            Ok(p) => Some(p),
            Err(_) => {
                self.0.skip_to_end();
                None
            }
        }
    }
}

/// A property block: the validated borrowed bytes after decoding, a list
/// when building a packet, or (for a broker forwarding a PUBLISH) the bytes
/// of a received block minus some identifiers, followed by a list.
#[derive(Debug, Clone, Copy)]
pub enum Properties<'a> {
    Raw(&'a [u8]),
    List(&'a [Property<'a>]),
    /// `raw` without the properties whose identifier is in `drop`, then
    /// `extra`. For forwarding: drop Topic Alias and Message Expiry
    /// Interval, append the subscriber's Subscription Identifiers and the
    /// remaining expiry (ADR-273).
    Forward {
        raw: &'a [u8],
        drop: PropertyMask,
        extra: &'a [Property<'a>],
    },
}

impl Default for Properties<'_> {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Iterator over a [`Properties`].
#[derive(Debug, Clone)]
pub struct PropIter<'a> {
    raw: RawProps<'a>,
    drop: PropertyMask,
    list: core::slice::Iter<'a, Property<'a>>,
}

impl<'a> Iterator for PropIter<'a> {
    type Item = Property<'a>;

    fn next(&mut self) -> Option<Property<'a>> {
        for p in self.raw.by_ref() {
            if !self.drop.contains(p.id()) {
                return Some(p);
            }
        }
        self.list.next().copied()
    }
}

impl<'a> Properties<'a> {
    pub const EMPTY: Self = Self::Raw(&[]);

    pub fn iter(&self) -> PropIter<'a> {
        let (raw, drop, list): (&'a [u8], PropertyMask, &'a [Property<'a>]) = match *self {
            Self::Raw(r) => (r, PropertyMask::EMPTY, &[]),
            Self::List(l) => (&[], PropertyMask::EMPTY, l),
            Self::Forward { raw, drop, extra } => (raw, drop, extra),
        };
        PropIter {
            raw: RawProps::new(raw),
            drop,
            list: list.iter(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// The first property with this identifier.
    pub fn get(&self, id: PropertyId) -> Option<Property<'a>> {
        self.iter().find(|p| p.id() == id)
    }

    /// The (name, value) pairs of the User Properties, in order.
    pub fn user_properties(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.iter().filter_map(|p| match p {
            Property::UserProperty(k, v) => Some((k, v)),
            _ => None,
        })
    }

    /// The Subscription Identifiers, in order.
    pub fn subscription_identifiers(&self) -> impl Iterator<Item = u32> + 'a {
        self.iter().filter_map(|p| match p {
            Property::SubscriptionIdentifier(v) => Some(v),
            _ => None,
        })
    }

    /// Bytes the block takes when encoded, without the Property Length.
    pub fn encoded_len(&self) -> usize {
        match *self {
            Self::Raw(r) => r.len(),
            _ => self.iter().map(|p| p.encoded_len()).sum(),
        }
    }

    fn u32_of(&self, id: PropertyId) -> Option<u32> {
        match self.get(id)? {
            Property::MessageExpiryInterval(v)
            | Property::SessionExpiryInterval(v)
            | Property::WillDelayInterval(v)
            | Property::MaximumPacketSize(v) => Some(v),
            _ => None,
        }
    }

    fn u16_of(&self, id: PropertyId) -> Option<u16> {
        match self.get(id)? {
            Property::ServerKeepAlive(v)
            | Property::ReceiveMaximum(v)
            | Property::TopicAliasMaximum(v)
            | Property::TopicAlias(v) => Some(v),
            _ => None,
        }
    }

    pub fn session_expiry_interval(&self) -> Option<u32> {
        self.u32_of(PropertyId::SessionExpiryInterval)
    }

    pub fn message_expiry_interval(&self) -> Option<u32> {
        self.u32_of(PropertyId::MessageExpiryInterval)
    }

    pub fn will_delay_interval(&self) -> Option<u32> {
        self.u32_of(PropertyId::WillDelayInterval)
    }

    pub fn maximum_packet_size(&self) -> Option<u32> {
        self.u32_of(PropertyId::MaximumPacketSize)
    }

    pub fn receive_maximum(&self) -> Option<u16> {
        self.u16_of(PropertyId::ReceiveMaximum)
    }

    pub fn topic_alias_maximum(&self) -> Option<u16> {
        self.u16_of(PropertyId::TopicAliasMaximum)
    }

    pub fn topic_alias(&self) -> Option<u16> {
        self.u16_of(PropertyId::TopicAlias)
    }

    pub fn server_keep_alive(&self) -> Option<u16> {
        self.u16_of(PropertyId::ServerKeepAlive)
    }

    pub fn authentication_method(&self) -> Option<&'a str> {
        match self.get(PropertyId::AuthenticationMethod)? {
            Property::AuthenticationMethod(s) => Some(s),
            _ => None,
        }
    }

    pub fn reason_string(&self) -> Option<&'a str> {
        match self.get(PropertyId::ReasonString)? {
            Property::ReasonString(s) => Some(s),
            _ => None,
        }
    }
}

impl PartialEq for Properties<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Properties<'_> {}

const _: () = assert!(MAX_VARINT == crate::MAX_REMAINING_LENGTH);
