//! Zero-copy MQTT 3.1.1 packet decoder and encoder (OASIS MQTT 3.1.1).
//!
//! - `no_std`, `forbid(unsafe_code)`, no allocation: decoded packets borrow
//!   from the input buffer.
//! - Streaming: [`decode`] returns [`Error::Incomplete`] with the number of
//!   bytes the packet needs, so the caller can buffer exactly that much.
//! - Hostile input: every length is checked against [`Limits`] as soon as it
//!   is known (the declared packet size before waiting for the body), and no
//!   input makes the decoder panic (fuzzed: `fuzz/fuzz_targets/mqtt_decode`).
//!
//! MQTT 5.0 support arrives after v1 (PROMPT §9 "later").

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod decode;
mod encode;
mod validate;

pub use decode::decode;
pub use encode::{EncodeError, encode, encoded_len};
pub use validate::{is_valid_topic_filter, is_valid_topic_name, topic_matches};

/// Largest remaining length MQTT can encode (4-byte varint).
pub const MAX_REMAINING_LENGTH: u32 = 268_435_455;
/// Protocol level of MQTT 3.1.1.
pub const PROTOCOL_LEVEL_3_1_1: u8 = 4;

/// Bounds applied while decoding (from the build-time configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Whole packet: fixed header + remaining length.
    pub max_packet_size: u32,
    pub max_topic_len: u16,
    pub max_topic_levels: u16,
    pub max_client_id_len: u16,
    /// Topic filters in one SUBSCRIBE/UNSUBSCRIBE.
    pub max_topics_per_packet: u16,
}

impl Limits {
    /// The protocol's own maxima (useful for tests and tools).
    pub const PROTOCOL_MAX: Self = Self {
        max_packet_size: MAX_REMAINING_LENGTH + 5,
        max_topic_len: u16::MAX,
        max_topic_levels: u16::MAX,
        max_client_id_len: u16::MAX,
        max_topics_per_packet: u16::MAX,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// At least this many bytes (counted from the start of the packet) are
    /// needed; call again once they have arrived.
    Incomplete(usize),
    MalformedRemainingLength,
    PacketTooLarge,
    InvalidPacketType(u8),
    InvalidFixedHeaderFlags,
    InvalidProtocolName,
    /// Protocol level other than 4. The broker answers CONNACK 0x01.
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
    InvalidReturnCode,
    /// Lengths inside the packet disagree with the remaining length.
    MalformedPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl QoS {
    pub const fn from_bits(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Will<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub qos: QoS,
    pub retain: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect<'a> {
    pub protocol_level: u8,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub client_id: &'a str,
    pub will: Option<Will<'a>>,
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectReturnCode {
    Accepted = 0,
    UnacceptableProtocolVersion = 1,
    IdentifierRejected = 2,
    ServerUnavailable = 3,
    BadUserNameOrPassword = 4,
    NotAuthorized = 5,
}

impl ConnectReturnCode {
    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Accepted,
            1 => Self::UnacceptableProtocolVersion,
            2 => Self::IdentifierRejected,
            3 => Self::ServerUnavailable,
            4 => Self::BadUserNameOrPassword,
            5 => Self::NotAuthorized,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnAck {
    pub session_present: bool,
    pub code: ConnectReturnCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publish<'a> {
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub topic: &'a str,
    /// Present (and non-zero) exactly when `qos > 0`.
    pub packet_id: Option<u16>,
    pub payload: &'a [u8],
}

/// SUBSCRIBE topic list: borrowed raw payload after decoding, or a list
/// when building a packet to encode.
#[derive(Debug, Clone, Copy)]
pub enum SubscribeTopics<'a> {
    Raw(&'a [u8]),
    List(&'a [(&'a str, QoS)]),
}

impl<'a> SubscribeTopics<'a> {
    /// The (filter, requested QoS) pairs. Raw payloads were validated by
    /// `decode`, so iteration cannot fail.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, QoS)> + 'a {
        let (raw, list): (&'a [u8], &'a [(&'a str, QoS)]) = match *self {
            Self::Raw(r) => (r, &[]),
            Self::List(l) => (&[], l),
        };
        decode::RawTopics::new(raw)
            .filter_map(|t| t.ok())
            .map(|(f, opts)| (f, QoS::from_bits(opts & 3).unwrap_or(QoS::AtMostOnce)))
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Subscribe<'a> {
    pub packet_id: u16,
    pub topics: SubscribeTopics<'a>,
}

/// SUBACK return codes: 0x00–0x02 granted QoS, 0x80 failure.
pub const SUBACK_FAILURE: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubAck<'a> {
    pub packet_id: u16,
    pub return_codes: &'a [u8],
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
            .filter_map(|t| t.ok())
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Unsubscribe<'a> {
    pub packet_id: u16,
    pub topics: UnsubscribeTopics<'a>,
}

/// Every MQTT 3.1.1 control packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Packet<'a> {
    Connect(Connect<'a>),
    ConnAck(ConnAck),
    Publish(Publish<'a>),
    PubAck(u16),
    PubRec(u16),
    PubRel(u16),
    PubComp(u16),
    Subscribe(Subscribe<'a>),
    SubAck(SubAck<'a>),
    Unsubscribe(Unsubscribe<'a>),
    UnsubAck(u16),
    PingReq,
    PingResp,
    Disconnect,
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
