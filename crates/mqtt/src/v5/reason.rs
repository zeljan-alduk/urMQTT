//! Reason codes (§2.4) and the codes each packet may carry (§3.2.2.2,
//! §3.4.2.1, §3.5.2.1, §3.6.2.1, §3.7.2.1, §3.9.3, §3.11.3, §3.14.2.1,
//! §3.15.2.1).

use super::PacketType;

/// One reason code. 0x00 is Success, Normal disconnection (DISCONNECT) and
/// Granted QoS 0 (SUBACK) at once; 0x01/0x02 are Granted QoS 1/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ReasonCode {
    Success = 0x00,
    GrantedQos1 = 0x01,
    GrantedQos2 = 0x02,
    DisconnectWithWillMessage = 0x04,
    NoMatchingSubscribers = 0x10,
    NoSubscriptionExisted = 0x11,
    ContinueAuthentication = 0x18,
    ReAuthenticate = 0x19,
    UnspecifiedError = 0x80,
    MalformedPacket = 0x81,
    ProtocolError = 0x82,
    ImplementationSpecificError = 0x83,
    UnsupportedProtocolVersion = 0x84,
    ClientIdentifierNotValid = 0x85,
    BadUserNameOrPassword = 0x86,
    NotAuthorized = 0x87,
    ServerUnavailable = 0x88,
    ServerBusy = 0x89,
    Banned = 0x8a,
    ServerShuttingDown = 0x8b,
    BadAuthenticationMethod = 0x8c,
    KeepAliveTimeout = 0x8d,
    SessionTakenOver = 0x8e,
    TopicFilterInvalid = 0x8f,
    TopicNameInvalid = 0x90,
    PacketIdentifierInUse = 0x91,
    PacketIdentifierNotFound = 0x92,
    ReceiveMaximumExceeded = 0x93,
    TopicAliasInvalid = 0x94,
    PacketTooLarge = 0x95,
    MessageRateTooHigh = 0x96,
    QuotaExceeded = 0x97,
    AdministrativeAction = 0x98,
    PayloadFormatInvalid = 0x99,
    RetainNotSupported = 0x9a,
    QosNotSupported = 0x9b,
    UseAnotherServer = 0x9c,
    ServerMoved = 0x9d,
    SharedSubscriptionsNotSupported = 0x9e,
    ConnectionRateExceeded = 0x9f,
    MaximumConnectTime = 0xa0,
    SubscriptionIdentifiersNotSupported = 0xa1,
    WildcardSubscriptionsNotSupported = 0xa2,
}

/// The packets that carry reason codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonTable {
    ConnAck,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    SubAck,
    UnsubAck,
    Disconnect,
    Auth,
}

impl ReasonTable {
    pub const ALL: [Self; 9] = [
        Self::ConnAck,
        Self::PubAck,
        Self::PubRec,
        Self::PubRel,
        Self::PubComp,
        Self::SubAck,
        Self::UnsubAck,
        Self::Disconnect,
        Self::Auth,
    ];

    const fn bit(self) -> u16 {
        1 << (self.packet_type() as u8)
    }

    pub const fn packet_type(self) -> PacketType {
        match self {
            Self::ConnAck => PacketType::ConnAck,
            Self::PubAck => PacketType::PubAck,
            Self::PubRec => PacketType::PubRec,
            Self::PubRel => PacketType::PubRel,
            Self::PubComp => PacketType::PubComp,
            Self::SubAck => PacketType::SubAck,
            Self::UnsubAck => PacketType::UnsubAck,
            Self::Disconnect => PacketType::Disconnect,
            Self::Auth => PacketType::Auth,
        }
    }
}

// Bit per packet type (the PacketType value): which packets may carry a code.
const CA: u16 = 1 << 2;
const PA: u16 = 1 << 4;
const PR: u16 = 1 << 5;
const PL: u16 = 1 << 6;
const PC: u16 = 1 << 7;
const SA: u16 = 1 << 9;
const UA: u16 = 1 << 11;
const DI: u16 = 1 << 14;
const AU: u16 = 1 << 15;

impl ReasonCode {
    /// Every reason code of §2.4, ascending.
    pub const ALL: [Self; 43] = [
        Self::Success,
        Self::GrantedQos1,
        Self::GrantedQos2,
        Self::DisconnectWithWillMessage,
        Self::NoMatchingSubscribers,
        Self::NoSubscriptionExisted,
        Self::ContinueAuthentication,
        Self::ReAuthenticate,
        Self::UnspecifiedError,
        Self::MalformedPacket,
        Self::ProtocolError,
        Self::ImplementationSpecificError,
        Self::UnsupportedProtocolVersion,
        Self::ClientIdentifierNotValid,
        Self::BadUserNameOrPassword,
        Self::NotAuthorized,
        Self::ServerUnavailable,
        Self::ServerBusy,
        Self::Banned,
        Self::ServerShuttingDown,
        Self::BadAuthenticationMethod,
        Self::KeepAliveTimeout,
        Self::SessionTakenOver,
        Self::TopicFilterInvalid,
        Self::TopicNameInvalid,
        Self::PacketIdentifierInUse,
        Self::PacketIdentifierNotFound,
        Self::ReceiveMaximumExceeded,
        Self::TopicAliasInvalid,
        Self::PacketTooLarge,
        Self::MessageRateTooHigh,
        Self::QuotaExceeded,
        Self::AdministrativeAction,
        Self::PayloadFormatInvalid,
        Self::RetainNotSupported,
        Self::QosNotSupported,
        Self::UseAnotherServer,
        Self::ServerMoved,
        Self::SharedSubscriptionsNotSupported,
        Self::ConnectionRateExceeded,
        Self::MaximumConnectTime,
        Self::SubscriptionIdentifiersNotSupported,
        Self::WildcardSubscriptionsNotSupported,
    ];

    pub const fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::Success,
            0x01 => Self::GrantedQos1,
            0x02 => Self::GrantedQos2,
            0x04 => Self::DisconnectWithWillMessage,
            0x10 => Self::NoMatchingSubscribers,
            0x11 => Self::NoSubscriptionExisted,
            0x18 => Self::ContinueAuthentication,
            0x19 => Self::ReAuthenticate,
            0x80 => Self::UnspecifiedError,
            0x81 => Self::MalformedPacket,
            0x82 => Self::ProtocolError,
            0x83 => Self::ImplementationSpecificError,
            0x84 => Self::UnsupportedProtocolVersion,
            0x85 => Self::ClientIdentifierNotValid,
            0x86 => Self::BadUserNameOrPassword,
            0x87 => Self::NotAuthorized,
            0x88 => Self::ServerUnavailable,
            0x89 => Self::ServerBusy,
            0x8a => Self::Banned,
            0x8b => Self::ServerShuttingDown,
            0x8c => Self::BadAuthenticationMethod,
            0x8d => Self::KeepAliveTimeout,
            0x8e => Self::SessionTakenOver,
            0x8f => Self::TopicFilterInvalid,
            0x90 => Self::TopicNameInvalid,
            0x91 => Self::PacketIdentifierInUse,
            0x92 => Self::PacketIdentifierNotFound,
            0x93 => Self::ReceiveMaximumExceeded,
            0x94 => Self::TopicAliasInvalid,
            0x95 => Self::PacketTooLarge,
            0x96 => Self::MessageRateTooHigh,
            0x97 => Self::QuotaExceeded,
            0x98 => Self::AdministrativeAction,
            0x99 => Self::PayloadFormatInvalid,
            0x9a => Self::RetainNotSupported,
            0x9b => Self::QosNotSupported,
            0x9c => Self::UseAnotherServer,
            0x9d => Self::ServerMoved,
            0x9e => Self::SharedSubscriptionsNotSupported,
            0x9f => Self::ConnectionRateExceeded,
            0xa0 => Self::MaximumConnectTime,
            0xa1 => Self::SubscriptionIdentifiersNotSupported,
            0xa2 => Self::WildcardSubscriptionsNotSupported,
            _ => return None,
        })
    }

    /// Codes 0x80 and above are failures (§2.4).
    pub const fn is_error(self) -> bool {
        self as u8 >= 0x80
    }

    /// The packets that may carry this code (the "MQTT Control Packets"
    /// column of §2.4, Table 2-6).
    const fn packets(self) -> u16 {
        match self {
            Self::Success => CA | PA | PR | PL | PC | SA | UA | DI | AU,
            Self::GrantedQos1 | Self::GrantedQos2 => SA,
            Self::DisconnectWithWillMessage => DI,
            Self::NoMatchingSubscribers => PA | PR,
            Self::NoSubscriptionExisted => UA,
            Self::ContinueAuthentication | Self::ReAuthenticate => AU,
            Self::UnspecifiedError | Self::ImplementationSpecificError | Self::NotAuthorized => {
                CA | PA | PR | SA | UA | DI
            }
            Self::MalformedPacket | Self::ProtocolError => CA | DI,
            Self::UnsupportedProtocolVersion
            | Self::ClientIdentifierNotValid
            | Self::BadUserNameOrPassword
            | Self::ServerUnavailable
            | Self::Banned => CA,
            Self::ServerBusy
            | Self::BadAuthenticationMethod
            | Self::PacketTooLarge
            | Self::RetainNotSupported
            | Self::QosNotSupported
            | Self::UseAnotherServer
            | Self::ServerMoved
            | Self::ConnectionRateExceeded => CA | DI,
            Self::ServerShuttingDown
            | Self::KeepAliveTimeout
            | Self::SessionTakenOver
            | Self::ReceiveMaximumExceeded
            | Self::TopicAliasInvalid
            | Self::MessageRateTooHigh
            | Self::AdministrativeAction
            | Self::MaximumConnectTime => DI,
            Self::TopicFilterInvalid => SA | UA | DI,
            Self::TopicNameInvalid | Self::PayloadFormatInvalid => CA | PA | PR | DI,
            Self::PacketIdentifierInUse => PA | PR | SA | UA,
            Self::PacketIdentifierNotFound => PL | PC,
            Self::QuotaExceeded => CA | PA | PR | SA | DI,
            Self::SharedSubscriptionsNotSupported
            | Self::SubscriptionIdentifiersNotSupported
            | Self::WildcardSubscriptionsNotSupported => SA | DI,
        }
    }

    /// Whether `table`'s packet may carry this code.
    pub const fn allowed_in(self, table: ReasonTable) -> bool {
        self.packets() & table.bit() != 0
    }

    /// Decodes a byte for `table`'s packet.
    pub const fn for_packet(b: u8, table: ReasonTable) -> Option<Self> {
        match Self::from_u8(b) {
            Some(c) if c.allowed_in(table) => Some(c),
            _ => None,
        }
    }

    /// The SUBACK code granting `qos`.
    pub const fn granted(qos: crate::QoS) -> Self {
        match qos {
            crate::QoS::AtMostOnce => Self::Success,
            crate::QoS::AtLeastOnce => Self::GrantedQos1,
            crate::QoS::ExactlyOnce => Self::GrantedQos2,
        }
    }
}
