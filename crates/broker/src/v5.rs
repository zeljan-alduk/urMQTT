//! The MQTT 5.0 side of the broker (ADR-273 part 2, ADR-274): the state a
//! 5.0 connection carries, the version-neutral views the packet handlers work
//! on, and the helpers that turn the codec's property blocks into what the
//! broker stores. Nothing here is on the path of a 3.1.1 connection: such a
//! connection never has a [`V5State`], and its packets never reach this file.

use alloc::boxed::Box;
use alloc::vec::Vec;

use urmqtt_mqtt::v5 as mqtt5;
use urmqtt_mqtt::v5::{self, Properties, Property, PropertyId, PropertyMask, ReasonCode};
use urmqtt_mqtt::{Limits, QoS};

use crate::{
    Broker, CloseReason, Conn, ConnId, Flow, Msg, PersistOp, Role, SessionId, SubOpts, raw_props,
};

/// The properties the broker adds to a PUBLISH: two inline (the expiry and
/// one identifier), more on the heap (a session with several matching
/// identified subscriptions).
pub(crate) struct ExtraProps {
    buf: [Property<'static>; 2],
    n: usize,
    heap: Vec<Property<'static>>,
}

impl Default for ExtraProps {
    fn default() -> Self {
        Self {
            buf: [Property::PayloadFormatIndicator(0); 2],
            n: 0,
            heap: Vec::new(),
        }
    }
}

impl ExtraProps {
    fn push(&mut self, p: Property<'static>) {
        if !self.heap.is_empty() {
            self.heap.push(p);
        } else if let Some(slot) = self.buf.get_mut(self.n) {
            *slot = p;
            self.n += 1;
        } else {
            self.heap.extend_from_slice(&self.buf);
            self.heap.push(p);
        }
    }
}

impl core::ops::Deref for ExtraProps {
    type Target = [Property<'static>];

    fn deref(&self) -> &[Property<'static>] {
        if self.heap.is_empty() {
            self.buf.get(..self.n).unwrap_or_default()
        } else {
            &self.heap
        }
    }
}

/// What a 5.0 connection carries beyond a 3.1.1 one (ADR-273 rule 19): one
/// box, allocated when its CONNECT is accepted, and the alias table only
/// once the client uses an alias.
#[derive(Debug)]
pub(crate) struct V5State {
    /// The client's Receive Maximum (65 535 when it sent none): with
    /// `max_inflight`, the window of QoS 1 and 2 deliveries to it (rule 7).
    pub receive_max: u16,
    /// The client's Maximum Packet Size (the protocol maximum when it sent
    /// none): a larger packet is not sent (rule 8).
    pub max_packet: u32,
    /// Request Problem Information: reason strings may be sent (rule 13).
    pub problem_info: bool,
    /// The CONNECT asked for Session Expiry 0, so a DISCONNECT may not raise
    /// it [MQTT-3.14.2-2].
    pub connect_expiry_zero: bool,
    /// Topic aliases the client set (index alias − 1), allocated on the
    /// first one with the announced maximum as its length (rule 9).
    pub aliases: Option<Box<[Option<Box<str>>]>>,
}

/// A CONNECT, from either decoder.
pub(crate) struct ConnectIn<'a> {
    pub clean_start: bool,
    pub keep_alive: u16,
    pub client_id: &'a str,
    pub will: Option<WillIn<'a>>,
    /// The 5.0 fields; `None` for a 3.1.1 CONNECT.
    pub v5: Option<ConnectV5>,
}

/// The Will of a CONNECT.
pub(crate) struct WillIn<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    pub qos: QoS,
    pub retain: bool,
    /// The Will Properties (validated by the codec), empty for 3.1.1.
    pub props: &'a [u8],
}

/// The properties of a 5.0 CONNECT that the broker acts on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectV5 {
    /// Session Expiry Interval (absent: 0).
    pub session_expiry: u32,
    pub receive_max: u16,
    pub max_packet: u32,
    pub problem_info: bool,
    /// An Authentication Method was given (enhanced authentication: refused
    /// with 0x8C, rule 15).
    pub auth_method: bool,
}

impl ConnectV5 {
    pub fn of(p: &Properties<'_>) -> Self {
        let mut c = Self {
            session_expiry: 0,
            receive_max: u16::MAX,
            max_packet: v5::MAX_VARINT + 5,
            problem_info: true,
            auth_method: false,
        };
        for prop in p.iter() {
            match prop {
                Property::SessionExpiryInterval(v) => c.session_expiry = v,
                Property::ReceiveMaximum(v) => c.receive_max = v,
                Property::MaximumPacketSize(v) => c.max_packet = v,
                Property::RequestProblemInformation(v) => c.problem_info = v != 0,
                Property::AuthenticationMethod(_) => c.auth_method = true,
                _ => {}
            }
        }
        c
    }
}

/// A PUBLISH from a client, from either decoder, with its topic resolved
/// (a Topic Alias already replaced by its topic).
pub(crate) struct PublishIn<'a> {
    pub qos: QoS,
    pub retain: bool,
    pub topic: &'a str,
    pub packet_id: Option<u16>,
    pub payload: &'a [u8],
    /// The property block (validated by the codec); empty for 3.1.1.
    pub props: &'a [u8],
    /// From a 5.0 connection.
    pub v5: bool,
}

impl Broker {
    /// The 5.0 decoder's bounds over a connection's 3.1.1 ones: the User
    /// Properties bound of the configuration, and one Subscription
    /// Identifier (a client may send none in a PUBLISH, one in a SUBSCRIBE;
    /// the broker refuses a PUBLISH that carries one, 0x82).
    pub(crate) fn limits5(&self, base: Limits) -> mqtt5::Limits {
        mqtt5::Limits {
            base,
            max_user_properties: self.cfg.mqtt5.max_user_properties,
            max_subscription_identifiers: 1,
        }
    }

    /// Closes a 5.0 connection with DISCONNECT `code`.
    pub(crate) fn close5(&mut self, c: ConnId, code: ReasonCode) {
        let why = match code {
            ReasonCode::ProtocolError => CloseReason::ProtocolError,
            ReasonCode::KeepAliveTimeout => CloseReason::KeepAliveTimeout,
            ReasonCode::SessionTakenOver => CloseReason::TakenOver,
            ReasonCode::AdministrativeAction => CloseReason::Disallowed,
            c => CloseReason::Refused(c as u8),
        };
        self.close_with(c, why, Some(code));
    }

    /// A server DISCONNECT with `code` and, if the client allows problem
    /// information, its fixed reason string.
    pub(crate) fn send_disconnect(&mut self, c: ConnId, code: ReasonCode) {
        if let Some(n) = self.stats.disconnects_sent.get_mut(reason_slot(code)) {
            *n += 1;
        }
        let text = reason_text(code);
        let props = [Property::ReasonString(text)];
        let with = self.problem_info(c) && !text.is_empty();
        let p = |props| {
            mqtt5::Packet::Disconnect(mqtt5::Disconnect {
                reason: code,
                properties: props,
            })
        };
        if !(with && self.send5(c, &p(Properties::List(&props)))) {
            self.send5(c, &p(Properties::EMPTY));
        }
    }

    pub(crate) fn problem_info(&self, c: ConnId) -> bool {
        self.conns
            .get(c)
            .and_then(Conn::v5)
            .is_some_and(|v| v.problem_info)
    }

    /// Encodes a 5.0 packet onto `c`'s output. False (nothing written) if
    /// the codec refuses it or it exceeds the client's Maximum Packet Size
    /// (ADR-273 rule 8): the caller decides what to do instead.
    pub(crate) fn send5(&mut self, c: ConnId, p: &mqtt5::Packet<'_>) -> bool {
        let Ok(n) = mqtt5::encoded_len(p) else {
            return false;
        };
        let Some(conn) = self.conn(c) else {
            return false;
        };
        let max = conn.v5().map_or(u32::MAX, |v| v.max_packet);
        if n > max as usize {
            return false;
        }
        let out = conn.outbuf.vec_mut();
        let start = out.len();
        out.resize(start + n, 0);
        let ok = out
            .get_mut(start..)
            .is_some_and(|dst| mqtt5::encode(p, dst).is_ok());
        if !ok {
            out.truncate(start);
        }
        conn.outbuf.release();
        self.make_ready(c);
        ok
    }

    /// One decoded 5.0 packet: mapped onto the version-neutral handlers.
    pub(crate) fn handle5(&mut self, c: ConnId, packet: mqtt5::Packet<'_>, now_ms: u64) {
        let connected = self.conn(c).is_some_and(|k| k.session.is_some());
        match packet {
            mqtt5::Packet::Connect(p) if !connected => self.on_connect5(c, &p, now_ms),
            mqtt5::Packet::Connect(_) => self.close5(c, ReasonCode::ProtocolError),
            _ if !connected => self.mark_close(c, CloseReason::ProtocolError),
            mqtt5::Packet::Publish(p) => self.on_publish5(c, &p, now_ms),
            mqtt5::Packet::PubAck(a) => self.on_puback(c, a.packet_id),
            // A PUBREC with a failure code ends the QoS 2 flow: no PUBREL.
            mqtt5::Packet::PubRec(a) if a.reason.is_error() => {
                if let Some(sid) = self.conn(c).and_then(|k| k.session)
                    && self.complete(sid, a.packet_id, Flow::Pubrec)
                {
                    self.pump(sid);
                }
            }
            mqtt5::Packet::PubRec(a) => self.on_pubrec(c, a.packet_id),
            mqtt5::Packet::PubRel(a) => self.on_pubrel(c, a.packet_id),
            mqtt5::Packet::PubComp(a) => self.on_pubcomp(c, a.packet_id),
            mqtt5::Packet::Subscribe(s) => {
                let topics: Vec<(&str, SubOpts)> = s
                    .topics
                    .iter()
                    .map(|(f, o)| (f, SubOpts(o.to_byte())))
                    .collect();
                let sub_id = s.properties.iter().find_map(|p| match p {
                    Property::SubscriptionIdentifier(id) => Some(id),
                    _ => None,
                });
                self.on_subscribe(c, s.packet_id, &topics, sub_id);
            }
            mqtt5::Packet::Unsubscribe(u) => {
                let topics: Vec<&str> = u.topics.iter().collect();
                self.on_unsubscribe(c, u.packet_id, &topics);
            }
            mqtt5::Packet::PingReq => {
                self.send5(c, &mqtt5::Packet::PingResp);
            }
            mqtt5::Packet::Disconnect(d) => self.on_disconnect5(c, &d),
            // Enhanced authentication is not offered (rule 15).
            mqtt5::Packet::Auth(_) => self.close5(c, ReasonCode::ProtocolError),
            mqtt5::Packet::ConnAck(_)
            | mqtt5::Packet::SubAck(_)
            | mqtt5::Packet::UnsubAck(_)
            | mqtt5::Packet::PingResp => self.close5(c, ReasonCode::ProtocolError),
        }
    }

    /// Refuses a 5.0 CONNECT with `code` (and its reason string when the
    /// client allows problem information).
    pub(crate) fn reject5(&mut self, c: ConnId, code: ReasonCode) {
        if let Some(n) = self.stats.connack_refused.get_mut(reason_slot(code)) {
            *n += 1;
        }
        let text = reason_text(code);
        let props = [Property::ReasonString(text)];
        let with = self.problem_info(c) && !text.is_empty();
        let p = |props| {
            mqtt5::Packet::ConnAck(mqtt5::ConnAck {
                session_present: false,
                reason: code,
                properties: props,
            })
        };
        if !(with && self.send5(c, &p(Properties::List(&props)))) {
            self.send5(c, &p(Properties::EMPTY));
        }
        self.mark_close(c, CloseReason::Rejected);
    }

    /// A 5.0 CONNECT: the connection becomes a 5.0 one (its CONNACK, even a
    /// refusal, already honours the client's Maximum Packet Size and Request
    /// Problem Information), then the version-neutral checks.
    pub(crate) fn on_connect5(&mut self, c: ConnId, p: &mqtt5::Connect<'_>, now_ms: u64) {
        let v = ConnectV5::of(&p.properties);
        if let Some(k) = self.conn(c) {
            k.extra_mut().v5 = Some(Box::new(V5State {
                receive_max: v.receive_max,
                max_packet: v.max_packet,
                problem_info: v.problem_info,
                connect_expiry_zero: v.session_expiry == 0,
                aliases: None,
            }));
        }
        if !self.cfg.mqtt5.enabled {
            return self.reject5(c, ReasonCode::UnsupportedProtocolVersion);
        }
        if v.auth_method {
            return self.reject5(c, ReasonCode::BadAuthenticationMethod);
        }
        let ci = ConnectIn {
            clean_start: p.clean_start,
            keep_alive: p.keep_alive,
            client_id: p.client_id,
            will: p.will.as_ref().map(|w| WillIn {
                topic: w.topic,
                payload: w.payload,
                qos: w.qos,
                retain: w.retain,
                props: raw_props(&w.properties),
            }),
            v5: Some(v),
        };
        self.on_connect(c, &ci, now_ms);
    }

    /// A 5.0 PUBLISH: a Topic Alias resolved or set (ADR-273 rule 9), then
    /// the version-neutral handler.
    pub(crate) fn on_publish5(&mut self, c: ConnId, p: &mqtt5::Publish<'_>, now_ms: u64) {
        // Only a server sends Subscription Identifiers [MQTT-3.3.4-6].
        if p.properties
            .get(mqtt5::PropertyId::SubscriptionIdentifier)
            .is_some()
        {
            return self.close5(c, ReasonCode::ProtocolError);
        }
        let max = self.cfg.mqtt5.topic_alias_maximum;
        let mut held: Option<(u16, Box<str>)> = None;
        if let Some(alias) = p.properties.topic_alias() {
            if alias == 0 || alias > max {
                return self.close5(c, ReasonCode::TopicAliasInvalid);
            }
            let i = usize::from(alias - 1);
            let Some(v) = self.conn(c).and_then(Conn::v5_mut) else {
                return;
            };
            let table = v.aliases.get_or_insert_with(|| {
                (0..max)
                    .map(|_| None)
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            });
            let Some(slot) = table.get_mut(i) else {
                return self.close5(c, ReasonCode::TopicAliasInvalid);
            };
            if p.topic.is_empty() {
                // Taken out while the message is handled (no copy), put back
                // below.
                match slot.take() {
                    Some(t) => held = Some((alias, t)),
                    None => return self.close5(c, ReasonCode::TopicAliasInvalid),
                }
            } else {
                *slot = Some(p.topic.into());
            }
        }
        let topic: &str = match &held {
            Some((_, t)) => t,
            None => p.topic,
        };
        self.on_publish(
            c,
            &PublishIn {
                qos: p.qos,
                retain: p.retain,
                topic,
                packet_id: p.packet_id,
                payload: p.payload,
                props: raw_props(&p.properties),
                v5: true,
            },
            now_ms,
        );
        if let Some((alias, t)) = held
            && let Some(slot) = self
                .conn(c)
                .and_then(Conn::v5_mut)
                .and_then(|v| v.aliases.as_mut())
                .and_then(|a| a.get_mut(usize::from(alias - 1)))
            && slot.is_none()
        {
            *slot = Some(t);
        }
    }

    /// Whether a delivery of `msg` to session `sid` fits the client's
    /// Maximum Packet Size (always for 3.1.1), with the properties the
    /// broker adds (expiry, Subscription Identifiers). A delivery that does
    /// not is dropped as if sent [MQTT-3.1.2-25] and counted.
    pub(crate) fn fits_for(
        &self,
        c: ConnId,
        sid: SessionId,
        msg: &Msg,
        qos: QoS,
        share: u32,
    ) -> bool {
        let Some(v) = self.conns.get(c).and_then(Conn::v5) else {
            return true;
        };
        let extra = self.extra_props(sid, msg, share);
        let p = mqtt5::Packet::Publish(mqtt5::Publish {
            dup: false,
            qos,
            retain: false,
            topic: &msg.topic,
            packet_id: (qos != QoS::AtMostOnce).then_some(1),
            properties: Properties::Forward {
                raw: msg.props(),
                drop: mqtt5::PropertyMask::EMPTY,
                extra: &extra,
            },
            payload: &msg.payload,
        });
        mqtt5::encoded_len(&p).is_ok_and(|n| n <= v.max_packet as usize)
    }

    /// The properties a PUBLISH of `msg` to connection `c` gets besides the
    /// forwarded ones.
    pub(crate) fn publish_extra(&self, c: ConnId, msg: &Msg, share: u32) -> ExtraProps {
        match self.conns.get(c).and_then(|k| k.session) {
            Some(sid) => self.extra_props(sid, msg, share),
            None => ExtraProps::default(),
        }
    }

    /// The remaining Message Expiry Interval (ADR-273 rule 5) and the
    /// Subscription Identifiers of the matching subscriptions (ADR-275).
    /// No allocation unless the session uses identifiers.
    fn extra_props(&self, sid: SessionId, msg: &Msg, share: u32) -> ExtraProps {
        let mut x = ExtraProps::default();
        if msg.expires_ms != 0 {
            x.push(Property::MessageExpiryInterval(remaining_s(
                msg.expires_ms,
                self.now_ms,
            )));
        }
        for id in self.ids_for(sid, &msg.topic, share) {
            x.push(Property::SubscriptionIdentifier(id));
        }
        x
    }

    /// A 5.0 DISCONNECT (§3.14): any reason but 0x00 keeps the Will (0x04
    /// asks for it); a Session Expiry Interval changes the session's, but
    /// never from 0 [MQTT-3.14.2-2] (0x82).
    pub(crate) fn on_disconnect5(&mut self, c: ConnId, d: &mqtt5::Disconnect<'_>) {
        if let Some(e) = d.properties.session_expiry_interval() {
            let from_zero = self
                .conns
                .get(c)
                .and_then(Conn::v5)
                .is_some_and(|v| v.connect_expiry_zero);
            if from_zero && e != 0 {
                return self.close5(c, ReasonCode::ProtocolError);
            }
            let max = self.cfg.mqtt5.max_session_expiry_s;
            let mut upsert = None;
            if let Some(sid) = self.conn(c).and_then(|k| k.session)
                && let Some(s) = self.session(sid)
            {
                let kept = !matches!(s.role, Role::Bootstrap | Role::Plain | Role::Web);
                let new = if kept { e.min(max) } else { 0 };
                s.expiry_s = new;
                if s.persisted && new > 0 {
                    upsert = Some(s.client_id.clone());
                }
            }
            if let Some(client_id) = upsert {
                let expiry_s = e.min(max);
                self.emit(PersistOp::SessionUpsert {
                    client_id,
                    expiry_s,
                });
            }
        }
        if d.reason == ReasonCode::Success
            && let Some(k) = self.conn(c)
            && let Some(e) = &mut k.extra
        {
            e.will = None;
            k.release_extra();
        }
        self.mark_close(c, CloseReason::ClientDisconnect);
    }
}

/// The properties a stored message never keeps (ADR-273 rule 2): Topic
/// Alias and Subscription Identifier belong to one connection, the Message
/// Expiry Interval is kept as a deadline beside the bytes, the Will Delay
/// Interval of a Will is spent when the Will is published.
pub(crate) const NOT_STORED: PropertyMask = PropertyMask::EMPTY
    .with(PropertyId::TopicAlias)
    .with(PropertyId::SubscriptionIdentifier)
    .with(PropertyId::MessageExpiryInterval)
    .with(PropertyId::WillDelayInterval);

/// The bytes of the validated block `raw` without the properties in
/// `drop`, or `None` when nothing is left (a message without properties
/// costs no allocation). The block was validated by the decoder, so each
/// property's encoded length is exactly what it took in `raw` (every
/// Variable Byte Integer the decoder accepts is minimal).
pub(crate) fn strip(raw: &[u8], drop: PropertyMask) -> Option<Box<[u8]>> {
    if raw.is_empty() {
        return None;
    }
    let mut out = alloc::vec::Vec::new();
    let mut at = 0usize;
    for p in Properties::Raw(raw).iter() {
        let n = p.encoded_len();
        let end = at.saturating_add(n);
        if !drop.contains(p.id())
            && let Some(bytes) = raw.get(at..end)
        {
            out.extend_from_slice(bytes);
        }
        at = end;
    }
    (!out.is_empty()).then(|| out.into_boxed_slice())
}

/// The Message Expiry Interval of a property block, if any.
pub(crate) fn message_expiry(raw: &[u8]) -> Option<u32> {
    Properties::Raw(raw).message_expiry_interval()
}

/// The fixed reason string of a server-sent CONNACK or DISCONNECT (rule 13:
/// short, nothing of the client's echoed).
pub(crate) fn reason_text(code: ReasonCode) -> &'static str {
    match code {
        ReasonCode::UnspecifiedError => "unspecified error",
        ReasonCode::MalformedPacket => "malformed packet",
        ReasonCode::ProtocolError => "protocol error",
        ReasonCode::ImplementationSpecificError => "beyond a limit of this server",
        ReasonCode::UnsupportedProtocolVersion => "MQTT 5.0 is disabled on this server",
        ReasonCode::ClientIdentifierNotValid => "client identifier not accepted",
        ReasonCode::BadUserNameOrPassword => "bad user name or password",
        ReasonCode::NotAuthorized => "not authorized",
        ReasonCode::ServerUnavailable => "server unavailable",
        ReasonCode::ServerBusy => "server busy",
        ReasonCode::Banned => "banned",
        ReasonCode::ServerShuttingDown => "server shutting down",
        ReasonCode::BadAuthenticationMethod => "enhanced authentication is not supported",
        ReasonCode::KeepAliveTimeout => "keep alive timeout",
        ReasonCode::SessionTakenOver => "session taken over",
        ReasonCode::TopicFilterInvalid => "topic filter not accepted",
        ReasonCode::TopicNameInvalid => "topic name not accepted",
        ReasonCode::ReceiveMaximumExceeded => "receive maximum exceeded",
        ReasonCode::TopicAliasInvalid => "topic alias invalid",
        ReasonCode::PacketTooLarge => "packet too large",
        ReasonCode::MessageRateTooHigh => "message rate too high",
        ReasonCode::QuotaExceeded => "quota exceeded",
        ReasonCode::AdministrativeAction => "administrative action",
        ReasonCode::RetainNotSupported => "retain not available",
        ReasonCode::ConnectionRateExceeded => "connection rate exceeded",
        _ => "",
    }
}

/// Index of a failure reason code in the per-code counters (0x80..=0xA2).
pub const REASON_SLOTS: usize = 0xa3 - 0x80;

pub(crate) fn reason_slot(code: ReasonCode) -> usize {
    usize::from(code as u8)
        .saturating_sub(0x80)
        .min(REASON_SLOTS - 1)
}

/// The seconds of a message's remaining lifetime as a delivery states it
/// [MQTT-3.3.2-6]: rounded up, so it is never 0 while the message is alive.
pub(crate) fn remaining_s(deadline_ms: u64, now_ms: u64) -> u32 {
    let ms = deadline_ms.saturating_sub(now_ms);
    u32::try_from(ms.div_ceil(1000)).unwrap_or(u32::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_keeps_the_forwarded_properties_in_order() {
        let props = [
            Property::PayloadFormatIndicator(1),
            Property::TopicAlias(3),
            Property::MessageExpiryInterval(10),
            Property::UserProperty("k", "v"),
            Property::ContentType("text/plain"),
        ];
        let mut raw = alloc::vec![0u8; 64];
        let p = v5::Packet::Publish(v5::Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "t",
            packet_id: None,
            properties: Properties::List(&props),
            payload: b"",
        });
        let n = v5::encode(&p, &mut raw).unwrap();
        let (dec, _) = v5::decode(&raw[..n], &v5::Limits::PROTOCOL_MAX).unwrap();
        let v5::Packet::Publish(dec) = dec else {
            panic!()
        };
        let Properties::Raw(block) = dec.properties else {
            panic!()
        };
        let kept = strip(block, NOT_STORED).unwrap();
        let got: alloc::vec::Vec<_> = Properties::Raw(&kept).iter().collect();
        assert_eq!(
            got,
            [
                Property::PayloadFormatIndicator(1),
                Property::UserProperty("k", "v"),
                Property::ContentType("text/plain"),
            ]
        );
        assert_eq!(message_expiry(block), Some(10));
        assert!(strip(&[], NOT_STORED).is_none());
    }

    #[test]
    fn remaining_lifetime_rounds_up_and_never_says_zero() {
        assert_eq!(remaining_s(10_000, 0), 10);
        assert_eq!(remaining_s(10_000, 1), 10);
        assert_eq!(remaining_s(10_000, 9_001), 1);
        assert_eq!(remaining_s(10_000, 10_000), 1);
    }
}
