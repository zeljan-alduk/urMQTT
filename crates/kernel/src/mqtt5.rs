//! MQTT 5.0 in the kernel (ADR-273 part 2, ADR-274). The broker speaks both
//! versions by itself; what the kernel adds is here, so the shared service
//! files only call in:
//!
//! - the CONNECT peek of the login paths (the plaintext listener, P1; the
//!   WebSocket listener's password mode, ADR-272; the dev plaintext port),
//!   which read the client's credentials and client id before the broker sees
//!   the connection: the protocol level picks the decoder (rule 1);
//! - the CONNACK a refused login is answered with, in the client's version;
//! - the restore of the store's sessions and retained messages with their
//!   expiry, properties and subscription options at boot (schema 4).

use core::sync::atomic::{AtomicU64, Ordering};

use urmqtt_broker::sys::Mqtt5Info;
use urmqtt_broker::{Broker, REASON_SLOTS, StoredMsg, StoredSession};
use urmqtt_config::CONFIG;
use urmqtt_mqtt::v5 as m5;
use urmqtt_mqtt::{Limits, QoS};

use crate::dataplane;
use crate::db::Restored;
use crate::smp::MAX_CPUS;

/// A CONNECT as the login checks read it, from either version.
pub struct ConnectView<'a> {
    pub v5: bool,
    pub client_id: &'a str,
    /// 3.1.1: its `clean_session`. 5.0: always true: Clean Start 0 does not
    /// ask for a stored session there, and a Session Expiry Interval that
    /// does is granted 0 by the broker (and told so) instead of refused.
    pub clean_session: bool,
    pub username: Option<&'a str>,
    pub password: Option<&'a [u8]>,
}

/// What the first bytes of a login connection are.
pub enum Peek<'a> {
    Connect(ConnectView<'a>),
    /// Not complete yet (and within the bound).
    Wait,
    /// A CONNECT of a protocol level this broker does not take: 3.1.1's
    /// CONNACK 1, or (level 5 with `mqtt5.enabled` off) 5.0's 0x84.
    Unsupported {
        v5: bool,
    },
    /// No MQTT, or a CONNECT the decoder refuses.
    Garbage,
}

/// The 5.0 decoder's bounds for a login connection: the 3.1.1 ones and the
/// configured User Properties bound.
pub fn limits5(base: Limits) -> m5::Limits {
    m5::Limits {
        base,
        max_user_properties: CONFIG.mqtt5.max_user_properties as u16,
        max_subscription_identifiers: 1,
    }
}

/// Peeks at the CONNECT in `buf` (bytes held so far, at most `max` before it
/// must be complete).
pub fn peek_connect<'a>(buf: &'a [u8], limits: &Limits, max: usize) -> Peek<'a> {
    match m5::connect_protocol_level(buf) {
        Ok(m5::PROTOCOL_LEVEL_5) if !CONFIG.mqtt5.enabled => Peek::Unsupported { v5: true },
        Ok(m5::PROTOCOL_LEVEL_5) => match m5::decode(buf, &limits5(*limits)) {
            Ok((m5::Packet::Connect(p), _)) => Peek::Connect(ConnectView {
                v5: true,
                client_id: p.client_id,
                clean_session: true,
                username: p.username,
                password: p.password,
            }),
            Err(m5::Error::Incomplete(_)) if buf.len() <= max => Peek::Wait,
            _ => Peek::Garbage,
        },
        _ => match urmqtt_mqtt::decode(buf, limits) {
            Ok((urmqtt_mqtt::Packet::Connect(p), _)) => Peek::Connect(ConnectView {
                v5: false,
                client_id: p.client_id,
                clean_session: p.clean_session,
                username: p.username,
                password: p.password,
            }),
            Err(urmqtt_mqtt::Error::Incomplete(_)) if buf.len() <= max => Peek::Wait,
            Err(urmqtt_mqtt::Error::UnsupportedProtocolLevel(_)) => Peek::Unsupported { v5: false },
            _ => Peek::Garbage,
        },
    }
}

/// The CONNACK refusing a login with 3.1.1 return code `code` (1 to 5), in
/// the client's version: 5.0 maps it as the broker does (ADR-273 rule 14:
/// 0x84, 0x85, 0x88, 0x86, 0x87), with no properties. Returns the bytes and
/// their length.
pub fn refusal(code: u8, v5: bool) -> ([u8; 5], usize) {
    if !v5 {
        return ([0x20, 0x02, 0x00, code, 0], 4);
    }
    let reason = match code {
        1 => 0x84,
        2 => 0x85,
        3 => 0x88,
        4 => 0x86,
        5 => 0x87,
        _ => 0x80,
    };
    ([0x20, 0x03, 0x00, reason, 0x00], 5)
}

fn qos_of(q: u8) -> QoS {
    QoS::from_bits(q).unwrap_or(QoS::AtMostOnce)
}

/// Restores what the store holds into the broker of data core `me` (of
/// `n`): every shard a replica of the retained messages, each persistent
/// session on its home shard. Expiry is measured on the wall clock (ADR-273
/// rule 4): a session offline for longer than its Session Expiry Interval is
/// dropped here (ADR-274: at boot, not at first touch), and messages whose
/// Message Expiry Interval ended while the broker was down are not restored.
/// Without a wall clock at boot the time the broker was down is not counted
/// (the latest time the store recorded stands for "now").
pub fn restore(
    broker: &mut Broker,
    r: &Restored,
    me: usize,
    n: usize,
    homed: &mut usize,
    expired: &mut usize,
) {
    let now_ms = urmqtt_arch::time::uptime_ns() / 1_000_000;
    let now = crate::boot::now_unix()
        .and_then(|t| i64::try_from(t).ok())
        .unwrap_or_else(|| {
            r.sessions
                .iter()
                .filter_map(|s| s.offline_since)
                .max()
                .unwrap_or(0)
        });
    let left = |at: Option<i64>| at.map(|t| t.saturating_sub(now));
    for m in &r.retained {
        broker.restore_retained_v5(
            &m.topic,
            &m.payload,
            qos_of(m.qos),
            m.props.as_deref(),
            left(m.expires_at),
            now_ms,
        );
    }
    for sess in r
        .sessions
        .iter()
        .filter(|s| dataplane::home_of(&s.client_id, n) == me)
    {
        let before = broker.stats().sessions_expired;
        let st = StoredSession {
            expiry_s: sess.expiry_s,
            offline_for_s: sess
                .offline_since
                .map_or(0, |t| u64::try_from(now.saturating_sub(t)).unwrap_or(0)),
            now_ms,
        };
        let ok = broker.restore_session_v5(
            &sess.client_id,
            st,
            sess.subscriptions.iter().map(|(f, o)| (f.as_str(), *o)),
            sess.queued.iter().map(|q| StoredMsg {
                topic: &q.topic,
                payload: &q.payload,
                qos: qos_of(q.qos),
                pid: (q.pid != 0).then_some(q.pid),
                props: q.props.as_deref(),
                expires_in_s: left(q.expires_at),
            }),
            sess.qos2_ids.iter().map(|i| {
                if i.released {
                    urmqtt_broker::Qos2Id::Released(i.pid)
                } else {
                    urmqtt_broker::Qos2Id::Received(i.pid)
                }
            }),
        );
        if ok {
            *homed += 1;
        } else if broker.stats().sessions_expired > before {
            *expired += 1;
        }
    }
}

/// The broker's MQTT 5.0 policy from the configuration (format 12).
pub fn broker_policy() -> urmqtt_broker::Mqtt5Policy {
    let m = &CONFIG.mqtt5;
    let l = &CONFIG.limits;
    urmqtt_broker::Mqtt5Policy {
        enabled: m.enabled,
        receive_maximum: m.receive_maximum as u16,
        topic_alias_maximum: m.topic_alias_maximum as u16,
        max_user_properties: m.max_user_properties as u16,
        max_keep_alive_s: m.max_keep_alive_s as u16,
        max_session_expiry_s: l.max_session_expiry_s,
        default_session_expiry_s: l.default_session_expiry_s,
        max_message_expiry_s: l.max_message_expiry_s,
    }
}

/// What one shard reports about MQTT 5.0 (`$SYS/broker/...`, ADR-274), as
/// the other counters of `crate::sys`: each written by its own core,
/// relaxed.
struct Shard5 {
    online: AtomicU64,
    messages_expired: AtomicU64,
    dropped_too_large: AtomicU64,
    sessions_expired: AtomicU64,
    sessions_expiring: AtomicU64,
    wills_delayed: AtomicU64,
    wills_pending: AtomicU64,
    disconnects: [AtomicU64; REASON_SLOTS],
    refused: [AtomicU64; REASON_SLOTS],
}

impl Shard5 {
    const fn new() -> Self {
        Self {
            online: AtomicU64::new(0),
            messages_expired: AtomicU64::new(0),
            dropped_too_large: AtomicU64::new(0),
            sessions_expired: AtomicU64::new(0),
            sessions_expiring: AtomicU64::new(0),
            wills_delayed: AtomicU64::new(0),
            wills_pending: AtomicU64::new(0),
            disconnects: [const { AtomicU64::new(0) }; REASON_SLOTS],
            refused: [const { AtomicU64::new(0) }; REASON_SLOTS],
        }
    }
}

static SHARDS5: [Shard5; MAX_CPUS] = [const { Shard5::new() }; MAX_CPUS];

/// Writes core `me`'s MQTT 5.0 counters from its broker's statistics.
pub fn report(me: usize, st: &urmqtt_broker::Stats) {
    let Some(s) = SHARDS5.get(me) else { return };
    // Relaxed: statistics, written by this core only.
    let put = |a: &AtomicU64, v: u64| a.store(v, Ordering::Relaxed);
    put(&s.online, st.online_v5 as u64);
    put(&s.messages_expired, st.messages_expired);
    put(&s.dropped_too_large, st.dropped_too_large);
    put(&s.sessions_expired, st.sessions_expired);
    put(&s.sessions_expiring, st.sessions_expiring as u64);
    put(&s.wills_delayed, st.wills_delayed);
    put(&s.wills_pending, st.wills_pending as u64);
    for (a, v) in s.disconnects.iter().zip(st.disconnects_sent) {
        put(a, v);
    }
    for (a, v) in s.refused.iter().zip(st.connack_refused) {
        put(a, v);
    }
}

/// The MQTT 5.0 counters of all cores.
pub fn info() -> Mqtt5Info {
    let mut m = Mqtt5Info::default();
    // Relaxed: statistics.
    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
    for s in SHARDS5.iter() {
        m.connected += get(&s.online);
        m.messages_expired += get(&s.messages_expired);
        m.dropped_too_large += get(&s.dropped_too_large);
        m.sessions_expired += get(&s.sessions_expired);
        m.sessions_expiring += get(&s.sessions_expiring);
        m.wills_delayed += get(&s.wills_delayed);
        m.wills_pending += get(&s.wills_pending);
        for (t, a) in m.disconnects.iter_mut().zip(s.disconnects.iter()) {
            *t += get(a);
        }
        for (t, a) in m.refused.iter_mut().zip(s.refused.iter()) {
            *t += get(a);
        }
    }
    m
}
