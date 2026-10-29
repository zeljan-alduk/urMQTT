//! MQTT over plain TCP (dev builds only, M9): smoltcp sockets on
//! `network.mqtt_plain_port` pumping bytes into the sans-IO broker.
//!
//! The build-time configuration refuses a plaintext port outside `dev`, so
//! production images never contain a listener for this module.

use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use urmqtt_broker::{Acl, Broker, CloseReason, Config, ConnId};
use urmqtt_config::CONFIG;
use urmqtt_log::{info, warn};
use urmqtt_mqtt::Limits;

/// Simultaneous plaintext connections (dev only; the TLS data plane scales
/// differently, M13–M15).
const SOCKETS: usize = 32;
const RX_BUF: usize = 8 * 1024;
const TX_BUF: usize = 32 * 1024;

struct Slot {
    handle: SocketHandle,
    conn: Option<ConnId>,
    closing: bool,
}

pub struct PlainMqtt {
    port: u16,
    broker: Broker,
    slots: Vec<Slot>,
    buf: Vec<u8>,
}

/// Broker configuration derived from the build-time configuration.
pub fn broker_config(max_connections: usize) -> Config {
    let l = CONFIG.limits;
    Config {
        limits: Limits {
            max_packet_size: l.max_packet_size,
            max_topic_len: l.max_topic_len as u16,
            max_topic_levels: l.max_topic_levels as u16,
            // Identities become topic levels, so the topic bound applies.
            max_client_id_len: l.max_topic_len as u16,
            max_topics_per_packet: l.max_subscriptions_per_session as u16,
        },
        max_connections: max_connections.min(l.max_connections_per_core as usize),
        max_subscriptions_per_session: l.max_subscriptions_per_session as usize,
        max_inflight: l.max_inflight_qos1 as usize,
        max_queued: l.max_queued_per_offline_session as usize,
        rate_tokens: l.publish_rate_per_device.tokens,
        rate_period_ms: l.publish_rate_per_device.per_ms,
        max_outbound_bytes: TX_BUF,
        acl: Acl {
            device_publish: CONFIG.acl.device_publish,
            device_subscribe: CONFIG.acl.device_subscribe,
            service_ids: CONFIG.acl.service_ids,
            service_publish: CONFIG.acl.service_publish,
            service_subscribe: CONFIG.acl.service_subscribe,
        },
    }
}

impl PlainMqtt {
    pub fn new(port: u16, sockets: &mut SocketSet<'_>) -> Self {
        let slots = (0..SOCKETS)
            .map(|_| Slot {
                handle: sockets.add(tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; RX_BUF]),
                    tcp::SocketBuffer::new(vec![0; TX_BUF]),
                )),
                conn: None,
                closing: false,
            })
            .collect();
        warn!("mqtt: PLAINTEXT listener on port {port} (dev build only, identity = client id)");
        Self {
            port,
            broker: Broker::new(broker_config(SOCKETS)),
            slots,
            buf: vec![0; RX_BUF],
        }
    }

    /// One pass over every socket. Returns true if any bytes moved.
    pub fn poll(&mut self, sockets: &mut SocketSet<'_>, now_ms: u64) -> bool {
        let mut activity = false;
        self.broker.tick(now_ms);
        for slot in &mut self.slots {
            let s = sockets.get_mut::<tcp::Socket>(slot.handle);
            if !s.is_open() {
                if let Some(c) = slot.conn.take() {
                    finish(&mut self.broker, c, now_ms);
                }
                slot.closing = false;
                let _ = s.listen(self.port);
                continue;
            }
            if slot.conn.is_none() && s.may_recv() {
                match self.broker.open(now_ms) {
                    Some(c) => slot.conn = Some(c),
                    None => {
                        s.abort();
                        continue;
                    }
                }
            }
            let Some(c) = slot.conn else { continue };
            while s.can_recv() {
                let n = s.recv_slice(&mut self.buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                activity = true;
                self.broker
                    .input(c, self.buf.get(..n).unwrap_or(&[]), now_ms);
            }
            let out = self.broker.output(c);
            if !out.is_empty() && s.can_send() {
                let n = s.send_slice(out).unwrap_or(0);
                if n > 0 {
                    activity = true;
                    self.broker.consumed(c, n);
                }
            }
            // Peer closed its side (or reset): the session ends uncleanly
            // unless a DISCONNECT arrived first.
            let peer_gone = !s.may_recv() && !s.may_send() || s.state() == tcp::State::CloseWait;
            let want_close =
                self.broker.close_requested(c).is_some() && self.broker.output(c).is_empty();
            if (want_close || peer_gone) && !slot.closing {
                slot.closing = true;
                s.close();
            }
            if slot.closing
                && (s.state() == tcp::State::TimeWait || s.state() == tcp::State::Closed)
            {
                finish(&mut self.broker, c, now_ms);
                slot.conn = None;
                slot.closing = false;
                s.abort();
            }
        }
        activity
    }
}

fn finish(broker: &mut Broker, c: ConnId, now_ms: u64) {
    let who = broker.client_id(c).map(alloc::string::String::from);
    let reason = broker.close_requested(c);
    broker.closed(c, now_ms);
    let st = broker.stats();
    info!(
        "mqtt: {} disconnected ({}), {} session(s), {} retained",
        who.as_deref().unwrap_or("<no session>"),
        match reason {
            Some(CloseReason::ClientDisconnect) => "clean",
            Some(CloseReason::KeepAliveTimeout) => "keepalive timeout",
            Some(CloseReason::TakenOver) => "taken over",
            Some(CloseReason::ProtocolError) => "protocol error",
            Some(CloseReason::Rejected) => "rejected",
            Some(CloseReason::Unsupported) => "unsupported",
            None => "network closed, will published if set",
        },
        st.sessions,
        st.retained
    );
}
