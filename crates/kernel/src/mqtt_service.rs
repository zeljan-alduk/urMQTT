//! MQTT service on smoltcp: the TLS listener (`network.mqtt_tls_port`, mTLS,
//! identity from the client certificate) and, in dev builds only, the
//! plaintext listener. Both feed one sans-IO broker.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use urmqtt_broker::{Acl, Broker, CloseReason, Config, ConnId};
use urmqtt_config::CONFIG;
use urmqtt_log::{info, warn};
use urmqtt_mqtt::Limits;
use urmqtt_tls::{Event, IdentityField, ServerSetup, TlsServer, TlsSession};

const TLS_SOCKETS: usize = 32;
/// Plaintext connections (dev only).
const PLAIN_SOCKETS: usize = 16;
const RX_BUF: usize = 8 * 1024;
const TX_BUF: usize = 32 * 1024;
/// A handshake must finish within this time (PROMPT §6).
const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

struct Slot {
    handle: SocketHandle,
    port: u16,
    tls: bool,
    session: Option<Box<TlsSession>>,
    conn: Option<ConnId>,
    /// Ciphertext (or plaintext on the dev port) not yet taken by the socket.
    pending: Vec<u8>,
    accepted_ms: u64,
    closing: bool,
}

/// Per-core handshake admission (token bucket, PROMPT §6).
struct Admission {
    tokens: u32,
    last_ms: u64,
}

pub struct MqttService {
    broker: Broker,
    tls: Option<TlsServer>,
    slots: Vec<Slot>,
    buf: Vec<u8>,
    app: Vec<u8>,
    admission: Admission,
    refused: u64,
}

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

fn tls_server() -> Option<TlsServer> {
    let setup = ServerSetup {
        ca_pem: urmqtt_config::CA_PEM,
        cert_pem: urmqtt_config::SERVER_CERT_PEM,
        key_pem: urmqtt_config::SERVER_KEY_PEM,
        identity_field: match CONFIG.tls.identity_field {
            urmqtt_config::IdentityField::Cn => IdentityField::Cn,
            urmqtt_config::IdentityField::SanUri => IdentityField::SanUri,
        },
        resumption: CONFIG.tls.resumption,
        revoked_hex: CONFIG.tls.revoked_serials,
        version: crate::VERSION,
    };
    match TlsServer::new(&setup) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("tls: server setup failed: {e:?}");
            None
        }
    }
}

fn add_slots(sockets: &mut SocketSet<'_>, slots: &mut Vec<Slot>, n: usize, port: u16, tls: bool) {
    for _ in 0..n {
        slots.push(Slot {
            handle: sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; RX_BUF]),
                tcp::SocketBuffer::new(vec![0; TX_BUF]),
            )),
            port,
            tls,
            session: None,
            conn: None,
            pending: Vec::new(),
            accepted_ms: 0,
            closing: false,
        });
    }
}

impl MqttService {
    pub fn new(sockets: &mut SocketSet<'_>) -> Self {
        let mut slots = Vec::new();
        let tls = tls_server();
        if tls.is_some() {
            add_slots(
                sockets,
                &mut slots,
                TLS_SOCKETS,
                CONFIG.network.mqtt_tls_port,
                true,
            );
            info!(
                "mqtt: TLS 1.3 listener on port {} (mutual TLS, identity = certificate {:?}, {} revoked serial(s))",
                CONFIG.network.mqtt_tls_port,
                CONFIG.tls.identity_field,
                CONFIG.tls.revoked_serials.len()
            );
        }
        if let Some(port) = CONFIG.network.mqtt_plain_port {
            add_slots(sockets, &mut slots, PLAIN_SOCKETS, port, false);
            warn!("mqtt: PLAINTEXT listener on port {port} (dev build only, identity = client id)");
        }
        Self {
            broker: Broker::new(broker_config(TLS_SOCKETS + PLAIN_SOCKETS)),
            tls,
            slots,
            buf: vec![0; RX_BUF],
            app: Vec::new(),
            admission: Admission {
                tokens: CONFIG.limits.handshakes_per_core_per_sec,
                last_ms: 0,
            },
            refused: 0,
        }
    }

    /// One pass over every socket. Returns true if any bytes moved.
    pub fn poll(&mut self, sockets: &mut SocketSet<'_>, now_ms: u64) -> bool {
        let mut activity = false;
        self.broker.tick(now_ms);
        for i in 0..self.slots.len() {
            activity |= self.poll_slot(i, sockets, now_ms);
        }
        activity
    }

    fn reset_slot(broker: &mut Broker, slot: &mut Slot, now_ms: u64) {
        if let Some(c) = slot.conn.take() {
            finish(broker, c, now_ms);
        }
        slot.session = None;
        slot.pending.clear();
        slot.closing = false;
    }

    fn poll_slot(&mut self, i: usize, sockets: &mut SocketSet<'_>, now_ms: u64) -> bool {
        let Some(slot) = self.slots.get_mut(i) else {
            return false;
        };
        let s = sockets.get_mut::<tcp::Socket>(slot.handle);
        if !s.is_open() {
            Self::reset_slot(&mut self.broker, slot, now_ms);
            let _ = s.listen(slot.port);
            return false;
        }
        let mut activity = false;
        let fresh = slot.session.is_none() && slot.conn.is_none() && s.may_recv() && !slot.closing;
        if fresh {
            if slot.tls {
                let admitted = {
                    let rate = CONFIG.limits.handshakes_per_core_per_sec;
                    let elapsed = now_ms.saturating_sub(self.admission.last_ms);
                    let refill = (elapsed * u64::from(rate) / 1000) as u32;
                    if refill > 0 {
                        self.admission.tokens =
                            self.admission.tokens.saturating_add(refill).min(rate);
                        self.admission.last_ms = now_ms;
                    }
                    self.admission.tokens > 0
                };
                let session = self.tls.as_ref().and_then(|t| t.accept().ok());
                match (admitted, session) {
                    (true, Some(sess)) => {
                        self.admission.tokens -= 1;
                        slot.session = Some(Box::new(sess));
                        slot.accepted_ms = now_ms;
                    }
                    _ => {
                        self.refused += 1;
                        // Rate-limited log: 1st, 2nd, 4th, 8th, ... refusal.
                        if self.refused.is_power_of_two() {
                            warn!(
                                "tls: {} handshake(s) refused by admission control",
                                self.refused
                            );
                        }
                        s.abort();
                        return false;
                    }
                }
            } else {
                match self.broker.open(now_ms) {
                    Some(c) => slot.conn = Some(c),
                    None => {
                        s.abort();
                        return false;
                    }
                }
            }
        }

        // A listening (or not yet accepted) socket has nothing more to do;
        // in particular it must not be mistaken for a closed peer below.
        if slot.session.is_none() && slot.conn.is_none() {
            return activity;
        }

        // Inbound.
        while s.can_recv() {
            let n = s.recv_slice(&mut self.buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            activity = true;
            let data = self.buf.get(..n).unwrap_or(&[]);
            if let Some(sess) = slot.session.as_mut() {
                self.app.clear();
                match sess.input(data, &mut slot.pending, &mut self.app) {
                    Ok(Event::Established {
                        identity,
                        suite,
                        resumed,
                    }) => match self.broker.open(now_ms) {
                        Some(c) => {
                            self.broker.set_identity(c, &identity);
                            slot.conn = Some(c);
                            info!(
                                "tls: {identity} authenticated ({suite}{})",
                                if resumed { ", resumed" } else { "" }
                            );
                        }
                        None => slot.closing = true,
                    },
                    Ok(Event::PeerClosed) => slot.closing = true,
                    Ok(Event::None) => {}
                    Err(e) => {
                        warn!("tls: connection refused: {e:?}");
                        slot.closing = true;
                        s.abort();
                        return true;
                    }
                }
                if let Some(c) = slot.conn
                    && !self.app.is_empty()
                {
                    self.broker.input(c, &self.app, now_ms);
                }
            } else if let Some(c) = slot.conn {
                self.broker.input(c, data, now_ms);
            }
        }

        // Handshake deadline.
        if slot.conn.is_none()
            && slot.session.is_some()
            && now_ms.saturating_sub(slot.accepted_ms) > HANDSHAKE_TIMEOUT_MS
        {
            warn!("tls: handshake timed out");
            s.abort();
            Self::reset_slot(&mut self.broker, slot, now_ms);
            return true;
        }

        // Outbound: broker -> (TLS) -> socket.
        if let Some(c) = slot.conn
            && slot.pending.len() < TX_BUF
        {
            let out = self.broker.output(c);
            if !out.is_empty() {
                let n = out.len();
                match slot.session.as_mut() {
                    Some(sess) => {
                        if sess.send(out, &mut slot.pending).is_err() {
                            slot.closing = true;
                        }
                    }
                    None => slot.pending.extend_from_slice(out),
                }
                self.broker.consumed(c, n);
            }
        }
        if !slot.pending.is_empty() && s.can_send() {
            let n = s.send_slice(&slot.pending).unwrap_or(0);
            if n > 0 {
                activity = true;
                slot.pending.drain(..n);
            }
        }

        // Closing.
        let peer_gone = (!s.may_recv() && !s.may_send()) || s.state() == tcp::State::CloseWait;
        let broker_done = slot.conn.is_some_and(|c| {
            self.broker.close_requested(c).is_some() && self.broker.output(c).is_empty()
        });
        if (broker_done || peer_gone || slot.closing)
            && slot.pending.is_empty()
            && s.state() != tcp::State::Closed
        {
            // close_notify even after the peer's FIN (CloseWait still allows
            // sending): clients like mosquitto half-close right after
            // DISCONNECT and OpenSSL 3 treats a missing close_notify as an error.
            if let Some(sess) = slot.session.as_mut()
                && s.may_send()
            {
                sess.close(&mut slot.pending);
                if !slot.pending.is_empty() && s.can_send() {
                    let n = s.send_slice(&slot.pending).unwrap_or(0);
                    slot.pending.drain(..n);
                }
            }
            if !slot.closing || broker_done || peer_gone {
                slot.closing = true;
                s.close();
            }
        }
        // Once our FIN is acknowledged the session is over. The socket stays
        // in TIME_WAIT and re-listens when it closes: aborting here would
        // send a RST that can overtake our close_notify on its way to the
        // client (OpenSSL 3 then reports "unexpected eof").
        if slot.closing && matches!(s.state(), tcp::State::TimeWait | tcp::State::Closed) {
            Self::reset_slot(&mut self.broker, slot, now_ms);
        }
        activity
    }
}

fn finish(broker: &mut Broker, c: ConnId, now_ms: u64) {
    let who: Option<String> = broker.client_id(c).map(String::from);
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
