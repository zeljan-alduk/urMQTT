//! The WebSocket listener's connections in the MQTT service (ADR-272): a
//! transport adapter between the TLS session and the MQTT session. The
//! service's own paths call in here at a few points (accept, TLS established,
//! decrypted bytes, output, close); everything WebSocket-specific happens here
//! and in `crate::websocket`, so the TLS and plaintext paths are unchanged.
//!
//! What reaches the broker is exactly the MQTT bytes inside the client's
//! binary frames, parsed by the broker's own parser with its own limits.

use alloc::string::String;
use alloc::vec::Vec;

use urmqtt_ws::frame::op;
use urmqtt_ws::upgrade::{self, Scan};

use super::{Leave, MqttService, TX_BUF};
use crate::dataplane::{self, Link};
use crate::websocket::{Decision, Frames, Phase};

impl MqttService {
    /// Whether `port` is the WebSocket listener's.
    pub(super) fn is_ws_port(&self, port: u16) -> bool {
        self.ws.as_ref().is_some_and(|w| w.port() == port)
    }

    /// Whether `c` is a WebSocket connection.
    pub(super) fn is_ws(&self, c: u32) -> bool {
        self.ws.as_ref().is_some_and(|w| w.has(c))
    }

    /// The TLS handshake of WebSocket connection `c` finished. With mtls the
    /// identity waits for the upgrade (the registry was asked already).
    pub(super) fn ws_tls_done(&mut self, c: u32, identity: Option<(String, bool)>) {
        if let Some(w) = self.ws.as_mut() {
            w.tls_done(c, identity.map(|(i, b)| (i.into_boxed_str(), b)));
        }
    }

    /// Decrypted bytes of WebSocket connection `c`: the upgrade request,
    /// then frames. `data` is unmasked in place.
    pub(super) fn ws_input(&mut self, c: u32, data: &mut [u8], link: &mut Link, now_ms: u64) {
        let Some(phase) = self.ws.as_ref().and_then(|w| w.phase(c)) else {
            return;
        };
        match phase {
            // Nothing is read before TLS is up or after the close.
            Phase::Tls | Phase::Closing => {}
            Phase::Request => self.ws_request(c, data, link, now_ms),
            Phase::Login | Phase::Open => self.ws_frames(c, data, phase, link, now_ms),
        }
    }

    /// Sends bytes that are not a frame (the HTTP response) to `c`.
    fn ws_raw(&mut self, c: u32, bytes: &[u8]) {
        if let Some(k) = self.conns.get_mut(&c)
            && let Some(sess) = k.session.as_mut()
            && sess.send(bytes, k.pending.vec_mut()).is_err()
        {
            k.closing = true;
        }
    }

    /// The upgrade request, until it is complete (at most 4 KiB, buffered in
    /// the connection's `early`).
    fn ws_request(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let end = match upgrade::scan(k.early.as_slice()) {
            Scan::Incomplete => return,
            Scan::TooLarge => {
                k.early.take();
                let resp = self.ws.as_mut().map(|w| w.too_large(c));
                if let Some(r) = resp {
                    self.ws_raw(c, r);
                }
                self.start_close(c);
                self.mark_blocked(c);
                return;
            }
            Scan::Complete { end } => end,
        };
        let buf = k.early.take();
        let Some((resp, ok)) = self
            .ws
            .as_mut()
            .map(|w| w.upgrade(c, buf.get(..end).unwrap_or(&[])))
        else {
            return;
        };
        self.ws_raw(c, &resp);
        if !ok {
            self.start_close(c);
            self.mark_blocked(c);
            return;
        }
        // mtls: the certificate's identity is the session's, as on the TLS
        // port; the connection stops being a handshake in flight.
        if !self.ws.as_ref().is_some_and(|w| w.is_password()) {
            let identity = self.ws.as_mut().and_then(|w| w.take_identity(c));
            let attached = match identity {
                Some((id, bootstrap)) => {
                    let home = dataplane::home_of(&id, self.n);
                    if let Some(dbl) = self.db.as_mut()
                        && !bootstrap
                    {
                        dbl.seen(&id);
                    }
                    self.attach(c, home, Some(&id), bootstrap, link, now_ms)
                }
                None => false,
            };
            if !attached {
                self.start_close(c);
                self.mark_blocked(c);
                return;
            }
            self.leave_flight(c, Leave::Done, now_ms);
        }
        // Frames the client sent right behind its request.
        let mut rest = buf.get(end..).unwrap_or(&[]).to_vec();
        if !rest.is_empty()
            && let Some(phase) = self.ws.as_ref().and_then(|w| w.phase(c))
        {
            self.ws_frames(c, &mut rest, phase, link, now_ms);
        }
        self.mark_blocked(c);
    }

    /// Frames of an upgraded connection.
    fn ws_frames(&mut self, c: u32, data: &mut [u8], phase: Phase, link: &mut Link, now_ms: u64) {
        let mut mqtt = Vec::new();
        let mut pongs: Vec<Vec<u8>> = Vec::new();
        let r = match self.ws.as_mut() {
            Some(w) => w.frames(c, data, &mut mqtt, &mut pongs),
            None => return,
        };
        // Pongs while there is room: a client that pings without reading
        // does not grow our buffers (RFC 6455 5.5.3 allows answering only
        // the latest).
        if let (Some(k), Some(w)) = (self.conns.get_mut(&c), self.ws.as_mut())
            && let Some(sess) = k.session.as_mut()
        {
            for p in &pongs {
                if k.pending.len() < TX_BUF {
                    let _ = w.send(c, sess, op::PONG, p, k.pending.vec_mut());
                }
            }
        }
        // MQTT bytes that arrived before a close or a violation still count.
        if !mqtt.is_empty() {
            match phase {
                Phase::Open => self.deliver(c, &mqtt, link, now_ms),
                Phase::Login => self.ws_login(c, &mqtt, link, now_ms),
                _ => {}
            }
        }
        match r {
            Frames::More | Frames::Gone => {}
            // The client closed, or broke the protocol: the MQTT session ends
            // as on a lost connection (the will is published unless it sent
            // DISCONNECT), our close frame answers, then TLS and TCP close.
            Frames::Closed | Frames::Violation(_) => {
                self.detach(c, link, now_ms);
                self.start_close(c);
            }
        }
        self.mark_blocked(c);
    }

    /// Password mode: holds MQTT bytes until the CONNECT is complete, decides
    /// the login, and only then lets the broker see them, as a session of
    /// that identity (`$ws/<identity>/<client id>`) on its home shard.
    fn ws_login(&mut self, c: u32, data: &[u8], link: &mut Link, now_ms: u64) {
        let Some(k) = self.conns.get_mut(&c) else {
            return;
        };
        k.early.extend_from_slice(data);
        let limit = urmqtt_config::CONFIG.websocket.max_packet_size as usize + 5;
        enum Next {
            Wait,
            Refuse(u8),
            Garbage,
            Accept {
                identity: &'static str,
                key: String,
                no_id: bool,
            },
        }
        let decoded = urmqtt_mqtt::decode(k.early.as_slice(), &crate::websocket::mqtt_limits());
        let next = match decoded {
            Ok((urmqtt_mqtt::Packet::Connect(p), _)) => {
                match self.ws.as_mut().map(|w| w.decide(c, &p, now_ms)) {
                    Some(Decision::Accept(identity)) => Next::Accept {
                        identity,
                        key: urmqtt_broker::web_session_key(identity, p.client_id),
                        no_id: p.client_id.is_empty(),
                    },
                    Some(Decision::Refuse(code)) => Next::Refuse(code),
                    None => Next::Refuse(3),
                }
            }
            Err(urmqtt_mqtt::Error::Incomplete(_)) if k.early.len() <= limit => Next::Wait,
            Err(urmqtt_mqtt::Error::UnsupportedProtocolLevel(_)) => Next::Refuse(1),
            _ => Next::Garbage,
        };
        match next {
            Next::Wait => {}
            Next::Refuse(code) => self.ws_refuse(c, code),
            Next::Garbage => {
                if let Some(w) = self.ws.as_mut() {
                    w.garbage(c, now_ms);
                }
                self.ws_refuse(c, 0);
            }
            Next::Accept {
                identity,
                key,
                no_id,
            } => {
                let home = if no_id {
                    self.me
                } else {
                    dataplane::home_of(&key, self.n)
                };
                let home = if dataplane::workers(self.n).contains(&home) {
                    home
                } else {
                    self.me
                };
                let early = self
                    .conns
                    .get_mut(&c)
                    .map(|k| k.early.take())
                    .unwrap_or_default();
                if self.attach_plain(c, home, identity, true, link, now_ms) {
                    self.leave_flight(c, Leave::Done, now_ms);
                    if let Some(w) = self.ws.as_mut() {
                        w.opened(c);
                    }
                    self.deliver(c, &early, link, now_ms);
                } else {
                    self.start_close(c);
                }
            }
        }
    }

    /// A refused login: the CONNACK (`code` 0: none, the bytes were no MQTT)
    /// in a frame, then a close frame 1008 (policy violation).
    fn ws_refuse(&mut self, c: u32, code: u8) {
        if let (Some(k), Some(w)) = (self.conns.get_mut(&c), self.ws.as_mut()) {
            k.early.take();
            if code != 0
                && let Some(sess) = k.session.as_mut()
            {
                let _ = w.send(
                    c,
                    sess,
                    op::BINARY,
                    &[0x20, 0x02, 0x00, code],
                    k.pending.vec_mut(),
                );
            }
            w.set_close(c, urmqtt_ws::frame::close::POLICY);
        }
        self.start_close(c);
        self.mark_blocked(c);
    }

    /// Upgrades that did not complete within `websocket.upgrade_timeout_s`:
    /// reset, as a handshake that timed out.
    pub(super) fn ws_expire(&mut self, link: &mut Link, now_ms: u64) {
        let Some(late) = self.ws.as_mut().map(|w| w.expire(now_ms)) else {
            return;
        };
        for c in late {
            self.detach(c, link, now_ms);
            self.leave_flight(c, Leave::TimedOut, now_ms);
            self.drop_conn(c, now_ms);
            self.aborts.push(c);
        }
    }
}
