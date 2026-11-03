// A small MQTT 3.1.1 client for the "Try urMQTT live" page: plain JavaScript, no dependencies, no network
// access of its own except the WebSocket it is given. It speaks over a WebSocket with the subprotocol "mqtt"
// (binary messages), the way the demo bridge (deploy/demo-bridge) expects. Only what the page needs: CONNECT with
// a clean session and no credentials, PUBLISH (QoS 0 and 1), SUBSCRIBE / UNSUBSCRIBE, PINGREQ, DISCONNECT, and
// receiving PUBLISH (QoS 0 and 1). It refuses everything else instead of guessing.

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

const T = { CONNECT: 1, CONNACK: 2, PUBLISH: 3, PUBACK: 4, SUBSCRIBE: 8, SUBACK: 9, UNSUBSCRIBE: 10, UNSUBACK: 11, PINGREQ: 12, PINGRESP: 13, DISCONNECT: 14 };

const CONNACK_TEXT = {
  1: 'unacceptable protocol version', 2: 'client identifier rejected', 3: 'server unavailable', 4: 'bad user name or password', 5: 'not authorised',
};

function varLen(n) {
  const out = [];
  do {
    let d = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) d |= 128;
    out.push(d);
  } while (n > 0);
  return out;
}

function str(s) {
  const b = typeof s === 'string' ? enc.encode(s) : s;
  if (b.length > 65535) throw new Error('string too long');
  return [b.length >> 8, b.length & 255, ...b];
}

function packet(first, body) {
  const head = [first, ...varLen(body.length)];
  const out = new Uint8Array(head.length + body.length);
  out.set(head, 0);
  out.set(body, head.length);
  return out;
}

const bytes = a => Uint8Array.from(a);

function encodeConnect(clientId, keepalive) {
  return packet(T.CONNECT << 4, bytes([...str('MQTT'), 4, 0x02, keepalive >> 8, keepalive & 255, ...str(clientId)]));
}

function encodePublish(topic, payload, qos, id) {
  const t = str(topic);
  const body = new Uint8Array(t.length + (qos ? 2 : 0) + payload.length);
  body.set(t, 0);
  if (qos) { body[t.length] = id >> 8; body[t.length + 1] = id & 255; }
  body.set(payload, t.length + (qos ? 2 : 0));
  return packet((T.PUBLISH << 4) | (qos << 1), body);
}

const encodePuback = id => bytes([T.PUBACK << 4, 2, id >> 8, id & 255]);
const encodeSubscribe = (id, filter, qos) => packet((T.SUBSCRIBE << 4) | 2, bytes([id >> 8, id & 255, ...str(filter), qos]));
const encodeUnsubscribe = (id, filter) => packet((T.UNSUBSCRIBE << 4) | 2, bytes([id >> 8, id & 255, ...str(filter)]));
const encodePingreq = () => bytes([T.PINGREQ << 4, 0]);
const encodeDisconnect = () => bytes([T.DISCONNECT << 4, 0]);

/** Splits a byte stream into packets. Throws on a packet larger than `max` or a malformed length. */
class PacketParser {
  constructor(max = 4096) { this.buf = new Uint8Array(0); this.max = max; }

  push(chunk) {
    const nb = new Uint8Array(this.buf.length + chunk.length);
    nb.set(this.buf, 0);
    nb.set(chunk, this.buf.length);
    this.buf = nb;
    const out = [];
    for (;;) {
      if (this.buf.length < 2) break;
      let n = 0, mult = 1, i = 1, done = false;
      while (i < this.buf.length && i <= 4) {
        const d = this.buf[i++];
        n += (d & 127) * mult;
        mult *= 128;
        if (!(d & 128)) { done = true; break; }
      }
      if (!done) {
        if (i > 4) throw new Error('malformed remaining length');
        break;
      }
      if (n > this.max) throw new Error('packet too large');
      if (this.buf.length < i + n) break;
      out.push({ type: this.buf[0] >> 4, flags: this.buf[0] & 15, body: this.buf.slice(i, i + n) });
      this.buf = this.buf.slice(i + n);
    }
    return out;
  }
}

/** Parses a PUBLISH packet's body: {topic, payload, id}. */
function parsePublish(flags, body) {
  if (body.length < 2) throw new Error('short PUBLISH');
  const n = (body[0] << 8) | body[1];
  if (body.length < 2 + n) throw new Error('short PUBLISH topic');
  const topic = dec.decode(body.subarray(2, 2 + n));
  const qos = (flags >> 1) & 3;
  let at = 2 + n, id = 0;
  if (qos) {
    if (body.length < at + 2) throw new Error('short PUBLISH id');
    id = (body[at] << 8) | body[at + 1];
    at += 2;
  }
  return { topic, qos, retain: !!(flags & 1), dup: !!(flags & 8), id, payload: body.slice(at) };
}

/**
 * The client. `WebSocketImpl` is the browser's WebSocket (or node's); `url` is ws:// or wss://.
 * Events (client.on(name, fn)): 'message' {topic, payload, qos, retain}, 'close' {clean, reason}, 'log' string.
 */
class MqttClient {
  constructor({ url, clientId, keepaliveS = 30, WebSocketImpl, timeoutMs = 10000, maxPacket = 4096, wsOptions }) {
    this.url = url;
    this.clientId = clientId;
    this.keepaliveS = keepaliveS;
    this.WS = WebSocketImpl || globalThis.WebSocket;
    this.timeoutMs = timeoutMs;
    this.maxPacket = maxPacket;
    this.wsOptions = wsOptions;
    this.handlers = { message: [], close: [], log: [] };
    this.pending = new Map(); // packet id -> {resolve, reject, type, timer}
    this.nextId = 1;
    this.state = 'idle';
  }

  on(name, fn) { this.handlers[name].push(fn); return this; }

  emit(name, arg) { for (const fn of this.handlers[name]) { try { fn(arg); } catch (e) { /* a handler's bug is not ours */ } } }

  /** Resolves when the broker accepts the connection; rejects with a readable reason. */
  connect() {
    if (this.state !== 'idle') return Promise.reject(new Error('already used'));
    this.state = 'connecting';
    return new Promise((resolve, reject) => {
      let ws;
      try {
        ws = this.wsOptions ? new this.WS(this.url, this.wsOptions) : new this.WS(this.url, ['mqtt']);
      } catch (e) {
        this.state = 'closed';
        reject(new Error(`cannot open ${this.url}: ${e.message}`));
        return;
      }
      ws.binaryType = 'arraybuffer';
      this.ws = ws;
      this.parser = new PacketParser(this.maxPacket);
      this.connectTimer = setTimeout(() => fail(new Error('timeout: no answer from the broker')), this.timeoutMs);
      const fail = err => {
        clearTimeout(this.connectTimer);
        if (this.state === 'connecting') { this.state = 'closed'; reject(err); try { ws.close(); } catch (e) { /* closing */ } }
      };
      this.onConnack = code => {
        clearTimeout(this.connectTimer);
        if (code === 0) { this.state = 'open'; this.startKeepalive(); resolve(); }
        else fail(new Error(`the broker refused the connection: ${CONNACK_TEXT[code] || `code ${code}`}`));
      };
      ws.onopen = () => ws.send(encodeConnect(this.clientId, this.keepaliveS));
      ws.onmessage = ev => {
        try {
          for (const p of this.parser.push(new Uint8Array(ev.data))) this.handle(p);
        } catch (e) {
          this.protocolError(e.message);
        }
      };
      ws.onerror = () => { if (this.state === 'connecting') fail(new Error('could not connect (the bridge or the broker is not reachable, or this page is not allowed to use it)')); };
      ws.onclose = ev => {
        clearTimeout(this.connectTimer);
        if (this.state === 'connecting') { this.state = 'closed'; reject(new Error(`connection closed before the broker answered${ev && ev.code ? ` (code ${ev.code})` : ''}`)); return; }
        this.finish(this.state === 'closing', ev && ev.reason ? `${ev.code} ${ev.reason}` : (ev && ev.code ? String(ev.code) : ''));
      };
    });
  }

  finish(clean, reason) {
    if (this.state === 'closed') return;
    this.state = 'closed';
    clearInterval(this.pingTimer);
    clearTimeout(this.pongTimer);
    for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(new Error('connection closed')); }
    this.pending.clear();
    this.emit('close', { clean, reason });
  }

  protocolError(why) {
    this.emit('log', `protocol error: ${why}`);
    this.state = 'closing';
    try { this.ws.close(1002); } catch (e) { /* closing */ }
  }

  startKeepalive() {
    if (!this.keepaliveS) return;
    this.pingTimer = setInterval(() => {
      if (this.state !== 'open') return;
      this.ws.send(encodePingreq());
      clearTimeout(this.pongTimer);
      this.pongTimer = setTimeout(() => this.protocolError('no PINGRESP'), this.timeoutMs);
    }, this.keepaliveS * 1000);
  }

  handle(p) {
    switch (p.type) {
      case T.CONNACK:
        if (p.body.length !== 2) throw new Error('bad CONNACK');
        this.onConnack(p.body[1]);
        break;
      case T.PUBLISH: {
        const m = parsePublish(p.flags, p.body);
        if (m.qos === 2) throw new Error('QoS 2 is not supported');
        if (m.qos === 1) this.ws.send(encodePuback(m.id));
        this.emit('message', { topic: m.topic, payload: m.payload, qos: m.qos, retain: m.retain });
        break;
      }
      case T.PUBACK: case T.SUBACK: case T.UNSUBACK: {
        if (p.body.length < 2) throw new Error('short acknowledgement');
        const id = (p.body[0] << 8) | p.body[1];
        const w = this.pending.get(id);
        if (!w) break; // late or unknown: ignore
        if (w.type !== p.type) throw new Error('unexpected acknowledgement');
        clearTimeout(w.timer);
        this.pending.delete(id);
        w.resolve(p.type === T.SUBACK ? p.body[2] : undefined);
        break;
      }
      case T.PINGRESP:
        clearTimeout(this.pongTimer);
        break;
      default:
        throw new Error(`unexpected packet type ${p.type}`);
    }
  }

  newId() {
    for (let i = 0; i < 65535; i++) {
      const id = this.nextId;
      this.nextId = this.nextId % 65535 + 1;
      if (!this.pending.has(id)) return id;
    }
    throw new Error('too many requests in flight');
  }

  expect(id, type) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('timeout: no acknowledgement from the broker')); }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, type, timer });
    });
  }

  requireOpen() { if (this.state !== 'open') throw new Error('not connected'); }

  /** QoS 0 resolves when sent; QoS 1 when the broker acknowledges. */
  async publish(topic, payload, qos = 0) {
    this.requireOpen();
    const body = typeof payload === 'string' ? enc.encode(payload) : payload;
    if (qos !== 0 && qos !== 1) throw new Error('QoS 0 or 1');
    if (qos === 0) { this.ws.send(encodePublish(topic, body, 0, 0)); return; }
    const id = this.newId();
    const done = this.expect(id, T.PUBACK);
    this.ws.send(encodePublish(topic, body, 1, id));
    return done;
  }

  /** Resolves with the granted QoS (0 or 1), or rejects when the broker refuses the filter (0x80). */
  async subscribe(filter, qos = 0) {
    this.requireOpen();
    const id = this.newId();
    const done = this.expect(id, T.SUBACK);
    this.ws.send(encodeSubscribe(id, filter, qos));
    const granted = await done;
    if (granted === 0x80 || granted === undefined) throw new Error('the broker refused this subscription');
    return granted;
  }

  async unsubscribe(filter) {
    this.requireOpen();
    const id = this.newId();
    const done = this.expect(id, T.UNSUBACK);
    this.ws.send(encodeUnsubscribe(id, filter));
    return done;
  }

  disconnect() {
    if (this.state === 'open') {
      this.state = 'closing';
      try { this.ws.send(encodeDisconnect()); } catch (e) { /* already gone */ }
      try { this.ws.close(1000); } catch (e) { /* already gone */ }
    } else if (this.state === 'connecting') {
      try { this.ws.close(); } catch (e) { /* already gone */ }
    }
  }
}

export { MqttClient, PacketParser, encodeConnect, encodePublish, encodeSubscribe, encodeUnsubscribe, encodePingreq, encodeDisconnect, encodePuback, parsePublish, T as MQTT_TYPES };
