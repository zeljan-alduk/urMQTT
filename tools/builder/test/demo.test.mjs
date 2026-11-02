// "Try urMQTT live" (D1b): the MQTT client in plain JS, the page's texts, and the client through the real demo bridge
// (deploy/demo-bridge/bridge.py) to a fake MQTT server and, when installed, to a local mosquitto. Everything listens on
// 127.0.0.1 and a free port. No Chrome needed here (see demo-page.test.mjs).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { ROOT } from './helpers.mjs';
import { findMosquitto, haveMosquittoPub, havePython, startBridge, startFakeBroker, startMosquitto } from './demo-fixture.mjs';
import { MqttClient, PacketParser, encodeConnect, encodePublish, encodeSubscribe, encodeUnsubscribe, parsePublish } from '../demo/src/mqtt.js';

const LANGS = ['en', 'hr'];
const dir = join(ROOT, 'tools/builder/demo');
const load = lang => JSON.parse(readFileSync(join(dir, 'i18n', `${lang}.json`), 'utf8'));
const placeholders = s => [...String(s).matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort().join(',');
const hex = u8 => Buffer.from(u8).toString('hex');
const ORIGIN = 'https://example.test';

// ---- the texts ---------------------------------------------------------------------------------------------------

test('English and Croatian have the same keys and placeholders, and there are no other languages yet', () => {
  assert.deepEqual(readdirSync(join(dir, 'i18n')).sort(), LANGS.map(l => `${l}.json`).sort());
  const en = load('en'), hr = load('hr');
  assert.deepEqual(Object.keys(hr).sort(), Object.keys(en).sort());
  for (const [k, v] of Object.entries(hr)) {
    assert.ok(v.trim().length > 0, `hr.${k} is empty`);
    assert.equal(placeholders(v), placeholders(en[k]), `hr.${k}: placeholders differ from English`);
  }
  const same = Object.keys(en).filter(k => en[k].length > 40 && hr[k] === en[k]);
  assert.deepEqual(same, [], 'untranslated long texts in hr');
});

test('every key the page asks for exists, and no key is unused', () => {
  const en = load('en');
  const src = readFileSync(join(dir, 'src/demo.js'), 'utf8');
  const used = new Set();
  for (const m of src.matchAll(/\bt\('([A-Za-z0-9_.\-]+)'/g)) used.add(m[1]);
  for (const m of src.matchAll(/\bt\(`([A-Za-z0-9_.\-]+)\$\{/g)) for (const x of ['1', '2', '3', '4', '5', '6']) if (m[1] === 'limits.') used.add(`limits.${x}`);
  for (const k of ['sent', 'received', 'info', 'error']) used.add(`log.${k}`);
  for (const k of ['idle', 'connecting', 'connected', 'failed', 'closed', 'lost']) used.add(`status.${k}`);
  for (const m of src.matchAll(/setStatus\('([\w.\-]+)'/g)) used.add(m[1]);
  assert.deepEqual([...used].filter(k => !(k in en)).sort(), [], 'keys used but missing');
  const unused = Object.keys(en).filter(k => !used.has(k) && k !== 'noscript');
  assert.deepEqual(unused, [], 'keys never used');
});

test('the page has no third-party script, no tracking and does not store anything', () => {
  const files = ['src/demo.js', 'src/mqtt.js', 'index.html', 'app.css'].map(f => readFileSync(join(dir, f), 'utf8')).join('\n');
  assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|navigator\.sendBeacon|XMLHttpRequest/.test(files), 'storage or beacons');
  assert.ok(!/<script[^>]+src="https?:/.test(files) && !/@import|url\(\s*['"]?https?:/.test(files), 'a third-party resource');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(files), 'HTML injection or eval: messages must be shown as text');
});

// ---- the codec ---------------------------------------------------------------------------------------------------

test('packets are encoded as MQTT 3.1.1 says', () => {
  assert.equal(hex(encodeConnect('test', 0)), '101000044d51545404020000000474657374'); // same bytes as the bridge's test CONNECT
  assert.equal(hex(encodeConnect('a', 30)), '100d00044d5154540402001e000161');
  assert.equal(hex(encodePublish('a/b', new TextEncoder().encode('hi'), 0, 0)), '30070003612f626869');
  assert.equal(hex(encodePublish('a/b', new TextEncoder().encode('hi'), 1, 258)), '320900' + '03612f6201026869');
  assert.equal(hex(encodeSubscribe(1, 'x/#', 1)), '8208000100' + '03782f2301');
  assert.equal(hex(encodeUnsubscribe(2, 'x')), 'a2050002000178');
  // a long remaining length
  const big = encodePublish('t', new Uint8Array(200), 0, 0);
  assert.equal(hex(big.subarray(0, 3)), '30cb01');
});

test('the parser splits a stream, waits for the rest and refuses what is too large or malformed', () => {
  const p = new PacketParser(64);
  const a = Uint8Array.from([0x20, 2, 0, 0]);
  const b = encodePublish('t', new TextEncoder().encode('hello'), 0, 0);
  const stream = Uint8Array.from([...a, ...b]);
  const got = [];
  for (const byte of stream) got.push(...p.push(Uint8Array.from([byte])));
  assert.deepEqual(got.map(x => x.type), [2, 3]);
  const m = parsePublish(got[1].flags, got[1].body);
  assert.equal(m.topic, 't');
  assert.equal(new TextDecoder().decode(m.payload), 'hello');
  assert.throws(() => new PacketParser(64).push(Uint8Array.from([0x30, 0xc1, 0x02, 0])), /too large/);
  assert.throws(() => new PacketParser(64).push(Uint8Array.from([0x30, 0x80, 0x80, 0x80, 0x80, 1])), /malformed/);
  assert.throws(() => parsePublish(0, Uint8Array.from([0, 9, 65])), /short/);
  assert.equal(parsePublish(2, Uint8Array.from([0, 1, 65, 0, 7, 9])).id, 7);
});

// ---- through the bridge ------------------------------------------------------------------------------------------

const wsOptions = (url, origin = ORIGIN) => ({ protocols: ['mqtt'], headers: { Origin: origin } });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const waitFor = async (fn, ms = 5000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return; await sleep(25); } throw new Error('timed out'); };

function client(bridge, id, origin) {
  const url = `ws://127.0.0.1:${bridge.port}/demo/mqtt`;
  const c = new MqttClient({ url, clientId: id, keepaliveS: 30, wsOptions: wsOptions(url, origin), timeoutMs: 4000 });
  c.messages = [];
  c.closed = null;
  c.on('message', m => c.messages.push({ ...m, text: new TextDecoder().decode(m.payload) }));
  c.on('close', ev => { c.closed = ev; });
  return c;
}

const python = havePython();
const skipBridge = !python && 'needs python3';

test('connect, subscribe, publish QoS 0 and 1, unsubscribe and disconnect through the bridge to a fake server', { skip: skipBridge }, async () => {
  const broker = await startFakeBroker();
  const bridge = await startBridge({ upstreamPort: broker.port, origins: [ORIGIN] });
  try {
    const a = client(bridge, 'urmqtt-web-a');
    const b = client(bridge, 'urmqtt-web-b');
    await a.connect();
    await b.connect();
    assert.equal(a.state, 'open');
    assert.equal(await a.subscribe('demo/web/room-1/#', 1), 0);
    await b.publish('demo/web/room-1/hello', 'hello a', 0);
    await waitFor(() => a.messages.length === 1);
    assert.deepEqual([a.messages[0].topic, a.messages[0].text, a.messages[0].qos], ['demo/web/room-1/hello', 'hello a', 0]);
    await b.publish('demo/web/room-1/again', 'acked', 1); // resolves on PUBACK
    await waitFor(() => a.messages.length === 2);
    await assert.rejects(a.subscribe('devices/#', 0), /refused/);
    await a.unsubscribe('demo/web/room-1/#');
    a.disconnect();
    await waitFor(() => a.closed);
    assert.equal(a.closed.clean, true);
    b.disconnect();
    await waitFor(() => b.closed);
    assert.equal(broker.state.connects, 2);
  } finally {
    await bridge.stop();
    await broker.stop();
  }
});

test('a page that is not on the allow-list cannot connect, and nothing reaches the server', { skip: skipBridge }, async () => {
  const broker = await startFakeBroker();
  const bridge = await startBridge({ upstreamPort: broker.port, origins: [ORIGIN] });
  try {
    const c = client(bridge, 'urmqtt-web-x', 'https://evil.test');
    await assert.rejects(c.connect(), /could not connect|closed/);
    assert.equal(broker.state.connects, 0);
  } finally {
    await bridge.stop();
    await broker.stop();
  }
});

test('an unreachable broker is a clear error, a dropped connection is reported, not hidden', { skip: skipBridge }, async () => {
  const broker = await startFakeBroker();
  const bridge = await startBridge({ upstreamPort: broker.port, origins: [ORIGIN] });
  try {
    const c = client(bridge, 'urmqtt-web-y');
    await c.connect();
    await broker.stop(); // the server goes away: the bridge closes the WebSocket
    await waitFor(() => c.closed);
    assert.equal(c.closed.clean, false);
    assert.equal(c.state, 'closed');
    await assert.rejects(c.publish('demo/web/x', 'y'), /not connected/);
    const d = client(bridge, 'urmqtt-web-z');
    await assert.rejects(d.connect(), /could not connect|closed/); // 503 from the bridge
  } finally {
    await bridge.stop();
  }
});

test('a payload that looks like HTML is just bytes to the client', { skip: skipBridge }, async () => {
  const broker = await startFakeBroker();
  const bridge = await startBridge({ upstreamPort: broker.port, origins: [ORIGIN] });
  try {
    const a = client(bridge, 'urmqtt-web-a');
    await a.connect();
    await a.subscribe('demo/web/#', 0);
    await a.publish('demo/web/x', '<img src=x onerror=alert(1)>', 0);
    await waitFor(() => a.messages.length === 1);
    assert.equal(a.messages[0].text, '<img src=x onerror=alert(1)>');
    a.disconnect();
  } finally {
    await bridge.stop();
    await broker.stop();
  }
});

const skipMosq = (!python && 'needs python3') || (!findMosquitto() && 'mosquitto is not installed');

test('connect, subscribe and publish through the bridge to a real mosquitto, and from mosquitto_pub', { skip: skipMosq }, async () => {
  const mosq = await startMosquitto();
  const bridge = await startBridge({ upstreamPort: mosq.port, origins: [ORIGIN] });
  try {
    const a = client(bridge, 'urmqtt-web-a');
    const b = client(bridge, 'urmqtt-web-b');
    await a.connect();
    await b.connect();
    assert.equal(await a.subscribe('demo/web/room-9/#', 1), 1);
    await b.publish('demo/web/room-9/hi', 'from a browser', 1);
    await waitFor(() => a.messages.length === 1);
    assert.equal(a.messages[0].text, 'from a browser');
    if (haveMosquittoPub()) {
      const r = spawnSync('mosquitto_pub', ['-h', '127.0.0.1', '-p', String(mosq.port), '-t', 'demo/web/room-9/tcp', '-m', 'from tcp', '-q', '1']);
      assert.equal(r.status, 0);
      await waitFor(() => a.messages.length === 2);
      assert.equal(a.messages[1].text, 'from tcp');
    }
    a.disconnect();
    b.disconnect();
    await waitFor(() => a.closed && b.closed);
  } finally {
    await bridge.stop();
    await mosq.stop();
  }
});
