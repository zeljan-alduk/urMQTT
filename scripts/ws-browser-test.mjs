#!/usr/bin/env node
// A real browser against the WebSocket listener (ADR-272): headless Chrome
// loads a page with MQTT.js and talks MQTT over wss to a running dev VM whose
// image has [websocket] auth = "password", the account web-1/web-secret and
// origins = ["http://localhost:<page port>"].
//
//   node scripts/ws-browser-test.mjs WS_PORT PAGE_PORT MQTT_JS_DIR
//
// MQTT_JS_DIR holds node_modules/mqtt (a pinned version installed by hand:
// `npm install mqtt@5.10.1` in a scratch directory; the repository does not
// carry it). Chrome runs with --ignore-certificate-errors because the dev CA is
// not in its trust store; the page and the broker are both on this machine.
//
// Checks: the page from the allowed origin logs in, subscribes, publishes and
// receives its own message (QoS 0 and 1), and the broker's close ends the
// connection cleanly; the same page served from another origin
// (http://127.0.0.1:<page port>) gets no connection (403 at the upgrade); a
// wrong password gets CONNACK 4. Prints "browser: <check> ok|FAILED".
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { launch } = await import(join(here, '../tools/builder/test/cdp.mjs'));
const [wsPort, pagePort, mqttDir] = process.argv.slice(2);
const bundle = readFileSync(join(mqttDir, 'node_modules/mqtt/dist/mqtt.min.js'));
const version = JSON.parse(readFileSync(join(mqttDir, 'node_modules/mqtt/package.json'))).version;

const page = `<!doctype html><meta charset="utf-8"><title>wss test</title>
<script src="/mqtt.min.js"></script>
<script>
window.run = (user, password) => new Promise(done => {
  const out = { connected: false, got: [], error: null, closed: false };
  const c = mqtt.connect('wss://localhost:${wsPort}/mqtt', {
    username: user, password, clientId: 'page-' + Math.random().toString(16).slice(2, 8),
    protocolVersion: 4, clean: true, reconnectPeriod: 0, connectTimeout: 8000,
  });
  const finish = () => { c.end(true); done(out); };
  c.on('connect', () => {
    out.connected = true;
    c.subscribe('web/web-1/#', { qos: 1 }, (e, granted) => {
      out.granted = granted && granted.map(g => g.qos);
      c.publish('web/web-1/q0', 'zero', { qos: 0 });
      c.publish('web/web-1/q1', 'one', { qos: 1 });
    });
  });
  c.on('message', (t, m) => { out.got.push(t + '=' + m.toString()); if (out.got.length === 2) finish(); });
  c.on('error', e => { out.error = String(e && (e.code ?? e.message ?? e)); finish(); });
  c.on('close', () => { out.closed = true; if (!out.connected) done(out); });
  setTimeout(finish, 10000);
});
</script>`;

const server = createServer((req, res) => {
  if (req.url === '/mqtt.min.js') {
    res.writeHead(200, { 'content-type': 'text/javascript' });
    return res.end(bundle);
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(page);
}).listen(Number(pagePort), '127.0.0.1');

const results = [];
const report = (name, ok, detail) => {
  results.push(ok);
  console.log(`browser: ${name} ${ok ? 'ok' : 'FAILED'} ${detail}`);
};

const browser = await launch({ args: ['--ignore-certificate-errors'] });
try {
  const p = await browser.newPage();
  await p.goto(`http://localhost:${pagePort}/`);
  const ua = await p.eval('navigator.userAgent');
  const good = await p.eval(`run('web-1', 'web-secret')`);
  report(`mqtt.js-${version}-pubsub-qos0-qos1`, good.connected && good.got.sort().join() === 'web/web-1/q0=zero,web/web-1/q1=one' && String(good.granted) === '1',
    `${JSON.stringify(good)} (${ua.replace(/ .*Chrome/, ' Chrome')})`);
  const bad = await p.eval(`run('web-1', 'wrong')`);
  report('wrong-password-refused', !bad.connected && /4|Bad|password|Not authorized/i.test(String(bad.error)), JSON.stringify(bad));
  // The same page from another origin: the broker answers 403.
  await p.goto(`http://127.0.0.1:${pagePort}/`);
  const other = await p.eval(`run('web-1', 'web-secret')`);
  report('other-origin-gets-no-connection', !other.connected, JSON.stringify(other));
  await p.close();
} finally {
  await browser.close();
  server.close();
}
process.exit(results.every(Boolean) ? 0 : 1);
