// The "Try urMQTT live" page in a real (headless) Chrome, against the real demo bridge and a fake MQTT server on
// loopback: connect, subscribe, publish, the message log, validation, hostile payloads shown as text, Croatian, the
// dark theme, a phone-width screen, labels for every control, and no request to anywhere but the page's own server
// and the bridge. Skipped when there is no Chrome (CHROME=/path) or no python3.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { serve } from './serve.mjs';
import { ROOT, tmp } from './helpers.mjs';
import { havePython, startBridge, startFakeBroker } from './demo-fixture.mjs';
import { MqttClient } from '../demo/src/mqtt.js';

if (!haveBrowser() || !havePython()) {
  console.log('skipped: needs a Chrome (CHROME=/path), Node 22 and python3');
  process.exit(0);
}

let dir, server, broker, bridge, browser, page, base, origin;
const sleep = ms => new Promise(r => setTimeout(r, ms));

before(async () => {
  dir = tmp('urmqtt-demo-page-');
  execFileSync('node', [join(ROOT, 'tools/builder/demo/bundle.mjs'), dir], { stdio: ['ignore', 'ignore', 'inherit'] });
  server = await serve({ app: dir });
  origin = `http://127.0.0.1:${server.port}`;
  broker = await startFakeBroker();
  bridge = await startBridge({ upstreamPort: broker.port, origins: [origin] });
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 900);
});

after(async () => {
  await browser?.close();
  await bridge?.stop();
  await broker?.stop();
  await server?.close();
});

const url = (q = '') => `${origin}/?ws=${encodeURIComponent(`ws://127.0.0.1:${bridge.port}/demo/mqtt`)}${q}`;
const text = sel => page.eval(`(document.querySelector(${JSON.stringify(sel)}) || {}).textContent || ''`);
const logText = () => text('#ud-log');
const enabled = sel => page.eval(`!document.querySelector(${JSON.stringify(sel)}).disabled`);
const setValue = (sel, v) => page.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input', { bubbles: true })); })()`);

async function open(q = '') {
  await page.goto(url(q));
  await page.waitFor(`document.documentElement.dataset.udReady === '1'`, { what: 'the page' });
}

test('the page loads with its statement of limits, no error, and no request outside its own server', async () => {
  await open();
  assert.match(await text('h1'), /Try urMQTT live/);
  const warn = await text('.ud-warn');
  for (const phrase of [/shared test machine/i, /reset/i, /public/i, /Do not send anything private/i, /demo\/web\//]) assert.match(warn, phrase);
  assert.deepEqual(page.consoleErrors, []);
  const foreign = page.requests.filter(r => !r.url.startsWith(origin) && !r.url.startsWith('data:'));
  assert.deepEqual(foreign, []);
  assert.equal(await page.eval(`document.documentElement.lang`), 'en');
  assert.equal(await enabled('#ud-connect'), true);
  assert.equal(await enabled('#ud-publish'), false);
  assert.equal(await enabled('#ud-disconnect'), false);
});

test('connect, subscribe, publish and see the message come back; then disconnect', async () => {
  await open();
  await page.click('#ud-connect');
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'ok'`, { what: 'the connection' });
  assert.match(await text('#ud-status'), /^Connected as urmqtt-web-[0-9a-f]{10}\./);
  assert.equal(await enabled('#ud-publish'), true);
  await page.click('#ud-subscribe');
  await page.waitFor(`document.querySelectorAll('#ud-subs li').length === 1`, { what: 'the subscription' });
  await page.click('#ud-publish');
  await page.waitFor(`document.querySelectorAll('#ud-log .ud-received').length === 1`, { what: 'the message' });
  const log = await logText();
  assert.match(log, /Sent/);
  assert.match(log, /Received/);
  assert.match(log, /demo\/web\/room-[0-9a-f]{4}\/hello/);
  assert.match(log, /Hello from my browser/);
  assert.equal(await page.eval(`document.querySelector('#ud-log-empty').hidden`), true);
  assert.equal(await page.eval(`document.querySelector('#ud-log').getAttribute('role')`), 'log');
  await page.click('#ud-clear');
  assert.equal(await page.eval(`document.querySelectorAll('#ud-log li').length`), 0);
  await page.click('#ud-disconnect');
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'idle' && /Disconnected/.test(document.querySelector('#ud-status').textContent)`, { what: 'the disconnect' });
  assert.equal(await enabled('#ud-connect'), true);
  assert.equal(await enabled('#ud-publish'), false);
  assert.deepEqual(page.consoleErrors, []);
});

test('what other clients publish is shown as text, never as HTML', async () => {
  await open();
  await page.click('#ud-connect');
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'ok'`);
  await setValue('#ud-filter', '#');
  await page.click('#ud-subscribe');
  await page.waitFor(`document.querySelectorAll('#ud-subs li').length === 1`);
  const other = new MqttClient({ url: `ws://127.0.0.1:${bridge.port}/demo/mqtt`, clientId: 'other-client', wsOptions: { protocols: ['mqtt'], headers: { Origin: origin } } });
  await other.connect();
  const evil = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';
  await other.publish('demo/web/<b>topic</b>', evil, 0);
  await page.waitFor(`document.querySelectorAll('#ud-log .ud-received').length === 1`);
  await sleep(200);
  assert.ok((await logText()).includes(evil), 'the payload is shown literally');
  assert.equal(await page.eval(`document.querySelectorAll('#ud-log img, #ud-log script, #ud-log b').length`), 0);
  assert.equal(await page.eval(`window.__pwned === undefined`), true);
  other.disconnect();
  await page.click('#ud-disconnect');
});

test('what the page refuses before it sends anything', async () => {
  await open();
  await page.click('#ud-connect');
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'ok'`);
  await setValue('#ud-topic', 'a/+/b');
  await page.click('#ud-publish');
  assert.match(await text('#ud-pub-error'), /cannot contain \+ or #/);
  await setValue('#ud-topic', 'fine');
  await setValue('#ud-payload', 'x'.repeat(257));
  await page.click('#ud-publish');
  assert.match(await text('#ud-pub-error'), /too long \(at most 256 bytes\)/);
  assert.match(await text('#ud-payload-count'), /257 of 256 bytes/);
  await setValue('#ud-payload', 'ok');
  await setValue('#ud-topic', '');
  await page.click('#ud-publish');
  assert.match(await text('#ud-pub-error'), /Type a topic/);
  await setValue('#ud-topic', 'a/b/c/d/e/f/g/h');
  await page.click('#ud-publish');
  assert.match(await text('#ud-pub-error'), /too many levels/);
  await setValue('#ud-filter', 'a#');
  await page.click('#ud-subscribe');
  assert.match(await text('#ud-sub-error'), /wildcard must be a whole level/);
  assert.equal(await page.eval(`document.querySelector('#ud-filter').getAttribute('aria-invalid')`), 'true');
  for (const f of ['one', 'two', 'three', 'four']) {
    await setValue('#ud-filter', f);
    await page.click('#ud-subscribe');
    await page.waitFor(`document.querySelectorAll('#ud-subs li').length === ${['one', 'two', 'three', 'four'].indexOf(f) + 1}`);
  }
  await setValue('#ud-filter', 'five');
  await page.click('#ud-subscribe');
  assert.match(await text('#ud-sub-error'), /At most 4 subscriptions/);
  await page.click('#ud-subs li button');
  await page.waitFor(`document.querySelectorAll('#ud-subs li').length === 3`);
  await page.click('#ud-disconnect');
});

test('every control has a label, the log is a live region, and the keyboard reaches the buttons', async () => {
  await open();
  const unlabeled = await page.eval(`[...document.querySelectorAll('.ud input, .ud select, .ud textarea')].filter(e => !e.labels || e.labels.length === 0).map(e => e.id)`);
  assert.deepEqual(unlabeled, []);
  assert.equal(await page.eval(`document.querySelector('#ud-status').getAttribute('role')`), 'status');
  assert.equal(await page.eval(`document.querySelector('#ud-log').getAttribute('aria-live')`), 'polite');
  assert.equal(await page.eval(`document.querySelector('#ud-pub-error').getAttribute('role')`), 'alert');
  await page.eval(`document.querySelector('#ud-connect').focus()`);
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'ok'`, { what: 'a connection started with the keyboard' });
  await page.click('#ud-disconnect');
});

test('Croatian', async () => {
  await open('&lang=hr');
  assert.match(await text('h1'), /Isprobajte urMQTT uživo/);
  assert.match(await text('.ud-warn'), /zajednička igračka/);
  assert.equal(await text('#ud-connect'), 'Spoji se');
});

test('a language without a text file falls back to English', async () => {
  await open('&lang=de');
  assert.match(await text('h1'), /Try urMQTT live/);
});

test('dark scheme and a phone-width screen: nothing scrolls sideways and the text stays readable', async () => {
  await page.media({ scheme: 'dark' });
  await page.viewport(375, 800, { mobile: true });
  await open();
  const overflow = await page.eval(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  assert.ok(overflow <= 1, `horizontal overflow of ${overflow}px`);
  const [fg, bg] = await page.eval(`(() => { const c = getComputedStyle(document.querySelector('.ud-lead')); const b = getComputedStyle(document.body); return [c.color, b.backgroundColor]; })()`);
  const lum = css => { const [r, g, b] = css.match(/\d+/g).slice(0, 3).map(Number).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const ratio = (Math.max(lum(fg), lum(bg)) + 0.05) / (Math.min(lum(fg), lum(bg)) + 0.05);
  assert.ok(ratio >= 4.5, `contrast ${ratio.toFixed(2)} (${fg} on ${bg})`);
  await page.media({});
  await page.viewport(1280, 900);
});

test('when the bridge is gone the page says so and stays usable', async () => {
  await open();
  await bridge.stop();
  await page.click('#ud-connect');
  await page.waitFor(`document.querySelector('#ud-status').dataset.state === 'error'`, { what: 'the failure' });
  assert.match(await text('#ud-status'), /Could not connect/);
  assert.equal(await enabled('#ud-connect'), true);
  assert.match(await logText(), /Error/);
  bridge = null;
});
