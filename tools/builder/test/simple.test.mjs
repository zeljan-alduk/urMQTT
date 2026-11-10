// The simple view, the default: three plain steps over the same state as the advanced form. End to end in headless
// Chrome: the certificates dropped in one go, the build, the result card, and switching to the advanced view and back
// without losing anything. Skipped when there is no Chrome (set CHROME=/path) or no build/builder.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, haveDevCerts, haveWasm } from './helpers.mjs';

if (!haveBrowser() || !haveWasm() || !haveDevCerts()) {
  console.log('skipped: needs a Chrome (CHROME=/path), build/builder (make builder) and `make certs`');
  process.exit(0);
}

let site, server, browser, page, base;
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };
const status = () => page.eval(`document.querySelector('.ub-bar-status').textContent`);
const mode = () => page.eval(`document.querySelector('#urmqtt-builder').dataset.mode`);

before(async () => {
  site = await prepareSite({
    releases: small => [
      { tag: 'v0.5.0', published: '2026-11-05T09:00:00Z', template: small },
      { tag: 'v0.4.0', published: '2026-11-04T09:00:00Z', template: small },
    ],
  });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: ISOLATION });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 1000);
  await page.goto(base + '/#');
  await page.eval('sessionStorage.clear(); localStorage.clear()');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('the default is the simple view: three steps, the newest release chosen and checked, one next action', async () => {
  assert.equal(await mode(), 'simple');
  assert.equal(await page.eval(`document.querySelector('.ub-advanced').hidden`), true);
  const heads = await page.eval(`[...document.querySelectorAll('.ub-simple h2')].map(h => h.textContent.replace(/^\\d/, ''))`);
  assert.deepEqual(heads, ['Where will it run?', 'How will devices connect?', 'Name your image']);
  // The release is chosen without a click and the check ran silently: a green chip.
  await page.waitFor(`document.querySelector('.ub-chip.ok')`, { what: 'the verified chip' });
  assert.match(await page.eval(`document.querySelector('.ub-version-line').textContent`), /v0\.5\.0.*Verified/);
  assert.equal(await status(), 'Next: add your certificates');
  assert.equal(await page.eval(`document.querySelector('#ub-s-addr') && document.querySelector('.ub-fixed').hidden`), true, 'no address field before a card needs one');
  // Nothing of the emulator was asked for, and nothing complains about untouched fields.
  assert.deepEqual(page.requests.filter(r => /\/emulator\//.test(r.url)), []);
  assert.equal(await page.eval(`document.querySelectorAll('[aria-invalid="true"]').length`), 0);
});

test('a card that needs an address shows only the address and gateway, and the bar names the next step', async () => {
  await page.click('.ub-where[data-id="vps"]');
  await page.waitFor(`!document.querySelector('.ub-fixed').hidden`);
  await page.waitFor(`document.querySelector('.ub-bar-status').textContent === "Next: enter the server's address and gateway"`);
  await page.type('#ub-s-addr', '203.0.113.10/24');
  await page.type('#ub-s-gw', '203.0.113.1');
  await page.waitFor(`document.querySelector('.ub-bar-status').textContent === 'Next: add your certificates'`);
  assert.equal(await page.eval(`document.querySelector('.ub-where[data-id="vps"]').getAttribute('aria-pressed')`), 'true');
});

test('the certificate, its key and the CA are dropped in one go and sorted by what they contain', async () => {
  await page.setFiles('#ub-s-drop input[type=file]', [join(DEV, 'ca.pem'), join(DEV, 'server.key'), join(DEV, 'server.pem')]);
  await page.waitFor(`document.querySelectorAll('.ub-simple .ub-checks li').length >= 3 && /valid/.test(document.querySelector('.ub-bar-status').textContent)`, { what: 'the files to be sorted' });
  const found = await page.eval(`[...document.querySelectorAll('.ub-simple .ub-checks li')].map(l => l.textContent)`);
  assert.match(found[0], /^Server certificate: .*localhost/);
  assert.match(found[1], /^Private key: /);
  assert.match(found[2], /^CA certificate: /);
  assert.equal(found.some(l => /missing/i.test(l)), false);
  assert.equal(await status(), 'The configuration is valid.');
  // A file that is not PEM is named, nothing else changes.
  await page.setFiles('#ub-s-drop input[type=file]', [join(DEV, '../../Cargo.toml')]);
  await page.waitFor(`document.querySelector('#ub-s-tls [role=alert]')`);
  assert.match(await page.eval(`document.querySelector('#ub-s-tls [role=alert]').textContent`), /No usable certificate or key was found in: Cargo\.toml/);
});

test('the extras: diagnostics is a plain checkbox, and plain MQTT (a listener of its own) can be switched on and off', async () => {
  await page.click('#ub-x-diag');
  await page.waitFor(`document.querySelector('#ub-x-diag').checked`);
  await page.click('#ub-x-plain');
  assert.equal(await page.eval(`!document.querySelector('#ub-s-plain').hidden`), true, 'plain MQTT shows its own questions');
  await page.click('#ub-x-plain'); // off again: its accounts would be needed
  await page.type('#ub-s-name', 'trial');
  assert.match(await page.eval(`document.querySelector('.ub-simple .ub-code').textContent`), /urmqtt-0\.5\.0-trial-universal\.iso/);
});

test('random numbers: a visible choice of two, the weak path is the default and warned about, the strict one is one click (ADR-263)', async () => {
  const legend = await page.eval(`document.querySelector('#ub-s-entropy legend').textContent`);
  assert.equal(legend, 'Random numbers');
  const text = await page.eval(`document.querySelector('#ub-s-entropy').textContent`);
  assert.match(text, /Allow CPU-jitter fallback \(default\)Boots on hosts without a hardware random number generator, seeding the generator from CPU timing jitter and the firmware's values; weaker than a hardware source\./);
  assert.match(text, /Require a hardware random number generatorThe image refuses to boot without virtio-rng or a CPU instruction \(RNDR, RDRAND\/RDSEED\) and says so on the console\./);
  assert.equal(await page.eval(`document.querySelector('#ub-s-entropy-jitter').checked`), true, 'the default allows the fallback');
  assert.equal(await page.eval(`document.querySelector('#ub-s-entropy-warn').hidden`), false, 'and warns');
  assert.match(await page.eval(`document.querySelector('#ub-s-entropy-warn').textContent`), /^Warning: on a host with neither virtio-rng nor RNDR\/RDRAND/);
  assert.match(await page.eval(`document.querySelector('.ub-notes').textContent`), /Random numbers may come from CPU jitter/);
  // One click: the strict option. The warning and the note go, the advanced field follows.
  await page.click('#ub-s-entropy-none');
  await page.waitFor(`document.querySelector('#ub-s-entropy-none').checked && document.querySelector('#ub-s-entropy-warn').hidden`);
  await page.waitFor(`!document.querySelector('.ub-notes').textContent.includes('Random numbers may come from CPU jitter')`, { what: 'the note to go' });
  const hash = JSON.parse(Buffer.from((await page.eval(`location.hash`)).slice(3), 'base64url').toString());
  assert.equal(hash.v['entropy.fallback'], 'none', 'the choice is in the address, so it can be linked');
  // Back to the default for the rest of the file; the result card of the build below names it.
  await page.click('#ub-s-entropy-jitter');
  await page.waitFor(`document.querySelector('#ub-s-entropy-jitter').checked && document.querySelector('.ub-notes').textContent.includes('Random numbers may come from CPU jitter')`);
});

test('the build ends in a result card, without a dialog in the way', async () => {
  await page.waitFor(`!document.querySelector('#ub-build').disabled`);
  await page.click('#ub-build');
  await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { timeout: 60000, what: 'the ISO' });
  assert.equal(await page.eval(`Boolean(document.querySelector('dialog[open]'))`), false, 'the simple view does not open a dialog after the build');
  const card = await page.eval(`document.querySelector('.ub-result').textContent`);
  assert.match(card, /urmqtt-0\.5\.0-trial-universal\.iso/);
  assert.match(card, /[0-9a-f]{8} [0-9a-f]{8}/);
  assert.match(card, /Random numbers\s*CPU-jitter fallback allowed/, 'the card says which entropy option was built');
  assert.equal(await page.eval(`document.querySelector('#ub-emulator').getAttribute('aria-disabled')`), 'false');
  assert.equal(await page.eval(`document.activeElement.id`), 'ub-download', 'the focus is on Download');
});

test('switching to advanced shows the same values, and back loses nothing', async () => {
  await page.click('#ub-advanced-toggle');
  await page.waitFor(`document.querySelector('#urmqtt-builder').dataset.mode === 'advanced'`);
  assert.equal(await page.eval(`document.querySelector('#ub-advanced-toggle').getAttribute('aria-checked')`), 'true');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="network.address"] input').value`), '203.0.113.10/24');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="storage.diagnostic"] input[type=checkbox]').checked`), true);
  assert.match(await page.eval(`location.hash`), /^#s=/);
  const hash = JSON.parse(Buffer.from((await page.eval(`location.hash`)).slice(3), 'base64url').toString());
  assert.equal(hash.a, 1, 'the view is in the address, so it can be linked');
  // The release list moved with it.
  assert.equal(await page.eval(`Boolean(document.querySelector('.ub-advanced .ub-release'))`), true);
  // Search and the changed filter.
  // Several settings say "gateway" since IPv6 (ADR-334): IPv4's gateway is
  // among them, every one shown says it, and the others are filtered out.
  await page.type('#ub-search', 'gateway');
  await page.waitFor(`document.querySelector('.ub-field[data-id="network.mtu"]').hasAttribute('data-filtered')`);
  const found = await page.eval(`[...document.querySelectorAll('.ub-field:not([data-filtered]):not([hidden])')].map(f => [f.dataset.id, (f.dataset.id + ' ' + f.textContent).toLowerCase().includes('gateway')])`);
  assert.ok(found.some(([id]) => id === 'network.gateway'), JSON.stringify(found));
  assert.ok(found.every(([, says]) => says), JSON.stringify(found));
  assert.ok(found.length < 5, JSON.stringify(found));
  await page.eval(`document.querySelector('#ub-search').value = ''; document.querySelector('#ub-search').dispatchEvent(new Event('input'))`);
  await page.click('#ub-only-changed');
  await page.waitFor(`document.querySelectorAll('.ub-field:not([data-filtered]):not([hidden])').length > 0`);
  const changed = await page.eval(`[...document.querySelectorAll('.ub-field:not([data-filtered]):not([hidden])')].map(f => f.dataset.changed)`);
  assert.ok(changed.every(c => c === 'true'), 'only changed settings are shown');
  await page.click('#ub-only-changed');
  // Back: the plain view has what was typed in the advanced one.
  await page.type('.ub-field[data-id="network.gateway"] input', '203.0.113.19');
  await page.click('#ub-advanced-toggle');
  await page.waitFor(`document.querySelector('#urmqtt-builder').dataset.mode === 'simple'`);
  assert.equal(await page.eval(`document.querySelector('#ub-s-gw').value`), '203.0.113.19');
  assert.equal(await page.eval(`document.querySelector('#ub-s-addr').value`), '203.0.113.10/24');
  assert.equal(await page.eval(`document.querySelector('#ub-s-name').value`), 'trial');
  assert.equal(await page.eval(`document.querySelectorAll('.ub-simple .ub-checks li').length`), 3);
});

test('the choice of view is remembered in the browser and can be linked', async () => {
  await page.click('#ub-advanced-toggle');
  await page.goto(base + '/#');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  assert.equal(await mode(), 'advanced', 'remembered');
  await page.click('#ub-advanced-toggle');
  await page.eval(`localStorage.clear()`);
  const link = `${base}/#s=${Buffer.from(JSON.stringify({ a: 1 })).toString('base64url')}`;
  await page.goto(base + '/#');
  await page.goto(link);
  await page.goto(link); // a second navigation within the document does not reload: force it
  await page.eval('location.reload()');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  assert.equal(await mode(), 'advanced', 'from the address');
  assert.deepEqual(page.consoleErrors.filter(e => !/favicon/.test(e)), []);
});
