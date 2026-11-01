// The two listeners of the simple view (ADR-233): TLS only (the default), plain only (TLS off) and both, what each
// asks for, what the page says about it, and which release it needs. In headless Chrome with a local test mirror.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, cli, haveCli, haveDevCerts, haveWasm, tmp } from './helpers.mjs';

if (!haveBrowser() || !haveWasm() || !haveDevCerts() || !haveCli()) {
  console.log('skipped: needs a Chrome, build/builder, `make certs` and the urmqtt-config binary');
  process.exit(0);
}

let site, server, browser, page, base;
const status = () => page.eval(`document.querySelector('.ub-bar-status').textContent`);
const checked = id => page.eval(`document.querySelector('${id}').checked`);

async function fresh() {
  await page.goto(base + '/#');
  await page.eval('sessionStorage.clear(); localStorage.clear()');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  await page.waitFor(`document.querySelector('.ub-chip.ok')`);
}

async function buildAndDownload() {
  await page.waitFor(`!document.querySelector('#ub-build').disabled`);
  await page.click('#ub-build');
  // The risk question of plain MQTT (and of TLS off) comes first.
  for (let i = 0; i < 40; i++) {
    const asking = await page.eval(`(() => { const d = document.querySelector('dialog[open]'); return d ? d.textContent : ''; })()`);
    if (/Build anyway|Continue|Yes, build/i.test(asking) || /Plaintext MQTT is on|TLS listener is off/.test(asking)) {
      await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => !b.classList.contains('secondary')).click()`);
      break;
    }
    if (await page.eval(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`)) break;
    await new Promise(r => setTimeout(r, 250));
  }
  await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { timeout: 60000, what: 'the ISO' });
  const dir = tmp('urmqtt-dl-');
  await page.download('#ub-download', dir);
  return join(dir, readdirSync(dir)[0]);
}

before(async () => {
  site = await prepareSite({
    releases: small => [
      { tag: 'v0.6.0', published: '2026-11-06T09:00:00Z', template: small, format: 2 },
      { tag: 'v0.5.0', published: '2026-11-05T09:00:00Z', template: small },
    ],
  });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' } });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 1000);
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('TLS only is the default: TLS on, plain off, certificates asked for, nothing else', async () => {
  await fresh();
  assert.equal(await checked('#ub-x-tls'), true);
  assert.equal(await checked('#ub-x-plain'), false);
  assert.equal(await page.eval(`document.querySelector('#ub-s-tls').hidden`), false);
  assert.equal(await page.eval(`document.querySelector('#ub-s-plain').hidden`), true);
  assert.equal(await status(), 'Next: add your certificates');
  assert.match(await page.eval(`document.querySelector('.ub-version-line').textContent`), /v0\.6\.0/, 'the newest release');
  // No card turns plain MQTT on.
  for (const id of ['lab', 'vps', 'auto']) {
    await page.click(`.ub-where[data-id="${id}"]`);
    assert.equal(await checked('#ub-x-plain'), false, id);
  }
});

test('at least one listener stays on: the last box cannot be switched off, and the page says why', async () => {
  await fresh();
  await page.click('#ub-x-tls'); // TLS off while plain is off: refused
  assert.equal(await checked('#ub-x-tls'), true);
  assert.match(await page.eval(`document.querySelector('#ub-x-tls').closest('fieldset').querySelector('[role=alert]').textContent`), /At least one of the two must stay on/);
  await page.click('#ub-x-plain');
  await page.click('#ub-x-tls');
  assert.equal(await checked('#ub-x-tls'), false);
  await page.click('#ub-x-plain'); // plain off while TLS is off: refused
  assert.equal(await checked('#ub-x-plain'), true);
});

test('plain MQTT on shows the networks, prefilled and editable, and the login choice in plain words', async () => {
  await fresh();
  await page.click('#ub-x-plain');
  assert.equal(await page.eval(`document.querySelector('#ub-s-plain').hidden`), false);
  assert.equal(await page.eval(`document.querySelector('#ub-s-networks').value`), '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16');
  const labels = await page.eval(`[...document.querySelectorAll('#ub-s-plain input[type=radio]')].map(r => r.closest('label').textContent.trim())`);
  assert.deepEqual(labels.map(l => l.split(' (')[0].split(':')[0]), ['User name and password', 'No login', 'By network']);
  assert.equal(await page.eval(`document.querySelector('#ub-s-auth-password').checked`), true);
  // The accounts editor is in this view (the form's own), and the bar asks for an account first.
  assert.equal(await page.eval(`Boolean(document.querySelector('#ub-s-plain .ub-field[data-id="plaintext.users"]'))`), true);
  await page.type('#ub-s-networks', '192.0.2.0/24');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="plaintext.allow_from"] textarea').value`), '192.0.2.0/24');
  await page.click('#ub-s-auth-anonymous');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="plaintext.auth"] input[value="anonymous"]').checked`), true);
});

test('plain only: the certificate step is hidden, nothing is asked of TLS, the page states the consequences, and the image builds', async () => {
  await fresh();
  await page.click('#ub-x-plain');
  await page.click('#ub-x-tls');
  assert.equal(await page.eval(`document.querySelector('#ub-s-tls').hidden`), true, 'hidden, not just empty');
  assert.match(await page.eval(`document.querySelector('.ub-simple .ub-banner:not([hidden])').textContent`), /no operator, service or control rights/);
  await page.click('#ub-s-auth-anonymous');
  await page.waitFor(`document.querySelector('.ub-bar-status').textContent === 'The configuration is valid.'`);
  // The release follows what was asked: TLS off needs a template that reads format 3.
  assert.match(await page.eval(`document.querySelector('.ub-version-line').textContent`), /v0\.5\.0/);
  const iso = await buildAndDownload();
  const out = cli(['show', iso]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /mqtt_tls_port\s*=\s*0/);
  assert.equal(cli(['verify', iso]).status, 0);
  // The advanced view has the same: the port, no certificate fields.
  await page.click('#ub-advanced-toggle');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="network.mqtt_tls_port"] input').value`), '0');
  assert.equal(await page.eval(`document.querySelector('.ub-field[data-id="tls.cert"]').hidden`), true);
  // Back to TLS: the newest release is chosen again and the certificate step is back.
  await page.click('#ub-advanced-toggle');
  await page.click('#ub-x-tls');
  assert.equal(await page.eval(`document.querySelector('#ub-s-tls').hidden`), false);
  await page.waitFor(`/v0\\.6\\.0/.test(document.querySelector('.ub-version-line').textContent)`);
});

test('both listeners: one image with TLS and plain MQTT, certificates still required', async () => {
  await fresh();
  await page.click('#ub-x-plain');
  await page.click('#ub-s-auth-anonymous');
  assert.equal(await status(), 'Next: add your certificates');
  await page.setFiles('#ub-s-drop input[type=file]', [join(DEV, 'ca.pem'), join(DEV, 'server.key'), join(DEV, 'server.pem')]);
  await page.waitFor(`document.querySelector('.ub-bar-status').textContent === 'The configuration is valid.'`);
  const iso = await buildAndDownload();
  const out = cli(['show', iso]);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /plaintext/i);
  assert.doesNotMatch(out.stdout, /mqtt_tls_port\s*=\s*0/);
  assert.equal(cli(['verify', iso]).status, 0);
  assert.match(await page.eval(`document.querySelector('.ub-version-line').textContent`), /v0\.6\.0/, 'both listeners work with the older release');
});

test('a release that cannot turn TLS off is greyed out in the list with the reason', async () => {
  await fresh();
  await page.click('#ub-x-plain');
  await page.click('#ub-x-tls');
  await page.click('#ub-advanced-toggle');
  const rows = await page.eval(`[...document.querySelectorAll('.ub-advanced .ub-release')].map(l => ({ tag: l.querySelector('input').value, disabled: l.querySelector('input').disabled, text: l.textContent }))`);
  assert.deepEqual(rows.map(r => [r.tag, r.disabled]), [['v0.6.0', true], ['v0.5.0', false]]);
  assert.match(rows[0].text, /needs v0\.2\.1 or newer/);
  assert.deepEqual(page.consoleErrors.filter(e => !/favicon/.test(e)), []);
  assert.ok(readFileSync(join(DEV, 'ca.pem')).length > 0);
});
