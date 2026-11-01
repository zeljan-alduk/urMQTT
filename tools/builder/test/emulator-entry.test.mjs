// The emulator's boot menu: the entry chosen in the dialog without keys, and the keyboard reaching the guest.
// Slow (about 30 s) and needs the emulator runtime (`make builder-emulator`), a real template ISO and `make certs`.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, ROOT, haveDevCerts, haveWasm, realTemplate } from './helpers.mjs';

const runtime = existsSync(join(ROOT, 'build/emulator-runtime/qemu/qemu-system-x86_64.wasm'));
const big = realTemplate();
if (!haveBrowser() || !haveWasm() || !runtime || !big || !haveDevCerts()) {
  console.log('skipped: needs Chrome, build/builder, the emulator runtime, a real template ISO and `make certs`');
  process.exit(0);
}

let site, server, browser, page, base;
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };
const field = id => `.ub-field[data-id="${id}"]`;
const serial = () => page.eval(`document.querySelector('.ub-emu-log').textContent`);

/** A built image with the Lab VM preset (diagnostics on), and the emulator's dialog open. */
async function openEmulator() {
  await page.goto(base + '/#');
  await page.eval(`sessionStorage.clear(); localStorage.clear(); localStorage.setItem('urmqtt-builder-advanced', '1')`);
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  for (const [id, f] of [['tls.cert', 'server.pem'], ['tls.key', 'server.key'], ['trust.operational', 'ca.pem'], ['control.public_key', 'control.pub']]) {
    await page.click(`${field(id)} .ub-slot button.ub-btn`);
    await page.waitFor(`document.querySelector('dialog[open]')`);
    await page.setFiles('dialog[open] input[type=file]', [join(DEV, f)]);
    await page.waitFor(`document.querySelector('dialog[open] .ub-parsed')`);
    await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => !b.classList.contains('secondary')).click()`);
    await page.waitFor(`!document.querySelector('dialog[open]')`);
  }
  await page.click('.ub-preset:nth-child(1)');
  await page.waitFor(`!document.querySelector('#ub-build').disabled`);
  await page.click('#ub-build');
  await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { timeout: 120000 });
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await page.click('#ub-emulator');
  await page.waitFor(`document.querySelector('dialog[open]')`);
}

before(async () => {
  site = await prepareSite({ real: true, releases: (_s, b) => [{ tag: 'v9.9.9', published: '2026-11-05T09:00:00Z', template: { path: b } }] });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: ISOLATION });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 1000);
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('choosing the Diagnostic entry in the dialog boots the diagnostic, with no key pressed', { timeout: 240000 }, async () => {
  await openEmulator();
  assert.match(await page.eval(`document.querySelector('dialog[open]').textContent`), /Boot menu entry/);
  await page.click('#ub-emu-entry-3');
  assert.match(await page.eval(`document.querySelector('#ub-emu-entry-note').textContent`), /about 20 seconds/);
  await page.click('#ub-emu-start');
  await page.waitFor(`/URMQTT DIAG DONE/.test(document.querySelector('.ub-emu-log').textContent)`, { timeout: 150000, what: 'the diagnostic to finish' });
  const log = await serial();
  assert.match(log, /URMQTT DIAG START/);
  assert.doesNotMatch(log, /URMQTT READY/, 'the broker was not started: the diagnostic entry ran');
  // The screen is the diagnostic's framebuffer UI, not the menu.
  const lit = await page.eval(`(() => { const c = document.querySelector('dialog[open] canvas'); const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0; for (let i = 0; i < d.length; i += 4000) if (d[i] || d[i + 1] || d[i + 2]) n++; return n; })()`);
  assert.ok(lit > 10);
});

test('the keyboard reaches the guest: arrow keys and Enter choose the Diagnostic entry in the boot menu', { timeout: 240000 }, async () => {
  await openEmulator();
  await page.click('#ub-emu-skip'); // keep the countdown: the menu waits for keys
  await page.click('#ub-emu-start');
  await page.waitFor(`document.activeElement && document.activeElement.tagName === 'CANVAS'`, { what: 'the screen to take the keyboard' });
  await new Promise(r => setTimeout(r, 5000)); // the menu is up (it counts down from 10)
  await page.key('ArrowDown', { code: 'ArrowDown', vk: 40 });
  await page.key('ArrowDown', { code: 'ArrowDown', vk: 40 });
  await page.key('Enter', { code: 'Enter', vk: 13 });
  await page.waitFor(`/URMQTT DIAG DONE/.test(document.querySelector('.ub-emu-log').textContent)`, { timeout: 150000, what: 'the diagnostic chosen with keys' });
  assert.doesNotMatch(await serial(), /URMQTT READY/);
});
