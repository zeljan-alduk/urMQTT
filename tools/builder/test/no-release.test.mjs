// The page while no release has a template: the state aldo.tech is in until the first release that comes with
// `urmqtt-template-<version>-universal.iso` is published (ADR-227). The page has to say so plainly, keep the releases
// that exist greyed out with their reasons, point to where releases appear, and have no button that looks usable and
// is not. Skipped when there is no Chrome (set CHROME=/path) or no build/builder.
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { haveWasm } from './helpers.mjs';

if (!haveBrowser() || !haveWasm()) {
  console.log('skipped: needs a Chrome (CHROME=/path), Node 22 and build/builder (make builder)');
  process.exit(0);
}

let site, server, browser, page, base;
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };

before(async () => {
  // What the mirror on aldo.tech lists today: v0.1.0, built before the runtime configuration existed.
  site = await prepareSite({
    releases: () => [{ tag: 'v0.1.0', prerelease: true, published: '2026-10-30T00:50:09Z', template: null }],
  });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: ISOLATION });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 900);
  await page.goto(base + '/#');
  await page.eval('sessionStorage.clear(); localStorage.clear()');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`, { what: 'the releases to load' });
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('it says plainly that there is no release to configure yet, and keeps the releases that exist greyed out', async () => {
  const banner = await page.eval(`(() => { const b = document.querySelector('#ub-no-release'); return b && { text: b.textContent, role: b.getAttribute('role') }; })()`);
  assert.ok(banner, 'a message about the missing release is on the page');
  assert.equal(banner.role, 'status');
  assert.match(banner.text, /No release with a configurable template has been published yet\./);
  assert.match(banner.text, /built before the runtime configuration existed/);
  const rows = await page.eval(`[...document.querySelectorAll('.ub-release')].map(l => ({ tag: l.querySelector('input').value, disabled: l.querySelector('input').disabled, checked: l.querySelector('input').checked, ariaDisabled: l.getAttribute('aria-disabled'), text: l.textContent }))`);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tag, 'v0.1.0');
  assert.equal(rows[0].disabled, true);
  assert.equal(rows[0].checked, false, 'nothing is selected');
  assert.equal(rows[0].ariaDisabled, 'true');
  assert.match(rows[0].text, /pre-release/);
  assert.match(rows[0].text, /cannot be configured here/);
});

test('it links to the releases on GitHub (and to nothing but GitHub)', async () => {
  const links = await page.eval(`[...document.querySelectorAll('#ub-no-release a')].map(a => ({ href: a.href, text: a.textContent, target: a.target, rel: a.rel }))`);
  assert.equal(links.length, 1);
  assert.equal(links[0].href, 'https://github.com/zeljan-alduk/urMQTT/releases');
  assert.equal(links[0].text, 'All releases on GitHub');
  assert.equal(links[0].target, '_blank');
  assert.match(links[0].rel, /noopener/);
  // Nothing was fetched from GitHub: the link is only a link.
  assert.ok(page.requests.every(r => r.url.startsWith(base) || r.url.startsWith('data:') || r.url.startsWith('blob:')), JSON.stringify(page.requests.map(r => r.url)));
});

test('no button looks usable and is not: Build is off with the reason, Download and the emulator are off with it too', async () => {
  const why = 'There is no release to build from yet.';
  const state = await page.eval(`({
    build: { disabled: document.querySelector('#ub-build').disabled, hint: document.querySelector('#ub-build-hint').textContent },
    status: document.querySelector('.ub-bar-status').textContent,
    download: { aria: document.querySelector('#ub-download').getAttribute('aria-disabled'), href: document.querySelector('#ub-download').getAttribute('href') },
    emulator: document.querySelector('#ub-emulator') && document.querySelector('#ub-emulator').getAttribute('aria-disabled'),
    emulatorHint: document.querySelector('#ub-emulator-hint').textContent,
  })`);
  assert.equal(state.build.disabled, true);
  assert.equal(state.build.hint, why);
  assert.equal(state.status, why);
  assert.equal(state.download.aria, 'true');
  assert.equal(state.download.href, '#');
  assert.equal(state.emulator, 'true', 'the emulator button is there (the page is isolated) and off');
  assert.equal(state.emulatorHint, why);
  // Clicking the off buttons does nothing: no dialog, no request for the emulator.
  await page.click('#ub-emulator');
  await page.click('#ub-download');
  assert.equal(await page.eval(`Boolean(document.querySelector('dialog[open]'))`), false);
  assert.deepEqual(page.requests.filter(r => /\/emulator\//.test(r.url)), []);
});

test('the form still works, and files from the computer are still a way in', async () => {
  // A preset changes the form, and the page keeps saying why it cannot build.
  await page.click('.ub-preset:nth-child(2)');
  await page.waitFor(`/Settings changed from the defaults: [1-9]/.test(document.body.textContent)`, { what: 'the changed count' });
  assert.equal(await page.eval(`document.querySelector('#ub-build').disabled`), true);
  // The message has its own way out: use files from the computer (the link below the releases).
  await page.eval(`[...document.querySelectorAll('.ub-link-btn')].find(b => b.textContent === 'Use files from my computer').click()`);
  await page.waitFor(`document.querySelector('dialog[open]')`, { what: 'the dialog for files from the computer' });
  assert.match(await page.eval(`document.querySelector('dialog[open]').textContent`), /SHA256SUMS/);
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
  assert.deepEqual(page.consoleErrors.filter(e => !/favicon/.test(e)), []);
});
