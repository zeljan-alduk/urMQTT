// Takes the pictures of the page for docs/screenshots/ (README and ADR-226): desktop, phone, dark, a dialog
// (a certificate imported, with what the page says about it) and, if the emulator runtime is built, the
// emulator. They are taken in headless Chrome against a local test mirror signed with a throwaway key, so the
// release names are the fixture's. Run: node tools/builder/test/screenshots.mjs [OUT_DIR]
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, ROOT, haveDevCerts, realTemplate } from './helpers.mjs';

const OUT = process.argv[2] || join(ROOT, 'docs/screenshots');
if (!haveDevCerts()) throw new Error('run `make certs` first');
const emulator = existsSync(join(ROOT, 'build/emulator-runtime/qemu/qemu-system-x86_64.wasm')) && realTemplate();

const site = await prepareSite({
  real: Boolean(emulator),
  releases: (small, big) => [
    { tag: 'v0.2.0', published: '2026-11-10T09:00:00Z', template: emulator ? { path: big } : small },
    { tag: 'v0.2.0-rc.1', prerelease: true, published: '2026-11-03T09:00:00Z', template: small },
    { tag: 'v0.1.0', prerelease: true, published: '2026-10-30T00:50:09Z', template: null },
  ],
});
const server = await serve({
  app: site.appDir, mirror: site.mirrorDir,
  headers: { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' },
});
const browser = await launch();
const page = await browser.newPage();
const base = `http://127.0.0.1:${server.port}`;
const field = id => `.ub-field[data-id="${id}"]`;
const ready = () => page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);

async function importSlot(fieldId, path) {
  await page.click(`${field(fieldId)} .ub-slot button.ub-btn`);
  await page.waitFor(`document.querySelector('dialog[open]')`);
  await page.setFiles('dialog[open] input[type=file]', [path]);
  await page.waitFor(`document.querySelector('dialog[open] .ub-parsed')`);
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => !b.classList.contains('secondary')).click()`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
}
async function setField(id, text) {
  await page.eval(`(() => { const d = document.querySelector('${field(id)}').closest('details'); if (d) d.open = true; })()`);
  await page.type(`${field(id)} input, ${field(id)} textarea`, text);
}

try {
  await page.viewport(1280, 800);
  await page.goto(`${base}/#`);
  await page.eval('sessionStorage.clear()');
  await page.goto(`${base}/`);
  await ready();
  // A configuration in the middle of being made: the VPS preset, a fixed address, the certificates.
  await page.click('.ub-preset:nth-child(2)');
  await setField('network.address', '203.0.113.10/24');
  await setField('network.gateway', '203.0.113.1');
  await importSlot('tls.cert', join(DEV, 'server.pem'));
  await importSlot('tls.key', join(DEV, 'server.key'));
  await importSlot('trust.operational', join(DEV, 'ca.pem'));
  await importSlot('control.public_key', join(DEV, 'control.pub'));
  await page.type('#ub-name', 'vps');
  await page.eval('window.scrollTo(0, 0)');
  // The summary is refreshed a moment after the last change: wait for it to show the changes made.
  await page.waitFor(`document.querySelector('.ub-bar-status').classList.contains('ok') && /Settings changed from the defaults: [1-9]/.test(document.body.textContent)`);
  await page.screenshot(join(OUT, 'builder-desktop.png'));

  // The same in the dark.
  await page.media({ scheme: 'dark' });
  await page.eval('window.scrollTo(0, 0)');
  await page.screenshot(join(OUT, 'builder-dark.png'));
  await page.media({});

  // A dialog: what the page says about the server certificate.
  await page.click(`${field('tls.cert')} .ub-slot button.ub-btn`);
  await page.waitFor(`document.querySelector('dialog[open]')`);
  await page.setFiles('dialog[open] input[type=file]', [join(DEV, 'server.pem')]);
  await page.waitFor(`document.querySelector('dialog[open] .ub-parsed')`);
  await page.screenshot(join(OUT, 'builder-dialog.png'));
  await page.eval(`document.querySelector('dialog[open]').close('')`);

  // The phone.
  await page.viewport(390, 844, { mobile: true, scale: 1 });
  await page.eval('window.scrollTo(0, 0)');
  await page.screenshot(join(OUT, 'builder-phone.png'));
  await page.viewport(1280, 800);

  if (emulator) {
    await page.click('#ub-build');
    await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { timeout: 60000 });
    await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
    await page.click('#ub-emulator');
    await page.waitFor(`document.querySelector('dialog[open]')`);
    await page.click('#ub-emu-start');
    await page.waitFor(`/URMQTT READY|refusing to serve/.test(document.querySelector('.ub-emu-log').textContent)`, { timeout: 120000 });
    await page.eval(`document.querySelector('dialog[open] .ub-body').scrollTop = 0`);
    await page.screenshot(join(OUT, 'builder-emulator.png'));
  }
  console.log('screenshots in', OUT);
} finally {
  await browser.close();
  await server.close();
}
