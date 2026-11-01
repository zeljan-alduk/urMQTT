// Pictures of the simple view and the advanced view (README, ADR-226), taken against a local test mirror signed
// with a throwaway key.   node tools/builder/test/screenshots-simple.mjs [OUT_DIR]
import { join } from 'node:path';

import { launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, ROOT, haveDevCerts } from './helpers.mjs';

const OUT = process.argv[2] || join(ROOT, 'docs/screenshots');
if (!haveDevCerts()) throw new Error('run `make certs` first');
const site = await prepareSite({ releases: small => [{ tag: 'v0.2.0', published: '2026-11-10T09:00:00Z', template: small }] });
const server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' } });
const browser = await launch();
const page = await browser.newPage();
const base = `http://127.0.0.1:${server.port}`;
try {
  await page.viewport(1280, 900);
  await page.goto(`${base}/#`);
  await page.eval('sessionStorage.clear(); localStorage.clear()');
  await page.goto(`${base}/`);
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  await page.waitFor(`document.querySelector('.ub-chip.ok')`);
  await page.screenshot(join(OUT, 'simple-start.png'));
  await page.click('.ub-where[data-id="vps"]');
  await page.type('#ub-s-addr', '203.0.113.10/24');
  await page.type('#ub-s-gw', '203.0.113.1');
  await page.setFiles('#ub-s-drop input[type=file]', [join(DEV, 'ca.pem'), join(DEV, 'server.key'), join(DEV, 'server.pem')]);
  await page.type('#ub-s-name', 'vps');
  await page.waitFor(`document.querySelector('.ub-bar-status').textContent === 'The configuration is valid.'`).catch(async e => { console.log(await page.eval(`document.querySelector('.ub-bar-status').textContent + ' / ' + document.querySelector('.ub-simple').textContent.slice(0, 700)`)); throw e; });
  await page.screenshot(join(OUT, 'simple-ready.png'));
  await page.click('#ub-build');
  await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { timeout: 60000 });
  await page.screenshot(join(OUT, 'simple-result.png'));
  await page.viewport(390, 844, { mobile: true, scale: 1 });
  await page.eval('window.scrollTo(0, 0)');
  await page.screenshot(join(OUT, 'simple-phone.png'));
  await page.viewport(1280, 900);
  await page.click('#ub-advanced-toggle');
  await page.type('#ub-search', 'port');
  await page.waitFor(`document.querySelector('#ub-search').value === 'port'`);
  await page.eval('window.scrollTo(0, 0)');
  await page.screenshot(join(OUT, 'advanced-search.png'));
  console.log('pictures in', OUT);
} finally {
  await browser.close();
  await server.close();
}
