// The page after the release key rotation (ROADMAP NOW-2, docs/release-key-rotation.md): it trusts two keys,
// each for its tags only. The former test key verifies v0.1.0 to v0.4.1 and the page says so; the release key
// verifies the later releases; a signature by the test key on a newer tag, or by a key the page does not know,
// is a failed check. Both keys here are THROWAWAY keys made by the fixture. Skipped when there is no Chrome
// (set CHROME=/path) or no build/builder.
import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { newKey } from './mirror-fixture.mjs';
import { serve } from './serve.mjs';
import { haveWasm } from './helpers.mjs';

if (!haveBrowser() || !haveWasm()) {
  console.log('skipped: needs a Chrome (CHROME=/path), Node 22 and build/builder (make builder)');
  process.exit(0);
}

let site, server, browser, page, base;
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };
const stranger = newKey();

before(async () => {
  site = await prepareSite({
    rotation: true,
    releases: (small, _big, { oldKey }) => [
      { tag: 'v0.6.0', prerelease: true, published: '2026-11-09T09:00:00Z', template: small, signer: oldKey },
      { tag: 'v0.5.1', prerelease: true, published: '2026-11-08T09:00:00Z', template: small, signer: stranger },
      { tag: 'v0.5.0', prerelease: true, published: '2026-11-07T09:00:00Z', template: small },
      { tag: 'v0.4.1', prerelease: true, published: '2026-11-05T09:00:00Z', template: small, signer: oldKey },
      { tag: 'v0.1.0', prerelease: true, published: '2026-10-30T00:50:09Z', template: null },
    ],
  });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: ISOLATION });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 900);
  await page.goto(base + '/#');
  await page.eval(`sessionStorage.clear(); localStorage.clear(); localStorage.setItem("urmqtt-builder-advanced", "1")`);
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`, { what: 'the releases to load' });
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

async function select(tag) {
  await page.click(`.ub-release input[value="${tag}"]`);
  await page.waitFor(`document.querySelector('#ub-verify.ok, #ub-verify.bad')`, { what: `the signature check of ${tag}` });
  return page.eval(`document.querySelector('#ub-verify').className + ' | ' + document.querySelector('#ub-verify').textContent`);
}

test('the page names both keys and marks the releases of the former test key', async () => {
  const note = await page.eval(`[...document.querySelectorAll('.ub-help')].map(p => p.textContent).join(' ')`);
  assert.ok(note.includes(site.key.idText), 'the release key is named');
  assert.ok(note.includes(`signed with the project's former test key ${site.oldKey.idText}`), 'the former test key is named with its releases');
  const rows = await page.eval(`Object.fromEntries([...document.querySelectorAll('.ub-release')].map(l => [l.querySelector('input').value, l.textContent]))`);
  for (const tag of ['v0.4.1', 'v0.1.0']) assert.match(rows[tag], /signed with the project's former test key/, tag);
  for (const tag of ['v0.5.0', 'v0.5.1', 'v0.6.0']) assert.doesNotMatch(rows[tag], /former test key/, tag);
});

test('a release after the rotation verifies with the release key', async () => {
  const v = await select('v0.5.0');
  assert.match(v, new RegExp(`^ub-verify ok \\|.*valid \\(key ${site.key.idText}\\)`));
  assert.doesNotMatch(v, /former test key/);
  assert.equal(await page.eval(`document.querySelector('#ub-build').disabled`), false);
});

test('an old release verifies with the former test key, and the page says which key it was', async () => {
  const v = await select('v0.4.1');
  assert.match(v, /^ub-verify ok \|/);
  assert.ok(v.includes(`key ${site.oldKey.idText}: signed with the project's former test key, accepted for v0.1.0 to v0.4.1 only`), v);
  await page.eval(`[...document.querySelectorAll('#ub-verify .ub-link-btn')].find(b => b.textContent === 'Integrity report').click()`);
  await page.waitFor(`document.querySelector('dialog[open]')`);
  const rep = await page.eval(`document.querySelector('dialog[open]').textContent`);
  assert.match(rep, /Signed withthe project's former test key \(accepted for v0\.1\.0 to v0\.4\.1 only\)/);
  assert.ok(rep.includes(site.key.publicText.split('\n')[1]) && rep.includes(site.oldKey.publicText.split('\n')[1]), 'both public keys are shown');
  assert.match(rep, /releases v0\.4\.2 and later: minisign\.pub/);
  assert.ok(rep.includes(`--pubkey keys/minisign-test-${site.oldKey.idText}.pub`), 'the offline check names the key file that signed it');
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
});

test('the former test key is refused for a release newer than its range', async () => {
  const v = await select('v0.6.0');
  assert.match(v, /^ub-verify bad \|/);
  assert.ok(v.includes(`key ${site.oldKey.idText}, the project's former test key, is trusted for v0.1.0 to v0.4.1 only, not for v0.6.0`), v);
});

test('a signature by a key the page does not know is refused', async () => {
  const v = await select('v0.5.1');
  assert.match(v, /^ub-verify bad \|/);
  assert.ok(v.includes(`made with key ${stranger.idText}, which this page does not trust`), v);
});
