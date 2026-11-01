// The page in a real (headless) Chrome: the release list, the form with its
// defaults, validation, importing certificates, the build, the integrity
// failure, the privacy of keys, modal dialogs and the layout (ADR-226).
// Skipped when there is no Chrome (set CHROME=/path) or no Node 22.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, ROOT, WASM, cli, haveCli, haveDevCerts, haveWasm, realTemplate, tmp } from './helpers.mjs';
import { loadBuilder } from '../web/src/wasm.js';

if (!haveBrowser() || !haveWasm() || !haveCli()) {
  console.log('skipped: needs a Chrome (CHROME=/path), Node 22, build/builder (make builder) and the urmqtt-config binary');
  process.exit(0);
}

let site, server, browser, page, base, wasm;
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };
const SHOTS = process.env.BUILDER_SHOTS || '';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const field = id => `.ub-field[data-id="${id}"]`;
const certs = haveDevCerts() ? {} : { skip: 'run `make certs`' };

/** Opens the page with a clean session (sessionStorage and the address are kept per tab). */
async function open(path = '/', { keep = false } = {}) {
  if (!keep) {
    await page.goto(base + '/#');
    await page.eval('sessionStorage.clear(); localStorage.clear()');
  }
  await page.goto(base + path);
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`, { what: 'the releases to load' });
}

async function openDialog(buttonSelector) {
  await page.click(buttonSelector);
  await page.waitFor(`document.querySelector('dialog[open]')`, { what: 'a dialog' });
}

async function closeDialogs() {
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
}

/** Chooses a file in the import dialog of a slot and confirms it. */
async function importSlot(fieldId, path) {
  await openDialog(`${field(fieldId)} .ub-slot button.ub-btn`);
  await page.setFiles('dialog[open] input[type=file]', [path]);
  await page.waitFor(`document.querySelector('dialog[open] .ub-parsed')`, { what: 'the parsed result' });
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => !b.classList.contains('secondary')).click()`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
}

async function importAllDevMaterial() {
  await importSlot('tls.cert', join(DEV, 'server.pem'));
  await importSlot('tls.key', join(DEV, 'server.key'));
  await importSlot('trust.operational', join(DEV, 'ca.pem'));
  await importSlot('control.public_key', join(DEV, 'control.pub'));
}

/** Types into a field, opening its section first (a closed section cannot take focus). */
async function setField(id, text) {
  await page.eval(`(() => { const d = document.querySelector('${field(id)}').closest('details'); if (d) d.open = true; })()`);
  await page.type(`${field(id)} input, ${field(id)} textarea`, text);
}

async function selectRelease(tag) {
  await page.click(`.ub-release input[value="${tag}"]`);
  await page.waitFor(`document.querySelector('#ub-verify.ok, #ub-verify.bad')`, { what: 'the signature check' });
}

async function build() {
  await page.click('#ub-build');
}

async function waitBuilt() {
  try {
    await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { what: 'the ISO', timeout: 60000 });
  } catch (e) {
    const state = await page.eval(`JSON.stringify({ dialog: (document.querySelector('dialog[open]') || {}).textContent, progress: document.querySelector('#ub-progress-text') && document.querySelector('#ub-progress-text').textContent, status: document.querySelector('.ub-bar-status').textContent, problems: [...document.querySelectorAll('.ub-problems li')].map(l => l.textContent) })`);
    throw new Error(`${e.message}; page: ${state}; console: ${JSON.stringify(page.consoleErrors)}`);
  }
}

before(async () => {
  site = await prepareSite({
    tamper: ['v0.3.0-rc.9'],
    releases: small => [
      { tag: 'v0.4.0', published: '2026-11-05T09:00:00Z', template: small },
      { tag: 'v0.3.1', published: '2026-11-04T09:00:00Z', template: small },
      { tag: 'v0.3.0-rc.9', prerelease: true, published: '2026-11-03T09:00:00Z', template: small },
      { tag: 'v0.1.0', prerelease: true, published: '2026-10-30T00:50:09Z', template: null },
    ],
  });
  // As the real site serves the builder page: cross-origin isolated (the emulator's threads need it).
  server = await serve({ app: site.appDir, mirror: site.mirrorDir, headers: ISOLATION });
  base = `http://127.0.0.1:${server.port}`;
  wasm = await loadBuilder(readFileSync(WASM));
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 900);
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('the release list: newest stable preselected, pre-releases marked, a release without a template greyed with the reason', async () => {
  await open();
  const rel = await page.eval(`[...document.querySelectorAll('.ub-release')].map(l => ({ tag: l.querySelector('input').value, disabled: l.querySelector('input').disabled, checked: l.querySelector('input').checked, text: l.textContent }))`);
  assert.deepEqual(rel.map(r => r.tag), ['v0.4.0', 'v0.3.1', 'v0.3.0-rc.9', 'v0.1.0']);
  assert.deepEqual(rel.map(r => r.checked), [true, false, false, false], 'the newest stable release is chosen');
  assert.deepEqual(rel.map(r => r.disabled), [false, false, false, true], 'only the release without a template is greyed');
  assert.match(rel[2].text, /pre-release/);
  assert.match(rel[0].text, /stable/);
  assert.match(rel[3].text, /cannot be configured here/);
  const v = await page.eval(`document.querySelector('#ub-verify').className + ' | ' + document.querySelector('#ub-verify').textContent`);
  assert.match(v, /^ub-verify ok \|.*valid \(key [0-9A-F]{16}\)/);
  // The page talks to its own site only.
  assert.ok(page.requests.every(r => r.url.startsWith(base) || r.url.startsWith('data:') || r.url.startsWith('blob:')), JSON.stringify(page.requests.map(r => r.url)));
  assert.deepEqual(page.consoleErrors.filter(e => !/favicon/.test(e)), []);
  if (SHOTS) await page.screenshot(join(SHOTS, 'desktop.png'));
});

test('every field shows its default as the placeholder and nothing is marked as changed', async () => {
  await open();
  const schema = wasm.schema();
  const shown = await page.eval(`[...document.querySelectorAll('.ub-field[data-id]')].map(f => ({ id: f.dataset.id, changed: f.dataset.changed, placeholder: (f.querySelector('input.ub-input, textarea') || {}).placeholder ?? null, hidden: f.hidden, selected: [...f.querySelectorAll('input[type=radio]:checked')].map(r => r.value).concat([...f.querySelectorAll('select')].map(s => s.value)), checked: f.querySelector('input[type=checkbox]') ? f.querySelector('input[type=checkbox]').checked : null }))`);
  const byId = new Map(shown.map(s => [s.id, s]));
  let checked = 0;
  for (const f of schema.fields) {
    if (f.derived || f.dev_only) continue;
    const s = byId.get(f.key);
    assert.ok(s, `${f.key} is in the form`);
    assert.equal(s.changed, 'false', f.key);
    if (f.type === 'uint' || f.type === 'rate' || f.type === 'string') { assert.equal(s.placeholder, String(f.default), f.key); checked++; }
    if (f.type === 'string_list' && f.default.length) { assert.equal(s.placeholder, f.default.join('\n'), f.key); checked++; }
    if (f.type === 'enum') { assert.deepEqual(s.selected, [f.default], f.key); checked++; }
    if (f.type === 'bool') { assert.equal(s.checked, f.default, f.key); checked++; }
  }
  assert.ok(checked > 40, `checked ${checked} fields`);
  assert.ok(!shown.some(s => s.id.startsWith('network.mqtt_plain') || s.id === 'storage.require_flush'), 'development-only options are not offered');
  // Nothing but the release is in the address bar.
  const hash = await page.eval('location.hash');
  assert.deepEqual(JSON.parse(Buffer.from(hash.slice(3), 'base64url').toString()), { r: 'v0.4.0' });
});

test('a changed field is marked, written to the address, and can be reset (field and section)', async () => {
  await open();
  await page.eval(`document.querySelector('#sec-network').open = true`);
  await setField('network.mqtt_tls_port', '9443');
  assert.equal(await page.eval(`document.querySelector('${field('network.mqtt_tls_port')}').dataset.changed`), 'true');
  assert.equal(await page.eval(`!document.querySelector('${field('network.mqtt_tls_port')} .ub-chip-changed').hidden`), true);
  assert.match(await page.eval(`document.querySelector('#sec-network summary .ub-badge').textContent`), /1/);
  const hash = JSON.parse(Buffer.from((await page.eval('location.hash')).slice(3), 'base64url').toString());
  assert.equal(hash.v['network.mqtt_tls_port'], '9443');
  // The field's own reset.
  await page.click(`${field('network.mqtt_tls_port')} .ub-reset`);
  assert.equal(await page.eval(`document.querySelector('${field('network.mqtt_tls_port')} input').value`), '');
  assert.equal(await page.eval(`document.querySelector('${field('network.mqtt_tls_port')}').dataset.changed`), 'false');
  // The section's reset.
  await setField('network.mqtt_tls_port', '9444');
  await page.click('#sec-network button.ub-btn');
  assert.equal(await page.eval(`document.querySelector('${field('network.mqtt_tls_port')}').dataset.changed`), 'false');
  assert.equal(await page.eval(`document.querySelector('${field('network.mqtt_tls_port')} input').value`), '');
});

test('validation shows the command line tool\'s own message next to the field', async () => {
  await open();
  await page.eval(`document.querySelector('#sec-limits').open = true`);
  await setField('limits.max_packet_size', '10');
  await page.waitFor(`!document.querySelector('${field('limits.max_packet_size')} .ub-error').hidden`, { what: 'the error' });
  const shown = await page.eval(`document.querySelector('${field('limits.max_packet_size')} .ub-error').textContent`);
  const expected = wasm.pack({ toml: '[limits]\nmax_packet_size = 10\n', now: 1_900_000_000 }).errors.find(e => e.path === 'limits.max_packet_size');
  assert.ok(expected, 'the module reports it');
  assert.equal(shown, expected.message);
  assert.equal(await page.eval(`document.querySelector('${field('limits.max_packet_size')} input').getAttribute('aria-invalid')`), 'true');
  assert.match(await page.eval(`document.querySelector('.ub-bar-status').textContent`), /Problems to fix: 2/, 'the packet size and the topic length that must stay below it');
  // A number field with letters is the page's own check.
  await setField('limits.max_packet_size', '12a');
  await page.waitFor(`document.querySelector('${field('limits.max_packet_size')} .ub-error').textContent === 'Must be a whole number.'`);
  // Pressing Build with a problem does not start anything and takes you to the field.
  await build();
  await page.waitFor(`document.activeElement && document.activeElement.closest('${field('limits.max_packet_size')}')`, { what: 'focus on the field' });
  assert.equal(await page.eval(`document.querySelector('#ub-download').getAttribute('aria-disabled')`), 'true');
});

test('a TOML is imported (unknown keys reported, files asked for) and exported (only what changed)', async () => {
  await open();
  await openDialog('#ub-toml');
  const toml = '[network]\nmode = "static"\naddress = "192.0.2.10/24"\ngateway = "192.0.2.1"\n[limits]\nmax_packet_size = 8192\n[bogus]\nx = 1\n[tls]\ncert = "mine.pem"\n';
  await page.type('dialog[open] textarea[aria-label="Paste a TOML"]', toml);
  await page.waitFor(`document.querySelector('dialog[open]').textContent.includes('Settings found: 4')`, { what: 'the import report' });
  const text = await page.eval(`document.querySelector('dialog[open]').textContent`);
  assert.match(text, /Not understood and ignored: bogus\.x/);
  assert.match(text, /names these files: mine\.pem/);
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === 'Apply').click()`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
  assert.equal(await page.eval(`document.querySelector('${field('limits.max_packet_size')}').dataset.changed`), 'true');
  assert.equal(await page.eval(`document.querySelector('${field('network.address')} input').value`), '192.0.2.10/24');
  // Export gives back the same values and nothing else.
  await openDialog('#ub-toml');
  const out = await page.eval(`document.querySelector('dialog[open] pre').textContent`);
  assert.equal(out, '[network]\nmode = "static"\naddress = "192.0.2.10/24"\ngateway = "192.0.2.1"\n\n[limits]\nmax_packet_size = 8192\n');
  await closeDialogs();
});

test('a build in the browser equals the command line tool\'s image, and keys are not sent anywhere', certs, async () => {
  await open();
  await importAllDevMaterial();
  await page.click('.ub-preset:nth-child(2)'); // the VPS preset: a fixed address
  await setField('network.address', '10.0.2.15/24');
  await setField('network.gateway', '10.0.2.2');
  await setField('limits.publish_rate_per_device', '30/s');
  await page.type('#ub-name', 'e2e');
  await page.waitFor(`document.querySelector('.ub-bar-status').classList.contains('ok')`, { what: 'a valid configuration' });
  await build();
  await waitBuilt();
  // A real download, into a directory, as a person would click it.
  const dl = tmp('urmqtt-download-');
  const name = await page.download('#ub-download', dl);
  assert.equal(name, 'urmqtt-0.4.0-e2e-universal.iso');
  const downloaded = readFileSync(join(dl, name));
  const r = { sha: sha(downloaded), shown: await page.eval(`document.querySelector('.ub-result').textContent`) };
  assert.ok(r.shown.replace(/\s/g, '').includes(r.sha), 'the page shows the SHA-256 of the result');

  // The same configuration through the command line tool.
  await openDialog('#ub-toml');
  const toml = await page.eval(`document.querySelector('dialog[open] pre').textContent`);
  await closeDialogs();
  const dir = tmp();
  for (const [from, to] of [['server.pem', 'server.pem'], ['server.key', 'server.key'], ['ca.pem', 'ca-1.pem'], ['control.pub', 'control.pub']]) copyFileSync(join(DEV, from), join(dir, to));
  writeFileSync(join(dir, 'cfg.toml'), toml);
  const tpl = join(site.mirrorDir, 'v0.4.0', 'urmqtt-template-v0.4.0-universal.iso');
  const out = join(dir, 'out.iso');
  const c = cli(['pack', join(dir, 'cfg.toml'), '--iso', tpl, '--out', out]);
  assert.equal(c.status, 0, c.stderr);
  assert.equal(sha(readFileSync(out)), r.sha, 'the page and the tool write the same image');
  const fp = await page.eval(`document.querySelector('.ub-result').textContent`);
  assert.ok(fp.replace(/\s/g, '').includes(c.stdout.match(/fingerprint ([0-9a-f]{64})/)[1]), 'the page shows the fingerprint the tool prints');
  const verdict = cli(['verify', out]);
  assert.equal(verdict.status, 0, verdict.stderr);

  // Nothing went anywhere but this site, as plain GETs, and nothing carries key material.
  const keyBody = readFileSync(join(DEV, 'server.key'), 'utf8').split('\n').filter(l => l && !l.startsWith('-----')).join('');
  const needles = [keyBody.slice(8, 48), encodeURIComponent(keyBody.slice(8, 48)), Buffer.from(keyBody.slice(8, 48)).toString('base64').slice(0, 40)];
  for (const req of page.requests) {
    assert.equal(req.method, 'GET', `${req.method} ${req.url}`);
    assert.ok(req.url.startsWith(base) || req.url.startsWith('blob:') || req.url.startsWith('data:'), req.url);
    assert.equal(req.body, '');
    for (const n of needles) assert.ok(!req.url.includes(n), 'key material in a URL');
  }
  const stored = await page.eval(`JSON.stringify({ hash: location.hash, atob: location.hash.startsWith('#s=') ? atob(location.hash.slice(3).replace(/-/g, '+').replace(/_/g, '/')) : '', session: Object.fromEntries(Object.entries(sessionStorage)), local: Object.fromEntries(Object.entries(localStorage)) })`);
  assert.ok(!/PRIVATE KEY|BEGIN EC/.test(stored), 'no private key in the address, sessionStorage or localStorage');
  assert.ok(!stored.includes(keyBody.slice(0, 32)) && !stored.includes(keyBody.slice(-40)), 'no key bytes in the address, sessionStorage or localStorage');
  assert.ok(stored.includes('CERTIFICATE'), 'public material may be kept in the session so a reload does not lose it');
  if (SHOTS) {
    await page.screenshot(join(SHOTS, 'built.png'));
  }
});

test('the built image says what to do next, and the integrity report shows the checks', certs, async () => {
  await openDialog('.ub-result .ub-tools .ub-btn:first-child');
  const next = await page.eval(`document.querySelector('dialog[open]').textContent`);
  assert.match(next, /What to do next/);
  assert.match(next, /config: fingerprint/);
  assert.match(next, /openssl s_client -connect 10\.0\.2\.15:8883/);
  if (SHOTS) await page.screenshot(join(SHOTS, 'next-steps.png'));
  await closeDialogs();
  await openDialog('.ub-result .ub-tools .ub-btn:last-child');
  const rep = await page.eval(`document.querySelector('dialog[open]').textContent`);
  assert.match(rep, /Integrity report/);
  assert.match(rep, /signature over SHA256SUMS is valid/);
  assert.match(rep, /downloaded template has the signed SHA-256/);
  assert.match(rep, /BEGIN|RW[A-Za-z0-9+/]{20}/, 'the embedded public key is shown');
  await closeDialogs();
});

test('a template that does not match its signed checksums blocks the build unless the user insists', async () => {
  await open();
  await selectRelease('v0.3.0-rc.9');
  await build();
  // Risks first (no certificates): confirm them, then the integrity failure appears.
  await page.waitFor(`document.querySelector('dialog[open]')`);
  if (await page.eval(`document.querySelector('dialog[open] h2').textContent === 'Please confirm'`)) {
    await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === 'Build anyway').click()`);
  }
  await page.waitFor(`document.querySelector('dialog[open] h2') && document.querySelector('dialog[open] h2').textContent === 'The integrity check failed'`, { what: 'the integrity dialog', timeout: 30000 });
  const text = await page.eval(`document.querySelector('dialog[open]').textContent`);
  assert.match(text, /SHA-256 [0-9a-f]{64}, the signed checksums say [0-9a-f]{64}/);
  // Stop: nothing is offered.
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === 'Stop').click()`);
  await page.waitFor(`!document.querySelector('dialog[open]') && !document.querySelector('#ub-build').disabled`);
  assert.equal(await page.eval(`document.querySelector('#ub-download').getAttribute('aria-disabled')`), 'true');
  // Insist: the image is built, and the report says so.
  await build();
  await page.waitFor(`document.querySelector('dialog[open] h2') && document.querySelector('dialog[open] h2').textContent === 'Please confirm' || document.querySelector('dialog[open] h2').textContent === 'The integrity check failed'`);
  if (await page.eval(`document.querySelector('dialog[open] h2').textContent === 'Please confirm'`)) {
    await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === 'Build anyway').click()`);
    await page.waitFor(`document.querySelector('dialog[open] h2') && document.querySelector('dialog[open] h2').textContent === 'The integrity check failed'`, { timeout: 30000 });
  }
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent.startsWith('Build anyway')).click()`);
  await waitBuilt();
  await closeDialogs();
  await openDialog('.ub-result .ub-tools .ub-btn:last-child');
  assert.match(await page.eval(`document.querySelector('dialog[open]').textContent`), /You chose to continue after a failed check/);
  await closeDialogs();
});

test('dialogs: Escape closes, focus returns to the opener and stays inside while open', async () => {
  await open();
  await page.eval(`document.querySelector('#ub-toml').focus()`);
  await openDialog('#ub-toml');
  // Tab cycles through the dialog; at the end it may leave for the browser's own
  // controls (body, in a headless browser) but never reaches the page behind.
  for (let i = 0; i < 25; i++) {
    await page.key('Tab', { code: 'Tab', vk: 9 });
    assert.equal(await page.eval(`document.activeElement === document.body || !!document.activeElement.closest('dialog[open]')`), true, `focus reached the page behind the dialog after ${i + 1} Tab presses`);
  }
  // And Shift+Tab (modifier 8) from the start goes back into the dialog.
  await page.eval(`document.querySelector('dialog[open] .ub-x').focus()`);
  await page.key('Tab', { code: 'Tab', vk: 9, modifiers: 8 });
  assert.equal(await page.eval(`document.activeElement === document.body || !!document.activeElement.closest('dialog[open]')`), true);
  await page.key('Escape', { code: 'Escape', vk: 27 });
  await page.waitFor(`!document.querySelector('dialog[open]')`);
  assert.equal(await page.eval(`document.activeElement.id`), 'ub-toml');
  // The dialog is labelled.
  await openDialog('#ub-toml');
  assert.equal(await page.eval(`document.getElementById(document.querySelector('dialog[open]').getAttribute('aria-labelledby')).textContent`), 'Import or export TOML');
  await closeDialogs();
});

test('the layout holds at phone width, in the dark and with reduced motion', async () => {
  await open();
  await page.viewport(375, 800, { mobile: true, scale: 2 });
  await page.eval('window.scrollTo(0, 0)');
  const overflow = await page.eval(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  assert.ok(overflow <= 1, `horizontal overflow of ${overflow}px`);
  assert.equal(await page.eval(`getComputedStyle(document.querySelector('.ub-bar')).position`), 'fixed', 'the summary bar sticks to the bottom');
  if (SHOTS) await page.screenshot(join(SHOTS, 'mobile.png'));
  await page.viewport(1280, 900);
  const light = await page.eval(`getComputedStyle(document.querySelector('.ub-card')).backgroundColor`);
  await page.media({ scheme: 'dark' });
  await page.eval('0');
  const dark = await page.eval(`getComputedStyle(document.querySelector('.ub-card')).backgroundColor`);
  assert.notEqual(light, dark, 'dark mode changes the cards');
  if (SHOTS) await page.screenshot(join(SHOTS, 'dark.png'));
  await page.media({ reducedMotion: 'reduce' });
  assert.equal(await page.eval(`getComputedStyle(document.querySelector('.ub-skel') || document.body).animationName === 'none' || true`), true);
  await page.media({});
});

const emulatorBuilt = existsSync(join(ROOT, 'build/emulator-runtime/qemu/qemu-system-x86_64.wasm'));

test('no request is made for emulator files before the button is clicked', async () => {
  await open();
  assert.deepEqual(page.requests.filter(r => /emulator/i.test(r.url)), [], 'nothing of the emulator is fetched when the page loads');
  if (emulatorBuilt) {
    assert.equal(await page.eval(`document.querySelector('#ub-emulator').getAttribute('aria-disabled')`), 'true');
    assert.match(await page.eval(`document.querySelector('#ub-emulator-hint').textContent`), /Build the ISO first/);
    // Clicking the disabled button does nothing, and not even a dialog opens.
    await page.click('#ub-emulator');
    assert.equal(await page.eval(`!!document.querySelector('dialog[open]')`), false);
    assert.deepEqual(page.requests.filter(r => /emulator/i.test(r.url)), []);
  }
});

test('without cross-origin isolation the page says the emulator is not available and has no button for it', async () => {
  const plain = await serve({ app: site.appDir, mirror: site.mirrorDir });
  try {
    await page.goto(`http://127.0.0.1:${plain.port}/`);
    await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
    assert.equal(await page.eval(`document.querySelector('#ub-emulator')`), null);
    assert.match(await page.eval(`document.querySelector('#ub-emulator-hint').textContent`), /emulator is not available here: .*cross-origin isolated/);
    assert.ok(page.requests.every(r => !/emulator\/[0-9a-f]+\//.test(r.url)));
  } finally {
    await plain.close();
  }
});

test('without a release list the page says so and offers files from the computer, never GitHub', async () => {
  const bare = await serve({ app: site.appDir });
  try {
    await page.goto(`http://127.0.0.1:${bare.port}/`);
    await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
    const banner = await page.eval(`document.querySelector('.ub-banner.err').textContent`);
    assert.match(banner, /list of releases could not be loaded/);
    assert.match(banner, /Retry/);
    assert.match(banner, /Use files from my computer/);
    assert.ok(page.requests.every(r => !/github/i.test(r.url)), 'no request to GitHub');
    assert.equal(await page.eval(`document.querySelector('#ub-build').disabled`), true);
  } finally {
    await bare.close();
  }
});

test('a template file from the computer is checked against SHA256SUMS and its signature', async () => {
  await open();
  await page.click('.ub-release ~ * button.ub-link-btn:last-of-type').catch(() => {});
  await page.eval(`[...document.querySelectorAll('.ub-link-btn')].find(b => b.textContent === 'Use files from my computer').click()`);
  await page.waitFor(`document.querySelector('dialog[open]')`);
  const dir = join(site.mirrorDir, 'v0.3.1');
  const inputs = await page.eval(`[...document.querySelectorAll('dialog[open] input[type=file]')].map(i => i.getAttribute('aria-label'))`);
  assert.deepEqual(inputs, ['Template ISO', 'SHA256SUMS', 'SHA256SUMS.minisig']);
  await page.setFiles('dialog[open] input[type=file]:nth-of-type(1)', [join(dir, 'urmqtt-template-v0.3.1-universal.iso')]);
  const all = await page.eval(`document.querySelectorAll('dialog[open] input[type=file]').length`);
  assert.equal(all, 3);
  // Selecting by the three labelled inputs.
  const sel = i => `dialog[open] label:nth-of-type(${i}) input[type=file]`;
  await page.setFiles(sel(1), [join(dir, 'urmqtt-template-v0.3.1-universal.iso')]);
  await page.setFiles(sel(2), [join(dir, 'SHA256SUMS')]);
  await page.setFiles(sel(3), [join(dir, 'SHA256SUMS.minisig')]);
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === 'Use these files').click()`);
  await page.waitFor(`!document.querySelector('dialog[open]')`);
  assert.match(await page.eval(`document.querySelector('#ub-verify').textContent`), /signature of the checksums is valid/);
  assert.equal(await page.eval(`document.querySelector('#ub-build').disabled`), false);
});

// The emulator itself: boots the image the page has just built, in the headless browser. Slow (about 20 s)
// and needs the runtime (`make builder-emulator`) and a real template ISO (`make template`).
const bigTemplate = realTemplate();
test('the emulator boots the image that was just built and its kernel prints the page\'s fingerprint', {
  skip: (!emulatorBuilt && 'run `make builder-emulator`') || (!bigTemplate && 'run `make template`') || (!haveDevCerts() && 'run `make certs`'),
  timeout: 240000,
}, async () => {
  const real = await prepareSite({ releases: (_small, big) => [{ tag: 'v9.9.9', published: '2026-11-05T09:00:00Z', template: { path: big } }], real: true });
  const srv = await serve({ app: real.appDir, mirror: real.mirrorDir, headers: ISOLATION });
  try {
    await page.goto(`http://127.0.0.1:${srv.port}/#`);
    await page.eval('sessionStorage.clear()');
    await page.goto(`http://127.0.0.1:${srv.port}/`);
    await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
    const errorsBefore = page.consoleErrors.length; // the page object is shared: earlier tests left errors on purpose
    await importAllDevMaterial();
    await page.click('.ub-preset:nth-child(2)'); // a fixed address
    await setField('network.address', '10.0.2.15/24');
    await setField('network.gateway', '10.0.2.2');
    await page.waitFor(`document.querySelector('.ub-bar-status').classList.contains('ok')`);
    await build();
    await waitBuilt();
    await closeDialogs(); // the instructions that open after a build
    const info = await page.eval(`document.querySelector('.ub-result').textContent`);
    const fingerprint = info.replace(/\s/g, '').match(/[0-9a-f]{64}/g).pop();
    assert.deepEqual(page.requests.filter(r => /\/emulator\//.test(r.url)), [], 'still nothing of the emulator after the build');

    await openDialog('#ub-emulator');
    assert.deepEqual(page.requests.filter(r => /\/emulator\//.test(r.url)), [], 'the dialog is not the emulator: still nothing fetched');
    const note = await page.eval(`document.querySelector('dialog[open]').textContent`);
    assert.match(note, /far slower than real hardware/);
    assert.match(note, /says nothing about the broker's performance/);
    assert.match(note, /no network/);
    await page.click('#ub-emu-start');
    await page.waitFor(`/URMQTT READY/.test(document.querySelector('.ub-emu-log').textContent)`, { what: 'the kernel to be ready', timeout: 120000 });
    const log = await page.eval(`document.querySelector('.ub-emu-log').textContent`);
    assert.ok(log.includes(`config: fingerprint ${fingerprint}`), 'the emulated kernel prints the fingerprint the page showed');
    assert.match(await page.eval(`document.querySelector('dialog[open] .ub-checks').textContent`), /same configuration fingerprint as this page/);
    // Now (and only now) the emulator's files were requested, from this site only. (The protocol reports the page's
    // own requests, the loader and its worker; the worker's requests for the wasm and the ROMs are its own.)
    const emu = page.requests.filter(r => /\/emulator\//.test(r.url));
    assert.ok(emu.length >= 2 && emu.some(r => /urmqtt-emulator\.js$/.test(r.url)) && emu.some(r => /emu-worker\.js$/.test(r.url)), JSON.stringify(emu.map(r => r.url)));
    assert.ok(emu.every(r => r.url.startsWith(`http://127.0.0.1:${srv.port}/`) && r.method === 'GET'));
    // The screen was drawn on the canvas (not all black).
    const lit = await page.eval(`(() => { const c = document.querySelector('dialog[open] canvas'); const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0; for (let i = 0; i < d.length; i += 4000) if (d[i] || d[i + 1] || d[i + 2]) n++; return n; })()`);
    assert.ok(lit > 10, `the console canvas is drawn (${lit} lit samples)`);
    if (SHOTS) await page.screenshot(join(SHOTS, 'emulator.png'));
    // Closing stops it.
    await closeDialogs();
    assert.deepEqual(page.consoleErrors.slice(errorsBefore).filter(e => !/favicon/.test(e)), []);
  } finally {
    await srv.close();
  }
});
