// Encryption at rest in the page (NOW-16, ADR-300), in a real (headless) Chrome: the encrypted project file and
// the encrypted copy in this browser never hold a secret in the clear, a wrong passphrase and a damaged file are
// refused with the dialog still open, the project comes back exactly (the TOML is the same), wiping removes the
// secrets, and nothing is sent anywhere. Skipped when there is no Chrome.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { DEV, haveCli, haveDevCerts, haveWasm, tmp } from './helpers.mjs';

if (!haveBrowser() || !haveWasm() || !haveCli() || !haveDevCerts()) {
  console.log('skipped: needs a Chrome (CHROME=/path), build/builder (make builder), the urmqtt-config binary and `make certs`');
  process.exit(0);
}

let site, server, browser, page, base;
const field = id => `.ub-field[data-id="${id}"]`;
const USERS = field('plaintext.users');
const PASS = 'orange-bicycle-staple-77';
const ACCOUNT_PW = 'Sensor-pw-4711-xyz';
const toHash = values => '#s=' + Buffer.from(JSON.stringify({ v: values })).toString('base64url');
const SAFE = { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'] };
const keyBody = readFileSync(join(DEV, 'server.key'), 'utf8').split('\n').filter(l => l && !l.startsWith('-----'))[0];

async function open(hash = '', { keep = false } = {}) {
  if (!keep) {
    await page.goto(base + '/#');
    await page.eval('sessionStorage.clear(); localStorage.clear(); localStorage.setItem("urmqtt-builder-advanced", "1")');
  }
  await page.goto('about:blank');
  await page.goto(base + '/' + hash);
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`, { what: 'the releases to load' });
  await page.eval(`window.__blobs = []; const o = URL.createObjectURL.bind(URL); URL.createObjectURL = b => { window.__blobs.push(b); return o(b); }`);
}

const pressButton = text => page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === ${JSON.stringify(text)}).click()`);
const waitPassphraseDialog = () => page.waitFor(`document.querySelector('dialog[open] input[data-role=passphrase]')`, { what: 'the passphrase dialog' });
const dialogError = () => page.eval(`(document.querySelector('dialog[open] [data-role=error]:not([hidden])') || {}).textContent || ''`);
const status = () => page.eval(`document.querySelector('#ub-project .ub-project-status').textContent`);
const waitNoDialog = () => page.waitFor(`!document.querySelector('dialog')`, { what: 'the dialog to close' });
const slotText = id => page.eval(`document.querySelector('${field(id)} .ub-slot').textContent`);
const accounts = () => page.eval(`document.querySelectorAll('${USERS} .ub-account').length`);

async function importSlot(fieldId, path) {
  await page.click(`${field(fieldId)} .ub-slot button.ub-btn`);
  await page.waitFor(`document.querySelector('dialog[open]')`);
  await page.setFiles('dialog[open] input[type=file]', [path]);
  await page.waitFor(`document.querySelector('dialog[open] .ub-parsed')`, { what: 'the parsed result' });
  await page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => !b.classList.contains('secondary')).click()`);
  await waitNoDialog();
}

async function tomlExport() {
  await page.click('#ub-toml');
  await page.waitFor(`document.querySelector('dialog[open] pre')`);
  const text = await page.eval(`document.querySelector('dialog[open] pre').textContent`);
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await waitNoDialog();
  return text;
}

/** Fills the project with a private key and one account. */
async function fill() {
  await open(toHash(SAFE));
  await importSlot('tls.cert', join(DEV, 'server.pem'));
  await importSlot('tls.key', join(DEV, 'server.key'));
  await page.eval(`document.querySelector('#sec-plaintext').open = true`);
  await page.click(`${USERS} .ub-add-account`);
  await page.type(`${USERS} .ub-account:nth-child(1) .ub-account-id input`, 'sensor-1');
  await page.type(`${USERS} .ub-account:nth-child(1) .ub-pw-edit input`, ACCOUNT_PW);
  await page.eval(`document.activeElement.blur()`);
  await page.waitFor(`!document.querySelector('${USERS} .ub-account:nth-child(1) .ub-error:not([hidden])')`, { what: 'the account to be hashed' });
}

/** The save dialog, answered. Returns the text of the file the page produced. */
async function saveProject(pass = PASS, again = pass) {
  await page.click('#ub-project-save');
  await waitPassphraseDialog();
  await page.type('dialog[open] input[data-role=passphrase]', pass);
  await page.type('dialog[open] input[data-role=passphrase-again]', again);
  await pressButton('Encrypt and save');
}

const lastBlobText = () => page.eval(`window.__blobs.length ? window.__blobs[window.__blobs.length - 1].text() : ''`);

async function everything() {
  const dump = await page.eval(`JSON.stringify({ hash: location.hash, session: Object.fromEntries(Object.entries(sessionStorage)), local: Object.fromEntries(Object.entries(localStorage)), html: document.documentElement.outerHTML })`);
  return dump + JSON.stringify(page.requests);
}

function assertClean(text, what, { ids = true } = {}) {
  for (const n of ['PRIVATE KEY', keyBody, ACCOUNT_PW, PASS, 'pbkdf2-sha256$', ...(ids ? ['sensor-1'] : [])]) assert.ok(!text.includes(n), `${what} holds ${n.slice(0, 12)} in the clear`);
}

before(async () => {
  site = await prepareSite({ releases: small => [{ tag: 'v0.4.0', published: '2026-11-05T09:00:00Z', template: small }] });
  server = await serve({ app: site.appDir, mirror: site.mirrorDir });
  base = `http://127.0.0.1:${server.port}`;
  browser = await launch();
  page = await browser.newPage();
  await page.viewport(1280, 900);
}, { timeout: 120000 });

after(async () => {
  if (browser) await browser.close();
  if (server) await server.close();
});

test('an encrypted project file: no secret in it, the same project comes back, a wrong passphrase and a damaged file are refused', async () => {
  await fill();
  const keyBefore = await slotText('tls.key');
  assert.ok(keyBefore.length > 5);
  const tomlBefore = await tomlExport();
  const requestsBefore = page.requests.length;

  // A weak passphrase and two that differ stay in the dialog.
  await saveProject('short', 'short');
  assert.match(await dialogError(), /at least 12 characters/);
  await page.type('dialog[open] input[data-role=passphrase]', PASS);
  await page.type('dialog[open] input[data-role=passphrase-again]', PASS + 'x');
  await pressButton('Encrypt and save');
  assert.match(await dialogError(), /differ/);
  await page.type('dialog[open] input[data-role=passphrase-again]', PASS);
  await pressButton('Encrypt and save');
  await waitNoDialog();
  await page.waitFor(`window.__blobs.length > 0`, { what: 'the file' });
  const file = await lastBlobText();
  await page.waitFor(`/saved to a file/.test(document.querySelector('#ub-project .ub-project-status').textContent)`, { what: 'the file to be saved' });
  assertClean(file, 'the project file');
  const env = JSON.parse(file);
  assert.equal(env.format, 'urmqtt-project');
  assert.equal(env.version, 1);
  assert.equal(env.iterations, 600000);
  assertClean(await everything(), 'the page, its storage and its requests', { ids: false });
  assert.equal(page.requests.length, requestsBefore, 'saving sent nothing');
  const path = join(tmp(), 'project.urmqtt-project');
  writeFileSync(path, file);

  // Wipe: the key, the account and (with them) the build are gone from the page.
  await page.click('#ub-project-wipe');
  assert.equal(await accounts(), 0);
  assert.notEqual(await slotText('tls.key'), keyBefore);
  assert.match(await status(), /removed from the page/);
  assert.notEqual(await tomlExport(), tomlBefore, 'the wiped form differs');

  // Open: a wrong passphrase keeps the dialog open with the reason.
  await page.click('#ub-project-open');
  await page.waitFor(`document.querySelector('dialog[open] input[type=file]')`);
  await page.setFiles('dialog[open] input[type=file]', [path]);
  await pressButton('Continue');
  await waitPassphraseDialog();
  await page.type('dialog[open] input[data-role=passphrase]', PASS + '!');
  await pressButton('Decrypt and open');
  await page.waitFor(`document.querySelector('dialog[open] [data-role=error]:not([hidden])')`);
  assert.match(await dialogError(), /Wrong passphrase, or the file was changed/);
  assert.equal(await page.eval(`document.querySelector('dialog[open] input[data-role=passphrase]').value`), PASS + '!', 'the field is not cleared while the dialog is open');
  await page.type('dialog[open] input[data-role=passphrase]', PASS);
  await pressButton('Decrypt and open');
  await waitNoDialog();
  await page.waitFor(`/was opened/.test(document.querySelector('#ub-project .ub-project-status').textContent)`, { what: 'the project to open' });
  assert.equal(await accounts(), 1);
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-account:nth-child(1) .ub-account-id input').value`), 'sensor-1');
  assert.equal(await slotText('tls.key'), keyBefore);
  assert.equal(await tomlExport(), tomlBefore, 'the project is the same as the one saved');
  assert.equal(await page.eval(`[...document.querySelectorAll('input[type=password]')].every(i => i.value === '')`), true, 'no passphrase is left in a field');
  assertClean(await everything(), 'the page after opening (storage and requests)', { ids: false });

  // A file with one changed byte, and a file that is not a project.
  const bad = JSON.parse(file);
  const raw = Buffer.from(bad.data, 'base64');
  raw[10] ^= 1;
  bad.data = raw.toString('base64');
  const badPath = join(tmp(), 'damaged.urmqtt-project');
  writeFileSync(badPath, JSON.stringify(bad));
  await page.click('#ub-project-open');
  await page.waitFor(`document.querySelector('dialog[open] input[type=file]')`);
  await page.setFiles('dialog[open] input[type=file]', [badPath]);
  await pressButton('Continue');
  await waitPassphraseDialog();
  await page.type('dialog[open] input[data-role=passphrase]', PASS);
  await pressButton('Decrypt and open');
  await page.waitFor(`document.querySelector('dialog[open] [data-role=error]:not([hidden])')`);
  assert.match(await dialogError(), /Wrong passphrase, or the file was changed/);
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await waitNoDialog();
  const notAProject = join(tmp(), 'other.json');
  writeFileSync(notAProject, '{"hello":1}');
  await page.click('#ub-project-open');
  await page.waitFor(`document.querySelector('dialog[open] input[type=file]')`);
  await page.setFiles('dialog[open] input[type=file]', [notAProject]);
  await pressButton('Continue');
  await page.waitFor(`/not a project file/.test(document.querySelector('#ub-project .ub-project-status').textContent)`, { what: 'the refusal' });
  assert.equal(await accounts(), 1, 'a refused file changes nothing');
  assert.deepEqual(page.consoleErrors.filter(m => !/favicon/.test(m)), []);
});

test('an encrypted copy in this browser: only ciphertext is stored, it survives a reload, it can be deleted', async () => {
  await fill();
  const tomlBefore = await tomlExport();
  await page.click('#ub-project-browser-keep');
  await waitPassphraseDialog();
  await page.type('dialog[open] input[data-role=passphrase]', PASS);
  await page.type('dialog[open] input[data-role=passphrase-again]', PASS);
  await pressButton('Encrypt and save');
  await waitNoDialog();
  await page.waitFor(`/encrypted copy is kept/.test(document.querySelector('#ub-project .ub-project-status').textContent)`, { what: 'the copy to be kept' });
  const stored = await page.eval(`localStorage.getItem('urmqtt-builder-vault-v1')`);
  assert.ok(stored && JSON.parse(stored).format === 'urmqtt-project');
  assertClean(stored, 'the browser copy');
  assertClean(await everything(), 'the page and its storage', { ids: false });

  // After a reload the secrets are gone, the copy is offered, and opens with the passphrase.
  await open('', { keep: true });
  assert.equal(await accounts(), 0);
  assert.equal(await page.eval(`document.querySelector('#ub-project-browser-open').hidden`), false);
  await page.click('#ub-project-browser-open');
  await waitPassphraseDialog();
  await page.type('dialog[open] input[data-role=passphrase]', PASS);
  await pressButton('Decrypt and open');
  await waitNoDialog();
  assert.equal(await accounts(), 1);
  assert.equal(await tomlExport(), tomlBefore);

  // Deleting asks first, then removes it.
  await page.click('#ub-project-browser-delete');
  await page.waitFor(`document.querySelector('dialog[open]')`);
  await pressButton('Cancel');
  await waitNoDialog();
  assert.ok(await page.eval(`localStorage.getItem('urmqtt-builder-vault-v1')`), 'Cancel keeps it');
  await page.click('#ub-project-browser-delete');
  await page.waitFor(`document.querySelector('dialog[open]')`);
  await pressButton('Delete browser copy');
  await waitNoDialog();
  assert.equal(await page.eval(`localStorage.getItem('urmqtt-builder-vault-v1')`), null);
  assert.equal(await page.eval(`document.querySelector('#ub-project-browser-open').hidden`), true);
});

test('the card is in the simple view too, and no request leaves the origin', async () => {
  await open('');
  assert.equal(await page.eval(`!!document.querySelector('#ub-project')`), true);
  await page.eval(`localStorage.setItem("urmqtt-builder-advanced", "0")`);
  await open('', { keep: true });
  assert.equal(await page.eval(`document.querySelector('#ub-project').offsetParent !== null`), true, 'shown in the simple view');
  const external = page.requests.filter(r => !r.url.startsWith(base));
  assert.deepEqual(external, [], 'no request leaves the origin');
});
