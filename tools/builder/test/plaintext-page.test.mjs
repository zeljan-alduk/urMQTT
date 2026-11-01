// The plaintext MQTT part of the page in a real (headless) Chrome (P1, ADR-229,
// ADR-230): the questions asked on the switches, the sections per mode, the
// accounts editor and what happens to a password, the reload, a build that is
// byte-identical to the command line tool's, keyboard operation, phone width
// and the dark theme. Skipped when there is no Chrome.
import assert from 'node:assert/strict';
import { createHash, pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { haveBrowser, launch } from './cdp.mjs';
import { prepareSite } from './fixture-site.mjs';
import { serve } from './serve.mjs';
import { FIXTURES, cli, haveCli, haveWasm, tmp } from './helpers.mjs';

if (!haveBrowser() || !haveWasm() || !haveCli()) {
  console.log('skipped: needs a Chrome (CHROME=/path), Node 22, build/builder (make builder) and the urmqtt-config binary');
  process.exit(0);
}

let site, server, browser, page, base;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const field = id => `.ub-field[data-id="${id}"]`;
const ENABLED = `${field('plaintext.enabled')} input[type=checkbox]`;
const ANYWHERE = `${field('plaintext.allow_from_anywhere')} input[type=checkbox]`;
const USERS = field('plaintext.users');
const row = i => `${USERS} .ub-account:nth-child(${i})`;
const idInput = i => `${row(i)} .ub-account-id input`;
const pwInput = i => `${row(i)} .ub-pw-edit input`;
const toHash = values => '#s=' + Buffer.from(JSON.stringify({ v: values })).toString('base64url');
const SAFE = { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'] };

/** A fresh page: empty storage, then the address given (a real load, so that the hash is read again). */
async function open(hash = '') {
  await page.goto(base + '/#');
  await page.eval('sessionStorage.clear(); localStorage.clear()');
  await page.goto('about:blank');
  await page.goto(base + '/' + hash);
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`, { what: 'the releases to load' });
}

const dialogText = () => page.eval(`(document.querySelector('dialog[open]') || {}).textContent || ''`);
const dialogOpen = () => page.eval(`!!document.querySelector('dialog[open]')`);
const waitDialog = () => page.waitFor(`document.querySelector('dialog[open]')`, { what: 'a dialog' });
// (A closed dialog stays in the page until its close event ran; what the question decided is done by then.)
const waitNoDialog = () => page.waitFor(`!document.querySelector('dialog')`, { what: 'the dialog to close' });
const pressButton = text => page.eval(`[...document.querySelectorAll('dialog[open] footer .ub-btn')].find(b => b.textContent === ${JSON.stringify(text)}).click()`);
const checked = sel => page.eval(`document.querySelector(${JSON.stringify(sel)}).checked`);
const hidden = id => page.eval(`document.querySelector('${field(id)}').hidden`);
const openSection = () => page.eval(`document.querySelector('#sec-plaintext').open = true`);

async function tomlExport() {
  await page.click('#ub-toml');
  await waitDialog();
  const text = await page.eval(`document.querySelector('dialog[open] pre').textContent`);
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);
  await waitNoDialog();
  return text;
}

/** Sets a password the way a person does: type it, leave the field. */
async function typePassword(i, text) {
  await page.type(pwInput(i), text);
  await page.eval(`document.activeElement.blur()`);
}

/** Everything a page keeps or sends, as text, to look for a secret in. */
async function everything() {
  const dump = await page.eval(`JSON.stringify({
    hash: location.hash,
    decoded: location.hash.startsWith('#s=') ? atob(location.hash.slice(3).replace(/-/g, '+').replace(/_/g, '/')) : '',
    session: Object.fromEntries(Object.entries(sessionStorage)),
    local: Object.fromEntries(Object.entries(localStorage)),
    html: document.documentElement.outerHTML,
    text: document.body.innerText,
    values: [...document.querySelectorAll('input, textarea')].map(e => e.value),
  })`);
  return dump + JSON.stringify(page.requests) + JSON.stringify(page.consoleAll);
}

function assertNoSecret(haystack, secret, what = '') {
  const needles = [secret, encodeURIComponent(secret), Buffer.from(secret).toString('base64'), Buffer.from(secret).toString('base64url'), Buffer.from(secret).toString('hex')];
  for (const n of needles) assert.ok(!haystack.includes(n), `the clear password is in ${what || 'the page'} (${n.slice(0, 6)}...)`);
}

/** WCAG contrast of an element's text colour against the first opaque background above it. */
async function contrast(selector) {
  return page.eval(`(() => {
    const parse = s => {
      let m = /rgba?\\(([^)]+)\\)/.exec(s);
      if (m) { const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { c: p.slice(0, 3), a: p.length > 3 ? p[3] : 1 }; }
      m = /color\\(srgb ([^)]+)\\)/.exec(s);
      if (m) { const p = m[1].split(/[ \\/]+/).filter(Boolean).map(Number); return { c: p.slice(0, 3).map(x => x * 255), a: p.length > 3 ? p[3] : 1 }; }
      return { c: [0, 0, 0], a: 0 };
    };
    const lum = ([r, g, b]) => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
    const el = document.querySelector(${JSON.stringify(selector)});
    const fg = parse(getComputedStyle(el).color);
    // Blend the backgrounds from the page up to the element.
    const chain = [];
    for (let e = el; e; e = e.parentElement) chain.push(parse(getComputedStyle(e).backgroundColor));
    let bg = [255, 255, 255];
    for (const layer of chain.reverse()) bg = bg.map((v, i) => layer.c[i] * layer.a + v * (1 - layer.a));
    const a = lum(fg.c) + 0.05, b = lum(bg) + 0.05;
    return Math.max(a, b) / Math.min(a, b);
  })()`);
}

before(async () => {
  site = await prepareSite({
    releases: small => [{ tag: 'v0.4.0', published: '2026-11-05T09:00:00Z', template: small }],
  });
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

test('the section is collapsed and off; switching it on asks first, Cancel keeps it off, confirming shows its fields', async () => {
  await open();
  assert.equal(await page.eval(`document.querySelector('#sec-plaintext').open`), false, 'collapsed by default');
  await openSection();
  assert.equal(await checked(ENABLED), false);
  const others = await page.eval(`[...document.querySelectorAll('.ub-field[data-id^="plaintext."]')].filter(f => f.dataset.id !== 'plaintext.enabled').map(f => f.hidden)`);
  assert.equal(others.length, 16, 'the other sixteen fields are in the form');
  assert.ok(others.every(Boolean), 'and all hidden while it is off');
  assert.equal(await page.eval(`document.querySelector('#ub-plain-banner').hidden`), true);

  await page.click(ENABLED);
  await waitDialog();
  const text = await dialogText();
  assert.match(text, /Switch on plaintext MQTT\?/);
  assert.match(text, /Nothing is encrypted/);
  assert.match(text, /Anyone on the network path can read and change/);
  assert.match(text, /known only by its password or its address/);
  assert.match(text, /only on a network you control/);
  assert.match(text, /allow_from, for example 10\.0\.0\.0\/8/, 'says what will be required');
  assert.equal(await checked(ENABLED), false, 'the switch stays off behind the question');
  await pressButton('Cancel');
  await waitNoDialog();
  assert.equal(await checked(ENABLED), false, 'Cancel leaves it off');
  const hashNow = await page.eval('location.hash');
  assert.ok(!Buffer.from(hashNow.slice(3), 'base64url').toString().includes('plaintext'), 'nothing was written');
  assert.equal(await hidden('plaintext.port'), true);

  await page.click(ENABLED);
  await waitDialog();
  await pressButton('I understand, switch it on');
  await waitNoDialog();
  assert.equal(await checked(ENABLED), true);
  for (const id of ['plaintext.port', 'plaintext.allow_from', 'plaintext.allow_from_anywhere', 'plaintext.auth', 'plaintext.users', 'plaintext.max_connections', 'plaintext.acl_publish', 'plaintext.retain']) {
    assert.equal(await hidden(id), false, `${id} is shown`);
  }
  assert.equal(await hidden('plaintext.anonymous_identity'), true, 'only for anonymous');
  assert.equal(await hidden('plaintext.ip_identities'), true, 'only for ip');
  assert.match(await page.eval(`document.querySelector('#ub-plain-banner').textContent`), /Not encrypted\. Anyone on the network path/);
  assert.equal(await page.eval(`document.querySelector('#ub-plain-banner').classList.contains('err')`), false);
  assert.match(await page.eval(`document.querySelector('#sec-plaintext summary .ub-badge').textContent`), /1/);
  // The section is checked: without allow_from and an account the validator says so, at the fields.
  await page.waitFor(`!document.querySelector('${field('plaintext.allow_from')} .ub-error').hidden`, { what: 'the allow_from error' });
  await page.waitFor(`!document.querySelector('${USERS} > .ub-error').hidden`, { what: 'the accounts error' });
});

test('the authentication choice: three radios with their explanations, each mode shows its own fields', async () => {
  await open(toHash(SAFE));
  await openSection();
  const radios = await page.eval(`[...document.querySelectorAll('${field('plaintext.auth')} input[type=radio]')].map(r => r.value + ' | ' + r.closest('label').textContent)`);
  assert.deepEqual(radios.map(r => r.split(' | ')[0]), ['password', 'anonymous', 'ip']);
  assert.match(radios[0], /a user name and password per client/);
  assert.match(radios[1], /no login; all clients share one identity/);
  assert.match(radios[2], /the client's address decides who it is/);
  await page.click(`${field('plaintext.auth')} input[value="anonymous"]`);
  assert.equal(await hidden('plaintext.users'), true);
  assert.equal(await hidden('plaintext.anonymous_identity'), false);
  assert.equal(await hidden('plaintext.ip_identities'), true);
  await page.click(`${field('plaintext.auth')} input[value="ip"]`);
  assert.equal(await hidden('plaintext.ip_identities'), false);
  assert.equal(await hidden('plaintext.anonymous_identity'), true);
  assert.equal(await page.eval(`document.querySelector('${field('plaintext.ip_identities')} textarea').placeholder`), '10.0.1.0/24 plc');
  assert.equal(await page.eval(`document.querySelector('${field('plaintext.allow_from')} textarea').placeholder`), '10.0.0.0/8');
  assert.match(await page.eval(`document.querySelector('${field('plaintext.ip_identities')}').textContent`), /One entry per line: a network, a space, then the identity/);
  // Networks with identities, typed one per line, are written as tables.
  await page.type(`${field('plaintext.ip_identities')} textarea`, '10.0.1.0/24 plc\n10.0.2.0/24 line-2');
  const toml = await tomlExport();
  assert.match(toml, /ip_identities = \[\{ from = "10\.0\.1\.0\/24", id = "plc" \}, \{ from = "10\.0\.2\.0\/24", id = "line-2" \}\]/);
  assert.match(toml, /auth = "ip"/);
  // A hidden field's text does not reach the validator: back to password mode, no ip_identities in the export.
  await page.click(`${field('plaintext.auth')} input[value="password"]`);
  assert.ok(!(await tomlExport()).includes('ip_identities'));
});

test('allow_from_anywhere asks a second, stronger question; nothing asks when the state comes from the address or a TOML', async () => {
  await open(toHash(SAFE));
  await openSection();
  assert.equal(await dialogOpen(), false, 'a state restored from the address asks nothing');
  assert.equal(await checked(ENABLED), true);
  await page.click(ANYWHERE);
  await waitDialog();
  const text = await dialogText();
  assert.match(text, /Accept connections from anywhere\?/);
  assert.match(text, /Never use this on a machine with a public address/);
  assert.match(text, /loud warning at every boot/);
  await pressButton('Cancel');
  await waitNoDialog();
  assert.equal(await checked(ANYWHERE), false, 'Cancel leaves it off');
  assert.equal(await page.eval(`document.querySelector('#ub-plain-banner').classList.contains('err')`), false);
  await page.click(ANYWHERE);
  await waitDialog();
  assert.equal(await page.eval(`document.querySelector('dialog[open] footer .ub-btn.danger').textContent`), 'I understand, accept from anywhere');
  await pressButton('I understand, accept from anywhere');
  await waitNoDialog();
  assert.equal(await checked(ANYWHERE), true);
  assert.equal(await page.eval(`document.querySelector('#ub-plain-banner').classList.contains('err')`), true, 'the banner turns red');
  assert.match(await page.eval(`document.querySelector('#ub-plain-banner').textContent`), /Danger: connections are accepted from every address/);

  // A TOML with both switches on is applied without a question.
  await open();
  await page.click('#ub-toml');
  await waitDialog();
  await page.type('dialog[open] textarea[aria-label="Paste a TOML"]', '[plaintext]\nenabled = true\nallow_from_anywhere = true\nauth = "anonymous"\n');
  await page.waitFor(`document.querySelector('dialog[open]').textContent.includes('Settings found: 3')`);
  await pressButton('Apply');
  await waitNoDialog();
  assert.equal(await dialogOpen(), false);
  assert.equal(await checked(ENABLED), true);
  assert.equal(await checked(ANYWHERE), true);
  // The build asks again, once, for what it is.
  await page.click('#ub-build');
  await waitDialog();
  const risks = await dialogText();
  assert.match(risks, /Plaintext MQTT is on/);
  assert.match(risks, /Plaintext MQTT accepts every address/);
  await pressButton('Go back');
  await waitNoDialog();
});

test('an account: id, password typed and left, stored as a hash only, and the clear password is nowhere', async () => {
  await open(toHash(SAFE));
  await openSection();
  assert.equal(await page.eval(`document.querySelectorAll('${USERS} .ub-account').length`), 0);
  await page.click(`${USERS} .ub-add-account`);
  assert.equal(await page.eval(`document.querySelectorAll('${USERS} .ub-account').length`), 1);
  assert.equal(await page.eval(`document.activeElement === document.querySelector('${idInput(1)}')`), true, 'the new row takes the focus');
  assert.equal(await page.eval(`document.querySelector('${idInput(1)}').placeholder`), 'sensor-1');
  const pwType = await page.eval(`document.querySelector('${pwInput(1)}').type + '|' + document.querySelector('${pwInput(1)}').autocomplete`);
  assert.equal(pwType, 'password|new-password');

  await page.type(idInput(1), 'sensor-1');
  // A row with an id and no password is a problem that blocks the build, at the row.
  await page.waitFor(`document.querySelector('${row(1)} .ub-error:not([hidden])')`, { what: 'the row error' });
  assert.equal(await page.eval(`document.querySelector('${row(1)} .ub-error').textContent`), 'Enter a password.');
  assert.match(await page.eval(`document.querySelector('.ub-bar-status').textContent`), /Problems to fix/);
  await page.click('#ub-build');
  assert.equal(await dialogOpen(), false, 'Build does not ask anything');
  assert.equal(await page.eval(`document.querySelector('.ub-progress').hidden`), true, 'and does not start');
  assert.equal(await page.eval(`document.activeElement === document.querySelector('${idInput(1)}')`), true, 'and takes you to the row');

  const secret = 'Tr0ub4dor-and-3-horses';
  await page.type(pwInput(1), secret);
  // While it is typed it exists in the input only.
  assertNoSecret(await everything().then(s => s.replace(/"values":\[[^\]]*\]/, '"values":[]')), secret, 'the page while it is typed');
  await page.eval(`document.activeElement.blur()`);
  await page.waitFor(`document.querySelector('${row(1)} .ub-pw-done:not([hidden])')`, { what: 'the password to be set' });
  assert.match(await page.eval(`document.querySelector('${row(1)} .ub-pw-set').textContent`), /Password set, stored as a PBKDF2-SHA-256 hash\. It cannot be shown again\./);
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').value`), '', 'the input is emptied');
  assert.equal(await page.eval(`document.querySelector('${row(1)} .ub-pw-edit').hidden`), true);
  assert.equal(await page.eval(`document.querySelector('${row(1)} .ub-pw-done button').textContent`), 'Change password');
  assert.equal(await page.eval(`document.querySelector('.ub-sr[role=status][aria-live=polite]') !== null`), true, 'a live region announces it');
  await page.waitFor(`!document.querySelector('${row(1)} .ub-error') || document.querySelector('${row(1)} .ub-error').hidden`);
  await page.waitFor(`document.querySelector('${USERS} > .ub-error').hidden`, { what: 'the accounts error to clear' });

  const toml = await tomlExport();
  const m = /users = \[\{ id = "sensor-1", password_hash = "(pbkdf2-sha256\$10000\$([0-9a-f]{32})\$([0-9a-f]{64}))" \}\]/.exec(toml);
  assert.ok(m, toml);
  assert.equal(pbkdf2Sync(secret, Buffer.from(m[2], 'hex'), 10000, 32, 'sha256').toString('hex'), m[3], 'the hash is the PBKDF2 of the password');
  assertNoSecret(toml + await everything(), secret);
  // The hash itself is not in the address or the storage either: memory only.
  const kept = await page.eval(`JSON.stringify([location.hash, atob(location.hash.slice(3).replace(/-/g, '+').replace(/_/g, '/')), Object.entries(sessionStorage), Object.entries(localStorage)])`);
  assert.ok(!kept.includes(m[3]) && !kept.includes('sensor-1') && !kept.includes('pbkdf2'), kept);
  // Every request the page made was a GET of its own site, without a body.
  for (const r of page.requests) { assert.equal(r.method, 'GET', r.url); assert.equal(r.body, ''); assert.ok(r.url.startsWith(base) || r.url.startsWith('blob:') || r.url.startsWith('data:'), r.url); }

  // Changing the id keeps the hash.
  await page.type(idInput(1), 'sensor-9');
  assert.match(await tomlExport(), new RegExp(`id = "sensor-9", password_hash = "${m[1].replace(/\$/g, '\\$')}"`));
  // Change password: a new hash for the same row; Cancel keeps the old one.
  await page.click(`${row(1)} .ub-pw-done button`);
  assert.equal(await page.eval(`document.activeElement === document.querySelector('${pwInput(1)}')`), true);
  await page.click(`${row(1)} .ub-pw-edit .ub-link-btn`);
  assert.match(await tomlExport(), new RegExp(m[1].replace(/\$/g, '\\$')));
  await page.click(`${row(1)} .ub-pw-done button`);
  await typePassword(1, 'another one');
  await page.waitFor(`document.querySelector('${row(1)} .ub-pw-done:not([hidden])')`);
  const t2 = await tomlExport();
  assert.ok(!t2.includes(m[3]) && /password_hash = "pbkdf2-sha256\$10000\$/.test(t2), 'a new hash');
  // A row is removed, and a second one added; ids are checked by the validator while typed.
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(2), 'bad id');
  await page.waitFor(`document.querySelector('${row(2)} .ub-error:not([hidden])')`);
  assert.ok((await page.eval(`document.querySelector('${row(2)} .ub-error').textContent`)).length > 5, 'the validator\'s own words at the row');
  await page.click(`${row(2)} .ub-account-remove`);
  assert.equal(await page.eval(`document.querySelectorAll('${USERS} .ub-account').length`), 1);
});

test('a generated password: 20 characters, shown or hidden, copied, then hashed', async () => {
  await open(toHash(SAFE));
  await openSection();
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(1), 'gen-1');
  const buttons = await page.eval(`[...document.querySelectorAll('${row(1)} .ub-pw-edit button')].map(b => b.textContent)`);
  assert.deepEqual(buttons, ['Generate', 'Show', 'Copy', 'Set password', 'Cancel']);
  await page.click(`${row(1)} .ub-pw-edit button:nth-of-type(1)`); // Generate
  const pw = await page.eval(`document.querySelector('${pwInput(1)}').value`);
  assert.match(pw, /^[A-Za-z0-9]{20}$/);
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').type`), 'text', 'a generated password is shown, to be copied');
  assert.match(await page.eval(`document.querySelector('${row(1)} .ub-pw-edit .ub-help').textContent`), /Copy it now: after you set it, it cannot be shown again/);
  // Hide and show.
  await page.click(`${row(1)} .ub-pw-edit button:nth-of-type(2)`);
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').type`), 'password');
  assert.equal(await page.eval(`document.querySelector('${row(1)} .ub-pw-edit button:nth-of-type(2)').textContent`), 'Show');
  await page.click(`${row(1)} .ub-pw-edit button:nth-of-type(2)`);
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').type`), 'text');
  // Copy: the page says whether it worked (a headless browser may refuse the clipboard).
  await page.click(`${row(1)} .ub-pw-edit button:nth-of-type(3)`);
  await page.waitFor(`/^(Copied|Copy failed)$/.test(document.querySelector('${row(1)} .ub-pw-edit button:nth-of-type(3)').textContent)`, { what: 'the copy message' });
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').value`), pw, 'still there to be copied');
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-sr[role=status]').getAttribute('aria-live')`), 'polite');
  // Nothing is stored before it is set.
  assertNoSecret((await everything()).replace(/"values":\[[^\]]*\]/, '"values":[]'), pw, 'the page before it is set');
  // Set it with the button.
  await page.click(`${row(1)} .ub-pw-edit button:nth-of-type(4)`);
  await page.waitFor(`document.querySelector('${row(1)} .ub-pw-done:not([hidden])')`);
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').value`), '');
  assert.equal(await page.eval(`document.querySelector('${pwInput(1)}').type`), 'password');
  const toml = await tomlExport();
  const m = /gen-1", password_hash = "pbkdf2-sha256\$10000\$([0-9a-f]{32})\$([0-9a-f]{64})"/.exec(toml);
  assert.ok(m, toml);
  assert.equal(pbkdf2Sync(pw, Buffer.from(m[1], 'hex'), 10000, 32, 'sha256').toString('hex'), m[2]);
  assertNoSecret(toml + await everything(), pw);
  // Two accounts with the same password get different hashes (a salt each).
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(2), 'gen-2');
  await page.type(pwInput(2), pw);
  await page.eval('document.activeElement.blur()');
  await page.waitFor(`document.querySelector('${row(2)} .ub-pw-done:not([hidden])')`);
  const hashes = [...(await tomlExport()).matchAll(/password_hash = "([^"]+)"/g)].map(x => x[1]);
  assert.equal(hashes.length, 2);
  assert.notEqual(hashes[0].split('$')[2], hashes[1].split('$')[2], 'another salt');
  assert.notEqual(hashes[0], hashes[1]);
});

test('after a reload the accounts are gone and the page says so; the rest of the section stays', async () => {
  await open(toHash(SAFE));
  await openSection();
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(1), 'sensor-1');
  await typePassword(1, 'secret-for-reload');
  await page.waitFor(`document.querySelector('${row(1)} .ub-pw-done:not([hidden])')`);
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-warn').hidden`), true, 'no note while there are accounts');
  const session = await page.eval(`JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))`);
  assert.ok(!session.includes('sensor-1') && !session.includes('pbkdf2') && !session.includes('secret-for-reload'), session);
  await page.goto('about:blank');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  assert.equal(await checked(ENABLED), true, 'the switch survived (it is in the address)');
  assert.equal(await page.eval(`document.querySelectorAll('${USERS} .ub-account').length`), 0, 'the accounts did not');
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-warn').hidden`), false);
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-warn').textContent`), 'The accounts are not kept across a reload: add them again.');
  // The note stays through a second reload, and goes when an account is added.
  await page.goto('about:blank');
  await page.goto(base + '/');
  await page.waitFor(`document.documentElement.dataset.ubReleases === '1'`);
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-warn').hidden`), false);
  await page.eval(`document.querySelector('#sec-plaintext').open = true`);
  await page.click(`${USERS} .ub-add-account`);
  assert.equal(await page.eval(`document.querySelector('${USERS} .ub-warn').hidden`), true);
});

test('a TOML with accounts fills the rows with their hashes; the build equals the command line tool\'s image byte for byte', async () => {
  const fixture = readFileSync(join(FIXTURES, 'plain.toml'), 'utf8');
  await open();
  await page.click('#ub-toml');
  await waitDialog();
  await page.type('dialog[open] textarea[aria-label="Paste a TOML"]', fixture);
  await page.waitFor(`/Settings found: \\d+/.test(document.querySelector('dialog[open]').textContent)`);
  assert.ok(!/Not understood/.test(await dialogText()), 'every key is known');
  await pressButton('Apply');
  await waitNoDialog();
  assert.equal(await dialogOpen(), false, 'no question for an import');
  await openSection();
  assert.equal(await page.eval(`document.querySelectorAll('${USERS} .ub-account').length`), 2);
  assert.deepEqual(await page.eval(`[...document.querySelectorAll('${USERS} .ub-account-id input')].map(i => i.value)`), ['sensor-1', 'sensor-2']);
  assert.equal(await page.eval(`[...document.querySelectorAll('${USERS} .ub-pw-done')].every(d => !d.hidden)`), true, 'no password needed: the hashes are there');
  await page.waitFor(`document.querySelector('.ub-bar-status').classList.contains('ok')`, { what: 'a valid configuration' });
  // The export is the same configuration (the tool reads it to the same blob).
  const exported = await tomlExport();
  assert.match(exported, /password_hash = "pbkdf2-sha256\$1000\$00112233445566778899aabbccddeeff\$4c5805526868/);

  await page.click('#ub-build');
  await waitDialog();
  const risks = await dialogText();
  assert.match(risks, /Plaintext MQTT is on/);
  assert.match(risks, /The machine has a public address/, '192.0.2.10 is not a private address');
  assert.match(risks, /The address 192\.0\.2\.10 is not a private one/);
  await pressButton('Build anyway');
  try {
    await page.waitFor(`document.querySelector('#ub-download').getAttribute('aria-disabled') === 'false'`, { what: 'the ISO', timeout: 60000 });
  } catch (e) {
    throw new Error(`${e.message}: ${await dialogText()} ${JSON.stringify(page.consoleErrors)}`);
  }
  const dl = tmp('urmqtt-download-');
  const name = await page.download('#ub-download', dl);
  const built = readFileSync(join(dl, name));
  await page.eval(`document.querySelectorAll('dialog[open]').forEach(d => d.close(''))`);

  // The tool, given the exported TOML and the fixture itself.
  const tpl = join(site.mirrorDir, 'v0.4.0', 'urmqtt-template-v0.4.0-universal.iso');
  const dir = tmp();
  for (const [label, text] of [['exported', exported], ['fixture', fixture]]) {
    writeFileSync(join(dir, `${label}.toml`), text);
    const out = join(dir, `${label}.iso`);
    const c = cli(['pack', join(dir, `${label}.toml`), '--iso', tpl, '--out', out]);
    assert.equal(c.status, 0, c.stderr);
    assert.equal(sha(readFileSync(out)), sha(built), `the page and the tool write the same image (${label})`);
  }
  assert.equal(cli(['verify', join(dir, 'fixture.iso')]).status, 0);
});

test('keyboard: the switch is a checkbox, the question traps the focus and Escape cancels, the editor is in reading order', async () => {
  await open();
  await openSection();
  await page.eval(`document.querySelector('${ENABLED}').focus()`);
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space', text: ' ', windowsVirtualKeyCode: 32 });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space', windowsVirtualKeyCode: 32 });
  await waitDialog();
  for (let i = 0; i < 12; i++) {
    await page.key('Tab', { code: 'Tab', vk: 9 });
    assert.equal(await page.eval(`document.activeElement === document.body || !!document.activeElement.closest('dialog[open]')`), true, `focus reached the page behind the question after ${i + 1} Tab presses`);
  }
  assert.equal(await page.eval(`document.getElementById(document.querySelector('dialog[open]').getAttribute('aria-labelledby')).textContent`), 'Switch on plaintext MQTT?');
  await page.key('Escape', { code: 'Escape', vk: 27 });
  await waitNoDialog();
  assert.equal(await checked(ENABLED), false, 'Escape is Cancel');
  assert.equal(await page.eval(`document.activeElement === document.querySelector('${ENABLED}')`), true, 'the focus returns to the switch');

  // The stronger question, too.
  await open(toHash(SAFE));
  await openSection();
  await page.eval(`document.querySelector('${ANYWHERE}').focus()`);
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space', text: ' ', windowsVirtualKeyCode: 32 });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space', windowsVirtualKeyCode: 32 });
  await waitDialog();
  await page.key('Escape', { code: 'Escape', vk: 27 });
  await waitNoDialog();
  assert.equal(await checked(ANYWHERE), false);
  assert.equal(await page.eval(`document.activeElement === document.querySelector('${ANYWHERE}')`), true);

  // The editor: id, password, then the buttons, then Remove; Enter in the password field sets it.
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(1), 'kbd-1');
  const order = [];
  for (let i = 0; i < 7; i++) {
    await page.key('Tab', { code: 'Tab', vk: 9 });
    order.push(await page.eval(`(e => e.getAttribute('aria-label') || e.textContent)(document.activeElement)`));
  }
  assert.deepEqual(order.slice(0, 6), ['Password', 'Generate', 'Show', 'Copy', 'Set password', 'Remove']);
  await page.eval(`document.querySelector('${pwInput(1)}').focus()`);
  await page.send('Input.insertText', { text: 'enter-sets-it' });
  await page.key('Enter', { code: 'Enter', vk: 13 });
  await page.waitFor(`document.querySelector('${row(1)} .ub-pw-done:not([hidden])')`, { what: 'Enter to set the password' });
  assert.equal(await page.eval(`document.activeElement.textContent`), 'Change password', 'the focus moves to what replaced the field');
  // Fields have labels and descriptions.
  const label = await page.eval(`(() => { const i = document.querySelector('${idInput(1)}'); return i.getAttribute('aria-label') + '|' + !!document.getElementById(i.getAttribute('aria-describedby').split(' ')[0]); })()`);
  assert.equal(label, 'Account id|true');
});

test('phone width: no sideways scrolling with the section open; both themes keep the warnings readable', async () => {
  await open(toHash({ ...SAFE, 'plaintext.allow_from_anywhere': true }));
  await openSection();
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(1), 'phone-1');
  await page.click(`${USERS} .ub-add-account`);
  await page.type(idInput(2), 'phone-2');
  await typePassword(2, 'x');
  await page.viewport(375, 800, { mobile: true, scale: 2 });
  await page.eval('window.scrollTo(0, 0)');
  await page.eval(`document.querySelector('#sec-plaintext').scrollIntoView()`);
  const overflow = await page.eval(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  assert.ok(overflow <= 1, `horizontal overflow of ${overflow}px`);
  const wide = await page.eval(`[...document.querySelectorAll('#sec-plaintext *')].filter(e => e.offsetParent && e.getBoundingClientRect().right > document.documentElement.clientWidth + 1).map(e => e.className || e.tagName)`);
  assert.deepEqual(wide, [], 'nothing of the section sticks out');
  await page.viewport(1280, 900);
  for (const scheme of ['light', 'dark']) {
    await page.media({ scheme });
    await page.eval('0');
    for (const sel of ['#ub-plain-banner .ub-strong', '#ub-plain-banner .ub-help', `${row(2)} .ub-pw-set`, `${row(1)} .ub-error`]) {
      const c = await contrast(sel);
      assert.ok(c >= 4.5, `${scheme}: ${sel} has contrast ${c.toFixed(2)}`);
    }
  }
  await page.media({});
});
