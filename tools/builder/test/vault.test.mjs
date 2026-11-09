// Encryption at rest (NOW-16, ADR-300): the envelope round trip, a wrong passphrase, every kind of tampering,
// hostile parameters, interoperability with an independent implementation (Node's crypto), and the snapshot
// of the page's state (what is sealed, what a hostile snapshot cannot do).
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { WASM, haveWasm } from './helpers.mjs';
import { buildModel, emptyState, isUserList } from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';
import {
  ENVELOPE_FORMAT, KDF_ITERATIONS, MIN_PASSPHRASE, VaultError, fromB64, hasSecrets, openValue, parseEnvelope, sealValue,
  snapshotState, stateFromSnapshot, toB64, withoutSecrets,
} from '../web/src/vault.js';

const PASS = 'correct horse battery staple';
const SECRET = { key: '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKE\n-----END PRIVATE KEY-----\n', n: 7, ü: 'čšž' };
const code = async p => { try { await p; } catch (e) { return e instanceof VaultError ? e.code : `other:${e}`; } return 'none'; };
const tamper = (text, fn) => { const e = JSON.parse(text); fn(e); return JSON.stringify(e); };
const flip = (b64, i) => { const b = fromB64(b64); b[i] ^= 1; return toB64(b); };

test('a sealed value opens with the passphrase and nothing else', async () => {
  const text = await sealValue(PASS, SECRET);
  assert.deepEqual(await openValue(PASS, text), SECRET);
  const e = JSON.parse(text);
  assert.equal(e.format, ENVELOPE_FORMAT);
  assert.equal(e.version, 1);
  assert.equal(e.kdf, 'PBKDF2-HMAC-SHA256');
  assert.equal(e.cipher, 'AES-256-GCM');
  assert.equal(e.iterations, KDF_ITERATIONS);
  assert.ok(KDF_ITERATIONS >= 600000);
  assert.equal(fromB64(e.salt).length, 16);
  assert.equal(fromB64(e.iv).length, 12);
  // Neither the secret (in any usual encoding) nor the passphrase is in the file.
  for (const needle of ['PRIVATE KEY', 'FAKEKEY', Buffer.from(SECRET.key).toString('base64').slice(0, 24), PASS, 'čšž']) assert.ok(!text.includes(needle), needle);
});

test('every seal uses a new salt and a new nonce, and the length hides small differences', async () => {
  const a = JSON.parse(await sealValue(PASS, { x: 1 }));
  const b = JSON.parse(await sealValue(PASS, { x: 1 }));
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.data, b.data);
  const c = JSON.parse(await sealValue(PASS, { x: 'a longer value than the other one, by far' }));
  assert.equal(fromB64(a.data).length, fromB64(c.data).length, 'both are padded to the same block');
});

test('a wrong passphrase, a missing one and a different spelling of it are refused the same way', async () => {
  const text = await sealValue(PASS, SECRET);
  assert.equal(await code(openValue(PASS + ' ', text)), 'auth');
  assert.equal(await code(openValue(PASS.toUpperCase(), text)), 'auth');
  assert.equal(await code(openValue('', text)), 'auth');
  assert.equal(await code(openValue(undefined, text)), 'auth');
});

test('the passphrase is normalised (NFKC): the same word typed with composed or decomposed characters opens it', async () => {
  const composed = 'Zażółć gęślą jaźń 12 ž';
  const text = await sealValue(composed, { ok: true });
  assert.deepEqual(await openValue(composed.normalize('NFD'), text), { ok: true });
  // Full-width letters are the same letters under NFKC.
  const ascii = await sealValue('passphrase-ascii-12', { ok: 2 });
  assert.deepEqual(await openValue('ｐａｓｓｐｈｒａｓｅ-ａｓｃｉｉ-12', ascii), { ok: 2 });
});

test('a short passphrase is not accepted for sealing', async () => {
  assert.equal(await code(sealValue('a'.repeat(MIN_PASSPHRASE - 1), {})), 'weak');
  assert.equal(await code(sealValue('', {})), 'weak');
  assert.equal(await code(sealValue(undefined, {})), 'weak');
  assert.equal(await code(sealValue('a'.repeat(MIN_PASSPHRASE), { ok: 1 })), 'none');
});

test('any change to the file is detected: data, nonce, salt, the round count, every bit position tried', async () => {
  const text = await sealValue(PASS, SECRET);
  const e = JSON.parse(text);
  const n = fromB64(e.data).length;
  for (const i of [0, 1, 100, n - 17, n - 16, n - 1]) {
    assert.equal(await code(openValue(PASS, tamper(text, x => { x.data = flip(x.data, i); }))), 'auth', `data byte ${i}`);
  }
  for (let i = 0; i < 12; i++) assert.equal(await code(openValue(PASS, tamper(text, x => { x.iv = flip(x.iv, i); }))), 'auth', `nonce byte ${i}`);
  for (let i = 0; i < 16; i++) assert.equal(await code(openValue(PASS, tamper(text, x => { x.salt = flip(x.salt, i); }))), 'auth', `salt byte ${i}`);
  // A changed round count is a different key AND a different header: refused either way.
  assert.equal(await code(openValue(PASS, tamper(text, x => { x.iterations += 1; }))), 'auth');
  // Truncation and extension of the ciphertext.
  assert.ok(['format', 'auth'].includes(await code(openValue(PASS, tamper(text, x => { x.data = toB64(fromB64(x.data).subarray(0, -4096)); })))));
  assert.equal(await code(openValue(PASS, tamper(text, x => { x.data = toB64(new Uint8Array([...fromB64(x.data), ...new Uint8Array(4096)])); }))), 'auth');
});

test('a file that is not an envelope of this version is refused before any key is derived', async () => {
  const text = await sealValue(PASS, SECRET);
  const bad = {
    'not JSON': 'hello',
    'JSON array': '[]',
    'another format': tamper(text, x => { x.format = 'other'; }),
    'a newer version': tamper(text, x => { x.version = 2; }),
    'another KDF': tamper(text, x => { x.kdf = 'scrypt'; }),
    'another cipher': tamper(text, x => { x.cipher = 'AES-128-GCM'; }),
    'one round': tamper(text, x => { x.iterations = 1; }),
    'a billion rounds': tamper(text, x => { x.iterations = 1e9; }),
    'rounds as text': tamper(text, x => { x.iterations = '600000'; }),
    'a field more': tamper(text, x => { x.extra = 1; }),
    'a field less': tamper(text, x => { delete x.iv; }),
    'short salt': tamper(text, x => { x.salt = toB64(new Uint8Array(8)); }),
    'short nonce': tamper(text, x => { x.iv = toB64(new Uint8Array(8)); }),
    'not base64': tamper(text, x => { x.data = '!!!!'; }),
    'data of one byte': tamper(text, x => { x.data = toB64(new Uint8Array(1)); }),
    'data not in blocks': tamper(text, x => { x.data = toB64(new Uint8Array(4096 + 16 + 1)); }),
  };
  for (const [what, file] of Object.entries(bad)) {
    const c = await code(openValue(PASS, file));
    assert.ok(['format', 'version', 'params'].includes(c), `${what}: ${c}`);
    assert.throws(() => parseEnvelope(file), VaultError, what);
  }
  assert.equal(await code(openValue(PASS, 'x'.repeat(20 * 1024 * 1024))), 'format');
});

test('interoperability: an envelope made by Node\'s crypto opens, and one made here opens with Node\'s crypto', async () => {
  const header = (iterations, salt) => Buffer.from(['urmqtt-project', 1, 'PBKDF2-HMAC-SHA256', iterations, 'AES-256-GCM', salt.toString('base64')].join('\n'));
  // Node -> page
  const salt = randomBytes(16), iv = randomBytes(12), iterations = 600000;
  const json = Buffer.from(JSON.stringify({ from: 'node' }));
  const plain = Buffer.concat([json, Buffer.alloc(4096 - json.length, 0x20)]);
  const key = pbkdf2Sync(Buffer.from(PASS.normalize('NFKC')), salt, iterations, 32, 'sha256');
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(header(iterations, salt));
  const data = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
  const file = JSON.stringify({ format: 'urmqtt-project', version: 1, kdf: 'PBKDF2-HMAC-SHA256', iterations, salt: salt.toString('base64'), cipher: 'AES-256-GCM', iv: iv.toString('base64'), data: data.toString('base64') });
  assert.deepEqual(await openValue(PASS, file), { from: 'node' });
  // page -> Node
  const e = JSON.parse(await sealValue(PASS, { from: 'page' }));
  const s = Buffer.from(e.salt, 'base64');
  const k2 = pbkdf2Sync(Buffer.from(PASS), s, e.iterations, 32, 'sha256');
  const raw = Buffer.from(e.data, 'base64');
  const d = createDecipheriv('aes-256-gcm', k2, Buffer.from(e.iv, 'base64'));
  d.setAAD(header(e.iterations, s));
  d.setAuthTag(raw.subarray(raw.length - 16));
  const out = Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString();
  assert.deepEqual(JSON.parse(out), { from: 'page' });
});

// --- the state that is sealed ------------------------------------------------------------------------------------

test('the snapshot of the state: what is sealed comes back, nothing hostile gets in', { skip: !haveWasm() && 'needs the module' }, async () => {
  const b = await loadBuilder(readFileSync(WASM));
  const model = buildModel(b.schema());
  const users = model.fields.find(f => f.id === 'plaintext.users');
  assert.ok(users, 'the schema has the accounts');
  const s = emptyState();
  s.values['network.mode'] = 'static';
  s.values[users.id] = [{ id: 'sensor-1', hash: 'pbkdf2-sha256$600000$00$11' }];
  s.files.cert = { pem: 'CERT', summary: 'c' };
  s.files.key = { pem: 'KEY', summary: 'k' };
  s.files.operational = [{ pem: 'CA', summary: 'ca' }];
  s.signing = { pem: 'SIGN', publicKey: 'ab', signerId: 'cd', summary: 's' };
  s.name = 'prod';
  assert.ok(hasSecrets(model, s));
  assert.ok(!hasSecrets(model, emptyState()));
  const text = await sealValue(PASS, snapshotState(s));
  const back = stateFromSnapshot(model, await openValue(PASS, text));
  assert.deepEqual(back, s);
  // Without secrets: the private key, the signing key and the accounts are gone, the rest stays.
  const bare = withoutSecrets(model, s);
  assert.equal(bare.files.key, null);
  assert.equal(bare.signing, null);
  assert.ok(!(users.id in bare.values));
  assert.equal(bare.files.cert.pem, 'CERT');
  assert.ok(!hasSecrets(model, bare));
  assert.ok(s.files.key, 'the live state is not changed');
  // Hostile content: unknown ids, wrong types, a snapshot of another version.
  const hostile = stateFromSnapshot(model, {
    snapshot: 1,
    state: {
      values: { 'no.such.field': 'x', 'network.mode': { a: 1 }, 'storage.diagnostic': true, [users.id]: [{ id: 5, hash: ['x'] }, null, 'x'], __proto__: { polluted: 1 } },
      files: { cert: { pem: 5, summary: 'x' }, key: 'KEY', operational: [{ pem: 'a', summary: 'b' }, 7, { pem: 'c' }], bootstrap: 'no' },
      signing: { pem: 'x' }, name: 'n'.repeat(100), preset: 7, release: ['v'],
    },
  });
  assert.equal(hostile.values['no.such.field'], undefined);
  assert.equal(hostile.values['network.mode'], undefined);
  assert.equal(hostile.values['storage.diagnostic'], true);
  assert.deepEqual(hostile.values[users.id], [{ id: '', hash: '' }]);
  assert.equal(hostile.files.cert, null);
  assert.equal(hostile.files.key, null);
  assert.deepEqual(hostile.files.operational, [{ pem: 'a', summary: 'b' }]);
  assert.deepEqual(hostile.files.bootstrap, []);
  assert.equal(hostile.signing, null);
  assert.equal(hostile.name, '');
  assert.equal(hostile.preset, '');
  assert.equal(hostile.release, '');
  assert.equal({}.polluted, undefined);
  // Typing rules of the address: a bool field refuses a string, a string field a bool, an enum a stranger.
  const bool = model.fields.find(f => f.type === 'bool' && !isUserList(f));
  const en = model.fields.find(f => f.type === 'enum');
  const str = model.fields.find(f => f.type === 'string');
  assert.ok(bool && en && str);
  const typed = stateFromSnapshot(model, { snapshot: 1, state: { values: { [bool.id]: 'yes', [en.id]: 'no-such-variant', [str.id]: true }, preset: 'nonsense' } });
  assert.equal(typed.values[bool.id], undefined);
  assert.equal(typed.values[en.id], undefined);
  assert.equal(typed.values[str.id], undefined);
  assert.equal(typed.preset, '');
  assert.equal(stateFromSnapshot(model, { snapshot: 1, state: { values: { [en.id]: en.variants[0] } } }).values[en.id], en.variants[0]);
  for (const bad of [null, 5, 'x', {}, { snapshot: 2, state: {} }, { snapshot: 1 }, { snapshot: 1, state: 5 }]) {
    assert.throws(() => stateFromSnapshot(model, bad), VaultError);
  }
});
