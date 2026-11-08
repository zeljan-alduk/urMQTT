// MQTT over WebSocket in the form's logic (ADR-272): its accounts as the same
// TOML tables as plaintext's, which fields exist when, and what stays out of the
// address bar. Against the real module, like plaintext.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, fieldForPath, importToml, isApplicable, isUserList,
} from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';
import { WASM, haveWasm } from './helpers.mjs';

if (!haveWasm()) {
  console.log(`skipped: needs ${WASM} (make builder)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const model = buildModel(b.schema());
const NOW = 1_900_000_000;
const pack = toml => b.pack({ toml, now: NOW });

const HASH1 = 'pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$4c5805526868c915a4cba43d75ec6b0a07152bb7b9ca30501c96ea0f91886829';

test('the section comes after plaintext, with an account editor and the two modes', () => {
  const ids = model.sections.map(s => s.id);
  assert.equal(ids.indexOf('websocket'), ids.indexOf('plaintext') + 1);
  const users = model.byId.get('websocket.users');
  assert.ok(isUserList(users));
  assert.deepEqual(model.byId.get('websocket.auth').variants, ['mtls', 'password']);
  assert.equal(model.byId.get('websocket.auth').default, 'mtls');
  assert.equal(fieldForPath(model, 'websocket.users[1].password_hash'), users);
  assert.equal(fieldForPath(model, 'websocket.origins[0]'), model.byId.get('websocket.origins'));
});

test('a password listener becomes the TOML the tool reads, and back', () => {
  const s = emptyState();
  Object.assign(s.values, {
    'websocket.enabled': true,
    'websocket.auth': 'password',
    'websocket.origins': ['https://app.example.com'],
    'websocket.users': [{ id: ' browser-1 ', hash: HASH1 }],
  });
  const { toml } = buildToml(model, s);
  assert.equal(toml, `[websocket]\nenabled = true\nauth = "password"\norigins = ["https://app.example.com"]\nusers = [{ id = "browser-1", password_hash = "${HASH1}" }]\n`);
  const r = pack(toml);
  assert.ok(r.ok, JSON.stringify(r));
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.deepEqual(back.state.values['websocket.users'], [{ id: 'browser-1', hash: HASH1 }]);
  assert.equal(buildToml(model, back.state).toml, toml);
  // Without origins the validator names the key.
  delete s.values['websocket.origins'];
  const bad = pack(buildToml(model, s).toml);
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.some(e => e.path === 'websocket.origins'), JSON.stringify(bad.errors));
});

test('websocket fields exist only while it is on; the password ones only with password logins', () => {
  const s = emptyState();
  const shown = () => model.fields.filter(x => x.section === 'websocket' && isApplicable(x, s)).map(x => x.id.slice(10));
  assert.deepEqual(shown(), ['enabled']);
  s.values['websocket.enabled'] = true;
  assert.deepEqual(shown(), ['enabled', 'port', 'path', 'auth', 'origins', 'upgrade_timeout_s', 'max_connections', 'max_connections_per_ip']);
  s.values['websocket.auth'] = 'password';
  assert.equal(shown().length, 16);
  // Leftovers of password mode are not written once it is mtls again.
  Object.assign(s.values, { 'websocket.auth': 'mtls', 'websocket.users': [{ id: 'a', hash: HASH1 }], 'websocket.lockout_s': '60' });
  assert.deepEqual(changedIds(model, s), ['websocket.enabled']);
  assert.equal(buildToml(model, s).toml, '[websocket]\nenabled = true\n');
  assert.ok(pack(buildToml(model, s).toml).ok);
});

test('the accounts never go to the address bar', () => {
  const s = emptyState();
  Object.assign(s.values, { 'websocket.enabled': true, 'websocket.auth': 'password', 'websocket.users': [{ id: 'a', hash: HASH1 }] });
  const hash = encodeHash(model, s);
  assert.ok(!hash.includes('pbkdf2') && !hash.includes('websocket.users'), hash);
  assert.equal(decodeHash(model, hash).values['websocket.users'], undefined);
});
