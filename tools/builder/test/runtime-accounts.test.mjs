// Run-time password accounts in the form's logic (NOW-15, ADR-285): the one
// limit of format 15 in [limits], what the TOML says, what the validator
// refuses, and when it is shown. Against the real module, like shared.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, importToml, isApplicable } from '../web/src/core.js';
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
const version = blob => blob[8] | (blob[9] << 8);
const ID = 'limits.max_runtime_accounts';
// A hash the packer accepts (the form's users table: id and hash).
const HASH = 'pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$4c5805526868c915a4cba43d75ec6b0a07152bb7b9ca30501c96ea0f91886829';
/** The plaintext listener in password mode, which is where an account can log in. */
const withPlaintext = s => Object.assign(s.values, {
  'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.users': [{ id: 'sensor-1', hash: HASH }],
});

test('the limit is in [limits], off by default, 0 to 1024, the only key of format 15', () => {
  assert.equal(model.formatVersion, 18);
  assert.ok(model.sections.find(s => s.id === 'limits').fields.some(f => f.id === ID));
  const f = model.byId.get(ID);
  assert.deepEqual([f.default, f.min, f.max, f.since], [0, 0, 1024, 15]);
  assert.deepEqual(model.fields.filter(x => x.since === 15).map(x => x.id), [ID]);
});

test('untouched or at 0 the configuration keeps its format; any other value needs 15', () => {
  const s = emptyState();
  s.values[ID] = '0';
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  for (const v of ['1', '1024']) {
    const st = emptyState();
    withPlaintext(st);
    st.values[ID] = v;
    assert.ok(changedIds(model, st).includes(ID));
    const r = pack(buildToml(model, st).toml);
    assert.ok(r.ok, `${v}: ${JSON.stringify(r)}`);
    assert.equal(version(r.blob), 15, v);
    assert.equal(r.blob.length > 0, true);
  }
});

test('the limit becomes the TOML the tool reads, and back', () => {
  const s = emptyState();
  withPlaintext(s);
  s.values[ID] = '32';
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[limits]\nmax_runtime_accounts = 32\n'), toml);
  assert.ok(pack(toml).ok);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  // The address keeps the limit (the password hashes are left out of it, by design).
  assert.equal(decodeHash(model, encodeHash(model, s)).values[ID], '32');
});

test('the validator names the key: 1025 is refused', () => {
  const s = emptyState();
  withPlaintext(s);
  s.values[ID] = '1025';
  const built = buildToml(model, s);
  const r = pack(built.toml);
  assert.ok(Object.keys(built.local).includes(ID) || (!r.ok && r.errors.some(e => e.path === ID)), JSON.stringify(r));
});

test('it is shown only where an account could log in: a password listener and the TLS listener', () => {
  const f = model.byId.get(ID);
  const s = emptyState();
  assert.equal(isApplicable(f, s), false, 'nothing takes passwords by default');
  s.values['plaintext.enabled'] = true;
  assert.equal(isApplicable(f, s), true, 'plaintext.auth defaults to password');
  s.values['plaintext.auth'] = 'anonymous';
  assert.equal(isApplicable(f, s), false);
  s.values['websocket.enabled'] = true;
  assert.equal(isApplicable(f, s), false, 'websocket.auth defaults to mtls');
  s.values['websocket.auth'] = 'password';
  assert.equal(isApplicable(f, s), true);
  // The TLS listener off: no control channel, so no account commands.
  s.values['network.mqtt_tls_port'] = '0';
  assert.equal(isApplicable(f, s), false);
});
