// MQTT 5.0 in the form's logic (ADR-273 rule 21): the [mqtt5] section and the
// expiry limits of format 12, which fields exist when, what the TOML says and
// what the validator refuses. Against the real module, like websocket.test.mjs.
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

test('the section comes after websocket with the documented defaults; the expiry limits are in [limits]', () => {
  assert.equal(model.formatVersion, 18);
  const ids = model.sections.map(s => s.id);
  assert.equal(ids.indexOf('mqtt5'), ids.indexOf('websocket') + 1);
  const mqtt5 = model.sections.find(s => s.id === 'mqtt5').fields.map(f => [f.name, f.default]);
  assert.deepEqual(mqtt5, [
    ['enabled', true], ['receive_maximum', 32], ['topic_alias_maximum', 10], ['max_user_properties', 16],
    ['max_keep_alive_s', 0], ['shared_subscriptions', true], ['subscription_identifiers', true],
  ]);
  const limits = model.sections.find(s => s.id === 'limits').fields.map(f => f.name);
  for (const n of ['max_session_expiry_s', 'default_session_expiry_s', 'max_message_expiry_s']) assert.ok(limits.includes(n), n);
  assert.equal(model.byId.get('limits.max_session_expiry_s').max, 4294967295);
  assert.equal(model.byId.get('limits.max_session_expiry_s').default, 2592000);
  assert.equal(model.byId.get('mqtt5.receive_maximum').min, 1);
  for (const f of model.fields.filter(x => x.since === 12)) assert.ok(f.section === 'mqtt5' || f.section === 'limits', f.id);
  assert.equal(model.fields.filter(x => x.since === 12).length, 10);
});

test('untouched, the configuration keeps its format; any key set needs 12', () => {
  const s = emptyState();
  assert.equal(buildToml(model, s).toml, '');
  assert.equal(version(pack('').blob), 2);
  for (const [id, v] of [
    ['mqtt5.enabled', false], ['mqtt5.receive_maximum', '8'], ['mqtt5.topic_alias_maximum', '0'],
    ['mqtt5.max_user_properties', '1024'], ['mqtt5.max_keep_alive_s', '300'],
    ['mqtt5.shared_subscriptions', false], ['mqtt5.subscription_identifiers', false],
    ['limits.max_session_expiry_s', '4294967295'], ['limits.default_session_expiry_s', '3600'],
    ['limits.max_message_expiry_s', '600'],
  ]) {
    const st = emptyState();
    st.values[id] = v;
    assert.deepEqual(changedIds(model, st), [id]);
    const r = pack(buildToml(model, st).toml);
    assert.ok(r.ok, `${id}: ${JSON.stringify(r)}`);
    assert.equal(version(r.blob), 12, id);
  }
});

test('a tuned section becomes the TOML the tool reads, and back', () => {
  const s = emptyState();
  Object.assign(s.values, {
    'mqtt5.receive_maximum': '8',
    'mqtt5.max_keep_alive_s': '300',
    'limits.max_session_expiry_s': '86400',
    'limits.default_session_expiry_s': '3600',
  });
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[mqtt5]\nreceive_maximum = 8\nmax_keep_alive_s = 300\n'), toml);
  assert.ok(toml.includes('[limits]\nmax_session_expiry_s = 86400\ndefault_session_expiry_s = 3600\n'), toml);
  const r = pack(toml);
  assert.ok(r.ok, JSON.stringify(r));
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  // The settings survive the address bar.
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, s))).toml, toml);
});

test('the validator names the key: ranges, and the 3.1.1 default above the maximum', () => {
  for (const [id, v] of [['mqtt5.receive_maximum', '0'], ['mqtt5.max_user_properties', '1025'], ['mqtt5.topic_alias_maximum', '65536']]) {
    const s = emptyState();
    s.values[id] = v;
    const built = buildToml(model, s);
    const r = pack(built.toml);
    assert.ok(Object.keys(built.local).includes(id) || (!r.ok && r.errors.some(e => e.path === id)), `${id} = ${v}: ${JSON.stringify(r)}`);
  }
  const s = emptyState();
  s.values['limits.max_session_expiry_s'] = '3600';
  const r = pack(buildToml(model, s).toml);
  assert.equal(r.ok, false);
  const e = r.errors.find(x => x.path === 'limits.default_session_expiry_s');
  assert.ok(e && e.message.includes('limits.max_session_expiry_s'), JSON.stringify(r.errors));
});

test('with MQTT 5.0 off its other keys are not shown and not written', () => {
  const s = emptyState();
  const shown = () => model.fields.filter(x => x.section === 'mqtt5' && isApplicable(x, s)).map(x => x.name);
  assert.equal(shown().length, 7);
  Object.assign(s.values, { 'mqtt5.enabled': false, 'mqtt5.receive_maximum': '8' });
  // Shared subscriptions apply to 3.1.1 clients too (ADR-275): they stay.
  assert.deepEqual(shown(), ['enabled', 'shared_subscriptions']);
  assert.deepEqual(changedIds(model, s), ['mqtt5.enabled']);
  assert.equal(buildToml(model, s).toml, '[mqtt5]\nenabled = false\n');
  // The expiry limits apply to MQTT 3.1.1 too: they stay.
  assert.ok(isApplicable(model.byId.get('limits.max_session_expiry_s'), s));
});
