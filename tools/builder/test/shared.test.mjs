// Shared subscriptions in the form's logic (ADR-275): the two group limits of
// format 13 in [limits], what the TOML says, what the validator refuses, and
// when they are shown. Against the real module, like mqtt5.test.mjs.
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
const KEYS = ['limits.max_shared_groups', 'limits.max_shared_group_members'];

test('the two limits are in [limits] with the documented defaults and ranges, the only keys of format 13', () => {
  assert.equal(model.formatVersion, 16);
  const limits = model.sections.find(s => s.id === 'limits').fields.map(f => f.id);
  for (const id of KEYS) {
    assert.ok(limits.includes(id), id);
    const f = model.byId.get(id);
    assert.deepEqual([f.default, f.min, f.max, f.since], [1024, 1, 65535, 13], id);
  }
  assert.deepEqual(model.fields.filter(x => x.since === 13).map(x => x.id), KEYS);
});

test('untouched or at the defaults the configuration keeps its format; either set needs 13', () => {
  const s = emptyState();
  Object.assign(s.values, { 'limits.max_shared_groups': '1024', 'limits.max_shared_group_members': '1024' });
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  for (const id of KEYS) {
    for (const v of ['1', '65535']) {
      const st = emptyState();
      st.values[id] = v;
      assert.deepEqual(changedIds(model, st), [id]);
      const r = pack(buildToml(model, st).toml);
      assert.ok(r.ok, `${id} = ${v}: ${JSON.stringify(r)}`);
      assert.equal(version(r.blob), 13, `${id} = ${v}`);
    }
  }
});

test('the limits become the TOML the tool reads, and back', () => {
  const s = emptyState();
  Object.assign(s.values, { 'limits.max_shared_groups': '64', 'limits.max_shared_group_members': '8' });
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[limits]\nmax_shared_groups = 64\nmax_shared_group_members = 8\n'), toml);
  assert.ok(pack(toml).ok);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, s))).toml, toml);
});

test('the validator names the key: 0 and 65536 are refused', () => {
  for (const id of KEYS) {
    for (const v of ['0', '65536']) {
      const s = emptyState();
      s.values[id] = v;
      const built = buildToml(model, s);
      const r = pack(built.toml);
      assert.ok(Object.keys(built.local).includes(id) || (!r.ok && r.errors.some(e => e.path === id)), `${id} = ${v}: ${JSON.stringify(r)}`);
    }
  }
});

test('with shared subscriptions off the limits are not shown and not written, also with MQTT 5.0 off (3.1.1 clients share too)', () => {
  const s = emptyState();
  const shown = () => KEYS.filter(id => isApplicable(model.byId.get(id), s));
  assert.deepEqual(shown(), KEYS);
  Object.assign(s.values, { 'mqtt5.shared_subscriptions': false, 'limits.max_shared_groups': '64' });
  assert.deepEqual(shown(), []);
  assert.deepEqual(changedIds(model, s), ['mqtt5.shared_subscriptions']);
  // MQTT 5.0 off: the switch is still shown and written (it applies to 3.1.1 clients).
  s.values['mqtt5.enabled'] = false;
  assert.ok(isApplicable(model.byId.get('mqtt5.shared_subscriptions'), s));
  assert.deepEqual(shown(), []);
  assert.deepEqual(changedIds(model, s), ['mqtt5.enabled', 'mqtt5.shared_subscriptions']);
  s.values['mqtt5.shared_subscriptions'] = true;
  assert.deepEqual(shown(), KEYS);
  assert.deepEqual(changedIds(model, s), ['mqtt5.enabled', 'limits.max_shared_groups']);
});
