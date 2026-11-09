// A/B updates in the form's logic (ADR-297): the three `[update]` keys of
// format 17, what the TOML says and what the validator refuses. Against the
// real module, like shared.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, importToml } from '../web/src/core.js';
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
const KEYS = ['update.confirm', 'update.confirm_after_s', 'update.trial_timeout_s'];

test('the section is last, with the documented defaults and ranges, the only keys of format 17', () => {
  assert.equal(model.formatVersion, 20);
  const ids = model.sections.map(s => s.id);
  assert.equal(ids.indexOf('update'), ids.indexOf('mqtt5') + 1);
  const update = model.sections.find(s => s.id === 'update').fields.map(f => [f.id, f.default]);
  assert.deepEqual(update, [['update.confirm', 'auto'], ['update.confirm_after_s', 60], ['update.trial_timeout_s', 900]]);
  assert.deepEqual(model.byId.get('update.confirm').variants, ['auto', 'operator']);
  for (const id of ['update.confirm_after_s', 'update.trial_timeout_s']) {
    const f = model.byId.get(id);
    assert.deepEqual([f.min, f.max, f.since], [0, 86400, 17], id);
  }
  assert.deepEqual(model.fields.filter(x => x.since === 17).map(x => x.id), KEYS);
});

test('untouched or at the defaults the configuration keeps its format; any key set needs 17', () => {
  const s = emptyState();
  Object.assign(s.values, { 'update.confirm': 'auto', 'update.confirm_after_s': '60', 'update.trial_timeout_s': '900' });
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  for (const [id, v] of [['update.confirm', 'operator'], ['update.confirm_after_s', '0'], ['update.trial_timeout_s', '0']]) {
    const st = emptyState();
    st.values[id] = v;
    assert.deepEqual(changedIds(model, st), [id]);
    const r = pack(buildToml(model, st).toml);
    assert.ok(r.ok, `${id} = ${v}: ${JSON.stringify(r)}`);
    assert.equal(version(r.blob), 17, `${id} = ${v}`);
  }
});

test('the keys become the TOML the tool reads, and back', () => {
  const s = emptyState();
  Object.assign(s.values, { 'update.confirm': 'operator', 'update.confirm_after_s': '5', 'update.trial_timeout_s': '600' });
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[update]\nconfirm = "operator"\nconfirm_after_s = 5\ntrial_timeout_s = 600\n'), toml);
  assert.ok(pack(toml).ok);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, s))).toml, toml);
});

test('the validator names the key: out of range, and a timeout the automatic confirmation cannot beat', () => {
  for (const [values, id] of [
    [{ 'update.confirm_after_s': '86401' }, 'update.confirm_after_s'],
    [{ 'update.trial_timeout_s': '86401' }, 'update.trial_timeout_s'],
    [{ 'update.trial_timeout_s': '60' }, 'update.trial_timeout_s'],
  ]) {
    const s = emptyState();
    Object.assign(s.values, values);
    const built = buildToml(model, s);
    const r = pack(built.toml);
    assert.ok(Object.keys(built.local).includes(id) || (!r.ok && r.errors.some(e => e.path === id)), `${JSON.stringify(values)}: ${JSON.stringify(r)}`);
  }
  const s = emptyState();
  Object.assign(s.values, { 'update.confirm': 'operator', 'update.trial_timeout_s': '60' });
  assert.ok(pack(buildToml(model, s).toml).ok, 'an operator confirms: the timeout is theirs to beat');
});
