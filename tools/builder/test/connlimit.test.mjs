// The per-address limit on established connections in the form's logic
// (ADR-280): limits.max_connections_per_ip of format 14, its default, its
// range and the TOML it becomes. Against the real module, like shared.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildModel, buildToml, changedIds, emptyState, importToml, isApplicable } from '../web/src/core.js';
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
const KEY = 'limits.max_connections_per_ip';

test('the key is in [limits] with the documented default and range, the only key of format 14', () => {
  assert.equal(model.formatVersion, 20);
  assert.ok(model.sections.find(s => s.id === 'limits').fields.some(f => f.id === KEY));
  const f = model.byId.get(KEY);
  assert.deepEqual([f.default, f.min, f.max, f.since], [1024, 0, 1000000, 14]);
  assert.deepEqual(model.fields.filter(x => x.since === 14).map(x => x.id), [KEY]);
  assert.ok(isApplicable(f, emptyState()));
});

test('untouched or at the default the configuration keeps its format; any other value, 0 included, needs 14', () => {
  const s = emptyState();
  s.values[KEY] = '1024';
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  for (const v of ['0', '1', '1000000']) {
    const st = emptyState();
    st.values[KEY] = v;
    assert.deepEqual(changedIds(model, st), [KEY]);
    const r = pack(buildToml(model, st).toml);
    assert.ok(r.ok, `${v}: ${JSON.stringify(r)}`);
    assert.equal(version(r.blob), 14, v);
  }
});

test('the limit becomes the TOML the tool reads, and back; 1000001 is refused naming the key', () => {
  const s = emptyState();
  s.values[KEY] = '200';
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[limits]\nmax_connections_per_ip = 200\n'), toml);
  assert.ok(pack(toml).ok);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  const bad = pack('[limits]\nmax_connections_per_ip = 1000001\n');
  assert.equal(bad.ok, false);
  assert.ok(JSON.stringify(bad).includes('limits.max_connections_per_ip'), JSON.stringify(bad));
});
