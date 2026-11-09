// DMA remapping in the form's logic (ADR-305): `devices.iommu` of format 18 in
// [devices], off by default and writing nothing, "auto" and "require" need
// format 18, what the TOML says and that it comes back. Against the real
// module, like shared.test.mjs.
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
const ID = 'devices.iommu';

test('the key is in [devices], off by default, the only key of format 18', () => {
  assert.equal(model.formatVersion, 19);
  const devices = model.sections.find(s => s.id === 'devices').fields.map(f => f.id);
  assert.ok(devices.includes(ID));
  const f = model.byId.get(ID);
  assert.equal(f.default, 'off');
  assert.equal(f.since, 18);
  assert.deepEqual(model.fields.filter(x => x.since === 18).map(x => x.id), [ID]);
});

test('off writes nothing; auto and require need format 18 and come back', () => {
  const s = emptyState();
  s.values[ID] = 'off';
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  for (const v of ['auto', 'require']) {
    const st = emptyState();
    st.values[ID] = v;
    assert.deepEqual(changedIds(model, st), [ID]);
    const { toml } = buildToml(model, st);
    assert.ok(toml.includes(`[devices]\niommu = "${v}"\n`), toml);
    const r = pack(toml);
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(version(r.blob), 18, v);
    const back = importToml(model, b.tomlToJson(toml));
    assert.deepEqual(back.unknown, []);
    assert.equal(buildToml(model, back.state).toml, toml);
    assert.equal(buildToml(model, decodeHash(model, encodeHash(model, st))).toml, toml);
  }
});
