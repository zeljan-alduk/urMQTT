// A disk key that is not in the image (LATER-7, ADR-328) in the form's logic:
// `storage.encryption` is offered (the key file `storage.disk_key` is not),
// `storage.disk_key_source` of format 22 appears only with encryption on, the
// default writes nothing, "console" packs into format 22 with no key, the image
// source without a key file is refused by the module, the risk asks for a
// confirmation, and the TOML comes back. Against the real module.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, evaluateRisks, fieldForPath, importToml, isApplicable } from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';
import { FORMAT, WASM, haveWasm } from './helpers.mjs';

if (!haveWasm()) {
  console.log(`skipped: needs ${WASM} (make builder)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const model = buildModel(b.schema());
const NOW = 1_900_000_000;
const pack = toml => b.pack({ toml, now: NOW });
const version = blob => blob[8] | (blob[9] << 8);
const ID = 'storage.disk_key_source';

test('the key source is in [storage], image by default, the only key of format 22; the key file is not offered', () => {
  assert.equal(model.formatVersion, FORMAT);
  const storage = model.sections.find(s => s.id === 'storage').fields.map(f => f.id);
  assert.ok(storage.includes(ID));
  assert.ok(storage.includes('storage.encryption'));
  assert.ok(!model.byId.has('storage.disk_key'));
  const f = model.byId.get(ID);
  assert.equal(f.default, 'image');
  assert.equal(f.since, 22);
  assert.deepEqual(model.fields.filter(x => x.since === 22).map(x => x.id), [ID]);
});

test('the source applies only with encryption on', () => {
  const f = model.byId.get(ID);
  const s = emptyState();
  assert.equal(isApplicable(f, s), false);
  s.values['storage.encryption'] = 'aes-256-xts';
  assert.equal(isApplicable(f, s), true);
});

test('image writes nothing; console with encryption packs into format 22 without a key and comes back', () => {
  const s = emptyState();
  s.values[ID] = 'image';
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  const st = emptyState();
  st.values['storage.encryption'] = 'aes-256-xts';
  st.values[ID] = 'console';
  const { toml } = buildToml(model, st);
  assert.ok(toml.includes('[storage]\n'), toml);
  assert.ok(toml.includes('encryption = "aes-256-xts"\n'), toml);
  assert.ok(toml.includes('disk_key_source = "console"\n'), toml);
  assert.ok(!toml.includes('disk_key ='), toml);
  const r = pack(toml);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 22);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, st))).toml, toml);
  // The availability trade-off is confirmed before the build.
  const risks = evaluateRisks(model, st, null).filter(x => x.id === 'console-unlock');
  assert.deepEqual(risks, [{ id: 'console-unlock', level: 'confirm' }]);
  assert.deepEqual(evaluateRisks(model, emptyState(), null).filter(x => x.id === 'console-unlock'), []);
});

test('encryption with the image as the source needs a key file the page cannot give: the module says so', () => {
  const st = emptyState();
  st.values['storage.encryption'] = 'aes-256-xts';
  const r = pack(buildToml(model, st).toml);
  assert.equal(r.ok, false);
  assert.ok(JSON.stringify(r).includes('storage.disk_key'), JSON.stringify(r));
  // The page shows that problem at the source choice, the key file not being on the page.
  for (const e of r.errors) assert.equal(fieldForPath(model, e.path).id, ID, JSON.stringify(e));
  // And the console source without encryption.
  const c = pack('[storage]\ndisk_key_source = "console"\n');
  assert.equal(c.ok, false);
  assert.ok(JSON.stringify(c).includes('storage.disk_key_source'), JSON.stringify(c));
});
