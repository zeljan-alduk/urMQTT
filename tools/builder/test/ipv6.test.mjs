// IPv6 in the form's logic (ADR-334): `network.ipv6` of format 23 in
// [network], off by default and writing nothing; slaac needs format 23;
// static needs its address and gateway, and the module refuses what the
// kernel's check refuses; an IPv6 network in an allow-list lifts the format to
// 23. Against the real module, like netqueues.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, importToml } from '../web/src/core.js';
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
const KEYS = ['network.ipv6', 'network.ipv6_address', 'network.ipv6_gateway'];

test('the keys are in [network], off by default, the only keys of format 23', () => {
  assert.equal(model.formatVersion, FORMAT);
  const network = model.sections.find(s => s.id === 'network').fields.map(f => f.id);
  for (const k of KEYS) assert.ok(network.includes(k), k);
  const f = model.byId.get('network.ipv6');
  assert.equal(f.default, 'off');
  assert.deepEqual(f.variants, ['off', 'slaac', 'static']);
  assert.deepEqual(model.fields.filter(x => x.since === 23).map(x => x.id), KEYS);
});

test('off writes nothing; slaac needs format 23 and comes back', () => {
  const s = emptyState();
  s.values['network.ipv6'] = 'off';
  assert.deepEqual(changedIds(model, s), []);
  assert.equal(buildToml(model, s).toml, '');
  const st = emptyState();
  st.values['network.ipv6'] = 'slaac';
  assert.deepEqual(changedIds(model, st), ['network.ipv6']);
  const { toml } = buildToml(model, st);
  assert.ok(toml.includes('[network]\nipv6 = "slaac"\n'), toml);
  const r = pack(toml);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 23);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, st))).toml, toml);
});

test('static needs its address and gateway; the module refuses what the kernel refuses', () => {
  const ok = '[network]\nipv6 = "static"\nipv6_address = "2001:db8:1::10/64"\nipv6_gateway = "fe80::1"\n';
  const r = pack(ok);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 23);
  for (const bad of [
    '[network]\nipv6 = "static"\n',
    '[network]\nipv6 = "static"\nipv6_address = "2001:db8:1::10/64"\nipv6_gateway = "2001:db8:2::1"\n',
    '[network]\nipv6 = "static"\nipv6_address = "fe80::10/64"\nipv6_gateway = "fe80::1"\n',
    '[network]\nipv6 = "slaac"\nipv6_address = "2001:db8:1::10/64"\n',
  ]) {
    assert.ok(!pack(bad).ok, bad);
  }
});

test('an IPv6 network in an allow-list needs format 23', () => {
  const r = pack('[metrics]\nenabled = true\nallow_from = ["10.0.0.0/8", "2001:db8::/32"]\n');
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 23);
  assert.ok(!pack('[metrics]\nenabled = true\nallow_from = ["::/0"]\n').ok);
});
