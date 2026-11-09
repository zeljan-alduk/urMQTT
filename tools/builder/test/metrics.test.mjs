// The Prometheus endpoint in the form's logic (ADR-290): the [metrics]
// section of format 16, what the TOML says, what the validator refuses, and
// when its keys are shown. Against the real module, like shared.test.mjs.
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
const KEYS = ['enabled', 'port', 'allow_from', 'max_connections', 'max_connections_per_ip', 'request_timeout_s'].map(k => `metrics.${k}`);

test('the six keys are in their own section with the documented defaults, the only keys of format 16', () => {
  assert.equal(model.formatVersion, 20);
  const section = model.sections.find(s => s.id === 'metrics');
  assert.deepEqual(section.fields.map(f => f.id), KEYS);
  assert.deepEqual(model.fields.filter(x => x.since === 16).map(x => x.id), KEYS);
  const d = id => model.byId.get(id).default;
  assert.deepEqual([d('metrics.enabled'), d('metrics.port'), d('metrics.max_connections'), d('metrics.max_connections_per_ip'), d('metrics.request_timeout_s')], [false, 9100, 8, 2, 5]);
  assert.equal(model.byId.get('metrics.allow_from').item, 'cidr');
});

test('untouched, the configuration keeps its format; with the endpoint on it needs 16', () => {
  const s = emptyState();
  assert.equal(buildToml(model, s).toml, '');
  assert.equal(version(pack('').blob), 2);
  s.values['metrics.enabled'] = true;
  s.values['metrics.allow_from'] = ['10.0.0.0/8', '192.168.1.5/32'];
  assert.deepEqual(changedIds(model, s), ['metrics.enabled', 'metrics.allow_from']);
  const { toml } = buildToml(model, s);
  assert.ok(toml.includes('[metrics]\nenabled = true\nallow_from = ["10.0.0.0/8", "192.168.1.5/32"]\n'), toml);
  const r = pack(toml);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 16);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.equal(buildToml(model, decodeHash(model, encodeHash(model, s))).toml, toml);
});

test('the validator names the key: no allow-list, a bad network, a port already taken', () => {
  const s = emptyState();
  s.values['metrics.enabled'] = true;
  let r = pack(buildToml(model, s).toml);
  assert.ok(!r.ok && r.errors.some(e => e.path === 'metrics.allow_from' && /anywhere/.test(e.message)), JSON.stringify(r));
  s.values['metrics.allow_from'] = ['0.0.0.0/0'];
  r = pack(buildToml(model, s).toml);
  assert.ok(!r.ok && r.errors.some(e => e.path === 'metrics.allow_from[0]'), JSON.stringify(r));
  s.values['metrics.allow_from'] = ['10.0.0.0/8'];
  s.values['metrics.port'] = '8883';
  r = pack(buildToml(model, s).toml);
  assert.ok(!r.ok && r.errors.some(e => e.path === 'metrics.port'), JSON.stringify(r));
});

test('while the endpoint is off only its switch is shown', () => {
  const s = emptyState();
  const shown = () => KEYS.filter(id => isApplicable(model.byId.get(id), s));
  assert.deepEqual(shown(), ['metrics.enabled']);
  s.values['metrics.enabled'] = true;
  assert.deepEqual(shown(), KEYS);
});
