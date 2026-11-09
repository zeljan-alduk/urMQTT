// Log shipping over TLS in the form's logic (NEXT-7, ADR-318): the four
// `observability.log_tls*` keys of format 20, the collector's trust anchors as
// a list of PEM files (the `logca` slot), what the TOML says and what the
// validator refuses. Against the real module, like update.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { buildModel, buildToml, changedIds, emptyState, FILE_KEYS, importToml, LIST_SLOTS, listFileNames } from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';
import { DEV, WASM, haveDevCerts, haveWasm } from './helpers.mjs';

if (!haveWasm()) {
  console.log(`skipped: needs ${WASM} (make builder)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const model = buildModel(b.schema());
const NOW = 1_900_000_000;
const version = blob => blob[8] | (blob[9] << 8);
const KEYS = ['observability.log_tls', 'observability.log_tls_name', 'observability.log_tls_ca', 'observability.log_tls_queue_kb'];

test('the keys are in the observability section, the only ones of format 20, with their defaults', () => {
  assert.equal(model.formatVersion, 22);
  const obs = model.sections.find(s => s.id === 'observability').fields.map(f => f.id);
  for (const id of KEYS) assert.ok(obs.includes(id), id);
  assert.deepEqual(model.fields.filter(x => x.since === 20).map(x => x.id), KEYS);
  const q = model.byId.get('observability.log_tls_queue_kb');
  assert.deepEqual([q.min, q.max, q.default], [16, 4096, 256]);
  assert.deepEqual(FILE_KEYS['observability.log_tls_ca'], { slot: 'logca', file: 'log-ca-%d.pem', list: true });
  assert.ok(LIST_SLOTS.includes('logca'));
  assert.deepEqual(emptyState().files.logca, []);
  assert.deepEqual(listFileNames('logca', 2), ['log-ca-1.pem', 'log-ca-2.pem']);
  assert.deepEqual(listFileNames('operational', 1), ['ca-1.pem']);
});

test('untouched the configuration keeps its format and names no file', () => {
  const s = emptyState();
  Object.assign(s.values, { 'observability.log_tls': '', 'observability.log_tls_queue_kb': '256' });
  assert.deepEqual(changedIds(model, s), []);
  const built = buildToml(model, s);
  assert.equal(built.toml, '');
  assert.deepEqual(built.files, {});
});

test('a collector with its anchors becomes the TOML the tool reads, packs into format 20, and imports back', { skip: !haveDevCerts() }, () => {
  const ca = readFileSync(join(DEV, 'ca.pem'), 'utf8');
  const s = emptyState();
  Object.assign(s.values, { 'observability.log_tls': '192.0.2.52:6514', 'observability.log_tls_name': 'logs.example.com' });
  s.files.logca = [{ pem: ca, summary: 'dev CA' }];
  const { toml, files } = buildToml(model, s);
  assert.ok(toml.includes('[observability]\nlog_tls = "192.0.2.52:6514"\nlog_tls_name = "logs.example.com"\nlog_tls_ca = ["log-ca-1.pem"]\n'), toml);
  assert.deepEqual(Object.keys(files), ['log-ca-1.pem']);
  const r = b.pack({ toml, files, now: NOW });
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(version(r.blob), 20);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.deepEqual(back.needFiles, [{ field: 'observability.log_tls_ca', names: ['log-ca-1.pem'] }]);
});

test('the validator names the key: no anchors, a name that is not a DNS name, a key without the collector', () => {
  for (const [values, id] of [
    [{ 'observability.log_tls': '192.0.2.52:6514' }, 'observability.log_tls_ca'],
    [{ 'observability.log_tls_name': 'logs.example.com' }, 'observability.log_tls_name'],
    [{ 'observability.log_tls_queue_kb': '64' }, 'observability.log_tls_queue_kb'],
    [{ 'observability.log_tls_queue_kb': '8' }, 'observability.log_tls_queue_kb'],
    [{ 'observability.log_tls': '127.0.0.1:6514' }, 'observability.log_tls'],
  ]) {
    const s = emptyState();
    Object.assign(s.values, values);
    const built = buildToml(model, s);
    const r = b.pack({ toml: built.toml, now: NOW });
    assert.ok(Object.keys(built.local).includes(id) || (!r.ok && r.errors.some(e => e.path === id)), `${JSON.stringify(values)}: ${JSON.stringify(r)}`);
  }
});
