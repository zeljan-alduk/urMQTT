// Plaintext MQTT in the form's logic (P1, ADR-229): the accounts and the
// networks with identities as TOML, which fields exist when, what stays out of
// the address bar, the private-address check, the risks, the presets and the
// generated password. Against the real module, like core.test.mjs.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  applyPreset, buildModel, buildToml, changedIds, decodeHash, DRAFT_HASH, draftUsers, emptyState, encodeHash, evaluateRisks, fieldForPath,
  importToml, isApplicable, isChanged, isPrivateAddress, PRESETS, randomPassword, userProblems,
} from '../web/src/core.js';
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

const HASH1 = 'pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$4c5805526868c915a4cba43d75ec6b0a07152bb7b9ca30501c96ea0f91886829';
const HASH2 = 'pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$d8e0e2fe5529c9a22ab5544ab7731dee2bd812edd94059f6f97ff26be82c319b';

test('the accounts and the networks with identities become the TOML tables the tool reads, and back', () => {
  const s = emptyState();
  Object.assign(s.values, {
    'plaintext.enabled': true,
    'plaintext.allow_from': ['10.0.0.0/8'],
    'plaintext.users': [{ id: 'sensor-1', hash: HASH1 }, { id: ' sensor-2 ', hash: HASH2 }],
  });
  const { toml } = buildToml(model, s);
  assert.match(toml, /^\[plaintext\]\nenabled = true\nallow_from = \["10\.0\.0\.0\/8"\]\nusers = \[\{ id = "sensor-1", password_hash = "pbkdf2-sha256\$1000\$[0-9a-f]+\$[0-9a-f]+" \}, \{ id = "sensor-2", /);
  assert.ok(pack(toml).ok, JSON.stringify(pack(toml)));
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.deepEqual(back.state.values['plaintext.users'], [{ id: 'sensor-1', hash: HASH1 }, { id: 'sensor-2', hash: HASH2 }]);
  assert.equal(buildToml(model, back.state).toml, toml);

  const ip = emptyState();
  Object.assign(ip.values, { 'plaintext.enabled': true, 'plaintext.auth': 'ip', 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.ip_identities': ['10.0.1.0/24 plc', '  10.0.2.0/24   line-2 '] });
  const t2 = buildToml(model, ip).toml;
  assert.ok(t2.includes('ip_identities = [{ from = "10.0.1.0/24", id = "plc" }, { from = "10.0.2.0/24", id = "line-2" }]'), t2);
  assert.ok(pack(t2).ok, JSON.stringify(pack(t2)));
  assert.deepEqual(importToml(model, b.tomlToJson(t2)).state.values['plaintext.ip_identities'], ['10.0.1.0/24 plc', '10.0.2.0/24 line-2']);
});

test('plaintext fields exist only while it is on, and each mode shows its own', () => {
  const f = id => model.byId.get(id);
  const s = emptyState();
  const shown = () => model.fields.filter(x => x.section === 'plaintext' && isApplicable(x, s)).map(x => x.id.slice(10));
  assert.deepEqual(shown(), ['enabled']);
  s.values['plaintext.enabled'] = true;
  assert.ok(shown().includes('users') && shown().includes('allow_from') && shown().includes('port'));
  assert.ok(!shown().includes('anonymous_identity') && !shown().includes('ip_identities'));
  s.values['plaintext.auth'] = 'anonymous';
  assert.ok(isApplicable(f('plaintext.anonymous_identity'), s) && !isApplicable(f('plaintext.users'), s) && !isApplicable(f('plaintext.ip_identities'), s));
  s.values['plaintext.auth'] = 'ip';
  assert.ok(isApplicable(f('plaintext.ip_identities'), s) && !isApplicable(f('plaintext.users'), s) && !isApplicable(f('plaintext.anonymous_identity'), s));

  // Values left over from a hidden field never reach the validator (nor count as changes).
  const left = emptyState();
  Object.assign(left.values, {
    'plaintext.port': '2000', 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.users': [{ id: 'a', hash: HASH1 }],
    'plaintext.allow_from_anywhere': true, 'plaintext.anonymous_identity': 'x',
  });
  assert.equal(buildToml(model, left).toml, '');
  assert.deepEqual(changedIds(model, left), []);
  assert.ok(pack(buildToml(model, left).toml).ok);
  left.values['plaintext.enabled'] = true;
  left.values['plaintext.auth'] = 'ip';
  const t = buildToml(model, left).toml;
  assert.ok(!t.includes('users') && !t.includes('anonymous_identity'), t);
});

test('the accounts never go to the address bar or come in from it', () => {
  const s = emptyState();
  Object.assign(s.values, { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.users': [{ id: 'sensor-1', hash: HASH1 }] });
  const h = encodeHash(model, s);
  const text = Buffer.from(h.slice(3), 'base64url').toString();
  assert.ok(!text.includes('sensor-1') && !text.includes('pbkdf2') && !text.includes(HASH1.split('$')[3]), text);
  assert.ok(text.includes('plaintext.allow_from'), 'the rest of the section is kept');
  // A hostile address cannot plant accounts (or break the editor with strings).
  const planted = decodeHash(model, '#s=' + Buffer.from(JSON.stringify({ v: { 'plaintext.users': ['evil'], 'plaintext.enabled': true } })).toString('base64url'));
  assert.deepEqual(planted.values, { 'plaintext.enabled': true });
});

test('blank rows are no changes; a row needs both an id and a password', () => {
  const users = model.byId.get('plaintext.users');
  assert.equal(isChanged(users, [{ id: '', hash: '' }]), false);
  assert.equal(isChanged(users, [{ id: 'a', hash: '' }]), true);
  assert.deepEqual(userProblems([{ id: '', hash: '' }, { id: 'a', hash: '' }, { id: '', hash: HASH1 }, { id: 'b', hash: HASH1 }]), [{ row: 1, kind: 'password' }, { row: 2, kind: 'id' }]);
  // The checked TOML (not the exported one) carries a stand-in hash, so ids are validated while typed.
  const s = emptyState();
  Object.assign(s.values, { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.users': [{ id: '', hash: '' }, { id: 'bad id', hash: '' }, { id: 'ok', hash: HASH1 }] });
  assert.ok(!buildToml(model, s).toml.includes('bad id'), 'the export has only complete accounts');
  const draft = buildToml(model, s, { draft: true }).toml;
  assert.ok(draft.includes('bad id') && draft.includes(DRAFT_HASH), draft);
  const r = pack(draft);
  assert.equal(r.ok, false);
  const e = r.errors.find(x => /users\[\d+\]\.id/.test(x.path));
  assert.ok(e, JSON.stringify(r.errors));
  assert.equal(fieldForPath(model, e.path).id, 'plaintext.users');
  // The validator's index counts the rows with an id: the editor row is found through draftUsers.
  assert.equal(draftUsers(s.values['plaintext.users']).rows[Number(/\[(\d+)\]/.exec(e.path)[1])], 1);
  // The stand-in is a well-formed hash for a password nobody has.
  const only = { ...s, values: { ...s.values, 'plaintext.users': [{ id: 'ok', hash: '' }] } };
  assert.ok(pack(buildToml(model, only, { draft: true }).toml).ok);
});

test('isPrivateAddress: the ranges that are not routed on the Internet', () => {
  for (const a of ['10.0.0.1', '10.255.255.255/8', '172.16.0.1', '172.31.255.254/12', '192.168.1.5/24', '100.64.0.1', '100.127.255.255', '169.254.1.1', '127.0.0.1', ' 10.1.2.3 ']) assert.equal(isPrivateAddress(a), true, a);
  for (const a of ['11.0.0.1', '172.15.0.1', '172.32.0.1', '192.167.1.1', '192.169.1.1', '100.63.255.255', '100.128.0.1', '169.253.1.1', '8.8.8.8/24', '192.0.2.10/24', '', 'abc', '10.0.0', '10.0.0.256', '10.0.0.1.2', 'fe80::1']) assert.equal(isPrivateAddress(a), false, a);
});

test('plaintext risks: asked at the build, with the public address as its own', () => {
  const s = emptyState();
  const got = () => Object.fromEntries(evaluateRisks(model, s, null).map(r => [r.id, r.level]));
  assert.ok(!Object.keys(got()).some(k => k.startsWith('plaintext')), 'nothing while it is off');
  s.values['plaintext.enabled'] = true;
  assert.equal(got()['plaintext-on'], 'confirm');
  assert.ok(!('plaintext-anywhere' in got()) && !('plaintext-anonymous' in got()) && !('plaintext-public-address' in got()));
  s.values['plaintext.allow_from_anywhere'] = true;
  s.values['plaintext.auth'] = 'anonymous';
  assert.equal(got()['plaintext-anywhere'], 'confirm');
  assert.equal(got()['plaintext-anonymous'], 'note');
  // The address matters in the fixed modes only, and only when it is not a private one.
  s.values['network.address'] = '192.0.2.10/24';
  assert.ok(!('plaintext-public-address' in got()), 'DHCP: the address is not used');
  s.values['network.mode'] = 'static';
  assert.equal(got()['plaintext-public-address'], 'confirm');
  assert.equal(evaluateRisks(model, s, null).find(r => r.id === 'plaintext-public-address').args.address, '192.0.2.10');
  s.values['network.mode'] = 'auto';
  assert.equal(got()['plaintext-public-address'], 'confirm');
  s.values['network.address'] = '10.0.2.15/24';
  assert.ok(!('plaintext-public-address' in got()));
  // Off again: none of it applies.
  s.values['plaintext.enabled'] = false;
  s.values['network.address'] = '192.0.2.10/24';
  assert.ok(!Object.keys(got()).some(k => k.startsWith('plaintext')));
});

test('no preset switches plaintext MQTT on', () => {
  for (const id of [...Object.keys(PRESETS), 'defaults']) {
    const s = applyPreset(id);
    assert.ok(!Object.keys(s.values).some(k => k.startsWith('plaintext.')), `${id} leaves plaintext alone`);
    assert.notEqual(s.values['plaintext.enabled'], true, id);
    assert.ok(!buildToml(model, s).toml.includes('[plaintext]'), id);
  }
});

test('a generated password has 20 characters of a-zA-Z0-9, drawn without bias', () => {
  const p = randomPassword();
  assert.match(p, /^[A-Za-z0-9]{20}$/);
  assert.notEqual(randomPassword(), randomPassword());
  // Bytes at or above 248 (the largest multiple of 62 below 256) are thrown away.
  let calls = 0;
  const q = randomPassword(5, n => { calls++; return Uint8Array.from({ length: n }, (_, i) => (calls === 1 ? 255 - (i % 8) : i)); });
  assert.equal(q.length, 5);
  assert.ok(calls >= 2, 'the rejected bytes were not used');
  assert.equal(q, 'abcde', q);
  // Every character occurs about equally often.
  const seen = new Map();
  for (let i = 0; i < 400; i++) for (const c of randomPassword(20)) seen.set(c, (seen.get(c) || 0) + 1);
  assert.equal(seen.size, 62);
  assert.ok([...seen.values()].every(n => n > 50 && n < 220), JSON.stringify([...seen.values()].sort((a, b) => a - b).slice(0, 3)));
});
