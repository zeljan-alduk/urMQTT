// The form's logic against the real module: every field has a default, a
// state that sets nothing (or sets defaults) writes nothing and packs to the
// blob of the empty configuration, and every field can be changed to a valid
// other value and written as TOML the validator accepts (ADR-226).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  applyPreset, buildModel, buildToml, changedIds, decodeHash, emptyState, encodeHash, evaluateRisks, fieldForPath,
  importToml, isChanged, isFileType, isListType, outputName, PRESETS, tomlString,
} from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';
import { WASM, haveWasm } from './helpers.mjs';

if (!haveWasm()) {
  console.log(`skipped: needs ${WASM} (make builder)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const schema = b.schema();
const model = buildModel(schema);
const NOW = 1_900_000_000;
const pack = toml => b.pack({ toml, now: NOW });
const emptyBlob = Buffer.from(pack('').blob);

test('every field of the schema has a default, a help text and a known type', () => {
  const known = new Set(['bool', 'uint', 'enum', 'string', 'string_list', 'rate', 'pem', 'pem_list', 'ipv4', 'cidr', 'socket_addr', 'socket_addr_list', 'ed25519_public_key']);
  assert.ok(model.fields.length >= 40, 'the form has fields');
  for (const f of schema.fields) {
    assert.ok('default' in f, `${f.key} has a default entry`);
    assert.ok(f.help && f.help.length > 8, `${f.key} has help text`);
    assert.ok(known.has(f.type), `${f.key}: unknown type ${f.type}`);
    if (f.type === 'uint') {
      assert.ok(f.default >= f.min && f.default <= f.max, `${f.key}: default ${f.default} outside ${f.min}..${f.max}`);
      assert.ok(Number.isSafeInteger(f.max), `${f.key}: max is a safe integer`);
    }
    if (f.type === 'enum') assert.ok(f.variants.includes(f.default), f.key);
  }
  // Fields without a default are optional and the page has an example for each.
  for (const f of model.fields) {
    if (f.default === null && !isFileType(f)) assert.ok(f.example, `${f.key} needs an example placeholder`);
  }
  // Dev-only fields are not offered.
  assert.ok(model.devOnly.length >= 4);
  assert.ok(!model.fields.some(f => f.dev_only));
  assert.ok(!model.fields.some(f => f.derived));
});

test('the page writes nothing for an untouched form, and defaults typed in are not written either', () => {
  const none = buildToml(model, emptyState());
  assert.equal(none.toml, '');
  assert.deepEqual(none.files, {});
  const s = emptyState();
  for (const f of model.fields) {
    if (isFileType(f) || f.default === null) continue;
    if (f.type === 'bool') s.values[f.id] = f.default;
    else if (isListType(f)) s.values[f.id] = [...f.default];
    else s.values[f.id] = String(f.default);
  }
  assert.equal(changedIds(model, s).length, 0, 'typing the defaults changes nothing');
  assert.equal(buildToml(model, s).toml, '');
  assert.deepEqual(Buffer.from(pack(buildToml(model, s).toml).blob), emptyBlob);
});

/** Another valid value for a field, or null if there is none worth trying. */
function otherValue(f) {
  switch (f.type) {
    case 'bool': return !f.default;
    case 'uint': return String(f.default < f.max ? f.default + 1 : f.default - 1);
    case 'enum': return f.variants.find(v => v !== f.default);
    case 'string': return f.id === 'env' ? 'staging' : 'x';
    case 'rate': return '5/m';
    case 'cidr': return '10.1.2.3/24';
    case 'ipv4': return '10.1.2.1';
    case 'socket_addr': return '10.1.2.50:514';
    case 'string_list':
      if (f.item === 'user') return [{ id: 'sensor-1', hash: 'pbkdf2-sha256$1000$00112233445566778899aabbccddeeff$4c5805526868c915a4cba43d75ec6b0a07152bb7b9ca30501c96ea0f91886829' }];
      if (f.item === 'ip_identity') return ['10.1.0.0/16 plc'];
      if (f.item === 'cidr') return ['10.1.0.0/16'];
      if (f.id === 'cpu.disable') return ['aes'];
      if (f.id === 'tls.revoked_serials') return ['0a1b2c'];
      if (f.id === 'acl.service_ids' || f.id === 'acl.operator_ids' || f.id === 'control.service_ids') return ['svc-one'];
      return ['lab/{id}/#'];
    case 'socket_addr_list': return ['10.1.2.3'];
    default: return null;
  }
}

test('every field can be changed on its own and the validator accepts it or blames that field', () => {
  let packed = 0;
  for (const f of model.fields) {
    if (isFileType(f)) continue;
    const v = otherValue(f);
    assert.notEqual(v, null, f.id);
    const s = emptyState();
    // Fields that only exist in another network mode come with their mode.
    if (f.id === 'network.address') Object.assign(s.values, { 'network.mode': 'static', 'network.gateway': '10.1.2.1' });
    if (f.id === 'network.gateway') Object.assign(s.values, { 'network.mode': 'static', 'network.address': '10.1.2.3/24' });
    if (f.id === 'network.dhcp_timeout_s') Object.assign(s.values, { 'network.mode': 'auto', 'network.address': '10.1.2.3/24', 'network.gateway': '10.1.2.1' });
    // Plaintext fields only exist while plaintext MQTT is on, and each of the three modes has its own.
    if (f.section === 'plaintext' && f.id !== 'plaintext.enabled') {
      Object.assign(s.values, { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'] });
      if (f.id === 'plaintext.anonymous_identity') s.values['plaintext.auth'] = 'anonymous';
      if (f.id === 'plaintext.ip_identities') s.values['plaintext.auth'] = 'ip';
      if (f.id === 'plaintext.auth') s.values['plaintext.users'] = otherValue(model.byId.get('plaintext.users'));
    }
    s.values[f.id] = v;
    if (f.id === 'plaintext.enabled') Object.assign(s.values, { 'plaintext.allow_from': ['10.0.0.0/8'], 'plaintext.users': otherValue(model.byId.get('plaintext.users')) });
    if (f.id === 'plaintext.users') Object.assign(s.values, { 'plaintext.enabled': true, 'plaintext.allow_from': ['10.0.0.0/8'] });
    if (f.id === 'tls.min_server_cert_days' || f.id === 'trust.min_anchor_days') continue; // checked with certificates
    const { toml, files } = buildToml(model, s);
    assert.ok(toml.length > 0, `${f.id} is written when changed`);
    const r = b.pack({ toml, files, now: NOW });
    if (r.ok) {
      packed++;
      assert.notDeepEqual(Buffer.from(r.blob), emptyBlob, `${f.id}: a changed field must change the blob`);
    } else {
      // A field that needs another one (the address of a static network) is
      // allowed to complain, but about a key the form knows, never about TOML syntax.
      for (const e of r.errors) {
        assert.ok(e.path === '' ? false : fieldForPath(model, e.path) || e.path === 'network.mode', `${f.id}: unexpected ${JSON.stringify(e)}`);
      }
    }
  }
  assert.ok(packed >= 30, `only ${packed} fields pack on their own`);
});

test('a static network needs its address and gateway, and the form can supply them', () => {
  const s = emptyState();
  s.values['network.mode'] = 'static';
  let r = b.pack({ ...buildToml(model, s), now: NOW });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some(e => e.path.startsWith('network')), JSON.stringify(r.errors));
  s.values['network.address'] = '192.0.2.10/24';
  s.values['network.gateway'] = '192.0.2.1';
  r = b.pack({ ...buildToml(model, s), now: NOW });
  assert.ok(r.ok, JSON.stringify(r));
  // The presets are valid starting points (the fixed address ones wait for an address).
  for (const id of Object.keys(PRESETS)) {
    const p = applyPreset(id);
    const q = b.pack({ ...buildToml(model, p), now: NOW });
    if (!q.ok) assert.ok(q.errors.every(e => e.path.startsWith('network')), `${id}: ${JSON.stringify(q.errors)}`);
  }
});

test('text the user types cannot break the TOML', () => {
  const s = emptyState();
  s.values['acl.device_publish'] = ['a"b', 'c\\d', 'line\nbreak', 'tab\there', 'é中'];
  s.values['limits.max_packet_size'] = '4096; evil = 1';
  s.values['observability.log_level'] = 'info"\n[x]';
  const built = buildToml(model, s);
  const { toml } = built;
  assert.doesNotThrow(() => b.tomlToJson(toml), 'still valid TOML');
  // Junk in a number field is caught by the page (it never reaches the TOML)
  // and the rest of the configuration still packs.
  assert.deepEqual(built.local, { 'limits.max_packet_size': 'int', 'observability.log_level': 'enum' });
  assert.ok(!toml.includes('max_packet_size'));
  const r = b.pack({ toml, now: NOW });
  assert.ok(r.ok || r.errors.every(e => e.path), JSON.stringify(r));
  assert.equal(tomlString('a"b\\c\n'), '"a\\"b\\\\c\\n"');
});

test('a TOML written by the page is read back into the same state', () => {
  const s = emptyState();
  s.values['network.mode'] = 'auto';
  s.values['network.address'] = '192.0.2.10/24';
  s.values['network.gateway'] = '192.0.2.1';
  s.values['network.dhcp_timeout_s'] = '30';
  s.values['limits.publish_rate_per_device'] = '600/m';
  s.values['acl.operator_ids'] = [];
  s.values['acl.device_publish'] = ['lab/{id}/#'];
  s.values['storage.diagnostic'] = true;
  s.values['observability.syslog_udp'] = '192.0.2.50:514';
  s.values.env = 'staging';
  const { toml } = buildToml(model, s);
  const back = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(back.unknown, []);
  assert.deepEqual(back.state.values, s.values);
  // The imported state writes the very same TOML, and packs to the same bytes.
  assert.equal(buildToml(model, back.state).toml, toml);
  assert.deepEqual(Buffer.from(pack(toml).blob), Buffer.from(pack(buildToml(model, back.state).toml).blob));
});

test('importing a TOML reports unknown keys and the files it names', () => {
  const toml = `[tls]
cert = "my-server.pem"
key = "my-server.key"
bogus = 1

[trust]
operational = ["a.pem", "b.pem"]

[nonsense]
x = 1
`;
  const r = importToml(model, b.tomlToJson(toml));
  assert.deepEqual(r.unknown.sort(), ['nonsense.x', 'tls.bogus']);
  assert.deepEqual(r.needFiles, [
    { field: 'tls.cert', names: ['my-server.pem'] },
    { field: 'tls.key', names: ['my-server.key'] },
    { field: 'trust.operational', names: ['a.pem', 'b.pem'] },
  ]);
  // The shipped production template imports without unknown keys.
  const prod = readFileSync(new URL('../../../deploy/prod/config.toml', import.meta.url), 'utf8');
  const p = importToml(model, b.tomlToJson(prod));
  assert.deepEqual(p.unknown.filter(k => !['tls.early_data', 'network.mqtt_plain_port', 'storage.require_flush', 'storage.require_data_disk', 'storage.refuse_on_corruption'].includes(k)), []);
});

test('the hash holds what is safe and nothing else', () => {
  const s = applyPreset('vps');
  s.name = 'my vps';
  s.release = 'v0.2.0';
  s.values['acl.device_publish'] = ['x/#'];
  s.files.cert = { pem: '-----BEGIN CERTIFICATE-----SECRET-----END CERTIFICATE-----' };
  s.files.key = { pem: '-----BEGIN PRIVATE KEY-----SECRETKEY-----END PRIVATE KEY-----' };
  s.signing = { pem: 'SIGNINGSECRET' };
  const h = encodeHash(model, s);
  assert.ok(h.startsWith('#s='));
  assert.ok(!/SECRET/.test(Buffer.from(h.slice(3), 'base64url').toString()), 'no key or certificate in the address bar');
  assert.ok(h.length < 400, `short hash (${h.length})`);
  const back = decodeHash(model, h);
  assert.equal(back.release, 'v0.2.0');
  assert.equal(back.preset, 'vps');
  assert.equal(back.name, 'my vps');
  assert.deepEqual(back.values, { 'network.mode': 'static', 'memory.kernel_heap_mb': '256', 'acl.device_publish': ['x/#'] });
  // Garbage and hostile hashes are ignored, never thrown.
  for (const bad of ['', '#', '#s=', '#s=!!!', '#s=' + Buffer.from('{"v":{"nope":"x","limits.max_packet_size":{"a":1}}}').toString('base64url'), '#s=' + Buffer.from('[1]').toString('base64url')]) {
    assert.doesNotThrow(() => decodeHash(model, bad));
  }
  const odd = decodeHash(model, '#s=' + Buffer.from('{"v":{"nope":"x","limits.max_packet_size":{"a":1}}}').toString('base64url'));
  assert.deepEqual(odd.values, {});
  assert.equal(encodeHash(model, emptyState()), '', 'an untouched form leaves the address alone');
});

test('risks name what deserves a second look', () => {
  const s = emptyState();
  const ids = () => evaluateRisks(model, s, { missing: ['tls.cert'] }).map(r => r.id);
  assert.ok(ids().includes('cannot-serve'));
  assert.ok(!evaluateRisks(model, s, { missing: [] }).some(r => r.id === 'cannot-serve'));
  s.values['storage.mode'] = 'ram';
  s.values['acl.device_publish'] = ['#'];
  s.values['watchdog.action'] = 'reset';
  const got = Object.fromEntries(evaluateRisks(model, s, null).map(r => [r.id, r.level]));
  assert.equal(got['ram-storage'], 'confirm');
  assert.equal(got['wide-acl'], 'confirm');
  assert.equal(got['watchdog-reset'], 'note');
});

test('the CPU-jitter entropy fallback is a note by default, and a hardware-only image says so instead (ADR-263)', () => {
  const s = emptyState();
  const risk = () => Object.fromEntries(evaluateRisks(model, s, null).map(r => [r.id, r.level]));
  assert.equal(risk()['entropy-jitter'], 'note', 'the default allows the weak path, and the page says so');
  assert.ok(!('entropy-none' in risk()));
  s.values['entropy.fallback'] = 'none';
  assert.ok(!('entropy-jitter' in risk()), 'requiring hardware removes the warning');
  assert.equal(risk()['entropy-none'], 'note');
  s.values['entropy.fallback'] = 'jitter';
  assert.equal(risk()['entropy-jitter'], 'note');
  // The choice is in the TOML only when it is not the default; `none` survives a round trip and the hash.
  s.values['entropy.fallback'] = 'none';
  assert.match(buildToml(model, s).toml, /\[entropy\]\s+fallback = "none"/);
  assert.equal(decodeHash(model, encodeHash(model, s)).values['entropy.fallback'], 'none');
});

test('the file name of the result', () => {
  assert.equal(outputName('v0.2.0', 'My Lab!'), 'urmqtt-0.2.0-my-lab-universal.iso');
  assert.equal(outputName('v0.2.0', ''), 'urmqtt-0.2.0-custom-universal.iso');
  assert.equal(outputName('v1.0.0-rc.1', '../../etc'), 'urmqtt-1.0.0-rc.1-etc-universal.iso');
  assert.ok(!outputName('v1', 'a/b\\c').includes('/'));
});

test('isChanged compares like the packer does', () => {
  const f = id => model.byId.get(id);
  assert.equal(isChanged(f('limits.publish_rate_per_device'), '10/s'), false);
  assert.equal(isChanged(f('limits.publish_rate_per_device'), ' 10 / s '), false);
  assert.equal(isChanged(f('limits.publish_rate_per_device'), '11/s'), true);
  assert.equal(isChanged(f('limits.max_packet_size'), '4096'), false);
  assert.equal(isChanged(f('limits.max_packet_size'), ''), false);
  assert.equal(isChanged(f('limits.max_packet_size'), '4097'), true);
  assert.equal(isChanged(f('acl.operator_ids'), []), true, 'an explicit empty list is a change (none)');
  assert.equal(isChanged(f('acl.service_ids'), ['backend']), false);
});
