// The WebAssembly module and the `urmqtt-config` command line tool must produce
// the same bytes for the same input (docs/PLAN.md C1e, ADR-225). The module is
// the one the page loads (build/builder/urmqtt-cfg<N>.wasm); the tool is the
// debug binary of the same workspace.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { loadBuilder, hex } from '../web/src/wasm.js';
import { CLI, DEV, FIXTURES, FORMAT, ROOT, WASM, cli, haveCli, haveDevCerts, haveWasm, realTemplate, syntheticTemplate, tmp } from './helpers.mjs';

if (!haveWasm() || !haveCli()) {
  console.log(`skipped: needs ${WASM} (make builder) and ${CLI} (cargo build -p urmqtt-config-tool)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const NOW = 1_900_000_000;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

test('the schema is the command line schema, byte for byte', () => {
  const j = b.x.ub_schema();
  const text = b.takeText(j);
  assert.equal(text, cli(['schema']).stdout);
});

test('the module reads the format version the tool writes', () => {
  assert.equal(b.formatVersion, FORMAT);
});

test('a configuration without files packs to the same bytes', () => {
  const dir = tmp();
  const out = join(dir, 'lab.blob');
  const toml = readFileSync(join(FIXTURES, 'lab.toml'), 'utf8');
  const r = cli(['pack', join(FIXTURES, 'lab.toml'), '--now', String(NOW), '--out', out]);
  assert.equal(r.status, 0, r.stderr);
  const w = b.pack({ toml, now: NOW });
  assert.ok(w.ok, JSON.stringify(w));
  assert.deepEqual(Buffer.from(w.blob), readFileSync(out));
  assert.deepEqual(Buffer.from(w.blob), readFileSync(join(FIXTURES, 'lab.blob')), 'the golden blob');
  // The fingerprint the page shows is the one the tool prints.
  const info = b.blobInfo(w.blob);
  assert.ok(r.stdout.includes(info.fingerprint), r.stdout);
});

test('the empty configuration and every default written out are the same blob', () => {
  const empty = b.pack({ toml: '', now: NOW });
  const explicit = b.pack({ toml: b.defaultToml(), now: NOW });
  assert.ok(empty.ok && explicit.ok);
  assert.deepEqual(Buffer.from(empty.blob), Buffer.from(explicit.blob));
});

test('the same problems are reported, in the same words', () => {
  const r = cli(['pack', join(FIXTURES, 'bad.toml'), '--now', String(NOW), '--out', join(tmp(), 'x')]);
  assert.notEqual(r.status, 0);
  const cliProblems = r.stderr.split('\n').filter(l => l.startsWith('  - ')).map(l => l.slice(4));
  const w = b.pack({ toml: readFileSync(join(FIXTURES, 'bad.toml'), 'utf8'), now: NOW });
  assert.equal(w.ok, false);
  const wasmProblems = w.errors.map(e => (e.path ? `${e.path}: ${e.message}` : e.message));
  assert.ok(cliProblems.length >= 3, r.stderr);
  assert.deepEqual(wasmProblems, cliProblems);
});

test('a configuration with certificates, a control key and a signature', { skip: !haveDevCerts() && 'run `make certs`' }, () => {
  const dir = tmp();
  const names = { 'server.pem': 'server.pem', 'server.key': 'server.key', 'ca.pem': 'ca.pem', 'control.pub': 'control.pub' };
  for (const n of Object.values(names)) copyFileSync(join(DEV, n), join(dir, n));
  const toml = `[network]
mode = "static"
address = "10.0.2.15/24"
gateway = "10.0.2.2"

[tls]
cert = "server.pem"
key = "server.key"

[trust]
operational = ["ca.pem"]

[control]
public_key = "control.pub"
service_ids = ["ops"]

[limits]
publish_rate_per_device = "30/s"
`;
  writeFileSync(join(dir, 'cfg.toml'), toml);
  const files = Object.fromEntries(Object.values(names).map(n => [n, readFileSync(join(dir, n))]));

  // Unsigned. The development certificates are valid today, not in 2030: use a
  // clock that both sides share and that is inside their validity.
  const out = join(dir, 'a.blob');
  const now = Math.floor(Date.now() / 1000);
  let r = cli(['pack', join(dir, 'cfg.toml'), '--now', String(now), '--out', out]);
  assert.equal(r.status, 0, r.stderr);
  const w = b.pack({ toml, files, now });
  assert.ok(w.ok, JSON.stringify(w));
  assert.deepEqual(Buffer.from(w.blob), readFileSync(out));
  assert.deepEqual(b.blobInfo(w.blob).missing, []);

  // Signed with the same key: Ed25519 is deterministic, so the bytes agree.
  const key = b.newSigningKey(new Uint8Array(32).fill(7));
  writeFileSync(join(dir, 'sign.pem'), key.private_pem);
  const outSigned = join(dir, 'b.blob');
  r = cli(['pack', join(dir, 'cfg.toml'), '--now', String(now), '--sign', join(dir, 'sign.pem'), '--out', outSigned]);
  assert.equal(r.status, 0, r.stderr);
  const ws = b.pack({ toml, files, now, signPem: key.private_pem });
  assert.ok(ws.ok, JSON.stringify(ws));
  assert.deepEqual(Buffer.from(ws.blob), readFileSync(outSigned));
  assert.equal(b.blobInfo(ws.blob).signer_id, key.signer_id);
  assert.ok(r.stdout.includes('signed'), r.stdout);
  assert.equal(b.blobInfo(ws.blob).fingerprint, b.blobInfo(w.blob).fingerprint, 'signing does not change the fingerprint');
});

function isoCases() {
  const cases = [['synthetic template', () => syntheticTemplate(d => b.blake2bHex(d))]];
  const real = realTemplate();
  if (real) cases.push([`the real template ${real.split('/').pop()}`, () => readFileSync(real)]);
  return cases;
}

for (const [label, make] of isoCases()) {
  test(`configuring ${label}: the same image, the same report, the same verdict`, () => {
    const tpl = make();
    const dir = tmp();
    const tplPath = join(dir, 'template.iso');
    writeFileSync(tplPath, tpl);
    const toml = readFileSync(join(FIXTURES, 'lab.toml'), 'utf8');
    const w = b.pack({ toml, now: NOW });
    assert.ok(w.ok);

    // The tool.
    const outPath = join(dir, 'out.iso');
    const r = cli(['pack', join(FIXTURES, 'lab.toml'), '--now', String(NOW), '--iso', tplPath, '--out', outPath]);
    assert.equal(r.status, 0, r.stderr);

    // The module, in place in its own memory.
    const iso = b.alloc(tpl.length);
    b.view(iso).set(tpl);
    const probe = b.isoProbe(iso);
    assert.equal(probe.supported, true);
    assert.equal(probe.format_version, FORMAT);
    const report = b.isoConfigure(iso, w.blob);
    const mine = Buffer.from(b.view(iso));
    assert.equal(mine.length, tpl.length);
    assert.ok(mine.equals(readFileSync(outPath)), 'the module and the tool configure the image identically');
    assert.ok(r.stderr.includes(report), `${report} vs ${r.stderr}`);
    assert.equal(b.sha256Hex(iso), sha(mine), 'SHA-256 of the image');

    // The verdicts agree.
    const verdict = b.isoVerify(iso);
    assert.equal(verdict, cli(['verify', outPath]).stdout.trim());
    assert.ok(verdict.includes(b.blobInfo(w.blob).fingerprint));

    // A template can be configured again and returns to the original when
    // configured with the empty configuration.
    const emptyBlob = b.pack({ toml: '', now: NOW }).blob;
    b.isoConfigure(iso, emptyBlob);
    assert.ok(Buffer.from(b.view(iso)).equals(tpl), 'back to the template, byte for byte');
    b.free(iso);
  });
}

test('a file that is not a template is refused before anything changes', () => {
  const junk = new Uint8Array(100_000).fill(1);
  const iso = b.alloc(junk.length);
  b.view(iso).set(junk);
  assert.throws(() => b.isoProbe(iso), /no configuration slot/);
  const blob = b.pack({ toml: '', now: NOW }).blob;
  assert.throws(() => b.isoConfigure(iso, blob), /no configuration slot/);
  assert.ok(Buffer.from(b.view(iso)).equals(Buffer.from(junk)));
  b.free(iso);
});

test('the release check agrees with minisign and with the command line', () => {
  const pubkey = readFileSync(join(ROOT, 'minisign.pub'), 'utf8');
  const dir = join(FIXTURES, 'minisign');
  const sums = readFileSync(join(dir, 'SHA256SUMS'));
  const sig = readFileSync(join(dir, 'SHA256SUMS.minisig'), 'utf8');
  const v = b.verifyRelease(pubkey, sums, sig);
  assert.equal(v.key_id, '9229E05252D01F8E');
  assert.equal(v.trusted_comment, 'urMQTT v0.1.0 dev bf311aa0810a7ad2b31e4dc911cb45d8131c350c');
  assert.equal(v.files.length, 3);
  const r = cli(['check-release', '--pubkey', join(ROOT, 'minisign.pub'), '--sums', join(dir, 'SHA256SUMS')]);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes(v.trusted_comment));
  assert.equal(b.minisignKeyId(pubkey), '9229E05252D01F8E');
  // One flipped bit anywhere is refused.
  for (const i of [0, 40, sums.length - 2]) {
    const bad = Buffer.from(sums);
    bad[i] ^= 1;
    assert.throws(() => b.verifyRelease(pubkey, bad, sig), /does not match/);
  }
  const badSig = sig.replace(/^(.*\n)(.)/, (m, a, c) => a + (c === 'R' ? 'Q' : 'R'));
  assert.throws(() => b.verifyRelease(pubkey, sums, badSig));
});

test('hashes: SHA-256 and BLAKE2b agree with the reference implementations', () => {
  const data = Buffer.from('urMQTT builder '.repeat(1000));
  assert.equal(b.sha256Hex(data), sha(data));
  assert.equal(b.blake2bHex(data), createHash('blake2b512').update(data).digest('hex'));
  assert.equal(b.sha256Hex(new Uint8Array(0)), sha(Buffer.alloc(0)));
});
