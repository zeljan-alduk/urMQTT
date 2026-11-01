// The password hash made in the browser (ub_hash_password) against the command
// line tool: the same format, the same default cost, accepted by `pack`, and
// right for the clear password when checked with an independent PBKDF2 (Node's).
import assert from 'node:assert/strict';
import { pbkdf2Sync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { loadBuilder, PASSWORD_ITERATIONS } from '../web/src/wasm.js';
import { CLI, WASM, cli, haveCli, haveWasm, tmp } from './helpers.mjs';

if (!haveWasm() || !haveCli()) {
  console.log(`skipped: needs ${WASM} (make builder) and ${CLI} (cargo build -p urmqtt-config-tool)`);
  process.exit(0);
}

const b = await loadBuilder(readFileSync(WASM));
const NOW = 1_900_000_000;

/** Whether `hash` (pbkdf2-sha256$iterations$salt$key) is the hash of `password`, by Node's PBKDF2. */
function verifies(hash, password) {
  const [scheme, iterations, salt, key] = hash.split('$');
  assert.equal(scheme, 'pbkdf2-sha256');
  const mine = pbkdf2Sync(Buffer.from(password), Buffer.from(salt, 'hex'), Number(iterations), 32, 'sha256');
  return mine.toString('hex') === key;
}

test('the page hashes with the cost the command line tool uses', () => {
  const r = cli(['hash-password'], { input: 'pw\n' });
  assert.equal(r.status, 0, r.stderr);
  const [, iterations] = r.stdout.trim().split('$');
  assert.equal(PASSWORD_ITERATIONS, Number(iterations), 'PASSWORD_ITERATIONS is the tool\'s default');
  assert.ok(verifies(r.stdout.trim(), 'pw'), 'the tool\'s own hash verifies, so the check below is a fair one');
});

test('a hash made by the module is the PBKDF2-SHA-256 of the password and the salt', () => {
  const salt = Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 1);
  const hash = b.hashPassword('correct horse', salt);
  assert.match(hash, new RegExp(`^pbkdf2-sha256\\$${PASSWORD_ITERATIONS}\\$[0-9a-f]{32}\\$[0-9a-f]{64}$`));
  assert.ok(verifies(hash, 'correct horse'));
  assert.ok(!verifies(hash, 'correct horse '));
  assert.equal(hash, b.hashPassword('correct horse', salt), 'the same salt gives the same hash');
  assert.notEqual(hash, b.hashPassword('correct horse', salt.map(x => x ^ 1)), 'another salt another hash');
  // Non-ASCII passwords are hashed as UTF-8, like the tool does.
  assert.ok(verifies(b.hashPassword('Grüße 中', salt), 'Grüße 中'));
  // The module does not accept what the kernel could not use.
  assert.throws(() => b.hashPassword('x', new Uint8Array(8)), /salt/i);
});

test('the tool accepts the module\'s hash in a TOML, and the module and the tool pack the same bytes', () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = b.hashPassword('sensor-secret', salt);
  const toml = `[plaintext]\nenabled = true\nallow_from = ["10.0.0.0/8"]\nusers = [{ id = "sensor-1", password_hash = "${hash}" }]\n`;
  const dir = tmp();
  writeFileSync(join(dir, 'cfg.toml'), toml);
  const out = join(dir, 'cfg.blob');
  const r = cli(['pack', join(dir, 'cfg.toml'), '--now', String(NOW), '--out', out]);
  assert.equal(r.status, 0, r.stderr);
  const w = b.pack({ toml, now: NOW });
  assert.ok(w.ok, JSON.stringify(w));
  assert.deepEqual(Buffer.from(w.blob), readFileSync(out));
  // The clear password is nowhere in the configuration.
  assert.ok(!Buffer.from(w.blob).includes('sensor-secret'));
});
