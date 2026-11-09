// A mutation fuzzer for the one parser of untrusted bytes NOW-16 adds: the project file envelope (vault.js
// parseEnvelope and openValue). Starts from the seeds in seeds/vault/ and applies random byte and structure
// mutations for VAULT_FUZZ_SECONDS (default 4; the release check runs it for 120). Invariants: only VaultError
// is ever thrown, no input is slow (the round count is bounded before any key is derived), and a mutated file
// opens only if every field the cipher uses is exactly the original's.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { VaultError, openValue, parseEnvelope } from '../web/src/vault.js';

const SEEDS = join(dirname(fileURLToPath(import.meta.url)), 'seeds/vault');
const PASS = 'fuzz-seed-passphrase';
const SECONDS = Number(process.env.VAULT_FUZZ_SECONDS || 4);
const seeds = readdirSync(SEEDS).sort().map(n => readFileSync(join(SEEDS, n), 'utf8'));
const original = JSON.parse(readFileSync(join(SEEDS, 'valid'), 'utf8'));

let state = Number(process.env.VAULT_FUZZ_SEED || 0x9e3779b9) >>> 0;
const rnd = n => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state % n; };
const JUNK = ['"', '\\', '{', '}', '[', ']', ':', ',', '0', '9', '-', 'e', 'null', 'true', '\u0000', 'é', '😀', '1e999', '4294967296'];

function mutate(text) {
  let s = text;
  for (let n = 1 + rnd(4); n > 0; n--) {
    const i = rnd(s.length + 1);
    switch (rnd(7)) {
      case 0: s = s.slice(0, i) + s.slice(i + 1 + rnd(8)); break;
      case 1: s = s.slice(0, i) + JUNK[rnd(JUNK.length)] + s.slice(i); break;
      case 2: s = s.slice(0, i) + String.fromCharCode(rnd(0x250)) + s.slice(i + 1); break;
      case 3: s = s.slice(0, i); break;
      case 4: { const j = rnd(s.length + 1); s = s.slice(0, i) + s.slice(Math.min(i, j), Math.max(i, j)) + s.slice(i); break; }
      case 5: { // swap a whole field for another value
        try {
          const o = JSON.parse(s);
          const k = Object.keys(o);
          if (k.length) o[k[rnd(k.length)]] = [0, -1, 2 ** 53, 'x', null, [], {}, 600000.5, original.data, original.salt][rnd(10)];
          s = JSON.stringify(o);
        } catch { /* not JSON any more */ }
        break;
      }
      default: if (s.length) { const b = s.charCodeAt(i % s.length) ^ (1 << rnd(8)); s = s.slice(0, i % s.length) + String.fromCharCode(b) + s.slice(i % s.length + 1); }
    }
  }
  return s;
}

test(`the project file parser survives ${SECONDS} s of mutated input`, async () => {
  const t0 = Date.now();
  let runs = 0, parsed = 0, opened = 0;
  while (Date.now() - t0 < SECONDS * 1000) {
    const input = mutate(seeds[rnd(seeds.length)]);
    runs++;
    let env = null;
    try { env = parseEnvelope(input); parsed++; } catch (e) { assert.ok(e instanceof VaultError, `parseEnvelope threw ${e}`); }
    if (env && env.iterations <= 200000) {
      try {
        await openValue(PASS, input);
        opened++;
        // It opened: then nothing the cipher uses can differ from the original.
        assert.equal(env.iterations, original.iterations);
        assert.equal(Buffer.from(env.salt).toString('base64'), original.salt);
        assert.equal(Buffer.from(env.iv).toString('base64'), original.iv);
        assert.equal(Buffer.from(env.data).toString('base64'), original.data);
      } catch (e) { assert.ok(e instanceof VaultError, `openValue threw ${e}`); }
    }
  }
  console.log(`vault fuzz: ${runs} inputs, ${parsed} parsed, ${opened} opened, seed ${process.env.VAULT_FUZZ_SEED || 'default'}`);
  assert.ok(runs > 100);
});
