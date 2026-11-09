// Writes the seed files of vault-fuzz.test.mjs into seeds/vault/ (run once; the output is committed).
//   node tools/builder/test/make-vault-seeds.mjs
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromB64, sealValue, toB64 } from '../web/src/vault.js';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'seeds/vault');
export const SEED_PASSPHRASE = 'fuzz-seed-passphrase';
const good = await sealValue(SEED_PASSPHRASE, { snapshot: 1, state: { values: { 'network.mode': 'static' }, files: { key: { pem: 'x', summary: 'y' } } } }, { iterations: 200000 });
const e = JSON.parse(good);
const flipLast = b => { b[b.length - 1] ^= 1; return b; };
const w = (name, text) => writeFileSync(join(dir, name), text);
w('valid', good);
w('valid-compact', JSON.stringify(e));
w('wrong-version', JSON.stringify({ ...e, version: 2 }));
w('huge-iterations', JSON.stringify({ ...e, iterations: 4294967296 }));
w('low-iterations', JSON.stringify({ ...e, iterations: 1 }));
w('short-nonce', JSON.stringify({ ...e, iv: toB64(new Uint8Array(4)) }));
w('flipped-tag', JSON.stringify({ ...e, data: toB64(flipLast(fromB64(e.data))) }));
w('not-base64', JSON.stringify({ ...e, salt: '%%%' }));
w('extra-field', JSON.stringify({ ...e, extra: [] }));
w('other-format', JSON.stringify({ format: 'something-else' }));
w('empty-object', '{}');
w('array', '[1,2,3]');
w('text', 'this is not a project file\n');
