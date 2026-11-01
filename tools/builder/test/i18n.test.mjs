// The page's texts: every key the code uses exists, and each of the 15 site
// languages has exactly the keys of English, with the same {placeholders}.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { ROOT, WASM, haveWasm } from './helpers.mjs';
import { buildModel, PRESETS } from '../web/src/core.js';
import { loadBuilder } from '../web/src/wasm.js';

const LANGS = ['hr', 'en', 'de', 'nl', 'fr', 'it', 'es', 'pt', 'hu', 'cs', 'sk', 'pl', 'sl', 'sr', 'ru'];
const dir = join(ROOT, 'tools/builder/web');
const load = lang => JSON.parse(readFileSync(join(dir, 'i18n', `${lang}.json`), 'utf8'));
const placeholders = s => [...String(s).matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort().join(',');

test('there is a text file for each of the 15 site languages and nothing else', () => {
  const files = readdirSync(join(dir, 'i18n')).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).sort();
  assert.deepEqual(files, [...LANGS].sort());
});

test('every language has the keys of English, no more and no fewer, with the same placeholders', () => {
  const en = load('en');
  for (const lang of LANGS) {
    const t = load(lang);
    const missing = Object.keys(en).filter(k => !(k in t));
    const extra = Object.keys(t).filter(k => !(k in en));
    assert.deepEqual(missing, [], `${lang} lacks keys`);
    assert.deepEqual(extra, [], `${lang} has keys English does not`);
    for (const [k, v] of Object.entries(t)) {
      assert.equal(typeof v, 'string', `${lang}.${k}`);
      assert.ok(v.trim().length > 0, `${lang}.${k} is empty`);
      assert.equal(placeholders(v), placeholders(en[k]), `${lang}.${k}: placeholders differ from English`);
    }
  }
});

test('every key the code asks for exists in English', { skip: !haveWasm() && 'needs the module' }, async () => {
  const en = load('en');
  const src = readdirSync(join(dir, 'src')).filter(f => f.endsWith('.js')).map(f => readFileSync(join(dir, 'src', f), 'utf8')).join('\n');
  const used = new Set();
  // t('section.' + id) and the like are prefixes of keys built at run time (enumerated below).
  for (const m of src.matchAll(/\bt\('([A-Za-z0-9_.\-]+)'/g)) if (!m[1].endsWith('.')) used.add(m[1]);
  // Keys built from a field, section, preset, risk, slot or unit: enumerate them.
  const b = await loadBuilder(readFileSync(WASM));
  const model = buildModel(b.schema());
  for (const s of model.sections) used.add(`section.${s.id}`);
  for (const id of [...Object.keys(PRESETS), 'defaults']) { used.add(`preset.${id}`); used.add(`preset.${id}.desc`); }
  for (const slot of ['cert', 'key', 'operational', 'bootstrap', 'control', 'signing']) { used.add(`cert.title.${slot}`); used.add(`cert.help.${slot}`); }
  for (const id of ['cannot-serve', 'ram-storage', 'wide-acl', 'watchdog-reset', 'cpu-disable', 'no-time', 'no-control', 'registry-open', 'entropy-none', 'plaintext-on', 'plaintext-anywhere', 'plaintext-anonymous', 'plaintext-public-address']) {
    used.add(`risk.${id}.title`); used.add(`risk.${id}.text`);
  }
  for (const u of ['ms', 'mb', 's', 'min', 'h', 'days']) used.add(`unit.${u}`);
  for (const e of ['int', 'enum']) used.add(`err.${e}`);
  for (const rel of ['no-template', 'no-slot', 'no-signature', 'format-unsupported', 'unverified', 'removed']) used.add(`release.${rel}`);
  const missing = [...used].filter(k => !(k in en) && !/^enum\./.test(k)).sort();
  assert.deepEqual(missing, []);
  // The section names exist for every section the schema has, and the enum hints
  // that do exist belong to fields that exist.
  for (const k of Object.keys(en).filter(k => k.startsWith('enum.'))) {
    const [, ...rest] = k.split('.');
    const variant = rest.pop();
    const f = model.byId.get(rest.join('.'));
    assert.ok(f && f.variants.includes(variant), `${k} names no field choice`);
  }
});

test('no text in any language is left as an English copy of a long sentence (untranslated)', () => {
  const en = load('en');
  for (const lang of LANGS.filter(l => l !== 'en')) {
    const t = load(lang);
    const same = Object.keys(en).filter(k => en[k].length > 60 && t[k] === en[k]);
    assert.deepEqual(same, [], `${lang}: still English`);
  }
});
