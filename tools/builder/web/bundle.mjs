// Assembles the page into a directory (default build/builder): app.js from the
// ES modules in src/, app.css, index.html, the i18n files and a manifest with
// content hashes. No npm, no bundler: the modules are concatenated in order
// with their import and export keywords removed, inside one function scope, so
// every top-level name of src/ must be unique. The same files are what the
// aldo.tech site build copies (ADR-226).
//
//   node tools/builder/web/bundle.mjs [OUT_DIR]
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../..');
const OUT = resolve(process.argv[2] || join(ROOT, 'build/builder'));
const SRC = join(HERE, 'src');

// Dependency order: a module may use the names of the ones before it.
const ORDER = ['wasm.js', 'core.js', 'i18n.js', 'dom.js', 'release.js', 'dialogs.js', 'certs.js', 'form.js', 'plaintext.js', 'emulator.js', 'ui.js', 'simple.js', 'main.js'];

function strip(name, text) {
  let out = text;
  // import { a, b } from './x.js';   (also multi-line, default and side-effect imports)
  out = out.replace(/^import\s[^;]*?from\s*['"][^'"]+['"];?[ \t]*\n/gm, '');
  out = out.replace(/^import\s*['"][^'"]+['"];?[ \t]*\n/gm, '');
  // export function / const / let / class / async function
  out = out.replace(/^export\s+(default\s+)?(async\s+function|function\*?|const|let|class)\b/gm, '$2');
  // export { a, b };
  out = out.replace(/^export\s*\{[^}]*\};?[ \t]*\n/gm, '');
  const left = out.match(/^\s*(import|export)\b/m);
  if (left) throw new Error(`${name}: an import/export form the bundler does not handle: ${left[0].trim()}`);
  return `// ---- ${name} ----\n${out}`;
}

const PLACEHOLDER = 'REPLACE-WITH-THE-NEW-PUBLIC-KEY';

/** The key id of a minisign public key file (`Ed` ‖ id ‖ key, the id shown reversed in hex), or null. */
function keyIdOf(text) {
  const line = text.split('\n').map(l => l.trim()).find(l => l && !l.startsWith('untrusted comment:'));
  const raw = line && /^[A-Za-z0-9+/]+=*$/.test(line) ? Buffer.from(line, 'base64') : null;
  if (!raw || raw.length !== 42 || raw.subarray(0, 2).toString() !== 'Ed') return null;
  return [...raw.subarray(2, 10)].reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * The keys the page trusts: [{name, keyId, text, file, validFrom, validTo, formerTest, pinned}]
 * (pinned: tag -> SHA-256 of the SHA256SUMS that key signed for it; the former test key's releases).
 * BUILDER_KEYRING_JSON (a JSON array of such objects) or BUILDER_PUBKEY_TEXT (one key, any tag)
 * replace keys/release-keys.json for the tests, which sign with throwaway keys.
 * A key file that is still the placeholder is left out, loudly: such a page trusts
 * only the former test key, and scripts/deploy-builder-site.sh refuses to deploy it.
 */
function releaseKeys() {
  if (process.env.BUILDER_KEYRING_JSON) return JSON.parse(process.env.BUILDER_KEYRING_JSON);
  if (process.env.BUILDER_PUBKEY_TEXT) {
    const text = process.env.BUILDER_PUBKEY_TEXT;
    return [{ name: 'release', keyId: keyIdOf(text), text, file: 'minisign.pub', validFrom: null, validTo: null, formerTest: false }];
  }
  const ringPath = join(ROOT, 'keys/release-keys.json');
  const ring = JSON.parse(readFileSync(ringPath, 'utf8'));
  if (ring.schema !== 1 || !Array.isArray(ring.keys) || !ring.keys.length) throw new Error(`${ringPath}: not a key ring of schema 1`);
  const out = [];
  for (const k of ring.keys) {
    const path = resolve(dirname(ringPath), k.file);
    const text = readFileSync(path, 'utf8');
    if (text.includes(PLACEHOLDER)) {
      console.warn(`builder: WARNING ${relative(ROOT, path)} is still the placeholder; the page leaves the "${k.name}" key out (docs/release-key-rotation.md)`);
      continue;
    }
    const keyId = keyIdOf(text);
    if (!keyId) throw new Error(`${path} is not a minisign public key`);
    if (k.key_id && k.key_id !== keyId) throw new Error(`${path} has key id ${keyId}, keys/release-keys.json says ${k.key_id}`);
    const pinned = k.pinned || {};
    for (const [tag, sha] of Object.entries(pinned)) if (!/^[0-9a-f]{64}$/.test(sha)) throw new Error(`keys/release-keys.json: the pin of ${tag} is not a SHA-256`);
    out.push({ name: k.name, keyId, text: text.trim() + '\n', file: relative(ROOT, path), validFrom: k.valid_from || null, validTo: k.valid_to || null, formerTest: k.former_test_key === true, pinned });
  }
  if (!out.length) throw new Error('keys/release-keys.json: no usable key');
  if (new Set(out.map(k => k.keyId)).size !== out.length) throw new Error('keys/release-keys.json lists one key twice');
  return out;
}

function build() {
  mkdirSync(OUT, { recursive: true });
  const present = ORDER.filter(n => existsSync(join(SRC, n)));
  const unknown = readdirSync(SRC).filter(n => n.endsWith('.js') && !ORDER.includes(n));
  if (unknown.length) throw new Error(`src/ has modules that are not in the bundle order: ${unknown.join(', ')}`);
  let js = present.map(n => strip(n, readFileSync(join(SRC, n), 'utf8'))).join('\n');

  // The release signing keys the page trusts, each for its range of tags (keys/release-keys.json).
  const keys = releaseKeys();
  js = js.split('__RELEASE_KEYS__').join(JSON.stringify(keys));
  const format = readFileSync(join(ROOT, 'crates/cfg/src/blob.rs'), 'utf8').match(/pub const FORMAT_VERSION: u16 = (\d+);/)[1];
  js = js.split('__FORMAT_VERSION__').join(format);
  js = `// urMQTT builder (generated by tools/builder/web/bundle.mjs; do not edit)\n(() => {\n'use strict';\n${js}\n})();\n`;
  writeFileSync(join(OUT, 'app.js'), js);

  for (const f of ['app.css']) if (existsSync(join(HERE, f))) cpSync(join(HERE, f), join(OUT, f));
  if (existsSync(join(HERE, 'i18n'))) cpSync(join(HERE, 'i18n'), join(OUT, 'i18n'), { recursive: true });

  // The emulator (C1g, ADR-228): its loader (tools/builder/emulator) and, if make-runtime.sh has made it, the
  // runtime. The directory is named after the wasm's hash, so everything in it can be cached forever; the
  // page learns the name from the manifest. Without a runtime the page says the emulator is not part of this build.
  rmSync(join(OUT, 'emulator'), { recursive: true, force: true });
  let emulator = null;
  const runtime = join(ROOT, 'build/emulator-runtime/qemu');
  if (existsSync(join(runtime, 'qemu-system-x86_64.wasm'))) {
    emulator = createHash('sha256').update(readFileSync(join(runtime, 'qemu-system-x86_64.wasm'))).digest('hex').slice(0, 10);
    const dest = join(OUT, 'emulator', emulator);
    mkdirSync(dest, { recursive: true });
    for (const f of ['urmqtt-emulator.js', 'emu-worker.js', 'emu-core.js', 'SOURCE.txt', 'qemu-wasm-ctpop-fix.patch']) {
      cpSync(join(ROOT, 'tools/builder/emulator', f), join(dest, f));
    }
    cpSync(runtime, join(dest, 'qemu'), { recursive: true });
  }

  // The hashes the site build turns into ?v= query strings (immutable caching).
  const hashes = {};
  const walk = (dir, rel = '') => {
    for (const e of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (r !== 'emulator') walk(dir, r); }
      else if (e.name !== 'manifest.json' && e.name !== 'index.html') {
        hashes[r] = createHash('sha256').update(readFileSync(join(dir, r))).digest('hex').slice(0, 10);
      }
    }
  };
  walk(OUT);

  if (existsSync(join(HERE, 'index.html'))) {
    let html = readFileSync(join(HERE, 'index.html'), 'utf8');
    html = html.replace(/__V:([A-Za-z0-9_./-]+)__/g, (m, f) => {
      if (!hashes[f]) throw new Error(`index.html names ${f}, which is not built`);
      return hashes[f];
    });
    html = html.replace(/__FORMAT_VERSION__/g, format);
    writeFileSync(join(OUT, 'index.html'), html);
  }
  const release = keys.find(k => !k.formerTest) || null;
  writeFileSync(join(OUT, 'manifest.json'), JSON.stringify({ format: Number(format), files: hashes, emulator, keys: keys.map(k => ({ name: k.name, key_id: k.keyId, valid_from: k.validFrom, valid_to: k.validTo, former_test_key: k.formerTest })), release_key: release ? release.keyId : null }, null, 2) + '\n');
  console.log(`builder: ${Object.keys(hashes).length} files in ${OUT}${emulator ? `, emulator ${emulator}` : ', without the emulator runtime'}; keys ${keys.map(k => `${k.keyId} (${k.name})`).join(', ')}`);
}

build();
