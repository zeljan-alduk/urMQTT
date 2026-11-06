// Builds a complete test site in a temporary directory: the page bundled with a
// THROWAWAY release key, the module, and a local mirror signed with that key.
// Used by the browser tests and by `node dev.mjs` (to look at the page).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { ROOT, WASM, WASM_NAME, realTemplate, syntheticTemplate, tmp } from './helpers.mjs';
import { loadBuilder } from '../web/src/wasm.js';
import { newKey, writeMirror } from './mirror-fixture.mjs';
import { readFileSync } from 'node:fs';

/**
 * @param {object} o
 * @param {boolean} [o.real] use the real 63 MB template for the stable release when `make template` made one
 * @param {string[]} [o.tamper] tags whose ISO is altered after signing
 * @param {boolean} [o.rotation] the page trusts two keys, as after the key rotation: `key` (the release
 *   key, for v0.4.2 and later) and `oldKey` (the former test key, for v0.1.0 to v0.4.1 only); `releases`
 *   is then called with (small, bigPath, {key, oldKey}) and a release may set `signer`
 * @param {Function} [o.pins] with rotation: (sumsSha) => {tag: sha256}, the old key's pins, where
 *   sumsSha(tag) is the SHA-256 of the SHA256SUMS written for that tag
 */
export async function prepareSite({ real = false, tamper = [], releases, rotation = false, pins = null } = {}) {
  const dir = tmp('urmqtt-site-');
  const appDir = join(dir, 'app');
  const mirrorDir = join(dir, 'mirror');
  mkdirSync(appDir, { recursive: true });
  const key = newKey();
  const oldKey = rotation ? newKey() : null;
  copyFileSync(WASM, join(appDir, WASM_NAME));
  const b = await loadBuilder(readFileSync(WASM));
  const small = syntheticTemplate(d => b.blake2bHex(d));
  const bigPath = real ? realTemplate() : null;
  const list = (typeof releases === 'function' ? releases(small, bigPath, { key, oldKey }) : releases) || [
    { tag: 'v0.3.0-rc.1', prerelease: true, published: '2026-11-03T09:00:00Z', template: small },
    { tag: 'v0.2.0', published: '2026-11-02T09:00:00Z', template: bigPath ? { path: bigPath } : small },
    { tag: 'v0.1.0', prerelease: true, published: '2026-10-30T00:50:09Z', template: null },
  ];
  writeMirror(mirrorDir, key, list, { tamper });
  // The page is bundled after the mirror exists, so that pins can name the SHA256SUMS written for a tag.
  const sumsSha = tag => createHash('sha256').update(readFileSync(join(mirrorDir, tag, 'SHA256SUMS'))).digest('hex');
  const keyEnv = rotation
    ? { BUILDER_KEYRING_JSON: JSON.stringify([
        { name: 'release', keyId: key.idText, text: key.publicText, file: 'minisign.pub', validFrom: 'v0.4.2', validTo: null, formerTest: false, pinned: {} },
        { name: 'test', keyId: oldKey.idText, text: oldKey.publicText, file: `keys/minisign-test-${oldKey.idText}.pub`, validFrom: 'v0.1.0', validTo: 'v0.4.1', formerTest: true, pinned: pins ? pins(sumsSha) : {} },
      ]) }
    : { BUILDER_PUBKEY_TEXT: key.publicText };
  execFileSync('node', [join(ROOT, 'tools/builder/web/bundle.mjs'), appDir], {
    env: { ...process.env, BUILDER_KEYRING_JSON: '', BUILDER_PUBKEY_TEXT: '', ...keyEnv },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  return { dir, appDir, mirrorDir, key, oldKey, template: small };
}
