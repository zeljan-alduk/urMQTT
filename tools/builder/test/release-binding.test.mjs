// The release checks of the page (web/src/release.js) without a browser: the real module verifies
// signatures made with THROWAWAY keys, and the key ring is the one the page is built with, its keys
// replaced by the throwaway ones (as tools/builder/test/fixture-site.mjs does).
//
// Security review of v0.6.0:
// - SUPPLY-2: the tag a mirror claims for a release must be the tag its signature covers (the trusted
//   comment `urMQTT <tag> release <commit>`), or the signed SHA256SUMS of an older release (with its
//   known flaws) is offered, verified and labelled as the newest one.
// - SUPPLY-4: the release's GitHub and attestation links from releases.json are shown only when they
//   are that release's pages on github.com.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { loadBuilder } from '../web/src/wasm.js';
import { HERE, WASM, haveWasm } from './helpers.mjs';
import { minisignSignature, newKey } from './mirror-fixture.mjs';

if (!haveWasm()) {
  console.log(`skipped: needs ${WASM} (make builder)`);
  process.exit(0);
}

const builder = await loadBuilder(readFileSync(WASM));
const release = newKey();
const formerTest = newKey();
const KEYS = [
  { name: 'release', keyId: release.idText, text: release.publicText, file: 'minisign.pub', validFrom: 'v0.4.2', validTo: null, formerTest: false, pinned: {} },
  { name: 'test', keyId: formerTest.idText, text: formerTest.publicText, file: 'keys/minisign-test.pub', validFrom: 'v0.1.0', validTo: 'v0.4.1', formerTest: true, pinned: {} },
];

/** release.js as the bundle puts it in the page, with `fetch` given. */
function loadReleaseJs(fetchImpl) {
  const src = readFileSync(join(HERE, '../web/src/release.js'), 'utf8')
    .split('__RELEASE_KEYS__').join(JSON.stringify(KEYS))
    .split('__FORMAT_VERSION__').join('99');
  // eslint-disable-next-line no-new-func
  return new Function('fetch', `'use strict';\n${src}\nreturn { verifyWithKeys, loadReleases, commentTag };`)(fetchImpl);
}

const enc = s => new TextEncoder().encode(s);
const sums = enc('1111111111111111111111111111111111111111111111111111111111111111  urmqtt-template-v0.5.0-universal.iso\n');

test('a signed v0.5.0 offered as v0.6.0 is refused (SUPPLY-2)', () => {
  const { verifyWithKeys } = loadReleaseJs(null);
  const sig = minisignSignature(release, Buffer.from(sums), 'urMQTT v0.5.0 release 0123456789abcdef');
  // Its own tag: verified.
  const { v } = verifyWithKeys(builder, 'v0.5.0', sums, sig);
  assert.equal(v.trusted_comment, 'urMQTT v0.5.0 release 0123456789abcdef');
  // Another tag the key may sign: refused, whatever the mirror says.
  assert.throws(() => verifyWithKeys(builder, 'v0.6.0', sums, sig), /the signature is for v0\.5\.0, not v0\.6\.0/);
  for (const other of ['v0.5.0-rc.1', 'v0.5', '0.5.0', 'v0.5.00']) {
    assert.throws(() => verifyWithKeys(builder, other, sums, sig), /the signature is for/, other);
  }
  // A comment that names no tag cannot be bound to one.
  const bare = minisignSignature(release, Buffer.from(sums), 'timestamp:0\tfile:SHA256SUMS');
  assert.throws(() => verifyWithKeys(builder, 'v0.5.0', sums, bare), /the signature is for no release tag, not v0\.5\.0/);
  // A file from the computer (no tag claimed): the signed tag counts, and the key's range applies to it.
  assert.equal(verifyWithKeys(builder, null, sums, sig).key.name, 'release');
  const old = minisignSignature(release, Buffer.from(sums), 'urMQTT v0.4.1 release x');
  assert.throws(() => verifyWithKeys(builder, null, sums, old), /v0\.4\.2 and later only, not for v0\.4\.1/);
  // The former test key's comments (`urMQTT v0.4.1 dev <commit>`) bind the same way.
  const dev = minisignSignature(formerTest, Buffer.from(sums), 'urMQTT v0.4.1 dev 0123');
  assert.equal(verifyWithKeys(builder, 'v0.4.1', sums, dev).key.name, 'test');
  assert.throws(() => verifyWithKeys(builder, 'v0.4.0', sums, dev), /the signature is for v0\.4\.1, not v0\.4\.0/);
});

test('release links are shown only when they are the release\'s GitHub pages (SUPPLY-4)', async () => {
  const doc = {
    schema: 1, source: 'https://github.com/zeljan-alduk/urMQTT/releases', key_id: release.idText,
    releases: [
      { tag: 'v0.6.0', url: 'https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.6.0', attestations: 'https://github.com/zeljan-alduk/urMQTT/attestations' },
      { tag: 'v0.5.0', url: 'javascript:alert(1)', attestations: 'https://github.com.evil.example/zeljan-alduk/urMQTT/attestations' },
      { tag: 'v0.4.2', url: 'https://github.com/someone-else/urMQTT/releases/tag/v0.4.2', attestations: 'https://evil.example/attestations' },
      { tag: 'v0.4.1', url: 'https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.4.0', attestations: 'https://github.com/zeljan-alduk/urMQTT/attestations/../../x' },
      { tag: 'v0.4.0', url: 42, attestations: null },
    ],
  };
  const fetchImpl = async () => ({ ok: true, json: async () => doc });
  const { loadReleases } = loadReleaseJs(fetchImpl);
  const got = await loadReleases('https://mirror.example/releases.json');
  assert.deepEqual(got.releases.map(r => [r.tag, r.url, r.attestations]), [
    ['v0.6.0', 'https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.6.0', 'https://github.com/zeljan-alduk/urMQTT/attestations'],
    ['v0.5.0', '', ''],
    ['v0.4.2', '', ''],
    ['v0.4.1', '', ''],
    ['v0.4.0', '', ''],
  ]);
  // Without a valid source, any github.com repository's own pages are still links.
  doc.source = 'https://evil.example/releases';
  const loose = await loadReleases('https://mirror.example/releases.json');
  assert.equal(loose.source, '');
  assert.equal(loose.releases[0].url, 'https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.6.0');
  assert.equal(loose.releases[1].url, '');
});
