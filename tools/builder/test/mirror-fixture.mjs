// A local stand-in for the release mirror on aldo.tech: releases.json and, per
// release, the template ISO, SHA256SUMS and its minisign signature, signed with
// a THROWAWAY key made here (never the real release key). The page under test
// is built with that key's public half (BUILDER_PUBKEY_TEXT).
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { FORMAT } from './helpers.mjs';

const b64 = buf => Buffer.from(buf).toString('base64');

/** A new throwaway minisign key pair. */
export function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const id = randomBytes(8);
  const idText = [...id].reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return {
    privateKey: createPrivateKey(privateKey.export({ format: 'pem', type: 'pkcs8' })),
    id,
    idText,
    publicText: `untrusted comment: minisign public key ${idText}\n${b64(Buffer.concat([Buffer.from('Ed'), id, raw]))}\n`,
  };
}

/** What `minisign -S` writes for `message` (the prehashed 'ED' algorithm). */
export function minisignSignature(key, message, trustedComment) {
  const digest = createHash('blake2b512').update(message).digest();
  const sig = sign(null, digest, key.privateKey);
  const global = sign(null, Buffer.concat([sig, Buffer.from(trustedComment)]), key.privateKey);
  return `untrusted comment: signature from minisign secret key\n${b64(Buffer.concat([Buffer.from('ED'), key.id, sig]))}\ntrusted comment: ${trustedComment}\n${b64(global)}\n`;
}

const sha256 = buf => createHash('sha256').update(buf).digest('hex');

/**
 * Writes a mirror directory. `releases`: [{tag, prerelease, template: Buffer|{path},
 * published}], newest first; a release with `template: null` has none (greyed).
 * `tamper`: tags whose ISO is altered after signing (to test the checks).
 */
export function writeMirror(dir, key, releases, { tamper = [] } = {}) {
  mkdirSync(dir, { recursive: true });
  const out = [];
  for (const r of releases) {
    const rel = {
      tag: r.tag, name: r.name || r.tag, published: r.published || '2026-11-01T10:00:00Z', prerelease: Boolean(r.prerelease),
      url: `https://github.com/zeljan-alduk/urMQTT/releases/tag/${r.tag}`,
      attestations: 'https://github.com/zeljan-alduk/urMQTT/attestations',
      status: 'ok', edited: false, template: null, sums: null, verified: true, reason: null, assets: [],
      mirrored_at: '2026-11-01T11:00:00Z', checked_at: '2026-11-01T12:00:00Z',
    };
    if (r.template) {
      const tdir = join(dir, r.tag);
      mkdirSync(tdir, { recursive: true });
      const file = `urmqtt-template-${r.tag}-universal.iso`;
      const bytes = Buffer.isBuffer(r.template) ? r.template : null;
      const content = bytes || readFileSync(r.template.path);
      const digest = sha256(content);
      const size = content.length;
      const sums = `${digest}  ${file}\n`;
      writeFileSync(join(tdir, 'SHA256SUMS'), sums);
      writeFileSync(join(tdir, 'SHA256SUMS.minisig'), minisignSignature(key, Buffer.from(sums), `urMQTT ${r.tag} test fixture`));
      const target = join(tdir, file);
      if (bytes) {
        const served = tamper.includes(r.tag) ? Buffer.from(bytes) : bytes;
        if (tamper.includes(r.tag)) served[served.length - 1] ^= 1;
        writeFileSync(target, served);
      } else if (!existsSync(target)) {
        try { symlinkSync(r.template.path, target); } catch { copyFileSync(r.template.path, target); }
      }
      rel.template = { file, path: `${r.tag}/${file}`, size, sha256: digest, config_format: r.format || FORMAT };
      rel.sums = { path: `${r.tag}/SHA256SUMS`, sig_path: `${r.tag}/SHA256SUMS.minisig` };
      rel.assets = [{ name: file, size, sha256: digest, mirrored: true, github_url: `https://github.com/zeljan-alduk/urMQTT/releases/download/${r.tag}/${file}` }];
    } else {
      rel.reason = 'no-template';
    }
    out.push(rel);
  }
  writeFileSync(join(dir, 'releases.json'), JSON.stringify({
    schema: 1, generated: '2026-11-01T12:00:00Z', repo: 'zeljan-alduk/urMQTT', source: 'https://github.com/zeljan-alduk/urMQTT/releases',
    key_id: key.idText, releases: out, templates: out.filter(x => x.template).length,
  }, null, 2));
  return out;
}
