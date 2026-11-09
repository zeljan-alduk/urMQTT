// Encryption at rest for the page's secrets (NOW-16, ADR-300). Everything the user typed or loaded that must not
// be readable by someone who finds the file or the browser profile (private keys, account password hashes, the
// signing key, the whole form) is sealed here before it is exported or kept in browser storage. Web Crypto only:
// PBKDF2-HMAC-SHA-256 (600 000 rounds, random 16-byte salt) derives a non-extractable AES-256-GCM key; each seal
// uses a fresh random 12-byte nonce; the envelope header is authenticated as additional data. The passphrase
// is never stored, never put in the address and never sent anywhere. No DOM here: the Node tests run this file.
import { emptyState, isListType, isUserList, PRESETS } from './core.js';

export const ENVELOPE_FORMAT = 'urmqtt-project';
export const ENVELOPE_VERSION = 1;
export const KDF_NAME = 'PBKDF2-HMAC-SHA256';
export const CIPHER_NAME = 'AES-256-GCM';
export const KDF_ITERATIONS = 600000;
/** What an opened envelope may ask for (a hostile file must not make the page hang for minutes). */
export const KDF_MIN_ITERATIONS = 200000;
export const KDF_MAX_ITERATIONS = 5000000;
export const MIN_PASSPHRASE = 12;
export const MAX_ENVELOPE_BYTES = 8 * 1024 * 1024;
const SALT_LEN = 16;
const IV_LEN = 12;
const PAD = 4096;          // the plaintext is padded to a multiple of this, so the size says little
const SNAPSHOT_VERSION = 1;

/** An error with a code the page translates: weak, format, version, params, auth, snapshot. */
export class VaultError extends Error {
  constructor(code, message) { super(message || code); this.name = 'VaultError'; this.code = code; }
}

const vaultEnc = new TextEncoder();
const vaultDec = new TextDecoder('utf-8', { fatal: true });

export function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new VaultError('format', 'not base64');
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** The passphrase as bytes: Unicode NFKC, so the same word typed on another keyboard or system is the same key. */
const passphraseBytes = p => vaultEnc.encode(String(p).normalize('NFKC'));

/** The header text that is authenticated with the data: a changed round count or label fails the tag. */
const headerAad = (iterations, salt) => vaultEnc.encode([ENVELOPE_FORMAT, ENVELOPE_VERSION, KDF_NAME, iterations, CIPHER_NAME, toB64(salt)].join('\n'));

async function deriveKey(passphrase, salt, iterations) {
  const pw = passphraseBytes(passphrase);
  try {
    const base = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    pw.fill(0);
  }
}

/** Seals a JSON-able value into the envelope text (a JSON document). `iterations` is for tests only. */
export async function sealValue(passphrase, value, { iterations = KDF_ITERATIONS } = {}) {
  if (typeof passphrase !== 'string' || [...passphrase.normalize('NFKC')].length < MIN_PASSPHRASE) throw new VaultError('weak', 'passphrase too short');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const json = vaultEnc.encode(JSON.stringify(value));
  const plain = new Uint8Array(Math.ceil((json.length + 1) / PAD) * PAD).fill(0x20); // trailing spaces: JSON ignores them
  plain.set(json);
  const key = await deriveKey(passphrase, salt, iterations);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: headerAad(iterations, salt), tagLength: 128 }, key, plain));
  plain.fill(0);
  json.fill(0);
  return JSON.stringify({
    format: ENVELOPE_FORMAT, version: ENVELOPE_VERSION, kdf: KDF_NAME, iterations, salt: toB64(salt),
    cipher: CIPHER_NAME, iv: toB64(iv), data: toB64(data),
  }, null, 2) + '\n';
}

/** Checks the shape of an envelope without any key: returns its parts or throws VaultError(format | version | params). */
export function parseEnvelope(text) {
  if (typeof text !== 'string' || text.length > MAX_ENVELOPE_BYTES * 1.4) throw new VaultError('format', 'size');
  let e;
  try { e = JSON.parse(text); } catch { throw new VaultError('format', 'not JSON'); }
  if (!e || typeof e !== 'object' || Array.isArray(e) || e.format !== ENVELOPE_FORMAT) throw new VaultError('format', 'not a project file');
  const keys = Object.keys(e).sort().join(',');
  if (keys !== 'cipher,data,format,iterations,iv,kdf,salt,version') throw new VaultError('format', 'fields');
  if (e.version !== ENVELOPE_VERSION) throw new VaultError('version', String(e.version));
  if (e.kdf !== KDF_NAME || e.cipher !== CIPHER_NAME) throw new VaultError('params', 'algorithm');
  if (!Number.isInteger(e.iterations) || e.iterations < KDF_MIN_ITERATIONS || e.iterations > KDF_MAX_ITERATIONS) throw new VaultError('params', 'iterations');
  const salt = fromB64(e.salt);
  const iv = fromB64(e.iv);
  const data = fromB64(e.data);
  if (salt.length !== SALT_LEN || iv.length !== IV_LEN) throw new VaultError('format', 'salt or nonce length');
  if (data.length < 16 + PAD || data.length > MAX_ENVELOPE_BYTES || (data.length - 16) % PAD !== 0) throw new VaultError('format', 'data length');
  return { iterations: e.iterations, salt, iv, data };
}

/**
 * Opens an envelope: the value inside, or VaultError('auth') for a wrong passphrase or any change to the file
 * (the two cannot be told apart, on purpose).
 */
export async function openValue(passphrase, text) {
  const { iterations, salt, iv, data } = parseEnvelope(text);
  if (typeof passphrase !== 'string' || passphrase === '') throw new VaultError('auth', 'no passphrase');
  const key = await deriveKey(passphrase, salt, iterations);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: headerAad(iterations, salt), tagLength: 128 }, key, data));
  } catch { throw new VaultError('auth', 'wrong passphrase or damaged file'); }
  try {
    return JSON.parse(vaultDec.decode(plain));
  } catch { throw new VaultError('snapshot', 'plaintext is not JSON'); } finally { plain.fill(0); }
}

// --- what is sealed: the page's state ------------------------------------------------------------------------------

/** The state as a plain value to seal (a deep copy, so nothing aliases the live state). */
export function snapshotState(state) {
  return { snapshot: SNAPSHOT_VERSION, state: JSON.parse(JSON.stringify(state)) };
}

const vStr = (v, max) => (typeof v === 'string' && v.length <= max ? v : null);

function vFileItem(x) {
  if (!x || typeof x !== 'object') return null;
  const pem = vStr(x.pem, 200000), summary = vStr(x.summary, 1000);
  return pem !== null && summary !== null ? { pem, summary } : null;
}

/**
 * A state built from an opened snapshot, field by field: unknown fields are dropped and every value is checked
 * for its type, so a snapshot from a newer or hostile page cannot put a strange object into the form.
 * Throws VaultError('snapshot') if it is not a snapshot of this version.
 */
export function stateFromSnapshot(model, snap) {
  if (!snap || typeof snap !== 'object' || snap.snapshot !== SNAPSHOT_VERSION || !snap.state || typeof snap.state !== 'object') throw new VaultError('snapshot', 'version');
  const src = snap.state;
  const s = emptyState();
  for (const [id, v] of Object.entries(src.values && typeof src.values === 'object' ? src.values : {})) {
    const f = model.byId.get(id);
    if (!f) continue;
    if (isUserList(f)) {
      if (!Array.isArray(v)) continue;
      s.values[id] = v.slice(0, 1000).filter(u => u && typeof u === 'object').map(u => ({ id: vStr(u.id, 256) ?? '', hash: vStr(u.hash, 1000) ?? '' }));
    } else if (f.type === 'bool' ? typeof v === 'boolean'
      : f.type === 'enum' ? typeof v === 'string' && f.variants.includes(v)
        : isListType(f) ? Array.isArray(v) && v.length <= 10000 && v.every(x => typeof x === 'string')
          : typeof v === 'string') {
      // Same typing rules as an address (decodeHash): a value of the wrong type for its field never reaches the form.
      s.values[id] = isListType(f) ? v.slice() : v;
    }
  }
  const f = src.files && typeof src.files === 'object' ? src.files : {};
  s.files.cert = vFileItem(f.cert);
  s.files.key = vFileItem(f.key);
  s.files.control = vFileItem(f.control);
  s.files.operational = (Array.isArray(f.operational) ? f.operational : []).map(vFileItem).filter(Boolean).slice(0, 8);
  s.files.bootstrap = (Array.isArray(f.bootstrap) ? f.bootstrap : []).map(vFileItem).filter(Boolean).slice(0, 8);
  const g = src.signing;
  if (g && typeof g === 'object' && vStr(g.pem, 200000) !== null && vStr(g.publicKey, 200) !== null && vStr(g.signerId, 200) !== null && vStr(g.summary, 1000) !== null) {
    s.signing = { pem: g.pem, publicKey: g.publicKey, signerId: g.signerId, summary: g.summary };
  }
  s.name = (vStr(src.name, 40) ?? '');
  s.preset = typeof src.preset === 'string' && PRESETS[src.preset] ? src.preset : '';
  s.release = (vStr(src.release, 100) ?? '');
  if (typeof src.advanced === 'boolean') s.advanced = src.advanced;
  return s;
}

/** True if the state holds anything a passphrase should protect. */
export function hasSecrets(model, state) {
  if (state.files.key || state.signing) return true;
  return model.fields.some(f => isUserList(f) && (state.values[f.id] || []).some(u => u && (u.id || u.hash)));
}

/** A copy of the state without any secret: the private key, the signing key and the accounts. */
export function withoutSecrets(model, state) {
  const s = JSON.parse(JSON.stringify(state));
  s.files.key = null;
  s.signing = null;
  for (const f of model.fields) if (isUserList(f)) delete s.values[f.id];
  return s;
}
