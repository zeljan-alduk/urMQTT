// The builder's logic without a DOM: the form model made from the exported
// schema, the state the user changes, the TOML that state stands for, the
// import of a TOML, presets, risks, and the URL hash. Used by the page and by
// the Node tests (ADR-226).
//
// Principle (docs/PLAN.md C1e): every field has a default, shown as the
// placeholder; a field the user does not touch is not written anywhere. The
// state holds only what the user changed.

/** TOML keys that name files; the page supplies their contents. */
export const FILE_KEYS = {
  'tls.cert': { slot: 'cert', file: 'server.pem' },
  'tls.key': { slot: 'key', file: 'server.key' },
  'trust.operational': { slot: 'operational', file: 'ca-%d.pem', list: true },
  'trust.bootstrap': { slot: 'bootstrap', file: 'bootstrap-%d.pem', list: true },
  'control.public_key': { slot: 'control', file: 'control.pub' },
  'tls.revoked_serials': { slot: 'revoked', file: 'revoked.txt' },
};

/** Fields the page does not offer. Disk encryption (S7, ADR-240) needs a key
 * dialog (generate, save, import) the page does not have yet; it is set with
 * `urmqtt-config pack` and the TOML (docs/OPERATE.md). */
export const HIDDEN = new Set(['storage.encryption', 'storage.disk_key']);

/** Section order of the form and which sections open by default. */
export const SECTION_ORDER = [
  'network', 'tls', 'trust', 'control', 'limits', 'acl', 'storage',
  'observability', 'time', 'watchdog', 'memory', 'registry', 'entropy', 'cpu',
  'console', 'devices', 'plaintext', 'websocket',
];

/** Examples shown as the placeholder of fields that have no default. */
export const EXAMPLES = {
  'network.address': '192.0.2.10/24',
  'network.gateway': '192.0.2.1',
  'observability.syslog_udp': '192.0.2.50:514',
  'observability.metrics_udp': '192.0.2.51:8125',
  'time.servers': '192.0.2.123',
  'plaintext.allow_from': '10.0.0.0/8',
  'plaintext.ip_identities': '10.0.1.0/24 plc',
  'websocket.origins': 'https://app.example.com',
};

/** Builds the form model from the exported schema. */
export function buildModel(schema) {
  const fields = [];
  const dev = [];
  for (const f of schema.fields) {
    if (f.derived) continue; // computed from the certificate, not chosen
    if (HIDDEN.has(f.key)) continue;
    const field = {
      ...f,
      id: f.key,
      // The TOML key differs for the revocation list (a file of serials).
      tomlKey: f.toml_key || f.key,
      fileKey: FILE_KEYS[f.key] || null,
      example: EXAMPLES[f.key] || '',
    };
    (f.dev_only ? dev : fields).push(field);
  }
  const bySection = new Map();
  for (const f of fields) {
    const s = f.section || '';
    if (!bySection.has(s)) bySection.set(s, []);
    bySection.get(s).push(f);
  }
  const sections = [...bySection.keys()]
    .filter(s => s !== '')
    .sort((a, b) => rank(a) - rank(b))
    .map(id => ({ id, fields: bySection.get(id) }));
  return {
    formatVersion: schema.format_version,
    slotSize: schema.slot_size,
    fields,
    devOnly: dev,
    sections,
    top: bySection.get('') || [],
    byId: new Map(fields.map(f => [f.id, f])),
    byToml: new Map(fields.map(f => [f.tomlKey, f])),
  };
}

function rank(section) {
  const i = SECTION_ORDER.indexOf(section);
  return i < 0 ? SECTION_ORDER.length : i;
}

// --- values ------------------------------------------------------------------

/** The default as text the way a person writes it (for placeholders). */
export function defaultText(f) {
  switch (f.type) {
    case 'bool': return f.default ? 'on' : 'off';
    case 'string_list': case 'socket_addr_list': return (f.default || []).join('\n');
    case 'pem': case 'pem_list': case 'ed25519_public_key': return '';
    default: return f.default === null || f.default === undefined ? '' : String(f.default);
  }
}

export const isListType = f => f.type === 'string_list' || f.type === 'socket_addr_list';
export const isFileType = f => f.type === 'pem' || f.type === 'pem_list' || f.type === 'ed25519_public_key';
/**
 * The accounts of a password listener (`plaintext.users`, P1; `websocket.users`, ADR-272): the state holds
 * `[{id, hash}]`, never a clear password; the TOML gets
 * `{ id = ..., password_hash = ... }` tables.
 */
export const isUserList = f => f.type === 'string_list' && f.item === 'user';
/** Networks and their identities (P1): lines `a.b.c.d/len id` in the state, `{ from, id }` tables in the TOML. */
export const isIpIdentityList = f => f.type === 'string_list' && f.item === 'ip_identity';

const PASSWORD_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/**
 * A random password of `length` characters from a-zA-Z0-9. Bytes come from
 * `crypto.getRandomValues`; a byte that would favour the first characters
 * (those at or above the largest multiple of 62 below 256) is thrown away.
 */
export function randomPassword(length = 20, random = n => crypto.getRandomValues(new Uint8Array(n))) {
  const n = PASSWORD_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = '';
  while (out.length < length) {
    for (const b of random(length * 2)) {
      if (b < limit && out.length < length) out += PASSWORD_ALPHABET[b % n];
    }
  }
  return out;
}

/** The entries of a user list that are complete (an id and a hash). */
export const completeUsers = v => (v || []).filter(u => u && String(u.id || '').trim() && String(u.hash || '').trim());

/** A hash that has the right shape and belongs to no password: stands in for a missing one while the form is checked (never built, never exported). */
export const DRAFT_HASH = 'pbkdf2-sha256$100000$' + '00'.repeat(16) + '$' + '00'.repeat(32);

/**
 * The rows of the accounts editor, as the validator should see them: every row
 * with an id, a row without a password carrying [DRAFT_HASH]. `rows[k]` is the
 * editor row of the validator's `plaintext.users[k]` (or `websocket.users[k]`).
 */
export function draftUsers(v) {
  const rows = [];
  const users = [];
  (v || []).forEach((u, i) => {
    const id = String((u && u.id) || '').trim();
    if (!id) return;
    rows.push(i);
    users.push({ id, hash: String(u.hash || '').trim() || DRAFT_HASH });
  });
  return { rows, users };
}

/** What blocks a build in the accounts editor: [{row, kind: 'password' | 'id'}]. Empty rows are ignored. */
export function userProblems(v) {
  const out = [];
  (v || []).forEach((u, i) => {
    const id = String((u && u.id) || '').trim();
    const hash = String((u && u.hash) || '').trim();
    if (id && !hash) out.push({ row: i, kind: 'password' });
    else if (!id && hash) out.push({ row: i, kind: 'id' });
  });
  return out;
}

/** Whether the user's raw value differs from the default (and so is written). */
export function isChanged(f, v) {
  if (v === undefined) return false;
  if (isUserList(f)) return (v || []).some(u => u && (String(u.id || '').trim() || String(u.hash || '').trim()));
  switch (f.type) {
    case 'bool': return v !== f.default;
    case 'uint': return String(v).trim() !== '' && Number(String(v).trim()) !== f.default;
    case 'enum': return v !== f.default;
    case 'string': return v !== f.default && String(v) !== '';
    case 'rate': return String(v).trim() !== '' && normRate(v) !== normRate(f.default);
    case 'string_list': case 'socket_addr_list': {
      const a = (v || []).map(s => String(s).trim()).filter(Boolean);
      const d = f.default || [];
      return JSON.stringify(a) !== JSON.stringify(d);
    }
    default: return String(v).trim() !== '';
  }
}

const normRate = r => String(r).replace(/\s+/g, '').toLowerCase();

/** A TOML basic string. */
export function tomlString(s) {
  let o = '"';
  for (const ch of String(s)) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += '\\"';
    else if (ch === '\\') o += '\\\\';
    else if (ch === '\n') o += '\\n';
    else if (ch === '\r') o += '\\r';
    else if (ch === '\t') o += '\\t';
    else if (c < 0x20 || c === 0x7f) o += '\\u' + c.toString(16).padStart(4, '0');
    else o += ch;
  }
  return o + '"';
}

/** Whether a number field holds a plain non-negative integer. */
export const isWholeNumber = v => /^\d{1,15}$/.test(String(v).trim());

/** One value as TOML text (a number field must pass [isWholeNumber]). */
export function tomlValue(f, v, draft = false) {
  if (isUserList(f)) {
    return '[' + (draft ? draftUsers(v).users : completeUsers(v)).map(u => `{ id = ${tomlString(String(u.id).trim())}, password_hash = ${tomlString(String(u.hash).trim())} }`).join(', ') + ']';
  }
  if (isIpIdentityList(f)) {
    return '[' + (v || []).map(s => String(s).trim()).filter(Boolean).map(line => {
      const [from, ...rest] = line.split(/\s+/);
      return `{ from = ${tomlString(from)}, id = ${tomlString(rest.join(' '))} }`;
    }).join(', ') + ']';
  }
  switch (f.type) {
    case 'bool': return v ? 'true' : 'false';
    case 'uint': return String(Number(String(v).trim()));
    case 'string_list': case 'socket_addr_list':
      return '[' + (v || []).map(s => String(s).trim()).filter(Boolean).map(tomlString).join(', ') + ']';
    default: return tomlString(String(v).trim());
  }
}

// --- state ---------------------------------------------------------------------

/** An empty state: everything at its default. */
export function emptyState() {
  return {
    values: {},          // field id -> raw value, only what the user changed
    files: {             // imported material; never leaves the page, never stored by key
      cert: null, key: null, control: null,
      operational: [], bootstrap: [],
    },
    signing: null,       // { pem, publicKey, signerId } (never stored)
    name: '',            // output file name part
    preset: '',          // preset id the state started from
    release: '',         // selected release tag
  };
}

export function changedIds(model, state) {
  const out = [];
  for (const f of model.fields) {
    if (!isApplicable(f, state)) continue;
    if (isFileType(f)) {
      if (fileIsSet(f, state)) out.push(f.id);
    } else if (f.id === 'tls.revoked_serials') {
      if ((state.values[f.id] || []).some(s => String(s).trim())) out.push(f.id);
    } else if (isChanged(f, state.values[f.id])) out.push(f.id);
  }
  return out;
}

export function fileIsSet(f, state) {
  const k = f.fileKey;
  if (!k) return false;
  const v = state.files[k.slot];
  return k.list ? (v || []).length > 0 : Boolean(v);
}

/** Names of the virtual files for a list slot: ca-1.pem, ca-2.pem ... */
export function listFileNames(slot, n) {
  const pattern = slot === 'operational' ? 'ca-%d.pem' : 'bootstrap-%d.pem';
  return Array.from({ length: n }, (_, i) => pattern.replace('%d', String(i + 1)));
}

/**
 * The TOML text and the files it names for a state. Only what differs from
 * the defaults is written.
 */
export function buildToml(model, state, { draft = false } = {}) {
  const top = [];
  const sections = new Map();
  let current = null;
  const add = (section, line) => {
    if (!sections.has(section)) sections.set(section, []);
    sections.get(section).push({ line, id: current });
  };
  const files = {};
  const local = {};
  for (const f of model.fields) {
    // A value left over from another network mode must not reach the validator.
    if (!isApplicable(f, state)) continue;
    const [section, name] = f.tomlKey.includes('.') ? f.tomlKey.split('.') : ['', f.tomlKey];
    current = f.id;
    const emit = text => (section ? add(section, `${name} = ${text}`) : top.push({ line: `${name} = ${text}`, id: f.id }));
    if (f.fileKey) {
      const slot = f.fileKey.slot;
      if (slot === 'revoked') {
        const serials = (state.values[f.id] || []).map(s => String(s).trim()).filter(Boolean);
        if (serials.length) {
          files['revoked.txt'] = serials.join('\n') + '\n';
          emit(tomlString('revoked.txt'));
        }
      } else if (f.fileKey.list) {
        const list = state.files[slot] || [];
        if (list.length) {
          const names = listFileNames(slot, list.length);
          list.forEach((item, i) => { files[names[i]] = item.pem; });
          emit('[' + names.map(tomlString).join(', ') + ']');
        }
      } else if (state.files[slot]) {
        files[f.fileKey.file] = state.files[slot].pem;
        emit(tomlString(f.fileKey.file));
      }
      continue;
    }
    const v = state.values[f.id];
    if (!isChanged(f, v)) continue;
    if (f.type === 'uint' && !isWholeNumber(v)) { local[f.id] = 'int'; continue; }
    if (f.type === 'enum' && !f.variants.includes(v)) { local[f.id] = 'enum'; continue; }
    emit(tomlValue(f, v, draft));
  }
  // Render, remembering which field each line belongs to so that a TOML
  // syntax or type error (which names a line, not a key) can be shown at its field.
  const out = [];
  const owners = [];
  const emitLine = (text, id) => { out.push(text); owners.push(id); };
  if (top.length) top.forEach(t => emitLine(t.line, t.id));
  for (const id of [...sections.keys()].sort((a, b) => rank(a) - rank(b))) {
    if (out.length) emitLine('', null);
    emitLine(`[${id}]`, null);
    sections.get(id).forEach(t => emitLine(t.line, t.id));
  }
  return { toml: out.length ? out.join('\n') + '\n' : '', files, owners, local };
}

/** Which field (if any) a validator problem is about. */
export function fieldForPath(model, path) {
  if (!path) return null;
  // "acl.device_publish[0]" names an entry of the list field.
  const key = path.replace(/\[\d+\](\.\w+)?$/, '');
  return model.byId.get(key) || model.byToml.get(key) || null;
}

// --- importing a TOML ------------------------------------------------------------

/**
 * Applies a parsed TOML (the JSON of `toml_to_json`) to a fresh state. Returns
 * {state, unknown: [keys not in the schema], needFiles: [{field, names}]}.
 * Files are not read here: the caller asks the user for `needFiles`.
 */
export function importToml(model, json, base = emptyState()) {
  const state = { ...base, values: {}, files: { ...base.files, operational: [], bootstrap: [] } };
  const unknown = [];
  const needFiles = [];
  const visit = (section, key, value) => {
    const full = section ? `${section}.${key}` : key;
    const f = model.byToml.get(full) || model.byId.get(full);
    if (!f) { unknown.push(full); return; }
    if (f.fileKey) {
      const names = Array.isArray(value) ? value : [value];
      const wanted = names.filter(n => typeof n === 'string' && n !== '');
      if (wanted.length) needFiles.push({ field: f.id, names: wanted });
      return;
    }
    state.values[f.id] = fromJson(f, value);
  };
  for (const [k, v] of Object.entries(json)) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      for (const [k2, v2] of Object.entries(v)) visit(k, k2, v2);
    } else visit('', k, v);
  }
  return { state, unknown, needFiles };
}

function fromJson(f, v) {
  if (isUserList(f)) {
    return (Array.isArray(v) ? v : []).filter(u => u && typeof u === 'object').map(u => ({ id: String(u.id ?? ''), hash: String(u.password_hash ?? '') }));
  }
  if (isIpIdentityList(f)) {
    return (Array.isArray(v) ? v : []).filter(e => e && typeof e === 'object').map(e => `${e.from ?? ''} ${e.id ?? ''}`.trim());
  }
  switch (f.type) {
    case 'bool': return Boolean(v);
    case 'string_list': case 'socket_addr_list': return Array.isArray(v) ? v.map(String) : [String(v)];
    default: return String(v);
  }
}

// --- presets ------------------------------------------------------------------

/** Presets are sets of changed values; everything else stays at the default. */
export const PRESETS = {
  lab: { values: { 'storage.diagnostic': true } },
  vps: { values: { 'network.mode': 'static', 'memory.kernel_heap_mb': '256' } },
  auto: { values: { 'network.mode': 'auto' } },
};

export function applyPreset(id) {
  const s = emptyState();
  s.preset = id;
  const p = PRESETS[id];
  if (p) s.values = { ...p.values };
  return s;
}

// --- visibility ----------------------------------------------------------------------

/** `[websocket]` keys that mean something only with `auth = "password"` (with mtls the broker's own limits and ACL apply). */
const WEBSOCKET_PASSWORD_ONLY = new Set([
  'websocket.users', 'websocket.max_packet_size', 'websocket.publish_rate_per_device',
  'websocket.max_failed_auths_per_ip', 'websocket.lockout_s', 'websocket.acl_publish',
  'websocket.acl_subscribe', 'websocket.retain',
]);

/** Whether a field applies given the network mode (static/auto fields). */
export function isApplicable(f, state) {
  const mode = state.values['network.mode'] || 'dhcp';
  if (f.id === 'network.address' || f.id === 'network.gateway') return mode !== 'dhcp';
  if (f.id === 'network.dhcp_timeout_s') return mode === 'auto';
  // The TLS listener is off (ADR-233): its certificate, its CAs, the control key and the revocations have no use.
  if (tlsOff(state) && (f.section === 'tls' || f.section === 'trust' || f.section === 'control')) return false;
  // Plaintext MQTT (P1): nothing but the switch while it is off; then what the mode uses.
  if (f.section === 'plaintext' && f.id !== 'plaintext.enabled') {
    if (state.values['plaintext.enabled'] !== true) return false;
    const auth = state.values['plaintext.auth'] || 'password';
    if (f.id === 'plaintext.users') return auth === 'password';
    if (f.id === 'plaintext.anonymous_identity') return auth === 'anonymous';
    if (f.id === 'plaintext.ip_identities') return auth === 'ip';
  }
  // MQTT over WebSocket (ADR-272): the same, and what only password logins use.
  if (f.section === 'websocket' && f.id !== 'websocket.enabled') {
    if (state.values['websocket.enabled'] !== true) return false;
    if (WEBSOCKET_PASSWORD_ONLY.has(f.id)) return (state.values['websocket.auth'] || 'mtls') === 'password';
  }
  return true;
}

/**
 * Whether an IPv4 address (`a.b.c.d`, or `a.b.c.d/len`) is one that is not
 * routed on the Internet: 10/8, 172.16/12, 192.168/16, 100.64/10 (carrier-grade
 * NAT), 169.254/16 (link-local) and 127/8 (loopback). Anything else, also a
 * text that is no address, is false.
 */
export function isPrivateAddress(text) {
  const m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d{1,2})?\s*$/.exec(String(text));
  if (!m) return false;
  const [a, b, c, d] = m.slice(1).map(Number);
  if ([a, b, c, d].some(x => x > 255)) return false;
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254);
}

// --- risks ---------------------------------------------------------------------------

/**
 * Combinations worth a second look. `info` is the `blobInfo` of the packed
 * configuration (or null). Each risk has an id (the page has a text for it)
 * and a level: "confirm" asks the user before the build, "note" only shows.
 */
export function evaluateRisks(model, state, info) {
  const risks = [];
  const val = id => {
    const f = model.byId.get(id);
    const v = state.values[id];
    return v === undefined ? f.default : v;
  };
  if (info && info.missing.length) risks.push({ id: 'cannot-serve', level: 'confirm', args: { missing: info.missing.join(', ') } });
  if (val('entropy.fallback') !== 'none') risks.push({ id: 'entropy-jitter', level: 'note' });
  if (val('storage.mode') === 'ram') risks.push({ id: 'ram-storage', level: 'confirm' });
  const wide = ['acl.device_publish', 'acl.device_subscribe'].filter(id => {
    const v = state.values[id];
    return v !== undefined && v.some(t => /^(#|\+\/#|\/#)$/.test(String(t).trim()));
  });
  if (wide.length) risks.push({ id: 'wide-acl', level: 'confirm', args: { keys: wide.join(', ') } });
  if (val('watchdog.action') === 'reset') risks.push({ id: 'watchdog-reset', level: 'note' });
  const disabled = state.values['cpu.disable'];
  if (disabled && disabled.some(s => String(s).trim())) risks.push({ id: 'cpu-disable', level: 'note' });
  const servers = val('time.servers');
  if (!servers || servers.length === 0) risks.push({ id: 'no-time', level: 'note' });
  if (!state.files.control) risks.push({ id: 'no-control', level: 'note' });
  if (val('registry.mode') === 'open') risks.push({ id: 'registry-open', level: 'note' });
  if (val('entropy.fallback') === 'none') risks.push({ id: 'entropy-none', level: 'note' });
  if (tlsOff(state)) risks.push({ id: 'tls-off', level: 'confirm' });
  if (val('plaintext.enabled')) {
    risks.push({ id: 'plaintext-on', level: 'confirm' });
    if (val('plaintext.allow_from_anywhere')) risks.push({ id: 'plaintext-anywhere', level: 'confirm' });
    if (val('plaintext.auth') === 'anonymous') risks.push({ id: 'plaintext-anonymous', level: 'note' });
    const mode = val('network.mode');
    const addr = String(state.values['network.address'] || '').trim();
    if ((mode === 'static' || mode === 'auto') && addr && !isPrivateAddress(addr)) {
      risks.push({ id: 'plaintext-public-address', level: 'confirm', args: { address: addr.split('/')[0] } });
    }
  }
  return risks;
}

/** The TLS listener is off: its port is 0 (ADR-233). */
export const tlsOff = state => String(state.values['network.mqtt_tls_port'] ?? '').trim() === '0';

// --- the URL hash -------------------------------------------------------------------

/**
 * Encodes what is safe to keep in the address bar: the release, the preset, the
 * name and the values the user changed. Never a certificate, a key or a signing
 * key; those live in memory only.
 */
export function encodeHash(model, state) {
  const v = {};
  for (const f of model.fields) {
    if (f.fileKey) continue;
    // The accounts hold password hashes: like a private key they are kept in
    // memory only, never in the address bar (which people copy and share).
    if (isUserList(f)) continue;
    if (state.values[f.id] !== undefined && isChanged(f, state.values[f.id])) v[f.id] = state.values[f.id];
  }
  const payload = { r: state.release || undefined, p: state.preset || undefined, n: state.name || undefined, a: state.advanced ? 1 : undefined, v: Object.keys(v).length ? v : undefined };
  const json = JSON.stringify(payload);
  if (json === '{}') return '';
  return '#s=' + b64url(new TextEncoder().encode(json));
}

/** Parses a hash made by [encodeHash]; unknown keys are dropped. */
export function decodeHash(model, hash) {
  const m = /^#s=([A-Za-z0-9_-]+)$/.exec(hash || '');
  if (!m) return null;
  let p;
  try { p = JSON.parse(new TextDecoder().decode(unb64url(m[1]))); } catch { return null; }
  if (!p || typeof p !== 'object') return null;
  const s = emptyState();
  s.release = typeof p.r === 'string' ? p.r.slice(0, 64) : '';
  s.preset = typeof p.p === 'string' && PRESETS[p.p] ? p.p : '';
  s.name = typeof p.n === 'string' ? p.n.slice(0, 40) : '';
  if (p.a) s.advanced = true;
  if (p.v && typeof p.v === 'object') {
    for (const [id, v] of Object.entries(p.v)) {
      const f = model.byId.get(id);
      if (!f || f.fileKey || isUserList(f)) continue; // hashes never come from an address
      if (f.type === 'bool' ? typeof v === 'boolean'
        : f.type === 'enum' ? f.variants.includes(v)
          : isListType(f) ? Array.isArray(v) && v.every(x => typeof x === 'string')
            : typeof v === 'string') s.values[id] = v;
    }
  }
  return s;
}

function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

// --- file names ------------------------------------------------------------------

/** `urmqtt-<ver>-<name>-universal.iso`, with the name made file-name safe. */
export function outputName(tag, name) {
  const clean = s => String(s).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 40);
  const ver = clean(String(tag).replace(/^v/i, '')) || 'x';
  const n = clean(name) || 'custom';
  return `urmqtt-${ver}-${n}-universal.iso`;
}

/** Splits a text area into trimmed non-empty lines. */
export const lines = text => String(text).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
