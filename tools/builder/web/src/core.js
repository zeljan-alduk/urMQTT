// The builder's logic without a DOM: the form model made from the exported
// schema, the state the user changes, the TOML that state stands for, the
// import of a TOML, presets, risks, and the URL hash. Used by the page and by
// the Node tests (ADR-221).
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

/** Section order of the form and which sections open by default. */
export const SECTION_ORDER = [
  'network', 'tls', 'trust', 'control', 'limits', 'acl', 'storage',
  'observability', 'time', 'watchdog', 'memory', 'registry', 'entropy', 'cpu',
];

/** Examples shown as the placeholder of fields that have no default. */
export const EXAMPLES = {
  'network.address': '192.0.2.10/24',
  'network.gateway': '192.0.2.1',
  'observability.syslog_udp': '192.0.2.50:514',
  'observability.metrics_udp': '192.0.2.51:8125',
  'time.servers': '192.0.2.123',
};

/** Builds the form model from the exported schema. */
export function buildModel(schema) {
  const fields = [];
  const dev = [];
  for (const f of schema.fields) {
    if (f.derived) continue; // computed from the certificate, not chosen
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

/** Whether the user's raw value differs from the default (and so is written). */
export function isChanged(f, v) {
  if (v === undefined) return false;
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
export function tomlValue(f, v) {
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
export function buildToml(model, state) {
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
    emit(tomlValue(f, v));
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
  const key = path.replace(/\[\d+\]$/, '');
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

/** Whether a field applies given the network mode (static/auto fields). */
export function isApplicable(f, state) {
  const mode = state.values['network.mode'] || 'dhcp';
  if (f.id === 'network.address' || f.id === 'network.gateway') return mode !== 'dhcp';
  if (f.id === 'network.dhcp_timeout_s') return mode === 'auto';
  return true;
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
  return risks;
}

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
    if (state.values[f.id] !== undefined && isChanged(f, state.values[f.id])) v[f.id] = state.values[f.id];
  }
  const payload = { r: state.release || undefined, p: state.preset || undefined, n: state.name || undefined, v: Object.keys(v).length ? v : undefined };
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
  if (p.v && typeof p.v === 'object') {
    for (const [id, v] of Object.entries(p.v)) {
      const f = model.byId.get(id);
      if (!f || f.fileKey) continue;
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
