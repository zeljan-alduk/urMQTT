// The builder's WebAssembly module (tools/builder/wasm, ADR-225) as a JavaScript
// object. Everything crosses as a buffer handle; see exports.rs. This file is
// used unchanged by the page and by the Node tests.

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

/** The interface version this file was written for (core::ABI_VERSION). */
export const ABI_VERSION = 1;

/**
 * Loads the module. `source` is a URL string, a Response (or promise of one),
 * an ArrayBuffer/Uint8Array, or a compiled WebAssembly.Module.
 */
export async function loadBuilder(source) {
  let instance;
  if (source instanceof WebAssembly.Module) {
    instance = await WebAssembly.instantiate(source, {});
  } else if (typeof source === 'string' || (source && typeof source.then === 'function') ||
             (typeof Response !== 'undefined' && source instanceof Response)) {
    const res = typeof source === 'string' ? fetch(source) : source;
    if (typeof WebAssembly.instantiateStreaming === 'function') {
      try {
        ({ instance } = await WebAssembly.instantiateStreaming(res, {}));
      } catch (e) {
        // A server that sends the wrong content type: fall back to the bytes.
        const r = typeof source === 'string' ? await fetch(source) : await res;
        ({ instance } = await WebAssembly.instantiate(await r.arrayBuffer(), {}));
      }
    } else {
      const r = await res;
      ({ instance } = await WebAssembly.instantiate(await r.arrayBuffer(), {}));
    }
  } else {
    ({ instance } = await WebAssembly.instantiate(source, {}));
  }
  const b = new Builder(instance);
  if (b.x.ub_abi_version() !== ABI_VERSION) {
    throw new Error('the builder module has another interface version than this page');
  }
  return b;
}

export class Builder {
  constructor(instance) {
    this.x = instance.exports;
    this.mem = this.x.memory;
  }

  /** The configuration format version the module reads and writes. */
  get formatVersion() { return this.x.ub_format_version(); }

  // --- buffers -------------------------------------------------------------

  /** A new zeroed buffer of `len` bytes; returns its handle (throws if out of memory). */
  alloc(len) {
    const h = this.x.ub_buf_new(len);
    if (!h) throw new Error('out of memory (' + len + ' bytes)');
    return h;
  }

  /** A live view of the buffer. Valid until the next call into the module. */
  view(h) {
    return new Uint8Array(this.mem.buffer, this.x.ub_buf_ptr(h), this.x.ub_buf_len(h));
  }

  /** Copies bytes (or a string, as UTF-8) into a new buffer. */
  put(data) {
    const bytes = typeof data === 'string' ? enc.encode(data) : data;
    const h = this.alloc(bytes.length);
    this.view(h).set(bytes);
    return h;
  }

  free(h) { if (h) this.x.ub_buf_free(h); }

  /** Copies the buffer out and frees it. */
  take(h) {
    const out = this.view(h).slice();
    this.free(h);
    return out;
  }

  takeText(h) {
    const out = dec.decode(this.view(h));
    this.free(h);
    return out;
  }

  /** The reason the last call failed. */
  error() {
    const h = this.x.ub_error();
    return h ? this.takeText(h) : 'unknown error';
  }

  /** Runs `fn` with temporary buffers for `inputs`, frees them, returns fn's result. */
  with(inputs, fn) {
    const hs = inputs.map(i => (i === null || i === undefined ? 0 : this.put(i)));
    try { return fn(...hs); } finally { hs.forEach(h => this.free(h)); }
  }

  /** Calls a function that returns a text buffer handle; throws Error(reason) on 0. */
  text(h) {
    if (!h) throw new Error(this.error());
    return this.takeText(h);
  }

  json(h) { return JSON.parse(this.text(h)); }

  bytes(h) {
    if (!h) throw new Error(this.error());
    return this.take(h);
  }

  // --- schema and configuration -------------------------------------------

  schema() { return this.json(this.x.ub_schema()); }
  defaultToml() { return this.text(this.x.ub_default_toml()); }

  /**
   * Packs a configuration. `toml` is the text, `files` maps the names the TOML
   * uses to bytes or text, `env` an optional environment name, `now` the clock
   * in Unix seconds, `signPem` an optional Ed25519 PKCS#8 private key (PEM).
   * Returns {ok: true, blob} or {ok: false, errors: [{path, message}]}.
   */
  pack({ toml, files = {}, env = null, now, signPem = null }) {
    this.x.ub_file_clear();
    const held = [];
    try {
      for (const [name, data] of Object.entries(files)) {
        const n = this.put(name), d = this.put(data);
        held.push(n, d);
        if (!this.x.ub_file_put(n, d)) throw new Error(this.error());
      }
      const t = this.put(toml);
      held.push(t);
      const e = env === null ? 0 : this.put(env);
      held.push(e);
      const s = signPem === null ? 0 : this.put(signPem);
      held.push(s);
      const h = this.x.ub_pack(t, e, now, s);
      if (!h) {
        let errors;
        try { errors = JSON.parse(this.error()); } catch { errors = [{ path: '', message: 'internal error' }]; }
        return { ok: false, errors };
      }
      return { ok: true, blob: this.take(h) };
    } finally {
      held.forEach(h => this.free(h));
      this.x.ub_file_clear();
    }
  }

  blobInfo(blob) { return this.with([blob], b => this.json(this.x.ub_blob_info(b))); }
  describeAll(blob) { return this.with([blob], b => this.text(this.x.ub_describe_all(b))); }
  tomlToJson(text) { return this.with([text], t => this.json(this.x.ub_toml_to_json(t))); }

  // --- certificates and keys ---------------------------------------------------

  certInfo(pem) { return this.with([pem], p => this.json(this.x.ub_cert_info(p))); }
  keyInfo(pem) { return this.with([pem], p => this.json(this.x.ub_key_info(p))); }
  crossCheck(certPem, keyPem, caPem) {
    return this.with([certPem, keyPem, caPem], (c, k, a) => this.json(this.x.ub_cross_check(c, k, a)));
  }
  controlKey(pem) { return this.with([pem], p => this.json(this.x.ub_control_key(p))); }
  newSigningKey(seed) { return this.with([seed], s => this.json(this.x.ub_new_signing_key(s))); }
  signingKeyInfo(pem) { return this.with([pem], p => this.json(this.x.ub_signing_key_info(p))); }

  // --- releases --------------------------------------------------------------

  verifyRelease(pubkey, sums, sig) {
    return this.with([pubkey, sums, sig], (p, s, g) => this.json(this.x.ub_verify_release(p, s, g)));
  }
  minisignKeyId(pubkey) { return this.with([pubkey], p => this.text(this.x.ub_minisign_key_id(p))); }

  /** SHA-256 of a buffer handle or bytes, as lower-case hex. */
  sha256Hex(data) {
    const own = typeof data === 'number' ? 0 : this.put(data);
    try {
      return hex(this.bytes(this.x.ub_sha256(own || data)));
    } finally { this.free(own); }
  }

  blake2bHex(data) {
    const own = typeof data === 'number' ? 0 : this.put(data);
    try {
      return hex(this.bytes(this.x.ub_blake2b(own || data)));
    } finally { this.free(own); }
  }

  // --- the image -------------------------------------------------------------

  /** Probes the template held in buffer `iso` (a handle). */
  isoProbe(iso) { return this.json(this.x.ub_iso_probe(iso)); }

  /** Writes `blob` into the template held in buffer handle `iso`, in place. */
  isoConfigure(iso, blob) {
    return this.with([blob], b => this.text(this.x.ub_iso_configure(iso, b)));
  }

  isoVerify(iso) { return this.text(this.x.ub_iso_verify(iso)); }
}

export function hex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
