// Releases: the list the mirror publishes (releases.json), the check of a
// release's SHA256SUMS signature against the key embedded in this page, and the
// download of the template into WebAssembly memory. The mirror is not trusted:
// everything it serves is checked here (docs/PLAN.md C1e, ADR-227).

/** The release signing key (minisign.pub of the repository), put in at build time. */
const RELEASE_PUBKEY = __RELEASE_PUBKEY__;
/** The configuration format this build of the module reads. */
const SUPPORTED_FORMAT = __FORMAT_VERSION__;

/** Why a release cannot be used, as the text key shown next to it (or ''). */
function releaseProblem(r) {
  if (r.status === 'removed') return 'release.removed';
  if (!r.template) {
    if (r.reason === 'verification-failed') return 'release.unverified';
    if (r.reason === 'no-config-slot') return 'release.no-slot';
    return 'release.no-template';
  }
  if (!r.sums) return 'release.no-signature';
  if (r.template.config_format > SUPPORTED_FORMAT || r.template.config_format < 1) return 'release.format-unsupported';
  if (r.status !== 'ok' || r.verified === false) return 'release.unverified';
  return '';
}

/** Loads and normalises releases.json. */
async function loadReleases(url) {
  const res = await fetch(url, { cache: 'no-cache', credentials: 'omit' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  if (!j || j.schema !== 1 || !Array.isArray(j.releases)) throw new Error('not a releases.json of schema 1');
  const releases = j.releases.map(r => ({ ...r, usable: releaseProblem(r) === '', problem: releaseProblem(r) }));
  // Where the releases are published, for a link: only a GitHub address is ever shown as one.
  const source = typeof j.source === 'string' && /^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/releases\/?$/.test(j.source) ? j.source : '';
  return { generated: j.generated, keyId: j.key_id, source, releases };
}

/** Newest stable release with a usable template, else newest pre-release with one. */
function defaultRelease(releases) {
  const usable = releases.filter(r => r.usable);
  return usable.find(r => !r.prerelease) || usable[0] || null;
}

/** A URL under the directory that holds releases.json. */
const mirrorUrl = (base, path) => new URL(path, base).href;

/**
 * Fetches SHA256SUMS and its signature and verifies them with the embedded key.
 * Returns {ok, keyId, trustedComment, templateSha256, error}; never throws.
 */
async function verifyRelease(builder, base, release, signal) {
  const out = { ok: false, keyId: '', trustedComment: '', templateSha256: '', error: '', files: [] };
  try {
    const [sums, sig] = await Promise.all([
      fetchBytes(mirrorUrl(base, release.sums.path), signal),
      fetchBytes(mirrorUrl(base, release.sums.sig_path), signal),
    ]);
    const v = builder.verifyRelease(RELEASE_PUBKEY, sums, new TextDecoder().decode(sig));
    out.keyId = v.key_id;
    out.trustedComment = v.trusted_comment;
    out.files = v.files;
    const entry = v.files.find(f => f.name === release.template.file);
    if (!entry) throw new Error(`SHA256SUMS does not list ${release.template.file}`);
    out.templateSha256 = entry.sha256;
    if (release.template.sha256 && release.template.sha256 !== entry.sha256) {
      throw new Error('the mirror lists another SHA-256 for the template than the signed SHA256SUMS');
    }
    out.ok = true;
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    out.error = e.message || String(e);
  }
  return out;
}

async function fetchBytes(url, signal) {
  const res = await fetch(url, { signal, credentials: 'omit', cache: 'no-cache' });
  if (!res.ok) throw new Error(`${url.split('/').slice(-2).join('/')}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Downloads the template into a buffer of the module (no copy in JavaScript).
 * `onProgress(received, total)`; `signal` cancels. Returns the buffer handle.
 */
async function downloadTemplate(builder, url, expectedSize, onProgress, signal) {
  const res = await fetch(url, { signal, credentials: 'omit' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const header = Number(res.headers.get('content-length')) || 0;
  const total = expectedSize || header;
  if (!total) throw new Error('the size of the template is not known');
  if (header && expectedSize && header !== expectedSize && !res.headers.get('content-encoding')) {
    throw new Error(`the server sends ${header} bytes, the release list says ${expectedSize}`);
  }
  const buf = builder.alloc(total);
  try {
    let got = 0;
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (got + value.length > total) throw new Error('the download is larger than the release list says');
      builder.view(buf).set(value, got);
      got += value.length;
      onProgress(got, total);
    }
    if (got !== total) throw new Error(`the download ended after ${got} of ${total} bytes`);
    return buf;
  } catch (e) {
    builder.free(buf);
    throw e;
  }
}
