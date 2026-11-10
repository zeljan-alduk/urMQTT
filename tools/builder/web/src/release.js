// Releases: the list the mirror publishes (releases.json), the check of a
// release's SHA256SUMS signature against the key embedded in this page, and the
// download of the template into WebAssembly memory. The mirror is not trusted:
// everything it serves is checked here (docs/PLAN.md C1e, ADR-227).

/**
 * The release signing keys, put in at build time from keys/release-keys.json:
 * [{name, keyId, text, file, validFrom, validTo, formerTest, pinned}]. Each key is
 * trusted for the tags in its range only (and a key with pins only for the
 * SHA256SUMS whose SHA-256 is pinned for the tag): the former test key for the releases
 * it signed (v0.1.0 to v0.4.1), the release key for every later one. A signature
 * is checked with the key it names; an unknown key, or a key outside its range,
 * is a failed check.
 */
const RELEASE_KEYS = __RELEASE_KEYS__;
/** The configuration format this build of the module reads. */
const SUPPORTED_FORMAT = __FORMAT_VERSION__;

/** `v1.2.3` (also `1.2.3`, `v1.2.3-rc.1`) as [1, 2, 3]; anything else as null. */
function tagVersion(tag) {
  const m = /^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:[-+][0-9A-Za-z.+-]*)?$/.exec(String(tag || ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

/** Whether `key` may sign `tag`. A key with a range signs only tags that parse as versions inside it. */
function keyCovers(key, tag) {
  if (!key.validFrom && !key.validTo) return true;
  const v = tagVersion(tag);
  if (!v) return false;
  if (key.validFrom && compareVersions(v, tagVersion(key.validFrom)) < 0) return false;
  if (key.validTo && compareVersions(v, tagVersion(key.validTo)) > 0) return false;
  return true;
}

/** The key new releases are signed with (else the first key: a page built before the owner set it). */
function currentKey() {
  return RELEASE_KEYS.find(k => !k.formerTest) || RELEASE_KEYS[0] || null;
}

/** True when only the former test key may have signed `tag` (v0.1.0 to v0.4.1). */
function signedWithTestKey(tag) {
  const keys = RELEASE_KEYS.filter(k => keyCovers(k, tag));
  return keys.length > 0 && keys.every(k => k.formerTest);
}

/** The tag a trusted comment names (`urMQTT v0.4.1 dev <commit>`), or ''. */
function commentTag(comment) {
  const m = /^urMQTT (\S+)/.exec(String(comment || ''));
  return m ? m[1] : '';
}

/**
 * Verifies `sig` over `sums` with the key the signature names, and checks that
 * the key may sign `tag` (for a file from the computer, `tag` is null and the
 * tag of the signed comment counts). Returns {v, key}; throws with the reason.
 */
function verifyWithKeys(builder, tag, sums, sig) {
  const id = builder.minisigKeyId(sig);
  const key = RELEASE_KEYS.find(k => k.keyId === id);
  if (!key) throw new Error(`SHA256SUMS.minisig was made with key ${id}, which this page does not trust (it trusts ${RELEASE_KEYS.map(k => k.keyId).join(', ')})`);
  const v = builder.verifyRelease(key.text, sums, sig);
  const signedTag = commentTag(v.trusted_comment);
  // The tag the mirror claims is not trusted: the signature must be for that tag (its trusted
  // comment, `urMQTT <tag> release <commit>`), or the signed SHA256SUMS of an older release could be
  // offered as a newer one (security review of v0.6.0, SUPPLY-2, ADR-381).
  if (tag && signedTag !== tag) {
    throw new Error(`the signature is for ${signedTag || 'no release tag'}, not ${tag} (trusted comment "${v.trusted_comment}"): the mirror offers another release under this tag`);
  }
  const forTag = tag || signedTag;
  const who = `key ${id}${key.formerTest ? ", the project's former test key," : ''}`;
  if (!keyCovers(key, forTag)) {
    const range = key.validTo ? `${key.validFrom || 'the first release'} to ${key.validTo}` : `${key.validFrom} and later`;
    throw new Error(`${who} is trusted for ${range} only, not for ${forTag || 'a release without a version'}`);
  }
  // A pinned key (the former test key) signs only the SHA256SUMS whose SHA-256 is pinned for the tag:
  // a valid signature on other bytes is a forgery made with the leaked key.
  const pins = key.pinned || {};
  if (Object.keys(pins).length) {
    const want = Object.prototype.hasOwnProperty.call(pins, forTag) ? pins[forTag] : '';
    if (!want) throw new Error(`${who} signs only its pinned releases, and ${forTag || 'this file'} is not one of them`);
    const got = builder.sha256Hex(sums);
    if (got !== want) throw new Error(`SHA256SUMS of ${forTag} has SHA-256 ${got}, but the page pins ${want} for it: this is not the published file`);
  }
  return { v, key };
}

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

/**
 * `link` if it is `https://github.com/<owner>/<repo>/<page>` (with `/<tag>` appended for a tag page,
 * the tag percent-encoded or not) and, when the list names its GitHub source, of that repository; else ''.
 */
function releaseLink(link, source, page, tag) {
  if (typeof link !== 'string') return '';
  const m = /^https:\/\/github\.com\/([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+)\/(.*)$/.exec(link);
  if (!m) return '';
  if (source && !source.startsWith(`https://github.com/${m[1]}/`)) return '';
  if (tag === null) return m[2] === page || m[2] === page + '/' ? link : '';
  if (typeof tag !== 'string' || !tag) return '';
  return m[2] === page + tag || m[2] === page + encodeURIComponent(tag) ? link : '';
}

/** Loads and normalises releases.json. */
async function loadReleases(url) {
  const res = await fetch(url, { cache: 'no-cache', credentials: 'omit' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  if (!j || j.schema !== 1 || !Array.isArray(j.releases)) throw new Error('not a releases.json of schema 1');
  // Where the releases are published, for a link: only a GitHub address is ever shown as one.
  const source = typeof j.source === 'string' && /^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/releases\/?$/.test(j.source) ? j.source : '';
  const releases = j.releases.map(r => {
    const out = { ...r, usable: releaseProblem(r) === '', problem: releaseProblem(r) };
    // The links of a release are shown as links only when they are its GitHub pages (security review of
    // v0.6.0, SUPPLY-4): a mirror cannot send the visitor to a look-alike "verification" page.
    out.url = releaseLink(r.url, source, 'releases/tag/', r.tag);
    out.attestations = releaseLink(r.attestations, source, 'attestations', null);
    return out;
  });
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
 * Fetches SHA256SUMS and its signature and verifies them with the embedded key
 * that signed them (verifyWithKeys). Returns {ok, keyId, key, trustedComment,
 * templateSha256, error}; never throws.
 */
async function verifyRelease(builder, base, release, signal) {
  const out = { ok: false, keyId: '', key: null, trustedComment: '', templateSha256: '', error: '', files: [] };
  try {
    const [sums, sig] = await Promise.all([
      fetchBytes(mirrorUrl(base, release.sums.path), signal),
      fetchBytes(mirrorUrl(base, release.sums.sig_path), signal),
    ]);
    const { v, key } = verifyWithKeys(builder, release.tag, sums, new TextDecoder().decode(sig));
    out.keyId = v.key_id;
    out.key = key;
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
