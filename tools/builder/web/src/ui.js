// The page: layout, the release list, presets, the summary bar with the build
// button, the validation pipeline, persistence, and the dialogs that are not
// about certificates. Single page, no navigation: details open in modal dialogs.

const STORE_KEY = 'urmqtt-builder-v1';

const app = {
  el: null,          // root element
  base: '',          // URL of the directory the app's files are in
  releasesUrl: '',   // URL of releases.json
  v: {},             // content hashes of the app's files (for ?v= caching)
  lang: 'en',
  builder: null,     // the WebAssembly module
  schema: null,
  model: null,
  state: null,       // what the user changed (core.emptyState)
  releases: null,    // {generated, keyId, releases}
  release: null,     // the chosen release (or a local template)
  verify: null,      // result of verifying the chosen release's SHA256SUMS
  verifyState: 'idle',
  current: null,     // result of the last validation
  result: null,      // the last built image
  stale: false,      // the form changed after the last build
  busy: false,
  abort: null,
  local: null,       // {iso: File, sums, sig} when a local template was chosen
  ui: {},            // elements the update functions need
  nowUnix() {
    const floor = this.release && this.release.published ? Math.floor(Date.parse(this.release.published) / 1000) || 0 : 0;
    return Math.max(Math.floor(Date.now() / 1000), floor);
  },
};

/** Called by the form and the dialogs after any change to the state. */
app.onChange = () => {
  persist();
  app.stale = Boolean(app.result);
  scheduleRefresh();
  paintResult();
};

const scheduleRefresh = debounce(() => refresh(), 120);

// --- persistence --------------------------------------------------------------

/** What survives a reload: the hash (values, no files) and sessionStorage (public files). Never keys. */
function persist() {
  const s = app.state;
  try {
    const hash = encodeHash(app.model, s);
    history.replaceState(null, '', location.pathname + location.search + hash);
  } catch { /* some embedders forbid it */ }
  try {
    const pub = x => (x ? { pem: x.pem, summary: x.summary } : null);
    sessionStorage.setItem(STORE_KEY, JSON.stringify({
      v: 1, values: s.values, name: s.name, preset: s.preset, release: s.release,
      files: { cert: pub(s.files.cert), control: pub(s.files.control), operational: s.files.operational.map(pub), bootstrap: s.files.bootstrap.map(pub) },
    }));
  } catch { /* private window: the form simply starts empty after a reload */ }
}

function restore() {
  let s = decodeHash(app.model, location.hash);
  let saved = null;
  try { saved = JSON.parse(sessionStorage.getItem(STORE_KEY) || 'null'); } catch { saved = null; }
  if (!s && saved && saved.v === 1) {
    s = emptyState();
    for (const [id, v] of Object.entries(saved.values || {})) if (app.model.byId.has(id)) s.values[id] = v;
    s.name = String(saved.name || '').slice(0, 40);
    s.preset = saved.preset || '';
    s.release = saved.release || '';
  }
  s = s || emptyState();
  if (saved && saved.v === 1 && saved.files) {
    const ok = x => (x && typeof x.pem === 'string' && typeof x.summary === 'string' ? { pem: x.pem, summary: x.summary } : null);
    s.files.cert = ok(saved.files.cert);
    // The private key is never kept: after a reload the form says so instead of only complaining that the key is missing.
    app.keyForgotten = Boolean(s.files.cert);
    s.files.control = ok(saved.files.control);
    s.files.operational = (saved.files.operational || []).map(ok).filter(Boolean).slice(0, 8);
    s.files.bootstrap = (saved.files.bootstrap || []).map(ok).filter(Boolean).slice(0, 8);
  }
  app.state = s;
}

// --- validation ---------------------------------------------------------------------

function relationIssues() {
  const f = app.state.files;
  const out = { issues: [], lines: [] };
  if (!f.cert) return out;
  try {
    const x = app.builder.crossCheck(f.cert.pem, f.key ? f.key.pem : null, f.operational.length ? f.operational.map(c => c.pem).join('\n') : null);
    if (x.key_matches === true) out.lines.push(['ok', t('cert.key-matches')]);
    if (x.key_matches === false) {
      out.lines.push(['bad', t('cert.key-mismatch')]);
      out.issues.push({ field: app.model.byId.get('tls.key'), path: 'tls.key', message: t('cert.key-mismatch') });
    }
    if (f.operational.length && x.signers[0]) {
      out.lines.push(x.signers[0].by === 'ca' && x.signers[0].verified !== false ? ['ok', t('cert.signed-by-ca')] : ['info', t('cert.not-signed-by-ca')]);
    }
  } catch { /* the import dialog already showed what is wrong with the file */ }
  return out;
}

function refresh() {
  if (!app.builder) return;
  const built = buildToml(app.model, app.state);
  const res = app.builder.pack({
    toml: built.toml, files: built.files, now: app.nowUnix(),
    signPem: app.state.signing ? app.state.signing.pem : null,
  });
  const issues = [];
  for (const [id, code] of Object.entries(built.local)) {
    issues.push({ field: app.model.byId.get(id), path: id, message: t('err.' + code) });
  }
  let info = null;
  if (res.ok) info = app.builder.blobInfo(res.blob);
  else for (const e of res.errors) issues.push({ field: fieldForPath(app.model, e.path), path: e.path, message: e.message });
  const rel = relationIssues();
  issues.push(...rel.issues);
  app.current = { built, res, info, issues, relations: rel.lines, risks: evaluateRisks(app.model, app.state, info) };
  paintValidation();
}

function paintValidation() {
  const c = app.current;
  if (!c) return;
  const loose = showIssues(c.issues);
  // Lines about how certificate, key and CA fit together.
  const rel = app.ui.relations;
  if (rel) {
    clear(rel);
    c.relations.forEach(([k, text]) => rel.append(statusLine(k, text)));
  }
  const ui = app.ui;
  const problems = c.issues.length;
  const notes = c.risks.length;
  const noRelease = !app.release;
  let kind = 'ok';
  let text = t('bar.valid');
  if (problems) { kind = 'bad'; text = t('bar.problems', { n: problems }); }
  else if (noRelease) { kind = 'work'; text = t('bar.choose-release'); }
  setStatus(ui.status, kind, text);
  clear(ui.problems);
  c.issues.slice(0, 6).forEach(is => {
    const label = is.field ? `${is.field.name}: ${is.message}` : (is.path ? `${is.path}: ${is.message}` : is.message);
    ui.problems.append(h('li', {}, is.field
      ? h('button', { class: 'ub-link-btn', type: 'button', text: label, on: { click: () => focusField(is.field.id) } })
      : label));
  });
  ui.problems.hidden = problems === 0;
  clear(ui.notes);
  if (!problems) {
    c.risks.slice(0, 4).forEach(r => ui.notes.append(h('li', { text: riskTitle(r) })));
  }
  ui.notes.hidden = problems !== 0 || notes === 0;
  const changed = changedIds(app.model, app.state).length;
  ui.changed.textContent = t('bar.changed', { n: changed });
  ui.fingerprint.hidden = !c.info;
  if (c.info) ui.fingerprintValue.textContent = groupHex(c.info.fingerprint.slice(0, 32), 8) + '…';
  ui.build.disabled = app.busy || noRelease;
  ui.buildHint.textContent = noRelease ? t('bar.choose-release') : '';
  if (loose.length === 0) ui.loose.hidden = true;
  else {
    clear(ui.loose);
    loose.forEach(is => ui.loose.append(h('li', { text: is.path ? `${is.path}: ${is.message}` : is.message })));
    ui.loose.hidden = false;
  }
}

function setStatus(el, kind, text) {
  el.className = `ub-bar-status ${kind}`;
  clear(el);
  el.append(icon(kind === 'ok' ? 'check' : kind === 'bad' ? 'alert' : 'info'), h('span', { text }));
}

// --- release card -------------------------------------------------------------------

function renderReleases() {
  const box = app.ui.releaseBox;
  clear(box);
  const r = app.releases;
  if (app.releaseError) {
    box.append(h('div', { class: 'ub-banner err', role: 'alert' },
      h('p', { text: t('release.failed', { reason: app.releaseError }) }),
      h('p', { class: 'ub-help', text: t('release.failed-help') }),
      h('div', { class: 'ub-row' },
        h('button', { class: 'ub-btn small', type: 'button', text: t('common.retry'), on: { click: () => loadReleaseList() } }),
        h('button', { class: 'ub-btn small secondary', type: 'button', text: t('release.local'), on: { click: () => openLocalDialog() } }))));
    return;
  }
  if (!r) {
    box.append(h('div', { 'aria-hidden': 'true', style: 'display:grid;gap:8px' }, h('span', { class: 'ub-skel', style: 'height:66px' }), h('span', { class: 'ub-skel', style: 'height:66px' })));
    return;
  }
  if (!r.releases.length || !r.releases.some(x => x.usable)) {
    box.append(h('div', { class: 'ub-banner' }, h('p', { text: t('release.none') })));
  }
  const group = h('fieldset', { class: 'ub-releases' }, h('legend', { class: 'ub-sr', text: t('release.title') }));
  const name = nextId('rel');
  for (const rel of r.releases) {
    const usable = rel.usable;
    const input = h('input', { type: 'radio', name, value: rel.tag, disabled: !usable, checked: app.release && app.release.tag === rel.tag, on: { change: () => selectRelease(rel) } });
    const labelId = nextId('rl');
    group.append(h('label', { class: 'ub-release', 'aria-disabled': String(!usable) },
      input,
      h('span', {},
        h('span', { class: 'ub-tag', id: labelId, text: rel.name && rel.name !== rel.tag ? `${rel.tag} — ${rel.name}` : rel.tag }),
        rel.prerelease ? h('span', { class: 'ub-badge pre', text: t('release.prerelease') }) : h('span', { class: 'ub-badge ok', text: t('release.stable') }),
        rel.edited ? h('span', { class: 'ub-badge changed', text: t('release.edited') }) : null),
      h('span', { class: 'ub-meta', style: 'grid-column:2' },
        h('span', { text: t('release.published', { date: formatDate(rel.published, app.lang) }) }),
        rel.template ? h('span', { text: formatBytes(rel.template.size) }) : null,
        rel.template ? h('span', { text: `${t('release.format')} ${rel.template.config_format}` }) : null),
      !usable ? h('span', { class: 'ub-why', text: t(rel.problem) }) : null,
      h('span', { class: 'ub-links' },
        rel.url ? h('a', { href: rel.url, rel: 'noopener', target: '_blank', text: t('release.github') }) : null,
        rel.attestations ? h('a', { href: rel.attestations, rel: 'noopener', target: '_blank', text: t('release.attestations') }) : null)));
  }
  box.append(group);
  box.append(h('div', { class: 'ub-verify work', id: 'ub-verify', 'aria-live': 'polite' }));
  app.ui.verifyBox = $('#ub-verify', box);
  paintVerify();
  box.append(h('p', { class: 'ub-help', style: 'margin-top:10px' },
    t('release.key-note', { key: app.keyId }), ' ',
    h('button', { class: 'ub-link-btn', type: 'button', text: t('release.local'), on: { click: () => openLocalDialog() } })));
}

function paintVerify() {
  const box = app.ui.verifyBox;
  if (!box) return;
  clear(box);
  const v = app.verify;
  if (!app.release) { box.hidden = true; return; }
  box.hidden = false;
  if (app.verifyState === 'work') {
    box.className = 'ub-verify work';
    box.append(icon('info'), h('span', { text: t('release.verifying') }));
  } else if (v && v.ok) {
    box.className = 'ub-verify ok';
    box.append(icon('check'), h('span', {}, t('release.verified', { key: v.keyId }), ' ', h('button', { class: 'ub-link-btn', type: 'button', text: t('release.report'), on: { click: () => openIntegrityDialog() } })));
  } else if (v) {
    box.className = 'ub-verify bad';
    box.append(icon('alert'), h('span', {}, t('release.verify-failed', { reason: v.error }), ' ', h('button', { class: 'ub-link-btn', type: 'button', text: t('release.report'), on: { click: () => openIntegrityDialog() } })));
  } else if (app.release.local && !app.release.local.sums) {
    box.className = 'ub-verify bad';
    box.append(icon('alert'), h('span', { text: t('release.local-unverified') }));
  }
}

async function selectRelease(rel) {
  if (app.abortVerify) app.abortVerify.abort();
  app.release = rel;
  app.state.release = rel.tag;
  app.verify = null;
  app.override = false;
  paintFileName();
  app.onChange();
  paintValidation();
  if (rel.local) { app.verifyState = 'idle'; paintVerify(); return; }
  const ctl = new AbortController();
  app.abortVerify = ctl;
  app.verifyState = 'work';
  paintVerify();
  try {
    const v = await verifyRelease(app.builder, new URL('.', app.releasesUrl).href, rel, ctl.signal);
    if (app.release !== rel) return;
    app.verify = v;
  } catch (e) {
    if (e.name === 'AbortError') return;
    app.verify = { ok: false, error: e.message };
  }
  app.verifyState = 'done';
  paintVerify();
  announce(app.verify.ok ? t('release.verified', { key: app.verify.keyId }) : t('release.verify-failed', { reason: app.verify.error }));
}

async function loadReleaseList() {
  app.releaseError = '';
  app.releases = null;
  renderReleases();
  try {
    const r = await loadReleases(app.releasesUrl);
    app.releases = r;
    app.keyId = app.builder.minisignKeyId(RELEASE_PUBKEY);
    renderReleases();
    const want = app.state.release && r.releases.find(x => x.tag === app.state.release && x.usable);
    const pick = want || defaultRelease(r.releases);
    if (pick) {
      const input = $$('input[type=radio]', app.ui.releaseBox).find(i => i.value === pick.tag);
      if (input) input.checked = true;
      await selectRelease(pick);
    } else paintValidation();
  } catch (e) {
    app.releaseError = e.message || String(e);
    app.keyId = app.builder.minisignKeyId(RELEASE_PUBKEY);
    renderReleases();
    paintValidation();
  }
}

// --- presets --------------------------------------------------------------------------------

function renderPresets() {
  const box = app.ui.presetBox;
  clear(box);
  const ids = ['lab', 'vps', 'auto', 'defaults'];
  const buttons = ids.map(id => h('button', { class: 'ub-preset', type: 'button', 'aria-pressed': String(app.state.preset === id), on: { click: () => choosePreset(id) } },
    h('strong', { text: t(`preset.${id}`) }), h('span', { text: t(`preset.${id}.desc`) })));
  box.append(h('div', { class: 'ub-presets', role: 'group', 'aria-label': t('preset.title') }, buttons));
  app.ui.presetButtons = buttons;
}

async function choosePreset(id) {
  const dirty = changedIds(app.model, app.state).some(x => !isFileType(app.model.byId.get(x)));
  if (dirty) {
    const v = await ask({
      title: t('preset.confirm-title'),
      body: h('p', { text: t('preset.confirm') }),
      buttons: [{ label: t('common.cancel'), value: '', kind: 'secondary' }, { label: t('preset.apply'), value: 'yes' }],
    });
    if (v !== 'yes') return;
  }
  app.state.values = id === 'defaults' ? {} : { ...PRESETS[id].values };
  app.state.preset = id;
  syncFields(true);
  app.ui.presetButtons.forEach((b, i) => b.setAttribute('aria-pressed', String(['lab', 'vps', 'auto', 'defaults'][i] === id)));
  app.onChange();
  announce(t('preset.applied', { name: t(`preset.${id}`) }));
}

// --- the summary bar ---------------------------------------------------------------------------

function renderBar() {
  const ui = app.ui;
  ui.status = h('div', { class: 'ub-bar-status work', role: 'status' });
  ui.changed = h('span', { class: 'ub-help' });
  ui.problems = h('ul', { class: 'ub-problems', hidden: true });
  ui.loose = h('ul', { class: 'ub-problems', hidden: true });
  ui.notes = h('ul', { class: 'ub-notes', hidden: true });
  ui.fingerprintValue = h('span', { class: 'ub-code' });
  ui.fingerprint = h('p', { class: 'ub-help', hidden: true }, t('bar.fingerprint'), ' ', ui.fingerprintValue);
  ui.buildHint = h('span', { class: 'ub-sr', id: 'ub-build-hint' });
  ui.name = h('input', { class: 'ub-input', id: 'ub-name', type: 'text', maxlength: '40', autocomplete: 'off', spellcheck: 'false', placeholder: 'custom', value: app.state.name, 'aria-describedby': 'ub-name-help', on: { input: e => { app.state.name = e.target.value; persist(); paintFileName(); } } });
  ui.fileName = h('span', { class: 'ub-code' });
  ui.build = h('button', { class: 'ub-btn', type: 'button', id: 'ub-build', 'aria-describedby': 'ub-build-hint', on: { click: () => build() } }, icon('shield'), t('action.build'));
  ui.download = h('a', { class: 'ub-btn secondary', id: 'ub-download', role: 'button', 'aria-disabled': 'true', href: '#', on: { click: e => { if (ui.download.getAttribute('aria-disabled') === 'true') e.preventDefault(); } } }, icon('download'), t('action.download'));
  ui.emulator = h('button', { class: 'ub-btn secondary', type: 'button', id: 'ub-emulator', 'aria-disabled': 'true', 'aria-describedby': 'ub-emulator-hint', on: { click: () => { if (ui.emulator.getAttribute('aria-disabled') !== 'true') openEmulatorDialog(); } } }, icon('play'), t('action.emulator'));
  ui.emulatorHint = h('p', { class: 'ub-help', id: 'ub-emulator-hint', text: t('emulator.need-build') });
  ui.progress = h('div', { class: 'ub-progress', hidden: true, role: 'group', 'aria-label': t('progress.title') },
    h('div', { class: 'ub-progress-row' }, h('span', { id: 'ub-progress-text', role: 'status', 'aria-live': 'polite' }), h('span', { id: 'ub-progress-pct' })),
    h('progress', { id: 'ub-progress-bar', max: '100', value: '0', 'aria-labelledby': 'ub-progress-text' }),
    h('button', { class: 'ub-btn small secondary', type: 'button', id: 'ub-cancel', text: t('common.cancel'), on: { click: () => { if (app.abort) app.abort.abort(); } } }));
  ui.resultBox = h('div', { class: 'ub-result', hidden: true, 'aria-live': 'polite' });

  const more = h('button', { class: 'ub-btn small secondary ub-bar-more', type: 'button', 'aria-expanded': 'false', text: t('bar.details'), on: { click: e => {
    const open = ui.bar.dataset.open !== 'true';
    ui.bar.dataset.open = String(open);
    e.target.setAttribute('aria-expanded', String(open));
  } } });
  ui.bar = h('div', { class: 'ub-bar', data: { open: 'false', ready: 'false' } },
    h('div', { class: 'ub-bar-top' }, ui.status, ui.changed),
    h('div', { class: 'ub-bar-actions' }, ui.build, more),
    h('div', { class: 'ub-pair' }, ui.download, ui.emulator),
    ui.progress,
    h('div', { class: 'ub-bar-detail' },
      ui.problems, ui.loose, ui.notes,
      h('div', { class: 'ub-name' },
        h('label', { class: 'ub-label', style: 'font-family:inherit', for: 'ub-name', text: t('bar.name') }), ui.name,
        h('p', { class: 'ub-help', id: 'ub-name-help' }, t('bar.name-help'), ' ', ui.fileName)),
      ui.fingerprint,
      ui.emulatorHint,
      h('div', { class: 'ub-tools' },
        h('button', { class: 'ub-link-btn', type: 'button', id: 'ub-toml', text: t('action.toml'), on: { click: () => openTomlDialog() } }),
        h('button', { class: 'ub-link-btn', type: 'button', id: 'ub-signing', text: t('action.signing'), on: { click: () => openSlotDialog('signing') } }),
        h('button', { class: 'ub-link-btn', type: 'button', id: 'ub-reset-all', text: t('action.reset-all'), on: { click: () => resetAll() } }))),
  );
  paintFileName();
  return h('aside', { class: 'ub-aside', 'aria-label': t('bar.title') }, ui.bar, ui.resultBox);
}

function paintFileName() {
  if (app.ui.fileName) app.ui.fileName.textContent = outputName(app.release ? app.release.tag : 'x', app.state.name);
}

function paintResult() {
  const ui = app.ui;
  if (!ui.download) return;
  const r = app.result;
  const ready = Boolean(r) && !app.stale;
  ui.bar.dataset.ready = String(ready);
  ui.download.setAttribute('aria-disabled', String(!ready));
  ui.download.href = ready ? r.url : '#';
  if (ready) ui.download.setAttribute('download', r.name); else ui.download.removeAttribute('download');
  ui.emulator.setAttribute('aria-disabled', String(!ready));
  ui.emulatorHint.textContent = !r ? t('emulator.need-build') : app.stale ? t('result.stale') : t('emulator.hint');
  ui.emulatorHint.hidden = false;
  if (!r) { ui.resultBox.hidden = true; return; }
  ui.resultBox.hidden = false;
  clear(ui.resultBox);
  append(ui.resultBox, [
    h('h2', { text: app.stale ? t('result.stale-title') : t('result.title') }),
    app.stale ? h('p', { class: 'ub-warn', text: t('result.stale') }) : null,
    h('dl', { class: 'ub-kv' },
      h('dt', { text: t('result.file') }), h('dd', { class: 'mono', text: r.name }),
      h('dt', { text: t('result.size') }), h('dd', { text: formatBytes(r.size) }),
      h('dt', { text: t('result.sha256') }), h('dd', { class: 'mono', text: groupHex(r.sha256, 8) }),
      h('dt', { text: t('result.fingerprint') }), h('dd', { class: 'mono', text: groupHex(r.fingerprint, 8) })),
    h('p', { class: 'ub-help', text: t('result.compare') }),
    h('div', { class: 'ub-tools' },
      h('button', { class: 'ub-btn small secondary', type: 'button', text: t('action.next'), on: { click: () => openNextDialog() } }),
      h('button', { class: 'ub-btn small secondary', type: 'button', text: t('action.report'), on: { click: () => openIntegrityDialog() } })),
  ]);
}

async function resetAll() {
  const v = await ask({
    title: t('action.reset-all'),
    body: h('p', { text: t('reset.confirm') }),
    buttons: [{ label: t('common.cancel'), value: '', kind: 'secondary' }, { label: t('action.reset-all'), value: 'yes', kind: 'danger' }],
  });
  if (v !== 'yes') return;
  const release = app.state.release;
  app.state = emptyState();
  app.state.release = release;
  app.ui.name.value = '';
  syncFields(true);
  app.ui.presetButtons.forEach(b => b.setAttribute('aria-pressed', 'false'));
  app.onChange();
  announce(t('reset.done'));
}

// --- the build ---------------------------------------------------------------------------------------------

function setProgress(text, pct) {
  const ui = app.ui;
  ui.progress.hidden = false;
  $('#ub-progress-text', ui.progress).textContent = text;
  const bar = $('#ub-progress-bar', ui.progress);
  if (pct === null) bar.removeAttribute('value'); else bar.value = pct;
  $('#ub-progress-pct', ui.progress).textContent = pct === null ? '' : `${Math.round(pct)} %`;
}

async function build() {
  if (app.busy) return;
  refresh();
  const c = app.current;
  if (c.issues.length) {
    const first = c.issues.find(i => i.field) || c.issues[0];
    announce(t('bar.problems', { n: c.issues.length }));
    if (first.field) focusField(first.field.id);
    return;
  }
  if (!app.release) { announce(t('bar.choose-release')); return; }
  const confirm = c.risks.filter(r => r.level === 'confirm');
  if (confirm.length && !(await confirmRisks(confirm))) return;

  app.busy = true;
  app.abort = new AbortController();
  const ui = app.ui;
  ui.build.disabled = true;
  const blob = c.res.blob;
  let iso = 0;
  try {
    // 1. The template, into WebAssembly memory.
    setProgress(t('progress.download'), 0);
    const total = app.release.local ? app.release.local.iso.size : app.release.template.size;
    const onProgress = (got, all) => setProgress(`${t('progress.download')} ${formatBytes(got)} / ${formatBytes(all)}`, (got / all) * 100);
    if (app.release.local) iso = await streamToBuffer(app.builder, app.release.local.iso.stream(), total, onProgress, app.abort.signal);
    else iso = await downloadTemplate(app.builder, mirrorUrl(new URL('.', app.releasesUrl).href, app.release.template.path), total, onProgress, app.abort.signal);

    // 2. Is it the template the signed sums name?
    setProgress(t('progress.verify'), null);
    await paint();
    const sha = app.builder.sha256Hex(iso);
    const expected = app.release.local ? (app.verify && app.verify.templateSha256) : app.verify && app.verify.templateSha256;
    const problems = [];
    if (!app.release.local && !(app.verify && app.verify.ok)) problems.push(t('integrity.signature-failed', { reason: app.verify ? app.verify.error : '?' }));
    else if (expected && sha !== expected) problems.push(t('integrity.hash-mismatch', { got: sha, want: expected }));
    if (app.release.local && !expected) problems.push(t('release.local-unverified'));
    if (problems.length && !app.override) {
      app.abort = null;
      const go = await integrityOverride(problems);
      if (!go) throw Object.assign(new Error('declined'), { name: 'Declined' });
      app.override = true;
      app.abort = new AbortController();
    }
    const probe = app.builder.isoProbe(iso);
    if (!probe.supported) throw new Error(t('release.format-unsupported'));

    // 3. The configuration goes in.
    setProgress(t('progress.write'), null);
    await paint();
    const report = app.builder.isoConfigure(iso, blob);

    // 4. Checksums and the file to offer.
    setProgress(t('progress.hash'), null);
    await paint();
    const outSha = app.builder.sha256Hex(iso);
    const verdict = app.builder.isoVerify(iso);
    const file = new Blob([app.builder.view(iso)], { type: 'application/x-iso9660-image' });
    if (app.result && app.result.url) URL.revokeObjectURL(app.result.url);
    app.result = {
      blob: file, url: URL.createObjectURL(file), name: outputName(app.release.tag, app.state.name),
      size: file.size, sha256: outSha, fingerprint: c.info.fingerprint, report, verdict, probe,
      templateSha256: sha, signed: c.info.signed, signerId: c.info.signer_id, port: portOfConfig(), overridden: problems.length > 0,
    };
    app.stale = false;
    paintResult();
    announce(t('result.title'));
    openNextDialog(true);
  } catch (e) {
    if (e.name === 'AbortError') announce(t('progress.cancelled'));
    else if (e.name === 'Declined') announce(t('progress.cancelled'));
    else {
      openDialog({
        title: t('build.failed'), size: 'narrow',
        body: [h('p', { text: cleanMessage(e.message || String(e)) }), h('p', { class: 'ub-help', text: t('build.failed-help') })],
        actions: [dialogButton(t('common.close'), 'close')],
      });
    }
  } finally {
    if (iso) app.builder.free(iso);
    app.busy = false;
    app.abort = null;
    ui.progress.hidden = true;
    ui.build.disabled = !app.release;
    paintResult();
    paintValidation();
  }
}

function portOfConfig() {
  const v = app.state.values['network.mqtt_tls_port'];
  return v !== undefined && isWholeNumber(v) ? Number(v) : app.model.byId.get('network.mqtt_tls_port').default;
}

async function confirmRisks(risks) {
  const body = [
    h('p', { text: t('risk.intro') }),
    h('ul', { class: 'ub-steps' }, risks.map(r => h('li', {}, h('strong', { text: riskTitle(r) }), h('p', { class: 'ub-help', text: riskText(r) })))),
  ];
  const v = await ask({
    title: t('risk.title'), body: body, size: '',
    buttons: [{ label: t('risk.back'), value: '', kind: 'secondary' }, { label: t('risk.continue'), value: 'go' }],
  });
  return v === 'go';
}

const riskTitle = r => t(`risk.${r.id}.title`, r.args);
const riskText = r => t(`risk.${r.id}.text`, r.args);

async function integrityOverride(problems) {
  const v = await ask({
    title: t('integrity.failed-title'), size: '',
    body: [
      h('p', { class: 'ub-error', text: t('integrity.failed') }),
      h('ul', { class: 'ub-steps' }, problems.map(p => h('li', { text: p }))),
      h('p', { text: t('integrity.override-help') }),
    ],
    buttons: [{ label: t('integrity.stop'), value: '', kind: 'secondary' }, { label: t('integrity.override'), value: 'go', kind: 'danger' }],
  });
  return v === 'go';
}

/** Streams a ReadableStream into a new module buffer of `total` bytes. */
async function streamToBuffer(builder, stream, total, onProgress, signal) {
  const buf = builder.alloc(total);
  try {
    let got = 0;
    const reader = stream.getReader();
    for (;;) {
      if (signal && signal.aborted) throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      const { done, value } = await reader.read();
      if (done) break;
      if (got + value.length > total) throw new Error('the file is larger than expected');
      builder.view(buf).set(value, got);
      got += value.length;
      onProgress(got, total);
    }
    if (got !== total) throw new Error(`the file ended after ${got} of ${total} bytes`);
    return buf;
  } catch (e) {
    builder.free(buf);
    throw e;
  }
}

// --- dialogs: next steps, integrity, TOML, local template ---------------------------------------------------------------

function copyRow(text, label) {
  const code = h('code', { class: 'ub-code', text });
  const btn = h('button', { class: 'ub-btn small secondary', type: 'button', 'aria-label': `${t('common.copy')}: ${label}`, on: { click: async () => {
    const ok = await copyText(text);
    announce(ok ? t('common.copied') : t('common.copy-failed'));
    btn.textContent = ok ? t('common.copied') : t('common.copy-failed');
    setTimeout(() => { btn.textContent = t('common.copy'); }, 1500);
  } } }, t('common.copy'));
  return h('div', { class: 'ub-copyrow' }, code, btn);
}

function openNextDialog(afterBuild = false) {
  const r = app.result;
  if (!r) return;
  const st = app.state.values;
  const mode = st['network.mode'] || 'dhcp';
  const addr = mode !== 'dhcp' && st['network.address'] ? String(st['network.address']).split('/')[0] : '<ip>';
  const cmd = `openssl s_client -connect ${addr}:${r.port} -CAfile ca.pem -cert device.pem -key device.key -tls1_3`;
  openDialog({
    title: t('next.title'), size: 'wide',
    body: [
      h('p', { text: afterBuild ? t('next.built', { name: r.name }) : t('next.intro') }),
      h('ol', { class: 'ub-steps' },
        h('li', {}, h('strong', { text: t('next.step1') }), h('p', { class: 'ub-help', text: t('next.step1.text') })),
        h('li', {}, h('strong', { text: t('next.step2') }), h('p', { class: 'ub-help', text: t('next.step2.text') })),
        h('li', {}, h('strong', { text: t('next.step3') }), h('p', { class: 'ub-help', text: t('next.step3.text') }), copyRow(r.fingerprint, t('result.fingerprint')),
          r.signed ? h('p', { class: 'ub-help', text: t('next.signed', { id: r.signerId }) }) : null),
        h('li', {}, h('strong', { text: t('next.step4') }), h('p', { class: 'ub-help', text: t('next.step4.text') }), copyRow(cmd, 'openssl')),
        h('li', {}, h('strong', { text: t('next.step5') }), h('p', { class: 'ub-help', text: t('next.step5.text') }))),
      h('p', { class: 'ub-help', text: t('next.sha', { sha: r.sha256 }) }),
      h('p', { class: 'ub-help', text: t('next.no-official-hash') }),
    ],
    actions: [
      app.stale ? null : h('a', { class: 'ub-btn secondary', role: 'button', href: r.url, download: r.name }, icon('download'), t('action.download')),
      dialogButton(t('common.close'), 'close'),
    ],
  });
}

function openIntegrityDialog() {
  const rel = app.release;
  const v = app.verify;
  const r = app.result;
  const kv = [];
  const add = (k, val, mono = false) => kv.push(h('dt', { text: k }), h('dd', { class: mono ? 'mono' : '', text: val }));
  add(t('integrity.release'), rel ? `${rel.tag}${rel.prerelease ? ` (${t('release.prerelease')})` : ''}` : '—');
  add(t('integrity.key'), app.keyId || '—', true);
  const pubLines = RELEASE_PUBKEY.trim().split('\n');
  const checks = h('ul', { class: 'ub-checks' });
  if (v) {
    checks.append(v.ok ? statusLine('ok', t('integrity.sig-ok', { key: v.keyId })) : statusLine('bad', t('release.verify-failed', { reason: v.error })));
    if (v.ok) checks.append(statusLine('ok', t('integrity.sums-lists', { file: rel.template.file })));
  } else checks.append(statusLine('info', t('integrity.not-checked')));
  if (r) {
    checks.append(r.templateSha256 === (v && v.templateSha256) ? statusLine('ok', t('integrity.template-ok')) : statusLine('bad', t('integrity.template-bad')));
    if (r.overridden) checks.append(statusLine('warn', t('integrity.overridden')));
    checks.append(statusLine('ok', t('integrity.verified-image')));
  }
  if (v && v.trustedComment) add(t('integrity.comment'), v.trustedComment);
  if (rel && rel.template) add(t('integrity.template'), rel.template.file, true);
  if (v && v.templateSha256) add(t('integrity.template-sha'), groupHex(v.templateSha256, 8), true);
  if (r) {
    add(t('integrity.result'), r.name, true);
    add(t('result.sha256'), groupHex(r.sha256, 8), true);
    add(t('result.fingerprint'), groupHex(r.fingerprint, 8), true);
    add(t('integrity.slots'), t('integrity.slots-text', { n: r.probe.slot_copies, m: r.probe.hash_refs }));
  }
  openDialog({
    title: t('integrity.title'), size: 'wide',
    body: [
      h('dl', { class: 'ub-kv' }, kv),
      checks,
      h('h3', { text: t('integrity.pubkey') }),
      h('p', { class: 'ub-help', text: t('integrity.pubkey-help') }),
      h('pre', { class: 'ub-code', text: pubLines.join('\n') }),
      rel && rel.url ? h('p', {}, h('a', { href: rel.url, target: '_blank', rel: 'noopener', text: t('release.github') }), ' · ', rel.attestations ? h('a', { href: rel.attestations, target: '_blank', rel: 'noopener', text: t('release.attestations') }) : '') : null,
      h('p', { class: 'ub-help', text: t('integrity.offline') }),
      copyRow(`urmqtt-config check-release --pubkey minisign.pub --sums SHA256SUMS ${rel && rel.template ? rel.template.file : ''}`.trim(), 'check-release'),
    ],
    actions: [dialogButton(t('common.close'), 'close')],
  });
}

function openTomlDialog() {
  const built = buildToml(app.model, app.state);
  const names = Object.keys(built.files);
  const exportText = built.toml || `# ${t('toml.nothing')}\n`;
  const pre = h('pre', { class: 'ub-code', tabindex: '0', 'aria-label': t('toml.export'), text: exportText });
  const importArea = h('textarea', { class: 'ub-textarea', rows: 6, spellcheck: 'false', 'aria-label': t('toml.paste'), placeholder: '[network]\nmode = "static"' });
  const report = h('div', { 'aria-live': 'polite', style: 'display:grid;gap:8px' });
  const filesInput = h('input', { type: 'file', multiple: true, accept: '.pem,.crt,.cer,.key,.pub,.txt', 'aria-label': t('toml.choose-files') });
  const filesBox = h('div', { hidden: true, style: 'display:grid;gap:8px' }, h('p', { class: 'ub-sub', id: 'ub-toml-needs' }), filesInput);
  let imported = null;
  const apply = h('button', { class: 'ub-btn', type: 'button', disabled: true, text: t('toml.apply') });
  const analyze = async () => {
    clear(report);
    imported = null;
    apply.disabled = true;
    filesBox.hidden = true;
    const text = importArea.value;
    if (!text.trim()) return;
    let json;
    try { json = app.builder.tomlToJson(text); } catch (e) {
      report.append(h('p', { class: 'ub-error', text: cleanMessage(e.message) }));
      return;
    }
    const r = importToml(app.model, json, app.state);
    imported = r;
    const n = Object.keys(r.state.values).length;
    report.append(h('p', { text: t('toml.found', { n }) }));
    if (r.unknown.length) report.append(h('p', { class: 'ub-warn', text: t('toml.unknown', { keys: r.unknown.join(', ') }) }));
    if (r.needFiles.length) {
      const wanted = r.needFiles.flatMap(x => x.names);
      $('#ub-toml-needs', filesBox).textContent = t('toml.needs-files', { names: wanted.join(', ') });
      filesBox.hidden = false;
    }
    apply.disabled = false;
  };
  const debouncedAnalyze = debounce(analyze, 250);
  importArea.addEventListener('input', debouncedAnalyze);
  const fileInput = h('input', { type: 'file', accept: '.toml,.txt', 'aria-label': t('toml.choose'), on: { change: async e => {
    const f = e.target.files[0];
    if (f) { importArea.value = await readText(f); analyze(); }
  } } });

  apply.addEventListener('click', async () => {
    if (!imported) return;
    // Files the TOML names, chosen by the user, matched by name.
    const chosen = new Map();
    for (const f of filesInput.files) chosen.set(f.name, await readText(f));
    const st = imported.state;
    st.files = { ...app.state.files };
    for (const need of imported.needFiles) {
      const f = app.model.byId.get(need.field);
      const slot = f.fileKey.slot;
      if (slot === 'revoked') continue;
      const found = need.names.map(nm => chosen.get(nm)).filter(Boolean);
      if (!found.length) continue;
      const items = found.map(pem => analyzeSlot(slot, pem, '')).filter(x => x.ok).map(x => x.item);
      if (f.fileKey.list) st.files[slot] = items;
      else if (items[0]) st.files[slot] = items[0];
    }
    app.state = { ...app.state, values: st.values, files: st.files, preset: '' };
    syncFields(true);
    app.ui.presetButtons.forEach(b => b.setAttribute('aria-pressed', 'false'));
    app.onChange();
    apply.closest('dialog').close('applied');
    announce(t('toml.applied'));
  });

  openDialog({
    title: t('toml.title'), size: 'wide',
    body: [
      h('section', { 'aria-labelledby': 'ub-toml-ex' },
        h('h3', { id: 'ub-toml-ex', text: t('toml.export') }),
        h('p', { class: 'ub-help', text: names.length ? t('toml.export-files', { names: names.join(', ') }) : t('toml.export-help') }),
        pre,
        h('div', { class: 'ub-tools' },
          h('button', { class: 'ub-btn small secondary', type: 'button', on: { click: async () => announce((await copyText(exportText)) ? t('common.copied') : t('common.copy-failed')) } }, icon('copy'), t('common.copy')),
          h('button', { class: 'ub-btn small secondary', type: 'button', on: { click: () => saveText(exportText, 'config.toml', 'application/toml') } }, icon('download'), t('toml.download')))),
      h('section', { 'aria-labelledby': 'ub-toml-im', style: 'display:grid;gap:8px' },
        h('h3', { id: 'ub-toml-im', text: t('toml.import') }),
        h('p', { class: 'ub-help', text: t('toml.import-help') }),
        fileInput, importArea, report, filesBox),
    ],
    actions: [dialogButton(t('common.close'), 'close', 'secondary'), apply],
  });
}

function openLocalDialog() {
  const iso = h('input', { type: 'file', accept: '.iso', 'aria-label': t('local.iso') });
  const sums = h('input', { type: 'file', 'aria-label': t('local.sums') });
  const sig = h('input', { type: 'file', accept: '.minisig,.txt', 'aria-label': t('local.sig') });
  const report = h('div', { 'aria-live': 'polite', style: 'display:grid;gap:8px' });
  const useBtn = h('button', { class: 'ub-btn', type: 'button', disabled: true, text: t('local.use') });
  iso.addEventListener('change', () => { useBtn.disabled = !iso.files[0]; });
  useBtn.addEventListener('click', async () => {
    const file = iso.files[0];
    if (!file) return;
    clear(report);
    let verify = null;
    if (sums.files[0] || sig.files[0]) {
      if (!(sums.files[0] && sig.files[0])) { report.append(h('p', { class: 'ub-error', text: t('local.both') })); return; }
      try {
        const v = app.builder.verifyRelease(RELEASE_PUBKEY, new Uint8Array(await sums.files[0].arrayBuffer()), await readText(sig.files[0]));
        const entry = v.files.find(f => f.name === file.name);
        if (!entry) throw new Error(`SHA256SUMS does not list ${file.name}`);
        verify = { ok: true, keyId: v.key_id, trustedComment: v.trusted_comment, templateSha256: entry.sha256, files: v.files, error: '' };
      } catch (e) {
        report.append(h('p', { class: 'ub-error', text: t('release.verify-failed', { reason: cleanMessage(e.message) }) }));
        return;
      }
    }
    const rel = { tag: 'local', name: file.name, local: { iso: file, sums: Boolean(verify) }, published: new Date(file.lastModified).toISOString(), template: { file: file.name, size: file.size, config_format: SUPPORTED_FORMAT }, usable: true };
    app.local = rel;
    app.release = rel;
    app.state.release = '';
    app.verify = verify;
    app.verifyState = verify ? 'done' : 'idle';
    app.override = false;
    $$('input[type=radio]', app.ui.releaseBox).forEach(i => { i.checked = false; });
    useBtn.closest('dialog').close('used');
    paintVerify();
    paintFileName();
    app.onChange();
    paintValidation();
  });
  openDialog({
    title: t('local.title'),
    body: [
      h('p', { class: 'ub-sub', text: t('local.help') }),
      h('label', { class: 'ub-label-row' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('local.iso') }), iso),
      h('label', { class: 'ub-label-row' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('local.sums') }), sums),
      h('label', { class: 'ub-label-row' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('local.sig') }), sig),
      h('p', { class: 'ub-help', text: t('local.warn') }),
      report,
    ],
    actions: [dialogButton(t('common.cancel'), 'cancel', 'secondary'), useBtn],
  });
}

// --- the shell -------------------------------------------------------------------------------------------------------------------

function renderShell() {
  const root = app.el;
  clear(root);
  root.classList.add('ub');
  root.setAttribute('lang', app.lang);
  const ui = app.ui;
  ui.releaseBox = h('div', {});
  ui.presetBox = h('div', {});
  const head = h('div', { class: 'ub-head' },
    h('h1', { text: t('title') }),
    h('p', { class: 'ub-lead', text: t('lead') }),
    h('div', { class: 'ub-privacy' }, icon('shield'), h('p', {}, h('strong', { text: t('privacy.title') + ' ' }), t('privacy.text'))));
  const releaseCard = h('section', { class: 'ub-card', 'aria-labelledby': 'ub-h-release' },
    h('header', {}, h('h2', { id: 'ub-h-release' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '1' }), t('release.title'))),
    h('p', { class: 'ub-sub', text: t('release.help') }), ui.releaseBox);
  const presetCard = h('section', { class: 'ub-card', 'aria-labelledby': 'ub-h-preset' },
    h('header', {}, h('h2', { id: 'ub-h-preset' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '2' }), t('preset.title'))),
    h('p', { class: 'ub-sub', text: t('preset.help') }), ui.presetBox);
  const sections = renderSections();
  ui.relations = h('ul', { class: 'ub-checks', style: 'margin-top:12px', 'aria-live': 'polite' });
  const tlsFields = $('#sec-tls .ub-fields', sections);
  if (tlsFields) tlsFields.after(ui.relations);
  const formHead = h('h2', { style: 'margin:10px 0 -4px' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '3' }), t('form.title'));
  const main = h('div', { class: 'ub-main' }, releaseCard, presetCard, formHead, sections);
  const layout = h('div', { class: 'ub-layout' }, main, renderBar());
  root.append(h('div', { class: 'ub-wrap' }, head, layout));
  renderPresets();
  renderReleases();
}

function resetUiState() { rows.clear(); sectionViews.clear(); }
