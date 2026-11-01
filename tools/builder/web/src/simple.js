// The simple view (the default): three plain steps over the same state as the advanced form, and the advanced
// switch with its search and filters. Nothing here keeps a state of its own except what is on screen.

// --- which view -----------------------------------------------------------------------------

function setAdvanced(on) {
  app.advanced = Boolean(on);
  try { localStorage.setItem(ADVANCED_KEY, app.advanced ? '1' : '0'); } catch { /* private window */ }
  applyView();
  persist();
  paintValidation();
}

function applyView() {
  const ui = app.ui;
  app.el.dataset.mode = app.advanced ? 'advanced' : 'simple';
  ui.simple.hidden = app.advanced;
  ui.advanced.hidden = !app.advanced;
  ui.toggle.setAttribute('aria-checked', String(app.advanced));
  // The list of releases lives in the simple view's "change version" or in the first advanced card.
  (app.advanced ? ui.releaseSlot : ui.versionDetails).append(ui.releaseBox);
  syncSimple();
}

/** From a problem in the list: the simple view has only the address fields. */
function simpleFocus(id) {
  const el = id === 'network.address' ? app.ui.addr : id === 'network.gateway' ? app.ui.gw : null;
  if (!el) return false;
  el.scrollIntoView({ block: 'center' });
  el.focus();
  return true;
}

const plainIsOn = () => app.state.values['plaintext.enabled'] === true;
const needsNetworks = () => plainIsOn() && !(app.state.values['plaintext.allow_from'] || []).length && app.state.values['plaintext.allow_from_anywhere'] !== true;
const needsAccount = () => plainIsOn() && (app.state.values['plaintext.auth'] || 'password') === 'password' && !completeUsers(app.state.values['plaintext.users']).length;
const needsAddress = () => ['static', 'auto'].includes(app.state.values['network.mode']) && !(app.state.values['network.address'] || '').trim();
const certsMissing = () => !tlsOff(app.state) && !(app.state.files.cert && app.state.files.key && app.state.files.operational.length);

// --- building the view -------------------------------------------------------------------------

const WHERE = [['vps', 'vps'], ['lab', 'lab'], ['auto', 'auto']];

function setSimple(id, v) {
  if (v === '' || v === false || v === undefined) delete app.state.values[id]; else app.state.values[id] = v;
  syncFields();
  app.onChange();
  syncSimple();
}

function renderSimple() {
  const ui = app.ui;
  // 1. Where
  ui.whereCards = WHERE.map(([id]) => h('button', { class: 'ub-where', type: 'button', 'aria-pressed': 'false', data: { id }, on: { click: () => choosePreset(id) } },
    h('strong', { text: t(`simple.where.${id}`) }), h('span', { text: t(`simple.where.${id}.desc`) })));
  ui.addr = h('input', { class: 'ub-input', id: 'ub-s-addr', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: t('simple.address.ph'), 'aria-describedby': 'ub-s-addr-help', on: { input: e => setSimple('network.address', e.target.value.trim()) } });
  ui.gw = h('input', { class: 'ub-input', id: 'ub-s-gw', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: t('simple.gateway.ph'), on: { input: e => setSimple('network.gateway', e.target.value.trim()) } });
  ui.fixed = h('div', { class: 'ub-fixed' },
    h('label', { class: 'ub-label-row', for: 'ub-s-addr' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('simple.address') }), ui.addr),
    h('label', { class: 'ub-label-row', for: 'ub-s-gw' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('simple.gateway') }), ui.gw),
    h('p', { class: 'ub-help', id: 'ub-s-addr-help', text: t('simple.address.help') }));
  const where = h('section', { class: 'ub-card', 'aria-labelledby': 'ub-s-h-where' },
    h('header', {}, h('h2', { id: 'ub-s-h-where' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '1' }), t('simple.title.where'))),
    h('div', { class: 'ub-presets', role: 'group', 'aria-labelledby': 'ub-s-h-where' }, ui.whereCards), ui.fixed);

  // 2. How devices connect: the two listeners, each its own checkbox, and what each needs.
  ui.xTls = h('input', { type: 'checkbox', id: 'ub-x-tls', on: { change: e => toggleListener('tls', e.target.checked) } });
  ui.xPlain = h('input', { type: 'checkbox', id: 'ub-x-plain', on: { change: e => toggleListener('plain', e.target.checked) } });
  ui.listenerMsg = h('p', { class: 'ub-error', role: 'alert', hidden: true });
  ui.certFound = h('ul', { class: 'ub-checks', 'aria-live': 'polite' });
  ui.certInput = h('input', { type: 'file', multiple: true, 'aria-label': t('simple.certs.drop'), on: { change: async e => { await takeFiles(e.target.files); e.target.value = ''; } } });
  const drop = h('div', { class: 'ub-drop', id: 'ub-s-drop' }, icon('upload'), ' ', h('span', { text: t('simple.certs.drop') }), ui.certInput);
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => takeFiles(e.dataTransfer.files));
  ui.certClear = h('button', { class: 'ub-link-btn', type: 'button', text: t('simple.certs.clear'), hidden: true, on: { click: () => { clearCerts(); } } });
  ui.certProblems = h('div', { style: 'display:grid;gap:8px' });
  ui.tlsBox = h('div', { class: 'ub-sub-card', id: 'ub-s-tls' },
    h('h3', { text: t('simple.title.certs') }),
    h('p', { class: 'ub-sub', text: t('simple.certs.help') }), drop, ui.certProblems, ui.certFound,
    h('p', { class: 'ub-help' }, ui.certClear, ' ', h('a', { href: 'https://github.com/zeljan-alduk/urMQTT/blob/main/docs/DEPLOY.md', target: '_blank', rel: 'noopener', text: t('simple.certs.test') })));
  // Plain MQTT: which networks, and how a device logs in. The accounts editor is the advanced form's own
  // (it hashes the passwords); it is moved in while this view is shown.
  ui.networks = h('textarea', { class: 'ub-textarea', id: 'ub-s-networks', rows: 3, spellcheck: 'false', autocomplete: 'off', 'aria-describedby': 'ub-s-networks-help', on: { input: e => setSimple('plaintext.allow_from', lines(e.target.value)) } });
  ui.authRadios = ['password', 'anonymous', 'ip'].map(id => h('label', { class: 'ub-switch', for: `ub-s-auth-${id}` },
    h('input', { type: 'radio', name: 'ub-s-auth', id: `ub-s-auth-${id}`, value: id, on: { change: () => setSimple('plaintext.auth', id === 'password' ? '' : id) } }),
    h('span', { text: t(`simple.plain.auth.${id}`) })));
  ui.plainRows = h('div', { class: 'ub-plain-rows' });
  ui.plainBox = h('div', { class: 'ub-sub-card', id: 'ub-s-plain' },
    h('h3', { text: t('simple.plain.title') }),
    h('label', { class: 'ub-label-row', for: 'ub-s-networks' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('simple.plain.networks') }), ui.networks),
    h('p', { class: 'ub-help', id: 'ub-s-networks-help', text: t('simple.plain.networks.help') }),
    h('fieldset', { class: 'ub-extras' }, h('legend', { text: t('simple.plain.auth') }), ui.authRadios), ui.plainRows);
  ui.tlsOffNote = h('p', { class: 'ub-banner', role: 'status', hidden: true, text: t('simple.tls-off.note') });
  const certs = h('section', { class: 'ub-card', 'aria-labelledby': 'ub-s-h-connect' },
    h('header', {}, h('h2', { id: 'ub-s-h-connect' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '2' }), t('simple.title.connect'))),
    h('fieldset', { class: 'ub-extras' }, h('legend', { class: 'ub-sr', text: t('simple.title.connect') }),
      h('label', { class: 'ub-switch', for: 'ub-x-tls' }, ui.xTls, h('span', { text: t('simple.listener.tls') })),
      h('p', { class: 'ub-help', text: t('simple.listener.tls.help') }),
      h('label', { class: 'ub-switch', for: 'ub-x-plain' }, ui.xPlain, h('span', { text: t('simple.listener.plain') })),
      h('p', { class: 'ub-help', text: t('simple.listener.plain.help') }), ui.listenerMsg),
    ui.tlsOffNote, ui.tlsBox, ui.plainBox);

  // 3. Name, extras, version
  ui.sName = h('input', { class: 'ub-input', id: 'ub-s-name', type: 'text', maxlength: '40', autocomplete: 'off', spellcheck: 'false', placeholder: 'custom', 'aria-describedby': 'ub-s-name-help', on: { input: e => { app.state.name = e.target.value; ui.name.value = e.target.value; persist(); paintFileName(); } } });
  ui.sFile = h('span', { class: 'ub-code' });
  ui.xDiag = h('input', { type: 'checkbox', id: 'ub-x-diag', on: { change: e => setSimple('storage.diagnostic', e.target.checked) } });
  ui.versionLine = h('span', { class: 'ub-version-line' });
  ui.versionDetails = h('details', { class: 'ub-version-details' }, h('summary', { class: 'ub-link-btn', text: t('simple.change-version') }));
  const name = h('section', { class: 'ub-card', 'aria-labelledby': 'ub-s-h-name' },
    h('header', {}, h('h2', { id: 'ub-s-h-name' }, h('span', { class: 'ub-step', 'aria-hidden': 'true', text: '3' }), t('simple.title.name'))),
    h('label', { class: 'ub-label-row', for: 'ub-s-name' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('bar.name') }), ui.sName),
    h('p', { class: 'ub-help', id: 'ub-s-name-help' }, t('simple.name.help'), ' ', ui.sFile),
    h('fieldset', { class: 'ub-extras' }, h('legend', { text: t('simple.extras') }),
      h('label', { class: 'ub-switch', for: 'ub-x-diag' }, ui.xDiag, h('span', { text: t('simple.extra.diagnostic') }))),
    h('p', { class: 'ub-help' }, t('simple.version'), ' ', ui.versionLine), ui.versionDetails);

  return h('div', { class: 'ub-simple' }, where, certs, name);
}

/** Brings everything on the simple view in line with the state (called after every change). */
function syncSimple() {
  const ui = app.ui;
  if (!ui.simple) return;
  ensureRelease();
  const v = app.state.values;
  ui.whereCards.forEach(b => b.setAttribute('aria-pressed', String(app.state.preset === b.dataset.id)));
  const fixed = ['static', 'auto'].includes(v['network.mode']);
  ui.fixed.hidden = !fixed;
  const put = (el, val) => { if (document.activeElement !== el) el.value = val || ''; };
  put(ui.addr, v['network.address']); put(ui.gw, v['network.gateway']); put(ui.sName, app.state.name);
  if (document.activeElement !== ui.name) ui.name.value = app.state.name || '';
  ui.sFile.textContent = outputName(app.release ? app.release.tag : 'x', app.state.name);
  ui.xDiag.checked = v['storage.diagnostic'] === true;
  const plainOn = v['plaintext.enabled'] === true;
  const off = tlsOff(app.state);
  ui.xTls.checked = !off;
  ui.xPlain.checked = plainOn;
  ui.tlsBox.hidden = off;          // hidden, not just empty: nothing of TLS is asked for
  ui.plainBox.hidden = !plainOn;
  ui.tlsOffNote.hidden = !off;
  if (document.activeElement !== ui.networks) ui.networks.value = (v['plaintext.allow_from'] || []).join('\n');
  const auth = v['plaintext.auth'] || 'password';
  ui.authRadios.forEach(l => { const r = l.querySelector('input'); r.checked = r.value === auth; });
  parkPlainRows(!app.advanced && plainOn);
  // What the certificate files say.
  clear(ui.certFound);
  const f = app.state.files;
  const line = (kind, key, item) => ui.certFound.append(item ? statusLine('ok', t(`simple.certs.found.${key}`, { what: item.summary })) : statusLine('warn', t(`simple.certs.missing.${key}`)));
  line('cert', 'cert', f.cert);
  line('key', 'key', f.key);
  if (f.operational.length) f.operational.forEach(c => line('ca', 'ca', c)); else line('ca', 'ca', null);
  if (app.keyForgotten && !f.key) ui.certFound.append(statusLine('info', t('simple.certs.key-forgotten')));
  ui.certClear.hidden = !(f.cert || f.key || f.operational.length);
  paintChip();
}

/** The version, and the small green chip for the signature check. */
function paintChip() {
  const ui = app.ui;
  if (!ui.versionLine) return;
  clear(ui.versionLine);
  if (!app.release) { ui.versionLine.append(h('span', { text: noReleaseYet() ? t('bar.no-release') : '…' })); return; }
  ui.versionLine.append(h('strong', { text: app.release.local ? app.release.name : app.release.tag }), ' ');
  if (releaseTooOld()) ui.versionLine.append(h('span', { class: 'ub-chip bad', text: t('release.no-tls-off') }), ' ');
  let kind = '', text = '';
  if (app.verifyState === 'work') { kind = 'work'; text = t('simple.chip.checking'); }
  else if (app.verify && app.verify.ok) { kind = 'ok'; text = t('simple.chip.ok'); }
  else if (app.verify || (app.release.local && !app.release.local.sums)) { kind = 'bad'; text = t('simple.chip.bad'); }
  if (kind) {
    ui.versionLine.append(h('span', { class: `ub-chip ${kind}` }, icon(kind === 'ok' ? 'check' : kind === 'bad' ? 'alert' : 'info'), text), ' ',
      h('button', { class: 'ub-link-btn', type: 'button', text: t('simple.chip.report'), on: { click: () => openIntegrityDialog() } }));
  }
}

// --- the drop zone: one go for the certificate, its key and the CA -----------------------------

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

async function takeFiles(files) {
  const b = app.builder;
  const bad = [];
  const certs = [];
  let key = null;
  for (const file of [...files].slice(0, 12)) {
    if (file.size > 1_000_000) { bad.push(file.name); continue; }
    const text = await readText(file);
    const blocks = text.match(PEM_BLOCK) || [];
    if (!blocks.length) bad.push(file.name);
    for (const blk of blocks) {
      const head = blk.slice(0, 40);
      if (/PRIVATE KEY/.test(head)) key = key || blk + '\n';
      else if (/BEGIN CERTIFICATE/.test(head)) {
        try { certs.push({ pem: blk + '\n', info: b.certInfo(blk + '\n')[0] }); } catch { bad.push(file.name); }
      }
    }
  }
  const results = [];
  // The key first: the checks of the certificate use it.
  if (key) {
    const r = analyzeSlot('key', key);
    if (r.ok) app.state.files.key = r.item; else results.push(r);
    app.keyForgotten = false;
  }
  const server = certs.filter(c => !c.info.is_ca);
  const cas = certs.filter(c => c.info.is_ca);
  if (server.length) {
    const keyPem = app.state.files.key && app.state.files.key.pem;
    const pick = (keyPem && server.find(c => { try { return b.crossCheck(c.pem, keyPem, null).key_matches === true; } catch { return false; } })) || server[0];
    const r = analyzeSlot('cert', pick.pem);
    if (r.ok) app.state.files.cert = r.item; else results.push(r);
  }
  if (cas.length) {
    const kept = [];
    for (const c of cas.slice(0, 8)) {
      const r = analyzeSlot('operational', c.pem);
      if (r.ok) kept.push(r.item); else results.push(r);
    }
    if (kept.length) app.state.files.operational = kept;
  }
  clear(app.ui.certProblems);
  results.forEach(r => app.ui.certProblems.append(r.node));
  if (bad.length || (!key && !certs.length)) {
    app.ui.certProblems.append(h('p', { class: 'ub-error', role: 'alert', text: t('simple.certs.nothing', { files: bad.join(', ') || '…' }) }));
  }
  syncFields();
  app.onChange();
}

function clearCerts() {
  const f = app.state.files;
  f.cert = null; f.key = null; f.operational = [];
  app.keyForgotten = false;
  clear(app.ui.certProblems);
  syncFields();
  app.onChange();
}

// --- advanced: search and filter ----------------------------------------------------------------

function renderAdvancedTools() {
  const ui = app.ui;
  ui.search = h('input', { class: 'ub-input', type: 'search', id: 'ub-search', autocomplete: 'off', placeholder: t('adv.search.ph'), 'aria-label': t('adv.search'), on: { input: debounce(applyFilter, 100) } });
  ui.onlyChanged = h('input', { type: 'checkbox', id: 'ub-only-changed', on: { change: applyFilter } });
  ui.filterCount = h('p', { class: 'ub-help', role: 'status', 'aria-live': 'polite' });
  return h('div', { class: 'ub-filter' }, ui.search,
    h('label', { class: 'ub-switch', for: 'ub-only-changed' }, ui.onlyChanged, h('span', { text: t('adv.changed-only') })), ui.filterCount);
}

function applyFilter() {
  const ui = app.ui;
  const q = ui.search.value.trim().toLowerCase();
  const only = ui.onlyChanged.checked;
  const active = Boolean(q) || only;
  let shown = 0;
  for (const [id, row] of rows) {
    const ok = !active || ((!q || (id + ' ' + row.el.textContent).toLowerCase().includes(q)) && (!only || row.el.dataset.changed === 'true'));
    if (ok) row.el.removeAttribute('data-filtered'); else row.el.setAttribute('data-filtered', 'true');
    if (ok && !row.el.hidden) shown++;
  }
  for (const s of sectionViews.values()) {
    const any = [...s.el.querySelectorAll('.ub-field')].some(x => !x.hasAttribute('data-filtered') && !x.hidden);
    if (active && !any) s.el.setAttribute('data-filtered', 'true'); else s.el.removeAttribute('data-filtered');
    if (active && any) s.el.open = true;
  }
  ui.filterCount.textContent = active ? (shown ? t('adv.count', { n: shown }) : t('adv.none')) : '';
}

// --- the template while the page is being filled in -----------------------------------------------

const lowMemoryDevice = () => /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) || (navigator.deviceMemory && navigator.deviceMemory < 4);

function startPrefetch(rel) {
  cancelPrefetch();
  if (!rel || rel.local || !rel.template || lowMemoryDevice()) return;
  const ctl = new AbortController();
  const p = { tag: rel.tag, ctl, got: 0, t0: Date.now(), onProgress: null };
  p.promise = downloadTemplate(app.builder, mirrorUrl(new URL('.', app.releasesUrl).href, rel.template.path), rel.template.size,
    (got, all) => { p.got = got; if (p.onProgress) p.onProgress(got, all); }, ctl.signal);
  p.promise.catch(() => {});
  app.prefetch = p;
}

function cancelPrefetch() {
  const p = app.prefetch;
  if (!p) return;
  app.prefetch = null;
  p.ctl.abort();
  p.promise.then(buf => app.builder.free(buf), () => {});
}

/** " · about 12 s left" once the speed is known. */
function etaText(got, all, t0) {
  const ms = Date.now() - t0;
  if (!got || ms < 1500 || got >= all) return '';
  const s = Math.round(((all - got) / (got / ms)) / 1000);
  return s >= 2 ? ` · ${t('progress.eta', { s })}` : '';
}

/** After a build in the simple view: the result card is what the page shows. */
function showResultCard() {
  const ui = app.ui;
  ui.bar.dataset.open = 'true';
  ui.resultBox.scrollIntoView({ block: 'nearest', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  ui.download.focus();
}

// --- the two listeners ----------------------------------------------------------------------------

const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

/** Turns a listener on or off; at least one must stay on (the box goes back and says why). */
function toggleListener(which, on) {
  const ui = app.ui;
  const v = app.state.values;
  const tlsOn = !tlsOff(app.state);
  const plainOn = v['plaintext.enabled'] === true;
  ui.listenerMsg.hidden = true;
  if (!on && ((which === 'tls' && !plainOn) || (which === 'plain' && !tlsOn))) {
    ui.listenerMsg.textContent = t('simple.listener.one');
    ui.listenerMsg.hidden = false;
    syncSimple();
    return;
  }
  if (which === 'tls') {
    if (on) { if (tlsOff(app.state)) delete v['network.mqtt_tls_port']; } else v['network.mqtt_tls_port'] = '0';
  } else if (on) {
    v['plaintext.enabled'] = true;
    // The networks are prefilled with the private ranges, where the user sees and edits them.
    if (!(v['plaintext.allow_from'] || []).length && v['plaintext.allow_from_anywhere'] !== true) v['plaintext.allow_from'] = [...PRIVATE_RANGES];
  } else {
    delete v['plaintext.enabled'];
  }
  syncFields(true);
  app.onChange();
  syncSimple();
}

/** The advanced form's rows for the accounts, the shared identity and the network identities live in this view while plain MQTT is on. */
function parkPlainRows(here) {
  const ids = ['plaintext.users', 'plaintext.anonymous_identity', 'plaintext.ip_identities'];
  const list = here ? ids : [...ids].reverse();
  for (const id of list) {
    const row = rows.get(id);
    if (!row) continue;
    if (here) {
      if (!row.el.__home) row.el.__home = { parent: row.el.parentNode, next: row.el.nextSibling };
      if (row.el.parentNode !== app.ui.plainRows) app.ui.plainRows.append(row.el);
    } else if (row.el.__home && row.el.parentNode === app.ui.plainRows) {
      row.el.__home.parent.insertBefore(row.el, row.el.__home.next);
    }
  }
}

// --- what the chosen listeners need of the release --------------------------------------------------

/** A release's template reads configuration format 3 from v0.2.1 on; turning the TLS listener off needs it. */
function releaseSupports(rel) {
  if (!tlsOff(app.state)) return true;
  if (rel.local) return true;
  return Boolean(rel.template) && rel.template.config_format >= 3;
}

const releaseTooOld = () => Boolean(app.release) && !releaseSupports(app.release);

/**
 * While the release was chosen by the page (not by the user), it follows the choice of listeners: the newest
 * stable release that can do what is asked, else the newest pre-release; the list greys out the ones that cannot.
 */
function ensureRelease() {
  if (!app.releases || !app.release || app.release.local || app.ensuring) return;
  const ok = app.releases.releases.filter(r => r.usable && releaseSupports(r));
  const best = defaultRelease(ok);
  const wrong = !releaseSupports(app.release);
  if (!best || !(wrong || (app.autoRelease && best.tag !== app.release.tag))) return;
  app.ensuring = true;
  app.autoRelease = true;
  const input = $$('input[type=radio]', app.ui.releaseBox).find(i => i.value === best.tag);
  renderReleases();
  if (input) { const i2 = $$('input[type=radio]', app.ui.releaseBox).find(i => i.value === best.tag); if (i2) i2.checked = true; }
  selectRelease(best).finally(() => { app.ensuring = false; });
}

/** The one thing to do next in the simple view when something is still missing: the key of its text, or ''. */
function nextStep() {
  if (needsAddress()) return 'bar.next-address';
  if (needsNetworks()) return 'bar.next-networks';
  if (needsAccount()) return 'bar.next-account';
  return '';
}
