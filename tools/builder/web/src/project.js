// The "Project and secrets" card (NOW-16, ADR-300): save and open an encrypted project file, keep an encrypted
// copy in this browser, wipe the secrets from memory. The sealing itself is vault.js; nothing here is sent
// anywhere, and the passphrase lives only in a dialog's input field until the operation ends.

const VAULT_KEY = 'urmqtt-builder-vault-v1';

function vaultStored() {
  try { return localStorage.getItem(VAULT_KEY); } catch { return null; }
}

/** The text of a vault error, in the page's language. */
function vaultMessage(e) {
  if (e instanceof VaultError) return t(`project.err.${e.code}`, { n: MIN_PASSPHRASE });
  return t('project.err.other', { reason: e && e.message ? e.message : String(e) });
}

/**
 * Asks for a passphrase in a dialog (twice when `confirm`). Resolves to the passphrase or null. The fields are
 * emptied when the dialog closes. `check(passphrase)` may return an error text (the dialog stays open) or ''.
 */
function askPassphrase({ title, help, confirm = false, okLabel, extra = null, check }) {
  const id = nextId('pp');
  const pass = h('input', { class: 'ub-input', id: `${id}-p`, type: 'password', autocomplete: confirm ? 'new-password' : 'current-password', spellcheck: 'false', 'data-role': 'passphrase' });
  const again = confirm ? h('input', { class: 'ub-input', id: `${id}-c`, type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'data-role': 'passphrase-again' }) : null;
  const err = h('p', { class: 'ub-warn', role: 'alert', hidden: true, 'data-role': 'error' });
  const showError = m => { err.textContent = m; err.hidden = !m; };
  const body = [
    help ? h('p', { class: 'ub-help', text: help }) : null,
    extra,
    h('label', { for: `${id}-p`, text: t('project.passphrase') }), pass,
    again ? h('label', { for: `${id}-c`, text: t('project.passphrase-again'), style: 'margin-top:10px;display:block' }) : null, again,
    confirm ? h('p', { class: 'ub-help', text: t('project.passphrase-help', { n: MIN_PASSPHRASE }) }) : null,
    err,
  ];
  let answer = null;
  const dlg = openDialog({
    title, body, size: 'narrow',
    actions: [
      dialogButton(t('common.cancel'), '', 'secondary'),
      dialogButton(okLabel, 'ok', '', async () => {
        const p = pass.value;
        if (confirm) {
          if ([...p.normalize('NFKC')].length < MIN_PASSPHRASE) { showError(t('project.err.weak', { n: MIN_PASSPHRASE })); return false; }
          if (p !== again.value) { showError(t('project.err.mismatch')); return false; }
        } else if (!p) { showError(t('project.err.empty')); return false; }
        if (check) {
          const m = await check(p);
          if (m) { showError(m); return false; }
        }
        answer = p;
      }),
    ],
    onOpen: () => pass.focus(),
  });
  return dlg.done.then(() => { pass.value = ''; if (again) again.value = ''; return answer; });
}

/** Puts a state (from a project file or the browser copy) into the form. The chosen release stays. */
function applyOpenedState(s) {
  s.release = app.state.release;
  app.state = s;
  app.keyForgotten = false;
  app.accountsForgotten = false;
  app.ui.name.value = s.name;
  if (s.advanced === true && !app.advanced) setAdvanced(true);
  syncFields(true);
  app.ui.presetButtons.forEach((b, i) => b.setAttribute('aria-pressed', String(['lab', 'vps', 'auto', 'defaults'][i] === s.preset)));
  app.onChange();
}

function projectStatus(text, kind = 'ok') {
  const el = app.ui.projectStatus;
  el.textContent = text;
  el.className = `ub-help ub-project-status ${kind}`;
  el.hidden = !text;
  if (text) announce(text);
}

function paintProjectButtons() {
  const has = vaultStored() !== null;
  app.ui.projectBrowserOpen.hidden = !has;
  app.ui.projectBrowserDelete.hidden = !has;
}

async function saveProjectFile() {
  const pass = await askPassphrase({ title: t('project.save.title'), help: t('project.save.help'), confirm: true, okLabel: t('project.save.ok') });
  if (pass === null) return;
  try {
    projectStatus(t('project.working'), 'info');
    const text = await sealValue(pass, snapshotState(app.state));
    saveText(text, `${(app.state.name || 'urmqtt').replace(/[^A-Za-z0-9._-]/g, '_')}.urmqtt-project`, 'application/json');
    projectStatus(t('project.saved'));
  } catch (e) { projectStatus(vaultMessage(e), 'bad'); }
}

/** Opens `text` with a passphrase asked for in a dialog; applies it on success. Wrong passphrases keep the dialog open. */
async function openEnvelopeText(text, title, extra) {
  try { parseEnvelope(text); } catch (e) { projectStatus(vaultMessage(e), 'bad'); return false; }
  let opened = null;
  const pass = await askPassphrase({
    title, help: t('project.open.help'), okLabel: t('project.open.ok'), extra,
    check: async p => {
      try { opened = stateFromSnapshot(app.model, await openValue(p, text)); return ''; } catch (e) { return vaultMessage(e); }
    },
  });
  if (pass === null || !opened) return false;
  applyOpenedState(opened);
  projectStatus(t('project.opened'));
  return true;
}

async function openProjectFile() {
  const file = h('input', { type: 'file', id: nextId('pf'), accept: '.urmqtt-project,.json,application/json', 'data-role': 'project-file' });
  const picked = h('div', {}, h('label', { for: file.id, text: t('project.file') }), file);
  const ask1 = await openDialog({
    title: t('project.open.title'), size: 'narrow', body: [h('p', { class: 'ub-help', text: t('project.open.pick') }), picked],
    actions: [dialogButton(t('common.cancel'), '', 'secondary'), dialogButton(t('project.open.next'), 'ok', '', () => {
      if (!file.files || !file.files[0]) return false;
      return undefined;
    })],
  }).done;
  const f = file.files && file.files[0];
  if (ask1 !== 'ok' || !f) return;
  if (f.size > MAX_ENVELOPE_BYTES * 1.4) { projectStatus(t('project.err.format'), 'bad'); return; }
  await openEnvelopeText(await readText(f), t('project.open.title'));
}

async function keepBrowserCopy() {
  const pass = await askPassphrase({ title: t('project.browser.title'), help: t('project.browser.help'), confirm: true, okLabel: t('project.save.ok') });
  if (pass === null) return;
  try {
    projectStatus(t('project.working'), 'info');
    const text = await sealValue(pass, snapshotState(app.state));
    localStorage.setItem(VAULT_KEY, text);
    paintProjectButtons();
    projectStatus(t('project.browser.saved'));
  } catch (e) { projectStatus(e instanceof VaultError ? vaultMessage(e) : t('project.err.storage'), 'bad'); }
}

async function openBrowserCopy() {
  const text = vaultStored();
  if (text === null) { paintProjectButtons(); return; }
  await openEnvelopeText(text, t('project.browser.open'));
}

async function deleteBrowserCopy() {
  const v = await ask({
    title: t('project.browser.delete'), body: h('p', { text: t('project.browser.delete-confirm') }),
    buttons: [{ label: t('common.cancel'), value: '', kind: 'secondary' }, { label: t('project.browser.delete'), value: 'yes', kind: 'danger' }],
  });
  if (v !== 'yes') return;
  try { localStorage.removeItem(VAULT_KEY); } catch { /* blocked: nothing was kept */ }
  paintProjectButtons();
  projectStatus(t('project.browser.deleted'));
}

/** Drops every secret the page holds: the private key, the signing key, the accounts and the built image (which contains them). */
function wipeSecrets() {
  const hadKey = Boolean(app.state.files.key);
  app.state.files.key = null;
  app.state.signing = null;
  let accounts = 0;
  for (const f of app.model.fields) {
    if (!isUserList(f)) continue;
    accounts += (app.state.values[f.id] || []).length;
    delete app.state.values[f.id];
  }
  if (app.result && app.result.url) URL.revokeObjectURL(app.result.url);
  app.result = null;
  app.keyForgotten = hadKey && Boolean(app.state.files.cert);
  app.accountsForgotten = accounts > 0;
  for (const el of app.el.querySelectorAll('input[type=password], textarea[data-secret]')) el.value = '';
  syncFields(true);
  app.onChange();
  projectStatus(t('project.wiped'));
}

function renderProject() {
  const ui = app.ui;
  const btn = (key, fn, cls = 'secondary', extra = {}) => h('button', { class: `ub-btn small ${cls}`, type: 'button', text: t(key), on: { click: fn }, ...extra });
  ui.projectStatus = h('p', { class: 'ub-help ub-project-status', role: 'status', 'aria-live': 'polite', hidden: true });
  ui.projectBrowserOpen = btn('project.browser.open', () => openBrowserCopy(), 'secondary', { id: 'ub-project-browser-open' });
  ui.projectBrowserDelete = btn('project.browser.delete', () => deleteBrowserCopy(), 'secondary', { id: 'ub-project-browser-delete' });
  const card = h('section', { class: 'ub-card ub-project', id: 'ub-project', 'aria-labelledby': 'ub-h-project' },
    h('header', {}, h('h2', { id: 'ub-h-project', text: t('project.title') })),
    h('p', { class: 'ub-sub', text: t('project.help') }),
    h('div', { class: 'ub-tools' },
      btn('project.save', () => saveProjectFile(), 'secondary', { id: 'ub-project-save' }),
      btn('project.open', () => openProjectFile(), 'secondary', { id: 'ub-project-open' }),
      btn('project.browser.keep', () => keepBrowserCopy(), 'secondary', { id: 'ub-project-browser-keep' }),
      ui.projectBrowserOpen, ui.projectBrowserDelete,
      btn('project.wipe', () => wipeSecrets(), 'danger', { id: 'ub-project-wipe' })),
    h('p', { class: 'ub-help', text: t('project.limits') }),
    ui.projectStatus);
  paintProjectButtons();
  return card;
}
