// Plaintext MQTT (P1, ADR-229): the questions asked when it is switched on, the
// warning banner of its section, and the accounts editor. The accounts hold
// password hashes, never a clear password: the password is typed into an input
// element, hashed in the WebAssembly module with a salt from
// crypto.getRandomValues, and then the input is emptied (ADR-231).

/** Switches that ask before they turn on: field id -> a function that resolves true when the user agrees. */
const SWITCH_GATES = {
  'plaintext.enabled': () => askRisk('plaintext.on', 4, false),
  'plaintext.allow_from_anywhere': () => askRisk('plaintext.anywhere', 3, true),
};

async function askRisk(prefix, points, strong) {
  const body = [
    h('p', {}, h('strong', { text: t(`${prefix}.lead`) })),
    h('ul', { class: 'ub-steps' }, Array.from({ length: points }, (_, i) => h('li', { text: t(`${prefix}.point${i + 1}`) }))),
  ];
  const v = await ask({
    title: t(`${prefix}.title`), body,
    buttons: [{ label: t('common.cancel'), value: '', kind: 'secondary' }, { label: t(`${prefix}.yes`), value: 'yes', kind: strong ? 'danger' : '' }],
  });
  return v === 'yes';
}

/**
 * A short note inside the WebSocket section while it is on with password logins (ADR-272): not a warning (the
 * listener is inside TLS), only what the validator will ask for.
 */
function buildWebsocketNote() {
  const el = h('p', { class: 'ub-help ub-ws-note', id: 'ub-ws-note', hidden: true, text: t('websocket.note') });
  const sync = () => {
    el.hidden = !(app.state.values['websocket.enabled'] === true && app.state.values['websocket.auth'] === 'password');
  };
  return { el, sync };
}

/** The warning inside the section while plaintext MQTT is on; red while it accepts every address. */
function buildPlaintextBanner() {
  const text = h('p', { class: 'ub-strong' });
  const more = h('p', { class: 'ub-help' });
  const el = h('div', { class: 'ub-banner ub-plain-banner', id: 'ub-plain-banner', hidden: true }, icon('alert'), h('div', {}, text, more));
  const sync = () => {
    const on = app.state.values['plaintext.enabled'] === true;
    const anywhere = on && app.state.values['plaintext.allow_from_anywhere'] === true;
    el.hidden = !on;
    el.classList.toggle('err', anywhere);
    text.textContent = t(anywhere ? 'plaintext.banner.anywhere' : 'plaintext.banner');
    more.textContent = anywhere ? t('plaintext.banner.anywhere-more') : t('plaintext.banner-more');
  };
  return { el, sync };
}

// --- the accounts editor ---------------------------------------------------------

/** A row for an account list (`plaintext.users`, `websocket.users`): accounts (id, password set or not). Same controller as buildRow. */
function buildUsersRow(f) {
  const id = nextId('f');
  const max = f.max_items || 256;
  const views = new Map(); // state entry -> {el, sync, setIssue, focus}
  const root = h('div', { class: 'ub-field wide', data: { id: f.id, changed: 'false' } });
  const label = h('span', { class: 'ub-label', id: `${id}-l`, text: f.name });
  const changedChip = h('span', { class: 'ub-chip-changed', hidden: true, text: t('field.changed') });
  const reset = h('button', { class: 'ub-link-btn ub-reset', type: 'button', hidden: true, text: t('field.reset'), on: { click: () => resetField(f) } });
  const help = h('p', { class: 'ub-help', id: `${id}-h` }, f.help);
  const err = h('p', { class: 'ub-error', id: `${id}-e`, hidden: true });
  const note = h('p', { class: 'ub-warn', id: `${id}-n`, hidden: true, text: t('plaintext.forgotten') });
  const empty = h('p', { class: 'ub-help', text: t('plaintext.no-accounts') });
  const live = h('p', { class: 'ub-sr', role: 'status', 'aria-live': 'polite' });
  const list = h('div', { class: 'ub-accounts', role: 'group', 'aria-labelledby': `${id}-l`, 'aria-describedby': `${id}-h ${id}-e ${id}-n` });
  const add = h('button', { class: 'ub-btn small secondary ub-add-account', type: 'button', text: t('plaintext.add'), on: { click: () => {
    const rows = ensureUsers();
    if (rows.length >= max) return;
    const entry = { id: '', hash: '' };
    rows.push(entry);
    app.accountsForgotten = false;
    syncFields();
    app.onChange();
    const v = views.get(entry);
    if (v) v.focus();
  } } });
  const limit = h('span', { class: 'ub-help', text: t('plaintext.max', { n: max }), hidden: true });

  const users = () => app.state.values[f.id] || [];
  function ensureUsers() {
    if (!Array.isArray(app.state.values[f.id])) app.state.values[f.id] = [];
    return app.state.values[f.id];
  }
  const say = text => {
    live.textContent = '';
    setTimeout(() => { live.textContent = text; }, 30);
  };
  /** Removes the entry and brings the form in line. */
  function remove(entry) {
    const rows = ensureUsers();
    const i = rows.indexOf(entry);
    if (i < 0) return;
    rows.splice(i, 1);
    if (!rows.length) delete app.state.values[f.id];
    syncFields();
    app.onChange();
    // Focus moves to the neighbour, or to the add button.
    const next = users()[Math.min(i, users().length - 1)];
    (next && views.get(next) ? views.get(next) : { focus: () => add.focus() }).focus();
    say(t('plaintext.removed'));
  }

  function accountView(entry) {
    const rid = nextId('acc');
    const errId = `${rid}-e`;
    const view = { editing: false };
    const idInput = h('input', {
      class: 'ub-input', type: 'text', id: `${rid}-id`, placeholder: 'sensor-1', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
      'aria-label': t('plaintext.account-id'), 'aria-describedby': `${errId} ${id}-h`,
      on: { input: () => { entry.id = idInput.value; syncFields(); app.onChange(); } },
    });
    const pw = h('input', {
      class: 'ub-input', type: 'password', id: `${rid}-pw`, autocomplete: 'new-password', spellcheck: 'false', autocapitalize: 'off',
      'aria-label': t('plaintext.password'), 'aria-describedby': `${rid}-pwh ${errId}`,
      on: {
        change: () => setPassword(),
        // Enter hashes at once (Enter does not always fire change in an input that was filled by a button).
        keydown: e => { if (e.key === 'Enter') { e.preventDefault(); setPassword(); } },
      },
    });
    const pwHelp = h('span', { class: 'ub-help', id: `${rid}-pwh`, text: t('plaintext.password-help') });
    const show = h('button', { class: 'ub-btn small secondary', type: 'button', 'aria-pressed': 'false', text: t('plaintext.show'), on: { click: () => {
      const shown = pw.type === 'password';
      pw.type = shown ? 'text' : 'password';
      show.textContent = t(shown ? 'plaintext.hide' : 'plaintext.show');
      show.setAttribute('aria-pressed', String(shown));
    } } });
    const gen = h('button', { class: 'ub-btn small secondary', type: 'button', text: t('plaintext.generate'), on: { click: () => {
      pw.value = randomPassword(20);
      pw.type = 'text';
      show.textContent = t('plaintext.hide');
      show.setAttribute('aria-pressed', 'true');
      say(t('plaintext.generated'));
      pwHelp.textContent = t('plaintext.generated');
      pw.focus();
    } } });
    const copy = h('button', { class: 'ub-btn small secondary', type: 'button', text: t('common.copy'), on: { click: async () => {
      if (!pw.value) { pw.focus(); return; }
      const ok = await copyText(pw.value);
      say(ok ? t('common.copied') : t('common.copy-failed'));
      copy.textContent = ok ? t('common.copied') : t('common.copy-failed');
      setTimeout(() => { copy.textContent = t('common.copy'); }, 1500);
    } } });
    const use = h('button', { class: 'ub-btn small', type: 'button', text: t('plaintext.use'), on: { click: () => { if (pw.value) setPassword(); else pw.focus(); } } });
    const cancel = h('button', { class: 'ub-link-btn', type: 'button', hidden: true, text: t('common.cancel'), on: { click: () => {
      pw.value = '';
      pw.type = 'password';
      view.editing = false;
      view.sync();
      change.focus();
    } } });
    const setBox = h('div', { class: 'ub-pw-edit' }, pw, h('div', { class: 'ub-tools' }, gen, show, copy, use, cancel), pwHelp);
    const status = h('span', { class: 'ub-pw-set', text: t('plaintext.pw-set') });
    const change = h('button', { class: 'ub-btn small secondary', type: 'button', text: t('plaintext.change'), on: { click: () => {
      view.editing = true;
      view.sync();
      pw.focus();
    } } });
    const doneBox = h('div', { class: 'ub-pw-done' }, status, change);
    const rowErr = h('p', { class: 'ub-error', id: errId, hidden: true });
    const removeBtn = h('button', { class: 'ub-btn small secondary ub-account-remove', type: 'button', 'aria-label': t('plaintext.remove'), on: { click: () => remove(entry) } }, icon('x'), h('span', { text: t('plaintext.remove') }));
    const el = h('div', { class: 'ub-account' },
      h('div', { class: 'ub-account-id' }, idInput),
      h('div', { class: 'ub-account-pw' }, setBox, doneBox),
      removeBtn, rowErr);

    function setPassword() {
      const value = pw.value;
      if (!value) return;
      let hash;
      try {
        hash = app.builder.hashPassword(value, crypto.getRandomValues(new Uint8Array(16)));
      } catch (e) {
        view.setIssue(cleanMessage(e.message || String(e)));
        return;
      }
      const hadFocus = document.activeElement === pw || document.activeElement === use;
      entry.hash = hash;
      // Nothing of the clear password stays: the input is emptied and hidden again.
      pw.value = '';
      pw.type = 'password';
      show.textContent = t('plaintext.show');
      show.setAttribute('aria-pressed', 'false');
      pwHelp.textContent = t('plaintext.password-help');
      view.editing = false;
      app.accountsForgotten = false;
      view.setIssue('');
      syncFields();
      app.onChange();
      say(t('plaintext.pw-set-live'));
      if (hadFocus) change.focus();
    }

    view.el = el;
    view.sync = () => {
      if (document.activeElement !== idInput && idInput.value !== entry.id) idInput.value = entry.id;
      const has = Boolean(entry.hash);
      const editing = !has || view.editing;
      setBox.hidden = !editing;
      doneBox.hidden = editing;
      cancel.hidden = !(has && editing);
    };
    view.setIssue = text => {
      rowErr.textContent = text || '';
      rowErr.hidden = !text;
      el.dataset.invalid = String(Boolean(text));
      if (text) { idInput.setAttribute('aria-invalid', 'true'); } else idInput.removeAttribute('aria-invalid');
    };
    view.focus = () => idInput.focus();
    view.sync();
    return view;
  }

  root.append(
    h('div', { class: 'ub-label-row' }, label, changedChip, reset),
    h('div', { class: 'ub-field-group', style: 'display:grid;gap:10px' }, note, empty, list, h('div', { class: 'ub-tools' }, add, limit), live),
    help, err);

  const ctl = {
    id: f.id, el: root, field: f, input: list,
    sync(force) {
      const rows = users();
      for (const [entry, v] of views) {
        if (!rows.includes(entry)) { v.el.remove(); views.delete(entry); }
      }
      rows.forEach((entry, i) => {
        let v = views.get(entry);
        if (!v) { v = accountView(entry); views.set(entry, v); }
        if (list.children[i] !== v.el) list.insertBefore(v.el, list.children[i] || null);
        v.sync(force);
      });
      empty.hidden = rows.length > 0;
      note.hidden = !(app.accountsForgotten && rows.length === 0);
      add.disabled = rows.length >= max;
      limit.hidden = rows.length < max;
      const changed = isChanged(f, app.state.values[f.id]);
      root.dataset.changed = String(changed);
      changedChip.hidden = !changed;
      reset.hidden = !changed;
      root.hidden = !isApplicable(f, app.state);
    },
    /** The validator's and the page's problems for this field, each for its row (or for the whole list). */
    setIssues(issues) {
      const { rows } = draftUsers(users());
      const general = [];
      const per = new Map();
      for (const is of issues) {
        let r = is.row;
        if (r === undefined) {
          const prefix = `${f.id}[`;
          const m = (is.path || '').startsWith(prefix) ? /^(\d+)\]/.exec(is.path.slice(prefix.length)) : null;
          if (m) r = rows[Number(m[1])];
        }
        if (r === undefined) general.push(is.message);
        else per.set(r, [...(per.get(r) || []), is.message]);
      }
      this.setIssue(general.join(' '));
      users().forEach((entry, i) => {
        const v = views.get(entry);
        if (v) v.setIssue((per.get(i) || []).join(' '));
      });
    },
    setIssue(text) {
      err.textContent = text || '';
      err.hidden = !text;
      root.dataset.invalid = String(Boolean(text));
    },
    firstControl: () => root.querySelector('input, button') || root,
    focus() {
      const p = userProblems(users())[0];
      const target = p && views.get(users()[p.row]);
      (target || { focus: () => ctl.firstControl().focus() }).focus();
    },
  };
  return ctl;
}
