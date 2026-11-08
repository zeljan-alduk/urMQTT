// The form: one row per field of the schema, in cards per section. Every field
// shows its default (as the placeholder, or as the selected choice) and writes
// nothing into the state until the user changes it; a changed field is marked,
// and each field and each section can be reset. Field names are the TOML keys
// and the help is the schema's (English); only the section names are translated.

/** field id -> row controller {el, sync(), setIssue(text), focus()} */
const rows = new Map();
/** section id -> {el, count, sync()} */
const sectionViews = new Map();

function getValue(f) { return app.state.values[f.id]; }

/** Sets (or, with undefined, resets) a field and updates what depends on it. */
function setValue(f, v) {
  if (v === undefined) delete app.state.values[f.id];
  else app.state.values[f.id] = v;
  syncFields();
  app.onChange();
}

function resetField(f) {
  if (isFileType(f)) clearSlot(f.fileKey.slot);
  delete app.state.values[f.id];
  syncFields(true);
  app.onChange();
}

/** Brings every row and section header in line with the state. */
function syncFields(force = false) {
  for (const row of rows.values()) row.sync(force);
  for (const s of sectionViews.values()) s.sync();
}

function fieldRange(f) {
  // A field whose range has a meaning of its own (network.mtu: 0 is "from DHCP").
  if (has(`field.range.${f.id}`)) return t(`field.range.${f.id}`);
  if (f.type === 'uint') return t('field.range', { min: f.min, max: f.max });
  return '';
}

function unitHint(f) {
  const m = /_(ms|mb|s|min|h|days)$/.exec(f.name);
  return m ? t('unit.' + m[1]) : '';
}

/** The text of an enum choice: the TOML value, and a short explanation if the page has one. */
function enumLabel(f, variant) {
  const key = `enum.${f.id}.${variant}`;
  return has(key) ? `${variant} — ${t(key)}` : variant;
}

function buildRow(f) {
  if (isUserList(f)) return buildUsersRow(f);
  const id = nextId('f');
  const ctl = {};
  const label = h('label', { class: 'ub-label', for: id, text: f.name });
  const changedChip = h('span', { class: 'ub-chip-changed', hidden: true, text: t('field.changed') });
  const reset = h('button', { class: 'ub-link-btn ub-reset', type: 'button', hidden: true, text: t('field.reset'), on: { click: () => resetField(f) } });
  const help = h('p', { class: 'ub-help', id: `${id}-h` }, f.help, ' ', [fieldRange(f), unitHint(f)].filter(Boolean).join(' '));
  const err = h('p', { class: 'ub-error', id: `${id}-e`, hidden: true });
  const warn = h('p', { class: 'ub-warn', id: `${id}-w`, hidden: true });
  const root = h('div', { class: 'ub-field', data: { id: f.id, changed: 'false' } });
  const describedBy = `${id}-h ${id}-e ${id}-w`;
  let control;
  let extraSync = () => {};

  const isList = isListType(f);
  if (f.fileKey && f.fileKey.slot !== 'revoked') {
    root.classList.add('wide');
    label.removeAttribute('for');
    const slot = buildSlot(f, id);
    control = slot.el;
    extraSync = slot.sync;
  } else if (f.type === 'bool') {
    const input = h('input', { type: 'checkbox', id, 'aria-describedby': describedBy, on: { change: async () => {
      // Some switches ask first; only the user flipping it asks (not an import or the address bar).
      const gate = SWITCH_GATES[f.id];
      if (input.checked && gate) {
        input.checked = false;
        if (!(await gate())) return;
        input.checked = true;
      }
      setValue(f, input.checked);
    } } });
    const text = h('span', {});
    control = h('div', { class: 'ub-switch' }, input, text);
    extraSync = () => {
      const v = getValue(f);
      const on = v === undefined ? f.default : v;
      input.checked = on;
      text.textContent = (on ? t('common.on') : t('common.off')) + (v === undefined ? ` (${t('field.default')})` : '');
    };
  } else if (f.type === 'enum' && f.variants.length <= 4) {
    root.classList.add('wide');
    label.removeAttribute('for');
    label.id = `${id}-l`;
    const name = nextId('r');
    const radios = f.variants.map(v => {
      const input = h('input', { type: 'radio', name, value: v, 'aria-describedby': describedBy, on: { change: () => setValue(f, v === f.default ? undefined : v) } });
      return { v, input, el: h('label', {}, input, h('span', { text: enumLabel(f, v) + (v === f.default ? ` (${t('field.default')})` : '') })) };
    });
    control = h('div', { class: 'ub-seg', role: 'radiogroup', 'aria-labelledby': `${id}-l` }, radios.map(r => r.el));
    extraSync = () => {
      const cur = getValue(f) ?? f.default;
      for (const r of radios) r.input.checked = r.v === cur;
    };
  } else if (f.type === 'enum') {
    const select = h('select', { class: 'ub-select', id, 'aria-describedby': describedBy, on: { change: () => setValue(f, select.value === f.default ? undefined : select.value) } },
      f.variants.map(v => h('option', { value: v, text: enumLabel(f, v) + (v === f.default ? ` (${t('field.default')})` : '') })));
    control = select;
    extraSync = () => { select.value = getValue(f) ?? f.default; };
  } else if (isList || f.id === 'tls.revoked_serials') {
    root.classList.add('wide');
    const hasDefault = isList && f.default.length > 0;
    const placeholder = hasDefault ? f.default.join('\n') : (f.example || (f.id === 'tls.revoked_serials' ? '0a1b2c3d' : ''));
    const ta = h('textarea', { class: 'ub-textarea', id, rows: Math.min(Math.max(3, (hasDefault ? f.default.length : 3) + 1), 7), spellcheck: 'false', autocomplete: 'off', placeholder, 'aria-describedby': describedBy, on: {
      input: () => {
        const items = lines(ta.value);
        setValue(f, items.length ? items : (none && none.checked ? [] : undefined));
      },
    } });
    let none = null;
    const tools = [];
    if (hasDefault) {
      none = h('input', { type: 'checkbox', on: { change: () => {
        if (none.checked) { ta.value = ''; setValue(f, []); } else setValue(f, undefined);
      } } });
      tools.push(h('label', { class: 'ub-listmode' }, none, h('span', { text: t('list.none') })));
      tools.push(h('button', { class: 'ub-link-btn', type: 'button', text: t('list.copy-default'), on: { click: () => {
        if (none) none.checked = false;
        ta.value = f.default.join('\n');
        ta.dispatchEvent(new Event('input'));
        ta.focus();
      } } }));
    }
    const hintKey = has(`list.hint.${f.item}`) ? `list.hint.${f.item}` : 'list.hint';
    control = h('div', { class: 'ub-field-group', style: 'display:grid;gap:6px' }, ta, h('div', { class: 'ub-tools' }, tools, h('span', { class: 'ub-help', text: t(hintKey) })));
    extraSync = force => {
      const v = getValue(f);
      const editing = !force && document.activeElement === ta;
      if (v === undefined) { if (!editing) ta.value = ''; if (none) none.checked = false; ta.disabled = false; }
      else if (v.length === 0) { ta.value = ''; if (none) none.checked = true; ta.disabled = Boolean(none); }
      else { if (!editing) ta.value = v.join('\n'); if (none) none.checked = false; ta.disabled = false; }
    };
  } else {
    const placeholder = f.default !== null && f.default !== undefined ? String(f.default) : f.example;
    const input = h('input', { class: 'ub-input', id, type: 'text', inputmode: f.type === 'uint' ? 'numeric' : 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder, 'aria-describedby': describedBy, on: {
      input: () => setValue(f, input.value.trim() === '' ? undefined : input.value),
    } });
    control = input;
    extraSync = force => {
      const v = getValue(f);
      if (force || document.activeElement !== input) input.value = v === undefined ? '' : String(v);
    };
  }

  root.append(h('div', { class: 'ub-label-row' }, label, changedChip, reset), control, help, err, warn);

  ctl.id = f.id;
  ctl.el = root;
  ctl.field = f;
  ctl.input = control;
  ctl.sync = force => {
    extraSync(force);
    const changed = !isApplicable(f, app.state) ? false : isFileType(f) ? fileIsSet(f, app.state) : f.id === 'tls.revoked_serials' ? (getValue(f) || []).some(s => String(s).trim()) : isChanged(f, getValue(f));
    root.dataset.changed = String(changed);
    changedChip.hidden = !changed;
    reset.hidden = !changed;
    root.hidden = !isApplicable(f, app.state);
  };
  ctl.setIssue = (text, kind = 'error') => {
    const el = kind === 'error' ? err : warn;
    el.textContent = text || '';
    el.hidden = !text;
    if (kind === 'error') {
      root.dataset.invalid = String(Boolean(text));
      if (text) ctl.firstControl().setAttribute('aria-invalid', 'true');
      else ctl.firstControl().removeAttribute('aria-invalid');
    }
  };
  ctl.firstControl = () => root.querySelector('input, select, textarea, button.ub-btn') || root;
  ctl.focus = () => ctl.firstControl().focus();
  return ctl;
}

/** The sections as <details> cards; returns the container. */
function renderSections() {
  const wrap = h('div', { class: 'ub-main-sections', style: 'display:grid;gap:18px' });
  const open = new Set(['network', 'tls', 'trust']);
  const sectionBody = fields => h('div', { class: 'ub-fields' }, fields.map(f => {
    const row = buildRow(f);
    rows.set(f.id, row);
    return row.el;
  }));

  for (const s of app.model.sections) {
    const count = h('span', { class: 'ub-badge changed', hidden: true });
    const resetBtn = h('button', { class: 'ub-btn small secondary', type: 'button', text: t('section.reset'), hidden: true, on: { click: () => resetSection(s) } });
    const banner = s.id === 'plaintext' ? buildPlaintextBanner() : s.id === 'websocket' ? buildWebsocketNote() : null;
    const details = h('details', { class: 'ub-card', id: `sec-${s.id}`, open: open.has(s.id) },
      h('summary', {}, h('span', { class: 'ub-title' }, h('h2', { text: t('section.' + s.id) }), count), icon('chevron', 'ub-chev')),
      h('div', { class: 'ub-tools', style: 'justify-content:flex-end;margin:-4px 0 10px' }, resetBtn),
      banner ? banner.el : null,
      sectionBody(s.fields));
    sectionViews.set(s.id, {
      el: details,
      sync: () => {
        if (banner) banner.sync();
        const n = s.fields.filter(f => rows.get(f.id) && rows.get(f.id).el.dataset.changed === 'true').length;
        count.hidden = n === 0;
        count.textContent = t('section.changed', { n });
        resetBtn.hidden = n === 0;
        resetBtn.parentElement.hidden = n === 0;
      },
    });
    wrap.append(details);
  }
  if (app.model.top.length) {
    const details = h('details', { class: 'ub-card', id: 'sec-misc' },
      h('summary', {}, h('span', { class: 'ub-title' }, h('h2', { text: t('section.misc') })), icon('chevron', 'ub-chev')),
      sectionBody(app.model.top));
    sectionViews.set('misc', { el: details, sync: () => {} });
    wrap.append(details);
  }
  return wrap;
}

async function resetSection(s) {
  const withFiles = s.fields.some(f => isFileType(f) && fileIsSet(f, app.state));
  if (withFiles) {
    const v = await ask({
      title: t('section.reset-title'),
      body: h('p', { text: t('section.reset-files') }),
      buttons: [{ label: t('common.cancel'), value: '', kind: 'secondary' }, { label: t('section.reset'), value: 'yes', kind: 'danger' }],
    });
    if (v !== 'yes') return;
  }
  for (const f of s.fields) {
    if (isFileType(f)) clearSlot(f.fileKey.slot);
    delete app.state.values[f.id];
  }
  syncFields(true);
  app.onChange();
  announce(t('section.reset-done'));
}

/** Opens the section a field is in and focuses the field. */
function focusField(id) {
  const row = rows.get(id);
  if (!row) return;
  if (!app.advanced && simpleFocus(id)) return;
  if (!app.advanced) setAdvanced(true);
  const details = row.el.closest('details');
  if (details) details.open = true;
  row.el.scrollIntoView({ block: 'center', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  row.focus();
}

/** Puts the validator's problems next to their fields; returns those that belong to none. */
function showIssues(issues) {
  const loose = [];
  const byField = new Map();
  for (const is of issues) {
    if (is.field && rows.has(is.field.id)) {
      if (!byField.has(is.field.id)) byField.set(is.field.id, []);
      byField.get(is.field.id).push(is);
    } else loose.push(is);
  }
  for (const [id, row] of rows) {
    const mine = byField.get(id);
    if (row.setIssues) row.setIssues(mine || []);
    else row.setIssue(mine ? mine.map(m => m.message).join(' ') : '', 'error');
  }
  return loose;
}

/** Slot widget: set / not set, with the buttons that open the import dialog. */
function buildSlot(f, id) {
  const slot = f.fileKey.slot;
  const status = h('span', { id: `${id}-s` });
  const choose = h('button', { class: 'ub-btn small secondary', type: 'button', id, 'aria-describedby': `${id}-s ${id}-h`, on: { click: () => openSlotDialog(slot) } });
  const remove = h('button', { class: 'ub-btn small secondary', type: 'button', hidden: true, text: t('file.remove'), on: { click: () => { clearSlot(slot); syncFields(); app.onChange(); } } });
  const items = h('ul', { class: 'ub-slot-items' });
  const el = h('div', { class: 'ub-slot', data: { set: 'false' } },
    h('div', { class: 'ub-slot-line' }, status, h('span', { class: 'ub-tools' }, choose, remove)), items);
  const sync = () => {
    clear(items);
    if (f.fileKey.list) {
      const list = app.state.files[slot];
      el.dataset.set = String(list.length > 0);
      status.textContent = list.length ? t('file.count', { n: list.length }) : t('file.none');
      choose.textContent = list.length ? t('file.manage') : t('file.choose');
      remove.hidden = true;
      list.forEach((item, i) => {
        items.append(h('li', {}, icon('file'), h('span', { text: describeItem(slot, item) }),
          h('button', { class: 'ub-link-btn', type: 'button', text: t('file.remove'), on: { click: () => { app.state.files[slot].splice(i, 1); syncFields(); app.onChange(); } } })));
      });
    } else {
      const item = app.state.files[slot];
      el.dataset.set = String(Boolean(item));
      const none = slot === 'control' ? t('file.none-optional') : slot === 'key' && app.keyForgotten ? t('file.key-forgotten') : t('file.none');
      status.textContent = item ? describeItem(slot, item) : none;
      if (item) app.keyForgotten = false;
      choose.textContent = item ? t('file.replace') : t('file.choose');
      remove.hidden = !item;
    }
  };
  return { el, sync };
}

function clearSlot(slot) {
  if (slot === 'operational' || slot === 'bootstrap') app.state.files[slot] = [];
  else if (slot === 'revoked') delete app.state.values['tls.revoked_serials'];
  else app.state.files[slot] = null;
}

/** One line about an imported file, for the slot and the lists. */
function describeItem(slot, item) {
  return item.summary || t('file.imported');
}
