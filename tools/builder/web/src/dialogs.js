// Icons and modal dialogs. Dialogs are native <dialog> elements opened with
// showModal(): the rest of the page becomes inert, Tab stays inside, Escape
// closes, and the focus returns to the button that opened it. They are added
// inside the page's root element so that its colour variables apply.

const SVG_NS = 'http://www.w3.org/2000/svg';

const ICONS = {
  shield: 'M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z M9 12l2 2 4-4',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  x: 'M6 6l12 12M18 6L6 18',
  alert: 'M12 4l9 16H3z M12 10v4 M12 17.2v.1',
  info: 'M12 21a9 9 0 100-18 9 9 0 000 18z M12 11v5 M12 7.8v.1',
  download: 'M12 4v11 M7 11l5 5 5-5 M5 20h14',
  upload: 'M12 16V5 M7 9l5-5 5 5 M5 20h14',
  play: 'M8 5l11 7-11 7z',
  stop: 'M7 7h10v10H7z',
  copy: 'M9 9h10v11H9z M5 15V4h10',
  chevron: 'M6 9l6 6 6-6',
  refresh: 'M20 12a8 8 0 11-2.3-5.7 M20 4v5h-5',
  file: 'M7 3h7l4 4v14H7z M14 3v5h4',
  key: 'M14 10a4 4 0 11-1 2.6L4 21v-3l2-2h2v-2l3.5-3.5',
  list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
  spin: 'M12 3a9 9 0 109 9',
};

/** An inline SVG icon (decorative: aria-hidden). */
function icon(name, cls) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', cls ? `ub-ico ${cls}` : 'ub-ico');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  for (const d of ICONS[name].split(' M')) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d.startsWith('M') ? d : 'M' + d);
    svg.append(p);
  }
  return svg;
}

/**
 * Opens a modal dialog. `body` is a node (or list of nodes), `actions` buttons
 * for the footer. Returns {dialog, close(value), done}: `done` resolves with the
 * value the dialog was closed with ('' for Escape and the close button).
 * `onOpen(dialog)` runs after it is shown (set the initial focus there).
 */
function openDialog({ title, body, actions = [], size = '', onOpen, dismissible = true }) {
  const id = nextId('dlg');
  let resolve;
  const done = new Promise(r => { resolve = r; });
  const dlg = h('dialog', { class: `ub-dialog ${size}`.trim(), 'aria-labelledby': `${id}-t` });
  const closeBtn = h('button', { class: 'ub-x', type: 'button', 'aria-label': t('common.close'), on: { click: () => dlg.close('') } }, icon('x'));
  dlg.append(
    h('header', {}, h('h2', { id: `${id}-t`, text: title }), closeBtn),
    h('div', { class: 'ub-body' }, body),
  );
  if (actions.length) dlg.append(h('footer', {}, actions));
  dlg.addEventListener('close', () => {
    const v = dlg.returnValue;
    dlg.remove();
    resolve(v);
  });
  if (!dismissible) dlg.addEventListener('cancel', e => e.preventDefault());
  // A click on the backdrop (the dialog element itself, outside its box) closes it.
  dlg.addEventListener('mousedown', e => {
    if (dismissible && e.target === dlg) dlg.close('');
  });
  app.el.append(dlg);
  dlg.showModal();
  if (onOpen) onOpen(dlg);
  return { dialog: dlg, close: v => dlg.close(v ?? ''), done };
}

/** A footer button that closes the dialog with `value`. */
function dialogButton(label, value, kind = '', onClick) {
  return h('button', {
    class: `ub-btn ${kind}`.trim(),
    type: 'button',
    'data-value': value,
    on: {
      click: async e => {
        if (onClick) {
          const keep = await onClick(e);
          if (keep === false) return;
        }
        e.target.closest('dialog').close(value);
      },
    },
  }, label);
}

/** A question with two or more answers; resolves to the chosen value ('' if dismissed). */
function ask({ title, body, buttons, size = 'narrow' }) {
  return openDialog({ title, body, size, actions: buttons.map(b => dialogButton(b.label, b.value, b.kind)) }).done;
}

/** A line with a status icon, for checks and verification results. */
function statusLine(kind, text) {
  const name = kind === 'ok' ? 'check' : kind === 'bad' ? 'x' : kind === 'warn' ? 'alert' : 'info';
  return h('li', { class: kind }, icon(name), h('span', {}, text));
}
