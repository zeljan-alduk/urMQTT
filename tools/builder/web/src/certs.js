// Importing certificates and keys. A file is chosen (or pasted), parsed in the
// browser by the WebAssembly module and shown with what it says and what is
// wrong with it; nothing is sent anywhere. Private keys are held in memory only:
// not in the address bar, not in sessionStorage.

const SLOT_KINDS = {
  cert: { list: false, accept: '.pem,.crt,.cer,.txt' },
  key: { list: false, accept: '.pem,.key,.txt' },
  operational: { list: true, accept: '.pem,.crt,.cer,.txt' },
  bootstrap: { list: true, accept: '.pem,.crt,.cer,.txt' },
  logca: { list: true, accept: '.pem,.crt,.cer,.txt' },
  control: { list: false, accept: '.pem,.pub,.key,.txt' },
  signing: { list: false, accept: '.pem,.key,.txt' },
};

const daysUntil = (unix) => Math.floor((unix - app.nowUnix()) / 86400);
const dateOf = unix => formatUnix(unix, currentLang());

/** Minimum remaining validity the build requires, from the form or the default. */
function minDays(id) {
  const f = app.model.byId.get(id);
  const v = app.state.values[id];
  return v !== undefined && isWholeNumber(v) ? Number(v) : f.default;
}

/** One certificate as a key/value list. */
function certBlock(c, index, total) {
  const kv = [
    [t('cert.subject'), c.subject],
    [t('cert.issuer'), c.self_issued ? `${c.issuer} (${t('cert.self-issued')})` : c.issuer],
    [t('cert.valid'), `${dateOf(c.not_before)} → ${dateOf(c.not_after)}`],
    c.names.length ? [t('cert.names'), c.names.join(', ')] : null,
    [t('cert.key'), `${c.key_type}, ${c.signature_type}`],
    [t('cert.serial'), c.serial],
    [t('cert.sha256'), groupHex(c.sha256, 8)],
  ].filter(Boolean);
  return h('div', {},
    total > 1 ? h('h3', { text: t('cert.number', { i: index + 1, n: total }) }) : null,
    h('dl', { class: 'ub-kv' }, kv.map(([k, v]) => [h('dt', { text: k }), h('dd', { class: /sha256|serial/.test(k) ? 'mono' : '', text: v })]).flat()));
}

/**
 * Looks at PEM text for a slot. Returns {ok, item, node, problems} where `item`
 * is what the state would hold ({pem, summary, ...}) and `node` the parsed result.
 */
function analyzeSlot(slot, pem, label) {
  const b = app.builder;
  const checks = h('ul', { class: 'ub-checks' });
  const box = h('div', { class: 'ub-parsed' }, label ? h('h3', { text: label }) : null);
  const fail = (msg) => {
    box.classList.add('bad');
    box.append(h('ul', { class: 'ub-checks' }, statusLine('bad', msg)));
    return { ok: false, node: box };
  };
  try {
    if (slot === 'cert' || slot === 'operational' || slot === 'bootstrap' || slot === 'logca') {
      if (/PRIVATE KEY/.test(pem)) return fail(t('cert.is-a-key'));
      const certs = b.certInfo(pem);
      certs.forEach((c, i) => box.append(certBlock(c, i, certs.length)));
      const first = certs[0];
      const need = slot === 'cert' ? minDays('tls.min_server_cert_days') : minDays('trust.min_anchor_days');
      let ok = true;
      for (const c of certs) {
        const left = daysUntil(c.not_after);
        if (c.not_before > app.nowUnix() + 86400) { checks.append(statusLine('bad', t('cert.not-yet-valid', { date: dateOf(c.not_before) }))); ok = false; }
        else if (left < 0) { checks.append(statusLine('bad', t('cert.expired', { date: dateOf(c.not_after) }))); ok = false; }
        else if (left < need) { checks.append(statusLine('bad', t('cert.too-short', { days: left, need }))); ok = false; }
        else checks.append(statusLine('ok', t('cert.valid-for', { days: left })));
        if (!c.supported_key && slot === 'cert') { checks.append(statusLine('bad', t('cert.unsupported-key', { type: c.key_type }))); ok = false; }
      }
      if (slot === 'cert') {
        if (first.is_ca) checks.append(statusLine('warn', t('cert.is-ca')));
        if (!first.names.length) checks.append(statusLine('warn', t('cert.no-names')));
        if (certs.length > 1) checks.append(statusLine('info', t('cert.chain', { n: certs.length })));
        // Does it match the key and the CAs already chosen?
        const keyPem = app.state.files.key && app.state.files.key.pem;
        const caPem = app.state.files.operational.map(c => c.pem).join('\n');
        if (keyPem || caPem) {
          const x = b.crossCheck(pem, keyPem || null, caPem || null);
          if (x.key_matches === true) checks.append(statusLine('ok', t('cert.key-matches')));
          if (x.key_matches === false) { checks.append(statusLine('bad', t('cert.key-mismatch'))); ok = false; }
          const s = x.signers[0];
          if (caPem && s) checks.append(s.by === 'ca' && s.verified !== false ? statusLine('ok', t('cert.signed-by-ca')) : statusLine('info', t('cert.not-signed-by-ca')));
        }
      } else {
        if (!first.is_ca) checks.append(statusLine('warn', t('cert.not-a-ca')));
      }
      box.append(checks);
      const item = { pem, summary: certSummary(first, certs.length) };
      return { ok, item, node: box };
    }
    if (slot === 'key') {
      if (/CERTIFICATE/.test(pem)) return fail(t('cert.is-a-cert'));
      const k = b.keyInfo(pem);
      box.append(h('dl', { class: 'ub-kv' }, h('dt', { text: t('cert.key') }), h('dd', { text: k.key_type }), h('dt', { text: t('cert.sha256-public') }), h('dd', { class: 'mono', text: groupHex(k.public_key_sha256, 8) })));
      checks.append(statusLine('info', t('cert.key-private')));
      let ok = true;
      const certPem = app.state.files.cert && app.state.files.cert.pem;
      if (certPem) {
        const x = b.crossCheck(certPem, pem, null);
        if (x.key_matches === true) checks.append(statusLine('ok', t('cert.key-matches')));
        else { checks.append(statusLine('bad', t('cert.key-mismatch'))); ok = false; }
      }
      box.append(checks);
      return { ok, item: { pem, summary: `${k.key_type} ${t('cert.private-key')} (${groupHex(k.public_key_sha256.slice(0, 16), 8)}…)` }, node: box };
    }
    if (slot === 'control') {
      const k = b.controlKey(pem);
      box.append(h('dl', { class: 'ub-kv' }, h('dt', { text: t('control.public-key') }), h('dd', { class: 'mono', text: groupHex(k.public_key, 8) })));
      if (k.from_private) checks.append(statusLine('info', t('control.from-private')));
      checks.append(statusLine('ok', t('control.ok')));
      box.append(checks);
      return { ok: true, item: { pem: k.public_pem, summary: `Ed25519 ${t('control.public-key')} ${k.public_key.slice(0, 16)}…` }, node: box };
    }
    if (slot === 'signing') {
      const k = b.signingKeyInfo(pem);
      box.append(h('dl', { class: 'ub-kv' },
        h('dt', { text: t('sign.signer-id') }), h('dd', { class: 'mono', text: k.signer_id }),
        h('dt', { text: t('control.public-key') }), h('dd', { class: 'mono', text: groupHex(k.public_key, 8) })));
      checks.append(statusLine('info', t('sign.private')));
      box.append(checks);
      return { ok: true, item: { pem, publicKey: k.public_key, signerId: k.signer_id, summary: `Ed25519 ${t('sign.signer-id')} ${k.signer_id}` }, node: box };
    }
  } catch (e) {
    return fail(cleanMessage(e.message));
  }
  return fail('?');
}

/** The module's error text without Rust debug noise. */
const cleanMessage = m => String(m).replace(/^Error: /, '');

function certSummary(c, n) {
  const left = daysUntil(c.not_after);
  return `${c.subject}${n > 1 ? ` (+${n - 1})` : ''} · ${t('cert.until', { date: dateOf(c.not_after) })}${left < 60 ? ` (${left} ${t('common.days')})` : ''} · ${c.key_type}`;
}

/** The slot's import dialog. */
function openSlotDialog(slot) {
  const kind = SLOT_KINDS[slot];
  const pending = []; // {name, pem, result}
  const results = h('div', { class: 'ub-body-results', 'aria-live': 'polite', style: 'display:grid;gap:10px' });
  const paste = h('textarea', { class: 'ub-textarea', rows: 4, spellcheck: 'false', autocomplete: 'off', 'aria-label': t('cert.paste'), placeholder: '-----BEGIN …-----', on: { input: () => debouncedPaste() } });
  const useBtn = h('button', { class: 'ub-btn', type: 'button', disabled: true, text: t('cert.use'), on: { click: () => commit() } });
  let dlgRef;

  const existing = h('div', {});
  const renderExisting = () => {
    clear(existing);
    if (!kind.list) return;
    const list = app.state.files[slot];
    if (!list.length) return;
    existing.append(h('h3', { text: t('cert.already') }), h('ul', { class: 'ub-slot-items' }, list.map((item, i) => h('li', {}, icon('file'), h('span', { text: item.summary }),
      h('button', { class: 'ub-link-btn', type: 'button', text: t('file.remove'), on: { click: () => { list.splice(i, 1); syncFields(); app.onChange(); renderExisting(); } } })))));
  };

  const refreshResults = () => {
    clear(results);
    pending.forEach(p => results.append(p.result.node));
    useBtn.disabled = !pending.length || pending.some(p => !p.result.ok);
    if (pending.some(p => !p.result.ok) && pending.length) results.setAttribute('aria-invalid', 'true');
    else results.removeAttribute('aria-invalid');
  };

  const analyzeAll = () => {
    for (const p of pending) p.result = analyzeSlot(slot, p.pem, pending.length > 1 || p.name ? p.name : '');
    refreshResults();
  };

  const addFiles = async files => {
    const take = kind.list ? [...files] : [files[0]];
    for (const file of take.filter(Boolean)) {
      if (file.size > 1_000_000) {
        pending.push({ name: file.name, pem: '', result: { ok: false, node: h('div', { class: 'ub-parsed bad' }, h('h3', { text: file.name }), h('p', { class: 'ub-error', text: t('cert.too-big') })) } });
        continue;
      }
      const pem = await readText(file);
      if (!kind.list) pending.length = 0;
      pending.push({ name: file.name, pem });
    }
    analyzeAll();
  };

  const pasteEntry = () => {
    const i = pending.findIndex(p => p.pasted);
    if (i >= 0) pending.splice(i, 1);
    const text = paste.value.trim();
    if (!text) return;
    if (!kind.list) pending.length = 0;
    pending.push({ name: t('cert.pasted'), pem: text + '\n', pasted: true });
  };
  const debouncedPaste = debounce(() => { pasteEntry(); analyzeAll(); }, 250);

  const drop = h('div', { class: 'ub-drop' },
    icon('upload'), ' ', h('span', { text: kind.list ? t('cert.drop-many') : t('cert.drop') }),
    h('input', { type: 'file', accept: kind.accept, multiple: kind.list, 'aria-label': t('cert.choose-file'), on: { change: async e => { await addFiles(e.target.files); e.target.value = ''; } } }));
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => addFiles(e.dataTransfer.files));

  const generate = slot === 'signing' ? h('button', { class: 'ub-btn secondary', type: 'button', text: t('sign.generate'), on: { click: () => {
    const key = app.builder.newSigningKey(crypto.getRandomValues(new Uint8Array(32)));
    paste.value = key.private_pem;
    saveText(key.private_pem, `urmqtt-signing-${key.signer_id}.key`, 'application/x-pem-file');
    pending.length = 0;
    pending.push({ name: t('sign.generated'), pem: key.private_pem, pasted: true });
    analyzeAll();
  } } }) : null;

  const current = kind.list ? null : (slot === 'signing' ? app.state.signing : app.state.files[slot]);
  const removeBtn = !kind.list && current ? h('button', { class: 'ub-btn secondary', type: 'button', text: t('file.remove'), on: { click: () => {
    if (slot === 'signing') app.state.signing = null; else clearSlot(slot);
    syncFields(); app.onChange(); app.refreshSigning && app.refreshSigning(); dlgRef.close('removed');
  } } }) : null;

  const commit = () => {
    const ok = pending.filter(p => p.result.ok);
    if (!ok.length) return;
    if (kind.list) {
      for (const p of ok) {
        if (app.state.files[slot].length < 8) app.state.files[slot].push(p.result.item);
      }
    } else if (slot === 'signing') {
      app.state.signing = ok[0].result.item;
    } else {
      app.state.files[slot] = ok[0].result.item;
    }
    syncFields();
    app.onChange();
    app.refreshSigning && app.refreshSigning();
    dlgRef.close('used');
  };

  renderExisting();
  const body = [
    h('p', { class: 'ub-sub', text: t(`cert.help.${slot}`) }),
    existing,
    drop,
    h('label', { class: 'ub-label-row' }, h('span', { class: 'ub-label', style: 'font-family:inherit', text: t('cert.paste') }), paste),
    generate ? h('div', {}, generate, ' ', h('span', { class: 'ub-help', text: t('sign.generate-help') })) : null,
    h('p', { class: 'ub-help' }, icon('shield', 'ub-inline-icon'), ' ', t('cert.local-only')),
    results,
  ];
  dlgRef = openDialog({
    title: t(`cert.title.${slot}`),
    size: 'wide',
    body,
    actions: [removeBtn, dialogButton(t('common.cancel'), 'cancel', 'secondary'), useBtn],
    onOpen: d => { drop.querySelector('input').focus(); },
  });
  return dlgRef.done;
}
