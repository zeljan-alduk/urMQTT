// Start-up: check the browser, load the texts and the module, build the page.

function missingFeatures() {
  const m = [];
  if (typeof WebAssembly !== 'object') m.push('WebAssembly');
  if (typeof HTMLDialogElement === 'undefined' || !HTMLDialogElement.prototype.showModal) m.push('<dialog>');
  if (typeof ReadableStream === 'undefined') m.push('streams');
  if (typeof Blob === 'undefined' || !URL.createObjectURL) m.push('Blob');
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) m.push('crypto.getRandomValues');
  return m;
}

function showFatal(root, title, detail) {
  clear(root);
  root.classList.add('ub');
  root.append(h('div', { class: 'ub-wrap' }, h('div', { class: 'ub-banner err', role: 'alert', style: 'margin:40px 0' },
    h('h2', { text: title }), h('p', { text: detail }))));
}

async function main() {
  const root = document.getElementById('urmqtt-builder');
  if (!root) return;
  app.el = root;
  app.base = new URL(root.dataset.base || './', location.href).href;
  app.releasesUrl = new URL(root.dataset.releases || '/urmqtt/releases.json', location.href).href;
  app.lang = (root.dataset.lang || document.documentElement.lang || 'en').toLowerCase().split('-')[0];

  const missing = missingFeatures();
  // The content hashes of the app's files (for ?v= caching) and the emulator's version, from the page
  // that embeds us (data-v) or from manifest.json next to the script.
  try {
    const manifest = root.dataset.v ? JSON.parse(root.dataset.v) : await (await fetch(`${app.base}manifest.json`, { cache: 'no-cache' })).json();
    app.v = manifest.files || {};
    app.emulator = manifest.emulator || '';
  } catch { app.v = {}; app.emulator = ''; }
  try {
    await loadTexts(app.base, app.lang, app.v);
  } catch (e) {
    showFatal(root, 'urMQTT builder', `Could not load the page texts: ${e.message}`);
    return;
  }
  if (missing.length) {
    showFatal(root, t('title'), t('unsupported', { features: missing.join(', ') }));
    return;
  }
  const wasmName = `urmqtt-cfg${SUPPORTED_FORMAT}.wasm`;
  try {
    app.builder = await loadBuilder(`${app.base}${wasmName}${app.v[wasmName] ? `?v=${app.v[wasmName]}` : ''}`);
  } catch (e) {
    showFatal(root, t('title'), t('module-failed', { reason: e.message }));
    return;
  }
  app.schema = app.builder.schema();
  app.model = buildModel(app.schema);
  app.keyId = app.builder.minisignKeyId(RELEASE_PUBKEY);
  restore();
  resetUiState();
  renderShell();
  syncFields();
  refresh();
  document.documentElement.dataset.ubReady = '1';
  await loadReleaseList();
  document.documentElement.dataset.ubReleases = '1';
}

main().catch(e => {
  const root = document.getElementById('urmqtt-builder');
  if (root) showFatal(root, 'urMQTT builder', String(e && e.message ? e.message : e));
  console.error(e);
});
