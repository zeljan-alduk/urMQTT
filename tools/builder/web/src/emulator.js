// "Try in the emulator" (C1g, ADR-228). Nothing of the emulator is fetched, parsed or started before the
// user clicks the button: the page carries only this dialog. The click opens it with what the emulator is
// and what it is not; "Start" then loads the emulator (a module under emulator/<version>/, about 3 MB the
// first time and then cached for good) and boots the image just built, with the serial output as text and
// the screen on a canvas. Closing the dialog stops it: the emulator lives in a Worker that is terminated,
// which frees all of its memory.

/** Why the emulator cannot be offered here: a text key, or '' when it can. */
function emulatorUnavailable() {
  if (!app.emulator) return 'emulator.no-runtime';
  if (!self.crossOriginIsolated || typeof SharedArrayBuffer === 'undefined' || typeof Worker === 'undefined') return 'emulator.no-isolation';
  const phone = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) || (navigator.deviceMemory && navigator.deviceMemory < 4);
  return phone ? 'emulator.phone' : '';
}

/** The machine's memory for a configuration: the kernel needs its heap and some room besides. */
function emulatorMemory() {
  const v = app.state.values['memory.kernel_heap_mb'];
  const heap = v !== undefined && isWholeNumber(v) ? Number(v) : app.model.byId.get('memory.kernel_heap_mb').default;
  if (heap <= 128) return { ram: '512M', heap, ok: true };
  if (heap <= 512) return { ram: '1024M', heap, ok: true };
  return { ram: '1024M', heap, ok: false };
}

const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g; // eslint-disable-line no-control-regex

function openEmulatorDialog() {
  const r = app.result;
  if (!r || app.stale) return;
  const mem = emulatorMemory();
  let vm = null;
  let abort = null;
  let starting = false;
  let introRef = null;
  let text = '';
  const checks = h('ul', { class: 'ub-checks', 'aria-live': 'polite' });
  const status = h('p', { class: 'ub-help', role: 'status', 'aria-live': 'polite', text: t('emulator.idle') });
  const canvas = h('canvas', { width: '1280', height: '800', role: 'img', 'aria-label': t('emulator.screen'), hidden: true });
  const log = h('pre', { class: 'ub-emu-log', tabindex: '0', role: 'log', 'aria-label': t('emulator.serial'), hidden: true });
  const skip = h('input', { type: 'checkbox', id: 'ub-emu-skip', checked: true });
  const startBtn = h('button', { class: 'ub-btn', type: 'button', id: 'ub-emu-start', disabled: !mem.ok }, icon('play'), t('emulator.start'));
  const stopBtn = h('button', { class: 'ub-btn secondary', type: 'button', id: 'ub-emu-stop', hidden: true }, icon('stop'), t('emulator.stop'));
  const resetBtn = h('button', { class: 'ub-btn secondary', type: 'button', id: 'ub-emu-reset', hidden: true }, icon('refresh'), t('emulator.reset'));
  const closeBtn = dialogButton(t('common.close'), 'close', 'secondary');

  const seen = new Set();
  const addCheck = (id, kind, msg) => {
    if (seen.has(id)) return;
    seen.add(id);
    checks.append(statusLine(kind, msg));
  };
  // What the serial output says that the page can check against what it built.
  const inspect = line => {
    const fp = /config: fingerprint ([0-9a-f]{64})/.exec(line);
    if (fp) {
      addCheck('fp', fp[1] === r.fingerprint ? 'ok' : 'bad', fp[1] === r.fingerprint ? t('emulator.fp-ok') : t('emulator.fp-bad', { got: fp[1].slice(0, 16), want: r.fingerprint.slice(0, 16) }));
    }
    if (/URMQTT READY/.test(line)) addCheck('ready', 'ok', t('emulator.ready'));
    if (/refusing to serve/.test(line)) addCheck('refuse', 'warn', t('emulator.refuses'));
    if (/ERROR fatal:|configuration refused|PANIC|panicked/.test(line)) addCheck('fatal:' + line.slice(0, 60), 'bad', t('emulator.fatal', { line: line.replace(/^\[[^\]]*\]\s*/, '').slice(0, 160) }));
  };
  // The serial output arrives in pieces that end anywhere, also inside a line (and inside a CR LF or an escape
  // sequence): only complete lines are looked at, the rest waits for its end.
  let partial = '';
  const plain = s => s.replace(ANSI, '').replace(/\r/g, '');
  const onSerial = chunk => {
    const data = (partial + chunk).replace(/\r\n/g, '\n');
    const cut = data.lastIndexOf('\n') + 1;
    const complete = plain(data.slice(0, cut));
    partial = data.slice(cut);
    text += complete;
    if (text.length > 400_000) text = text.slice(-300_000);
    log.textContent = text + plain(partial);
    log.scrollTop = log.scrollHeight;
    for (const line of complete.split('\n')) if (line) inspect(line);
  };
  const onStatus = s => {
    const key = { 'fetching-runtime': 'emulator.loading', instantiating: 'emulator.starting', running: 'emulator.running', exited: 'emulator.exited', stopped: 'emulator.stopped', crashed: 'emulator.crashed' }[s];
    if (key) status.textContent = t(key);
    if (s === 'exited' || s === 'stopped' || s === 'crashed') { stopBtn.hidden = true; resetBtn.hidden = true; startBtn.hidden = false; startBtn.disabled = !mem.ok; starting = false; introRef.hidden = false; }
  };

  const start = async () => {
    if (starting || !mem.ok) return;
    starting = true;
    startBtn.hidden = true;
    introRef.hidden = true;
    stopBtn.hidden = false; resetBtn.hidden = false;
    clear(checks); seen.clear(); text = ''; partial = ''; log.textContent = '';
    canvas.hidden = false; log.hidden = false;
    abort = new AbortController();
    try {
      status.textContent = t('emulator.loading');
      const url = new URL(`emulator/${app.emulator}/urmqtt-emulator.js`, app.base).href;
      const mod = await import(url);
      // The ISO as bytes: moved to the emulator's worker, not copied; the Blob stays for the download.
      const iso = new Uint8Array(await r.blob.arrayBuffer());
      vm = await mod.bootIso({
        iso, transferIso: true, canvas, onSerial, onStatus, signal: abort.signal,
        memory: mem.ram, tbSizeMiB: 128,
        // The image is configured, so it has a network card to configure (without a backend: the broker
        // starts and listens, nothing can connect).
        extraArgs: ['-device', 'virtio-net-pci,romfile='],
        autoKeys: skip.checked ? [{ afterMs: 3200, qcode: 'ret' }] : [],
      });
      vm.done.then(res => { vm = null; if (res.reason === 'crashed') status.textContent = t('emulator.failed', { reason: String(res.detail || '').slice(0, 200) }); });
    } catch (e) {
      starting = false;
      vm = null;
      status.textContent = t('emulator.failed', { reason: cleanMessage(e.message || String(e)) });
      startBtn.hidden = false; stopBtn.hidden = true; resetBtn.hidden = true; introRef.hidden = false;
    }
  };
  const stop = () => { if (abort) abort.abort(); abort = null; vm = null; starting = false; };

  startBtn.addEventListener('click', start);
  stopBtn.addEventListener('click', () => { stop(); status.textContent = t('emulator.stopped'); stopBtn.hidden = true; resetBtn.hidden = true; startBtn.hidden = false; startBtn.disabled = !mem.ok; introRef.hidden = false; });
  resetBtn.addEventListener('click', () => { if (vm) { clear(checks); seen.clear(); text = ''; partial = ''; log.textContent = ''; vm.reset(); } });

  // What the user reads before Start; it makes room for the console once the machine runs.
  const intro = h('div', { style: 'display:grid;gap:14px' },
    h('p', { text: t('emulator.note') }),
    h('ul', { class: 'ub-notes', style: 'color:inherit' },
      h('li', { text: t('emulator.limit-size') }),
      h('li', { text: t('emulator.limit-slow') }),
      h('li', { text: t('emulator.limit-memory') }),
      h('li', { text: t('emulator.limit-network') })),
    mem.ok ? null : h('p', { class: 'ub-error', text: t('emulator.too-big', { heap: mem.heap }) }),
    h('label', { class: 'ub-switch', for: 'ub-emu-skip' }, skip, h('span', { text: t('emulator.skip') })),
    h('p', { class: 'ub-help' }, t('emulator.licence'), ' ', h('a', { href: new URL(`emulator/${app.emulator}/SOURCE.txt`, app.base).href, target: '_blank', rel: 'noopener', text: t('emulator.source') })));
  introRef = intro;
  const d = openDialog({
    title: t('emulator.title'), size: 'wide',
    body: [intro, status, checks, h('div', { class: 'ub-emu-screen' }, canvas), log],
    actions: [closeBtn, resetBtn, stopBtn, startBtn],
    onOpen: dlg => startBtn.focus(),
  });
  // Closing in any way (Close, Escape, the backdrop) ends the machine and frees its memory.
  d.dialog.addEventListener('close', stop);
}
