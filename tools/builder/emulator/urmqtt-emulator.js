// urmqtt-emulator.js -- boot an x86-64 ISO inside the browser with qemu-wasm (QEMU 8.2.0, TCG -> wasm).
//
//   import { bootIso } from './urmqtt-emulator.js';
//   const ac = new AbortController();
//   const vm = await bootIso({
//     iso,                         // Uint8Array with the ISO (copied into the worker; pass transferIso:true to move it instead)
//     canvas,                      // optional HTMLCanvasElement: VGA/VESA picture is drawn here (~1 frame/s)
//     onSerial(text, bytes) {},    // serial console (COM1), as produced; text is UTF-8 decoded incl. ANSI/CR LF
//     onStatus(s) {},              // 'fetching-runtime' | 'instantiating' | 'running' | 'exited' | 'stopped' | 'crashed'
//     signal: ac.signal,           // abort() == vm.stop()
//   });                            // resolves once QEMU's main() is running (~0.1-0.3 s after the files are in the cache)
//   vm.done.then(({ reason, detail, marks }) => {});   // reason: 'stopped' | 'exited' | 'crashed'
//   vm.reset();                    // guest hard reset (firmware runs again, ISO stays attached)
//   vm.stop();                     // worker.terminate(): every emulator thread and the 2.3 GB shared memory are released
//
// The hosting page must be cross-origin isolated (COOP: same-origin + COEP: require-corp) because the
// pthread build needs SharedArrayBuffer. Everything is loaded relative to this file (./qemu/...).

export async function bootIso(opts) {
  const {
    iso,
    canvas = null,
    onSerial = () => {},
    onStatus = () => {},
    onQemuLog = () => {},
    signal,
    baseUrl = new URL('./qemu/', import.meta.url).href,
    transferIso = false,
    ...options          // memory, machine, cpu, smp, tbSizeMiB, firmware, screenIntervalMs, serialPollMs, extraArgs, ...
  } = opts;
  if (!(iso instanceof Uint8Array)) throw new TypeError('iso must be a Uint8Array');
  if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
  if (!globalThis.crossOriginIsolated) {
    throw new Error('page is not cross-origin isolated: serve it with "Cross-Origin-Opener-Policy: same-origin" and "Cross-Origin-Embedder-Policy: require-corp" (SharedArrayBuffer is required)');
  }

  const tStart = performance.now();
  const worker = new Worker(new URL('./emu-worker.js', import.meta.url), { type: 'module' });
  let ended = false;
  let doneResolve;
  const done = new Promise((r) => { doneResolve = r; });
  const qmpWaiters = new Map();
  let qmpId = 0;
  let marks = {};
  const ctx = canvas ? canvas.getContext('2d') : null;

  const end = (reason, detail) => {
    if (ended) return;
    ended = true;
    worker.terminate();                       // kills the emulator's pthread sub-workers too
    signal?.removeEventListener('abort', onAbort);
    onStatus(reason);
    doneResolve({ reason, detail, marks, totalMs: Math.round(performance.now() - tStart) });
  };
  const onAbort = () => end('stopped');
  signal?.addEventListener('abort', onAbort);

  const started = new Promise((resolve, reject) => {
    worker.onerror = (e) => { const err = new Error('emulator worker failed: ' + (e.message || 'load error')); reject(err); end('crashed', String(err)); };
    worker.onmessage = (e) => {
      const m = e.data;
      switch (m.type) {
        case 'started': marks = m.marks; resolve(); break;
        case 'serial': onSerial(m.text, m.bytes); break;
        case 'status': onStatus(m.value); break;
        case 'log': onQemuLog(m.line); break;
        case 'frame': if (ctx) drawFrame(canvas, ctx, m.frame); break;
        case 'qmp-result': { const w = qmpWaiters.get(m.id); qmpWaiters.delete(m.id); if (w) (m.error ? w.reject(new Error(m.error)) : w.resolve(m.result)); break; }
        case 'done': marks = m.marks; end(m.reason, m.detail); break;
        case 'error': reject(new Error(m.message)); end('crashed', m.message); break;
      }
    };
  });

  const msg = { cmd: 'start', iso, baseUrl, options };
  worker.postMessage(msg, transferIso ? [iso.buffer] : []);
  await started;

  return {
    done,
    get marks() { return marks; },
    reset: () => worker.postMessage({ cmd: 'reset' }),
    stop: () => end('stopped'),
    grab: () => worker.postMessage({ cmd: 'grab' }),
    /** raw QMP command (debugging): returns the "return" object. */
    qmp: (execute, args) => new Promise((resolve, reject) => { const id = ++qmpId; qmpWaiters.set(id, { resolve, reject }); worker.postMessage({ cmd: 'qmp', id, execute, args }); }),
  };
}

const VGA16 = [0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa,
  0x555555, 0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff];
const hex6 = (n) => '#' + n.toString(16).padStart(6, '0');

function drawFrame(canvas, ctx, f) {
  if (f.kind === 'rgba') {
    if (canvas.width !== f.width || canvas.height !== f.height) { canvas.width = f.width; canvas.height = f.height; }
    ctx.putImageData(new ImageData(f.rgba, f.width, f.height), 0, 0);
    return;
  }
  // legacy 80x25 text mode (SeaBIOS banner, "Booting from DVD/CD..."): ASCII only, no VGA font ROM.
  const W = 720, H = 400;
  if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
  ctx.fillStyle = '#000'; ctx.fillRect(0, 0, W, H);
  ctx.font = '16px ui-monospace, Menlo, monospace'; ctx.textBaseline = 'top';
  for (let row = 0; row < f.rows; row++) for (let col = 0; col < f.cols; col++) {
    const ch = f.cells[(row * f.cols + col) * 2], at = f.cells[(row * f.cols + col) * 2 + 1];
    if ((at >> 4) & 7) { ctx.fillStyle = hex6(VGA16[(at >> 4) & 7]); ctx.fillRect(col * 9, row * 16, 9, 16); }
    if (ch > 32 && ch < 127) { ctx.fillStyle = hex6(VGA16[at & 15]); ctx.fillText(String.fromCharCode(ch), col * 9, row * 16); }
  }
}
