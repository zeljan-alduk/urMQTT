// emu-worker.js -- module Worker that hosts the emulator, so the page's main thread stays free and
// `worker.terminate()` is a complete, immediate teardown (all pthread sub-workers and the 2.3 GB
// shared wasm memory die with it).
//
// Messages in  : {cmd:'start', iso:Uint8Array, baseUrl, options}  {cmd:'reset'}  {cmd:'grab'}  {cmd:'qmp', id, execute, args}
// Messages out : {type:'status'|'serial'|'frame'|'log'|'started'|'done'|'qmp-result'|'error', ...}
import { runEmulator } from './emu-core.js';

let vm = null;

self.onmessage = async (e) => {
  const m = e.data;
  try {
    if (m.cmd === 'start') {
      vm = await runEmulator({ ...m.options, iso: m.iso, baseUrl: m.baseUrl }, {
        onSerial: (text, bytes) => self.postMessage({ type: 'serial', text, bytes }, [bytes.buffer]),
        onFrame: (f) => {
          const t = f.kind === 'rgba' ? [f.rgba.buffer] : [f.cells.buffer];
          self.postMessage({ type: 'frame', frame: f }, t);
        },
        onStatus: (s) => self.postMessage({ type: 'status', value: s }),
        onQemuLog: (line) => self.postMessage({ type: 'log', line }),
      });
      self.postMessage({ type: 'started', marks: vm.marks });
      vm.done.then((r) => self.postMessage({ type: 'done', ...r }));
    } else if (m.cmd === 'reset') {
      await vm?.reset();
    } else if (m.cmd === 'grab') {
      await vm?.grab();
    } else if (m.cmd === 'qmp') {
      try { self.postMessage({ type: 'qmp-result', id: m.id, result: await vm.qmp(m.execute, m.args) }); }
      catch (err) { self.postMessage({ type: 'qmp-result', id: m.id, error: String(err) }); }
    } else if (m.cmd === 'stop') {
      vm?.stop();
    }
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err), stack: err?.stack });
  }
};
