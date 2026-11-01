// emu-core.js -- drives the prebuilt qemu-wasm (QEMU 8.2.0, x86_64, TCG->wasm) from JavaScript.
// Runs inside a dedicated Worker (see emu-worker.js); it only needs fetch, WebAssembly,
// SharedArrayBuffer, TextEncoder/Decoder and timers, so it can also run on a page's main thread.
//
// What the host gets:
//   host.onSerial(text, bytes)         COM1 output as it is produced (polled from a MEMFS file every serialPollMs)
//   host.onFrame({kind,...})           the VGA/VESA picture (read out of guest RAM with QMP `pmemsave`)
//   host.onStatus(s) / onQemuLog(l)    lifecycle and QEMU's own stdout/stderr lines
//   returns { done, marks, qmp, reset(), stop(), grab() }

const QEMU_JS = 'qemu-system-x86_64.js';
const ROM_FILES = ['bios-256k.bin', 'vgabios-stdvga.bin', 'kvmvapic.bin', 'linuxboot_dma.bin'];
const SERIAL_PATH = '/serial.log';
const ISO_PATH = '/urmqtt.iso';

/** Stand-in for the xterm-pty "slave" object that this build's TTY layer talks to. QEMU's stdio
 *  chardev (used here as the QMP monitor) reads and writes through it. */
class FakePty {
  constructor(onWrite) {
    this.queue = [];
    this.readWaiters = new Set();
    this.signalWaiters = new Set();
    this.onWrite = onWrite;
    this.writable = true;
  }
  get readable() { return this.queue.length > 0; }
  read(length) { return this.queue.splice(0, length); }
  write(bytes) { this.onWrite(bytes); }
  onReadable(cb) { this.readWaiters.add(cb); return { dispose: () => this.readWaiters.delete(cb) }; }
  onSignal(cb) { this.signalWaiters.add(cb); return { dispose: () => this.signalWaiters.delete(cb) }; }
  ioctl(request) {
    switch (request) {
      case 'TCGETS': return { iflag: 0, oflag: 0, cflag: 0, lflag: 0, cc: [] };
      case 'TCSETS': return undefined;
      case 'TIOCGWINSZ': return [25, 80];
      default: return undefined;
    }
  }
  push(bytes) {
    for (const b of bytes) this.queue.push(b);
    for (const w of [...this.readWaiters]) w();
  }
}

export function defaultArgs({ machine, cpu, smp, memory, tbSizeMiB, firmware, noReboot }) {
  const a = [
    '-machine', machine,
    '-accel', `tcg,tb-size=${tbSizeMiB}`,
    '-cpu', cpu,
    '-smp', String(smp),
    '-m', memory,
    '-L', '/roms/',
    '-display', 'none',
    '-vga', 'std',
    '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
    '-device', 'virtio-scsi-pci,romfile=',
    '-device', 'virtio-rng-pci,romfile=',
    '-drive', `if=none,id=cd0,file=${ISO_PATH},format=raw,readonly=on,media=cdrom`,
    '-device', 'ide-cd,drive=cd0,bootindex=0',
    '-nic', 'none',
    '-serial', `file:${SERIAL_PATH}`,
    '-qmp', 'stdio',
  ];
  if (noReboot) a.push('-no-reboot');   // guest reset == QEMU exit (also turns QMP system_reset into an exit)
  if (firmware === 'uefi') a.push('-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/roms/OVMF_CODE.fd', '-drive', 'if=pflash,format=raw,unit=1,file=/roms/OVMF_VARS.fd');
  return a;
}

export async function runEmulator(opts, host) {
  const {
    iso,
    baseUrl,
    memory = '512M',
    machine = 'q35',
    cpu = 'max',
    smp = 1,
    tbSizeMiB = 128,
    firmware = 'bios',
    noReboot = false,
    screenIntervalMs = 1000,   // 0 = never read the framebuffer (serial only)
    serialPollMs = 40,
    extraArgs = [],
    qemuArgsOverride = null,
    extraRoms = [],            // [{name, url}] fetched into /roms/
    autoKeys = [],             // [{afterMs, qcode}] keys sent through QMP send-key, e.g. [{afterMs: 3000, qcode: 'ret'}] to skip Limine's 10 s menu timeout
    wasmUrl = null,
    wasmMemoryMiB = 0,         // size of the (fixed) shared WebAssembly.Memory; 0 = the build's default, 2300 MiB
  } = opts;
  const { onSerial = () => {}, onFrame = () => {}, onStatus = () => {}, onQemuLog = () => {}, onModule = () => {} } = host;

  const t0 = performance.now();
  const marks = { start: 0 };
  const mark = (name) => { if (!(name in marks)) marks[name] = Math.round(performance.now() - t0); };
  const textDecoder = new TextDecoder('utf-8');
  const serialDecoder = new TextDecoder('utf-8');
  const qmpDecoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();

  onStatus('fetching-runtime');
  const romFiles = [...ROM_FILES.map((n) => ({ name: n, url: new URL('roms/' + n, baseUrl).href })), ...extraRoms];
  const romsP = Promise.all(romFiles.map(async ({ name, url }) => {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`fetch ${name}: ${r.status}`);
    return [name, new Uint8Array(await r.arrayBuffer())];
  }));
  const glue = await import(/* @vite-ignore */ new URL(QEMU_JS, baseUrl).href);
  const createQemu = glue.default;
  const roms = await romsP;
  mark('glueLoaded');

  // ---- QMP over the fake pty ---------------------------------------------------
  let qmpBuf = '';
  let qmpGreeted = false;
  let qmpReadyResolve;
  const qmpReady = new Promise((r) => { qmpReadyResolve = r; });
  const qmpPending = [];
  const pty = new FakePty((bytes) => {
    qmpBuf += qmpDecoder.decode(Uint8Array.from(bytes), { stream: true });
    let nl;
    while ((nl = qmpBuf.indexOf('\n')) >= 0) {
      const line = qmpBuf.slice(0, nl).trim();
      qmpBuf = qmpBuf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { onQemuLog(line); continue; }
      if (msg.QMP && !qmpGreeted) {
        qmpGreeted = true;
        pty.push(encoder.encode('{"execute":"qmp_capabilities"}\n'));
        mark('qmpGreeting');
      } else if ('return' in msg || 'error' in msg) {
        if (!marks.qmpReady) { mark('qmpReady'); qmpReadyResolve(); continue; }
        const p = qmpPending.shift();
        if (p) ('error' in msg ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.return));
      } else if (msg.event) {
        onQemuLog('QMP event ' + line);
        if (msg.event === 'SHUTDOWN') finish('exited', msg.data?.reason);
      }
    }
  });
  const qmp = (execute, args) => new Promise((resolve, reject) => {
    qmpPending.push({ resolve, reject });
    pty.push(encoder.encode(JSON.stringify(args ? { execute, arguments: args } : { execute }) + '\n'));
  });

  const args = qemuArgsOverride ?? [...defaultArgs({ machine, cpu, smp, memory, tbSizeMiB, firmware, noReboot }), ...extraArgs];

  // ---- instantiate ---------------------------------------------------------------
  let Module;
  let finished = false;
  let doneResolve;
  const done = new Promise((r) => { doneResolve = r; });
  let serialTimer = 0;
  let screenTimer = 0;
  let serialPos = 0;

  const moduleArg = {
    ...(wasmMemoryMiB ? { INITIAL_MEMORY: wasmMemoryMiB * 1048576 } : {}),
    arguments: args,
    pty,
    locateFile: (p) => (wasmUrl && p.endsWith('.wasm') ? wasmUrl : new URL(p, baseUrl).href),
    mainScriptUrlOrBlob: new URL(QEMU_JS, baseUrl).href,
    print: (s) => onQemuLog(String(s)),
    printErr: (s) => onQemuLog(String(s)),
    onExit: (code) => finish('exited', code),
    onAbort: (what) => finish('crashed', what),
    preRun: [
      (m) => {
        m.FS.mkdir('/roms');
        for (const [name, bytes] of roms) m.FS.writeFile('/roms/' + name, bytes);
        // canOwn: MEMFS keeps a view on this Uint8Array instead of copying 60+ MB.
        m.FS.writeFile(ISO_PATH, iso, { canOwn: true });
        mark('isoStaged');
      },
    ],
  };

  function readNewSerial() {
    if (!Module?.FS) return;
    let node;
    try { node = Module.FS.lookupPath(SERIAL_PATH).node; } catch { return; }
    const size = node.usedBytes;
    if (size > serialPos) {
      const chunk = node.contents.slice(serialPos, size);
      serialPos = size;
      mark('firstSerialByte');
      onSerial(serialDecoder.decode(chunk, { stream: true }), chunk);
    }
  }

  // ---- framebuffer -----------------------------------------------------------------
  // The prebuilt QEMU has no display backend and no `screendump` command, so the picture is
  // read straight out of guest physical memory with QMP `pmemsave`:
  //   * the std-VGA's Bochs VBE ("dispi") registers (BAR2 + 0x500) give xres/yres/bpp/stride,
  //   * the linear framebuffer is BAR0 (found with `query-pci`),
  //   * legacy text mode (SeaBIOS banner) is read from 0xB8000.
  let vga = null;
  let grabBusy = false;
  async function readPhys(addr, size, path) {
    await qmp('pmemsave', { val: addr, size, filename: path });
    const node = Module.FS.lookupPath(path).node;
    return node.contents.subarray(0, node.usedBytes);
  }
  async function findVga() {
    const pci = await qmp('query-pci');
    for (const bus of pci) for (const d of bus.devices) {
      if (d.id.vendor === 0x1234 && d.id.device === 0x1111) {
        const bar = (n) => d.regions.find((r) => r.bar === n)?.address;
        return { fb: bar(0), mmio: bar(2) };
      }
    }
    return null;
  }
  async function grab() {
    if (finished || grabBusy) return null;
    grabBusy = true;
    try {
      vga ??= await findVga();
      if (!vga) return null;
      const regBytes = (await readPhys(vga.mmio + 0x500, 20, '/dispi.bin')).slice();
      const reg = new DataView(regBytes.buffer, regBytes.byteOffset, regBytes.byteLength);
      const r = (i) => reg.getUint16(i * 2, true);
      const xres = r(1), yres = r(2), bpp = r(3), enabled = r(4) & 1, vw = r(6), xoff = r(8), yoff = r(9);
      if (enabled && xres && yres && (bpp === 32 || bpp === 24 || bpp === 16 || bpp === 15)) {
        const bytesPP = (bpp + 7) >> 3;
        const stride = (vw || xres) * bytesPP;
        const src = await readPhys(vga.fb + yoff * stride + xoff * bytesPP, stride * yres, '/fb.bin');
        const rgba = new Uint8ClampedArray(xres * yres * 4);
        let o = 0;
        for (let y = 0; y < yres; y++) {
          let i = y * stride;
          if (bpp >= 24) {
            for (let x = 0; x < xres; x++, i += bytesPP, o += 4) { rgba[o] = src[i + 2]; rgba[o + 1] = src[i + 1]; rgba[o + 2] = src[i]; rgba[o + 3] = 255; }
          } else {
            for (let x = 0; x < xres; x++, i += 2, o += 4) {
              const v = src[i] | (src[i + 1] << 8);
              if (bpp === 16) { rgba[o] = ((v >> 11) & 31) * 255 / 31; rgba[o + 1] = ((v >> 5) & 63) * 255 / 63; rgba[o + 2] = (v & 31) * 255 / 31; }
              else { rgba[o] = ((v >> 10) & 31) * 255 / 31; rgba[o + 1] = ((v >> 5) & 31) * 255 / 31; rgba[o + 2] = (v & 31) * 255 / 31; }
              rgba[o + 3] = 255;
            }
          }
        }
        const frame = { kind: 'rgba', width: xres, height: yres, rgba, mode: `vbe ${xres}x${yres}x${bpp}` };
        onFrame(frame);
        return frame;
      }
      const cells = (await readPhys(0xb8000, 4000, '/text.bin')).slice();
      const frame = { kind: 'text', cols: 80, rows: 25, cells, mode: 'text 80x25' };
      onFrame(frame);
      return frame;
    } finally { grabBusy = false; }
  }

  function finish(reason, detail) {
    if (finished) return;
    finished = true;
    clearInterval(serialTimer);
    clearInterval(screenTimer);
    try { readNewSerial(); } catch { /* ignore */ }
    try { Module?.PThread?.terminateAllThreads(); } catch { /* ignore */ }
    const m = Module;
    Module = undefined;
    if (m) for (const k of Object.keys(m)) { try { delete m[k]; } catch { /* ignore */ } }
    pty.queue.length = 0; pty.readWaiters.clear(); pty.signalWaiters.clear();
    onStatus(reason);
    doneResolve({ reason, detail, marks });
  }

  onStatus('instantiating');
  mark('instantiateStart');
  Module = await createQemu(moduleArg).catch((e) => { finish('crashed', String(e)); throw e; });
  mark('instantiated');
  onModule(Module);
  if (!finished) {
    serialTimer = setInterval(readNewSerial, serialPollMs);
    onStatus('running');
    qmpReady.then(() => {
      if (screenIntervalMs > 0 && !finished) screenTimer = setInterval(() => { grab().catch(() => {}); }, screenIntervalMs);
      for (const k of autoKeys) {
        setTimeout(() => { if (!finished) qmp('send-key', { keys: [{ type: 'qcode', data: k.qcode }], 'hold-time': 100 }).catch(() => {}); },
          Math.max(0, k.afterMs - (performance.now() - t0)));
      }
    });
  }
  return {
    done, marks, qmp, grab,
    reset: () => qmp('system_reset'),
    stop: () => finish('stopped'),
  };
}
