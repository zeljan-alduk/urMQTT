// A tiny Chrome DevTools Protocol client (no dependencies): enough to open the
// page in a headless Chrome, click, type, upload files, look at the network
// requests and take screenshots. Needs Node 22+ (global WebSocket) and a
// Chrome or Chromium (CHROME=/path, or the usual places).
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

export function findChrome() {
  const candidates = [
    process.env.CHROME,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  ].filter(Boolean);
  return candidates.find(existsSync) || null;
}

export const haveBrowser = () => Boolean(findChrome()) && typeof WebSocket === 'function';

const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function launch({ args = [] } = {}) {
  const chrome = findChrome();
  const dir = mkdtempSync(join(tmpdir(), 'urmqtt-chrome-'));
  const proc = spawn(chrome, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-gpu', '--hide-scrollbars', '--mute-audio', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--no-sandbox', ...args, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  const url = await new Promise((ok, fail) => {
    let buf = '';
    const timer = setTimeout(() => fail(new Error('Chrome did not start')), 20000);
    proc.stderr.on('data', d => {
      buf += d;
      const m = /DevTools listening on (ws:\/\/\S+)/.exec(buf);
      if (m) { clearTimeout(timer); ok(m[1]); }
    });
    proc.on('exit', c => fail(new Error(`Chrome exited (${c}): ${buf.slice(-500)}`)));
  });
  const ws = new WebSocket(url);
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = () => fail(new Error('cannot connect to Chrome')); });
  let nextId = 1;
  const pending = new Map();
  const listeners = new Set();
  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { ok, fail } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? fail(new Error(`${msg.error.message} (${msg.error.code})`)) : ok(msg.result);
    } else listeners.forEach(l => l(msg));
  };
  const send = (method, params = {}, sessionId) => new Promise((ok, fail) => {
    const id = nextId++;
    pending.set(id, { ok, fail });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
  const browser = {
    send,
    on: fn => { listeners.add(fn); return () => listeners.delete(fn); },
    async newPage() { return newPage(browser); },
    async close() {
      try { await send('Browser.close'); } catch { /* already gone */ }
      ws.close();
      proc.kill();
      await sleep(100);
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return browser;
}

async function newPage(browser) {
  const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
  const send = (m, p) => browser.send(m, p, sessionId);
  const page = {
    requests: [], consoleErrors: [], consoleAll: [], dialogs: [],
    send,
    async goto(url) {
      this.requests.length = 0;
      // A navigation that only changes the fragment fires no load event.
      const loaded = new Promise((ok, fail) => {
        const timer = setTimeout(() => { off(); fail(new Error(`navigation to ${url} did not finish`)); }, 30000);
        const off = browser.on(m => {
          if (m.sessionId === sessionId && (m.method === 'Page.loadEventFired' || m.method === 'Page.navigatedWithinDocument')) { clearTimeout(timer); off(); ok(); }
        });
      });
      await send('Page.navigate', { url });
      await loaded;
    },
    /** Evaluates an expression (a promise is awaited) and returns its JSON value. */
    async eval(expr) {
      const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error('page error: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
      return r.result.value;
    },
    async waitFor(expr, { timeout = 15000, what = expr } = {}) {
      const t0 = Date.now();
      for (;;) {
        let v;
        try { v = await this.eval(expr); } catch { v = false; }
        if (v) return v;
        if (Date.now() - t0 > timeout) throw new Error(`timed out waiting for ${what}`);
        await sleep(50);
      }
    },
    async click(selector) {
      const ok = await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return false; e.scrollIntoView({block:'center'}); e.click(); return true; })()`);
      if (!ok) throw new Error(`no element ${selector}`);
    },
    /** Types into an input the way a person does (focus, then key events for text). */
    async type(selector, text) {
      await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); e.scrollIntoView({block:'center'}); e.focus(); e.select && e.select(); })()`);
      await send('Input.insertText', { text });
    },
    async key(key, { code = key, vk = 0, modifiers = 0 } = {}) {
      await send('Input.dispatchKeyEvent', { type: 'keyDown', key, code, windowsVirtualKeyCode: vk, modifiers });
      await send('Input.dispatchKeyEvent', { type: 'keyUp', key, code, windowsVirtualKeyCode: vk, modifiers });
    },
    /** Chooses files in a file input (also a hidden one). */
    async setFiles(selector, paths) {
      const { root } = await send('DOM.getDocument', { depth: 0 });
      const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector });
      if (!nodeId) throw new Error(`no element ${selector}`);
      await send('DOM.setFileInputFiles', { files: paths, nodeId });
    },
    /** Clicks a download link and waits for the file to arrive in `dir`; returns its name. */
    async download(selector, dir) {
      await browser.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir, eventsEnabled: true });
      const done = new Promise((ok, fail) => {
        let name = '';
        const timer = setTimeout(() => fail(new Error('the download did not finish')), 60000);
        const off = browser.on(m => {
          if (m.method === 'Browser.downloadWillBegin') name = m.params.suggestedFilename;
          if (m.method === 'Browser.downloadProgress' && m.params.state === 'completed') { clearTimeout(timer); off(); ok(name); }
          if (m.method === 'Browser.downloadProgress' && m.params.state === 'canceled') { clearTimeout(timer); off(); fail(new Error('the download was canceled')); }
        });
      });
      await this.click(selector);
      return done;
    },
    async viewport(width, height, { mobile = false, scale = 1 } = {}) {
      await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile });
    },
    async media({ scheme, reducedMotion } = {}) {
      const features = [];
      if (scheme) features.push({ name: 'prefers-color-scheme', value: scheme });
      if (reducedMotion) features.push({ name: 'prefers-reduced-motion', value: reducedMotion });
      await send('Emulation.setEmulatedMedia', { features });
    },
    async screenshot(path, { full = false } = {}) {
      const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: full });
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, Buffer.from(data, 'base64'));
    },
    async close() { await browser.send('Target.closeTarget', { targetId }); },
  };
  browser.on(m => {
    if (m.sessionId !== sessionId) return;
    if (m.method === 'Network.requestWillBeSent') {
      const r = m.params.request;
      page.requests.push({ url: r.url, method: r.method, body: r.postData || '', type: m.params.type });
    }
    if (m.method === 'Runtime.consoleAPICalled') {
      const text = m.params.args.map(a => a.value ?? a.description ?? '').join(' ');
      page.consoleAll.push({ type: m.params.type, text });
      if (m.params.type === 'error') page.consoleErrors.push(text);
    }
    if (m.method === 'Runtime.exceptionThrown') page.consoleErrors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') page.consoleErrors.push(m.params.entry.text + ' ' + (m.params.entry.url || ''));
  });
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');
  await send('Log.enable');
  await send('DOM.enable');
  return page;
}
