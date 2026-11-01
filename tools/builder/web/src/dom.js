// Small DOM helpers. No framework: elements are built with h() and updated in place.

/**
 * Creates an element. `props`: class, text, attributes (including aria-*),
 * `on` ({event: handler}) and `data` ({name: value}). Children are nodes or
 * strings (strings become text nodes, never HTML).
 */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'data') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = Boolean(v);
    else if (k === 'disabled' || k === 'hidden' || k === 'required' || k === 'multiple' || k === 'open') el[k] = Boolean(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Lets the browser paint (a hidden tab never runs animation frames: fall back to a timer). */
const paint = () => new Promise(r => {
  let done = false;
  const fin = () => { if (!done) { done = true; r(); } };
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => setTimeout(fin, 0));
  setTimeout(fin, 50);
});

function debounce(fn, ms) {
  let timer = 0;
  const wrapped = (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
  wrapped.now = (...args) => { clearTimeout(timer); fn(...args); };
  return wrapped;
}

/** Binary sizes: 62.9 MB (decimal, as the release page shows them). */
function formatBytes(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + ' kB';
  return n + ' B';
}

function formatDate(iso, lang) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  try { return new Intl.DateTimeFormat(lang, { year: 'numeric', month: 'short', day: 'numeric' }).format(d); } catch { return d.toISOString().slice(0, 10); }
}

function formatUnix(sec, lang) {
  return formatDate(new Date(sec * 1000).toISOString(), lang);
}

/** Splits a long hex string into groups for reading and comparing. */
function groupHex(s, n = 8) {
  return s.replace(new RegExp(`(.{${n}})`, 'g'), '$1 ').trim();
}

/** Starts a file download of a Blob URL. */
function saveAs(url, name) {
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  setTimeout(() => a.remove(), 0);
}

/** Text as a download (small files: the TOML). */
function saveText(text, name, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type: type + ';charset=utf-8' }));
  saveAs(url, name);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = h('textarea', { 'aria-hidden': 'true', style: 'position:fixed;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { /* not allowed */ }
    ta.remove();
    return ok;
  }
}

/** The polite live region screen readers hear. */
function announce(text) {
  const region = document.getElementById('ub-live');
  if (!region) return;
  region.textContent = '';
  setTimeout(() => { region.textContent = text; }, 30);
}

/** Reads a File as text or bytes. */
const readText = file => file.text();
const readBytes = async file => new Uint8Array(await file.arrayBuffer());

let uid = 0;
const nextId = (p = 'ub') => `${p}-${++uid}`;

const prefersReducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
