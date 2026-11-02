// "Try urMQTT live": the page. It connects to the demo bridge over a WebSocket, subscribes and publishes under
// demo/web/ and shows what it sends and receives. No third-party script, no analytics, nothing stored in the
// browser, no request except the page's own files and the WebSocket. Everything that arrives from the broker is
// shown as TEXT (textContent), never as HTML: anybody can publish to these topics.

const TOPIC_PREFIX = 'demo/web/';
const LIMITS = { payload: 256, topic: 128, levels: 8, subscriptions: 4, logEntries: 200, publishGapMs: 250 };

let texts = {};
let fallbackTexts = {};

async function loadTexts(base, lang, version) {
  const get = async code => {
    const v = version && version[`i18n/${code}.json`];
    const res = await fetch(`${base}i18n/${code}.json${v ? `?v=${v}` : ''}`);
    if (!res.ok) throw new Error(`texts ${code}: HTTP ${res.status}`);
    return res.json();
  };
  fallbackTexts = await get('en');
  texts = lang === 'en' ? fallbackTexts : await get(lang).catch(() => fallbackTexts);
}

/** The text for `key`, with {name} placeholders filled from `args`. */
function t(key, args) {
  let s = texts[key] ?? fallbackTexts[key] ?? key;
  if (args) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in args ? String(args[k]) : m));
  return s;
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null) el.append(c);
  return el;
}

const utf8Length = s => new TextEncoder().encode(s).length;
const pad2 = n => String(n).padStart(2, '0');
const stamp = () => { const d = new Date(); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; };
const randomHex = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, '0')).join('');

/** The bridge's address: data-ws, else wss://<this host>/demo/mqtt; `?ws=` only on the local machine (tests). */
function bridgeUrl(root) {
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  const param = local ? new URLSearchParams(location.search).get('ws') : null;
  if (param) return param;
  if (root.dataset.ws) return root.dataset.ws;
  return `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/demo/mqtt`;
}

/** Why a topic or filter may not be used, or '' if it may. `wild` allows + and #. */
function topicProblem(rest, wild) {
  if (!rest) return t('err.empty');
  const full = TOPIC_PREFIX + rest;
  if (utf8Length(full) > LIMITS.topic) return t('err.topic-long', { max: LIMITS.topic });
  if (full.split('/').length > LIMITS.levels) return t('err.levels', { max: LIMITS.levels });
  if (/[\u0000-\u001f]/.test(full)) return t('err.chars');
  if (!wild && /[+#]/.test(full)) return t('err.wildcard');
  if (wild && /([^/]#|#.|[^/]\+|\+[^/])/.test(rest)) return t('err.filter');
  return '';
}

function buildPage(root, state) {
  const ids = {};
  const id = name => (ids[name] = ids[name] || `ud-${name}`);
  const field = (name, label, input, hint) => h('div', { class: 'ud-field' },
    h('label', { for: id(name), text: label }), input, hint ? h('p', { class: 'ud-hint', id: id(`${name}-hint`), text: hint }) : null);

  const status = h('p', { id: id('status'), class: 'ud-status', role: 'status', 'data-state': 'idle', text: t('status.idle') });
  const connectBtn = h('button', { type: 'button', class: 'ud-btn ud-primary', id: id('connect'), text: t('conn.connect') });
  const disconnectBtn = h('button', { type: 'button', class: 'ud-btn', id: id('disconnect'), text: t('conn.disconnect'), disabled: true });

  const room = randomHex(2);
  const subInput = h('input', { type: 'text', id: id('filter'), value: `room-${room}/#`, autocomplete: 'off', spellcheck: 'false', maxlength: '100', 'aria-describedby': id('filter-hint') });
  const subBtn = h('button', { type: 'button', class: 'ud-btn', id: id('subscribe'), text: t('sub.button'), disabled: true });
  const subList = h('ul', { class: 'ud-subs', id: id('subs'), 'aria-label': t('sub.list') });

  const topicInput = h('input', { type: 'text', id: id('topic'), value: `room-${room}/hello`, autocomplete: 'off', spellcheck: 'false', maxlength: '100', 'aria-describedby': id('topic-hint') });
  const payloadInput = h('textarea', { id: id('payload'), rows: '3', maxlength: '400', 'aria-describedby': id('payload-hint'), text: t('pub.payload-default') });
  const qosSelect = h('select', { id: id('qos') }, h('option', { value: '0', text: t('pub.qos0') }), h('option', { value: '1', text: t('pub.qos1') }));
  const pubBtn = h('button', { type: 'button', class: 'ud-btn ud-primary', id: id('publish'), text: t('pub.button'), disabled: true });
  const pubCount = h('span', { class: 'ud-count', id: id('payload-count'), 'aria-hidden': 'true' });
  const pubError = h('p', { class: 'ud-error', id: id('pub-error'), role: 'alert' });
  const subError = h('p', { class: 'ud-error', id: id('sub-error'), role: 'alert' });

  const logList = h('ol', { class: 'ud-log', id: id('log'), role: 'log', 'aria-live': 'polite', 'aria-label': t('log.title') });
  const empty = h('p', { class: 'ud-muted', id: id('log-empty'), text: t('log.empty') });
  const clearBtn = h('button', { type: 'button', class: 'ud-btn', id: id('clear'), text: t('log.clear') });

  const limits = h('ul', { class: 'ud-limits' }, ['1', '2', '3', '4', '5', '6'].map(n => h('li', { text: t(`limits.${n}`, { payload: LIMITS.payload, subs: LIMITS.subscriptions }) })));
  const certZip = `${state.base}certs/demo-certs.zip`;
  const host = state.brokerHost;

  const page = h('div', { class: 'ud' },
    h('header', { class: 'ud-head' }, h('h1', { text: t('title') }), h('p', { class: 'ud-lead', text: t('lead') })),
    h('aside', { class: 'ud-warn', 'aria-labelledby': id('limits-title') }, h('h2', { id: id('limits-title'), text: t('limits.title') }), limits),
    h('div', { class: 'ud-grid' },
      h('section', { class: 'ud-card', 'aria-labelledby': id('conn-title') },
        h('h2', { id: id('conn-title'), text: t('conn.title') }),
        h('p', { class: 'ud-muted' }, t('conn.to'), ' ', h('code', { text: state.url })),
        status, h('div', { class: 'ud-row' }, connectBtn, disconnectBtn)),
      h('section', { class: 'ud-card', 'aria-labelledby': id('sub-title') },
        h('h2', { id: id('sub-title'), text: t('sub.title') }),
        field('filter', t('sub.filter', { prefix: TOPIC_PREFIX }), subInput, t('sub.hint', { prefix: TOPIC_PREFIX })),
        h('div', { class: 'ud-row' }, subBtn), subError, subList),
      h('section', { class: 'ud-card', 'aria-labelledby': id('pub-title') },
        h('h2', { id: id('pub-title'), text: t('pub.title') }),
        field('topic', t('pub.topic', { prefix: TOPIC_PREFIX }), topicInput, t('pub.topic-hint', { prefix: TOPIC_PREFIX })),
        field('payload', t('pub.payload'), payloadInput, null),
        h('p', { class: 'ud-hint', id: id('payload-hint') }, t('pub.payload-hint', { max: LIMITS.payload }), ' ', pubCount),
        field('qos', t('pub.qos'), qosSelect, null),
        h('div', { class: 'ud-row' }, pubBtn), pubError)),
    h('section', { class: 'ud-card ud-wide', 'aria-labelledby': id('log-title') },
      h('div', { class: 'ud-row ud-between' }, h('h2', { id: id('log-title'), text: t('log.title') }), clearBtn),
      empty, logList),
    h('section', { class: 'ud-card ud-wide', 'aria-labelledby': id('real-title') },
      h('h2', { id: id('real-title'), text: t('real.title') }),
      h('p', { text: t('real.p1', { host }) }),
      h('pre', { class: 'ud-code', tabindex: '0', 'aria-label': t('real.cmd-label'), text:
        `mosquitto_sub -h ${host} -p 8883 --cafile server-ca.pem \\\n  --cert clients/web.pem --key clients/web.key -i web \\\n  -t '${TOPIC_PREFIX}#' -v` }),
      h('p', { class: 'ud-muted', text: t('real.p2') }),
      h('p', {}, h('a', { href: certZip, download: '', text: t('real.download') })),
      h('p', { class: 'ud-muted', text: t('real.p3') })));
  root.replaceChildren(page);

  return { status, connectBtn, disconnectBtn, subInput, subBtn, subList, subError, topicInput, payloadInput, qosSelect, pubBtn, pubCount, pubError, logList, empty, clearBtn };
}

async function main() {
  const root = document.getElementById('urmqtt-demo');
  if (!root) return;
  const base = new URL(root.dataset.base || './', location.href).href;
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  const wanted = (local && new URLSearchParams(location.search).get('lang')) || root.dataset.lang || document.documentElement.lang || 'en';
  const lang = /^[a-z]{2}$/.test(wanted.toLowerCase().split('-')[0]) ? wanted.toLowerCase().split('-')[0] : 'en';
  let version = {};
  try { version = (root.dataset.v ? JSON.parse(root.dataset.v) : await (await fetch(`${base}manifest.json`, { cache: 'no-cache' })).json()).files || {}; } catch { version = {}; }
  try {
    await loadTexts(base, lang, version);
  } catch (e) {
    root.textContent = `urMQTT demo: ${e.message}`;
    return;
  }
  const url = bridgeUrl(root);
  const state = { base, url, brokerHost: root.dataset.broker || 'demo-mqtt.aldo.tech', client: null, subs: new Map(), lastPublish: 0 };
  const ui = buildPage(root, state);

  const setStatus = (key, st, args) => { ui.status.textContent = t(key, args); ui.status.dataset.state = st; };
  const connected = () => state.client && state.client.state === 'open';
  const syncButtons = () => {
    const open = connected();
    const busy = state.client && state.client.state === 'connecting';
    ui.connectBtn.disabled = open || busy;
    ui.disconnectBtn.disabled = !(open || busy);
    ui.subBtn.disabled = !open;
    ui.pubBtn.disabled = !open;
  };

  const log = (kind, text, topic) => {
    ui.empty.hidden = true;
    const li = h('li', { class: `ud-entry ud-${kind}` },
      h('span', { class: 'ud-time', text: stamp() }), ' ',
      h('span', { class: 'ud-kind', text: t(`log.${kind}`) }), ' ',
      topic != null ? h('code', { class: 'ud-topic', text: topic }) : null,
      topic != null ? ' ' : null,
      h('span', { class: 'ud-text', text }));
    ui.logList.append(li);
    while (ui.logList.children.length > LIMITS.logEntries) ui.logList.firstChild.remove();
    li.scrollIntoView?.({ block: 'nearest' });
  };

  const renderSubs = () => {
    ui.subList.replaceChildren(...[...state.subs.keys()].map(f => h('li', {},
      h('code', { text: TOPIC_PREFIX + f }), ' ',
      h('button', { type: 'button', class: 'ud-btn ud-small', 'data-filter': f, 'aria-label': t('sub.remove-label', { filter: TOPIC_PREFIX + f }), text: t('sub.remove'),
        onclick: async ev => {
          const filter = ev.currentTarget.dataset.filter;
          try { await state.client.unsubscribe(TOPIC_PREFIX + filter); } catch (e) { log('error', e.message); }
          state.subs.delete(filter);
          renderSubs();
        } }))));
  };

  const doConnect = async () => {
    const client = new MqttClient({ url, clientId: `urmqtt-web-${randomHex(5)}`, keepaliveS: 30, maxPacket: 4096 });
    state.client = client;
    client.on('message', m => {
      let text = new TextDecoder().decode(m.payload);
      if (text.length > 512) text = `${text.slice(0, 512)}…`;
      log('received', text, m.topic);
    });
    client.on('log', msg => log('info', msg));
    client.on('close', ev => {
      state.subs.clear();
      renderSubs();
      setStatus(ev.clean ? 'status.closed' : 'status.lost', ev.clean ? 'idle' : 'error', { reason: ev.reason || '-' });
      log('info', ev.clean ? t('log.closed') : t('log.lost', { reason: ev.reason || '-' }));
      syncButtons();
    });
    setStatus('status.connecting', 'busy');
    syncButtons();
    try {
      await client.connect();
      setStatus('status.connected', 'ok', { id: client.clientId });
      log('info', t('log.connected', { id: client.clientId }));
    } catch (e) {
      setStatus('status.failed', 'error', { reason: e.message });
      log('error', e.message);
    }
    syncButtons();
  };

  ui.connectBtn.addEventListener('click', doConnect);
  ui.disconnectBtn.addEventListener('click', () => { if (state.client) state.client.disconnect(); });
  ui.clearBtn.addEventListener('click', () => { ui.logList.replaceChildren(); ui.empty.hidden = false; });

  ui.subBtn.addEventListener('click', async () => {
    ui.subError.textContent = '';
    const rest = ui.subInput.value.trim();
    const problem = topicProblem(rest, true) || (state.subs.has(rest) ? t('err.already') : '') || (state.subs.size >= LIMITS.subscriptions ? t('err.too-many-subs', { max: LIMITS.subscriptions }) : '');
    if (problem) { ui.subError.textContent = problem; ui.subInput.setAttribute('aria-invalid', 'true'); return; }
    ui.subInput.removeAttribute('aria-invalid');
    try {
      await state.client.subscribe(TOPIC_PREFIX + rest, 1);
      state.subs.set(rest, 1);
      renderSubs();
      log('info', t('log.subscribed', { filter: TOPIC_PREFIX + rest }));
    } catch (e) {
      ui.subError.textContent = e.message;
      log('error', e.message);
    }
  });

  const updateCount = () => { ui.pubCount.textContent = t('pub.count', { n: utf8Length(ui.payloadInput.value), max: LIMITS.payload }); };
  ui.payloadInput.addEventListener('input', updateCount);
  updateCount();

  ui.pubBtn.addEventListener('click', async () => {
    ui.pubError.textContent = '';
    const rest = ui.topicInput.value.trim();
    const payload = ui.payloadInput.value;
    const problem = topicProblem(rest, false) || (utf8Length(payload) > LIMITS.payload ? t('err.payload-long', { max: LIMITS.payload }) : '')
      || (Date.now() - state.lastPublish < LIMITS.publishGapMs ? t('err.slow-down') : '');
    if (problem) { ui.pubError.textContent = problem; ui.topicInput.setAttribute('aria-invalid', String(!!topicProblem(rest, false))); return; }
    ui.topicInput.removeAttribute('aria-invalid');
    state.lastPublish = Date.now();
    const qos = Number(ui.qosSelect.value);
    try {
      await state.client.publish(TOPIC_PREFIX + rest, payload, qos);
      log('sent', payload, TOPIC_PREFIX + rest);
    } catch (e) {
      ui.pubError.textContent = e.message;
      log('error', e.message);
    }
  });

  syncButtons();
  document.documentElement.dataset.udReady = '1';
}

main().catch(e => { console.error(e); const r = document.getElementById('urmqtt-demo'); if (r) r.textContent = `urMQTT demo: ${e.message}`; });
