// A small static file server for the builder tests and for looking at the page:
//   node serve.mjs --app DIR [--mirror DIR] [--port N] [--cors-isolated]
// `/` serves the app directory (build/builder), `/releases/` the mirror
// directory. It sends no-store so a test never sees a stale file.
import { createServer } from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.wasm': 'application/wasm', '.iso': 'application/octet-stream',
  '.minisig': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
};

/** Starts the server; resolves to {port, close(), requests}. `requests` lists every request path. */
export function serve({ app, mirror = null, port = 0, headers = {}, handlers = {} }) {
  const requests = [];
  const roots = [['/releases/', mirror], ['/', app]].filter(([, d]) => d);
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    requests.push(`${req.method} ${url.pathname}`);
    let path = decodeURIComponent(url.pathname);
    if (handlers[path]) {
      Promise.resolve(handlers[path](req)).then(text => { res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }); res.end(String(text ?? 'ok')); },
        e => { res.writeHead(500); res.end(String(e)); });
      return;
    }
    for (const [prefix, dir] of roots) {
      if (!path.startsWith(prefix)) continue;
      const root = resolve(dir);
      let rel = path.slice(prefix.length);
      if (rel === '' || rel.endsWith('/')) rel += 'index.html';
      const file = resolve(join(root, normalize(rel)));
      if (file !== root && !file.startsWith(root + sep)) break;
      let st;
      try { st = statSync(file); } catch { break; }
      if (!st.isFile()) break;
      res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Content-Length': st.size, 'Cache-Control': 'no-store', ...headers });
      if (req.method === 'HEAD') { res.end(); return; }
      createReadStream(file).pipe(res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    res.end('not found');
  });
  return new Promise(ok => server.listen(port, '127.0.0.1', () => ok({
    port: server.address().port,
    requests,
    close: () => new Promise(r => { server.closeAllConnections?.(); server.close(r); }),
  })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const arg = n => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : null; };
  const s = await serve({ app: arg('--app'), mirror: arg('--mirror'), port: Number(arg('--port') || 0) });
  console.log(`http://127.0.0.1:${s.port}/`);
}
