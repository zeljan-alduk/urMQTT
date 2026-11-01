// Looks at the page: node tools/builder/test/dev.mjs [--real] [--port N]
// Builds a test site (throwaway release key, local mirror) and serves it.
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

import { serve } from './serve.mjs';
import { prepareSite } from './fixture-site.mjs';
import { ROOT } from './helpers.mjs';

const real = process.argv.includes('--real');
const pi = process.argv.indexOf('--port');
const site = await prepareSite({ real });
// GET /__rebuild bundles the page again (after editing tools/builder/web/src).
const rebuild = () => {
  execFileSync('node', [join(ROOT, 'tools/builder/web/bundle.mjs'), site.appDir], { env: { ...process.env, BUILDER_PUBKEY_TEXT: site.key.publicText }, stdio: 'inherit' });
  return 'rebuilt';
};
const s = await serve({ app: site.appDir, mirror: site.mirrorDir, port: pi > 0 ? Number(process.argv[pi + 1]) : 0, handlers: { '/__rebuild': rebuild } });
console.log(`builder test site: http://127.0.0.1:${s.port}/   (key ${site.key.idText}; Ctrl-C to stop)`);
