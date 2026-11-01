// The page resolves the files of a release (SHA256SUMS, the template) relative to the directory of releases.json,
// and the mirror keeps them in /urmqtt/releases/<tag>/ next to /urmqtt/releases/releases.json: the address the
// site gives the page and the page's own default must both point into that directory. (A first version
// pointed at /urmqtt/releases.json and every signature check on the live site answered 404.)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');

test('the list of releases is served from the directory that holds the releases', () => {
  const site = readFileSync(join(ROOT, 'tools/builder/site/products.py'), 'utf8');
  assert.match(site, /URMQTT_RELEASES_URL", "\/urmqtt\/releases\/releases\.json"/);
  const main = readFileSync(join(ROOT, 'tools/builder/web/src/main.js'), 'utf8');
  assert.match(main, /'\/urmqtt\/releases\/releases\.json'/);
});
