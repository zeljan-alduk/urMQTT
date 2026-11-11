// Shared by the builder tests: where things are, and the command line tool.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(HERE, '../../..');
/** The configuration format version the kernel and the module speak (crates/cfg/src/blob.rs). */
export const FORMAT = Number(readFileSync(join(ROOT, 'crates/cfg/src/blob.rs'), 'utf8').match(/pub const FORMAT_VERSION: u16 = (\d+);/)[1]);
/** The file name of the module the page loads for that format. */
export const WASM_NAME = `urmqtt-cfg${FORMAT}.wasm`;
export const WASM = process.env.BUILDER_WASM || join(ROOT, 'build/builder', WASM_NAME);
export const CLI = process.env.URMQTT_CONFIG || join(ROOT, 'target/debug/urmqtt-config');
export const FIXTURES = join(ROOT, 'tools/config/tests/fixtures');
export const DEV = join(ROOT, 'deploy/dev');

export function haveWasm() { return existsSync(WASM); }
export function haveCli() { return existsSync(CLI); }
export function haveDevCerts() { return existsSync(join(DEV, 'server.pem')) && existsSync(join(DEV, 'control.pub')); }

export function tmp(prefix = 'urmqtt-builder-') { return mkdtempSync(join(tmpdir(), prefix)); }

/** Runs the command line tool; returns {status, stdout, stderr}. */
export function cli(args, opts = {}) {
  const r = spawnSync(CLI, args, { encoding: 'utf8', maxBuffer: 1 << 28, ...opts });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** The real template ISO built by `make template`, if there is one. */
export function realTemplate() {
  const dir = join(ROOT, 'build');
  if (!existsSync(dir)) return null;
  // Only a template of this version: the tests expect the kernel to read the newest configuration format, which
  // an older release's template (a leftover of checking a release) does not.
  const ver = /^version\s*=\s*"([^"]+)"/m.exec(readFileSync(join(ROOT, 'Cargo.toml'), 'utf8'));
  const prefix = ver ? `urmqtt-template-v${ver[1]}` : 'urmqtt-template-v';
  const f = readdirSync(dir).filter(n => n.startsWith(prefix) && /-universal\.iso$/.test(n)).sort().pop();
  return f ? join(dir, f) : null;
}

/**
 * A stand-in for the template ISO, made like the one in tools/config/tests:
 * filler, the slot twice (the ISO 9660 file and the one in the FAT image), the
 * unconfigured slot of the installation image twice, and four limine.conf
 * copies naming the slot's hash. `blake2bHex` is the module's.
 */
export function syntheticTemplate(blake2bHex) {
  const dir = tmp();
  writeFileSync(join(dir, 'empty.toml'), '');
  const out = join(dir, 'slot.bin');
  const r = cli(['pack', join(dir, 'empty.toml'), '--latest-format', '--out-slot', out]);
  if (r.status !== 0) throw new Error('cannot make the empty slot: ' + r.stderr);
  const slot = readFileSync(out);
  const disk = Buffer.from(slot);
  disk.write('URMQTT-CFG-DISK\0', 0, 'latin1');
  const hash = blake2bHex(slot);
  const conf = Buffer.from(
    `timeout: 0\n/urMQTT\n    protocol: limine\n    module_path: boot():/boot/urmqtt.cfg#${hash}\n/Install\n    protocol: limine\n    module_path: boot():/boot/urmqtt.cfg#${hash}\n`);
  const parts = [];
  let len = 0;
  const push = buf => { parts.push(buf); len += buf.length; };
  const pad = n => push(Buffer.from(Array.from({ length: n }, (_, i) => (i * 31) % 251)));
  for (let part = 0; part < 4; part++) {
    pad(4096 + part * 512);
    push(part % 2 === 0 ? slot : disk);
    pad(1000);
    push(conf);
    const aligned = Math.ceil(len / 512) * 512;
    push(Buffer.alloc(aligned - len));
  }
  push(Buffer.from('URMQTT-CFG-SLOT\0', 'latin1'));
  push(Buffer.alloc(1000, 0xaa));
  return Buffer.concat(parts);
}
