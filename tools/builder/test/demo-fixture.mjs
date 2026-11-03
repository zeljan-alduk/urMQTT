// Fixtures of the "Try urMQTT live" tests: a local mosquitto (when installed), a fake MQTT server, and the real demo
// bridge (deploy/demo-bridge/bridge.py) in front of either. Everything listens on 127.0.0.1 and a free port, and is
// stopped at the end of the test.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ROOT } from './helpers.mjs';

export const BRIDGE = join(ROOT, 'deploy/demo-bridge/bridge.py');

export function freePort() {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.once('error', fail);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => ok(port)); });
  });
}

export function findMosquitto() {
  for (const c of ['/opt/homebrew/sbin/mosquitto', '/usr/local/sbin/mosquitto', '/usr/sbin/mosquitto', '/usr/bin/mosquitto']) if (existsSync(c)) return c;
  const r = spawnSync('which', ['mosquitto'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function haveMosquittoPub() { return spawnSync('which', ['mosquitto_pub']).status === 0; }
export function havePython() { return spawnSync('python3', ['--version']).status === 0; }

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function waitPort(port, tries = 100) {
  for (let i = 0; i < tries; i++) {
    const ok = await new Promise(res => { const s = createServer(); s.once('error', () => res(true)); s.listen(port, '127.0.0.1', () => s.close(() => res(false))); });
    if (ok) return;
    await sleep(50);
  }
  throw new Error(`nothing listens on ${port}`);
}

/** A mosquitto on 127.0.0.1:port, anonymous. -> {port, stop()} */
export async function startMosquitto() {
  const port = await freePort();
  const dir = mkdtempSync(join(tmpdir(), 'urmqtt-mosq-'));
  const conf = join(dir, 'mosquitto.conf');
  writeFileSync(conf, `listener ${port} 127.0.0.1\nallow_anonymous true\npersistence false\nlog_dest none\n`);
  const proc = spawn(findMosquitto(), ['-c', conf], { stdio: 'ignore' });
  await waitPort(port);
  return { port, stop: async () => { proc.kill(); rmSync(dir, { recursive: true, force: true }); } };
}

/** The real bridge, listening on a free loopback port. -> {port, stop(), log} */
export async function startBridge({ upstreamPort, origins, extra = [] }) {
  const port = await freePort();
  const proc = spawn('python3', ['-I', BRIDGE, '--listen', `127.0.0.1:${port}`, '--upstream', `127.0.0.1:${upstreamPort}`,
    '--origins', origins.join(','), '--stats-interval-s', '0', ...extra], { stdio: ['ignore', 'ignore', 'pipe'] });
  const log = [];
  proc.stderr.on('data', d => log.push(String(d)));
  await waitPort(port);
  return {
    port,
    log,
    stop: () => new Promise(ok => { proc.once('exit', ok); proc.kill('SIGTERM'); setTimeout(() => proc.kill('SIGKILL'), 8000).unref(); }),
  };
}

/** A fake MQTT 3.1.1 server: CONNACK 0, SUBACK (granted = requested, a filter outside demo/web/ is refused with 0x80),
 *  PUBACK, PINGRESP, and every PUBLISH is delivered to every subscribed connection. -> {port, stop(), connects} */
export async function startFakeBroker() {
  const conns = new Set();
  const state = { connects: 0 };
  const server = createServer(sock => {
    let buf = Buffer.alloc(0);
    const sub = { sock, filters: [] };
    conns.add(sub);
    sock.on('close', () => conns.delete(sub));
    sock.on('error', () => {});
    sock.on('data', d => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        if (buf.length < 2) return;
        let n = 0, mult = 1, i = 1;
        for (;;) { const b = buf[i++]; n += (b & 127) * mult; mult *= 128; if (!(b & 128)) break; }
        if (buf.length < i + n) return;
        const type = buf[0] >> 4, flags = buf[0] & 15, body = buf.subarray(i, i + n);
        buf = buf.subarray(i + n);
        if (type === 1) { state.connects++; sock.write(Buffer.from([0x20, 2, 0, 0])); }
        else if (type === 8) {
          const id = body.subarray(0, 2);
          const len = body.readUInt16BE(2);
          const filter = body.subarray(4, 4 + len).toString();
          const ok = filter.startsWith('demo/web/');
          if (ok) sub.filters.push(filter);
          sock.write(Buffer.concat([Buffer.from([0x90, 3]), id, Buffer.from([ok ? 0 : 0x80])]));
        } else if (type === 10) sock.write(Buffer.concat([Buffer.from([0xB0, 2]), body.subarray(0, 2)]));
        else if (type === 3) {
          const qos = (flags >> 1) & 3;
          const tl = body.readUInt16BE(0);
          const topic = body.subarray(2, 2 + tl).toString();
          const payload = body.subarray(2 + tl + (qos ? 2 : 0));
          if (qos) sock.write(Buffer.from([0x40, 2, body[2 + tl], body[3 + tl]]));
          const out = Buffer.concat([Buffer.from([topic.length + 2 + payload.length]), Buffer.from([0, topic.length]), Buffer.from(topic), payload]);
          for (const c of conns) if (c.filters.some(f => f === '#' || topic.startsWith(f.replace(/#$/, '')))) c.sock.write(Buffer.concat([Buffer.from([0x30]), out]));
        } else if (type === 12) sock.write(Buffer.from([0xD0, 0]));
        else if (type === 14) sock.end();
      }
    });
  });
  await new Promise(ok => server.listen(0, '127.0.0.1', ok));
  return { port: server.address().port, state, stop: async () => { for (const c of conns) c.sock.destroy(); server.close(); } };
}
