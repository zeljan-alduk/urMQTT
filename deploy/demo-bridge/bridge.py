#!/usr/bin/env python3
"""urMQTT demo bridge (D1b): a small WebSocket (RFC 6455) to TCP proxy for MQTT.

A browser connects to wss://<site>/demo/mqtt (a reverse proxy terminates TLS and passes the upgrade on); this
process checks the request, opens ONE fixed upstream TCP connection (the demo broker's plaintext listener) and
copies bytes: each binary WebSocket message goes to the broker as it is, each chunk from the broker goes to the
browser as one binary message. It does not parse MQTT beyond one check (the first message must start with a
CONNECT packet), holds no secrets, writes nothing to disk and never logs a payload.

Python 3 standard library only. Hard limits (all configurable, defaults in CONFIG_FIELDS):
  connections   per client address and in total; new connections per client address per minute
  messages      one frame / one reassembled message at most --max-message bytes (the broker's plaintext
                max_packet_size); client frames must be masked, text frames are refused
  rate          messages per second and bytes per second per connection (token buckets)
  time          the request head within 10 s, a frame within 10 s of its first byte, no client frame at all for
                --idle-s seconds closes the connection, and a connection lives at most --max-lifetime-s
  origin        the Origin header must be on the allow-list (browsers always send it)
  upstream      host:port is configuration, never taken from the request
  shutdown      SIGTERM/SIGINT: stop accepting, close every WebSocket with 1001 and wait up to --grace-s

Usage: bridge.py [--listen HOST:PORT] [--upstream HOST:PORT] [--origin URL]... (every option also has an
environment variable DEMO_BRIDGE_<NAME>; see --help). The healthcheck: GET /healthz.
"""
import argparse
import asyncio
import base64
import collections
import hashlib
import ipaddress
import json
import os
import signal
import struct
import sys
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

# name -> (type, default, help)
CONFIG_FIELDS = {
    "listen": (str, "127.0.0.1:18090", "address to listen on (a container uses 0.0.0.0:8080 and publishes it on 127.0.0.1 only)"),
    "upstream": (str, "127.0.0.1:1883", "HOST:PORT of the broker's plaintext listener"),
    "path": (str, "/demo/mqtt", "the only request path that upgrades"),
    "origins": (str, "", "comma separated allowed Origin values, e.g. https://aldo.tech,https://aldotech.io"),
    "allow_no_origin": (bool, False, "accept a request without Origin (tests, non-browser clients); off by default"),
    "max_per_ip": (int, 4, "simultaneous connections per client address (IPv6: per /64)"),
    "max_total": (int, 50, "simultaneous connections in total (keep below the broker's plaintext.max_connections)"),
    "connect_rate": (int, 20, "new connections per client address per minute"),
    "max_message": (int, 1024, "bytes in one frame and in one reassembled message (the broker's plaintext.max_packet_size)"),
    "msg_rate": (float, 20.0, "client messages per second per connection (sustained)"),
    "msg_burst": (int, 40, "client messages a connection may send in a burst"),
    "byte_rate": (int, 8192, "client bytes per second per connection (sustained)"),
    "byte_burst": (int, 16384, "client bytes a connection may send in a burst"),
    "idle_s": (float, 120.0, "close when the client sends nothing (not even a ping) for this long"),
    "max_lifetime_s": (float, 3600.0, "close a connection after this long"),
    "head_timeout_s": (float, 10.0, "time for the HTTP request head"),
    "frame_timeout_s": (float, 10.0, "time to finish a frame once its first byte arrived"),
    "write_timeout_s": (float, 10.0, "time a write may take to drain (a client or broker that does not read)"),
    "connect_timeout_s": (float, 5.0, "time to open the upstream connection"),
    "grace_s": (float, 5.0, "time to let connections close on shutdown"),
    "trusted_proxies": (str, "127.0.0.0/8,::1/128,172.16.0.0/12", "peers whose X-Forwarded-For (last entry) names the client"),
    "log_ips": (bool, False, "put client addresses in log lines (personal data: off by default)"),
    "stats_interval_s": (float, 60.0, "seconds between counter summaries in the log (0 = off)"),
}


class Config:
    def __init__(self, **kw):
        for name, (_, default, _) in CONFIG_FIELDS.items():
            setattr(self, name, kw.pop(name, default))
        if kw:
            raise TypeError(f"unknown option(s): {', '.join(sorted(kw))}")
        self.validate()

    def validate(self):
        host, port = split_hostport(self.listen, allow_zero=True)
        split_hostport(self.upstream)
        if not self.path.startswith("/") or "?" in self.path or " " in self.path:
            raise ValueError("path must start with / and have no query")
        self.origin_set = {o.strip().rstrip("/").lower() for o in str(self.origins).split(",") if o.strip()}
        if not self.origin_set and not self.allow_no_origin:
            raise ValueError("no allowed origin: set origins (or allow_no_origin for tests)")
        for o in self.origin_set:
            if not (o.startswith("https://") or o.startswith("http://")) or "*" in o:
                raise ValueError(f"origin {o!r} must be an exact http(s)://host[:port], no wildcard")
        self.proxy_nets = [ipaddress.ip_network(n.strip(), strict=False) for n in str(self.trusted_proxies).split(",") if n.strip()]
        for name in ("max_per_ip", "max_total", "connect_rate", "max_message", "msg_burst", "byte_burst"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.max_message < 64 or self.max_message > 65535:
            raise ValueError("max_message must be 64..65535")
        if min(self.msg_rate, self.byte_rate, self.idle_s, self.max_lifetime_s) <= 0:
            raise ValueError("rates and times must be positive")
        _ = (host, port)


def split_hostport(text, allow_zero=False):
    host, sep, port = str(text).rpartition(":")
    if not sep or not host or not port.isdigit() or not (0 if allow_zero else 1) <= int(port) < 65536:
        raise ValueError(f"{text!r} is not HOST:PORT")
    return host.strip("[]"), int(port)


def config_from(argv, environ):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    for name, (typ, default, text) in CONFIG_FIELDS.items():
        env = environ.get("DEMO_BRIDGE_" + name.upper())
        if typ is bool:
            start = default if env is None else env.lower() in ("1", "true", "yes", "on")
            ap.add_argument("--" + name.replace("_", "-"), dest=name, action=argparse.BooleanOptionalAction, default=start, help=f"{text} [{default}]")
        else:
            ap.add_argument("--" + name.replace("_", "-"), dest=name, type=typ, default=typ(env) if env is not None else default,
                            help=f"{text} [{default}]")
    ap.add_argument("--origin", dest="origin_extra", action="append", default=[], help="an allowed Origin (repeatable; added to --origins)")
    args = ap.parse_args(argv)
    values = {n: getattr(args, n) for n in CONFIG_FIELDS}
    if args.origin_extra:
        values["origins"] = ",".join(filter(None, [values["origins"], *args.origin_extra]))
    return Config(**values)


def unmask(data, mask):
    """XOR `data` with the 4-byte `mask` repeated."""
    if not data:
        return b""
    n = len(data)
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def frame(opcode, payload=b""):
    """A server frame (unmasked, FIN set)."""
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def accept_key(key):
    return base64.b64encode(hashlib.sha1(key.encode("ascii") + GUID).digest()).decode("ascii")


class Bucket:
    """A token bucket."""

    def __init__(self, rate, burst):
        self.rate, self.burst, self.tokens, self.at = rate, float(burst), float(burst), time.monotonic()

    def take(self, n=1):
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens < n:
            return False
        self.tokens -= n
        return True


class Refuse(Exception):
    """Answer the HTTP request with this status and stop."""

    def __init__(self, status, reason, counter):
        super().__init__(reason)
        self.status, self.reason, self.counter = status, reason, counter


class Closing(Exception):
    """End the WebSocket with this close code."""

    def __init__(self, code, reason, counter):
        super().__init__(reason)
        self.code, self.reason, self.counter = code, reason, counter


STATUS_TEXT = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
               426: "Upgrade Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large", 503: "Service Unavailable"}


class Bridge:
    def __init__(self, config, log=None):
        self.cfg = config
        self.log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        self.total = 0
        self.per_ip = collections.Counter()
        self.recent = collections.defaultdict(collections.deque)  # client key -> connection start times (last minute)
        self.counters = collections.Counter()
        self.active = set()
        self.stopping = False
        self.server = None
        self.started = time.time()
        self._stats_task = None

    # ---- lifecycle -----------------------------------------------------------------

    async def start(self):
        host, port = split_hostport(self.cfg.listen, allow_zero=True)
        self.server = await asyncio.start_server(self.handle, host, port, limit=16384, backlog=128)
        self.port = self.server.sockets[0].getsockname()[1]
        if self.cfg.stats_interval_s:
            self._stats_task = asyncio.ensure_future(self._stats_loop())
        self.log(f"bridge: listening on {host}:{self.port}, upstream {self.cfg.upstream}, path {self.cfg.path}, "
                 f"origins {sorted(self.cfg.origin_set) or 'none'}, per-address {self.cfg.max_per_ip}, total {self.cfg.max_total}, "
                 f"message {self.cfg.max_message} bytes")
        return self

    async def stop(self):
        """Graceful: no new connections, every WebSocket gets close 1001, then wait."""
        self.stopping = True
        if self._stats_task:
            self._stats_task.cancel()
        if self.server:
            self.server.close()
        for conn in list(self.active):
            conn.shutdown.set()
        end = time.monotonic() + self.cfg.grace_s
        while self.total and time.monotonic() < end:
            await asyncio.sleep(0.05)
        if self.server:
            try:
                await asyncio.wait_for(self.server.wait_closed(), 2)
            except asyncio.TimeoutError:
                pass
        self.log(f"bridge: stopped ({self.total} connection(s) still open)")

    async def _stats_loop(self):
        last = None
        while True:
            await asyncio.sleep(self.cfg.stats_interval_s)
            snap = dict(self.counters)
            if snap != last:
                last = snap
                self.log("bridge: " + json.dumps({"open": self.total, **snap}, sort_keys=True))

    def health(self):
        return {"ok": not self.stopping, "open": self.total, "max_total": self.cfg.max_total, "uptime_s": int(time.time() - self.started),
                "counters": dict(self.counters)}

    # ---- the HTTP part -------------------------------------------------------------

    def client_key(self, peer, headers):
        """The address limits are counted by: the peer, or the last X-Forwarded-For entry when the peer is a trusted proxy."""
        try:
            ip = ipaddress.ip_address(peer)
        except ValueError:
            return str(peer)
        if any(ip in net for net in self.cfg.proxy_nets):
            fwd = headers.get("x-forwarded-for", "")
            last = fwd.rsplit(",", 1)[-1].strip()
            try:
                ip = ipaddress.ip_address(last)
            except ValueError:
                pass
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv6Address):
            return str(ipaddress.ip_network((ip, 64), strict=False))
        return str(ip)

    async def read_head(self, reader):
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.cfg.head_timeout_s)
        except asyncio.TimeoutError:
            raise Refuse(408, "request head too slow", "refused_slow_head")
        except asyncio.LimitOverrunError:
            raise Refuse(431, "request head too large", "refused_bad_request")
        except (asyncio.IncompleteReadError, ConnectionError):
            raise Refuse(0, "closed", "closed_before_request")
        if len(raw) > 8192:
            raise Refuse(431, "request head too large", "refused_bad_request")
        try:
            text = raw[:-4].decode("latin-1")
        except UnicodeDecodeError:
            raise Refuse(400, "bad request", "refused_bad_request")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise Refuse(400, "bad request line", "refused_bad_request")
        headers = {}
        if len(lines) > 65:
            raise Refuse(431, "too many headers", "refused_bad_request")
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if not sep or not name or name != name.strip() or line[0] in " \t":
                raise Refuse(400, "bad header", "refused_bad_request")
            name = name.lower()
            value = value.strip()
            if name in headers and name in ("host", "origin", "upgrade", "sec-websocket-key", "sec-websocket-version", "content-length", "transfer-encoding"):
                raise Refuse(400, "duplicate header", "refused_bad_request")
            headers[name] = value if name not in headers else headers[name] + ", " + value
        return parts[0], parts[1], headers

    def check_upgrade(self, method, target, headers):
        if method != "GET":
            raise Refuse(405, "GET only", "refused_bad_request")
        if target != self.cfg.path:
            raise Refuse(404, "not found", "refused_path")
        if "content-length" in headers and headers["content-length"] != "0" or "transfer-encoding" in headers:
            raise Refuse(400, "no request body expected", "refused_bad_request")
        origin = headers.get("origin")
        if origin is None:
            if not self.cfg.allow_no_origin:
                raise Refuse(403, "Origin required", "refused_origin")
        elif origin.rstrip("/").lower() not in self.cfg.origin_set:
            raise Refuse(403, "Origin not allowed", "refused_origin")
        if headers.get("upgrade", "").lower() != "websocket" or "upgrade" not in [t.strip().lower() for t in headers.get("connection", "").split(",")]:
            raise Refuse(426, "WebSocket upgrade required", "refused_not_websocket")
        if headers.get("sec-websocket-version") != "13":
            raise Refuse(426, "WebSocket version 13 required", "refused_not_websocket")
        key = headers.get("sec-websocket-key", "")
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError
        except ValueError:
            raise Refuse(400, "bad Sec-WebSocket-Key", "refused_bad_request")
        protocols = [p.strip() for p in headers.get("sec-websocket-protocol", "").split(",")]
        if "mqtt" not in protocols:
            raise Refuse(400, "subprotocol mqtt required", "refused_subprotocol")
        return key

    async def respond(self, writer, status, body, extra=""):
        data = body.encode()
        head = (f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Error')}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(data)}\r\nConnection: close\r\nCache-Control: no-store\r\n{extra}\r\n")
        try:
            writer.write(head.encode() + data)
            await asyncio.wait_for(writer.drain(), 3)
        except (OSError, asyncio.TimeoutError):
            pass

    def admit(self, key):
        """Per-address connection and rate limits; returns the reason to refuse, or None (and counts the connection)."""
        now = time.monotonic()
        if len(self.recent) > 4096:
            for k in [k for k, d in self.recent.items() if k not in self.per_ip and (not d or now - d[-1] > 60)]:
                del self.recent[k]
        recent = self.recent[key]
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= self.cfg.connect_rate:
            return "refused_rate"
        if self.per_ip[key] >= self.cfg.max_per_ip:
            return "refused_per_ip"
        recent.append(now)
        self.per_ip[key] += 1
        return None

    def release(self, key):
        self.per_ip[key] -= 1
        if self.per_ip[key] <= 0:
            del self.per_ip[key]
            if not self.recent.get(key):
                self.recent.pop(key, None)

    async def handle(self, reader, writer):
        if self.total >= self.cfg.max_total or self.stopping:
            self.counters["refused_total"] += 1
            await self.respond(writer, 503, "busy\n", "Retry-After: 30\r\n")
            await self._close(writer)
            return
        self.total += 1
        key = None
        upstream = None
        try:
            peer = (writer.get_extra_info("peername") or ("?",))[0]
            method, target, headers = await self.read_head(reader)
            if method == "GET" and target == "/healthz":
                await self.respond(writer, 200, json.dumps(self.health()) + "\n")
                return
            client = self.client_key(peer, headers)
            ws_key = self.check_upgrade(method, target, headers)
            reason = self.admit(client)
            if reason:
                raise Refuse(429, "too many connections", reason)
            key = client
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(*split_hostport(self.cfg.upstream)), self.cfg.connect_timeout_s)
            except (OSError, asyncio.TimeoutError):
                raise Refuse(503, "broker unavailable", "refused_upstream")
            writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {accept_key(ws_key)}\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n").encode())
            await asyncio.wait_for(writer.drain(), self.cfg.write_timeout_s)
            self.counters["accepted"] += 1
            conn = Conn(self, reader, writer, upstream[0], upstream[1], client if self.cfg.log_ips else "-")
            self.active.add(conn)
            try:
                await conn.run()
            finally:
                self.active.discard(conn)
        except Refuse as r:
            self.counters[r.counter] += 1
            if r.status:
                extra = "Sec-WebSocket-Version: 13\r\n" if r.status == 426 else ""
                await self.respond(writer, r.status, r.reason + "\n", extra)
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            self.counters["errors"] += 1
        finally:
            if key is not None:
                self.release(key)
            self.total -= 1
            if upstream:
                await self._close(upstream[1])
            await self._close(writer)

    @staticmethod
    async def _close(writer):
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            pass


class Conn:
    """One upgraded connection: browser <-> broker."""

    def __init__(self, bridge, reader, writer, up_reader, up_writer, who):
        self.b, self.cfg = bridge, bridge.cfg
        self.r, self.w, self.ur, self.uw, self.who = reader, writer, up_reader, up_writer, who
        self.shutdown = asyncio.Event()
        self.msgs = Bucket(self.cfg.msg_rate, self.cfg.msg_burst)
        self.bytes = Bucket(self.cfg.byte_rate, self.cfg.byte_burst)
        self.first = True
        self.closed_sent = False
        self.last_client = time.monotonic()
        self.born = time.monotonic()

    async def send(self, data):
        self.w.write(data)
        await asyncio.wait_for(self.w.drain(), self.cfg.write_timeout_s)

    async def send_close(self, code, reason=""):
        if self.closed_sent:
            return
        self.closed_sent = True
        try:
            await self.send(frame(OP_CLOSE, struct.pack("!H", code) + reason.encode()[:100]))
        except (OSError, asyncio.TimeoutError):
            pass

    async def run(self):
        tasks = [asyncio.ensure_future(self.from_client()), asyncio.ensure_future(self.from_broker()),
                 asyncio.ensure_future(self.watch())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            # A task that ended with a close code has already said so; the rest is cleanup.
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.send_close(1001 if self.shutdown.is_set() else 1000)

    async def watch(self):
        """Idle timeout, lifetime, shutdown."""
        try:
            while True:
                now = time.monotonic()
                if self.shutdown.is_set():
                    await self.send_close(1001, "server stopping")
                    self.b.counters["closed_shutdown"] += 1
                    return
                if now - self.last_client > self.cfg.idle_s:
                    await self.send_close(1001, "idle")
                    self.b.counters["closed_idle"] += 1
                    return
                if now - self.born > self.cfg.max_lifetime_s:
                    await self.send_close(1001, "lifetime")
                    self.b.counters["closed_lifetime"] += 1
                    return
                try:
                    await asyncio.wait_for(self.shutdown.wait(), min(1.0, self.cfg.idle_s / 4))
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            raise

    async def from_broker(self):
        try:
            while True:
                data = await self.ur.read(4096)
                if not data:
                    self.b.counters["closed_by_broker"] += 1
                    await self.send_close(1000, "broker closed")
                    return
                await self.send(frame(OP_BINARY, data))
        except (OSError, asyncio.TimeoutError):
            self.b.counters["errors"] += 1
            await self.send_close(1011, "error")

    async def read_exact(self, n):
        return await asyncio.wait_for(self.r.readexactly(n), self.cfg.frame_timeout_s)

    async def read_frame(self):
        """-> (fin, opcode, payload). The first byte may take as long as the idle timeout allows."""
        first = await self.r.readexactly(2)
        b0, b1 = first
        fin, rsv, opcode = b0 & 0x80, b0 & 0x70, b0 & 0x0F
        masked, n = b1 & 0x80, b1 & 0x7F
        if rsv:
            raise Closing(1002, "reserved bits", "closed_protocol")
        if not masked:
            raise Closing(1002, "client frames must be masked", "closed_protocol")
        if n == 126:
            n = struct.unpack("!H", await self.read_exact(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", await self.read_exact(8))[0]
        if opcode >= 0x8 and (n > 125 or not fin):
            raise Closing(1002, "bad control frame", "closed_protocol")
        if n > self.cfg.max_message:
            raise Closing(1009, "frame too large", "closed_too_large")
        mask = await self.read_exact(4)
        payload = unmask(await self.read_exact(n), mask) if n else b""
        return bool(fin), opcode, payload

    async def from_client(self):
        buf = None  # a fragmented message in progress
        try:
            while True:
                try:
                    fin, opcode, payload = await self.read_frame()
                except asyncio.IncompleteReadError:
                    self.b.counters["closed_by_client"] += 1
                    return
                except asyncio.TimeoutError:
                    raise Closing(1008, "frame too slow", "closed_slow_frame")
                self.last_client = time.monotonic()
                if not self.msgs.take(1) or not self.bytes.take(len(payload) + 2):
                    raise Closing(1008, "rate limit", "closed_rate")
                if opcode == OP_CLOSE:
                    self.b.counters["closed_by_client"] += 1
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1000
                    await self.send_close(code if 1000 <= code <= 4999 and code not in (1004, 1005, 1006, 1015) else 1000)
                    return
                if opcode == OP_PING:
                    await self.send(frame(OP_PONG, payload))
                    continue
                if opcode == OP_PONG:
                    continue
                if opcode == OP_TEXT:
                    raise Closing(1003, "binary frames only", "closed_protocol")
                if opcode == OP_BINARY:
                    if buf is not None:
                        raise Closing(1002, "new message inside a fragmented one", "closed_protocol")
                    buf = bytearray()
                elif opcode == OP_CONT:
                    if buf is None:
                        raise Closing(1002, "continuation without a message", "closed_protocol")
                else:
                    raise Closing(1002, "unknown opcode", "closed_protocol")
                buf += payload
                if len(buf) > self.cfg.max_message:
                    raise Closing(1009, "message too large", "closed_too_large")
                if not fin:
                    continue
                msg, buf = bytes(buf), None
                if not msg:
                    continue
                if self.first:
                    # Only an MQTT CONNECT may start a session: this is not a general TCP relay.
                    if msg[0] != 0x10:
                        raise Closing(1008, "MQTT CONNECT first", "closed_not_mqtt")
                    self.first = False
                self.uw.write(msg)
                await asyncio.wait_for(self.uw.drain(), self.cfg.write_timeout_s)
        except Closing as c:
            self.b.counters[c.counter] += 1
            await self.send_close(c.code, c.reason)
        except (OSError, asyncio.TimeoutError):
            self.b.counters["errors"] += 1
            await self.send_close(1011, "error")


async def serve(cfg):
    bridge = await Bridge(cfg).start()
    loop = asyncio.get_running_loop()
    done = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, done.set)
    await done.wait()
    bridge.log("bridge: shutting down")
    await bridge.stop()


def main(argv=None):
    try:
        cfg = config_from(sys.argv[1:] if argv is None else argv, os.environ)
    except ValueError as e:
        print(f"bridge: configuration error: {e}", file=sys.stderr)
        return 2
    asyncio.run(serve(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
