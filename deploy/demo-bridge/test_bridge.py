#!/usr/bin/env python3
"""Tests of the demo bridge: unit tests, an integration test against a local TCP echo / fake MQTT server and, when
`mosquitto` is installed, against a local mosquitto on a free port.

    python3 -I deploy/demo-bridge/test_bridge.py

Everything binds 127.0.0.1 and port 0 (a free port); nothing is reachable from outside this machine.
"""
import asyncio
import base64
import contextlib
import ipaddress
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bridge as B  # noqa: E402

ORIGIN = "https://example.test"
CONNECT = bytes.fromhex("101000044d51545404020000000474657374")  # MQTT 3.1.1 CONNECT, client id "test", clean session


def cfg(**kw):
    values = dict(listen="127.0.0.1:0", upstream="127.0.0.1:1", origins=ORIGIN, stats_interval_s=0, grace_s=2)
    values.update(kw)
    return B.Config(**values)


def mask_frame(opcode, payload=b"", fin=True, mask=b"\x01\x02\x03\x04", masked=True):
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    flag = 0x80 if masked else 0
    if n < 126:
        head += bytes([flag | n])
    elif n < 65536:
        head += bytes([flag | 126]) + struct.pack("!H", n)
    else:
        head += bytes([flag | 127]) + struct.pack("!Q", n)
    if masked:
        return head + mask + B.unmask(payload, mask)
    return head + payload


class WS:
    """A WebSocket test client over asyncio streams."""

    def __init__(self, reader, writer):
        self.r, self.w = reader, writer

    @classmethod
    async def open(cls, port, origin=ORIGIN, path="/demo/mqtt", protocol="mqtt", extra="", method="GET", version="13", key=None,
                    upgrade=True, xff=None):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        key = key or base64.b64encode(os.urandom(16)).decode()
        lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
        if upgrade:
            lines += ["Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", f"Sec-WebSocket-Version: {version}"]
        if protocol:
            lines.append(f"Sec-WebSocket-Protocol: {protocol}")
        if origin is not None:
            lines.append(f"Origin: {origin}")
        if xff:
            lines.append(f"X-Forwarded-For: {xff}")
        w.write(("\r\n".join(lines) + "\r\n" + extra + "\r\n").encode())
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)
        ws = cls(r, w)
        ws.head = head.decode("latin-1")
        ws.status = int(ws.head.split(" ", 2)[1])
        ws.key = key
        return ws

    def header(self, name):
        for line in self.head.split("\r\n")[1:]:
            k, _, v = line.partition(":")
            if k.lower() == name.lower():
                return v.strip()

    async def body(self):
        n = int(self.header("content-length") or 0)
        return (await self.r.readexactly(n)).decode() if n else ""

    def send(self, data):
        self.w.write(data)

    def binary(self, payload, **kw):
        self.send(mask_frame(B.OP_BINARY, payload, **kw))

    async def frame(self, timeout=5):
        """-> (opcode, payload) of the next server frame, or None when the connection ended."""
        try:
            b0, b1 = await asyncio.wait_for(self.r.readexactly(2), timeout)
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack("!H", await self.r.readexactly(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", await self.r.readexactly(8))[0]
            assert not b1 & 0x80, "server frames are never masked"
            return b0 & 0x0F, await self.r.readexactly(n)
        except (asyncio.IncompleteReadError, ConnectionError):
            return None

    async def close_code(self, timeout=5):
        """Reads frames until a close frame; returns its code (None: ended without one)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            f = await self.frame(max(0.1, end - time.monotonic()))
            if f is None:
                return None
            if f[0] == B.OP_CLOSE:
                return struct.unpack("!H", f[1][:2])[0] if len(f[1]) >= 2 else 1005
        return "timeout"

    async def ended(self, timeout=3):
        try:
            return (await asyncio.wait_for(self.r.read(), timeout)) == b""
        except (asyncio.TimeoutError, ConnectionError):
            return False

    async def aclose(self):
        self.w.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.w.wait_closed(), 2)


class Upstream:
    """A fake MQTT server on a free loopback port: counts connections, records bytes, echoes them back."""

    def __init__(self, echo=True):
        self.echo, self.received, self.connections, self.writers = echo, [], 0, []
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, r, w):
        self.connections += 1
        self.writers.append(w)
        try:
            while True:
                data = await r.read(4096)
                if not data:
                    break
                self.received.append(data)
                if self.echo:
                    w.write(data)
                    await w.drain()
        except ConnectionError:
            pass
        finally:
            w.close()

    async def stop(self):
        self.server.close()
        for w in self.writers:
            w.close()


class Env:
    """A bridge in front of a fake upstream, with the log captured."""

    def __init__(self, upstream=None, **kw):
        self.kw, self.up, self.log = kw, upstream, []

    async def __aenter__(self):
        if self.up is None:
            self.up = await Upstream().start()
        c = cfg(upstream=f"127.0.0.1:{self.up.port}", **self.kw)
        # No test may bind a non-loopback address.
        assert ipaddress.ip_address(B.split_hostport(c.listen, True)[0]).is_loopback
        self.bridge = await B.Bridge(c, log=self.log.append).start()
        self.port = self.bridge.port
        return self

    async def __aexit__(self, *exc):
        await self.bridge.stop()
        await self.up.stop()


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


class UnitTests(unittest.TestCase):
    def test_accept_key_is_the_rfc_6455_example(self):
        self.assertEqual(B.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_unmask_and_frame(self):
        self.assertEqual(B.unmask(b"", b"abcd"), b"")
        mask = b"\x37\xfa\x21\x3d"  # RFC 6455 section 5.7: "Hello"
        self.assertEqual(B.unmask(bytes.fromhex("7f9f4d5158"), mask), b"Hello")
        for n in (1, 3, 4, 5, 125, 126, 1000):
            data = os.urandom(n)
            self.assertEqual(B.unmask(B.unmask(data, mask), mask), data)
        self.assertEqual(B.frame(B.OP_BINARY, b"ab"), b"\x82\x02ab")
        self.assertEqual(B.frame(B.OP_BINARY, b"x" * 200)[:4], b"\x82\x7e\x00\xc8")
        self.assertEqual(B.frame(B.OP_BINARY, b"x" * 70000)[:2], b"\x82\x7f")

    def test_bucket(self):
        b = B.Bucket(1000.0, 3)
        self.assertTrue(b.take() and b.take() and b.take())
        self.assertFalse(b.take())
        time.sleep(0.02)
        self.assertTrue(b.take())
        self.assertFalse(B.Bucket(1, 2).take(3))

    def test_configuration_is_checked(self):
        with self.assertRaises(ValueError):
            cfg(origins="")  # no allowed origin
        with self.assertRaises(ValueError):
            cfg(origins="https://*.example.test")
        with self.assertRaises(ValueError):
            cfg(origins="example.test")
        with self.assertRaises(ValueError):
            cfg(upstream="no-port")
        with self.assertRaises(ValueError):
            cfg(max_message=10)
        with self.assertRaises(ValueError):
            cfg(path="demo")
        cfg(origins="", allow_no_origin=True)
        c = cfg(origins="https://A.example.test/, http://b.example.test:8080")
        self.assertEqual(c.origin_set, {"https://a.example.test", "http://b.example.test:8080"})

    def test_configuration_from_arguments_and_environment(self):
        c = B.config_from(["--origin", "https://x.test", "--max-per-ip", "7"], {"DEMO_BRIDGE_UPSTREAM": "10.1.2.3:1883", "DEMO_BRIDGE_ORIGINS": "https://y.test"})
        self.assertEqual((c.upstream, c.max_per_ip, c.origin_set), ("10.1.2.3:1883", 7, {"https://x.test", "https://y.test"}))
        self.assertFalse(c.allow_no_origin)
        self.assertTrue(B.config_from(["--origin", "https://x.test"], {"DEMO_BRIDGE_LOG_IPS": "true"}).log_ips)

    def test_client_address_is_the_peer_or_a_trusted_proxies_last_xff_entry(self):
        b = B.Bridge(cfg(), log=lambda m: None)
        self.assertEqual(b.client_key("198.51.100.9", {"x-forwarded-for": "203.0.113.1"}), "198.51.100.9")  # not a proxy: header ignored
        self.assertEqual(b.client_key("127.0.0.1", {"x-forwarded-for": "6.6.6.6, 203.0.113.1"}), "203.0.113.1")  # the last entry
        self.assertEqual(b.client_key("172.17.0.1", {"x-forwarded-for": "203.0.113.1"}), "203.0.113.1")
        self.assertEqual(b.client_key("127.0.0.1", {"x-forwarded-for": "garbage"}), "127.0.0.1")
        self.assertEqual(b.client_key("127.0.0.1", {}), "127.0.0.1")
        self.assertEqual(b.client_key("127.0.0.1", {"x-forwarded-for": "2001:db8:1:2:3:4:5:6"}), "2001:db8:1:2::/64")
        self.assertEqual(b.client_key("127.0.0.1", {"x-forwarded-for": "::ffff:203.0.113.1"}), "203.0.113.1")
        self.assertEqual(B.Bridge(cfg(trusted_proxies=""), log=lambda m: None).client_key("127.0.0.1", {"x-forwarded-for": "1.2.3.4"}), "127.0.0.1")

    def test_per_address_admission(self):
        b = B.Bridge(cfg(max_per_ip=2, connect_rate=3), log=lambda m: None)
        self.assertIsNone(b.admit("a"))
        self.assertIsNone(b.admit("a"))
        self.assertEqual(b.admit("a"), "refused_per_ip")
        b.release("a")
        self.assertIsNone(b.admit("a"))  # the third start inside the minute
        b.release("a")
        b.release("a")
        self.assertEqual(b.admit("a"), "refused_rate")  # 3 starts in a minute
        self.assertIsNone(b.admit("b"))


class IntegrationTests(unittest.TestCase):
    def test_handshake_and_a_session_through_a_fake_server(self):
        async def go():
            async with Env() as e:
                ws = await WS.open(e.port)
                self.assertEqual(ws.status, 101)
                self.assertEqual(ws.header("Sec-WebSocket-Accept"), B.accept_key(ws.key))
                self.assertEqual(ws.header("Sec-WebSocket-Protocol"), "mqtt")
                ws.binary(CONNECT)
                self.assertEqual(await ws.frame(), (B.OP_BINARY, CONNECT))  # sent upstream as it was, echoed back as one message
                self.assertEqual(e.up.received, [CONNECT])
                ws.binary(b"\xc0\x00")  # PINGREQ
                self.assertEqual(await ws.frame(), (B.OP_BINARY, b"\xc0\x00"))
                ws.send(mask_frame(B.OP_PING, b"hi"))
                self.assertEqual(await ws.frame(), (B.OP_PONG, b"hi"))
                ws.send(mask_frame(B.OP_CLOSE, struct.pack("!H", 1000)))
                self.assertEqual(await ws.close_code(), 1000)
                self.assertTrue(await ws.ended())
                await ws.aclose()
        run(go())

    def test_requests_that_are_refused(self):
        async def go():
            async with Env() as e:
                cases = [
                    ("wrong origin", dict(origin="https://evil.test"), 403),
                    ("origin with a suffix of the right one", dict(origin=ORIGIN + ".evil.test"), 403),
                    ("no origin", dict(origin=None), 403),
                    ("origin null", dict(origin="null"), 403),
                    ("wrong path", dict(path="/other"), 404),
                    ("path with a query", dict(path="/demo/mqtt?x=1"), 404),
                    ("no upgrade", dict(upgrade=False), 426),
                    ("version 8", dict(version="8"), 426),
                    ("no subprotocol", dict(protocol=None), 400),
                    ("another subprotocol", dict(protocol="chat"), 400),
                    ("bad key", dict(key="AAAA"), 400),
                    ("POST", dict(method="POST"), 405),
                    ("a body", dict(extra="Content-Length: 5\r\n"), 400),
                ]
                for name, kw, status in cases:
                    ws = await WS.open(e.port, **kw)
                    self.assertEqual(ws.status, status, name)
                    await ws.body()
                    await ws.aclose()
                self.assertEqual(e.up.connections, 0, "a refused request must not reach the broker")
        run(go())

    def test_a_missing_origin_is_allowed_only_when_configured(self):
        async def go():
            async with Env(allow_no_origin=True) as e:
                ws = await WS.open(e.port, origin=None)
                self.assertEqual(ws.status, 101)
                await ws.aclose()
        run(go())

    def test_garbage_and_oversized_heads_are_refused(self):
        async def go():
            async with Env(head_timeout_s=0.5) as e:
                for raw in (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 40 + b"\r\n\r\n", b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 20000 + b"\r\n\r\n"):
                    r, w = await asyncio.open_connection("127.0.0.1", e.port)
                    w.write(raw)
                    data = await asyncio.wait_for(r.read(), 5)
                    self.assertTrue(data.startswith(b"HTTP/1.1 400") or data.startswith(b"HTTP/1.1 431") or data == b"", data[:40])
                    w.close()
                # a request that never ends
                r, w = await asyncio.open_connection("127.0.0.1", e.port)
                w.write(b"GET /demo/mqtt HTTP/1.1\r\nHost: x\r\n")
                data = await asyncio.wait_for(r.read(), 5)
                self.assertTrue(data.startswith(b"HTTP/1.1 408"), data[:40])
                w.close()
                self.assertEqual(e.up.connections, 0)
        run(go())

    def test_only_an_mqtt_connect_may_start_a_session(self):
        async def go():
            async with Env() as e:
                ws = await WS.open(e.port)
                ws.binary(b"GET / HTTP/1.1\r\n\r\n")  # a relay for something else
                self.assertEqual(await ws.close_code(), 1008)
                await ws.aclose()
                self.assertEqual(e.up.received, [])
        run(go())

    def test_frame_rules(self):
        async def go():
            async with Env(max_message=64) as e:
                async def after(frames, code):
                    ws = await WS.open(e.port)
                    for f in frames:
                        ws.send(f)
                    self.assertEqual(await ws.close_code(), code)
                    await ws.aclose()
                await after([mask_frame(B.OP_BINARY, CONNECT, masked=False)], 1002)  # unmasked
                await after([mask_frame(B.OP_TEXT, b"text")], 1003)
                await after([mask_frame(B.OP_BINARY, b"x" * 65)], 1009)  # one frame over the limit
                await after([mask_frame(B.OP_BINARY, b"\x10" + b"x" * 40, fin=False), mask_frame(B.OP_CONT, b"x" * 40)], 1009)  # fragments over it
                await after([mask_frame(B.OP_CONT, b"x")], 1002)
                await after([mask_frame(B.OP_BINARY, b"\x10", fin=False), mask_frame(B.OP_BINARY, b"x")], 1002)
                await after([mask_frame(B.OP_PING, b"x" * 100)], 1009)  # over the 64 byte limit (a control frame over 125 would be 1002)
                await after([bytes([0x82 | 0x40, 0x80]) + b"\x00" * 4], 1002)  # reserved bit
                await after([mask_frame(0x3, b"")], 1002)  # unknown opcode
                await after([bytes([0x82, 0xFF]) + struct.pack("!Q", 1 << 40) + b"\x00" * 4], 1009)  # a length that never arrives is refused unread
                # fragments within the limit are one message
                ws = await WS.open(e.port)
                ws.send(mask_frame(B.OP_BINARY, CONNECT[:5], fin=False))
                ws.send(mask_frame(B.OP_CONT, CONNECT[5:]))
                self.assertEqual(await ws.frame(), (B.OP_BINARY, CONNECT))
                self.assertEqual(e.up.received[-1], CONNECT)
                await ws.aclose()
        run(go())

    def test_a_frame_that_stalls_is_closed(self):
        async def go():
            async with Env(frame_timeout_s=0.4) as e:
                ws = await WS.open(e.port)
                ws.send(bytes([0x82, 0x85, 1, 2, 3, 4]))  # promises 5 bytes, sends none
                self.assertEqual(await ws.close_code(), 1008)
                await ws.aclose()
        run(go())

    def test_per_address_and_total_caps(self):
        async def go():
            async with Env(max_per_ip=2, max_total=3, connect_rate=100) as e:
                a = [await WS.open(e.port, xff="203.0.113.1") for _ in range(2)]
                self.assertEqual([w.status for w in a], [101, 101])
                third = await WS.open(e.port, xff="203.0.113.1")
                self.assertEqual(third.status, 429)  # the address is at its cap
                await third.aclose()
                other = await WS.open(e.port, xff="203.0.113.2")
                self.assertEqual(other.status, 101)  # another address is not
                over = await WS.open(e.port, xff="203.0.113.3")
                self.assertEqual(over.status, 503)  # the whole bridge is at its cap
                await over.aclose()
                await a[0].aclose()
                await asyncio.sleep(0.2)
                again = await WS.open(e.port, xff="203.0.113.1")
                self.assertEqual(again.status, 101)  # a closed connection makes room
                for w in a[1:] + [other, again]:
                    await w.aclose()
                self.assertEqual(e.bridge.counters["refused_per_ip"], 1)
                self.assertEqual(e.bridge.counters["refused_total"], 1)
        run(go())

    def test_xff_from_an_untrusted_peer_cannot_dodge_the_cap(self):
        async def go():
            async with Env(max_per_ip=1, trusted_proxies="192.0.2.0/24", connect_rate=100) as e:  # 127.0.0.1 is not a trusted proxy
                a = await WS.open(e.port, xff="203.0.113.1")
                b = await WS.open(e.port, xff="203.0.113.2")
                self.assertEqual((a.status, b.status), (101, 429))
                await a.aclose()
                await b.aclose()
        run(go())

    def test_new_connections_per_minute_per_address(self):
        async def go():
            async with Env(connect_rate=3, max_per_ip=10) as e:
                got = []
                for _ in range(5):
                    w = await WS.open(e.port, xff="203.0.113.5")
                    got.append(w.status)
                    await w.aclose()
                self.assertEqual(got, [101, 101, 101, 429, 429])
        run(go())

    def test_rate_limit_closes_a_flooding_connection(self):
        async def go():
            async with Env(msg_rate=1.0, msg_burst=5, byte_burst=100000, byte_rate=100000) as e:
                ws = await WS.open(e.port)
                ws.binary(CONNECT)
                for _ in range(30):
                    ws.binary(b"\xc0\x00")
                code = None
                while True:
                    f = await ws.frame()
                    if f is None:
                        break
                    if f[0] == B.OP_CLOSE:
                        code = struct.unpack("!H", f[1][:2])[0]
                        break
                self.assertEqual(code, 1008)
                self.assertLess(len(e.up.received), 10)
                await ws.aclose()
            async with Env(byte_rate=100, byte_burst=300, msg_burst=1000, msg_rate=1000) as e:
                ws = await WS.open(e.port)
                ws.binary(CONNECT)
                for _ in range(10):
                    ws.binary(b"\x30" + b"x" * 100)
                self.assertEqual(await ws.close_code(), 1008)
                await ws.aclose()
        run(go())

    def test_idle_timeout_and_pings_keep_a_connection_alive(self):
        async def go():
            async with Env(idle_s=0.8) as e:
                quiet = await WS.open(e.port)
                busy = await WS.open(e.port)
                for _ in range(5):
                    await asyncio.sleep(0.3)
                    busy.send(mask_frame(B.OP_PING, b""))
                self.assertEqual(await quiet.close_code(1), 1001)
                self.assertEqual((await busy.frame())[0], B.OP_PONG)
                await quiet.aclose()
                await busy.aclose()
                self.assertEqual(e.bridge.counters["closed_idle"], 1)
        run(go())

    def test_lifetime_limit(self):
        async def go():
            async with Env(max_lifetime_s=0.5, idle_s=0.8) as e:
                ws = await WS.open(e.port)
                self.assertEqual(await ws.close_code(3), 1001)
                await ws.aclose()
        run(go())

    def test_the_broker_closing_closes_the_websocket_and_an_unreachable_broker_is_a_503(self):
        async def go():
            async with Env() as e:
                ws = await WS.open(e.port)
                ws.binary(CONNECT)
                await ws.frame()
                for w in e.up.writers:
                    w.close()
                self.assertEqual(await ws.close_code(), 1000)
                await ws.aclose()
            async with Env() as e:
                await e.up.stop()
                ws = await WS.open(e.port)
                self.assertEqual(ws.status, 503)
                await ws.aclose()
        run(go())

    def test_client_closing_closes_the_broker_side(self):
        async def go():
            async with Env() as e:
                ws = await WS.open(e.port)
                ws.binary(CONNECT)
                await ws.frame()
                await ws.aclose()  # no close frame: the TCP connection just ends
                for _ in range(40):
                    if e.bridge.total == 0:
                        break
                    await asyncio.sleep(0.05)
                self.assertEqual(e.bridge.total, 0)
                self.assertEqual(dict(e.bridge.per_ip), {})
        run(go())

    def test_graceful_shutdown_sends_1001(self):
        async def go():
            async with Env() as e:
                ws = await WS.open(e.port)
                ws.binary(CONNECT)
                await ws.frame()
                stopper = asyncio.ensure_future(e.bridge.stop())
                self.assertEqual(await ws.close_code(), 1001)
                await stopper
                await ws.aclose()
                with self.assertRaises(OSError):
                    await asyncio.open_connection("127.0.0.1", e.port)
        run(go())

    def test_healthz_has_counters_and_no_addresses(self):
        async def go():
            async with Env() as e:
                r, w = await asyncio.open_connection("127.0.0.1", e.port)
                w.write(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                data = (await asyncio.wait_for(r.read(), 5)).decode()
                self.assertTrue(data.startswith("HTTP/1.1 200"), data)
                self.assertIn('"ok": true', data)
                self.assertNotIn("127.0.0.1", data)
                w.close()
        run(go())

    def test_payloads_and_addresses_are_not_logged(self):
        async def go():
            async with Env(stats_interval_s=0) as e:
                secret = b"SECRET-PAYLOAD-0123456789"
                ws = await WS.open(e.port, xff="203.0.113.77")
                ws.binary(CONNECT)
                await ws.frame()
                ws.binary(b"\x30" + bytes([len(secret) + 2]) + b"\x00\x00" + secret)
                await ws.frame()
                await ws.aclose()
                bad = await WS.open(e.port, origin="https://evil.test")
                await bad.aclose()
                await e.bridge.stop()
                text = "\n".join(e.log)
                self.assertNotIn("SECRET-PAYLOAD", text)
                self.assertNotIn("203.0.113.77", text)
                self.assertNotIn("evil.test", text)
                self.assertEqual(e.bridge.counters["refused_origin"], 1)
        run(go())


def find_mosquitto():
    for cand in (shutil.which("mosquitto"), "/opt/homebrew/sbin/mosquitto", "/usr/local/sbin/mosquitto", "/usr/sbin/mosquitto"):
        if cand and os.path.exists(cand):
            return cand
    return None


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pkt(first, body):
    n, out = len(body), b""
    while True:
        d, n = n % 128, n // 128
        out += bytes([d | (128 if n else 0)])
        if not n:
            break
    return bytes([first]) + out + body


def mstr(s):
    s = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(s)) + s


def mqtt_connect(client_id):
    return pkt(0x10, mstr("MQTT") + bytes([4, 2]) + struct.pack("!H", 30) + mstr(client_id))


@unittest.skipUnless(find_mosquitto(), "mosquitto is not installed")
class MosquittoTests(unittest.TestCase):
    """MQTT over WebSocket through the bridge to a real mosquitto on a free loopback port."""

    @contextlib.contextmanager
    def broker(self):
        port = free_port()
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "mosquitto.conf")
            with open(conf, "w") as fh:
                fh.write(f"listener {port} 127.0.0.1\nallow_anonymous true\npersistence false\nlog_dest none\n")
            proc = subprocess.Popen([find_mosquitto(), "-c", conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    with contextlib.suppress(OSError):
                        socket.create_connection(("127.0.0.1", port), 0.2).close()
                        break
                    time.sleep(0.05)
                yield port
            finally:
                proc.terminate()
                proc.wait(5)

    async def packet(self, ws):
        """Reads WebSocket messages until they hold one whole MQTT packet; returns (first byte, body)."""
        buf = b""
        while True:
            if len(buf) >= 2:
                n, mult, i = 0, 1, 1
                while i < len(buf):
                    n += (buf[i] & 127) * mult
                    mult *= 128
                    i += 1
                    if not buf[i - 1] & 128:
                        break
                if len(buf) >= i + n and not buf[i - 1] & 128:
                    return buf[0], buf[i:i + n]
            f = await ws.frame()
            self.assertIsNotNone(f)
            self.assertEqual(f[0], B.OP_BINARY)
            buf += f[1]

    def test_connect_subscribe_publish_through_the_bridge(self):
        async def go(port):
            c = cfg(upstream=f"127.0.0.1:{port}")
            bridge = await B.Bridge(c, log=lambda m: None).start()
            try:
                sub = await WS.open(bridge.port)
                self.assertEqual(sub.status, 101)
                sub.binary(mqtt_connect("ws-sub"))
                self.assertEqual(await self.packet(sub), (0x20, b"\x00\x00"))
                sub.binary(pkt(0x82, struct.pack("!H", 1) + mstr("demo/web/#") + b"\x00"))
                self.assertEqual(await self.packet(sub), (0x90, b"\x00\x01\x00"))
                pub = await WS.open(bridge.port)
                pub.binary(mqtt_connect("ws-pub"))
                self.assertEqual(await self.packet(pub), (0x20, b"\x00\x00"))
                pub.binary(pkt(0x30, mstr("demo/web/room") + b"hello from a browser"))
                first, body = await self.packet(sub)
                self.assertEqual(first, 0x30)
                self.assertEqual(body, mstr("demo/web/room") + b"hello from a browser")
                # and from a plain TCP client (what mosquitto_pub is): the browser side receives it
                if shutil.which("mosquitto_pub"):
                    r = subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", str(port), "-t", "demo/web/tcp", "-m", "from tcp", "-q", "1"], capture_output=True)
                    self.assertEqual(r.returncode, 0)
                    first, body = await self.packet(sub)
                    self.assertEqual(body, mstr("demo/web/tcp") + b"from tcp")
                pub.binary(b"\xe0\x00")  # DISCONNECT
                sub.binary(b"\xc0\x00")
                self.assertEqual(await self.packet(sub), (0xD0, b""))
                await pub.aclose()
                await sub.aclose()
            finally:
                await bridge.stop()

        with self.broker() as port:
            run(go(port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
