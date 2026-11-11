#!/usr/bin/env python3
"""MQTT over WebSocket scenarios (ADR-272) against a booted dev VM.

    scripts/ws-scenarios.py MODE WS_PORT TLS_PORT CERTDIR [IDLE]

MODE says which image the VM runs (scripts/smoke.sh, group `websocket`, builds
them from the dev configuration plus a [websocket] section):

  mtls      auth = "mtls", origins = ["https://app.example.com"],
            upgrade_timeout_s = 3, room for IDLE connections from one address
  password  auth = "password", account web-1 (password web-secret), the same
            origin list, acl web/{id}/# and devices/+/t, 3 failures lock out
            for 8 s, packets up to 1024 bytes

The WebSocket clients are of two kinds: paho-mqtt with transport
"websockets" (what applications use), and a raw client written here that
puts every byte on the wire itself (fragments, pings, bad requests, slow
requests, protocol violations). Prints one "client: <scenario> ok|FAILED"
line per scenario and exits non-zero if any failed.
"""
import os
import socket
import ssl
import struct
import sys
import threading
import time

import paho.mqtt.client as mqtt

MODE, WS, TLS, DIR = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
IDLE = int(sys.argv[5]) if len(sys.argv) > 5 else 10000
ORIGIN = "https://app.example.com"
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


# ---- MQTT packets ------------------------------------------------------------


def varlen(n):
    out = b""
    while True:
        b, n = n % 128, n // 128
        out += bytes([b | (128 if n else 0)])
        if not n:
            return out


def mstr(x):
    x = x if isinstance(x, bytes) else x.encode()
    return struct.pack(">H", len(x)) + x


def pkt(first, body):
    return bytes([first]) + varlen(len(body)) + body


def connect_pkt(client_id, user=None, password=None, clean=True, keepalive=60, will=None):
    flags = (0x02 if clean else 0) | (0x80 if user is not None else 0) | (0x40 if password is not None else 0)
    if will:
        flags |= 0x04
    body = mstr("MQTT") + bytes([4, flags]) + struct.pack(">H", keepalive) + mstr(client_id)
    if will:
        body += mstr(will[0]) + mstr(will[1])
    if user is not None:
        body += mstr(user)
    if password is not None:
        body += mstr(password)
    return pkt(0x10, body)


def publish_pkt(topic, payload, qos=0, pid=1):
    body = mstr(topic) + (struct.pack(">H", pid) if qos else b"") + payload
    return pkt(0x30 | (qos << 1), body)


# ---- TLS -------------------------------------------------------------------


def tls_ctx(cert=None):
    ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
    ctx.check_hostname = False
    if cert:
        p = os.path.join(DIR, cert)
        ctx.load_cert_chain(p + ".pem", p + ".key")
    return ctx


def tls_sock(port, cert=None, timeout=10):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    return tls_ctx(cert).wrap_socket(s, server_hostname="localhost")


# ---- a raw WebSocket client --------------------------------------------------


def request(path="/mqtt", proto="mqtt", version="13", origin=ORIGIN, extra=""):
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: localhost",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        f"Sec-WebSocket-Version: {version}",
    ]
    if proto is not None:
        lines.append(f"Sec-WebSocket-Protocol: {proto}")
    if origin is not None:
        lines.append(f"Origin: {origin}")
    return ("\r\n".join(lines) + "\r\n" + extra + "\r\n").encode()


def frame(opcode, payload, fin=True, mask=b"\x11\x22\x33\x44", masked=True):
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    m = 0x80 if masked else 0
    if n < 126:
        head += bytes([m | n])
    elif n <= 0xFFFF:
        head += bytes([m | 126]) + struct.pack(">H", n)
    else:
        head += bytes([m | 127]) + struct.pack(">Q", n)
    if not masked:
        return head + payload
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class Ws:
    """One WebSocket connection, every byte by hand."""

    def __init__(self, cert=None, req=None, timeout=10):
        self.s = tls_sock(WS, cert, timeout)
        self.buf = b""
        if req is not None:
            self.s.sendall(req)
            self.status = self.read_response()

    def read_response(self):
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d:
                break
            self.buf += d
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.head = head.decode(errors="replace")
        return self.head.split("\r\n", 1)[0]

    def send(self, data):
        self.s.sendall(data)

    def recv_frame(self):
        """(opcode, payload) of the next server frame, None at the end."""

        def need(n):
            while len(self.buf) < n:
                d = self.s.recv(65536)
                if not d:
                    return False
                self.buf += d
            return True

        if not need(2):
            return None
        b0, b1 = self.buf[0], self.buf[1]
        if b1 & 0x80:
            raise ValueError("server frame is masked")
        n, off = b1 & 0x7F, 2
        if n == 126:
            if not need(4):
                return None
            n, off = struct.unpack(">H", self.buf[2:4])[0], 4
        elif n == 127:
            if not need(10):
                return None
            n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
        if not need(off + n):
            return None
        payload = self.buf[off : off + n]
        self.buf = self.buf[off + n :]
        if not b0 & 0x80:
            raise ValueError("server frame is fragmented")
        return b0 & 0x0F, payload

    def mqtt(self):
        """The payload of the next binary frame (skipping pongs)."""
        while True:
            f = self.recv_frame()
            if f is None:
                return None
            if f[0] == 2:
                return f[1]
            if f[0] == 8:
                return ("close", f[1])

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def run(name, fn):
    try:
        ok, detail = fn()
    except Exception as e:  # noqa: BLE001: a scenario that throws failed
        ok, detail = False, f"{type(e).__name__}: {e}"
    report(name, ok, detail)


# ---- paho ------------------------------------------------------------------


def paho_client(client_id, cert=None, user=None, password=None, ws=True, origin=ORIGIN, v5=False):
    proto = mqtt.MQTTv5 if v5 else mqtt.MQTTv311
    if hasattr(mqtt, "CallbackAPIVersion"):
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                        transport="websockets" if ws else "tcp", protocol=proto)
    else:
        c = mqtt.Client(client_id=client_id, transport="websockets" if ws else "tcp", protocol=proto)
    if ws:
        c.ws_set_options(path="/mqtt", headers={"Origin": origin} if origin else None)
    c.tls_set_context(tls_ctx(cert))
    c.tls_insecure_set(True)
    if user is not None:
        c.username_pw_set(user, password)
    got = []
    ev = threading.Event()
    c.on_message = lambda cl, ud, msg: (got.append((msg.topic, msg.payload, msg.qos)), ev.set(),
                                        c.props.append(getattr(msg, "properties", None)))
    c.props = []
    c.got, c.ev = got, ev
    return c


def connect(c, port):
    rc = []
    done = threading.Event()

    def on_connect(cl, ud, flags, reason, props=None):
        rc.append(int(reason) if not hasattr(reason, "value") else reason.value)
        done.set()

    c.on_connect = on_connect
    c.connect("127.0.0.1", port, keepalive=30)
    c.loop_start()
    if not done.wait(10):
        c.loop_stop()
        return None
    return rc[0]


def wait_msgs(c, n, timeout=8):
    end = time.time() + timeout
    while len(c.got) < n and time.time() < end:
        time.sleep(0.05)
    return c.got


def sys_value(topic):
    """One retained $SYS value, read by the operator over TLS (mutual), in a
    process of its own: paho's loop uses select(), which cannot take the
    descriptors of a process that holds thousands of sockets."""
    import subprocess

    cert = os.path.join(DIR, "services/operator")
    try:
        out = subprocess.run(
            ["mosquitto_sub", "-h", "127.0.0.1", "-p", str(TLS), "--cafile", os.path.join(DIR, "ca.pem"),
             "--cert", cert + ".pem", "--key", cert + ".key", "--insecure", "-i", "operator",
             "-t", topic, "-C", "1", "-W", "8", "-V", "mqttv311"],
            capture_output=True, timeout=15, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    v = out.stdout.strip()
    return v or None


# ---- mtls mode -------------------------------------------------------------


def mtls_mqtt5():
    """MQTT 5.0 over wss (ADR-274): a 5.0 backend and device, a user property
    forwarded."""
    from paho.mqtt.packettypes import PacketTypes
    from paho.mqtt.properties import Properties

    backend = paho_client("backend", cert="services/backend", v5=True)
    if connect(backend, WS) != 0:
        return False, "backend could not connect over wss"
    backend.subscribe("devices/#", 1)
    time.sleep(0.5)
    dev = paho_client("device-001", cert="devices/device-001", v5=True)
    if connect(dev, WS) != 0:
        return False, "device could not connect over wss"
    p = Properties(PacketTypes.PUBLISH)
    p.UserProperty = [("via", "wss")]
    dev.publish("devices/device-001/t", b"five", qos=1, properties=p).wait_for_publish(5)
    got = wait_msgs(backend, 1)
    for c in (dev, backend):
        c.disconnect()
        c.loop_stop()
    up = getattr(backend.props[0], "UserProperty", None) if backend.props else None
    return [x[1] for x in got] == [b"five"] and up == [("via", "wss")], f"got {got} {up}"


def mtls_pubsub():
    backend = paho_client("backend", cert="services/backend")
    if connect(backend, WS) != 0:
        return False, "backend could not connect over wss"
    backend.subscribe("devices/#", 1)
    time.sleep(0.5)
    dev = paho_client("device-001", cert="devices/device-001")
    if connect(dev, WS) != 0:
        return False, "device could not connect over wss"
    dev.publish("devices/device-001/t", b"q0", qos=0)
    dev.publish("devices/device-001/t", b"q1", qos=1).wait_for_publish(5)
    got = wait_msgs(backend, 2)
    for c in (dev, backend):
        c.disconnect()
        c.loop_stop()
    payloads = sorted(p for _, p, _ in got)
    return payloads == [b"q0", b"q1"], f"got {got}"


def mtls_large():
    backend = paho_client("backend", cert="services/backend")
    connect(backend, WS)
    backend.subscribe("devices/#", 0)
    time.sleep(0.5)
    dev = paho_client("device-001", cert="devices/device-001")
    connect(dev, WS)
    topic = "devices/device-001/big"
    # limits.max_packet_size = 4096 in the dev image: header 1 + 2 length
    # bytes + 2 + topic, the rest payload: exactly 4096 bytes.
    payload = bytes(range(256)) * 16
    payload = payload[: 4096 - 3 - 2 - len(topic)]
    dev.publish(topic, payload, qos=0)
    got = wait_msgs(backend, 1)
    # One byte more is refused: the broker's own limit, as on the TLS port.
    over = paho_client("device-002", cert="devices/device-002")
    connect(over, WS)
    gone = threading.Event()
    over.on_disconnect = lambda *a: gone.set()
    over.publish("devices/device-002/big", payload + b"xx", qos=0)
    cut = gone.wait(5)
    for c in (dev, backend, over):
        c.disconnect()
        c.loop_stop()
    ok = bool(got) and got[0][1] == payload and cut
    return ok, f"{len(payload) + 5 + len(topic)}-byte packet delivered: {bool(got) and got[0][1] == payload}; one over closes: {cut}"


def mtls_fragmented():
    backend = paho_client("backend", cert="services/backend")
    connect(backend, WS)
    backend.subscribe("devices/#", 0)
    time.sleep(0.5)
    w = Ws("devices/device-002", request())
    if "101" not in w.status:
        return False, w.status
    w.send(frame(2, connect_pkt("device-002")))
    ack = w.mqtt()
    pub = publish_pkt("devices/device-002/frag", b"in three pieces")
    # Three fragments, a ping between them, then PINGREQ in its own frame.
    w.send(frame(2, pub[:5], fin=False) + frame(9, b"hello?") + frame(0, pub[5:12], fin=False) + frame(0, pub[12:]))
    pong = w.recv_frame()
    w.send(frame(2, b"\xc0\x00"))
    pingresp = w.mqtt()
    got = wait_msgs(backend, 1)
    w.send(frame(2, b"\xe0\x00") + frame(8, struct.pack(">H", 1000)))
    closing = w.recv_frame()
    eof = w.recv_frame()
    w.close()
    backend.disconnect()
    backend.loop_stop()
    ok = (
        ack == b"\x20\x02\x00\x00"
        and pong == (10, b"hello?")
        and pingresp == b"\xd0\x00"
        and got
        and got[0][1] == b"in three pieces"
        and closing == (8, struct.pack(">H", 1000))
        and eof is None
    )
    return ok, f"connack {ack!r}, pong {pong!r}, pingresp {pingresp!r}, got {got}, close {closing!r}, then {eof!r}"


def abrupt_close():
    backend = paho_client("backend", cert="services/backend")
    connect(backend, WS)
    backend.subscribe("devices/device-003/will", 0)
    time.sleep(0.5)
    w = Ws("devices/device-003", request())
    w.send(frame(2, connect_pkt("device-003", will=("devices/device-003/will", "gone"))))
    w.mqtt()
    # TCP ends without a close frame (and without MQTT DISCONNECT).
    w.s.shutdown(socket.SHUT_RDWR)
    w.close()
    got = wait_msgs(backend, 1)
    backend.disconnect()
    backend.loop_stop()
    return bool(got) and got[0][1] == b"gone", f"will: {got}"


def refused(name, req, want, cert="devices/device-001"):
    def fn():
        w = Ws(cert, req)
        status, head = w.status, w.head
        eof = w.s.recv(100)
        w.close()
        ok = status.startswith(want) and "Connection: close" in head and eof == b""
        return ok, f"{status!r}, then {eof!r}"

    run(name, fn)


def violation(name, data, code):
    def fn():
        w = Ws("devices/device-001", request())
        w.send(frame(2, connect_pkt("device-001")))
        w.mqtt()
        w.send(data)
        f = w.recv_frame()
        eof = w.recv_frame()
        w.close()
        return f == (8, struct.pack(">H", code)) and eof is None, f"close {f!r}, then {eof!r}"

    run(name, fn)


def slowloris():
    s = tls_sock(WS, "devices/device-001")
    t0 = time.time()
    req = request()
    sent = 0
    closed_at = None
    try:
        for b in req:
            s.sendall(bytes([b]))
            sent += 1
            time.sleep(0.25)
            if time.time() - t0 > 10:
                break
    except OSError:
        closed_at = time.time() - t0
    if closed_at is None:
        try:
            s.settimeout(5)
            d = s.recv(100)
            closed_at = time.time() - t0 if d == b"" else None
        except (OSError, ssl.SSLError):
            closed_at = time.time() - t0
    s.close()
    # upgrade_timeout_s = 3, checked every 100 ms; the whole request would
    # have taken len(req) / 4 s.
    ok = closed_at is not None and closed_at < 6 and sent < len(req)
    return ok, f"cut after {closed_at and round(closed_at, 1)} s, {sent} of {len(req)} bytes sent"


def mtls_needs_a_certificate():
    try:
        w = Ws(None, request())
        w.mqtt()
        return False, f"answered {w.status!r} without a client certificate"
    except (OSError, ssl.SSLError) as e:
        return True, type(e).__name__


def idle_round(req):
    """Opens IDLE upgraded connections (no MQTT inside), holds them, reads the
    heap with them open, closes them; returns (sockets, failures, seconds,
    memory used with them)."""
    socks, errors = [], 0
    t0 = time.time()
    lock = threading.Lock()

    def opener(n):
        nonlocal errors
        for _ in range(n):
            for attempt in range(20):
                try:
                    w = Ws("devices/device-005", None, timeout=20)
                    w.send(req)
                    st = w.read_response()
                    if "101" not in st:
                        raise OSError(st)
                    with lock:
                        socks.append(w)
                    break
                except (OSError, ssl.SSLError):
                    time.sleep(0.2 * (attempt + 1))
            else:
                with lock:
                    errors += 1

    threads = [threading.Thread(target=opener, args=(IDLE // 16,)) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    opened = time.time() - t0
    # $SYS is refreshed every 10 s: wait for values taken with them open.
    time.sleep(11)
    during = sys_value("$SYS/broker/memory/used")
    conns = sys_value("$SYS/broker/websocket/connections")
    n = len(socks)
    for w in socks:
        w.close()
    return n, errors, opened, during, conns


def idle_connections():
    req = request()
    time.sleep(11)
    before = int(sys_value("$SYS/broker/memory/used") or -1)
    out = []
    for _ in range(2):
        n, errors, opened, during, conns = idle_round(req)
        # The service returns memory a peak left every 10 s; $SYS is refreshed
        # every 10 s.
        time.sleep(22)
        after = int(sys_value("$SYS/broker/memory/used") or -1)
        left = sys_value("$SYS/broker/websocket/connections")
        out.append((n, errors, opened, int(during or -1), conns, after, left))
    (n1, e1, o1, d1, c1, a1, l1), (n2, e2, o2, d2, c2, a2, l2) = out
    want = IDLE // 16 * 16
    per = (d1 - before) // max(n1, 1)
    # A leak grows with every round; what a peak leaves behind does not.
    ok = (
        n1 == n2 == want and e1 == e2 == 0 and int(c1 or 0) >= want and int(c2 or 0) >= want and l1 == l2 == "0"
        and min(before, d1, a1, d2, a2) >= 0 and a2 <= a1 + (512 << 10)
    )
    return ok, (
        f"two rounds of {want} upgraded idle connections (opened in {o1:.0f} s and {o2:.0f} s, {e1 + e2} failed, "
        f"$SYS connections {c1}/{c2}); memory used {before >> 10} KiB before, {d1 >> 10} KiB with them "
        f"({per} B each, TLS and WebSocket state and the broker's connection), {a1 >> 10} KiB after the first round, "
        f"{d2 >> 10} KiB with the second, {a2 >> 10} KiB after it; connections after {l1}/{l2}"
    )


def counters():
    # $SYS is refreshed every 10 s.
    time.sleep(11)
    names = ["upgrades", "refused/origin", "refused/protocol", "refused/version", "refused/path", "refused/timeout", "close/client/1000", "close/server/1002", "close/server/1003", "close/abrupt"]
    vals = {n: sys_value(f"$SYS/broker/websocket/{n}") for n in names}
    ok = all(v is not None and int(v) >= 1 for v in vals.values())
    return ok, " ".join(f"{k}={v}" for k, v in vals.items())


# ---- password mode -----------------------------------------------------------


def password_pubsub():
    web = paho_client("page-1", user="web-1", password="web-secret")
    rc = connect(web, WS)
    if rc != 0:
        return False, f"connack {rc}"
    r = web.subscribe([("devices/+/t", 0), ("web/web-1/#", 1)])
    time.sleep(0.5)
    dev = paho_client("device-001", cert="devices/device-001", ws=False)
    connect(dev, TLS)
    dev.publish("devices/device-001/t", b"from a device", qos=0)
    web.publish("web/web-1/echo", b"to myself", qos=1).wait_for_publish(5)
    got = wait_msgs(web, 2)
    for c in (dev, web):
        c.disconnect()
        c.loop_stop()
    payloads = sorted(p for _, p, _ in got)
    return payloads == [b"from a device", b"to myself"], f"got {got} (sub {r})"


def password_refusals():
    out = []
    w = Ws(None, request())
    w.send(frame(2, connect_pkt("p", user="web-1", password="wrong")))
    ack = w.mqtt()
    close = w.recv_frame()
    w.close()
    out.append(ack == b"\x20\x02\x00\x04" and close == (8, struct.pack(">H", 1008)))
    # A good login: the same user, then the ACL.
    w = Ws(None, request())
    w.send(frame(2, connect_pkt("p", user="web-1", password="web-secret")))
    ok_ack = w.mqtt()
    sub = pkt(0x82, struct.pack(">H", 7) + mstr("$SYS/#") + b"\x00" + mstr("devices/device-001/cmd/#") + b"\x00" + mstr("web/web-1/x") + b"\x00")
    w.send(frame(2, sub))
    suback = w.mqtt()
    w.send(frame(2, b"\xe0\x00") + frame(8, struct.pack(">H", 1000)))
    w.close()
    out.append(ok_ack == b"\x20\x02\x00\x00" and suback == b"\x90\x05\x00\x07\x80\x80\x00")
    # A stored session is not offered.
    w = Ws(None, request())
    w.send(frame(2, connect_pkt("p", user="web-1", password="web-secret", clean=False)))
    stored = w.mqtt()
    w.close()
    out.append(stored == b"\x20\x02\x00\x05")
    return all(out), f"wrong password {ack!r}/{close!r}, login {ok_ack!r}, suback {suback!r}, stored session {stored!r}"


def connect5_pkt(client_id, user, password, expiry):
    props = b"\x11" + struct.pack(">I", expiry)
    body = mstr("MQTT") + bytes([5, 0xC2]) + struct.pack(">H", 60) + varlen(len(props)) + props
    return pkt(0x10, body + mstr(client_id) + mstr(user) + mstr(password))


def password_mqtt5():
    """A 5.0 login (ADR-274): a wrong password gets a 5.0 CONNACK 0x86; a good
    one asking for a stored session is granted Session Expiry 0 and told so;
    the section's ACL answers SUBACK 0x87. After the lock-out of `lockout`
    has run out."""
    time.sleep(9)
    w = Ws(None, request())
    w.send(frame(2, connect5_pkt("p5", "web-1", "wrong", 0)))
    bad = w.mqtt()
    w.close()
    w = Ws(None, request())
    w.send(frame(2, connect5_pkt("p5", "web-1", "web-secret", 3600)))
    ok = w.mqtt()
    sub = pkt(0x82, struct.pack(">H", 7) + b"\x00" + mstr("$SYS/#") + b"\x00" + mstr("web/web-1/x") + b"\x01")
    w.send(frame(2, sub))
    suback = w.mqtt()
    w.send(frame(2, b"\xe0\x00") + frame(8, struct.pack(">H", 1000)))
    w.close()
    good = isinstance(ok, bytes) and ok[:4] == b"\x20" + bytes([len(ok) - 2]) + b"\x00\x00" \
        and b"\x11\x00\x00\x00\x00" in ok
    return (bad == b"\x20\x03\x00\x86\x00" and good and suback == b"\x90\x05\x00\x07\x00\x87\x01",
            f"wrong {bad!r}, login {ok!r}, suback {suback!r}")


def password_without_origin_header():
    # A non-browser client sends no Origin: allowed (it cannot be a
    # cross-site request); a browser's wrong Origin is refused.
    w = Ws(None, request(origin=None))
    st = w.status
    w.close()
    w2 = Ws(None, request(origin="https://evil.example.com"))
    st2 = w2.status
    w2.close()
    return "101" in st and "403" in st2, f"{st!r} / {st2!r}"


def lockout():
    # The wrong password of `password_refusals` a moment ago still counts (a
    # success does not clear the failures, ADR-363): the third failure in the
    # window locks, whichever attempt that is, and a connection after it gets
    # no answer.
    for _ in range(3):
        try:
            w = Ws(None, request(), timeout=3)
        except (OSError, ssl.SSLError):
            break
        w.send(frame(2, connect_pkt("p", user="web-1", password="wrong")))
        w.mqtt()
        w.close()
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", WS), timeout=3)
        s.settimeout(3)
        tls_ctx().wrap_socket(s, server_hostname="localhost")
        locked = False
    except (OSError, ssl.SSLError):
        locked = True
    time.sleep(max(0, 9 - (time.time() - t0)))
    w = Ws(None, request())
    w.send(frame(2, connect_pkt("p", user="web-1", password="web-secret")))
    back = w.mqtt()
    w.close()
    return locked and back == b"\x20\x02\x00\x00", f"locked out: {locked}, after 9 s: {back!r}"


if MODE == "mtls":
    run("wss-mtls-pubsub-qos0-qos1", mtls_pubsub)
    run("wss-mtls-mqtt5-properties-forwarded", mtls_mqtt5)
    run("wss-max-packet-size", mtls_large)
    run("wss-fragmented-message-and-ping", mtls_fragmented)
    run("wss-abrupt-close-publishes-the-will", abrupt_close)
    refused("wss-wrong-origin-403", request(origin="https://evil.example.com"), "HTTP/1.1 403")
    refused("wss-wrong-subprotocol-400", request(proto="chat"), "HTTP/1.1 400")
    refused("wss-wrong-version-426", request(version="8"), "HTTP/1.1 426")
    refused("wss-wrong-path-404", request(path="/"), "HTTP/1.1 404")
    refused("wss-request-with-a-body-400", request(extra="Content-Length: 5\r\n"), "HTTP/1.1 400")
    violation("wss-text-frame-1003", frame(1, b"text"), 1003)
    violation("wss-unmasked-frame-1002", frame(2, b"\xc0\x00", masked=False), 1002)
    violation("wss-reserved-bit-1002", bytes([0xC2]) + frame(2, b"\xc0\x00")[1:], 1002)
    run("wss-slowloris-upgrade-cut-at-the-deadline", slowloris)
    run("wss-mtls-needs-a-client-certificate", mtls_needs_a_certificate)
    if IDLE > 0:
        run(f"wss-{IDLE}-idle-connections-no-leak", idle_connections)
    run("wss-operator-reads-the-websocket-counters", counters)
elif MODE == "password":
    run("wss-password-pubsub-with-a-device", password_pubsub)
    run("wss-password-refusals-acl-and-clean-session", password_refusals)
    run("wss-origin-header-optional-but-checked", password_without_origin_header)
    run("wss-password-lockout", lockout)
    run("wss-password-mqtt5-login-codes-and-acl", password_mqtt5)
else:
    sys.exit(f"unknown mode {MODE}")
sys.exit(0 if all(results) else 1)
