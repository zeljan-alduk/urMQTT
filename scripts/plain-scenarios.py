#!/usr/bin/env python3
"""Plaintext MQTT scenarios (P1, ADR-229, ADR-230) against a booted dev VM.

    scripts/plain-scenarios.py MODE PLAIN_PORT TLS_PORT CERTDIR

MODE says which image the VM runs (scripts/smoke.sh, group `plaintext`, builds
them from the dev configuration plus a [plaintext] section; QEMU user
networking makes every client appear as 10.0.2.2, so a refused address is
refused by the allow-list of the image, not by the client):

  password   accounts sensor-1 and sensor-2, 10.0.2.0/24 allowed, a high
             failure limit (so that each refusal can be tried on its own)
  lockout    3 failed logins lock the address out for 10 s
  refused    the allow-list does not contain 10.0.2.2
  anonymous  no login, identity "lan", topics under home/
  ip         the address decides: 10.0.2.2 is "gateway"
  limits     3 connections per address
  registry   registry.mode = allowlist: the plaintext identity needs the allowlist

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed. Needs the mosquitto clients for the "default client"
scenarios (the real tools people point at 1883).
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

MODE, PLAIN, TLS, DIR = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
results = []
S1, S2 = ("sensor-1", "alpha-secret"), ("sensor-2", "beta-secret")


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


# ---- a small MQTT 3.1.1 client (raw, so that every byte is ours) --------------


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


def connect_pkt(client_id, user=None, password=None, clean=True, keepalive=60, level=4, will=None):
    flags = (0x02 if clean else 0) | (0x80 if user is not None else 0) | (0x40 if password is not None else 0)
    body = mstr("MQTT") + bytes([level, flags]) + struct.pack(">H", keepalive)
    if level == 5:
        # MQTT 5.0: a Session Expiry Interval of an hour (a plaintext session
        # is granted 0), so the property block is not empty.
        body += b"\x05\x11" + struct.pack(">I", 3600)
    body += mstr(client_id)
    if user is not None:
        body += mstr(user)
    if password is not None:
        body += mstr(password)
    return pkt(0x10, body)


class Conn:
    def __init__(self, port, tls=None, timeout=5):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        if tls:
            cert = os.path.join(DIR, tls)
            ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
            ctx.check_hostname = False
            ctx.load_cert_chain(cert + ".pem", cert + ".key")
            self.s = ctx.wrap_socket(self.s)
        self.buf = b""
        self.closed = False

    def send(self, b):
        try:
            self.s.sendall(b)
        except OSError:
            self.closed = True

    def read(self, wait=3.0):
        """The next packet as (type, flags, body); None on silence; "EOF" if closed."""
        end = time.time() + wait
        while True:
            if len(self.buf) >= 2:
                n, mult, i = 0, 1, 1
                while i < len(self.buf):
                    n += (self.buf[i] & 127) * mult
                    mult *= 128
                    i += 1
                    if not self.buf[i - 1] & 128:
                        break
                else:
                    i = None
                if i is not None and len(self.buf) >= i + n:
                    first, body = self.buf[0], self.buf[i : i + n]
                    self.buf = self.buf[i + n :]
                    return first >> 4, first & 15, body
            left = end - time.time()
            if left <= 0:
                return "EOF" if self.closed else None
            self.s.settimeout(left)
            try:
                d = self.s.recv(65536)
            except (socket.timeout, ssl.SSLError):
                return "EOF" if self.closed else None
            except OSError:
                self.closed = True
                return "EOF"
            if not d:
                self.closed = True
                return "EOF"
            self.buf += d

    def connect(self, client_id, *a, wait=3.0, **kw):
        """Sends CONNECT; returns the CONNACK return code, or None (silence), or "EOF"."""
        self.send(connect_pkt(client_id, *a, **kw))
        p = self.read(wait)
        if p is None or p == "EOF":
            return p
        return p[2][1] if p[0] == 2 else f"unexpected {p[0]}"

    def subscribe(self, filters, pid=1):
        body = struct.pack(">H", pid) + b"".join(mstr(f) + bytes([q]) for f, q in filters)
        self.send(pkt(0x82, body))
        p = self.read(3)
        return list(p[2][2:]) if p and p != "EOF" and p[0] == 9 else None

    def publish(self, topic, payload=b"x", qos=0, retain=False, pid=7):
        body = mstr(topic) + (struct.pack(">H", pid) if qos else b"") + payload
        self.send(pkt(0x30 | (qos << 1) | (1 if retain else 0), body))
        if qos:
            p = self.read(3)
            return p is not None and p != "EOF" and p[0] == 4
        return True

    def messages(self, wait):
        """All PUBLISH messages arriving within `wait` seconds: [(topic, payload, flags)]."""
        out, end = [], time.time() + wait
        while time.time() < end:
            p = self.read(max(0.05, end - time.time()))
            if p is None or p == "EOF":
                break
            if p[0] == 3:
                n = struct.unpack(">H", p[2][:2])[0]
                out.append((p[2][2 : 2 + n].decode(), p[2][2 + n + (2 if (p[1] >> 1) & 3 else 0) :], p[1]))
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def plain(client_id, user=None, password=None, **kw):
    c = Conn(PLAIN)
    code = c.connect(client_id, user, password, **kw)
    return c, code


def login(account, client_id="c1", **kw):
    return plain(client_id, account[0], account[1], **kw)


def backend():
    """The TLS service identity that sees what the plaintext clients publish."""
    c = Conn(TLS, tls="services/backend")
    assert c.connect("backend") == 0
    assert c.subscribe([("devices/#", 0)]) == [0]
    return c


def mosq(tool, *args, timeout=15):
    r = subprocess.run([tool, "-h", "127.0.0.1", "-V", "mqttv311", *args], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


# ---- scenarios -----------------------------------------------------------------


def password_mode():
    bk = backend()
    # A default client, the way people use them: a random client id, a user and a password.
    rc, out = mosq("mosquitto_pub", "-p", str(PLAIN), "-u", S1[0], "-P", S1[1], "-t", "devices/sensor-1/telemetry/t", "-m", "21", "-q", "1")
    got = bk.messages(3)
    report("default-client-publishes", rc == 0 and ("devices/sensor-1/telemetry/t", b"21") == got[0][:2] if got else False, f"rc={rc} {out!r} {got}")

    # The other direction: a plaintext subscriber gets a command a TLS service sends.
    sub = subprocess.Popen(["mosquitto_sub", "-h", "127.0.0.1", "-p", str(PLAIN), "-V", "mqttv311", "-u", S1[0], "-P", S1[1],
                            "-t", "devices/sensor-1/cmd/#", "-C", "1", "-W", "12"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)
    bk.publish("devices/sensor-1/cmd/reboot", b"now", qos=1)
    bk.messages(1)  # the backend hears its own command, too (it subscribes to devices/#)
    try:
        out, err = sub.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        sub.kill()
        out, err = sub.communicate()
    report("default-client-receives-a-command", out.strip() == "now", f"{out.strip()!r} {err.strip()!r}")

    # Refusals: always CONNACK 4, whatever the reason, and the connection closes.
    for name, args in [("wrong-password", ("sensor-1", "nope")), ("unknown-user", ("ghost", "alpha-secret")),
                       ("no-credentials", (None, None)), ("user-without-password", ("sensor-1", None)),
                       ("right-password-wrong-user", ("sensor-2", "alpha-secret"))]:
        c, code = plain("c-" + name, *args)
        again = c.read(2)
        report(f"login-refused-{name}", code == 4 and again in ("EOF", None), f"CONNACK {code}")
        c.close()

    # A stored session is not available; an MQTT 5 client is told so.
    c, code = login(S1, "stored", clean=False)
    report("stored-session-refused", code == 5, f"CONNACK {code}")
    c.close()
    # MQTT 5.0 (ADR-274): served on this listener too; a stored session is not
    # refused but granted Session Expiry 0 (told in the CONNACK).
    c, code = plain("v5", S1[0], S1[1], level=5, clean=False)
    report("mqtt5-client-logs-in-without-a-stored-session", code == 0, f"CONNACK reason {code}")
    c.close()
    c, code = plain("v5", S1[0], "wrong", level=5)
    report("mqtt5-wrong-password-0x86", code == 0x86, f"CONNACK reason {code}")
    c.close()
    # A client id is free (mosquitto's default one has a slash), but there must be one.
    c, code = login(S1, "mosqpub/4711-host")
    report("client-id-with-a-slash-is-fine", code == 0, f"CONNACK {code}")
    c.close()
    # None at all (what the mosquitto tools send): a clean session is named by the
    # broker; a stored one without an id is an identifier it cannot accept.
    c, code = login(S1, "")
    report("empty-client-id-is-named-by-the-broker", code == 0, f"CONNACK {code}")
    c.close()
    c, code = login(S1, "", clean=False)
    report("empty-client-id-with-a-stored-session-refused", code == 2, f"CONNACK {code}")
    c.close()

    # The ACL is the login's: the device may publish to its own topics only.
    c, code = login(S1, "acl")
    assert code == 0, code
    c.publish("devices/sensor-2/telemetry/t", b"stolen", qos=1)
    c.publish("fleet/everyone", b"x", qos=1)
    c.publish("devices/sensor-1/telemetry/own", b"mine", qos=1)
    got = [m[:2] for m in bk.messages(3)]
    report("acl-publish-only-own-topics", got == [("devices/sensor-1/telemetry/own", b"mine")], f"{got}")
    codes = c.subscribe([("devices/sensor-1/cmd/#", 1), ("devices/sensor-2/cmd/#", 1), ("devices/+/cmd/#", 0), ("#", 0)])
    report("acl-subscribe-only-own-commands", codes == [1, 0x80, 0x80, 0x80], f"{codes}")
    codes = c.subscribe([("$SYS/#", 0), ("$SYS/broker/plaintext/enabled", 0), ("$urmqtt/#", 0)], pid=2)
    report("no-sys-subscribe", codes == [0x80, 0x80, 0x80], f"{codes}")
    c.publish("$SYS/console/in", b"reboot", qos=1)
    c.publish("$SYS/query/info", b"", qos=1)
    c.publish("$urmqtt/control", b"forged control message", qos=1)
    time.sleep(1)
    c.close()

    # Retained messages are delivered but not kept (plaintext.retain = false).
    c, _ = login(S1, "ret")
    c.publish("devices/sensor-1/state", b"on", qos=1, retain=True)
    c.close()
    bk.messages(1)  # delivered live to the backend
    c2, _ = login(S1, "ret2")
    c2.subscribe([("devices/sensor-1/cmd/#", 0)])
    kept = c2.messages(1.5)
    report("retained-publish-not-retained", kept == [], f"{kept}")
    c2.close()

    # The packet limit is the image's (256 bytes here); a TLS client has 4096.
    c, _ = login(S1, "big")
    c.publish("devices/sensor-1/telemetry/t", b"x" * 400)
    p = c.read(2)
    report("packet-limit", p == "EOF", f"{p!r}")
    c.close()

    # One identity, several clients with their own ids; the same id takes over.
    a, ca = login(S1, "dev-a")
    b, cb = login(S1, "dev-b")
    ok_two = ca == 0 and cb == 0
    a.publish("devices/sensor-1/telemetry/a", b"1")
    b.publish("devices/sensor-1/telemetry/b", b"2")
    seen = sorted(m[0] for m in bk.messages(2))
    a2, ca2 = login(S1, "dev-a")
    taken = a.read(2)
    report("one-login-many-client-ids", ok_two and seen == ["devices/sensor-1/telemetry/a", "devices/sensor-1/telemetry/b"] and ca2 == 0
           and taken == "EOF", f"{ca} {cb} {seen} {ca2} {taken!r}")
    for x in (a, b, a2):
        x.close()

    # A plaintext client named like a TLS device does not meet it: the TLS
    # device "backend" stays connected when plaintext client id "backend" comes.
    c, code = login(S1, "backend")
    report("plaintext-client-id-cannot-take-over-a-tls-session", code == 0 and bk.read(1) is None, f"CONNACK {code}")
    c.close()

    # The publish rate (5/s here): a burst of 40 is cut to about a second's worth.
    c, _ = login(S1, "rate")
    for i in range(40):
        c.publish("devices/sensor-1/telemetry/rate", str(i).encode())
    n = len(bk.messages(2))
    report("publish-rate-limited", 0 < n <= 15, f"{n} of 40 delivered")
    c.close()
    bk.close()

    # The operator, over TLS, reads what the listener reports.
    op = Conn(TLS, tls="services/operator")
    op.connect("operator")
    op.subscribe([("$SYS/broker/plaintext/#", 0)])
    # The numbers are refreshed every 10 s: keep reading until they have caught up.
    topics, end = {}, time.time() + 14
    while time.time() < end:
        for t, v, _f in op.messages(2):
            topics[t] = v.decode()
        if int(topics.get("$SYS/broker/plaintext/auth_failed", "0")) >= 5 and int(topics.get("$SYS/broker/plaintext/accepted", "0")) >= 10:
            break
    op.close()
    need = {"enabled": "true", "port": "1883", "auth": "password", "allow_from": "10.0.2.0/24", "accounts": "2"}
    ok = all(topics.get(f"$SYS/broker/plaintext/{k}") == v for k, v in need.items())
    fails = int(topics.get("$SYS/broker/plaintext/auth_failed", "0"))
    accepted = int(topics.get("$SYS/broker/plaintext/accepted", "0"))
    report("operator-reads-the-plaintext-counters", ok and fails >= 5 and accepted >= 10, f"{topics}")


def lockout_mode():
    # Two failures, a success, two failures: the success clears the count.
    for pw in ("bad1", "bad2"):
        c, code = login((S1[0], pw))
        assert code == 4, code
        c.close()
    c, code = login(S1)
    report("success-clears-the-failures", code == 0, f"CONNACK {code}")
    c.close()
    for pw in ("bad3", "bad4"):
        c, code = login((S1[0], pw))
        assert code == 4, code
        c.close()
    c, code = login(S1)
    report("two-failures-after-a-success-do-not-lock", code == 0, f"CONNACK {code}")
    c.close()
    # Three in a row lock the address out: the next attempt, even with the right
    # password, gets no answer at all (the SYN is dropped, so there is no CONNACK).
    for pw in ("bad5", "bad6", "bad7"):
        c, code = login((S1[0], pw))
        assert code == 4, code
        c.close()
    t0 = time.time()
    c, code = login(S1, wait=2.5)
    report("locked-out-address-gets-no-answer", code is None, f"{code!r}")
    c.close()
    # TLS is not affected by it.
    t = Conn(TLS, tls="devices/device-001")
    report("tls-is-not-locked-out", t.connect("device-001") == 0)
    t.close()
    # After the lock-out (6 s) the right password works again.
    time.sleep(max(0, 11 - (time.time() - t0)))
    c, code = login(S1)
    report("login-works-again-after-the-lockout", code == 0, f"CONNACK {code}")
    c.close()


def refused_mode():
    c, code = login(S1, wait=3)
    report("refused-source-gets-no-answer", code is None, f"{code!r}")
    c.close()
    t = Conn(TLS, tls="devices/device-001")
    report("tls-works-beside-a-refused-plaintext-source", t.connect("device-001") == 0)
    t.close()


def anonymous_mode():
    # The default clients of Tasmota, ESPHome, Home Assistant and mosquitto: no login.
    sub = subprocess.Popen(["mosquitto_sub", "-h", "127.0.0.1", "-p", str(PLAIN), "-V", "mqttv311", "-t", "home/#", "-C", "1", "-W", "12"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)
    rc, out = mosq("mosquitto_pub", "-p", str(PLAIN), "-t", "home/lights/kitchen", "-m", "on", "-q", "1")
    try:
        got, err = sub.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        sub.kill()
        got, err = sub.communicate()
    report("anonymous-default-clients", rc == 0 and got.strip() == "on", f"rc={rc} {out!r} {got.strip()!r} {err.strip()!r}")
    c, code = plain("anon", None, None)
    report("anonymous-needs-no-login", code == 0, f"CONNACK {code}")
    c.publish("devices/lan/x", b"outside the ACL", qos=1)
    codes = c.subscribe([("home/#", 0), ("devices/#", 0), ("$SYS/#", 0)])
    report("anonymous-acl", codes == [0, 0x80, 0x80], f"{codes}")
    c.close()
    c, code = plain("anon2", "someone", "anything")
    report("anonymous-ignores-credentials", code == 0, f"CONNACK {code}")
    c.close()


def plainonly_mode():
    # TLS is off (network.mqtt_tls_port = 0, ADR-233): the plaintext listener works for an allowed source ...
    anonymous_mode()
    # ... and nothing answers a TLS client on the TLS port: the connection is reset or closed, no handshake.
    try:
        c = Conn(TLS, tls="devices/device-001", timeout=6)
        ok = c.connect("device-001") != 0
        c.close()
    except (OSError, ssl.SSLError, AssertionError, TypeError, ValueError, TimeoutError):
        ok = True
    report("no-tls-listener", ok, "a TLS client got in" if not ok else "")


def ip_mode():
    bk = backend()
    c, code = plain("whatever")
    report("ip-mode-needs-no-login", code == 0, f"CONNACK {code}")
    c.publish("devices/gateway/telemetry/t", b"from the gateway", qos=1)
    c.publish("devices/sensor-1/telemetry/t", b"not mine", qos=1)
    got = [m[:2] for m in bk.messages(3)]
    report("ip-mode-identity-is-the-networks", got == [("devices/gateway/telemetry/t", b"from the gateway")], f"{got}")
    c.close()
    bk.close()


def limits_mode():
    conns = []
    for i in range(3):
        c, code = login(S1, f"l{i}")
        conns.append((c, code))
    ok3 = all(code == 0 for _, code in conns)
    c4, code4 = login(S1, "l3", wait=2.5)
    report("per-address-connection-limit", ok3 and code4 is None, f"{[x[1] for x in conns]} then {code4!r}")
    c4.close()
    conns[0][0].close()
    time.sleep(1.5)
    c5, code5 = login(S1, "l4")
    report("a-closed-connection-makes-room", code5 == 0, f"CONNACK {code5}")
    c5.close()
    for c, _ in conns:
        c.close()


def registry_mode():
    c, code = login(S1)
    report("not-on-the-allowlist-refused", code == 5, f"CONNACK {code}")
    c.close()


MODES = {
    "password": password_mode, "lockout": lockout_mode, "refused": refused_mode, "anonymous": anonymous_mode,
    "ip": ip_mode, "limits": limits_mode, "registry": registry_mode, "plainonly": plainonly_mode,
}
try:
    MODES[MODE]()
except Exception as e:  # a broken scenario is a failure, with the reason
    report(f"{MODE}-scenarios-ran", False, repr(e))
sys.exit(0 if results and all(results) else 1)
