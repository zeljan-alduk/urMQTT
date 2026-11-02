#!/usr/bin/env python3
"""Acceptance scenarios of the public demo broker (D1) against a booted demo image.

    scripts/demo-scenarios.py TLS_PORT PLAIN_PORT PKIDIR

PKIDIR is deploy/demo/pki (scripts/demo-certs.sh). The VM runs the image made by scripts/demo-pack.sh
(scripts/demo-smoke.sh boots it under QEMU). Clients are raw sockets, so every byte is ours; the TLS ones use
the demo certificates the way a visitor would (server-ca.pem for the broker, a downloaded client pair). QEMU's
user networking makes the host appear as 10.0.2.2, so the image must have been packed with --bridge 10.0.2.0/24.
Hostname checking is off (the connection goes to 127.0.0.1; the certificate names demo-mqtt.aldo.tech); the chain
is verified.

Prints one "client: <scenario> ok|FAILED ..." line per scenario; exits non-zero if any failed.
"""
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

TLS_PORT, PLAIN_PORT, PKI = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


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


class Conn:
    def __init__(self, port, cert=None, cafile="server-ca.pem", certdir=None):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        if cert is not None:
            ctx = ssl.create_default_context(cafile=os.path.join(PKI, cafile))
            ctx.check_hostname = False
            base = os.path.join(certdir or os.path.join(PKI, "clients"), cert)
            ctx.load_cert_chain(base + ".pem", base + ".key")
            s = ctx.wrap_socket(s)
        self.s, self.buf, self.closed = s, b"", False

    def send(self, b):
        try:
            self.s.sendall(b)
        except OSError:
            self.closed = True

    def read(self, wait=3.0):
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

    def connect(self, client_id, clean=True, user=None):
        flags = (0x02 if clean else 0) | (0x80 if user else 0)
        body = mstr("MQTT") + bytes([4, flags]) + struct.pack(">H", 60) + mstr(client_id) + (mstr(user) if user else b"")
        self.send(pkt(0x10, body))
        p = self.read(5)
        if p is None or p == "EOF":
            return p
        return p[2][1] if p[0] == 2 else f"unexpected {p[0]}"

    def subscribe(self, filters, pid=1):
        self.send(pkt(0x82, struct.pack(">H", pid) + b"".join(mstr(f) + bytes([q]) for f, q in filters)))
        p = self.read(3)
        return list(p[2][2:]) if p and p != "EOF" and p[0] == 9 else None

    def publish(self, topic, payload=b"x", qos=0, retain=False, pid=7):
        self.send(pkt(0x30 | (qos << 1) | (1 if retain else 0), mstr(topic) + (struct.pack(">H", pid) if qos else b"") + payload))
        if qos:
            p = self.read(3)
            return p is not None and p != "EOF" and p[0] == 4
        return True

    def messages(self, wait):
        out, end = [], time.time() + wait
        while time.time() < end:
            p = self.read(max(0.05, end - time.time()))
            if p is None or p == "EOF":
                break
            if p[0] == 3:
                n = struct.unpack(">H", p[2][:2])[0]
                out.append((p[2][2 : 2 + n].decode(), p[2][2 + n + (2 if (p[1] >> 1) & 3 else 0) :]))
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def tls(cid, cert=None, **kw):
    """A TLS connection with the client certificate of `cid` (or `cert`) and its CONNECT; returns (conn, code)."""
    try:
        c = Conn(TLS_PORT, cert or cid, **kw)
    except (ssl.SSLError, OSError) as e:
        return None, f"tls-refused: {e}"
    return c, c.connect(cid)


def plain(cid, **kw):
    c = Conn(PLAIN_PORT)
    return c, c.connect(cid, **kw)


# 1. The documented use: a demo certificate publishes and subscribes under demo/<id>/#.
a, code = tls("demo-001")
ok = code == 0 and a.subscribe([("demo/demo-001/#", 1)]) == [1]
a.publish("demo/demo-001/hello", b"hi", qos=1)
got = a.messages(2)
report("tls-own-topic-roundtrip", ok and got == [("demo/demo-001/hello", b"hi")], f"{code} {got}")

# 2. Publishing to another id's topics is dropped (nothing arrives), and subscribing there, to `#`, to $SYS, to $urmqtt is refused.
b, code2 = tls("demo-002")
b.subscribe([("demo/demo-002/#", 0)])
a.publish("demo/demo-002/x", b"intruder", qos=1)
a.publish("fleet/everyone", b"x", qos=1)
report("tls-publish-to-another-id-dropped", code2 == 0 and b.messages(2) == [], "")
# (the demo allows 4 subscriptions per session, so the refusals are asked in two packets)
codes = (a.subscribe([("demo/demo-002/#", 0), ("demo/+/x", 0), ("#", 0)], pid=2) or []) + (a.subscribe([("$SYS/#", 0), ("$urmqtt/#", 0), ("devices/#", 0), ("fleet/#", 0)], pid=3) or [])
report("tls-subscribe-elsewhere-refused", codes == [0x80] * 7, f"{codes}")
a.close()
b.close()

# 3. A certificate is checked against the client id: demo-002's certificate with the client id demo-001 is refused.
c, code = tls("demo-001", cert="demo-002")
report("tls-client-id-must-match-the-certificate", code not in (0, None) or (c is not None and c.read(2) == "EOF"), f"{code}")
if c:
    c.close()

# 4. The client CA is public, the broker CA is not: a client that trusts only ca.pem does not accept the broker.
_, code = tls("demo-001", cafile="ca.pem")
report("tls-broker-is-not-signed-by-the-public-ca", isinstance(code, str) and code.startswith("tls-refused"), f"{code}")

# 5. Anyone can mint a certificate with the published CA key (that is the point of the toy) -- and gets nothing
#    beyond demo/<its id>/#, whatever name it claims: not an operator, not a service, not the control channel.
tmp = tempfile.mkdtemp(prefix="demo-minted-")
try:
    for name in ("operator", "backend", "web-x"):
        subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{tmp}/{name}.key",
                        "-subj", f"/CN={name}", "-out", f"{tmp}/{name}.csr"], check=True, capture_output=True)
        with open(f"{tmp}/ext", "w") as fh:
            fh.write("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n")
        subprocess.run(["openssl", "x509", "-req", "-in", f"{tmp}/{name}.csr", "-CA", f"{PKI}/ca.pem", "-CAkey", f"{PKI}/ca.key", "-CAserial", f"{tmp}/serial", "-CAcreateserial",
                        "-days", "30", "-extfile", f"{tmp}/ext", "-out", f"{tmp}/{name}.pem"], check=True, capture_output=True)
    m, code = tls("operator", certdir=tmp)
    ok = code == 0
    codes = m.subscribe([("$SYS/#", 0), ("$urmqtt/#", 0), ("devices/#", 0), ("demo/#", 0)]) if ok else None
    codes = (codes or []) + (m.subscribe([("demo/operator/#", 0)], pid=2) or []) if ok else None
    m.publish("$urmqtt/control", b"forged", qos=1) if ok else None
    report("minted-operator-certificate-has-no-operator-rights", ok and codes == [0x80, 0x80, 0x80, 0x80, 0], f"{code} {codes}")
    if m:
        m.close()
    m, code = tls("backend", certdir=tmp)
    codes = m.subscribe([("devices/#", 0), ("fleet/#", 0), ("demo/backend/x", 0)]) if code == 0 else None
    report("minted-backend-certificate-has-no-service-rights", codes == [0x80, 0x80, 0], f"{code} {codes}")
    if m:
        m.close()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# 6. Retained messages are never kept (limits.max_retained_per_device = 0): delivered live, not to a later subscriber.
live, _ = tls("demo-003")
live.subscribe([("demo/demo-003/#", 0)])
a, _ = tls("demo-004")
a.publish("demo/demo-004/r", b"kept?", qos=1, retain=True)
late, _ = tls("demo-004")
late.subscribe([("demo/demo-004/#", 0)])
report("tls-retained-not-kept", late.messages(2) == [], "")
a.close()
late.close()
live.close()

# 7. The browser page's identity: the plaintext bridge client is "web", and the "web" demo certificate sees the same topics.
w, code = tls("web")
w.subscribe([("demo/web/#", 0)])
p, pcode = plain("browser-1")
p.publish("demo/web/room1", b"from the page", qos=0)
got = w.messages(3)
report("plaintext-web-and-tls-web-share-demo-web", code == 0 and pcode == 0 and got == [("demo/web/room1", b"from the page")], f"{pcode} {got}")
p.close()
w.close()

# 8. Plaintext, anonymous (no user name needed), narrowest role.
p, code = plain("browser-2")
report("plaintext-anonymous-connect", code == 0, f"{code}")
codes = (p.subscribe([("demo/web/#", 0), ("demo/web/a/+/b", 1), ("demo/demo-001/#", 0), ("#", 0)]) or []) + (p.subscribe([("$SYS/#", 0), ("$urmqtt/#", 0), ("devices/#", 0)], pid=2) or [])
report("plaintext-subscribe-only-demo-web", codes == [0, 1, 0x80, 0x80, 0x80, 0x80, 0x80], f"{codes}")
p.publish("$urmqtt/control", b"forged control message", qos=1)
p.publish("$SYS/console/in", b"reboot", qos=1)
q, _ = plain("browser-3")
q.subscribe([("demo/web/#", 0)])
p.publish("demo/demo-001/x", b"not mine", qos=1)
p.publish("demo/web/ok", b"mine", qos=1)
got = q.messages(2)
report("plaintext-publish-only-demo-web", got == [("demo/web/ok", b"mine")], f"{got}")
p.close()
q.close()

# 9. Plaintext: no retained messages, no stored sessions, packets over 1024 bytes end the connection.
p, _ = plain("browser-4")
p.publish("demo/web/ret", b"x", qos=1, retain=True)
p.close()
q, _ = plain("browser-5")
q.subscribe([("demo/web/#", 0)])
report("plaintext-retained-not-kept", q.messages(2) == [], "")
q.close()
c = Conn(PLAIN_PORT)
report("plaintext-stored-session-refused", c.connect("browser-6", clean=False) == 5, "")
c.close()
p, _ = plain("browser-7")
p.publish("demo/web/big", b"x" * 1200, qos=0)
tail = p.read(3)
report("plaintext-packet-over-1024-bytes-closes-the-connection", tail == "EOF" or p.closed, f"{tail}")
p.close()

# 10. The TLS port still works while the plaintext port is busy, and a publish flood is limited (5/s per session).
p, _ = plain("flood")
p.subscribe([("demo/web/#", 0)])
for i in range(40):
    p.publish(f"demo/web/f{i}", b"y", qos=0)
n = len(p.messages(2))
report("plaintext-publish-rate-limited", 0 < n < 30, f"{n} of 40 delivered")
p.close()

# 11. The real tools, as the download's README shows them (mosquitto 2.x; --insecure only skips the host name check
#     because the test connects to 127.0.0.1; the chain is verified against server-ca.pem).
if shutil.which("mosquitto_pub") and shutil.which("mosquitto_sub"):
    def mosq(tool, cid, *args):
        base = os.path.join(PKI, "clients", cid)
        return [tool, "-h", "127.0.0.1", "-p", str(TLS_PORT), "-V", "mqttv311", "--cafile", os.path.join(PKI, "server-ca.pem"),
                "--insecure", "--cert", base + ".pem", "--key", base + ".key", "-i", cid, *args]
    # One connection per certificate at a time: a second one with the same client id takes the first over. So the
    # subscriber is the TLS client "web" and the publisher the default mosquitto_pub on the plaintext port (anonymous).
    sub = subprocess.Popen(mosq("mosquitto_sub", "web", "-t", "demo/web/#", "-C", "1", "-W", "15", "-v"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(4)  # a TLS handshake under emulation can take a while
    r = subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", str(PLAIN_PORT), "-V", "mqttv311", "-t", "demo/web/hello", "-m", "hi", "-q", "1"],
                       capture_output=True, text=True, timeout=15)
    out, err = sub.communicate(timeout=20)
    report("mosquitto-clients-tls-sub-plaintext-pub", r.returncode == 0 and out.strip() == "demo/web/hello hi", f"{out.strip()!r} {err.strip()} {r.stderr.strip()}")
    r = subprocess.run(mosq("mosquitto_sub", "demo-010", "-t", "demo/demo-011/#", "-E"), capture_output=True, text=True, timeout=15)
    report("mosquitto-subscribe-to-another-id-denied", "denied" in (r.stdout + r.stderr).lower() or "128" in (r.stdout + r.stderr), (r.stdout + r.stderr).strip())
else:
    report("mosquitto-clients-tls-sub-plaintext-pub", False, "the mosquitto clients are not installed")

sys.exit(0 if all(results) else 1)
