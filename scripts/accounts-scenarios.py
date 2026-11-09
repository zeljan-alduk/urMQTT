#!/usr/bin/env python3
"""Run-time password accounts (NOW-15, ADR-285) against a booted dev VM.

    scripts/accounts-scenarios.py MODE PLAIN_PORT WS_PORT TLS_PORT CERTDIR TOOL SCRATCH

MODE says which boot of the VM this is (scripts/smoke.sh, group `accounts`):

  first    a fresh data disk. The image lists one account in [plaintext]
           (img-1) and has limits.max_runtime_accounts = 3. The operator adds,
           changes and removes accounts with `urmqtt-control` over mutual TLS
           while the clients log in on the plaintext port and over secure
           WebSocket; the signed messages that matter later are kept in SCRATCH.
  second   the same disk after a power cut: the accounts are still there, the
           removed one is still gone, and a message of the first boot replayed
           is refused.

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed. The passwords are only ever given to the operator tool
(which hashes them) and to the clients; the serial log is checked by smoke.sh
for the broker's audit lines and for the absence of every password and hash.
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

MODE, PLAIN, WS, TLS, DIR, TOOL, SCRATCH = (
    sys.argv[1],
    int(sys.argv[2]),
    int(sys.argv[3]),
    int(sys.argv[4]),
    sys.argv[5],
    sys.argv[6],
    sys.argv[7],
)
ORIGIN = "https://app.example.com"
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


# ---- MQTT 3.1.1 packets -------------------------------------------------------


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


def connect_pkt(client_id, user=None, password=None, will=None):
    flags = 0x02 | (0x80 if user is not None else 0) | (0x40 if password is not None else 0) | (0x04 if will else 0)
    body = mstr("MQTT") + bytes([4, flags]) + struct.pack(">H", 60) + mstr(client_id)
    if will:
        body += mstr(will[0]) + mstr(will[1])
    if user is not None:
        body += mstr(user)
    if password is not None:
        body += mstr(password)
    return pkt(0x10, body)


def split(buf):
    """(type, flags, body, rest) of the first packet in `buf`, or None."""
    if len(buf) < 2:
        return None
    n, mult, i = 0, 1, 1
    while i < len(buf):
        n += (buf[i] & 127) * mult
        mult *= 128
        i += 1
        if not buf[i - 1] & 128:
            break
    else:
        return None
    if len(buf) < i + n:
        return None
    return buf[0] >> 4, buf[0] & 15, buf[i : i + n], buf[i + n :]


class Plain:
    """A plaintext MQTT connection."""

    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PLAIN), timeout=5)
        self.buf = b""
        self.closed = False

    def send(self, b):
        try:
            self.s.sendall(b)
        except OSError:
            self.closed = True

    def read(self, wait=3.0):
        end = time.time() + wait
        while True:
            p = split(self.buf)
            if p:
                self.buf = p[3]
                return p[:3]
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

    def connect(self, client_id, user=None, password=None, will=None):
        self.send(connect_pkt(client_id, user, password, will))
        p = self.read()
        if p is None or p == "EOF":
            return p
        return p[2][1] if p[0] == 2 else f"unexpected {p[0]}"

    def subscribe(self, filters):
        self.send(pkt(0x82, struct.pack(">H", 1) + b"".join(mstr(f) + bytes([0]) for f in filters)))
        p = self.read()
        return list(p[2][2:]) if p and p != "EOF" and p[0] == 9 else None

    def publish(self, topic, payload=b"x"):
        self.send(pkt(0x30, mstr(topic) + payload))

    def messages(self, wait):
        out, end = [], time.time() + wait
        while time.time() < end:
            p = self.read(max(0.05, end - time.time()))
            if p is None or p == "EOF":
                break
            if p[0] == 3:
                n = struct.unpack(">H", p[2][:2])[0]
                out.append((p[2][2 : 2 + n].decode(), p[2][2 + n :]))
        return out

    def closed_within(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            p = self.read(max(0.05, end - time.time()))
            if p == "EOF":
                return True
        return False

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def login(user, password, client_id="c1", will=None):
    c = Plain()
    return c, c.connect(client_id, user, password, will)


def tls_ctx(cert=None):
    ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
    ctx.check_hostname = False
    if cert:
        p = os.path.join(DIR, cert)
        ctx.load_cert_chain(p + ".pem", p + ".key")
    return ctx


def backend_subscribed():
    """The TLS service identity that sees what the accounts publish."""
    s = socket.create_connection(("127.0.0.1", TLS), timeout=5)
    s = tls_ctx("services/backend").wrap_socket(s, server_hostname="localhost")
    p = Plain.__new__(Plain)
    p.s, p.buf, p.closed = s, b"", False
    assert p.connect("backend") == 0
    return p


# ---- a raw secure WebSocket client (the account's other listener) -----------


def ws_frame(payload, opcode=2):
    mask = b"\x11\x22\x33\x44"
    n = len(payload)
    head = bytes([0x80 | opcode])
    head += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_login(user, password, client_id="w1"):
    """CONNACK return code of a login over wss, or None."""
    s = socket.create_connection(("127.0.0.1", WS), timeout=10)
    s = tls_ctx().wrap_socket(s, server_hostname="localhost")
    s.sendall(
        (
            "GET /mqtt HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: mqtt\r\nOrigin: {ORIGIN}\r\n\r\n"
        ).encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            return None
        buf += d
    if b" 101 " not in buf.split(b"\r\n", 1)[0]:
        return None
    s.sendall(ws_frame(connect_pkt(client_id, user, password)))
    s.settimeout(5)
    buf = buf.partition(b"\r\n\r\n")[2]
    try:
        while len(buf) < 2 + 4:
            d = s.recv(4096)
            if not d:
                return None
            buf += d
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()
    # An unmasked server frame: 0x82 len, then the CONNACK 20 02 sp rc.
    return buf[2 + 3] if buf[0] == 0x82 and buf[2] == 0x20 else None


# ---- the operator ---------------------------------------------------------------


def control(command, *args, stdin=None, out=None):
    """Runs `urmqtt-control` as the operator; (ok, stderr)."""
    cmd = [
        TOOL,
        command,
        *args,
        "--env",
        "dev",
        "--key",
        os.path.join(DIR, "control.key"),
        "--port",
        str(TLS),
        "--ca",
        os.path.join(DIR, "ca.pem"),
        "--client-cert",
        os.path.join(DIR, "services/operator.pem"),
        "--client-key",
        os.path.join(DIR, "services/operator.key"),
    ]
    if out:
        # Saved for a replay after the reboot: valid for the longest window the image takes.
        cmd += ["--out", out, "--valid-for", "590"]
    r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
    return r.returncode == 0, r.stderr.strip()


def set_account(account, password, cls="full", out=None):
    return control(
        "set-account",
        "--id",
        account,
        "--password-stdin",
        "--iterations",
        "3000",
        "--class",
        cls,
        stdin=password + "\n",
        out=out,
    )


def settle(s=1.0):
    time.sleep(s)


DYN, DYN_PW = "dyn-1", "dyn-secret-1"
VIEW, VIEW_PW = "viewer", "viewer-secret"
FEED, FEED_PW = "feeder", "feeder-secret"


def first_boot():
    # The image's own account works, and an account nobody added does not.
    c, code = login("img-1", "img-secret")
    report("image-account-logs-in", code == 0, f"CONNACK {code}")
    c.close()
    c, code = login(DYN, DYN_PW)
    report("account-unknown-before-it-is-added", code == 4, f"CONNACK {code}")
    c.close()
    ws = ws_login(DYN, DYN_PW)
    report("account-unknown-over-wss-before-it-is-added", ws == 4, f"CONNACK {ws}")

    # Add: logs in at once on both listeners; the wrong password does not.
    ok, err = set_account(DYN, DYN_PW, out=os.path.join(SCRATCH, "set-dyn.bin"))
    settle()
    c, code = login(DYN, DYN_PW)
    bad, badcode = login(DYN, "not-" + DYN_PW, "c2")
    ws = ws_login(DYN, DYN_PW)
    wsbad = ws_login(DYN, "not-" + DYN_PW)
    report(
        "set-account-logs-in-on-both-listeners",
        ok and code == 0 and badcode == 4 and ws == 0 and wsbad == 4,
        f"plain {code}/{badcode} wss {ws}/{wsbad} {err}",
    )
    bad.close()

    # The listener's ACL still decides what it may do: its own topics only.
    bk = backend_subscribed()
    bk.subscribe(["devices/#"])
    c.publish(f"devices/{DYN}/telemetry/t", b"own")
    c.publish("devices/other/telemetry/t", b"foreign")
    got = [m for m in bk.messages(2.5)]
    report("account-acl-is-the-listeners", got == [(f"devices/{DYN}/telemetry/t", b"own")], f"{got}")

    # Change the password: the live login is cut at once, the old password is
    # refused, the new one works.
    ok, err = set_account(DYN, DYN_PW + "-new")
    t0 = time.time()
    gone = c.closed_within(2.0)
    c.close()
    old, oldcode = login(DYN, DYN_PW, "c3")
    new, newcode = login(DYN, DYN_PW + "-new", "c4")
    report(
        "changed-password-cuts-the-live-login",
        ok and gone and oldcode == 4 and newcode == 0,
        f"closed after {time.time() - t0:.2f} s, old {oldcode} new {newcode} {err}",
    )
    old.close()
    new.close()

    # An account of the image cannot be replaced or shadowed.
    ok, err = set_account("img-1", "attacker-chosen")
    settle()
    c, code = login("img-1", "attacker-chosen")
    c2, code2 = login("img-1", "img-secret", "c2")
    report("image-account-wins", ok and code == 4 and code2 == 0, f"new {code} image {code2} {err}")
    c.close()
    c2.close()

    # Classes: read-only subscribes and never publishes; write-only the other way.
    ok1, _ = set_account(VIEW, VIEW_PW, "read-only")
    ok2, _ = set_account(FEED, FEED_PW, "write-only")
    settle()
    v, vcode = login(VIEW, VIEW_PW, "v1")
    codes = v.subscribe([f"devices/{VIEW}/cmd/#"])
    v.publish(f"devices/{VIEW}/telemetry/t", b"nope")
    seen = bk.messages(2.0)
    report(
        "read-only-account-subscribes-but-cannot-publish",
        ok1 and vcode == 0 and codes == [0] and seen == [],
        f"CONNACK {vcode} suback {codes} leaked {seen}",
    )
    w, wcode = login(VIEW, VIEW_PW, "v2", will=(f"devices/{VIEW}/will", b"gone"))
    report("read-only-account-cannot-set-a-will", wcode == 5, f"CONNACK {wcode}")
    w.close()
    v.close()
    f, fcode = login(FEED, FEED_PW, "f1")
    fcodes = f.subscribe([f"devices/{FEED}/cmd/#"])
    f.publish(f"devices/{FEED}/telemetry/t", b"fed")
    seen = bk.messages(2.0)
    report(
        "write-only-account-publishes-but-cannot-subscribe",
        ok2 and fcode == 0 and fcodes == [0x80] and seen == [(f"devices/{FEED}/telemetry/t", b"fed")],
        f"CONNACK {fcode} suback {fcodes} seen {seen}",
    )
    f.close()
    bk.close()

    # The limit (3 accounts here: dyn-1, viewer, feeder): a fourth is refused
    # and not stored; after a removal there is room again.
    ok, err = set_account("extra-1", "extra-secret")
    settle()
    c, code = login("extra-1", "extra-secret")
    report("account-limit-refuses-one-more", ok and code == 4, f"CONNACK {code} {err}")
    c.close()
    h, hcode = login(DYN, DYN_PW + "-new", "h1")
    ok, err = control("remove-account", "--id", DYN, out=os.path.join(SCRATCH, "remove-dyn.bin"))
    gone = h.closed_within(2.0)
    h.close()
    c, code = login(DYN, DYN_PW + "-new", "c5")
    ws = ws_login(DYN, DYN_PW + "-new")
    report(
        "removed-account-is-cut-and-refused",
        ok and hcode == 0 and gone and code == 4 and ws == 4,
        f"live {hcode} closed {gone} plain {code} wss {ws} {err}",
    )
    c.close()
    ok, err = set_account("extra-1", "extra-secret")
    settle()
    c, code = login("extra-1", "extra-secret", "c6")
    report("removal-makes-room-under-the-limit", ok and code == 0, f"CONNACK {code} {err}")
    c.close()

    # Bad input never reaches the wire: the tool refuses it.
    refused = []
    for args, stdin in [
        (["--id", "bad id", "--password-stdin"], "pw\n"),
        (["--id", "x", "--hash", "plain-text-password"], None),
        (["--id", "x", "--password-stdin", "--iterations", "999999"], "pw\n"),
        (["--id", "x"], None),
        (["--id", "x", "--password-stdin", "--class", "root"], "pw\n"),
    ]:
        ok, _ = control("set-account", *args, "--no-publish", stdin=stdin)
        refused.append(not ok)
    report("tool-refuses-bad-input", all(refused), f"{refused}")


def second_boot():
    # After the power cut: the stored accounts log in, the removed one does not.
    c, code = login("extra-1", "extra-secret")
    ws = ws_login("extra-1", "extra-secret")
    report("accounts-survive-a-power-cut", code == 0 and ws == 0, f"plain {code} wss {ws}")
    c.close()
    v, vcode = login(VIEW, VIEW_PW, "v1")
    codes = v.subscribe([f"devices/{VIEW}/cmd/#"])
    report("account-class-survives-a-power-cut", vcode == 0 and codes == [0], f"CONNACK {vcode} suback {codes}")
    v.close()
    c, code = login(DYN, DYN_PW + "-new")
    report("removed-account-stays-removed", code == 4, f"CONNACK {code}")
    c.close()
    # The first boot's messages replayed: refused (the sequence number is stored).
    ok, err = control_publish(os.path.join(SCRATCH, "set-dyn.bin"))
    settle()
    c, code = login(DYN, DYN_PW)
    report("replayed-set-account-is-refused", ok and code == 4, f"CONNACK {code} {err}")
    c.close()
    ok, err = control_publish(os.path.join(SCRATCH, "remove-dyn.bin"))
    settle()
    report("replayed-remove-account-is-refused", ok, err)


def control_publish(f):
    r = subprocess.run(
        [
            TOOL,
            "publish-file",
            f,
            "--port",
            str(TLS),
            "--ca",
            os.path.join(DIR, "ca.pem"),
            "--client-cert",
            os.path.join(DIR, "services/operator.pem"),
            "--client-key",
            os.path.join(DIR, "services/operator.key"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return r.returncode == 0, r.stderr.strip()


{"first": first_boot, "second": second_boot}[MODE]()
sys.exit(0 if all(results) else 1)
