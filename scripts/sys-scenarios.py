#!/usr/bin/env python3
"""Operator scenarios: `$SYS/` over MQTT (O1).

    scripts/sys-scenarios.py CERTDIR PORT [reboot]

Every client connects with mutual TLS. The operator is the dev identity
`operator` (deploy/dev/services/operator.*); the ordinary clients, which must
not reach `$SYS/`, are a device and the backend service (mosquitto clients).
A session per client id means the operator's checks run one after the other,
each on its own connection.

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed.
"""
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

DIR, PORT = sys.argv[1], int(sys.argv[2])
TIMEOUT = 40
results = []

TOPICS = [
    "version", "uptime", "arch", "cpu/cores", "cpu/busy/0", "memory/total", "memory/used",
    "disk/total", "disk/used", "clients/connected", "clients/total", "subscriptions", "retained",
    "messages/received", "messages/sent", "connections/refused", "tls/server_cert_days",
    "console/dropped",
]


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


# ---- a minimal MQTT 3.1.1 client for the operator -------------------------------


def enc_len(n):
    out = b""
    while True:
        b, n = n % 128, n // 128
        out += bytes([b | (128 if n else 0)])
        if not n:
            return out


def string(x):
    x = x.encode()
    return struct.pack(">H", len(x)) + x


def packet(first, body):
    return bytes([first]) + enc_len(len(body)) + body


class Operator:
    """The operator identity over mutual TLS: subscribe, publish, listen."""

    def __init__(self, cert="services/operator", client_id="operator"):
        ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
        ctx.check_hostname = False
        ctx.load_cert_chain(os.path.join(DIR, cert + ".pem"), os.path.join(DIR, cert + ".key"))
        self.s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10))
        self.buf = b""
        self.s.sendall(packet(0x10, string("MQTT") + b"\x04\x02\x00\x3c" + string(client_id)))
        self.connack = self.wait(lambda p: p[0] >> 4 == 2, 5)

    def close(self):
        try:
            self.s.sendall(b"\xe0\x00")
        except OSError:
            pass
        self.s.close()

    def packets(self):
        while len(self.buf) >= 2:
            n, mult, i = 0, 1, 1
            while True:
                if i >= len(self.buf):
                    return
                b = self.buf[i]
                n += (b & 127) * mult
                mult *= 128
                i += 1
                if not b & 128:
                    break
            if len(self.buf) < i + n:
                return
            p, self.buf = self.buf[: i + n], self.buf[i + n :]
            yield p[0], p[i:]

    def pump(self, timeout):
        self.s.settimeout(max(timeout, 0.01))
        try:
            data = self.s.recv(65536)
        except (socket.timeout, TimeoutError):
            return True
        except (ssl.SSLError, OSError):
            return False
        self.buf += data
        return bool(data)

    def wait(self, want, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            for p in self.packets():
                if want(p):
                    return p
            if not self.pump(end - time.monotonic()):
                break
        return None

    def subscribe(self, *filters):
        body = struct.pack(">H", 1) + b"".join(string(f) + b"\x00" for f in filters)
        self.s.sendall(packet(0x82, body))
        ack = self.wait(lambda p: p[0] >> 4 == 9, 5)
        return list(ack[1][2:]) if ack else None

    def publish(self, topic, payload="", retain=False):
        self.s.sendall(packet(0x30 | int(retain), string(topic) + payload.encode()))

    def listen(self, seconds):
        """Every PUBLISH received within `seconds`, as (topic, payload, retained)."""
        got = []
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            for first, body in self.packets():
                if first >> 4 == 3:
                    n = struct.unpack(">H", body[:2])[0]
                    got.append((body[2 : 2 + n].decode(), body[2 + n :].decode(errors="replace"), bool(first & 1)))
            if not self.pump(end - time.monotonic()):
                break
        return got


# ---- mosquitto clients for the identities that must be refused ---------------------


def base(client_id, cert):
    certfile = os.path.join(DIR, f"{cert}.pem")
    return ["-h", "127.0.0.1", "-p", str(PORT), "-V", "mqttv311", "-i", client_id,
            "--cafile", os.path.join(DIR, "ca.pem"), "--cert", certfile, "--key", certfile[:-4] + ".key"]


def sub_denied(client_id, cert, topic):
    r = subprocess.run(["mosquitto_sub", *base(client_id, cert), "-d", "-v", "-t", topic, "-W", "3"],
                       capture_output=True, text=True, timeout=TIMEOUT)
    # -d prints the protocol trace; the failure code is in the SUBACK line.
    trace = r.stdout + r.stderr
    delivered = [l for l in r.stdout.splitlines() if l.startswith("$SYS/")]
    return "Subscribed (mid: 1): 128" in trace and not delivered, trace[-120:]


def pub(client_id, cert, topic, message, *extra):
    subprocess.run(["mosquitto_pub", *base(client_id, cert), "-t", topic, "-m", message, *extra],
                   capture_output=True, text=True, timeout=TIMEOUT)


if sys.argv[3:] == ["reboot"]:
    # Only the command's acceptance; the harness watches the VM reset.
    op = Operator()
    op.subscribe("$SYS/console/out")
    op.listen(1)
    op.publish("$SYS/console/in", "reboot")
    lines = [p for t, p, _ in op.listen(2)]
    report("console-reboot-accepted", any("rebooting in 1 s" in l for l in lines))
    sys.exit(0 if results[0] else 1)

# 1. The retained topics, refreshed every 10 s. Listen for 14 s: the first
# copies arrive at once (retained), a refresh comes within 10 s.
op = Operator()
ack = op.subscribe("$SYS/broker/#")
got = op.listen(14)
op.close()
by = {}
for t, v, retained in got:
    by.setdefault(t, []).append(v)


def val(t):
    return by.get(f"$SYS/broker/{t}", [""])[-1]


def num(t):
    return int(val(t)) if val(t).lstrip("-").isdigit() else -1


missing = [t for t in TOPICS if f"$SYS/broker/{t}" not in by]
sane = (
    val("version") != "" and val("arch") in ("aarch64", "x86_64") and num("cpu/cores") >= 1
    and num("memory/total") > 0 and 0 < num("memory/used") <= num("memory/total")
    and num("clients/connected") >= 1 and num("clients/total") >= 1 and num("subscriptions") >= 1
    and num("messages/received") >= 0 and num("messages/sent") >= 1 and num("connections/refused") >= 0
    and num("tls/server_cert_days") > 0 and num("disk/total") >= 0
)
report("sys-broker-topics", ack == [0] and not missing and sane,
       f"suback={ack} missing={missing} cores={val('cpu/cores')} up={val('uptime')} arch={val('arch')} "
       f"mem={val('memory/used')}/{val('memory/total')} disk={val('disk/used')}/{val('disk/total')} "
       f"clients={val('clients/connected')}/{val('clients/total')} subs={val('subscriptions')} "
       f"msgs={val('messages/received')}/{val('messages/sent')} cert-days={val('tls/server_cert_days')}")
ups = by.get("$SYS/broker/uptime", [])
report("sys-refresh", len(set(ups)) >= 2, f"uptime values {ups}")
cores = num("cpu/cores")
busy_ok = cores >= 1 and all(f"$SYS/broker/cpu/busy/{c}" in by for c in range(cores))
busy_ok = busy_ok and all(0 <= int(v) <= 100 for c in range(cores) for v in by.get(f"$SYS/broker/cpu/busy/{c}", []))
report("sys-cpu-busy-per-core", busy_ok, f"cores={cores}")
report("sys-retained-flag", all(r for t, v, r in got[:5]), "the first copies are retained messages")

# 2. Request/response. MQTT 3.1.1 has no Response Topic property: the reply
# goes to $SYS/query/info/response (ADR-060).
op = Operator()
op.subscribe("$SYS/query/info/response")
op.publish("$SYS/query/info", "")
got = [p for t, p, _ in op.listen(4) if t == "$SYS/query/info/response"]
op.close()
try:
    doc = json.loads(got[0])
    good = (
        doc["arch"] in ("aarch64", "x86_64") and doc["cpu"]["cores"] == len(doc["cpu"]["busy"]) >= 1
        and doc["memory"]["total"] > 0 and doc["clients"]["connected"] >= 1 and doc["uptime_s"] >= 0
        and doc["version"] and "server_cert_days" in doc["tls"] and "messages" in doc and "disk" in doc
    )
except (IndexError, ValueError, KeyError, TypeError) as e:
    good = False
    got = [f"{e!r}: {got!r}"]
report("sys-query-info", good, "" if good else got[0][:120])

# 3. Nobody else gets in, and nothing they publish does anything.
for who, cert in (("device-001", "devices/device-001"), ("backend", "services/backend")):
    ok, out = sub_denied(who, cert, "$SYS/#")
    report(f"sys-denied-to-{who}", ok, repr(out))
    pub(who, cert, "$SYS/broker/uptime", "forged", "-r")
# The operator itself may not forge a `$SYS/` topic either.
op = Operator()
op.publish("$SYS/broker/uptime", "forged", retain=True)
op.subscribe("$SYS/broker/uptime")
got = op.listen(3)
op.close()
report("sys-topics-cannot-be-forged", got and all("forged" not in p for _, p, _ in got), f"{len(got)} message(s)")

sys.exit(0 if all(results) else 1)
