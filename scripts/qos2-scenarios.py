#!/usr/bin/env python3
"""QoS 2, exactly once (ADR-271), byte by byte over mutual TLS.

    scripts/qos2-scenarios.py PORT --tls CERTDIR --phase live|1|2

The real clients (mosquitto, paho) cannot be told to stop in the middle of a
flow, so these scenarios speak MQTT 3.1.1 themselves: every PUBLISH, PUBREC,
PUBREL and PUBCOMP is ours, and a "kill" closes the socket without
DISCONNECT.

live  (any boot) duplicates: the same QoS 2 PUBLISH three times before
      PUBREL is delivered once; the inbound flow of a persistent session
      survives a kill of the client (the PUBLISH sent again with DUP is not
      routed again); the outbound flow too, at both points (killed before
      PUBREC: the PUBLISH comes again with DUP and its id; killed after
      PUBREC: the PUBREL comes again).
1     (fresh disk) leaves a persistent session in the middle of every flow
      and kills the client; the smoke test then kills the VM (SIGKILL).
2     (the next boot) the session resumes from the store: PUBREL and
      PUBLISH (DUP) with the ids of before, the held inbound id still
      suppresses the duplicate, and every flow completes.

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed.
"""
import os
import socket
import ssl
import struct
import sys
import time

args = sys.argv[1:]
DIR = args[args.index("--tls") + 1]
PHASE = args[args.index("--phase") + 1]
PORT = int(args[0])
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


PUBACK, PUBREC, PUBREL, PUBCOMP = 4, 5, 6, 7
NAMES = {2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 9: "SUBACK"}


class Client:
    """One MQTT 3.1.1 connection over mutual TLS with the dev certificates."""

    def __init__(self, cid, clean=True):
        cert = "services/backend" if cid == "backend" else f"devices/{cid}"
        ctx = ssl.create_default_context(cafile=os.path.join(DIR, "ca.pem"))
        ctx.check_hostname = False
        ctx.load_cert_chain(os.path.join(DIR, cert + ".pem"), os.path.join(DIR, cert + ".key"))
        self.s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10))
        self.buf = b""
        self.cid = cid
        flags = 0x02 if clean else 0
        self.send(pkt(0x10, mstr("MQTT") + bytes([4, flags]) + struct.pack(">H", 60) + mstr(cid)))
        p = self.read(10)
        if not p or p[0] != 2 or p[2][1] != 0:
            raise RuntimeError(f"{cid}: no CONNACK: {p!r}")
        self.present = bool(p[2][0] & 1)

    def send(self, b):
        self.s.sendall(b)

    def read(self, wait=3.0):
        """The next packet as (type, flags, body), or None after `wait` s of silence."""
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
                return None
            self.s.settimeout(left)
            try:
                d = self.s.recv(65536)
            except (socket.timeout, ssl.SSLError):
                return None
            if not d:
                return None
            self.buf += d

    def packets(self, wait=1.5):
        """Everything that arrives until `wait` s of silence, decoded."""
        out = []
        while True:
            p = self.read(wait)
            if p is None:
                return out
            out.append(decode(p))

    def subscribe(self, filt, qos=2):
        self.send(pkt(0x82, struct.pack(">H", 1) + mstr(filt) + bytes([qos])))
        p = self.read(5)
        return p is not None and p[0] == 9 and p[2][2:] == bytes([qos])

    def publish(self, topic, payload, pid, dup=False, qos=2):
        first = 0x30 | (qos << 1) | (0x08 if dup else 0)
        self.send(pkt(first, mstr(topic) + struct.pack(">H", pid) + payload))

    def ack(self, kind, pid):
        self.send(pkt((kind << 4) | (2 if kind == PUBREL else 0), struct.pack(">H", pid)))

    def kill(self):
        """Gone without DISCONNECT, as a crashed client is."""
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close()


def decode(p):
    t, flags, body = p
    if t == 3:
        qos = (flags >> 1) & 3
        tl = struct.unpack(">H", body[:2])[0]
        topic = body[2 : 2 + tl].decode()
        rest = body[2 + tl :]
        pid = struct.unpack(">H", rest[:2])[0] if qos else None
        return ("PUBLISH", topic, rest[2:] if qos else rest, qos, pid, bool(flags & 8))
    if t in (4, 5, 6, 7):
        return (NAMES[t], struct.unpack(">H", body[:2])[0])
    return (NAMES.get(t, str(t)),)


def drain_backend(b, wait=1.5):
    """The payloads a QoS 2 subscriber receives, each flow completed."""
    got = []
    while True:
        p = b.read(wait)
        if p is None:
            return got
        d = decode(p)
        if d[0] == "PUBLISH":
            got.append(d[2])
            if d[3] == 2:
                b.ack(PUBREC, d[4])
            elif d[3] == 1:
                b.ack(PUBACK, d[4])
        elif d[0] == "PUBREL":
            b.ack(PUBCOMP, d[1])


def scenario(name, f):
    try:
        ok, detail = f()
    except Exception as e:  # a scenario that breaks is a failed scenario
        ok, detail = False, f"{type(e).__name__}: {e}"
    report(name, ok, detail)


# ---- live -------------------------------------------------------------------


def duplicates_delivered_once():
    b = Client("backend")
    assert b.subscribe("devices/device-001/telemetry/q2")
    d = Client("device-001")
    t = "devices/device-001/telemetry/q2"
    d.publish(t, b"exactly-once", 41)
    d.publish(t, b"exactly-once", 41, dup=True)
    d.publish(t, b"exactly-once", 41, dup=True)
    acks = d.packets()
    d.ack(PUBREL, 41)
    comp = d.packets()
    got = drain_backend(b)
    d.kill()
    b.kill()
    ok = acks == [("PUBREC", 41)] * 3 and comp == [("PUBCOMP", 41)] and got == [b"exactly-once"]
    return ok, f"acks={acks} comp={comp} delivered={got}"


def inbound_flow_survives_a_kill():
    b = Client("backend")
    assert b.subscribe("devices/device-003/telemetry/q2")
    d = Client("device-003", clean=False)
    t = "devices/device-003/telemetry/q2"
    d.publish(t, b"in-flight", 7)
    first = d.packets()
    d.kill()
    time.sleep(0.5)
    d = Client("device-003", clean=False)
    present = d.present
    d.publish(t, b"in-flight", 7, dup=True)
    again = d.packets()
    d.ack(PUBREL, 7)
    comp = d.packets()
    got = drain_backend(b)
    d.kill()
    b.kill()
    ok = present and first == again == [("PUBREC", 7)] and comp == [("PUBCOMP", 7)] and got == [b"in-flight"]
    return ok, f"present={present} first={first} again={again} comp={comp} delivered={got}"


def outbound_flow_survives_a_kill():
    d = Client("device-003", clean=False)
    assert d.subscribe("devices/device-003/cmd/#")
    b = Client("backend")
    for i, pid in enumerate((101, 102)):
        b.publish("devices/device-003/cmd/q2", f"cmd-{i}".encode(), pid)
        b.read(3)
        b.ack(PUBREL, pid)
        b.read(3)
    got = d.packets()
    pubs = [g for g in got if g[0] == "PUBLISH"]
    if len(pubs) != 2:
        return False, f"first delivery: {got}"
    (_, _, _, q1, p1, _), (_, _, _, q2, p2, _) = pubs
    # The first is acknowledged with PUBREC (the PUBREL comes), the second
    # not at all; then the client dies.
    d.ack(PUBREC, p1)
    rel = d.packets()
    d.kill()
    time.sleep(0.5)
    d = Client("device-003", clean=False)
    resent = d.packets()
    want = [("PUBREL", p1), ("PUBLISH", "devices/device-003/cmd/q2", b"cmd-1", 2, p2, True)]
    d.ack(PUBCOMP, p1)
    d.ack(PUBREC, p2)
    rel2 = d.packets()
    d.ack(PUBCOMP, p2)
    tail = d.packets()
    d.kill()
    b.kill()
    # A clean session leaves nothing behind for the next run.
    Client("device-003", clean=True).kill()
    ok = (q1, q2) == (2, 2) and rel == [("PUBREL", p1)] and resent == want and rel2 == [("PUBREL", p2)] and tail == []
    return ok, f"rel={rel} resent={resent} rel2={rel2} tail={tail}"


# ---- across a restart of the VM ----------------------------------------------

STATE = "devices/device-002/telemetry/q2"
CMD = "devices/device-002/cmd/q2"


def phase1():
    b = Client("backend")
    assert b.subscribe(STATE)
    d = Client("device-002", clean=False)
    assert d.subscribe("devices/device-002/cmd/#")
    for i, pid in enumerate((201, 202)):
        b.publish(CMD, f"restart-{i}".encode(), pid)
        b.read(3)
        b.ack(PUBREL, pid)
        b.read(3)
    pubs = [g for g in d.packets() if g[0] == "PUBLISH"]
    d.ack(PUBREC, pubs[0][4])
    rel = d.packets()
    d.publish(STATE, b"held", 9)
    rec = d.packets()
    delivered = drain_backend(b)
    d.kill()
    b.kill()
    # Far longer than one DB batch: the disconnect snapshot is durable.
    time.sleep(1.0)
    ids = [p[4] for p in pubs]
    ok = (len(ids) == 2 and ids[0] != ids[1] and rel == [("PUBREL", ids[0])] and rec == [("PUBREC", 9)]
          and delivered == [b"held"])
    return ok, f"pubs={pubs} rel={rel} rec={rec} delivered={delivered}"


def phase2():
    b = Client("backend")
    assert b.subscribe(STATE)
    d = Client("device-002", clean=False)
    present = d.present
    resent = d.packets()
    # The ids of before (1 and 2 on a fresh disk; the session may have used
    # some already): the released one, then the one still in flight.
    p1 = resent[0][1] if resent and resent[0][0] == "PUBREL" else 1
    p2 = resent[1][4] if len(resent) > 1 and resent[1][0] == "PUBLISH" else 2
    want = [("PUBREL", p1), ("PUBLISH", CMD, b"restart-1", 2, p2, True)]
    # The inbound id 9 is still held: the PUBLISH again is a duplicate.
    d.publish(STATE, b"held", 9, dup=True)
    rec = d.packets()
    dup_routed = drain_backend(b)
    d.ack(PUBREL, 9)
    comp = d.packets()
    d.ack(PUBCOMP, p1)
    d.ack(PUBREC, p2)
    rel = d.packets()
    d.ack(PUBCOMP, p2)
    # Released: id 9 starts a new message now.
    d.publish(STATE, b"new", 9)
    rec2 = d.packets()
    d.ack(PUBREL, 9)
    d.packets()
    after = drain_backend(b)
    d.kill()
    b.kill()
    ok = (present and resent == want and rec == [("PUBREC", 9)] and dup_routed == []
          and p1 != p2 and comp == [("PUBCOMP", 9)] and rel == [("PUBREL", p2)] and rec2 == [("PUBREC", 9)]
          and after == [b"new"])
    return ok, f"present={present} resent={resent} rec={rec} dup_routed={dup_routed} comp={comp} rel={rel} after={after}"


if PHASE == "live":
    scenario("qos2-duplicates-delivered-once", duplicates_delivered_once)
    scenario("qos2-inbound-flow-survives-a-client-kill", inbound_flow_survives_a_kill)
    scenario("qos2-outbound-flow-survives-a-client-kill", outbound_flow_survives_a_kill)
elif PHASE == "1":
    scenario("qos2-restart-phase1", phase1)
else:
    scenario("qos2-restart-resumes-every-flow", phase2)

sys.exit(0 if all(results) else 1)
