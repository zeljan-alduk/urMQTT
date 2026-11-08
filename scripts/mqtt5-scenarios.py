#!/usr/bin/env python3
"""MQTT 5.0 against a booted broker (ADR-273 part 2, ADR-274): paho-mqtt 2.x
over mutual TLS, and a raw client for what paho does not send (a topic alias
with an empty topic, an AUTH packet, a connection dropped without
DISCONNECT).

    uv run --with 'paho-mqtt>=2,<3' scripts/mqtt5-scenarios.py PORT --tls CERTDIR --phase live|persist1|persist2

live      every rule on one boot: CONNACK properties, both versions on one
          port, property forwarding (also to a 3.1.1 subscriber, stripped),
          request/response, topic aliases, Receive Maximum, Maximum Packet
          Size, subscription options (No Local, Retain As Published, Retain
          Handling), reason codes (PUBACK 0x87, SUBACK 0x87/0x9E/0xA1,
          UNSUBACK 0x11), server DISCONNECT packets (0x8E takeover, 0x94 alias,
          0x82 AUTH), session expiry, message expiry, will delay, $SYS.
persist1  leaves state for a restart: device-005 with Session Expiry 3600,
          offline, a No Local subscription, two queued commands with
          properties (one expiring in 4 s); device-003 with Session Expiry 5.
persist2  after the broker was killed and booted again (at least 8 s
          later): device-005's session is back with its queue (properties
          kept, the short one expired, the expiry counted down) and its No
          Local option; device-003's session expired while the broker was
          down.

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed.
"""
import collections
import os
import socket
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.subscribeoptions import SubscribeOptions

args = sys.argv[1:]
DIR = args[args.index("--tls") + 1]
PHASE = args[args.index("--phase") + 1] if "--phase" in args else "live"
PORT = int(args[0])
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


def certs(cid):
    kind = "services" if cid in ("backend", "operator") else "devices"
    return os.path.join(DIR, kind, cid)


def wait_until(cond, secs):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.05)
    return cond()


def props(kind, **kv):
    p = Properties(kind)
    for k, v in kv.items():
        setattr(p, k, v)
    return p


class C:
    """A paho 5.0 client with what the scenarios read back."""

    def __init__(self, cid, v5=True, manual_ack=False):
        self.cid = cid
        self.c = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=cid,
            protocol=mqtt.MQTTv5 if v5 else mqtt.MQTTv311,
            manual_ack=manual_ack,
        )
        base = certs(cid)
        self.c.tls_set(
            ca_certs=os.path.join(DIR, "ca.pem"),
            certfile=base + ".pem",
            keyfile=base + ".key",
            cert_reqs=ssl.CERT_REQUIRED,
        )
        self.c.tls_insecure_set(True)
        self.msgs = []
        self.connack = None
        self.connected = threading.Event()
        self.subacks = []
        self.unsubacks = []
        self.pubacks = {}
        self.disconnect = None
        self.c.on_connect = self._on_connect
        self.c.on_message = lambda c, u, m: self.msgs.append(m)
        self.c.on_subscribe = lambda c, u, mid, rc, p: self.subacks.append([r.value for r in rc])
        self.c.on_unsubscribe = lambda c, u, mid, rc, p: self.unsubacks.append([r.value for r in rc])
        self.c.on_publish = self._on_publish
        self.c.on_disconnect = self._on_disconnect

    def _on_connect(self, c, u, flags, rc, p):
        self.connack = (flags.session_present, rc.value, p)
        self.connected.set()

    def _on_publish(self, c, u, mid, rc, p):
        self.pubacks[mid] = rc.value

    def _on_disconnect(self, c, u, flags, rc, p):
        self.disconnect = rc.value

    def connect(self, clean=True, **cprops):
        p = props(PacketTypes.CONNECT, **cprops) if cprops else None
        if self.c._protocol == mqtt.MQTTv5:
            self.c.connect("127.0.0.1", PORT, 30, clean_start=clean, properties=p)
        else:
            self.c.connect("127.0.0.1", PORT, 30)
        self.c.loop_start()
        if not self.connected.wait(10):
            raise RuntimeError(f"{self.cid}: no CONNACK")
        return self

    def sub(self, *subs, **sprops):
        n = len(self.subacks)
        p = props(PacketTypes.SUBSCRIBE, **sprops) if sprops else None
        if self.c._protocol == mqtt.MQTTv5:
            self.c.subscribe(list(subs), properties=p)
        else:
            self.c.subscribe([(t, o.QoS) for t, o in subs])
        wait_until(lambda: len(self.subacks) > n, 5)
        return self.subacks[-1] if len(self.subacks) > n else None

    def pub(self, topic, payload, qos=0, retain=False, **pprops):
        p = props(PacketTypes.PUBLISH, **pprops) if pprops else None
        info = self.c.publish(topic, payload, qos=qos, retain=retain, properties=p)
        if qos:
            wait_until(lambda: info.mid in self.pubacks, 5)
        return self.pubacks.get(info.mid)

    def stop(self, clean=True):
        if clean:
            self.c.disconnect()
        self.c.loop_stop()
        try:
            self.c.socket() and self.c.socket().close()
        except Exception:
            pass


def opts(qos, no_local=False, rap=False, rh=0):
    return SubscribeOptions(qos=qos, noLocal=no_local, retainAsPublished=rap, retainHandling=rh)


# ---- a raw MQTT 5.0 client over TLS ------------------------------------------


def vbi(n):
    b = bytearray()
    while True:
        x, n = n & 0x7F, n >> 7
        b.append(x | (0x80 if n else 0))
        if not n:
            return bytes(b)


def s(t):
    t = t.encode() if isinstance(t, str) else t
    return len(t).to_bytes(2, "big") + t


def pkt(first, body):
    return bytes([first]) + vbi(len(body)) + body


class Raw:
    def __init__(self, cid):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.load_verify_locations(os.path.join(DIR, "ca.pem"))
        base = certs(cid)
        ctx.load_cert_chain(base + ".pem", base + ".key")
        self.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=5))
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def connect(self, cid, clean=True, prop=b"\x00", will=None):
        flags = 0x02 if clean else 0
        tail = s(cid)
        if will:
            wprops, topic, payload, qos = will
            flags |= 0x04 | (qos << 3)
            tail += wprops + s(topic) + s(payload)
        self.send(pkt(0x10, s("MQTT") + bytes([5, flags, 0, 0]) + prop + tail))
        return self.packet()

    def packet(self, timeout=5):
        """(type, flags, body) of the next packet, or None."""
        self.sock.settimeout(timeout)
        try:
            while True:
                if len(self.buf) >= 2:
                    n, mul, i = 0, 1, 1
                    while i < len(self.buf):
                        b = self.buf[i]
                        n += (b & 0x7F) * mul
                        mul <<= 7
                        i += 1
                        if not b & 0x80:
                            break
                    else:
                        i = None
                    if i is not None and len(self.buf) >= i + n:
                        p = (self.buf[0] >> 4, self.buf[0] & 0x0F, self.buf[i : i + n])
                        self.buf = self.buf[i + n :]
                        return p
                data = self.sock.recv(4096)
                if not data:
                    return None
                self.buf += data
        except (socket.timeout, ssl.SSLError, OSError):
            return None

    def kill(self):
        """Drops the connection without DISCONNECT."""
        try:
            self.sock.close()
        except OSError:
            pass


def u32(i, v):
    return bytes([i]) + v.to_bytes(4, "big")


def u16(i, v):
    return bytes([i]) + v.to_bytes(2, "big")


def plist(*ps):
    body = b"".join(ps)
    return vbi(len(body)) + body


# ---- scenarios -----------------------------------------------------------------


def connack_properties():
    d = C("device-001").connect()
    present, rc, p = d.connack
    ok = (
        rc == 0
        and getattr(p, "ReceiveMaximum", None) == 32
        and getattr(p, "TopicAliasMaximum", None) == 10
        and getattr(p, "SharedSubscriptionAvailable", None) == 0
        and getattr(p, "SubscriptionIdentifierAvailable", None) == 0
        and getattr(p, "MaximumPacketSize", 0) > 0
    )
    d.stop()
    report("mqtt5-connack-announces-the-limits", ok, f"{p}")


def both_versions():
    a = C("device-001").connect()
    b = C("device-002", v5=False).connect()
    ok = a.connack[1] == 0 and b.connack[1] == 0
    a.stop()
    b.stop()
    report("mqtt5-and-311-on-one-port", ok)


def forwarding():
    be = C("backend").connect()
    be.sub(("devices/+/telemetry/#", opts(1)))
    d3 = C("device-003").connect()
    d3.sub(("devices/device-003/cmd/#", opts(1)))
    d2 = C("device-002", v5=False).connect()
    d2.sub(("devices/device-002/cmd/#", opts(1)))
    up = [("k", "v"), ("k", "w")]
    rc = C("device-001").connect()
    rc.pub("devices/device-001/telemetry/t", b"{}", qos=1, UserProperty=up, ContentType="application/json",
           PayloadFormatIndicator=1, ResponseTopic="devices/device-001/reply", CorrelationData=b"c1")
    wait_until(lambda: be.msgs, 5)
    m = be.msgs[-1] if be.msgs else None
    mp = m.properties if m else None
    ok = bool(m) and getattr(mp, "UserProperty", None) == up and getattr(mp, "ContentType", None) == "application/json" \
        and getattr(mp, "ResponseTopic", None) == "devices/device-001/reply" and getattr(mp, "CorrelationData", None) == b"c1" \
        and getattr(mp, "PayloadFormatIndicator", None) == 1
    report("mqtt5-properties-forwarded", ok, f"{mp}")
    # Commands to a 5.0 and a 3.1.1 device: the 3.1.1 one gets the payload.
    be.pub("devices/device-003/cmd/x", b"c3", qos=1, UserProperty=[("a", "b")])
    be.pub("devices/device-002/cmd/x", b"c2", qos=1, UserProperty=[("a", "b")])
    wait_until(lambda: d3.msgs and d2.msgs, 5)
    ok = bool(d3.msgs) and getattr(d3.msgs[-1].properties, "UserProperty", None) == [("a", "b")] \
        and bool(d2.msgs) and d2.msgs[-1].payload == b"c2"
    report("mqtt5-properties-stripped-for-a-311-subscriber", ok)
    # Request/response: the device answers on the response topic with the
    # correlation data; the backend reads both back.
    be.sub(("devices/device-003/reply", opts(1)))
    d3.c.on_message = lambda c, u, m: (d3.msgs.append(m), m.properties and getattr(m.properties, "ResponseTopic", None)
                                      and d3.pub(m.properties.ResponseTopic, b"pong",
                                                 CorrelationData=m.properties.CorrelationData))
    be.msgs.clear()
    be.pub("devices/device-003/cmd/ping", b"ping", ResponseTopic="devices/device-003/reply", CorrelationData=b"r7")
    wait_until(lambda: any(m.topic == "devices/device-003/reply" for m in be.msgs), 5)
    r = [m for m in be.msgs if m.topic == "devices/device-003/reply"]
    report("mqtt5-request-response", bool(r) and getattr(r[0].properties, "CorrelationData", None) == b"r7")
    for c in (be, d3, d2, rc):
        c.stop()


def aliases():
    be = C("backend").connect()
    be.sub(("devices/+/telemetry/#", opts(0)))
    r = Raw("device-001")
    t, _, _ = r.connect("device-001")
    alias = plist(u16(0x23, 1))
    r.send(pkt(0x30, s("devices/device-001/telemetry/a") + alias + b"1"))
    r.send(pkt(0x30, s("") + alias + b"2"))
    r.send(pkt(0x30, s("") + alias + b"3"))
    wait_until(lambda: len(be.msgs) >= 3, 5)
    ok = [m.topic for m in be.msgs] == ["devices/device-001/telemetry/a"] * 3 and [m.payload for m in be.msgs] == [b"1", b"2", b"3"]
    report("mqtt5-topic-alias-resolved", ok)
    # An alias never set: DISCONNECT 0x94.
    r.send(pkt(0x30, s("") + plist(u16(0x23, 7)) + b"x"))
    p = r.packet()
    report("mqtt5-unknown-alias-disconnect-0x94", p is not None and p[0] == 14 and p[2][:1] == b"\x94")
    r.kill()
    be.stop()


def flow_control():
    d = C("device-003", manual_ack=True).connect(clean=True, ReceiveMaximum=2)
    d.sub(("devices/device-003/cmd/#", opts(1)))
    be = C("backend").connect()
    for i in range(5):
        be.c.publish("devices/device-003/cmd/x", f"m{i}", qos=1)
    time.sleep(1.5)
    first = len(d.msgs)
    for m in list(d.msgs):
        d.c.ack(m.mid, m.qos)
    wait_until(lambda: len(d.msgs) >= 4, 5)
    report("mqtt5-receive-maximum-bounds-the-window", first == 2 and len(d.msgs) >= 4, f"{first} then {len(d.msgs)}")
    d.stop()
    small = C("device-003").connect(clean=True, MaximumPacketSize=128)
    small.sub(("devices/device-003/cmd/#", opts(1)))
    be.pub("devices/device-003/cmd/big", b"x" * 300, qos=1)
    be.pub("devices/device-003/cmd/small", b"y", qos=1)
    wait_until(lambda: small.msgs, 5)
    time.sleep(0.5)
    report("mqtt5-maximum-packet-size-honoured", [m.topic for m in small.msgs] == ["devices/device-003/cmd/small"])
    small.stop()
    be.stop()


def subscription_options():
    d = C("device-001").connect()
    d.sub(("devices/device-001/cmd/#", opts(1, no_local=True)))
    d.pub("devices/device-001/cmd/self", b"me", qos=1)
    be = C("backend").connect()
    be.pub("devices/device-001/cmd/other", b"them", qos=1)
    wait_until(lambda: d.msgs, 5)
    time.sleep(0.5)
    report("mqtt5-no-local", [m.payload for m in d.msgs] == [b"them"])
    # Retained command, then Retain Handling 2 (none), 1 (only when new),
    # Retain As Published on a live delivery.
    be.pub("devices/device-001/cmd/state", b"on", qos=1, retain=True)
    d.stop()
    d = C("device-001").connect()
    d.sub(("devices/device-001/cmd/state", opts(0, rh=2)))
    time.sleep(0.5)
    none = len(d.msgs)
    d.sub(("devices/device-001/cmd/state", opts(0, rh=1)))
    time.sleep(0.5)
    still = len(d.msgs)
    d.sub(("devices/device-001/cmd/#", opts(0, rh=1, rap=True)))
    wait_until(lambda: d.msgs, 5)
    replay = [m for m in d.msgs if m.retain]
    d.msgs.clear()
    be.pub("devices/device-001/cmd/state", b"off", qos=1, retain=True)
    wait_until(lambda: d.msgs, 5)
    live = d.msgs[-1] if d.msgs else None
    report("mqtt5-retain-handling-and-retain-as-published",
           none == 0 and still == 0 and len(replay) == 1 and live is not None and live.retain,
           f"{none} {still} {len(replay)} {live and live.retain}")
    be.pub("devices/device-001/cmd/state", b"", qos=1, retain=True)
    d.stop()
    be.stop()


def reason_codes():
    d = C("device-001").connect()
    rc = d.pub("fleet/not-mine", b"x", qos=1)
    report("mqtt5-puback-0x87-outside-the-acl", rc == 0x87, f"{rc}")
    codes = d.sub(("devices/device-002/cmd/#", opts(1)), ("$share/g/devices/device-001/cmd/#", opts(0)))
    report("mqtt5-suback-0x87-and-0x9e", codes == [0x87, 0x9E], f"{codes}")
    codes = d.sub(("devices/device-001/cmd/#", opts(0)), SubscriptionIdentifier=5)
    report("mqtt5-suback-0xa1-subscription-identifier", codes == [0xA1], f"{codes}")
    n = len(d.unsubacks)
    d.c.unsubscribe(["devices/device-001/cmd/none"])
    wait_until(lambda: len(d.unsubacks) > n, 5)
    report("mqtt5-unsuback-0x11", d.unsubacks[-1:] == [[0x11]], f"{d.unsubacks}")
    d.stop()


def server_disconnects():
    old = C("device-002").connect(clean=False, SessionExpiryInterval=60)
    new = C("device-002").connect(clean=False, SessionExpiryInterval=60)
    wait_until(lambda: old.disconnect is not None, 5)
    report("mqtt5-takeover-disconnect-0x8e", old.disconnect == 0x8E and new.connack[0], f"{old.disconnect}")
    old.stop(clean=False)
    new.c.disconnect(properties=props(PacketTypes.DISCONNECT, SessionExpiryInterval=0))
    new.stop(clean=False)
    r = Raw("device-001")
    r.connect("device-001")
    r.send(pkt(0xF0, b""))
    p = r.packet()
    report("mqtt5-auth-disconnect-0x82", p is not None and p[0] == 14 and p[2][:1] == b"\x82")
    r.kill()


def session_expiry():
    d = C("device-005").connect(clean=False, SessionExpiryInterval=3)
    d.sub(("devices/device-005/cmd/#", opts(1)))
    d.stop()
    d = C("device-005").connect(clean=False, SessionExpiryInterval=3)
    back = d.connack[0]
    d.stop()
    time.sleep(4.5)
    d = C("device-005").connect(clean=False, SessionExpiryInterval=3)
    gone = not d.connack[0]
    d.c.disconnect(properties=props(PacketTypes.DISCONNECT, SessionExpiryInterval=0))
    d.stop(clean=False)
    report("mqtt5-session-expiry", back and gone, f"{back} {gone}")


def message_expiry():
    d = C("device-005").connect(clean=False, SessionExpiryInterval=60)
    d.sub(("devices/device-005/cmd/#", opts(1)))
    d.stop()
    be = C("backend").connect()
    be.pub("devices/device-005/cmd/short", b"s", qos=1, MessageExpiryInterval=2)
    be.pub("devices/device-005/cmd/long", b"l", qos=1, MessageExpiryInterval=60)
    be.stop()
    time.sleep(3)
    d = C("device-005").connect(clean=False, SessionExpiryInterval=60)
    wait_until(lambda: d.msgs, 5)
    time.sleep(0.5)
    got = [(m.topic, getattr(m.properties, "MessageExpiryInterval", None)) for m in d.msgs]
    ok = len(got) == 1 and got[0][0] == "devices/device-005/cmd/long" and got[0][1] is not None and got[0][1] <= 57
    d.c.disconnect(properties=props(PacketTypes.DISCONNECT, SessionExpiryInterval=0))
    d.stop(clean=False)
    report("mqtt5-message-expiry", ok, f"{got}")


def will_delay():
    be = C("backend").connect()
    be.sub(("devices/+/status", opts(1)))
    wprops = plist(u32(0x18, 3))
    # Dropped, not back: the will after 3 s.
    r = Raw("device-002")
    r.connect("device-002", clean=True, prop=plist(u32(0x11, 30)), will=(wprops, "devices/device-002/status", b"gone", 1))
    t0 = time.time()
    r.kill()
    wait_until(lambda: be.msgs, 10)
    dt = time.time() - t0
    report("mqtt5-will-delay", bool(be.msgs) and 2.5 <= dt <= 5.5, f"{dt:.1f} s")
    # Dropped and back within the delay: no will.
    be.msgs.clear()
    r = Raw("device-002")
    r.connect("device-002", clean=True, prop=plist(u32(0x11, 30)), will=(wprops, "devices/device-002/status", b"gone", 1))
    r.kill()
    time.sleep(1)
    r = Raw("device-002")
    r.connect("device-002", clean=False, prop=plist(u32(0x11, 30)))
    time.sleep(4)
    report("mqtt5-will-cancelled-by-a-reconnect", not be.msgs)
    r.send(pkt(0xE0, b"\x00" + plist(u32(0x11, 0))))
    r.kill()
    be.stop()


def sys_counters():
    op = C("operator").connect()
    op.sub(("$SYS/broker/clients/connected/v5", opts(0)), ("$SYS/broker/disconnects/sent/0x8e", opts(0)),
           ("$SYS/broker/sessions/expired", opts(0)), ("$SYS/broker/messages/expired", opts(0)))
    wait_until(lambda: len(op.msgs) >= 4, 15)
    vals = {m.topic.rsplit("broker/", 1)[1]: m.payload.decode() for m in op.msgs}
    ok = vals.get("clients/connected/v5", "0") != "" and int(vals.get("disconnects/sent/0x8e", "0")) >= 1
    report("mqtt5-sys-counters", ok, f"{vals}")
    op.stop()


def persist1():
    d = C("device-005").connect(clean=True, SessionExpiryInterval=3600)
    d.sub(("devices/device-005/cmd/#", opts(1, no_local=True)))
    d.stop()
    d3 = C("device-003").connect(clean=True, SessionExpiryInterval=5)
    d3.sub(("devices/device-003/cmd/#", opts(1)))
    d3.stop()
    be = C("backend").connect()
    be.pub("devices/device-005/cmd/keep", b"k", qos=1, MessageExpiryInterval=3600, UserProperty=[("p", "1")],
           ContentType="text/plain")
    be.pub("devices/device-005/cmd/brief", b"b", qos=1, MessageExpiryInterval=4)
    be.stop()
    time.sleep(1)
    report("mqtt5-restart-phase1", True)


def persist2():
    d3 = C("device-003").connect(clean=False, SessionExpiryInterval=5)
    report("mqtt5-session-expired-while-the-broker-was-down", not d3.connack[0])
    d3.c.disconnect(properties=props(PacketTypes.DISCONNECT, SessionExpiryInterval=0))
    d3.stop(clean=False)
    d = C("device-005").connect(clean=False, SessionExpiryInterval=3600)
    present = d.connack[0]
    wait_until(lambda: d.msgs, 5)
    time.sleep(0.5)
    got = [(m.topic, getattr(m.properties, "UserProperty", None), getattr(m.properties, "ContentType", None),
            getattr(m.properties, "MessageExpiryInterval", None)) for m in d.msgs]
    ok = present and len(got) == 1 and got[0][0] == "devices/device-005/cmd/keep" and got[0][1] == [("p", "1")] \
        and got[0][2] == "text/plain" and got[0][3] is not None and got[0][3] < 3600
    report("mqtt5-restart-keeps-the-queue-properties-and-expiry", ok, f"present={present} {got}")
    # The No Local option came back from the store.
    d.msgs.clear()
    d.pub("devices/device-005/cmd/self", b"me", qos=1)
    time.sleep(1)
    report("mqtt5-restart-keeps-the-subscription-options", not d.msgs, f"{[m.topic for m in d.msgs]}")
    d.c.disconnect(properties=props(PacketTypes.DISCONNECT, SessionExpiryInterval=0))
    d.stop(clean=False)


def main():
    try:
        if PHASE == "live":
            for f in (connack_properties, both_versions, forwarding, aliases, flow_control, subscription_options,
                      reason_codes, server_disconnects, session_expiry, message_expiry, will_delay, sys_counters):
                try:
                    f()
                except Exception as e:  # one scenario's failure must not hide the others
                    report(f.__name__, False, f"exception {e!r}")
        elif PHASE == "persist1":
            persist1()
        elif PHASE == "persist2":
            persist2()
    except Exception as e:
        report(PHASE, False, f"exception {e!r}")
    sys.exit(0 if results and all(results) else 1)


main()
