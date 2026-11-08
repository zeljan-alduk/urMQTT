#!/usr/bin/env python3
"""QoS 2 interop with paho-mqtt (ADR-271), the client library most Python
devices use.

    uv run --with 'paho-mqtt>=2,<3' scripts/qos2-paho.py PORT --tls CERTDIR

1. A device publishes 40 QoS 2 messages in bursts of 8 (paho has them all
   in flight at once; the dev image accepts 10 publishes a second per
   identity); a backend subscribed at QoS 2 receives each exactly once, and
   every publish of the device completes.
2. A device with a persistent session subscribes at QoS 2 and goes away;
   24 QoS 2 commands are published meanwhile; when it comes back it
   receives each exactly once (the broker's queue holds 64 per session).

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed.
"""
import collections
import os
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt

args = sys.argv[1:]
DIR = args[args.index("--tls") + 1]
PORT = int(args[0])
results = []


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


def client(cid, clean=True):
    cert = "services/backend" if cid == "backend" else f"devices/{cid}"
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv311, clean_session=clean)
    c.tls_set(ca_certs=os.path.join(DIR, "ca.pem"), certfile=os.path.join(DIR, cert + ".pem"),
              keyfile=os.path.join(DIR, cert + ".key"), cert_reqs=ssl.CERT_REQUIRED)
    c.tls_insecure_set(True)
    return c


class Inbox:
    def __init__(self, c):
        self.got = collections.Counter()
        self.qos = set()
        self.subscribed = threading.Event()
        self.connected = threading.Event()
        self.present = None
        c.on_message = self.on_message
        c.on_subscribe = lambda *a: self.subscribed.set()
        c.on_connect = self.on_connect

    def on_connect(self, c, userdata, flags, reason, props):
        self.present = flags.session_present
        self.connected.set()

    def on_message(self, c, userdata, m):
        self.got[m.payload] += 1
        self.qos.add(m.qos)


def paced(c, topic, prefix, n):
    """Publishes n QoS 2 messages in bursts of 8 a second (under the rate)."""
    infos = []
    for i in range(n):
        infos.append(c.publish(topic, f"{prefix}{i}".encode(), qos=2))
        if i % 8 == 7:
            time.sleep(1.0)
    return infos


def wait_until(cond, secs):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.05)
    return cond()


def pipelined_publishes():
    b = client("backend")
    inbox = Inbox(b)
    b.connect("127.0.0.1", PORT, 60)
    b.loop_start()
    inbox.connected.wait(10)
    b.subscribe("devices/device-001/telemetry/paho", qos=2)
    inbox.subscribed.wait(10)
    d = client("device-001")
    d.connect("127.0.0.1", PORT, 60)
    d.loop_start()
    infos = paced(d, "devices/device-001/telemetry/paho", "m", 40)
    for info in infos:
        info.wait_for_publish(15)
    published = all(i.is_published() for i in infos)
    want = {f"m{i}".encode() for i in range(40)}
    wait_until(lambda: set(inbox.got) >= want, 15)
    time.sleep(1.0)  # a duplicate would arrive now
    d.disconnect()
    b.disconnect()
    d.loop_stop()
    b.loop_stop()
    once = set(inbox.got) == want and all(n == 1 for n in inbox.got.values())
    return published and once and inbox.qos == {2}, (
        f"published={published} received={len(inbox.got)} distinct, "
        f"{sum(inbox.got.values())} in all, qos={inbox.qos}")


def offline_queue_at_qos2():
    d = client("device-005", clean=False)
    inbox = Inbox(d)
    d.connect("127.0.0.1", PORT, 60)
    d.loop_start()
    inbox.connected.wait(10)
    d.subscribe("devices/device-005/cmd/#", qos=2)
    inbox.subscribed.wait(10)
    d.disconnect()
    d.loop_stop()
    b = client("backend")
    b.connect("127.0.0.1", PORT, 60)
    b.loop_start()
    infos = paced(b, "devices/device-005/cmd/paho", "c", 24)
    for info in infos:
        info.wait_for_publish(15)
    b.disconnect()
    b.loop_stop()
    d = client("device-005", clean=False)
    inbox = Inbox(d)
    d.connect("127.0.0.1", PORT, 60)
    d.loop_start()
    want = {f"c{i}".encode() for i in range(24)}
    wait_until(lambda: set(inbox.got) >= want, 20)
    time.sleep(1.0)
    present = inbox.present
    d.disconnect()
    d.loop_stop()
    # Clean up: a clean session deletes the stored one.
    c = client("device-005", clean=True)
    c.connect("127.0.0.1", PORT, 60)
    c.loop_start()
    time.sleep(0.5)
    c.disconnect()
    c.loop_stop()
    once = set(inbox.got) == want and all(n == 1 for n in inbox.got.values())
    return present and once and inbox.qos == {2}, (
        f"present={present} received={len(inbox.got)} distinct, {sum(inbox.got.values())} in all, qos={inbox.qos}")


for name, f in [("paho-qos2-pipelined-exactly-once", pipelined_publishes),
                ("paho-qos2-offline-queue-exactly-once", offline_queue_at_qos2)]:
    try:
        ok, detail = f()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    report(name, ok, detail)

sys.exit(0 if all(results) else 1)
