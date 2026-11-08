#!/usr/bin/env python3
# MQTT 5.0 capture helper: one paho-mqtt 2.x session exercising CONNECT,
# SUBSCRIBE options, PUBLISH QoS 0/1/2 with properties, UNSUBSCRIBE and
# DISCONNECT with reason code 0x04 plus a property. Used by
# scripts/mqtt5-capture.sh; run it through scripts/mqtt-record.py to record.
#
#   uv run --with 'paho-mqtt>=2,<3' python scripts/mqtt5-capture-paho.py \
#       --port 28832 --direct-port 28831
#
# --port is the recorded connection (the proxy); --direct-port is the broker
# itself, used by a second, unrecorded client that feeds the subscription
# (a retained message before SUBSCRIBE, QoS 1 and 2 messages after), so the
# recorded server->client stream carries PUBLISH with a subscription
# identifier and the QoS 1/2 flows in both directions.
import argparse
import sys
import threading

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.reasoncodes import ReasonCode
from paho.mqtt.subscribeoptions import SubscribeOptions

V2 = mqtt.CallbackAPIVersion.VERSION2


class Waiter:
    def __init__(self):
        self.cv = threading.Condition()
        self.events = []

    def add(self, ev):
        with self.cv:
            self.events.append(ev)
            self.cv.notify_all()

    def wait(self, pred, what, timeout=5.0):
        with self.cv:
            if not self.cv.wait_for(lambda: any(pred(e) for e in self.events), timeout):
                sys.exit(f"timeout waiting for {what}; events: {self.events}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--direct-port", type=int, required=True)
    a = ap.parse_args()

    # Unrecorded feeder: plant a retained message first.
    feed = mqtt.Client(V2, client_id="paho-feed", protocol=mqtt.MQTTv5)
    feed.connect(a.host, a.direct_port)
    feed.loop_start()
    feed.publish("paho/in/ret", b"retained", qos=1, retain=True).wait_for_publish(5)

    w = Waiter()
    c = mqtt.Client(V2, client_id="paho-capture", protocol=mqtt.MQTTv5)
    c.on_connect = lambda cl, ud, fl, rc, pr: w.add(("connack", rc.value))
    c.on_subscribe = lambda cl, ud, mid, rcs, pr: w.add(("suback", mid))
    c.on_unsubscribe = lambda cl, ud, mid, rcs, pr: w.add(("unsuback", mid))
    c.on_message = lambda cl, ud, m: w.add(("msg", m.topic, m.qos))
    c.on_publish = lambda cl, ud, mid, rc, pr: w.add(("puback", mid))

    will_props = Properties(PacketTypes.WILLMESSAGE)
    will_props.WillDelayInterval = 0
    c.will_set("paho/will", b"gone", qos=1, retain=False, properties=will_props)

    cp = Properties(PacketTypes.CONNECT)
    cp.SessionExpiryInterval = 60
    cp.ReceiveMaximum = 20
    cp.UserProperty = ("client", "paho")
    c.connect(a.host, a.port, keepalive=30, clean_start=True, properties=cp)
    c.loop_start()
    w.wait(lambda e: e[0] == "connack", "CONNACK")

    sp = Properties(PacketTypes.SUBSCRIBE)
    sp.SubscriptionIdentifier = 42
    sp.UserProperty = ("sub", "1")
    opts = SubscribeOptions(qos=1, noLocal=True, retainAsPublished=True, retainHandling=1)
    _, smid = c.subscribe([("paho/in/#", opts), ("paho/out/#", SubscribeOptions(qos=2))], properties=sp)
    w.wait(lambda e: e == ("suback", smid), "SUBACK")
    w.wait(lambda e: e[:2] == ("msg", "paho/in/ret"), "retained PUBLISH")

    # The feeder's QoS 1 and 2 messages reach the recorded client.
    feed.publish("paho/in/q1", b"one", qos=1).wait_for_publish(5)
    feed.publish("paho/in/q2", b"two", qos=2).wait_for_publish(5)
    w.wait(lambda e: e[:2] == ("msg", "paho/in/q1"), "QoS 1 PUBLISH")
    w.wait(lambda e: e[:2] == ("msg", "paho/in/q2"), "QoS 2 PUBLISH")

    # Recorded client publishes QoS 0/1/2 with properties. paho/out/# is
    # subscribed without noLocal, so these come back to it as well.
    for qos in (0, 1, 2):
        pp = Properties(PacketTypes.PUBLISH)
        pp.ResponseTopic = "paho/reply"
        pp.CorrelationData = b"corr-%d" % qos
        pp.UserProperty = [("k", "v"), ("qos", str(qos))]
        pp.MessageExpiryInterval = 120
        pp.ContentType = "text/plain"
        info = c.publish(f"paho/out/q{qos}", b"payload-%d" % qos, qos=qos, properties=pp)
        if qos:
            info.wait_for_publish(5)
        w.wait(lambda e, q=qos: e[:2] == ("msg", f"paho/out/q{q}"), f"echo of QoS {qos}")

    up = Properties(PacketTypes.UNSUBSCRIBE)
    up.UserProperty = ("unsub", "1")
    _, umid = c.unsubscribe(["paho/in/#", "paho/out/#"], properties=up)
    w.wait(lambda e: e == ("unsuback", umid), "UNSUBACK")

    dp = Properties(PacketTypes.DISCONNECT)
    dp.SessionExpiryInterval = 0
    c.disconnect(reasoncode=ReasonCode(PacketTypes.DISCONNECT, identifier=0x04), properties=dp)
    c.loop_stop()

    feed.publish("paho/in/ret", b"", qos=1, retain=True).wait_for_publish(5)
    feed.disconnect()
    feed.loop_stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
