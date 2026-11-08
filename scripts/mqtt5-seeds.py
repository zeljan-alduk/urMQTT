#!/usr/bin/env python3
# Writes the MQTT 5.0 fuzz seeds (ADR-274): python3 scripts/mqtt5-seeds.py \
#   fuzz/seeds/broker_input fuzz/seeds/broker_acl
"""Writes MQTT 5.0 seeds for fuzz/seeds/broker_input and broker_acl."""
import os, sys
out_input, out_acl = sys.argv[1], sys.argv[2]

def vbi(n):
    b = bytearray()
    while True:
        x = n & 0x7f; n >>= 7
        b.append(x | (0x80 if n else 0))
        if not n: return bytes(b)

def s(t): t = t.encode() if isinstance(t, str) else t; return len(t).to_bytes(2, 'big') + t
def props(*ps): body = b''.join(ps); return vbi(len(body)) + body
def u32(i, v): return bytes([i]) + v.to_bytes(4, 'big')
def u16(i, v): return bytes([i]) + v.to_bytes(2, 'big')
def pkt(first, body): return bytes([first]) + vbi(len(body)) + body

def connect(cid, clean=True, pr=b'\x00', will=None, ka=0):
    flags = 0x02 if clean else 0
    tail = s(cid)
    if will:
        wp, wt, wpl, wq, wr = will
        flags |= 0x04 | (wq << 3) | (0x20 if wr else 0)
        tail += wp + s(wt) + s(wpl)
    return pkt(0x10, s('MQTT') + bytes([5, flags]) + ka.to_bytes(2, 'big') + pr + tail)

def publish(topic, payload, qos=0, pid=1, retain=False, pr=b'\x00'):
    body = s(topic) + (pid.to_bytes(2, 'big') if qos else b'') + pr + payload
    return pkt(0x30 | (qos << 1) | (1 if retain else 0), body)

def subscribe(pid, filters, pr=b'\x00'):
    body = pid.to_bytes(2, 'big') + pr + b''.join(s(f) + bytes([o]) for f, o in filters)
    return pkt(0x82, body)

def ack(kind, pid): return pkt(kind, pid.to_bytes(2, 'big'))
def disconnect(reason=0, pr=b''): return pkt(0xe0, bytes([reason]) + pr)

# Ops of the input harness: 0x44 slot 0 "d1" (TLS), 0x45 slot 1 "d2", 0x4a slot 2
# "svc"; 0x1c closes slot 0; 0xfd ticks after 3150 ms.
D1, D2, SVC, CLOSE_D1, TICK = 0x44, 0x45, 0x4a, 0x1c, 0xfd

V311 = set()

def seed(seq):
    """Each (op, data) fills whole 64-byte chunks of that op: the data, then
    filler packets after its last packet (never inside one): PINGREQs, and
    for an odd gap one 5-byte packet (a 5.0 PUBACK for an unknown id, or a
    3.1.1 PUBLISH to "x" that the ACL drops)."""
    out = bytearray()
    for op, data in seq:
        if op in (TICK, CLOSE_D1):
            out += bytes([op]) + b'\x00' * 63  # body ignored
            continue
        pad = (-len(data)) % 63
        if pad % 2 and pad < 5:
            pad += 63
        filler = b''
        if pad % 2:
            filler = (bytes([0x30, 3, 0, 1, ord('x')]) if op in V311
                      else bytes([0x40, 3, 0xff, 0xfe, 0]))
            pad -= 5
        stream = data + filler + b'\xc0\x00' * (pad // 2)
        assert len(stream) % 63 == 0
        for i in range(0, len(stream), 63):
            out += bytes([op]) + stream[i:i+63]
    return bytes(out)

ALIAS = lambda a: u16(0x23, a)
SEI = lambda v: u32(0x11, v)
MEI = lambda v: u32(0x02, v)
UP = lambda k, v: bytes([0x26]) + s(k) + s(v)
RM = lambda v: u16(0x21, v)
WDI = lambda v: u32(0x18, v)

seeds = {
    "mqtt5_session_expiry": seed([
        (D1, connect('d1', clean=False, pr=props(SEI(2), RM(1)))),
        (D1, subscribe(1, [('devices/d1/#', 0x05)])),
        (SVC, connect('svc', pr=props())),
        (SVC, publish('devices/d1/cmd/a', b'x', qos=1, pid=3, pr=props(MEI(1), UP('k', 'v')))),
        (CLOSE_D1, b''),
        (SVC, publish('devices/d1/cmd/b', b'y', qos=1, pid=4, pr=props(MEI(60)))),
        (TICK, b''),
        (D1, connect('d1', clean=False, pr=props(SEI(2)))),
        (D1, ack(0x40, 1) + disconnect(0, props(SEI(0)))),
    ]),
    "mqtt5_will_delay_alias": seed([
        (D1, connect('d1', clean=True, pr=props(SEI(30)),
                     will=(props(WDI(2), UP('w', '1')), 'devices/d1/status', b'gone', 1, False))),
        (D1, publish('devices/d1/a', b'1', pr=props(ALIAS(1)))),
        (D1, publish('', b'2', pr=props(ALIAS(1)))),
        (D1, publish('devices/d1/b', b'3', qos=2, pid=7, retain=True, pr=props(ALIAS(2), MEI(5)))),
        (D1, ack(0x62, 7)),
        (D1, publish('', b'4', pr=props(ALIAS(9)))),
        (TICK, b''),
    ]),
    "mqtt5_mixed_versions": (V311.add(0x5a), seed([
        (D1, connect('d1', clean=True, pr=props(RM(2), u32(0x27, 128)))),
        (D1, subscribe(1, [('devices/d1/cmd/#', 0x2a), ('$share/g/devices/d1/cmd/x', 0)])),
        (D1, subscribe(2, [('devices/d1/cmd/x', 1)], pr=props(bytes([0x0b, 5])))),
        # 3.1.1 service publishes: properties stripped / none.
        (0x5a, bytes([0x10, 15, 0, 4]) + b'MQTT' + bytes([4, 2, 0, 0, 0, 3]) + b'svc'),
        (0x5a, bytes([0x33, 22, 0, 16]) + b'devices/d1/cmd/x' + bytes([0, 9]) + b'hi'),
        (0x5a, bytes([0x30, 20, 0, 16]) + b"devices/d1/cmd/x" + b"ab"),
        (D1, ack(0x40, 1) + ack(0x40, 2)),
        (D1, bytes([0xf0, 0])),  # AUTH: 0x82
    ]))[1],
    "mqtt5_flow_control": seed([
        # On slot 1 ("d2"): the input harness reads every 64-byte chunk also
        # as "another shard's subscriber of slot 0's publisher is full"
        # (ADR-269), which would pause a publisher on slot 0.
        (D2, connect('d2', clean=True, pr=props(RM(1)))),
    ] + [
        (D2, publish('devices/d2/q2', b'p', qos=2, pid=i)) for i in range(1, 36)
    ]),
}
for name, data in seeds.items():
    with open(os.path.join(out_input, name), 'wb') as f:
        f.write(data)

# broker_acl: op 9 with b1 & 0x30 == 0x30, then the 5.0 sub-op (see
# acl_oracle::decode_ops).
acl = {
    "mqtt5_no_local_retain_handling": bytes([
        9, 0x78, 0, 1, 11,             # Connect5 slot 0 d1 clean, expiry 600, rm 2
        9, 0x30, 1, 0, 5, 8,           # Subscribe5 devices/d1/cmd/# QoS 1 No Local
        9, 0x30, 2, 1, 4,              # Publish5 devices/d1/cmd/reboot QoS 1
        4, 0,                          # Ack
        9, 0x30, 2, 4, 4,              # Publish5 retained QoS 0
        9, 0x30, 1, 0, 0x20, 8,        # Subscribe5 again, Retain Handling 2
        9, 0x30, 1, 0, 0x10, 8,        # Retain Handling 1, not new
        9, 0x30, 3, 3,                 # Disconnect5 with will, ending the session
    ]),
    "mqtt5_expiry": bytes([
        9, 0x78, 0, 0, 2,              # Connect5 d1 persistent, expiry 3 s
        9, 0x30, 1, 0, 1, 8,           # Subscribe5 devices/d1/cmd/# QoS 1
        6, 0,                          # Drop
        0, 0x09, 0,                    # Connect svc (3.1.1)
        1, 0x05, 4, 1,                 # Publish devices/d1/cmd/reboot QoS 1
        9, 0x31, 2, 0x09, 4,           # Publish5 (3.1.1 slot: plain) with expiry 1
        7, 0, 4,                       # Tick 2000 ms
        9, 0x78, 0, 0, 2,              # Connect5 d1 again: present
        7, 0, 8,                       # Tick 4000 ms
    ]),
}
for name, data in acl.items():
    with open(os.path.join(out_acl, name), 'wb') as f:
        f.write(data)
print("seeds written")
