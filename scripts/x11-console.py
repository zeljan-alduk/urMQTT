#!/usr/bin/env python3
"""Reads the broker's console and counters over MQTT for a while (PERF, ADR-221/216).

    x11-console.py HOST PORT CERTDIR SECONDS [OUTFILE]

Connects as the `operator` identity (CERTDIR/ca.pem, operator.pem, operator.key),
subscribes to `$SYS/console/out` and `$SYS/broker/#` and writes every console
line, and the last value of every `$SYS/broker/...` topic at the end, to OUTFILE
(default stdout). Needs only the Python standard library; used on the load
generator host, which has no mosquitto_sub.
"""
import socket
import ssl
import sys
import time


def varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (128 if n else 0))
        if not n:
            return bytes(out)


def mstr(s):
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


def packet(first, body):
    return bytes([first]) + varint(len(body)) + body


def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise EOFError
        buf += d
    return buf


def read_packet(s):
    first = read_exact(s, 1)[0]
    mult, n = 1, 0
    while True:
        b = read_exact(s, 1)[0]
        n += (b & 127) * mult
        if not b & 128:
            break
        mult *= 128
    return first, read_exact(s, n) if n else b""


def main():
    host, port, certs, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
    out = open(sys.argv[5], "w") if len(sys.argv) > 5 else sys.stdout
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(f"{certs}/ca.pem")
    ctx.load_cert_chain(f"{certs}/operator.pem", f"{certs}/operator.key")
    raw = socket.create_connection((host, port), timeout=15)
    s = ctx.wrap_socket(raw, server_hostname=host)
    s.sendall(packet(0x10, mstr("MQTT") + bytes([4, 2]) + (60).to_bytes(2, "big") + mstr("operator")))
    first, body = read_packet(s)
    if first != 0x20 or body[1] != 0:
        print(f"x11-console: CONNACK refused {body!r}", file=sys.stderr)
        return 1
    topics = ["$SYS/console/out", "$SYS/broker/#"]
    body = (1).to_bytes(2, "big") + b"".join(mstr(t) + b"\x00" for t in topics)
    s.sendall(packet(0x82, body))
    broker = {}
    end = time.time() + secs
    s.settimeout(1.0)
    last_ping = time.time()
    while time.time() < end:
        try:
            first, body = read_packet(s)
        except socket.timeout:
            first = None
        except EOFError:
            break
        if time.time() - last_ping > 30:
            s.sendall(b"\xc0\x00")
            last_ping = time.time()
        if first is None or first >> 4 != 3:
            continue
        tl = int.from_bytes(body[:2], "big")
        topic = body[2 : 2 + tl].decode(errors="replace")
        payload = body[2 + tl :].decode(errors="replace")
        if topic == "$SYS/console/out":
            print(payload, file=out, flush=True)
        else:
            broker[topic] = payload
    for t in sorted(broker):
        print(f"SYSVAL {t}={broker[t]}", file=out)
    try:
        s.sendall(b"\xe0\x00")
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
