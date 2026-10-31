#!/usr/bin/env python3
"""A tiny SNTP server for the smoke tests (T1, dev only).

    sntp-responder.py PORT MODE SECONDS [LOGFILE]

MODE: ok (the host clock), past (1970 plus one hour: below the image's build
time), skew (host clock + 3 hours), kod (stratum 0, "RATE"), wrongorigin (a
valid reply to a request that was never sent), silent. Answers on 127.0.0.1
only; exits after SECONDS. Every request is logged to LOGFILE.
"""
import socket
import struct
import sys
import time

NTP_DELTA = 2208988800


def ts(unix):
    secs = int(unix) + NTP_DELTA
    frac = int((unix - int(unix)) * (1 << 32))
    return struct.pack(">II", secs & 0xFFFFFFFF, frac)


def main():
    port, mode, seconds = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    log = open(sys.argv[4], "a") if len(sys.argv) > 4 else sys.stderr
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.5)
    end = time.time() + seconds
    while time.time() < end:
        try:
            req, peer = s.recvfrom(512)
        except socket.timeout:
            continue
        if len(req) < 48:
            continue
        print(f"sntp-responder: request from {peer[0]}:{peer[1]} mode {mode}", file=log, flush=True)
        if mode == "silent":
            continue
        now = time.time()
        if mode == "past":
            now = 3600.0
        elif mode == "skew":
            now += 3 * 3600
        origin = req[40:48]
        if mode == "wrongorigin":
            origin = b"\x01" * 8
        stratum = 0 if mode == "kod" else 2
        ref = b"RATE" if mode == "kod" else b"\x7f\x00\x00\x01"
        pkt = struct.pack(">BBbb", (0 << 6) | (4 << 3) | 4, stratum, 6, -20)
        pkt += struct.pack(">II", 0, 0) + ref + ts(now) + origin + ts(now) + ts(now)
        s.sendto(pkt, peer)


main()
