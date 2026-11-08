#!/usr/bin/env python3
# TCP recording proxy for MQTT packet-capture fixtures (stdlib only).
#
#   scripts/mqtt-record.py --listen 127.0.0.1:28832 --upstream 127.0.0.1:28831 \
#       --out crates/mqtt/tests/fixtures/v5 --name pub-qos0 [--count N]
#
# Accepts client connections one after another, forwards bytes both ways to
# the upstream broker, and writes the raw byte streams of each connection to
#   OUT/NAME.c2s.bin  (client -> server)
#   OUT/NAME.s2c.bin  (server -> client)
# With --count N > 1 the files are numbered NAME-1, NAME-2, ... in accept order.
# Existing files are replaced. Exits once N connections have closed (default 1).
# Prints "READY" on stdout once listening, so a driver can wait for it.
import argparse
import os
import socket
import sys
import threading


def hostport(s):
    host, _, port = s.rpartition(":")
    return host, int(port)


def pump(src, dst, out_path, done):
    with open(out_path, "wb") as f:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                f.write(data)
                f.flush()
                dst.sendall(data)
        except OSError:
            pass
    # Propagate the half-close (or the error) to the other side.
    for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
        try:
            s.shutdown(how)
        except OSError:
            pass
    done.set()


def serve_one(client, upstream, out, name):
    server = socket.create_connection(upstream)
    for s in (client, server):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    d1, d2 = threading.Event(), threading.Event()
    t1 = threading.Thread(target=pump, args=(client, server, os.path.join(out, name + ".c2s.bin"), d1))
    t2 = threading.Thread(target=pump, args=(server, client, os.path.join(out, name + ".s2c.bin"), d2))
    t1.start()
    t2.start()
    # Once either direction ends, give the other a moment to drain, then
    # close both so the remaining pump ends too.
    while not (d1.is_set() or d2.is_set()):
        d1.wait(0.05)
    d1.wait(2.0)
    d2.wait(2.0)
    for s in (client, server):
        try:
            s.close()
        except OSError:
            pass
    t1.join()
    t2.join()


def main():
    ap = argparse.ArgumentParser(description="MQTT TCP recording proxy")
    ap.add_argument("--listen", required=True, type=hostport)
    ap.add_argument("--upstream", required=True, type=hostport)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--count", type=int, default=1)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(a.listen)
    ls.listen(a.count)
    print("READY", flush=True)
    threads = []
    for i in range(a.count):
        client, _ = ls.accept()
        name = a.name if a.count == 1 else f"{a.name}-{i + 1}"
        t = threading.Thread(target=serve_one, args=(client, a.upstream, a.out, name))
        t.start()
        threads.append(t)
    ls.close()
    for t in threads:
        t.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
