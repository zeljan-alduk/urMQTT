#!/usr/bin/env python3
"""A TLS log collector for the smoke scenarios of NEXT-7 (ADR-318).

    logtls-sink.py <port> <cert.pem> <key.pem> <out> <seconds>

Listens on 127.0.0.1:<port> (the guest reaches it as 10.0.2.2:<port> through
QEMU's user network), TLS 1.3 only, no client certificate. Every connection's
bytes are read as RFC 5425 frames (`MSG-LEN SP SYSLOG-MSG`); each message is
written to <out> as `sink: msg <message>`. Connections, closes, handshake
failures and frames that do not parse are written too, so the scenario can
check them. Exits after <seconds>.
"""

import socket
import ssl
import sys
import time


def frames(buf):
    """Splits off the complete frames: returns ([message, ...], rest).
    Raises ValueError on bytes that are not a frame."""
    msgs = []
    while True:
        sp = buf.find(b" ")
        if sp < 0:
            if len(buf) > 10:
                raise ValueError("no length")
            return msgs, buf
        head = buf[:sp]
        if not head.isdigit() or head.startswith(b"0") or len(head) > 9:
            raise ValueError(f"bad length {head[:20]!r}")
        n = int(head)
        if len(buf) < sp + 1 + n:
            return msgs, buf
        msgs.append(buf[sp + 1 : sp + 1 + n])
        buf = buf[sp + 1 + n :]


def main():
    port, cert, key, out_path, seconds = sys.argv[1:6]
    end = time.time() + float(seconds)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", int(port)))
    srv.listen(4)
    srv.settimeout(0.5)
    out = open(out_path, "a", buffering=1)
    out.write(f"sink: listening on {port}\n")
    while time.time() < end:
        try:
            raw, peer = srv.accept()
        except socket.timeout:
            continue
        out.write(f"sink: connection from {peer[0]}\n")
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            out.write(f"sink: handshake failed: {e}\n")
            raw.close()
            continue
        out.write(f"sink: handshake ok, {conn.version()}\n")
        conn.settimeout(0.5)
        buf = b""
        count = 0
        while time.time() < end:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            except (ssl.SSLError, OSError) as e:
                out.write(f"sink: read failed: {e}\n")
                break
            if not data:
                break
            try:
                msgs, buf = frames(buf + data)
            except ValueError as e:
                out.write(f"sink: BAD FRAME: {e}\n")
                break
            for msg in msgs:
                count += 1
                out.write("sink: msg " + msg.decode("utf-8", "replace").replace("\n", " ") + "\n")
        out.write(f"sink: connection closed after {count} message(s)\n")
        try:
            conn.close()
        except OSError:
            pass
    out.write("sink: done\n")


if __name__ == "__main__":
    main()
