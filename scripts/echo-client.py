#!/usr/bin/env python3
"""TCP echo check used by smoke.sh: sends random payloads, expects them back."""
import os
import socket
import sys

port = int(sys.argv[1])
ok = True
for n in (1, 3000, 60000):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        msg = os.urandom(n)
        s.sendall(msg)
        s.shutdown(socket.SHUT_WR)
        got = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        s.close()
        good = got == msg
    except OSError as e:
        print(f"client: echo {n} error {e}")
        good = False
    print(f"client: echo {n} {'ok' if good else 'FAILED'}")
    ok = ok and good
sys.exit(0 if ok else 1)
