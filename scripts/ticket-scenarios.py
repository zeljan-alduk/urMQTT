#!/usr/bin/env python3
"""H2 session-ticket scenarios against a running urMQTT VM (smoke.sh).

    ticket-scenarios.py <deploy dir> rotation <interval s> <port>
    ticket-scenarios.py <deploy dir> restart <go file> <port>

rotation: the image runs with `test=ticket-rotate:<interval>`. A ticket
issued late in the first key's interval still resumes after the rotation
(the previous key opens it); a resumption right after a full handshake
works too.

restart: a ticket is taken, then the script waits until <go file> exists
(smoke.sh reboots the VM meanwhile) and offers it to the new boot: it must
not resume (per-boot keys), and the full handshake must succeed.

Prints "client: <name> ok" or "client: <name> FAILED: <why>".
"""
import os
import socket
import ssl
import sys
import time

DIR = sys.argv[1]
MODE = sys.argv[2]
ARG = sys.argv[3]
PORT = int(sys.argv[4])
TIMEOUT = 30


def report(name, ok, detail=""):
    print(f"client: {name} {'ok' if ok else 'FAILED: ' + detail}", flush=True)


def context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(os.path.join(DIR, "ca.pem"))
    ctx.load_cert_chain(os.path.join(DIR, "devices/device-001.pem"),
                        os.path.join(DIR, "devices/device-001.key"))
    return ctx


CTX = context()


def connect(session=None):
    """One MQTT CONNECT over TLS. Returns (resumed, new session)."""
    raw = socket.create_connection(("127.0.0.1", PORT), timeout=TIMEOUT)
    s = CTX.wrap_socket(raw, server_hostname="localhost", session=session)
    body = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x0adevice-001"
    s.sendall(bytes([0x10, len(body)]) + body)
    ack = s.recv(4)
    if ack[:2] != b"\x20\x02" or ack[3:4] != b"\x00":
        raise RuntimeError(f"CONNACK {ack!r}")
    # The NewSessionTicket follows the handshake; CONNACK came after it.
    resumed, sess = s.session_reused, s.session
    s.sendall(b"\xe0\x00")  # DISCONNECT
    s.close()
    if sess is None or not sess.has_ticket:
        raise RuntimeError("no session ticket received")
    return resumed, sess


def rotation(interval):
    t0 = time.monotonic()
    resumed, first = connect()
    if resumed:
        return report("ticket-first-full", False, "first connection resumed")
    resumed, _ = connect(first)
    report("ticket-resume", resumed, "an immediate resumption did a full handshake")
    # Late in the first key's interval: a fresh ticket under that key.
    time.sleep(max(0.0, 0.6 * interval - (time.monotonic() - t0)))
    resumed, late = connect()
    # After the rotation, within that ticket's lifetime: the previous key.
    time.sleep(max(0.0, 1.4 * interval - (time.monotonic() - t0)))
    resumed, _ = connect(late)
    report("ticket-previous-key", resumed,
           "a ticket within its lifetime did not resume after the rotation")


def restart(go):
    resumed, sess = connect()
    resumed, sess2 = connect(sess)
    report("ticket-resume-before-restart", resumed, "no resumption on the same boot")
    print("client: ticket held", flush=True)
    deadline = time.monotonic() + 600
    while not os.path.exists(go):
        if time.monotonic() > deadline:
            return report("ticket-after-restart", False, "never told to continue")
        time.sleep(0.2)
    try:
        resumed, _ = connect(sess2)
    except Exception as e:  # noqa: BLE001 - reported
        return report("ticket-after-restart", False, f"handshake failed: {e}")
    report("ticket-after-restart", not resumed, "a ticket from the previous boot resumed")


try:
    if MODE == "rotation":
        rotation(int(ARG))
    elif MODE == "restart":
        restart(ARG)
    else:
        sys.exit(f"unknown mode {MODE}")
except Exception as e:  # noqa: BLE001 - reported
    report(f"ticket-{MODE}", False, str(e))
