#!/usr/bin/env python3
"""Control channel and identity lifecycle scenarios (H1).

    scripts/control-scenarios.py CERTDIR TOOL [--allowlist] PORT

TOOL is the `urmqtt-control` binary. Prints one "client: <scenario> ok|FAILED"
line per scenario and exits non-zero if any failed. The serial log is
checked by smoke.sh for the matching broker lines (applied, rejected:
<reason>, live connections closed).

Without --allowlist (registry "open"):
  control-revoke-live   a connected device is revoked: disconnected within 1 s,
                        refused on reconnect, admitted again after unrevoke
  control-forged        signed with another key: ignored
  control-replay        the same message twice: the second is ignored
  control-expired       validity window in the past: ignored
  control-from-device   a device publishes a valid message: ignored
  bootstrap-role        a bootstrap identity reaches provision/{id}/# only
  ca-rotation           devices of both operational CAs are admitted
With --allowlist (registry "allowlist", from the dev command line):
  registry-allowlist    unknown refused; allowed then admitted; disallowed
                        then disconnected and refused
"""
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time

# smoke.sh's `service` appends the port to the client's arguments.
CERTS, TOOL, PORT = [a for a in sys.argv[1:] if not a.startswith("--")]
ALLOWLIST = "--allowlist" in sys.argv[1:]
TIMEOUT = 15
results = []
TMP = tempfile.mkdtemp(prefix="urmqtt-control-")


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


def path(p):
    return os.path.join(CERTS, p)


def mqtt_args(client_id, cert):
    return ["-h", "127.0.0.1", "-p", PORT, "-V", "mqttv311", "-i", client_id,
            "--cafile", path("ca.pem"), "--cert", path(cert + ".pem"), "--key", path(cert + ".key")]


def pub(client_id, cert, topic, *extra):
    r = subprocess.run(["mosquitto_pub", *mqtt_args(client_id, cert), "-t", topic, "-m", "x", "-q", "1", *extra],
                       capture_output=True, text=True, timeout=TIMEOUT)
    return r.returncode == 0, r.stderr.strip()


def sub_once(client_id, cert, topic):
    """Subscribes and reports the SUBACK outcome (granted or refused)."""
    r = subprocess.run(["mosquitto_sub", *mqtt_args(client_id, cert), "-t", topic, "-E"],
                       capture_output=True, text=True, timeout=TIMEOUT)
    out = (r.stdout + r.stderr).lower()
    return r.returncode == 0 and "denied" not in out, out.strip()


def holder(client_id, cert):
    """An MQTT connection over TLS that stays open until the broker closes it
    (a raw socket, so the close is seen at once, not at a client library's
    next poll). Returns the socket, or None if the broker refused it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(path("ca.pem"))
    ctx.load_cert_chain(path(cert + ".pem"), path(cert + ".key"))
    raw = socket.create_connection(("127.0.0.1", int(PORT)), timeout=TIMEOUT)
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    cid = client_id.encode()
    body = b"\x00\x04MQTT\x04\x02\x00\x3c" + len(cid).to_bytes(2, "big") + cid
    s.sendall(bytes([0x10, len(body)]) + body)
    ack = s.recv(4)
    return s if ack[:2] == b"\x20\x02" and ack[3:4] == b"\x00" else None


def control(command, *items, key="control.key", operator="services/operator", out=None, extra=()):
    args = [TOOL, command, *items, "--env", "dev", "--key", path(key) if not os.path.isabs(key) else key,
            "--port", PORT, "--ca", path("ca.pem"),
            "--client-cert", path(operator + ".pem"), "--client-key", path(operator + ".key"), *extra]
    if out:
        args += ["--out", out]
    r = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
    return r.returncode == 0, r.stderr.strip()


def publish_file(f, operator="services/operator"):
    r = subprocess.run([TOOL, "publish-file", f, "--port", PORT, "--ca", path("ca.pem"),
                        "--client-cert", path(operator + ".pem"), "--client-key", path(operator + ".key")],
                       capture_output=True, text=True, timeout=TIMEOUT)
    return r.returncode == 0, r.stderr.strip()


def settle(s=0.5):
    time.sleep(s)


def closed_within(s, seconds):
    """Whether the broker closes `s` within `seconds` (EOF or reset)."""
    deadline = time.monotonic() + seconds
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            s.settimeout(left)
            if not s.recv(4096):
                return True
    except (socket.timeout, TimeoutError):
        return False
    except (ssl.SSLError, OSError):
        return True
    finally:
        s.close()


if not ALLOWLIST:
    # control-revoke-live
    h = holder("device-003", "devices/device-003")
    alive = h is not None
    ok, err = control("revoke", "--cert", path("devices/device-003.pem"))
    t0 = time.monotonic()
    gone = alive and closed_within(h, 1.0)
    dt = time.monotonic() - t0
    refused, rerr = pub("device-003", "devices/device-003", "devices/device-003/x")
    report("control-revoke-live", alive and ok and gone and not refused,
           f"closed after {dt:.3f} s, reconnect {'refused' if not refused else 'ADMITTED'} {err}")
    ok2, err2 = control("unrevoke", "--cert", path("devices/device-003.pem"))
    settle()
    back, berr = pub("device-003", "devices/device-003", "devices/device-003/x")
    report("control-unrevoke", ok2 and back, f"{err2} {berr}")

    # control-forged: another Ed25519 key.
    rogue = os.path.join(TMP, "rogue.key")
    subprocess.run([os.environ.get("OPENSSL", "openssl"), "genpkey", "-algorithm", "ed25519", "-out", rogue],
                   check=True, capture_output=True)
    ok, err = control("revoke", "--cert", path("devices/device-001.pem"), key=rogue)
    settle()
    still, serr = pub("device-001", "devices/device-001", "devices/device-001/x")
    report("control-forged", ok and still, f"{err} {serr}")

    # control-replay: a valid message, then the same bytes again. The first
    # revokes a serial nobody uses.
    msg = os.path.join(TMP, "replay.bin")
    ok, err = control("revoke", "--serial", "0badc0de", out=msg)
    ok2, err2 = publish_file(msg)
    settle()
    report("control-replay", ok and ok2, f"{err} {err2}")

    # control-expired: a window that ended long ago.
    ok, err = control("revoke", "--cert", path("devices/device-001.pem"),
                      extra=("--not-before", "1000000000", "--valid-for", "60"))
    settle()
    still, serr = pub("device-001", "devices/device-001", "devices/device-001/x")
    report("control-expired", ok and still, f"{err} {serr}")

    # control-from-device: correctly signed, but published by a device.
    ok, err = control("revoke", "--cert", path("devices/device-002.pem"), operator="devices/device-001")
    settle()
    still, serr = pub("device-002", "devices/device-002", "devices/device-002/x")
    report("control-from-device", ok and still, f"{err} {serr}")

    # bootstrap-role: provision/{id}/# only.
    boot = "bootstrap/device-006"
    p_ok, _ = pub("device-006", boot, "provision/device-006/csr")
    s_ok, _ = sub_once("device-006", boot, "provision/device-006/#")
    s_dev, sout = sub_once("device-006", boot, "devices/device-006/cmd/#")
    persistent, perr = pub("device-006", boot, "provision/device-006/csr", "--disable-clean-session")
    report("bootstrap-role", p_ok and s_ok and not s_dev and not persistent,
           f"pub={p_ok} sub-provision={s_ok} sub-devices={s_dev} persistent={persistent} {perr}")

    # ca-rotation: one device per operational CA.
    a, aerr = pub("device-001", "devices/device-001", "devices/device-001/x")
    b, berr = pub("device-005", "devices/device-005", "devices/device-005/x")
    report("ca-rotation", a and b, f"{aerr} {berr}")
else:
    # registry-allowlist
    unknown, uerr = pub("device-001", "devices/device-001", "devices/device-001/x")
    svc, serr = pub("backend", "services/backend", "devices/device-001/cmd/x")
    ok, err = control("allow", "--id", "device-001")
    settle()
    admitted, aerr = pub("device-001", "devices/device-001", "devices/device-001/x")
    h = holder("device-001", "devices/device-001")
    alive = h is not None
    ok2, err2 = control("disallow", "--id", "device-001")
    t0 = time.monotonic()
    gone = alive and closed_within(h, 1.0)
    dt = time.monotonic() - t0
    refused, rerr = pub("device-001", "devices/device-001", "devices/device-001/x")
    report("registry-allowlist",
           not unknown and svc and ok and admitted and alive and ok2 and gone and not refused,
           f"unknown={unknown} service={svc} admitted={admitted} live-closed={gone} after {dt:.3f} s, "
           f"after-disallow={refused} {err} {err2}")

sys.exit(0 if all(results) else 1)
