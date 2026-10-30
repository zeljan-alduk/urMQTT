#!/usr/bin/env python3
"""MQTT acceptance scenarios with the real mosquitto clients (M9, M10).

    scripts/mqtt-scenarios.py PORT [--tls CERTDIR]

Prints one "client: <scenario> ok|FAILED ..." line per scenario and exits
non-zero if any failed. With --tls, every client connects to PORT with the
dev CA and the device certificate matching its client id.
"""
import os
import signal
import subprocess
import sys
import time

args = sys.argv[1:]
TLS = None
if "--tls" in args:
    i = args.index("--tls")
    TLS = args[i + 1]
    del args[i : i + 2]
PORT = args[0]
TIMEOUT = 15
results = []


def base(client_id, cert=None):
    """Connection arguments; `cert` overrides the certificate (path relative
    to the TLS directory without extension, e.g. "negative/rogue-device")."""
    args = ["-h", "127.0.0.1", "-p", PORT, "-V", "mqttv311", "-i", client_id]
    if TLS:
        if cert is None:
            cert = "services/backend" if client_id == "backend" else f"devices/{client_id}"
        args += ["--cafile", os.path.join(TLS, "ca.pem")]
        certfile = os.path.join(TLS, f"{cert}.pem")
        args += ["--cert", certfile, "--key", certfile[:-4] + ".key"]
    return args


def pub(client_id, topic, message, *extra, cert=None):
    r = subprocess.run(["mosquitto_pub", *base(client_id, cert), "-t", topic, "-m", message, *extra],
                       capture_output=True, text=True, timeout=TIMEOUT)
    return r.returncode, r.stderr.strip()


def sub_start(client_id, *extra):
    return subprocess.Popen(["mosquitto_sub", *base(client_id), "-v", *extra],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def sub_wait(p):
    try:
        out, err = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    return out.strip(), err.strip()


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


def settle():
    time.sleep(1.0)


# 1. Publish/subscribe through a wildcard subscription of the backend.
s = sub_start("backend", "-t", "devices/+/telemetry/#", "-q", "1", "-C", "1", "-W", "10")
settle()
rc, err = pub("device-001", "devices/device-001/telemetry/temp", "21.5", "-q", "1")
out, serr = sub_wait(s)
report("pubsub-wildcard", rc == 0 and out == "devices/device-001/telemetry/temp 21.5", f"{out!r} {err} {serr}")

# 2. Retained: published first, delivered to a later subscriber.
rc, err = pub("device-001", "devices/device-001/fw", "1.2.3", "-q", "1", "-r")
s = sub_start("backend", "-t", "devices/+/fw", "-C", "1", "-W", "10")
out, serr = sub_wait(s)
report("retained", rc == 0 and out == "devices/device-001/fw 1.2.3", f"{out!r} {err} {serr}")

# 3. Last Will on a forced disconnect (client process killed, no DISCONNECT).
s = sub_start("backend", "-t", "devices/device-003/status", "-C", "1", "-W", "15", "-R")
settle()
victim = subprocess.Popen(["mosquitto_sub", *base("device-003"), "-t", "devices/device-003/cmd/#",
                           "-k", "60", "--will-topic", "devices/device-003/status",
                           "--will-payload", "offline", "--will-qos", "1"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
settle()
victim.send_signal(signal.SIGKILL)
victim.wait()
out, serr = sub_wait(s)
report("lwt-forced-disconnect", out == "devices/device-003/status offline", f"{out!r} {serr}")

# 4. QoS 1 delivery after reconnect: a persistent session subscribes and
#    leaves, the backend publishes, the device comes back and gets it.
setup = subprocess.run(["mosquitto_sub", *base("device-002"), "-c", "-q", "1", "-t",
                        "devices/device-002/cmd/#", "-E"], capture_output=True, text=True, timeout=TIMEOUT)
rc, err = pub("backend", "devices/device-002/cmd/reboot", "now", "-q", "1")
s = sub_start("device-002", "-c", "-q", "1", "-t", "devices/device-002/cmd/#", "-C", "1", "-W", "10")
out, serr = sub_wait(s)
report("qos1-after-reconnect", setup.returncode == 0 and rc == 0 and out == "devices/device-002/cmd/reboot now",
       f"{out!r} {setup.stderr.strip()} {err} {serr}")

# 5. ACL: a device may not subscribe to another device's commands.
r = subprocess.run(["mosquitto_sub", *base("device-001"), "-t", "devices/device-002/cmd/#", "-E"],
                   capture_output=True, text=True, timeout=TIMEOUT)
denied = "denied" in (r.stdout + r.stderr).lower()
report("acl-subscribe-denied", denied, (r.stdout + r.stderr).strip())

# 6. H3: an identity keeps at most limits.max_retained_per_device (32 in
#    dev) retained messages; the 33rd is delivered but not retained.
for i in range(33):
    pub("device-005", f"devices/device-005/r/{i}", "v", "-r", "-q", "1")
s = sub_start("backend", "-t", "devices/device-005/r/#", "-W", "4")
out, serr = sub_wait(s)
held = [line for line in out.splitlines() if line.startswith("devices/device-005/r/")]
report("retained-limit", len(held) == 32, f"{len(held)} retained {serr}")
for i in range(33):
    pub("device-005", f"devices/device-005/r/{i}", "", "-r", "-n")

if TLS:
    # 7-10. Each of these must be refused (PROMPT M10 acceptance).
    for name, cid, cert in [
        ("tls-wrong-ca-rejected", "device-001", "negative/rogue-device"),
        ("tls-expired-rejected", "device-002", "negative/expired-device"),
        ("tls-client-id-mismatch-rejected", "device-002", "devices/device-001"),
        ("tls-revoked-rejected", "device-004", "negative/revoked-device"),
    ]:
        rc, err = pub(cid, f"devices/{cid}/telemetry/t", "x", "-q", "1", cert=cert)
        report(name, rc != 0, err)

sys.exit(0 if all(results) else 1)
