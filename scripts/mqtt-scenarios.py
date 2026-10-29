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

PORT = sys.argv[1]
TLS = None
if "--tls" in sys.argv:
    TLS = sys.argv[sys.argv.index("--tls") + 1]
TIMEOUT = 15
results = []


def base(client_id, cert=None):
    args = ["-h", "127.0.0.1", "-p", PORT, "-V", "mqttv311", "-i", client_id]
    if TLS:
        cert = cert or client_id
        args += ["--cafile", os.path.join(TLS, "ca.pem")]
        certfile = os.path.join(TLS, "devices", f"{cert}.pem")
        if cert == "backend":
            certfile = os.path.join(TLS, "services", "backend.pem")
        args += ["--cert", certfile, "--key", certfile[:-4] + ".key"]
    return args


def pub(client_id, topic, message, *extra):
    r = subprocess.run(["mosquitto_pub", *base(client_id), "-t", topic, "-m", message, *extra],
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

sys.exit(0 if all(results) else 1)
