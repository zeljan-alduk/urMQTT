#!/usr/bin/env python3
"""Broker state across a VM restart (M11), with the real mosquitto clients.

    scripts/mqtt-persist.py PORT --tls CERTDIR --phase 1|2|live1|gone

Phase 1 (fresh disk): a retained message, a persistent session with a
command subscription, a QoS 1 command queued while that device is
offline, and one telemetry PUBLISH. The smoke test then kills QEMU (SIGKILL) and boots again on the
same disk. Phase 2: the retained message and the queued command must be
delivered (the smoke test checks the telemetry record in the boot log).

The live mode (O3, data in RAM, lost on reboot) has its own pair: `live1`
publishes a retained message and reads it back in the same boot; `gone`, on
the next boot of the same medium, checks that it is NOT delivered any more
(and that the broker works: a new retained message is).
"""
import os
import subprocess
import sys
import time

args = sys.argv[1:]
TLS = args[args.index("--tls") + 1]
PHASE = args[args.index("--phase") + 1]
PORT = args[0]
TIMEOUT = 15
results = []


def base(client_id):
    cert = "services/backend" if client_id == "backend" else f"devices/{client_id}"
    certfile = os.path.join(TLS, f"{cert}.pem")
    return ["-h", "127.0.0.1", "-p", PORT, "-V", "mqttv311", "-i", client_id,
            "--cafile", os.path.join(TLS, "ca.pem"), "--cert", certfile, "--key", certfile[:-4] + ".key"]


def run(cmd, *a):
    r = subprocess.run([cmd, *a], capture_output=True, text=True, timeout=TIMEOUT)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def report(name, ok, detail=""):
    results.append(ok)
    print(f"client: {name} {'ok' if ok else 'FAILED'} {detail}".rstrip(), flush=True)


if PHASE == "live1":
    rc1, _, e1 = run("mosquitto_pub", *base("device-001"), "-t", "devices/device-001/fw",
                     "-m", "live-1", "-q", "1", "-r")
    rc2, _, e2 = run("mosquitto_pub", *base("device-001"), "-t", "devices/device-001/telemetry/temp",
                     "-m", "21.5", "-q", "1")
    time.sleep(0.5)
    rc, out, err = run("mosquitto_sub", *base("backend"), "-t", "devices/+/fw", "-v", "-C", "1", "-W", "10")
    report("live-retained", rc1 == rc2 == 0 and rc == 0 and out == "devices/device-001/fw live-1",
           f"{out!r} {e1} {e2} {err}")
elif PHASE == "gone":
    rc1, _, e1 = run("mosquitto_pub", *base("device-003"), "-t", "devices/device-003/fw",
                     "-m", "after-reboot", "-q", "1", "-r")
    # Two retained messages if the old one survived: wait for both.
    rc, out, err = run("mosquitto_sub", *base("backend"), "-t", "devices/+/fw", "-v", "-C", "2", "-W", "4")
    report("live-gone", rc1 == 0 and out == "devices/device-003/fw after-reboot",
           f"{out!r} {e1} {err}")
elif PHASE == "1":
    rc1, _, e1 = run("mosquitto_pub", *base("device-001"), "-t", "devices/device-001/fw",
                     "-m", "2.0.0-persist", "-q", "1", "-r")
    rc2, _, e2 = run("mosquitto_sub", *base("device-002"), "-c", "-q", "1",
                     "-t", "devices/device-002/cmd/#", "-E")
    rc3, _, e3 = run("mosquitto_pub", *base("backend"), "-t", "devices/device-002/cmd/persist",
                     "-m", "queued-while-offline", "-q", "1")
    # One record for the telemetry log (storage.telemetry_topics).
    rc4, _, e4 = run("mosquitto_pub", *base("device-001"), "-t", "devices/device-001/telemetry/temp",
                     "-m", "21.5", "-q", "1")
    # Far longer than one DB batch (5 ms).
    time.sleep(0.5)
    report("persist-phase1", rc1 == rc2 == rc3 == rc4 == 0, f"{e1} {e2} {e3} {e4}")
else:
    rc, out, err = run("mosquitto_sub", *base("backend"), "-t", "devices/+/fw", "-v", "-C", "1", "-W", "10")
    report("persist-retained", rc == 0 and out == "devices/device-001/fw 2.0.0-persist", f"{out!r} {err}")
    rc, out, err = run("mosquitto_sub", *base("device-002"), "-c", "-q", "1", "-v",
                       "-t", "devices/device-002/cmd/#", "-C", "1", "-W", "10")
    report("persist-queued", rc == 0 and out == "devices/device-002/cmd/persist queued-while-offline",
           f"{out!r} {err}")

sys.exit(0 if all(results) else 1)
