#!/usr/bin/env python3
"""Checks the JSON document of the diagnostic entry (O4) in a serial log.

  scripts/diag-check.py LOG [--disk-state installed|blank|foreign] [--write skipped|done]

Prints `diag-json ok: ...` and exits 0 if the document parses, has the keys
the dashboard shows and sane values; otherwise prints why and exits 1.
"""
import json
import re
import sys


def fail(msg):
    print(f"diag-json FAILED: {msg}")
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args:
        fail("usage: diag-check.py LOG [--disk-state S] [--write W]")
    log, opts = args[0], dict(zip(args[1::2], args[2::2]))
    text = open(log, "r", errors="replace").read()
    lines = [
        re.sub(r"\x1b\[[0-9;?=]*[A-Za-z]", "", ln).rstrip("\r")
        for ln in text.split("\n")
        if "URMQTT-DIAG-JSON " in ln
    ]
    if len(lines) != 1:
        fail(f"expected one JSON line, found {len(lines)}")
    try:
        d = json.loads(lines[0].split("URMQTT-DIAG-JSON ", 1)[1])
    except ValueError as e:
        fail(f"not valid JSON: {e}")

    for key in ("urmqtt_diag", "version", "arch", "env", "hypervisor", "cpu", "memory",
                "pci", "disks", "nics", "time", "firmware", "ram", "crypto"):
        if key not in d:
            fail(f"missing key {key}")
    if d["urmqtt_diag"] != 1:
        fail("unknown schema version")
    cpu = d["cpu"]
    for key in ("vendor", "model", "identity", "logical", "features", "crypto_units", "crypto_backend"):
        if key not in cpu:
            fail(f"missing cpu.{key}")
    if not cpu["vendor"] or not cpu["crypto_backend"] or cpu["logical"] < 1:
        fail("cpu facts are empty")
    m = d["memory"]
    if not (0 < m["usable_bytes"] <= m["total_bytes"]) or m["total_bytes"] < 64 << 20:
        fail(f"implausible memory {m}")
    if not d["pci"] or not all("bdf" in p and "vendor" in p and "class" in p for p in d["pci"]):
        fail("pci list is empty or malformed")
    if d["firmware"]["kind"] not in ("BIOS", "UEFI (x86-64)", "UEFI (aarch64)", "UEFI (32-bit)"):
        fail(f"firmware {d['firmware']}")
    t = d["time"]
    if t["counter_hz"] < 1_000_000:
        fail("implausible time base frequency")
    if d["arch"] == "x86_64" and t["invariant_tsc"] is None:
        fail("x86 time facts missing")
    ram = d["ram"]
    if not ram or ram["read_mib_s"] <= 0 or ram["write_mib_s"] <= 0 or ram["copy_mib_s"] <= 0:
        fail("ram throughput missing")
    lat = ram["latency"]
    if len(lat) < 8 or lat[0]["bytes"] != 4096:
        fail("ram latency curve missing")
    if not (0 < lat[0]["ns"] and lat[-1]["ns"] > lat[0]["ns"]):
        fail(f"latency does not grow with the working set: {lat[0]} .. {lat[-1]}")
    c = d["crypto"]
    if not c or c["handshake_us"] <= 0 or c["x25519_us"] <= 0 or c["ecdsa_verify_us"] <= 0:
        fail("crypto figures missing")
    if c["handshake_ticks"] <= 0 or c["aes_gcm_mib_s"] <= 0 or c["sha256_mib_s"] <= 0:
        fail("crypto figures missing")

    want = opts.get("--disk-state")
    if want:
        disks = [x for x in d["disks"] if x["state"] == want]
        if len(disks) != 1:
            fail(f"expected one {want} disk, got {[x['state'] for x in d['disks']]}")
        k = disks[0]
        if not k["seq_read"] or k["seq_read"]["mib_s"] <= 0:
            fail("sequential read missing")
        r = k["rand_read"]
        if not r or r["iops"] <= 0 or r["block"] != 4096:
            fail("random read missing")
        lt = r["latency_ns"]
        if not (0 < lt["min"] <= lt["p50"] <= lt["p90"] <= lt["p99"] <= lt["max"]) or lt["samples"] < 100:
            fail(f"latency percentiles {lt}")
        w = k["seq_write"]
        wanted = opts.get("--write")
        if wanted and w["status"] != wanted:
            fail(f"seq_write is {w}, wanted {wanted}")
        if w["status"] == "done" and not w["verified"]:
            fail("write test not verified")
        print(f"diag-json ok: disk {want}, seq_write {w['status']}, {d['arch']}")
    else:
        print(f"diag-json ok: {len(d['disks'])} disk(s), {d['arch']}")


main()
