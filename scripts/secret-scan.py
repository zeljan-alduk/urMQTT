#!/usr/bin/env python3
"""Looks for the bytes of the server private key and the disk key in logs (H8, image secrecy).

    secret-scan.py --server-key server.key [--disk-key disk.key] [--found-in FILE]... FILE...

The files after the options are logs and comparison artifacts (serial logs, build logs,
the transcript of `make repro`): none of them may contain the keys in any form this
tool knows. Each key gives these needles: the raw bytes, lower and upper case hex, hex
with spaces and with colons, base64 (all three alignments of a substring), and for an
EC private key (PEM, PKCS#8 or SEC1) the 32-byte private scalar in the same forms and
the DER file whole. A disk key (64 raw bytes or 128 hex digits) is also searched as its
two 32-byte halves.

--found-in FILE names a file that DOES hold the keys (the image, the configuration blob):
the scan must find at least one needle there. Without that control a scan that cannot see
anything would pass; with it, the result says it can.

Exit status: 0 clean (and the controls found), 1 a leak or a blind scan, 2 usage.
"""
import argparse
import base64
import re
import subprocess
import sys


def der_of(path: str) -> bytes:
    """The DER of a private key file, whatever it was written as (PEM, DER)."""
    raw = open(path, "rb").read()
    if b"-----BEGIN" in raw:
        out = subprocess.run(
            ["openssl", "pkey", "-in", path, "-outform", "DER"],
            capture_output=True,
            check=False,
        )
        if out.returncode != 0:
            sys.exit(f"secret-scan: openssl could not read {path}: {out.stderr.decode()[:200]}")
        return out.stdout
    return raw


def ec_scalar(der: bytes):
    """The 32-byte private scalar of a P-256 ECPrivateKey inside `der` (SEC1 or PKCS#8)."""
    # ECPrivateKey ::= SEQUENCE { version INTEGER 1, privateKey OCTET STRING (32 bytes), ...}
    m = re.search(rb"\x02\x01\x01\x04\x20(.{32})", der, re.S)
    return m.group(1) if m else None


def forms(b: bytes, label: str):
    """(label, needle) for a byte string in the encodings a log could show it in."""
    out = [(f"{label} raw", b)]
    hx = b.hex()
    out += [(f"{label} hex", hx.encode()), (f"{label} HEX", hx.upper().encode())]
    n = min(len(b), 16)
    out += [
        (f"{label} spaced hex", " ".join(f"{x:02x}" for x in b[:n]).encode()),
        (f"{label} colon hex", ":".join(f"{x:02x}" for x in b[:n]).encode()),
        (f"{label} 0x hex", ", ".join(f"0x{x:02x}" for x in b[:n]).encode()),
    ]
    # base64 of a substring is not the substring of the base64: all three alignments.
    for skip in range(3):
        chunk = b[skip:]
        chunk = chunk[: len(chunk) - len(chunk) % 3]
        if len(chunk) >= 12:
            out.append((f"{label} base64+{skip}", base64.b64encode(chunk)[:64]))
    return out


def needles(server_key, disk_key):
    out = []
    if server_key:
        der = der_of(server_key)
        out += forms(der[:96], "server key DER")
        out.append(("server key DER (whole)", der))
        sc = ec_scalar(der)
        if sc:
            out += forms(sc, "server key scalar")
        # The PEM body: any whole line of it.
        raw = open(server_key, "rb").read()
        for line in raw.splitlines():
            if len(line) >= 32 and not line.startswith(b"-----"):
                out.append(("server key PEM line", line.strip()))
    if disk_key:
        raw = open(disk_key, "rb").read().strip()
        if len(raw) in (128, 129) and re.fullmatch(rb"[0-9a-fA-F]+", raw):
            key = bytes.fromhex(raw.decode())
        else:
            key = raw
        if len(key) != 64:
            sys.exit(f"secret-scan: {disk_key} is not a 64-byte key ({len(key)} bytes)")
        out += forms(key, "disk key")
        out += forms(key[:32], "disk key half 1")
        out += forms(key[32:], "disk key half 2")
    return out


# The escapes and carriage returns a console log is full of break a needle that spans a line;
# search the raw bytes and the same bytes with them stripped.
CSI = re.compile(rb"\x1b\[[0-9;?=]*[A-Za-z]")


def scan(data: bytes, needle_list):
    plain = CSI.sub(b"", data).replace(b"\r", b"")
    hits = []
    for label, n in needle_list:
        if len(n) < 8:
            continue
        low = n.lower()
        if n in data or n in plain or low in plain.lower():
            hits.append(label)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-key")
    ap.add_argument("--disk-key")
    ap.add_argument("--found-in", action="append", default=[])
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    if not (a.server_key or a.disk_key) or not (a.files or a.found_in):
        ap.error("a key and at least one file are required")
    nl = needles(a.server_key, a.disk_key)
    bad = 0
    for f in a.found_in:
        hits = scan(open(f, "rb").read(), nl)
        if hits:
            print(f"secret-scan: control {f}: the scan finds {len(hits)} needle(s) ({hits[0]}, ...): it can see the keys")
        else:
            print(f"secret-scan: control {f}: NO needle found in a file that holds the keys: the scan is blind")
            bad = 1
    for f in a.files:
        hits = scan(open(f, "rb").read(), nl)
        if hits:
            print(f"secret-scan: LEAK in {f}: {', '.join(sorted(set(hits)))}")
            bad = 1
        else:
            print(f"secret-scan: clean {f} ({len(nl)} needles)")
    return bad


if __name__ == "__main__":
    sys.exit(main())
