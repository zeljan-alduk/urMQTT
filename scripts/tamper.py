#!/usr/bin/env python3
"""Modify a built boot image the way an attacker with write access to it would (H8 tests).

    tamper.py IMAGE --file FILE [--offset N] [--bit B] [--out IMAGE2]
    tamper.py IMAGE --replace OLD NEW [--out IMAGE2]

--file: flips bit B (default 0) of the byte at offset N (default: the middle of the
file) in every complete copy of FILE inside IMAGE. An ISO or a raw disk image holds
the kernel several times (the ISO9660 tree, the El Torito ESP, the installation image
in each), every copy contiguous; all of them are changed.

--replace: replaces every occurrence of the text OLD by NEW (same length; \\n and \\xNN
escapes allowed) anywhere in IMAGE, to edit a limine.conf in place without parsing
the ISO9660 or FAT structures.

Writes to --out (default: in place). Exits 1 when nothing was found: a test must never
pass because it modified nothing. No other tool of the project uses this; it only
builds the negative cases of scripts/smoke.sh.
"""
import argparse
import codecs
import shutil
import sys


def esc(s: str) -> bytes:
    return codecs.decode(s, "unicode_escape").encode("latin-1")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--file")
    ap.add_argument("--offset", type=lambda s: int(s, 0))
    ap.add_argument("--bit", type=int, default=0)
    ap.add_argument("--out")
    ap.add_argument("--replace", nargs=2, metavar=("OLD", "NEW"))
    a = ap.parse_args()
    if bool(a.file) == bool(a.replace):
        print("error: exactly one of --file and --replace", file=sys.stderr)
        return 2

    out = a.out or a.image
    if out != a.image:
        shutil.copyfile(a.image, out)
    with open(out, "r+b") as f:
        img = f.read()
        if a.replace:
            old, new = esc(a.replace[0]), esc(a.replace[1])
            if len(old) != len(new) or not old:
                print("error: --replace needs two texts of the same, non-zero length", file=sys.stderr)
                return 2
            hits = []
            pos = img.find(old)
            while pos >= 0:
                hits.append(pos)
                pos = img.find(old, pos + 1)
            if not hits:
                print(f"error: {a.replace[0]!r} not found in {a.image}", file=sys.stderr)
                return 1
            for pos in hits:
                f.seek(pos)
                f.write(new)
            print(f"tamper: {len(hits)} occurrence(s) of {a.replace[0]!r} replaced in {out}")
            return 0

        ref = open(a.file, "rb").read()
        if len(ref) < 64:
            print("error: reference file too small to find reliably", file=sys.stderr)
            return 2
        head = ref[: min(len(ref), 4096)]
        copies = []
        pos = img.find(head)
        while pos >= 0:
            if img[pos : pos + len(ref)] == ref:
                copies.append(pos)
            pos = img.find(head, pos + 1)
        if not copies:
            print(f"error: no complete copy of {a.file} in {a.image}", file=sys.stderr)
            return 1
        off = a.offset if a.offset is not None else len(ref) // 2
        if not 0 <= off < len(ref):
            print("error: offset outside the file", file=sys.stderr)
            return 2
        for pos in copies:
            f.seek(pos + off)
            f.write(bytes([ref[off] ^ (1 << a.bit)]))
    print(f"tamper: {len(copies)} cop{'y' if len(copies) == 1 else 'ies'} of {a.file} modified in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
