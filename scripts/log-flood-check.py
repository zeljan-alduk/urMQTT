#!/usr/bin/env python3
"""Checks the serial log of a `test=log-flood:MS` run (ADR-090).

Run as the client of smoke.sh's `service` (the argument is the port, unused);
the serial log is named by $SMOKE_LOG. Waits, then checks that every core's
`logflood: core N seq K` lines are all there (no gap from seq 0 to the last
one seen), that no line was dropped or suppressed, and that the timestamps of
the whole log are in order (the drain merges the cores' rings by timestamp;
only the few microseconds between reading the clock and queueing a line can
reorder two cores' lines, so an inversion over 2 ms is a failure).
"""

import os
import re
import sys
import time

WAIT_S = float(os.environ.get("LOG_FLOOD_WAIT", "16"))
LINE = re.compile(r"^\[\s*(\d+)\.(\d{6})\] (\w+)\s+(.*)$")
FLOOD = re.compile(r"^logflood: core (\d+) seq (\d+)$")
MAX_INVERSION_US = 2000


def main() -> int:
    path = os.environ.get("SMOKE_LOG")
    if not path:
        print("FAILED: SMOKE_LOG is not set")
        return 1
    time.sleep(WAIT_S)
    esc = re.compile(r"\x1b\[[0-9;?=]*[A-Za-z]")
    with open(path, errors="replace") as f:
        text = [esc.sub("", ln).rstrip("\r\n") for ln in f]

    seqs: dict[int, list[int]] = {}
    stamps: list[int] = []
    problems: list[str] = []
    for ln in text:
        m = LINE.match(ln)
        if not m:
            continue
        us = int(m.group(1)) * 1_000_000 + int(m.group(2))
        stamps.append(us)
        msg = m.group(4)
        fm = FLOOD.match(msg)
        if fm:
            seqs.setdefault(int(fm.group(1)), []).append(int(fm.group(2)))
        if msg.startswith("log: ") and ("dropped" in msg or "suppressed" in msg):
            problems.append(f"lines lost: {ln}")

    if len(seqs) < 2:
        problems.append(f"only {len(seqs)} core(s) logged flood lines")
    total = 0
    for core, s in sorted(seqs.items()):
        total += len(s)
        if len(s) < 100:
            problems.append(f"core {core}: only {len(s)} flood lines")
        if s != list(range(s[0], s[0] + len(s))):
            missing = sorted(set(range(s[0], s[-1] + 1)) - set(s))
            problems.append(f"core {core}: seq gaps or reordering, missing {missing[:5]}")
        if s[0] != 0:
            problems.append(f"core {core}: first line seen is seq {s[0]}, not 0")

    inversions = 0
    worst = 0
    for a, b in zip(stamps, stamps[1:]):
        if b < a:
            inversions += 1
            worst = max(worst, a - b)
    if worst > MAX_INVERSION_US:
        problems.append(f"timestamps out of order by up to {worst} us")

    if problems:
        for p in problems:
            print(f"FAILED: {p}")
        return 1
    print(
        f"client: log-flood ok ({total} lines from {len(seqs)} cores, none lost, "
        f"{inversions} timestamp inversion(s), worst {worst} us)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
