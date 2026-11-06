#!/usr/bin/env python3
"""Keeps docs/KNOWN-ISSUES.md in step with the documents it cites.

Every reference in docs/KNOWN-ISSUES.md must exist where it points:

  H0-W8, H8-W1, A255-W2, ...   a row of a weakness table in docs/AUDIT.md
                               (and that row must still be open: a row whose
                               weakness is struck through, ~~like this~~, is
                               fixed, so citing it as a known issue is stale)
  NOW-2, NEXT-1, LATER-7       an item of docs/ROADMAP.md ("**NOW-2. ...")
  D-3                          a row of the decisions table of docs/ROADMAP.md
  ADR-038                      a heading of docs/DECISIONS.md ("## ADR-038 ...")

It fails, listing every problem, if one does not. Run it after editing either
side: CI runs it in the Lint job.

Usage: scripts/check-known-issues.py [--root DIR]
"""

import pathlib
import re
import sys

AUDIT_ID = re.compile(r"\b((?:H\d+|A\d+)-W\d+)\b")
ROADMAP_ID = re.compile(r"\b((?:NOW|NEXT|LATER)-\d+)\b")
DECISION_ID = re.compile(r"(?<![A-Za-z0-9-])(D-\d+)\b")
ADR_ID = re.compile(r"\bADR-(\d{3})\b")


def main():
    args = sys.argv[1:]
    root = pathlib.Path(args[args.index("--root") + 1]) if "--root" in args else pathlib.Path(__file__).resolve().parent.parent
    known = (root / "docs/KNOWN-ISSUES.md").read_text(encoding="utf-8")
    audit = (root / "docs/AUDIT.md").read_text(encoding="utf-8")
    roadmap = (root / "docs/ROADMAP.md").read_text(encoding="utf-8")
    decisions = (root / "docs/DECISIONS.md").read_text(encoding="utf-8")

    # AUDIT.md weakness rows: "| H0-W8 | **...** | ..." ; fixed ones start the weakness cell with ~~.
    audit_rows = {}
    for line in audit.splitlines():
        m = re.match(r"^\|\s*((?:H\d+|A\d+)-W\d+)\s*\|\s*(.*?)\s*\|", line)
        if m:
            audit_rows[m.group(1)] = m.group(2).startswith("~~")
    roadmap_items = set(re.findall(r"^\*\*((?:NOW|NEXT|LATER)-\d+)\.", roadmap, re.M))
    decision_rows = set(re.findall(r"^\|\s*(D-\d+)\s*\|", roadmap, re.M))
    adrs = set(re.findall(r"^#{2,3} ADR-(\d{3})\b", decisions, re.M))

    problems = []
    cited = {"audit": set(), "roadmap": set(), "decision": set(), "adr": set()}
    for n, line in enumerate(known.splitlines(), 1):
        for ref in AUDIT_ID.findall(line):
            cited["audit"].add(ref)
            if ref not in audit_rows:
                problems.append(f"line {n}: {ref} is not a row of docs/AUDIT.md")
            elif audit_rows[ref]:
                problems.append(f"line {n}: {ref} is marked fixed in docs/AUDIT.md (struck through): update the entry")
        for ref in ROADMAP_ID.findall(line):
            cited["roadmap"].add(ref)
            if ref not in roadmap_items:
                problems.append(f"line {n}: {ref} is not an item of docs/ROADMAP.md")
        for ref in DECISION_ID.findall(line):
            cited["decision"].add(ref)
            if ref not in decision_rows:
                problems.append(f"line {n}: {ref} is not a decision row of docs/ROADMAP.md")
        for num in ADR_ID.findall(line):
            cited["adr"].add(num)
            if num not in adrs:
                problems.append(f"line {n}: ADR-{num} is not a heading of docs/DECISIONS.md")

    for p in problems:
        print(f"docs/KNOWN-ISSUES.md: {p}", file=sys.stderr)
    if problems:
        return 1
    print(
        "check-known-issues: ok ({} AUDIT ids, {} ROADMAP items, {} decisions, {} ADRs cited)".format(
            len(cited["audit"]), len(cited["roadmap"]), len(cited["decision"]), len(cited["adr"])
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
