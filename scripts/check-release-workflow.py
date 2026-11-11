#!/usr/bin/env python3
"""Checks the shape of the Release workflow (security review of v0.6.0, SUPPLY-1, ADR-380).

    python3 -I scripts/check-release-workflow.py [.github/workflows/release.yml]

The release key must never be in a job that runs build code: the build runs
third-party code (build.rs files, proc macros, apt packages), and on a hosted
runner every secret a job references is sent to that job's runner when it
starts, where any earlier step can read it. So:

1. exactly one job references secrets.MINISIGN_SECRET_KEY (the signing job), and
   no other secret is referenced anywhere but github.token;
2. the signing job runs in the environment `release` (its protection rules, a
   required reviewer and deployments from `v*` tags only, are set in the
   repository settings), holds no write permission, uses no action but
   actions/checkout (a sparse checkout) and upload-artifact, runs nothing of
   the tagged tree (no make, cargo, scripts/, local actions), and never writes
   the key to a file;
3. the job that runs `make dist` holds no write permission and no secret, and
   runs scripts/check-release-tag.sh (the tag is on main) before it builds;
4. a job with id-token, attestations or contents write builds and checks out
   nothing;
5. the workflow-wide permissions are read-only.

The workflow is read line by line (no YAML library in CI's Python): the jobs
are the two-space-indented keys under `jobs:`. Exit status 1 with one line per
problem.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRET = "secrets.MINISIGN_SECRET_KEY"
BUILD_WORDS = re.compile(r"\b(make|cargo|rustup|npm|npx|node|pip3?|python3?)\b|scripts/|uses:\s*\./")


def jobs_of(text: str) -> tuple[list[str], dict[str, list[str]]]:
    """The lines before `jobs:`, and each job's lines."""
    lines = text.splitlines()
    try:
        start = lines.index("jobs:")
    except ValueError:
        return lines, {}
    jobs: dict[str, list[str]] = {}
    name = None
    for line in lines[start + 1 :]:
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            name = m.group(1)
            jobs[name] = []
        elif re.match(r"^\S", line):
            name = None
        elif name is not None:
            jobs[name].append(line)
    return lines[:start], jobs


def code(lines: list[str]) -> list[str]:
    """The lines without their comments (a `#` after a space, outside a string well enough here)."""
    out = []
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        out.append(re.sub(r"\s+#\s.*$", "", line))
    return out


def permissions(lines: list[str]) -> dict[str, str]:
    """The job's `permissions:` block."""
    perms: dict[str, str] = {}
    inside = False
    for line in lines:
        if re.match(r"^    permissions:\s*$", line):
            inside = True
            continue
        if inside:
            m = re.match(r"^      ([a-z-]+):\s*(\S+)\s*$", line)
            if m:
                perms[m.group(1)] = m.group(2)
                continue
            inside = False
        m = re.match(r"^    permissions:\s*(\S+)\s*$", line)
        if m:
            perms["*"] = m.group(1)
    return perms


def environment(lines: list[str]) -> str | None:
    for i, line in enumerate(lines):
        m = re.match(r"^    environment:\s*(\S+)\s*$", line)
        if m:
            return m.group(1).strip("'\"")
        if re.match(r"^    environment:\s*$", line):
            for nxt in lines[i + 1 :]:
                m = re.match(r"^      name:\s*(\S+)\s*$", nxt)
                if m:
                    return m.group(1).strip("'\"")
                if not nxt.startswith("      "):
                    break
    return None


def check(text: str) -> list[str]:
    problems: list[str] = []
    top, jobs = jobs_of(text)
    if not jobs:
        return ["no jobs"]
    top_code = "\n".join(code(top))
    if re.search(r":\s*write\b|write-all", top_code):
        problems.append("the workflow-wide permissions grant a write permission")
    if SECRET in top_code:
        problems.append(f"{SECRET} is referenced outside a job")
    for name, lines in jobs.items():
        for line in code(lines):
            for m in re.finditer(r"secrets\.([A-Za-z0-9_]+)", line):
                if m.group(1) != "MINISIGN_SECRET_KEY":
                    problems.append(f"job {name}: references the secret {m.group(1)}")
    signers = [n for n, ls in jobs.items() if any(SECRET in x for x in code(ls))]
    if len(signers) != 1:
        problems.append(f"{SECRET} must be referenced by exactly one job, not {signers or 'none'}")
    builders = [n for n, ls in jobs.items() if any(re.search(r"\bmake dist\b", x) for x in code(ls))]
    if not builders:
        problems.append("no job runs make dist")
    for name in signers:
        lines = code(jobs[name])
        body = "\n".join(lines)
        if environment(lines) != "release":
            problems.append(f"job {name} signs but does not run in the environment release")
        perms = permissions(lines)
        if not perms or any(v != "read" and v != "none" for v in perms.values()):
            problems.append(f"job {name} signs and must hold read permissions only, not {perms or 'the defaults'}")
        for line in lines:
            m = re.search(r"uses:\s*(\S+)", line)
            if m and not re.match(r"actions/(checkout|upload-artifact)@[0-9a-f]{40}$", m.group(1)):
                problems.append(f"job {name} signs and uses {m.group(1)}")
            if BUILD_WORDS.search(line):
                problems.append(f"job {name} signs and runs build code: {line.strip()}")
        if re.search(r"uses:\s*actions/checkout@", body) and "sparse-checkout:" not in body:
            problems.append(f"job {name} signs and checks out the whole tree (a sparse checkout of minisign.pub only)")
        if re.search(r"RUNNER_TEMP|minisign\.key|>\s*\"?\$\{?key|>\s*\S*\.key\b|tee\s", body):
            problems.append(f"job {name} writes the release key to a file (pass it to minisign through a pipe)")
        if name in builders:
            problems.append(f"job {name} both builds and signs")
    for name in builders:
        lines = code(jobs[name])
        perms = permissions(lines)
        writes = [k for k, v in perms.items() if v not in ("read", "none")]
        if not perms or writes:
            problems.append(f"job {name} builds and must hold read permissions only, not {writes or 'the defaults'}")
        if any("secrets." in x for x in lines):
            problems.append(f"job {name} builds and references a secret")
        tag_check = next((i for i, x in enumerate(lines) if "scripts/check-release-tag.sh" in x), None)
        build = next(i for i, x in enumerate(lines) if re.search(r"\bmake dist\b", x))
        if tag_check is None or tag_check > build:
            problems.append(f"job {name} builds without checking first that the tag is on main (scripts/check-release-tag.sh)")
    for name, ls in jobs.items():
        lines = code(ls)
        perms = permissions(lines)
        writes = [k for k, v in perms.items() if v not in ("read", "none")]
        if not writes or name in signers:
            continue
        for line in lines:
            if BUILD_WORDS.search(line) or re.search(r"uses:\s*actions/checkout@", line):
                problems.append(f"job {name} holds {', '.join(writes)} write and runs or checks out code: {line.strip()}")
    return problems


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".github/workflows/release.yml"
    problems = check(path.read_text(encoding="utf-8"))
    for p in problems:
        print(f"{path}: {p}", file=sys.stderr)
    if not problems:
        print(f"{path}: the release key is only in the signing job, which builds nothing (ADR-380)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
