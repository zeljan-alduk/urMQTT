#!/usr/bin/env python3
"""Generates the trusted-computing-base inventory for docs/AUDIT.md (H0).

    scripts/audit-inventory.py           write docs/audit/inventory.md and docs/audit/unsafe.md
    scripts/audit-inventory.py --check   fail if either file is out of date

The output is deterministic (sorted, no dates) so CI can diff it. Line counts
are non-blank lines, comments included; "src" includes inline unit tests.
Dependency sizes come from the Cargo registry sources of the exact locked
versions (run `cargo fetch` first).
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "audit"
KERNEL_TARGET = "aarch64-unknown-none"

UNSAFE_PATTERNS = [
    ("block", re.compile(r"\bunsafe\s*\{")),
    # A named function, not a function-pointer type such as `unsafe extern "C" fn(...)`.
    ("fn", re.compile(r"\bunsafe\s+(?:extern\s+\"[^\"]*\"\s+)?fn\s+[A-Za-z_]")),
    ("impl", re.compile(r"\bunsafe\s+impl\b")),
    ("extern block", re.compile(r"\bunsafe\s+extern\s+\"[^\"]*\"\s*\{")),
    ("attribute", re.compile(r"#\[unsafe\(")),
]
LINT_ATTR = re.compile(r"#!\[(forbid|deny|allow)\(unsafe_code\)\]")


def nonblank(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def rust_files(d):
    return sorted(p for p in Path(d).rglob("*.rs") if "target" not in p.parts)


def strip_comment(line):
    # Good enough for an inventory: ignore line comments, keep code.
    i = line.find("//")
    return line if i < 0 else line[:i]


def workspace_packages():
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], cwd=ROOT
        )
    )
    pkgs = []
    for p in meta["packages"]:
        d = Path(p["manifest_path"]).parent
        pkgs.append((p["name"], d.relative_to(ROOT)))
    return sorted(pkgs)


def test_lines(lines):
    """Indices of lines inside `#[cfg(test)]` items (brace-matched)."""
    skip = set()
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("#[cfg(test)]"):
            depth, started, j = 0, False, i
            while j < len(lines):
                code = strip_comment(lines[j])
                depth += code.count("{") - code.count("}")
                started = started or "{" in code
                skip.add(j)
                if started and depth <= 0 or (not started and code.rstrip().endswith(";")):
                    break
                j += 1
            i = j
        i += 1
    return skip


def unsafe_scan(d):
    """Unsafe sites in non-test code (`tests.rs` files and `#[cfg(test)]` items excluded)."""
    found = []
    for f in rust_files(ROOT / d / "src"):
        if f.name == "tests.rs":
            continue
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        tests = test_lines(lines)
        for i, raw in enumerate(lines):
            if i in tests:
                continue
            code = strip_comment(raw)
            for kind, pat in UNSAFE_PATTERNS:
                if not pat.search(code):
                    continue
                # A justification: `// SAFETY:` (blocks, impls) or a `# Safety`
                # doc section (fns) shortly before, or on the same line.
                window = lines[max(0, i - 12) : i + 1]
                justified = any("SAFETY" in w or "# Safety" in w for w in window)
                found.append((str(f.relative_to(ROOT)), i + 1, kind, justified))
    return found


def lint_level(d):
    for entry in ("src/lib.rs", "src/main.rs"):
        p = ROOT / d / entry
        if p.exists():
            m = LINT_ATTR.search(p.read_text(encoding="utf-8", errors="replace"))
            return m.group(1) if m else "default"
    return "-"


def _tree(edges):
    out = subprocess.check_output(
        ["cargo", "tree", "--locked", "-p", "urmqtt-kernel", "--target", KERNEL_TARGET,
         "-e", edges, "--prefix", "none", "--format", "{p}"],
        cwd=ROOT, text=True,
    )
    found = {}
    for line in out.splitlines():
        m = re.match(r"^(\S+) v(\S+)(.*)$", line.strip())
        if m and "(/" not in m.group(3):  # path dependencies are workspace crates
            found[(m.group(1), m.group(2))] = "(proc-macro)" in m.group(3)
    return found


def kernel_dependencies():
    """(name, version, kind): linked into the kernel, proc-macro, or build script only."""
    linked = _tree("normal,no-proc-macro")
    normal = _tree("normal")
    everything = _tree("normal,build")
    deps = []
    for key in everything:
        if key in linked:
            kind = "linked"
        elif key in normal:
            kind = "proc-macro (build time)"
        else:
            kind = "build script (build time)"
        deps.append((key[0], key[1], kind))
    return sorted(deps)


def registry_dir(name, version):
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for idx in sorted((home / "registry" / "src").glob("*")):
        d = idx / f"{name}-{version}"
        if d.is_dir():
            return d
    return None


def crate_loc(d):
    total = 0
    for f in rust_files(d):
        rel = f.relative_to(d).parts
        if rel and rel[0] in ("tests", "benches", "examples"):
            continue
        total += nonblank(f)
    return total


def fuzz_targets():
    text = (ROOT / "fuzz" / "Cargo.toml").read_text()
    return sorted(re.findall(r'\[\[bin\]\]\s*name\s*=\s*"([^"]+)"', text))


def vendored():
    rows = []
    h = (ROOT / "vendor/sqlite/sqlite3.h").read_text(errors="replace")
    ver = re.search(r'#define SQLITE_VERSION\s+"([^"]+)"', h)
    rows.append(("SQLite amalgamation (C)", ver.group(1) if ver else "?",
                 f"{nonblank(ROOT / 'vendor/sqlite/sqlite3.c')} lines (sqlite3.c)"))
    shims = sorted((ROOT / "crates/store/csrc").rglob("*.h"))
    rows.append(("libc headers for SQLite (C)", "own",
                 f"{sum(nonblank(p) for p in shims)} lines in {len(shims)} headers"))
    first = (ROOT / "vendor/limine/CHECKSUMS").read_text().splitlines()[0]
    lim = re.search(r"Limine (v\S+)", first)
    efi = ROOT / "vendor/limine/BOOTAA64.EFI"
    rows.append(("Limine bootloader (binary)", lim.group(1) if lim else "?",
                 f"BOOTAA64.EFI, {efi.stat().st_size} bytes"))
    return rows


def render():
    pkgs = workspace_packages()
    inv = ["<!-- Generated by scripts/audit-inventory.py; do not edit. -->", "",
           "# TCB inventory", "",
           "## Workspace crates", "",
           "| Crate | Path | src lines | tests/ lines | unsafe sites (justified) | `unsafe_code` lint |",
           "|---|---|---:|---:|---:|---|"]
    unsafe_rows = []
    tot_src = tot_unsafe = tot_just = 0
    for name, d in pkgs:
        src = sum(nonblank(f) for f in rust_files(ROOT / d / "src"))
        tests = sum(nonblank(f) for f in rust_files(ROOT / d / "tests")) if (ROOT / d / "tests").is_dir() else 0
        sites = unsafe_scan(d)
        just = sum(1 for s in sites if s[3])
        tot_src += src
        tot_unsafe += len(sites)
        tot_just += just
        inv.append(f"| `{name}` | `{d}` | {src} | {tests} | {len(sites)} ({just}) | {lint_level(d)} |")
        unsafe_rows += [(name,) + s for s in sites]
    inv.append(f"| **total** | | **{tot_src}** | | **{tot_unsafe} ({tot_just})** | |")
    inv += ["", "## Vendored components", "", "| Component | Version | Size |", "|---|---|---|"]
    inv += [f"| {a} | {b} | {c} |" for a, b, c in vendored()]

    deps = kernel_dependencies()
    workspace = {n for n, _ in pkgs}
    inv += ["", f"## Third-party crates in the kernel (`{KERNEL_TARGET}`, normal and build dependencies)", "",
            "| Crate | Version | Lines | Kind |", "|---|---|---:|---|"]
    dep_total = 0
    linked_total = 0
    for name, version, kind in deps:
        if name in workspace:
            continue
        d = registry_dir(name, version)
        loc = crate_loc(d) if d else 0
        dep_total += loc
        linked_total += loc if kind == "linked" else 0
        inv.append(f"| `{name}` | {version} | {loc if d else 'not fetched'} | {kind} |")
    inv.append(f"| **total** | | **{dep_total}** (linked: {linked_total}) | |")
    inv += ["", "## Fuzz targets", "", ", ".join(f"`{t}`" for t in fuzz_targets()), ""]

    uns = ["<!-- Generated by scripts/audit-inventory.py; do not edit. -->", "",
           "# `unsafe` inventory", "",
           "Every `unsafe` block, function, impl, extern block and `#[unsafe(...)]` attribute",
           "in the workspace crates' non-test code (`tests.rs` and `#[cfg(test)]` items excluded). *Justified* means a `// SAFETY:` comment or a",
           "`# Safety` doc section within the 12 lines before it.", "",
           "| Crate | Location | Kind | Justified |", "|---|---|---|---|"]
    uns += [f"| `{c}` | `{f}:{l}` | {k} | {'yes' if j else '**no**'} |" for c, f, l, k, j in unsafe_rows]
    uns.append("")
    return "\n".join(inv), "\n".join(uns)


def main():
    inv, uns = render()
    targets = {OUT / "inventory.md": inv, OUT / "unsafe.md": uns}
    if "--check" in sys.argv:
        stale = [p for p, t in targets.items() if not p.exists() or p.read_text() != t]
        if stale:
            for p in stale:
                print(f"out of date: {p.relative_to(ROOT)} (run scripts/audit-inventory.py)", file=sys.stderr)
            return 1
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for p, t in targets.items():
        p.write_text(t)
        print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
