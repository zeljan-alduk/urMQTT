#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM for a urMQTT release (H9, ADR-190).

    scripts/sbom.py [--out FILE] [--version V] [--check] [--strict]

Covers (1) every Rust package in the lockfile (name, version, crates.io
.crate SHA-256 from Cargo.lock, license, source), (2) the vendored C and
binaries (SQLite, Limine, the nistz256 assembly) with the hashes recorded in
vendor/*/CHECKSUMS and vendor/README.md, re-computed from the files here and
compared, (3) the three vendored, patched crates (cpufeatures x2, primeorder)
with their crates.io ancestor and a hash of the patched tree, and (4) the Rust
toolchain pin. Each Rust package carries a `urmqtt:role` property: `kernel`
(linked into a kernel), `build-time` (proc-macro or build script of a kernel),
`workspace` or `host-tool` (tests, tools, not shipped in an image).

Works offline once `cargo fetch` has populated the registry cache (it runs
`cargo metadata --locked --offline`; when that fails it retries online). No
tool beyond cargo and Python 3 is needed. The output is deterministic for a
given commit: the serial number is a UUIDv5 of version and lockfile hash, the
timestamp is SOURCE_DATE_EPOCH (default: the commit time).

--check  validate the document (unique refs, every dependency resolves, every
         vendored hash matches its file) and print a summary; writes nothing
         unless --out is given too.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
TARGETS = ["aarch64-unknown-none", "x86_64-unknown-none"]
TOOL_VERSION = "1"


def run(cmd, **kw):
    return subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.PIPE, **kw)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(d):
    """SHA-256 over sorted (relative path, file hash) lines: a hash of a directory."""
    h = hashlib.sha256()
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        h.update(f"{f.relative_to(d).as_posix()}\0{sha256_file(f)}\n".encode())
    return h.hexdigest()


def read_checksums(path):
    out = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([0-9a-f]{64})  (\S+)$", line)
        if m:
            out[m.group(2)] = m.group(1)
    return out


def cargo_metadata():
    base = ["cargo", "metadata", "--format-version", "1", "--locked"]
    try:
        return json.loads(run(base + ["--offline"]))
    except subprocess.CalledProcessError:
        return json.loads(run(base))


def lock_checksums():
    """(name, version) -> sha256 of the .crate, from Cargo.lock."""
    out = {}
    text = (ROOT / "Cargo.lock").read_text()
    for blk in text.split("[[package]]")[1:]:
        n = re.search(r'^name = "([^"]+)"', blk, re.M)
        v = re.search(r'^version = "([^"]+)"', blk, re.M)
        c = re.search(r'^checksum = "([0-9a-f]{64})"', blk, re.M)
        if n and v and c:
            out[(n.group(1), v.group(1))] = c.group(1)
    return out


def roles(warnings):
    """(name, version) -> 'kernel' | 'build-time', for the union of the kernel targets."""
    found = {}

    def tree(edges):
        keys = set()
        for t in TARGETS:
            try:
                out = run(["cargo", "tree", "--locked", "--offline", "-p", "urmqtt-kernel", "--target", t,
                           "-e", edges, "--prefix", "none", "--format", "{p}"])
            except subprocess.CalledProcessError as e:
                warnings.append(f"cargo tree for {t} failed ({e.stderr.strip().splitlines()[-1] if e.stderr else '?'}): roles incomplete")
                continue
            for line in out.splitlines():
                m = re.match(r"^(\S+) v(\S+)(.*)$", line.strip())
                if m and "(/" not in m.group(3):
                    keys.add((m.group(1), m.group(2)))
        return keys

    linked = tree("normal,no-proc-macro")
    everything = tree("normal,build")
    for k in everything:
        found[k] = "kernel" if k in linked else "build-time"
    return found


def toolchain():
    t = (ROOT / "rust-toolchain.toml").read_text()
    m = re.search(r'channel\s*=\s*"([^"]+)"', t)
    return m.group(1) if m else "unknown"


def lic(expr):
    if not expr:
        return []
    expr = expr.replace("/", " OR ")
    return [{"expression": expr}]


def purl(name, version):
    return f"pkg:cargo/{name}@{version}"


def build(version, warnings):
    meta = cargo_metadata()
    sums = lock_checksums()
    role = roles(warnings)
    ws_ids = set(meta["workspace_members"])
    commit = run(["git", "rev-parse", "HEAD"]).strip()
    lock_hash = sha256_file(ROOT / "Cargo.lock")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or run(["git", "log", "-1", "--format=%ct"]).strip())
    ts = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    vendored_paths = {}  # package id -> vendor component ref
    comps, refs = [], {}

    def add(c):
        assert c["bom-ref"] not in refs, f"duplicate bom-ref {c['bom-ref']}"
        refs[c["bom-ref"]] = c
        comps.append(c)

    # --- Rust packages -----------------------------------------------------
    for p in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        pid = p["id"]
        mp = Path(p["manifest_path"]).resolve()
        in_vendor = VENDOR in mp.parents
        if in_vendor:
            ref = f"vendor:{p['name']}@{p['version']}"
            vendored_paths[pid] = ref
            d = mp.parent
            upstream = sums.get((p["name"], p["version"])) or UPSTREAM_CRATE_SHA.get((p["name"], p["version"]))
            c = {
                "type": "library", "bom-ref": ref, "name": p["name"], "version": p["version"],
                "description": "vendored RustCrypto crate patched for bare metal (vendor/README.md); the hash is of the patched tree",
                "purl": purl(p["name"], p["version"]) + "?vendored=urmqtt-patched",
                "hashes": [{"alg": "SHA-256", "content": tree_hash(d)}],
                "licenses": lic(p["license"]),
                "pedigree": {
                    "ancestors": [{
                        "type": "library", "name": p["name"], "version": p["version"],
                        "purl": purl(p["name"], p["version"]),
                        "hashes": [{"alg": "SHA-256", "content": upstream}] if upstream else [],
                    }],
                    "notes": "crates.io source with a small documented patch; see vendor/README.md",
                },
                "properties": [{"name": "urmqtt:role", "value": role.get((p["name"], p["version"]), "kernel")},
                               {"name": "urmqtt:path", "value": d.relative_to(ROOT).as_posix()}],
            }
            add(c)
            continue
        if pid in ws_ids:
            ref = f"ws:{p['name']}"
            c = {"type": "library", "bom-ref": ref, "name": p["name"], "version": p["version"],
                 "purl": purl(p["name"], p["version"]) + "?workspace=true",
                 "licenses": lic(p["license"]),
                 "properties": [{"name": "urmqtt:role", "value": "workspace"},
                                {"name": "urmqtt:path", "value": Path(p["manifest_path"]).parent.relative_to(ROOT).as_posix()}]}
            add(c)
            vendored_paths[pid] = ref
            continue
        key = (p["name"], p["version"])
        ref = purl(*key)
        c = {"type": "library", "bom-ref": ref, "name": p["name"], "version": p["version"], "purl": ref,
             "licenses": lic(p["license"]),
             "externalReferences": [{"type": "distribution", "url": f"https://crates.io/api/v1/crates/{p['name']}/{p['version']}/download"}],
             "properties": [{"name": "urmqtt:role", "value": role.get(key, "host-tool")}]}
        if key in sums:
            c["hashes"] = [{"alg": "SHA-256", "content": sums[key]}]
        else:
            warnings.append(f"{key[0]} {key[1]}: no checksum in Cargo.lock")
        if p.get("repository"):
            c["externalReferences"].append({"type": "vcs", "url": p["repository"]})
        add(c)
        vendored_paths[pid] = ref

    # --- Vendored C and binaries ------------------------------------------
    sq = read_checksums(VENDOR / "sqlite" / "CHECKSUMS")
    sq_ver = re.search(r"SQLite (\d+\.\d+\.\d+)", (VENDOR / "sqlite" / "CHECKSUMS").read_text()).group(1)
    sq_zip = re.search(r"zip SHA3-256 ([0-9a-f]{64})", (VENDOR / "sqlite" / "CHECKSUMS").read_text()).group(1)
    sq_num = "{}{:02d}{:02d}00".format(*map(int, sq_ver.split(".")))
    add({"type": "library", "bom-ref": "vendor:sqlite", "name": "sqlite", "version": sq_ver,
         "description": "SQLite amalgamation (C), linked into the kernel through crates/store",
         "purl": f"pkg:generic/sqlite@{sq_ver}", "cpe": f"cpe:2.3:a:sqlite:sqlite:{sq_ver}:*:*:*:*:*:*:*",
         "licenses": [{"license": {"name": "Public domain (SQLite blessing)"}}],
         "hashes": [{"alg": "SHA-256", "content": sq["sqlite3.c"]}],
         "externalReferences": [{"type": "distribution", "url": f"https://sqlite.org/2026/sqlite-amalgamation-{sq_num}.zip",
                                 "hashes": [{"alg": "SHA3-256", "content": sq_zip}]}],
         "components": [{"type": "file", "name": f, "bom-ref": f"vendor:sqlite/{f}", "hashes": [{"alg": "SHA-256", "content": sq[f]}]} for f in sorted(sq)],
         "properties": [{"name": "urmqtt:role", "value": "kernel"}, {"name": "urmqtt:path", "value": "vendor/sqlite"}]})

    lm = read_checksums(VENDOR / "limine" / "CHECKSUMS")
    lm_ver = re.search(r"Limine v(\d+\.\d+\.\d+)", (VENDOR / "limine" / "CHECKSUMS").read_text()).group(1)
    lm_tar = re.search(r"tarball sha256 ([0-9a-f]{64})", (VENDOR / "limine" / "CHECKSUMS").read_text()).group(1)
    add({"type": "application", "bom-ref": "vendor:limine", "name": "limine", "version": lm_ver,
         "description": "Limine bootloader binaries (unmodified), on the boot media; limine.c is built into a host tool by scripts/mkiso.sh",
         "purl": f"pkg:github/limine-bootloader/limine@v{lm_ver}",
         "licenses": [{"license": {"id": "BSD-2-Clause"}}],
         "hashes": [{"alg": "SHA-256", "content": lm_tar}],
         "externalReferences": [{"type": "distribution", "url": f"https://github.com/limine-bootloader/limine/releases/download/v{lm_ver}/limine-binary.tar.gz"}],
         "components": [{"type": "file", "name": f, "bom-ref": f"vendor:limine/{f}", "hashes": [{"alg": "SHA-256", "content": lm[f]}]} for f in sorted(lm)],
         "properties": [{"name": "urmqtt:role", "value": "boot-media"}, {"name": "urmqtt:path", "value": "vendor/limine"},
                        {"name": "urmqtt:hash-of", "value": "the component hash is the upstream tarball; the files are listed below"}]})

    readme = (VENDOR / "README.md").read_text()
    ring_ver = re.search(r"\*\*ring (\d+\.\d+\.\d+)\*\*", readme).group(1)
    ring_sha = re.search(r"\.crate` SHA-256 `([0-9a-f]{64})`", readme.split("## `nistz256`")[1]).group(1)
    nz = {}
    for m in re.finditer(r"\| `([^`]+)` \|[^|]*\| `([0-9a-f]{64})` \|", readme.split("## `nistz256`")[1]):
        nz[m.group(1)] = m.group(2)
    add({"type": "library", "bom-ref": "vendor:nistz256", "name": "nistz256", "version": f"ring-{ring_ver}",
         "description": "P-256 assembly and generator table derived from ring (OpenSSL/Intel nistz256), x86_64 only (crates/nistz256, vendor/nistz256/derive.py)",
         "purl": "pkg:generic/nistz256@ring-" + ring_ver + "?vendored=urmqtt-derived",
         "licenses": [{"license": {"id": "Apache-2.0"}}],
         "pedigree": {"ancestors": [{"type": "library", "name": "ring", "version": ring_ver, "purl": purl("ring", ring_ver),
                                     "hashes": [{"alg": "SHA-256", "content": ring_sha}]}],
                      "notes": "mechanical derivation, see vendor/README.md"},
         "components": [{"type": "file", "name": f, "bom-ref": f"vendor:nistz256/{f}", "hashes": [{"alg": "SHA-256", "content": sha256_file(VENDOR / "nistz256" / f)}]}
                        for f in sorted(nz)],
         "properties": [{"name": "urmqtt:role", "value": "kernel"}, {"name": "urmqtt:path", "value": "vendor/nistz256"}]})
    # Recorded hashes must equal the files (a drifted README is a finding).
    for f, h in nz.items():
        actual = sha256_file(VENDOR / "nistz256" / f)
        if actual != h:
            raise SystemExit(f"vendor/nistz256/{f}: README records {h}, file is {actual}")
    for d, sums_ in (("sqlite", sq), ("limine", lm)):
        for f, h in sums_.items():
            actual = sha256_file(VENDOR / d / f)
            if actual != h:
                raise SystemExit(f"vendor/{d}/{f}: CHECKSUMS records {h}, file is {actual}")

    add({"type": "application", "bom-ref": "toolchain:rust", "name": "rust-nightly", "version": toolchain(),
         "description": "Pinned Rust toolchain (rust-toolchain.toml); builds the kernel with -Zbuild-std, so core, alloc and compiler_builtins of this toolchain are in the image",
         "purl": f"pkg:generic/rust@{toolchain()}",
         "licenses": [{"expression": "MIT OR Apache-2.0"}],
         "properties": [{"name": "urmqtt:role", "value": "kernel"}]})

    # --- Dependency graph ---------------------------------------------------
    deps = []
    for n in sorted(meta["resolve"]["nodes"], key=lambda n: vendored_paths.get(n["id"], n["id"])):
        ref = vendored_paths.get(n["id"])
        if not ref:
            continue
        on = sorted({vendored_paths[d] for d in n["dependencies"] if d in vendored_paths})
        if ref == "ws:urmqtt-store":
            on = sorted(set(on) | {"vendor:sqlite"})
        if ref == "ws:urmqtt-nistz256":
            on = sorted(set(on) | {"vendor:nistz256"})
        deps.append({"ref": ref, "dependsOn": on})
    root_ref = "urmqtt:image"
    deps.insert(0, {"ref": root_ref, "dependsOn": sorted(["ws:urmqtt-kernel", "vendor:limine", "toolchain:rust"])})
    deps.append({"ref": "toolchain:rust", "dependsOn": []})
    deps.append({"ref": "vendor:limine", "dependsOn": []})
    deps.append({"ref": "vendor:sqlite", "dependsOn": []})
    deps.append({"ref": "vendor:nistz256", "dependsOn": []})

    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:urmqtt:sbom:{version}:{commit}:{lock_hash}")
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{serial}", "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": {"components": [{"type": "application", "name": "urmqtt scripts/sbom.py", "version": TOOL_VERSION}]},
            "component": {"type": "firmware", "bom-ref": root_ref, "name": "urmqtt", "version": version,
                          "description": "urMQTT unikernel MQTT broker image",
                          "licenses": [{"expression": "MIT OR Apache-2.0"}],
                          "purl": f"pkg:github/zeljan-alduk/urMQTT@{version}",
                          "externalReferences": [{"type": "vcs", "url": "https://github.com/zeljan-alduk/urMQTT"}],
                          "properties": [{"name": "urmqtt:commit", "value": commit}, {"name": "urmqtt:cargo-lock-sha256", "value": lock_hash}]},
            "properties": [{"name": "urmqtt:note", "value": "dependencies of the fuzz workspace (fuzz/) are not shipped and are not listed"}],
        },
        "components": comps,
        "dependencies": deps,
    }
    return bom


# Upstream .crate hashes of the vendored crates (vendor/README.md), for the
# ancestors; cpufeatures 0.2.17 / 0.3.1 and primeorder 0.14.0 are not in
# Cargo.lock with a checksum because they are path packages there.
UPSTREAM_CRATE_SHA = {}


def load_upstream_from_readme():
    text = (VENDOR / "README.md").read_text()
    for name, ver, h in re.findall(r"\| (cpufeatures) (\d+\.\d+\.\d+) \| `([0-9a-f]{64})` \|", text):
        UPSTREAM_CRATE_SHA[(name, ver)] = h
    m = re.search(r"## `primeorder` (\d+\.\d+\.\d+).*?Upstream `\.crate` SHA-256: `([0-9a-f]{64})`", text, re.S)
    if m:
        UPSTREAM_CRATE_SHA[("primeorder", m.group(1))] = m.group(2)


def validate(bom):
    refs = set()

    def walk(cs):
        for c in cs:
            r = c.get("bom-ref")
            if r:
                assert r not in refs, f"duplicate bom-ref {r}"
                refs.add(r)
            for h in c.get("hashes", []):
                n = {"SHA-256": 64, "SHA3-256": 64}[h["alg"]]
                assert re.fullmatch(f"[0-9a-f]{{{n}}}", h["content"]), f"bad hash on {r}"
            walk(c.get("components", []))

    refs.add(bom["metadata"]["component"]["bom-ref"])
    walk(bom["components"])
    for d in bom["dependencies"]:
        assert d["ref"] in refs, f"dependency of unknown ref {d['ref']}"
        for t in d["dependsOn"]:
            assert t in refs, f"{d['ref']} depends on unknown {t}"
    seen = [d["ref"] for d in bom["dependencies"]]
    assert len(seen) == len(set(seen)), "a ref has two dependency entries"
    for c in bom["components"]:
        if c["bom-ref"].startswith("pkg:cargo/"):
            assert c.get("hashes"), f"{c['bom-ref']} has no hash"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--version")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true", help="a warning (incomplete roles, a missing checksum) is an error; releases use it")
    a = ap.parse_args()
    version = a.version or os.environ.get("URMQTT_VERSION") or run(["git", "describe", "--tags", "--always", "--dirty"]).strip()
    load_upstream_from_readme()
    warnings = []
    bom = build(version, warnings)
    validate(bom)
    for w in warnings:
        print(f"sbom: warning: {w}", file=sys.stderr)
    if warnings and a.strict:
        raise SystemExit("sbom: --strict and there are warnings")
    text = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
    elif not a.check:
        sys.stdout.write(text)
    by_role = {}
    for c in bom["components"]:
        r = next((p["value"] for p in c.get("properties", []) if p["name"] == "urmqtt:role"), "?")
        by_role[r] = by_role.get(r, 0) + 1
    print(f"sbom: {len(bom['components'])} components ({', '.join(f'{k} {v}' for k, v in sorted(by_role.items()))}), "
          f"version {version}" + (f", wrote {a.out}" if a.out else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
