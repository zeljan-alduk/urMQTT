#!/usr/bin/env bash
# Checks the release signing keys before anything is signed or published with
# them (ROADMAP NOW-2, docs/release-key-rotation.md):
#
#   scripts/check-release-key.sh [--root DIR] [--allow-placeholder]
#
#   - minisign.pub is a minisign Ed25519 public key, NOT the placeholder
#     REPLACE-WITH-THE-NEW-PUBLIC-KEY and NOT the former test key 9229E05252D01F8E;
#   - keys/release-keys.json is a key ring of schema 1: every key file it names
#     parses, a declared key_id matches its file, no key is listed twice, the
#     "release" key is ../minisign.pub with no upper bound, and the former test
#     key is bounded (it may sign v0.1.0 to v0.4.1 only).
#
# Exit 0 and one line per key when all is well; 1 with the reason otherwise.
# The Release workflow, `make sign` and scripts/deploy-builder-site.sh run it
# first, so a release cannot be signed, and the builder page cannot be
# deployed, while the placeholder is in the repository. --allow-placeholder
# turns only the placeholder into a warning (CI of the branch before the owner
# has set the key; never for a release). --root checks another checkout (tests).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ALLOW=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --root) ROOT=$(cd "$2" && pwd); shift 2 ;;
        --allow-placeholder) ALLOW=1; shift ;;
        *) echo "usage: $0 [--root DIR] [--allow-placeholder]" >&2; exit 2 ;;
    esac
done

python3 -I - "$ROOT" "$ALLOW" <<'PY'
import base64, json, re, sys
from pathlib import Path

root, allow = Path(sys.argv[1]).resolve(), sys.argv[2] == "1"
PLACEHOLDER = "REPLACE-WITH-THE-NEW-PUBLIC-KEY"
TEST_KEY_ID = "9229E05252D01F8E"
VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]*)?")


def fail(msg: str) -> None:
    print(f"check-release-key: ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def key_id(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    body = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("untrusted comment:")]
    try:
        raw = base64.b64decode(body[0], validate=True) if len(body) == 1 else b""
    except ValueError:
        raw = b""
    if len(raw) != 42 or raw[:2] != b"Ed":
        fail(f"{path.relative_to(root)} is not a minisign Ed25519 public key")
    return raw[2:10][::-1].hex().upper()


def version(tag):
    m = VERSION.fullmatch(tag or "")
    return tuple(int(x) for x in m.groups()) if m else None


pub = root / "minisign.pub"
if not pub.is_file():
    fail("minisign.pub is missing")
placeholder = PLACEHOLDER in pub.read_text(encoding="utf-8")
if placeholder:
    msg = ("minisign.pub is still the placeholder " + PLACEHOLDER + ": the release key has not been set. "
           "Generate it offline and commit its public half first (docs/release-key-rotation.md); "
           "nothing may be signed or published with this tree.")
    if not allow:
        fail(msg)
    print(f"check-release-key: WARNING: {msg}", file=sys.stderr)
elif key_id(pub) == TEST_KEY_ID:
    fail("minisign.pub is the former test key 9229E05252D01F8E; it must be the new release key")

ring_path = root / "keys" / "release-keys.json"
try:
    ring = json.loads(ring_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    fail(f"keys/release-keys.json: {exc}")
if not isinstance(ring, dict) or ring.get("schema") != 1 or not isinstance(ring.get("keys"), list) or not ring["keys"]:
    fail("keys/release-keys.json is not a key ring of schema 1 with at least one key")
seen = {}
names = set()
for entry in ring["keys"]:
    name, file = entry.get("name"), entry.get("file")
    if not isinstance(name, str) or not isinstance(file, str):
        fail("keys/release-keys.json: every key needs a name and a file")
    names.add(name)
    lo, hi = entry.get("valid_from"), entry.get("valid_to")
    for b in (lo, hi):
        if b is not None and version(b) is None:
            fail(f"keys/release-keys.json, key {name}: {b!r} is not a version tag")
    if lo and hi and version(lo) > version(hi):
        fail(f"keys/release-keys.json, key {name}: valid_from is after valid_to")
    path = (ring_path.parent / file).resolve()
    if not path.is_file():
        fail(f"keys/release-keys.json, key {name}: {file} does not exist")
    if name == "release":
        if path != pub.resolve():
            fail("keys/release-keys.json: the release key must be ../minisign.pub")
        if hi is not None or entry.get("former_test_key"):
            fail("keys/release-keys.json: the release key must have no upper bound and must not be marked as the test key")
        if placeholder:
            print(f"  release  (placeholder)  {lo or 'any'} and later   minisign.pub")
            continue
    kid = key_id(path)
    if entry.get("key_id") not in (None, kid):
        fail(f"keys/release-keys.json, key {name}: {file} has key id {kid}, the ring says {entry['key_id']}")
    if kid in seen:
        fail(f"keys/release-keys.json: key {kid} is listed twice ({seen[kid]} and {name})")
    seen[kid] = name
    if kid == TEST_KEY_ID and (not entry.get("former_test_key") or hi is None):
        fail("keys/release-keys.json: the former test key 9229E05252D01F8E must be marked former_test_key and bounded (valid_to)")
    rng = f"{lo or 'any'} to {hi}" if hi else f"{lo or 'any'} and later"
    print(f"  {name:<8} {kid}  {rng:<18} {path.relative_to(root)}")
if "release" not in names:
    fail("keys/release-keys.json has no \"release\" key")
print("check-release-key: ok" + (" (with the placeholder: NOT releasable)" if placeholder else ""))
PY
