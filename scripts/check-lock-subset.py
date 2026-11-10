#!/usr/bin/env python3
"""Checks that every crates.io package of a lockfile is in another one, same version and checksum.

    scripts/check-lock-subset.py examples/edition/Cargo.lock Cargo.lock

The example edition (examples/edition, NOW-18) is a Cargo workspace of its own with its own lockfile. cargo-vet,
cargo-deny and the SBOM look at the repository's workspace only, so the example may use no third-party crate (and
no version of one) that the workspace's lockfile does not already hold (docs/SUPPLY-CHAIN.md).
"""

import sys
import tomllib


def packages(path):
    with open(path, "rb") as f:
        lock = tomllib.load(f)
    return {(p["name"], p["version"], p.get("checksum")) for p in lock.get("package", []) if "source" in p}


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    sub, sup = packages(sys.argv[1]), packages(sys.argv[2])
    extra = sorted(sub - sup)
    for name, version, _ in extra:
        print(f"{sys.argv[1]}: {name} {version} is not in {sys.argv[2]}", file=sys.stderr)
    if extra:
        return 1
    print(f"check-lock-subset: {len(sub)} third-party packages of {sys.argv[1]}, all in {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
