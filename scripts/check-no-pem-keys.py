#!/usr/bin/env python3
"""Fails if any of the given files holds a PEM private key (a BEGIN ... PRIVATE KEY
line followed by base64): a release asset must hold none (ROADMAP NOW-2; the dev
build with throwaway certificates is not a release asset any more).

    scripts/check-no-pem-keys.py FILE...

The bare marker text without key material after it (a parser's string constant
inside a kernel) does not count. Exit 0 when clean, 1 with the file names otherwise.
"""

import re
import sys

PEM_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{40}")


def main(paths: list[str]) -> int:
    if not paths:
        print("usage: check-no-pem-keys.py FILE...", file=sys.stderr)
        return 2
    bad = []
    for path in paths:
        with open(path, "rb") as f:
            if PEM_KEY.search(f.read()):
                bad.append(path)
    for path in bad:
        print(f"check-no-pem-keys: {path} contains a PEM private key", file=sys.stderr)
    if not bad:
        print(f"check-no-pem-keys: no PEM private key in {len(paths)} file(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
