#!/usr/bin/env python3
"""Adds what the release mirror and the builder page need to a Caddyfile (C1e, C1g, ADR-227).

    caddy-apply.py [--print] [--check] CADDYFILE

The site block of aldo.tech (the `(site)` snippet) gets two marked regions:

  1. site level, next to the other `header` rules: the builder page is served cross-origin isolated
     (COOP is already set for the whole site; this adds COEP), because the emulator's threads need
     SharedArrayBuffer. Everything the page loads is from the same site, so nothing else changes.
  2. before the catch-all `handle`: /urmqtt/releases and /urmqtt/releases.json go to the mirror's nginx on
     127.0.0.1:18089 (scripts/mirror/nginx.conf: rate limits, which Caddy has none of); /urmqtt/builder/emulator/*
     is the emulator's files, versioned in their path, cached for good and sent pre-compressed.

Running it again replaces the marked regions (and removes the unmarked mirror blocks an earlier, manual
version of this change left), so it is idempotent. A backup is written next to the file the first time.
It does not reload Caddy: `caddy validate --config CADDYFILE` and `systemctl reload caddy` are yours.
"""
import datetime
import os
import re
import shutil
import sys

HEADERS = """\t# BEGIN urMQTT builder (C1e, ADR-227): the builder page is cross-origin isolated (the emulator needs SharedArrayBuffer).
\t@urmqtt_builder path_regexp ^/([a-z]{2}/)?[a-z0-9-]+/urmqtt-builder(/.*)?$
\theader @urmqtt_builder Cross-Origin-Embedder-Policy "require-corp"
\t# END urMQTT builder
"""

HANDLES = """\t# BEGIN urMQTT mirror and emulator (C1e, C1g, ADR-227, ADR-228)
\t# The Products page is at an address in each language (/proizvodi/, /en/products/, /de/produkte/, ...); the
\t# plain English /products/ goes to the English one.
\t@urmqtt_products path /products /products/
\thandle @urmqtt_products {
\t\tredir * /en/products/ 302
\t}
\t# The release mirror: files written by urmqtt-mirror.service, served by a small nginx (container
\t# urmqtt-mirror-web, 127.0.0.1:18089) that adds the rate limits Caddy does not have. If the container is
\t# down the page says that the list of releases could not be loaded; the rest of the site is unaffected.
\thandle /urmqtt/releases/* {
\t\turi strip_prefix /urmqtt/releases
\t\treverse_proxy 127.0.0.1:18089 {
\t\t\theader_down -Server
\t\t}
\t}
\thandle /urmqtt/releases.json {
\t\trewrite * /releases.json
\t\treverse_proxy 127.0.0.1:18089 {
\t\t\theader_down -Server
\t\t}
\t}
\t# The emulator of "Try in the emulator" (loaded only after a click): a directory per version, so every file
\t# is cached for good; the page is isolated, so its workers' scripts must say the same.
\thandle /urmqtt/builder/emulator/* {
\t\theader Cross-Origin-Embedder-Policy "require-corp"
\t\theader Cross-Origin-Resource-Policy "same-origin"
\t\theader Cache-Control "public, max-age=31536000, immutable"
\t\tfile_server {
\t\t\tprecompressed br gzip
\t\t}
\t}
\t# END urMQTT mirror and emulator
"""

# What the first, manual version of this change put in (unmarked): removed before the marked block goes in.
# Its comment named the ADR under the number that was current then, so the number is not part of the pattern.
OLD_MIRROR = re.compile(
    r"\t# urMQTT release mirror \(C1e, ADR-\d+\)\. The files are written by urmqtt-mirror\.service[^\n]*\n"
    r"\t# \(container urmqtt-mirror-web, 127\.0\.0\.1:18089\)[^\n]*\n"
    r"\t# to the site block, before the final catch-all `handle`[^\n]*\n"
    r"\t# releases could not be loaded; the rest of the site is unaffected\.\n"
    r"\thandle /urmqtt/releases/\* \{\n\t\turi strip_prefix /urmqtt/releases\n\t\treverse_proxy 127\.0\.0\.1:18089\n\t\}\n"
    r"\thandle /urmqtt/releases\.json \{\n\t\trewrite \* /releases\.json\n\t\treverse_proxy 127\.0\.0\.1:18089\n\t\}\n"
)

HEADERS_ANCHOR = "\t# Umami analytics served first-party:"
HANDLES_ANCHOR = '\thandle {\n\t\theader / Vary "Accept-Language, Cookie"'


def replace_region(text: str, begin: str, end: str, block: str, anchor: str) -> str:
    """Puts `block` where the marked region is, or before `anchor` if there is none yet."""
    i = text.find(begin)
    if i >= 0:
        j = text.index(end, i)
        j = text.index("\n", j) + 1
        return text[:i] + block + text[j:]
    if text.count(anchor) != 1:
        raise SystemExit(f"the anchor {anchor!r} was found {text.count(anchor)} times; refusing to guess where to insert")
    return text.replace(anchor, block + anchor)


def apply(text: str) -> str:
    text = OLD_MIRROR.sub("", text)
    text = replace_region(text, "\t# BEGIN urMQTT builder", "\t# END urMQTT builder", HEADERS, HEADERS_ANCHOR)
    text = replace_region(text, "\t# BEGIN urMQTT mirror and emulator", "\t# END urMQTT mirror and emulator", HANDLES, HANDLES_ANCHOR)
    return text


def main(argv: list[str]) -> int:
    if "--print" in argv:
        sys.stdout.write(HEADERS + "\n" + HANDLES)
        return 0
    paths = [a for a in argv[1:] if not a.startswith("--")]
    if len(paths) != 1:
        sys.stderr.write(__doc__)
        return 2
    path = paths[0]
    with open(path, encoding="utf-8") as fh:
        old = fh.read()
    new = apply(old)
    if new == old:
        print(f"{path}: already up to date")
        return 0
    if "--check" in argv:
        print(f"{path}: would change")
        return 1
    backup = f"{path}.bak-{datetime.date.today():%Y%m%d}-urmqtt"
    if not os.path.exists(backup):  # the first backup of the day is the original
        shutil.copy2(path, backup)
        print(f"backup: {backup}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    print(f"{path}: updated; now run: caddy validate --config {path} --adapter caddyfile && systemctl reload caddy")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
