#!/usr/bin/env python3
"""Tests for scripts/mirror/caddy-apply.py (C1e, ADR-227): the edit of the web server's Caddyfile.

    python3 -I scripts/test-caddy-apply.py [-v]

The file is edited on a production host, so what matters is what it refuses to do and that it can be run twice: it
needs both anchors exactly once, keeps one copy of each marked region, removes the unmarked block the first manual
version of this change left (whatever ADR number its comment carried) and leaves everything else byte for byte as it
was. It does not run Caddy: `caddy validate` is the operator's step, and was run on the real file.
"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("caddy_apply", HERE / "mirror" / "caddy-apply.py")
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

BEFORE = (
    "(site) {\n"
    "\troot * /var/www/aldotech.io\n"
    "\tencode zstd gzip\n"
    "\theader {\n\t\tCross-Origin-Opener-Policy same-origin\n\t}\n"
    "\t# Umami analytics served first-party: only the tracker script and its collect endpoint, nothing else of the app.\n"
    "\thandle /u/script.js {\n\t\trewrite * /script.js\n\t}\n"
)
AFTER = (
    '\thandle {\n\t\theader / Vary "Accept-Language, Cookie"\n\t\theader ?Cache-Control "public, max-age=300"\n\t}\n'
    "}\n"
)
OLD_BLOCK = (
    "\t# urMQTT release mirror (C1e, ADR-{n}). The files are written by urmqtt-mirror.service and served by a small nginx\n"
    "\t# (container urmqtt-mirror-web, 127.0.0.1:18089) which adds the rate limits Caddy does not have. Add these two blocks\n"
    "\t# to the site block, before the final catch-all `handle`. If the container is down the page says that the list of\n"
    "\t# releases could not be loaded; the rest of the site is unaffected.\n"
    "\thandle /urmqtt/releases/* {\n\t\turi strip_prefix /urmqtt/releases\n\t\treverse_proxy 127.0.0.1:18089\n\t}\n"
    "\thandle /urmqtt/releases.json {\n\t\trewrite * /releases.json\n\t\treverse_proxy 127.0.0.1:18089\n\t}\n"
)


class CaddyApply(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "Caddyfile"

    def run_main(self, *args: str) -> int:
        with redirect_stdout(io.StringIO()):
            return M.main(["caddy-apply.py", *args, str(self.path)])

    def test_adds_both_regions_before_their_anchors_and_changes_nothing_else(self) -> None:
        text = BEFORE + AFTER
        out = M.apply(text)
        self.assertEqual(out.count("# BEGIN urMQTT builder"), 1)
        self.assertEqual(out.count("# END urMQTT builder"), 1)
        self.assertEqual(out.count("# BEGIN urMQTT mirror and emulator"), 1)
        self.assertEqual(out.count("# END urMQTT mirror and emulator"), 1)
        self.assertLess(out.index("# END urMQTT builder"), out.index("# Umami analytics"))
        self.assertLess(out.index("# END urMQTT mirror and emulator"), out.index("\thandle {\n\t\theader / Vary"))
        # Taking the two regions out gives the original file back, byte for byte.
        stripped = out.replace(M.HEADERS, "").replace(M.HANDLES, "")
        self.assertEqual(stripped, text)

    def test_runs_twice_without_a_change(self) -> None:
        once = M.apply(BEFORE + AFTER)
        self.assertEqual(M.apply(once), once)
        self.path.write_text(once)
        self.assertEqual(self.run_main("--check"), 0)

    def test_replaces_a_region_that_changed(self) -> None:
        once = M.apply(BEFORE + AFTER)
        edited = once.replace("header_down -Server", "header_down -Via")
        self.assertEqual(M.apply(edited), once)

    def test_removes_the_unmarked_block_of_the_first_manual_change(self) -> None:
        for n in ("220", "222", "227"):
            with self.subTest(adr=n):
                out = M.apply(BEFORE + OLD_BLOCK.replace("{n}", n) + AFTER)
                self.assertNotIn("# urMQTT release mirror (C1e", out)
                self.assertEqual(out.count("handle /urmqtt/releases/* {"), 1)
                self.assertEqual(out.count("handle /urmqtt/releases.json {"), 1)

    def test_refuses_when_an_anchor_is_missing_or_ambiguous(self) -> None:
        with self.assertRaises(SystemExit):
            M.apply(BEFORE.replace("# Umami analytics served first-party:", "# something else") + AFTER)
        with self.assertRaises(SystemExit):
            M.apply(BEFORE + AFTER + AFTER)

    def test_the_emulator_is_served_where_the_page_asks_for_it(self) -> None:
        # The application is published at /urmqtt/builder/ and asks for emulator/<version>/ below its own address.
        self.assertIn("handle /urmqtt/builder/emulator/* {", M.HANDLES)
        self.assertIn("precompressed br gzip", M.HANDLES)
        self.assertIn('Cross-Origin-Embedder-Policy "require-corp"', M.HANDLES)
        # The pages of the builder carry the same header, in every language and under every localised slug.
        self.assertIn("urmqtt-builder", M.HEADERS)
        self.assertIn("require-corp", M.HEADERS)

    def test_the_builder_pages_are_isolated_in_every_language_and_nothing_else_is(self) -> None:
        import re

        pattern = re.search(r"path_regexp (\S+)", M.HEADERS)
        assert pattern
        rx = re.compile(pattern.group(1))
        for path in (
            "/proizvodi/urmqtt-builder/", "/en/products/urmqtt-builder/", "/de/produkte/urmqtt-builder/",
            "/sr/proizvodi/urmqtt-builder/", "/ru/produkty/urmqtt-builder/", "/pt/produtos/urmqtt-builder/",
            "/en/products/urmqtt-builder/index.html",
        ):
            self.assertTrue(rx.match(path), path)
        for path in (
            "/", "/en/products/", "/proizvodi/", "/blog/urmqtt-vps-handshake-disk-hardening/", "/urmqtt/builder/app.js",
            "/urmqtt/releases.json", "/en/blog/urmqtt-vps-handshake-disk-hardening/", "/urmqtt-builder/",
        ):
            self.assertFalse(rx.match(path), path)

    def test_the_plain_english_products_address_goes_to_the_english_page(self) -> None:
        self.assertIn("@urmqtt_products path /products /products/", M.HANDLES)
        # `redir` takes an optional matcher first: without the `*` the path would be read as one and nothing would redirect.
        self.assertIn("redir * /en/products/ 302", M.HANDLES)

    def test_the_file_is_written_with_a_backup_of_the_original_and_only_once(self) -> None:
        original = BEFORE + OLD_BLOCK.replace("{n}", "222") + AFTER
        self.path.write_text(original)
        self.assertEqual(self.run_main(), 0)
        backups = [p for p in self.path.parent.iterdir() if ".bak-" in p.name]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), original)
        self.assertEqual(self.path.read_text(), M.apply(original))
        # A second run the same day does not replace the first backup, and a check writes nothing.
        self.path.write_text(self.path.read_text().replace("-Server", "-Via"))
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(backups[0].read_text(), original)
        self.assertEqual(self.run_main("--check"), 0)

    def test_check_reports_a_pending_change_and_writes_nothing(self) -> None:
        self.path.write_text(BEFORE + AFTER)
        self.assertEqual(self.run_main("--check"), 1)
        self.assertEqual(self.path.read_text(), BEFORE + AFTER)
        self.assertEqual([p.name for p in self.path.parent.iterdir()], ["Caddyfile"])


if __name__ == "__main__":
    os.environ.setdefault("TZ", "UTC")
    unittest.main()
