#!/usr/bin/env python3
"""Tests of apply_demo.py and demo.py. The real site generator (build.py of aldo.tech) is not in this repository, so
the stand-in is made from what apply_products.py writes (the 'new' text of each of its edits, inside a string so that
the file compiles): apply_demo.py must find each of its anchors exactly once in it, apply, compile, and be idempotent,
and must refuse a generator that changed. This does NOT prove the edits fit the real build.py: run
`apply_demo.py --check` against it on the server (docs/DEPLOY.md, section 11)."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import apply_demo  # noqa: E402
import apply_products  # noqa: E402

APPLY = os.path.join(HERE, "apply_demo.py")


def run(*args):
    return subprocess.run([sys.executable, "-I", *args], capture_output=True, text=True)


def stand_in(drop=None):
    head = apply_products.EDITS[0][1] + "PR.LISTED = PR.listed()\n"
    frags = [new for i, (_, new) in enumerate(apply_products.EDITS[1:], 1) if i != drop]
    assert not any("'''" in f for f in frags)
    return head + "FRAGMENTS = r'''" + "".join(frags) + "'''\n"


def write(text):
    path = os.path.join(tempfile.mkdtemp(), "build.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class T(unittest.TestCase):
    def test_every_anchor_is_found_once_and_the_result_compiles(self):
        path = write(stand_in())
        r = run(APPLY, "--check", path)
        self.assertEqual((r.returncode, r.stdout.strip().endswith("can be patched")), (0, True), r.stderr)
        before = open(path).read()
        r = run(APPLY, path)
        self.assertEqual(r.returncode, 0, r.stderr)
        after = open(path).read()
        self.assertNotEqual(before, after)
        compile(after, path, "exec")
        for needle in ("import demo as DM", 'kind == "demo"', "DM.demo_url", "DM.render", 'kind in ("builder", "demo")', "DM.DEMO_SLUG", "DM.APP_DIR", "DM.LISTED"):
            self.assertIn(needle, after)
        self.assertEqual(after.count("import demo as DM"), 1)
        # a second run changes nothing
        r = run(APPLY, path)
        self.assertEqual(r.returncode, 0)
        self.assertIn("already", r.stdout)
        self.assertEqual(open(path).read(), after)

    def test_refuses_a_generator_without_the_products_pages(self):
        path = write("print('some other generator')\n")
        r = run(APPLY, path)
        self.assertEqual(r.returncode, 1)
        self.assertIn("apply_products.py first", r.stderr)
        self.assertEqual(open(path).read(), "print('some other generator')\n")

    def test_refuses_when_an_anchor_is_missing_and_changes_nothing(self):
        for drop in range(1, len(apply_products.EDITS)):
            text = stand_in(drop=drop)
            path = write(text)
            r = run(APPLY, path)
            if r.returncode == 0:
                continue  # that fragment is not an anchor of apply_demo
            self.assertIn("matches 0 times", r.stderr)
            self.assertEqual(open(path).read(), text)

    def test_render(self):
        import demo
        home = lambda c: f"/{c}/"
        for code in ("en", "hr", "de"):
            r = demo.render(code, {"home": home, "back": "x"})
            self.assertIn('id="urmqtt-demo"', r["main"])
            self.assertIn(f'data-lang="{code}"', r["main"])
            self.assertIn("/urmqtt/demo/app.js", r["main"])
            self.assertTrue(r["title"].endswith("| ALDO TECH"))
        self.assertIn("uživo", demo.render("hr", {"home": home, "back": "x"})["title"])
        self.assertIn("live", demo.render("de", {"home": home, "back": "x"})["title"])  # the English page
        self.assertFalse(demo.LISTED)  # unlisted unless the owner says so
        self.assertTrue(demo.demo_url("en", home).endswith("/urmqtt-live/"))
        self.assertTrue(apply_demo.EDITS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
