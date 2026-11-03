#!/usr/bin/env python3
"""Adds the "Try urMQTT live" page to the aldo.tech site generator (build.py), D1b. Apply AFTER apply_products.py.

    apply_demo.py /path/to/site/build.py          # edits in place; refuses a build.py it does not recognise
    apply_demo.py --check /path/to/site/build.py  # only says whether it can be applied / is applied

Same discipline as apply_products.py: every edit replaces text that must occur exactly once (text apply_products.py
wrote), so a generator that changed is refused instead of half-edited, and a second run changes nothing. The page is
unlisted (noindex, no navigation, no sitemap entry) unless URMQTT_DEMO_LISTED=1 is set for the build; its analytics
script is always left out (the page promises no tracking).
"""
import sys

EDITS = [
    ("import products as PR  # Products and urMQTT builder pages (C1e)\n",
     "import products as PR  # Products and urMQTT builder pages (C1e)\nimport demo as DM  # Try urMQTT live (D1b)\n"),
    ('    elif kind == "builder":\n        where = {c: PR.builder_url(c, url) for c in L}\n',
     '    elif kind == "builder":\n        where = {c: PR.builder_url(c, url) for c in L}\n'
     '    elif kind == "demo":\n        where = {c: DM.demo_url(c, url) for c in L}\n'),
    ("    if kind in (\"products\", \"builder\") and not PR.LISTED:\n        alternates = '<meta name=\"robots\" content=\"noindex\">'\n",
     "    if kind in (\"products\", \"builder\") and not PR.LISTED:\n        alternates = '<meta name=\"robots\" content=\"noindex\">'\n"
     "    if kind == \"demo\" and not DM.LISTED:\n        alternates = '<meta name=\"robots\" content=\"noindex\">'\n"),
    ('        main_html, page_title, page_desc, head_extra = r["main"], r["title"], r["desc"], r["head"]\n',
     '        main_html, page_title, page_desc, head_extra = r["main"], r["title"], r["desc"], r["head"]\n'
     '    elif kind == "demo":\n'
     '        r = DM.render(code, {"home": url, "back": p["back"]})\n'
     '        main_html, page_title, page_desc, head_extra = r["main"], r["title"], r["desc"], r["head"]\n'),
    ('umami = "" if kind == "builder" else', 'umami = "" if kind in ("builder", "demo") else'),
    ('        write(os.path.join(d, PR.slug(code), PR.BUILDER_SLUG), "index.html", with_csp(page(code, "builder")))\n',
     '        write(os.path.join(d, PR.slug(code), PR.BUILDER_SLUG), "index.html", with_csp(page(code, "builder")))\n'
     '        write(os.path.join(d, PR.slug(code), DM.DEMO_SLUG), "index.html", with_csp(page(code, "demo")))\n'),
    ('        shutil.copytree(PR.APP_DIR, os.path.join(OUT, "urmqtt", "builder"), dirs_exist_ok=True)\n',
     '        shutil.copytree(PR.APP_DIR, os.path.join(OUT, "urmqtt", "builder"), dirs_exist_ok=True)\n'
     '    if os.path.isdir(DM.APP_DIR):\n'
     '        shutil.copytree(DM.APP_DIR, os.path.join(OUT, "urmqtt", "demo"), dirs_exist_ok=True)\n'),
    ('        pages += [(PR.products_url(c, url), None) for c in L] + [(PR.builder_url(c, url), None) for c in L]\n',
     '        pages += [(PR.products_url(c, url), None) for c in L] + [(PR.builder_url(c, url), None) for c in L]\n'
     '    if DM.LISTED:\n        pages += [(DM.demo_url(c, url), None) for c in L]\n'),
]

MARK = "import demo as DM"


def main(argv):
    check = "--check" in argv
    paths = [a for a in argv[1:] if not a.startswith("--")]
    if len(paths) != 1:
        sys.exit(__doc__)
    path = paths[0]
    text = open(path, encoding="utf-8").read()
    if MARK in text:
        print(f"{path}: already has the demo page")
        return 0
    if "import products as PR" not in text:
        print(f"{path}: run apply_products.py first", file=sys.stderr)
        return 1
    for i, (old, new) in enumerate(EDITS, 1):
        n = text.count(old)
        if n != 1:
            print(f"{path}: edit {i} matches {n} times (expected 1): {old[:70]!r}", file=sys.stderr)
            return 1
        text = text.replace(old, new)
    compile(text, path, "exec")
    if check:
        print(f"{path}: can be patched")
        return 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"{path}: patched ({len(EDITS)} edits)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
