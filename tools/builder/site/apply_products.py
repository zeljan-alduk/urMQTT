#!/usr/bin/env python3
"""Adds the Products and urMQTT builder pages to the aldo.tech site generator (build.py), C1e, ADR-227.

    apply_products.py /path/to/site/build.py          # edits in place; refuses a build.py it does not recognise
    apply_products.py --check /path/to/site/build.py  # only says whether it can be applied / is applied

Every edit is a replacement of text that must occur exactly once, so a generator that changed since this was written is
refused instead of half-edited, and a second run changes nothing. The result is the same as applying tools/builder/site/
build.py.patch, which is kept for reading. The pages: products.py and products_i18n.py (next to build.py).
"""
import re
import sys

EDITS = [
    # 1. The module and the decision whether the pages are listed.
    ("from privacy_i18n import P\n",
     "from privacy_i18n import P\nimport products as PR  # Products and urMQTT builder pages (C1e)\n"),
    # 2. Where the pages live in each language (for the language menu and hreflang).
    ('    elif kind == "meeting":\n        where = {c: murl(c) for c in L}\n',
     '    elif kind == "meeting":\n        where = {c: murl(c) for c in L}\n'
     '    elif kind == "products":\n        where = {c: PR.products_url(c, url) for c in L}\n'
     '    elif kind == "builder":\n        where = {c: PR.builder_url(c, url) for c in L}\n'),
    # 3. Not listed yet: noindex and no hreflang, whatever the language menu shows.
    ('    if kind in ("home", "blog", "post"):\n        alternates += f\'\\n<link rel="alternate" type="application/rss+xml"',
     '    if kind in ("products", "builder") and not PR.LISTED:\n        alternates = \'<meta name="robots" content="noindex">\'\n'
     '    if kind in ("home", "blog", "post"):\n        alternates += f\'\\n<link rel="alternate" type="application/rss+xml"'),
    # 4. The content of the two pages.
    ('    else:\n        nf = NOT_FOUND[code]\n',
     '    elif kind in ("products", "builder"):\n'
     '        r = PR.render(kind, code, {"home": url, "back": p["back"], "github_icon": GITHUB_ICON})\n'
     '        main_html, page_title, page_desc, head_extra = r["main"], r["title"], r["desc"], r["head"]\n'
     '    else:\n        nf = NOT_FOUND[code]\n'),
    # 5. What the head may carry beyond the common part (the builder's style sheet).
    ('    path = where.get(code, url(code))\n',
     '    path = where.get(code, url(code))\n    head_extra = ""\n'),
    ('<link rel="icon" href="{asset("favicon.svg")}" type="image/svg+xml">\n',
     '<link rel="icon" href="{asset("favicon.svg")}" type="image/svg+xml">{head_extra}\n'),
    # 6. The header button and the footer link, once the builder is usable.
    # Products goes first in the header, whatever follows it (since the Services link was added to the site's own
    # header, the order is Products | Services | Tech stack | Blog): so anchor on the start of the tools block only.
    ('      <div class="tools">\n      ',
     '      <div class="tools">\n      {products_nav}'),
    # (anchored on the Tech stack link alone: other footer links may sit between it and the meeting link)
    ('<a href="{surl(code)}">{e(STACK_LABEL[code])}</a>',
     '<a href="{surl(code)}">{e(STACK_LABEL[code])}</a>{products_foot}'),
    ('    seo_meta = ""\n    if where:\n',
     '    products_nav = f\'<a class="nav" href="{PR.products_url(code, url)}">{e(PR.label(code))}</a>\\n      \' if PR.LISTED else ""\n'
     '    products_foot = f\'<a href="{PR.products_url(code, url)}">{e(PR.label(code))}</a>\' if PR.LISTED else ""\n'
     '    seo_meta = ""\n    if where:\n'),
    # 6b. The builder page handles private keys: no analytics script on it at all (the page promises no tracking).
    ('<script defer src="/u/script.js" data-website-id="{UMAMI_WEBSITE_ID}" data-domains="aldo.tech,aldotech.io" data-do-not-track="true"></script>\n</body>',
     '{umami}\n</body>'),
    ('    seo_meta = ""\n    if where:\n',
     '    umami = "" if kind == "builder" else f\'<script defer src="/u/script.js" data-website-id="{UMAMI_WEBSITE_ID}" data-domains="aldo.tech,aldotech.io" data-do-not-track="true"></script>\'\n'
     '    seo_meta = ""\n    if where:\n'),
    # 7. The builder needs WebAssembly: the one addition to the page's script policy.
    ('    csp = ("default-src \'self\'; script-src \'self\' " + hashes + "; style-src',
     '    wasm = " \'wasm-unsafe-eval\'" if \'id="urmqtt-builder"\' in doc else ""\n'
     '    csp = ("default-src \'self\'; script-src \'self\'" + wasm + " " + hashes + "; style-src'),
    # 8. The pages and the application's files.
    ('        write(os.path.join(d, BOOK_SLUG[code]), "index.html", with_csp(page(code, "meeting")))\n',
     '        write(os.path.join(d, BOOK_SLUG[code]), "index.html", with_csp(page(code, "meeting")))\n'
     '        write(os.path.join(d, PR.slug(code)), "index.html", with_csp(page(code, "products")))\n'
     '        write(os.path.join(d, PR.slug(code), PR.BUILDER_SLUG), "index.html", with_csp(page(code, "builder")))\n'),
    ('    # Hand-made client pages (concepts, proposals) are published as-is',
     '    # The urMQTT builder application (made by `make builder` in the urMQTT repository, copied here by its deploy script).\n'
     '    if os.path.isdir(PR.APP_DIR):\n'
     '        shutil.copytree(PR.APP_DIR, os.path.join(OUT, "urmqtt", "builder"), dirs_exist_ok=True)\n'
     '    # Hand-made client pages (concepts, proposals) are published as-is'),
    # 9. The sitemap lists them only when they are listed.
    ('    for lang in B.LANGS:\n        pages.append((burl(lang), max(',
     '    if PR.LISTED:\n        pages += [(PR.products_url(c, url), None) for c in L] + [(PR.builder_url(c, url), None) for c in L]\n'
     '    for lang in B.LANGS:\n        pages.append((burl(lang), max('),
    # 10. The posts about urMQTT link to the builder: at the end of their card (home page and blog listing) ...
    (r"""                    f'<p>{e(p.description)}</p></div>\n')""",
     r"""                    f'<p>{e(p.description)}{PR.row_link(code, p, url)}</p></div>\n')"""),
    # ... and under their lead.
    ('      <p class="lead">{e(post.description)}</p>\n{cover}      <div class="body">',
     '      <p class="lead">{e(post.description)}</p>\n{PR.post_note(code, post, url)}{cover}      <div class="body">'),
    # ... in the site's own box style (a link in a card has to stay above the card's whole-row link).
    ('  .post .cta a { color: var(--link); font-weight: 600; }\n',
     '  .post .cta a { color: var(--link); font-weight: 600; }\n'
     '  .post .product-note { margin: 4px 0 22px; padding: 12px 18px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; color: var(--muted); }\n'
     '  .post .product-note a { color: var(--link); font-weight: 600; }\n'
     '  .row p .row-extra { position: relative; z-index: 1; color: var(--link); font-weight: 600; text-decoration: none; }\n'
     '  .row p .row-extra:hover { text-decoration: underline; }\n'),
]

MARK = "import products as PR"


def main(argv):
    check = "--check" in argv
    paths = [a for a in argv[1:] if not a.startswith("--")]
    if len(paths) != 1:
        sys.exit(__doc__)
    path = paths[0]
    text = open(path, encoding="utf-8").read()
    if MARK in text:
        print(f"{path}: already has the products pages")
        return 0
    for i, (old, new) in enumerate(EDITS, 1):
        n = text.count(old)
        if n != 1:
            print(f"{path}: edit {i} matches {n} times (expected 1): {old[:70]!r}", file=sys.stderr)
            return 1
        text = text.replace(old, new)
    # PR.LISTED is decided once per build.
    text = text.replace("import products as PR  # Products and urMQTT builder pages (C1e)\n",
                        "import products as PR  # Products and urMQTT builder pages (C1e)\nPR.LISTED = PR.listed()\n", 1)
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
