"""The Products and urMQTT builder pages of aldo.tech (C1e, ADR-227), for build.py of the site generator.

build.py calls render(kind, code, h) for the kinds "products" and "builder" and gets the page's <main>, its title and
description and what belongs in <head>. The builder application itself (page script, style, the WebAssembly module and
the texts) is built from the urMQTT repository (`make builder`) and copied to site/urmqtt-builder/ by
`scripts/deploy-builder-site.sh`; this module only wraps it in the site's layout and language.

The pages are *listed*: a Products link in the header and the footer of every page, the sitemap, hreflang, and a short
link from the blog cards and the posts about urMQTT (row_link, post_note). That was the owner's decision of 2026-11-01,
made while no release has a template yet; the builder page itself says so plainly, with the releases there are greyed
out and a link to GitHub (tools/builder/web, ADR-227). `URMQTT_PRODUCTS_LISTED=0` in the environment of the build
takes the links, the sitemap entries and the indexing away again (the pages stay reachable by address, with noindex).
"""
import html
import json
import os

from products_i18n import BUILDER, LABEL, PAGE, SLUG, URMQTT

HERE = os.path.dirname(os.path.abspath(__file__))
BUILDER_SLUG = "urmqtt-builder"
GITHUB_REPO = "https://github.com/zeljan-alduk/urMQTT"

# Where the generator finds the built application.
APP_DIR = os.environ.get("URMQTT_BUILDER_DIR", os.path.join(HERE, "urmqtt-builder"))
# The addresses the page uses for itself and for the release list. Overridable only to test a copy of the page
# under another path (a labelled, unlisted test directory); production uses the defaults.
APP_URL = os.environ.get("URMQTT_APP_URL", "/urmqtt/builder/")
RELEASES_URL = os.environ.get("URMQTT_RELEASES_URL", "/urmqtt/releases/releases.json")


def pick(table, code):
    """The text for a language, English where the language has none yet."""
    return table.get(code) or table["en"]


def listed():
    """True unless the build is told (URMQTT_PRODUCTS_LISTED=0) to keep the pages out of the navigation."""
    return os.environ.get("URMQTT_PRODUCTS_LISTED", "1") != "0"


# build.py decides once per build (it sets PR.LISTED again after the import, the same way).
LISTED = listed()


def label(code):
    return pick(LABEL, code)


def slug(code):
    return pick(SLUG, code)


def products_url(code, home):
    return f"{home(code)}{slug(code)}/"


def builder_url(code, home):
    return f"{products_url(code, home)}{BUILDER_SLUG}/"


def about_urmqtt(post):
    """The posts about urMQTT: their directory in the blog starts with urmqtt (the next one is covered without a change)."""
    return post.dir.startswith("urmqtt")


def row_link(code, post, home):
    """The short link at the end of a blog card (home page, blog listing) of a post about urMQTT, else nothing."""
    if not (LISTED and about_urmqtt(post)):
        return ""
    return f'<br><a class="row-extra" href="{builder_url(code, home)}">{html.escape(pick(URMQTT, code)["builder"])} →</a>'


def post_note(code, post, home):
    """The same link under the lead of a post about urMQTT, as a one-line note in the site's own box style."""
    if not (LISTED and about_urmqtt(post)):
        return ""
    return (f'      <aside class="product-note"><strong>urMQTT</strong> · '
            f'<a href="{builder_url(code, home)}">{html.escape(pick(URMQTT, code)["builder"])} →</a></aside>\n')


def _manifest():
    try:
        with open(os.path.join(APP_DIR, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def manifest():
    """The content hashes of the application's files, for the ?v= parts of their addresses."""
    return _manifest().get("files", {})


def emulator_version():
    """The directory name of the emulator the application carries (None: this build has none)."""
    return _manifest().get("emulator")


# What shows while the application loads, shaped like the page it becomes (no layout shift).
SKELETON = (
    '<div class="ub ub-wrap" aria-hidden="true">'
    '<div class="ub-head"><span class="ub-skel" style="height:40px;width:46%;margin-bottom:16px"></span>'
    '<span class="ub-skel" style="height:22px;width:82%;margin-bottom:10px"></span><span class="ub-skel" style="height:22px;width:58%"></span></div>'
    '<div class="ub-layout"><div class="ub-main"><span class="ub-skel" style="height:300px"></span>'
    '<span class="ub-skel" style="height:130px"></span><span class="ub-skel" style="height:100px"></span></div>'
    '<div class="ub-aside"><span class="ub-skel" style="height:290px"></span></div></div></div>'
)


def render(kind, code, h):
    """-> {"main": html, "title": str, "desc": str, "head": html} for the products and builder pages.

    `h` carries what build.py already has: e (html.escape), home (code -> address of the home page), products
    (back link label source: the privacy page's "back" text), github_icon.
    """
    e = html.escape
    home = h["home"]
    if kind == "products":
        title, lead = pick(PAGE, code)
        u = pick(URMQTT, code)
        main = f"""  </div>
  <main class="wrap blog stack">
    <p class="crumbs"><a href="{home(code)}">← {e(h['back'])}</a></p>
    <h1>{e(title)}</h1>
    <p class="lead">{e(lead)}</p>
    <div class="group">
      <div><h2>urMQTT</h2></div>
      <div class="rows">
        <div class="row"><h3>urMQTT</h3><div><p><strong>{e(u['tagline'])}</strong></p><p style="margin-top:10px">{e(u['p1'])}</p><p style="margin-top:10px">{e(u['p2'])}</p></div></div>
        <div class="row"><h3><a class="row-link" href="{builder_url(code, home)}">{e(u['builder_h'])}</a> →</h3><p>{e(u['builder_p'])}</p></div>
        <div class="row"><h3><a class="row-link" href="{GITHUB_REPO}" rel="noopener">{e(u['source'])}</a> {h['github_icon']}</h3><p>{GITHUB_REPO.split('//')[1]}</p></div>
      </div>
    </div>
  </main>"""
        return {"main": main, "title": f"{title} | ALDO TECH", "desc": lead, "head": ""}
    # The builder page: the application mounts into #urmqtt-builder.
    b = pick(BUILDER, code)
    v = manifest()
    suffix = lambda f: f"?v={v[f]}" if f in v else ""
    data_v = e(json.dumps({"files": v, "emulator": emulator_version()}, separators=(",", ":")), quote=True)
    head = f'\n<link rel="stylesheet" href="{APP_URL}app.css{suffix("app.css")}">'
    main = f"""  </div>
  <main class="wrap">
    <p class="crumbs ub-crumbs" style="margin-top:28px"><a href="{products_url(code, home)}">← {e(b['back'])}</a></p>
    <div id="urmqtt-builder" class="ub-embedded" data-lang="{code}" data-base="{APP_URL}" data-releases="{RELEASES_URL}" data-v="{data_v}">
      {SKELETON}
      <noscript><p>{e(b['noscript'])}</p></noscript>
    </div>
    <div id="ub-live" class="sr-only" role="status" aria-live="polite"></div>
  </main>
  <script src="{APP_URL}app.js{suffix('app.js')}" defer></script>"""
    return {"main": main, "title": f"{b['title']} | ALDO TECH", "desc": b["desc"], "head": head}
