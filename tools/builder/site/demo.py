"""The "Try urMQTT live" page of aldo.tech (D1b), for build.py of the site generator (patched by apply_demo.py).

render(code, h) returns the page's <main>, title, description and <head> addition, like products.render. The application
(script, style, texts, the certificate download) is built by `node tools/builder/demo/bundle.mjs` and copied to
site/urmqtt-demo/ by scripts/deploy-builder-site.sh --with-demo; the generator publishes it as /urmqtt/demo/.

Unlisted by default: no header or footer link, no sitemap entry, noindex, reachable by its address only, until the owner
sets URMQTT_DEMO_LISTED=1 in the environment of the build. Texts: English and Croatian; every other language shows the
English page (the application itself falls back the same way).
"""
import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_SLUG = "urmqtt-live"
APP_DIR = os.environ.get("URMQTT_DEMO_DIR", os.path.join(HERE, "urmqtt-demo"))
APP_URL = os.environ.get("URMQTT_DEMO_APP_URL", "/urmqtt/demo/")
BROKER_HOST = os.environ.get("URMQTT_DEMO_BROKER_HOST", "demo-mqtt.aldo.tech")

TEXT = {
    "en": {"title": "Try urMQTT live", "desc": "A real urMQTT broker you can use from your browser: connect, subscribe, publish and watch the messages. A shared toy; nothing private.",
           "back": "Products", "noscript": "This page needs JavaScript to run an MQTT client in your browser."},
    "hr": {"title": "Isprobajte urMQTT uživo", "desc": "Pravi urMQTT broker koji možete koristiti iz preglednika: spojite se, pretplatite, objavite i gledajte poruke. Zajednička igračka; ništa privatno.",
           "back": "Proizvodi", "noscript": "Ova stranica treba JavaScript za pokretanje MQTT klijenta u Vašem pregledniku."},
}


def listed():
    return os.environ.get("URMQTT_DEMO_LISTED", "0") == "1"


LISTED = listed()


def pick(code):
    return TEXT.get(code) or TEXT["en"]


def demo_url(code, home):
    """The page's address in a language: next to the Products page (…/<products slug>/urmqtt-live/)."""
    from products import products_url
    return f"{products_url(code, home)}{DEMO_SLUG}/"


def _manifest():
    try:
        with open(os.path.join(APP_DIR, "manifest.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def render(code, h):
    """-> {"main", "title", "desc", "head"}; `h` carries e (unused), home (code -> home address) and back (label source)."""
    from products import products_url
    e = html.escape
    home = h["home"]
    x = pick(code)
    v = _manifest().get("files", {})
    suffix = lambda f: f"?v={v[f]}" if f in v else ""
    data_v = e(json.dumps({"files": v}, separators=(",", ":")), quote=True)
    head = f'\n<link rel="stylesheet" href="{APP_URL}app.css{suffix("app.css")}">'
    main = f"""  </div>
  <main class="wrap">
    <p class="crumbs" style="margin-top:28px"><a href="{products_url(code, home)}">← {e(x['back'])}</a></p>
    <div id="urmqtt-demo" data-lang="{code}" data-base="{APP_URL}" data-broker="{e(BROKER_HOST)}" data-v="{data_v}">
      <noscript><p>{e(x['noscript'])}</p></noscript>
    </div>
  </main>
  <script src="{APP_URL}app.js{suffix('app.js')}" defer></script>"""
    return {"main": main, "title": f"{x['title']} | ALDO TECH", "desc": x["desc"], "head": head}
