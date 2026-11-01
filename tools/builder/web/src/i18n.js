// Texts of the page. One JSON file per site language (i18n/<lang>.json); a key
// missing in a language falls back to English. Field labels are the TOML keys
// and the help texts come from the schema, in English (ADR-226): only the page's
// own words and the section names are translated.

let texts = {};
let fallbackTexts = {};
let pageLang = 'en';

/** Loads the language file (and English as the fallback). */
async function loadTexts(base, lang, version) {
  const get = async code => {
    const v = version && version[`i18n/${code}.json`];
    const res = await fetch(`${base}i18n/${code}.json${v ? `?v=${v}` : ''}`);
    if (!res.ok) throw new Error(`texts ${code}: HTTP ${res.status}`);
    return res.json();
  };
  pageLang = lang;
  fallbackTexts = await get('en');
  texts = lang === 'en' ? fallbackTexts : await get(lang).catch(() => fallbackTexts);
}

/** The text for `key`, with {name} placeholders filled from `args`. */
function t(key, args) {
  let s = texts[key] ?? fallbackTexts[key] ?? key;
  if (args) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in args ? String(args[k]) : m));
  return s;
}

const has = key => key in texts || key in fallbackTexts;
const currentLang = () => pageLang;
