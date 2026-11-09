# NOW-16: encryption at rest on the builder page

Branch `v060/now16`, ADR-300. Only `tools/builder/web` (page script, style, texts), its tests and docs changed.

## What changes for operators

- The builder page has a new card, **Project and secrets** (simple and advanced view):
  - **Save encrypted project**: the whole form (changed values, certificates, the private key, the accounts with
    their hashes, the signing key) is encrypted in the browser with a passphrase and downloaded as
    `<name>.urmqtt-project`. **Open encrypted project** loads it again; the TOML it produces is the same as before
    saving.
  - **Keep encrypted copy in this browser**, **Restore browser copy**, **Delete browser copy**: the same envelope in
    the browser's `localStorage` under `urmqtt-builder-vault-v1`, only when asked for.
  - **Wipe secrets from memory**: drops the private key, the signing key, the accounts and the built image from the
    page. A browser cannot overwrite a string, so close the tab afterwards (the page says so).
- Cryptography: PBKDF2-HMAC-SHA-256 (600 000 rounds, random 16-byte salt), AES-256-GCM (random 12-byte nonce, the
  header authenticated), non-extractable key, plaintext padded to 4096 bytes. Passphrase: at least 12 characters
  when saving, NFKC-normalised, never stored. A forgotten passphrase cannot be recovered.
- Envelope: JSON with `format = urmqtt-project`, `version = 1`. Files outside 200 000 to 5 000 000 rounds, with other
  algorithms, extra fields, bad lengths or more than 8 MiB are refused before any key is derived.
- Unchanged: the address bar and `sessionStorage` still never hold a private key, an account or a hash (ADR-226); the
  page makes no new request; CSP is unchanged.

## Configuration keys, format, store

None. No configuration format number, no store schema, no kernel or crate change. Upgrading and downgrading the
kernel is unaffected; a project file is page data, not image data.

## Deploy note

The page is static: `app.js`, `app.css` and `i18n/*.json` (40 new `project.*` keys in each of the 15 languages)
change. The owner deploys the site later; aldotech-web was not touched.

## Tests

`tools/builder/test/vault.test.mjs`, `vault-page.test.mjs`, `vault-fuzz.test.mjs` (seeds in
`tools/builder/test/seeds/vault/`, `make-vault-seeds.mjs` regenerates them; `VAULT_FUZZ_SECONDS=120` for the long
run), `i18n.test.mjs` extended.

## Deliberately not done

- The disk-key dialog of the original NOW-16 text (generate/download/import for configuration format 4): needs a
  format number and belongs with LATER-7; `storage.encryption` and `storage.disk_key` stay hidden on the page.
- A memory-hard KDF (Argon2, scrypt): not in Web Crypto, and a WebAssembly one would add trusted code to the page.
- Automatic saving, sync, passphrase recovery, true zeroisation of JavaScript strings.
