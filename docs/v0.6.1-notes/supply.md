# v0.6.1 release notes: supply chain, build, CI and release (security review of v0.6.0)

- **Release signing is separated from the build (SUPPLY-1, medium, ADR-380).** The release key is now used only by a
  `sign` job in the protected GitHub environment `release` (required reviewer, `v*` tags only) that builds nothing;
  the build job holds no secret and no write permission and refuses a tag whose commit is not on `main`; the key is
  passed to minisign through a pipe, never a file. Owner action before the next release: create the environment and
  move the secret (docs/release-key-rotation.md step 2).
- **A release's signature is bound to its tag (SUPPLY-2, medium, ADR-381).** The builder page, the release mirror
  and `urmqtt-config check-release --keyring --tag` refuse a signed `SHA256SUMS` whose trusted comment names another
  tag, so a mirror can no longer offer an older signed release as a newer one.
- **`urmqtt-disk slots stage --keyring` (SUPPLY-3, low, ADR-382).** Staging a release can apply the key ring (key
  ranges, pins of the former test key, the signed tag); DEPLOY.md now uses it. `--pubkey` alone warns that it does not.
- **Release links checked (SUPPLY-4, low, ADR-383).** The builder page shows a release's "GitHub" and "attestations"
  links only when they are that release's pages on github.com.
