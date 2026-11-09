# Release day: v0.5.0

For the maintainer: the commands for the day, in order. Made from docs/release-day-template.md and
docs/release-day-v0.4.2.md. Nothing here has been run; docs/RELEASE.md explains each step and the rollback (section
6). The preparation (version, CHANGELOG, notes, local gates) is on the branch `release-v0.5.0`; its local results are
in docs/PROGRESS.md, "Release candidate v0.5.0".

What is new on the day, against docs/release-day-v0.4.2.md:

- **The key is unchanged.** v0.5.0 is the second release signed with the release key `721316B961DCB94B`; the key
  rotation is done (docs/release-key-rotation.md). Only the checks remain: no key step.
- **The builder page must be redeployed, before the tag.** The configuration format goes from 7 to 13 (ADR-269,
  ADR-270, ADR-272, ADR-274, ADR-275), and the live page reads format 7 (its manifest, checked 2026-11-09: `"format":
  7`, `urmqtt-cfg7.wasm`). A format-7 page greys out a template of format 13, and the mirror runs hourly: deploy the
  page built from the release commit **after CI is green and before the tag** (step 2). A format-13 page serves
  v0.4.2 and older as before (a configuration is written in the lowest format that holds it).
- **The database migrates one way** (schema 2 to 5 at the first boot): the notes say so first; the rollback (step 9)
  cannot give a v0.4.2 kernel a migrated disk.
- The assets are named as for v0.4.2 (`urmqtt-v0.5.0.elf/.iso/.img/.cdx.json`, the template, `SHA256SUMS` and its
  signature); trusted comment `urMQTT v0.5.0 release <commit>`.

## 0. Check what is in place

```bash
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -c "import json,sys; d=json.load(sys.stdin); print([(r['tag'], (r.get('template') or {}).get('config_format'), (r.get('signed_by') or {}).get('key_id')) for r in d['releases']])"
#   v0.4.2 7 721316B961DCB94B; v0.4.1 to v0.2.0 the test key 9229E05252D01F8E (6, 6, 4, 3, 2); v0.1.0 None None
curl -fsS https://aldo.tech/urmqtt/builder/manifest.json | python3 -I -c "import json,sys; d=json.load(sys.stdin); print(d['format'], [k for k in d['files'] if k.endswith('.wasm')])"
#   7 [... 'urmqtt-cfg7.wasm']: the page to replace in step 2
ssh build systemctl cat urmqtt-mirror | grep ExecStart     # ... --keyring /etc/urmqtt-mirror/keys/release-keys.json
gh secret list --repo zeljan-alduk/urMQTT                  # MINISIGN_SECRET_KEY
```

## 1. Merge and wait for CI

```bash
cd ~/dev/urMQTT                     # a normal clone, not a worktree nested in another checkout
git switch main && git pull --ff-only
git merge --no-ff release-v0.5.0    # or through a pull request
git push origin main
gh run list --repo zeljan-alduk/urMQTT --branch main --limit 5
gh run watch --repo zeljan-alduk/urMQTT          # CI on the merge commit: every job green, "Release keys" included
RELEASE_COMMIT=$(git rev-parse HEAD); echo "$RELEASE_COMMIT"
scripts/check-release-key.sh                     # ok: release 721316B961DCB94B v0.4.2 and later, test 9229E05252D01F8E v0.1.0 to v0.4.1
make repro ENV=release                           # both release kernels, the template ISO and the raw image: identical twice
```

Do not tag before CI is green on `$RELEASE_COMMIT`. Before this branch, `main`'s Lint job failed at shellcheck (SC2016
in `scripts/smoke.sh`, since 3bdbe01); the branch carries the fix (docs/PROGRESS.md, "Release candidate v0.5.0"). If a job fails, fix on `main` and start again here; the date in
CHANGELOG (`[0.5.0] - 2026-11-09`) is the preparation date: change it in the fix commit if the tag lands on another
day. Also: `git status` is clean and `git describe --tags` says `v0.4.2-<n>-g<commit>`.

## 2. The builder page, before the tag

Built from `$RELEASE_COMMIT` (format 13, both keys), deployed with the urMQTT script, published with the site's own
publisher. **Never the aldotech-web repository's `deploy.sh`** (it rsyncs with `--delete` and removes the builder,
`products*.py` and the patch; docs/RELEASE.md section 4).

```bash
git switch --detach "$RELEASE_COMMIT"
make builder-emulator                              # build/builder/; the emulator download is pinned by hash
python3 -I -c "import json; d=json.load(open('build/builder/manifest.json')); print(d['format'], d.get('release_key'), [k['name'] for k in d.get('keys', [])])"
#   13 721316B961DCB94B ['release', 'test']
make builder-test                                  # with the emulator runtime: every test passes
ssh build "grep -q 'import demo as DM' /opt/aldotech-site/site/build.py && echo demo-patched || echo no-demo"
scripts/deploy-builder-site.sh --dry-run           # add --with-demo only if the line above said demo-patched (then `make demo-page` first)
scripts/deploy-builder-site.sh --chown aldotech:aldotech
ssh build 'runuser -u aldotech -- /opt/aldotech-site/publish.sh'   # leaves /urmqtt/releases/ alone
curl -fsS https://aldo.tech/urmqtt/builder/manifest.json | python3 -I -c "import json,sys; d=json.load(sys.stdin); print(d['format'])"   # 13
git switch main
```

In a browser on `https://aldo.tech/en/products/urmqtt-builder/` and the Croatian page: v0.4.2 is still the chosen
release and builds; the advanced view offers `[websocket]`, `[mqtt5]`, `limits.publisher_backpressure`,
`devices.virtio_net_interrupt` and the shared-group limits; with one of them set, v0.4.2 is refused with "use a
newer release" (no release reads format 8 or newer yet). The statuses of the URLs in `sitemap.xml` are unchanged.
If the page misbehaves: docs/DEPLOY.md section 10, "Rolling back", and stop here (do not tag).

## 3. Tag and push

Earlier tags (v0.2.0 to v0.4.2) are annotated, not signed; v0.5.0 follows them.

```bash
git switch main && git pull --ff-only
test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
git tag -a v0.5.0 -m "urMQTT v0.5.0" "$RELEASE_COMMIT"
git cat-file -t v0.5.0                                  # tag
git push origin v0.5.0                                  # starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT
```

The workflow runs `scripts/check-release-key.sh` and checks the signing secret before building, builds `make dist
ENV=release` on an arm64 runner, checks the asset set (no dev asset, the `.iso` equal to the template, no PEM private
key), signs `SHA256SUMS` (trusted comment `urMQTT v0.5.0 release <commit>`), verifies it with `minisign.pub`, attests
the SBOM and the provenance and creates the pre-release.

## 4. The release notes

```bash
gh release edit v0.5.0 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.5.0.md
gh release view v0.5.0 --repo zeljan-alduk/urMQTT --json isPrerelease,isDraft,assets -q '.isPrerelease, .isDraft, [.assets[].name]'
```

Expected: `true`, `false`, and the seven files `SHA256SUMS`, `SHA256SUMS.minisig`, `urmqtt-v0.5.0.cdx.json`,
`urmqtt-v0.5.0.elf`, `urmqtt-v0.5.0.img`, `urmqtt-v0.5.0.iso`, `urmqtt-template-v0.5.0-universal.iso`; no
`urmqtt-dev-*`. Only if the workflow did not create the release: `gh release create v0.5.0 --repo zeljan-alduk/urMQTT
--verify-tag --prerelease --notes-file docs/release-notes-v0.5.0.md <the workflow's files>`.

## 5. Verify the assets

In an empty directory outside the repository:

```bash
mkdir /tmp/urmqtt-v0.5.0 && cd /tmp/urmqtt-v0.5.0
gh release download v0.5.0 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.5.0/minisign.pub
head -1 minisign.pub                             # untrusted comment: minisign public key 721316B961DCB94B
minisign -Vm SHA256SUMS -p minisign.pub          # Trusted comment: urMQTT v0.5.0 release $RELEASE_COMMIT
shasum -a 256 -c SHA256SUMS                      # every file OK
cmp urmqtt-v0.5.0.iso urmqtt-template-v0.5.0-universal.iso
gh attestation verify urmqtt-v0.5.0.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-v0.5.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json; d=json.load(open('urmqtt-v0.5.0.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The key ring and the release kernel, from the clone at the tag:

```bash
cd ~/dev/urMQTT && git switch --detach v0.5.0
cargo build --release -p urmqtt-config-tool
(cd /tmp/urmqtt-v0.5.0 && ~/dev/urMQTT/target/release/urmqtt-config check-release --keyring ~/dev/urMQTT/keys/release-keys.json --tag v0.5.0 --sums SHA256SUMS urmqtt-*)
target/release/urmqtt-config verify /tmp/urmqtt-v0.5.0/urmqtt-v0.5.0.img      # the empty configuration, format 13
make dist ENV=release && grep 'urmqtt-v0.5.0.elf' build/dist/SHA256SUMS
grep 'urmqtt-v0.5.0.elf' /tmp/urmqtt-v0.5.0/SHA256SUMS   # the same line only with clang 18.1.3 (Ubuntu 24.04 runner); a Mac's clang differs and so does the ELF (checked on release day: clang 23.1.1)
```

The `.iso` and `.img` lines match only with the runner's xorriso and mtools (Ubuntu 24.04 arm64), not necessarily on
macOS (docs/RELEASE.md section 0.6).

## 6. The templates: format 7 and format 13

The check of the preparation (docs/PROGRESS.md, "Release candidate v0.5.0") with the published template. Still in the
clone at the tag:

```bash
mkdir -p /tmp/urmqtt-v0.4.2 && (cd /tmp/urmqtt-v0.4.2 && gh release download v0.4.2 --repo zeljan-alduk/urMQTT -p 'urmqtt-template-*' -p 'SHA256SUMS*' --skip-existing \
  && minisign -Vm SHA256SUMS -p ~/dev/urMQTT/minisign.pub && shasum -a 256 -c SHA256SUMS --ignore-missing)
make certs
mkdir -p /tmp/cfg-7 /tmp/cfg-13
cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-7/ && cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-13/
printf '[tls]\ncert = "server.pem"\nkey = "server.key"\n\n[trust]\noperational = ["ca.pem"]\n\n[control]\npublic_key = "control.pub"\n\n[network]\nmtu = 1460\n' > /tmp/cfg-7/config.toml
{ cat /tmp/cfg-7/config.toml; printf '\n[limits]\nmax_shared_groups = 64\n'; } > /tmp/cfg-13/config.toml
for f in 7 13; do for t in v0.5.0 v0.4.2; do
  echo "== format $f, $t"; target/release/urmqtt-config pack /tmp/cfg-$f/config.toml --iso /tmp/urmqtt-$t/urmqtt-template-$t-universal.iso --out /tmp/mine-$f-$t.iso
done; done
target/release/urmqtt-config show /tmp/mine-13-v0.5.0.iso | head -5   # urmqtt-cfg version 13
git switch main
```

Expected: format 7 packs on v0.5.0 and v0.4.2 (the same fingerprint); format 13 packs on v0.5.0 and is refused by
v0.4.2 with "this configuration needs configuration format 13, which this template's kernel does not read (it reads
up to 7): use a newer release".

## 7. The mirror and the builder page

The page was deployed in step 2. The mirror picks the release up within the hour; to do it now:

```bash
ssh build systemctl start urmqtt-mirror
ssh build journalctl -u urmqtt-mirror -n 50 --no-pager      # exit 0; "release v0.5.0: mirrored urmqtt-template-v0.5.0-universal.iso (..., config format 13); signature ok (key 721316B961DCB94B, ...)"
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A30 '"tag": "v0.5.0"'
```

Expected for v0.5.0: `"prerelease": true`, `"status": "ok"`, `"verified": true`, `"signed_by": {"key_id":
"721316B961DCB94B", "name": "release", ...}`, and a `template` whose `sha256` equals the template's line in
`SHA256SUMS` and whose `"config_format": 13`. v0.4.2 unchanged (format 7, the release key); v0.4.1 to v0.2.0
unchanged (the test key); v0.1.0 listed without a template.

In a browser on `https://aldo.tech/en/products/urmqtt-builder/` and the Croatian page:

- v0.5.0 is the chosen release; the check mark names the key `721316B961DCB94B` without the test-key note;
- a build ends in a result card and "Try in the emulator" boots it;
- with `[mqtt5]`, `[websocket]` or a shared-group limit set, v0.5.0 builds and v0.4.2 chosen by hand is refused with
  "use a newer release"; with `network.mtu` set, v0.5.0 and v0.4.2 build; TLS off still picks v0.2.1 or newer;
- v0.4.1 and older, chosen by hand, show "signed with the project's former test key" and still verify;
- the statuses of the URLs in `sitemap.xml` are unchanged.

## 8. After

- `docs/VULNERABILITY-HANDLING.md` section 6 needs no edit (the latest release is supported): v0.4.2 and older stop
  being supported, as the notes say.
- The `[Unreleased]` section of CHANGELOG.md is empty and open.
- Record the results of steps 2, 5, 6 and 7 in docs/PROGRESS.md.
- The VPS measurement of v0.5.0 (PERFORMANCE section 13's pair) is the blog post the notes announce; the notes carry
  only the 2026-11-07/08 numbers.

## 9. Rollback (details in docs/RELEASE.md section 6)

- **Workflow failed, no release:** `git tag -d v0.5.0 && git push origin :refs/tags/v0.5.0`, fix on `main`, start
  again at step 1. The page (format 13) and the mirror keep offering v0.4.2. If it failed at `check-release-key.sh` or
  the secret check, the cause is the key setup, not the code.
- **A bad release is published:** `gh release edit v0.5.0 --repo zeljan-alduk/urMQTT --prerelease --notes "WITHDRAWN:
  <reason>"`; to keep the page from offering it, delete its assets or the release (the mirror marks it removed;
  `ssh build systemctl start urmqtt-mirror` applies it now) and the page goes back to v0.4.2. Do not reuse the tag for
  different bytes; publish v0.5.1.
- **The page misbehaves:** restore it as in docs/DEPLOY.md section 10, "Rolling back" (the backups the deploy script
  made), then withdraw v0.5.0 as above if the mirror already lists it: a format-7 page greys it out anyway.
- **Users who want v0.4.2 back:** the disk layout (v2.1) is the same but the database is not: a v0.4.2 kernel refuses
  a disk v0.5.0 has booted (schema 5) and the snapshots v0.5.0 took. Pack the same configuration without format 8 to
  13 keys into the v0.4.2 template and give it the data disk copied or backed up before the update, or a new disk.
