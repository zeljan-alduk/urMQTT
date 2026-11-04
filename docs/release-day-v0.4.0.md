# Release day: v0.4.0

For the maintainer: the commands for the day, in order. Nothing here has been run; docs/RELEASE.md explains each
step and the rollback (section 6). The preparation (version, CHANGELOG, notes, local gates) is on the branch
`release-v0.4.0`; its local results are in docs/PROGRESS.md, "Release candidate v0.4.0".

The order matters for one reason: the builder page reads the configuration format of each release's template from the
mirror's `releases.json`, and a page built before this release (format 4) lists a format-6 template as unusable. The
mirror job runs **every hour by itself** once the GitHub release exists, so the new page goes onto aldo.tech **before
the tag is pushed**. The new page is safe with the old releases: it chooses v0.3.0 until v0.4.0 is mirrored.

## 1. Merge and wait for CI

```bash
cd ~/dev/urMQTT                     # a normal clone, not a worktree nested in another checkout
git switch main && git pull --ff-only
git merge --no-ff release-v0.4.0    # or through a pull request
git push origin main
gh run list --repo zeljan-alduk/urMQTT --branch main --limit 5
gh run watch --repo zeljan-alduk/urMQTT          # CI on the merge commit: every job green
RELEASE_COMMIT=$(git rev-parse HEAD); echo "$RELEASE_COMMIT"
```

Do not tag before CI is green on `$RELEASE_COMMIT`. If a job fails, fix on `main` and start again here; the date in
CHANGELOG (`[0.4.0] - 2026-11-04`) is the preparation date: change it in the fix commit if the tag lands on another day.

Also check before the tag:

- the secret `MINISIGN_SECRET_KEY` still exists (`gh secret list --repo zeljan-alduk/urMQTT`; it was there on
  2026-11-04), or the assets are published unsigned and the mirror and the page refuse them;
- `git status` is clean and `git describe --tags` says `v0.3.0-<n>-g<commit>`.

## 2. The builder page, from the release commit, before the tag

On the Mac, in a clean checkout of `$RELEASE_COMMIT`:

```bash
git switch --detach "$RELEASE_COMMIT"
make builder-emulator               # build/builder/: urmqtt-cfg6.wasm, app.js, i18n/, emulator/ (a pinned 45 MB download, hash-checked)
ls build/builder/urmqtt-cfg6.wasm build/builder/manifest.json build/builder/emulator
make builder-test                   # every test passes with the emulator runtime in place
```

Then put it into the site generator on the server and publish with the site's own script (host `build`, the site's
user `aldotech`):

```bash
scripts/deploy-builder-site.sh --dry-run                 # prints the rsync lines; runs apply_products.py --check over ssh
scripts/deploy-builder-site.sh --chown aldotech:aldotech # copies products*.py, apply_products.py and build/builder/ (as urmqtt-builder/) to /opt/aldotech-site/site
ssh build runuser -u aldotech -- /opt/aldotech-site/publish.sh   # build.py, then rsync -a --delete --exclude /urmqtt/releases/ into the web root
```

- `deploy-builder-site.sh` copies `build/builder/` with `--delete`, so the old `urmqtt-cfg4.wasm` goes and
  `urmqtt-cfg6.wasm` comes; `apply_products.py` leaves an already patched `build.py` alone.
- **Never run `deploy.sh` of the aldotech-web repository** for this, and not on this day at all: it rsyncs that
  repository's `site/` over `/opt/aldotech-site/site/` with `--delete`, which removes `urmqtt-builder/`,
  `products.py`, `products_i18n.py` and `apply_products.py` (they exist only on the server), and so the builder
  page. If it was run by mistake, run the two `deploy-builder-site.sh` and `publish.sh` lines above again.
- `publish.sh` never touches `/urmqtt/releases/` (the mirror's directory, its own user).

Check the page now, with the old releases (it must still work): `https://aldo.tech/en/products/urmqtt-builder/` and
the Croatian page; v0.3.0 is chosen, the signature check mark appears, a build ends in a result card, "Try in the
emulator" boots it, TLS off still chooses v0.2.1 or newer. With `console.virtio_gpu = "on"` in the advanced view the
build is refused with "use a newer release" (no release with format 6 is mirrored yet). The statuses of the URLs in
`sitemap.xml` are the same as before.

## 3. Tag and push

```bash
git switch main && git pull --ff-only
test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
git tag -s v0.4.0 -m "urMQTT v0.4.0" "$RELEASE_COMMIT"   # -a instead of -s if you do not sign tags
git push origin v0.4.0                                  # starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT
```

The workflow builds `make dist ENV=dev` on an arm64 runner, signs `SHA256SUMS` (trusted comment
`urMQTT v0.4.0 dev <commit>`), attests the SBOM and the provenance and creates the GitHub release as a pre-release.

## 4. The release notes

The workflow has created the release with generated notes; replace them:

```bash
gh release edit v0.4.0 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.4.0.md
gh release view v0.4.0 --repo zeljan-alduk/urMQTT --json isPrerelease,isDraft,assets -q '.isPrerelease, .isDraft, [.assets[].name]'
```

Expected: `true`, `false`, and the seven files `SHA256SUMS`, `SHA256SUMS.minisig`, `urmqtt-dev-v0.4.0.cdx.json`,
`urmqtt-dev-v0.4.0.elf`, `.img`, `.iso`, `urmqtt-template-v0.4.0-universal.iso`. Only if the workflow did not create
the release: `gh release create v0.4.0 --repo zeljan-alduk/urMQTT --verify-tag --prerelease --notes-file
docs/release-notes-v0.4.0.md <the workflow's files>`.

## 5. Verify the assets

In an empty directory outside the repository:

```bash
mkdir /tmp/urmqtt-v0.4.0 && cd /tmp/urmqtt-v0.4.0
gh release download v0.4.0 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.0/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # comment: urMQTT v0.4.0 dev $RELEASE_COMMIT
shasum -a 256 -c SHA256SUMS
gh attestation verify urmqtt-dev-v0.4.0.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-dev-v0.4.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json; d=json.load(open('urmqtt-dev-v0.4.0.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The template, with the tool of the tag (in the clone):

```bash
cargo build --release -p urmqtt-config-tool
target/release/urmqtt-config pack deploy/dev/config.toml --iso /tmp/urmqtt-v0.4.0/urmqtt-template-v0.4.0-universal.iso --out /tmp/mine.iso
target/release/urmqtt-config show /tmp/mine.iso
```

`deploy/dev/config.toml` sets `console.virtio_gpu` and the `[devices]` keys to "auto", so this pack is format 6: it
succeeds with the v0.4.0 template, and the same command with the v0.3.0 template must be refused ("needs
configuration format 6 ... reads up to 4: use a newer release"). The kernel: `make build ENV=dev ARCH=aarch64` on the tag and compare
`shasum -a 256 target/aarch64-unknown-none/release/urmqtt` with the `.elf` line of `SHA256SUMS`.

## 6. The mirror

It picks the release up within the hour. To do it now, on the web server as root:

```bash
systemctl start urmqtt-mirror
journalctl -u urmqtt-mirror -n 50 --no-pager            # exit 2 means a release failed verification
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A25 '"tag": "v0.4.0"'
```

Expected for `v0.4.0`: `"prerelease": true`, `"status": "ok"`, `"verified": true`, a `template` whose `sha256` is the
template's line in `SHA256SUMS` and whose `config_format` is **6**. v0.3.0, v0.2.1, v0.2.0 (format 4, 3, 2) and v0.1.0
(no template) stay listed as before.

Then the page again: v0.4.0 is the chosen release, the check mark appears, a build ends in a result card, the emulator
boots it, and with `console.virtio_gpu = "on"` or a `[devices]` key not "off" the build succeeds with v0.4.0 and is
refused for v0.3.0 chosen by hand.

## 7. After

- `docs/VULNERABILITY-HANDLING.md` section 6 needs no edit (the latest release is supported): v0.3.0 and older stop
  being supported, as the notes say.
- The `[Unreleased]` section of CHANGELOG.md is empty and open.

## 8. Rollback (details in docs/RELEASE.md section 6)

- **Workflow failed, no release:** `git tag -d v0.4.0 && git push origin :refs/tags/v0.4.0`, fix on `main`, start
  again at step 1. The new page stays: it works with v0.3.0.
- **A bad release is published:** `gh release edit v0.4.0 --repo zeljan-alduk/urMQTT --prerelease --notes "WITHDRAWN:
  <reason>"`; to keep the page from offering it, delete its assets or the release (the mirror marks it removed;
  `systemctl start urmqtt-mirror` applies it now). Do not reuse the tag for different bytes; publish v0.4.1.
- **The page misbehaves:** go back to the v0.3.0 page: `git switch --detach v0.3.0 && make builder-emulator`, the same
  `deploy-builder-site.sh --chown aldotech:aldotech` and `publish.sh` lines as in step 2. That page lists v0.4.0 as
  unusable and keeps offering v0.3.0. The mirror needs no change.
- **Users who want v0.3.0 back:** the disk layout is unchanged; repack the configuration with `console.virtio_gpu` and
  the `[devices]` keys "off" into the v0.3.0 template.
