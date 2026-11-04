# Release day: v0.4.1

For the maintainer: the commands for the day, in order. Nothing here has been run; docs/RELEASE.md explains each
step and the rollback (section 6). The preparation (version, CHANGELOG, notes, local gates) is on the branch
`release-v0.4.1`; its local results are in docs/PROGRESS.md, "Release candidate v0.4.1".

**No builder page deploy this time.** `git diff v0.4.0..main -- tools/builder crates/config-schema crates/cfg
crates/config tools/config` is empty (checked at 51fabe2, the commit this branch starts from), and the configuration
format stays 6. The page deployed for v0.4.0 already reads format-6 templates, so it offers v0.4.1 as soon as the
mirror lists it. Nothing goes onto aldo.tech by hand: the mirror picks the release up by itself within the hour, or at
once with `systemctl start urmqtt-mirror` (step 6). Check the diff again on the release commit (step 1); if it is not
empty, do docs/release-day-v0.4.0.md step 2 (the page, before the tag) first.

**Blocker found during the preparation: do not tag until it is explained.** The `storm` smoke scenario hangs with
every kernel that contains 1fb37ba (4 of 4 runs on HVF; v0.4.0's kernel passed 2 of 2): docs/PROGRESS.md, "Release
candidate v0.4.1". CI's "Smoke misc (QEMU TCG)" job runs that scenario, so step 1 cannot be green while it hangs (the
job's timeout is 120 minutes). To check it on the Mac before merging a fix:
`SMOKE_ONLY=misc SMOKE_GROUPS='^storm$' scripts/smoke.sh --accels hvf` (passes in about 3 minutes, or hangs with the
connections stuck below 3000 in round 1).

## 1. Merge and wait for CI

```bash
cd ~/dev/urMQTT                     # a normal clone, not a worktree nested in another checkout
git switch main && git pull --ff-only
git merge --no-ff release-v0.4.1    # or through a pull request
git push origin main
gh run list --repo zeljan-alduk/urMQTT --branch main --limit 5
gh run watch --repo zeljan-alduk/urMQTT          # CI on the merge commit: every job green
RELEASE_COMMIT=$(git rev-parse HEAD); echo "$RELEASE_COMMIT"
git diff --stat v0.4.0.."$RELEASE_COMMIT" -- tools/builder crates/config-schema crates/cfg crates/config tools/config   # must print nothing
```

Do not tag before CI is green on `$RELEASE_COMMIT`, "Smoke misc (QEMU TCG)" included (the `storm` blocker above). CI's `make ct` on the arm64 runner is the first run of the new
`x25519_ladder_is_constant_time` case outside Docker on the Mac: look at its |t| in the job log. If a job fails, fix
on `main` and start again here; the date in CHANGELOG (`[0.4.1] - 2026-11-04`) is the preparation date: change it in
the fix commit if the tag lands on another day.

Also check before the tag:

- the secret `MINISIGN_SECRET_KEY` still exists (`gh secret list --repo zeljan-alduk/urMQTT`; it was there on
  2026-11-04), or the assets are published unsigned and the mirror and the page refuse them;
- `git status` is clean and `git describe --tags` says `v0.4.0-<n>-g<commit>`.

## 2. Tag and push

Earlier tags (v0.2.0 to v0.4.0) are annotated, not signed; v0.4.1 follows them.

```bash
git switch main && git pull --ff-only
test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
git tag -a v0.4.1 -m "urMQTT v0.4.1" "$RELEASE_COMMIT"
git cat-file -t v0.4.1                                  # tag
git push origin v0.4.1                                  # starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT
```

The workflow builds `make dist ENV=dev` on an arm64 runner, signs `SHA256SUMS` (trusted comment
`urMQTT v0.4.1 dev <commit>`), attests the SBOM and the provenance and creates the GitHub release as a pre-release.

## 3. The release notes

The workflow has created the release with generated notes; replace them:

```bash
gh release edit v0.4.1 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.4.1.md
gh release view v0.4.1 --repo zeljan-alduk/urMQTT --json isPrerelease,isDraft,assets -q '.isPrerelease, .isDraft, [.assets[].name]'
```

Expected: `true`, `false`, and the seven files `SHA256SUMS`, `SHA256SUMS.minisig`, `urmqtt-dev-v0.4.1.cdx.json`,
`urmqtt-dev-v0.4.1.elf`, `.img`, `.iso`, `urmqtt-template-v0.4.1-universal.iso`. Only if the workflow did not create
the release: `gh release create v0.4.1 --repo zeljan-alduk/urMQTT --verify-tag --prerelease --notes-file
docs/release-notes-v0.4.1.md <the workflow's files>`.

## 4. Verify the assets

In an empty directory outside the repository:

```bash
mkdir /tmp/urmqtt-v0.4.1 && cd /tmp/urmqtt-v0.4.1
gh release download v0.4.1 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.1/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # comment: urMQTT v0.4.1 dev $RELEASE_COMMIT
shasum -a 256 -c SHA256SUMS
gh attestation verify urmqtt-dev-v0.4.1.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-dev-v0.4.1.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json; d=json.load(open('urmqtt-dev-v0.4.1.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The template, with the tool of the tag (in the clone), and the two earlier templates for comparison:

```bash
cd ~/dev/urMQTT && git switch --detach v0.4.1
make certs && cargo build --release -p urmqtt-config-tool
for t in v0.4.0 v0.3.0; do
  mkdir -p /tmp/urmqtt-$t && (cd /tmp/urmqtt-$t && gh release download $t --repo zeljan-alduk/urMQTT -p 'urmqtt-template-*' -p 'SHA256SUMS*' --skip-existing \
    && minisign -Vm SHA256SUMS -p ~/dev/urMQTT/minisign.pub && shasum -a 256 -c SHA256SUMS --ignore-missing)
done
mkdir -p /tmp/cfg-new && cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-new/
printf '[tls]\ncert = "server.pem"\nkey = "server.key"\n\n[trust]\noperational = ["ca.pem"]\n\n[control]\npublic_key = "control.pub"\n\n[console]\nvirtio_gpu = "on"\n\n[devices]\nvirtio_balloon = "on"\n' > /tmp/cfg-new/config.toml
for t in v0.4.1 v0.4.0 v0.3.0; do
  echo "== $t"; target/release/urmqtt-config pack /tmp/cfg-new/config.toml --iso /tmp/urmqtt-$t/urmqtt-template-$t-universal.iso --out /tmp/mine-$t.iso
done
target/release/urmqtt-config show /tmp/mine-v0.4.1.iso | head -5   # format: urmqtt-cfg version 6
git switch main
```

Expected: v0.4.1 and v0.4.0 print `ok: fingerprint ..., unsigned, complete: a kernel will serve with it` (the same
fingerprint for both: the same configuration); v0.3.0 is refused with "this configuration needs configuration format 6,
which this template's kernel does not read (it reads up to 4): use a newer release". (This file was checked on
2026-11-04 against the published v0.4.0 and v0.3.0 templates and the locally built v0.4.1 template; not
`deploy/dev/config.toml`, whose plaintext port and `require_data_disk = false` a release template refuses.)

The kernel: the `.elf` of the release is a **dev** build, and a dev build embeds the development certificates that
`make certs` generates at random on each machine, so its hash cannot be reproduced on another machine. Reproducibility
is checked with `make repro` (ENV=prod, two builds of the same tree, identical).

## 5. The builder page

Nothing to deploy (see the top). After step 6, in a browser on `https://aldo.tech/en/products/urmqtt-builder/` and the
Croatian page: v0.4.1 is the chosen release, the signature check mark appears, a build ends in a result card, "Try in
the emulator" boots it, TLS off still chooses v0.2.1 or
newer, and with `console.virtio_gpu = "on"` in the advanced view the build succeeds with v0.4.1 and is refused for
v0.3.0 chosen by hand.

## 6. The mirror

It picks the release up within the hour by itself. To do it now, on the web server as root:

```bash
systemctl start urmqtt-mirror
journalctl -u urmqtt-mirror -n 50 --no-pager            # exit 2 means a release failed verification
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A25 '"tag": "v0.4.1"'
```

Expected for `v0.4.1`: `"prerelease": true`, `"status": "ok"`, `"verified": true`, a `template` whose `sha256` is the
template's line in `SHA256SUMS` and whose `config_format` is **6**. v0.4.0 (format 6), v0.3.0, v0.2.1, v0.2.0
(format 4, 3, 2) and v0.1.0 (no template) stay listed as before.

## 7. After

- `docs/VULNERABILITY-HANDLING.md` section 6 needs no edit (the latest release is supported): v0.4.0 and older stop
  being supported, as the notes say.
- The `[Unreleased]` section of CHANGELOG.md is empty and open.

## 8. Rollback (details in docs/RELEASE.md section 6)

- **Workflow failed, no release:** `git tag -d v0.4.1 && git push origin :refs/tags/v0.4.1`, fix on `main`, start
  again at step 1. The page and the mirror keep offering v0.4.0.
- **A bad release is published:** `gh release edit v0.4.1 --repo zeljan-alduk/urMQTT --prerelease --notes "WITHDRAWN:
  <reason>"`; to keep the page from offering it, delete its assets or the release (the mirror marks it removed;
  `systemctl start urmqtt-mirror` applies it now) and the page goes back to v0.4.0. Do not reuse the tag for different
  bytes; publish v0.4.2.
- **The page misbehaves:** it was not changed, so the cause is the release or the mirror, not the page; withdraw the
  release as above.
- **Users who want v0.4.0 back:** nothing to convert: the configuration format (6) and the disk layout (v2.1) are the
  same; pack the same configuration into the v0.4.0 template.
