# Release day: v0.4.2

For the maintainer: the commands for the day, in order. Made from docs/release-day-template.md (the first release
after the key rotation). Nothing here has been run; docs/RELEASE.md explains each step and the rollback (section 6).
The preparation (version, CHANGELOG, notes, local gates) is on the branch `release-v0.4.2`; its local results are in
docs/PROGRESS.md, "Release candidate v0.4.2".

What is new on the day, against docs/release-day-v0.4.1.md:

- **The key.** v0.4.2 is the first release signed with the release key `721316B961DCB94B` (`minisign.pub`, generated
  2026-11-06). The former test key `9229E05252D01F8E` is accepted for v0.1.0 to v0.4.1 only, each pinned
  (`keys/release-keys.json`).
- **The assets.** `make dist ENV=release`: `urmqtt-v0.4.2.elf/.iso/.img/.cdx.json`, the template, `SHA256SUMS` and its
  signature; no dev build with throwaway certificates. Trusted comment `urMQTT v0.4.2 release <commit>`.
- **The configuration format is 7** (`network.mtu`, ADR-264); everything else still packs into format-6 templates.

**Already done, before the day (docs/release-key-rotation.md steps 1 to 6):** the key generated, the secret
`MINISIGN_SECRET_KEY` set, `minisign.pub` committed (685bb21), the **builder page on aldo.tech rebuilt from `main`
with the key ring and configuration format 7 and deployed on 2026-11-06** (the live manifest shows format 7 and the
keys `721316B961DCB94B` and `9229E05252D01F8E`), and the **release mirror switched to `--keyring`** by
`scripts/mirror/install.sh` on 2026-11-06 at 22:23 UTC (`releases.json` lists both keys and shows `signed_by` = the
test key for v0.2.0 to v0.4.1; v0.1.0 shows no `signed_by`, an observation whose cause was not investigated). So
there is no page deploy and no mirror install on the day: only the checks below. If a check of step 0 fails, stop and
redo the step of docs/release-key-rotation.md it belongs to; a page or mirror without the release key refuses v0.4.2.

## 0. Check what was done before the day

```bash
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -A12 '"keys"'
#   two keys: 721316B961DCB94B (release, valid_from v0.4.2) and 9229E05252D01F8E (test, v0.1.0 to v0.4.1, pinned)
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -c "import json,sys; d=json.load(sys.stdin); print([(r['tag'], (r.get('signed_by') or {}).get('key_id')) for r in d['releases']])"
#   v0.4.1 to v0.2.0 signed_by 9229E05252D01F8E; v0.1.0 None (as observed on 2026-11-06, cause not investigated)
ssh build systemctl cat urmqtt-mirror | grep ExecStart     # ... --keyring /etc/urmqtt-mirror/keys/release-keys.json
gh secret list --repo zeljan-alduk/urMQTT                  # MINISIGN_SECRET_KEY, updated 2026-11-06
```

In a browser on `https://aldo.tech/en/products/urmqtt-builder/`: v0.4.1 is still the chosen release and shows "signed
with the project's former test key"; the advanced view offers `network.mtu`; with it set, the build of v0.4.1 is
refused with "use a newer release" (no release reads format 7 yet).

## 1. Merge and wait for CI

```bash
cd ~/dev/urMQTT                     # a normal clone, not a worktree nested in another checkout
git switch main && git pull --ff-only
git merge --no-ff release-v0.4.2    # or through a pull request
git push origin main
gh run list --repo zeljan-alduk/urMQTT --branch main --limit 5
gh run watch --repo zeljan-alduk/urMQTT          # CI on the merge commit: every job green, "Release keys" included
RELEASE_COMMIT=$(git rev-parse HEAD); echo "$RELEASE_COMMIT"
scripts/check-release-key.sh                     # ok: release 721316B961DCB94B v0.4.2 and later, test 9229E05252D01F8E v0.1.0 to v0.4.1
make repro ENV=release                           # both release kernels, the template ISO and the raw image: identical twice
```

Do not tag before CI is green on `$RELEASE_COMMIT`. If a job fails, fix on `main` and start again here; the date in
CHANGELOG (`[0.4.2] - 2026-11-06`) is the preparation date: change it in the fix commit if the tag lands on another
day. Also: `git status` is clean and `git describe --tags` says `v0.4.1-<n>-g<commit>`.

Open from the preparation (docs/PROGRESS.md, "Release candidate v0.4.2"): one HVF run of the core smoke shard
measured the in-guest `dp-bench` scaling at 2.99x with 4 worker cores, just under the HVF-only threshold of 3.0x (CI
runs TCG, where it is only reported). To look again on the Mac before the tag:
`SMOKE_NO_GROUPS=1 SMOKE_SCENARIOS='^dp-bench$' scripts/smoke.sh --accels hvf` (after `make build`).

## 2. Tag and push

Earlier tags (v0.2.0 to v0.4.1) are annotated, not signed; v0.4.2 follows them.

```bash
git switch main && git pull --ff-only
test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
git tag -a v0.4.2 -m "urMQTT v0.4.2" "$RELEASE_COMMIT"
git cat-file -t v0.4.2                                  # tag
git push origin v0.4.2                                  # starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT
```

The workflow runs `scripts/check-release-key.sh` and checks that the signing secret exists before building (it refuses
a placeholder or test-key `minisign.pub`; the release key is in place), builds `make dist ENV=release` on an arm64
runner, checks the asset set (no dev asset, the `.iso` equal to the template, no PEM private key), signs `SHA256SUMS`
(trusted comment `urMQTT v0.4.2 release <commit>`), verifies the signature with `minisign.pub`, attests the SBOM and
the provenance and creates the pre-release.

## 3. The release notes

```bash
gh release edit v0.4.2 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.4.2.md
gh release view v0.4.2 --repo zeljan-alduk/urMQTT --json isPrerelease,isDraft,assets -q '.isPrerelease, .isDraft, [.assets[].name]'
```

Expected: `true`, `false`, and the seven files `SHA256SUMS`, `SHA256SUMS.minisig`, `urmqtt-v0.4.2.cdx.json`,
`urmqtt-v0.4.2.elf`, `urmqtt-v0.4.2.img`, `urmqtt-v0.4.2.iso`, `urmqtt-template-v0.4.2-universal.iso`; no
`urmqtt-dev-*`. Only if the workflow did not create the release: `gh release create v0.4.2 --repo zeljan-alduk/urMQTT
--verify-tag --prerelease --notes-file docs/release-notes-v0.4.2.md <the workflow's files>`.

## 4. Verify the assets with the new key

In an empty directory outside the repository:

```bash
mkdir /tmp/urmqtt-v0.4.2 && cd /tmp/urmqtt-v0.4.2
gh release download v0.4.2 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.2/minisign.pub
head -1 minisign.pub                             # untrusted comment: minisign public key 721316B961DCB94B
minisign -Vm SHA256SUMS -p minisign.pub          # Trusted comment: urMQTT v0.4.2 release $RELEASE_COMMIT
shasum -a 256 -c SHA256SUMS                      # every file OK
cmp urmqtt-v0.4.2.iso urmqtt-template-v0.4.2-universal.iso
gh attestation verify urmqtt-v0.4.2.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-v0.4.2.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json; d=json.load(open('urmqtt-v0.4.2.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The key ring and the release kernel, from the clone at the tag:

```bash
cd ~/dev/urMQTT && git switch --detach v0.4.2
cargo build --release -p urmqtt-config-tool
(cd /tmp/urmqtt-v0.4.2 && ~/dev/urMQTT/target/release/urmqtt-config check-release --keyring ~/dev/urMQTT/keys/release-keys.json --tag v0.4.2 --sums SHA256SUMS urmqtt-*)
target/release/urmqtt-config verify /tmp/urmqtt-v0.4.2/urmqtt-v0.4.2.img      # the empty configuration
make dist ENV=release && grep 'urmqtt-v0.4.2.elf' build/dist/SHA256SUMS
grep 'urmqtt-v0.4.2.elf' /tmp/urmqtt-v0.4.2/SHA256SUMS   # the same line: the release kernel is reproducible anywhere
```

The `.iso` and `.img` lines match only with the runner's xorriso and mtools (Ubuntu 24.04 arm64), not necessarily on
macOS (docs/RELEASE.md section 0.6).

## 5. The templates: format 6 and format 7

The same check as in the preparation (docs/PROGRESS.md, "Release candidate v0.4.2"), with the published v0.4.2
template. Still in the clone at the tag:

```bash
for t in v0.4.1 v0.4.0; do
  mkdir -p /tmp/urmqtt-$t && (cd /tmp/urmqtt-$t && gh release download $t --repo zeljan-alduk/urMQTT -p 'urmqtt-template-*' -p 'SHA256SUMS*' --skip-existing \
    && minisign -Vm SHA256SUMS -p ~/dev/urMQTT/keys/minisign-test-9229E05252D01F8E.pub && shasum -a 256 -c SHA256SUMS --ignore-missing)
done
make certs
mkdir -p /tmp/cfg-6 /tmp/cfg-7
cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-6/ && cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-7/
printf '[tls]\ncert = "server.pem"\nkey = "server.key"\n\n[trust]\noperational = ["ca.pem"]\n\n[control]\npublic_key = "control.pub"\n\n[console]\nvirtio_gpu = "on"\n\n[devices]\nvirtio_balloon = "on"\n' > /tmp/cfg-6/config.toml
{ cat /tmp/cfg-6/config.toml; printf '\n[network]\nmtu = 1460\n'; } > /tmp/cfg-7/config.toml
for f in 6 7; do for t in v0.4.2 v0.4.1 v0.4.0; do
  echo "== format $f, $t"; target/release/urmqtt-config pack /tmp/cfg-$f/config.toml --iso /tmp/urmqtt-$t/urmqtt-template-$t-universal.iso --out /tmp/mine-$f-$t.iso
done; done
target/release/urmqtt-config show /tmp/mine-7-v0.4.2.iso | head -5   # urmqtt-cfg version 7
git switch main
```

Expected: format 6 packs on v0.4.2, v0.4.1 and v0.4.0 (`ok: fingerprint ...`, the same fingerprint on all three);
format 7 packs on v0.4.2 and is refused by v0.4.1 and v0.4.0 with "this configuration needs configuration format 7,
which this template's kernel does not read (it reads up to 6): use a newer release".

## 6. The mirror and the builder page

The mirror already runs with the key ring (step 0). It picks the release up within the hour; to do it now:

```bash
ssh build systemctl start urmqtt-mirror
ssh build journalctl -u urmqtt-mirror -n 50 --no-pager      # exit 0; "release v0.4.2: mirrored urmqtt-template-v0.4.2-universal.iso (..., config format 7); signature ok (key 721316B961DCB94B, ...)"
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A30 '"tag": "v0.4.2"'
```

Expected for v0.4.2: `"prerelease": true`, `"status": "ok"`, `"verified": true`, `"signed_by": {"key_id":
"721316B961DCB94B", "name": "release", "valid_from": "v0.4.2", "valid_to": null, "former_test_key": false, ...}`, and a
`template` whose `sha256` equals the template's line in `SHA256SUMS` and whose `"config_format": 7`. v0.4.1 to v0.2.0
unchanged (format 6, 6, 4, 3, 2), `"signed_by"` the test key `9229E05252D01F8E`; v0.1.0 listed without a template (and, as on 2026-11-06, without
`signed_by`).

In a browser on `https://aldo.tech/en/products/urmqtt-builder/` and the Croatian page:

- v0.4.2 is the chosen release; the check mark names the key `721316B961DCB94B` without the test-key note;
- v0.4.1 and older, chosen by hand, show "signed with the project's former test key" and still verify;
- a build ends in a result card and "Try in the emulator" boots it;
- with `network.mtu` = 1460 in the advanced view, v0.4.2 builds and v0.4.1 chosen by hand is refused with "use a newer
  release"; TLS off still picks v0.2.1 or newer;
- the statuses of the URLs in `sitemap.xml` are unchanged.

## 7. After

- `docs/VULNERABILITY-HANDLING.md` section 6 needs no edit (the latest release is supported): v0.4.1 and older stop
  being supported, as the notes say.
- The `[Unreleased]` section of CHANGELOG.md is empty and open.
- ROADMAP NOW-2's last check ("RELEASE.md §3 on the next tag; the page shows v0.4.1 with the test-key note and the new
  release without") is steps 4 and 6 above; record the result in docs/PROGRESS.md. The status word "pre-alpha"
  changes only when the owner changes it (ROADMAP, "Definition of alpha").

## 8. Rollback (details in docs/RELEASE.md section 6)

- **Workflow failed, no release:** `git tag -d v0.4.2 && git push origin :refs/tags/v0.4.2`, fix on `main`, start
  again at step 1. The page and the mirror keep offering v0.4.1. If it failed at `check-release-key.sh` or the secret
  check, the cause is the key setup (docs/release-key-rotation.md steps 2 and 3), not the code.
- **A bad release is published:** `gh release edit v0.4.2 --repo zeljan-alduk/urMQTT --prerelease --notes "WITHDRAWN:
  <reason>"`; to keep the page from offering it, delete its assets or the release (the mirror marks it removed;
  `ssh build systemctl start urmqtt-mirror` applies it now) and the page goes back to v0.4.1. Do not reuse the tag for
  different bytes; publish v0.4.3.
- **The signature does not verify with the new key on the page or the mirror:** withdraw as above; do not fall back
  to the test key (every tool refuses it for v0.4.2, by design).
- **The page misbehaves:** it was deployed before the day (with both keys and format 7); restore it as in docs/DEPLOY.md
  section 10, "Rolling back". A page without the key ring refuses v0.4.2, so withdraw the release until the page is back.
- **Users who want v0.4.1 back:** the disk layout (v2.1) is the same; pack the same configuration, without
  `network.mtu`, into the v0.4.1 template.
