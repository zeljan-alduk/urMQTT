# Release day: template for the first release after the key rotation (vX.Y.Z)

Copy to `docs/release-day-vX.Y.Z.md`, replace `vX.Y.Z` and the previous tag `vP.Q.R`, and fill in what is specific to
the release. It differs from docs/release-day-v0.4.1.md in the key (ROADMAP NOW-2) and the assets: the release ships the
release kernel and images with the empty configuration, no dev build. The reasons for each step are in docs/RELEASE.md.

**Before anything else: docs/release-key-rotation.md steps 1 to 6 are done** (the key generated offline, the secret
set, `minisign.pub` committed, the builder page rebuilt and deployed with both keys, the mirror on `--keyring`).
Otherwise the workflow refuses to start, or the page and the mirror refuse the new release.

## 1. Merge and wait for CI

```bash
cd ~/dev/urMQTT && git switch main && git pull --ff-only
git merge --no-ff release-vX.Y.Z && git push origin main
gh run watch --repo zeljan-alduk/urMQTT          # every job green, "Release keys" included
RELEASE_COMMIT=$(git rev-parse HEAD); echo "$RELEASE_COMMIT"
scripts/check-release-key.sh                     # ok: release <KEY ID> v0.4.2 and later, test 9229E05252D01F8E v0.1.0 to v0.4.1
gh secret list --repo zeljan-alduk/urMQTT        # MINISIGN_SECRET_KEY, updated on the rotation day
make repro ENV=release                           # both release kernels, the template ISO and the raw image: identical twice
```

## 2. Tag and push

```bash
git tag -a vX.Y.Z -m "urMQTT vX.Y.Z" "$RELEASE_COMMIT"
git push origin vX.Y.Z
gh run watch --repo zeljan-alduk/urMQTT
```

The workflow checks the key and the secret first, builds `make dist ENV=release`, checks the asset set (no dev asset,
no PEM private key), signs `SHA256SUMS` (trusted comment `urMQTT vX.Y.Z release <commit>`), verifies the signature with
`minisign.pub`, attests the SBOM and the provenance and creates the pre-release.

## 3. The release notes

```bash
gh release edit vX.Y.Z --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-vX.Y.Z.md
gh release view vX.Y.Z --repo zeljan-alduk/urMQTT --json isPrerelease,isDraft,assets -q '.isPrerelease, .isDraft, [.assets[].name]'
```

Expected: `true`, `false`, and the seven files `SHA256SUMS`, `SHA256SUMS.minisig`, `urmqtt-vX.Y.Z.cdx.json`,
`urmqtt-vX.Y.Z.elf`, `urmqtt-vX.Y.Z.img`, `urmqtt-vX.Y.Z.iso`, `urmqtt-template-vX.Y.Z-universal.iso`. The notes say
which key signed it (docs/RELEASE.md section 7, "For the first release after the key rotation").

## 4. Verify the assets

```bash
mkdir /tmp/urmqtt-vX.Y.Z && cd /tmp/urmqtt-vX.Y.Z
gh release download vX.Y.Z --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/vX.Y.Z/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # key <KEY ID>; comment: urMQTT vX.Y.Z release $RELEASE_COMMIT
shasum -a 256 -c SHA256SUMS
cmp urmqtt-vX.Y.Z.iso urmqtt-template-vX.Y.Z-universal.iso
gh attestation verify urmqtt-vX.Y.Z.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-vX.Y.Z.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
cd ~/dev/urMQTT && git switch --detach vX.Y.Z && make dist ENV=release && grep 'urmqtt-vX.Y.Z.elf' build/dist/SHA256SUMS
grep 'urmqtt-vX.Y.Z.elf' /tmp/urmqtt-vX.Y.Z/SHA256SUMS   # the same line only with the runner's clang (18.1.3, Ubuntu 24.04); another clang gives another ELF
```

The images with a configuration (a throwaway PKI from scripts/pki.sh, not the dev certificates):

```bash
cargo build --release -p urmqtt-config-tool
URMQTT_CA_PASSPHRASE=throwaway scripts/pki.sh init /tmp/pki-vX.Y.Z --dns test.example.org
mkdir -p /tmp/cfg-new && cp /tmp/pki-vX.Y.Z/deploy/{ca.pem,server.pem,server.key,control.pub,revoked.txt,config-snippet.toml} /tmp/cfg-new/
mv /tmp/cfg-new/config-snippet.toml /tmp/cfg-new/config.toml
target/release/urmqtt-config pack /tmp/cfg-new/config.toml --iso /tmp/urmqtt-vX.Y.Z/urmqtt-vX.Y.Z.iso --out /tmp/mine.iso
target/release/urmqtt-config pack /tmp/cfg-new/config.toml --image /tmp/urmqtt-vX.Y.Z/urmqtt-vX.Y.Z.img --out /tmp/mine.img
target/release/urmqtt-config verify /tmp/mine.iso && target/release/urmqtt-config verify /tmp/mine.img
git switch main
```

## 5. The mirror and the builder page

```bash
ssh build systemctl start urmqtt-mirror
ssh build journalctl -u urmqtt-mirror -n 50 --no-pager      # exit 0; "signature ok (key <KEY ID>, urMQTT vX.Y.Z release ...)"
curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A30 '"tag": "vX.Y.Z"'
```

Expected for vX.Y.Z: `"status": "ok"`, `"verified": true`, a `template` with `"config_format": 7` (format 7 since
the MTU change, ADR-264: deploy the page built from the release commit **before** the mirror lists it, docs/RELEASE.md
section 4, or the deployed page greys the release out), `"signed_by": {"key_id": "<KEY ID>", "name": "release", ...}`.
v0.4.1 and older: unchanged, `"signed_by"` the test key. In a browser: vX.Y.Z is chosen, the check mark says "(key
<KEY ID>)" without the test-key note, a build ends in a result card and "Try in the emulator" boots it; choosing v0.4.1
by hand shows "signed with the project's former test key" and still verifies.

## 6. After, and rollback

As docs/release-day-v0.4.1.md sections 7 and 8, and docs/RELEASE.md section 6. A tag is never reused for different
bytes.
