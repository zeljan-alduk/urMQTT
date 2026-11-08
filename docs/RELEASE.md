# Cutting a release (v0.5.0 as the worked example)

For the maintainer. The workflow that does the work is
[`.github/workflows/release.yml`](../.github/workflows/release.yml); this page is the order in which to do things
around it, the commands, the text to paste, and how to take it back. Replace `v0.5.0` for another version, and `v0.4.2` for the release before it (v0.4.2, v0.4.1, v0.4.0 and v0.3.0 were the examples before; their notes are docs/release-notes-v0.4.2.md, docs/release-notes-v0.4.1.md, docs/release-notes-v0.4.0.md and section 8).

What a release is: a tag `vX.Y.Z` pushed to GitHub. The workflow builds on an arm64 runner (`make dist ENV=release`)
and publishes, in `build/dist/`:

| File | What |
|---|---|
| `urmqtt-vX.Y.Z.elf` | the **release** kernel for aarch64 (no certificate or key in it; the same bytes as the aarch64 kernel inside the ISO) |
| `urmqtt-vX.Y.Z.iso` | the universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) with the **empty configuration**: byte for byte the template below, under the plain name |
| `urmqtt-vX.Y.Z.img` | its raw disk image (GPT, both kernels, the empty configuration); `urmqtt-config pack --image` configures it |
| `urmqtt-template-vX.Y.Z-universal.iso` | the same ISO under the name the builder page, the release mirror and `urmqtt-config pack --iso` have always used |
| `urmqtt-vX.Y.Z.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | checksums of all of the above, and their minisign signature with the **release key** (`minisign.pub`); trusted comment `urMQTT vX.Y.Z release <commit>` |

plus SLSA build provenance and an SBOM attestation (GitHub attestations). The release is created as a **pre-release**
(`v0.*`). No image with keys is published, and since the key rotation no dev build either: an image that serves is
made by the user from the template (builder page, `urmqtt-config pack --iso/--image`) or from their own
`deploy/prod/` (docs/DEPLOY.md).

Names before and after the rotation (both are understood by the mirror, which only ever fetches the template and the
sums; the builder page uses the template only):

| Releases | Assets | Signed with |
|---|---|---|
| v0.1.0 | `urmqtt-dev-v0.1.0.{elf,iso,img}` (no template) | the former test key `9229E05252D01F8E` |
| v0.2.0 to v0.4.1 | `urmqtt-dev-<tag>.{elf,iso,img,cdx.json}` (dev builds, throwaway certificates), `urmqtt-template-<tag>-universal.iso` | the former test key `9229E05252D01F8E` |
| after v0.4.1 | `urmqtt-<tag>.{elf,iso,img,cdx.json}`, `urmqtt-template-<tag>-universal.iso` | the release key in `minisign.pub` |

## 0. Before the tag

1. `main` is the commit to release; the working tree is clean (`git status`).
2. The version is already `0.5.0` in `Cargo.toml` (workspace), `Cargo.lock` and `fuzz/Cargo.lock`; `CHANGELOG.md` has the
   dated `[0.5.0]` section. (`make` takes the image version from `git describe`, so the tag decides the file names and the
   version the kernel reports; the crate version is only the fallback when no tag is known, and the host tools' package version.)
3. The gates, on the commit to be tagged (the list in docs/PROGRESS.md "Release candidate v0.5.0" says which were run
   and what they found):

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   make clippy-kernel && make check-x86
   cargo test --workspace
   make builder-emulator && make builder-test      # the emulator runtime is needed for the simple-view result-card test
   make supply-chain                                # cargo-vet, cargo-deny, SBOM check (Linux; see the caveat in PROGRESS)
   scripts/smoke.sh --accels "hvf tcg"              # aarch64 full suite (macOS)
   scripts/smoke.sh --arch x86_64
   scripts/smoke.sh --arch universal
   make repro                                       # prod, built twice; needs deploy/prod/{ca.pem,server.pem,server.key,control.pub}
   make repro ENV=release                           # the release assets built twice (no deploy/ needed); from the rotation on
   ```

   From a checkout nested inside another checkout (a Claude worktree), cargo reads two `.cargo/config.toml` files and the
   kernel builds fail on a duplicated `-Zbranch-protection`; build from a normal clone, or pass the flags once (see
   `make print-rustflags`).
4. `cargo vet regenerate imports && cargo vet prune` (docs/SUPPLY-CHAIN.md asks for it at each release); commit the
   result if it changed anything.
5. The signing key. `minisign.pub` in the repository is the release key (section 9); its secret half must be in the
   repository secret `MINISIGN_SECRET_KEY` (a passwordless key, `minisign -G -W`). `scripts/check-release-key.sh` must
   print `ok` with the release key and the former test key. The workflow **refuses to start** while `minisign.pub` is the
   placeholder or the former test key, or the secret is missing, and it checks after signing that the signature
   verifies with `minisign.pub`. The deployed builder page and the mirror must already know the release key (section 9,
   steps 5 and 6 of docs/release-key-rotation.md) before the first release signed with it.
6. Reproducibility of the release assets, on your machine (needs `xorriso` and `mtools`):

   ```bash
   make repro ENV=release     # builds HEAD twice (make release-images): both release kernels, the template ISO, the raw image
   make dist ENV=release      # build/dist/: the files of the table above and SHA256SUMS
   ```

   `make repro ENV=release` needs no `deploy/` directory (a release holds no key). The kernels are reproducible across
   hosts: the line of `urmqtt-vX.Y.Z.elf` in your `SHA256SUMS` must equal the workflow's. The ISO and raw image are
   identical only with the same xorriso and mtools versions (docs/DEPLOY.md section 3), so a macOS ISO need not equal the
   Linux runner's; compare those on Ubuntu 24.04 arm64.

## 1. Tag and run the workflow

```bash
git switch main && git pull --ff-only
git tag -a v0.5.0 -m "urMQTT v0.5.0"        # annotated, like v0.2.0 to v0.4.2; -s if you sign tags
git push origin main
git push origin v0.5.0                       # this starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT      # about the time of `make dist` on an arm64 runner
```

The workflow: checkout with full history, `scripts/check-release-key.sh` and a check that the signing secret exists
(both before anything is built), `make dist ENV=release` (release kernels, universal ISO, raw image, template ISO, SBOM,
`SHA256SUMS`), a check that every asset is there and in `SHA256SUMS`, that the `.iso` equals the template, that no dev
asset and no PEM private key is among them (`scripts/check-no-pem-keys.py`), the minisign signature of `SHA256SUMS`
(trusted comment `urMQTT vX.Y.Z release <commit>`) and its verification with `minisign.pub`, SBOM attestation, build
provenance, and the GitHub release with generated notes. (v0.4.1 and earlier: `make dist ENV=dev`, comment `urMQTT
v0.4.1 dev <commit>`, the former test key.)

If it fails, nothing is published except possibly a half-made release: see Rollback.

## 2. The release notes

The workflow sets `generate_release_notes: true`. Replace the body with the text below:

```bash
# the text of section 7 is also the file docs/release-notes-v0.5.0.md (no outer fence), ready for --notes-file:
gh release edit v0.5.0 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.5.0.md
```

The workflow creates the release itself (`softprops/action-gh-release`), so this is `gh release edit`, not
`gh release create`. Only if the workflow built and signed everything but failed to create the release, create it by
hand from the workflow's artifacts: `gh release create v0.5.0 --repo zeljan-alduk/urMQTT --verify-tag --prerelease
--notes-file docs/release-notes-v0.5.0.md build/dist/*` (the files must be the workflow's, with their attestations).

Do it as soon as the workflow is green. Editing the notes does not matter to the mirror (it re-checks assets, not text).
Leave the release marked pre-release.

## 3. Verify the published release

In an empty directory, not inside the repository:

A release after the rotation (vX.Y.Z):

```bash
mkdir /tmp/urmqtt-vX.Y.Z && cd /tmp/urmqtt-vX.Y.Z
gh release download vX.Y.Z --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/vX.Y.Z/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # the release key's id; comment "urMQTT vX.Y.Z release <the tag's commit>"
shasum -a 256 -c SHA256SUMS                      # every file OK
cmp urmqtt-vX.Y.Z.iso urmqtt-template-vX.Y.Z-universal.iso
gh attestation verify urmqtt-vX.Y.Z.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-vX.Y.Z.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json,sys; d=json.load(open('urmqtt-vX.Y.Z.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
urmqtt-config verify urmqtt-vX.Y.Z.img           # the empty configuration, as a release kernel reads it
```

A release up to v0.4.1 (here v0.4.1) verifies with the former test key; `minisign.pub` at those tags **is** that key,
and the repository keeps it as `keys/minisign-test-9229E05252D01F8E.pub`:

```bash
mkdir /tmp/urmqtt-v0.4.1 && cd /tmp/urmqtt-v0.4.1
gh release download v0.4.1 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/main/keys/minisign-test-9229E05252D01F8E.pub
minisign -Vm SHA256SUMS -p minisign-test-9229E05252D01F8E.pub   # key 9229E05252D01F8E, comment "urMQTT v0.4.1 dev <commit>"
shasum -a 256 -c SHA256SUMS
gh attestation verify urmqtt-dev-v0.4.1.elf --repo zeljan-alduk/urMQTT
```

`urmqtt-config check-release --pubkey minisign.pub --pubkey keys/minisign-test-9229E05252D01F8E.pub --sums SHA256SUMS
<files>` takes both keys and uses the one the signature names; it does not know the tag ranges (the page and the mirror
enforce them: the test key is accepted for v0.1.0 to v0.4.1 only).

The template works without a toolchain (docs/DEPLOY.md section 1b):

```bash
cargo build --release -p urmqtt-config-tool      # in a clone of the tag; `make certs` for deploy/dev/'s files
mkdir -p /tmp/cfg-new && cp deploy/dev/{ca.pem,server.pem,server.key,control.pub} /tmp/cfg-new/
printf '[tls]\ncert = "server.pem"\nkey = "server.key"\n\n[trust]\noperational = ["ca.pem"]\n\n[control]\npublic_key = "control.pub"\n\n[console]\nvirtio_gpu = "on"\n\n[devices]\nvirtio_balloon = "on"\n' > /tmp/cfg-new/config.toml
target/release/urmqtt-config pack /tmp/cfg-new/config.toml --iso /tmp/urmqtt-v0.5.0/urmqtt-template-v0.5.0-universal.iso --out /tmp/mine.iso
target/release/urmqtt-config show /tmp/mine.iso
```

The raw image takes the same configuration: `target/release/urmqtt-config pack /tmp/cfg-new/config.toml --image
urmqtt-vX.Y.Z.img --out /tmp/mine.img`. A production PKI for these files: docs/PKI.md (`scripts/pki.sh`).

Not `deploy/dev/config.toml`: a release template refuses its dev-only keys (the plaintext port,
`require_data_disk = false`). The file above is format 6; it must also pack into the templates of v0.4.1 and v0.4.0
(they read format 6) and be refused by v0.3.0's ("needs configuration format 6 ... reads up to 4: use a newer release").
With `[network]` `mtu = 1460` added it is format 7: it packs into the v0.4.2 and v0.5.0 templates and is refused by
v0.4.1's and v0.4.0's ("needs configuration format 7 ... reads up to 6: use a newer release"). With `[limits]`
`max_shared_groups = 64` added as well it is format 13: it packs into the v0.5.0 template only and is refused by
v0.4.2's ("needs configuration format 13 ... reads up to 7: use a newer release").

The kernel: from the rotation on, `urmqtt-vX.Y.Z.elf` is the **release** kernel, which embeds nothing machine-specific,
so anyone can rebuild it from the tag and compare (`make repro ENV=release` builds it twice; `make dist ENV=release`
at the tag gives the line to compare with the published `SHA256SUMS`). Up to v0.4.1 the `.elf` was a **dev** build
with development certificates generated at random on each machine, so its hash could not be reproduced elsewhere.

## 4. The release mirror and the builder page on aldo.tech (docs/DEPLOY.md section 10)

Order matters: **the page first, the mirror second.** The page of the previous release only understands templates up to
the configuration format it was built with (`FORMAT_VERSION` in `crates/cfg/src/blob.rs` is 13 since MQTT 5.0 part 3 (ADR-275), 7 in v0.4.2, 6 in v0.4.0 and v0.4.1, 4 in v0.3.0; the page reads
`release.template.config_format` from the mirror's `releases.json` and greys out a release whose format is newer than
its WebAssembly module). A release that appears in the mirror before the new page is deployed may be listed but unusable.

Steps 1 and 2 are needed only when the page or the configuration changed since the previous release:
`git diff v0.4.2..HEAD -- tools/builder crates/config-schema crates/cfg crates/config tools/config`. If that is empty
(it was for v0.4.1), the deployed page already handles the new template, nothing is deployed, and only step 3 onward
applies. For v0.4.2 it was not empty (format 7, the key ring), and the page was deployed on 2026-11-06, before the tag.
For v0.5.0 it is not empty (formats 8, 9, 11, 12 and 13: `[websocket]`, `[mqtt5]`, back-pressure, the receive
interrupt, the shared-group limits), and the deployed page reads format 7 (its live manifest, checked 2026-11-09):
**build the page from the release commit and deploy it after CI is green and before the tag**, since the mirror runs
hourly and would otherwise list a format-13 template the page greys out (docs/release-day-v0.5.0.md). A page of
format 13 still serves every older release (a configuration is written in the lowest format that holds it, as the
format-7 page did for v0.4.1).

1. Build the page from the release commit (or the tag): `git switch --detach v0.5.0 && make builder-emulator` (the emulator needs a one-time
   download that is pinned by hash; `build/builder/` is the output).
2. Deploy it to the site generator's directory and publish with the site's own script:

   ```bash
   scripts/deploy-builder-site.sh --dry-run                # still runs `apply_products.py --check` over ssh
   scripts/deploy-builder-site.sh --chown aldotech:aldotech # defaults: host `build`, /opt/aldotech-site/site
   ssh build runuser -u aldotech -- /opt/aldotech-site/publish.sh   # the site's publisher; it excludes /urmqtt/releases/
   ```

   **Never run the aldotech-web repository's `deploy.sh` for this**: it rsyncs that repository's `site/` over
   `/opt/aldotech-site/site/` with `--delete`, which removes `urmqtt-builder/`, `products.py`, `products_i18n.py`
   and `apply_products.py` (they live only on the server) and with them the builder page. The step-by-step lists are
   docs/release-day-v0.4.0.md (with a page deploy) and docs/release-day-v0.4.1.md (without).

3. The mirror picks the release up within the hour; to do it now, on the web server as root:

   ```bash
   systemctl start urmqtt-mirror
   journalctl -u urmqtt-mirror -n 50 --no-pager            # exit 2 means a release failed verification
   curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A25 '"tag": "v0.5.0"'
   ```

   Expected: `v0.5.0` with `"prerelease": true`, `"status": "ok"`, `"verified": true`, `"signed_by"` naming the key
   (the former test key up to v0.4.1, the release key after), and a `template` whose `sha256`
   equals the template's line in `SHA256SUMS` and whose `config_format` is **13** for v0.5.0 (**7** for v0.4.2, **6** for v0.4.0 and v0.4.1) (the empty configuration in the template
   is stamped with `FORMAT_VERSION`; checked on the locally built template). The older releases stay listed as before.
4. In a browser on `https://aldo.tech/en/products/urmqtt-builder/` (and the Croatian page): v0.5.0 is the chosen release
   (the newest stable one, else the newest pre-release; all of ours are pre-releases), the check mark for the signature
   appears, a build ends in a result card, "Try in the emulator" boots it. Turning TLS off must still pick a release of
   v0.2.1 or newer. In the advanced view `console.virtio_gpu` and the `[devices]` keys are offered; with one of them
   not "off", v0.5.0 (and v0.4.2, v0.4.1, v0.4.0) builds and v0.3.0 or older chosen by hand is refused with "use a newer
   release"; with `network.mtu` set, v0.5.0 and v0.4.2 build and v0.4.1 chosen by hand is refused the same way; with a
   `[websocket]`, `[mqtt5]` or shared-group limit key set, v0.5.0 builds and v0.4.2 chosen by hand is refused the same
   way. v0.5.0's and v0.4.2's check marks name the release key without the test-key note; v0.4.1 chosen by hand shows
   "signed with the project's former test key".
   Encryption at rest is not on the page; do not claim it is.
5. Statuses of the URLs in `sitemap.xml` before and after must not change except for the new pages.

## 5. After the release

- Move the README's version references if any are left (`grep -rn "v0.4.2\|v0.5.0" README.md docs/`), and open the
  development branch for the next change: the `[Unreleased]` section of `CHANGELOG.md` is empty.
- `docs/VULNERABILITY-HANDLING.md` section 6: the supported version is the latest release, so **v0.4.1 and older stop
  being supported** with this release (v0.5.0: **v0.4.2 and older**). Say so in the release notes (the text below does).
- The daily `cargo-deny` job and Dependabot continue as before; nothing to change.
- Tell the people who deployed v0.4.2: their configuration keeps its format (7 or lower); repacking the same
  configuration into the v0.5.0 template is the update, **but the first boot migrates the database to schema 5 and
  v0.4.2 cannot read it afterwards** (back the data disk up first), persistent sessions now expire after 30 days
  offline, and MQTT 5.0 clients are served (CHANGELOG 0.5.0, "Upgrading from v0.4.2"). Formats 8 to 13 are read by
  v0.5.0 and newer only. Verify v0.5.0 with `minisign.pub` at the tag (the release key).

## 6. Rollback

What can go wrong and what to do. Nothing here rewrites history on `main`.

- **The workflow failed before the release existed.** Fix on `main`, delete the tag locally and on the remote
  (`git tag -d v0.5.0 && git push origin :refs/tags/v0.5.0`), tag the fixed commit again. A tag that was only visible for
  minutes and had no release can be moved; the mirror ignores a tag without release.
- **A bad release is published** (wrong file, unsigned, a defect): first make it unusable for the page and the mirror
  without deleting evidence: `gh release edit v0.5.0 --prerelease --notes "WITHDRAWN: <reason>"`. To keep the page from
  offering it, delete the release's assets or the release (the mirror marks a release that disappeared upstream as
  removed, "removed-upstream", and the page will not offer it); on the server `systemctl start urmqtt-mirror` applies it
  now. This path of the mirror is covered by `scripts/test-mirror-releases.py` but was not exercised against a real
  withdrawn release. `gh release delete v0.5.0 --cleanup-tag` is irreversible: the tag name `v0.5.0` should not be reused for different bytes (people have
  verified the old ones); publish `v0.5.1` instead.
- **A security defect:** follow docs/VULNERABILITY-HANDLING.md section 4; the fix is the next release (`v0.5.1`), the
  advisory names v0.5.0 as affected.
- **The page misbehaves after the redeploy:** restore `build.py` and `publish.sh` from the backups the deploy script made,
  remove `urmqtt-builder/` from the generator's directory and publish (docs/DEPLOY.md section 10, "Rolling back"); the
  mirror needs no change.
- **Users who updated and want v0.4.2 back:** the data-disk layout is unchanged (v2.1), but **the database is not**:
  v0.5.0 migrated it to schema 5 at its first boot, and a v0.4.2 kernel refuses it (`schema version 5 is newer than
  this build`), and every backup snapshot v0.5.0 took. Pack the same configuration (format 7 or lower: no
  `[websocket]`, `[mqtt5]`, expiry, back-pressure "off", receive-interrupt "off" or shared-group key) into the v0.4.2
  template and give it the data disk copied or backed up before the update (CHANGELOG 0.5.0, "Upgrading from
  v0.4.2"), or a new disk; what happened since the update is lost. There is no downgrade migration.
- **Users who want v0.4.1 or v0.4.0 back** from v0.4.2: as above with format 6 or lower (no `network.mtu`).
- **Users who want v0.3.0 back:** v0.4.0 to v0.4.2 do not change the data-disk layout (v2.1) or the schema, so a
  v0.3.0 kernel opens a disk v0.5.0 never booted. Its configuration must be one v0.3.0 reads: pack it again with `console.virtio_gpu` and every
  `[devices]` key "off" (format 4 or lower) into the v0.3.0 template. (For v0.2.1 and older: a layout-v2.1 disk is
  refused by those kernels, S5; restore a snapshot taken before that update, or use `urmqtt-disk backup-extract`.)

## 7. Release notes (paste)

v0.5.0 is the second release signed with the release key: its notes keep the "Verify" block and name the key, and
drop v0.4.2's paragraphs about the rotation. Because the database migrates one way (schema 2 to 5), "Upgrading from
v0.4.2" comes before anything an operator might skip.

The same text is the file [`docs/release-notes-v0.5.0.md`](release-notes-v0.5.0.md), for `--notes-file` (section 2).
If one of the two changes, change the other. The notes of v0.4.2, v0.4.1 and v0.4.0 are
[`docs/release-notes-v0.4.2.md`](release-notes-v0.4.2.md), [`docs/release-notes-v0.4.1.md`](release-notes-v0.4.1.md)
and [`docs/release-notes-v0.4.0.md`](release-notes-v0.4.0.md).

```markdown
## urMQTT v0.5.0 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 and **MQTT 5.0** over TLS 1.3
with mutual TLS. This release covers everything since v0.4.2. Its three headline features: **QoS 2, exactly once**
(ADR-271), **MQTT over secure WebSocket** in the kernel (ADR-272, off by default) and **MQTT 5.0** beside 3.1.1 on
every listener (ADR-273, ADR-274, ADR-275), with shared subscriptions and Subscription Identifiers; only enhanced
authentication is refused (CONNACK 0x8C). With them, the TCP and NIC work of the single-flow performance item
(ADR-265, ADR-266, ADR-268, ADR-269, ADR-270). **Read "Upgrading from v0.4.2" before you update: the database
migrates one way.**

Signed with the release key `721316B961DCB94B` (`minisign.pub` at the tag), as v0.4.2 was. The former test key
`9229E05252D01F8E` signed v0.1.0 to v0.4.1 only; a signature by it on any later tag is a forgery (SECURITY.md).

**The assets**

The release kernel and images with an empty configuration; configure them with the builder page
(https://aldo.tech/en/products/urmqtt-builder/, in your browser, keys never leave it) or `urmqtt-config pack
--iso/--image` (docs/FIRST-HOUR.md walks through it).

| File | What |
|---|---|
| `urmqtt-v0.5.0.elf` | the release kernel for aarch64 (no certificate or key in it; reproducible from the tag with `make dist ENV=release`) |
| `urmqtt-v0.5.0.iso` | the universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) with the empty configuration: byte for byte the template |
| `urmqtt-v0.5.0.img` | its raw disk image; `urmqtt-config pack --image` configures it |
| `urmqtt-template-v0.5.0-universal.iso` | the same ISO under the template name the builder page and the mirror use |
| `urmqtt-v0.5.0.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | the checksums and their signature with the release key; trusted comment `urMQTT v0.5.0 release <commit>` |

**New**

- **QoS 2, exactly once** (ADR-271). PUBREC, PUBREL, PUBCOMP; a duplicate PUBLISH is answered again and never routed
  again; subscriptions are granted QoS 2; a persistent session resumes every flow after a reconnect and, while it is
  offline, across a restart. Database schema 3.
- **MQTT over secure WebSocket** (ADR-272): `wss://host:8084/mqtt`, TLS 1.3, subprotocol `mqtt`, for browsers and web
  stacks. `auth = "mtls"` takes a client certificate like the TLS port; `auth = "password"` checks an account inside
  TLS, with its own ACL, limits and clean sessions only; an origin allowlist. Off unless `[websocket] enabled = true`
  (configuration format 9).
- **MQTT 5.0** on every listener (TLS, plaintext, WebSocket), chosen per connection by the CONNECT's protocol level
  (`mqtt5.enabled`, on by default). Properties forwarded (user properties, content type, response topic, correlation
  data, payload format), reason codes on every acknowledgement and a server DISCONNECT, reason strings, Session
  Expiry, Message Expiry and Will Delay Intervals, Receive Maximum and Maximum Packet Size both ways, topic aliases
  from the client, subscription options, assigned client identifiers, Server Keep Alive (ADR-274, configuration
  format 12, database schema 4). **Shared subscriptions** (`$share/{group}/{filter}`, also for 3.1.1 clients; a group
  per role class, round robin over its online members, `limits.max_shared_groups` and
  `limits.max_shared_group_members`) and **Subscription Identifiers** (ADR-275, configuration format 13, database
  schema 5). Enhanced authentication is refused (CONNACK 0x8C). The Eclipse Paho interoperability suite passes 25 of
  27 (5.0) and 8 of 10 (3.1.1) on the development port; the rest are expected failures by design
  (docs/MQTT5-CONFORMANCE.md).
- **Performance** (ROADMAP NOW-13): TCP recovers from the peer's SACK blocks and acknowledges every second segment on
  arrival (ADR-265), and its loss detection counts the flow's own segments, which fixes the QoS 1 regression of the
  SACK build on one core (ADR-268); virtio-net queues of up to 1024 descriptors (ADR-266); **publisher back-pressure**:
  a QoS 0 message whose only subscriber is full pauses its publisher instead of being dropped (ADR-269,
  `limits.publisher_backpressure`); the **virtio-net receive interrupt** wakes the NIC's core instead of 200 us
  polling, on probation until verified, with the poll as the fallback (ADR-270, `[devices] virtio_net_interrupt`).
- Plaintext password hashes at 100 000 PBKDF2 iterations by default (ADR-267); the watchdog self-test and
  `$SYS/query/info` fixes; a second, coverage-guided ACL oracle (`broker_acl`); new `$SYS/broker/` topics for QoS 2,
  back-pressure, MQTT 5.0 and shared subscriptions.

**Upgrading from v0.4.2**

- **The database migrates from schema 2 to schema 5 on the first boot, one way.** A v0.4.2 kernel refuses the
  migrated database (`schema version 5 is newer than this build`) and every backup snapshot the new kernel takes. If
  you may want to go back, take a backup first, with the VM stopped: a copy of the whole data disk, or v0.4.2's
  `urmqtt-disk backup DISK --write` and then `urmqtt-disk backup-extract DISK OUT` to keep the snapshot outside the
  disk. A power cut during the migration leaves a whole schema with every row. The data-disk layout (v2.1) does not
  change.
- **Configuration formats go up to 13.** A configuration is written with the format of its newest key that is not at
  its default; one that sets no new key keeps format 7 or lower and packs into the v0.4.2 template as before. A new
  key needs: `limits.publisher_backpressure = "off"` 8, `[websocket]` 9, `devices.virtio_net_interrupt = "off"` 11,
  `[mqtt5]` keys and the expiry limits 12, the shared-group limits 13. Packed into an older template it is refused
  ("needs configuration format N ... use a newer release"), so no older kernel boots with a key it would ignore. The
  v0.5.0 template declares format 13; the builder page picks the newest release that reads what the form asks for.
- **Behaviour changes with an unchanged configuration:**
  - persistent sessions, **3.1.1 ones included, expire after 30 days offline** (they were kept forever): raise
    `limits.default_session_expiry_s` and `limits.max_session_expiry_s` before the update if your devices sleep
    longer (4 294 967 295 = never);
  - **MQTT 5.0 clients are served** (`mqtt5.enabled` on; v0.4.2 refused a 5.0 CONNECT); `false` answers CONNACK 0x84;
  - **`limits.publisher_backpressure = "single"`**: a QoS 0 publisher whose only subscriber cannot keep up is paused
    (at most 500 ms at a time) instead of having its messages dropped; `"off"` is v0.4.2's behaviour;
  - **`devices.virtio_net_interrupt = "auto"`**: the receive interrupt where the device offers it and it is verified,
    otherwise polling as before (a boot line says which); `"off"` forces polling;
  - **a connection the broker closes** (keep alive, protocol error, takeover) **ends its session and publishes its
    Will at once**, not when TCP is done with the socket;
  - **QoS 2 is served** (v0.4.2 closed the connection on a QoS 2 PUBLISH and granted QoS 1 to a QoS 2 subscription);
    `limits.max_inflight_qos1` counts QoS 1 and QoS 2 deliveries.
- **A new listener only if you turn it on:** the WebSocket port (8084) opens only with `[websocket] enabled = true`.
- **Rollback to v0.4.2:** pack the same configuration (format 7 or lower) into the v0.4.2 template and give it a data
  disk it can read: the copy or backup taken before the update, or a new disk.

| Template of | Its kernel reads | What the builder page and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; everything newer is refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest through `urmqtt-config pack` only |
| v0.4.0, v0.4.1 | formats 1 to 6 | as v0.3.0, and `console.virtio_gpu` and the `[devices]` keys |
| v0.4.2 | formats 1 to 7 | as v0.4.1, and `network.mtu`; formats 8 to 13 are refused ("use a newer release") |
| v0.5.0 | formats 1 to 9 and 11 to 13 | everything the page offers, including `[websocket]`, `[mqtt5]`, back-pressure, the receive interrupt and the shared-group limits |

**Read this before relying on it**

- Alpha: fit for trials and pilots whose operator reads docs/KNOWN-ISSUES.md, not for unattended production.
- MQTT 5.0 without enhanced authentication (CONNACK 0x8C) and without topic aliases sent by the broker; 0x96, 0x89,
  0x8A and 0x9F are never sent; MQTT 3.1 is refused. Shared subscriptions are grouped per role class.
- Wills live in RAM: lost at a restart, not sent at the console's `reboot`. QoS 2 is exactly once across disconnects,
  takeovers and a restart while the client is away, not across a broker crash while it is connected (AUDIT A271-W1).
- WebSocket: `wss://` only, no compression, password sessions are clean only.
- **Nothing of this release ran on a VPS or on physical hardware.** The receive interrupt has run under QEMU only
  (HVF with a GICv2m frame, TCG with the GICv3 ITS, x86_64 TCG); on a hypervisor that delivers it differently the
  broker falls back to polling after 8 frames that waited. Publisher back-pressure and the ADR-268 fix have rig
  numbers only. The real machines so far are one netcup ARM64 VPS and, for x86_64, a Contabo KVM VPS at the H7
  commit. The x86_64 unit tests and the x86_64 and universal-ISO smoke suites are not in CI.
- Plaintext password checks are PBKDF2 (100 000 iterations by default, not memory-hard); plaintext accounts and the
  WebSocket accounts change only with a new image.
- Unchanged from v0.4.2: IPv4 only, virtio over PCI only, no bridging, the AArch64 X25519 assembly has had no
  independent review, PSTATE.DIT is never set, Secure Boot only partly done (release images are not signed), no
  IOMMU, encryption at rest not on the builder page, most kernel crates are cargo-vet exemptions, the audit package
  is a self-review, and the builder's new texts are AI translations, unreviewed. docs/KNOWN-ISSUES.md lists the rest.
- Support: only the latest release gets fixes; **v0.4.2 and older are no longer supported.**

**Measured performance (2026-11-07/08)**

From docs/PERFORMANCE.md section 13: two VPSes, each loaded from the other, against Mosquitto 2.0.21. The urMQTT
builds measured were v0.4.2 and the SACK build of that day (`main` at 318f60b, ADR-265 and ADR-266), **not this
release**: ADR-268 (the QoS 1 fix on one core), ADR-269 (back-pressure) and ADR-270 (the receive interrupt) came after
and have local-rig numbers only. A new measurement of v0.5.0 on the same pair will follow in a blog post.

| Median of three runs | urMQTT SACK build | Mosquitto 2.0.21 |
|---|---|---|
| Contabo x86_64, 4 vCPU: new mTLS connections/s | 1,956 | 639 |
| Contabo: 16 pairs, QoS 0, 64 B, delivered/s | 201k | 60k |
| Contabo: 64 pairs, QoS 1, 64 B, delivered/s | 69k | 30k |
| Contabo: 1 flow, QoS 0, 64 B, delivered/s | 87k | 51k |
| Contabo: 16 x 1000/s, QoS 0, p99 latency | 27 ms | 95 ms |
| Contabo: 20,000 idle mTLS connections | 17.6 MB heap | 546 MB RSS |
| netcup ARM64, one broker core: new mTLS connections/s | 820 (v0.4.2: 923) | 419 |
| netcup: 16 pairs, QoS 0, 64 B, delivered/s | 43.7k | 57.9k |
| netcup: 1 flow, QoS 0, 64 B, delivered/s | 22.3k | 48.7k |
| netcup: 64 pairs, QoS 1, 64 B, delivered/s | 42.4k (v0.4.2: 51.8k) | 20.1k |
| netcup: fan-out 1 -> 1000 at 10/s, delivered; p50 | 8,639; 222 ms | 9,841; 56 ms |

With cores to use, the SACK build led Mosquitto in nearly every row (section 13.3: one 1 KiB flow stayed inside
Mosquitto's range). On one ARM core Mosquitto
kept raw QoS 0 throughput and fan-out to 1000 slow subscribers, and the SACK build was 10-30 % behind v0.4.2 on
QoS 1, the regression ADR-268 fixes (on the local rig with one data core and 1 % loss: 13.4k delivered/s against
v0.4.2's 13.0k and the SACK build's 9.0k). On the local rig, publisher back-pressure delivers everything a single
flow accepts (0 dropped, section 13.5). Raw files and figures: `docs/perf-results/x11-2026-11-07/`.

**Verify** (in an empty directory):

    gh release download v0.5.0 --repo zeljan-alduk/urMQTT
    curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.5.0/minisign.pub
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    cmp urmqtt-v0.5.0.iso urmqtt-template-v0.5.0-universal.iso
    gh attestation verify urmqtt-v0.5.0.elf --repo zeljan-alduk/urMQTT
    gh attestation verify urmqtt-v0.5.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom

`minisign` must report the key `721316B961DCB94B` (`RWRLudxhuRYTcpqyk9TNXAj1qzClrFEvzXTyFMBK6NEuyvk6tVUxjUlH`)
and the trusted comment `urMQTT v0.5.0 release <the tag's commit>`. The SBOM is `urmqtt-v0.5.0.cdx.json`
(CycloneDX), attested with the ISO. With a clone of the repository, `urmqtt-config check-release --keyring
keys/release-keys.json --tag v0.5.0 --sums SHA256SUMS urmqtt-*` applies the same key ring as the builder page, and
`make dist ENV=release` at the tag gives the same line for `urmqtt-v0.5.0.elf` as the published `SHA256SUMS`.
Full changelog: CHANGELOG.md.
```

## 8. Earlier release notes: v0.3.0 (the previous worked example)

As published for v0.3.0; kept as the model for the format.

```markdown
## urMQTT v0.3.0 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 over TLS 1.3 with mutual TLS.
This release covers everything since v0.1.0 (v0.2.0 and v0.2.1 were tagged without notes).

**New**

- **Configuration is data.** One kernel, one template ISO per release; `urmqtt-config pack` (or the builder page at
  https://aldo.tech/en/products/urmqtt-builder/, in your browser, keys never leave it) writes your limits, ACLs, network,
  certificates and keys into it. The kernel prints the configuration fingerprint at every boot.
- **Plain MQTT for trusted networks**, off by default, with a mandatory source allowlist checked at the SYN, three login
  modes and tight defaults; TLS can be left off entirely (`mqtt_tls_port = 0`).
- **x86_64** next to aarch64, and one universal ISO that boots on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS and installs
  itself. Smoke suites under QEMU TCG; run on a real KVM VPS (Contabo, AMD EPYC) at the H7 commit (X11), not the later code and not on physical hardware.
- **Storage:** layout v2, growing disks, TRIM/UNMAP, in-disk database backups with automatic restore, background scrubbing,
  and optional **encryption at rest** (AES-256-XTS, `urmqtt-disk encrypt | decrypt | rekey`).
- **Security work:** SQLite runs as an unprivileged component (EL0 / ring 3), kernel hardening (KASLR, MTE, stack
  protector, allocator hardening), SBOM, cargo-vet/cargo-deny, a vulnerability handling process, and an audit package
  (docs/AUDIT.md).
- **Fixes:** a lost wake-up that could leave a subscriber unserved, TCP loss recovery and window handling, a watchdog that
  dropped healthy connections when the host stalled a vCPU, wiping of captured TLS traffic secrets.

**Compatibility.** Existing images and disks keep working: older configuration blobs are read, format 4 is written only
when disk encryption is on, layout-v2.0 disks open and are upgraded in place (an older kernel then refuses them),
layout-v1 disks are converted offline with `urmqtt-disk migrate`.

**Read this before relying on it**

- Pre-alpha. The assets here are **dev builds with throwaway keys** for evaluation; production images are built from your
  own `deploy/prod/` (docs/DEPLOY.md).
- First supported target: a VPS or VM under KVM. x86_64 has run on a real KVM VPS (Contabo, 4 vCPU AMD EPYC: X11, at the H7 commit), but not the code added since (disk encryption, boot integrity) and not on physical hardware. aarch64 is verified on Apple HVF and QEMU TCG.
- Partly done: Secure Boot (H8). The loaders' configuration is enrolled and a signing path works under OVMF on x86_64, but release images are not signed and no physical machine was tried. Not done: an IOMMU. Encryption at rest is not on the builder page yet. 53 of the 67
  crates in the kernel are cargo-vet exemptions, not audits. The audit package is a self-review, not an external audit.
- Support: only the latest release gets fixes; **v0.2.1 and older are no longer supported.**

**Verify** (in an empty directory):

    gh release download v0.3.0 --repo zeljan-alduk/urMQTT
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    gh attestation verify urmqtt-dev-v0.3.0.elf --repo zeljan-alduk/urMQTT

`minisign.pub` is in the repository root (key `RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`). Full changelog:
CHANGELOG.md.
```

## 9. The release key and its rotation (ROADMAP NOW-2)

`keys/release-keys.json` is the key ring: the release key (`minisign.pub`, tags from v0.4.2 on) and the former test
key (`keys/minisign-test-9229E05252D01F8E.pub`, v0.1.0 to v0.4.1 only), each with a note. Every verifier reads it:

- the builder page embeds it at build time (`tools/builder/web/bundle.mjs`), verifies a release with the key its
  signature names, refuses an unknown key and a key outside its range, and marks the test-key releases "signed with
  the project's former test key"; a page built while `minisign.pub` is the placeholder trusts only the test key, and
  `scripts/deploy-builder-site.sh` refuses to deploy it;
- the release mirror runs with `--keyring /etc/urmqtt-mirror/keys/release-keys.json` (the same rules; `releases.json`
  lists the keys and each release's `signed_by`);
- `scripts/check-release-key.sh` checks the ring and refuses a placeholder or test-key `minisign.pub`; the Release
  workflow, `make sign` and the deploy script run it.

The rotation itself, done once by the owner, with the exact commands: **[docs/release-key-rotation.md](release-key-rotation.md)**
(generate the key offline, `gh secret set MINISIGN_SECRET_KEY`, commit `minisign.pub`, rebuild and deploy the page,
then on the web server `scripts/mirror/install.sh`, which installs `/etc/urmqtt-mirror/minisign.pub` and
`/etc/urmqtt-mirror/keys/`, switches the unit to `--keyring` and restarts the timer; `systemctl start urmqtt-mirror`
runs it at once). Nothing is re-downloaded by the mirror; old releases keep their test-key signature and stay
verifiable. A later rotation (a leaked key) is the same with a new entry and a `valid_to` on the old one (and pins of
the releases the old key signed).

**Pinning the former test key's releases.** For the test key, `keys/release-keys.json` also lists `pinned`: the
SHA-256 of the published `SHA256SUMS` of each of the six releases it signed (v0.1.0, v0.2.0, v0.2.1, v0.3.0, v0.4.0,
v0.4.1; fetched from GitHub and checked against the test key on 2026-11-06). The builder page, the mirror
(`--keyring`) and `urmqtt-config check-release --keyring keys/release-keys.json --tag TAG` accept, for a pinned tag,
only a `SHA256SUMS` with exactly that hash, whatever the signature says; a tag that is not pinned may not use the test
key at all; the release key has no pins. So a leaked test key can no longer sign a forged `SHA256SUMS` for an old tag.
What pinning does not do: it protects `SHA256SUMS`, and through it every file that `SHA256SUMS` lists, but nothing
beyond what that file lists (an asset added to an old release later is covered by no signature and no pin; the page
and the mirror use only the template, which is listed). The pins are only as trustworthy as the repository: someone
who controls the GitHub account could replace them, but only through a commit to `keys/release-keys.json` (visible in
the history, and the deployed page and mirror change only when they are rebuilt or reinstalled from it).
