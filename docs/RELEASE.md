# Cutting a release (v0.3.0 as the worked example)

For the maintainer. The workflow that does the work is
[`.github/workflows/release.yml`](../.github/workflows/release.yml); this page is the order in which to do things
around it, the commands, the text to paste, and how to take it back. Replace `v0.3.0` for another version.

What a release is: a tag `vX.Y.Z` pushed to GitHub. The workflow builds on an arm64 runner (`make dist ENV=dev`) and
publishes, in `build/dist/`:

| File | What |
|---|---|
| `urmqtt-dev-vX.Y.Z.elf`, `.iso`, `.img` | the **dev** kernel for aarch64 (throwaway certificates; evaluation only), its UEFI ISO and raw disk image |
| `urmqtt-template-vX.Y.Z-universal.iso` | the release kernels for aarch64 and x86_64 and an empty configuration; what `urmqtt-config pack --iso` and the builder page turn into a configured image |
| `urmqtt-dev-vX.Y.Z.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | checksums of all of the above, and their minisign signature (only if the secret `MINISIGN_SECRET_KEY` exists) |

plus SLSA build provenance and an SBOM attestation (GitHub attestations). The release is created as a **pre-release**
(`v0.*`). Production images are not published: the operator builds them from their own `deploy/prod/`
(docs/DEPLOY.md).

Note for the decision below: the dev ELF, ISO and image are aarch64 only. x86_64 reaches users through the template ISO
(and so through the builder page). `make dist-universal` would also publish the x86_64 ELF and a universal dev ISO; the
workflow does not call it today.

## 0. Before the tag

1. `main` is the commit to release; the working tree is clean (`git status`).
2. The version is already `0.3.0` in `Cargo.toml` (workspace), `Cargo.lock` and `fuzz/Cargo.lock`; `CHANGELOG.md` has the
   dated `[0.3.0]` section. (`make` takes the image version from `git describe`, so the tag decides the file names and the
   version the kernel reports; the crate version is only the fallback when no tag is known, and the host tools' package version.)
3. The gates, on the commit to be tagged (the list in docs/PROGRESS.md "Release candidate v0.3.0" says which were run
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
   ```

   From a checkout nested inside another checkout (a Claude worktree), cargo reads two `.cargo/config.toml` files and the
   kernel builds fail on a duplicated `-Zbranch-protection`; build from a normal clone, or pass the flags once (see
   `make print-rustflags`).
4. `cargo vet regenerate imports && cargo vet prune` (docs/SUPPLY-CHAIN.md asks for it at each release); commit the
   result if it changed anything.
5. The signing key. `minisign.pub` in the repository is the release key; the secret half must be in the repository secret
   `MINISIGN_SECRET_KEY` (a passwordless key, `minisign -G -W`). Check: Settings, Secrets and variables, Actions. Without
   it the workflow publishes **unsigned** assets, and the release mirror and the builder page refuse an unsigned release.
   The key is a test key (docs/DEPLOY.md section 3); replacing it with an offline key is a separate change that also
   needs the new `minisign.pub` in the builder page and in the mirror (`/etc/urmqtt-mirror/minisign.pub`).
6. Optional dry run of the artifacts on your machine: `make dist ENV=dev` (needs `xorriso` and `mtools`) and compare
   `build/dist/SHA256SUMS` with what the workflow produces later. The kernels are reproducible, the ISO and raw image
   only with the same xorriso and mtools versions (docs/DEPLOY.md section 3), so the Linux runner's ISO need not equal a
   macOS one; the ELFs must.

## 1. Tag and run the workflow

```bash
git switch main && git pull --ff-only
git tag -s v0.3.0 -m "urMQTT v0.3.0"        # or -a if you do not sign tags
git push origin main
git push origin v0.3.0                       # this starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT      # about the time of `make dist` on an arm64 runner
```

The workflow: checkout with full history, `make certs`, `make dist ENV=dev` (kernels, ISO, raw image, template ISO,
SBOM, `SHA256SUMS`), a check that the template is listed in `SHA256SUMS`, minisign signature of `SHA256SUMS` (trusted
comment `urMQTT v0.3.0 dev <commit>`), SBOM attestation, build provenance, and the GitHub release with generated notes.

If it fails, nothing is published except possibly a half-made release: see Rollback.

## 2. The release notes

The workflow sets `generate_release_notes: true`. Replace the body with the text below:

```bash
# save the text of section 7 (without the outer code fence) to /tmp/notes-v0.3.0.md, then:
gh release edit v0.3.0 --repo zeljan-alduk/urMQTT --notes-file /tmp/notes-v0.3.0.md
```

Do it as soon as the workflow is green. Editing the notes does not matter to the mirror (it re-checks assets, not text).
Leave the release marked pre-release.

## 3. Verify the published release

In an empty directory, not inside the repository:

```bash
mkdir /tmp/urmqtt-v0.3.0 && cd /tmp/urmqtt-v0.3.0
gh release download v0.3.0 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.3.0/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # "Signature and comment signature verified", comment names v0.3.0 and the tag's commit
shasum -a 256 -c SHA256SUMS                      # every file OK
gh attestation verify urmqtt-dev-v0.3.0.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-dev-v0.3.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json,sys; d=json.load(open('urmqtt-dev-v0.3.0.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The template works without a toolchain (docs/DEPLOY.md section 1b):

```bash
cargo build --release -p urmqtt-config-tool      # in a clone of the tag
target/release/urmqtt-config pack deploy/dev/config.toml --iso /tmp/urmqtt-v0.3.0/urmqtt-template-v0.3.0-universal.iso --out /tmp/mine.iso
target/release/urmqtt-config show /tmp/mine.iso
```

Reproduce the kernel: `git clone`, `git checkout v0.3.0`, `make build ENV=dev ARCH=aarch64` and compare
`shasum -a 256 target/aarch64-unknown-none/release/urmqtt` with `urmqtt-dev-v0.3.0.elf` in `SHA256SUMS` (same toolchain
from `rust-toolchain.toml`, any host). For the prod flow `make repro` on the tag compares two builds of the same
commit; a second person with the same `deploy/prod/` compares `SHA256SUMS` before deploying.

## 4. The release mirror and the builder page on aldo.tech (docs/DEPLOY.md section 10)

Order matters: **the page first, the mirror second.** The page of the previous release only understands templates up to
the configuration format it was built with (`FORMAT_VERSION` in `crates/cfg/src/blob.rs` is 4 now; the page reads
`release.template.config_format` from the mirror's `releases.json` and greys out a release whose format is newer than
its WebAssembly module). A release that appears in the mirror before the new page is deployed may be listed but unusable.

1. Build the page from the tag: `git switch --detach v0.3.0 && make builder-emulator` (the emulator needs a one-time
   download that is pinned by hash; `build/builder/` is the output).
2. Deploy it to the site generator's directory and publish with the site's own script:

   ```bash
   scripts/deploy-builder-site.sh --dry-run
   scripts/deploy-builder-site.sh --chown USER:GROUP      # defaults: host `build`, /opt/aldotech-site/site
   ssh build ./publish.sh                                  # as the site's publisher; it must exclude /urmqtt/releases/
   ```

3. The mirror picks the release up within the hour; to do it now, on the web server as root:

   ```bash
   systemctl start urmqtt-mirror
   journalctl -u urmqtt-mirror -n 50 --no-pager            # exit 2 means a release failed verification
   curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A25 '"tag": "v0.3.0"'
   ```

   Expected: `v0.3.0` with `"prerelease": true`, `"status": "ok"`, `"verified": true`, and a `template` whose `sha256`
   equals the template's line in `SHA256SUMS` and whose `config_format` is **4** (the empty configuration in the template
   is stamped with `FORMAT_VERSION`; checked on the locally built template). The older releases stay listed as before.
4. In a browser on `https://aldo.tech/en/products/urmqtt-builder/` (and the Croatian page): v0.3.0 is the chosen release
   (the newest stable one, else the newest pre-release; all of ours are pre-releases), the check mark for the signature
   appears, a build ends in a result card, "Try in the emulator" boots it. Turning TLS off must still pick a release of
   v0.2.1 or newer. Encryption at rest is not on the page; do not claim it is.
5. Statuses of the URLs in `sitemap.xml` before and after must not change except for the new pages.

## 5. After the release

- Move the README's version references if any are left (`grep -rn "v0.2.1\|v0.3.0" README.md docs/`), and open the
  development branch for the next change: the `[Unreleased]` section of `CHANGELOG.md` is empty.
- `docs/VULNERABILITY-HANDLING.md` section 6: the supported version is the latest release, so **v0.2.1 and older stop
  being supported** with this release. Say so in the release notes (the text below does).
- The daily `cargo-deny` job and Dependabot continue as before; nothing to change.
- Tell the people who deployed v0.2.x: configuration format 4 is read by v0.3.0 only, but an image that does not use
  encryption is still written as format 2 or 3 and boots on v0.2.1.

## 6. Rollback

What can go wrong and what to do. Nothing here rewrites history on `main`.

- **The workflow failed before the release existed.** Fix on `main`, delete the tag locally and on the remote
  (`git tag -d v0.3.0 && git push origin :refs/tags/v0.3.0`), tag the fixed commit again. A tag that was only visible for
  minutes and had no release can be moved; the mirror ignores a tag without release.
- **A bad release is published** (wrong file, unsigned, a defect): first make it unusable for the page and the mirror
  without deleting evidence: `gh release edit v0.3.0 --prerelease --notes "WITHDRAWN: <reason>"`. To keep the page from
  offering it, delete the release's assets or the release (the mirror marks a release that disappeared upstream as
  removed, "removed-upstream", and the page will not offer it); on the server `systemctl start urmqtt-mirror` applies it
  now. This path of the mirror is covered by `scripts/test-mirror-releases.py` but was not exercised against a real
  withdrawn release. `gh release delete v0.3.0 --cleanup-tag` is irreversible: the tag name `v0.3.0` should not be reused for different bytes (people have
  verified the old ones); publish `v0.3.1` instead.
- **A security defect:** follow docs/VULNERABILITY-HANDLING.md section 4; the fix is the next release (`v0.3.1`), the
  advisory names v0.3.0 as affected.
- **The page misbehaves after the redeploy:** restore `build.py` and `publish.sh` from the backups the deploy script made,
  remove `urmqtt-builder/` from the generator's directory and publish (docs/DEPLOY.md section 10, "Rolling back"); the
  mirror needs no change.
- **Users who updated and want v0.2.1 back:** a data disk of layout v2.1 is refused by an older kernel (S5). Restore the
  disk from a snapshot taken before the update, or keep v0.3.0 and use `urmqtt-disk backup-extract` to take the database
  out. A v1 disk migrated by `urmqtt-disk migrate` has a `--rollback` while the migration record exists (docs/DEPLOY.md).

## 7. Release notes (paste)

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
  itself. Verified under QEMU TCG only.
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
- First supported target: a VPS or VM under KVM. x86_64 has **not** been run on KVM or real hardware. aarch64 is verified
  on Apple HVF and QEMU TCG.
- Not done: Secure Boot and signed loaders (H8), an IOMMU. Encryption at rest is not on the builder page yet. 53 of the 67
  crates in the kernel are cargo-vet exemptions, not audits. The audit package is a self-review, not an external audit.
- Support: only the latest release gets fixes; **v0.2.1 and older are no longer supported.**

**Verify** (in an empty directory):

    gh release download v0.3.0 --repo zeljan-alduk/urMQTT
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    gh attestation verify urmqtt-dev-v0.3.0.elf --repo zeljan-alduk/urMQTT

`minisign.pub` is in the repository root (key `RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`). Full changelog:
CHANGELOG.md.
```
