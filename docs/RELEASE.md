# Cutting a release (v0.4.0 as the worked example)

For the maintainer. The workflow that does the work is
[`.github/workflows/release.yml`](../.github/workflows/release.yml); this page is the order in which to do things
around it, the commands, the text to paste, and how to take it back. Replace `v0.4.0` for another version (v0.3.0 was the example before; its notes are kept in section 8).

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
2. The version is already `0.4.0` in `Cargo.toml` (workspace), `Cargo.lock` and `fuzz/Cargo.lock`; `CHANGELOG.md` has the
   dated `[0.4.0]` section. (`make` takes the image version from `git describe`, so the tag decides the file names and the
   version the kernel reports; the crate version is only the fallback when no tag is known, and the host tools' package version.)
3. The gates, on the commit to be tagged (the list in docs/PROGRESS.md "Release candidate v0.4.0" says which were run
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
git tag -s v0.4.0 -m "urMQTT v0.4.0"        # or -a if you do not sign tags
git push origin main
git push origin v0.4.0                       # this starts the Release workflow
gh run watch --repo zeljan-alduk/urMQTT      # about the time of `make dist` on an arm64 runner
```

The workflow: checkout with full history, `make certs`, `make dist ENV=dev` (kernels, ISO, raw image, template ISO,
SBOM, `SHA256SUMS`), a check that the template is listed in `SHA256SUMS`, minisign signature of `SHA256SUMS` (trusted
comment `urMQTT v0.4.0 dev <commit>`), SBOM attestation, build provenance, and the GitHub release with generated notes.

If it fails, nothing is published except possibly a half-made release: see Rollback.

## 2. The release notes

The workflow sets `generate_release_notes: true`. Replace the body with the text below:

```bash
# the text of section 7 is also the file docs/release-notes-v0.4.0.md (no outer fence), ready for --notes-file:
gh release edit v0.4.0 --repo zeljan-alduk/urMQTT --notes-file docs/release-notes-v0.4.0.md
```

The workflow creates the release itself (`softprops/action-gh-release`), so this is `gh release edit`, not
`gh release create`. Only if the workflow built and signed everything but failed to create the release, create it by
hand from the workflow's artifacts: `gh release create v0.4.0 --repo zeljan-alduk/urMQTT --verify-tag --prerelease
--notes-file docs/release-notes-v0.4.0.md build/dist/*` (the files must be the workflow's, with their attestations).

Do it as soon as the workflow is green. Editing the notes does not matter to the mirror (it re-checks assets, not text).
Leave the release marked pre-release.

## 3. Verify the published release

In an empty directory, not inside the repository:

```bash
mkdir /tmp/urmqtt-v0.4.0 && cd /tmp/urmqtt-v0.4.0
gh release download v0.4.0 --repo zeljan-alduk/urMQTT
curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.0/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub          # "Signature and comment signature verified", comment names v0.4.0 and the tag's commit
shasum -a 256 -c SHA256SUMS                      # every file OK
gh attestation verify urmqtt-dev-v0.4.0.elf --repo zeljan-alduk/urMQTT
gh attestation verify urmqtt-dev-v0.4.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
python3 -I -c "import json,sys; d=json.load(open('urmqtt-dev-v0.4.0.cdx.json')); print(d['metadata']['component']['version'], len(d['components']))"
```

The template works without a toolchain (docs/DEPLOY.md section 1b):

```bash
cargo build --release -p urmqtt-config-tool      # in a clone of the tag
target/release/urmqtt-config pack deploy/dev/config.toml --iso /tmp/urmqtt-v0.4.0/urmqtt-template-v0.4.0-universal.iso --out /tmp/mine.iso
target/release/urmqtt-config show /tmp/mine.iso
```

Reproduce the kernel: `git clone`, `git checkout v0.4.0`, `make build ENV=dev ARCH=aarch64` and compare
`shasum -a 256 target/aarch64-unknown-none/release/urmqtt` with `urmqtt-dev-v0.4.0.elf` in `SHA256SUMS` (same toolchain
from `rust-toolchain.toml`, any host). For the prod flow `make repro` on the tag compares two builds of the same
commit; a second person with the same `deploy/prod/` compares `SHA256SUMS` before deploying.

## 4. The release mirror and the builder page on aldo.tech (docs/DEPLOY.md section 10)

Order matters: **the page first, the mirror second.** The page of the previous release only understands templates up to
the configuration format it was built with (`FORMAT_VERSION` in `crates/cfg/src/blob.rs` is 6 now, 4 in v0.3.0; the page reads
`release.template.config_format` from the mirror's `releases.json` and greys out a release whose format is newer than
its WebAssembly module). A release that appears in the mirror before the new page is deployed may be listed but unusable.

1. Build the page from the tag: `git switch --detach v0.4.0 && make builder-emulator` (the emulator needs a one-time
   download that is pinned by hash; `build/builder/` is the output).
2. Deploy it to the site generator's directory and publish with the site's own script:

   ```bash
   scripts/deploy-builder-site.sh --dry-run                # still runs `apply_products.py --check` over ssh
   scripts/deploy-builder-site.sh --chown aldotech:aldotech # defaults: host `build`, /opt/aldotech-site/site
   ssh build runuser -u aldotech -- /opt/aldotech-site/publish.sh   # the site's publisher; it excludes /urmqtt/releases/
   ```

   **Never run the aldotech-web repository's `deploy.sh` for this**: it rsyncs that repository's `site/` over
   `/opt/aldotech-site/site/` with `--delete`, which removes `urmqtt-builder/`, `products.py`, `products_i18n.py`
   and `apply_products.py` (they live only on the server) and with them the builder page. The step-by-step list for
   v0.4.0 is docs/release-day-v0.4.0.md.

3. The mirror picks the release up within the hour; to do it now, on the web server as root:

   ```bash
   systemctl start urmqtt-mirror
   journalctl -u urmqtt-mirror -n 50 --no-pager            # exit 2 means a release failed verification
   curl -fsS https://aldo.tech/urmqtt/releases.json | python3 -I -m json.tool | grep -B3 -A25 '"tag": "v0.4.0"'
   ```

   Expected: `v0.4.0` with `"prerelease": true`, `"status": "ok"`, `"verified": true`, and a `template` whose `sha256`
   equals the template's line in `SHA256SUMS` and whose `config_format` is **6** (the empty configuration in the template
   is stamped with `FORMAT_VERSION`; checked on the locally built template). The older releases stay listed as before.
4. In a browser on `https://aldo.tech/en/products/urmqtt-builder/` (and the Croatian page): v0.4.0 is the chosen release
   (the newest stable one, else the newest pre-release; all of ours are pre-releases), the check mark for the signature
   appears, a build ends in a result card, "Try in the emulator" boots it. Turning TLS off must still pick a release of
   v0.2.1 or newer. In the advanced view `console.virtio_gpu` and the `[devices]` keys are offered; with one of them
   not "off", v0.4.0 builds and an older release chosen by hand is refused with "use a newer release". Encryption at
   rest is not on the page; do not claim it is.
5. Statuses of the URLs in `sitemap.xml` before and after must not change except for the new pages.

## 5. After the release

- Move the README's version references if any are left (`grep -rn "v0.3.0\|v0.4.0" README.md docs/`), and open the
  development branch for the next change: the `[Unreleased]` section of `CHANGELOG.md` is empty.
- `docs/VULNERABILITY-HANDLING.md` section 6: the supported version is the latest release, so **v0.3.0 and older stop
  being supported** with this release. Say so in the release notes (the text below does).
- The daily `cargo-deny` job and Dependabot continue as before; nothing to change.
- Tell the people who deployed v0.3.0: formats 5 and 6 (`console.virtio_gpu`, `[devices]` keys not "off") are read
  by v0.4.0 only; an image that leaves them off is written as format 2, 3 or 4 as before and boots on the kernels
  that read that format.

## 6. Rollback

What can go wrong and what to do. Nothing here rewrites history on `main`.

- **The workflow failed before the release existed.** Fix on `main`, delete the tag locally and on the remote
  (`git tag -d v0.4.0 && git push origin :refs/tags/v0.4.0`), tag the fixed commit again. A tag that was only visible for
  minutes and had no release can be moved; the mirror ignores a tag without release.
- **A bad release is published** (wrong file, unsigned, a defect): first make it unusable for the page and the mirror
  without deleting evidence: `gh release edit v0.4.0 --prerelease --notes "WITHDRAWN: <reason>"`. To keep the page from
  offering it, delete the release's assets or the release (the mirror marks a release that disappeared upstream as
  removed, "removed-upstream", and the page will not offer it); on the server `systemctl start urmqtt-mirror` applies it
  now. This path of the mirror is covered by `scripts/test-mirror-releases.py` but was not exercised against a real
  withdrawn release. `gh release delete v0.4.0 --cleanup-tag` is irreversible: the tag name `v0.4.0` should not be reused for different bytes (people have
  verified the old ones); publish `v0.4.1` instead.
- **A security defect:** follow docs/VULNERABILITY-HANDLING.md section 4; the fix is the next release (`v0.4.1`), the
  advisory names v0.4.0 as affected.
- **The page misbehaves after the redeploy:** restore `build.py` and `publish.sh` from the backups the deploy script made,
  remove `urmqtt-builder/` from the generator's directory and publish (docs/DEPLOY.md section 10, "Rolling back"); the
  mirror needs no change.
- **Users who updated and want v0.3.0 back:** v0.4.0 does not change the data-disk layout (v2.1), so a v0.3.0 kernel
  opens the disk. Its configuration must be one v0.3.0 reads: pack it again with `console.virtio_gpu` and every
  `[devices]` key "off" (format 4 or lower) into the v0.3.0 template. (For v0.2.1 and older: a layout-v2.1 disk is
  refused by those kernels, S5; restore a snapshot taken before that update, or use `urmqtt-disk backup-extract`.)

## 7. Release notes (paste)

The same text is the file [`docs/release-notes-v0.4.0.md`](release-notes-v0.4.0.md), for `--notes-file` (section 2).
If one of the two changes, change the other.

```markdown
## urMQTT v0.4.0 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 over TLS 1.3 with mutual TLS.
This release covers everything since v0.3.0. Its main reason: the builder page only offers published templates, and
v0.3.0's template reads configuration format 4, so the new console and device options below can be used from the
page only with this release.

**New**

- **A console on virtio-gpu**, off by default (`[console] virtio_gpu = "off" | "auto" | "on"`), for VMs whose
  firmware display goes dark after boot. Seen working on a netcup VPS 500 ARM G12.5: the Diagnostic dashboard live in
  the provider's Screen tab, and the final "press any key" screen staying.
- **A virtio driver framework** and four optional drivers, each off unless set in the new `[devices]` section:
  virtio-console (the log, and the Diagnostic prompts' keys), virtio-balloon (memory statistics for the host; it never
  gives memory back), virtio-input (a keyboard for "press any key" and `WIPE` from a provider's VNC console),
  virtio-vsock (the Diagnostic report, read-only, on port 2883). Every virtio device found is named in the boot log
  and in the Diagnostic report, also those without a driver. `urmqtt-config pack` refuses a key for a driver the
  image's kernel lacks.
- **P-256 on aarch64 through OpenSSL's ARMv8 `nistz256` assembly** (vendored from ring 0.17.14, like the x86_64
  code): measured on an Apple M4 Pro in Docker, not on the target CPU, sign 34.7 -> 11.6 us, verify 147 -> 29 us,
  ECDH 135 -> 25 us, the handshake's P-256 estimate 292 -> 104 us (docs/PERFORMANCE.md section 10). `make ct` covers
  P-256 key generation, ECDH and signing.
- **The Diagnostic entry over the network** (`diag-serve`): the measurements, then a normal live boot that serves the
  report as the retained `$SYS/diag/report` (operator certificate). The report gains the CPU clock and a random number
  generator panel (which sources seeded it, sanity tests of fresh bytes, throughput). `urmqtt-diag-png` draws the
  report as the dashboard's picture.
- **First records of a real aarch64 KVM guest** (netcup VPS 500 ARM G12.5, Neoverse N1, 2 vCPU, before the P-256
  change): AES-XTS 241 MiB/s per core, AES-GCM 314 MiB/s, one mutual-TLS handshake 1.08 ms; TLS 1.3 + mTLS, QoS 1
  publish/subscribe, 500 held connections and three 1000-client reconnect storms over the Internet without an error.
- **Fixes:** a virtio-gpu display-info response 4 bytes short was accepted (found by the new fuzz target before
  merge), `urmqtt-diag-png` drew no disks, a test that failed one run in eight, and several CI jobs (Miri split and
  given the development certificates, Kani as a real gate, the scheduled fuzz workflow, which failed to build every
  target).
- New fuzz targets for every new device input: `virtio_gpu_response`, `virtio_console_device`,
  `virtio_balloon_device`, `virtio_input_event`, `virtio_vsock_packet`.

**Compatibility.** Existing images and disks keep working; the data-disk layout is unchanged (v2.1). The kernel reads
configuration formats 1 to 6, and the packer writes the lowest format that can hold the configuration: an image whose
new keys are all "off" (the default) is written exactly as before and boots on the older kernels that read its
format. `console.virtio_gpu` not "off" needs format 5 and any `[devices]` key not "off" needs format 6; only a
v0.4.0 kernel reads those, and the packer and the builder page refuse to write them into an older template, with the
reason. Format 5 was never released on its own; this release's template declares format 6.

| Template of | Its kernel reads | What the builder page (v0.4.0) and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; TLS off is refused (format 3); the virtio-gpu console and `[devices]` keys are refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest (format 4) through `urmqtt-config pack` only, the page does not offer it |
| v0.4.0 | formats 1 to 6 | everything the page offers, including `console.virtio_gpu` and the `[devices]` keys |

The page picks the newest release that can do what the form asks; a page built before this release (format 4)
lists v0.4.0 as unusable, so the page is updated before the release mirror lists v0.4.0.

**Read this before relying on it**

- Pre-alpha. The assets here are **dev builds with throwaway keys** for evaluation, and the release signing key is
  still a test key; production images are built from your own `deploy/prod/` (docs/DEPLOY.md).
- First supported target: a VPS or VM under KVM. The real machines so far: one netcup ARM64 VPS (the Diagnostic
  entry, the measurements and load runs above, the virtio-gpu console; install, boot from the installed disk and a
  retained message that survived a power cut were reported by the owner and are not yet in the test records) and,
  for x86_64, a Contabo KVM VPS at the H7 commit (before disk encryption, boot integrity and this release). Nothing
  has run on physical hardware.
- The P-256 speed-up is measured on an Apple M4 Pro, not on a Neoverse N1 or any other server core.
- The virtio-console, -balloon, -input and -vsock drivers have run only under QEMU, not on a real VPS; vsock has run
  only against the test suite's fake device.
- The x86_64 and universal-ISO smoke suites are not in CI. For this release only the x86_64 virtio-gpu and
  virtio-device scenarios were run, under QEMU TCG; the full x86_64 and universal suites were not, and nothing ran on
  an x86_64 KVM guest.
- On the netcup VPS the random number generator was seeded from the CPU-jitter fallback and the bootloader's EFI RNG
  only (no virtio-rng, no `RNDR`): the weakest seeding the kernel accepts.
- Unchanged from v0.3.0: Secure Boot only partly done (release images are not signed), no IOMMU, encryption at rest
  not on the builder page, 53 of the 67 crates in the kernel are cargo-vet exemptions, not audits, and the audit
  package is a self-review. PSTATE.DIT is never set (docs/AUDIT.md A255-W2).
- Support: only the latest release gets fixes; **v0.3.0 and older are no longer supported.**

**Verify** (in an empty directory):

    gh release download v0.4.0 --repo zeljan-alduk/urMQTT
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    gh attestation verify urmqtt-dev-v0.4.0.elf --repo zeljan-alduk/urMQTT

`minisign.pub` is in the repository root (key `RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`). Full changelog:
CHANGELOG.md.
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
