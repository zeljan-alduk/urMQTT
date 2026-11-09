# LATER-6: Secure Boot completed — release notes input

ADRs: ADR-320 (sealed images, H8-W1), ADR-321 (`sign-iso`, H8-W2), ADR-322 (revocation through `dbx`, H8-W6),
ADR-323 (aarch64 enforcement on AAVMF, H8-W4), ADR-324 (keys: procedures, not keys; what is not done). Branch
`v060/later6`. New document: docs/secure-boot-keys.md.

## What changed for operators

- **An installed disk now boots under UEFI Secure Boot** (it did not in v0.5.0, AUDIT H8-W1). An image signed with
  your own Secure Boot key is **sealed**: the installed disk's `limine.conf` pins the configuration module by
  BLAKE2b, as Limine requires under Secure Boot. This holds for the disk the installer writes, for the raw disk image
  (`--disk-out`) and for an ESP staged into an A/B slot (`--esp-out`), on x86_64 and aarch64.
- **Sealed images take only the configuration they are sealed to**, everywhere, before anything is written:
  - the installer refuses an image sealed to another configuration (`install: the installation image is sealed for
    Secure Boot to another configuration than this boot's ...; nothing written to ...`);
  - `urmqtt-disk update-boot`, `create` and `slots stage` refuse an ESP sealed to another configuration than the one
    it would get (the disk keeps its own by default; `--replace-config` takes the ESP's), and print a new line
    `secure boot: sealed to its configuration` / `not sealed` (also in `urmqtt-disk info`);
  - `urmqtt-config pack --iso` and the builder page refuse a sealed (signed) ISO, naming `sign-iso`; `pack` into a
    sealed raw image takes only the pinned configuration.
- **`scripts/sign-loaders.sh sign-iso KEY CERT configured.iso signed.iso [--disk-out IMG] [--esp-out IMG]`**: sign an
  ISO that the builder page or `urmqtt-config pack --iso` configured, with your own key, without building a kernel
  (the kernels are taken from the image and must be the ones its menu pins). `--config FILE` signs a template with a
  configuration instead. The result is byte for byte the direct `mkiso.sh --config ... --sb-key ...` build. `--template TPL.iso` (the
  verified release template) requires the configured ISO's kernels to be the template's, byte for byte; without it
  sign-iso prints a NOTE that the kernels were checked only against the ISO's own menu. An
  unconfigured template is refused unless `--allow-empty`.
- **Revocation:** `scripts/sign-loaders.sh authenticode FILE...` prints the Authenticode SHA-256 of a loader (what
  `dbx` matches); `ovmf-vars DIR IN OUT --dbx-hash HASH` puts it into an OVMF/AAVMF variable store. The procedure for
  real firmware (KEK-signed `dbx` update) is in docs/secure-boot-keys.md.
- **aarch64 Secure Boot is tested now:** `scripts/run-qemu.sh --secure-vars FILE` works on aarch64 with AAVMF's
  Secure Boot build (`/usr/share/AAVMF/AAVMF_CODE.secboot.fd` of Debian/Ubuntu `qemu-efi-aarch64`, or
  `URMQTT_FIRMWARE_SECURE_AA64`); `ovmf-vars` makes its variable store from `AAVMF_VARS.fd`.
- `scripts/mkiso.sh --universal`: `--seal` (the default with `--sb-key`) and `--no-seal` (the v0.5.0 behaviour, kept
  as the tests' control).
- docs/secure-boot-keys.md: generating PK/KEK/db offline, enrolling, signing, revoking one image, rotating db, a
  leaked key. DEPLOY.md section 5d rewritten (the "two limits" are gone or narrowed).
- Smoke `SMOKE_ONLY=secureboot --arch universal` grew from 10 to 30 checks (x86_64 OVMF and aarch64 AAVMF, both
  enforcing); new fuzz target `seal_pins`.

## Configuration, store, formats

- **No configuration key** (configuration format 21, reserved for LATER-6, is not used) and **no store change**.
- No change to release images: they stay unsigned. Unsigned images are built exactly as before (same bytes for the
  same inputs).

## Upgrade and downgrade

- Nothing changes for existing images, disks and configurations: an unsealed disk (every disk installed so far) is
  treated exactly as before by every tool.
- A disk installed from a sealed image is tied to its configuration. A new configuration means a new signed image
  (`sign-iso ... --esp-out`), staged into the standby slot (`urmqtt-disk slots stage --esp ... --unsigned
  --replace-config`). A sealed disk refuses an unsealed ESP (the release's own `.img`, for one) in `slots stage` and
  `update-boot`: under Secure Boot the firmware would refuse the new slot before any trial, so nothing would roll
  back; `--allow-unsealed` does it on a machine without Secure Boot. A disk
  prepared before v0.6.0 has one slot and takes `update-boot` with the sealed ESP.
- Downgrading a sealed disk to v0.5.0 tools: v0.5.0's `urmqtt-disk update-boot` does not know seals and would carry the
  disk's configuration into a sealed ESP of another configuration, leaving a disk its loader refuses (fail closed, no
  data lost; fix with the v0.6.0 tool or an ESP sealed to the right configuration).

## Defaults and limits

- Sealing is on only for signed images. Signing needs your own key: the project signs nothing with a Secure Boot key.
- The test needs openssl, osslsigncode or sbsign, virt-firmware (`pip install virt-firmware`), OVMF with Secure Boot,
  and for aarch64 AAVMF with Secure Boot (Ubuntu 24.04's works; Homebrew's QEMU has none); it is run by hand, not in
  CI.

## Deliberately not done

- **No version counter / anti-rollback** (H8-W6 stays open in part): an older signed image that nobody revoked in
  `dbx` boots. A counter needs UEFI runtime services in the kernel, a TPM (ADR-254, LATER-7) or a loader with a
  rollback index.
- **No signed `dbx` update tooling for real firmware** (an authenticated variable signed by KEK): documented with
  efitools commands in docs/secure-boot-keys.md, not tested.
- **No shim/MOK** (ADR-324): firmware that trusts only Microsoft's keys cannot boot these images under Secure Boot.
- **No release signed with a project key** (D-2 is the maintainer's decision); the builder page cannot sign.
- **Untested:** Proxmox, a physical PC, cloud firmware; the BIOS path has no signatures (H8-W3).
- **Not in CI:** the universal suites, `secureboot` included, are run by hand (they need an x86_64 kernel, OVMF,
  AAVMF, virt-firmware and a signer on the runner; hash-pinning virt-firmware and its dependencies for the runner
  was not done).
- **The BLI boot-once entry** (A295-W1: a kernel that dies before its block driver is not counted as a failed trial):
  needs UEFI runtime services in the kernel; not done.
