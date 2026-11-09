# NEXT-11: updates and rollback, A/B boot slots (ADR-295 to ADR-299)

## What changed for operators

- **A new install has two boot slots.** The first boot of a disk with a v0.6.0 kernel reserves, next to the EFI
  system partition and before the data partition, a second region of the same size (10 MiB with the aarch64
  image, about 20 MiB with the universal one). The log says `gpt: standby boot slot reserved ...`. The data
  partition keeps everything else, as before.
- **Updating such a disk** (VM stopped): `urmqtt-disk slots stage DISK --image <release>.img --sums SHA256SUMS
  --sig SHA256SUMS.minisig --pubkey minisign.pub --write` writes the release into the standby slot after checking
  its minisign signature and SHA-256 (your configuration is kept, as `update-boot` keeps it), then `urmqtt-disk
  slots activate DISK --write` makes it the boot entry **on trial** (3 trial boots by default, `--tries 1..7`).
  `slots status`, `slots confirm` and `slots rollback` complete the set; every `slots` command is a dry run without
  `--write`. Own builds: `--esp ESP --unsigned`.
- **The new kernel confirms itself** once the store is open and a listener has been up for
  `update.confirm_after_s` (default 60 s). A trial that crashes, stops with a fatal error, is reset by the watchdog,
  or is not confirmed within `update.trial_timeout_s` (default 900 s) uses one trial boot; when none is left the
  kernel switches the boot entry back to the previous slot and resets into the previous release, which then boots
  normally. The failed slot is marked bad. The data disk is not touched by any of this.
- **Operator confirmation:** `[update] confirm = "operator"` and the new control messages
  `urmqtt-control boot-confirm --disk-guid GUID` and `boot-rollback --disk-guid GUID` (signed and authorised like
  every control message; the GUID is the boot disk's, printed by `slots status` and the boot log, so a message
  for one broker is refused by every other). `boot-rollback` goes back to the previous slot and resets.
- **Power cuts:** every write of every step (offline staging and switching, the kernel's trial count, the
  confirmation, the switch back) leaves the disk in the state before or after. Tested at every write on the host
  and at the critical writes in QEMU on aarch64 (edk2) and x86_64 (OVMF).
- **Downgrade rules** (`urmqtt-disk slots`): a kernel from before v0.6.0 (it cannot confirm) and a kernel whose
  store schema is older than the disk's store are always refused; an older release only with
  `--allow-downgrade`; a newer store schema only with `activate --one-way` (after its migration ran, the previous
  slot is marked bad: there is no way back past a one-way migration).
- `urmqtt-disk update-boot` refuses a disk with two slots (it would overwrite the running slot with no way back);
  `--in-place` does it anyway, never during a trial.
- Every kernel prints `build: <version> (A/B protocol 1, store schema N, configuration formats up to M)`.

## Configuration keys (format 17)

| Key | Values (default) | Format |
|---|---|---|
| `update.confirm` | `auto` \| `operator` (`auto`) | 17 |
| `update.confirm_after_s` | 0..=86400 (60) | 17 |
| `update.trial_timeout_s` | 0..=86400 (900; 0: never). In auto mode 0 or longer than `confirm_after_s` | 17 |

At their defaults the keys write nothing: an untouched configuration keeps its format and boots on older
kernels. Any other value needs **configuration format 17** (the builder page and `urmqtt-config` refuse it for an
older template). Tags 340 to 342. The builder page shows the section `[update]` after `[mqtt5]` in 15 languages
(machine translations, unreviewed). On this branch formats 14 to 16 are reserved for the other v0.6.0 items
(`RESERVED_VERSIONS`); the release merge removes the entries as they land.

Control commands: `boot-confirm` = 7, `boot-rollback` = 8 (5 and 6 belong to NOW-15). New rejection reasons
`other_disk` and `boot_refused` (statsd `urmqtt.control.rejected.*`).

## Upgrade effect (write this in the release notes)

- **Existing installed disks stay single-slot.** Their data partition starts right after the ESP; a v0.6.0 kernel
  does not move data to make room. They keep updating with `urmqtt-disk update-boot` exactly as before (the
  kernel logs `boot: one boot slot (a disk prepared before v0.6.0) ...`). A/B needs a disk installed (or
  re-installed, with `export-db`/`import-devices`) by v0.6.0 or later.
- New disks use one ESP's worth of space more (10 to 20 MiB).
- No store schema change, no data layout change.

## Downgrade

- A v0.5.x kernel boots an A/B disk (it ignores the standby entry; its data partition is still the last one) but
  never counts, confirms or switches: do not activate one in a slot (the tool refuses a kernel without a build
  note). Going back to v0.5.x on an A/B disk: `update-boot --in-place` (no way back), or keep v0.6.x.
- A configuration with an `[update]` key is refused by a kernel older than format 17.

## Limits and what is deliberately NOT done (also in left_out)

- **Converting a pre-v0.6.0 disk to A/B** (needs the data partition moved, or the ESP halved with a FAT writer).
- **A kernel that dies before its block driver runs is not counted**: the counter is the kernel's because Limine
  reads no mutable state and its configuration is enrolled; such a kernel boots again until `slots rollback`
  offline. The interface that would close it is the Boot Loader Interface one-shot entry (`LoaderEntryOneShot`,
  which Limine 12.9.4 reads) set by the kernel through UEFI runtime services (not available) (ADR-295, A295-W1).
- **Firmware-level anti-rollback** (version counter, `dbx`; H8-W6 proper, LATER-6): the tool's rules stop an
  operator's mistake, not an attacker who can write the disk.
- **Online staging** (an update over the network into the running broker): needs NEXT-7 or an upload path and an
  ESP writer in the kernel; the kernel writes no ESP.
- **`$SYS` topics for the slot state**: the boot log and `urmqtt-disk slots status` carry it.
- **The universal image's BIOS path** is not in the `ab` smoke group (aarch64 edk2 and x86_64 OVMF are);
  Limine's BIOS stage finds its volume through the same partition table, ESP entry first.
- **Secure Boot** (LATER-6): nothing here blocks it (the switch changes which partition is the ESP, no loader
  step was added); a per-machine signed ESP is staged with `--replace-config`. Not tested under Secure Boot.

## Validation on this branch

`cargo test` (store, cfg, config, config-schema, control, urmqtt-disk, urmqtt-control, urmqtt-config), clippy on
the workspace and both kernels, `make build` aarch64 and x86_64, `SMOKE_ONLY=ab` on aarch64 (HVF) and x86_64 (TCG)
10/10 each, fuzz `boot_slots` and `control_message` 2 minutes each, the builder tests, `cargo vet`.
