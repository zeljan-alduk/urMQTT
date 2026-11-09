# LATER-7: a disk key that is not in the image (v0.6.0 notes)

ADR-325 to ADR-329 (docs/DECISIONS.md). Configuration format **22**. Store schema: **unchanged** (the reserved
schema 7 is not used: nothing in the SQLite database changes). Data disk: a new superblock flag and 256 bytes of
key slots (DISK-FORMAT §14.2), no layout version or minor spent.

## What changed for operators

- **`storage.disk_key_source = "console"`** (with `storage.encryption = "aes-256-xts"` and no `storage.disk_key`):
  the image holds no disk key. The data partition's random 64-byte key is wrapped (RFC 3394 AES key wrap under
  PBKDF2-HMAC-SHA-256 of a passphrase, a per-slot salt and the disk UUID) in up to two **key slots** in the
  superblock. A copy of the ISO no longer reads a copied data disk.
- **At every boot** the kernel asks for the passphrase on the VM's console (serial port, the VNC console's keyboard,
  a virtio-console, a virtio-input keyboard), before the store opens and before any listener exists. Nothing typed is
  echoed or logged. A wrong passphrase is answered after 2 s and asked again; the prompt is repeated (and logged)
  every minute.
- **The first boot of a blank disk** asks for a new passphrase twice (12 to 256 printable ASCII characters) and
  formats the partition with a random key wrapped in slot 0 (300 000 PBKDF2 iterations).
- **A RAM store** (the ISO's live entry, `storage.mode = "ram"`) asks for nothing: it is encrypted under a random
  key of that boot and is gone at power-off.
- **`change`** typed at the prompt changes the passphrase (the current one, the new one twice); only the superblock
  is rewritten.
- **Availability trade-off:** after any reboot (crash, watchdog reset, provider maintenance, A/B update) the broker
  stays down, every port closed, until a person types the passphrase. The A/B trial timeout does not count that
  wait.
- **`urmqtt-disk keys DISK`** lists the slots; **`keys DISK add | change | remove | unwrap`** change them offline
  (`--key FILE` or `--passphrase-file FILE` as the authorisation, `--new-passphrase-file`, `--slot`, `--iterations`
  10 000 to 10 000 000, `--key-out FILE` for `unwrap`, a dry run without `--write`). **`--passphrase-file FILE`**
  opens a wrapped disk for every other command (`info`, `verify`, `export-*`, `scrub`, `backup*`, `grow`,
  `import-devices`, `rekey`, `decrypt`).
- `urmqtt-disk encrypt | decrypt | rekey` now empty the key slots when they change the key (the slots wrapped the old
  key) and say so.
- New boot lines (OPERATE.md, "The disk passphrase at the console"): `storage: the data partition is locked: waiting
  for the disk passphrase on the console`, `storage: wrong disk passphrase (N so far)`, `storage: data partition
  unlocked with the console passphrase (key slot N)`, `storage: data partition formatted with a new key, wrapped
  under the console passphrase in key slot 0 (...)`, `storage: the disk passphrase of key slot N was changed ...`,
  `storage: the older superblock still held a replaced key slot ...`; refusals `storage: refused
  reason=not-wrapped` and `reason=key-slot-mismatch` (an edited header). The encryption line now says where the key
  came from: `storage: encryption aes-256-xts (key check ok, key from the image|console passphrase; ...)`.
- **Builder page:** offers `storage.encryption` and, while it is on, `storage.disk_key_source` (Storage section).
  The key file (`storage.disk_key`) stays off the page; choosing "console" asks for a confirmation (texts in the 15
  languages). A problem with the key file is shown at the source choice.
- `scripts/run-qemu.sh --serial-in SOCKET`: the serial port as a Unix socket a test can type into.

## Configuration

| Key | Format | Default | Values |
|---|---|---|---|
| `storage.disk_key_source` (tag 365) | **22** | `"image"` (writes no record) | `"image"`, `"console"` (needs `storage.encryption = "aes-256-xts"` and no `storage.disk_key`) |

Merge note: formats 19 to 21 belong to other items of the release. In this branch `FORMAT_VERSION` is 22 and
`UNUSED_VERSIONS` is `[10, 19, 20, 21]` (the release merge removes the ones it brings in, as with 14 to 17 for
ADR-305). The builder's tests that asserted their own format as the page's newest now compare with the tree's
`FORMAT_VERSION` (`helpers.mjs` `FORMAT`), so they need no edit at the next merge. `tools/config/tests/cli.rs` gains
a `("format 18", 18)` template row and `storage.disk_key_source` needing 22. The test that counted `"since":2` in
the schema JSON counted `"since":22` too; it now counts whole numbers (an oracle fix).

## Upgrade and downgrade

- **Nothing changes** for an image that does not set the key (format, behaviour, disk bytes).
- **An image-key disk to console mode**, offline, no rewrite: `urmqtt-disk keys DISK add --key disk.key
  --new-passphrase-file new.txt --write`, then the image with `disk_key_source = "console"`. Old ISOs still hold
  that key: `urmqtt-disk rekey` to a fresh key first (a full rewrite) to make them useless.
- **Back to an image key, or to v0.5.x** (which refuses a disk with key slots, by the unknown superblock flag):
  `urmqtt-disk keys DISK unwrap --passphrase-file cur.txt --key-out disk.key --write`, then an image with
  `disk_key = "disk.key"`. A format 22 image needs a v0.6.0 kernel (older kernels and templates refuse it by its
  version).
- The kernel refuses a console-mode image on an image-key disk (`reason=not-wrapped`) and says how to add a slot.

## Limits and rules

Two key slots per disk; passphrases of 12 to 256 bytes of printable ASCII; 10 000 to 10 000 000 PBKDF2 iterations
per slot (300 000 by default; a header outside that range is refused); the last slot cannot be removed (only
`unwrap` empties them all). A passphrase change is two superblock writes, each flushed; a cut leaves the old or the
new passphrase working, and an old wrap left in the older superblock by a cut is overwritten at the next open. The
header is plaintext: whoever copies the volume can guess the passphrase offline at one PBKDF2 per guess, so the
passphrase must be strong (a generated one of 20 characters or more).

## Tests

`crates/store/src/keyslot/tests.rs` (RFC 3394 §4.3 and §4.6 vectors, slot codec, passphrase rules, line editor),
`crates/store/tests/wrapped.rs` (format, unlock, seven header edits with and without a CRC, a foreign slot, a swapped
key, rotation, recovery slot, last slot, unwrap, a power cut at every write of a rotation and of a sealed format),
`crates/store/tests/disk_format_spec.rs` (the superblock with the wrapped flag and the key slot table),
`tools/disk/tests/keys.rs` (the commands end to end, only superblock sectors change, a cut at every write of `add` and
`change`, `rekey` empties the slots), `crates/cfg`, `crates/config`, `crates/config-schema`, `tools/config` (format
22, rules, templates), `tools/builder/test/disk-key.test.mjs`, fuzz `disk_keyslot` (seeds in
`fuzz/seeds/disk_keyslot`; 179 492 runs in 2 minutes, no finding), smoke group **`unlock`** (`SMOKE_ONLY=unlock`,
also a CI shard): aarch64 HVF and TCG, x86_64 TCG, 7 checks each.

## Deliberately not done

- **TPM 2.0 sealing:** not built. `swtpm` is not installed on the development machine, so it could not be tested end
  to end under QEMU; ADR-254's analysis stands (driver, TPM2 command layer, PCR policy and its update workflow). The
  slot format leaves room for it (a slot kind).
- **Network unlock** (an operator mTLS endpoint holding the listeners closed until a signed unlock): not built; it
  needs a TLS listener and replay state while the store is sealed (ADR-329).
- **A key file on a separate device**, confidential VMs: not built.
- **Rekey at boot or online:** no; `urmqtt-disk rekey` stays offline.
- **The VNC keyboard path** with a passphrase is not exercised in QEMU (the smoke types on the serial port; the
  readers are the Diagnostic entry's, tested there).
- **Integrity of the data:** XTS gives none, as before.
- `tools/builder/test/simple.test.mjs` "the build ends in a result card" fails on `release-v0.6.0` as well (checked
  on a clean worktree of that branch); not touched here.
