# NOW-18: the kernel as a library (ADR-335 to ADR-339)

## What changed for operators

- **Nothing in the open image's behaviour.** The kernel crate is now a library (`urmqtt_kernel`) and the open
  image is one line on top of it (`urmqtt_kernel::image!(Edition::OPEN)`). The open image runs the same code on
  empty extension tables: no new log line, no new key, no new port, no device bound differently. The image is still
  reproducible (`make repro`), but not byte-identical to a v0.5.x or pre-NOW-18 build of the same configuration
  (the library's symbol names and the extension checks are new code); release hashes change as with any release.
- **For the commercial edition and other editions** (docs/EDITIONS.md §5, docs/ARCHITECTURE.md §8b): a second
  repository builds its own kernel image from this repository's crates (a git dependency pinned to a tag; nothing
  is published) and adds, through `urmqtt_kernel::ext::Edition`:
  - PCI drivers bound by vendor:device, vendor, or class:subclass (`PciDriver`, `PciId`), offered only the
    functions no open driver claims and never a virtio function (vendor `0x1AF4`; naming it is a compile error),
    with their function's configuration space, memory BARs (`map_bar`) and DMA memory in its IOMMU domain;
    boot lines `ext: <driver> at <bdf>: driven: ...` / `spare` / `failed: ...`, and the driver's name in the
    Diagnostic report's PCI list;
  - configuration keys in the reserved range (tags `0xF000..=0xFFFE`, TOML `[ext.<section>]`), packed by the
    edition's own packer (`urmqtt_config_schema::pack::pack_ext`, `urmqtt_cfg::build::sign_ext`);
  - boot hooks: early, after the device probe, before `URMQTT READY`, and the 10 ms tick.
- **An open image refuses an edition's configuration**: `fatal: configuration refused: blob: unknown field tag`,
  and the open `urmqtt-config` and the builder page refuse an `[ext]` table (unknown key). An image never boots
  ignoring the configuration of a driver it does not have.
- `examples/edition`: a complete example edition in its own Cargo workspace (a driver for QEMU's `edu` test device,
  two keys, every hook, its own packer). `make edition-example [ARCH=x86_64]` builds it into `target/`.
- `scripts/mkiso.sh --config-slot FILE`: puts an edition's configuration slot (made by the edition's packer) into
  an image as it is; the open `--config` path is unchanged.
- New smoke group `SMOKE_ONLY=edition` (in CI's smoke matrix); new fuzz target `cfg_ext`.

## Configuration keys and format

No open key. No configuration format number (none was reserved for this item, none is used). The tags
`0xF000..=0xFFFE` and the TOML table `[ext]` are reserved for editions from this release on; no open key will ever
use them. Store schema unchanged (5).

## Upgrade and downgrade

- Existing configurations, images and stores keep working unchanged in both directions: no record, key or schema
  changes. An open image's configuration means exactly what it meant.
- A configuration made by an edition's packer with an `[ext]` key does not boot on the open image (by design,
  refused at boot with the reason) or on any image before v0.6.0 (an unknown tag there too).

## Defaults and limits

- An edition: at most 32 PCI drivers, names `[a-z0-9-]` of at most 32 bytes; at most 256 configuration keys of the
  kinds Bool, UInt, Enum, Str, Strs, keys `ext.<section>.<name>` of at most 64 bytes; `map_bar` at most 16 MiB of a
  BAR, during the probe only. All checked at compile time of the edition's image (`Edition::check`, a `const fn`).

## Deliberately not done (ADR-339)

- **No NIC, disk, entropy-source or timer interface for devices that are not virtio.** An edition's driver can
  bind and drive its device, read its keys and run code at boot, but it cannot yet be the broker's network device
  (the data path and its RSS queues are written for virtio-net), hold the store (the boot disk selection is
  virtio-blk / virtio-scsi), or add an entropy source (the pool's sources are a fixed, audited list). This is the
  next step for a commercial NIC or disk driver (gVNIC, ENA, NVMe).
- No interrupts (MSI-X vectors) for an edition's device; drivers poll from the `tick` hook.
- No builder-page or JSON-schema export of an edition's keys.
- The universal ISO, the installer and Secure Boot signing were not exercised with an edition's kernel
  (`make universal` and `make release-images` build the open image).
- The private repository is not created; nothing is published to crates.io.
