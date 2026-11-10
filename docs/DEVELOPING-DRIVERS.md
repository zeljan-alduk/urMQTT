# Adding a virtio driver

The framework is ADR-257 ([DECISIONS.md](DECISIONS.md)); the drivers of phase 1
(console, balloon, input, vsock) are ADR-258 and the examples to copy. Every
driver parses data the hypervisor controls and is part of the trusted base when
it runs: the security steps below are not optional.

## Checklist

1. **The module.** `crates/virtio/src/<name>.rs`, virtio 1.x modern only
   (`F_VERSION_1` required). Make the driver generic over `bus::Bus`, not
   `Transport`, so the fake device can test it. Use `bus::make_queue` for
   queues, `bus::dma_read`/`dma_write` for buffers, `bus::cfg_consistent` for
   multi-field configuration reads, `bus::ByteRing` for received bytes.
   Rules: clamp every length the device reports to the buffer you gave it;
   check every completed head against a slot map of what you posted; bound
   every loop (by the queue size, or a constant); no waiting without a
   timeout, and in anything the log, the tick or a prompt calls, no waiting at
   all; no device value as a pointer or an unchecked index. Put the parsers
   that are worth fuzzing in pure functions (`Event::parse`, `vsock::Stack`).
2. **The feature.** In `crates/virtio/Cargo.toml`: a feature `<name> = []`,
   added to `all`, and to `vps` only if the MQTT image on a VPS should carry
   it. In `crates/virtio/src/lib.rs`: `#[cfg(feature = "<name>")] pub mod <name>;`.
3. **The registry row.** One row in `crates/virtio/src/registry.rs::KINDS`, in
   device-ID order: type, transitional PCI ID if the specification has one,
   name, feature, `cfg!(feature = "<name>")`, the `[devices]` key, and
   `needs_device_cfg` (false when the device has no configuration structure).
   Add a `pub const <NAME>: u16` for the type. Remove the type from
   `type_name`'s fallback list if it is there.
4. **The kernel row.** In `crates/kernel/Cargo.toml`: `virtio-<name> =
   ["urmqtt-virtio/<name>"]`, added to `virtio-all` (and `virtio-vps` if step 2
   did). A glue module `crates/kernel/src/vdev/<name>.rs` (copy `console.rs` or
   `balloon.rs`): the driver in a `SpinLock` behind `#[cfg(feature =
   "virtio-<name>")]`, an `init(cfg, env, bdf, caps) -> Result<String,
   String>` that maps the transport with `devices::transport` and starts the
   driver, and `pub const INIT: Option<super::Init>` (`Some(imp::init)` with
   the feature, `None` without). Then one `Driver` row in
   `vdev/mod.rs::DRIVERS` at the same position as the `KINDS` row (`Generic {
   init: <name>::INIT, max: 1 }`), and the glue's `tick`/`report`/`read_byte`
   hooks in `vdev::tick`, `vdev::report`, `vdev::read_byte` if it has them. The
   const check in `vdev/mod.rs` fails the build if a row is missing or out of
   place.
5. **The configuration key** (follow `devices.virtio_vsock` through these
   files): a tag (`crates/cfg/src/fields.rs`, the next free number), a `FIELDS`
   entry with `Kind::Enum { variants: DEVICE_MODES, default: 0 }` and
   `since(..., 6)` (a newer format version if old kernels must refuse it: then
   `FORMAT_VERSION` and its doc in `blob.rs`), a `DEVICE_KEYS` row (tag, key,
   feature); `Devices` in `crates/config-schema/src/lib.rs` (field and `iter`
   row); `deploy/{dev,prod,bench,demo}/config.toml` (`"auto"` in dev, `"off"`
   elsewhere, with a comment); the builder page's label
   `enum.devices.virtio_<name>.{off,auto,on}` in all 15 files of
   `tools/builder/web/i18n/`; a sentence in docs/DEPLOY.md. The tests that
   compare the tables (`registry` against `DEVICE_KEYS`, config-schema against
   the templates) tell you what you missed.
6. **Tests.** Host tests in the module against `fake::FakeBus`: feature
   negotiation, what is posted, normal completions, clamped lengths, hostile
   heads and indices, missing queues. A fuzz target under `fuzz/fuzz_targets/`
   for each parser (or the driver against the fake, as
   `virtio_console_device` does; the `fake` feature makes it available) with
   seeds in `fuzz/seeds/<target>/` and a `[[bin]]` in `fuzz/Cargo.toml`. A
   smoke scenario in `scripts/smoke.sh` if the QEMU here has the device (see
   `virtio_devices`; put it in an existing CI group, `misc` for these).
7. **Documents.** An ADR (or a section of the family's ADR) with the policy,
   the threat model, what is not done and what has not run on a real device;
   docs/AUDIT.md: a row in §2 (external inputs) and in §3 (mitigation matrix);
   `make audit` and commit `docs/audit/*`; CHANGELOG.
8. **Gates.** `cargo fmt --all --check`, `cargo clippy --workspace
   --all-targets -- -D warnings`, `make clippy-kernel` for both `ARCH`es
   (it checks the default set, `virtio-all` and `--no-default-features`),
   `make build` for both, host tests of the touched crates, the fuzz targets
   for a while, `make builder-test`, the smoke scenario.

## What the framework does for you

- The device is listed in the boot log and in the Diagnostic report with its
  state (`virtio: <name> at <bdf>: driven`, `off`, `no driver in this image`,
  ...), whether or not the driver is compiled in.
- The `[devices]` key decides: "off" never calls `init`, "auto" calls it when
  the device is found, "on" also warns when there is none.
- A key that is not "off" for a driver the image lacks is refused by
  `urmqtt-config pack --iso`/`--image`/`--kernel` (the kernel's
  `URMQTT-VIRTIO-DRIVERS:` marker) and warned about at boot.

## A driver that is not virtio (out of tree)

A driver for a device that is not virtio does not go into this repository
([EDITIONS.md](EDITIONS.md) §6); it lives in an edition's own crate that uses
the kernel as a library (NOW-18, ADR-335 to ADR-339,
[ARCHITECTURE.md](ARCHITECTURE.md) §8b). It is a `urmqtt_kernel::ext::PciDriver`
in the edition's `Edition`: its PCI IDs, a `max`, and a `probe` that gets a
`PciDevice` (configuration space, memory BARs, DMA memory). Its configuration
keys are fields in the reserved range (`urmqtt_cfg::ext::field`, keys
`ext.<section>.<name>`). `examples/edition` is a complete one to copy: the
driver (`src/edu.rs`), the key table shared with the packer (`src/lib.rs`), the
build script that links the image, and the packer (`src/config.rs`). The same
security steps apply to it as to a virtio driver: what the device returns is
hostile input, every loop is bounded, and the edition's own fuzz targets and
smoke tests are its audit evidence (the commercial edition publishes them,
EDITIONS.md §4 point 5).
