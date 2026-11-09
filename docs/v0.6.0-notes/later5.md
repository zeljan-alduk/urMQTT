# LATER-5 (H4b): DMA remapping through the IOMMU — release notes input

ADRs: ADR-305 (design), ADR-306 (faults), ADR-307 (verification and what is not done). Branch `v060/later5`.

## What changed for operators

- New key **`devices.iommu = "off" | "auto" | "require"`**, **configuration format 18**, default **`"off"`**.
  - `off`: the IOMMU is left as the firmware set it, exactly as in v0.5.0. The boot log names an IOMMU it found
    (`iommu: VT-d@0xfed90000/...: not used (devices.iommu = "off")`).
  - `auto`: the broker drives every IOMMU the firmware describes (Intel VT-d from DMAR, AMD-Vi from IVRS, Arm
    SMMUv3 from IORT or the device tree). Every device's DMA is blocked from before the first driver runs; each
    driven device gets a domain holding only its own buffers (and on aarch64 the MSI doorbell page). Where that is
    not possible (no IOMMU, a unit that fails, a device outside every unit's scope, a virtio device without
    VIRTIO_F_ACCESS_PLATFORM) it warns and goes on.
  - `require`: each of those cases refuses to boot with the reason.
- Blocked DMA is counted and logged: `$SYS/broker/iommu/{mode,state,units,domains,pages,faults,overflows}`, an
  `iommu` object in the info query, a `status` line when the key is not `off`; boot lines `iommu: ...` (the
  description, each unit, each device's domain, a summary). Faults are read every 100 ms, at most 16 per unit per
  poll; the first 16 are logged one line each, then every power of two.
- virtio: the kernel now accepts VIRTIO_F_ACCESS_PLATFORM whenever a device offers it (no change for devices that
  do not offer it, which is every default QEMU and cloud device).
- The builder page shows the key in the advanced `[devices]` section (with hints in the 15 languages); its form
  model, the CLI and the kernel agree on format 18.
- `scripts/run-qemu.sh --iommu intel|amd|smmuv3` adds the emulated unit and `iommu_platform=on,disable-legacy=on`
  to every virtio device (`QEMU_IOMMU_PLATFORM=off` leaves them bypassing it).
- New smoke group `SMOKE_ONLY=iommu` (also in the default run and in `misc`), new fuzz target `iommu_tables`.
- Dev-only command-line word `test=iommu-dma` (makes the entropy device write outside its domain).

## Upgrade and downgrade

- An existing configuration does not change: `off` writes no record, so its format number stays what it was and
  the image still boots on v0.5.0. No store change (schema stays 5).
- A configuration with `auto` or `require` is format 18: a v0.5.0 (format 13) template refuses it at pack time
  ("needs configuration format 18, which this template's kernel does not read"), and a v0.5.0 kernel refuses
  such a blob by its version at boot. Downgrading means setting the key back to `off` (or removing it).
- Format numbers 14 to 17 are the other v0.6.0 items'; this branch does not read them until the release merge
  (`urmqtt_cfg::blob::UNUSED_VERSIONS`). The record's tag is 318.

## Defaults and limits

- Default `off` (a KVM VPS's devices are the hypervisor's, and an emulated IOMMU slows every DMA). Recommended:
  `require` on bare metal or under a hypervisor whose device models are not trusted.
- At most 4 IOMMU units and 32 requester-ID ranges per unit are used (more are counted; their devices are not
  translated, which `require` refuses). Page tables: 4 KiB pages, 48-bit (or 39-bit) identity mapping.
- Memory: AMD-Vi needs a 2 MiB device table; VT-d and SMMUv3 a few pages per device (40 to 60 KiB for three
  devices in QEMU).

## Deliberately not done

- Not run on real hardware: only QEMU 11.1's intel-iommu, amd-iommu (`dma-remap=on`) and virt SMMUv3, under TCG
  (both architectures) and HVF (aarch64). Not run under KVM (intel-iommu with interrupt remapping then needs
  `kernel-irqchip=split`, which `run-qemu.sh` adds).
- Interrupt remapping is not enabled on any unit; a VT-d unit whose firmware enabled it is refused (`auto` goes on
  without it). With a GICv2m frame a device can still raise any SPI of the frame.
- Reserved regions (VT-d RMRR, AMD IVMD, Arm RMR) are counted, not mapped; DMAR scopes behind a bridge are not
  followed.
- VT-d: no queued invalidation, scalable mode, 5-level tables or ATS. AMD-Vi: no exclusion range or ATS; QEMU's
  model reports fault addresses where the decoder reads 0. SMMUv3: no two-level stream table, stage 2, PRI, ATS or
  stall; the cache maintenance for a non-coherent unit is untested.
- No fault interrupt (polling by design, ADR-306); no unmapping (DMA memory lives as long as the device).
- The throughput cost of translation is not measured.
