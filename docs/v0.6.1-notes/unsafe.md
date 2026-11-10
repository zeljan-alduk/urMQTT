# Security review of v0.6.0: memory safety and the trusted computing base (ADR-345 to ADR-347)

## Fixed

- **A device's MSI-X table must lie inside its BAR** (medium; ADR-345). The kernel mapped and wrote the MSI-X table
  at the offset and size the device's capability gave, without checking them against the BAR, so a hostile device
  could make the kernel write MSI entries into RAM up to 4 GiB above its BAR, out of the IOMMU's sight. The table
  is now checked against the probed BAR size (a device that fails is polled and its boot line says why), and no
  device mapping may overlap RAM in the memory map. Regression test: `pci`
  `msix_table_outside_its_bar_is_refused`.
- **`limits.max_topic_levels` is capped at 128** (low; ADR-346). It accepted any u32, the kernel truncated it to
  16 bits (65 536 refused every topic), and with it and `limits.max_topic_len` raised one device could overflow
  a data core's stack with a topic hundreds of levels deep, stopping the broker. A configuration above 128 is now
  refused at validation (the default, 16, is unchanged; no format number changed). The kernel also saturates the
  other 32-bit limits it narrows to 16 bits (`max_subscriptions_per_session` above 65 535 no longer refuses every
  SUBSCRIBE). Regression tests: `cfg` and `config-schema` `topic_levels_are_capped`, `broker`
  `deepest_allowed_topic_fits_a_data_core_stack`.
- **The IOMMU drivers reach only the frames lent to them** (low, hardening; ADR-347). The kernel turned any aligned
  physical address the safe `urmqtt-iommu` crate asked for into a pointer; it now refuses addresses outside the
  frames that crate was given. Regression test: `kernel` `only_lent_frames_are_reachable`.

## Operators

- A configuration with `limits.max_topic_levels` above 128 no longer validates; lower it before upgrading.
