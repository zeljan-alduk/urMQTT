# v0.6.1 release notes: boot chain, updates and installation (security review of v0.6.0)

- The builder page and `urmqtt-config check-release --keyring --tag` refuse a signed release offered under another
  tag: the signed trusted comment must name the tag (ADR-365). Before, a genuinely signed older release could be
  listed by a mirror as a newer one.
- `urmqtt-config check-release --pubkey` and `urmqtt-disk slots stage --pubkey` apply the key ring built into the
  tool: the former test key is accepted only for its six pinned releases, however it is passed (ADR-366).
  docs/RELEASE.md now shows `--keyring` with `--tag`.
- `urmqtt-config pack --iso` (an image configured before) and `pack --image` refuse a configuration format the
  image's kernel does not read, judged by the kernels' build note (ADR-367); such an image would not boot.
- `urmqtt-disk update-boot` (also `--in-place` on an A/B disk) applies the rules of `slots stage`: no older store
  schema, no older release without `--allow-downgrade`, no configuration format the kernel does not read, and on an
  A/B disk no kernel without a build note (ADR-368).
