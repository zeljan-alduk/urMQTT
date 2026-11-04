## urMQTT v0.4.1 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 over TLS 1.3 with mutual TLS.
This release covers everything since v0.4.0: a faster server side of the mutual-TLS handshake (ADR-259). No
configuration format change; the builder page stays as it is.

**New**

- **The trust anchors get their verification tables.** Since ADR-111 no CA ever had one: the key was stored in a form
  the registration did not parse, so a device's first handshake checked its certificate on the slower unknown-key
  path (no effect on verdicts). Fixed (docs/AUDIT.md A259-W1).
- **X25519 on aarch64 in `mul`/`umulh` inline assembly** for the shared secret, instead of dalek's 51-bit ladder. The
  boot line reads `crypto: ecc=... x25519=armv8|adx|portable`. `make ct` gains `x25519_ladder_is_constant_time`.
- **P-256 verification** with a width-5 NAF and a variable-time scalar inversion (public inputs only; signing and ECDH
  keep their constant-time paths), on both architectures.
- **Measured on the netcup Neoverse N1 VPS** (2 vCPUs, so one data core; one run each, the load host shared, the CPU
  clock 2.58 GHz in the earlier run and 2.89 GHz in this one): the server's CPU per handshake 461 us against 553 us
  with the P-256 assembly of ADR-255 alone and about 1.0 to 1.08 ms with the portable code; X25519 128 us, ECDSA verify
  124 us. Full mTLS handshakes per second, 0 errors, medians of three runs: 1,451 / 1,624 / 1,599 at 32 / 64 / 128
  threads, against 1,317 / 1,398 / 1,316 with the assembly alone and 848 / 827 / 778 with the portable code
  (docs/PERFORMANCE.md section 12.1, raw files in docs/perf-results/).
- **Profiled stage by stage** (Docker on an Apple M4 Pro, not the target CPU; PERFORMANCE.md section 12): the
  server's CPU per full mutual-TLS handshake 88.8 -> 80.3 us for a returning device, 118.6 -> 87.8 us for a first
  contact. The profiler is a host-only feature (`stage-profile`, example `handshake_profile`) and not in the image.
- **ADR-260, a proposal only**: a cache of verified client certificates. Not built, and recommended against (about
  1 us per returning device's handshake for a new trust decision).

**Compatibility.** Nothing changes for images, disks or the builder page. The kernel reads configuration formats 1 to
6 and the template declares format 6, as in v0.4.0; the data-disk layout is unchanged (v2.1). The cipher suites,
key-exchange groups and signature schemes offered are unchanged.

| Template of | Its kernel reads | What the builder page and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; TLS off is refused (format 3); the virtio-gpu console and `[devices]` keys are refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest (format 4) through `urmqtt-config pack` only, the page does not offer it |
| v0.4.0 | formats 1 to 6 | everything the page offers, including `console.virtio_gpu` and the `[devices]` keys |
| v0.4.1 | formats 1 to 6 | as v0.4.0 |

The page picks the newest release that can do what the form asks, so it chooses v0.4.1 once the release mirror lists
it.

**Read this before relying on it**

- Pre-alpha. The assets here are **dev builds with throwaway keys** for evaluation, and the release signing key is
  still a test key; production images are built from your own `deploy/prod/` (docs/DEPLOY.md).
- The aarch64 X25519 assembly is new code written for this project, not vendored from an upstream. It is tested
  against RFC 7748 and against dalek; the timing records in the repository are from Docker on an Apple M4 Pro only.
  It has had no independent review and needs a human review. PSTATE.DIT is never set (docs/AUDIT.md A255-W2), now
  for the X25519 field arithmetic as well as for P-256.
- The Neoverse N1 figures above are one netcup VPS, one run each, from a shared load host; at 32 threads the ranges of
  this release and of the assembly alone overlap. No other server core was measured.
- The P-256 verification change runs on x86_64 too, unmeasured. The x86_64 unit tests do not run in CI (its host tests
  run on arm64 Linux and macOS), the x86_64 and universal-ISO smoke suites are not in CI, and nothing of this release
  ran on an x86_64 KVM guest.
- Unchanged from v0.4.0: the real machines so far are one netcup ARM64 VPS and, for x86_64, a Contabo KVM VPS at the
  H7 commit; nothing has run on physical hardware. The virtio-console, -balloon, -input and -vsock drivers have run only
  under QEMU. On the netcup VPS the random number generator was seeded from the CPU-jitter fallback and the
  bootloader's EFI RNG only. Secure Boot only partly done (release images are not signed), no IOMMU, encryption at rest
  not on the builder page, 53 of the 67 crates in the kernel are cargo-vet exemptions, not audits, and the audit
  package is a self-review.
- Support: only the latest release gets fixes; **v0.4.0 and older are no longer supported.**

**Verify** (in an empty directory):

    gh release download v0.4.1 --repo zeljan-alduk/urMQTT
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    gh attestation verify urmqtt-dev-v0.4.1.elf --repo zeljan-alduk/urMQTT

`minisign.pub` is in the repository root (key `RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`). Full changelog:
CHANGELOG.md.
