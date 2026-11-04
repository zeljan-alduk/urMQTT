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
- The x86_64 and universal-ISO smoke suites are not in CI; they run under QEMU TCG, not on KVM.
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
