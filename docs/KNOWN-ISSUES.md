# Known issues and limits

Read this before you deploy urMQTT. It lists what is known to be missing, weak or unproven, what each item means
for you, what to do about it, and where it is tracked. It is a summary: the sources are
[AUDIT.md](AUDIT.md) sections 5 and 6 (weaknesses and accepted risks), [ROADMAP.md](ROADMAP.md) (planned work),
the "Limits, stated plainly" paragraphs of [CHANGELOG.md](../CHANGELOG.md) for v0.4.0 and v0.4.1, and
[EDITIONS.md](EDITIONS.md). `scripts/check-known-issues.py` (run in CI) fails if an AUDIT id or ROADMAP item cited
here no longer exists, or if an AUDIT weakness cited here has been marked fixed.

Status as of v0.4.1 plus the `main` branch of 2026-11-06. **The project is pre-alpha.** It becomes "alpha" when a
real release signing key, the entropy decision and the MTU fix have landed ([ROADMAP.md](ROADMAP.md), "Community
readiness").

## 1. The release itself

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **v0.1.0 to v0.4.1 are signed with the project's former test key** `9229E05252D01F8E`. Its secret half was a passwordless CI secret. The rotation to a release key is prepared (branch `release-key`) and waits for the owner. | A valid signature on those releases proves the files match what this repository's CI signed, not that an offline key holder approved them; from the rotation on, the test key is trusted for those tags only. | Verify anyway (`minisign -Vm SHA256SUMS -p keys/minisign-test-9229E05252D01F8E.pub`, then the checksums); for anything that matters, build the template yourself (`make template`, `make repro ENV=release`) and compare. | ROADMAP NOW-2; [RELEASE.md](RELEASE.md) section 9 |
| **The assets of v0.4.1 and earlier are dev builds with throwaway certificates.** From the next release on, the assets are the release kernel and images with an empty configuration. | `urmqtt-dev-*.iso`/`.img` contain keys anyone can read. | Use the template ISO with your own configuration (builder page or `urmqtt-config pack`), or build your own image. | CHANGELOG 0.4.0 and 0.4.1, "Limits"; [RELEASE.md](RELEASE.md) |
| **The image holds your server private key** (and, with encryption at rest, the disk key). | A copy of the ISO or of the installed disk is a copy of both keys. | Store, copy and delete the ISO like the key itself; keep the installed disk's snapshots private. | AUDIT.md section 6; ADR-240, ADR-252, ADR-254; ROADMAP LATER-7 |
| **No external audit yet.** The audit package exists; the review has not happened. Most third-party crates in the kernel are cargo-vet exemptions, not audits. | The security claims are the project's own, backed by its tests. | Read [AUDIT.md](AUDIT.md) and decide; report findings privately ([SECURITY.md](../SECURITY.md)). | AUDIT.md sections 6 and 8; ROADMAP NOW-11 |
| **The site and the builder page are AI-translated** into 13 of their 15 languages, not reviewed by native speakers. The Products page's edition texts likewise. | A translated sentence may be wrong. | The English page is the reference; report a wrong translation as an issue. | ROADMAP section 3, "Not technical, but blocking adoption" |
| **The builder page's emulator** boots BIOS only, has no network, and was tested in Chrome only. | It shows that an image boots, not that it serves. | Boot the image in QEMU ([FIRST-HOUR.md](FIRST-HOUR.md)). | ROADMAP section 3; ADR-228 |
| **Encryption at rest is not on the builder page.** | An image with `storage.encryption = "aes-256-xts"` needs the command line. | `urmqtt-config pack` with `storage.disk_key` naming a key file ([DEPLOY.md](DEPLOY.md), "Encryption at rest"). | ROADMAP NOW-16; ADR-240 |

## 2. Protocol and features

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **MQTT 3.1.1 only.** A CONNECT for MQTT 5.0 (or 3.1) is refused. | Clients must speak 3.1.1 (`mosquitto_* -V mqttv311`; it is the default of most libraries). | Configure the client for 3.1.1. | ROADMAP NEXT-3 |
| **QoS 0 and 1 only.** A QoS 2 PUBLISH closes the connection; a QoS 2 subscription is granted QoS 1. | A device that publishes at QoS 2 is disconnected on every publish. | Publish at QoS 1 (at least once) and make the receiver idempotent. | ADR-028; ROADMAP NEXT-2 |
| **No MQTT over WebSocket.** | Browser clients cannot connect directly. | The external bridge of the demo (`deploy/demo-bridge/`), which is not a supported product. | ROADMAP NEXT-5, D-5 |
| **No bridging, no outbound connections.** The broker only accepts connections (server-only TCP). | No forwarding to another broker, no webhooks, no TLS log shipping. | A service identity (`acl.service_ids`) that subscribes and forwards from outside. | ADR-033; ROADMAP NEXT-7, NEXT-8 |
| **Offline persistent sessions never expire.** | The store grows with every identity that ever connected with a persistent session. | Issue certificates sparingly; prefer clean sessions where queues are not needed. | ROADMAP NEXT-4 |
| **No per-address limit on established TLS connections** (only on handshakes in flight). | One address with valid certificates can hold many connections. | Issue certificates only to devices you control; revoke a misbehaving one. | ROADMAP NOW-14 |
| **Plaintext accounts cannot change at run time.** | Adding or removing a `[plaintext]` user needs a new image. | `disallow` an identity on the signed control channel (allowlist mode), rebuild for new accounts. | ROADMAP NOW-15 |
| **A control message's sender learns nothing about its result.** | A PUBACK means "received", not "applied". | Read the broker log or `urmqtt.control.applied` / `rejected.*`. | AUDIT H1-W1 |
| **Metrics and logs only as statsd and syslog over UDP**; no Prometheus endpoint. | Plain UDP to a private collector. | Keep the collectors on a private network; `$SYS` over MQTT for an operator. | ROADMAP NEXT-9 |

## 3. Network

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **IPv4 only.** | No IPv6 listener, no SLAAC. | An IPv4 address on the VM. | ROADMAP NEXT-1 |
| **The MTU is assumed to be 1500 bytes.** The MTU a network announces (DHCP option 26) is ignored. **Open.** | On a network with a smaller MTU (Google Cloud's default network: 1460) large segments are lost without an error. | Use a network with an MTU of 1500 (the usual VPS and QEMU case). | ROADMAP NOW-19 |
| **No DNS.** | SNTP servers and collectors are IPv4 literals. | Give addresses, not names. | ROADMAP NEXT-10 |
| **Many VPS providers run no DHCP for a custom ISO.** | With `network.mode = "dhcp"` the broker gets no address. | `"static"` with the provider's values, or `"auto"` (DHCP first, then static). | [DEPLOY.md](DEPLOY.md), README "Configuring the network of a VPS" |

## 4. Platforms and devices

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **virtio over PCI only.** No drivers for AWS ENA or NVMe, Google gVNIC, Azure MANA/NetVSC, VMware VMXNET3/PVSCSI, physical NICs or disk controllers. | A production image without a virtio-net NIC stops with a message that names the NIC and says what to attach; a disk that is not virtio is not used (no data partition). | A machine type that offers virtio-net and virtio-blk or virtio-scsi (KVM, Proxmox, netcup, Contabo, Hetzner, Google Cloud e2/n2, ...). The drivers are the commercial edition's scope. | [EDITIONS.md](EDITIONS.md); ROADMAP LATER-2, LATER-3, LATER-4 |
| **No Firecracker** (virtio over MMIO, no firmware). | Not supported: the kernel's virtio transport is PCI and it is started by UEFI or BIOS firmware. | A hypervisor with UEFI or BIOS and virtio-pci. | [EDITIONS.md](EDITIONS.md) section 2 |
| **Legacy-only (pre-1.0) virtio devices are refused**, and disks with 4096-byte logical blocks (4Kn) are not supported by the boot path. | A legacy-only device is refused with a message naming it; a 4Kn boot disk is not supported. | Modern virtio (`disable-legacy=on`) and 512-byte logical blocks. | ADR-257; ROADMAP LATER-11 |
| **Two real machines only.** A release-candidate image has run on one netcup aarch64 KVM VPS and one Contabo x86_64 KVM VPS. The x86_64 code after the H7 commit (disk encryption, boot integrity, everything since) has not run on an x86_64 KVM guest or on hardware. | Other providers are expected to work because of their devices; nobody has checked. | Treat a first boot on a new provider as an experiment; the [boot-failure form](../.github/ISSUE_TEMPLATE/boot-failure.yml) is how to report it. | AUDIT.md section 6; ROADMAP NOW-12 |
| **A VPS console that goes dark after the boot menu** ("Display output is not active", netcup ARM). | The boot log is invisible there. | `console.virtio_gpu = "on"` or `"auto"`; or read `$SYS/console/out` over MQTT ([FIRST-HOUR.md](FIRST-HOUR.md) step 4). With `"auto"`, a VM that has both QEMU's `ramfb` and a virtio-gpu gets the virtio-gpu and the `ramfb` picture freezes. | ADR-256; AUDIT A256-W2 |
| **Secure Boot is not used by release images**, and where you sign images yourself: an installed disk does not boot under Secure Boot, a signed image cannot be configured afterwards, the BIOS path has no signature, aarch64 enforcement is untested, and an older signed image boots (no downgrade protection). | Boot integrity rests on the hypervisor and on the loader's enrolled hashes. | Configure first, then sign ([DEPLOY.md](DEPLOY.md) section 5d); on a VPS the firmware is the provider's. | AUDIT H8-W1, H8-W2, H8-W3, H8-W4, H8-W6; ROADMAP LATER-6 |
| **No IOMMU, and the PCI and virtio parsers are not fuzzed.** | A hostile or buggy virtual device is trusted. In a VM the hypervisor is trusted anyway. | Run it under a hypervisor you trust. | AUDIT H0-W9; ROADMAP LATER-5, NOW-8 |
| **Updates are offline and have no automatic rollback.** | A kernel update means stopping the VM. | `urmqtt-disk update-boot` (keeps the data) or reinstall; keep the previous image. | ROADMAP NEXT-11 |

## 5. Storage

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **The live entry keeps everything in RAM.** | Retained messages, sessions, telemetry and run-time revocations are gone at the next reboot. | Install to a disk; `storage.mode = "disk"` forbids the live entry. | [DEPLOY.md](DEPLOY.md), "Live mode" |
| **Rolling the data disk back** to an old snapshot restores old revocations. Encryption at rest (XTS) gives no integrity. | A revoked device can come back with an old snapshot. | Also list revocations in the image (`tls.revocation_list`): they are re-applied at every boot. | AUDIT H1-W2; ADR-240 |
| **SQLite reads the data disk without fuzzing of crafted database files.** It runs as an unprivileged, restartable worker. | A crafted disk could make the store give wrong answers or restart. | Treat the data disk as trusted; do not attach disks of unknown origin. | AUDIT H0-W8; ROADMAP NOW-10 |

## 6. Entropy

| Issue | What it means for you | Workaround | Tracking |
|---|---|---|---|
| **A VPS without virtio-rng and without `RNDR`/`RDRAND`** (the netcup ARM VPS is one) seeds the random generator from CPU timing jitter plus the bootloader's EFI RNG: the weakest seeding the kernel accepts. The boot log says `WARN entropy: no hardware source ... CPU jitter fallback`; `$SYS` does not show it yet. | The TLS keys of that machine depend on the jitter estimate, which was measured under QEMU and on that one VPS. | Ask the provider for a virtio-rng; or set `entropy.fallback = "none"` and the image refuses to boot without a hardware source. | ADR-038; ROADMAP NOW-4, D-3 |

## 7. Not proven yet (the "Limits" of v0.4.0 and v0.4.1)

- **AArch64 X25519 assembly** (new in v0.4.1, written for this project): tested against RFC 7748 and another
  implementation; timing records from Docker on an Apple M4 Pro only; no independent review. PSTATE.DIT is never
  set (AUDIT A255-W2). Constant-time evidence does not cover the X25519 key share or Ed25519 (AUDIT.md section 6;
  ROADMAP NOW-9).
- **x86_64:** built and checked by clippy, but its unit tests run nowhere (CI's host tests run on arm64), the
  x86_64 and universal-ISO smoke suites are not in CI, and nothing of v0.4.0 or v0.4.1 ran on an x86_64 KVM guest.
- **The Neoverse N1 figures** are from one netcup VPS, one run each, on shared hosts.
- **virtio-console, -balloon, -input and -vsock** have not run on a real VPS; vsock only against a test double.
- **100k and 1M connections** were not generated; the per-connection memory was measured at 10k (AUDIT.md
  section 6).

## Reporting

A limit that is not here, or an item here that is wrong: open an issue (the forms are in
`.github/ISSUE_TEMPLATE/`). A vulnerability: privately, as [SECURITY.md](../SECURITY.md) says.
