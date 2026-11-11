## urMQTT v0.6.0 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 and MQTT 5.0 over TLS 1.3
with mutual TLS. This release covers everything since v0.5.0. Headline features: **IPv6** with SLAAC or static
addresses on every listener (ADR-330 to ADR-334); **Prometheus metrics** served by the kernel (ADR-290 to ADR-294);
**A/B updates with automatic rollback** (ADR-295 to ADR-299); **password accounts added and removed at run time**
(ADR-285 to ADR-289); a **limit on established connections per source address** (ADR-280); **virtio-net multiqueue
with RSS** (ADR-310 to ADR-314); and the broker's first **outbound connection**, log shipping over TLS 1.3 (ADR-315
to ADR-319). Security: **DMA remapping through the IOMMU** (ADR-305 to ADR-307), **Secure Boot completed for
installed disks** (ADR-320 to ADR-324) and **a disk key that is not in the image** (ADR-325 to ADR-329). **Read
"Upgrading from v0.5.0" before you update: the database migrates one way, and a source address is now limited to 1024
connections.**

### Security review of this release

Before the tag the release went through an internal, AI-assisted security review (nine lenses, proof per finding, three
independent skeptics per finding; **not** an independent audit, see the report for its limits):
[docs/audit/security-review-v0.6.0.md](https://github.com/zeljan-alduk/urMQTT/blob/main/docs/audit/security-review-v0.6.0.md).
It reported 48 candidates; **31 findings are fixed in this release, with a regression test each, three of them of high
severity**: a leak of captured TLS handshake secrets that, after 4096 abandoned handshakes, made later overlapping
handshakes fail until a reboot (ADR-340); a client certificate with more than one common name that the broker and the
signing script read differently, so that it could carry another identity (ADR-360); and a TLS handshake refused under a
zero window that left a connection never freed, until the heap was full (ADR-355). The code behind them is older than this
release, so **assume earlier releases are affected and update**. The medium and low findings are listed in the report;
the 8 findings that are still open are all of low severity and their details are withheld until they are fixed
(docs/VULNERABILITY-HANDLING.md). The release pipeline changed as a result: the build job holds no secret, a separate
job in the protected environment `release` signs, and a signed older release can no longer be offered under a newer tag
(ADR-380, ADR-381).

Signed with the release key `721316B961DCB94B` (`minisign.pub` at the tag), as v0.4.2 and v0.5.0 were. The former test
key `9229E05252D01F8E` signed v0.1.0 to v0.4.1 only; a signature by it on any later tag is a forgery (SECURITY.md).

**The assets**

The release kernel and images with an empty configuration; configure them with the builder page
(https://aldo.tech/en/products/urmqtt-builder/, in your browser, keys never leave it) or `urmqtt-config pack
--iso/--image` (docs/FIRST-HOUR.md walks through it).

| File | What |
|---|---|
| `urmqtt-v0.6.0.elf` | the release kernel for aarch64 (no certificate or key in it; reproducible from the tag with `make dist ENV=release` on Ubuntu 24.04 arm64 with clang 18.1.3, the release runner's toolchain; another clang gives another ELF) |
| `urmqtt-v0.6.0.iso` | the universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) with the empty configuration: byte for byte the template |
| `urmqtt-v0.6.0.img` | its raw disk image; `urmqtt-config pack --image` configures it |
| `urmqtt-template-v0.6.0-universal.iso` | the same ISO under the template name the builder page and the mirror use |
| `urmqtt-v0.6.0.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | the checksums and their signature with the release key; trusted comment `urMQTT v0.6.0 release <commit>` |

**New**

- **IPv6** (ADR-330 to ADR-334): `network.ipv6 = "slaac"` (link-local address from the MAC, one global address from
  the first /64 prefix advertised, the router and MTU from the advertisements) or `"static"` (`ipv6_address`,
  `ipv6_gateway`, the usual VPS case), duplicate address detection, every listener dual stack, an IPv6 /64 counted as
  one source by the per-address limits, IPv6 networks in `plaintext.allow_from` and `metrics.allow_from`, RSS for
  TCP/IPv6. Off by default (configuration format 23). Turning it on opens every listening port to IPv6: mind the
  firewall.
- **Prometheus metrics** (ADR-290 to ADR-294): `[metrics] enabled = true` serves `GET /metrics` on TCP 9100 to the
  networks in `metrics.allow_from` and to nobody else; every `$SYS/broker` number is a metric (about 170 series,
  bounded labels), text format 0.0.4 or OpenMetrics 1.0.0. Off by default (format 16). docs/OPERATE.md has the scrape
  configuration and alert rules.
- **A/B updates with rollback** (ADR-295 to ADR-299): a new install has two boot slots; `urmqtt-disk slots stage` writes
  a release (its minisign signature and SHA-256 checked) into the standby slot, `slots activate` boots it on trial,
  the kernel confirms itself after `update.confirm_after_s` (60 s) or, after a crash, a watchdog reset or no
  confirmation, switches back to the previous release by itself; `[update] confirm = "operator"` waits for the signed
  control messages `boot-confirm` and `boot-rollback`. Every step survives a power cut. Format 17.
- **Password accounts at run time** (ADR-285 to ADR-289): the signed control commands `set-account` and
  `remove-account` (`urmqtt-control`) add, change and remove plaintext and WebSocket accounts without a new image or a
  reboot; the operator's machine hashes, only the hash is signed; classes `full`, `read-only`, `write-only`; live
  connections are cut on a change. `limits.max_runtime_accounts` (default 0, format 15), database schema 6.
- **A per-address connection limit** (ADR-280): `limits.max_connections_per_ip`, default **1024** established TLS
  connections per source address (0 turns it off; format 14 when changed).
- **virtio-net multiqueue with RSS** (ADR-310 to ADR-314): one queue pair per data core when the device offers MQ and
  RSS, otherwise one pair as before; `devices.virtio_net_queues = "single"` (format 19) forces one.
- **An outbound TCP client** (ADR-315 to ADR-319) and **log shipping over TLS 1.3**: `observability.log_tls` with
  `log_tls_ca` (format 20); off unless configured; the only outbound connection the broker makes.
- **DMA remapping** (ADR-305 to ADR-307): `devices.iommu = "off" | "auto" | "require"` (format 18, default `off`) for
  Intel VT-d, AMD-Vi and Arm SMMUv3; blocked DMA is counted and logged.
- **Secure Boot completed** (ADR-320 to ADR-324): an image signed with your own key is sealed to its configuration so
  the installed disk boots under Secure Boot; `scripts/sign-loaders.sh sign-iso` signs an ISO the builder page
  configured; revocation by `dbx` hash; aarch64 enforcement tested with AAVMF (docs/secure-boot-keys.md).
- **A disk key outside the image** (ADR-325 to ADR-329): `storage.disk_key_source = "console"` (format 22) wraps the
  disk key under a passphrase typed on the console at every boot, before anything listens; `urmqtt-disk keys`.
- **Builder page:** encrypted project files and browser copies (ADR-300); the new keys in all 15 languages.
- **The kernel as a library** (ADR-335 to ADR-339): `urmqtt_kernel` and an `Edition` API (PCI drivers by ID, reserved
  configuration tags, boot hooks) for images built in another repository; the open image behaves as before.

**Upgrading from v0.5.0**

- **The database migrates from schema 5 to schema 6 on the first boot, one way.** A v0.5.x kernel refuses the
  migrated database (`schema version 6 is newer than this build`) and every backup snapshot the new kernel takes. If
  you may want to go back, take a backup first, with the VM stopped: a copy of the whole data disk, or v0.5.0's
  `urmqtt-disk backup DISK --write` and then `urmqtt-disk backup-extract DISK OUT` to keep the snapshot outside the
  disk. A power cut during the migration leaves a whole schema. The data-disk layout (v2.1) does not change.
- **Configuration formats go up to 23** (the kernel reads 1 to 9, 11 to 20, 22 and 23). A configuration is written with
  the format of its newest key that is not at its default; one that sets no new key keeps format 13 or lower and packs
  into the v0.5.0 template as before. A new key needs: `limits.max_connections_per_ip` (other than 1024) 14,
  `limits.max_runtime_accounts` 15, `[metrics]` 16, `[update]` 17, `devices.iommu` 18, `devices.virtio_net_queues =
  "single"` 19, `observability.log_tls*` 20, `storage.disk_key_source = "console"` 22, the IPv6 keys and IPv6 allow-list
  entries 23. Packed into an older template it is refused ("needs configuration format N ... use a newer release").
  The v0.6.0 template declares format 23; the builder page picks the newest release that reads what the form asks for.
- **Behaviour changes with an unchanged configuration:**
  - **at most 1024 established TLS connections per source address**: devices behind one NAT share an address; a site
    with more must set `limits.max_connections_per_ip` higher (or 0) before the update;
  - **a new install has two boot slots** (10 to 20 MiB more on the disk); **an existing installed disk stays
    single-slot** and keeps updating with `urmqtt-disk update-boot`; A/B needs a disk installed, or re-installed, by
    v0.6.0 or later;
  - a NIC that offers multiqueue with RSS gets one queue pair per data core (`"single"` restores one);
  - per-connection TCP state is 128 bytes instead of 112;
  - IPv6, metrics, the outbound connection, the IOMMU, run-time accounts and the console passphrase are all off until
    configured.
- **Rollback to v0.5.0:** pack the same configuration (format 13 or lower) into the v0.5.0 template and give it a data
  disk it can read: the backup taken before the update, or a new disk. A v0.5.x kernel boots a two-slot disk but never
  counts or confirms (do not activate a slot with it), refuses a disk with console key slots, and refuses a
  configuration of format 14 or newer.

| Template of | Its kernel reads | What the builder page and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; everything newer is refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest through `urmqtt-config pack` only |
| v0.4.0, v0.4.1 | formats 1 to 6 | as v0.3.0, and `console.virtio_gpu` and the `[devices]` keys |
| v0.4.2 | formats 1 to 7 | as v0.4.1, and `network.mtu`; formats 8 to 23 are refused ("use a newer release") |
| v0.5.0 | formats 1 to 9 and 11 to 13 | as v0.4.2, and `[websocket]`, `[mqtt5]`, back-pressure, the receive interrupt and the shared-group limits; formats 14 to 23 are refused |
| v0.6.0 | formats 1 to 9, 11 to 20, 22 and 23 | everything the page offers, including IPv6, `[metrics]`, `[update]`, the IOMMU, multiqueue, log shipping, the console disk key and the per-address and account limits |

**Read this before relying on it**

- Alpha: fit for trials and pilots whose operator reads docs/KNOWN-ISSUES.md, not for unattended production.
- **Nothing of this release ran on a VPS, on KVM or on physical hardware**: QEMU (HVF, TCG) and local rigs only. The
  IOMMU has run on QEMU's models only; multiqueue without a KVM host with vhost; the x86_64 `accounts` smoke group
  needs KVM; the A/B power-cut points are tested under UEFI only. The x86_64 unit tests and the x86_64 and
  universal-ISO smoke suites are not in CI.
- Partial items: A/B does not convert a disk prepared before v0.6.0 and does not count a kernel that dies before its
  block driver runs; Secure Boot has no version counter, no shim/MOK, no signed `dbx` tooling for real firmware, and
  no release image is signed; TPM sealing and network unlock are not built, and a console passphrase keeps the broker
  down after every reboot until it is typed; IPv6 has no fragment reassembly, one global address, no DHCPv6, and UDP
  (SNTP, syslog, statsd) stays IPv4; the outbound connection is log shipping only (IPv4 literal, no client
  certificate); metrics are plain HTTP behind an allow-list; an edition cannot bring a non-virtio NIC or disk yet.
  docs/ROADMAP.md says exactly what is left of each.
- Not started: an export bridge (NEXT-8), DNS names (NEXT-10), clustering (LATER-1).
- Unchanged from v0.5.0: wills live in RAM, MQTT 5.0 without enhanced authentication, the AArch64 X25519 assembly has
  had no independent review, most kernel crates are cargo-vet exemptions, the audit package is a self-review, and the
  builder's new texts are AI translations, unreviewed. docs/KNOWN-ISSUES.md lists the rest.
- Support: only the latest release gets fixes; **v0.5.0 and older are no longer supported.**

**Performance.** This release has no new VPS measurement: the numbers of the v0.5.0 notes (docs/PERFORMANCE.md section
13, with the blog post `urmqtt-0-5-0-vs-mosquitto`) are v0.5.0's. The multiqueue and IPv6 changes were measured on the
local QEMU rig only (docs/PERFORMANCE.md section 14 for multiqueue: no throughput gain is claimed; the in-guest
handshake rate with IPv6 was unchanged). A measurement of v0.6.0 on a KVM host will follow.

**Verify** (in an empty directory):

    gh release download v0.6.0 --repo zeljan-alduk/urMQTT
    curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.6.0/minisign.pub
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    cmp urmqtt-v0.6.0.iso urmqtt-template-v0.6.0-universal.iso
    gh attestation verify urmqtt-v0.6.0.elf --repo zeljan-alduk/urMQTT
    gh attestation verify urmqtt-v0.6.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom

`minisign` must report the key `721316B961DCB94B` (`RWRLudxhuRYTcpqyk9TNXAj1qzClrFEvzXTyFMBK6NEuyvk6tVUxjUlH`)
and the trusted comment `urMQTT v0.6.0 release <the tag's commit>`. The SBOM is `urmqtt-v0.6.0.cdx.json`
(CycloneDX), attested with the ISO. With a clone of the repository, `urmqtt-config check-release --keyring
keys/release-keys.json --tag v0.6.0 --sums SHA256SUMS urmqtt-*` applies the same key ring as the builder page, and
`make dist ENV=release` at the tag gives the same line for `urmqtt-v0.6.0.elf` as the published `SHA256SUMS` with the
runner's toolchain (Ubuntu 24.04, clang 18.1.3).
Full changelog: CHANGELOG.md.
