## urMQTT v0.4.2 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 over TLS 1.3 with mutual TLS.
This release covers everything since v0.4.1. It is the **first release signed with the project's release key**
(`721316B961DCB94B`) and the first whose assets hold **no throwaway certificates**. New: the MTU the network announces
is honoured (ADR-264, configuration format 7), and the CPU-jitter entropy fallback is an explicit, visible choice
(ADR-263).

**The release key (read this first)**

- `minisign.pub` at this tag is the release key `721316B961DCB94B`, generated on 2026-11-06. Fetch it **at the tag**
  (the commands below), not from an older checkout: at v0.4.1 and earlier `minisign.pub` is the former test key.
- The former test key `9229E05252D01F8E` is **retired and considered compromised** (its secret was a passwordless CI
  secret). It signed v0.1.0 to v0.4.1; those signatures stay valid, and the repository keeps the key as
  `keys/minisign-test-9229E05252D01F8E.pub`. A signature by it on any tag after v0.4.1 is a forgery: report it
  (SECURITY.md).
- The builder page, the release mirror and `urmqtt-config check-release --keyring keys/release-keys.json` accept the
  test key for v0.1.0 to v0.4.1 only, and for each of those six tags only the `SHA256SUMS` whose SHA-256 is pinned in
  `keys/release-keys.json`. The builder page marks those releases "signed with the project's former test key".

**What the assets are now**

The assets are the release kernel and images with an empty configuration (`urmqtt-v0.4.2.elf/.iso/.img`, the `.iso`
being the template); configure them with the builder page or `urmqtt-config pack --iso/--image`. There is no dev build
with throwaway keys any more: the `urmqtt-dev-<tag>.*` images of v0.4.1 and earlier are not published for v0.4.2.
Where you used one to try urMQTT, build your image on the builder page
(https://aldo.tech/en/products/urmqtt-builder/, in your browser, keys never leave it) or with `urmqtt-config pack`
from the template and your own certificates (`scripts/pki.sh`, docs/PKI.md; docs/FIRST-HOUR.md walks through it).

| File | What |
|---|---|
| `urmqtt-v0.4.2.elf` | the release kernel for aarch64 (no certificate or key in it; reproducible from the tag with `make dist ENV=release`) |
| `urmqtt-v0.4.2.iso` | the universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) with the empty configuration: byte for byte the template |
| `urmqtt-v0.4.2.img` | its raw disk image; `urmqtt-config pack --image` configures it |
| `urmqtt-template-v0.4.2-universal.iso` | the same ISO under the template name the builder page and the mirror use |
| `urmqtt-v0.4.2.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | the checksums and their signature with the release key; trusted comment `urMQTT v0.4.2 release <commit>` |

**New**

- **The network's MTU is honoured** (ROADMAP NOW-19, ADR-264). Every packet was sized for 1500 bytes, so on a smaller
  network (Google Cloud's VPC: 1460) full-sized TCP segments were lost without an error. The DHCP client reads option
  26 (576 to 9000 is used, another value ignored with a warning), and the new optional key **`network.mtu`** (0, the
  default: from DHCP, else 1500; or 576 to 9000; with a static address the only source) sets it. The MSS follows the
  MTU, open connections follow a lower MTU at a DHCP renewal, statsd datagrams stay within it, frames above 1500 bytes
  are never sent. Boot line `net: mtu 1460 (static|dhcp|default)`, `$SYS/broker/net/mtu`; the builder's advanced view
  has the key.
- **The weak entropy path is an explicit option** (NOW-4, ADR-263). The default stays `entropy.fallback = "jitter"`
  (a host with no virtio-rng and no `RNDR`/`RDRAND`, such as the netcup ARM VPS, still boots); the builder's basic
  view has a "Random numbers" choice with a warning, `urmqtt-config pack`, `verify` and `show` print a `WARNING` while
  the fallback is allowed, and `$SYS/broker/entropy/source` says what seeded the generator. `"none"` makes the image
  refuse to boot without a hardware source.
- **A production PKI**: `scripts/pki.sh` and docs/PKI.md (an offline CA, server, device and service certificates,
  rotation, revocation, the control key; `pki.sh check` runs `urmqtt-config pack`'s checks).
- **For the community**: docs/FIRST-HOUR.md (from nothing to a first message over mutual TLS), docs/KNOWN-ISSUES.md,
  docs/EDITIONS.md (the open edition is everything that runs on virtio devices), issue forms, and a DCO sign-off on
  pull requests.

**Compatibility.** The kernel reads configuration formats 1 to 7 and the template declares format 7. Only
`network.mtu` (not 0) needs format 7; any other configuration keeps its format, so what packed into the v0.4.0 or
v0.4.1 template packs into v0.4.2's unchanged, and repacking it into the v0.4.2 template is the update. The data-disk
layout is unchanged (v2.1), so going back to v0.4.1 or v0.4.0 is packing the same configuration (without
`network.mtu`) into that template. The cipher suites, key-exchange groups and signature schemes offered are unchanged.

| Template of | Its kernel reads | What the builder page and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; TLS off is refused (format 3); the virtio-gpu console, `[devices]` keys and `network.mtu` are refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest (format 4) through `urmqtt-config pack` only, the page does not offer it |
| v0.4.0 | formats 1 to 6 | as v0.3.0, and `console.virtio_gpu` and the `[devices]` keys; `network.mtu` is refused (format 7: "use a newer release") |
| v0.4.1 | formats 1 to 6 | as v0.4.0 |
| v0.4.2 | formats 1 to 7 | everything the page offers, including `network.mtu` |

The page picks the newest release that can do what the form asks, so it chooses v0.4.2 once the release mirror lists
it.

**Read this before relying on it**

- Pre-alpha. The three items of the ROADMAP's definition of "alpha" (a real release key, the entropy decision, the
  MTU) are in this release; the status word changes when the owner changes it, after this release has been verified
  with the new key on the builder page and the mirror.
- The release key's secret is passwordless because CI signs with it: its protection is GitHub's secret store and the
  owner's own copies (docs/release-key-rotation.md).
- The MTU change has run under QEMU only (QEMU's user network cannot announce an MTU; DHCP option 26 was tested with a
  raw test transport). **Nothing has run on Google Cloud yet**, the network it was made for.
- The virtio-console, -balloon, -input and -vsock drivers have run only under QEMU, never on a real machine; vsock
  only against the fake device of the tests.
- The real machines so far are one netcup ARM64 VPS and, for x86_64, a Contabo KVM VPS at the H7 commit; nothing of
  this release ran on either, and nothing has run on physical hardware. The x86_64 unit tests and the x86_64 and
  universal-ISO smoke suites are not in CI.
- The new builder texts (the entropy choice, the test-key note, the MTU range) are AI translations, unreviewed; so is
  most of the site.
- Unchanged from v0.4.1: the AArch64 X25519 assembly has had no independent review, PSTATE.DIT is never set, Secure
  Boot only partly done (release images are not signed), no IOMMU, encryption at rest not on the builder page, most
  kernel crates are cargo-vet exemptions, and the audit package is a self-review. docs/KNOWN-ISSUES.md lists the rest.
- Support: only the latest release gets fixes; **v0.4.1 and older are no longer supported.**

**Verify** (in an empty directory):

    gh release download v0.4.2 --repo zeljan-alduk/urMQTT
    curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.2/minisign.pub
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    gh attestation verify urmqtt-v0.4.2.elf --repo zeljan-alduk/urMQTT
    gh attestation verify urmqtt-v0.4.2.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom

`minisign` must report the key `721316B961DCB94B` (`RWRLudxhuRYTcpqyk9TNXAj1qzClrFEvzXTyFMBK6NEuyvk6tVUxjUlH`)
and the trusted comment `urMQTT v0.4.2 release <the tag's commit>`. Releases up to v0.4.1 were signed with the former
test key 9229E05252D01F8E (keys/minisign-test-9229E05252D01F8E.pub), which is no longer trusted for anything newer.
With a clone of the repository, `urmqtt-config check-release --keyring keys/release-keys.json --tag v0.4.2 --sums
SHA256SUMS urmqtt-*` applies the same key ring as the builder page. Full changelog: CHANGELOG.md.
