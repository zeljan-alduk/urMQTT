# Editions

Status: decided by the owner on 2026-11-05. This file says where the line between the two editions of urMQTT
runs, why it runs there, and what the owner promises about it. The parts that are not decided yet are listed in
[section 9](#9-not-decided-yet).

| | Open edition | Commercial edition |
|---|---|---|
| Repository | this one, `zeljan-alduk/urMQTT` | `urmqtt-enterprise` (private) |
| Name | urMQTT | urMQTT Enterprise |
| Licence | Apache-2.0 OR MIT | proprietary |
| Runs on | any hypervisor that gives the guest virtio devices | the same, plus machines whose devices are not virtio |

## 1. The line is "virtio"

The open edition contains everything that runs on virtio devices. The commercial edition adds drivers for
devices that are not virtio, and the services around them.

The line is drawn at the device interface, not at a hypervisor or a provider. KVM is not the line: a KVM guest
on a cloud that gives it an AWS ENA NIC and an NVMe disk cannot run the open edition, and a guest of bhyve or
Cloud Hypervisor that gives it virtio-net and virtio-blk can. A device type either is virtio or is not, which an
operator can check from the PCI vendor ID alone (`0x1AF4`), and the boot log and the Diagnostic report name
every PCI function they see, whichever edition the image is.

## 2. What is in the open edition

Everything in this repository, now and in future releases:

- **The protocol:** the MQTT codec and broker (today MQTT 3.1.1 with QoS 0 and 1; MQTT 5.0, QoS 2, MQTT over
  WebSocket and the other protocol features of [ROADMAP.md](ROADMAP.md) when they are built), the optional
  plaintext listener, the signed control channel, `$SYS`, syslog and statsd.
- **The network stack:** the own TCP/IP stack and DHCP client, IPv4 today and IPv6 when it is built.
- **Security:** TLS 1.3 with mutual TLS and its crypto, the entropy sources, the exploit mitigations, boot
  integrity and Secure Boot support (and, when they are built, IOMMU support and a disk key outside the image,
  LATER-5 and LATER-7 of [ROADMAP.md](ROADMAP.md)), the verification tooling (fuzz targets, Kani, Miri, sanitizers), the
  threat model, the audit package ([AUDIT.md](AUDIT.md)) and the vulnerability process.
- **Storage:** the raw-disk layout without a filesystem, SQLite in its isolated worker, the telemetry log,
  growth, discard, backup, scrubbing and encryption at rest ([DISK-FORMAT.md](DISK-FORMAT.md)).
- **The kernel and platform code** a virtio machine needs: aarch64 and x86_64, UEFI and legacy BIOS boot, the
  interrupt controllers, timers and firmware tables (DTB, ACPI), the PCIe ECAM, the UART and loader framebuffer
  consoles, multicore bring-up, the universal ISO and its installer.
- **The tools:** `urmqtt-config`, `urmqtt-disk`, `urmqtt-control`, `urmqtt-diag-png`, the load generator and
  attack tools, the builder page and its in-browser emulator, the Diagnostic boot entry.
- **The release process:** reproducible builds, signatures, SBOM, cargo-vet, the CI.
- **Every virtio driver,** present and future, in `crates/virtio` with the framework of ADR-257
  ([DECISIONS.md](DECISIONS.md), [DEVELOPING-DRIVERS.md](DEVELOPING-DRIVERS.md)).

The virtio drivers that exist today (vendor ID `0x1AF4`; the modern device ID is `0x1040` plus the virtio type,
see `crates/virtio/src/registry.rs`):

| Device | virtio type | Modern PCI ID | Transitional PCI ID | Driver state |
|---|---|---|---|---|
| virtio-net | 1 | `1AF4:1041` | `1AF4:1000` | always built |
| virtio-blk | 2 | `1AF4:1042` | `1AF4:1001` | always built |
| virtio-console | 3 | `1AF4:1043` | `1AF4:1003` | feature `console`, key `devices.virtio_console` |
| virtio-rng | 4 | `1AF4:1044` | `1AF4:1005` | always built |
| virtio-balloon | 5 | `1AF4:1045` | `1AF4:1002` | feature `balloon`, key `devices.virtio_balloon` |
| virtio-scsi | 8 | `1AF4:1048` | `1AF4:1004` | always built |
| virtio-gpu (2D console) | 16 | `1AF4:1050` | none | feature `gpu`, key `console.virtio_gpu` |
| virtio-input | 18 | `1AF4:1052` | none | feature `input`, key `devices.virtio_input` |
| virtio-vsock | 19 | `1AF4:1053` | none | feature `vsock`, key `devices.virtio_vsock` |

A driver for any other virtio type (virtio-iommu, virtio-mem, virtio-fs, a future type of the specification)
belongs to the open edition too. The kernel only drives modern (virtio 1.x) devices; a legacy-only device is
refused with a message (ADR-257, "States").

Hypervisors and providers that give a guest these devices over PCI include KVM/QEMU, Proxmox VE, Cloud
Hypervisor, bhyve, and VPS providers such as netcup, Contabo and Hetzner, and Google Cloud's instance types that
offer virtio-net and a virtio-scsi persistent disk (e2, n2 and others). Of these, only two machines have run a
release-candidate image and are recorded in this repository: a Contabo x86_64 KVM VPS and a netcup aarch64 KVM
VPS ([PERFORMANCE.md](PERFORMANCE.md), [PROGRESS.md](PROGRESS.md)). The others are expected to work because of
their devices; they are not tested, and [DEPLOY.md](DEPLOY.md) stays the list of what has been tried.
The kernel's virtio transport is PCI; a hypervisor that offers virtio only over MMIO and starts the guest without
UEFI or BIOS (Firecracker) is not supported today. That would be open-edition work (an MMIO transport and a direct
kernel boot), not commercial.

## 3. What the commercial edition adds

The commercial edition is this kernel plus drivers for devices that are not virtio, and the services around it:

| Platform | Devices (PCI vendor:device where it helps) |
|---|---|
| AWS, Nitro instances | Elastic Network Adapter (`1D0F:EC20`, `1D0F:EC21` and later), NVMe for EBS and instance storage (class `01:08:02`) |
| Google Cloud, newer instance types (including Arm) | gVNIC (`1AE0:0042`), NVMe persistent disk and local SSD |
| Azure | Hyper-V VMBus with NetVSC and StorVSC (not PCI), MANA (`1414:00BA`) |
| VMware | VMXNET3 (`15AD:07B0`), PVSCSI (`15AD:07C0`) |
| Bare metal | physical NICs and disk controllers (for example Intel e1000e/igb, NVMe, AHCI), USB boot, a hardware report, and the hardware compatibility list (X12 to X16 of [X86-PLAN.md](X86-PLAN.md)) |

It also includes support with a service-level agreement, and the service of adapting an existing service to a
unikernel that is already offered on aldo.tech. Google Cloud is the first commercial target.

These are the items LATER-2, LATER-3 and LATER-4 (the device drivers of it) of [ROADMAP.md](ROADMAP.md). The open
edition keeps naming such devices: a network controller without a driver is named at boot with its vendor
(`kernel/src/netproto.rs`), a production image without a virtio-net NIC stops with a message that says what to
attach, and the Diagnostic report lists every PCI function.

**Why the line is here.** Every device the open edition drives follows one public specification (OASIS virtio
1.x), is offered by many hypervisors, and can be tested in CI with QEMU's models. The cloud-native devices are one
provider's interface each, often without an emulator to test against, and they matter mostly to organisations
that run on that provider; bare metal needs a different driver for nearly every machine. That work is what the
commercial edition pays for. Drawing the line at a device interface keeps it checkable and keeps every protocol,
security and storage feature on the open side.

## 4. The promise

The owner, Željan Alduk, makes these commitments for the lifetime of the project:

1. **What is open stays open.** Code released under Apache-2.0 OR MIT in this repository stays under those
   licences, and nothing in it moves to the commercial edition.
2. **The line never moves backwards.** It may move so that more is open (a driver may be opened later); it never
   moves so that something on the open side becomes commercial-only. A new virtio driver, protocol feature,
   security feature or storage feature goes into the open edition.
3. **No crippling.** The open edition is not made weaker on purpose to sell the commercial one: no limits on
   connections, cores, memory or throughput, no withheld security fixes, no delayed releases. Infrastructure
   that protects users applies to both editions, for example the real release signing key (ROADMAP NOW-2).
4. **One security process.** A vulnerability is handled the same way in both editions, by the process of
   [VULNERABILITY-HANDLING.md](VULNERABILITY-HANDLING.md) and [SECURITY.md](../SECURITY.md). A fix to shared
   code lands in this repository and is released here, at the latest when the commercial edition gets it.
5. **A published audit summary.** For every release of the commercial edition, a summary of its audit state is
   published: the drivers it adds, the external inputs they parse, their fuzz targets and tests, and the open
   findings, in the form of [AUDIT.md](AUDIT.md) §2 and §5.

**Funded priority, open code.** A customer of the commercial edition may pay for the priority of a feature that belongs
to the open edition (for example QoS 2 or MQTT 5): the work is scheduled for that customer first, and the code lands in
this repository under its licence, like any other open feature (decided 2026-11-06). What is funded is the order, never
the exclusivity.

## 5. How the two relate technically

- **One kernel.** The commercial repository depends on tagged releases of this repository's crates (as git
  dependencies pinned to a tag; the crates are not published on crates.io) and builds its own kernel image with
  the extra drivers. It does not fork the broker, the stack, the crypto or the storage.
- **Drivers through the framework.** The extra drivers plug into the driver framework of ADR-257 the same way a
  virtio driver does: a device table row, a configuration key, a state in the boot log and the Diagnostic report,
  a refusal when a key names a driver the image lacks.
- **Today this needs a patched kernel crate,** because the framework's tables (`registry::KINDS`,
  `vdev::DRIVERS`) and the configuration tags are closed lists inside this repository. The planned fix is the
  roadmap item "kernel as a library" ([ROADMAP.md](ROADMAP.md), NOW-18): a driver registration API for
  out-of-tree drivers, generic PCI ID binding, and a reserved range of configuration tags, with the open
  kernel's behaviour unchanged and `make repro` identical. **It is not done.**
- **The same configuration format.** A configuration that the open edition accepts means the same in the
  commercial edition; keys for commercial drivers would use the reserved tag range, so they never collide with a
  future open key.
- **The same tests.** The commercial kernel runs this repository's test suites as well as its own.

## 6. Contributions

Contributions to this repository follow [CONTRIBUTING.md](../CONTRIBUTING.md), including the Developer
Certificate of Origin: every commit carries a `Signed-off-by:` line. Contributions are licensed Apache-2.0 OR MIT
like the rest of the project, and they stay open under the promise above.

A driver for a device that is not virtio, offered to this repository, is a case for the owner to decide.
Such contributions may be declined, because those drivers are the commercial edition's scope; the place for
that work is the commercial repository `urmqtt-enterprise`, which is private: ask the owner about it through
aldo.tech. A contribution that makes such drivers easier to build out of tree without changing the open
kernel's behaviour (the "kernel as a library" work) is welcome here.

## 7. Licensing facts

- **This repository:** Apache-2.0 OR MIT, at the user's option ([LICENSE-APACHE](../LICENSE-APACHE),
  [LICENSE-MIT](../LICENSE-MIT)).
- **The commercial repository:** proprietary. It uses this repository's crates under their Apache-2.0/MIT
  terms.
- **Vendored components** keep their own licences, as listed in [vendor/README.md](../vendor/README.md) and the
  README's licence section: Limine (BSD-2-Clause), SQLite (public domain), the patched RustCrypto crates
  (Apache-2.0 OR MIT), the `nistz256` assembly and table from ring/BoringSSL/OpenSSL (Apache-2.0). This is the
  same in both editions.
- **GPL code is never in the product.** wolfSSL (GPL) is built in CI only, to test TLS interoperability
  (`scripts/build-wolfssl.sh`, [CRYPTO.md](CRYPTO.md)). qemu-wasm (QEMU, GPL-2.0) runs only in the builder page's
  in-browser emulator (`tools/builder/emulator/`, ADR-228 in [DECISIONS.md](DECISIONS.md)). Neither is linked
  into a kernel image, in either edition.

## 8. Trademark

The name "urMQTT" belongs to the owner, Željan Alduk / ALDO TECH. The code licences do not grant rights to the
name. A fork is welcome under its own name; please do not ship a modified build as "urMQTT" or suggest that it is
an official edition. This is a note, not legal text.

## 9. Not decided yet

- Pricing.
- The terms of support and the service-level agreement, and how they relate to a support period for the open
  edition (ROADMAP D-15).
- The order of the commercial targets after Google Cloud.
- How the reserved configuration tag range and the registration API look in detail (NOW-18).
