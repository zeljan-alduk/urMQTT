# Deployment

An urMQTT image is a complete appliance: kernel, configuration, CA, server
certificate and key, all compiled in. Deploying means building an image from
your own `deploy/prod/`, checking it, and booting it on an aarch64 VM with UEFI
and virtio devices. There is nothing to configure after boot, and no way to
log in.

## 1. Inputs

`deploy/prod/` holds the committed `config.toml` template. Add your secrets
next to it. They are ignored by git (`.gitignore`) and must never be committed:

| File | Content |
|---|---|
| `config.toml` | committed; review every key (README, "Configuration") |
| `ca.pem` (and more) | the operational CAs named by `trust.operational`; bootstrap CAs by `trust.bootstrap` ([PROVISIONING.md](PROVISIONING.md)) |
| `server.pem` | broker certificate chain (leaf first); the build fails if it expires within `tls.min_server_cert_days` |
| `server.key` | unencrypted PEM private key (the VM cannot prompt for a passphrase) |
| `control.pub` | the Ed25519 public key of the offline control signing key (`openssl pkey -pubout`); required even if `control.service_ids` is empty |
| revocation list | optional: a file of hex serials named by `tls.revocation_list` |

Sizing: `memory.kernel_heap_mb` (1024 in the template) must fit the VM's RAM
together with `storage.sqlite_heap_mb` and about 64 MiB for the kernel, its
tables and frame buffers. An idle device connection costs about 500 bytes of
heap (ADR-034), so 1 GiB holds well over a million. The VM refuses to boot
with a clear message if the heap does not fit.

## 2. Build

```bash
make dist ENV=prod     # build/dist/: urmqtt-prod-<version>.{elf,iso,img} + SHA256SUMS
```

- `.iso`: UEFI-bootable ISO 9660 (El Torito EFI image), for hosts that attach ISOs.
- `.img`: raw GPT disk with one EFI system partition, for hosts that boot disks.
  Write it to the VM's boot disk.
- `.elf`: the kernel itself (for debugging, and for comparing builds).

Production images contain no plaintext listener, no self-tests and no TLS
client (`selftest` feature off; the prod ELF is about 180 KiB smaller than dev).
Dev-only command-line switches are ignored.

**The image embeds the server's private key.** Store it, copy it and delete it
like the key itself.

## 3. Verify: reproducible and signed

Every input of the build is pinned: toolchain (`rust-toolchain.toml`), crates
(`Cargo.lock`, `--locked`), Limine and SQLite (vendored, checksums verified at
build time), timestamps (`SOURCE_DATE_EPOCH` = commit time) and FAT/GPT
identifiers (derived from content). Paths of the toolchain, the crate cache and
the checkout are remapped (`--remap-path-prefix`), so the image does not depend
on where it was built.

```bash
make repro             # builds HEAD twice in fresh worktrees at different paths
# repro: prod image of 1f3c…, built twice
#   ✓ kernel ELF identical: …
#   ✓ ISO identical: …
#   ✓ raw disk image identical: …
```

CI runs the same check on every push, with throwaway certificates as the prod
inputs. The same commit, inputs and toolchain give a bit-identical kernel ELF on
any host. The ISO and the raw image are also identical when xorriso and mtools
are the same versions (they lay out the image; Homebrew and Ubuntu versions
differ), so compare images built on the same platform, for example both in CI's
Ubuntu 24.04. A
second person with the same `deploy/prod/` can rebuild and compare
`SHA256SUMS` before anything is deployed.

Signing uses [minisign](https://jedisct1.github.io/minisign/):

```bash
minisign -G                           # once: ~/.minisign/minisign.key + minisign.pub
make sign                             # signs build/dist/SHA256SUMS (MINISIGN_KEY=... for another key)
# on the receiving side:
minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
```

The trusted comment records environment, version and commit. The project's
release key is [`minisign.pub`](../minisign.pub) in the repository root
(`RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`). It is a **test**
key for this pre-alpha: its secret half sits passwordless in the CI secret
`MINISIGN_SECRET_KEY` and on the maintainer's machine. Replace it with an
offline, password-protected key before any real release. Published dev
releases carry SLSA build provenance (`gh attestation verify <file> -R
zeljan-alduk/urMQTT`), and a minisign signature when the repository secret
`MINISIGN_SECRET_KEY` holds a passwordless key (`minisign -G -W`).

## 4. Virtual hardware

| Device | Requirement |
|---|---|
| CPU | aarch64 (ARMv8.0+; PAC/BTI used when present) or x86_64 (x86-64-v2: SSE4.2, POPCNT, CX16; section 5b), 2+ vCPUs (with storage the last CPU is the DB core) |
| Firmware | UEFI (AAVMF/OVMF), ACPI or device tree; x86_64 also legacy BIOS (ACPI required) |
| Interrupts | GICv3, or GICv2 (at most 8 vCPUs; what KVM offers on a GIC-400 host such as the Raspberry Pi); MSI-X through GICv2m frames when present (QEMU `virt`), polling otherwise |
| NIC | one virtio-net (PCI); DHCP unless `network.mode = "static"` |
| Disk | **one** virtio-blk disk or virtio-scsi LUN (PCI), 512-byte blocks: the raw image written to it, the disk at least 16 MiB larger than the image (8 GiB or more in production, STORAGE-PLAN sizing); with `storage.require_data_disk = true` the broker refuses to serve without its data partition |
| Entropy | virtio-rng, or `RNDR` on the CPU; otherwise health-tested CPU jitter (`entropy.fallback`), else no boot |
| Boot medium | the raw image on the VM's disk, or the ISO's installer, which writes that image onto the disk (below); booted as a CD the ISO's **live** entry runs from RAM, no disk needed and nothing kept (below), if `storage.mode` allows it; without the live word a CD holds no data and production refuses to serve from it |

**Single-disk model (S1, STORAGE-PLAN §2a).** The disk the VM boots from is
the only one urMQTT writes:
- It finds that disk by the GPT disk GUID the bootloader reports.
- On the first boot it:
  - moves the backup GPT to the end of the larger disk;
  - gives the disk its own GUID (every copy of an image starts with the same one);
  - creates the urMQTT data partition (type `58D3F720-BDF5-4DB7-99EC-DE26C8B8850F`) over the free space and formats it.

  Every step survives a power cut.
- Later boots open the partition again. A damaged data partition is refused
  and left exactly as it is, never formatted again.
- Any other attached disk is only read once (its GPT GUID compared) and never
  written (smoke `first-boot`, `scsi-boot`). Do not attach a separate data
  disk: it would not be used.

Inspect a stopped VM's disk with `urmqtt-disk info|verify DISK`
(`tools/disk`); replace the kernel and keep the data with
`urmqtt-disk update-boot DISK --esp ESP --write`.

### Live mode: the ISO's first entry, from RAM (O3, ADR-061, ADR-062)

The ISO's first menu entry, **urMQTT**, runs the broker with **no disk at
all**: the kernel keeps its data in a block device made of RAM, with the same
data layout, SQLite and telemetry log as on a disk. It is for trying the
broker, for diskless appliances and for machines that have nothing to
install on. **Nothing survives a reboot or a power loss**: retained messages,
persistent sessions and their queues, the telemetry log, device history and
revocations applied at run time. The console says so in a framed banner and
the log has `EPHEMERAL: data is lost on reboot`; the statsd gauge
`urmqtt.storage.ephemeral` is 1. Install to a disk for persistence.

Configuration (`deploy/<env>/config.toml`, `[storage]`):

| Key | Values | Meaning |
|---|---|---|
| `mode` | `"disk"` \| `"auto"` \| `"ram"` | required outside dev. `"disk"`: data on the disk; the live entry is refused (a halted screen that says why). `"auto"`: the disk, except the ISO's live entry, which runs from RAM. `"ram"`: always RAM, even when booted from a disk |
| `ram_percent` | 2 to 50, default 10 | share of RAM for the store; the result must be at least 16 MiB |
| `diagnostic` | `true` \| `false`, default `false` | allows the ISO's third entry, *Diagnostic: hardware detection and benchmarks* (ADR-063): CPU, RAM, PCI, disk and NIC detection, RAM, crypto and disk measurements on screen and as one JSON line on the serial port. Reads only, except a write test in unallocated space (after typing `WIPE` on a blank disk). With `false` the entry stops with the reason |

The committed production template says `mode = "disk"`: the live entry is
off until you write `auto`. A production image is never ephemeral by default
and never falls back to RAM when a disk is missing (that stays a fatal
"no data partition"). Booting a disk image or the installed disk behaves as
before; the install entry is unchanged.

Memory: the store is `ram_percent` of the machine's RAM (10 % of 4 GiB is 409
MiB). It is subtracted from the connection budget: the kernel heap (about 500
B per idle connection, `memory.kernel_heap_mb`) keeps its configured size when
heap, store, the SQLite heap and 128 MiB of kernel overhead fit, and
otherwise shrinks to the largest power of two that does. The boot log gives
both figures (`live: RAM store ...`, `live: kernel heap ...` with the
connection count). A VPS with 1 GiB and `ram_percent = 10` runs a 512 MiB heap
(about a million connections) next to a 102 MiB store.

If the control channel is on, revocations applied through it and its replay
protection are lost at a reboot: only the revocation list baked into the image
is applied again. Keep that in mind before using live mode for production.

### Installing from the ISO (S1b)

Wherever writing a raw image is awkward (a hypervisor UI that only mounts
ISOs, a bare-metal machine with a USB stick), the ISO installs itself:

1. Give the machine one empty (or expendable) disk and the ISO as a CD (or a
   USB stick written with `dd`).
2. Boot it. The menu shows **urMQTT** (the default, after 10 s: the live
   entry, from RAM without a disk, see below) and **Install urMQTT on this
   machine's disk**. Choose the second.
3. The console names the target disk and its size, warns that its data will
   be erased, and counts down 30 seconds. Power off now to cancel.
4. The image is written, read back and verified. Then the machine powers off
   with "remove the installation medium".
5. Remove the CD or stick and boot from the disk. The first boot creates the
   data partition.

The installer writes only when exactly one disk qualifies (writable, not the
installation medium, at least the image plus 17 MiB). With several it lists
them, writes nothing and powers off: detach the others and run it again.
Installing over an existing urMQTT disk erases its data. To update the
kernel and keep the data, use `urmqtt-disk update-boot` or
`scripts/kvm-host/install.sh` instead.

Only TCP 8883 is served. Allow it inbound. Allow UDP from the VM to your syslog
and statsd collectors (`observability.*`) if configured, plus DHCP. Nothing else
is needed.

## 5. Generic KVM / Proxmox (aarch64 host)

**libvirt / virt-install** (the raw image on the VM's only disk, grown to its
final size; the first boot creates the data partition):

```bash
sudo cp build/dist/urmqtt-prod-*.img /var/lib/libvirt/images/urmqtt.img
sudo truncate -s 8G /var/lib/libvirt/images/urmqtt.img
virt-install --name urmqtt --arch aarch64 --machine virt --boot uefi \
  --cpu host-passthrough --vcpus 4 --memory 2048 \
  --disk path=/var/lib/libvirt/images/urmqtt.img,bus=virtio,format=raw,cache=none \
  --network network=default,model=virtio \
  --rng /dev/urandom --graphics none --console pty,target_type=serial \
  --noautoconsole
virsh console urmqtt          # the serial log: boot report, DHCP lease, listener
```

**Proxmox VE on aarch64** (Proxmox on ARM is a community port; the steps match
upstream Proxmox):

1. Create a VM: BIOS `OVMF (UEFI)`, machine `virt`, no EFI disk needed, SCSI
   controller left at its default, CPU type `host`, 2+ cores.
2. Import the raw image as the VM's disk:
   `qm importdisk <vmid> urmqtt-prod-<version>.img <storage>`. Attach it as
   `virtio0` (`cache=none`), grow it (`qm resize <vmid> virtio0 8G`) and make it
   first in the boot order.
3. Add a `virtio` network device and a VirtIO RNG (`/dev/urandom`). No second
   disk: the data lives in a partition of `virtio0`.
4. Add a serial port (`serial0: socket`) to read the log with `qm terminal <vmid>`.

**Updating** replaces only the kernel and keeps the data partition. With the
VM stopped, run `urmqtt-disk update-boot <disk> --esp <the new image's ESP>
--write` on the disk image or volume, or copy MiB 1 to 9 of the new raw image
(its EFI system partition) over the same bytes of the disk:
`dd if=new.img of=<disk> bs=1M skip=1 seek=1 count=8 conv=notrunc`. The
ISO's self-installer (S1b) will do the same from a boot menu.

## 5b. x86_64 (a KVM VPS, Proxmox) and the universal ISO

> **Verified:** QEMU 11.1.2 under TCG (q35 with OVMF, pc with SeaBIOS) on an
> Apple M-series host, and the aarch64 side under HVF and TCG. **Not
> verified:** KVM, any real VPS provider, real hardware, Secure Boot. Treat a
> first boot on a provider as an experiment and read the console.

**One ISO for everything.** `make universal ENV=prod` (builds both kernels)
writes `build/urmqtt-prod-<version>-universal.iso` (about 48 MiB) and the
matching raw disk image `...-universal.img` (14 MiB). The ISO boots on
aarch64 UEFI, x86_64 UEFI and x86_64 legacy BIOS; its boot menu shows each
machine only its own entries. `make dist-universal` collects both kernels,
both images and `SHA256SUMS`; `scripts/repro.sh prod --universal` builds twice
and compares them byte for byte. `make iso` and `make raw` are unchanged and
aarch64-only. The raw image also boots by all three paths; the installed disk
is the same image, so a data disk written under one architecture is restored
by the other.

**VPS with a VNC console and a custom-ISO feature** (the case this was built
for; the provider-specific upload and CD-attach steps are the provider's):

1. Upload the universal ISO and boot the VPS from it. Both firmware types work.
2. The framebuffer shows Limine's menu, **urMQTT** (default after 10 s: the live
   entry, from RAM with nothing kept, when `storage.mode` is `"auto"` or `"ram"`;
   with `"disk"` it stops with the reason) and **Install urMQTT on this machine's
   disk**. Press the arrow key, choose the second to persist.
3. The console names the target disk, warns that its data will be erased and
   counts down 30 s (power the VPS off to cancel). It then writes, verifies and
   powers off with "remove the installation medium". The installer refuses
   when more than one disk qualifies.
4. Detach the ISO and boot from the disk, by BIOS or UEFI. The first boot
   creates the data partition.

**What to look at on the VNC console** (the same lines are on COM1; the log
is drawn on the framebuffer from the first line on):

- `URMQTT BOOT <version> arch=x86_64 cpu=<n> mem=<MiB>` and
  `cpu: vendor=... hypervisor=KVMKVMKVM ...`: the CPU is at least x86-64-v2.
- `time: tsc <Hz> from <source>`, `apic: x2APIC mode ...`, `acpi: ...`,
  `power: ACPI S5 through PM1a_CNT ...`.
- `pci: ECAM ...` or `pci: ports 0xcf8/0xcfc (mechanism #1)`, then the devices:
  `virtio-blk`, `virtio-net`, `virtio-rng`.
- `blk: boot disk is virtio-blk ...`, `msi-x: ...`, `net: mac ..., link up`,
  `entropy: ...`, `smp: n/n cpus online`, and finally `URMQTT READY` and the
  `TLS 1.3 listener` line.

**Messages for what is missing:**

| Console says | Meaning |
|---|---|
| `URMQTT: this CPU does not implement the x86-64-v2 baseline. Missing: ...` (white text on black, before anything else) | the VPS CPU model is too old (a `qemu64` or `kvm64` default); use `host` or `x86-64-v2-AES` |
| `unsupported legacy virtio device ... attach it as a modern device (disable-legacy=on)` | the hypervisor exposes pre-1.0 virtio only; there is no legacy driver |
| `net: network controller <vendor>:<device> (...) has no driver; urMQTT needs virtio-net` and `net: no virtio-net NIC. Attach one ...` | the NIC is an e1000, Realtek or similar; no driver yet (X14). A dev image idles, a production image stops |
| `fatal: no entropy source (virtio-rng, RDRAND/RDSEED, or a jitter fallback that passes its health tests): refusing to run` | no hardware randomness and the jitter fallback is off or failed its health tests |
| `storage: no data partition: booted from read-only media` | you booted the ISO as a CD without the live word: use the installer |
| `fatal: live mode (RAM, ephemeral) was requested by the boot menu, but this image's storage.mode is "disk"` | the image forbids live mode: set `storage.mode = "auto"` and rebuild, or use the installer |
| `EPHEMERAL: data is lost on reboot` | the live entry is running: the broker works, nothing is kept |

The virtual hardware is the one of section 4 (one virtio-blk or virtio-scsi
disk, one virtio-net, virtio-rng or a CPU with RDRAND/RDSEED) with an
x86-64-v2 CPU (`host` on KVM). Up to 64 CPUs. Without ACPI HPET and PM timer
and without a hypervisor timing leaf the boot stops (`no usable time base`).

**Power:** power-off and reset use ACPI (the FADT's PM1 control blocks with the
DSDT's `_S5` sleep type, and the reset register) and then QEMU's ports under a
hypervisor. On real hardware this path has never run.

## 5c. Load testing a server from one address: the bench profile (PERF, ADR-082)

The production limits protect the server from one slow or abusive source:
`max_handshakes_in_flight_per_ip = 32` (per data core), `max_handshakes_in_flight_per_core = 256`
and `handshakes_per_core_per_sec = 2000`. A load generator on a laptop is one source
address, so against the production defaults it measures the per-address limit
(about 32 handshakes in flight on each worker core), not the server. For that,
and only for that, there is a bench profile:

- **A VPS or any machine:** `deploy/bench/config.toml` is the production template
  with `[limits]` raised to 100000 handshakes/s, 4096 in flight per core and 4096
  per address, `storage.mode = "auto"` and a switch for `cpu.dispatcher_serves`.
  `scripts/mkbench.sh --certs deploy/prod --static 169.58.184.193/17 169.58.128.1`
  copies the certificates, writes `deploy/bench-local/config.toml` (the repository
  ignores that directory) and runs `make universal ENV=bench-local`. Without
  `--static` the address comes from DHCP; `--serve-dispatcher` sets
  `dispatcher_serves = true` (ADR-081, compare both). The image is named
  `urmqtt-bench-local-*-universal.iso`. Never serve devices from it. (Building from
  a worktree inside another checkout: set `RUSTFLAGS` by hand, cargo merges both
  `.cargo/config.toml` files.)
- **QEMU:** the dev word `limits=bench` on the kernel command line relaxes the same
  limits in a dev image only (a production image ignores it); the kernel logs
  `limits: BENCH LIMITS on` when it is on. `scripts/bench.sh --relaxed` uses it for
  the network part.

Drive it with `urmqtt-loadgen handshake --host VPS --port 8883 --certs deploy/bench-local
--threads 256 --duration 30` (add `--error-sleep-ms 1000` to look like devices with
a backoff). The report gives the rate over the window, the latency percentiles of the whole
connection, of the TCP connect and of TLS + CONNECT, and the errors by kind. The server
side is in the kernel log every 5 s (`handshakes:`, `tcp:` and `dataplane:` lines) and in
`$SYS/broker/handshakes/#` and `cpu/accepted/<core>` (docs/OPERATE.md).

## 6. Hetzner Cloud CAX and Oracle Cloud A1 (Ampere Altra)

Both are aarch64 KVM clouds that attach disks through virtio-scsi; urMQTT drives
virtio-scsi disks as well as virtio-blk (the `scsi-boot` smoke scenario boots
the raw image from a SCSI LUN, keeps its data there, and leaves a second LUN
untouched). Neither has been
tried on the real service from here. Check two things before relying on one,
from a Linux rescue system or any Linux VM of the same shape:

- **Entropy:** `cat /sys/devices/virtual/misc/hw_random/rng_available` lists
  `virtio_rng` if the cloud offers one. Ampere Altra has no `RNDR`. Without
  virtio-rng, urMQTT seeds from health-tested CPU jitter
  (`entropy.fallback = "jitter"`, ADR-038) and says so in a warning at boot.
  Set `fallback = "none"` to refuse to boot instead.
- **NIC:** `ls /sys/bus/virtio/drivers/virtio_net/` must show a device (the
  "paravirtualized" or virtio NIC, not a VFIO/SR-IOV one). If there is none,
  the serial console names the NIC that was found and stops.

### Hetzner Cloud CAX

Hetzner does not import custom images, and ISOs are mounted only on request.
Write the raw image onto the server's disk from the rescue system. The rest
of that disk becomes the data partition on the first boot:

```bash
# 1. Create a CAX server, enable the rescue system, reboot into it.
scp build/dist/urmqtt-prod-<version>.img root@<server-ip>:/tmp/
# 2. In the rescue system (the server disk is usually /dev/sda; check with lsblk):
dd if=/tmp/urmqtt-prod-<version>.img of=/dev/sda bs=1M conv=fsync
# 3. Leave rescue mode and reboot. The web console shows the serial log.
```

The server's own disk (40 GB and up) holds both the image and the data. A
Volume is not used. Open TCP 8883 in the Hetzner firewall.

### Oracle Cloud Always Free (VM.Standard.A1.Flex)

The free tier includes up to 4 Ampere cores and 24 GB of RAM. Import the image
as a custom image:

```bash
qemu-img convert -f raw -O qcow2 build/dist/urmqtt-prod-<version>.img urmqtt.qcow2
oci os object put --bucket-name <bucket> --file urmqtt.qcow2
oci compute image import from-object --compartment-id <ocid> --namespace <ns> \
  --bucket-name <bucket> --name urmqtt.qcow2 --display-name urmqtt \
  --launch-mode PARAVIRTUALIZED --source-image-type QCOW2 --operating-system Linux
# Add VM.Standard.A1.Flex to the image's compatible shapes (console: Edit details).
```

Then launch an A1.Flex instance from the image with a boot volume of the size
you want (the data partition fills it), and allow TCP 8883 in the subnet's
security list.
The serial console (`oci compute instance-console-connection`) shows the log.

## 7. Raspberry Pi 4/5 and other aarch64 Linux boards (KVM)

urMQTT has no drivers for the Pi's own hardware (Ethernet, SD card). It runs
on the Pi as a KVM guest under 64-bit Linux, which gives it the same virtio
devices as a cloud. The Pi's interrupt controller is a GIC-400 (GICv2), so
KVM can only give guests a GICv2; urMQTT supports it (ADR-039).

Requirements: Raspberry Pi 4 or 5 with 4 GB of RAM or more (the prod image
reserves a 1 GiB heap; the VM gets 2 GiB by default), 64-bit Raspberry Pi OS
or Ubuntu (`ls /dev/kvm` must show the device), wired Ethernet.

```bash
# On the Pi, in a checkout of this repository, with your prod image (make dist ENV=prod)
# and its SHA256SUMS(.minisig) copied over (scp); the image holds the server key:
minisign -Vm SHA256SUMS -p minisign.pub && sha256sum -c SHA256SUMS --ignore-missing
sudo scripts/kvm-host/install.sh urmqtt-prod-<version>.img     # --disk-size 8G --cpus 4 --mem 2G
journalctl -u urmqtt -f          # the serial log: boot report, DHCP lease, listener
```

`install.sh` installs QEMU and the UEFI firmware (`qemu-system-arm`,
`qemu-efi-aarch64`). It copies the image onto the VM's only disk,
`/var/lib/urmqtt/disk.img`, sparse at `--disk-size`, whose first boot creates
the data partition. It writes `/etc/urmqtt/vm.conf` and enables
`urmqtt.service`. The service runs `scripts/kvm-host/urmqtt-vm.sh`:
`virt,gic-version=host` with KVM, virtio-rng, one virtio-blk disk,
virtio-net. `urmqtt-vm.sh --dry-run` prints the
QEMU command line. The same script works on any aarch64 Linux KVM host, with a
GICv2 or a GICv3.

**Network.** The default (`--net user`) forwards host port 8883 to the VM, so
clients connect to the Pi's address; forward TCP 8883 on your router to reach
it from outside. Every client then appears to come from one address (QEMU's
NAT), so `limits.max_handshakes_in_flight_per_ip` applies to all of them
together. With a Linux bridge on the Pi's Ethernet (`nmcli con add type bridge
ifname br0` and the Ethernet connection as its port), `--net bridge:br0` puts
the VM on the LAN with its own DHCP address and real client addresses.

**Updating:** run `install.sh` again with the new image. It replaces only the
EFI system partition (the kernel) on the disk, keeps the data partition and
restarts the service.

## 8. Operating

- **Logs:** the serial console, plus RFC 5424 syslog over UDP to
  `observability.syslog_udp`. Watch for `admission:`, `watchdog:`, `health:`
  and `db:` lines.
- **Metrics:** statsd to `observability.metrics_udp` every 10 s
  (`urmqtt.connections`, `urmqtt.heap.*`, `urmqtt.refused.*`, `urmqtt.health`,
  `urmqtt.tls.resume_refused.*`, `urmqtt.tls.tickets_issued`, …; see ADR-035
  and docs/CRYPTO.md). After a restart every device does one full handshake
  (session-ticket keys are per boot); `resume_refused.unknown_key` counts them.
- **Failure handling:** a stuck core or a fatal error resets the VM (PSCI
  `SYSTEM_RESET`); it comes back by itself, devices reconnect, and admission
  control absorbs the storm. Configure the hypervisor to reboot rather than stop
  the VM on reset.
- **Revoking a device at runtime (H1):** send a signed control message with
  `urmqtt-control revoke` from a control identity (`control.service_ids`).
  - The device's live connections are closed at once, and it is refused at
    every later handshake or resumption.
  - The change is stored in the data partition and survives reboots.
  - For a revocation that must survive even a lost disk, also add the
    serial to the image's revocation list at the next build.
  - Watch `urmqtt.control.applied` and `urmqtt.control.rejected.*`.
- **Allowlist mode:** with `registry.mode = "allowlist"`, admit devices with
  `urmqtt-control allow --id …` and remove them with `disallow`
  ([PROVISIONING.md](PROVISIONING.md)).
- **Rotating a CA:** add the new CA to `trust.operational` next to the old one,
  deploy, re-issue devices, then remove the old CA and deploy again. Devices of
  a removed CA are refused, also on resumption.
- **Server certificate expiry:** `urmqtt.tls.server_cert_days` and warnings at
  60, 30, 7 and 1 days. The build refuses a certificate with less than
  `tls.min_server_cert_days` left.
- **Rotating the server key:** a new image. Old session tickets become invalid
  with the new key.
- **Backups:** the data partition holds SQLite (registry, retained messages,
  sessions, control state) and the telemetry log. With the VM stopped:
  - snapshot the whole disk;
  - or export with `urmqtt-disk export-db DISK out.sqlite` (the WAL applied; opens in any `sqlite3`);
  - or export with `urmqtt-disk export-telemetry DISK --format csv|jsonl`.
- **Seeding devices offline:** `urmqtt-disk import-devices DISK ids.txt
  [--allowlist] --write` adds device ids to the registry and, for allowlist
  mode, to the allowlist.

## 9. The data disk: layout v2, migrating a v1 disk, growing (S2, S3)

The data partition has a **layout version**. Images built from S2 on use
**layout v2** (1 MiB and optimal-I/O alignment, a telemetry partition count
chosen at format time, two superblock slots; byte-level spec in
[DISK-FORMAT.md](DISK-FORMAT.md)). A disk written by an earlier image has
layout v1. The kernel does **not** convert it at boot. It stops, before it
writes anything, with:

```
data disk is layout v1; this image needs v2: run urmqtt-disk migrate (docs/DEPLOY.md)
```

and the line `storage: refused reason=layout-v1` on the serial console. The
VM resets every 60 s until the disk is migrated or the old image is put back.
A new disk (a first boot) is formatted as v2 and needs nothing. Check a disk
with `urmqtt-disk info DISK`.

### Migrating a v1 disk

`urmqtt-disk migrate` runs **offline**, on the stopped VM's disk (an image file
or a block device), and does nothing without `--write`:

```
urmqtt-disk migrate DISK                  # the plan and the checks: old and new regions, bytes to copy,
                                          # free space needed, SQLite and telemetry verified; nothing written
urmqtt-disk migrate DISK --write [--rollback-file FILE] [--align-mib N]
urmqtt-disk migrate DISK --resume --write       # finish an interrupted run
urmqtt-disk migrate DISK --rollback --write     # back to v1 (after the switch also --force)
```

What it does and why it is safe:
- It refuses unless the disk is a valid v1 disk, `integrity_check` of the
  database passes on an in-memory copy, the telemetry opens, and the rollback
  journal is empty (if it is not, boot the old image once and power it off
  cleanly first). A non-empty WAL is fine: it is copied and replayed by the
  next boot.
- The database, WAL and journal (megabytes) are **copied** into new aligned
  regions made from the unused tail of the old database region. Nothing the
  old layout uses is overwritten before the new superblock is written, which
  is one 4 KiB write. A power cut at any write leaves a valid v1 disk or a
  valid v2 disk, never a corrupt one; `--resume` finishes, `--rollback` undoes.
- The **telemetry ring stays where it is**. It is not realigned (its writes
  are still whole 4 KiB blocks), so a migrated disk has an unaligned ring
  until the disk is reinstalled.
- A copy of the v1 superblock is kept on the disk (LBA 32) and in the
  rollback file next to the disk (`DISK.urmqtt-migrate-rollback` by default;
  an existing file is never overwritten). Keep it until the migrated disk
  has run well. After the switch, `--rollback --force` returns to the
  old files and **loses every change made since**.
- After the run the tool verifies the result from a read-only view: the v2
  layout opens, the database and WAL bytes are identical, `integrity_check`
  passes, every table has the same number of rows as before, and the
  telemetry has the same records (count and content digest).
- "not enough free space for the new regions" means the live database is
  almost as large as its region. Grow the volume first (below), then migrate.

Per platform:
- **A VM image file on the host** (QEMU, libvirt, Proxmox raw/qcow2 converted
  to raw): shut the VM down, `urmqtt-disk migrate disk.img`, review, then
  `--write`, then start it with the new image's ESP
  (`urmqtt-disk update-boot disk.img --esp esp.img --write`).
- **A cloud volume**: power the server off, attach its boot volume to a small
  Linux helper VM in the same region as an extra disk (do not mount it), run
  `urmqtt-disk migrate /dev/vdb` (the device name the helper shows; `info`
  first), detach the volume and reattach it to the original server. If the
  provider cannot move a boot volume, snapshot it, create a volume from the
  snapshot, migrate that one and attach it as the boot disk of a new server.
- **Bare metal**: boot a Linux live USB stick, copy the `urmqtt-disk`
  binary (built with `cargo build --release -p urmqtt-disk-tool`, or from the
  release), `urmqtt-disk migrate /dev/nvme0n1`, power off, remove the stick.
  On macOS use `/dev/rdiskN`.

### Growing the disk

When the disk is larger than the layout, urMQTT uses the new space. Nothing to
configure except how it is shared, and nothing is ever moved or shrunk:
- **At boot:** if the volume was enlarged, the first boot afterwards moves the
  backup partition table to the new end, extends the data partition to it, and
  grows the layout with one superblock write. The boot log says `gpt: data
  partition extended to the end of the … MiB disk` and `storage: grew the
  layout from … MiB to … MiB (generation N): database +… MiB, telemetry +… MiB`.
  A power cut anywhere leaves the old or the new size and the next boot
  finishes.
- **While running:** a virtio-blk disk tells the guest when it is resized
  (a configuration-change interrupt: QEMU/KVM, Proxmox, libvirt's
  `virsh blockresize`, most clouds that use virtio-blk). The server logs
  `storage: grew the layout online from … MiB to … MiB` about a second later
  and goes on serving; no reboot. A virtio-scsi disk is not notified (reboot
  to take it up), and the boot log's `blk: resize notification …` line says
  which case you have.
- **The split:** `storage.grow_ratio_db` (default 50) is the percentage of the
  new space that goes to the SQLite database; the rest goes to the telemetry
  ring. The WAL and journal keep their size.
- **Offline:** `urmqtt-disk grow DISK [--ratio N]` shows what would change;
  with `--write` it does the same as the boot (partition table, then layout).
- To enlarge the volume, use your platform's tool (`qemu-img resize` or
  `virsh blockresize` for libvirt, `qm resize <vmid> virtio0 +10G` for
  Proxmox, the volume or server-type resize in a cloud console; check the
  provider's documentation for what it allows). **Shrinking is never done by
  urMQTT**: a disk smaller than its layout is refused at boot.

### Disk safety, as before

Only the disk Limine booted from is written, and only inside its data
partition (and the partition table at the first boot and when growing). The
offline tool writes only with `--write`. `scripts/fault-loop.sh migrate|grow`
runs the procedures on an image with a power cut after every write and checks
that each case ends in a valid disk that finishes.
