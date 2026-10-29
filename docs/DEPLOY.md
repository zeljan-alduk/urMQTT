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
| CPU | aarch64 (ARMv8.0+; PAC/BTI used when present), 2+ vCPUs (with storage the last CPU is the DB core) |
| Firmware | UEFI (AAVMF/OVMF for aarch64), ACPI or device tree |
| Interrupts | GICv3, or GICv2 (at most 8 vCPUs; what KVM offers on a GIC-400 host such as the Raspberry Pi); MSI-X through GICv2m frames when present (QEMU `virt`), polling otherwise |
| NIC | one virtio-net (PCI); DHCP unless `network.mode = "static"` |
| Data disk | one virtio-blk disk or virtio-scsi LUN (PCI), 512-byte blocks, blank on first boot, ≥ 64 MiB; with `storage.require_data_disk = true` the broker refuses to serve without it |
| Entropy | virtio-rng, or `RNDR` on the CPU; otherwise health-tested CPU jitter (`entropy.fallback`), else no boot |
| Boot medium | the ISO (virtio-scsi CD) or the raw image (virtio-blk or virtio-scsi disk) |

The kernel uses the first disk (virtio-blk, or a virtio-scsi LUN) that is not
partitioned as its data disk (blank: formatted; urMQTT: opened; anything else: refused). A partitioned disk (MBR or GPT, such as the raw boot image) is never touched:
the `raw-disk` smoke scenario boots that way and checks that the boot disk is
byte-identical afterwards.

Only TCP 8883 is served. Allow it inbound. Allow UDP from the VM to your syslog
and statsd collectors (`observability.*`) if configured, plus DHCP. Nothing else
is needed.

## 5. Generic KVM / Proxmox (aarch64 host)

**libvirt / virt-install** (the raw image as the boot disk, a separate data disk):

```bash
sudo cp build/dist/urmqtt-prod-*.img /var/lib/libvirt/images/urmqtt-boot.img
sudo qemu-img create -f raw /var/lib/libvirt/images/urmqtt-data.img 8G
virt-install --name urmqtt --arch aarch64 --machine virt --boot uefi \
  --cpu host-passthrough --vcpus 4 --memory 2048 \
  --disk path=/var/lib/libvirt/images/urmqtt-boot.img,bus=virtio,format=raw \
  --disk path=/var/lib/libvirt/images/urmqtt-data.img,bus=virtio,format=raw,cache=none \
  --network network=default,model=virtio \
  --rng /dev/urandom --graphics none --console pty,target_type=serial \
  --noautoconsole
virsh console urmqtt          # the serial log: boot report, DHCP lease, listener
```

**Proxmox VE on aarch64** (Proxmox on ARM is a community port; the steps match
upstream Proxmox):

1. Create a VM: BIOS `OVMF (UEFI)`, machine `virt`, no EFI disk needed, SCSI
   controller left at its default, CPU type `host`, 2+ cores.
2. Import the raw image as the boot disk:
   `qm importdisk <vmid> urmqtt-prod-<version>.img <storage>`, then attach it as
   `virtio0` and make it first in the boot order.
3. Add a second disk as `virtio1` (blank, ≥ 64 MiB, `cache=none`), a `virtio`
   network device and a VirtIO RNG (`/dev/urandom`).
4. Add a serial port (`serial0: socket`) to read the log with `qm terminal <vmid>`.

To use the ISO instead, attach it as a CD-ROM and boot from it, with the data
disk on virtio-blk as above.

Update by replacing the boot disk (or ISO) with a new image and rebooting. The
data disk carries over: SQLite migrations are append-only, and the telemetry log
format is versioned.

## 6. Hetzner Cloud CAX and Oracle Cloud A1 (Ampere Altra)

Both are aarch64 KVM clouds that attach disks through virtio-scsi; urMQTT drives
virtio-scsi disks as well as virtio-blk (the `scsi-disks` smoke scenario boots
the raw image from SCSI LUN 0 and uses LUN 1 as the data disk). Neither has been
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
Write the raw image onto the server's disk from the rescue system, and attach a
Volume as the data disk:

```bash
# 1. Create a CAX server, attach a (blank) Volume, enable the rescue system, reboot into it.
scp build/dist/urmqtt-prod-<version>.img root@<server-ip>:/tmp/
# 2. In the rescue system (the server disk is usually /dev/sda; check with lsblk):
dd if=/tmp/urmqtt-prod-<version>.img of=/dev/sda bs=1M conv=fsync
# 3. Leave rescue mode and reboot. The web console shows the serial log.
```

Do not format the Volume: urMQTT formats a blank disk itself and never touches
the partitioned boot disk. Open TCP 8883 in the Hetzner firewall.

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

Then launch an A1.Flex instance from the image, attach a blank paravirtualized
block volume as the data disk, and allow TCP 8883 in the subnet's security list.
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
sudo scripts/kvm-host/install.sh urmqtt-prod-<version>.img     # --data-size 8G --cpus 4 --mem 2G
journalctl -u urmqtt -f          # the serial log: boot report, DHCP lease, listener
```

`install.sh` installs QEMU and the UEFI firmware (`qemu-system-arm`,
`qemu-efi-aarch64`), copies the image to `/var/lib/urmqtt/boot.img`, creates a
blank sparse data disk once (`data.img`, never overwritten), writes
`/etc/urmqtt/vm.conf` and enables `urmqtt.service`. The service runs
`scripts/kvm-host/urmqtt-vm.sh`: `virt,gic-version=host` with KVM, virtio-rng,
virtio-blk boot and data disks, virtio-net. `urmqtt-vm.sh --dry-run` prints the
QEMU command line. The same script works on any aarch64 Linux KVM host, with a
GICv2 or a GICv3.

**Network.** The default (`--net user`) forwards host port 8883 to the VM, so
clients connect to the Pi's address; forward TCP 8883 on your router to reach
it from outside. Every client then appears to come from one address (QEMU's
NAT), so `limits.max_handshakes_in_flight_per_ip` applies to all of them
together. With a Linux bridge on the Pi's Ethernet (`nmcli con add type bridge
ifname br0` and the Ethernet connection as its port), `--net bridge:br0` puts
the VM on the LAN with its own DHCP address and real client addresses.

**Updating:** run `install.sh` again with the new image. It replaces the boot
image, keeps the data disk and restarts the service.

## 8. Operating

- **Logs:** the serial console, plus RFC 5424 syslog over UDP to
  `observability.syslog_udp`. Watch for `admission:`, `watchdog:`, `health:`
  and `db:` lines.
- **Metrics:** statsd to `observability.metrics_udp` every 10 s
  (`urmqtt.connections`, `urmqtt.heap.*`, `urmqtt.refused.*`, `urmqtt.health`,
  …; see ADR-035).
- **Failure handling:** a stuck core or a fatal error resets the VM (PSCI
  `SYSTEM_RESET`); it comes back by itself, devices reconnect, and admission
  control absorbs the storm. Configure the hypervisor to reboot rather than stop
  the VM on reset.
- **Revoking a device at runtime (H1):** send a signed control message with
  `urmqtt-control revoke` from a control identity (`control.service_ids`).
  - The device's live connections are closed at once, and it is refused at
    every later handshake or resumption.
  - The change is stored on the data disk and survives reboots.
  - For a revocation that must survive even a lost data disk, also add the
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
- **Backups:** the data disk holds SQLite (registry, retained messages,
  sessions) and the telemetry log. Snapshot it while the VM is stopped, or rely
  on the export path of your backend service.
