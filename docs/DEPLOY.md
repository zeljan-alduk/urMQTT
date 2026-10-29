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
| `ca.pem` | the CA that signs device certificates |
| `server.pem` | broker certificate chain (leaf first) |
| `server.key` | unencrypted PEM private key (the VM cannot prompt for a passphrase) |
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

The trusted comment records version, environment and commit. Published dev
releases carry SLSA build provenance (`gh attestation verify <file> -R
zeljan-alduk/urMQTT`), and a minisign signature when the repository secret
`MINISIGN_SECRET_KEY` holds a passwordless key (`minisign -G -W`).

## 4. Virtual hardware

| Device | Requirement |
|---|---|
| CPU | aarch64 (ARMv8.0+; PAC/BTI used when present), 2+ vCPUs (with storage the last CPU is the DB core) |
| Firmware | UEFI (AAVMF/OVMF for aarch64), ACPI or device tree |
| Interrupts | GICv3; MSI-X through GICv2m frames when present (QEMU `virt`), polling otherwise |
| NIC | one virtio-net (PCI); DHCP unless `network.mode = "static"` |
| Data disk | one virtio-blk disk (PCI), blank on first boot, ≥ 64 MiB; with `storage.require_data_disk = true` the broker refuses to serve without it |
| Entropy | virtio-rng, or `RNDR` on the CPU; the kernel will not boot without entropy |
| Boot medium | the ISO (virtio-scsi CD) or the raw image (virtio-blk) |

The kernel uses the first virtio-blk disk that is not partitioned as its data
disk (blank: formatted; urMQTT: opened; anything else: refused). A partitioned disk (MBR or GPT, such as the raw boot image) is never touched:
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

## 6. Hetzner Cloud CAX (Ampere Altra)

Hetzner Cloud does not import custom images directly, and custom ISOs are
mounted only through a support request. The practical path is the raw image,
written onto the server's disk from the rescue system:

```bash
# 1. Create a CAX server (any image), enable the rescue system, reboot into it.
# 2. From your machine:
scp build/dist/urmqtt-prod-<version>.img root@<server-ip>:/tmp/
# 3. In the rescue system:
lsblk                                   # the server disk, usually /dev/sda
dd if=/tmp/urmqtt-prod-<version>.img of=/dev/sda bs=1M conv=fsync
# 4. Leave rescue mode and reboot. Optionally snapshot the server to clone it.
```

**Check before relying on it:** urMQTT drives only virtio-**blk** disks. Several
clouds, Hetzner among them, attach the boot disk and volumes through
virtio-**scsi**. Look in the rescue system: `ls /sys/bus/virtio/drivers/` shows
`virtio_blk` or `virtio_scsi`, and `lsblk` names virtio-blk disks `vd*`.

- If the server disk is virtio-scsi, UEFI still boots the image (the firmware has
  the driver), but the kernel finds no data disk.
- With `storage.require_data_disk = true` it then refuses to serve and says so
  on the console (Hetzner's web console shows it).
- `require_data_disk = false` is accepted only in dev builds. A memory-only
  production mode, or a virtio-scsi driver, is future work.

Until then, a KVM/Proxmox host (section 5) is the supported production target.
Networking on Hetzner (DHCP, a public IPv4 address) needs nothing special. Open
TCP 8883 in the Hetzner firewall.

## 7. Operating

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
- **Revoking a device:** add its serial to the revocation list, rebuild, deploy.
  Resumed sessions are checked too, so the device is refused as soon as the new
  image runs.
- **Rotating the server key or CA:** a new image. Old session tickets become
  invalid with the new key.
- **Backups:** the data disk holds SQLite (registry, retained messages,
  sessions) and the telemetry log. Snapshot it while the VM is stopped, or rely
  on the export path of your backend service.
