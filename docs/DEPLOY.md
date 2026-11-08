# Deployment

An urMQTT image is a complete appliance: the kernel (one binary, the same for
everyone) and its configuration, which holds the limits, ACLs, network, CA,
server certificate and key. The configuration is a blob in a fixed-size slot of
the image (C1, ADR-215, ADR-216), packed by `urmqtt-config` from a TOML and the
PEM files it names. Deploying means producing an image with your configuration
(section 1b: from a release's template ISO without a toolchain, or section 2:
from a checkout), checking it, and booting it on a VM with UEFI (or BIOS on
x86_64) and virtio devices. There is nothing to configure after boot, and no way
to log in.

## 1. Inputs

`deploy/prod/` holds the committed `config.toml` template (keys you leave out
take the defaults). Add your secrets next to it. They are ignored by git (`.gitignore`) and must never be committed:

| File | Content |
|---|---|
| `config.toml` | committed; review every key (README, "Configuration") |
| `ca.pem` (and more) | the operational CAs named by `trust.operational`; bootstrap CAs by `trust.bootstrap` ([PROVISIONING.md](PROVISIONING.md)) |
| `server.pem` | broker certificate chain (leaf first); the build fails if it expires within `tls.min_server_cert_days` |
| `server.key` | unencrypted PEM private key (the VM cannot prompt for a passphrase) |
| `control.pub` | the Ed25519 public key of the offline control signing key (`openssl pkey -pubout`); required even if `control.service_ids` is empty |
| revocation list | optional: a file of hex serials named by `tls.revocation_list`; at most 1024 serials go into the image (the control channel revokes more at run time) |

Sizing: `memory.kernel_heap_mb` (1024 in the template) must fit the VM's RAM
together with `storage.sqlite_heap_mb` and about 64 MiB for the kernel, its
tables and frame buffers. An idle device connection costs about 500 bytes of
heap (ADR-034), so 1 GiB holds well over a million. Fixed costs come first:
about 1.4 MiB at boot, plus about 150 KiB for every P-256 trust anchor
(`trust.operational` and `trust.bootstrap`, at most 8 get a verification
table; ADR-261), plus `memory.min_free_mb`; a handshake in flight holds tens of
KiB until it completes. The boot logs the tables (`tls: N trust-anchor
verification table(s), K KiB of heap`) and then the heap in use. The VM
refuses to boot with a clear message if the heap does not fit.

## 1b. Configuring an image without building: the template ISO (C1)

Every release carries `urmqtt-template-<version>-universal.iso` (listed in
`SHA256SUMS` like the other files): the release kernels for aarch64 UEFI,
x86_64 UEFI and x86_64 BIOS, and the **empty configuration**. On its own it
boots on the documented defaults and stops with `refusing to serve: no server
certificate and key`; the installer and the diagnostic entry work without one.
`urmqtt-config` (built from this repository with `cargo build --release -p
urmqtt-config-tool`; the releases do not ship the binary yet) writes your
configuration into a copy of it. The **builder page** on aldo.tech does the same
in the browser, with the same code compiled to WebAssembly (README, "Configure and
download your ISO"); the command line is the way to do it offline and to check a
page's result byte for byte:

```bash
# my/config.toml names ca.pem, server.pem, server.key, control.pub next to it;
# keys left out take the defaults (urmqtt-config schema lists them all)
urmqtt-config pack my/config.toml --iso urmqtt-template-v0.5.0-universal.iso --out urmqtt-mine.iso
# configuration fingerprint: the same one the kernel prints at every boot
urmqtt-config show urmqtt-mine.iso
urmqtt-config verify urmqtt-mine.iso      # kernel's checks; all slot copies and module hashes agree
```

What `pack` does: reads the TOML (a top-level `env = "name"` or `--env`, default
`prod`; `dev` only for dev kernels), fills in the defaults, validates it with the
same rules as the build (`config-schema`), reads and checks the PEM files
(structure, expiry against `tls.min_server_cert_days` and
`trust.min_anchor_days`, an Ed25519 control key, hex revocation serials) and
builds the blob; then it replaces the configuration slot in the copy of the ISO
(it is in the ISO 9660 tree and in the EFI system partition image) and the
`blake2b` of the slot in every `limine.conf` that lists it. Nothing changes
size, no file system is rebuilt, the kernels keep the hashes the release
published. The output is deterministic: the same inputs give the same bytes.
`--sign KEY.pem` attaches an optional Ed25519 signature over the fingerprint
(SECURITY.md, "Configured images"). `pack --image DISK.img` does the same for a
raw disk image's slot.

**The ISO you make is not the release ISO.** It has its own SHA-256, and no
official one: check the *template* against the release's `SHA256SUMS` and its
minisign signature, and the *configuration* by the fingerprint on the console
(`config: fingerprint <64 hex> (<n> bytes, unsigned), env=prod`) against the one
`pack`/`show` printed.

The same ISO then installs to the machine's disk (menu entry 2): the installer
copies the slot it booted with into the installed disk, so the installed system
boots with the same configuration. The installed disk's `limine.conf` lists the
module without a hash (its ESP is writable anyway). To change the configuration
of an installed disk offline, or to update the kernel and keep it:
`urmqtt-disk update-boot DISK --esp NEW-ESP --write` keeps the disk's own
configuration whenever it has a real one (the default, whatever configuration
the new ESP carries: a release's `.img` holds the dev one), `--config BLOB` sets
one, `--replace-config` takes the new ESP's own; `urmqtt-disk info DISK` prints the
installed configuration's fingerprint. Data-layout migration, grow and backup
never touch the ESP.

An installed disk or image whose slot is still the unconfigured template says
so at boot (`config: the configuration slot is empty`) and does not serve.

## 2. Build

```bash
make dist ENV=prod     # build/dist/: urmqtt-prod-<version>.{elf,iso,img}, urmqtt-template-<version>-universal.iso + SHA256SUMS
```

`make iso`, `make raw`, `make dist` and the other image targets pack
`deploy/$ENV/config.toml` with `urmqtt-config pack` (the same blob the template
route produces) into the slot. Every `ENV` but `dev` builds the **same kernel**;
`make template` builds the template ISO from it.

- `.iso`: UEFI-bootable ISO 9660 (El Torito EFI image), for hosts that attach ISOs.
- `.img`: raw GPT disk with one EFI system partition, for hosts that boot disks.
  Write it to the VM's boot disk.
- `.elf`: the kernel itself (for debugging, and for comparing builds).

Production images contain no development plaintext listener, no self-tests and
no TLS client (`selftest` feature off; the prod ELF is about 180 KiB smaller
than dev). A production image listens on a plaintext port only if its
configuration has `[plaintext] enabled = true` (P1, off by default, with a
mandatory `allow_from`; see the README and docs/SECURITY.md); the boot log and
the configuration report say so.
It serves MQTT over secure WebSocket only if the configuration has
`[websocket] enabled = true` (ADR-272, off by default; see below).
Dev-only command-line switches are ignored.

**The image embeds the server's private key** (in its configuration slot, and
the ISO has two copies of the slot). Store it, copy it and delete it like the key
itself.

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
minisign -G                           # once: ~/.minisign/minisign.key + minisign.pub (your own key, for your own images)
make sign                             # signs build/dist/SHA256SUMS (MINISIGN_KEY=... for another key)
# on the receiving side:
minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
```

The trusted comment records environment, version and commit. The project's
release key is [`minisign.pub`](../minisign.pub) in the repository root, for
every release after v0.4.1; v0.1.0 to v0.4.1 were signed with the former **test**
key `9229E05252D01F8E` (`keys/minisign-test-9229E05252D01F8E.pub`,
`RWSOH9BSUuApkkBWq/AZJ03Rn63oOYq+yXzC/vgI1PZ/i5yaE+SVzOWS`), which is trusted
for those tags only and considered compromised once the release key exists
(SECURITY.md, "Release signing keys"; the rotation: docs/release-key-rotation.md).
`make sign` on a release dist (`make dist ENV=release`) refuses a placeholder
`minisign.pub` and checks that the signature verifies with it. Releases carry
SLSA build provenance (`gh attestation verify <file> -R zeljan-alduk/urMQTT`)
and a CycloneDX SBOM (`urmqtt-VERSION.cdx.json`, `urmqtt-dev-VERSION.cdx.json` up
to v0.4.1, in `SHA256SUMS`, with an SBOM attestation: docs/SUPPLY-CHAIN.md),
which an operator can feed to a vulnerability scanner. `make repro ENV=release`
rebuilds the release assets twice and compares them; it needs no `deploy/`.

## 4. Virtual hardware

| Device | Requirement |
|---|---|
| CPU | aarch64 (ARMv8.0+; PAC/BTI used when present) or x86_64 (x86-64-v2: SSE4.2, POPCNT, CX16; section 5b), 2+ vCPUs (with storage the last CPU is the DB core) |
| Firmware | UEFI (AAVMF/OVMF), ACPI or device tree; x86_64 also legacy BIOS (ACPI required) |
| Interrupts | GICv3, or GICv2 (at most 8 vCPUs; what KVM offers on a GIC-400 host such as the Raspberry Pi); MSI-X through GICv2m frames when present (QEMU `virt`), polling otherwise |
| NIC | one virtio-net (PCI); DHCP unless `network.mode = "static"`; MTU from DHCP option 26 or `network.mtu`, else 1500 (below) |
| Disk | **one** virtio-blk disk or virtio-scsi LUN (PCI), 512-byte blocks: the raw image written to it, the disk at least 16 MiB larger than the image (8 GiB or more in production, STORAGE-PLAN sizing); with `storage.require_data_disk = true` the broker refuses to serve without its data partition |
| Display | optional: the boot framebuffer (GOP: ramfb, VGA), or a virtio-gpu PCI (2D) with `console.virtio_gpu` (below) |
| Entropy | virtio-rng, or `RNDR`/`RDRAND`/`RDSEED` on the CPU; otherwise, with `entropy.fallback = "jitter"` (the default), health-tested CPU jitter plus the firmware's values, which is weaker; with `"none"`, no boot (section "Entropy" below) |
| Boot medium | the raw image on the VM's disk, or the ISO's installer, which writes that image onto the disk (below); booted as a CD the ISO's **live** entry runs from RAM, no disk needed and nothing kept (below), if `storage.mode` allows it; without the live word a CD holds no data and production refuses to serve from it |

**Cloud networks and MTU (NOW-19, ADR-264).** Not every network carries 1500-byte packets. **Google Cloud's VPC
networks use an MTU of 1460 by default** (configurable per network from 1300 to 8896); some providers use jumbo
frames (8896, 9000), tunnels and overlays less than 1500. A sender that puts 1500-byte packets on a 1460-byte
network does not get an error: the large packets are dropped, so the TCP handshake and small messages work and
every full-sized segment (a TLS certificate flight, a 4 KiB publish) is lost and retransmitted until the
connection times out. urMQTT uses the MTU in this order:

| Source | When | Boot line |
|---|---|---|
| `network.mtu` in the configuration (576 to 9000) | set; in every network mode, and the only source with `mode = "static"` | `net: mtu 1460 (static)` |
| DHCP option 26 (Interface MTU) | `network.mtu` unset or 0, the lease carries it, 576 to 9000; another value is ignored with a warning | `net: mtu 1460 (dhcp)` |
| 1500 | neither | `net: mtu 1500 (default)` |

The MTU bounds every packet the broker sends: TCP announces and uses an MSS of MTU minus 40 (1420 at 1460; the
smaller of ours and the peer's wins), UDP datagrams (syslog, statsd, SNTP, DHCP) stay within it, and an ICMP echo
reply that would not fit is not sent (nothing is fragmented). Frames above 1500 bytes are never sent: a larger
value (jumbo frames) is used as 1500, which a jumbo network carries. The value in use is in
`$SYS/broker/net/mtu` (docs/OPERATE.md). Google Cloud's DHCP announces the network's MTU, so `mode = "dhcp"` needs
nothing; **with a static address on Google Cloud set `network.mtu = 1460`** (or the network's MTU). Setting it
needs configuration format 7: a template of an earlier release refuses such a configuration when it is packed.

**The console on a virtio-gpu (ADR-256).** Some VMs (netcup ARM) have a virtio-gpu as their only display: the
firmware draws its menu through it, but after boot the provider's console shows "Display output is not active"
(the firmware resets the device; the framebuffer it handed over is RAM nothing shows). With
`[console] virtio_gpu = "on"` (or `"auto"`) in the configuration the kernel drives the device itself and the boot
log, fatal errors and the Diagnostic dashboard become visible there. `"off"` (the default, and the production
template's) never starts the driver; `"auto"` starts it when the bootloader gave no usable framebuffer or one in
RAM, and leaves a virtio-gpu alone when the framebuffer is in a display controller's BAR (virtio-vga, std VGA,
which show it). The boot log says what was chosen and why (`console: virtio-gpu ...`). Anything but `"off"` needs a
kernel that reads configuration format 5; an older template refuses such a configuration when it is packed.

**The optional virtio drivers (ADR-257, ADR-258).** `[devices]` has one key per optional driver, each `"off"` (the
default, and the production template's), `"auto"` (start the driver when the device is found) or `"on"` (the same,
and a warning when there is none):

| Key | Device | What it does |
|---|---|---|
| `virtio_console` | virtio-console (`virtconsole`), port 0 | a copy of the log, and the Diagnostic entry's prompts read their keys from it |
| `virtio_balloon` | virtio-balloon | total, free and available memory for the host's statistics; **never inflates** (the heap is fixed): a host request is logged and refused |
| `virtio_input` | virtio-input keyboards (up to 4) | the Diagnostic entry's "press any key" and `WIPE` from a provider's VNC console that feeds a virtio keyboard |
| `virtio_vsock` | virtio-vsock | the Diagnostic report (the JSON of `$SYS/diag/report`), read-only, to the host on vsock port 2883 (`socat - VSOCK-CONNECT:<cid>:2883`); **not yet tried on a real device** |

Every virtio device the kernel finds is in the boot log (`virtio: <name> at <bdf>: <state>`) and in the Diagnostic
report, also those without a driver (`no driver in this image`, `no driver`). Anything but `"off"` needs a kernel
that reads configuration format 6 and was built with the driver; `urmqtt-config pack --iso` (and the builder page)
refuses a template without it. The release images carry all four (`virtio-vps`, ADR-257).

**The NIC's receive interrupt (ADR-270).** `devices.virtio_net_interrupt = "auto"` (the default) lets a frame that
arrives after the NIC has been quiet for 2 ms wake the core that owns the NIC through the receive queue's MSI-X interrupt: on
x86_64 through the local APIC, on aarch64 through a GICv2m frame or the GICv3 ITS (QEMU/KVM `virt`). Without one
(no MSI-X on the device, no MSI target) the core polls every 200 us while connections exist, as before. The boot log
says which: `net: receive wake-up: interrupt (MSI-X via ...), on probation ...` followed within the first seconds by
`net: receive interrupt verified: 3 frames woke core 0 by it`, or `net: receive wake-up: polling every 200 us ...
(<reason>)`. A hypervisor that accepts the vector but does not deliver it (always, or for some frames) is noticed after eight frames that waited
(`net: receive wake-up: 8 frames waited after a sleep without the receive interrupt; polling ...`) and the broker
polls from then on. `"off"` forces polling (configuration format 11).

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
| `diagnostic` | `true` \| `false`, default `false` | allows the ISO's third entry, *Diagnostic: hardware detection and benchmarks* (ADR-063): CPU (with its measured clock), RAM, PCI, disk and NIC detection, the random number generator's sources and a sanity test of them, RAM, crypto and disk measurements on screen and as one JSON line on the serial port. Reads only, except a write test in unallocated space (after typing `WIPE` on a blank disk). With `false` the entry stops with the reason. The boot word `diag-serve` (also needs `true`) runs the measurements (a blank or foreign disk's write test is skipped: it needs a typed `WIPE`), then boots live and publishes the JSON as the retained `$SYS/diag/report` for an operator certificate, for machines whose console is invisible (`mkiso.sh --diag-default --diag-cmdline diag-serve`); `urmqtt-diag-png report.json out.png` draws it as the dashboard |

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
| `fatal: no entropy source (virtio-rng, RDRAND/RDSEED) and entropy.fallback = "none" forbids the CPU-jitter fallback: refusing to run` | the image requires a hardware random number generator and the VM has none: ask the provider for virtio-rng, or build with `entropy.fallback = "jitter"` (Entropy, below) |
| `fatal: no entropy source (virtio-rng, RDRAND/RDSEED, or a jitter fallback that passes its health tests): refusing to run` | no hardware randomness and the jitter fallback ran but failed its health tests |
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

## 5d. Secure Boot (H8, ADR-250, ADR-251)

**Status: the signing path and the x86_64 OVMF test are done; nothing here has run on real
hardware, on Proxmox or on aarch64 firmware.** The first release targets a KVM VPS, whose
firmware and boot chain belong to the host; most VPS images boot with Secure Boot off. Use this
section when you control the firmware (your own hypervisor, a test PC).

**What it protects, and what it does not.** The firmware verifies the signature of the loader
(`BOOTX64.EFI`, `BOOTAA64.EFI`). The loader then checks its enrolled hash of `limine.conf`, and the
hashes of the kernel and of the configuration module that the file names (under Secure Boot Limine
refuses any file without one). So firmware, signature, loader, configuration, kernel and
configuration are one chain. It does **not** cover: the BIOS path (no signatures exist there),
rollback to an older, correctly signed image (there is no version counter and no `dbx` entries
are made), or a machine whose firmware lets whoever has physical access change the keys.

**Two limits of this design, both tested and both fail closed:**

1. **Sign after you configure.** The enrolled hash covers the module hash of your configuration,
   so `urmqtt-config pack --iso` on a *signed* ISO changes a signed loader and breaks its
   signature; the firmware then answers "Access Denied". Build the image with its configuration
   and the signature in one step, with your own key:
   `scripts/mkiso.sh --universal ... --config my/config.toml --sb-key db.key --sb-cert db.crt`
   (or `make universal` with the same two options passed through `MKISO_ARGS`). The template ISO of a
   release is **not** signed with a key you trust; to use Secure Boot you build the image yourself
   from the release artifacts (`make universal`), or sign with your own key as above.
2. **An installed disk does not boot under Secure Boot.** The installed disk's `limine.conf` names the
   configuration module without a hash (ADR-217: a configuration written later must not trip the
   loader), and Limine refuses a file with no hash when Secure Boot is active ("Secure Boot is active
   and URI ... has no associated hash"). Booting the ISO (live mode) works. Running an installed
   disk under Secure Boot needs a per-machine ESP (module pinned, loader re-enrolled and re-signed
   by you): **not done**.

**Keys.** `scripts/sign-loaders.sh gen-keys build/secureboot` makes a throwaway PK, KEK and db
(RSA 2048) for tests; they protect nothing. A real key is generated offline, kept offline (an HSM or an
air-gapped machine), and never enters this repository (`*.key`, `*.pem` and `build/` are ignored).
`scripts/sign-loaders.sh sign KEY CERT IN OUT` signs one EFI binary with `sbsign` (`apt install
sbsigntool`) or `osslsigncode` (`brew install osslsigncode`); `verify CERT FILE` checks it. The signing
time is `SOURCE_DATE_EPOCH`, so the same key and loader give the same bytes (the smoke scenario
compares two builds).

**QEMU with OVMF (tested).** Needs OVMF's Secure Boot build (QEMU ships `edk2-x86_64-secure-code.fd`;
Debian and Ubuntu `OVMF_CODE.secboot.fd`) and `virt-fw-vars` (`pip install virt-firmware`):

```
scripts/sign-loaders.sh gen-keys build/secureboot
scripts/mkiso.sh --universal ... --out build/signed.iso --sb-key build/secureboot/db.key --sb-cert build/secureboot/db.crt
cp "$(brew --prefix qemu)/share/qemu/edk2-i386-vars.fd" build/vars-empty.fd      # or OVMF_VARS.fd
scripts/sign-loaders.sh ovmf-vars build/secureboot build/vars-empty.fd build/vars-sb.fd
scripts/run-qemu.sh --arch x86_64 --iso build/signed.iso --secure-vars build/vars-sb.fd
```

`ovmf-vars` enrolls PK, KEK and db in the variable store and turns Secure Boot on (the machine is
`q35,smm=on` with a secure pflash; `--secure-vars` does that). An unsigned or foreign-signed image
shows `BdsDxe: failed to load ... Access Denied`. CI runs `SMOKE_ONLY=secureboot scripts/smoke.sh
--arch universal` (with `SMOKE_REQUIRE_SB=1`, so that missing tools fail instead of skipping).

**Proxmox (not tested).** Create the VM with OVMF and an EFI disk *without* the pre-enrolled
Microsoft keys, then put your keys into its variable store:

```
qm set VMID --bios ovmf --machine q35 --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=0
# stop the VM; the EFI disk is a raw 528 KiB volume with OVMF's variable store. Make a store with
# the keys (scripts/sign-loaders.sh ovmf-vars, starting from /usr/share/pve-edk2-firmware/OVMF_VARS_4M.fd)
# and write it to the volume, e.g.:  dd if=build/vars-sb.fd of=/dev/pve/vm-VMID-disk-0 bs=1 conv=notrunc
```

Alternatively, boot the VM once into the firmware setup (Esc at start), *Device Manager, Secure Boot
Configuration*, switch to *Custom Mode* and enroll `db.der` from a small FAT image attached to the VM.
The ISO then boots from the virtual CD.

**A physical PC (not tested; needs hardware).** Put the machine in *Setup Mode* (firmware setup,
Secure Boot, "Erase all keys" / "Custom mode"), copy `db.der` (and, to enroll a PK, `PK.der` and
`KEK.der`) to a FAT USB stick, enroll `db.der` as an authorized signature through the firmware menu (or
with `efi-updatevar` / `sbctl enroll-keys` from a Linux), turn Secure Boot on, and boot the ISO. If the
board offers only the Microsoft keys, the alternative is MOK through `shim`, which this project does
not ship: that choice is open (ADR-251). The Intel test PC of SECURITY-PLAN H8 was not available when
this was written.

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
  Set `fallback = "none"` to refuse to boot instead (see "Entropy" below).
- **NIC:** `ls /sys/bus/virtio/drivers/virtio_net/` must show a device (the
  "paravirtualized" or virtio NIC, not a VFIO/SR-IOV one). If there is none,
  the serial console names the NIC that was found and stops.

### Entropy: what a VPS user should check (ADR-263)

The generator behind every TLS handshake and every key the broker makes is a ChaCha20 CSPRNG, seeded at boot from
the best sources the VM has: **virtio-rng** (the hypervisor's), the CPU's own instruction (`RNDR` on aarch64,
`RDRAND`/`RDSEED` on x86_64), and the bootloader's values. Either hardware source alone seeds it.

When the VM has neither (a netcup ARM VPS on Neoverse N1 was the first found: no virtio-rng, no `RNDR`), the
default, `entropy.fallback = "jitter"`, still boots: the generator is seeded from CPU timing jitter (health-tested,
credited conservatively, at least 256 bits) plus the firmware's values. That is **weaker than a hardware source**, so
it is an explicit option and the image tells you wherever you decide or look:

- **The builder page** shows "Random numbers" in the basic view with two choices: *Allow CPU-jitter fallback
  (default)* and *Require a hardware random number generator*. The result card names the one built, and the notes
  list "Random numbers may come from CPU jitter" while the fallback is allowed.
- **`urmqtt-config pack`** (and `verify`, `show`) print `WARNING: entropy.fallback = "jitter": ...` when it is
  allowed; `show` has an `entropy:` line either way.
- **The boot log** has a `WARN entropy: no hardware source (...)` line with the clock, the samples and the credited
  bits whenever the fallback ran.
- **`$SYS/broker/entropy/source`** (and `"entropy":{"source":...}` in the `$SYS/query/info` reply, an
  `entropy source` line in `status`) names what seeded the generator: `virtio-rng`, `rndr` or `rdrand`,
  `virtio-rng+rndr`, or `jitter+firmware` (`jitter` when the firmware gave no value). Alert on the two `jitter`
  values if you want hardware only.
- **The Diagnostic entry** (boot menu) has an RNG panel with every source, what it delivered and the sanity test.

To check before you rely on a provider: from a Linux VM of the same shape, `cat
/sys/devices/virtual/misc/hw_random/rng_available` lists `virtio_rng` if the provider attaches one, and
`grep -m1 -o -w -E 'rng|rdrand|rdseed' /proc/cpuinfo` (aarch64: `Features` has `rng`) shows the CPU instruction.
To get virtio-rng, ask the provider's support to attach a `virtio-rng-pci` device (libvirt: `<rng model='virtio'>`
with `/dev/urandom` as the backend; Proxmox: the VM's "VirtIO RNG" device).

To refuse such hosts, set `[entropy] fallback = "none"` (the builder: *Require a hardware random number generator*).
The image then stops at boot with `fatal: no entropy source (virtio-rng, RNDR) and entropy.fallback = "none" forbids
the CPU-jitter fallback: refusing to run`, on the serial console and on the framebuffer.

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

### Releasing space: discard (S4)

With `storage.discard = "auto"` (the default) urMQTT tells the disk which space
it no longer uses, so that a thin-provisioned volume shrinks again: telemetry
segments older than `storage.retention_days`, the tail of a database or WAL
file that SQLite truncated, and the space a grow added. It uses virtio-blk
DISCARD or virtio-scsi UNMAP, within the limits the device reports, a few
requests per second and only when the broker is idle. The boot log says what the
disk offers (`storage: discard: auto, device discard (…)`), the counters follow
(`storage: discard: requests=… released=… KiB`).
- **KVM, libvirt, Proxmox, QEMU:** the host must pass the guest's discards on.
  For a qcow2 or a sparse raw file attach the disk with `discard=unmap`
  (QEMU `-drive …,discard=unmap`; libvirt `<driver … discard='unmap'/>`;
  Proxmox: tick "Discard" on the disk). Without it the commands are accepted and
  ignored, and the image only grows. On Linux the file shrinks as holes; on
  macOS (APFS) too.
- **Clouds:** most network volumes are provisioned in full and ignore it; where
  the provider thin-provisions or bills by allocation, it works through virtio-scsi
  UNMAP or virtio-blk DISCARD if the volume type supports it. Nothing breaks
  when it does not.
- **What it does not do:** it does not shrink a disk or its partition (never
  automatic), and it does not trim free pages inside the SQLite database file.
  `storage.discard = "off"` disables all of it. NVMe and SATA (bare metal) come
  with X13.
- **Safety:** a released range is never read as data, so a device that ignores
  the command, zeroes the range, or returns garbage changes nothing
  (docs/DISK-FORMAT.md section 11).

### The in-disk database backup (S5)

The broker's database (the device registry, revocations, retained messages,
persistent sessions with their queues) is copied into a **backup region** of the
same data partition, every `storage.backup_interval_min` minutes (default 60,
`0` turns it off). If the database file is found corrupt at boot, the newest
intact copy replaces it, and the log says exactly what was lost. Telemetry is a
ring of records with a checksum each and is not part of it.
- **What it is for:** corruption of the database file itself (a bad sector, a
  bug, a torn write beyond what SQLite's journalling covers). It is not a
  second copy in another place: **a lost or destroyed disk takes it along.**
  For that, keep your own: `urmqtt-disk backup-extract DISK out.sqlite` writes
  the newest intact snapshot as a plain SQLite file (offline, the disk is not
  changed), and the same file is what `export-db` gives you with the WAL applied.
- **How it works:** two slots, written alternately. A snapshot is copied in
  small steps while the broker serves (the commit latency does not move: ADR-162),
  read back, and only then made valid by a header (sequence, time, schema
  version, CRC). The slot holding the previous good snapshot is never written
  while the next one is made, so a power cut during a backup costs at most that
  backup.
- **Existing disks.** A disk formatted by an earlier build has no backup
  region. The first boot of this build adds one with a single write of the
  superblock (layout v2.0 becomes v2.1; the boot log says `storage: backup
  region added (layout v2.1)`), taken from the unused tail of the database's
  space; nothing moves, no data is copied, and a power cut during it leaves the
  disk as it was or upgraded. If the database is too large to give anything up
  (it must keep twice its size plus 1 MiB) the log says `storage: no backup
  region` and the broker runs as before. `urmqtt-disk backup DISK --write` does
  the same offline and takes the first snapshot.
- **Going back to an older kernel is refused.** A v2.1 disk is not opened by a
  kernel from before S5 (it checks the minor version and refuses). To go back,
  restore the disk from your own copy, or move the data with `urmqtt-disk
  export-db` / `export-telemetry`; there is no downgrade of the layout.
- **Provider snapshots versus this.** A snapshot of the volume (a cloud
  provider's, a hypervisor's, LVM, `qemu-img snapshot`) is **crash-consistent**:
  it is what the disk would hold after a power cut, which urMQTT recovers from
  by design (the SIGKILL and power-cut tests: SQLite's WAL and the telemetry
  ring's torn-tail truncation). You can take one while the broker runs. The
  in-disk backup does not replace it, and it does not replace the in-disk backup:
  a provider snapshot restores everything (including telemetry and the backup
  region itself) to a moment, from outside; the in-disk backup repairs a
  database file in place at boot without anyone doing anything. Do both; keep
  provider snapshots for disaster recovery.
- **Restoring.** Automatically at boot when `quick_check` (or opening the file)
  finds the database corrupt and `storage.auto_restore` is true (the default).
  The log shows `storage: DATABASE RESTORED FROM BACKUP: snapshot seq N from slot
  S …; T s of changes … are LOST` at error level; `urmqtt.backup.restored` is 1
  in statsd. Changes since the snapshot, up to `backup_interval_min`, are gone;
  devices reconnect and republish, retained messages and sessions are as they
  were at the snapshot. With `auto_restore = false`, or with no intact backup,
  the broker refuses to serve (`storage.refuse_on_corruption`), as before. A
  restore cut by a power loss is finished by the next boot. Offline:
  `urmqtt-disk backup-restore DISK --write`.
- **Watching it.** `urmqtt.backup.age_s` (seconds since the newest snapshot) is
  the gauge to alert on; `urmqtt.backup.failed` counts failed backups, and
  `backup: FAILED: …` in the log says why (typically `the database does not fit a
  backup slot`: a slot is an eighth of the database region at the time the
  region was added, at least 1 MiB). `urmqtt-disk info` and `verify` list both
  slots with their sequence, time, size and whether the payload matches its
  CRC.

### Scrubbing (S6)

Every `storage.scrub_interval_h` hours (default 24, `0` turns it off; the first
pass ten minutes after boot) the broker re-reads what is on its disk and checks
it, so that rot is found while a good copy may still exist:
- **the database**, table by table, with SQLite's `quick_check` straight from
  the disk (not from its cache);
- **the in-disk backups**: both slot headers and the checksum of every
  snapshot's contents;
- **the telemetry ring**, every segment, every record against its checksum.

It reads at most `storage.scrub_io_budget_mb_s` megabytes per second (default
8), measured on what it really reads, and only a sliver (one 256 KiB step per
100 ms, 2.5 MB/s at most) while the broker is busy, so a pass always ends and
never competes for the disk. A pass over a few hundred megabytes of telemetry
takes under a minute at the default.
- **What it reports.** `scrub: telemetry partition P segment S (seq N): DAMAGED
  record at byte B, valid records resume at byte R` (a flipped bit or a bad
  sector inside a segment), `… segment header DAMAGED …`, `scrub: database
  object T: DAMAGED …`, `scrub: backup slot S …: DAMAGED …`, and at the end
  `scrub: pass N done …` with the numbers, plus `scrub: pass N FOUND K
  problem(s)` at error level when it found any. Everything reaches the serial
  console, `$SYS/console/out` and syslog. A `bad tail` is a warning: it is what
  a crash leaves, and also what damage to the very last record looks like.
  statsd: `urmqtt.scrub.errors` (problems in the last pass: alert on it),
  `errors_total`, `age_s`, and the per-kind counts.
- **What it does about it:** nothing by itself. A damaged telemetry segment is
  reported, not rewritten (its other records stay readable); a damaged backup
  slot is replaced by the next scheduled backup; a damaged database is repaired
  by the restore at the next boot, if `quick_check` fails there. Use the report
  to decide: replace the disk, restore from your own copy, or note it.
- **What it cannot find:** a flipped bit inside a database row's value (SQLite
  pages carry no checksum here) and a flip in a segment's magic bytes.
- **Offline:** `urmqtt-disk scrub DISK` runs one pass on the host without
  changing the disk and exits non-zero on any damage; handy on a disk image
  copied from a server you suspect.
- **Boot time.** Since S6 a boot reads the segment headers and the newest
  segment of each telemetry partition, not the whole ring (`telemetry: log
  recovered … in the K newest segment(s) read of S`): seconds for hundreds of
  gigabytes instead of minutes. The rest is the scrubber's.

### Encryption at rest (S7, ADR-240)

Optional and off by default. It protects the data partition (registry,
retained and queued messages, telemetry, the backups) when a **volume or a
snapshot is taken away**: the cloud provider's snapshot, a copy of the disk
image, a disk pulled from a machine. It does **not** protect against whoever
holds the ISO (the key is in its configuration) or the running machine.

1. Make a key, once, and keep it somewhere that is not the repository:
   `head -c 64 /dev/urandom | xxd -p -c 200 > disk.key` (128 hex digits; 64 raw
   bytes work too). It is 512 random bits, not a passphrase.
2. In the configuration TOML:
   ```toml
   [storage]
   encryption = "aes-256-xts"
   disk_key = "disk.key"      # a file name next to the TOML, like tls.key
   ```
   `urmqtt-config pack` reads the file into the configuration (blob format 4;
   an image without encryption is still format 2, so older kernels keep
   booting those). The builder page does not offer this yet.
3. **A new disk** is formatted encrypted at its first boot
   (`storage: encryption aes-256-xts (key check ok …)` in the boot log).
   **An existing disk** is converted offline, with the VM stopped:
   `urmqtt-disk encrypt DISK --key-new disk.key --write`. The kernel never
   converts at boot: a plain disk with `storage.encryption` on, an encrypted
   disk without it, a different key and an interrupted conversion are all
   refused at boot with the reason.
4. `urmqtt-disk … --key disk.key` opens an encrypted disk for `info`, `verify`,
   `export-db`, `export-telemetry`, `scrub`, `backup`, `backup-extract`,
   `backup-restore`, `grow`, `import-devices`.
5. `urmqtt-disk rekey DISK --key old.key --key-new new.key --write` and
   `urmqtt-disk decrypt DISK --key disk.key --write` convert in place. They
   rewrite the used part of the disk (holes stay holes), so they take about as
   long as reading and writing it. If one is cut (power, `^C`), run the same
   command again with `--resume` and the same keys; the **journal**
   (`DISK.convert-journal`, or `--journal FILE`) must still be there. Until it
   finishes the kernel refuses the disk.
6. The CPU needs AES instructions (every VPS CPU of the supported kinds has
   them). Without, or with `[cpu] disable` turning them off, the kernel refuses
   rather than run XTS in software.

XTS gives confidentiality, not integrity: a flipped bit scrambles 16 bytes of
data (the checksums and the scrubber find it), and two snapshots can be mixed
sector by sector. The partition table, the superblock and the sizes are not
encrypted. Costs are in docs/PERFORMANCE.md.

### Disk safety, as before

Only the disk Limine booted from is written, and only inside its data
partition (and the partition table at the first boot and when growing). The
offline tool writes only with `--write`. `scripts/fault-loop.sh migrate|grow|backup`
runs the procedures on an image with a power cut after every write and checks
that each case ends in a valid disk that finishes.

## 10. The release mirror and the builder page on a web server (C1e, ADR-227)

Only for whoever runs the site (aldo.tech does); the broker needs none of this. The builder page loads its template
from the site it is served from, so the site mirrors the GitHub releases and serves the page. Everything below is
idempotent and prints what it does; `--dry-run` changes nothing.

1. **The mirror job** (root, from a checkout): `scripts/mirror/install.sh`. It creates the unprivileged `urmqtt-mirror`
   user and `/var/www/aldotech.io/urmqtt/releases`, and enables `urmqtt-mirror.timer` (hourly, nice 19, idle I/O,
   2 MiB/s). A release is published there only after its `SHA256SUMS` signature and the template's SHA-256 check
   out. The signature is checked with the key it names from the key ring `/etc/urmqtt-mirror/keys/release-keys.json`
   (a copy of `keys/release-keys.json`; the release key is `/etc/urmqtt-mirror/minisign.pub`, the former test key
   `keys/minisign-test-9229E05252D01F8E.pub`), and only for the tags that key may sign; the unit passes
   `--keyring`. The installer refuses a placeholder `minisign.pub`. Installs from before the rotation run with
   `--pubkey /etc/urmqtt-mirror/minisign.pub` (the test key): re-run the installer from the rotated checkout
   (docs/release-key-rotation.md, step 6). `systemctl start urmqtt-mirror` runs it now, `journalctl -u urmqtt-mirror`
   is its log; exit 2 means a release failed verification (the unit shows as failed).
2. **Its web server**: `scripts/mirror/install-web.sh` starts an nginx container (pinned image, read-only, no
   capabilities) on `127.0.0.1:18089` that serves only `releases.json`, `SHA256SUMS`, its signature and the template,
   with rate limits (Caddy has none).
3. **Caddy**: `python3 scripts/mirror/caddy-apply.py /etc/caddy/Caddyfile` adds two marked regions (a backup is written
   next to the file), then `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && systemctl reload caddy`.
   It proxies `/urmqtt/releases*` to the container, sends `Cross-Origin-Embedder-Policy` for the builder pages (the
   emulator needs it), serves the emulator's files pre-compressed and redirects `/products/` to the English page.
4. **The pages**: `make builder` (or `make builder-emulator` to include the emulator; the keys of
   `keys/release-keys.json` are built into the page, and the deploy script refuses a page without the release key), then
   `scripts/deploy-builder-site.sh --chown USER:GROUP` copies the page and the site modules to the generator's directory and
   patches its `build.py` (refused if it is not the generator it knows; a second run changes nothing). Publish with the
   site's own `publish.sh`, **which must leave the mirror alone**: `rsync -a --delete --exclude=/urmqtt/releases/ ...`.
   Try it first with `--site-dir` pointing at a scratch copy and `OUT=/somewhere python3 site/build.py`, and compare the
   output with the old one (every existing page must be the same page apart from the added links).
5. **Checking**: the status of every URL in `sitemap.xml` before and after (nothing may change except the new pages),
   and the page in a browser (`tools/builder/test/` has the harness).
6. **Taking the links away** without removing the pages: build the site with `URMQTT_PRODUCTS_LISTED=0` (no header or
   footer link, no sitemap entry, no card links, `noindex`).
7. **Rolling back**: restore `build.py` (and `publish.sh`) from the backups made before step 4, delete `products.py`,
   `products_i18n.py`, `apply_products.py` and `urmqtt-builder/` from the generator's directory and publish; restore the
   Caddyfile from its `.bak-<date>-urmqtt*` copy, validate, reload; `systemctl disable --now urmqtt-mirror.timer
   urmqtt-mirror-web`, remove the units, `/usr/local/lib/urmqtt-mirror`, `/etc/urmqtt-mirror` and the container.
   The mirrored files are only a copy of what GitHub has.

### TLS off, plain MQTT only (ADR-233)

A trusted plant network can run without certificates: `[network] mqtt_tls_port = 0` and `[plaintext] enabled = true` with `allow_from` and a login mode. The image then needs no `tls.cert`, `tls.key` or `trust.operational`, boots with `mqtt: TLS listener off`, and has no operator, service or control access (those need mutual TLS). The configuration is written in format 3, which a kernel of **v0.2.1 or newer** reads; older templates are refused with the reason. With both listeners on (the default of the simple view's second box plus plain MQTT) nothing changes for TLS.

### MQTT over secure WebSocket for browsers (ADR-272)

`[websocket] enabled = true` opens `wss://<host>:8084/mqtt` beside the TLS port, with the TLS listener's certificate and
key (so `network.mqtt_tls_port` must be on, and the certificate's name must be what the browser connects to: a
browser does not let a page skip the check). The configuration is written in format 9; a template whose kernel reads
less refuses it with the reason. Open the port in the provider's firewall as you did 8883.

- **Devices and services that speak WebSocket:** keep `auth = "mtls"` (the default). Nothing else changes: the same
  certificates, identities, ACL and revocation.
- **Browser pages:** `auth = "password"`, the page's origin in `origins` (exactly as the browser sends it:
  `https://dashboard.example.com`, or `http://localhost:3000` while developing), one account per user or page in
  `users` (`urmqtt-config hash-password`, or the builder page), and the topics they may use in `acl_publish` and
  `acl_subscribe`. Sessions are clean: the page subscribes again after every reconnect.

Check it from a machine that can reach the port (the second request must answer 403):

```bash
curl -sk --http1.1 -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: mqtt' -H 'Origin: https://dashboard.example.com' \
    https://broker.example.com:8084/mqtt     # 101 with auth = "password"; with mtls add --cert/--key
curl -sk --http1.1 -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: mqtt' -H 'Origin: https://evil.example' \
    https://broker.example.com:8084/mqtt     # 403
```

The boot log has one `mqtt: WebSocket listener on port 8084 (wss://.../mqtt, ...)` line with the mode, the origins and
the limits; refusals (`websocket: N connection(s) refused: origin`) and protocol violations are logged at powers of
two, lock-outs always; the operator reads `$SYS/broker/websocket/*`. A reverse proxy in front is not needed; if you
put one there (to serve the broker on 443 under the page's own name), it must pass the upgrade through unchanged and
keep the `Origin` header, and with `mtls` it cannot terminate TLS.

## 11. A public demo broker (D1)

> **Status: built and tested locally, NOT deployed.** Nothing below has been run on a server, in a DNS zone, in a firewall or
> in your Caddy. This section is the runbook for the day you decide to expose it. Read
> [SECURITY.md, "The public demo broker (D1)"](SECURITY.md#the-public-demo-broker-d1) first: what you are about to publish is
> a toy whose client CA key is public on purpose.

What it is: a urMQTT in **live mode** (`storage.mode = "ram"`, nothing persists, a reboot is a reset) with mutual TLS on
`demo-mqtt.aldo.tech:8883` and published throwaway client certificates (D1a), plus a plaintext listener that only the bridge
host may reach, behind a WebSocket bridge that serves `wss://aldo.tech/demo/mqtt` to the page "Try urMQTT live" (D1b).
Files: `deploy/demo/config.toml`, `scripts/demo-certs.sh`, `scripts/demo-pack.sh`, `scripts/demo-smoke.sh`,
`deploy/demo-bridge/` (bridge, Dockerfile, systemd unit, Caddy snippet), `tools/builder/demo/` (the page),
`tools/builder/site/{demo,apply_demo}.py`.

**Decide first.**
1. **Which machine.** Do **not** run the demo on the production broker's machine: one VM runs one image, so the demo would
   replace the production image and put a public toy on the address devices use. Use a second small KVM VPS with its own
   address. (PLAN.md D1 spoke of the Contabo VPS staying on the production image; that and a demo exclude each other on one VM.)
2. **The bridge host**: the machine that runs Caddy for aldo.tech and the bridge container. Its public address is what the
   firewall and `allow_from` below name (`BRIDGE_IP`).
3. **Listed or not**: the page is built unlisted (noindex, no menu or sitemap entry, reachable by its address) until you set
   `URMQTT_DEMO_LISTED=1` for the site build.

**1. The certificates** (any machine with OpenSSL >= 3; keep `deploy/demo/pki/server.key` private):
```bash
scripts/demo-certs.sh --host demo-mqtt.aldo.tech --count 20     # deploy/demo/pki/, git-ignored
```
It makes the public client CA (`ca.pem`, `ca.key`), a separate broker CA whose key it deletes, the broker certificate, `web` and
`demo-001..020`, and `pki/download/` with `demo-certs.zip`. The client CA lasts 730 days, the leaves 365: **repeat before they
expire** (`--force` starts over with new CAs, so repack the image and replace the download).

**2. The image.** A release with a template (`urmqtt-template-<version>-universal.iso`, checked against its `SHA256SUMS` and
signature as in section 1b) or `make template`. Then:
```bash
cargo build --release -p urmqtt-config-tool
scripts/demo-pack.sh --template urmqtt-template-<version>-universal.iso --out urmqtt-demo.iso \
    --bridge BRIDGE_IP/32 --static DEMO_IP/PREFIX GATEWAY --tool target/release/urmqtt-config
```
`--bridge` is the only source the plaintext port answers (any other source gets no SYN-ACK). It prints the configuration
fingerprint; the kernel prints the same one at every boot. **Before shipping it, run the local acceptance test** (no exposure;
QEMU forwards loopback ports only):
`scripts/demo-smoke.sh --template urmqtt-template-<version>-universal.iso --tool target/release/urmqtt-config`.

**3. Boot it** on the demo VPS as in section 5b (upload the ISO, boot from it; the first menu entry is the live entry, and
`storage.mode = "ram"` keeps everything in RAM). The console shows `EPHEMERAL: data is lost on reboot`,
`TLS 1.3 listener on port 8883`, `PLAINTEXT listener on port 1883` and `URMQTT READY`. Do not install it to the disk.

**4. Firewall** (the provider's panel; the broker has no firewall of its own beyond `allow_from`):

| Direction | Port | Source | Why |
|---|---|---|---|
| in | 8883/tcp | anywhere | demo clients (mutual TLS) |
| in | 1883/tcp | `BRIDGE_IP` only | the bridge; the broker's `allow_from` is the second lock |
| in | everything else | none | |

**5. DNS**: an `A` record `demo-mqtt.aldo.tech` -> `DEMO_IP`, **DNS only** (no CDN or HTTP proxy: it cannot carry raw TLS on
8883). The name must match `--host` of step 1 (the broker certificate's SAN).

**6. The bridge** (on the bridge host):
```bash
# the Dockerfile pins python:3.12-alpine by digest (Dependabot proposes newer ones); another digest:
#   --build-arg PYTHON_IMAGE=python:3.12-alpine@sha256:<digest>
docker build -t urmqtt-demo-bridge deploy/demo-bridge
# what the unit runs; read-only, no capabilities, non-root, loopback only, no secrets:
docker run --rm --name urmqtt-demo-bridge --read-only --tmpfs /tmp:rw,noexec,nosuid,size=4m \
    --cap-drop ALL --security-opt no-new-privileges --memory 96m --cpus 0.5 --pids-limit 32 \
    -e DEMO_BRIDGE_UPSTREAM=DEMO_IP:1883 -e DEMO_BRIDGE_ORIGINS=https://aldo.tech,https://aldotech.io \
    -p 127.0.0.1:18090:8080 urmqtt-demo-bridge
curl -s http://127.0.0.1:18090/healthz        # {"ok": true, "open": 0, ...}
```
For a service, edit the three `CHANGE` lines of `deploy/demo-bridge/urmqtt-demo-bridge.service`, install it and
`systemctl enable --now urmqtt-demo-bridge`. Its limits (all `DEMO_BRIDGE_*` variables; `bridge.py --help`): 4 connections per
visitor address and 50 in all (the broker's `plaintext.max_connections` is 60), 20 new connections a minute per address,
1024-byte messages (the broker's plaintext packet size), 20 messages and 8 KiB a second per connection, 120 s idle, 1 h
lifetime, an Origin allow-list. The log has counters, no payloads and no addresses.

**7. Caddy**: put `deploy/demo-bridge/Caddyfile.snippet` into the `(site)` snippet before the catch-all `handle`, then
`caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && systemctl reload caddy`. Do not configure `trusted_proxies`
for the clients: Caddy must overwrite `X-Forwarded-For` with the real peer, which is what the bridge counts by.

**8. The page**: `scripts/demo-certs.sh` first (the page links the zip), then
```bash
make demo-page
scripts/deploy-builder-site.sh --with-demo --chown USER:GROUP --dry-run     # then without --dry-run
```
`apply_demo.py` runs after `apply_products.py` (the script does it) and refuses a `build.py` it does not recognise. **It was
only tested against a stand-in generator**: back `build.py` up, try it with `--site-dir` on a scratch copy and compare the
output first. The page is `/<products slug>/urmqtt-live/` (for example `/en/products/urmqtt-live/`) with the site's own CSP: if
that blocks the WebSocket (an old Safari does not let `default-src 'self'` cover `wss:`), add `connect-src 'self'
wss://aldo.tech` to the generator's CSP. To list the page, build with `URMQTT_DEMO_LISTED=1`. The generator copies
`urmqtt-demo/` to `/urmqtt/demo/` like the builder; the publish script must not delete it.

**9. Check it from outside**:
```bash
mosquitto_pub -h demo-mqtt.aldo.tech -p 8883 --cafile server-ca.pem --cert clients/demo-001.pem --key clients/demo-001.key \
    -i demo-001 -t demo/demo-001/hello -m hi -q 1                      # works
nc -vz -w 3 DEMO_IP 1883                                               # from anywhere but BRIDGE_IP: no answer
curl -si -H 'Origin: https://evil.example' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Protocol: mqtt' https://aldo.tech/demo/mqtt | head -1   # 403
```
and open the page in a browser: connect, subscribe, publish, see the message.

**Reset**: reboot the demo VM (provider panel). Live mode keeps nothing: retained messages, sessions and the log are gone, and
the image is the whole state. **Monitoring**: `journalctl -u urmqtt-demo-bridge` (counter summaries: `accepted`, `refused_*`,
`closed_*`), `curl 127.0.0.1:18090/healthz`, an uptime check that opens TCP 8883 and the page, the broker's console (VNC) and, if
you set `observability.syslog_udp` to a private collector, its log. The demo has no operator identity, so there is no `$SYS`.
**Taking it down**: delete the Caddy block and reload; `systemctl disable --now urmqtt-demo-bridge` and remove the container;
close 8883 and 1883 and delete the DNS record; power off the VM (or put the production image back); remove the page: delete
`urmqtt-demo/`, `demo.py` and `apply_demo.py` from the generator's directory, restore `build.py` from the backup, publish. The
published CA key is then of no use to anybody.
