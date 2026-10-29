# TODO

Open work that needs real hardware or a decision. Finished work is recorded
in [docs/PROGRESS.md](docs/PROGRESS.md).

## Run on real hardware

- [ ] **Raspberry Pi 4/5 under KVM** (ADR-039, docs/DEPLOY.md §7). Needs a Pi with 4 GB or more and 64-bit Raspberry Pi OS (`ls /dev/kvm`).
  1. Build the prod image (`make dist ENV=prod`) and copy it, plus `SHA256SUMS` and `SHA256SUMS.minisig`, to the Pi.
  2. `sudo scripts/kvm-host/install.sh urmqtt-prod-<version>.img`
  3. In `journalctl -u urmqtt -f`, check:
     - `gic: v2 at …`;
     - `smp: 4/4 cpus online` and `ipi: 12/12`;
     - `msi-x: … via GICv2m`;
     - the DHCP lease and the TLS listener.
  4. Connect a device with mTLS from another machine (port 8883 on the Pi's address), then run `scripts/mqtt-scenarios.py` against it.
  5. Record the results in PROGRESS: boot time, IPI round trip, and handshakes/s from `tools/loadgen`. Remove the "not yet on a Pi" notes from the README and ADR-039.
- [ ] **A cloud with Ampere Altra** (Hetzner CAX; Oracle A1 did not work out). Check three things:
  - the jitter entropy figures in the boot warning (they have only been measured under QEMU);
  - virtio-scsi disks;
  - the virtio-net NIC.

## x86_64 and bare metal

- [ ] Hardware inventory of the Intel test PC (16 GB), from a Linux live USB:
  - `lscpu`;
  - `lspci -nn`;
  - `lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE`;
  - `ls /sys/firmware/efi`;
  - `mokutil --sb-state`;
  - does it have a serial port?

  This decides which NIC and storage drivers come first (docs/X86-PLAN.md, X12–X14).
- [ ] Milestones X0 to X16 as in docs/X86-PLAN.md; the README roadmap shows their status.

## Before a real release

- [ ] Replace the test minisign key (`minisign.pub`, CI secret `MINISIGN_SECRET_KEY`) with an offline, password-protected key.
- [ ] A real production PKI. `deploy/prod/` holds a local test CA (git-ignored).

## Known limits (no plan yet)

- No driver for SR-IOV NICs (Mellanox VFs), NVMe, AWS ENA or Google gVNIC, so AWS and Google Cloud are not supported.
- At most 8 CPUs on a GICv2 (an architectural limit).
- No limit on established connections per source address.
