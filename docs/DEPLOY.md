# Deployment

> **Status:** the deployment tooling arrives in M17. This page records the
> intended procedure so that the earlier milestones stay compatible with it.

## Build inputs

`deploy/prod/` must contain (none of these are committed, see ADR-004):

| File | Content |
|---|---|
| `config.toml` | committed template; review every key |
| `ca.pem` | CA that signs device certificates |
| `server.pem` | broker certificate chain |
| `server.key` | unencrypted PEM private key (the VM cannot prompt for a passphrase) |

```bash
make iso ENV=prod        # → build/urmqtt-prod-<version>.iso (M1+)
```

The image embeds the private key. Store and transfer it like a secret.

## Targets

### Generic KVM / Proxmox (aarch64 host)

Planned for M17. Create a VM with UEFI (OVMF/AAVMF), attach the ISO or raw
image, and add a virtio-net NIC, a virtio-blk data disk and virtio-rng.

### Hetzner Cloud CAX (Ampere)

Custom ISOs can only be mounted through Hetzner support. The practical path is
the raw disk image (`.img`, GPT + ESP), written to the server disk from the
rescue system and snapshotted. The procedure will be validated in M17.

### Oracle Cloud Always Free (Ampere A1)

A free candidate for permanent hosting. Custom image import in paravirtualized
mode exposes virtio devices. To be validated after M5 (ACPI) and M17 (image).

### Not supported

AWS Graviton, Azure Cobalt and other platforms that expose only non-virtio
NICs or disks (ENA, NVMe, MANA) are not supported. urMQTT ships virtio drivers
only.
