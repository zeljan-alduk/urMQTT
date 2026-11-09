# NEXT-6: virtio-net multiqueue with RSS (ADR-310 to ADR-314)

## What changed for operators

- **One NIC queue pair per data core** when the virtio-net device offers multiqueue **with** receive-side scaling
  (`VIRTIO_NET_F_MQ`, `VIRTIO_NET_F_CTRL_VQ` and `VIRTIO_NET_F_RSS`, a 40-byte key, a 128-entry table and the
  TCP/IPv4 hash). The broker programs the device's RSS with the same Toeplitz key and indirection table its own
  steering uses, so each TCP/IPv4 flow arrives on the queue of the core that owns it; that core receives, sends and
  is woken (its own MSI-X vector, with ADR-270's probation and polling fallback per pair) on its own pair. Core 0
  keeps pair 0 for ARP, ICMP, DHCP and anything the device does not hash, and no longer copies every frame.
- **Everything else is one pair, exactly as v0.5.0**: a device without MQ (QEMU's default, most VPSes), MQ without
  RSS (libvirt `queues=N` with vhost and no eBPF RSS), a device whose RSS limits are too small or that refuses the
  configuration, one data core (2 vCPUs with storage). The boot line says which: `net: multiqueue: P queue pairs
  (the device offers N), RSS ...`, or `net: one queue pair: <reason>`; per worker `net: queue pair k on core k: ...`.
- A frame that arrives on a worker's pair but is not that worker's flow (a TCP frame to a port core 0 serves, or a
  device that hashes differently) is passed to core 0 and steered as before: never lost, never reordered within a
  flow, and counted.
- **New `$SYS` topics** (nothing existing changed): `$SYS/broker/net/queues`, `$SYS/broker/net/queue/{received,
  sent,forwarded,interrupts}/<k>`; info reply `"net":{"mtu":..,"queues":[...]}`; metrics
  `urmqtt_network_queue_pairs`, `urmqtt_network_queue_frames_{received,sent,forwarded}_total{queue="k"}`,
  `urmqtt_network_queue_interrupts_total{queue="k"}` (new bounded label `queue`, at most 16 values). With
  multiqueue a console line per pair every 5 s: `net: queue pair k (core k): R frame(s) received, S sent, F
  forwarded to core 0, ...`.
- Tools: `scripts/run-qemu.sh --tap IFNAME[:QUEUES]` (a multi-queue tap with `mq=on,rss=on,vectors=2N+2`);
  `scripts/mq-rig.sh` (the Linux rig); smoke group `SMOKE_ONLY=mq` (the tap part on Linux as root or with sudo, or
  with `URMQTT_MQ_DOCKER=<image>`, see `docs/perf-results/next6-mq/Dockerfile`); fuzz target `virtio_net_mq`.

## Configuration

- `[devices] virtio_net_queues = "auto" | "single"`, **configuration format 19**, tag 395.
  - `"auto"` (default) writes nothing: every existing configuration keeps its format.
  - `"single"` asks for one pair and negotiates none of MQ, the control queue and RSS; needs format 19 (a v0.5.0
    or format-18 template refuses it with the reason). Use it on a host whose multiqueue misbehaves.
- Schema, `urmqtt-config`, the builder page (15 languages) and the dev, bench and demo configuration files know
  the key.

## Upgrade and downgrade

- Upgrade: on a NIC without MQ nothing changes. On a NIC with MQ, MQ, the control queue and (when offered) RSS are
  now negotiated; with RSS and two or more data cores the broker uses one pair per data core from the first boot.
  No stored state, no migration.
- Downgrade to v0.5.0: a reboot; a configuration with `"single"` needs format 19 and is refused by a v0.5.0 kernel
  (remove the key first).

## Defaults and limits

- At most 16 pairs; one per CPU is set up at probe (the store's DB core's pair is never used). Each pair: two queues
  of up to 1024 descriptors with 2 KiB buffers (4 MiB at 1024, 1 MiB at QEMU's default 256).
- The RSS configuration must be accepted within 1 s, else one pair.
- With more data cores than pairs, the cores without a pair are served through pair 0 by core 0.
- A 128-entry table splits flows unevenly over 3, 5, 6 or 7 cores (7: +3.9 % / -1.6 % of a fair share); without
  multiqueue the steering is the hash modulo the workers, as before. Home shards (persistent sessions) unchanged.

## Deliberately not done

- No KVM host: vhost-net with eBPF RSS, interrupt delivery to vCPUs other than 0 on a real hypervisor, and the
  throughput gain there are unverified (tested under QEMU TCG in Docker with QEMU's software RSS; D-9 open).
- Multiqueue without RSS is not used (its steering cannot be matched and can move a flow between queues).
- No `VIRTIO_NET_F_HASH_REPORT`, no IPv6 hash types (no IPv6), no table change at run time.
- On aarch64 with only a GICv3 ITS (QEMU TCG, the netcup ARM VPS) the worker pairs are polled (200 us while they
  have connections): the ITS driver has one collection (core 0).
- Throughput: see PERFORMANCE.md section 14 for what the local TCG rig shows and why it cannot show the gain a
  KVM host would.
