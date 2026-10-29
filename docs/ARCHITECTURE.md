# urMQTT architecture

> This is the target design. [PROGRESS.md](PROGRESS.md) records which parts exist, and
> [DECISIONS.md](DECISIONS.md) records where and why the design changed. The full
> specification is [PROMPT.md](../PROMPT.md).

## 1. One binary, one purpose

urMQTT is a unikernel. The bootloader (Limine, UEFI) loads one statically linked
aarch64 ELF that contains everything needed to be an MQTT broker:

```
┌───────────────────────────── urmqtt (one ELF, EL1) ─────────────────────────────┐
│  broker  ─ sessions · topic trie · subscriptions · QoS · retained · LWT · ACL    │
│  mqtt    ─ zero-copy 3.1.1/5.0 codec                                             │
│  tls     ─ rustls handshake → own TLS 1.3 record layer                           │
│  tcp     ─ server-only TCP, SYN cookies       net ─ Eth/ARP/IPv4/ICMP/DHCPv4     │
│  store   ─ SQLite (C, vendored) + raw-disk VFS · per-core telemetry log          │
│  virtio  ─ net · blk · rng      pci ─ ECAM · BARs · MSI-X                        │
│  mm      ─ frames · heap · per-CPU slabs · pools · key slab                      │
│  platform ─ DTB | ACPI → one PlatformInfo       log ─ per-CPU rings → sinks      │
│  arch-aarch64 ─ vectors · MMU (W^X) · GICv3/v2 · timer · PSCI · PAC/BTI · RNDR   │
│  config  ─ compile-time constants + embedded CA / server cert / key              │
└──────────────────────────────────────────────────────────────────────────────────┘
        ▲ UEFI + Limine                 ▲ virtio-pci devices from the hypervisor
```

There is no scheduler, no processes, no syscalls, no filesystem, no shell and
no console input. The only listening socket is TCP 8883 (plus 1883 in dev
builds only, enforced at build time).

## 2. Boot sequence

1. **UEFI → Limine.** Limine loads the kernel at its fixed higher-half address and hands over a memory map, HHDM offset, framebuffer, DTB and/or RSDP, the MP (CPU) list and the date at boot.
2. **Early console.** The PL011 address comes from the DTB `stdout-path` or the ACPI SPCR table (with a dev fallback). The framebuffer text logger starts.
3. **Exceptions.** The EL1 vector table is installed. Every synchronous exception prints a decoded ESR (exception class, ISS), ELR, FAR and SPSR. A panic logs, then calls PSCI `SYSTEM_RESET` (`SYSTEM_OFF` in smoke mode).
4. **Memory.** The frame allocator is built from the Limine memmap, and the kernel switches to its own translation tables with W^X: `.text` RX, `.rodata` R, everything else RW-NX. Every stack gets a guard page. PAC/BTI are enabled if `ID_AA64ISAR1_EL1` / `ID_AA64PFR1_EL1` report them. After boot the tables are locked: nothing is ever remapped executable.
5. **Platform.** DTB or ACPI tables are reduced to one `PlatformInfo` (CPUs, GIC, timer IRQs, UART, PCIe ECAM, PSCI conduit).
6. **Interrupts, time, entropy.** The GIC comes up (GICv3 distributor and redistributors, or a GICv2 distributor and CPU interface on GIC-400 hosts, ADR-039), along with the generic timer, the CSPRNG seeded from `RNDR` or virtio-rng. With no entropy source, the kernel halts with a clear error.
7. **SMP.** The application processors start (Limine MP or PSCI `CPU_ON`). Per-CPU data lives behind `TPIDR_EL1`.
8. **Devices.** PCIe enumeration, then virtio-blk (data disk), virtio-net (queues per core) and virtio-rng.
9. **Storage.** The data disk superblock is checked, SQLite opens in WAL + `locking_mode=EXCLUSIVE`, `PRAGMA quick_check` runs, and telemetry segments are recovered.
10. **Network.** DHCPv4 (or static), then the TLS listener on 8883.
11. The kernel prints `URMQTT READY`.

## 3. Execution model: thread-per-core, shared-nothing

```
 core 0                core 1                core N-2              core N-1 (DB)
┌────────────┐        ┌────────────┐        ┌────────────┐        ┌────────────┐
│ RX/TX q0   │        │ RX/TX q1   │        │ RX/TX qN-2 │        │ SQLite     │
│ TCP table  │        │ TCP table  │        │ TCP table  │        │ memsys5    │
│ TLS states │ ◀────▶ │ TLS states │ ◀────▶ │ TLS states │ ◀────▶ │ raw VFS    │
│ sessions   │  SPSC  │ sessions   │  SPSC  │ sessions   │  SPSC  │ batching   │
│ topic trie │ rings  │ topic trie │ rings  │ topic trie │ rings  │            │
│ timer wheel│        │ timer wheel│        │ timer wheel│        │            │
│ slabs/pools│        │ slabs/pools│        │ slabs/pools│        │            │
└────────────┘        └────────────┘        └────────────┘        └────────────┘
```

- Each data core runs one loop: poll RX, then process to completion, then flush TX, then run expired timers, then drain the rings. When idle it switches to interrupts and `WFI` (adaptive polling).
- Interrupt handlers only acknowledge and mark work.
- Cores share no mutable state. Cross-core traffic goes through bounded lock-free SPSC rings, one per ordered pair of cores. Every atomic documents its memory ordering, because AArch64 is weakly ordered.
- The highest-numbered core runs SQLite only. With one CPU, the DB work runs between loop iterations.
- A per-core 10 ms watchdog tick detects a handler that overruns its budget (ADR-013).

### Data path for one PUBLISH

```
NIC RX buffer ─▶ IPv4/TCP validate ─▶ TLS decrypt in place ─▶ MQTT parse (borrowed)
   ─▶ ACL check (no DB) ─▶ rate limit ─▶ route: local subscribers + cross-core summary
   ─▶ payload stored once, refcounted ─▶ per-subscriber encrypt into TX buffer
   ─▶ PUBACK coalesced with the TCP ACK ─▶ NIC TX
   └▶ telemetry topics: append to this core's log segment (batched)
```

### Multicore NIC

The NIC mode is chosen at boot from the virtio feature bits and logged:

| Mode | When | How |
|---|---|---|
| RSS | `VIRTIO_NET_F_RSS` | The device hashes the 4-tuple to one queue per core |
| Multiqueue, no RSS | `VIRTIO_NET_F_MQ` | The device's own steering, with fallback dispatch for flows that land on the wrong core |
| Fallback dispatcher | single queue | Core 0 computes a Toeplitz-style hash and forwards descriptors (not copies) through SPSC rings; TX goes through per-core queues or back to the owner |

## 4. Memory per connection

Target: **≤ 512 B per idle TLS connection** (stretch goal ~256 B). The idle
budget below is the plan that M15 will measure against, not a measurement:

| Part | Budget | Notes |
|---|---:|---|
| TCP control block | 64–96 B | 32-bit indices, bit-packed flags, timers as wheel slots |
| TLS 1.3 record state | ≤ 128 B | two directions × (key + IV + seq); raw keys in the crypto key slab, zeroized on free |
| MQTT session (hot) | ≤ 64 B | device id is interned; device-scoped topics use the session id |
| Subscriptions | ~8 B each | 32-bit topic-node ids |
| Connection table slot | ~16 B | open-addressing hash on the 4-tuple |
| Timer wheel entries | ~32 B | retransmit and keepalive |
| **Idle total** | **~300–400 B** | no per-connection RX/TX buffers while idle |

While idle there are no per-connection buffers. A pooled buffer is attached
only while an MQTT frame or TLS record is incomplete, or while TX data is
unacknowledged. `size_of` assertions in tests catch regressions.

Separate regions: kernel heap, per-CPU slabs, packet pools, the **crypto key
slab** (never compressed, zeroized on free) and a fixed SQLite `memsys5` heap.

## 5. TLS

- TLS 1.3 only, with mutual TLS: device certificates must chain to the CA compiled into the image.
- `device_id` is taken from the configured field (`cn` or `san_uri`), and the MQTT client id must match it.
- The handshake runs through rustls in `no_std` mode with a pure-Rust crypto provider. Admission control is a per-core token bucket. Every handshake phase has a timeout. Resumption uses PSK tickets.
- After the handshake the traffic keys are extracted and the rustls object is dropped. A minimal record layer (AES-128-GCM, ChaCha20-Poly1305) decrypts in place and encrypts directly into TX buffers (KeyUpdate: ADR-012).
- Revoked serials are stored in SQLite and mirrored read-only on every data core. A handshake never waits for the DB.

## 6. Broker

- MQTT 3.1.1 first, then 5.0. QoS 0 and 1 (QoS 2 later).
- Supported packets and features: CONNECT/CONNACK, PUBLISH/PUBACK, SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP, DISCONNECT, wildcards `+` and `#`, retained messages, LWT, clean and persistent sessions with bounded offline queues.
- Topic interning: each core has a topic trie, and sessions store 32-bit node ids. Fan-out to other cores sends a compact routing message (payload handle + topic id), guided by a "which cores have subscribers" bitmask per node.
- Reconnects to a different core go through the session directory (ADR-011).
- The default ACL lets a device publish to `devices/{id}/#` and subscribe to `devices/{id}/cmd/#`. Patterns are configurable. ACL checks never touch the DB.
- Every limit (packet size, topic length and levels, subscriptions, in-flight messages, queue depth, publish rate, connections per core) is a compile-time constant from `deploy/<env>/config.toml`.

## 7. Persistence

Data disk (virtio-blk, no filesystem):

```
[ superblock: magic · layout version · uuid · region table · CRC ]
[ region: SQLite main DB ]
[ region: SQLite WAL ]
[ regions: telemetry log, one per core ]
```

- **SQLite** holds the device registry, revocations, retained messages and persistent sessions. All SQL is fixed at compile time and prepared at boot, with `SQLITE_DBCONFIG_DEFENSIVE` on. Writes from data cores are batched into transactions every 5–10 ms. `xSync` maps to a virtio-blk FLUSH, and the kernel refuses to run without `VIRTIO_BLK_F_FLUSH` unless the config explicitly allows unsafe mode.
- The **telemetry log** is a set of per-core append-only segments with a CRC per record and batched writes. On boot, recovery truncates a torn tail. Retention is by age or size.

## 8. Hardware discovery

The same kernel runs on QEMU `virt` (device tree) and on ARM cloud VMs (ACPI:
MADT, GTDT, MCFG, SPCR). The `platform` crate turns either source into one
`PlatformInfo`, and M5 verifies that `-machine virt,acpi=on` and `acpi=off`
print identical summaries.

## 9. Crate dependency rules

- `kernel` depends on everything. Nothing depends on `kernel`.
- The host-testable crates (`timer-wheel`, `tcp`, `mqtt`, `broker`, `tls` record layer, `net` parsing, `config`, `platform` parsers) never touch registers. Hardware access sits behind traits implemented in `arch-aarch64`, `virtio` and `kernel`.
- `broker` is tested end to end over an in-memory transport.
- `unsafe` is allowed only in `arch-aarch64`, `mm`, `pci`, `virtio`, `store` (FFI) and minimal `kernel` glue, and every block carries a `// SAFETY:` comment (enforced by `clippy::undocumented_unsafe_blocks`).
