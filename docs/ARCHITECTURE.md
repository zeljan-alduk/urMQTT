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
│  store   ─ raw-disk VFS · SQL in Rust · per-core telemetry log · worker proxy    │
│  dbworker ─ SQLite (C, vendored) as an EL0 / ring-3 program (own address space)  │
│  virtio  ─ net · blk · rng      pci ─ ECAM · BARs · MSI-X                        │
│  mm      ─ frames · heap · per-CPU slabs · pools · key slab                      │
│  platform ─ DTB | ACPI → one PlatformInfo       log ─ per-CPU rings → sinks      │
│  arch-aarch64 ─ vectors · MMU (W^X) · GICv3/v2 · timer · PSCI · PAC/BTI · RNDR   │
│  config  ─ compile-time constants + embedded CA / server cert / key              │
└──────────────────────────────────────────────────────────────────────────────────┘
        ▲ UEFI + Limine                 ▲ virtio-pci devices from the hypervisor
```

There is no scheduler, no processes, no filesystem, no shell and no console
input. The one exception to "no processes, no syscalls" is the **database
worker** (section 4b): SQLite runs as an unprivileged program with twelve VFS
system calls (and `exit`), called synchronously by the kernel. The only listening socket is TCP 8883 (plus 1883 in dev
builds only, enforced at build time), and the optional ones an image's configuration turns on, each off by
default: a plaintext MQTT port (P1), a secure WebSocket port (ADR-272) and the Prometheus endpoint (ADR-290: plain
HTTP on 9100, `GET /metrics`, to an allow-list of networks; it has no session, no TLS state and no broker connection,
only a request reader, `urmqtt_broker::metrics::render` over the same `Info` as `$SYS`, and a deadline).

## 2. Boot sequence

1. **UEFI → Limine.** Limine loads the kernel at its fixed higher-half address and hands over a memory map, HHDM offset, framebuffer, DTB and/or RSDP, the MP (CPU) list and the date at boot, and the configuration slot as a module (`/boot/urmqtt.cfg`, pinned by blake2b in the ISO menu).
1b. **Configuration.** The first thing the kernel does: find the module, parse and re-validate the `urmqtt-cfg` blob (`crates/cfg`, ADR-215) and fill the typed `CONFIG` (`crates/config`, in `.bss`, no allocator needed), or stop with the reason; no module means the documented defaults. The heap size, log level and development switches all come from it. The fingerprint and signature state are logged once the console is up. A development kernel is the only build switch (`URMQTT_ENV=dev`); a release kernel refuses development options (ADR-216).
2. **Early console.** The PL011 address comes from the DTB `stdout-path` or the ACPI SPCR table (with a dev fallback). The framebuffer text logger starts.
3. **Exceptions.** The EL1 vector table is installed. Every synchronous exception prints a decoded ESR (exception class, ISS), ELR, FAR and SPSR. A panic logs, then calls PSCI `SYSTEM_RESET` (`SYSTEM_OFF` in smoke mode).
4. **Memory.** The frame allocator is built from the Limine memmap, and the kernel switches to its own translation tables with W^X: `.text` RX, `.rodata` R, everything else RW-NX. Every stack gets a guard page. PAC/BTI are enabled if `ID_AA64ISAR1_EL1` / `ID_AA64PFR1_EL1` report them. After boot the tables are locked: nothing is ever remapped executable.
5. **Platform.** DTB or ACPI tables are reduced to one `PlatformInfo` (CPUs, GIC, timer IRQs, UART, PCIe ECAM, PSCI conduit).
6. **Interrupts, time, entropy.** The GIC comes up (GICv3 distributor and redistributors, or a GICv2 distributor and CPU interface on GIC-400 hosts, ADR-039), along with the generic timer, the CSPRNG seeded from `RNDR` or virtio-rng. With no entropy source, the kernel halts with a clear error.
7. **SMP.** The application processors start (Limine MP or PSCI `CPU_ON`). Per-CPU data lives behind `TPIDR_EL1`.
8. **Devices.** PCIe enumeration, then virtio-blk (data disk), virtio-net (queues per core) and virtio-rng.
8b. **Boot slots** (A/B updates, ADR-295, ADR-296). On the boot disk, right after the GPT first-boot steps: a slot on trial uses one of its attempts, or the boot entry switches back to the previous slot (and the machine resets) when none is left. The DB core later confirms a healthy trial (`update.confirm_after_s` with the store open and a listener up). The kernel writes partition-table sectors only, never an ESP.
9. **Storage.** The data disk superblock is checked, SQLite opens in WAL + `locking_mode=EXCLUSIVE`, `PRAGMA quick_check` runs, and telemetry segments are recovered.
10. **Network.** DHCPv4 (or static), then the TLS listener on 8883.
11. The kernel prints `URMQTT READY`.

**Two architectures, one sequence.** The sequence above is `crates/kernel/src/boot.rs`
for aarch64 *and* x86_64; the differences are small seams in `boot_aarch64.rs`
and `boot_x86.rs` (ADR-059). On x86_64 (QEMU-verified only):

- step 2: COM1 is the console from the first instruction, then the framebuffer;
- step 3: a GDT/TSS/IDT with IST stacks for #DF, NMI, #MC and #PF, and the same decoded report;
- step 4: 4-level tables with NX, WP and SMEP/SMAP/UMIP where the CPU has them, the same W^X audit and locked tables (ADR-056);
- step 5: ACPI only (MADT, FADT, HPET, MCFG, SPCR, `_S5`), ADR-057;
- step 6: the TSC (calibrated against the HPET or the PM timer) and the local APIC timer, x2APIC, I/O APIC, MSI-X through the local APIC (ADR-045); entropy from virtio-rng, RDSEED/RDRAND and the jitter fallback;
- step 7: Limine's MP request, an AP stub that mirrors the boot CPU's control state, per-CPU GDT/TSS (ADR-059);
- step 8: ECAM or configuration mechanism #1 (ADR-058).

One universal ISO boots both architectures (ADR-043); the crypto runs the portable backends on x86 until X9.

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
- The highest-numbered core runs the store, and so the database worker, only. With one CPU, the DB work runs between loop iterations.
- A per-core 10 ms watchdog tick detects a handler that overruns its budget (ADR-013). The budget is **running time**: time the virtual CPU was not scheduled (a tick that arrives long after its deadline, KVM steal time where the host reports it) and time spent waiting for a spin lock are not charged to the handler (ADR-221), so a stalled vCPU does not cost a healthy connection.
- TCP keeps data that arrives beyond a hole (bounded per connection and per core), reports it with SACK, and negotiates window scaling, SACK and timestamps through the SYN cookie, so one lost segment costs one retransmission and a window can cover the bandwidth-delay product (ADR-222). Frames the NIC cannot take yet wait on core 0 instead of being dropped, and QoS 0 loss under overload is counted per cause in `$SYS` (ADR-223).

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
slab** (never compressed, zeroized on free) and, in the database worker's own
address space, a fixed SQLite `memsys5` heap.

## 4b. The database worker (H6, ADR-210 to ADR-212)

SQLite is 254k lines of C that parse a file from the volume. It does not run
in the kernel. `crates/dbworker` is a separate static program (own linker
script, no kernel symbol) that the kernel embeds, loads into frames of its own
and calls synchronously, on the core that owns the store:

```
 kernel (EL1 / ring 0)                          dbworker (EL0 / ring 3)
 ─────────────────────                          ───────────────────────
 db.rs / store.rs  (fixed SQL, Rust)            dispatcher + VFS shim (Rust)
   │  Db / Stmt  → remote.rs (sqlite3_* as RPC)    │
   │                                              SQLite 3.54.1 (C, unchanged)
   │  shared window: header + 1 MiB I/O area ◄──►  its heap (storage.sqlite_heap_mb)
   │  enter user mode (eret / iretq)                 stack, image (W^X), guard page
   ◄─ 12 system calls (VFS, random, time, log) ─────┘
 vfs::syscall → Disk → virtio-blk       exit / fault / 30 s budget → restart
```

- **Address spaces.** aarch64: the worker's tables hang off `TTBR0_EL1`, which is
  disabled (`EPD0`) except while a call runs; user pages are `PXN` always, `UXN`
  except code, non-global, and `PAN` is on for the kernel from the first call.
  x86_64: a second PML4 with the kernel's upper half shared (supervisor only) and
  the worker's lower half, `CR3` switched on entry and on leave; `SMEP` and
  `SMAP` are on, ring-3 entries swap `GS` and clear `EFLAGS.AC`, the I/O
  bitmap is empty. The kernel never dereferences a worker address: data moves
  through the shared window, which the kernel reaches through its own alias.
- **Calls.** One entry into the worker per store operation in the common case
  (binds and resets ride with the step). A call ends on the exit system call, on
  a fault (any exception from user mode: abort, undefined instruction, `#PF`,
  `#GP`, ...) or when it runs past 30 s; the last two restart the worker and the
  kernel reopens the store from the WAL (`open_or_restore`). More than five
  restarts in a minute and the worker is given up on: storage is unavailable until
  the next boot and the broker serves from memory.
- **What the worker can do** is read and write the database, WAL, journal and
  attached backup slot through twelve checked VFS system calls, and return wrong
  answers. See [SECURITY.md](SECURITY.md) for what is and is not isolated.

## 5. TLS

- TLS 1.3 only, with mutual TLS: device certificates must chain to a CA in the image's configuration.
- `device_id` is taken from the configured field (`cn` or `san_uri`), and the MQTT client id must match it.
- The handshake runs through rustls in `no_std` mode with a pure-Rust crypto provider. Admission control is a per-core token bucket plus handshake limits per core and per source address, and one table shared by all cores that bounds the established connections of a source address (`limits.max_connections_per_ip`, ADR-280: checked at the SYN, counted at the final ACK before a token is taken, given back in the one function every close path ends in). Every handshake phase has a timeout. Resumption uses PSK tickets.
- After the handshake the traffic keys are extracted and the rustls object is dropped. A minimal record layer (AES-128-GCM, ChaCha20-Poly1305) decrypts in place and encrypts directly into TX buffers (KeyUpdate: ADR-012).
- Revoked serials are stored in SQLite and mirrored read-only on every data core. A handshake never waits for the DB.

## 6. Broker

- MQTT 3.1.1 and 5.0 (5.0 since ADR-274: the CONNECT's protocol level picks the codec per connection, one
  version-neutral broker core; properties travel with the message's `Arc` across cores; session and message expiry,
  will delay, flow control, topic aliases from the client, subscription options; since ADR-275 subscription
  identifiers and shared subscriptions). QoS 0, 1 and 2 (QoS 2 since ADR-271: method B, the session's home core holds
  the packet ids, fan-out to other cores is an ordinary routed message).
- Supported packets and features: CONNECT/CONNACK, PUBLISH/PUBACK, PUBREC/PUBREL/PUBCOMP, SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP, DISCONNECT, wildcards `+` and `#`, retained messages, LWT, clean and persistent sessions with bounded offline queues.
- Topic interning: each core has a topic trie, and sessions store 32-bit node ids. Fan-out to other cores sends a compact routing message (payload handle + topic id), guided by a "which cores have subscribers" bitmask per node.
- Reconnects to a different core go through the session directory (ADR-011).
- Shared subscriptions (`$share/{group}/{filter}`, ADR-275): a group is (role class, group, filter) and lives on one
  owner shard chosen by a hash of the three. Every message already reaches every shard, so the owner sees it once and
  hands it round robin to one online member; the member's shard delivers it (`CoreMsg::Shared` carries the message's
  `Arc`). A SUBSCRIBE whose group lives on another shard holds its SUBACK and the connection's next packets until the
  owner has the member; a delivery that finds its member gone goes back to the owner for another.
- Password accounts added at run time (NOW-15, ADR-285 to ADR-287): the signed control channel's `set-account` and
  `remove-account` are applied on the DB core in one transaction with the sequence number (store schema 6, table
  `accounts`, hashes only), published with the revocations and the allowlist under the same epoch, and picked up by every
  data core's plaintext and WebSocket authenticator (`Authenticator::set_runtime`, image accounts first). An account's
  class (full, read-only, write-only) is asked by the broker at each publish, Will and SUBSCRIBE of a login session
  (`Broker::set_login_class`) and only narrows the listener's patterns; a removed or changed account's live logins are
  closed.
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
