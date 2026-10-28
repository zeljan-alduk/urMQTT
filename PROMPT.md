# ukmq — ARM64 unikernel with an integrated MQTT broker

> Working name: **ukmq** (unikernel MQTT). Rename freely.
> This document is the full specification and working agreement for implementing the project.
> Read it completely before writing any code. Keep it in the repo root and follow it as the source of truth.

---

## 0. How you (the agent) must work

1. **Communicate with the user in Croatian.** Code, comments, commit messages, docs and identifiers are in English.
2. **Work milestone by milestone** (section 9). Do not start a milestone before the previous one meets all of its acceptance criteria. After each milestone:
   - run `make check` (fmt, clippy, host tests) and `make smoke` (boot in QEMU + automated checks),
   - commit with a message `M<n>: <summary>`,
   - append a short entry to `docs/PROGRESS.md` (what was done, what was measured, known gaps),
   - stop and report to the user in Croatian: what works, how to run it, what is next. Wait for confirmation before the next milestone unless the user said to continue autonomously.
3. **Record every non-obvious decision** in `docs/DECISIONS.md` as a short ADR (context, decision, alternatives, consequences). Examples: choice of crypto provider, GIC version handling, how RSS fallback works.
4. **Verify, don't assume.** Crate `no_std` support, QEMU/HVF features, Limine protocol details and rustls APIs change over time. Before relying on any of them, check the current docs/source and prove it by building and running. If something in this spec turns out to be impossible or wrong, say so, propose an alternative, and record it in `DECISIONS.md`. Do not silently diverge.
5. **Never fake progress.** No stubbed functions presented as done, no tests that assert nothing, no "TODO: implement" in code paths a milestone claims to cover. If something is stubbed on purpose, it must return an explicit error and be listed in `PROGRESS.md`.
6. **Keep the build reproducible:** pinned toolchain (`rust-toolchain.toml`), committed `Cargo.lock`, `--locked` everywhere, vendored or hash-pinned external artifacts (Limine, SQLite amalgamation).
7. Prefer small, reviewable commits. Do not reformat unrelated code.

---

## 1. Product goal

A **single bootable ISO** that runs in a VM and *is* an MQTT broker for IoT devices. There is no general-purpose OS underneath: the kernel, network stack, TLS, MQTT broker and embedded database are one Rust binary (a unikernel).

Primary goals, in priority order:

1. **Security**: minimal attack surface. One public TCP port (8883, MQTT over TLS with client certificates). No shell, no console, no SSH, no remote management, no dynamic code loading, no writable code, no filesystem exposed to the network.
2. **Scale**: millions of mostly idle, long-lived device connections per VM. Target memory per idle TLS connection: **≤ 512 bytes** (stretch: ~256 B).
3. **Multicore performance**: native SMP, thread-per-core, shared-nothing, run-to-completion data path.
4. **Minimal footprint**: kernel image (without SQLite) ideally < 1 MB; whole VM must boot and serve with 64 MB RAM (more RAM = more connections).
5. **Immutable deployment**: code, configuration, CA certificate and server TLS key are compiled into the ISO. A new version = a new ISO. Persistent data lives on a separate virtio-blk data disk.

---

## 2. Hard constraints

- **Architecture: aarch64 only.** Target `aarch64-unknown-none` (kernel), `#![no_std]`, `#![no_main]`. No x86 code anywhere.
- **Language:** Rust for everything except the vendored SQLite amalgamation (C). Minimal `unsafe` (see section 8).
- **Boot:** Limine bootloader, UEFI on aarch64, hybrid-free UEFI ISO. Use the `limine` crate for the boot protocol.
- **Hardware model (virtual):**
  - Dev: QEMU `virt` machine (device tree), GICv3, PCIe ECAM, virtio-pci devices.
  - Prod target: ARM cloud VMs (e.g. Hetzner CAX / Ampere, KVM based) which describe hardware via **ACPI** (MADT, GTDT, MCFG, SPCR) and expose **virtio-pci** devices.
  - The kernel **must support both DTB and ACPI** discovery behind one abstraction.
- **Devices to support:** PL011 UART (dev logging), Limine framebuffer (text log, for providers whose web console shows only video), GICv3 (+ ITS optional later), ARM generic timer, PSCI (via HVC or SMC as described by firmware), virtio-pci modern transport: virtio-net, virtio-blk, virtio-rng.
- **No console input of any kind.** Output-only logging.
- **Deployment artifact:** `build/ukmq-<env>-<version>.iso`. Optionally also a raw disk image (`.img`) for providers that only accept disk images.

---

## 3. Development environment (host: macOS on Apple Silicon, M4 Pro)

The developer runs macOS on an Apple M4 Pro. Everything must build and run there.

- Rust via `rustup`, toolchain pinned in `rust-toolchain.toml` (choose current stable unless a feature needs nightly; document why if nightly). Components: `rust-src`, `llvm-tools`, `clippy`, `rustfmt`; target `aarch64-unknown-none`.
- Homebrew packages: `qemu`, `xorriso`, `llvm` (clang for compiling SQLite for bare metal), `mosquitto` (test clients), `aarch64-elf-gdb` or use `lldb`.
- QEMU with **HVF acceleration** (`-accel hvf -cpu host`). Also support `-accel tcg -cpu max` as a fallback (CI on Linux, or features HVF lacks).
- UEFI firmware: `edk2-aarch64-code.fd` shipped with Homebrew QEMU (locate it via `brew --prefix qemu`).
- **Verify early (M1/M3):** whether QEMU+HVF on this macOS version accepts `gic-version=3`. If not, record it, use TCG for GICv3 testing and consider adding GICv2 support for local HVF runs. Cloud targets are GICv3, so GICv3 is mandatory; GICv2 is optional.
- Networking for dev: QEMU user networking (`-netdev user,...,hostfwd=tcp::1883-:1883,hostfwd=tcp::8883-:8883`). For load tests use `vmnet-shared` (needs sudo) or a Linux host with tap + KVM; document the limits of user networking.

### Makefile targets (required)

| Target | Does |
|---|---|
| `make build` | builds the kernel ELF (release, LTO, `panic = "abort"`) |
| `make iso ENV=dev` | builds the bootable ISO with config/certs for `deploy/<ENV>/` |
| `make run` | boots the ISO in QEMU (HVF, 4 vCPU, 512 MB, virtio-net, virtio-blk data disk, virtio-rng), serial on stdio |
| `make run-tcg` | same but TCG |
| `make run-smp N=8` | configurable vCPU count |
| `make debug` | QEMU with `-s -S`, prints how to attach gdb/lldb |
| `make data-img` | creates/initializes the data disk image |
| `make check` | `cargo fmt --check`, `cargo clippy -D warnings`, host unit tests for all host-testable crates |
| `make fuzz T=<target>` | runs a cargo-fuzz target for a bounded time |
| `make smoke` | boots headless, waits for `UKMQ READY` on serial, runs automated client checks, shuts down, exit code reflects result |
| `make loadtest` | runs the load generator (section 10) |

Example run command (adjust after verification):

```bash
qemu-system-aarch64 \
  -machine virt,gic-version=3 -accel hvf -cpu host -smp 4 -m 512M \
  -bios "$(brew --prefix qemu)/share/qemu/edk2-aarch64-code.fd" \
  -cdrom build/ukmq-dev.iso \
  -drive if=none,id=data0,file=build/data.img,format=raw,cache=none \
  -device virtio-blk-pci,drive=data0 \
  -netdev user,id=n0,hostfwd=tcp::1883-:1883,hostfwd=tcp::8883-:8883 \
  -device virtio-net-pci,netdev=n0,mq=on,vectors=10 \
  -device virtio-rng-pci \
  -serial stdio -display none -no-reboot
```

---

## 4. Architecture

### 4.1 Execution model

- **Thread-per-core, shared-nothing.** Every CPU runs its own event loop with its own: network queue pair, TCP state, connection table, session table, slab allocators, timer wheel, telemetry log segment, metrics counters.
- **Run-to-completion** data path: a received packet is processed fully (TCP → TLS decrypt in place → MQTT parse → route → enqueue/encrypt outgoing → TX) on the same core, without task queues or copies into "application buffers".
- **Cooperative within a core**, preemptive only via interrupts. Interrupt handlers only acknowledge and mark work; processing happens in the core loop.
- **Adaptive polling:** busy-poll RX queues under load; fall back to interrupts + `WFI` when idle (configurable thresholds).
- **Cross-core communication** only via bounded lock-free SPSC rings (one per ordered core pair) for: cross-core fan-out, DB requests/responses, control events. Document memory orderings for every atomic (ARM is weakly ordered; this matters).
- **Dedicated DB core:** the highest-numbered CPU (when ≥ 2 CPUs) runs SQLite and nothing else on the data path. With 1 CPU, the DB runs on the same core between event-loop iterations.
- **Watchdog:** per-core generic-timer tick (e.g. 10 ms) detects a handler running too long; logs core, connection id and phase; configurable action (log / drop connection / reset VM).

### 4.2 Crate layout (Cargo workspace)

```
ukmq/
  rust-toolchain.toml
  Cargo.toml                (workspace, shared profile: lto, codegen-units=1, panic=abort, opt-level=3)
  Makefile
  PROMPT.md                 (this file)
  docs/  PROGRESS.md  DECISIONS.md  ARCHITECTURE.md  DEPLOY.md  SECURITY.md
  deploy/
    dev/   config.toml  ca.pem  server.pem  server.key   (dev certs generated by script; prod secrets gitignored)
    prod/  config.toml  (certs/keys NOT committed)
  scripts/  gen-dev-certs.sh  mkiso.sh  smoke.sh  run-qemu.sh
  vendor/   limine/  sqlite/   (pinned, with checksums)
  crates/
    arch-aarch64/   boot glue, exception vectors (EL1), MMU/page tables, GICv3, generic timer,
                    PSCI, per-CPU data (TPIDR_EL1), PAC/BTI enablement, cache/barrier helpers, RNDR
    platform/       hardware discovery abstraction over DTB (fdt parsing) and ACPI (MADT/GTDT/MCFG/SPCR)
    mm/             physical frame allocator, kernel heap, per-CPU slab allocators, buffer pools
    pci/            PCIe ECAM enumeration, BAR setup, MSI-X
    virtio/         virtio-pci modern transport, virtqueues (split; packed optional), net, blk, rng
    log/            lock-free per-CPU log rings → UART/framebuffer/UDP syslog sinks
    timer-wheel/    hierarchical timing wheel (no_std, host-testable)
    net/            Ethernet/ARP/IPv4/ICMP/DHCPv4 (+ IPv6/SLAAC later); dispatch to TCP
    tcp/            server-only TCP stack (no_std, host-testable)
    tls/            TLS 1.3 server: handshake via rustls (no_std), then minimal record layer
    mqtt/           MQTT 3.1.1 (then 5.0) zero-copy parser/encoder (no_std, no unsafe, host-testable)
    broker/         sessions, topic tree (interned), subscriptions, routing, QoS, retained, LWT, ACL, limits
    store/          SQLite FFI + VFS over virtio-blk, telemetry log, data disk layout
    config/         build-time config schema + build.rs that turns deploy/<env>/config.toml into consts
    kernel/         the binary: boot sequence, core loop, wiring of all crates, panic handler
  tools/
    loadgen/        host-side MQTT/TLS load generator (std, tokio OK here)
    certgen/        optional helper for device/test certificates
  fuzz/             cargo-fuzz targets (mqtt parser, tcp segment handling, tls records, config parsing)
```

**Host-testability rule:** `timer-wheel`, `tcp`, `mqtt`, `broker`, `tls` (record layer), `net` (packet parsing), `config` must compile for the host with `cargo test` on macOS. Hardware access is behind traits so these crates never touch registers. `broker` must be testable end-to-end over an in-memory transport.

### 4.3 Memory map and protection

- Use Limine's HHDM and memory map. Kernel at a fixed higher-half address.
- **W^X everywhere:** `.text` RX, `.rodata` R, `.data/.bss/heap/stacks` RW-NX. Lock page tables after boot (no runtime remapping as executable, ever).
- Guard pages below every stack.
- **Enable PAC (pointer authentication) and BTI** if the CPU reports them (`ID_AA64ISAR1_EL1`, `ID_AA64PFR1_EL1`); build with `-Z branch-protection=pac-ret,bti` or the stable equivalent if available (verify; record in DECISIONS). Kernel must still boot on CPUs without them.
- **MTE:** optional, only if available and only for the SQLite heap region; never required.
- Separate memory regions: kernel heap, per-CPU slabs, packet buffer pools, **crypto key slab** (never compressed, zeroized on free), SQLite heap (fixed region for `memsys5`).
- Prefer 4 KiB pages initially; design so 64 KiB or block mappings can be used for large pools later.

---

## 5. Networking

### 5.1 Phase A (prototype): smoltcp

- Use `smoltcp` + `virtio-drivers` (or own virtio) to get DHCPv4, ARP, ICMP echo and TCP working fast. MQTT over plain TCP 1883 in dev only.
- Single RX/TX queue, single core handles the NIC; other cores idle. This phase exists to validate drivers, boot, broker logic and tooling. It is **not** the final design.

### 5.2 Phase B (final): own server-only TCP stack

Requirements for `crates/tcp`:

- Server side only: passive open, no client connects, no routing, no IP forwarding.
- Per-core connection table: open-addressing hash on 4-tuple, O(1) lookup, no iteration over all connections on any hot path.
- Compact per-connection struct (target ≤ 64–96 B for TCP state): 32-bit indices instead of pointers, bit-packed flags, timers as wheel slots.
- **No per-connection buffers while idle.** RX: segments are processed in place from the NIC buffer; only incomplete MQTT frames retain a pooled buffer. TX: pooled buffers only while data is unacknowledged.
- Hierarchical timing wheel for retransmission, persist, keepalive/idle, TIME_WAIT (TIME_WAIT stored minimally or avoided via server-side RST policy; document choice).
- **SYN cookies** always on; no state for half-open connections.
- Congestion control: start with NewReno; keep pluggable.
- Window management tied to broker backpressure (shrink window when a session's inbound queue is full).
- **ACK coalescing with application replies**: when the broker produces a PUBACK/CONNACK/PINGRESP, send it in the same segment as the TCP ACK.
- TCP keepalive disabled; MQTT keepalive is the single liveness mechanism.
- Strict input validation: drop IP options, fragments (configurable), unknown protocols, malformed headers; rate-limit RST/ICMP responses.
- IPv4 first; IPv6 + SLAAC as a later milestone.
- DHCPv4 client (and static config option from build-time config). One ISO must work on many VMs, so DHCP is the default.

### 5.3 Multicore NIC

- virtio-net with **multiqueue**: one RX/TX pair per data-plane core, MSI-X vector per queue routed to its core (GICv3 ITS or per-device MSI mapping; verify what QEMU and target clouds provide).
- If `VIRTIO_NET_F_RSS` (or hash report) is available: program RSS so a 4-tuple always lands on the same core.
- **Fallback dispatcher** (very likely on cloud VMs): core 0 owns the single RX queue, computes a Toeplitz-like hash of the 4-tuple and forwards packet descriptors (not copies) through SPSC rings to the owning core. TX goes out through per-core TX queues if available, else via a TX ring back to the queue owner.
- Choose mode at boot from feature bits; log the chosen mode.

---

## 6. TLS

- TLS 1.3 only (TLS 1.2 optional later, off by default). Port 8883.
- **Mutual TLS:** devices present X.509 client certificates signed by the CA compiled into the ISO. Device identity = a configured field (e.g. CN or a SAN URI) → normalized `device_id`.
- Revocation: revoked serials live in SQLite; each data core keeps a read-only in-memory set (hash set / bloom + exact set), refreshed via a control message from the DB core. Handshake never waits for the DB.
- Handshake via **rustls in no_std mode** with a pure-Rust crypto provider. Verify current rustls `no_std` support and pick a provider (e.g. a RustCrypto-based provider); record the choice. Randomness: ARM `RNDR` if available, else virtio-rng, feeding a CSPRNG (e.g. ChaCha20-based). Never boot without an entropy source: halt with a clear error.
- **After the handshake**, extract traffic secrets (rustls exposes secret extraction for kTLS-style offload; verify the current API) and **drop the rustls connection object**. Continue with a minimal in-house TLS 1.3 record layer (AES-128-GCM and ChaCha20-Poly1305, sequence numbers, key update handling). Per-connection TLS state target: ≤ 128 B, stored in the crypto key slab.
- Decrypt in place in the RX buffer; encrypt directly into TX buffers.
- Handshake **admission control** per core (token bucket) to survive reconnect storms; TLS 1.3 **session resumption** (PSK tickets) with a ticket key from build-time config, rotated by version.
- Never compress before encryption.
- Timeouts for every handshake phase.

---

## 7. MQTT broker

### 7.1 Protocol scope

- MQTT **3.1.1 first** (milestone), **5.0 next** (properties, reason codes, session expiry, topic aliases, receive maximum, maximum packet size).
- QoS 0 and 1 required; QoS 2 later (document if deferred).
- Features: CONNECT/CONNACK, PUBLISH, PUBACK, SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP, DISCONNECT, wildcards `+` and `#`, retained messages, Last Will and Testament, clean session / persistent sessions with queued QoS 1 messages for offline clients (bounded).
- **Client ID** must equal (or be derived from) the certificate `device_id`; mismatch → reject.

### 7.2 Parser (`crates/mqtt`)

- `#![no_std]`, **`#![forbid(unsafe_code)]`**, zero-copy (borrows from the input buffer), streaming-friendly (returns `Incomplete(needed)`), never panics on any input, all lengths bounded by configured maximums **before** any allocation.
- Exhaustive tests against the spec, property tests (encode → decode roundtrip), fuzz target, and interop tests with `mosquitto_pub/sub`.

### 7.3 Broker core (`crates/broker`)

- **Topic interning:** per-core topic trie; sessions store 32-bit node ids, not strings. Device-scoped topics (`devices/{device_id}/...`) use the session's own id instead of storing the string.
- Subscriptions: per-core subscription index for local sessions. Cross-core fan-out: publish is routed locally, and a compact routing message (refcounted payload handle + topic id) is sent to other cores that have matching subscribers. Maintain a global, eventually-consistent "which cores have subscribers for which topic node" summary (bitmask per node) to avoid broadcasting to all cores.
- Payloads: stored once, refcounted, shared across subscribers; encrypted per connection at send time.
- **ACL:** default policy — device may publish only to `devices/{device_id}/#` and subscribe only to `devices/{device_id}/cmd/#` (configurable patterns in build-time config). Backend/service identities (separate CA or cert attribute) may have wider rights. ACL evaluation must not hit the DB.
- **Limits** (all configurable): max packet size, max topic length/levels, max subscriptions per session, max inflight QoS1, max queued messages per offline session, publish rate per device (token bucket), connections per core.
- Session state target (idle, typical device, 1–2 subscriptions): ≤ 64 B in hot form.
- Optional later: **cold tier** — sessions idle longer than N seconds have their compressible parts (subscriptions, queued messages, session metadata) compacted/compressed (LZ4 or zstd with a trained dictionary) into a cold region; TCP/TLS core state stays uncompressed. Only implement after measurements show it pays off.

### 7.4 Persistence

- Telemetry: every accepted PUBLISH on telemetry topics (configurable pattern) is appended to the owning core's **telemetry log** (append-only segments on the data disk, batched writes, CRC per record, recovery on boot). Retention policy by age/size. Optional time-series encoding (delta-of-delta timestamps, XOR floats) when payload format is known; otherwise store raw with optional zstd dictionary compression per segment.
- Device registry, revocation list, retained messages, persistent sessions: **SQLite** on the DB core.
- Export: a later milestone defines how data leaves the box (e.g. a bridge topic consumed by a backend service identity, or batch export). Do not add a general query interface over the network.

---

## 8. SQLite inside the kernel

- Vendor the official SQLite amalgamation (pin version + SHA3/SHA256 in `vendor/sqlite/CHECKSUMS`).
- Compile in `crates/store/build.rs` with the `cc` crate using Homebrew clang for target `aarch64-unknown-none` with flags that match the kernel ABI (e.g. `-ffreestanding -fno-builtin -fno-stack-protector -mgeneral-regs-only` if the kernel does not save FP/SIMD state in exceptions — **decide and document FP/SIMD policy for the whole kernel**; SQLite uses floating point, so FP must be enabled at least on the DB core).
- Compile-time options (verify each against the SQLite version used):
  `SQLITE_OS_OTHER=1`, `SQLITE_THREADSAFE=0`, `SQLITE_ENABLE_MEMSYS5`, `SQLITE_TEMP_STORE=3`, `SQLITE_DEFAULT_MEMSTATUS=0`, `SQLITE_DQS=0`, `SQLITE_OMIT_LOAD_EXTENSION`, `SQLITE_OMIT_ATTACH`, `SQLITE_OMIT_SHARED_CACHE`, `SQLITE_OMIT_DEPRECATED`, `SQLITE_OMIT_LOCALTIME`, `SQLITE_OMIT_PROGRESS_CALLBACK`, `SQLITE_OMIT_AUTHORIZATION` (only if unused), `SQLITE_MAX_EXPR_DEPTH=0` (optional), `SQLITE_USE_ALLOCA` (no — keep stack usage bounded).
- Provide the small set of libc symbols SQLite needs (`memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, `strncmp`, `strcspn`, … — derive the exact list from linker errors) in Rust with `#[no_mangle] extern "C"`, or via `compiler_builtins` mem functions.
- Memory: `sqlite3_config(SQLITE_CONFIG_HEAP, region, size, min)` with a dedicated region (size from config, default 32 MB); optional `SQLITE_CONFIG_PAGECACHE`.
- **VFS over raw virtio-blk**, no filesystem. Data disk layout:
  ```
  [superblock: magic, layout version, uuid, region table, CRC]
  [region: sqlite main db]
  [region: sqlite WAL]
  [regions: telemetry log, one per core (or a shared ring partitioned by core)]
  ```
  VFS methods: xOpen (maps names to regions), xRead/xWrite (bounds-checked), xSync → virtio-blk FLUSH (require `VIRTIO_BLK_F_FLUSH`; refuse to run without it unless config explicitly allows unsafe mode), xFileSize, xTruncate (logical), xLock/xUnlock (no-op, single owner), xRandomness (CSPRNG), xCurrentTime(Int64), xSleep (spin/timer), xSectorSize, xDeviceCharacteristics (be conservative).
- Use **WAL mode with `PRAGMA locking_mode=EXCLUSIVE`** so no shared-memory index (`xShmMap`) is needed — verify.
- Rust side: thin hand-written or bindgen-generated FFI and a safe wrapper (`Db`, `Stmt`, typed binds/columns). `rusqlite` is not usable (needs std).
- **All SQL is fixed at compile time**, prepared at boot. No SQL ever comes from the network. Enable `SQLITE_DBCONFIG_DEFENSIVE`.
- Writes from data cores are batched into transactions on the DB core (e.g. every 5–10 ms or N ops).
- On boot: `PRAGMA quick_check`; on failure log clearly and refuse to serve (configurable).
- **Isolation (later milestone):** run the DB core's SQLite at EL0 with its own translation tables mapping only its heap, its rings and its VFS bounce buffers, or use MTE tagging if available. Measure the overhead and document.

---

## 9. Milestones and acceptance criteria

Each milestone ends with `make check` and `make smoke` green and a report to the user.

**M0 — Workspace and tooling**
- Workspace with all crates as stubs that compile; `rust-toolchain.toml`; Makefile targets exist (unimplemented ones print a clear message); `scripts/gen-dev-certs.sh` generates a dev CA, server cert and 3 device certs; `docs/` files created; CI-friendly `make check`.
- Accept: `make check` passes on macOS.

**M1 — Boot**
- Limine UEFI ISO for aarch64; kernel entry in Rust; early PL011 output (address from DTB/SPCR, with a dev fallback); framebuffer text logger; exception vector table that prints ESR/ELR/FAR and the exception class; panic handler logs and calls PSCI `SYSTEM_RESET` (or `SYSTEM_OFF` in smoke mode).
- Prints `UKMQ BOOT <version> cpu=<n> mem=<MB>`.
- Accept: boots under HVF and TCG; a deliberate test fault shows a decoded exception report.

**M2 — Memory**
- Frame allocator from Limine memmap; own page tables with W^X; HHDM handling; kernel heap (`GlobalAlloc`); guard pages; PAC/BTI enabled when present (log which).
- Accept: unit/host tests for allocator logic; boot-time self-test allocates/frees and verifies W^X (writing to `.text` faults, executing heap faults — via a test mode flag).

**M3 — Interrupts and time**
- GICv3 distributor/redistributor/CPU interface (system registers); generic timer per core; monotonic clock; timer interrupts; documented HVF GIC findings.
- Accept: periodic tick logs on one core; latency of timer IRQ measured and logged.

**M4 — SMP**
- Bring up all CPUs (Limine MP response or PSCI `CPU_ON`); per-CPU data via `TPIDR_EL1`; per-core idle with `WFI`; SGI-based IPIs; per-core timer.
- Accept: `make run-smp N=8` prints one line per core; IPI ping-pong test between all core pairs passes.

**M5 — Platform discovery**
- `platform` crate: DTB path (QEMU) and ACPI path (MADT, GTDT, MCFG, SPCR). Same output struct either way (CPUs, GIC, timer IRQs, UART, PCIe ECAM).
- Accept: QEMU booted with and without ACPI (`-machine virt,acpi=on|off`) produces identical platform summaries.

**M6 — PCIe and virtio**
- ECAM enumeration, BARs, MSI-X; virtio-pci modern transport; virtio-rng → CSPRNG seeded; virtio-blk read/write/flush; virtio-net single queue RX/TX.
- Accept: blk self-test writes, flushes, reads back a pattern on the data disk; net sends a gratuitous ARP visible in a QEMU pcap (`-object filter-dump`).

**M7 — Network prototype (smoltcp)**
- DHCPv4, ARP, ICMP echo, TCP echo service on a dev port; logs IP lease.
- Accept: `smoke.sh` pings the guest (where possible) and gets an echo over TCP via hostfwd.

**M8 — MQTT codec**
- `crates/mqtt` 3.1.1 complete per 7.2 with tests, property tests and a fuzz target.
- Accept: `cargo test -p mqtt` green; `make fuzz T=mqtt_decode` runs 10 minutes with no crash.

**M9 — Broker over plain TCP (dev only, port 1883)**
- Broker core per 7.3 (single core, smoltcp), QoS 0/1, wildcards, retained, LWT, keepalive, limits; dev-mode identity from client ID (TLS comes in M10).
- Accept: `smoke.sh` runs `mosquitto_sub`/`mosquitto_pub` through hostfwd: pub/sub, wildcard, retained, LWT on forced disconnect, QoS 1 redelivery after reconnect. Host-side broker tests over in-memory transport.

**M10 — TLS 1.3 with mTLS (port 8883)**
- rustls no_std handshake, client-cert verification against baked-in CA, device identity → client ID enforcement, secret extraction + own record layer, resumption, admission control. Disable port 1883 in non-dev builds.
- Accept: `mosquitto_pub --cafile ... --cert ... --key ...` works; wrong CA, expired cert, client-ID mismatch and revoked cert are all rejected (test each).

**M11 — SQLite in kernel**
- Build integration, libc shims, memsys5 heap, raw-disk VFS, WAL exclusive mode, DB core with SPSC request/response rings, schema + migrations (embedded), device registry, revocation list, retained messages, persistent sessions.
- Accept: data survives VM restart; `quick_check` on boot; batched writes measured (ops/s logged); kill -9 QEMU during writes then reboot → DB consistent.

**M12 — Telemetry log**
- Per-core append-only segments, CRC, batching, recovery, retention.
- Accept: 1M messages written across cores, VM killed mid-write, reboot recovers all fully-flushed records and truncates torn tail.

**M13 — Multicore data plane**
- Per-core event loops serving connections; virtio-net multiqueue + RSS where available; fallback dispatcher; per-core slabs and buffer pools; cross-core fan-out.
- Accept: throughput scales near-linearly from 1 → 2 → 4 cores in a documented benchmark; fallback mode tested by disabling mq.

**M14 — Own TCP stack**
- Replace smoltcp in the data path per 5.2 (smoltcp may remain only if needed for DHCP; prefer own DHCP).
- Accept: all previous smoke tests pass; `tcp` crate host tests incl. retransmission/timeouts with simulated loss; fuzz target for segment processing.

**M15 — Memory per connection**
- Compact structs, topic interning, key slab; measurement endpoint in logs: bytes per idle connection.
- Accept: report measured bytes/idle TLS connection at 10k, 100k, 1M (where host allows); target ≤ 512 B; `size_of` assertions in tests to catch regressions.

**M16 — Hardening and ops**
- Watchdog actions, rate limits everywhere, metrics pushed via UDP (statsd or syslog) to a configured private collector, health/self-check, structured logs, fuzzing in CI for all parsers, `docs/SECURITY.md` threat model.
- Accept: documented threat model; reconnect-storm test (e.g. 100k clients reconnect at once) survives without OOM.

**M17 — Deployment**
- `make iso ENV=prod` reproducible (same commit → bit-identical ISO; verify by building twice); optional raw disk image; checksum + signature (e.g. minisign) of artifacts; `docs/DEPLOY.md` for Hetzner CAX (ISO via support, or image upload) and a generic KVM/Proxmox host.

Later (only after the above): MQTT 5.0, QoS 2, IPv6, cold-session compression, SQLite EL0 isolation, export bridge, ACPI-only cloud validation on real ARM VMs.

---

## 10. Testing and benchmarking

- **Host unit tests** for all host-testable crates; **property tests** (`proptest`) for codecs; **fuzzing** (`cargo-fuzz`, nightly allowed for fuzz only) for mqtt, tcp segment input, tls records, config parsing, DTB/ACPI parsers.
- **Smoke tests** (`scripts/smoke.sh`): boot headless, wait for `UKMQ READY`, run client scenarios, collect serial log, power off via PSCI, non-zero exit on any failure.
- **Load generator** (`tools/loadgen`, std + tokio allowed): opens N TLS MQTT connections with device certs (pre-generated pool), configurable connect rate, keepalive, publish rate, subscribe patterns, multiple source IPs. Reports connections established, failures, memory reported by the broker, latency percentiles.
- Note for the user: macOS + QEMU user networking cannot reach millions of connections; for ≥100k use `vmnet-shared` or a Linux host with KVM/tap and several client IPs. Document exact limits observed.
- Comparison benchmark (later): same ARM VM size running Mosquitto or EMQX on Linux vs ukmq; publish methodology and raw numbers.

---

## 11. Code rules

- `unsafe` allowed only in: `arch-aarch64`, `mm`, `pci`, `virtio`, `store` (FFI), and minimal glue in `kernel`. Every `unsafe` block has a `// SAFETY:` comment. `#![forbid(unsafe_code)]` in `mqtt`, `broker`, `timer-wheel`, `config`; `#![deny(unsafe_code)]` with justified exceptions elsewhere.
- **No panics on external input.** No `unwrap`/`expect`/indexing that can panic on data derived from the network or disk. Use `clippy::unwrap_used`, `clippy::expect_used`, `clippy::indexing_slicing` (deny) in data-path crates.
- **No allocation in the hot path** after a connection is established, except from per-core slabs/pools with fixed size classes. Allocation failure must be handled (reject/close), never panic.
- All limits come from `config` constants; no magic numbers in logic.
- Data-path types are `!Send`/`!Sync` by default (per-core); cross-core types are explicit and minimal.
- Atomics: every `Ordering` choice has a comment explaining why.
- Logging: structured, rate-limited, never logs secrets, keys, full certificates or payloads (payload logging only behind a dev-only flag).
- Keep binary size in check: report kernel ELF size per milestone in `PROGRESS.md`.

---

## 12. Build-time configuration

`deploy/<env>/config.toml` is parsed by `crates/config/build.rs` into typed Rust constants. Invalid config must fail the build with a clear message. Example keys:

```toml
[network]
mode = "dhcp"              # or "static"
# address = "10.0.0.10/24", gateway = "10.0.0.1"
mqtt_tls_port = 8883
mqtt_plain_port = 0        # 0 = disabled (dev may set 1883)

[tls]
ca = "ca.pem"
cert = "server.pem"
key = "server.key"
identity_field = "cn"      # or "san_uri"
resumption = true

[limits]
max_connections_per_core = 2000000
max_packet_size = 4096
max_topic_len = 256
max_subscriptions_per_session = 8
max_inflight_qos1 = 16
max_queued_per_offline_session = 64
publish_rate_per_device = "10/s"
handshakes_per_core_per_sec = 2000

[acl]
device_publish = ["devices/{id}/#"]
device_subscribe = ["devices/{id}/cmd/#"]

[storage]
sqlite_heap_mb = 32
telemetry_topics = ["devices/+/telemetry/#"]
retention_days = 30
require_flush = true

[observability]
log_level = "info"
syslog_udp = ""            # "10.0.0.5:514" for a private collector
metrics_udp = ""           # statsd

[watchdog]
handler_budget_ms = 10
action = "log"             # "log" | "drop" | "reset"
```

Certificates and keys are embedded with `include_bytes!`. Production secrets are never committed (`.gitignore` covers `deploy/prod/*.key`, `*.pem` except explicitly allowed public CA files).

---

## 13. Definition of done (project level, v1)

- One command produces a reproducible, signed ARM64 ISO.
- Boots in QEMU (HVF and TCG) and on a KVM-based ARM cloud VM via ACPI.
- Serves MQTT 3.1.1 over TLS 1.3 with mTLS, QoS 0/1, retained, LWT, persistent sessions, ACL.
- Persists device registry, revocations, retained messages, sessions (SQLite) and telemetry (log) across restarts and crashes.
- Scales across cores; measured bytes per idle connection ≤ 512 B.
- All parsers fuzzed; threat model documented; no console, no shell, one public port.

Start with **M0**. Before writing code, reply (in Croatian) with: your understanding of the goal in 5–8 bullet points, any spec items you believe are risky or wrong, and the exact plan for M0–M1.
