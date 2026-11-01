## PERF/ROBUST — single flow, QoS 0 overload and the watchdog (2026-11-01)

Goal set after X11: find and fix the causes behind its findings. Decisions ADR-214 to ADR-217; numbers, method and the honest list of what is
left in `docs/PERFORMANCE.md` section 7; raw files `docs/perf-results/urmqtt-x11v-{before,after,step-*}.txt`, `mosquitto-x11v-same-session.txt`,
`local-wan-rig.txt`.

**Causes found (with evidence in PERFORMANCE.md 7.1)**

- A **lost wake-up** in `MqttService::poll` (the drained ready list overwrote the connections just put back): a subscriber that fell behind once was never served again, QoS 0 to it was dropped until a PINGRESP - "delivered 0/s" in 4 of 6 single-flow runs on the VPS. Fixed.
- **TCP threw away every segment after a loss** (in-order receive only), had a 16 bit window, a 64 KiB send queue and counted ACKs instead of bytes. Now: bounded out-of-order queue per connection and per core, SACK blocks, window scaling / SACK / timestamps through the SYN cookie (options in the low bits of our timestamp value; stateless until the final ACK), send queue = 2 x cwnd up to 1 MiB, byte-counting congestion window. Host tests (16 new), fuzz target extended (2 M runs clean), H3 model test unchanged and passing.
- The **dispatcher slept until the 10 ms tick** (no RX interrupt on virtio-net): 0-10 ms per pause. Now polls every 200 us while connections exist (ADR-217): ping through the rig 13.1 -> 7.4 ms.
- Frames dropped for a full NIC queue: core 0 now holds up to 4 096; rings 2 048; spare frame buffers returned when quiet (this also repaired the `storm` smoke).
- QoS 0 loss now **counted per cause** (`$SYS/broker/messages/dropped/*`, `frames/dropped/*`, `status`, a warning line per core per 10 s).
- **Watchdog**: the budget is **running time** (late ticks, lock waits including a wait in progress, close-up 1 ms ticks for a long handler, confirmation at the next tick; KVM steal time read where the host offers it, Contabo's does not). Production `action = "drop"` unchanged.

**Results on the Contabo VPS** (same load host, same day, 24-30 runs each): connections lost per run 7-16 -> 0 (flood), watchdog aborts 148 in 30 runs -> 0 in 24; one 64 B flow 1.9k -> 23.7k published/s (Mosquitto 29.3k), 1 KiB 0 -> 3.9k (5.4k); 16 pairs flood 24.7k -> 43.2k (Mosquitto 31.4k). **One flow is still not faster than Mosquitto**; see the open items (lock wait of 4-7 % of a data core, up to 27 % in a window; SACK on our sending side; RX interrupt).

**The VPS** is back on the production ISO built from this tree (`v0.1.0-90-g120da49`, `deploy/prod` unmodified; the commit after it only adds this line): console `URMQTT READY`, `openssl s_client` from the build server completes TLS 1.3, `$SYS/broker/version` as above. Temporary images, the SSH secret, the served ISO directory and the generator's directory (with the CA key) were deleted; Mosquitto ran on Debian 13 for the same-session comparison before that.

**Not done / open**: heap lock contention (per-CPU caches above 2 KiB), SACK-driven recovery on our sending side, a receive interrupt, handshake/idle/fan-out not measured again, the shared load host (steal 58-77 %) limits every cell, bare metal.


## X11 — Performance on the real VPS, with Mosquitto on the same VPS (2026-11-01)

First release scope (VPS only). Method ADR-213; every number, caveat and the findings are in `docs/PERFORMANCE.md`; raw output in `docs/perf-results/` (`urmqtt-prod.txt`, `urmqtt-bench.txt` and `.pass1.txt`, `urmqtt-bench-log.txt`, `mosquitto.txt`, `mosquitto-idle*.txt`; tables with `scripts/x11-report.py`).

**Done**

- **Load generator.** `urmqtt-loadgen` has a `pubsub` mode (publishers, subscribers, topics, QoS 0/1, payload, fixed rate or flood, in-flight window, end-to-end latency stamped in the payload, `RESULT` line, its own CPU use, reasons for lost connections), `--keepalive`, and prints a `RESULT` line and its CPU for `handshake`; `hold` no longer waits for each close. Nothing else changed; no host tests touch it (a binary with `test = false`); `cargo clippy -p urmqtt-loadgen` is clean.
- **Images and configurations.** `scripts/mkbench.sh --x11` (prod configuration, ADR-082 handshake limits, publish rate lifted, `svc-*` identities with the backend's `fleet/#` rights) and `--x11-watchdog-log`; `scripts/mosquitto/urmqtt-x11.{conf,acl}` and `scripts/x11-mosquitto.sh` (Debian 13, Mosquitto 2.0.21, same CA/server certificate, TLS 1.3 with urMQTT's two suites, mTLS, ACL, no persistence).
- **Suite.** `scripts/x11-bench.sh` (guarded run of the whole matrix from a Linux host: nice 19, two pinned CPUs, waits for the host's load, stops if the web server on the shared host answers slowly, records the host's steal) and `scripts/x11-report.py`.
- **Run on the Contabo VPS (4 vCPU EPYC, KVM)**, from the build server 15 ms away: urMQTT `prod` as it stood, `bench-x11`, `bench-x11` with the watchdog in log mode, Debian 13 with Mosquitto, then **the production ISO restored** (console `URMQTT READY`, `openssl s_client` completes, `$SYS/broker/version` v0.1.0-74-g794f607). Temporary images, the served ISO and the temporary ssh key deleted.

**Results** (median of three; generator-limited figures are lower bounds; see PERFORMANCE.md for ranges, caveats and the rest)

- Full mTLS handshakes/s at 32/64/128 clients: urMQTT prod 185/262/333 (limits as shipped; 202-286 errors at 128), bench 169/278/413, Mosquitto 82/140/184 (its single thread 70-84 % busy). Server side: 260 us of TLS work per handshake (console).
- Idle connections: urMQTT 0.50-0.66 KB of kernel heap each, 19 975 held (generator 10 KB each); Mosquitto 26.8 KB of process growth each at 5 000, 10 000 and 20 000 (`mosquitto-idle3.txt`; the earlier attempts are invalid, see PERFORMANCE.md 3.2).
- Latency, 800 msg/s, 64 B, p50: urMQTT 14.0 ms (QoS 0), 14.8 (QoS 1); Mosquitto 21.4 and 39.5; RTT 15 ms; tails equal within noise.
- Offered load, 16 pairs, QoS 1: urMQTT delivers more at the top (5 204/s against 4 630/s at 16 000/s offered); QoS 0 64 B flood: urMQTT 18 280 delivered/s (24 299 published), Mosquitto 28 977 (its one core at 101 %).
- Fan-out 1 to 100 at 5 000 deliveries/s: both complete, p50 16.6 ms (urMQTT) against 99 ms (Mosquitto).

**Found**

- The 20 ms handler watchdog (`action = "drop"`, the production default) **dropped live connections** under load on this VPS: `watchdog: core N input handler over budget: 37-111 ms > 20 ms (action: Drop)` every couple of seconds, while the console's `longest stall` of the cores was 50-170 ms. The vCPU was not scheduled; the handler was not slow. With `action = "log"` the same sweeps lost no connection in any of 20 runs (the `drop` image: 1-8 per run at 300 msg/s per publisher and above). Not changed here (a design decision: measure in running time, or a stall-aware drop rule).
- One TCP flow through urMQTT carries 0.7 MB/s (1 KiB messages) or about 3 000 small messages/s with stalls of seconds, 2 to 8 times less than Mosquitto. Leads, not established: 16-bit window without scaling, `frames dropped for a full NIC queue` (39 per 5 s), retransmissions.
- The 1 000-subscriber fan-out and every flood row are limited by the generator (a shared VM with 60-70 % CPU steal); they are not capacity figures.

**Not done / honest limits**

- No calibration of the generator alone, no second source address, no more than 20 000 idle connections or 128 handshake clients, no dp-bench scaling on the VPS, no bare metal, no Intel. The Mac cannot reach the VPS, so every figure carries the build server's noise.
- The production-limits column covers handshakes only (the shipped image has no identity that may publish at speed).
- The Mosquitto 20 000-connection figure needed a longer keep-alive in the generator (the first attempt measured the keep-alive of connections opened more than 90 s before the pings started, not the broker).


## H6 — SQLite as an unprivileged component (2026-11-01)

SECURITY-PLAN H6, on both architectures. ADR-210 (design, what is and is not isolated), ADR-211 (interface and validation), ADR-212 (build). Two commits: the user-mode infrastructure with a hello worker, then SQLite moved in. **Closes the part of gap H0-W8 that was the privilege of SQLite; it does not close the fuzzing half (H5), and it is not a claim about wrong answers or speculative leaks** (SECURITY.md, "The database worker").

**Done**

- **The worker.** `crates/dbworker` is a separate static program (own linker script at 0x400000, no kernel symbol, no allocator) containing SQLite 3.54.1 unchanged, its libc shims, a dispatcher and a VFS shim whose callbacks are twelve system calls. Built by the kernel's `build.rs` (nested cargo, own flags: BTI but no PAC on aarch64, small code model on x86_64) and embedded; the kernel links no SQLite any more (`nm` of the kernel ELF: only the Rust proxies). aarch64 image 700 KiB.
- **User mode.** aarch64: EL0 with its own `TTBR0` tables (disabled by `EPD0` except during a call), `PAN`, `PXN` on every user page, BTI at EL0, SCTLR hardening of EL0, an entry that works whether the kernel runs on `SP_EL0` or `SP_EL1`, interrupts masked until the `eret`. x86_64: ring 3 with GDT user segments, TSS `rsp0`, a DPL 3 gate (`int 0xf0`), a second PML4 sharing the kernel's upper half, `CR3` switched per call, `SMEP`/`SMAP`, `swapgs` and `AC` clearing in the common exception path, 16-byte stack alignment as the ABI wants.
- **Protocol.** `urmqtt-store::remote` (the 32 SQLite functions `db.rs` uses, as calls; binds and resets ride with the step, a row comes back whole) and `vfs::syscall` (12 calls, checked); `usys` holds the formats with host tests. `db.rs`, `store.rs`, `backup.rs`, `scrub.rs` and every SQL string are unchanged.
- **Failure handling.** A fault or a 30 s overrun restarts the worker; the DB core reopens the store from the WAL (`open_or_restore`), tells the data cores the transaction failed and goes on; more than 5 restarts a minute and storage is out of service until the next boot while the broker serves from memory.

**Tests**

- `cargo test --workspace`: 729 passed. The whole store suite (131 tests) passes **directly linked and through the protocol** (`cargo test -p urmqtt-store --features loopback`: the worker's code in process, calling the kernel's real `vfs::syscall` on the same window). New: `usys` protocol (4), `vfs_syscall` (5: hostile file numbers, lengths, offsets, sizes, sleep, log), user page descriptors and the user mapper on both architectures, GDT/IDT user entries.
- Smoke `worker-contain` (kernel read/write/jump, privileged instruction, write to own code, jump into data, null, endless loop: all contained, kernel word intact, `PAN` or `SMEP+SMAP` asserted) and `worker-fault` (rows committed, more uncommitted, the worker made to fault on the DB core, the store back with exactly the committed rows): aarch64 HVF and TCG, x86_64 TCG.
- Storage group (`SMOKE_ONLY=storage`, 79 scenarios, every one of them runs SQLite in the worker): aarch64 HVF 79 passed, 0 failed, aarch64 TCG 76 passed, 0 failed (`grow-online` is skipped under TCG: no MSI-X), x86_64 TCG 79 passed, 0 failed. Hardening group: aarch64 HVF and TCG 32 passed, 0 failed; x86_64 TCG 14 passed, 0 failed. Default suite on aarch64 HVF (final kernel): **136 passed, 4 failed; the four are the `storm` scenario**, whose host-side load generator stalls at 0% CPU on this machine with the pre-H6 kernel too (same stall, same connection counts: 2128 against 2067 admitted; killed by hand after 20 minutes), so that scenario is unproven here either way. `mqtt-persist` (retained message, persistent session and queued message across a restart, over mTLS) passes on aarch64 HVF and, run standalone, on x86_64 TCG; the rest of the x86_64 default suite (TLS-heavy, about 15 minutes per scenario under TCG) was not run.
- Bugs found by the tests on the way (all fixed): a 1 MiB row buffer in the kernel heap starved the `storm` scenario (118 connections admitted; rows over 4 KiB are now fetched at their exact size); an interrupt between setting `ELR_EL1` and the `eret` sent the worker to a kernel address (TCG scsi-boot; HVF never hit it); a lazy reset of a statement stopped mid-row kept a table locked; x86 entered the worker with a stack pointer the ABI does not allow (SSE `movaps` faulted).

**Cost** (aarch64 HVF, `test=db-bench`, same VM, direct-linked kernel before, worker after; the disk work is identical: 1572 writes, 319 flushes)

- **Entering and leaving user mode:** 1.1 us per round trip (20 000 empty calls, `worker-contain`, HVF). `test=db-bench` makes 10 505 calls and 1 689 VFS system calls for its 5 100 inserts and spends 141 to 148 ms inside the worker, so the mode switches alone are about 12 ms of it (8%); the rest is SQLite and the disk flushes inside the system calls.
- **`db-bench`, six runs of each kernel, interleaved, HVF** (a quieter host than the first set, which spread from 23k to 47k ops/s with other VMs running and showed no difference beyond that noise): 5 000 inserts in 50 transactions, best / median: **54.7k / 53.3k ops/s with the worker against 61.9k / 58.4k direct** (-11.6% / -8.7%; 1.83 ms per commit against 1.62 ms); one insert per transaction: 2 307 / 2 126 against 2 319 / 2 148 ops/s (-0.5% / -1%: the flush dominates). Disk writes (1 572) and flushes (319) are identical, as they must be.
- **`backup-bench`** (23 MiB database, backup in 16-page steps while a writer commits; one run each, the first set): commits during the backup mean 533 us (was 532), max 2.3 ms (was 3.2); a 16-page step mean 930 us (was 1 081), longest 4.6 ms (was 4.7); commits alone 676/s (was 650/s). The whole copy as **one call** takes 635 ms (was 514 ms, +23%: 6 024 pages, a VFS system call each way per page).
- **Telemetry batches** do not touch SQLite (the log is Rust over the disk layer) and are unchanged; the DB core now also spends the mode switches above.
- **x86_64:** not quotable. Under TCG a round trip is 11.6 us and means nothing; the cost that is specific to x86 (a `CR3` write without PCID flushes the whole TLB at each entry and exit) is **not measured on KVM**.

**Not done / honest limits**

- No fuzzing of the worker or the protocol decoders beyond host tests (H5 / gap H0-W8). No KPTI, no PCID: x86_64 flushes the TLB at each entry and exit (cost not measurable under TCG; **not measured on KVM**); no measurement on real hardware.
- The kernel trusts the worker's *answers* (SECURITY.md): an empty revocation list from a compromised worker un-revokes certificates.
- PAC keys are shared on aarch64 (the worker has no PAC, but can sign with the kernel's key); NMI on x86_64 is not supported while a call is entering.
- Rows are limited to 1 MiB and 64 columns; binds to 1 MiB. `max_packet_size` is 4 KiB in every shipped configuration.
- VHE (entry at EL2) is untested, as before. The nested worktree still needs `RUSTFLAGS` set by hand to build the aarch64 kernel.


## H7 — time security (closed 2026-11-01)

Nothing new to build: the lower bound (ADR-050, H1) and SNTP with median consensus, per-step and total bounds and kiss-of-death handling (ADR-100, T1) cover the H7 scope. NTS (RFC 8915) stays out of scope and is a documented residual: with plain SNTP a man in the middle that controls every answer can move the clock by `max_step` in total after boot. `docs/AUDIT.md` question 3 is updated and `deploy/prod/config.toml` carries a commented `[time]` example (no servers by default: an operator picks IPv4 literals).
