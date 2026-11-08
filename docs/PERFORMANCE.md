# Performance: urMQTT and Mosquitto on the same VPS (X11)

What this file claims, in one paragraph. On one Contabo VPS (4 vCPU AMD EPYC, KVM, 8 GiB), loaded over the
internet from one Linux host 15 ms away, with mutual TLS 1.3 on both sides and the same certificates, urMQTT
completed more full handshakes per second than Mosquitto 2.0.21 on Debian 13 (about 2x at the same client
concurrency; the load generator, not urMQTT, was the limit), held 20 000 idle connections in about 0.5 KB each
of its heap where Mosquitto's process grew by about 27 KB per connection, and delivered small messages with
about the same or a lower end-to-end latency at modest rates. Under heavy offered load the picture is
mixed and **not in urMQTT's favour in two places**: a single TCP flow moves much less data through urMQTT than through
Mosquitto, and urMQTT's 20 ms handler watchdog **dropped live connections** when the hypervisor stalled a vCPU
(production setting `action = "drop"`). Both are in the tables and in "Findings" below. **Both turned out to have causes in urMQTT, found and fixed afterwards: section 7
(ADR-221 to ADR-224) holds the causes, the changes and the numbers measured again on the same VPS.** Everything else about
these numbers is limited by a shared, noisy load generator; read "Caveats" before quoting anything.

Method and decisions: ADR-213 in `docs/DECISIONS.md`. Raw files: `docs/perf-results/`. Tools: `scripts/x11-bench.sh`
(the suite), `scripts/x11-report.py` (tables), `scripts/x11-mosquitto.sh` and `scripts/mosquitto/` (Mosquitto side),
`scripts/mkbench.sh --x11` (the benchmark image), `tools/loadgen` (`urmqtt-loadgen`, modes `handshake`, `hold`, `pubsub`).

## 1. Setup

| | |
|---|---|
| Server | Contabo VPS "Cloud VPS 4 (2026)", instance 203712023, 4 vCPU (AMD EPYC family 23 model 1, Zen 1, KVM guest), 8 GiB, data centre EU 2, IPv4 169.58.184.193, port 8883 only |
| Load generator | the project's build server (also runs a production web server): 4 vCPU KVM guest on an AMD EPYC 9354P host, Linux 7.0, x86_64. The generator runs under `taskset -c 2,3` and `nice -n 19`. The host showed **60 to 70 % CPU steal** during the runs (hypervisor overcommit), see "Caveats" |
| Path | 15.2 ms mean round trip (ping min/avg/max 10.2/15.2/22.2 ms, 20 probes), one source address, no firewall between |
| TLS | TLS 1.3 only, ECDSA P-256 certificates (server and 1 to 1 000 simulated devices, all from the project's test CA), client certificate required, identity = certificate CN. Negotiated suite on both servers: `TLS_AES_128_GCM_SHA256` (Mosquitto is told to offer only the two suites urMQTT supports) |
| urMQTT `prod` | `build/urmqtt-prod-universal.iso` (v0.1.0-74-g794f607, sha256 `70118d7d...bfcd`), production configuration (`deploy/prod/config.toml`), live (RAM) boot |
| urMQTT `bench-x11` | built from commit 878a95e (H7) by `scripts/mkbench.sh --x11 --static 169.58.184.193/17 169.58.128.1`, sha256 `fbf83e03...8586`: production configuration with the ADR-082 handshake limits relaxed (2000 to 100000 per core per second, 256 and 32 in flight to 4096), `publish_rate_per_device` 10/s to 1000000/s, and identities `svc-*` allowed `fleet/#` like `backend`. Same code paths otherwise. Differs from `prod` by two commits of H6/H7 (the SQLite worker and time checks) that do not touch the data path |
| urMQTT `bench-x11-log` | the same with `[watchdog] action = "log"` instead of `"drop"` (`--x11-watchdog-log`), sha256 `2b72ebc4...9f9e`; used for the offered-load sweep only, to tell watchdog drops from other losses |
| Mosquitto | Debian 13 (trixie), kernel 6.12.38+deb13-cloud-amd64, `mosquitto` 2.0.21-1, OpenSSL 3.5.7, stock packages. `scripts/mosquitto/urmqtt-x11.conf` and `.acl`: same CA, server certificate and key, `tls_version tlsv1.3`, `require_certificate true`, `use_identity_as_username true`, `allow_anonymous false`, ACL file (own `devices/<id>/#`, `fleet/bench/#`; operator reads `$SYS`), `persistence false`, `max_connections -1`, `max_inflight_messages 16`, `max_packet_size 4096`, `LimitNOFILE=1048576`, `sys_interval 2`. Single thread (Mosquitto 2.0 has no worker threads) |
| Generator binary | `urmqtt-loadgen` built on the load host (`cargo build --release --locked -p urmqtt-loadgen`, nightly-2026-10-20); the `handshake` run against `prod` used an earlier build of the same code before the `RESULT` and CPU lines were added (sha 12 chars `e8aabc2e682e`; later runs `45ae7fd8e4fb`) |
| urMQTT cores | on this VPS the production image uses core 0 for the NIC and dispatch, **cores 1 and 2 as MQTT/TLS workers** and core 3 for the database (`$SYS/broker/cpu/accepted/<core>`: only 1 and 2 accept). So "3 data cores" is 2 here while storage is on |

Every run: three repetitions, median and (min-max) in the tables. A run measures 10 s after a 2 s warm-up (handshake: 10 s).
The suite guards the shared host: before every run it waits for the load average to fall (it was 3 to 15 all day,
mostly other tenants), reads the web server's response time (always 15 to 280 ms; the suite stops if it exceeds 1 s twice; it never did) and records the host's steal share.

## 2. What was measured and how

* **Handshakes** (`urmqtt-loadgen handshake`): N threads each loop TCP connect, full TLS 1.3 handshake with a client certificate (no resumption), CONNECT/CONNACK, DISCONNECT, close; the server closes first (ADR-080). The rate counts the window only. 32, 64, 128 threads (beyond 128 is the region of ADR-080's overload collapse and the production per-address limit; it was not run).
* **Idle capacity** (`hold`): 64 threads open N connections (full mTLS, CONNECT), they stay idle (PINGREQ at 30 s), and the broker's own figures are read: urMQTT `$SYS/broker/memory/used`, Mosquitto's process RSS over ssh (`ps -o rss`) and `$SYS/broker/heap/current`. Memory per connection is the growth from the baseline divided by the connections the broker reports.
* **Throughput, offered-load sweep** (`pubsub`): P publishers and P subscribers on P topics (1:1 pairs, P = 16 or 64), messages of 64 B or 1 KiB with the send time in the first 8 bytes, QoS 0 or 1 (QoS 1: window of 32 publishes in flight; the brokers' own limit on messages in flight to a subscriber is 16 for both). "flood": as fast as the broker lets it. "sweep": a fixed rate per publisher (100, 300, 1000 messages/s). Reported: published/s, acknowledged/s (QoS 1), **delivered/s** (what the subscribers received), end-to-end latency p50/p99 (publisher write to subscriber read, one process and clock; includes the network round trip once), connections lost during the run.
* **Latency at a modest rate**: 8 pairs x 100 messages/s, 64 B, QoS 0 and 1.
* **Fan-out**: 1 publisher to 100 or 1000 subscribers on one topic at a fixed rate (50/s and 10/s: 5 000 and 10 000 deliveries/s), QoS 0 and 1; and a 1 to 100 flood.
* **Single flow**: one publisher and one subscriber, flood: what one TCP connection each way carries.
* **Broker CPU**: urMQTT publishes the busy percentage of each core in `$SYS` (every 5 s; the DB core, core 3, polls and always shows high); Mosquitto's `utime+stime` is read over ssh for 10 s. Both are from the first 14 s of each run, so approximate.
* Generator CPU (`gen cpu`, cores of CPU time used by the whole process) and the host's steal/idle shares come with each run.

## 3. Results

All numbers: median (min-max) of three runs unless stated. Full tables with generator CPU and host steal for every row: run
`scripts/x11-report.py docs/perf-results/*.txt`.

### 3.1 Full mTLS handshakes per second (TLS 1.3 + client certificate + CONNECT, no resumption)

| clients (threads) | urMQTT prod (limits as shipped) | urMQTT bench (limits relaxed) | Mosquitto 2.0.21 |
|---|---|---|---|
| 32 | 185 (177-194), p50 177 ms | 169 (155-171), p50 186 ms | 82 (76-92), p50 361 ms |
| 64 | 262 (246-269), p50 212 ms, 1-11 errors | 278 (277-289), p50 201 ms | 140 (125-145), p50 401 ms |
| 128 | 333 (324-339), p50 310 ms, **202-286 errors** (resets during the handshake) | 413 (378-452), p50 299 ms | 184 (152-211), p50 597 ms; p99 1.6 s |

What these say. They are **lower bounds of what the servers can do**, not capacities: at 128 threads the
generator used 0.6-0.7 cores of CPU time while the host stole 60 to 66 % of its two pinned vCPUs, so it was at
about its own ceiling (1.6 ms of client CPU per handshake, about 450 handshakes/s on the share of two vCPUs it
got), and below that each client thread waits two to six round trips per connection. urMQTT's two workers (cores 1 and 2) were 12 to 13 % busy (bench) and 33 to 35 % (prod) at 128 threads,
so the server had room; its console reports 260 us of server-side TLS work per
handshake (X25519 + ECDSA P-256 sign and verify, 90 % public-key) on this CPU. Mosquitto's single thread was at
68 to 84 % of one core at 64 and 128 threads (about 4.6 ms of its CPU per connection including the kernel's TCP work), so it
was close to its own limit at 128 threads and the ratio at that point (about 2.2x) is the most meaningful one here; at 32 and
64 threads the generator waits are the limit and the ratio (2.0x) mostly reflects latency per handshake.
With the production limits one source address is capped (handshakes in flight per address and core, ADR-080): the 128-thread
errors are resets of connections in the handshake, which is what that limit does (the refusal counters in `$SYS` were not recorded per run, so
this is the expected cause, not a proven one); the 413 per second of the relaxed profile is the better indicator of the data
path, and it still rises with threads.

### 3.2 Idle connections

| | urMQTT bench | Mosquitto |
|---|---|---|
| 5 000 | 4 995 connected in 17 s; broker heap +3.3 MB = **0.66 KB per connection** (4.13 -> 7.42 MB) | 5 001 connected in 30 s; process RSS 10.6 -> 144.5 MB = **26.8 KB per connection** (`$SYS` heap counter: 0.8 KB, excludes OpenSSL's allocations) |
| 10 000 | 9 987 in 35 s; +6.0 MB = 0.60 KB | 10 001 in 55 s; RSS 278.5 MB = 26.8 KB |
| 20 000 | 19 975 in 94 s; +10.1 MB = **0.50 KB per connection** | 20 001 in 135 s; RSS 546.6 MB = **26.8 KB per connection** |

urMQTT's figure is the kernel heap in use (`$SYS/broker/memory/used`); it leaves out the NIC's receive buffers
and the per-core frame buffers (the console shows them separately, about 2 MiB) and the guest's own tables, so
the guest's total RAM per connection is somewhat more; the configuration's own estimate (`kernel_heap_mb`: about 500 B per idle connection) agrees. The generator held 20 000 connections in
204 MB of RSS (10 KB each) and was not the limit; the 28 000 usable source ports of one address would be (50 000 was
not attempted). The source address kept 5 000 to 20 000 TIME_WAIT sockets after each run, which is why the suite waits 65 s between sizes.
Mosquitto's numbers are from `mosquitto-idle3.txt` (fresh process, keep-alive 600 s in the generator). Two earlier attempts (`mosquitto.txt`, `mosquitto-idle.txt`, `mosquitto-idle2.txt`) are **not valid** and are kept as raw data: the suite sampled while connections were still being opened (a stale output file from the previous size ended its wait at once), and with the generator's 60 s keep-alive Mosquitto closed the first connections of a 150 s opening phase after 90 s (8 680 of 20 000 left), which is the keep-alive working, not a capacity limit. urMQTT's pass-1 rows were consistent (clients connected = clients established) but used the 60 s keep-alive too; its 94 s opening of 20 000 is at the edge of that window.

### 3.3 End-to-end latency at a modest rate (8 pairs x 100 msg/s = 800/s, 64 B)

| | urMQTT bench | Mosquitto |
|---|---|---|
| QoS 0 | p50 **14.0** (13.8-16.5) ms, p99 102 (100-114) | p50 21.4 (19.6-21.9), p99 200 (131-201) |
| QoS 1 | p50 **14.8** (13.9-18.9), p99 199 (106-208) | p50 39.5 (23.4-69.7), p99 277 (217-299) |

The path itself is one round trip (about 15 ms) so 14 ms is "no measurable broker time". The p99 near 100 ms and 200 ms
(both brokers, and with the generator being preempted for tens of ms) says the tail is dominated by the shared hosts
(generator steal; urMQTT's own console reports core stalls of 50 to 170 ms on the VPS), not by either design. The p50 gap of 7 to 25 ms to
Mosquitto is real in these runs and repeatable (ranges do not overlap for QoS 0), the cause was not investigated.

### 3.4 Offered-load sweep: 16 pairs, QoS 0 and 1 (delivered messages per second, p50 / p99 latency)

| offered | urMQTT bench (`action = "drop"`) | urMQTT bench-x11-log (2 runs) | Mosquitto |
|---|---|---|---|
| QoS 0, 64 B, 1 600/s | 1 599; 15 / 101 ms | 1 602; 16 / 146 | 1 598; 90 / 221 |
| QoS 0, 64 B, 4 800/s | 4 393; 20 / 808; 1-3 lost | 4 716; 20 / 950 | 4 803; 90 / 386 |
| QoS 0, 64 B, 16 000/s | 12 126; 599 / 4 204 ms; **3-8 lost** | 14 756; 557 / 3 655 | **15 901**; 100 / 592 |
| QoS 1, 64 B, 1 600/s | 1 601; 14 / 113 | 1 598; 18 / 295 | 1 582; 95 / 402 |
| QoS 1, 64 B, 4 800/s | 4 209; 77 / 417; 0-4 lost | 4 480; 61 / 406 | 4 235; 197 / 1 823 |
| QoS 1, 64 B, 16 000/s | **5 204**; 188 / 499 | 5 948; 186 / 449 | 4 630; 573 / 3 294 |
| QoS 0, 1 KiB, 1 600/s | 1 350; 23 / **1 313** | 1 420; 200 / 2 188 | **1 586**; 23 / 280 |
| QoS 0, 1 KiB, 4 800/s | 2 183; 1 015 / 5 499 | 2 076; 1 251 / 4 207 | **3 695**; 300 / 1 300 |

QoS 1 at 16 000/s is capped by the 16-in-flight window per subscriber over a 15 ms round trip (16 / 15 ms is about
1 000 messages/s per subscription, 16 000 for 16): both brokers sit well below it, urMQTT higher. Flood tests
(`throughput` rows in the result files: publishers as fast as the broker takes it) show the same ordering and a
behaviour worth stating plainly: with QoS 0 at flood, urMQTT delivered 18 280 (16 369-30 726) messages/s of 24 299 published and
**lost 6-8 connections** per run to the watchdog; Mosquitto delivered 28 977 of 29 430 published and its single core was at 101 %.
QoS 1 flood, 64 B, 16 pairs: urMQTT 5 975 delivered/s, Mosquitto 4 187; with 64 pairs 11 798 against 9 809.
At 1 KiB the picture reverses (QoS 0 sweep above; flood 1 414 against 4 168 delivered/s) and is the single-flow limit of 3.6.

### 3.5 Fan-out (1 publisher, QoS 0 unless noted, 64 B)

| | urMQTT bench | Mosquitto |
|---|---|---|
| 100 subscribers, 50 msg/s (5 000 deliveries/s) | 5 002 delivered/s, p50 16.6 ms, p99 101 | 5 019, p50 99 ms, p99 307 |
| 100 subscribers, QoS 1, 50 msg/s | 4 997, p50 18.9, p99 105 | 5 036, p50 103, p99 368 |
| 1 000 subscribers, 10 msg/s (10 000/s) | 9 790 (2 151-10 051; one run lost the publisher), p50 278 ms, p99 2.6 s | 9 849, p50 190 ms, p99 813 ms |
| 1 to 100 flood (unbounded publisher) | 15 602 (3 316-98 139) delivered/s, p50 2.3 s; both worker cores 100 % busy | 60 955 (43 025-72 020), p50 6.7 s; its core 98 % |

Steady fan-out of 5 000 deliveries per second is delivered completely and promptly by both. At 1 000 subscribers
the tails (seconds) are dominated by the generator (1 000 reading threads on two stolen vCPUs) and the 1 000
simultaneous connections' round trips; both brokers show it, urMQTT more. The flood row is unstable for
urMQTT (3 316 to 98 139) and should be read as "not characterised".

### 3.6 One TCP flow (1 publisher, 1 subscriber, QoS 0, flood)

| | urMQTT bench | Mosquitto |
|---|---|---|
| 64 B | 2 962 (0-7 733) published/s; some runs stall for seconds | **22 749** (16 664-28 971) |
| 1 KiB | 724 (498-990) published/s = 0.7 MB/s | **1 402** (772-2 162) |

## 4. Findings the numbers force

1. **The 20 ms handler watchdog drops healthy connections when the vCPU stalls.** The console (`$SYS/console/out`) during the
   sweep showed `watchdog: core 1 input handler ... over budget: 37 ms .. 111 ms > 20 ms (action: Drop)` followed by `aborting
   connection`, about one every two seconds, together with `longest stall` of 50 to 170 ms per core and `timer: irq latency max` of 2.3 ms at boot.
   The handler did not run for that long: the vCPU was not scheduled (this is a shared VPS), the wall-clock watchdog fired
   and aborted the connection that happened to be in the handler. With `action = "log"` the same sweeps had **zero lost connections**.
   Production keeps `drop`; on a noisy host that means random disconnects under load (the device reconnects). Either measure the budget in
   time the vCPU actually ran, or give `drop` a stall-aware rule. Not changed here (that is a design change, not a measurement).
   **Done afterwards: the budget is now running time (ADR-221, section 7.4).**
2. **A single flow is slow.** urMQTT moves 0.7 MB/s (1 KiB messages) and 3 000 small messages/s through one connection over a 15 ms
   path, 2 to 8 times less than Mosquitto and with large run-to-run spread (stalls of seconds). Leads (not established): the TCP receive window is 16 bit
   with no window scaling (`rcv_wnd: u16`, so at most 64 KiB per round trip is 4.4 MB/s, higher than measured), the console reports frames dropped for
   a full NIC queue (39 in 5 s under load) and TCP retransmissions, whose recovery without fast retransmit would stall a flow for
   an RTO. It matters for a few devices sending bulk data; for many small flows (3.4) it does not.
   **The leads were right and there were three more causes (a lost wake-up in the output loop, a dispatcher that slept until the next tick, a congestion window that counted ACKs); all fixed afterwards, section 7.**
3. **Handshakes: about 2x Mosquitto per second at equal concurrency, 0.26 ms of server CPU per handshake.** Limited by the generator in both cases, see 3.1.
4. **Memory per idle connection is about 40 to 50 times smaller** (0.5 to 0.7 KB of kernel heap against 27 KB of process growth; the two counters do not count the same things, see 3.2).
5. **Latency at modest rates is lower for urMQTT** (14 ms against 21 to 40 ms p50, tails equal within noise).

## 5. Caveats (read before quoting)

* **The load generator is a shared VM with 60-70 % steal.** It had two pinned vCPUs and was itself near its CPU
  limit in the handshake runs at 128 threads and in every run with 64 pairs or 1 000 subscribers. Handshake rates and
  flood throughput are therefore **lower bounds for both brokers**; latencies above about 100 ms and every
  figure in seconds include generator scheduling delay. Calibration of the generator alone (against a local broker)
  was not done on the shared host. The same generator and the same bounds apply to both brokers, but the steal varied
  over the day (58 to 71 %) and the brokers were measured hours apart, so differences under about 20 % are not claims.
* **The VPS is shared too.** Contabo's guest reports no steal; urMQTT's own stall counters show the vCPUs were descheduled for tens of ms
  repeatedly. Both brokers ran on the same VM type at different times.
* **One source address, 15 ms away, one path.** No many-client topology, no IPv6, no packet loss measured. A fleet of real devices differs.
* **Different products.** Mosquitto: one thread, MQTT 5, plugins, bridges. urMQTT: MQTT 3.1.1, two worker cores here, per-device ACL at every
  publish, admission control and SYN cookies, no persistence in live mode. Mosquitto was run with persistence off and without
  per-user limits; urMQTT was run in its benchmark profile (relaxed handshake limits; for the handshake rows also as shipped) and the build is not the
  production build in two commits. The ACLs are equivalent for the benchmark topics, not in general.
* **urMQTT `bench` is not a release image** (ADR-082, ADR-213). Every urMQTT row except the first column of 3.1 is from it.
* **Handshake rows from one `prod` run per concurrency** were taken with the older loadgen build and with identity names re-used between runs (two errors at most); the
  unique-identity rule (`uid` in the suite) came with the later runs. The first pass of the benchmark image
  (`urmqtt-bench.pass1.txt`) re-used client identities between runs (a risk: a new connection with an id re-used within seconds of an unclean close); the
  second pass, with a fresh identity prefix per run, lost fewer connections (QoS 0 flood: 6-8 against 11-15), and none with the watchdog in log mode. Idle capacity
  of urMQTT is from the first pass (it does not depend on identity reuse).
* Mosquitto's idle figure is the process RSS (including allocator slack that is not returned after the run: the RSS stays at its peak after the connections close).
* Not measured: bare metal, other CPUs, dp-bench scaling on the VPS, TLS resumption, retained messages, persistent sessions, MQTT 5, packets larger than 4 KiB, more than 20 000 idle connections, more than 128 handshake clients.

## 6. Reproduce

1. Build the benchmark image and the generator:

   ```sh
   scripts/mkbench.sh --certs deploy/prod --static ADDR/LEN GATEWAY --x11 --env bench-x11   # universal ISO in build/
   cargo build --release --locked -p urmqtt-loadgen                                          # on a Linux host near the VPS
   ```

2. Mosquitto: copy `deploy/prod/{ca.pem,server.pem,server.key}` and `scripts/mosquitto/*` to `/root/x11/` on a Debian 13 VPS and run `scripts/x11-mosquitto.sh`.
3. On the Linux host, in a directory with `urmqtt-loadgen`, `certs/` (`ca.pem`, `ca.key`, `operator.pem`, `operator.key` from `deploy/prod`) and `x11-bench.sh`:

   ```sh
   BROKER=urmqtt   ./x11-bench.sh urmqtt-bench handshake sweep throughput latency fanout idle
   BROKER=mosquitto SSHVPS=root@VPS DIR=. ./x11-bench.sh mosquitto handshake sweep throughput latency fanout idle   # needs DIR/id (ssh key)
   PUBSUB=0 ./x11-bench.sh urmqtt-prod handshake       # the shipped image: no identity may publish at speed
   python3 scripts/x11-report.py results/*.txt
   ```

4. Put the VPS back to the image it served before (the suite takes about 90 minutes per broker, the VPS is out of service for the duration).

## 7. Why one flow was slow and why the watchdog dropped connections: causes found and fixed (ADR-221 to ADR-224)

Written after X11, same VPS, same load host, same method (ADR-213), same day. Section 3 is the state of X11; this section is what the
findings of section 4 turned out to be and what changed. The honest summary: **most of the single-flow weakness and all of the
watchdog drops were urMQTT's own doing, not the hypervisor's; the hypervisor is real and large (below) and is why the
watchdog needed a different clock, not a bigger budget.**

### 7.1 Causes (each with its evidence)

| X11 symptom | Cause in urMQTT | Evidence | Change |
|---|---|---|---|
| single flow 1.9k msg/s, sometimes **0 delivered**, "stalls of seconds" | **A lost wake-up.** `MqttService::poll` put the drained ready-list back over the connections it had just listed again (TLS buffer full, no relay credit). A subscriber whose output buffer filled once was never served again; every later QoS 0 message to it was dropped until a PINGRESP woke it | VPS, X11 image, same session: `published 18 024/s, delivered 0` and `delivered 0` in 4 of 6 QoS 0 single-flow runs; on the rig `delivered 0/s` in 2 of 3 floods | ADR-223 |
| a few percent loss turns 48k msg/s into 14k | **Every segment after a lost one was thrown away** (in-order receive only): recovery cost one round trip per discarded segment, and a vCPU stall makes the host drop thousands of frames | rig, 0.1 % loss: 47.5k -> 14.3k published/s (X11 kernel), 0.5 %: 5.0k | out-of-order queue, SACK (ADR-222) |
| 4.4 MB/s ceiling at 15 ms, 1 MB/s per flow | **16-bit window, 64 KiB send queue; slow start counted ACKs, not bytes**, so a receiver that acknowledges in batches (the load host, with 60-70 % steal) made the window grow by two segments per round trip | rig: 31k msg/s = 64 KiB / 20 ms; VPS: `ss` on the generator showed the subscriber leg app-limited at ~1 MB/s while the window of the other leg sat at 115 segments | window scaling, timestamps, send queue = 2 x cwnd, byte counting (ADR-222) |
| every round trip of a flow that pauses pays 0-10 ms | **The dispatcher slept until the next 10 ms tick**: the virtio-net queues have no receive interrupt and core 0 sleeps after 100 us idle. Linux measured 66 ms round trips on a 15 ms path | rig: ping with one open connection 13.1 -> 7.4 ms mean; one 1 KiB flow 4.3k -> 11.3k delivered/s | poll every 200 us while connections exist (ADR-224) |
| "frames dropped for a full NIC queue", QoS 0 loss unattributed | core 0 dropped frames the 256-entry queue could not take yet; QoS 0 drops were counted in one number | X11 console: 39 per 5 s | frames wait (4 096), rings 2 048, drops counted per cause in `$SYS` (ADR-223) |
| 1-8 connections dropped per run by the 20 ms watchdog | **Elapsed time was charged to the handler.** The VPS stalls its vCPUs, a lot (7.4) | base image today: 148 aborted connections, 247 over-budget reports in 30 runs, median 32 ms, up to 371 ms | budget in running time (ADR-221) |

(The VPS rows are the production configuration with the benchmark limits (`bench-x11v`: `mkbench.sh --x11 --static`), `watchdog.action = "drop"`
as shipped, x86_64, 4 vCPU; "X11 code" is main at 7f9517e built the same way and run today, "now" is this tree at 86a71ff.)

### 7.2 One flow and the stress rows, measured again on the VPS (same load host, same method)

| published/s / delivered/s, median (min-max) | urMQTT X11 code (7f9517e) | urMQTT now | Mosquitto 2.0.21 |
|---|---|---|---|
| single flow, QoS 0, 64 B | 1.9k (1.8k-18.0k) / 0 (0-1.9k) | 23.7k (17.0k-28.0k) / 12.6k (6.9k-25.9k) | 29.3k (29.2k-33.1k) / 29.2k (27.7k-34.1k) |
| single flow, QoS 0, 1 KiB | 0 (0-589) / 0 (0-396) | 3.9k (2.5k-4.8k) / 2.3k (676-2.9k) | 5.4k (4.0k-5.9k) / 5.4k (4.0k-6.0k) |
| single flow, QoS 1, 64 B | 1.1k (1.1k-1.3k) / 529 (370-795) | 1.5k (1.4k-1.6k) / 744 (470-979) | 866 (782-927) / 652 (566-714) |
| 16 pairs flood, QoS 0, 64 B | 24.7k (16.9k-31.9k) / 20.0k (13.2k-27.1k) | 43.2k (33.5k-43.9k) / 37.4k (33.3k-43.9k) | 31.4k (22.4k-34.5k) / 30.7k (22.6k-33.1k) |
| 16 pairs flood, QoS 0, 1 KiB | 3.7k (3.3k-4.4k) / 2.9k (1.9k-3.2k) | 5.0k (4.3k-5.2k) / 4.5k (4.2k-4.7k) | 5.9k (5.3k-6.6k) / 5.7k (5.3k-6.7k) |
| 16 pairs x 1000 msg/s, QoS 0, 64 B | 9.3k (9.0k-12.2k) / 8.8k (6.9k-10.9k) | 16.0k (16.0k-16.2k) / 15.9k (15.8k-16.0k) | - |

| lost connections per run (median, min-max) | urMQTT X11 code | urMQTT now | Mosquitto |
|---|---|---|---|
| single flow, QoS 0, 64 B | 1 (0-1) | 0 (0-0) | 0 (0-0) |
| single flow, QoS 0, 1 KiB | 1 (1-1) | 0 (0-0) | 0 (0-0) |
| single flow, QoS 1, 64 B | 0 (0-0) | 0 (0-0) | 0 (0-0) |
| 16 pairs flood, QoS 0, 64 B | 13 (7-16) | 0 (0-0) | 0 (0-0) |
| 16 pairs flood, QoS 0, 1 KiB | 3 (2-9) | 0 (0-0) | 0 (0-0) |
| 16 pairs x 1000 msg/s, QoS 0, 64 B | 11 (6-13) | 0 (0-0) | - |

Median and (min-max) of three runs per cell; for the single-flow rows of the X11 code and of the new code, six where the sweep suite added
its own (see the raw files). QoS 0 "published" is what the broker accepted, "delivered" what the subscribers read; the difference is
what the broker dropped on purpose because the subscriber's buffer was full (counted: `$SYS/broker/messages/dropped/slow_subscriber`).

What this says, with the limits of the instrument. **The generator is the same shared VM (steal 58-77 % today) and was the limit in
many cells; a ratio under about 20 % is not a claim.**

* **The X11 code could not carry one flow; the new code carries about as much as Mosquitto at 64 B, and half at 1 KiB.** One 64 B flow: 1.9k
  published and 0 delivered (median) became 23.7k and 12.6k, against Mosquitto's 29.3k and 29.2k. At 1 KiB: 0 became 3.9k (2.3k delivered)
  against 5.4k. **urMQTT is not faster than Mosquitto on a single flow on this VPS; the claim of the task is not met for one flow.** What is left
  of the gap is on the subscriber leg (published is near 80 % of Mosquitto's, delivered 40 %): the broker drops QoS 0 when a subscriber's flow
  is slower than the publisher's, where Mosquitto queues without bound (its p50 latency in these runs is as long as ours). The subscriber leg
  is limited by the same receiver (the generator, a thread per connection on a stolen vCPU), by the congestion window of a sender that has
  not yet seen the path (slow start from 10 segments, no SACK on our sending side), and by core time spent waiting for a lock (7.4: 4-7 % of a data core on average, more than 20 % in one window in ten).
* **QoS 1, one flow:** 1.5k published/s against 0.87k for Mosquitto (16 in flight in both).
* **Many flows (16 pairs, flood):** 43.2k published and 37.4k delivered/s against 31.4k and 30.7k for Mosquitto (it was 24.7k and 20.0k
  before the change, with 7-16 connections lost per run); at 1 KiB 5.0k against 5.9k (Mosquitto ahead by 15 %, inside the noise). Both
  brokers' single core / worker cores were saturated or close to it.
* **Connections lost per run: 0 in every one of the 24 runs of the new code** (X11 code: 7-16 per flood run, 6-13 per 1 000 msg/s sweep run,
  1 per 300 msg/s run; Mosquitto: 0).
* The sweep at 1 000 messages/s per publisher: 15.9k delivered (it was 8.8k with 6-13 lost connections).

Intermediate images (each change measured as it went in, raw files `urmqtt-x11v-step-*.txt`): the first image (out-of-order queue, scaling, ready-list fix,
NIC backlog; 3036401) already reached 19.7k / 10.3k at 64 B and lost a connection in 2 of 27 runs (X11 code: in 26 of 30); the byte-counting congestion window and the
confirm-at-next-tick watchdog (c202c16) moved the single flow to 27.9k / 18.9k; the dispatcher's NIC polling (019a258) changed nothing
measurable on the VPS (24.8k; inside the noise, ping and one-flow numbers on the rig improved a lot, ADR-224); the close-up ticks and the
in-progress lock wait (86a71ff) removed the last drops.

### 7.3 The local rig (no VPS needed; the rig is in the repository)

`scripts/wan-bridge.c` joins a QEMU `-netdev dgram` socket to a tap in a Linux container, delaying each direction, dropping frames at random
and optionally limiting the rate, with `urmqtt-loadgen` in the same container as a real Linux TCP peer (SACK, timestamps, window scaling);
Docker on a Mac is enough (ADR-223). Guest: the production configuration under HVF, 4 vCPU. RTT 10-15 ms measured by ping through the
bridge. One publisher and one subscriber, QoS 0 flood, 10 s, two runs each; published/s (delivered/s), medians:

| | loss 0 | loss 0.1 % | loss 0.5 % |
|---|---|---|---|
| 64 B, X11 code (7f9517e) | 47.5k (47.5k) | 14.3k (8.8k) | 5.0k (2.5k) |
| 64 B, this tree | 108.2k (66.6k) | 41.0k (18.1k) | 17.7k (9.6k) |
| 1 KiB, X11 code | 4.4k (2.5k) | 1.4k (0.5k) | 0.24k (0.09k) |
| 1 KiB, this tree | 9.1k (4.2k) | 4.1k (1.7k) | 1.9k (0.74k) |

(A guest on this rig loses about 0.3 % of frames to bursts at loss 0; both kernels see it. A Linux stack against a Linux broker on the same
rig, Mosquitto 2.0.18, is not slowed by 15 ms or by 0.1 % loss: 304k and 243k published/s; the rig measures protocol behaviour, not capacity.)
The raw files are in `docs/perf-results/local-wan-rig.txt`.

### 7.4 The watchdog: what the hypervisor does and what the budget now means

**The VPS stalls its vCPUs, often and for long.** From the new `stalls:` line of every core, read over 24 runs (about 80 windows of 5 s per core):

| core | late ticks (>= 4 ms; 0.5 ms while a handler is looked at closely) per 5 s: median / 90th percentile | worst stall per window, median / worst | lock wait per window: median / 90th percentile |
|---|---|---|---|
| 0 (NIC and dispatch) | 80 / 152 | 74 ms / 891 ms | 189 ms / 1.10 s |
| 1 (worker) | 36 / 86 | 76 ms / 945 ms | 357 ms / 1.29 s |
| 2 (worker) | 36 / 77 | 68 ms / 898 ms | 353 ms / 1.33 s |
| 3 (database, log) | 27 / 39 | 279 ms / 1.55 s | 0 / 0 |

(At boot, before any load: 11-47 late ticks per 5 s per core, worst 673 ms.) The host does **not** report KVM steal time (`host steal 0 us`
in every line: the feature is absent or the figure is not maintained on this host), so the guest has only the late-tick and lock-wait
evidence; it cannot say who held the CPU. The Linux guest's `/proc/stat` showed no steal on this VPS in X11 either.

* **X11 code, today, `action = "drop"`, 30 loaded runs:** 247 over-budget reports (median 32 ms, up to 371 ms, 183 on input handlers) and **148 aborted
  connections**; the reports were not the handlers' time: with the same traffic, the new code's console lists 452 handlers whose elapsed time exceeded 20 ms
  with **0 ms of running time** charged (median elapsed 31 ms, 90th percentile 109 ms, up to 900 ms), and **0 reports, 0 aborted
  connections in 24 loaded runs**. The two intermediate images before the last change (confirm at the next tick, 10 ms ticks, a lock wait credited only when it ended)
  still dropped 2 connections in 24 runs each, every time a handler of 32-39 ms with nothing credited: most likely a wait for a lock whose
  holder was a descheduled vCPU (credited only when it ended, ADR-221 point 5) or a run of stalls shorter than a tick.
* So: **our code was not slow; the host was.** The part of the stalls that is urMQTT's own doing is the lock wait: every data core
  spends a median 4-7 % of its time, and in one window in ten 22-27 %, spinning on a ticket lock (the global heap's: blocks above 2 KiB and the per-core
  caches' refills; the data cores share nothing else). A descheduled lock holder is what makes it long. This costs throughput, not connections, and is
  the first thing to attack next (7.5).
* The stuck-core reset (1 s of running time) and the action (`drop`) are unchanged. A handler that really overruns, interrupts enabled,
  is still reported and dropped (smoke `watchdog`, `watchdog-stall`, `watchdog-lockwait`; and the external test below).
* **Injected stalls (rig, production profile, `drop`):** 16 publishers and 16 subscribers flooding QoS 0 while the QEMU process is stopped for
  60 ms every 1.5 s (a descheduled vCPU as the guest sees it): X11 code, 17 stalls: 2 over-budget reports (output handler, 64 and 72 ms);
  this tree, 16 stalls: 0 reports, 0 aborted, and the console names the handlers it did not charge.

### 7.5 What is left (honest list)

* **One flow is still not faster than Mosquitto's.** 64 B: 80 % of its published rate and 40 % of its delivered rate; 1 KiB: 70 % and 40 %.
  Candidates, none measured yet on the VPS: the lock wait (a per-CPU cache for blocks up to 16 KiB would remove most of it), SACK on our sending side
  (a lost segment of a long subscriber stream is retransmitted NewReno-style), and a receive interrupt for the NIC (ADR-224's polling is a stop-gap).
  *2026-11-07:* SACK on our sending side, ACKs on arrival and a validated congestion window are in (ADR-265; rig: one 1 KiB
  subscriber stream 4.3k -> 7.0k delivered/s without loss, 0-27 % more under 0.1-1 % loss, `perf-results/sack-rig-ab.txt`), and
  the NIC asks for 1024 descriptors with a receive-queue statistic (ADR-266; no gain on the rig). *2026-11-08:* measured on both
  VPSes against Mosquitto, section 13: on 4 vCPU one 64 B flow is now ahead of Mosquitto's (87k against 51k delivered/s) and 1 KiB
  inside its range; on one ARM core Mosquitto still wins QoS 0 throughput, and the SACK build is behind v0.4.2 on QoS 1 there
  (13.3, point 4). *2026-11-08, later:* that QoS 1 regression is ADR-265's loss detection counting segments in full
  MSS (an MQTT flow's losses waited for the retransmission timer); fixed in ADR-268, on the rig with one data core
  and 1 % loss back to v0.4.2's numbers or above. The per-CPU heap cache, the receive interrupt and publisher
  back-pressure remain.
  *2026-11-08 (ADR-270):* the receive interrupt is in: virtio-net's MSI-X wakes the dispatcher (x86_64 local APIC; aarch64
  GICv2m frame or GICv3 ITS), ADR-224's 200 us poll stays while NIC traffic is recent (2 ms) and as the fallback. Local rig
  (section 7.3, RTT 4 ms, HVF, two rounds per cell, `perf-results/now13b-rx-irq-rig.txt`), interrupt against polling forced
  with `devices.virtio_net_interrupt = "off"` on the same image:

  | | 2 vCPU (one data core), interrupt | 2 vCPU, polling | 4 vCPU, interrupt | 4 vCPU, polling |
  |---|---|---|---|---|
  | ping, no MQTT connection, mean | 8.7 / 8.5 ms | 14.2 / 14.1 ms | 8.3 / 7.8 ms | 14.8 / 12.7 ms |
  | ping, one idle connection, mean (ADR-224's method) | 9.1 / 8.7 ms | 8.5 / 8.4 ms | 8.3 / 7.8 ms | 8.6 / 8.1 ms |
  | 1 pub / 1 sub, 5 msg/s, p50 / p99 | 8.1 / 10.8, 8.1 / 11.0 ms | 8.1 / 9.9, 8.2 / 10.0 ms | 8.1 / 11.5, 7.3 / 9.5 ms | 7.5 / 10.5, 7.3 / 10.2 ms |
  | host CPU of QEMU, 100 idle mTLS connections, 60 s | **2.9 / 2.9 %** | 29.2 / 28.2 % | **5.0 / 4.8 %** | 31.6 / 31.3 % |
  | host CPU of QEMU, no connection | 2.8 / 2.8 % | 2.8 / 2.6 % | 5.1 / 4.5 % | 4.7 / 5.0 % |
  | 16 x 1000 msg/s QoS 0, p50 / p99 | 6.1 / 11.6, 6.2 / 11.6 ms | 6.2 / 12.3, 6.1 / 12.1 ms | 6.1 / 12.2, 6.0 / 11.4 ms | 6.1 / 11.1, 6.1 / 11.0 ms |
  | 16-pair QoS 0 flood, delivered/s | 341k, 346k | 338k, 297k | 306k, 335k | 342k, 345k |

  What it buys: an idle broker answers the first packet without waiting for the 10 ms tick (about 6 ms off the mean here),
  and idle connections no longer cost a tenth of a host CPU per hundred (the 200 us poll's 5 000 wake-ups a second are
  gone). One idle connection's round trip is unchanged: ADR-224's poll already bounded it to 200 us, which the interrupt's
  delivery under HVF does not beat. No storm: under the flood the dispatcher took 150-730 receive interrupts per 5 s window
  for 110 000-335 000 frames. A first version that armed the interrupt at every idle gap lost a fifth of the flood rate on
  one data core (261-263k/s) and had a p99 of 20-21 ms at 16 x 1000/s (`now13b-rx-irq-rig-v1.txt`), hence the 2 ms hold.
  Not measured on a VPS yet (KVM's interrupt delivery and halt polling differ from HVF's).
* **Stalls shorter than a millisecond** and the last part of every stall before a tick's deadline are still charged; with close-up ticks (1 ms) the error per tick is
  below 1 ms, so a drop now needs a handler that really ran for most of 20 ms or stalls of 20 ms in 1 ms pieces.
* The comparison with Mosquitto is one session, one path, one generator at 60-77 % steal; two cells (1 KiB, 16 pairs; delivered rate of one flow)
  are in its favour, three in ours, one is a tie. Not measured again: handshakes (the change does not touch the handshake path; `dp-bench` on the
  rig scaled 3.82x on 4 worker cores as before), idle capacity, fan-out.
* Memory per connection grew by 16 bytes (`Conn` 96 to 112) and a core now keeps up to 16 MiB of out-of-order data in the worst case, both bounded.

### 7.6 Reproduce section 7

* VPS: as section 6, with `scripts/mkbench.sh --x11 --static ADDR/LEN GATEWAY --env bench-x11v`, then `MAXLOAD=10 CONSOLE=1 REPS=3 THROUGHPUT_CFGS="0 64 16;0 1024 16"
  SWEEP_CFGS="0 64 1000" ./x11-bench.sh LABEL single throughput sweep` on the load host (with `x11-console.py` next to it: it reads the broker's console and `$SYS` counters
  over MQTT with only Python's standard library). Build the generator for the load host with the pinned nightly; ISO, image and reinstall as ADR-213 says.
* Local rig: a Docker image with `iproute2`, `gcc`, the pinned Rust nightly and the generator; `gcc -O2 -o wan-bridge scripts/wan-bridge.c`; inside the container
  `wan-bridge 27001 RTT_MS LOSS_PERCENT 0 1000` (start it before the guest: it learns QEMU's address from the first frame), and
  `scripts/run-qemu.sh --iso ISO --accel hvf --smp 4 --dgram 27002:27001` with a static-address image (`mkbench.sh --x11 --static 10.0.2.15/24 10.0.2.2`).
  The generator then connects to 10.0.2.15 from the container.

## 8. The plaintext path against the TLS path (P1, ADR-230)

`scripts/plain-bench.sh` boots one development image that serves TLS on 8883 and plaintext (anonymous mode) on 1883, 4 vCPUs under HVF
on an Apple-silicon laptop, reached through QEMU user networking, and drives both ports with the same `urmqtt-loadgen` (`--plain 1` for
plaintext). A second image in password mode measures logins. Heap 128 MB, the handshake limits and the publish rate lifted (a measurement
image, never a deployment). Three runs of 10 s each; raw output of the run quoted here: `docs/perf-results/plaintext-vs-tls.txt`.

| Load (16 publisher/subscriber pairs, 64 B unless noted) | TLS 1.3 + client certificate | plaintext |
|---|---|---|
| QoS 0, 500 msg/s each, delivered/s | 8000, 8000, 8000 | 8000, 8000, 8000 |
| same, latency p50 / p99 | 0.17 / 0.43 ms | 0.13-0.18 / 0.42-0.43 ms |
| QoS 1, 500 msg/s each, delivered/s | 8000 x 3 | 8000 x 3 |
| QoS 0, 512 B, 500 msg/s each, delivered/s | 8000 x 3 | 8000 x 3 |
| New connections per second (32 clients) | 2757, 2704, 2598 | anonymous 7824, 4893, 4868 |
| New connections per second, password mode (PBKDF2, 10 000 iterations) | - | 334, 308, 342 |

**What this says.** At a rate both can carry, the two paths deliver every message with the same latency: on this rig the record layer is
not visible at 8 000 messages a second. A plaintext connection costs less to set up (about 2x the TLS rate here, with the rig and the
generator in the way), and **a password login is the expensive part**: one PBKDF2 at 10 000 iterations costs about 2.5 ms on the guest's
cores (measured at boot, `plaintext: one password check costs about 2506 us`), so the login admission caps new password connections at
about 200 a second per data core, and the measured 310-340 a second over two data cores is that cap. Anonymous and `ip` modes have no
such cost. That is the price of a hash that is expensive to guess; it only matters in a reconnect storm, where the cap protects TLS clients
from sharing the cores with a flood of logins (the rate is also capped by `limits.handshakes_per_core_per_sec`).

**Since ADR-267** the default is 100 000 iterations: one check costs about 25.7 ms under HVF on this machine (boot line
`plaintext: one password check costs about 25683 us`), so the admission allows 19 new password logins a second per data
core, about a tenth of the row above (not re-measured with the load generator). Hashes made with 10 000 keep their cost.

**What this does not say.**
- The single-flow flood (1 pair, QoS 0, as fast as possible) ranged from 20k to 440k delivered a second between runs on both ports. The
  rig (user-mode networking, one generator thread per client, a guest that the watchdog resets when a core stays in one handler for a
  second) is not a stable instrument for floods. **No flood conclusion should be drawn**, and no claim that plaintext is faster or slower
  there. A flood from 16 pairs wedged the guest (the watchdog reset it) on both ports; the table above therefore uses a fixed rate.
- 32 connections opened at once time out in the user-mode network on both ports; the pair rows open 4 at a time (`--open-par 4`).
- The generator's CPU (whole process, user plus system, per wall second) is in the raw file; it stayed under 0.35 cores for the fixed-rate
  rows, so the generator is not the limit there. It is near one core in the flood rows.
- It is a laptop, not a VPS. The plan asked for plaintext against Mosquitto on the same VPS; that comparison needs the VPS (excluded
  from this task) and is open. The numbers above are not a capacity statement.
- The TLS path itself did not change: the plaintext listener adds one port comparison per SYN and per accepted connection, and an
  `Option` test on the connection-close path. No TLS-path row of sections 3 to 7 was re-measured on a VPS.

Reproduce: `scripts/plain-bench.sh --runs 3` (needs a kernel from `make build ENV=dev` and the Mosquitto-free host tools only).

## 9. Encryption at rest (S7, ADR-240)

AES-256-XTS under the disk layer, one 512-byte sector per data unit. Numbers, with what they are.

**XTS throughput, one core** (`cargo test -p urmqtt-store --release --lib crypt::tests::xts_throughput -- --ignored --nocapture`, Apple silicon host, 1 MiB of sectors in a loop, the `aes` crate):

| Backend | Encrypt | Decrypt |
|---|---|---|
| ARMv8 AES (`--cfg aes_armv8`, as the kernel is built) | 3109 MB/s | 3103 MB/s |
| software (no `--cfg`; what the kernel **refuses** to run) | 252 MB/s | 258 MB/s |

x86_64 uses AES-NI through the `aes` crate's own runtime detection; it was **not measured on KVM or on the Intel PC** (the smoke scenario runs on TCG, whose timing means nothing).

**The in-guest database benchmark** (`test=db-bench`, 5000 inserts in 50 transactions, aarch64 HVF, the same image with the configuration packed without and with `storage.encryption`, five runs each, interleaved; `SMOKE_ONLY=storage SMOKE_SCENARIOS=storage_encrypted_bench scripts/smoke.sh --accels hvf`):

| | ops/s, five runs | median | µs per commit, median |
|---|---|---|---|
| off | 49239, 47401, 50802, 53417, 46531 | 49239 | 2030 |
| on | 57790, 46173, 45939, 52787, 49632 | 49632 | 2014 |

The spread between runs (46k to 58k) is larger than the difference between the medians (+0.8 %): **no overhead is measurable here**. That is what the arithmetic says too: this benchmark writes 1572 sectors-worth of 4 KiB blocks and 319 flushes per run, about 6 MB, which at 3 GB/s is about 2 ms of AES in a run of 100 ms; a commit waits for the flush, not for the cipher. The acceptance line (≤ 5 %) is met on this hardware. Not measured: telemetry throughput at the disk's limit, the backup benchmark and boot time with encryption on (the first boot of a blank disk formats the same regions either way), the x86_64 machines.

**In the Diagnostic entry:** the crypto stage measures AES-256-XTS over 512-byte sectors on the machine it runs on, shows it under the crypto bars with whether the CPU has hardware AES (amber, "storage.encryption would be refused", when not), and writes `aes_xts_mib_s` and `aes_xts_hardware` into the JSON report. It is the cipher only, not a disk.

**The offline conversion** (`urmqtt-disk encrypt`, 54 MiB partition with 12 MiB used, a file on an SSD): the unused 43 MiB are skipped as holes. Its cost is reading and writing the used part once, plus a flush per MiB.


## 10. P-256 on the ARMv8 `nistz256` assembly (ADR-255)

**What this is and is not.** Microbenchmarks of the P-256 operations a handshake performs, before (RustCrypto's
portable code, `main` at eb3a5d3) and after (the vendored OpenSSL ARMv8 assembly). **All figures are from an Apple M4
Pro**, not from the target CPU: an Apple core is not a Neoverse N1, has different multiplier latencies and a much
larger out-of-order window, and the ratios on the netcup VPS may differ. The VPS (Neoverse N1, where verify took
508 us, sign 141 us and a mutual-TLS handshake 1.08 ms before this change) has **not** been measured with it.

**Host, production paths** (`cargo run --release -p urmqtt-tls --example profile`, which calls `provider::fastec`
as the handshake does; Docker 28 `linux/arm64` container on macOS, image `urmqtt-ci`, nightly-2026-10-20; both trees
built in the same container and run interleaved, 11 runs each; minimum / median in microseconds):

| | before | after | ratio (min) |
|---|---|---|---|
| key generation | 30.8 / 31.2 | 6.97 / 7.01 | 4.4x |
| ECDH P-256 | 135.2 / 137.5 | 25.0 / 25.1 | 5.4x |
| ECDSA sign | 34.7 / 35.4 | 11.6 / 12.1 | 3.0x |
| ECDSA verify (unknown key) | 147.4 / 152.1 | 29.1 / 29.6 | 5.1x |
| CA verify (registered issuer) | 54.2 / 55.7 | 9.6 / 10.0 | 5.6x |
| X25519 base / shared (unchanged code) | 7.4 / 20.4 | 7.5 / 20.1 | 1.0x |
| handshake estimate (the profile's sum) | 292 / 297 | 104 / 105 | 2.8x |

**Primitives** (`cargo test --release -p urmqtt-nistz256 -- --ignored --nocapture timings`, same container, best of
30 x 50): field multiplication 23 ns, squaring 15 ns, point doubling 165 ns, addition 315 ns, field inversion 2.8 us,
scalar inversion 4.5 us, constant-time generator multiplication 4.46 us (3.03 us variable time: the difference bounds
the cost of the constant-time table scans), variable-base multiplication 23.7 us, a trust-anchor `KeyTable` 0.53 ms.

**In the kernel** (the boot's own `crypto-profile` line, the same `bench::run`; smoke scenario `boot-acpi`, QEMU with
HVF on the M4 Pro, 4 vCPU; `main` and this change booted alternately, three boots each, median in microseconds; the
first `main` boot was slower in every P-256 row and is inside the medians):

| | before | after | ratio |
|---|---|---|---|
| key generation | 35.9 | 10.2 | 3.5x |
| ECDH P-256 | 155.9 | 27.3 | 5.7x |
| ECDSA sign | 44.3 | 18.9 | 2.3x |
| ECDSA verify | 164.3 | 32.8 | 5.0x |
| CA verify | 63.1 | 11.4 | 5.5x |
| handshake estimate | 347 (349, 347, 593) | 141 (142, 141, 143) | 2.5x |

The in-guest `dp-bench` (client and server in the guest, full TLS 1.3 + mTLS + CONNECT) gave 4008-4018 handshakes/s
on one worker core and 13 012-14 161 on four after the change; the same scenario did not complete on the `main`
snapshot in this session, so there is no before figure for it.

Reproduce: the two `cargo` commands above inside `linux/arm64` Docker (or natively on aarch64 Linux); for "before",
the same on a checkout of eb3a5d3.


## 11. The netcup ARM64 VPS (Neoverse N1), before and after the assembly (ADR-255)

**What this is.** The first real aarch64 server core in these records: netcup "VPS 500 ARM G12.5", Neoverse N1 at
about 3 GHz, **2 vCPUs**, 3.9 GiB, QEMU/KVM with UEFI, virtio-net and virtio-blk (the Diagnostic entry's PCI list is
in the PNG of the blog text). The server was the benchmark image of `scripts/mkbench.sh --x11` (handshake limits
relaxed, the production code paths otherwise), **installed on the VPS's disk** by the ISO's installer and booted from
it. The load generator is `urmqtt-loadgen` (the same binary as section 3) run on the shared build server, 9 ms away,
pinned to two CPUs under `nice -n 19` (`scripts/x11-bench.sh`, three repetitions, median and range). Because the VM has
two vCPUs, **core 0 does the network card, the dispatching and all MQTT and TLS work and core 1 is the database core**
(2 to 3 % busy throughout): every figure below is single-core broker performance. Raw output:
`docs/perf-results/urmqtt-netcup-before-asm.txt` and `docs/perf-results/urmqtt-netcup-asm.txt`
(`scripts/x11-report.py` turns them into tables). The load host is shared: it lost 3 to 60 % of its own CPU to other
guests during the runs, which is why one repetition of each set is an outlier.

**Full mTLS handshakes per second** (TLS 1.3 + client certificate + CONNECT, no resumption, 0 errors in every run), the
image before the assembly (main at the commit of the first netcup run, portable RustCrypto P-256) and after it
(`v0.3.0-29-gefddf6e`, ADR-255):

| threads | before | after | ratio |
|---|---|---|---|
| 32 | 848 (408-855) | 1,317 (957-1,317) | 1.55x |
| 64 | 827 (815-839) | 1,398 (1,352-1,416) | 1.69x |
| 128 | 778 (714-788) | 1,316 (1,313-1,383) | 1.69x |

The TLS part of a connection at 32 threads: p50 18.5 ms before, 13 ms after. At 128 threads the generator is at its own
limit on both machines (section 3.1).

**The server's own CPU per handshake**, from the Diagnostic entry's crypto stage (the boot's `bench::run`), **one run
with the assembly** against three runs before it: handshake **553 us** after (ECDSA verify 192.5 us, sign 77.8 us,
X25519 208.5 us), against about 1.0 to 1.08 ms before (verify 507.5 to 509.8 us, sign 125.4 to 142.1 us, X25519 156.4
to 176.8 us, three runs). The run with the assembly was at a CPU clock of 2.58 GHz against 2.95 to 2.98 GHz in the runs
before, so single figures on this shared machine move by tens of percent (the X25519 figure is unchanged code and went
from 176 to 209 us). It is one run. That the handshake rate rose 1.55 to 1.7 times while the server's CPU per handshake
fell about 1.95 times fits together: the rest of a connection is the stack, the generator and the network. X25519
(about 176 us of what remains) is the next candidate.

**The rest of the suite, after the assembly only** (there is no "before": the run was stopped to build the assembly,
the first rows of it are in the "before" file): idle connections 5 000 / 10 000 / 20 000 held without an error, kernel
heap growth 0.34 / 0.41 / 0.43 KB per connection (`$SYS/broker/memory/used` against its value before the first
connection; 0.50 to 0.66 KB on the x86_64 server at the H7 commit); latency at 800 messages/s (8 pairs x 100, 64 B) p50
4.0 ms (QoS 0) and 4.1 ms (QoS 1), p99 6.9 and 7.0 ms; fan-out to 100 subscribers at 50 messages/s delivered
completely (5 000/s, p50 5.9 ms, p99 8.6 ms), to 1 000 subscribers at 10 messages/s 8 805 of 10 000 per second (p50
207 ms, p99 5.4 s); flood with 16 pairs: QoS 0, 64 B, 231 317 published and 85 140 delivered per second (p50 1.36 s) with
**no connection lost**, QoS 1, 64 B, 107 349 published and 55 965 delivered per second (p50 21 ms, p99 29 ms). These are
**not comparable** with the x86_64 rows of sections 3 and 7: other CPU, 2 vCPUs against 4, another distance to the
generator (the latency is one trip), and the code between the two measurements changed in the data path (ADR-221 to
ADR-224).

**Other facts from the same machine** (Diagnostic entry, PROGRESS "netcup ARM64 VPS"): AES-XTS 217 to 248 MiB/s per
core with hardware AES, AES-GCM 272 to 321 MiB/s; the installed 64 GiB virtio-blk disk read 332 to 484 MiB/s
sequentially (64 KiB blocks) and 22 to 27 thousand random 4 KiB reads per second (p50 9.5 to 10.4 us, p99 398 to
671 us); RAM read 4.7 to 9.0 GiB/s.



## 12. The server's handshake, stage by stage, and three changes (ADR-259)

**What this is and is not.** Every figure in this section is from **Docker `linux/arm64` on an Apple M4 Pro** (image
`urmqtt-ci`, nightly-2026-10-20, release build, `RUSTFLAGS="--cfg aes_armv8 --cfg polyval_armv8"` so the AEADs use the
same hardware paths as the kernel) or from QEMU/HVF on the same Mac. **Nothing here was measured on the Neoverse N1**
(the netcup VPS of section 11) or on any other server core; an Apple core has more multipliers and a much larger
out-of-order window, so the ratios on the N1 may be different in either direction.

**Method.** `cargo run --release -p urmqtt-tls --features stage-profile --example handshake_profile` (new; ADR-259):
a stock rustls client with our provider runs full TLS 1.3 + mutual-TLS handshakes against `TlsServer` with the dev
certificates (P-256 CA, server and device keys; X25519; AES-128-GCM, the client's first choice), resumption off, and
only the server's `accept`/`input` calls are timed. The stages are exclusive (a signature check inside webpki's path
validation is counted once, under the signature); "rest" is the armed time no stage accounts for. Median round of 9
rounds x 200 handshakes per process, three processes per tree, before and after interleaved. "Before" is v0.4.0's
crypto (6cc343b) with the profiler added (the profiler is a no-op without its feature; the "before" tree is 1fb37ba
with its trust-anchor fix reverted). Microseconds per handshake:

| stage | returning, before | returning, after | first contact, before | first contact, after |
|---|---:|---:|---:|---:|
| X25519 key share (dalek fixed-base table) | 7.5 | 7.6 | 7.6 | 7.5 |
| X25519 shared secret | 19.6 | 15.2 | 19.8 | 15.2 |
| ECDSA sign (our CertificateVerify) | 12.4 | 12.1 | 12.4 | 12.2 |
| ECDSA verify, the client's CertificateVerify (unknown key) | 29.5 | 25.7 | 29.4 | 25.7 |
| ECDSA verify, the client certificate by the CA | memo hit | memo hit | 29.4 (unknown-key path) | 7.4 (CA table) |
| verification memo (digest, lookup) | 0.3 | 0.3 | 0.3 | 0.3 |
| webpki path validation (x509/DER parsing, checks) | 0.3 | 0.3 | 0.3 | 0.3 |
| serial, revocation, role | 0.3 | 0.3 | 0.3 | 0.3 |
| SHA-256 transcript (23 calls) | 1.6 | 1.6 | 1.6 | 1.6 |
| HMAC-SHA-256 / HKDF (45 calls) | 3.8 | 3.7 | 3.8 | 3.7 |
| AEAD of the handshake records (7 calls incl. key setup) | 3.8 | 3.8 | 3.8 | 3.8 |
| session ticket seal | 1.1 | 1.1 | 1.1 | 1.1 |
| RNG | 0.2 | 0.2 | 0.2 | 0.2 |
| finish: identity, serial, record keys | 2.5 | 2.5 | 2.5 | 2.5 |
| rest: rustls state machine, encoding, copies, allocation | 6.1 | 5.9 | 6.2 | 5.9 |
| **total (server), the run above** | **88.8** | **80.3** | **118.6** | **87.8** |
| total, all three processes | 88.8, 89.5, 93.9 | 80.3, 80.5, 80.5 | 118.6, 118.6, 123.8 | 87.8, 88.1, 88.5 |

(The "before" first-contact row splits its 58.7 us of unknown-key verification into two equal calls.) Allocations: 164
per handshake (48 KiB requested), unchanged. A resumed handshake (session ticket, `psk_dhe_ke`), after: 40.6 to 40.9 us
(X25519 key share 7.3 and shared secret 14.6, HKDF 4.6, AEAD 2.1, finish 2.7 (the chain from the ticket is checked
again), rest 6.5). The key-share figure is bimodal from process to process (7.5 us or 10.3 to 12.4 us, in both trees: the
placement of dalek's 30 KiB table), which is why three processes are shown.

**What changed** (ADR-259):
1. **The trust anchors get their tables.** `register_issuer` could not parse the key in the form webpki stores it, so
   since ADR-111 no anchor had a table and a device's first handshake verified its certificate on the unknown-key path.
   First contact: 118.6 -> 100.3 us with this fix alone (one process).
2. **X25519 shared secret on AArch64 in `mul`/`umulh` assembly** (`urmqtt-x25519`, `Backend::Armv8`) instead of dalek's
   51-bit ladder: one ladder 13.4 us against 18.0 us (microbenchmark), 19.6 -> 15.2 us in the handshake.
3. **P-256 verification**: a width-5 NAF for `u2 Q` (19.3 us against 21.7 us for the constant-time multiplication)
   and a variable-time scalar inversion (1.17 us against 3.89 us). Unknown key 29.5 -> 25.7 us in the handshake,
   CA table 10.1 -> 7.4 us. Shared code, so x86_64 gets it too (not measured).

Items that did not pay or were not built: interleaving `u1 G` into the NAF's doubling chain (the comb already has no
doublings; at most 0.4 us, and the mixed addition has no doubling case); wNAF widths 4 and 6 (computed: both worse than
5); everything outside the public-key operations (no stage above 5 %: HKDF 4.7 %, AEAD 4.7 %, the rest of rustls 7.4 %,
which is not ours to change cheaply); a cache of verified certificates (ADR-260: about 1 us of 80 us on top of the
memo, a security decision, not built).

**Primitives** (`cargo run --release -p urmqtt-tls --example profile`, the production paths, v0.4.0 and this branch
built in the same container and run interleaved, 7 runs each, minimum / median in microseconds). Note that
`ecdsa-verify-ca` measures a table it builds itself, so it never showed fix 1:

| | v0.4.0 | this branch | ratio (min) |
|---|---|---|---|
| X25519 key share (`x25519-base`) | 7.4 / 7.5 | 7.4 / 7.5 | 1.0x |
| X25519 shared secret (`x25519-dh`) | 20.0 / 20.3 | 14.4 / 14.6 | 1.38x |
| P-256 key generation | 6.7 / 6.9 | 6.7 / 6.8 | 1.0x |
| ECDH P-256 | 24.3 / 24.7 | 24.4 / 24.6 | 1.0x |
| ECDSA sign | 11.4 / 11.5 | 11.4 / 11.5 | 1.0x |
| ECDSA verify (unknown key) | 28.3 / 29.0 | 24.2 / 24.5 | 1.17x |
| CA verify (table) | 9.5 / 9.8 | 7.1 / 7.2 | 1.35x |
| handshake estimate (the profile's sum) | 92.1 / 92.8 | 79.8 / 80.8 | 1.15x |

**In the kernel** (the boot's `crypto-profile` line, smoke scenario `boot-acpi`, QEMU with HVF on the M4 Pro; v0.4.0 and
this branch booted alternately, three boots each, median in microseconds): X25519 shared secret 22.1 -> 15.8, ECDSA
verify 32.9 -> 27.7, CA verify 11.4 -> 8.5, key share 8.5 -> 8.5, sign 18.8 -> 18.8, the estimate 141.5 -> 127.6 (all
three: 137.6, 141.5, 142.8 -> 127.6, 128.9, 126.6). The estimate counts the CA verify through a table it builds itself,
so a real first contact on v0.4.0 cost about 20 us more than its estimate (fix 1).

**Field arithmetic** (`cargo test --release -p urmqtt-x25519 -- --ignored --nocapture timings` and the same for
`urmqtt-nistz256`, Docker, chained operations, so latency): X25519 multiplication 7 ns (portable 12 ns), squaring 6 ns
(portable, as a multiplication, 12 ns), addition about 1 ns, subtraction 4 ns (Rust), `* 121665` 3 ns (Rust); P-256
doubling 60 ns, addition 105 ns, `inv_n` 3.9 us, `invert_vartime` 1.17 us.

**For the VPS (the owner's measurement).** The same benchmark image as section 11, from this branch:
`scripts/mkbench.sh --x11 --env bench-netcup --static ADDR/LEN GATEWAY` (the netcup address and gateway of section 11,
certificates as then: `--certs DIR`), installed or booted as in section 11; then the Diagnostic entry's crypto stage
(the boot's `crypto-profile` line, which now also prints `x25519=armv8` in the `crypto:` line) and
`scripts/x11-bench.sh` for the handshake rate. Expect on the N1: the X25519 and the two verification rows to fall,
the key share and the signature to stay; how much is the open question this section cannot answer.

### 12.1 Measured on the netcup Neoverse N1 (2026-11-04, evening)

The question the previous paragraph leaves open, answered once, with the image built from this branch (`v0.4.0-4-g116e1c5`,
the three changes of ADR-259) on the same VPS, the same load generator and the same method as section 11
(`docs/perf-results/urmqtt-netcup-tlsopt.txt`, `docs/perf-results/netcup-diag-tlsopt.json`).

**The server's CPU per handshake, from the Diagnostic entry's crypto stage** (one run each; the CPU clock differs between
the runs, 2.58 GHz with the assembly alone, 2.89 GHz now, so single figures on this shared machine move by tens of
percent):

| | portable P-256 (about) | P-256 assembly (ADR-255), 2.58 GHz | this branch, 2.89 GHz |
|---|---|---|---|
| X25519 (shared secret) | 156 to 177 us | 208.5 us | **127.9 us** |
| ECDSA verify, unknown key | 508 to 510 us | 192.5 us | **124.0 us** |
| ECDSA sign | 125 to 142 us | 77.8 us | 67.8 us |
| handshake (the stage's estimate) | about 1.0 to 1.08 ms | 553 us | **461 us** |

**Full mTLS handshakes per second** (the benchmark image, handshake limits relaxed, 0 errors in every run; median of three
runs and the range; the load host is shared, one run of each set is usually an outlier):

| threads | portable P-256 | P-256 assembly | this branch | against the assembly | against portable |
|---|---|---|---|---|---|
| 32 | 848 (408-855) | 1,317 (957-1,317) | **1,451 (1,044-1,459)** | 1.10x | 1.71x |
| 64 | 827 (815-839) | 1,398 (1,352-1,416) | **1,624 (1,357-1,645)** | 1.16x | 1.96x |
| 128 | 778 (714-788) | 1,316 (1,313-1,383) | **1,599 (1,377-1,625)** | 1.22x | 2.05x |

The TLS part of a connection at 32 threads: p50 18.5 ms (portable), 13 ms (assembly), 11.3 to 12.3 ms now. What is
established: the full-handshake rate rose about 1.1 to 1.2 times over the assembly of ADR-255 and about 1.7 to 2.05
times over the portable code; the stage figures of X25519 and of the verification fell as the Apple-silicon profile
above predicted, by more than the clock difference explains. What is not: the share of this that is the shared load host
(the ranges overlap between the assembly and this branch at 32 threads), a second run on another day, and any other
server core.

### 12.2 The anchor tables' heap and the `storm` hang (ADR-261)

QEMU HVF on the Apple M4 Pro, 4 vCPUs, the dev image with `heap_limit_mb=8` (admission as if the heap had 8 MiB;
`min_free_mb = 4`), one run each unless stated. Kernels: v0.4.0 (6cc343b), 51fabe2 (ADR-259, before this fix), 51fabe2
without the `register_issuer` call (the bisection), and this fix.

**Idle heap with one connection** (`mem: 1 connection(s), heap ... in blocks`, the 25 s report):

| kernel | heap in blocks | requested | tables (boot line) |
|---|---|---|---|
| v0.4.0 | 1,510 KiB | 953 KiB | none (A259-W1) |
| 51fabe2 | 2,287 KiB | 1,406 KiB | 3, not reported (one 256 KiB block each) |
| 51fabe2 without registration | 1,510 KiB | 953 KiB | none |
| this fix | 1,964 KiB | 1,407 KiB | `3 ... table(s), 445 KiB of heap` |

The tables are one registry for all cores, not per core: the figures above are the whole heap of a 4-vCPU guest
(three data cores), and the fix's boot line is measured on the boot CPU before the data cores start.

**`storm` (3000 clients, 8 threads, `--retry-s 30`):**

| kernel, loadgen | rounds: connected of 3000, seconds | result |
|---|---|---|
| v0.4.0, old loadgen | 2,997 in 34.2 / 2,987 in 64.4 / 2,996 in 71.1 | pass |
| 51fabe2, old loadgen | round 1 at 2,741 after 190 s, core 0 at 100 % from about 97 s | hang (killed) |
| TCP fix only (tables of 256 KiB), old loadgen | 2,932 in 259 / 2,962 in 331 / 2,917 in 319 | pass, 15 min |
| this fix, new loadgen (3 runs) | 2,071-2,349 / 1,448-1,888 / 1,321-1,811, each round 34-36 s | pass 3 of 3, 124-126 s each |
| 51fabe2 without registration, new loadgen | 2,959 / 1,928 / 2,077 | pass |
| 51fabe2, new loadgen | 1,951 / 1,204 / 1,338 | pass (the rounds end before any keep-alive expires, so the FIN loop is not reached: hence the `fin_wait2` scenario) |

The old loadgen checked its deadline only between passes over a thread's devices, so a round lasted as long as the
dropped SYNs made it (each costs a device a 1 s SYN retransmission); the new one stops at `--retry-s`, which is why
fewer connect per round. Fewer connect with the tables than without in the same 30 s because 445 KiB of a 4 MiB
admission budget are gone; that is the intended price of a fast first contact, and in a production heap (1 GiB in the
template) it does not register. **The keep-alive closes with the FIN loop** (A261-W1), from the v0.4.0 kernel too:
`loadgen hold --clients 500 --keepalive 5 --duration 40`: core 0 100 % busy and 3.7 million frames dispatched per
5 s; with the fix 27 % and 132 frames per 5 s (the same kernel's level when nothing happens is about 27 %).

## 13. Two VPSes, three brokers, each VPS measured from the other (2026-11-07/08)

**What this is.** The X11 suite run on two machines with the two urMQTT builds the day had (the release **v0.4.2**
and `main` at **318f60b**, which adds ADR-265 SACK recovery / ACKs on arrival / the validated congestion window and
ADR-266 deeper NIC queues) and **Mosquitto 2.0.21** (Debian 13 package, OpenSSL 3.5.7, `scripts/x11-mosquitto.sh`,
the same CA and server certificate). The two machines are the Contabo x86_64 VPS of the earlier sections (4 vCPU AMD
EPYC, KVM, 8 GiB) and the netcup ARM64 VPS of section 11 (2 vCPU Neoverse N1; **one core does the network card, TLS,
the broker and the dispatching, the other is the database core**). Each VPS was loaded **from the other VPS**: netcup
(Debian 13, `urmqtt-loadgen` pinned to its two cores) generated the load for Contabo, Contabo (Debian 13, two of its
four cores) for netcup; 12 ms apart, 0 % steal on either generator in every run. On each machine the three brokers
were measured one after the other with the same generator, the same suite and the same order: `handshake`,
`throughput`, `latency`, `fanout`, `idle`, `sweep`, `single`, three repetitions each, median and min-max. A first pass
on Contabo from the shared build server (10-45 % steal) is kept as `contabo-urmqtt-*.txt` and `contabo-mosquitto.txt`
and is **not** used below; it made the same ranking with wider ranges.

Raw files: `perf-results/x11-2026-11-07/` (`*-from-netcup.txt` for Contabo, `netcup-*.txt` for netcup; `.console`
holds urMQTT's console and `$SYS` counters per run, `.ss` the generator's `ss -tin` samples). Tables:
`perf-results/x11-2026-11-07/tables.md` (`scripts/x11-report.py`). Figures: `perf-results/x11-2026-11-07/charts/`
(`scripts/x11-charts.py`; every figure puts the two machines side by side on one scale).

### 13.1 Contabo, x86_64, 4 vCPU (generator: netcup)

Delivered messages per second unless said otherwise; median (min-max) of three runs.

| | urMQTT v0.4.2 | urMQTT main 318f60b | Mosquitto 2.0.21 |
|---|---|---|---|
| New mTLS connections/s, 128 threads | 1,830 (1,368-1,834) | **1,956** (1,912-1,985) | 639 (599-697) |
| TLS p50 at 128 threads | 36 ms | 35 ms | 130 ms |
| 16 pairs, QoS 0, 64 B, flood | 125k (91-156k) | **201k** (182-212k) | 60k (54-61k) |
| 16 pairs, QoS 0, 1 KiB, flood | 20.3k | 22.2k | 22.1k |
| 16 pairs, QoS 1, 64 B, flood (acked / delivered) | 45k / 22.4k | 40k / 22.3k | 36.5k / 18.9k |
| 64 pairs, QoS 1, 64 B, flood (delivered) | 50k (38-52k) | **69k** (62-78k) | 30k (20-32k) |
| 1 flow, QoS 0, 64 B (published / delivered) | 59k / 54k (34-72k) | **94k / 87k** (71-97k) | 51k / 51k (48-53k) |
| 1 flow, QoS 0, 1 KiB (delivered) | 7.2k (5.0-8.3k) | 10.0k (6.2-13.6k) | **12.0k** (7.7-16.1k) |
| 1 flow, QoS 1, 64 B (delivered; p50) | 1.8k; 37 ms | **2.1k**; 33 ms | 1.1k; 801 ms |
| 16 x 1000/s, QoS 0: p50 / p99 latency | 11.1 / 138 ms | **7.3 / 27 ms** | 12.3 / 95 ms |
| 16 x 1000/s, QoS 1: delivered; p50 / p99 | 15.2k; 11.1 / 159 ms | **15.7k; 8.6 / 124 ms** | 14.3k; 38 / 2,085 ms |
| 8 x 100/s, QoS 0: p50 / p99 | 10.2 / 37 ms | 7.0 / 20 ms | **6.3** / 48 ms |
| Fan-out 1 -> 100, QoS 0, flood (delivered) | 276k | **287k** | 106k |
| Fan-out 1 -> 1000 at 10/s (delivered; p50) | 10,000; 28 ms | 10,000; **21 ms** | 10,000; 22 ms |
| 20,000 idle mTLS connections: memory held | 17.9 MB heap | 17.6 MB heap | **546 MB RSS** (its own heap counter: 17.1 MB) |
| 20,000 idle connections opened in | 40 s | 38 s | 51 s |
| Lost connections, any run | 0 | 0 | 0 |

### 13.2 netcup, ARM64, 2 vCPU, one broker core (generator: Contabo)

| | urMQTT v0.4.2 | urMQTT main 318f60b | Mosquitto 2.0.21 |
|---|---|---|---|
| New mTLS connections/s, 128 threads | **923** (834-1,156) | 820 (646-857) | 419 (411-425) |
| TLS p50 at 128 threads | 56 ms | 44 ms | 194 ms |
| 16 pairs, QoS 0, 64 B, flood (published / delivered) | 187k / 46.5k | 183k / 43.7k (40-69k) | 60k / **57.9k** |
| 16 pairs, QoS 0, 1 KiB, flood (delivered) | 12.6k | 12.4k | **14.8k** (10-15k) |
| 16 pairs, QoS 1, 64 B, flood (acked / delivered) | 36k / **17.5k** | 26k / 14.1k | 23k / 14.8k |
| 64 pairs, QoS 1, 64 B, flood (delivered) | **51.8k** | 42.4k | 20.1k |
| 1 flow, QoS 0, 64 B (delivered) | 11.8k (10-15k) | 22.3k (13-25k) | **48.7k** (34-52k) |
| 1 flow, QoS 0, 1 KiB (delivered) | 2.7k (0.45-3.8k) | 2.1k (0.1-3.0k) | **6.1k** (3.4-6.9k) |
| 1 flow, QoS 1, 64 B (delivered; p50) | **1.25k**; 44 ms | 0.94k; 39 ms | 0.96k; 847 ms |
| 16 x 1000/s, QoS 0: p50 / p99 | 18.1 / 137 ms | **11.6** / 238 ms | 18.8 / **69 ms** |
| 16 x 1000/s, QoS 1: delivered; p50 / p99 | **13.0k; 36 / 274 ms** | 8.8k; 33 / 308 ms | 13.0k; 527 / 2,589 ms |
| 8 x 100/s, QoS 0: p50 / p99 | **8.2 / 59 ms** | 15.7 / 218 ms | 8.2 / 140 ms |
| Fan-out 1 -> 100, QoS 0, flood (delivered) | 105k | **124k** | 86k |
| Fan-out 1 -> 1000 at 10/s (delivered; p50) | 8,192; 227 ms | 8,639; 222 ms | **9,841; 56 ms** |
| 20,000 idle mTLS connections: memory held | 10.7 MB heap | 10.8 MB heap | **546 MB RSS** |
| Frames dropped for a full NIC transmit queue in the suite (`frames/dropped/nic`; corrected 2026-11-08, see point 4) | 199,141 | 260,911 | n/a |
| Lost connections, any run | 0 | 0 | 0 |

### 13.3 What the numbers say

1. **With cores to use, urMQTT is ahead everywhere that matters to a fleet.** On the 4-vCPU machine `main` accepts
   3x the new mTLS connections per second (1,956 against 639, with a third of the TLS latency), delivers 3.3x the QoS 0
   messages with 16 clients a side (201k against 60k) and 2.3x the QoS 1 messages with 64 pairs, fans out 2.7x more, and
   has the lower latency at every steady rate (p99 27 ms against 95 ms at 16,000 msg/s; QoS 1 p99 124 ms against 2.1 s).
   Mosquitto is one process on one core (94-100 % of it in every heavy run); urMQTT's cores showed 0.5-2.8 cores busy
   in the first 14 s of those runs (a noisy sample, `BROKERBUSY` in the raw files) for 3.3x the work.
2. **One TCP flow was the weak point (sections 3.6, 7.5); on x86_64 it no longer is.** The SACK/ACK-on-arrival build
   moves a single 64 B stream from 54k to 87k delivered/s, past Mosquitto's 51k, and 1 KiB from 7.2k to 10.0k, inside
   Mosquitto's range (7.7-16.1k, median 12.0k). Latency on one flow halved (p50 427 -> 222 ms). What is left on a
   single flow is the publisher: urMQTT accepts 94k/s and delivers 87k/s because it drops QoS 0 messages to a subscriber
   whose single TCP stream cannot carry them (`messages/dropped/slow_subscriber` in the `.console` files); Mosquitto
   accepts 51k/s and delivers 51k/s because it stops reading the publisher instead (back-pressure). Both are legal for
   QoS 0; ours wins on delivered messages, theirs on "every accepted message arrives". The change that would make
   urMQTT do the latter when the subscriber is the only consumer is the next NOW-13 item. **Since ADR-269**
   (`limits.publisher_backpressure = "single"`, the default) it does: a QoS 0 message whose only subscriber is full
   pauses its publisher instead of being dropped, on the same shard or across shards; on the local rig accepted
   equals delivered and `dropped/slow_subscriber` stays 0 on one flow (section 13.5). **Caveat on "delivered vs
   accepted" in the tables above:** they were measured before ADR-269, so urMQTT's published/s there counts messages
   it read and then dropped; with "single" a published/s figure is what was delivered, and the comparison with
   Mosquitto's single-flow rows is like for like. The VPS rows have not been measured again.
3. **On one ARM core, raw QoS 0 throughput belongs to Mosquitto, everything else to urMQTT.** Mosquitto's event loop
   does more QoS 0 work per core than ours: 58k against 44-47k delivered with 16 pairs, 49k against 12-22k on one 64 B
   flow, 6.1k against 2-3k on one 1 KiB flow. Our single core is spent on the publishers (accepting 183-187k/s that are
   then dropped), on polling the NIC every 200 us (ADR-224; since ADR-270 only while NIC traffic is recent, the receive
   interrupt otherwise, not yet measured on this VPS) and on copies; the NIC's 256-descriptor transmit queue
   was full for 199,000-261,000 frames in the suite, nearly all in the fan-out runs (the netcup virtio-net offers no
   more than 256, so ADR-266's deeper queues could not help there; the first text of this section called these
   receive-queue overruns, but `frames/dropped/nic` counts transmit drops). Where the work is TLS, QoS 1 bookkeeping or fan-out, the same core beats Mosquitto's:
   2x the handshakes, 2.6x the QoS 1 messages with 64 pairs, 1.2-1.4x the fan-out, half the p50 at steady QoS 0 rates,
   and QoS 1 latency in tens of milliseconds where Mosquitto's is in hundreds (its p99 under QoS 1 load is above 2 s
   on both machines).
4. **The SACK build is not uniformly better on one core.** On netcup `main` is 10-30 % behind v0.4.2 on QoS 1 (16 pairs
   14.1k against 17.5k delivered, 64 pairs 42k against 52k, 16 x 1000/s 8.8k against 13.0k) and on the handshake run
   (820 against 923, with a 1.1 s p99 tail). *Found and fixed (ADR-268, 2026-11-08):* the netcup path loses segments
   in both builds (thousands of retransmissions per QoS 1 run against a few dozen on Contabo); v0.4.2 repaired them
   with fast retransmits (16 x 1000/s: 2,024 of 2,088), the SACK build with the retransmission timer (only 355 of
   3,256 fast; the console's "timeouts" counts connections given up, which hid it; the busiest sender sat at `cwnd
   1-4 KiB, ssthresh 2 KiB, rto 200-400 ms`). ADR-265's `IsLost` counted "three segments above the hole" in full
   1448-byte segments, some 25 of an MQTT flow's 100-byte ones, and no longer acted on three duplicate ACKs. Neither
   the CPU (40-46 % busy) nor the transmit ring (732 drops in all QoS 1 runs) nor the window rules were the cause.
   On the local rig with one data core and netcup's loss (1 %) the regression reproduces and the fix removes it:
   16 x 1000/s 13.0k (v0.4.2), 9.0k (`main`), 13.4k (fix); 16 pairs 12.2k, 10.0k, 12.5k; 64 pairs 47.7k, 42.2k,
   49.8k delivered/s; on three data cores the fix adds 0-8 % without loss and 23-46 % at 1 % loss (tables in ADR-268,
   raw `perf-results/adr268-rig.txt`). To be confirmed on netcup.
   The handshake tail is something else: it is in the TCP connect time (`tcp connect` p99 1.02-1.05 s in all nine
   runs, v0.4.2 0.06-0.19 s), i.e. Linux sending its SYN again after 1 s, with 1.5-3 % of our SYN-ACKs never
   answered (cookies sent minus validated; v0.4.2: 0.1-0.2 %). The SYN-ACK code is the same in both builds and the rig
   does not show it (tcp connect p99 20-22 ms for both without loss, 1.04 s for all three builds at 1 % loss); it
   stays open until it is captured on the VPS. Also: `frames/dropped/nic` in the table above counts frames dropped
   because the NIC's **transmit** queue was full (`DropSite::NicTx`), not receive-queue overruns; those the guest
   cannot see (ADR-266's queue-peak line is the only hint).
5. **Memory for idle connections is urMQTT's clearest win, and the earlier text (section 3.2) understated it.**
   20,000 idle mTLS connections cost urMQTT 10.7-17.9 MB of heap in total (there is no other memory: the kernel has no
   process, no page cache, no per-socket kernel state outside that heap), about 0.5-0.9 KB each. Mosquitto's process
   grew to 546 MB RSS on both machines, about 27 KB per connection, almost all of it OpenSSL's per-connection state;
   its own `$SYS/broker/heap/current` (17.1 MB) does not see that memory, which is why the two "17 MB" figures are not
   comparable. The RSS did not fall when the connections closed.
6. **Fan-out to 1000 slow subscribers on one core is a urMQTT weakness**: 8,200-8,600 of 10,000 messages/s delivered
   with a p50 of 220 ms, where Mosquitto delivers 9,800 at 56 ms; on four cores both deliver all 10,000 and urMQTT's
   p50 is the lower (21 against 22 ms). Candidate cause: the per-message walk over 1000 subscriptions on the one core
   that also runs the NIC; to be profiled.
7. **The generator matters as much as the broker.** The same Contabo urMQTT v0.4.2 measured from the shared build
   server gave 1,156-1,834 handshakes/s and 94-132k delivered/s with ranges twice as wide; from the quiet netcup VPS
   the medians rose and the ranges closed. Every number above comes from a generator with 0 % steal, and the two VPSes
   measured each other, which is the setup to reuse.

### 13.4 Reproduce

```sh
# Images: one per machine (static address), both urMQTT builds; the ISO's PKI is the test PKI of deploy/prod.
scripts/mkbench.sh --certs deploy/prod --static 169.58.184.193/17 169.58.128.1 --x11 --env bench-x11-contabo
scripts/mkbench.sh --certs deploy/prod --static 89.58.42.236/22 89.58.40.1 --x11 --env bench-x11-netcup
# Generator on the other VPS (Debian 13): rustup with the pinned nightly, `cargo build --release --locked -p urmqtt-loadgen`,
# scripts/x11-bench.sh, x11-console.py, x11-report.py and certs/{ca.pem,ca.key,operator.pem,operator.key} in /root/x11.
MAXLOAD=10 CONSOLE=1 SS=1 REPS=3 CORES=0,1 DIR=/root/x11 HOST=<vps> BROKER=urmqtt \
  ./x11-bench.sh <label> handshake throughput latency fanout idle sweep single
MAXLOAD=10 SS=1 REPS=3 CORES=0,1 DIR=/root/x11 HOST=<vps> BROKER=mosquitto SSHVPS=root@<vps> ./x11-bench.sh <label> ...
python3 scripts/x11-report.py results/*.txt                      # tables
uv run --no-project --with matplotlib python3 scripts/x11-charts.py OUT "Contabo/urMQTT v0.4.2=..." ...   # figures
```

Contabo was switched between images with the Contabo API (custom images from the ISOs, `cntb reinstall instance`),
netcup with the SCP API (ISO attach + power cycle; Debian via the image setup with `sshKeyIds`). Mosquitto measurements
needed a Debian install on the measured VPS; the production image was restored on Contabo afterwards.

### 13.5 Publisher back-pressure on the local rig (ADR-269, 2026-11-08)

The same suite on the local WAN rig of section 7.3 (aarch64 guest under HVF on the Apple-silicon Mac, 12 ms RTT
through `wan-bridge`, `urmqtt-loadgen` in the container), two runs per row, the images of
`mkbench.sh --x11 --static 10.0.2.15/24 10.0.2.2` with `limits.publisher_backpressure` "single" (the default) and
"off" (the behaviour before ADR-269; same kernel, so the difference is the policy alone). `--smp 2` is one data core
and the database core, like netcup; `--smp 4` is three data cores, where a publisher and its subscriber are usually
on different shards. Five other agents' builds and VMs shared the Mac, so the ranges are wide; each value below is
"run 1 / run 2". Raw files and a summary: `perf-results/backpressure-2026-11-08/`.

| one data core (`--smp 2`) | off: published / delivered | off: dropped | single: published / delivered | single: dropped |
|---|---|---|---|---|
| 1 flow, QoS 0, 64 B | 131k / 130k, 159k / 157k, 154k / 153k, 153k / 152k | 17-21k per run | 124k / 124k, 146k / 146k, 146k / 146k, 165k / 165k, 119k / 119k, 136k / 136k | 0 |
| 1 flow, QoS 0, 1 KiB | 11.5k / 10.8k, 9.4k / 8.9k, 11.9k / 11.4k, 10.1k / 9.9k | 3-12k per run | 12.1k / 12.1k, 10.2k / 10.2k, 9.7k / 9.7k, 9.9k / 9.9k, 9.2k / 9.2k, 9.8k / 9.8k | 0 |
| 1 flow, QoS 1, 64 B (delivered) | 966, 982 | | 978, 979, 946, 950 | |
| 16 pairs, QoS 0, 64 B, flood | 236k / 235k, 261k / 261k | 26-34k | 256k / 256k, 269k / 268k, 251k / 251k, 262k / 262k | 0-112 |
| 16 pairs, QoS 0, 1 KiB, flood | 21.0k / 20.9k, 21.6k / 21.5k | 3.0-3.5k | 21.3k / 21.3k, 20.5k / 20.5k | 0-28 |
| 16 pairs, QoS 1, 64 B (delivered) | 16.6k, 16.7k | | 16.7k, 16.5k | |
| 16 x 1000/s, QoS 0: p50 / p99 | 14 / 23 ms, 14 / 23 ms | | 14 / 20 ms, 14 / 20 ms | |
| 16 x 1000/s, QoS 1: delivered; p50 / p99 | 16.0k; 15 / 24 ms, 15 / 22 ms | | 15.6k, 16.0k; 15 / 118 ms, 16 / 32 ms | |
| fan-out 1 -> 100, flood (delivered) | 955k, 965k | 46-73 M | 910k, 906k | 56-75 M |
| fan-out 1 -> 1000 at 10/s (delivered; p50) | 6.6k, 7.9k; 218, 138 ms | | 6.3k, 7.5k; 159, 142 ms | |

| three data cores (`--smp 4`) | off: published / delivered | single, final build | single, same-shard pauses only (first build) |
|---|---|---|---|
| 1 flow, QoS 0, 64 B | 173k / 134k, 138k / 113k (160-500k dropped per run) | 146k / 146k, 143k / 143k (0 dropped) | 146k / 146k, 153k / 125k, 145k / 144k, 141k / 116k |
| 1 flow, QoS 0, 1 KiB | 10.2k / 8.2k, 10.0k / 7.6k | 9.3k / 9.3k, 12.1k / 12.1k (0 dropped) | 9.4k / 7.4k, 10.4k / 8.1k, 10.4k / 8.2k, 11.0k / 8.7k |
| 16 pairs, QoS 0, 64 B, flood | 224k / 224k, 229k / 229k | 235k / 235k, 248k / 247k | 231k / 231k, 244k / 244k |
| 16 pairs, QoS 0, 1 KiB, flood | 20.7k / 20.6k, 20.4k / 20.3k | 19.7k / 19.7k, 19.9k / 19.9k | 21.4k / 21.3k, 19.7k / 19.6k |
| 16 x 1000/s, QoS 0: p50 / p99 | 14 / 20 ms | 14 / 26 ms, 14 / 20 ms (cross-shard build) | |
| fan-out 1 -> 100, flood (delivered) | 885k, 912k | 941k, 944k (no pause) | |
| fan-out 1 -> 1000 at 10/s (delivered; p50) | 10.0k; 23, 24 ms | 10.0k; 23, 23 ms | |

**After the rebase onto ADR-268** (the TCP sender's SACK loss detection changed under these numbers), one data
core, three runs each (`post-off2.txt`, `post-on2.txt`):

| one data core, after ADR-268 | off: published / delivered (dropped per run) | single: published / delivered (dropped) |
|---|---|---|
| 1 flow, QoS 0, 64 B | 145k / 144k, 152k / 151k, 148k / 146k (8-28k) | 126k / 126k, 116k / 116k, 145k / 145k (0) |
| 1 flow, QoS 0, 1 KiB | 10.9k / 10.3k, 11.3k / 10.6k, 10.4k / 9.8k (9-14k) | 10.4k / 10.4k, 10.3k / 10.3k, 9.9k / 9.9k (0) |
| 1 flow, QoS 1, 64 B (delivered) | 984, 974, 990 | 1005, 992, 989 |

What it says:
1. **On one flow nothing accepted is lost any more**: published equals delivered and `dropped/slow_subscriber` stays
   0, on one data core and across shards (`--smp 4`, final build). Before, the same rig dropped 3-500k messages per
   10 s run on one flow. The first build paused only when publisher and subscriber shared a shard; three data cores
   then dropped as before (the "first build" column); the cross-shard request (ADR-269 point 2) alone still dropped
   a quarter, because the routes on their way when the pause came overflowed the subscriber's 32 KiB buffer; the
   256 KiB overshoot for a waited-for subscriber ended that.
2. **On one fast data core 64 B delivers somewhat less, 1 KiB the same; on three cores both deliver more.** One
   core: 64 B median 141k delivered (range 119-165k) with "single" against 152k (130-157k) with "off" before ADR-268,
   126k (116-145k) against 146k (144-151k) after it: about 10 % less, the cost of many short pauses on a subscriber
   that was keeping up with 85-95 % of the flood; 1 KiB 9.9k (9.2-12.1k) against
   10.4k (8.9-11.4k), after ADR-268 10.3k against 10.3k. On this rig the subscriber's stream is not starved (the Mac's core is fast; "off" drops 1-14 %),
   so there is little to win. Three cores: 64 B 143-146k against 113-134k, 1 KiB 9.3-12.1k against 7.6-8.2k. Where the
   subscriber *is* starved by the publisher (netcup, section 13.2: 85-90 % dropped), the cycles no longer spent on
   reading and dropping are expected to go to the subscriber; that is the VPS measurement still to do.
3. **No regression elsewhere that the rig can see:** 16 pairs, QoS 1, the latency sweep, fan-out (never paused, as
   designed) are within the run-to-run range (fan-out 1 -> 100 delivered 5 % less with "single" on one core and 5 %
   more on three, with no pause in either: the machine, not the code). One QoS 1 run at 16 x 1000/s had a 118 ms p99 with "single" (the other
   32 ms; "off" 22-24 ms); QoS 1 is never paused for, so it is attributed to the shared machine, not checked further.
4. **Latency on a flooded single flow rises** (p50 51-318 ms against 72-157 ms): the messages wait in the
   publisher's socket instead of being dropped, as with Mosquitto. At a rate the subscriber can take nothing pauses
   (0 pauses in every steady-rate row).
5. The pauses are short: 80 to 6,000 per 10 s flood, a fraction of a millisecond each on average
   (`paused_ms` / `paused`), none ran out (`timeouts` 0 everywhere); most end before the TCP window update would be
   worth sending (it is sent only when the window grows by an MSS), so the held input in the broker does the pacing
   and TCP's window takes over only for longer stalls.
