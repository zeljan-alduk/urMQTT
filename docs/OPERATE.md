# Operating a running urMQTT over MQTT

An **operator** connects with mutual TLS like any device and gets two things:
statistics under `$SYS/broker/` (O1) and a console under `$SYS/console/`
(O2). No VNC session, no serial port. Design and limits: ADR-060 and
SECURITY.md ("Operator role").

## Who is an operator

An identity listed in `acl.operator_ids` of `deploy/<env>/config.toml` (exact
ids, fixed at build time). Nothing else reaches `$SYS/`: not devices, not the
`backend` service, not an operator id on a connection without a certificate.

| Environment | Identity | Certificate and key |
|---|---|---|
| dev | `operator` | `deploy/dev/services/operator.{pem,key}` (`make certs`; the same identity signs control messages) |
| prod | `operator` | `deploy/prod/services/operator.{pem,key}`, issued with `scripts/gen-operator-cert.sh deploy/prod` |

The client id **must equal the identity** (`operator`). One session per
identity: a second login with the same certificate takes the first one over,
so give each person their own identity (`scripts/gen-operator-cert.sh
deploy/prod alice`, add `alice` to `acl.operator_ids`, rebuild).

## Connect

| Setting | Value |
|---|---|
| Host, port | the VM's address, `8883` (dev under QEMU: `127.0.0.1:18883` with `--fwd 18883:8883`) |
| Protocol | MQTT **3.1.1**, TLS 1.3, mutual TLS |
| Client id | `operator` |
| CA certificate | `deploy/<env>/ca.pem` |
| Client certificate, key | `deploy/<env>/services/operator.pem`, `.key` |
| Server name | the server certificate names `localhost` and `urmqtt.local` (dev); turn off hostname verification, or connect by a name the certificate has |
| Clean session | yes |
| Subscribe | `$SYS/#` (QoS 0 or 1; everything is delivered at QoS 0) |

**MQTTX:** New Connection, protocol `mqtts://`, port 8883, MQTT version 3.1.1,
Client ID `operator`, SSL/TLS on, *CA or Self signed certificates*, with
the three files above and *Strict validate certificate* off (or on, with a
server certificate for your host). Add the subscription `$SYS/#`.

**mosquitto:**

```sh
D=deploy/dev            # or deploy/prod
mosquitto_sub -h HOST -p 8883 -V mqttv311 -i operator --cafile $D/ca.pem \
  --cert $D/services/operator.pem --key $D/services/operator.key -v -t '$SYS/#'
```

## What is published (O1)

Retained, QoS 0, refreshed every 10 s by every data core into its own shard
(a subscriber sees the copy of the shard its session lives on). A
subscription to `$SYS/broker/#` gets the current values at once.

| Topic | Value |
|---|---|
| `$SYS/broker/version` | the image version |
| `$SYS/broker/uptime` | seconds since boot |
| `$SYS/broker/arch` | `aarch64` or `x86_64` |
| `$SYS/broker/cpu/cores` | CPUs |
| `$SYS/broker/cpu/busy/<core>` | percent busy over the last 5 s, per core |
| `$SYS/broker/memory/total`, `used` | kernel heap, bytes |
| `$SYS/broker/disk/total`, `used` | the data layout (it grows with the disk, S3: `storage: grew the layout` in the console), and what SQLite uses of it, bytes (0 without a data disk) |
| `$SYS/broker/clients/connected` | sessions attached to a connection |
| `$SYS/broker/clients/total` | sessions, offline persistent ones included |
| `$SYS/broker/subscriptions` | all subscriptions |
| `$SYS/broker/retained` | retained messages of devices (not these topics) |
| `$SYS/broker/messages/received`, `sent` | accepted publishes, deliveries |
| `$SYS/broker/connections/refused` | refused by admission control |
| `$SYS/broker/tls/server_cert_days` | days until the server certificate expires (`unknown` without a wall clock) |
| `$SYS/broker/time/source` | where the wall clock comes from: `rtc` (firmware clock at boot), `sntp` (corrected by SNTP, ADR-100) or `unknown` (no usable clock: certificate checks and control messages are refused) |
| `$SYS/broker/time/offset_ms` | the last SNTP offset against the clock as it was, in ms (`unknown` until one was measured against a known clock; a refused offset is shown too, and logged) |
| `$SYS/broker/console/dropped` | console lines lost to a slow reader |
| `$SYS/broker/handshakes/started` | connections admitted (TCP established, admission said yes) |
| `$SYS/broker/handshakes/done`, `failed`, `timed_out` | TLS handshakes completed, ended before completing, not finished within 10 s |
| `$SYS/broker/handshakes/refused`, `syn_dropped` | refused at the final ACK (RST sent), SYNs dropped without an answer (the client's TCP retries after its backoff) |
| `$SYS/broker/handshakes/in_flight`, `in_flight_max` | handshakes in flight now, and the most on one core in the last 5 s |
| `$SYS/broker/handshakes/slow` | completed handshakes that took more than 250 ms from accept to done |
| `$SYS/broker/handshakes/latency_sum_ms`, `latency_max_ms` | sum of accept-to-done times (divide the change by the change of `done` for the mean), longest in the last 5 s |
| `$SYS/broker/cpu/accepted/<core>` | connections accepted per core since boot: how evenly the flows spread |

**Time (T1, ADR-100).** The wall clock is the firmware RTC read at boot, plus
uptime. With `[time] servers = ["a.b.c.d", ...]` in `deploy/<env>/config.toml`
(IPv4 literals, at most four: the broker has no DNS) the kernel asks them with
SNTP once at boot and then every `interval_s` (default 3600) and corrects the
clock. Look for the `time:` lines on the console or in syslog: `sntp servers`,
`sntp set|stepped|adjusted the clock`, `sntp round failed`, `sntp offset ...
refused`. Rules: use two or three servers (the median of a majority is taken,
one wrong server cannot move the clock; with one server you trust it);
the clock never goes below the image's build time; a large forward step (a
dead RTC battery) happens once, at the first synchronisation; afterwards one
correction and the sum of all of them stay within `max_step_s` (default 600 s)
and a larger offset is refused and logged, not applied. SNTP is not
authenticated: on a network where the path to the servers is not trusted,
keep the list short and local and watch `time/offset_ms`. Without servers the
clock is the RTC, as before (`source` is `rtc`, or `unknown` if the RTC is
before the build time). UDP port 123 (or the one given) must be reachable
outward.

**Query.** Publish anything (an empty payload will do) to `$SYS/query/info`;
the answer is one JSON document on `$SYS/query/info/response` (subscribe
first). MQTT 3.1.1 has no Response Topic property, so the reply topic is fixed:

```json
{"version":"0.1.0","uptime_s":42,"arch":"aarch64","cpu":{"cores":4,"busy":[2,1,0,0]},
 "memory":{"total":33554432,"used":1503744},"disk":{"total":57651200,"used":78288},
 "clients":{"connected":1,"total":1},"subscriptions":1,"retained":0,
 "messages":{"received":0,"sent":21},"connections_refused":0,
 "tls":{"server_cert_days":824},"time":{"source":"sntp","offset_ms":-12},"console_dropped":0,
 "handshakes":{"started":0,"done":0,"failed":0,"timed_out":0,"refused":0,"syn_dropped":0,
 "in_flight":0,"in_flight_max":0,"slow":0,"latency_sum_ms":0,"latency_max_ms":0},
 "accepted":[0,0,0,0]}
```

**Reading the handshake numbers (PERF, ADR-080).** Admission has three stages
and each counts for itself: a SYN may be dropped without an answer
(`syn_dropped`, by reason in statsd as `syn_dropped.<reason>`), the final ACK
may be refused with a RST (`refused`, `refused.<reason>`), and an admitted
connection ends as `done`, `failed` or `timed_out`. Reasons: `rate` (token
bucket), `in_flight` (per core), `per_ip` (per source address), `memory`,
`storage`. The same numbers are in the kernel log every 5 s, one
`handshakes: core N:` line per core, next to `tcp: core N:` (cookies, SYNs
dropped, refused flows, retransmissions) and `dataplane: core N:` (busy, work
by category, microseconds of work per accepted connection, longest stall of
the core). The statsd names are `handshakes.{started,done,failed,timed_out,slow,latency_ms_sum}`
(counters), `handshakes.{in_flight,in_flight_max,latency_max_ms}` (gauges) and
`frames.dropped.{steer,worker_tx,nic_tx,nic_tx_local}` (a frame lost to a full ring
or NIC queue is retransmitted by TCP a second or more later).

## The console (O2)

- **Output:** subscribe to `$SYS/console/out`. Every kernel log line arrives as
  one message (`[   12.345678] INFO  text`), and a new subscriber first gets the
  last 64 lines. It never blocks the broker: a reader that is too slow loses
  lines, counted in `$SYS/broker/console/dropped`.
- **Input:** publish one command per message to `$SYS/console/in`; the answer
  comes on `$SYS/console/out`.

| Command | Effect |
|---|---|
| `help` | lists the commands |
| `status` | version, CPU, memory, disk, clients, messages, certificate, log level |
| `log level <error\|warn\|info\|debug\|trace>` | lowers or raises the log level (never above the build-time maximum) |
| `reboot` | resets the machine after 1 s |

Anything else is refused (`error: unknown command; try: help`). There is no
shell. At most 5 commands in a burst, then one every 2 s. Every command is
logged with your identity and the text, also when refused and whatever the
log level: `console: operator ran "status"`.

## Issuing and revoking

```sh
scripts/gen-operator-cert.sh deploy/prod            # services/operator.{pem,key}
scripts/gen-operator-cert.sh deploy/prod alice 365  # another identity, 365 days
```

Never commit the key (`deploy/*/services/` is git-ignored). A stolen operator
certificate is revoked like any other, with the control channel
(`urmqtt-control revoke`), which also closes its live session.

## The data disk in the console (S2, S3)

These lines appear in `$SYS/console/out` (and on the serial port, and in
syslog). Procedures are in [DEPLOY.md](DEPLOY.md) section 9.

| Line | Meaning |
|---|---|
| `blk: topology: logical 512 B, physical 4096 B, … optimal I/O … B` | what the disk reports; the layout is aligned to it |
| `storage: misaligned_writes=0 of N device writes …` | the store sent no write that is not a whole physical block (anything else is a bug: report it) |
| `storage: data disk opened (… MiB …): … N telemetry partition(s), aligned to … KiB, generation G` | the layout in force; the generation counts superblock writes (grow, migration) |
| `data disk is layout v1; this image needs v2: run urmqtt-disk migrate` with `storage: refused reason=layout-v1` | the disk predates layout v2; the VM resets every 60 s. Migrate it offline |
| `gpt: data partition extended to the end of the … MiB disk`, `storage: grew the layout from … to … MiB` | the volume was enlarged; the new space is in use. `… grew the layout online …` is the same without a reboot |
| `blk: resize notification (configuration-change interrupt): armed (online grow)` or `not available …` | whether the disk tells the guest when it is resized; if not, an enlarged disk is taken up at the next reboot |
| `storage: growing the layout failed …` / `online grow failed …` | the old layout stays in force (the update is one block write); check the disk and reboot |

`storage.grow_ratio_db` sets how the new space is shared (default 50: half to
the SQLite database, half to the telemetry ring).
