# Operating a running urMQTT over MQTT

An **operator** connects with mutual TLS like any device and gets two things:
statistics under `$SYS/broker/` (O1) and a console under `$SYS/console/`
(O2). No VNC session, no serial port. A Prometheus scrape target is an option
of its own ("Metrics for Prometheus" below). Design and limits: ADR-060 and
SECURITY.md ("Operator role").

## Who is an operator

An identity listed in `acl.operator_ids` of `deploy/<env>/config.toml` (exact
ids, fixed in the image's configuration). Nothing else reaches `$SYS/`: not devices, not the
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
| `$SYS/broker/connections/per_address/limit` | `limits.max_connections_per_ip`, 0 when there is no limit (then the rest stays 0) |
| `$SYS/broker/connections/per_address/established`, `addresses`, `peak` | TLS connections the per-address table counts now (all cores), distinct source addresses holding one, the most one address has held at once since boot |
| `$SYS/broker/connections/per_address/syn_dropped`, `refused` | SYNs dropped without an answer, and connections refused with a RST at the final ACK, because the address was at the limit (since boot) |
| `$SYS/broker/connections/per_address/untracked` | connections let through uncounted because the table was full (more than 32 768 addresses at once, or a bucket collision); normally 0 |
| `$SYS/broker/tls/server_cert_days` | days until the server certificate expires (`unknown` without a wall clock) |
| `$SYS/broker/time/source` | where the wall clock comes from: `rtc` (firmware clock at boot), `sntp` (corrected by SNTP, ADR-100) or `unknown` (no usable clock: certificate checks and control messages are refused) |
| `$SYS/broker/time/offset_ms` | the last SNTP offset against the clock as it was, in ms (`unknown` until one was measured against a known clock; a refused offset is shown too, and logged) |
| `$SYS/broker/entropy/source` | what seeded the random number generator at boot: `virtio-rng`, `rndr` (aarch64) or `rdrand` (x86_64), `virtio-rng+rndr`, or the weak path `jitter+firmware` (`jitter` when the firmware gave no value; ADR-263, docs/DEPLOY.md "Entropy"). Also `"entropy":{"source":...}` in the info reply |
| `$SYS/broker/console/dropped` | console lines lost to a slow reader |
| `$SYS/broker/net/mtu` | the link MTU in use, bytes: `network.mtu`, else DHCP option 26, else 1500; at most 1500 (NOW-19, ADR-264). The boot line `net: mtu N (static\|dhcp\|default)` says where it came from; a lower value than the network's is safe, a higher one loses the large packets |
| `$SYS/broker/net/ipv6/mode` | `off`, `slaac` or `static` (`network.ipv6`, NEXT-1, ADR-334) |
| `$SYS/broker/net/ipv6/address/link_local`, `address/global` | the IPv6 addresses in use (RFC 5952 text; empty: none yet, still in duplicate address detection, or duplicate) |
| `$SYS/broker/net/ipv6/router`, `mtu` | the IPv6 default router (empty: none) and the IPv6 MTU (the link's, or less from a Router Advertisement) |
| `$SYS/broker/net/ipv6/frames_in`, `dropped`, `fragments`, `ext_headers` | IPv6 frames the interfaces of all cores took, and dropped: in all, fragments (never reassembled), extension headers that may not be skipped (ADR-330) |
| `$SYS/broker/net/ipv6/dad_duplicate`, `prefixes_ignored` | addresses another node claimed (duplicate address detection; such an address is never used), and advertised prefixes not used (one global address only, ADR-331) |
| `$SYS/broker/net/queues` | virtio-net queue pairs in use: 1, or one per data core with a multiqueue NIC whose RSS steers flows (NEXT-6, ADR-310). The boot line `net: multiqueue: ...` or `net: one queue pair: <reason>` says why |
| `$SYS/broker/net/queue/received/<k>`, `sent/<k>`, `forwarded/<k>`, `interrupts/<k>` | per queue pair k (pair k belongs to data core k; ADR-312): frames received and sent on it, frames core k received there for another core's flow and passed to core 0 (should stay 0 for MQTT traffic: a growing number means the device does not hash as the broker programmed it, which costs a hop per frame but loses nothing), and its receive interrupts. Metrics `urmqtt_network_queue_*{queue="k"}`; every 5 s with multiqueue the console line `net: queue pair k (core k): ...` |
| `$SYS/broker/iommu/mode`, `state` | DMA remapping (H4b, ADR-305): `devices.iommu` (`off`, `auto`, `require`) and what it gave: `off` (not used), `none` (no IOMMU described: `auto` went on without), `failed` (described, none came up), `active`. Also `"iommu":{...}` in the info reply and a `status` line `iommu <state> (<mode>): ...` when the key is not `off` |
| `$SYS/broker/iommu/units`, `domains`, `pages` | units translating, devices with a domain of their own, pages mapped for device DMA. They do not change after boot |
| `$SYS/broker/iommu/faults`, `overflows` | DMA the IOMMU blocked (and unit errors), read from the units' fault logs every 100 ms (ADR-306), and the times a unit's log overflowed and faults were lost. Any fault is a device writing or reading where it was not given memory: a broken device model, a hostile device, or a kernel bug; the first 16 are logged one line each (`iommu: fault N: <unit> <base>: pci <bdf> ...`), then every power of two. The broker keeps running: the access did not happen |
| `$SYS/broker/messages/dropped/slow_subscriber` | QoS 0 messages not delivered because the subscriber's output buffer was full (it reads slower than the topic is published to). Deliberate, bounded, counted (ADR-223). With `limits.publisher_backpressure = "single"` (the default, ADR-269) a message with one subscriber pauses its publisher instead; what is left here is fan-out to two or more, QoS 0 from another core, and publishers in cool-down |
| `$SYS/broker/messages/backpressure/mode` | `single` or `off`: `limits.publisher_backpressure` (NOW-13, ADR-269) |
| `$SYS/broker/messages/backpressure/paused`, `paused_ms`, `timeouts`, `holding` | publishers paused because the only subscriber of their QoS 0 message was full (their TCP window closed instead of their messages being dropped), the milliseconds they spent paused, pauses that ran out after 500 ms (the publisher is then read and its messages dropped for 2 s), and publishers held now. Also `"backpressure":{...}` in the info reply, the `status` line `backpressure ...`, and at most every 10 s per core the console line `mqtt: core N paused P publisher(s) for a full single subscriber ...`. With `single`, a rising `paused` and a flat `dropped/slow_subscriber` is a subscriber setting its publisher's pace, as intended; a rising `timeouts` is a subscriber that stalls (or two clients that wait on each other) |
| `$SYS/broker/messages/dropped/offline` | QoS 0 messages for a subscription whose client is not connected (a QoS 0 message is never stored) |
| `$SYS/broker/messages/dropped/cross_core` | QoS 0 fan-out not offered to a core that was more than 16 384 messages behind |
| `$SYS/broker/messages/dropped/qos1_queue_full`, `publish_rate` | QoS 1 messages not queued (the session's queue was full), publishes refused by the per-identity rate limit |
| `$SYS/broker/messages/qos2/received`, `duplicates` | QoS 2 PUBLISHes received with a new packet id; those whose id was still held (no PUBREL yet), answered with PUBREC again and not delivered again (ADR-271) |
| `$SYS/broker/messages/qos2/completed`, `inbound_full` | QoS 2 deliveries to clients completed with PUBCOMP; connections closed because the client held more QoS 2 ids awaiting PUBREL than `max(limits.max_inflight_qos1, 64)` (normally 0) |
| `$SYS/broker/clients/connected/v311`, `v5` | Connected clients by protocol version (ADR-274) |
| `$SYS/broker/messages/expired`, `messages/dropped/too_large` | Messages not delivered because their MQTT 5.0 Message Expiry Interval had passed (from a queue, a retained replay, a restore); deliveries dropped because they exceeded a 5.0 client's Maximum Packet Size |
| `$SYS/broker/sessions/expired`, `sessions/expiring` | Sessions ended by their Session Expiry Interval (both versions; a 3.1.1 persistent session has `limits.default_session_expiry_s`, 30 days), also those that ran out while the broker was down; offline sessions whose expiry runs now |
| `$SYS/broker/wills/delayed`, `wills/pending` | Wills armed with a 5.0 Will Delay Interval since boot; armed now |
| `$SYS/broker/disconnects/sent/0x81` ... `0x9a`, `other` | DISCONNECT packets the broker sent to 5.0 clients, by reason code: 0x81 malformed, 0x82 protocol error (also an AUTH packet: enhanced authentication is not offered), 0x83 a limit (User Properties), 0x87 not authorized, 0x8b server shutting down (the console's `reboot`, ADR-275), 0x8d keep alive, 0x8e session taken over, 0x8f/0x90 topic filter/name, 0x93 Receive Maximum, 0x94 topic alias, 0x95 packet too large, 0x98 administrative (the allowlist, a revoked certificate), 0x9a retain not available. 0x96, 0x89, 0x8a and 0x9f are never sent (ADR-275) |
| `$SYS/broker/connections/refused/v5/0x84` ... `other` | 5.0 CONNECT packets refused, by CONNACK reason code: 0x84 MQTT 5.0 disabled (`mqtt5.enabled = false`), 0x85 client id, 0x86 user name or password, 0x87 not authorized, 0x8c an Authentication Method (enhanced authentication is not offered), 0x9a a retained Will without retain, 0x81/0x82 a malformed CONNECT |
| `$SYS/broker/shared/groups`, `shared/members` | Shared-subscription groups and their members now, counted on the data core that owns each group (ADR-275) |
| `$SYS/broker/shared/messages/delivered`, `dropped`, `redispatched` | Messages handed to one member of a group; dropped (QoS 0 with no member online or whose member was gone, a message handed on more than 4 times); handed to another member because the first one's session ended or it was gone |
| `$SYS/broker/shared/joins/refused` | Shared SUBSCRIBEs refused by `limits.max_shared_groups` or `limits.max_shared_group_members` (SUBACK 0x97, 3.1.1 0x80) |
| `$SYS/broker/retained/expiring` | Retained messages with a Message Expiry Interval waiting for the sweep (every data core holds a replica of every retained message; the largest count of a core is reported, not their sum) |
| `$SYS/broker/memory/topic_aliases` | Bytes held by 5.0 clients' topic-alias tables (at most `mqtt5.topic_alias_maximum` × (16 + `limits.max_topic_len`) per connection, 2 720 B with the defaults); part of `memory/used` |
| `$SYS/broker/frames/dropped/steer`, `worker_tx`, `nic` | network frames dropped because a worker core, the dispatcher, or the NIC queue plus the dispatcher's 4 096-frame backlog was full; TCP retransmits them. Normally 0 |
| `$SYS/broker/handshakes/started` | connections admitted (TCP established, admission said yes) |
| `$SYS/broker/handshakes/done`, `failed`, `timed_out` | TLS handshakes completed, ended before completing, not finished within 10 s |
| `$SYS/broker/handshakes/refused`, `syn_dropped` | refused at the final ACK (RST sent), SYNs dropped without an answer (the client's TCP retries after its backoff) |
| `$SYS/broker/handshakes/in_flight`, `in_flight_max` | handshakes in flight now, and the most on one core in the last 5 s |
| `$SYS/broker/handshakes/slow` | completed handshakes that took more than 250 ms from accept to done |
| `$SYS/broker/handshakes/latency_sum_ms`, `latency_max_ms` | sum of accept-to-done times (divide the change by the change of `done` for the mean), longest in the last 5 s |
| `$SYS/broker/cpu/accepted/<core>` | connections accepted per core since boot: how evenly the flows spread |
| `$SYS/broker/plaintext/enabled` | `true` or `false`: whether the plaintext listener (P1, ADR-229, ADR-230) is on. While it is off this is the only plaintext topic |
| `$SYS/broker/plaintext/port`, `auth`, `allow_from`, `accounts` | the plaintext port, the login mode (`password`, `anonymous`, `ip`), the networks that may connect (`10.0.0.0/8, 192.168.0.0/16` or `anywhere`) and how many password accounts the image holds |
| `$SYS/broker/plaintext/connections`, `accepted` | plaintext connections open now, and accepted since boot |
| `$SYS/broker/plaintext/refused/source`, `locked_out`, `limit` | SYNs dropped without an answer (or connections refused at the ACK): from an address outside `allow_from`, from a locked-out address, and for a limit (connections, per address, login rate, memory) |
| `$SYS/broker/plaintext/refused/registry`, `session` | logins refused because the identity is not on the registry's allowlist, and CONNECT packets refused for the session (a stored session asked for, an unusable client id) |
| `$SYS/broker/plaintext/auth_ok`, `auth_failed`, `lockouts` | logins accepted, logins refused (wrong password, unknown user, no credentials, an address that is no one's, a first packet that is no CONNECT) and addresses locked out. A rising `auth_failed` with no `lockouts` is a device with the wrong password; `lockouts` rising is a guesser or a NAT full of such devices |
| `$SYS/broker/websocket/enabled` | `true` or `false`: whether the secure WebSocket listener (ADR-272) is on. While it is off this is the only WebSocket topic |
| `$SYS/broker/websocket/port`, `path`, `auth`, `origins`, `accounts` | the port, the URL path, the mode (`mtls`, `password`), how many origins are allowed (0: any) and how many password accounts the image holds |
| `$SYS/broker/websocket/connections`, `accepted`, `upgrades` | WebSocket connections open now, TCP connections accepted and upgrades answered 101 since boot |
| `$SYS/broker/websocket/refused/request`, `method`, `path`, `version`, `protocol`, `origin`, `too_large`, `timeout`, `limit`, `locked_out` | refused upgrades by reason: a malformed request (400), not GET, another path (404), a WebSocket version other than 13 (426), no `mqtt` subprotocol (400), an origin not on the list (403), a request over 4 KiB, a request not complete within `upgrade_timeout_s` (slowloris), a limit (connections, per address, login rate), a locked-out address. `origin` rising is a page on another site trying your users' browsers |
| `$SYS/broker/websocket/auth_ok`, `auth_failed`, `lockouts` | password mode: logins accepted and refused, addresses locked out (as for plaintext) |
| `$SYS/broker/websocket/frames/in`, `frames/out`, `bytes/in`, `bytes/out` | messages and control frames from clients, frames to them, and the MQTT bytes carried each way |
| `$SYS/broker/websocket/close/client/<code>`, `close/server/<code>`, `close/abrupt` | close frames by code (`1000`, `1001`, `1002`, `1003`, `1007`, `1008`, `1009`, `1011`, `other`) sent by clients and by the broker, and connections that ended without a close frame from either side. `close/server/1002` rising is a client library that breaks RFC 6455 |

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
first). The reply topic is fixed (an MQTT 5.0 operator client may send a Response Topic since ADR-274, but the
console does not use it: replies stay on the fixed topic for both versions):

```json
{"version":"0.6.0","uptime_s":42,"arch":"aarch64","cpu":{"cores":4,"busy":[2,1,0,0]},
 "memory":{"total":33554432,"used":1503744},"disk":{"total":57651200,"used":78288},
 "clients":{"connected":1,"total":1},"subscriptions":1,"retained":0,
 "messages":{"received":0,"sent":21},"connections_refused":0,
 "tls":{"server_cert_days":824},"time":{"source":"sntp","offset_ms":-12},"console_dropped":0,
 "handshakes":{"started":0,"done":0,"failed":0,"timed_out":0,"refused":0,"syn_dropped":0,
 "in_flight":0,"in_flight_max":0,"slow":0,"latency_sum_ms":0,"latency_max_ms":0},
 "per_address":{"limit":1024,"established":0,"addresses":0,"peak":0,"syn_dropped":0,"refused":0,"untracked":0},
 "accepted":[0,0,0,0]}
```

**Reading the handshake numbers (PERF, ADR-080).** Admission has three stages
and each counts for itself: a SYN may be dropped without an answer
(`syn_dropped`, by reason in statsd as `syn_dropped.<reason>`), the final ACK
may be refused with a RST (`refused`, `refused.<reason>`), and an admitted
connection ends as `done`, `failed` or `timed_out`. Reasons: `rate` (token
bucket), `in_flight` (per core), `per_ip` (per source address), `memory`,
`storage`, `per_ip_established` (the per-address limit on *established*
connections, see below). The same numbers are in the kernel log every 5 s, one
`handshakes: core N:` line per core, next to `tcp: core N:` (cookies, SYNs
dropped, refused flows, retransmissions) and `dataplane: core N:` (busy, work
by category, microseconds of work per accepted connection, longest stall of
the core). The statsd names are `handshakes.{started,done,failed,timed_out,slow,latency_ms_sum}`
(counters), `handshakes.{in_flight,in_flight_max,latency_max_ms}` (gauges) and
`frames.dropped.{steer,worker_tx,nic_tx,nic_tx_local}` (a frame lost to a full ring
or NIC queue is retransmitted by TCP a second or more later).

**The limit on established connections per source address (NOW-14, ADR-280).**
`limits.max_connections_per_ip` (default 1024; 0: no limit) bounds how many TLS
connections (the MQTT port and the WebSocket port together) one IPv4 address, or
one IPv6 /64 (ADR-332), may hold at once, all cores added up: the per-address handshake limit above only
covers handshakes still in flight, so a client that finishes its handshakes could
otherwise hold thousands of connections. An address at its limit gets no SYN-ACK
(its TCP retries after its backoff, nothing is kept, no handshake token and no
crypto is spent); a connection that slips past the SYN check is refused with a
RST at the final ACK. Both are counted per core with the other refusals
(`syn_dropped.per_ip_established` and `refused.per_ip_established` in statsd, the
`established per address` figure in the `handshakes: core N:` log line) and in
total under `$SYS/broker/connections/per_address/*`; the console's `status` shows
one `per address limit ...` line. **Size it for the largest site:** devices behind
one NAT (a factory, a mobile carrier's gateway, QEMU's user network) share one
address and one limit; a limit the site reaches shows as `per_address/refused`
and `syn_dropped` growing while that site's devices fail to reconnect. The
plaintext listener has its own `plaintext.max_connections_per_ip` and is not
counted here.
## IPv6 (NEXT-1, ADR-330 to ADR-334)

**Off by default.** With `network.ipv6 = "slaac"` the broker makes its link-local address (`fe80::` and the
EUI-64 of its MAC) and one global address from the first /64 prefix the router advertises (the same interface
identifier, so the address is known in advance: `<prefix>:5054:ff:fe12:3456` for the MAC `52:54:00:12:34:56`);
with `"static"` it uses `network.ipv6_address` and `network.ipv6_gateway`. Every listener that takes IPv4 clients
(TLS, WebSocket, plaintext, metrics) then takes IPv6 ones too. The boot log says each step:

```text
net: ipv6 slaac: link-local address fe80::5054:ff:fe12:3456 (EUI-64), global address from router advertisements
net: ipv6 link-local address fe80::5054:ff:fe12:3456 in use (duplicate address detection passed)
net: ipv6 default router fe80::1 (lifetime 1800 s)
net: ipv6 global address 2001:db8:1:0:5054:ff:fe12:3456 in use (duplicate address detection passed)
```

What to look for: `... is in use by another node on the link (duplicate address detection): not used` (an error:
another machine has that address; fix the static address, or the other machine), `no router advertisement after 3
solicitations; link-local only` (the network sends no RAs: use `"static"`), `prefix ... advertised, not used` (a
second prefix; only the first is used), `valid lifetime over, removed` (the router stopped advertising the prefix).
The console's `status` has three `ipv6 ...` lines; the topics above and the `urmqtt_ipv6_*` metrics count what the
interfaces took and dropped. Per-address limits count an IPv6 /64 as one address (ADR-332): devices behind one
/64 share them as devices behind one IPv4 NAT do. `plaintext.allow_from` and `metrics.allow_from` take IPv6
networks (`2001:db8::/32`); `plaintext.ip_identities` does not (an IPv6 client of `auth = "ip"` is refused).
SNTP, syslog, statsd and log shipping stay IPv4.

## Metrics for Prometheus (ADR-290 to ADR-294)

The same numbers as `$SYS/broker/...`, as a Prometheus scrape target served by the kernel itself: no exporter to run.
**Off by default**; an image that does not name `[metrics]` opens no new port and boots exactly as before.

```toml
[metrics]
enabled = true
allow_from = ["10.0.0.0/24"]   # required: the networks that may scrape (the Prometheus server's address)
# port = 9100                  # TCP port (GET /metrics)
# max_connections = 8          # at once, on each data core
# max_connections_per_ip = 2   # at once from one address, on each data core
# request_timeout_s = 5        # from the connection to the end of the answer
```

The builder page has the section (Prometheus metrics); `urmqtt-config pack` and `verify` print a warning line while it
is on. Configuration format 16: an older kernel refuses the image by its version.

**What it is, and is not.** Plain HTTP/1.1, `GET /metrics` (and `HEAD`), no TLS, no login; the protection is the
allow-list, applied to the SYN: an address outside it gets no answer at all and the kernel keeps nothing for it.
Anything else (another path, a query string, a body, a second request, a method but GET and HEAD) gets a fixed
refusal (404, 400, 405, 431, 505) and the connection closes after every answer. At most 8 connections per core, 2
per address and core, 20 scrapes per second and core; a request not finished within `request_timeout_s` is cut.
**Put only the monitoring host's network in `allow_from`, never a public one** (the boot log warns if you do). The
text can be read by anyone on the path (no TLS) and by anyone who can forge an allowed address: if either matters,
scrape through a TLS-terminating proxy on a host inside the network, or keep the endpoint off and use an exporter that
subscribes to `$SYS` as an operator. What the text contains: counters and gauges of the broker; **never a client id,
user name, topic, address or certificate** (no label is chosen by a client, so a client cannot add a series).

Prometheus (`prometheus.yml`; port and address are the broker's):

```yaml
scrape_configs:
  - job_name: urmqtt
    scrape_interval: 15s
    scrape_timeout: 5s
    metrics_path: /metrics
    static_configs:
      - targets: ["10.0.0.5:9100"]
        labels: { site: "vps-1" }
```

Prometheus asks for OpenMetrics when it can and the broker answers in the format it prefers
(`application/openmetrics-text; version=1.0.0`, else the text format 0.0.4); `curl http://10.0.0.5:9100/metrics` shows
the text format. 13 KiB with four cores; about 170 series, fixed by the core count and the configuration.

**Names** (an interface: a change is in the CHANGELOG). `urmqtt_` prefix, base units (`_seconds`, `_bytes`,
`_ratio`), counters end in `_total` and restart at 0 on every boot (Prometheus treats that as a counter reset).
Every `$SYS/broker/...` topic has one; this is the mapping for the ones to build alerts on:

| Metric | Type | From `$SYS/broker/` | Meaning |
|---|---|---|---|
| `urmqtt_uptime_seconds` | gauge | `uptime` | seconds since boot (`resets()` or `changes()` catch a reboot) |
| `urmqtt_clients_connected` | gauge | `clients/connected` | sessions attached to a connection; `_by_version{version="3.1.1"\|"5"}` splits it |
| `urmqtt_sessions`, `urmqtt_subscriptions`, `urmqtt_retained_messages` | gauge | `clients/total`, `subscriptions`, `retained` | held state |
| `urmqtt_messages_received_total`, `urmqtt_messages_sent_total` | counter | `messages/received`, `sent` | PUBLISH in and out (`rate()` is messages per second) |
| `urmqtt_messages_dropped_total{reason}` | counter | `messages/dropped/*` | `slow_subscriber`, `offline`, `cross_core`, `qos1_queue_full`, `publish_rate`, `too_large`: never silent |
| `urmqtt_frames_dropped_total{reason}` | counter | `frames/dropped/*` | `steer`, `worker_tx`, `nic`: overload; TCP resends them |
| `urmqtt_connections_refused_total` | counter | `connections/refused` | refused at the final ACK |
| `urmqtt_mqtt5_connections_refused_total{code}`, `urmqtt_mqtt5_disconnects_sent_total{code}` | counter | `connections/refused/v5/*`, `disconnects/sent/*` | MQTT 5.0 reason codes (`0x87`, `0x8e`, ..., `other`) |
| `urmqtt_handshakes_{started,done,failed,timed_out,refused,syn_dropped,slow}_total` | counter | `handshakes/*` | TLS admission (OPERATE "Handshake admission") |
| `urmqtt_handshakes_in_flight`, `urmqtt_handshakes_in_flight_max` | gauge | `handshakes/in_flight`, `in_flight_max` | now, and the largest on one core in the last 5 s |
| `urmqtt_handshakes_latency_seconds_total`, `..._latency_max_seconds` | counter, gauge | `handshakes/latency_sum_ms`, `latency_max_ms` | the mean over a window is `rate(latency_seconds_total) / rate(handshakes_done_total)` |
| `urmqtt_cpu_busy_ratio{core}` | gauge | `cpu/busy/N` | 0 to 1 over the last 5 s; `urmqtt_cpu_cores` is the count |
| `urmqtt_core_connections_accepted_total{core}` | counter | `cpu/accepted/N` | how evenly flows spread over the cores |
| `urmqtt_memory_heap_bytes`, `urmqtt_memory_heap_used_bytes` | gauge | `memory/total`, `used` | kernel heap |
| `urmqtt_disk_bytes`, `urmqtt_disk_used_bytes` | gauge | `disk/total`, `used` | data layout (0 without a disk) |
| `urmqtt_tls_server_certificate_expiry_seconds` | gauge | `tls/server_cert_days` | whole days times 86 400; **absent** without a wall clock |
| `urmqtt_time_offset_seconds` | gauge | `time/offset_ms` | last SNTP step; **absent** until measured |
| `urmqtt_version_info{version}`, `_arch_info{arch}`, `_time_source_info{source}`, `_entropy_source_info{source}` | gauge (1) | `version`, `arch`, `time/source`, `entropy/source` | the text is the label |
| `urmqtt_listener_*{listener="plaintext"\|"websocket"}`, `urmqtt_websocket_*`, `urmqtt_plaintext_*` | gauge, counter | `plaintext/*`, `websocket/*` | `urmqtt_listener_enabled` is 0 for a listener that is off, and no other series exists for it |
| `urmqtt_connections_per_address_*` (`limit`, `established`, `addresses`, `peak` gauges; `syn_dropped_total`, `refused_total`, `untracked_total` counters) | gauge, counter | `connections/per_address/*` | the limit on established TLS connections per source address (ADR-280): an address at its limit shows as `refused` and `syn_dropped` growing |
| `urmqtt_iommu_mode_info{mode}`, `urmqtt_iommu_state_info{state}`, `urmqtt_iommu_units`, `_domains`, `_pages`, `urmqtt_iommu_faults_total`, `urmqtt_iommu_fault_overflows_total` | gauge, counter | `iommu/*` | DMA remapping (ADR-305): what the IOMMU gave, and the DMA it blocked (any fault is worth an alert) |
| `urmqtt_metrics_*` | gauge, counter | (the endpoint's own) | connections, accepted, refused by reason (`source`, `limit`), requests by result (`ok`, `malformed`, `too_large`, `method`, `version`, `not_found`), timeouts |

The full list is `urmqtt_broker::metrics::RULES` (`crates/broker/src/metrics.rs`); a test fails when a `$SYS` topic
has no metric.

Alert rules that need nothing but these (adjust to taste):

```yaml
groups:
  - name: urmqtt
    rules:
      - alert: UrmqttDown
        expr: up{job="urmqtt"} == 0
        for: 2m
      - alert: UrmqttRebooted
        expr: changes(urmqtt_uptime_seconds[10m]) > 0 and urmqtt_uptime_seconds < 600
      - alert: UrmqttCertificateExpires
        expr: urmqtt_tls_server_certificate_expiry_seconds < 14 * 86400
      - alert: UrmqttDroppingMessages
        expr: sum(rate(urmqtt_messages_dropped_total{reason=~"slow_subscriber|qos1_queue_full|cross_core"}[5m])) > 0
        for: 10m
      - alert: UrmqttHandshakesFailing
        expr: rate(urmqtt_handshakes_failed_total[5m]) + rate(urmqtt_handshakes_timed_out_total[5m]) > 1
        for: 10m
      - alert: UrmqttBusy
        expr: max(urmqtt_cpu_busy_ratio) > 0.9
        for: 15m
      - alert: UrmqttHeapNearlyFull
        expr: urmqtt_memory_heap_used_bytes / urmqtt_memory_heap_bytes > 0.9
        for: 10m
      - alert: UrmqttClockWrong
        expr: abs(urmqtt_time_offset_seconds) > 5
```

Without Grafana: `curl -s http://10.0.0.5:9100/metrics | grep -v '^#'` is the whole interface, and Prometheus's own
expression browser graphs any of the above. Statsd stays plain UDP; the log can go over TLS (next section).

## Log shipping over TLS (NEXT-7, ADR-315 to ADR-319)

With `observability.log_tls` set, core 0 keeps one TLS 1.3 connection to that collector and sends it every log
record, the same RFC 5424 message the UDP path sends, framed as RFC 5425 says (`MSG-LEN SP SYSLOG-MSG`). It is the
only connection the broker opens itself, and it goes only to the address in the image.

```toml
[observability]
log_tls = "198.51.100.20:6514"     # an IPv4 address: there is no DNS
log_tls_name = "logs.example.com"  # the certificate's DNS name; "" = the address, as an IP SAN
log_tls_ca = ["log-ca.pem"]        # the CA(s) of the collector's certificate, and nothing else
log_tls_queue_kb = 256             # records kept while it is unreachable (16 to 4096)
```

This needs configuration format 20 (a v0.6.0 kernel). Collectors that speak it: rsyslog (`imtcp` with
`StreamDriver.Name="gtls"`, `StreamDriver.Mode="1"`, `StreamDriver.AuthMode="anon"`: the broker presents no client
certificate), syslog-ng (`network(transport("tls") tls(peer-verify(optional-untrusted)))`), Fluent Bit (`syslog`
input, `mode tls`, `format rfc5424`), or `scripts/logtls-sink.py` for a try.

What the console says:

| Line | Meaning |
|---|---|
| `logtls: shipping log records over TLS to A:P (certificate name N, k trust anchor file(s), queue Q KiB)` | at boot: configured |
| `logtls: log shipping over TLS is OFF: …` | at boot: the anchors in the image are unusable; the broker serves without it |
| `logtls: waiting for the wall clock before connecting to A:P` | no clock yet (certificates are checked against it) |
| `logtls: connected to A:P (TLS 1.3, certificate verified for "N")` | up |
| `logtls: connection to A:P failed: TLS: Handshake("invalid peer certificate: UnknownIssuer"); next attempt in 4 s` | the collector's certificate is not from `log_tls_ca` (or `certificate not valid for name …`: another name; `certificate expired …`) |
| `logtls: connection to A:P refused` / `timed out` / `reset by the peer` / `closed`, `; next attempt in N s` | the TCP connection; the wait doubles to 5 minutes and resets after a connection that lasted 10 s |
| `logtls: N log record(s) dropped since the last report …` | the queue was full (at most once a minute) |

Records from boot wait in the queue until the first connection, so the collector gets the whole boot. A record
written into a connection that then breaks may be lost (at most 64 KiB; delivery is at most once, as over UDP).
With statsd configured, `urmqtt.logtls.up`, `.records_sent`, `.records_dropped`, `.connections`, `.failures`, `.attempts`,
`.bytes_out` and `.rx_dropped_bytes` say the same in numbers. The firewall must let the VM out to the collector (DEPLOY.md). Not done: DNS names, a client
certificate, statsd over TLS, IPv6 (ADR-319).

## MQTT 5.0 (ADR-274, ADR-275)

Every listener speaks MQTT 3.1.1 and 5.0; each connection keeps the version of its CONNECT. Things an operator
sees differently with 5.0 clients:

- **Reason codes.** A refused publish is acknowledged with 0x87 (not authorized) or 0x97 (the publish rate); a
  refused subscription with 0x87, 0x97 (the subscription limit, a shared-group limit), 0x9E (`$share/` while
  `mqtt5.shared_subscriptions = false`) or 0xA1 (a Subscription Identifier while `mqtt5.subscription_identifiers =
  false`); a closed connection gets a DISCONNECT that names the reason (`disconnects/sent/...` above). A 3.1.1
  client gets what it always got (acknowledged and dropped, 0x80, a silent close).
- **Session expiry for everybody.** A persistent session expires when it has been offline longer than its Session
  Expiry Interval: what a 5.0 client asked for, at most `limits.max_session_expiry_s`, or for a 3.1.1 client with
  `clean_session = 0` `limits.default_session_expiry_s`; both are 30 days by default. Devices that sleep longer need
  the two raised (4 294 967 295 never expires). The boot log reports per shard how many sessions ran out while the
  broker was down (`mqtt: shard N/M ready: ... (K expired while down, dropped)`).
- **Message expiry** a publisher sets is honoured in queues, retained messages and across a restart;
  `limits.max_message_expiry_s` caps it. Expired retained messages are cleared by a sweep (at most 64 per 100 ms
  tick, ADR-275) and when read. **Will delay** holds a Will back for its interval (at most the session's
  expiry) and drops it when the client is back in time.
- **A revoked certificate** (a revocation on the control channel) gets DISCONNECT 0x98 from the core that holds its
  session, then the close; the connection is cut after 1 s whatever happens. A connection still in its handshake is
  cut at once.
- **What is not there, by decision (ADR-275):** enhanced authentication (a CONNECT with an Authentication Method gets
  CONNACK 0x8C, an AUTH packet DISCONNECT 0x82); topic aliases from the broker (it never sends one; a client's
  aliases to the broker work); MQTT 3.1. Wills live in RAM: a broker restart loses them. `mqtt5.enabled = false`
  refuses 5.0 clients with CONNACK 0x84.

### Shared subscriptions (ADR-275)

A client subscribes to `$share/{group}/{filter}` (MQTT 5.0 and 3.1.1 alike); every client that subscribes with the
same group name and filter joins the group, and each matching message goes to **one** member instead of to all.
Use it to spread work over several consumers (backends reading `devices/+/telemetry`, say).

- **Groups are per role class.** A group is (role class, group name, filter); the classes are device, service,
  operator, bootstrap, plaintext and WebSocket login. A device and a service that both subscribe to
  `$share/g/fleet/#` are in two groups, and each group gets every message: no message crosses from one role to
  another through a group. The ACL judges the filter after `$share/{group}/` with the subscribe rules of the role
  (`$share/workers/fleet/#` needs the right to subscribe to `fleet/#`; the group name is not a topic).
- **Round robin over the online members.** Each group lives on one data core (chosen by a hash of class, name and
  filter); that core hands each message to the next member that is online, and the member's own core delivers it at
  min(QoS of the publish, QoS of the member's subscription). With no member online, QoS 0 is dropped
  (`shared/messages/dropped`) and QoS 1 and 2 go to the queue of the next offline persistent member. A message
  handed to a member stays with it while its session lives; when the session ends (a clean session closed, its
  expiry), its unacknowledged QoS 1 messages and its queue go to another member (`shared/messages/redispatched`),
  QoS 2 in flight never. A QoS 0 delivery to a member on a core that is more than 16 384 messages behind is dropped
  like any QoS 0 fan-out (`messages/dropped/cross_core`); QoS 1 and 2 deliveries are always sent.
- **No retained messages** are sent for a shared subscription (other filters of the same SUBSCRIBE get theirs).
  No Local on a share is a protocol error (DISCONNECT 0x82).
- **The SUBACK waits for the group's core** when it is another core (at most 2 s, then 0x80), so a message published
  after the SUBACK reaches the new member, and a limit is reported in the SUBACK.
- **Limits:** `limits.max_shared_groups` (groups one data core may own) and `limits.max_shared_group_members`
  (members per group), 1024 each, 1 to 65 535; one more is SUBACK 0x97 (3.1.1: 0x80) and counted in
  `shared/joins/refused`. A shared subscription also counts against `limits.max_subscriptions_per_session`. Each
  group costs its owner about 120 B plus its name and filter twice, each member 12 B.
- **Persistence:** a persistent session's shared subscriptions are stored like the others and join their groups
  again at boot.
- **`$SYS` through a share** (operators) gets only the `$SYS` messages of the core that owns the group; subscribe to
  `$SYS/broker/#` directly for the full figures.
- `mqtt5.shared_subscriptions = false` turns them off: CONNACK says Shared Subscription Available 0 and a `$share/`
  filter gets SUBACK 0x9E (3.1.1: 0x80).

The console's `status` has a line `shared: N group(s), N member(s); N delivered, N dropped, N handed on, N join(s)
refused`, and the info reply a `"shared":{...}` object inside `"mqtt5"`, with `"retained_expiring"` and
`"topic_alias_bytes"` beside it.

### Subscription identifiers (ADR-275)

A 5.0 SUBSCRIBE may carry a Subscription Identifier (1 to 268 435 455); it applies to every filter of that
SUBSCRIBE. Each PUBLISH the broker sends carries the identifiers of all the session's subscriptions that matched the
message (one PUBLISH per message, not one per subscription); a delivery through a shared subscription carries that
subscription's identifier only. Subscribing again to the same filter replaces the identifier (without one: removes
it). Identifiers are stored with a persistent session (database schema 5) and count against the client's Maximum
Packet Size. A 3.1.1 subscriber never sees one. `mqtt5.subscription_identifiers = false`: CONNACK says Subscription
Identifier Available 0 and a SUBSCRIBE that carries one gets SUBACK 0xA1.

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
| `reboot` | resets the machine after 1 s; in that second every MQTT 5.0 client is told DISCONNECT 0x8B and closed, and no Will is published (ADR-275) |

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

## Password accounts at run time (NOW-15, ADR-285)

Plaintext and WebSocket password accounts can be added, changed and removed
without a new image, through the signed control channel (the same
`urmqtt-control` tool, certificate and offline key as `revoke`).

**Switch it on in the image.** It is off by default. Set
`limits.max_runtime_accounts` (0 to 1024; the builder page shows it under
Limits once a listener takes passwords) in a configuration that has a
`[plaintext]` section with `auth = "password"` and/or a `[websocket]` section
with `auth = "password"`, the TLS listener, `control.service_ids` and a data
disk. The configuration is then written in format 15 (a v0.5.x kernel template
refuses it).

```sh
# add or change an account: the password is read from standard input, hashed
# here (100 000 iterations unless --iterations says fewer) and only the hash is signed
printf '%s\n' "$PASSWORD" | urmqtt-control set-account --id sensor-9 --password-stdin \
    --class full --env prod --key control.key --host broker.example --ca ca.pem \
    --client-cert operator.pem --client-key operator.key
# or give a hash made by `urmqtt-config hash-password`
urmqtt-control set-account --id dash-1 --hash 'pbkdf2-sha256$100000$...' --class read-only ...
urmqtt-control remove-account --id sensor-9 --id dash-1 ...
```

- **Classes.** `full` (the listener's `acl_publish` and `acl_subscribe`),
  `read-only` (subscribes, publishes nothing, no Will), `write-only` (publishes,
  subscribes to nothing). A class only narrows the listener's patterns.
- **Effect.** At once, on both listeners. A removed account, a changed password
  or a changed class closes that account's live connections (5.0 clients get
  DISCONNECT 0x98) and the next login uses the new state. The accounts are kept
  on the data disk and survive reboots; a new disk has none.
- **Limits.** At most `limits.max_runtime_accounts` accounts, 8 per message, ids
  of `A-Z a-z 0-9 - _ . :` up to 64 characters, hashes of at most 100 000
  iterations. An id the image itself lists as an account, or names as a
  service, operator or control identity, is refused (the image wins). A message
  that would exceed the limit changes nothing.
- **Result.** A PUBACK means received, as for every control message. The log
  says `control: seq N from operator: password account sensor-9 set (class full,
  K run-time account(s))` or `... rejected: <reason>` with the reason one of
  `accounts_disabled`, `account_limit`, `no_password_listener`,
  `account_shadows_image`, `malformed`, `replay`, `expired`, ...; the counters
  are `urmqtt.control.rejected.<reason>`. No log line, metric or message holds a
  password or a hash.
- **Keep your own list.** There is no command that lists accounts. The boot log
  says how many are stored. Messages are per disk: replacing the disk loses the
  run-time accounts, the image's own stay.
- **Upgrading.** The first boot of a v0.6.0 kernel migrates the data disk to
  schema 6 (one way; a v0.5.x kernel refuses it). Nothing else changes until an
  image sets `limits.max_runtime_accounts`.
## Boot slots and updates (NEXT-11, ADR-295 to ADR-299)

Procedures are in [DEPLOY.md](DEPLOY.md) section 8b. The lines a boot prints:

| Line | Meaning |
|---|---|
| `build: v0.6.1 (A/B protocol 1, store schema 6, configuration formats up to 23)` | what this kernel is (its build note, which `urmqtt-disk slots stage` reads) |
| `gpt: standby boot slot reserved next to the EFI system partition ...` | the first boot of a new disk made room for A/B updates |
| `boot: one boot slot (a disk prepared before v0.6.0) ...` | this disk updates with `update-boot` only |
| `boot: slot A (v0.6.0), confirmed; standby: empty` / `standby: v0.6.1 (the way back)` | the normal case; the standby is what a rollback would boot |
| `boot: slot B (v0.6.1) ON TRIAL: N trial boot(s) left after this one; confirmed after S s ...` / `waiting for a boot-confirm control message` | an update is on trial: it is confirmed by itself (`update.confirm = "auto"`) or by you (`"operator"`) |
| `boot: slot B confirmed (healthy for S s: store open, listener up)` / `(boot-confirm control message)` | the update is final; the previous slot is the standby |
| `boot: slot B was not confirmed within update.trial_timeout_s = T s: resetting (the attempt counts)` | the trial ran out of time |
| `boot: slot B gave up: <why>; slot A (...) is active again, resetting` | the automatic return: the update failed (no trial boots left, or a store schema change that was not activated as one-way); the next boot runs the previous release and the failed slot is marked bad. Look at the failed boots' logs |
| `boot: ... the firmware booted the previous slot: the new one did not even load ...` | the new ESP did not boot at all; the firmware fell back, the table now agrees |
| `boot: slot B (...): no trial boots left ..., but there is no way back (...); booting it anyway (no trial timeout)` | the previous slot is unusable (empty, bad, changed, or its kernel cannot read the migrated store); the trial timeout does not reset this boot; fix or re-stage offline |
| `boot: the firmware booted the standby slot X although the active slot is confirmed ...` | the active ESP may be damaged; nothing was changed. `urmqtt-disk slots status`, then re-stage |
| `boot: the store is at schema M (from N) ...: the previous slot cannot read it and is no longer a way back` | the store's schema is newer than the previous slot's kernel (a one-way update ran its migration, or a kernel replaced in place did): no automatic or operator's return to it any more |
| `boot: boot-rollback control message: slot A is active again, slot B is marked bad; resetting` | an operator's rollback |
| `control: message from ... rejected: other_disk` / `boot_refused` | a boot command for another disk GUID / with nothing to confirm or nowhere to go back to |

**Secure Boot (LATER-6, ADR-320).** A disk installed from an image signed with
your Secure Boot key is *sealed*: its `limine.conf` pins the configuration, so
the loader refuses any other. `urmqtt-disk info` (and `update-boot`, `slots
stage`) print `secure boot: sealed to its configuration` or `not sealed`; an ESP
sealed to another configuration is refused before anything is written. The
installer, started from a sealed image with a configuration that is not the one
the image is sealed to, prints `install: the installation image is sealed for
Secure Boot to another configuration than this boot's ...; nothing written`
and powers off. Keys and revocation: [secure-boot-keys.md](secure-boot-keys.md).

`[update]` (configuration format 17; all optional): `confirm = "auto"` (the
default) or `"operator"`; `confirm_after_s` (default 60) seconds of a healthy
trial before the automatic confirmation; `trial_timeout_s` (default 900; 0:
never) after which an unconfirmed trial resets and uses an attempt. In auto
mode the timeout must be 0 or longer than the delay.

## The disk passphrase at the console (LATER-7, ADR-325 to ADR-329)

With `storage.disk_key_source = "console"` the image holds no disk key: the data partition's key is wrapped under a
passphrase in its header, and **every boot stops before the store opens, every port closed, until someone types the
passphrase** on the VM's console: the provider's serial console or its VNC console (keyboard), a virtio-console or a
virtio-input keyboard. Nothing typed is echoed or logged. A reboot you did not plan (a crash, `watchdog.action =
"reset"`, the provider's maintenance, an A/B update) therefore needs a person at the console: watch for the line
below in your remote log.

| Line | Meaning |
|---|---|
| `storage: the data partition is blank: it is formatted encrypted, its key wrapped under a passphrase typed now` | the first boot: type a new passphrase twice (12 to 256 printable ASCII characters; generate it, e.g. `openssl rand -base64 24`, and keep it where you keep the CA key). Without it the data cannot be read by anyone, you included |
| `storage: data partition formatted with a new key, wrapped under the console passphrase in key slot 0 (300000 PBKDF2 iterations)` | done; the broker starts |
| `storage: the data partition is locked: waiting for the disk passphrase on the console`, repeated every minute | the broker is down until the passphrase is typed (the prompt is `Disk passphrase (or "change" to change it):`) |
| `storage: wrong disk passphrase (N so far)` | a wrong passphrase; asked again after 2 s. Never the text typed. Many of these from nobody you know: someone has your provider panel |
| `storage: data partition unlocked with the console passphrase (key slot N)` / `storage: unlocked after N wrong disk passphrase(s)` | opened; which slot (0: daily, 1: e.g. a recovery passphrase) |
| `storage: the disk passphrase of key slot N was changed; the old one no longer opens the disk` | `change` was typed at the prompt, then the current passphrase and the new one twice. Only the header was rewritten |
| `storage: the older superblock still held a replaced key slot (a passphrase change was interrupted); it now matches` | a passphrase change was cut by a power loss between its two writes; the old wrap is gone now |
| `storage: RAM store: encrypted under a random key of this boot, no passphrase asked` | the live entry (a RAM store): nothing to unlock, nothing kept |
| `storage: refused reason=not-wrapped` | the disk's key is in no key slot (it was encrypted with an image key): add one offline, `urmqtt-disk keys DISK add --key FILE --write` |
| `storage: refused reason=key-slot-mismatch` | the passphrase opened a slot whose key does not match the disk: the header was edited or assembled from two disks. Restore the disk from a backup you trust |

The A/B trial timeout (`update.trial_timeout_s`) does not count the time the boot waited at the prompt.

Offline, with the VM stopped (DEPLOY.md section 9): `urmqtt-disk keys DISK` lists the slots; `keys DISK add`,
`change`, `remove`, `unwrap` change them; `--passphrase-file FILE` opens the disk for every other command.

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
| `storage: discard: auto, device discard (… per range at most, … range(s) per request, granularity … B)` | the disk accepts discards (virtio-blk DISCARD, SCSI UNMAP; or `write-zeroes with unmap`); expired telemetry, truncated file tails and grown space go back to the host |
| `storage: discard: auto, but the device offers neither …` / `storage: discard: off (storage.discard = "off")` | nothing is released: the disk does not take discards, or you turned it off |
| `telemetry: N segment(s) past retention (30 days) retired, M still in use` | retention found whole segments older than `storage.retention_days` and queued their space for release |
| `storage: discard: requests=… ranges=… released=… KiB (queued: …) cancelled=… dropped=… failed=…` | the counters, once the queue is idle. `cancelled`: space a later write took back; `dropped`: queue overflow (space merely not released); `failed` must be 0 |
| `storage: discard failed …`, `storage: discard stopped for this boot` | the disk failed discards (three in a row stop them); nothing is lost, space is not released until the next boot |
| `storage: backup region added (layout v2.1): N MiB, two slots of K KiB, carved from the database's unused tail` | the disk predated the backup region and got one at this boot (one superblock write) |
| `storage: no backup region: the database leaves no room for one …` | the database is too large to give space up; the broker runs without in-disk backups |
| `backup: every N min into the backup region; newest snapshot: seq S taken at unix T (K KiB, schema vV)` or `no snapshot yet` | the backup schedule; the first snapshot comes 10 s after boot |
| `backup: snapshot seq S written to slot X: P page(s), K KiB, schema vV, N step(s) over M ms, longest step U us` | a snapshot finished; the other slot is the previous one |
| `backup: FAILED: …; the previous good snapshot is untouched; trying again in M min` | a backup failed (often: the database no longer fits a slot); `urmqtt.backup.failed` counts them |
| `storage: DATABASE RESTORED FROM BACKUP: snapshot seq N from slot S (…); T s of changes (since unix U) are LOST; reason: …` | the database was corrupt at boot and was replaced by the newest intact snapshot. Read the reason and the window; check the disk |
| `storage: the database is corrupt and storage.auto_restore is off …` / `restoring from a backup failed: …` | corruption that was not (or could not be) restored; the broker refuses to serve unless `storage.refuse_on_corruption = false` |
| `scrub: every N h, at most M MB/s; the first pass S s after boot` / `scrub: off (storage.scrub_interval_h = 0)` | the scrub schedule |
| `scrub: pass N done in T ms (S step(s)): K KiB read, R KiB/s against a budget of B KiB/s`, then `scrub: pass N: database …` and `scrub: pass N: telemetry …` | a pass finished; `R` stays at or under `B` (the budget is a rate over the pass; a busy broker is let through at 2.5 MB/s at most) |
| `scrub: telemetry partition P segment S (seq N): DAMAGED record at byte B, valid records resume at byte R …` | bit rot or a bad sector inside a telemetry segment; the records between `B` and `R` are unreadable. Check the disk |
| `scrub: telemetry partition P segment S: segment header DAMAGED …` | a segment that recovery cannot see; check the disk |
| `scrub: telemetry … bad tail at byte B, nothing valid after it …` (warning) | a torn write from a crash, or damage to the last record; expected after a power loss |
| `scrub: database object T: DAMAGED: …`, `scrub: backup slot S …: DAMAGED: …`, `scrub: backup control block DAMAGED …` | structural damage to a table (restart restores from the backup if `quick_check` fails), a snapshot that no longer matches its checksum (the next backup replaces it), a damaged control block |
| `scrub: pass N FOUND K problem(s): data on the disk is damaged …` | the pass found damage (not counting bad tails); alert on `urmqtt.scrub.errors` |
| `dbworker: address space built: I KiB image, K KiB stack, H MiB heap, W KiB shared window` | SQLite runs in an unprivileged program with its own address space (H6); `H` is `storage.sqlite_heap_mb` |
| `dbworker: call O faulted: …` / `… exceeded its budget of N ms` / `… ended with error code C`, then `dbworker: restarted (restart #R)` and `db: the database worker was restarted …; reopening the store, K uncommitted op(s) lost` / `db: store reopened after the worker restart` | SQLite (or the worker around it) crashed, looped or misbehaved; it was restarted and the store reopened from the WAL, what was not committed is lost like after a power cut. Alert on `urmqtt.dbworker.restarts`. A corrupt volume that crashes the worker every time ends in `dbworker: N restarts within 60 s: giving up on the database worker`: storage is unavailable until the next boot and the broker serves from memory |
| `telemetry: log recovered in N ms: R record(s) in the K newest segment(s) read of S …` | the boot read the newest segment of each telemetry partition (bounded boot); `R` counts those only |

`storage.grow_ratio_db` sets how the new space is shared (default 50: half to
the SQLite database, half to the telemetry ring).

`storage.discard` (`"auto"`, the default, or `"off"`) controls whether space
the store no longer uses is released to the disk. Discards are sent one at a
time, a few per second, only while the broker has nothing waiting for the disk,
and never destroy data in use (a write to a queued range takes it back). Turn it
off if a storage backend misbehaves under discards; nothing else changes.

`storage.backup_interval_min` (default 60; `0` = no backups and no backup
region) sets how often the broker copies its database into the backup region of
the data partition; `storage.auto_restore` (default `true`) lets it replace a
corrupt database from the newest intact copy at boot. statsd gauges:
`urmqtt.backup.enabled`, `snapshots_done`, `failed`, `restored`, `last_bytes`
and `age_s` (seconds since the newest snapshot: alert on it). Details and the
provider-snapshot question are in [DEPLOY.md](DEPLOY.md) section 9.

`storage.scrub_interval_h` (default 24; `0` = off) and
`storage.scrub_io_budget_mb_s` (default 8) set how often the broker re-reads
its database, backups and telemetry ring to look for damage, and how fast.
statsd gauges `urmqtt.scrub.*`: `errors` (problems in the last pass, the one to
alert on), `errors_total`, `passes`, `last_ms`, `age_s` (since the last pass),
`bytes_read`, `running`, and the per-kind counts. See
[DEPLOY.md](DEPLOY.md) section 9.
