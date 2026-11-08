## urMQTT v0.5.0 (pre-release)

A broker that is its own operating system: a Rust unikernel for VMs, serving MQTT 3.1.1 and **MQTT 5.0** over TLS 1.3
with mutual TLS. This release covers everything since v0.4.2. Its three headline features: **QoS 2, exactly once**
(ADR-271), **MQTT over secure WebSocket** in the kernel (ADR-272, off by default) and **MQTT 5.0** beside 3.1.1 on
every listener (ADR-273, ADR-274, ADR-275), with shared subscriptions and Subscription Identifiers; only enhanced
authentication is refused (CONNACK 0x8C). With them, the TCP and NIC work of the single-flow performance item
(ADR-265, ADR-266, ADR-268, ADR-269, ADR-270). **Read "Upgrading from v0.4.2" before you update: the database
migrates one way.**

Signed with the release key `721316B961DCB94B` (`minisign.pub` at the tag), as v0.4.2 was. The former test key
`9229E05252D01F8E` signed v0.1.0 to v0.4.1 only; a signature by it on any later tag is a forgery (SECURITY.md).

**The assets**

The release kernel and images with an empty configuration; configure them with the builder page
(https://aldo.tech/en/products/urmqtt-builder/, in your browser, keys never leave it) or `urmqtt-config pack
--iso/--image` (docs/FIRST-HOUR.md walks through it).

| File | What |
|---|---|
| `urmqtt-v0.5.0.elf` | the release kernel for aarch64 (no certificate or key in it; reproducible from the tag with `make dist ENV=release`) |
| `urmqtt-v0.5.0.iso` | the universal ISO (aarch64 UEFI, x86_64 UEFI and BIOS) with the empty configuration: byte for byte the template |
| `urmqtt-v0.5.0.img` | its raw disk image; `urmqtt-config pack --image` configures it |
| `urmqtt-template-v0.5.0-universal.iso` | the same ISO under the template name the builder page and the mirror use |
| `urmqtt-v0.5.0.cdx.json` | the CycloneDX SBOM |
| `SHA256SUMS`, `SHA256SUMS.minisig` | the checksums and their signature with the release key; trusted comment `urMQTT v0.5.0 release <commit>` |

**New**

- **QoS 2, exactly once** (ADR-271). PUBREC, PUBREL, PUBCOMP; a duplicate PUBLISH is answered again and never routed
  again; subscriptions are granted QoS 2; a persistent session resumes every flow after a reconnect and, while it is
  offline, across a restart. Database schema 3.
- **MQTT over secure WebSocket** (ADR-272): `wss://host:8084/mqtt`, TLS 1.3, subprotocol `mqtt`, for browsers and web
  stacks. `auth = "mtls"` takes a client certificate like the TLS port; `auth = "password"` checks an account inside
  TLS, with its own ACL, limits and clean sessions only; an origin allowlist. Off unless `[websocket] enabled = true`
  (configuration format 9).
- **MQTT 5.0** on every listener (TLS, plaintext, WebSocket), chosen per connection by the CONNECT's protocol level
  (`mqtt5.enabled`, on by default). Properties forwarded (user properties, content type, response topic, correlation
  data, payload format), reason codes on every acknowledgement and a server DISCONNECT, reason strings, Session
  Expiry, Message Expiry and Will Delay Intervals, Receive Maximum and Maximum Packet Size both ways, topic aliases
  from the client, subscription options, assigned client identifiers, Server Keep Alive (ADR-274, configuration
  format 12, database schema 4). **Shared subscriptions** (`$share/{group}/{filter}`, also for 3.1.1 clients; a group
  per role class, round robin over its online members, `limits.max_shared_groups` and
  `limits.max_shared_group_members`) and **Subscription Identifiers** (ADR-275, configuration format 13, database
  schema 5). Enhanced authentication is refused (CONNACK 0x8C). The Eclipse Paho interoperability suite passes 25 of
  27 (5.0) and 8 of 10 (3.1.1) on the development port; the rest are expected failures by design
  (docs/MQTT5-CONFORMANCE.md).
- **Performance** (ROADMAP NOW-13): TCP recovers from the peer's SACK blocks and acknowledges every second segment on
  arrival (ADR-265), and its loss detection counts the flow's own segments, which fixes the QoS 1 regression of the
  SACK build on one core (ADR-268); virtio-net queues of up to 1024 descriptors (ADR-266); **publisher back-pressure**:
  a QoS 0 message whose only subscriber is full pauses its publisher instead of being dropped (ADR-269,
  `limits.publisher_backpressure`); the **virtio-net receive interrupt** wakes the NIC's core instead of 200 us
  polling, on probation until verified, with the poll as the fallback (ADR-270, `[devices] virtio_net_interrupt`).
- Plaintext password hashes at 100 000 PBKDF2 iterations by default (ADR-267); the watchdog self-test and
  `$SYS/query/info` fixes; a second, coverage-guided ACL oracle (`broker_acl`); new `$SYS/broker/` topics for QoS 2,
  back-pressure, MQTT 5.0 and shared subscriptions.

**Upgrading from v0.4.2**

- **The database migrates from schema 2 to schema 5 on the first boot, one way.** A v0.4.2 kernel refuses the
  migrated database (`schema version 5 is newer than this build`) and every backup snapshot the new kernel takes. If
  you may want to go back, take a backup first, with the VM stopped: a copy of the whole data disk, or v0.4.2's
  `urmqtt-disk backup DISK --write` and then `urmqtt-disk backup-extract DISK OUT` to keep the snapshot outside the
  disk. A power cut during the migration leaves a whole schema with every row. The data-disk layout (v2.1) does not
  change.
- **Configuration formats go up to 13.** A configuration is written with the format of its newest key that is not at
  its default; one that sets no new key keeps format 7 or lower and packs into the v0.4.2 template as before. A new
  key needs: `limits.publisher_backpressure = "off"` 8, `[websocket]` 9, `devices.virtio_net_interrupt = "off"` 11,
  `[mqtt5]` keys and the expiry limits 12, the shared-group limits 13. Packed into an older template it is refused
  ("needs configuration format N ... use a newer release"), so no older kernel boots with a key it would ignore. The
  v0.5.0 template declares format 13; the builder page picks the newest release that reads what the form asks for.
- **Behaviour changes with an unchanged configuration:**
  - persistent sessions, **3.1.1 ones included, expire after 30 days offline** (they were kept forever): raise
    `limits.default_session_expiry_s` and `limits.max_session_expiry_s` before the update if your devices sleep
    longer (4 294 967 295 = never);
  - **MQTT 5.0 clients are served** (`mqtt5.enabled` on; v0.4.2 refused a 5.0 CONNECT); `false` answers CONNACK 0x84;
  - **`limits.publisher_backpressure = "single"`**: a QoS 0 publisher whose only subscriber cannot keep up is paused
    (at most 500 ms at a time) instead of having its messages dropped; `"off"` is v0.4.2's behaviour;
  - **`devices.virtio_net_interrupt = "auto"`**: the receive interrupt where the device offers it and it is verified,
    otherwise polling as before (a boot line says which); `"off"` forces polling;
  - **a connection the broker closes** (keep alive, protocol error, takeover) **ends its session and publishes its
    Will at once**, not when TCP is done with the socket;
  - **QoS 2 is served** (v0.4.2 closed the connection on a QoS 2 PUBLISH and granted QoS 1 to a QoS 2 subscription);
    `limits.max_inflight_qos1` counts QoS 1 and QoS 2 deliveries.
- **A new listener only if you turn it on:** the WebSocket port (8084) opens only with `[websocket] enabled = true`.
- **Rollback to v0.4.2:** pack the same configuration (format 7 or lower) into the v0.4.2 template and give it a data
  disk it can read: the copy or backup taken before the update, or a new disk.

| Template of | Its kernel reads | What the builder page and `urmqtt-config pack --iso` do with it |
|---|---|---|
| v0.1.0 | no template (configuration built in) | not offered: no configuration slot |
| v0.2.0 | formats 1 and 2 | TLS on, with or without plain MQTT; everything newer is refused |
| v0.2.1 | formats 1 to 3 | as v0.2.0, and TLS off (plain MQTT only) |
| v0.3.0 | formats 1 to 4 | as v0.2.1; encryption at rest through `urmqtt-config pack` only |
| v0.4.0, v0.4.1 | formats 1 to 6 | as v0.3.0, and `console.virtio_gpu` and the `[devices]` keys |
| v0.4.2 | formats 1 to 7 | as v0.4.1, and `network.mtu`; formats 8 to 13 are refused ("use a newer release") |
| v0.5.0 | formats 1 to 9 and 11 to 13 | everything the page offers, including `[websocket]`, `[mqtt5]`, back-pressure, the receive interrupt and the shared-group limits |

**Read this before relying on it**

- Alpha: fit for trials and pilots whose operator reads docs/KNOWN-ISSUES.md, not for unattended production.
- MQTT 5.0 without enhanced authentication (CONNACK 0x8C) and without topic aliases sent by the broker; 0x96, 0x89,
  0x8A and 0x9F are never sent; MQTT 3.1 is refused. Shared subscriptions are grouped per role class.
- Wills live in RAM: lost at a restart, not sent at the console's `reboot`. QoS 2 is exactly once across disconnects,
  takeovers and a restart while the client is away, not across a broker crash while it is connected (AUDIT A271-W1).
- WebSocket: `wss://` only, no compression, password sessions are clean only.
- **Nothing of this release ran on a VPS or on physical hardware.** The receive interrupt has run under QEMU only
  (HVF with a GICv2m frame, TCG with the GICv3 ITS, x86_64 TCG); on a hypervisor that delivers it differently the
  broker falls back to polling after 8 frames that waited. Publisher back-pressure and the ADR-268 fix have rig
  numbers only. The real machines so far are one netcup ARM64 VPS and, for x86_64, a Contabo KVM VPS at the H7
  commit. The x86_64 unit tests and the x86_64 and universal-ISO smoke suites are not in CI.
- Plaintext password checks are PBKDF2 (100 000 iterations by default, not memory-hard); plaintext accounts and the
  WebSocket accounts change only with a new image.
- Unchanged from v0.4.2: IPv4 only, virtio over PCI only, no bridging, the AArch64 X25519 assembly has had no
  independent review, PSTATE.DIT is never set, Secure Boot only partly done (release images are not signed), no
  IOMMU, encryption at rest not on the builder page, most kernel crates are cargo-vet exemptions, the audit package
  is a self-review, and the builder's new texts are AI translations, unreviewed. docs/KNOWN-ISSUES.md lists the rest.
- Support: only the latest release gets fixes; **v0.4.2 and older are no longer supported.**

**Measured performance (2026-11-07/08)**

From docs/PERFORMANCE.md section 13: two VPSes, each loaded from the other, against Mosquitto 2.0.21. The urMQTT
builds measured were v0.4.2 and the SACK build of that day (`main` at 318f60b, ADR-265 and ADR-266), **not this
release**: ADR-268 (the QoS 1 fix on one core), ADR-269 (back-pressure) and ADR-270 (the receive interrupt) came after
and have local-rig numbers only. A new measurement of v0.5.0 on the same pair will follow in a blog post.

| Median of three runs | urMQTT SACK build | Mosquitto 2.0.21 |
|---|---|---|
| Contabo x86_64, 4 vCPU: new mTLS connections/s | 1,956 | 639 |
| Contabo: 16 pairs, QoS 0, 64 B, delivered/s | 201k | 60k |
| Contabo: 64 pairs, QoS 1, 64 B, delivered/s | 69k | 30k |
| Contabo: 1 flow, QoS 0, 64 B, delivered/s | 87k | 51k |
| Contabo: 16 x 1000/s, QoS 0, p99 latency | 27 ms | 95 ms |
| Contabo: 20,000 idle mTLS connections | 17.6 MB heap | 546 MB RSS |
| netcup ARM64, one broker core: new mTLS connections/s | 820 (v0.4.2: 923) | 419 |
| netcup: 16 pairs, QoS 0, 64 B, delivered/s | 43.7k | 57.9k |
| netcup: 1 flow, QoS 0, 64 B, delivered/s | 22.3k | 48.7k |
| netcup: 64 pairs, QoS 1, 64 B, delivered/s | 42.4k (v0.4.2: 51.8k) | 20.1k |
| netcup: fan-out 1 -> 1000 at 10/s, delivered; p50 | 8,639; 222 ms | 9,841; 56 ms |

With cores to use, the SACK build led Mosquitto in nearly every row (section 13.3: one 1 KiB flow stayed inside
Mosquitto's range). On one ARM core Mosquitto
kept raw QoS 0 throughput and fan-out to 1000 slow subscribers, and the SACK build was 10-30 % behind v0.4.2 on
QoS 1, the regression ADR-268 fixes (on the local rig with one data core and 1 % loss: 13.4k delivered/s against
v0.4.2's 13.0k and the SACK build's 9.0k). On the local rig, publisher back-pressure delivers everything a single
flow accepts (0 dropped, section 13.5). Raw files and figures: `docs/perf-results/x11-2026-11-07/`.

**Verify** (in an empty directory):

    gh release download v0.5.0 --repo zeljan-alduk/urMQTT
    curl -fsSLO https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.5.0/minisign.pub
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS
    cmp urmqtt-v0.5.0.iso urmqtt-template-v0.5.0-universal.iso
    gh attestation verify urmqtt-v0.5.0.elf --repo zeljan-alduk/urMQTT
    gh attestation verify urmqtt-v0.5.0.iso --repo zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom

`minisign` must report the key `721316B961DCB94B` (`RWRLudxhuRYTcpqyk9TNXAj1qzClrFEvzXTyFMBK6NEuyvk6tVUxjUlH`)
and the trusted comment `urMQTT v0.5.0 release <the tag's commit>`. The SBOM is `urmqtt-v0.5.0.cdx.json`
(CycloneDX), attested with the ISO. With a clone of the repository, `urmqtt-config check-release --keyring
keys/release-keys.json --tag v0.5.0 --sums SHA256SUMS urmqtt-*` applies the same key ring as the builder page, and
`make dist ENV=release` at the tag gives the same line for `urmqtt-v0.5.0.elf` as the published `SHA256SUMS`.
Full changelog: CHANGELOG.md.
