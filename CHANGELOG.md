# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.6.0] - 2026-11-10

The **production-readiness release**: everything since v0.5.0 (signed with the release key `721316B961DCB94B`, as
v0.4.2 and v0.5.0 were). Headline features: **IPv6** with SLAAC or static addresses beside IPv4, on every listener
(ADR-330 to ADR-334); **Prometheus metrics** served by the kernel (ADR-290 to ADR-294); **A/B updates with
automatic rollback**, a second boot slot on new installs (ADR-295 to ADR-299); **password accounts added and removed
at run time** over the signed control channel (ADR-285 to ADR-289); **a limit on established TLS connections per
source address** (ADR-280); **virtio-net multiqueue with RSS** (ADR-310 to ADR-314); and the first **outbound TCP
connection** the broker makes, with TLS 1.3 log shipping as its user (ADR-315 to ADR-319). The security work of the
release: **DMA remapping through the IOMMU** (VT-d, AMD-Vi, SMMUv3; ADR-305 to ADR-307), **Secure Boot completed
for installed disks** with sealed images, `sign-iso` and revocation through `dbx` (ADR-320 to ADR-324), and **a disk
key that is not in the image**, a passphrase typed on the console (ADR-325 to ADR-329). Also: encrypted project
files on the builder page (ADR-300) and **the kernel as a library**, so another repository can build its own image
from these crates (ADR-335 to ADR-339). Nothing of this release ran on a VPS or on physical hardware (see the limits
below); nothing in it is on by default except the per-address connection limit, the new storage schema, the
multiqueue negotiation and the two-slot layout of new installs.

### Security review of this release

Before the tag the release went through an internal, AI-assisted security review (nine lenses, proof per finding, three
independent skeptics per finding; **not** an independent audit, see the report for its limits):
[docs/audit/security-review-v0.6.0.md](https://github.com/zeljan-alduk/urMQTT/blob/main/docs/audit/security-review-v0.6.0.md).
It reported 48 candidates; **31 findings are fixed in this release, with a regression test each, three of them of high
severity**: a leak of captured TLS handshake secrets that, after 4096 abandoned handshakes, made later overlapping
handshakes fail until a reboot (ADR-340); a client certificate with more than one common name that the broker and the
signing script read differently, so that it could carry another identity (ADR-360); and a TLS handshake refused under a
zero window that left a connection never freed, until the heap was full (ADR-355). The code behind them is older than this
release, so **assume earlier releases are affected and update**. The medium and low findings are listed in the report;
the 8 findings that are still open are all of low severity and their details are withheld until they are fixed
(docs/VULNERABILITY-HANDLING.md). The release pipeline changed as a result: the build job holds no secret, a separate
job in the protected environment `release` signs, and a signed older release can no longer be offered under a newer tag
(ADR-380, ADR-381).

### Upgrading from v0.5.0

- **The database migrates from schema 5 to schema 6 on the first boot, one way** (ADR-286: the `accounts` table,
  created whether or not run-time accounts are used; one transaction, a power cut leaves schema 5 or schema 6 whole).
  **A v0.5.x kernel refuses the migrated database** (`schema version 6 is newer than this build`) **and every backup
  snapshot the new kernel takes**. If you may want to go back, take a backup before the update, with the VM stopped: a
  copy of the whole data disk, or v0.5.0's `urmqtt-disk backup DISK --write` followed by `urmqtt-disk backup-extract
  DISK OUT`; a v0.6.0 `urmqtt-disk` that writes to the disk migrates the database first. The reserved schema 7 is not
  used: nothing else in the database changes (LATER-7 adds no schema). The data-disk layout (v2.1) is unchanged; a
  disk that is encrypted with a console passphrase gets a superblock flag and 256 bytes of key slots (DISK-FORMAT
  14.2) only when you choose that mode.
- **Configuration formats go up to 23** (the kernel reads 1 to 9, 11 to 20, 22 and 23; 10 and 21 were never used and
  are refused). A configuration is written with the format of its newest key that is not at its default, so one that
  sets none of the new keys keeps format 13 or lower, packs into the v0.5.0 template as before and boots either
  kernel. A new key needs: `limits.max_connections_per_ip` set to anything but 1024 **14** (ADR-280),
  `limits.max_runtime_accounts` above 0 **15** (ADR-285), `[metrics]` **16** (ADR-290), an `[update]` key at a
  non-default value **17** (ADR-297), `devices.iommu` other than `"off"` **18** (ADR-305),
  `devices.virtio_net_queues = "single"` **19** (ADR-313), `observability.log_tls*` **20** (ADR-318),
  `storage.disk_key_source = "console"` **22** (ADR-328), `network.ipv6`, `network.ipv6_address`,
  `network.ipv6_gateway` or an IPv6 network in `plaintext.allow_from` / `metrics.allow_from` **23** (ADR-334).
  One that sets a new key is refused when packed into an older template ("needs configuration format N, which this
  template's kernel does not read (it reads up to 13): use a newer release"), so no older kernel boots with a key it
  would ignore. The v0.6.0 template declares format 23. The builder page (rebuilt for format 23) picks the newest
  release that reads what the form asks for and greys out a release whose template it cannot read.
- **Behaviour changes with an unchanged configuration:**
  - **A source address holds at most 1024 established TLS connections** (the MQTT and WebSocket ports together):
    over the limit its SYN gets no answer. Devices behind one NAT share an address: a site with more than 1024
    devices behind one address must set `limits.max_connections_per_ip` higher (or 0, off; format 14) before the
    update. (The dev word `limits=bench` and `deploy/bench/config.toml` turn it off.)
  - **A new install has two boot slots**: the first boot of a disk with a v0.6.0 kernel reserves a second region the
    size of the ESP (10 MiB with the aarch64 image, about 20 MiB with the universal one) before the data partition
    (`gpt: standby boot slot reserved ...`). **Existing installed disks stay single-slot** (a v0.6.0 kernel does not
    move data to make room; the boot log says `boot: one boot slot (a disk prepared before v0.6.0)`) and keep
    updating with `urmqtt-disk update-boot` as before; A/B needs a disk installed, or re-installed with
    `export-db` / `import-devices`, by v0.6.0 or later. `urmqtt-disk update-boot` refuses a disk with two slots
    (`--in-place` overrides it, never during a trial).
  - **virtio-net multiqueue**: a NIC that offers multiqueue with receive-side scaling gets one queue pair per data
    core from the first boot (`devices.virtio_net_queues = "auto"`); every other NIC is as before. `"single"`
    (format 19) restores one pair.
  - **virtio devices may offer `VIRTIO_F_ACCESS_PLATFORM`**: the kernel now accepts it (no change for devices that do
    not offer it, which is every default QEMU and cloud device).
  - **Per-connection TCP state grows from 112 to 128 bytes** on every image (16-byte addresses).
  - **Off unless you turn them on**: IPv6 (IPv6 frames are dropped and counted as before), the metrics endpoint (TCP
    9100), the outbound log connection, the IOMMU (`devices.iommu = "off"`), run-time accounts
    (`limits.max_runtime_accounts = 0`: the control channel refuses account commands), the console passphrase, the
    A/B confirmation (`[update]` defaults: a trial boot confirms itself after 60 s).
  - Every kernel prints a `build: <version> (A/B protocol 1, store schema N, configuration formats up to M)` line; new
    `$SYS/broker/` topics, info-query fields and statsd names are added, none is changed.
  - The open image is no longer byte-identical to a v0.5.x build of the same inputs (the kernel is a library now,
    ADR-335); it is still reproducible (`make repro`) and release hashes change as with any release.
- **Turning IPv6 on opens every listening port to IPv6 clients too**: a firewall in front must allow (or deny) the
  same ports over IPv6, and allow-lists without IPv6 networks keep refusing IPv6 clients. Metrics need
  `metrics.allow_from` (required; no "anywhere").
- **Downgrade effects**: a v0.5.x kernel refuses the migrated database (above), a configuration of format 14 or newer
  (by its version, at boot) and a data disk with console key slots (an unknown superblock flag). A v0.5.x kernel
  boots a two-slot disk (it ignores the standby entry) but never counts, confirms or switches: do not activate a
  slot with it; going back to v0.5.x on such a disk is `update-boot --in-place` (no way back from there) or staying on
  v0.6.x. v0.5.0's `urmqtt-disk update-boot` does not know seals: on a sealed disk it can leave a disk its loader
  refuses (fail closed, no data lost). To go back to v0.5.0: pack the same configuration with no new key (format 13
  or lower) into the v0.5.0 template and give it the data disk backed up before the update, or a new disk;
  docs/RELEASE.md section 6.
- **Updates from now on**: on a disk with two slots, `urmqtt-disk slots stage DISK --image <release>.img --sums
  SHA256SUMS --sig SHA256SUMS.minisig --pubkey minisign.pub --write`, then `slots activate`; the kernel confirms
  itself or goes back (docs/OPERATE.md "Boot slots and updates", docs/DEPLOY.md 8b). A sealed (Secure Boot) disk stages only an ESP
  sealed to its configuration (`sign-iso ... --esp-out`, `slots stage --replace-config`).

**Limits, stated plainly.** Alpha: fit for trials and pilots whose operator reads docs/KNOWN-ISSUES.md, not for
unattended production. **Nothing of this release ran on a VPS, on KVM or on physical hardware**: QEMU only (HVF, TCG;
the IOMMU models, the multiqueue rig and the IPv6 router are QEMU's), and the x86_64 `accounts` smoke group needs
KVM (one 100 000-iteration check takes 5 to 8 s under TCG). Several items are delivered in part and say so:
**A/B updates** do not convert a disk prepared before v0.6.0, do not count a kernel that dies before its block
driver runs (A295-W1), have no firmware anti-rollback and no staging over the network; **Secure Boot** has no
version counter (H8-W6 stays open in part), no shim/MOK (firmware that trusts only Microsoft's keys cannot boot
these images), no signed `dbx` tooling for real firmware, and no release image is signed (the project holds no
Secure Boot key; the universal suites are run by hand, not in CI); **the console passphrase** keeps the broker down
after every reboot until a person types it, and the superblock is plaintext, so the passphrase must be strong; TPM
sealing and network unlock are not built; **the IOMMU** runs on QEMU's models only, with no interrupt remapping and
no fault interrupt; **multiqueue** has not run on KVM with vhost; **IPv6** has no fragment reassembly, no ICMPv6
errors, one global address, no DHCPv6, UDP stays IPv4 (SNTP, syslog, statsd, the log collector) and Neighbour
Discovery is unauthenticated; **the outbound connection** has one user (log shipping, an IPv4 literal, no client
certificate, at-most-once); **metrics** are plain HTTP behind an allow-list; **the kernel as a library** has no
driver interface for a non-virtio NIC, disk or entropy source; **the builder's encrypted project** has no recovery
for a forgotten passphrase. The builder test "the build ends in a result card" fails without the emulator runtime
(`make builder-emulator`). The new builder texts are AI translations, unreviewed. The rest of v0.5.0's limits is
unchanged: ROADMAP NEXT-8 (export bridge), NEXT-10 (DNS) and LATER-1 (clustering) are not started.

### Added

- **IPv6** (ROADMAP NEXT-1, ADR-330 to ADR-334): `network.ipv6 = "off" | "slaac" | "static"`, `ipv6_address`,
  `ipv6_gateway` (format 23). Link-local address from the MAC (EUI-64) and one global address from the first /64
  prefix of the router's advertisements (the default router and the MTU from them), or a static address and gateway;
  duplicate address detection on every address. Every listener (TLS, WebSocket, plaintext, metrics) is dual stack;
  an IPv6 /64 counts as one source for `limits.max_connections_per_ip`, `limits.max_handshakes_in_flight_per_ip` and
  the plaintext and WebSocket tables; `plaintext.allow_from` and `metrics.allow_from` take IPv6 networks; multiqueue
  NICs are asked for TCP/IPv6 RSS. Extension headers bounded (4, 256 bytes), fragments dropped and counted, Neighbour
  Discovery answers rate-limited, MLD queries answered. `$SYS/broker/net/ipv6/...`, `net.ipv6` in the info reply,
  `urmqtt_ipv6_*` metrics, console `status` lines. Fuzz `ipv6_nd` (it found that a multicast "prefix" in an RA made a
  multicast address: fixed), `net_frame`, `tcp_segment` over both families, the RFC 9293/5961 scripts rerun over
  IPv6, smoke group `ipv6` (SLAAC against QEMU's router, IPv6 only, dual stack), `scripts/run-qemu.sh --net6`,
  `scripts/ipv6-relay.py`.
- **Prometheus metrics** (ROADMAP NEXT-9, ADR-290 to ADR-294): `[metrics] enabled = true` serves `GET /metrics` on TCP
  9100 as plain HTTP/1.1 to the networks in `metrics.allow_from` (required, at most 16, no `0.0.0.0/0`) and answers
  nobody else. Every `$SYS/broker/...` number is a metric (about 170 series with four cores) made from the same
  `Info`, with base units, `_total` counters, `_info` gauges and labels that are bounded and never chosen by a client;
  text format 0.0.4, or OpenMetrics 1.0.0 when `Accept` prefers it. One bounded request (2048 bytes, 24 headers),
  GET and HEAD, one answer per connection, a deadline, 8 connections and 2 per address per core, 20 scrapes a
  second per core. New crate `urmqtt-http`, fuzz `http_request` and `metrics_render`, smoke group `metrics`, OPERATE.md
  "Metrics for Prometheus" (scrape configuration, names, alert rules). Configuration format 16.
- **A/B updates with rollback** (ROADMAP NEXT-11, ADR-295 to ADR-299): two boot slots on new installs;
  `urmqtt-disk slots stage | activate | status | confirm | rollback` (a release checked against its minisign signature
  and SHA-256, or an own ESP with `--unsigned`; a dry run without `--write`; 3 trial boots by default, `--tries
  1..7`); the kernel counts a trial boot, confirms itself once the store is open and a listener has been up for
  `update.confirm_after_s` (60 s), and, after a crash, a fatal error, a watchdog reset or no confirmation within
  `update.trial_timeout_s` (900 s) with no trial left, switches the boot entry back and resets into the previous
  release; the failed slot is marked bad. `[update] confirm = "operator"` waits for the signed control messages
  `boot-confirm` and `boot-rollback` (bound to the boot disk's GUID). Downgrade rules: a kernel from before v0.6.0 and
  one with an older store schema are always refused, an older release needs `--allow-downgrade`, a newer schema
  `--one-way` (the previous slot is then marked bad). Every write of every step is tested for a power cut (host, and
  QEMU on aarch64 and x86_64 UEFI). Configuration format 17 (`[update]`), control commands 7 and 8, smoke group `ab`
  (also on the universal image: x86_64 BIOS and UEFI, aarch64), fuzz `boot_slots`.
- **Password accounts at run time** (ROADMAP NOW-15, ADR-285 to ADR-289): the signed control commands `set-account`
  and `remove-account` (`urmqtt-control set-account --id ID --password-stdin [--class full|read-only|write-only]`;
  the operator's machine hashes with PBKDF2-HMAC-SHA-256 and only the hash is signed), accounts that log in on the
  plaintext and WebSocket listeners at once, without a reboot, and are kept on the data disk (schema 6, hashes only).
  A removed account, a changed password or class closes that account's live connections (5.0: DISCONNECT 0x98). A
  class only narrows the listener's patterns. `limits.max_runtime_accounts` (default 0, at most 1024; format 15); the
  image's own accounts and the service, operator and control identities cannot be shadowed; audit lines carry no
  secret. Fuzz `control_account`, smoke group `accounts`.
- **A limit on established TLS connections per source address** (ROADMAP NOW-14, ADR-280):
  `limits.max_connections_per_ip`, default 1024, 0 turns it off (format 14 for any other value); a table of 32 768
  addresses (beyond it a new address is let through uncounted and counted); counters
  `$SYS/broker/connections/per_address/...`. Fuzz `source_limit`, `tools/attack established-flood`, smoke group
  `conn-limit`.
- **virtio-net multiqueue with RSS** (ROADMAP NEXT-6, ADR-310 to ADR-314): one queue pair per data core when the
  device offers MQ, the control queue and RSS; the device's RSS is programmed with the broker's own Toeplitz key and
  table so each flow arrives on its owner's queue; per-queue MSI-X vectors with ADR-270's probation and fallback; a
  frame of another core goes to core 0 and is counted. `devices.virtio_net_queues = "auto" | "single"` (format 19),
  `$SYS/broker/net/queue*`, `urmqtt_network_queue_*` metrics, `scripts/run-qemu.sh --tap`, `scripts/mq-rig.sh`, smoke
  group `mq`, fuzz `virtio_net_mq`.
- **An outbound TCP client and log shipping over TLS 1.3** (ROADMAP NEXT-7, ADR-315 to ADR-319; D-6): active open in
  `urmqtt-tcp` (SYN-SENT, retransmission, RFC 6528 sequence numbers, ephemeral ports), a TLS 1.3 client that trusts only
  the configured anchors, and `observability.log_tls = "a.b.c.d:port"` with `log_tls_ca`, `log_tls_name` and
  `log_tls_queue_kb` (RFC 5425 octet counting, a bounded queue, reconnect with jittered backoff; format 20). Off unless
  configured; no remote input chooses a destination. Fuzz `tcp_active` and `tls_client`, smoke group `logtls`.
- **DMA remapping** (ROADMAP LATER-5, ADR-305 to ADR-307): `devices.iommu = "off" | "auto" | "require"` (format 18;
  default `off`): Intel VT-d, AMD-Vi and Arm SMMUv3 driven from the firmware's tables, every device's DMA blocked from
  before the first driver, a domain per device with only its own buffers; blocked DMA counted and logged
  (`$SYS/broker/iommu/...`); `require` refuses to boot where it cannot translate. Smoke group `iommu`, fuzz
  `iommu_tables`, `scripts/run-qemu.sh --iommu`.
- **Secure Boot completed** (ROADMAP LATER-6, ADR-320 to ADR-324): an image signed with your own key is sealed (the
  installed disk's `limine.conf` pins the configuration by BLAKE2b), so the installed disk, the raw image and an A/B
  slot boot under Secure Boot (AUDIT H8-W1); sealed images take only their own configuration (installer, `urmqtt-disk`,
  `urmqtt-config` refuse another before writing); `scripts/sign-loaders.sh sign-iso` signs an ISO the builder page
  configured, without building a kernel (H8-W2); revocation by `dbx` hash (`authenticode`, `ovmf-vars --dbx-hash`);
  aarch64 enforcement tested with AAVMF. docs/secure-boot-keys.md; smoke `secureboot` from 10 to 30 checks; fuzz
  `seal_pins`.
- **A disk key outside the image** (ROADMAP LATER-7, ADR-325 to ADR-329): `storage.disk_key_source = "console"` (format
  22). The data partition's random key is wrapped (RFC 3394 under PBKDF2 of a passphrase) in up to two key slots of
  the superblock; the kernel asks on the console at every boot, before the store opens and before any listener;
  `change` at the prompt changes the passphrase; `urmqtt-disk keys DISK [add | change | remove | unwrap]` and
  `--passphrase-file`. A RAM store asks for nothing. Smoke group `unlock`, fuzz `disk_keyslot`, `scripts/run-qemu.sh
  --serial-in`.
- **Encrypted project files on the builder page** (ROADMAP NOW-16, ADR-300): "Project and secrets" saves the whole
  form, secrets included, as `<name>.urmqtt-project` (PBKDF2 600 000 rounds, AES-256-GCM) or as an encrypted copy in
  the browser; "Wipe secrets from memory"; 40 new texts in each of the 15 languages; the page makes no new request.
  The builder also offers `storage.encryption` and `storage.disk_key_source`, the `[metrics]`, `[update]`, IPv6 and
  log-shipping keys and the new limits.
- **The kernel as a library** (ROADMAP NOW-18, ADR-335 to ADR-339): `urmqtt_kernel` with an `Edition` API (PCI drivers
  by ID, never a virtio function; configuration keys in the reserved tags `0xF000..=0xFFFE`, TOML `[ext.<section>]`;
  four boot hooks); the open image is `urmqtt_kernel::image!(Edition::OPEN)` and refuses an edition's
  configuration. `examples/edition`, `make edition-example`, `mkiso.sh --config-slot`, smoke group `edition`, fuzz
  `cfg_ext`, `scripts/check-lock-subset.py`; docs/EDITIONS.md 5, ARCHITECTURE 8b.

### Changed

- `urmqtt-disk update-boot` refuses a disk with two slots without `--in-place`; `slots rollback` refuses a previous
  slot whose kernel cannot read the store on the disk; `urmqtt-disk encrypt | decrypt | rekey` empty the key slots when
  they change the key.
- `$SYS`: the first pass runs when the shard is made, outside the handler watchdog.
- CI: new smoke shards (`metrics`, `conn-limit`, `ab`, `unlock`, `logtls`, `edition`, `ipv6`, `mq`, `iommu`) and fuzz
  targets; the example edition is formatted, linted, built and smoke-tested; its lockfile may hold nothing the
  workspace's does not.
- The builder tests compare with the tree's `FORMAT_VERSION` instead of each item's own number.

### Security

- Per-address limits cover the established connections (ADR-280); IPv6 sources are keyed by their /64.
- The IOMMU closes DMA by a device that is not its driver's buffer (LATER-5); a Secure Boot enforcing machine boots an
  installed disk and refuses another configuration (LATER-6); a stolen ISO or a copied data disk no longer opens the
  data when `storage.disk_key_source = "console"` (LATER-7).
- The metrics port answers only the networks listed; any other address gets nothing.
- The outbound client trusts only the configured anchors and the configured name, by the wall clock.
- Found and fixed while building it: a multicast "prefix" in a Router Advertisement made a multicast address
  (`ipv6_nd` fuzz); the sum of arbitrary counters in `sys.rs` `by_code` could overflow (`saturating_add`, found by the
  `metrics_render` fuzz target); a certificate chain larger than one TLS record during the outbound handshake; log
  records written into a connection the collector had closed; a stranded standby slot adopted by the firmware; a
  sealed disk accepting an unsealed ESP; `keys unwrap` emptying the slots before writing `--key-out`. The audit
  inventory and the code-scanning triage (docs/audit/) were refreshed.

## [0.5.0] - 2026-11-09

The **MQTT 5.0 and QoS 2 release**: everything since v0.4.2 (the first release signed with the release key
`721316B961DCB94B`, which signs this one too). Three headline features: **QoS 2, exactly once** (ADR-271);
**MQTT over secure WebSocket** in the kernel (`wss://`, ADR-272, off by default); and **MQTT 5.0** beside 3.1.1 on
every listener (the codec, ADR-273; broker semantics with session and message expiry, reason codes, properties, flow
control and topic aliases from the client, ADR-274; shared subscriptions and Subscription Identifiers, ADR-275), with
only enhanced authentication refused (CONNACK 0x8C). With them, the performance work of ROADMAP NOW-13: TCP recovery
from SACK blocks (ADR-265) and its loss detection counting the flow's own segments, which fixes the QoS 1 regression
of the SACK build on one core (ADR-268); deeper virtio-net queues (ADR-266); publisher back-pressure when a QoS 0
message has a single full subscriber (ADR-269); and the virtio-net receive interrupt with probation, verification
and a polling fallback (ADR-270). The two-VPS comparison against Mosquitto 2.0.21 (docs/PERFORMANCE.md section 13,
2026-11-07/08) measured v0.4.2 and the SACK build of that day; ADR-268 to ADR-270 have rig numbers only. Also:
plaintext password hashes at 100 000 PBKDF2 iterations by default (ADR-267), the watchdog self-test and
`$SYS/query/info` fixes, and a hashed paho-mqtt for CI's smoke scenarios.

### Upgrading from v0.4.2

- **The database migrates from schema 2 to schema 5 on the first boot, one way.** The kernel (and `urmqtt-disk`, when
  it opens the disk) runs the migrations 2 to 3 (ADR-271), 3 to 4 (ADR-274) and 4 to 5 (ADR-275) in order, each in one
  transaction; a power cut leaves a whole intermediate schema with every row. **A v0.4.2 kernel refuses the migrated
  database** (`schema version 5 is newer than this build`) **and every backup snapshot the new kernel takes** (a
  snapshot records its schema). If you may want to go back, take a backup before the update, with the VM stopped: a
  copy of the whole data disk, or v0.4.2's `urmqtt-disk backup DISK --write` followed by `urmqtt-disk backup-extract
  DISK OUT` (which does not change the disk) to keep the snapshot outside it; a v0.5.0 `urmqtt-disk` that writes to
  the disk migrates the database first. The data-disk layout itself (v2.1) does not change.
- **Configuration formats go up to 13** (the kernel reads 1 to 9 and 11 to 13; 10 was never used and is refused). A
  configuration is written with the format of its newest key that is not at its default: `network.mtu` 7 (ADR-264),
  `limits.publisher_backpressure = "off"` 8 (ADR-269), `[websocket]` 9 (ADR-272), `devices.virtio_net_interrupt = "off"`
  11 (ADR-270), any `[mqtt5]` key or `limits.max_session_expiry_s` / `default_session_expiry_s` /
  `max_message_expiry_s` 12 (ADR-274), `limits.max_shared_groups` / `max_shared_group_members` 13 (ADR-275). A
  configuration that sets none of them keeps format 7 or lower, packs into the v0.4.2 template as before, and boots
  either kernel. One that sets a new key is refused when packed into an older template ("needs configuration format
  N, which this template's kernel does not read (it reads up to 7): use a newer release"), so no older kernel boots
  with a key it would ignore. The v0.5.0 template declares format 13. The builder page (rebuilt for format 13) picks
  the newest release that reads what the form asks for and greys out a release whose template it cannot read;
  `urmqtt-config pack --iso/--image` refuses as above.
- **Behaviour changes with an unchanged configuration:**
  - **Persistent sessions expire after 30 days offline**, 3.1.1 sessions (`clean_session = 0`) included; they were kept
    forever. Raise `limits.default_session_expiry_s` and `limits.max_session_expiry_s` (4 294 967 295 = never;
    format 12) before the update if your devices sleep longer.
  - **`mqtt5.enabled` is on**: a CONNECT with protocol level 5 is served on every listener (v0.4.2 refused it).
    `mqtt5.enabled = false` (format 12) answers it with CONNACK 0x84.
  - **`limits.publisher_backpressure = "single"`**: a QoS 0 publisher whose only subscriber cannot keep up is paused
    (its TCP window closes, at most 500 ms at a time) instead of having its messages dropped. `"off"` (format 8) restores
    v0.4.2's behaviour.
  - **`devices.virtio_net_interrupt = "auto"`**: the receive interrupt wakes the NIC's core when the device offers
    MSI-X and it is verified; otherwise, and after 8 frames that waited without it, the broker polls as v0.4.2 did
    (a boot line says which). `"off"` (format 11) forces the polling.
  - **A connection the broker closes** (keep-alive timeout, a protocol error, a takeover) **ends its session and
    publishes its Will at once**, not when TCP is done with the socket.
  - **QoS 2 is served**: a QoS 2 PUBLISH is answered with PUBREC (v0.4.2 closed the connection), subscriptions are
    granted QoS 2; `limits.max_inflight_qos1` now counts QoS 1 and QoS 2 deliveries.
  - New plaintext password hashes from `urmqtt-config hash-password` and the builder cost 100 000 PBKDF2 iterations;
    existing hashes keep their own count.
- **New listener only if you turn it on**: the WebSocket port (8084) opens only with `[websocket] enabled = true`.
- **Rollback to v0.4.2**: pack the same configuration (formats 7 or lower) into the v0.4.2 template, and give it a data
  disk it can read: the backup taken before the update, or a new one. docs/RELEASE.md section 6.

**Limits, stated plainly.** Alpha: fit for trials and pilots whose operator reads docs/KNOWN-ISSUES.md, not for
unattended production. MQTT 5.0 is complete except enhanced authentication (refused, CONNACK 0x8C) and topic aliases
sent by the broker; the Eclipse Paho suite passes 25 of 27 (5.0) and 8 of 10 (3.1.1) on the development port, the rest
expected failures by design (docs/MQTT5-CONFORMANCE.md). Wills live in RAM (lost at a restart, not sent at
`reboot`); QoS 2 is exactly once across disconnects and restarts while the client is away, not across a broker crash
while it is connected (AUDIT A271-W1). The receive interrupt has run under QEMU only (HVF, TCG with the GICv3 ITS,
x86_64 TCG), publisher back-pressure and ADR-268 on the local rig only; **nothing of this release ran on a VPS**, and
nothing on physical hardware. The x86_64 unit tests and the x86_64 and universal-ISO smoke suites are not in CI. The
new builder texts are AI translations, unreviewed. The rest of v0.4.2's limits is unchanged.

### Added

- **MQTT 5.0 shared subscriptions and Subscription Identifiers** (ROADMAP NEXT-3 part 3, ADR-275; NEXT-3 is done
  with it). `$share/{group}/{filter}` for 5.0 and 3.1.1 clients: a group is (role class, group, filter), so a device
  and a service never share one; it lives on one owner data core, which hands each message round robin to one online
  member at that member's QoS (min of publish and subscription); with no member online QoS 0 is dropped and QoS 1 and
  2 go to an offline persistent member's queue. No retained messages on a share, No Local on a share is DISCONNECT
  0x82, the ACL judges the filter after `$share/{group}/`. A SUBSCRIBE whose group lives on another core waits for
  that core before its SUBACK. When a member's session ends, its unacknowledged QoS 1 messages and its queue go to
  another member (QoS 2 in flight never). `limits.max_shared_groups` (per data core) and
  `limits.max_shared_group_members`, 1024 each: one more is SUBACK 0x97 (3.1.1: 0x80). Subscription Identifiers: one
  per subscription, every matching identifier in one PUBLISH per message, stored with persistent sessions. CONNACK
  announces both (by leaving the properties out) unless `mqtt5.shared_subscriptions` or
  `mqtt5.subscription_identifiers` is `false`. Enhanced authentication is refused for good (CONNACK 0x8C; an AUTH
  after the CONNECT: DISCONNECT 0x82). Part 2's loose ends: retained messages with a Message Expiry Interval are
  swept (64 per 100 ms tick) instead of only cleared when read; the console's `reboot` tells 5.0 clients DISCONNECT
  0x8B and publishes no Will; a revoked certificate gets DISCONNECT 0x98 before the close (cut after 1 s anyway); the
  topic-alias tables are counted in the memory statistics. 0x96, 0x89, 0x8A and 0x9F are never sent, by design. New
  `$SYS/broker/` topics: `shared/groups`, `shared/members`, `shared/messages/delivered`, `/dropped`,
  `/redispatched`, `shared/joins/refused`, `retained/expiring`, `memory/topic_aliases`, `disconnects/sent/0x8b`;
  the info query gains `retained_expiring`, `topic_alias_bytes` and `mqtt5.shared`, the console's `status` a
  `shared:` line. Configuration format 13 (the two limits; formats 8, 9, 11, 12 and 13 are valid, 10 is refused);
  the builder page has both limits and keeps `mqtt5.shared_subscriptions` shown with MQTT 5.0 off, since 3.1.1
  clients share too. Database schema 5 (`subscriptions.sub_id`). The 3.1.1 QoS 0 and QoS 1 routing still makes 9 and
  15 allocations per message; the release kernel grows by 64 200 B (aarch64, 4 128 064 B) and 86 736 B (x86_64,
  4 308 600 B). Verified by 20 host tests (`shared_tests.rs`), a new reference-model proptest (`shared_model`: each
  group exactly once through one member, never across roles; mutation-checked), the ACL oracle, `acl_model` and
  `qos2_model` with shares, fuzz seeds `mqtt5_shared_and_ids` and `mqtt5_shared_groups`, store golden and power-cut
  tests for schema 4 to 5, the smoke group `mqtt5` (shares over mTLS, a restart keeping a shared subscription with
  its identifier, a four-vCPU image with a group of paho and mosquitto workers), and the Paho suite (results in
  docs/MQTT5-CONFORMANCE.md; an optional CI job `mqtt5-conformance` runs it under TCG when dispatched by hand).
- **MQTT 5.0 in the broker** (ROADMAP NEXT-3 part 2, ADR-274): every listener (TLS, plaintext, WebSocket) accepts
  MQTT 5.0 beside 3.1.1, chosen per connection by the CONNECT's protocol level (`mqtt5.enabled`, on by default;
  off: CONNACK 0x84). Properties are forwarded to 5.0 subscribers (user properties, content type, response topic,
  correlation data, payload format indicator), also across cores and in retained messages and stored queues, and
  stripped for 3.1.1 subscribers; reason codes on CONNACK, PUBACK, PUBREC, SUBACK, UNSUBACK and a server DISCONNECT
  instead of a silent close (0x8E takeover, 0x8D keep alive, 0x93 Receive Maximum, 0x94 topic alias, 0x95 packet
  size, 0x98 allowlist, 0x9A retain, ...), reason strings when the client allows them; Session Expiry Interval,
  Message Expiry Interval, Will Delay Interval; Receive Maximum and Maximum Packet Size both ways; topic aliases from
  the client; subscription options (No Local, Retain As Published, Retain Handling); assigned client identifier;
  Server Keep Alive (`mqtt5.max_keep_alive_s`). Shared subscriptions and subscription identifiers came with part 3
  (next entry); enhanced authentication stays refused (CONNACK 0x8C). New `$SYS/broker/` topics:
  `clients/connected/v311` and `/v5`, `messages/expired`, `messages/dropped/too_large`, `sessions/expired`,
  `sessions/expiring`, `wills/delayed`, `wills/pending`, `disconnects/sent/0xNN`, `connections/refused/v5/0xNN`.
  Configuration format 12: `[mqtt5]` (`enabled`, `receive_maximum`, `topic_alias_maximum`, `max_user_properties`,
  `max_keep_alive_s`, and the reserved part-3 keys), `limits.max_session_expiry_s`,
  `limits.default_session_expiry_s`, `limits.max_message_expiry_s`; the builder page has the section (formats 8, 9,
  11 and 12 are valid, 10 is refused as unknown). Database
  schema 4 (session expiry and offline time, subscription options, message properties and expiry), migrated at boot
  from schema 3. Verified by host tests per rule, the QoS 2 reference model and the ACL oracle extended to 5.0
  sessions, fuzz seeds, the smoke group `mqtt5` (paho-mqtt 2.x and mosquitto `-V mqttv5` over mTLS, a restart on
  the same disk, `mqtt5.enabled = false`), a schema 3 disk of the previous kernel booted by this one, and the Eclipse
  Paho interoperability suite (`scripts/mqtt5-conformance.sh`, expected failures listed and justified in
  docs/MQTT5-CONFORMANCE.md).
- **MQTT 5.0 codec** (`urmqtt_mqtt::v5`, ROADMAP NEXT-3 part 1, ADR-273): all 15 packet types including AUTH,
  properties checked against the specification's per-packet table, duplicate and value rules, reason codes per
  packet, subscription options, shared-subscription syntax; zero-copy and allocation-free like the 3.1.1 codec,
  with documented bounds for User Properties and Subscription Identifiers; an encoder that refuses what the decoder
  refuses. Tested from the specification's tables, with round-trip proptests, a negative corpus and packets
  captured from Mosquitto 2.x and paho-mqtt 2.x clients (`scripts/mqtt-record.py`, `scripts/mqtt5-capture.sh`);
  fuzz targets `mqtt5_packet` and `mqtt5_props`; Kani harnesses for the varint and property-length arithmetic.
  **The broker does not use it yet: a 5.0 CONNECT is still refused.** ADR-273 also decides the broker semantics of
  parts 2 and 3 (version negotiation, session and message expiry, flow control, topic aliases, subscription
  options, shared subscriptions, enhanced auth refused with 0x8C) and reserves configuration format 12;
  `docs/MQTT5-CONFORMANCE.md` is the test plan (Eclipse Paho interoperability suite, Mosquitto clients), with
  `scripts/mqtt5-conformance.sh` as its harness stub.
- **MQTT over secure WebSocket in the kernel** (ROADMAP NEXT-5, D-5 answered: in the kernel; ADR-272). A new
  `[websocket]` section (configuration format 9; off by default): `wss://host:8084/mqtt`, TLS 1.3, subprotocol `mqtt`,
  RFC 6455 binary frames. `auth = "mtls"` (default) takes a client certificate exactly as the TLS port does;
  `auth = "password"` serves browsers without a client certificate and checks an MQTT user name and password from
  `websocket.users` inside TLS (PBKDF2 hashes, lock-out and login rate as for plaintext accounts), with the section's
  own ACL (`web/{id}/#`), limits and a `$ws/` session namespace, clean sessions only. `websocket.origins` is the
  allowlist of web pages (required with passwords). The new `no_std` crate `urmqtt-ws` holds a bounded HTTP Upgrade
  parser (4 KiB, 32 header lines, fixed 400/403/404/426 answers) and a streaming frame codec without a reassembly
  buffer; the upgrade must finish within `websocket.upgrade_timeout_s`. `$SYS/broker/websocket/...`, the info query
  and the status line report upgrades, refusals by reason, logins, frames, bytes and close codes. Verified with fuzz
  targets `ws_upgrade` and `ws_frames`, Kani, Miri, Autobahn|Testsuite (0 failed; docs/audit/ws-autobahn.md) and the
  smoke group `websocket` (paho-mqtt over wss against the kernel in QEMU, 10 000 idle connections).
- **QoS 2, exactly once** (MQTT 3.1.1 4.3.3, ROADMAP NEXT-2, ADR-271). A QoS 2 PUBLISH is answered with PUBREC and
  routed once; its packet id is held until PUBREL, and a PUBLISH with a held id is answered again and never routed
  again (method B). Subscriptions are granted QoS 2; deliveries at QoS 2 take PUBLISH, PUBREC, PUBREL, PUBCOMP in the
  existing in-flight window (`limits.max_inflight_qos1` now covers QoS 1 and 2); wills and retained messages keep
  QoS 2. A persistent session resumes every flow after a reconnect (PUBLISH with DUP and PUBREL, with their ids) and,
  while it is offline, across a restart. A client may hold `max(max_inflight_qos1, 64)` ids awaiting PUBREL; one more
  closes its connection. New counters `$SYS/broker/messages/qos2/{received,duplicates,completed,inbound_full}`, also in
  the info reply and the `status` command. No configuration change (no new key, no format bump). Not across a crash of the
  broker while the client is connected (KNOWN-ISSUES section 5, AUDIT A271-W1).
- Smoke group `mqtt_qos2` (both architectures, also in `SMOKE_ONLY=misc`): duplicates, a client killed in the middle
  of each flow, paho-mqtt interop (through `uv` when installed), and a restart of the VM in the middle of every flow;
  QoS 2 scenarios with mosquitto `-q 2` in `mqtt-scenarios.py`. A reference-model proptest for QoS 2
  (`crates/broker/tests/qos2_model.rs`); the `broker_acl` oracle checks the exactly-once rules; `broker_input` has
  seeds (QoS 2), replayed by `cargo test`. `cargo run --release -p urmqtt-broker --example throughput` measures the
  broker core's routing rate.
- **Publisher back-pressure** (ADR-269, ROADMAP NOW-13): when a QoS 0 message has a single subscriber and that
  subscriber cannot keep up, the broker stops reading the publisher (its TCP receive window closes) until the
  subscriber has caught up, instead of reading and dropping; as Mosquitto behaves on one flow. With several data cores
  the subscriber's shard asks the publisher's shard for the pause and the resume. On the local rig one flow now
  delivers everything it accepts (0 dropped, PERFORMANCE §13.5); the VPS pair is not measured yet. Fan-out to two or more
  subscribers keeps dropping for a slow one; QoS 1 keeps its in-flight window. A pause lasts 500 ms at most (then 2 s of
  read-and-drop), never forms a cycle, counts as alive for keep-alive, and holds at most the TCP window it promised.
  New key `limits.publisher_backpressure = "single" | "off"` (default `"single"`; `"off"` needs configuration format
  8), `$SYS/broker/messages/backpressure/{mode,paused,paused_ms,timeouts,holding}`, `"backpressure"` in the info
  reply, a `status` line, a boot line and a console line. `TcpStack::reset_recv_space`.
- **virtio-net's receive interrupt** (ADR-270, NOW-13): a frame that arrives while the broker is idle wakes the core
  that owns the NIC through the receive queue's MSI-X interrupt (x86_64 local APIC; aarch64 GICv2m frame, or the GICv3
  ITS through a new minimal ITS driver, as on QEMU TCG and KVM `virt` such as the netcup ARM VPS) instead of ADR-224's
  200 us poll once the NIC has been quiet for 2 ms (while traffic is recent it polls as before, which batches frames
  better than one interrupt per idle gap). Interrupts are asked for only while that core sleeps (`VIRTQ_AVAIL_F_NO_INTERRUPT` otherwise, with a
  re-check after enabling, the CPU's own interrupts masked until the wait), so a flood is polled without interrupts.
  The poll stays as the fallback: no MSI-X, no MSI target, a refused vector, an ITS that cannot be set up, an interrupt
  that never arrives (noticed after 8 frames that waited), or `[devices] virtio_net_interrupt = "off"` (new key,
  configuration format 11; `"auto"`, the default, writes nothing). Boot line `net: receive wake-up: ...`; the
  dispatcher's statistics count receive interrupts. Smoke group `net_irq`.
- `docs/PERFORMANCE.md` §13: urMQTT v0.4.2, `main` (SACK, ADR-265/266) and Mosquitto 2.0.21 measured on two VPSes
  (Contabo x86_64 4 vCPU, netcup arm64 2 vCPU), each loaded from the other; raw files, tables and figures in
  `docs/perf-results/x11-2026-11-07/`, figures from the new `scripts/x11-charts.py`. Findings: with cores to use
  urMQTT leads 2-3x on connections, throughput, fan-out and latency and holds 20,000 idle mTLS connections in 18 MB
  where Mosquitto's process takes 546 MB; one 64 B flow is now ahead of Mosquitto's on x86_64; on one ARM core
  Mosquitto keeps QoS 0 throughput and the SACK build is behind v0.4.2 on QoS 1 (ROADMAP NOW-13).
- A second stateful ACL fuzzer, coverage-guided (H5 addendum): the cargo-fuzz target `broker_acl` with 18 seeds and
  the proptest `acl_invariants` in `cargo test` share an oracle written apart from `acl.rs` and from `acl_model.rs`. It
  checks what a SUBACK grants, the restore, remote-route and revocation entry points, the retained and in-flight
  bounds, RETAIN and `session_present`, and that `$urmqtt/` and `$SYS/` stay closed when the patterns grant them. No
  ACL bug found (docs/VERIFICATION.md, docs/PROGRESS.md).

### Changed

- **Behaviour change: 3.1.1 persistent sessions expire** (ROADMAP NEXT-4, ADR-274). A session with
  `clean_session = 0` used to be kept forever while offline; it now has the Session Expiry Interval
  `limits.default_session_expiry_s` (30 days by default, at most `limits.max_session_expiry_s`; 4 294 967 295 means
  never). Offline longer than that, the session is deleted with its subscriptions and queued messages, also when
  the time ran out while the broker was down (dropped at the next boot, logged per shard). A device that sleeps
  longer than 30 days comes back to an empty session: raise the two keys before updating if your fleet needs that.
- **Database schema 5** (ADR-275): `subscriptions.sub_id` (`INTEGER NOT NULL DEFAULT 0`, 0..=268 435 455, 0 = no
  Subscription Identifier), added in the migration's transaction (no table is rebuilt); a schema 4 database is
  migrated when the kernel or `urmqtt-disk` opens it, and a power cut at any write of the migration leaves schema 4
  or 5 with every row (golden files `schema4-mqtt5` frozen, `schema5-shared` new). A kernel before this one refuses
  a schema 5 database.
- **Database schema 4** (ADR-274): `sessions.expiry_s` and `sessions.offline_since`, `subscriptions.options`,
  `retained` and `queued` gain `props` and `expires_at`. Columns are added in the migration's transaction (no table
  is rebuilt); a schema 3 database is migrated when the kernel or `urmqtt-disk` opens it, and a power cut at any
  write of the migration leaves schema 3 or 4 with every row (golden files `schema3-qos2` frozen, `schema4-mqtt5`
  new). A kernel before this one refuses a schema 4 database (newer than this build).
- **Database schema 3** (ADR-271): `retained`, `subscriptions` and `queued` accept QoS 2 (the tables are rebuilt with
  every row in the migration's transaction), a queued message records the packet id it was in flight with, and
  `qos2_ids` holds the ids of unfinished QoS 2 flows. A schema 2 database is migrated when the kernel or
  `urmqtt-disk` opens it; a power cut during the migration leaves schema 2 or 3. **A kernel before this one refuses a
  schema 3 database** (and a backup snapshot taken by it): keep the previous image's data disk only if you will not
  go back. docs/DISK-FORMAT.md section 5.1.1.
- An unacknowledged QoS 1 message of an offline persistent session now comes back after a restart with its packet id
  and DUP set (4.4), not as a new message with a new id.
- **Plaintext password hashes: 100 000 PBKDF2 iterations by default** (was 10 000) in `urmqtt-config hash-password`
  and the builder page (ADR-267). Existing hashes carry their own count and keep working; hash again to get the new
  cost. The range stays 1000 to 200 000, below OWASP's 600 000 on purpose: the broker checks a password in one go on a
  data core for every login (about 25 ms per login under HVF, an estimated 50 ms on a VPS vCPU). Argon2 (ROADMAP D-16):
  not now, reasons in ADR-267.
- The plaintext login admission no longer admits at least 20 password logins a second per data core: above 25 ms per
  check that floor gave logins more than half a core. The floor is 1; admitted checks use at most half of each core.
  The boot log warns when one check costs more than the watchdog's handshake budget.

- The status word is **alpha** (README badge and banner, SECURITY.md, KNOWN-ISSUES.md, FIRST-HOUR.md): the three
  conditions of the ROADMAP's definition of "alpha" (release signing key, entropy option, MTU honoured) are in v0.4.2.
- TCP's sending side recovers from the peer's SACK blocks (RFC 6675 scoreboard, at most 8 ranges per connection,
  lost holes resent once each, paced by the pipe; a reordering window that grows with D-SACK reports); every second
  in-order segment is acknowledged when it arrives instead of once per pass; the congestion window grows only while
  it is used and a fast retransmit cuts it to 70 % (ADR-265). Peers without SACK get NewReno as before. On the local
  rig a single 1 KiB subscriber stream delivers 7.0k instead of 4.3k messages/s without loss and 0 to 27 % more under
  0.1 to 1 % loss; not yet measured on a VPS.
- virtio-net asks for 1024 receive and transmit descriptors and uses what the device offers (QEMU's default stays
  256); the boot log names the sizes, the `stalls:` line reports a receive queue three quarters full, and each data
  core logs its busiest TCP sender every 5 s under traffic (ADR-266). New tools: `scripts/x11-capture.sh`,
  `scripts/pcap-flows.py`, `SS=1` for `x11-bench.sh`, `QEMU_NIC_PROPS` for `run-qemu.sh`.
- A virtqueue's two driver-private tables (free-list next-pointers, chain lengths) live in the queue's DMA memory
  after the used ring instead of inline in `SplitQueue`: with `MAX_QUEUE` at 1024 the struct had grown to 4 KiB and a
  driver building three queues at probe time overflowed the 128 KiB main stack (aarch64, virtio-balloon, found by
  the `virtio-devices` smoke on CI right after ADR-266 landed). A test keeps the struct under 128 bytes.
- `scripts/smoke.sh`: the plaintext and `attack-app` scenarios wait for the DHCP lease before their clients start.
  `URMQTT READY` and the listener line come some 60 ms before the lease; a SYN in between is dropped and a client
  that does not retry sees no CONNACK (two CI runs on 2026-11-07, `plaintext-registry` and `plaintext-lockout`).
- CI's smoke jobs install paho-mqtt 2.1.0 from a hashed requirements file (`scripts/ci-requirements.txt`, a wheel
  with its SHA-256, `--require-hashes --only-binary`) into a virtual environment, instead of Ubuntu's 1.6.1 package;
  the QoS 2, WebSocket and MQTT 5.0 scenarios run on the same client library locally and in CI.

### Fixed

- A connection the broker itself closed (keep alive timeout, a protocol error, a takeover) published its Will only
  when TCP was done with the connection, which a client that never closes its socket drags out to the FIN_WAIT2
  timeout: the Eclipse Paho suite's `test_keepalive` (3.1.1 and 5.0) and `test_will_message` failed. The session now
  ends as soon as its last bytes are handed to TCP (ADR-274).
- The smoke scenario `watchdog-handshake` failed on x86_64 under TCG whenever the host was busy (main and branches
  alike, about half the runs): its self-test spun a fixed elapsed time, and the late ticks of a descheduled vCPU are
  credited as stalls (ADR-221), so the spin never reached the budget in running time. It now spins its length in
  running time as the watchdog counts it (bounded at 20 times that elapsed); 10 of 10 with and without host load.
- `$SYS/query/info` could report `clients.connected` 0 to an operator that had just reconnected: the answer used
  the counters each shard reports once a second. The answering shard (the asker's home) now refreshes its own first.
- The receive interrupt (ADR-270) is verified before it is trusted: it starts on probation (armed, with a 1 ms poll
  deadline while connections exist) until three frames have woken core 0 by it (`net: receive interrupt verified`),
  and falls back to polling after 8 frames that waited without it, before the verification or among any 32 later;
  a delivery that works only sometimes no longer escapes the fallback. The dispatcher's statistics count armed sleeps
  and misses. The CI failure of `attack-app [tcg]` (Ubuntu's QEMU 8.2.2) was not the interrupt: the scenario's
  slowloris opened its connections one at a time, and QEMU's user network under TCG accepted them only as fast as
  its main loop ran; `urmqtt-attack slowloris` now connects from 32 threads (ADR-270 amendment).
- A retained message replayed for a new subscription while the session's in-flight window was full was sent from
  the queue with RETAIN 0 (QoS 1, since M9; MQTT 3.1.1 3.3.1.3 requires 1). It keeps RETAIN now, also when it is sent
  again after a reconnect. Found by the `broker_acl` fuzzer's new QoS 2 checks (ADR-271).
- **QoS 1 on one data core was 10-30 % slower than v0.4.2 since ADR-265** (PERFORMANCE §13.3 point 4): the SACK loss
  detection counted "more than two segments above a hole" in full 1448-byte segments, which an MQTT flow of
  100-byte messages with a few of them in flight seldom reached, and no longer acted on three duplicate ACKs, so its
  losses waited for the retransmission timer (200 ms or more) and restarted from a one-segment window. It now counts
  the flow's own segment size and three duplicate ACKs with new SACK blocks start a recovery, as RFC 6675 has it
  (ADR-268). A new per-core log line says how the retransmissions came about (`tcp: core N: retransmissions: R
  recoveries started, T by the timer, S segment(s) resent in recoveries`); the "timeouts" of the existing line are
  connections given up, which hid the timer. On the local rig with one data core and 1 % loss, 16 x 1000 QoS 1
  messages/s deliver 13.4k/s again (v0.4.2 13.0k, before the fix 9.0k); with three data cores QoS 1 is the same or up to 8 % better without loss and 23-46 % better at 1 % loss.

## [0.4.2] - 2026-11-06

The **first release signed with the project's release key** (`minisign.pub`, key id `721316B961DCB94B`; the former
test key `9229E05252D01F8E` signed v0.1.0 to v0.4.1 and is accepted for those tags only, each pinned to its published
`SHA256SUMS`), and the first whose assets carry **no throwaway certificates**: the release kernel, the universal ISO
and raw image with an empty configuration, the template, the SBOM (`make dist ENV=release`). With it: the MTU the
network announces is honoured (ADR-264), the CPU-jitter entropy fallback is an explicit, visible choice (ADR-263), a
production PKI script (`scripts/pki.sh`), and the community documents (FIRST-HOUR, KNOWN-ISSUES, EDITIONS, issue
forms, DCO).

**Compatibility.** The kernel reads configuration formats 1 to 7 and the template declares **format 7**. Only the new
key `network.mtu` (not 0) needs format 7; every other configuration keeps the format it had, so whatever packed into
the v0.4.0 or v0.4.1 template still packs into those and into v0.4.2's, and a configuration with `network.mtu` is
refused by the v0.4.1 and older templates with "needs configuration format 7 ... use a newer release" (checked on the
published v0.4.0 and v0.4.1 templates and the locally built v0.4.2 template, docs/PROGRESS.md "Release candidate
v0.4.2"). The builder page was rebuilt for format 7 and both keys and deployed before this release; a page of v0.4.1
would grey out the v0.4.2 template. The data-disk layout is unchanged (v2.1). The asset names change:
`urmqtt-<tag>.elf/.iso/.img/.cdx.json` instead of `urmqtt-dev-<tag>.*`; the template keeps its name
(`urmqtt-template-<tag>-universal.iso`) and `urmqtt-<tag>.iso` is the same bytes. The trusted comment of `SHA256SUMS`
is `urMQTT <tag> release <commit>` (was `urMQTT <tag> dev <commit>`). The cipher suites, key-exchange groups and
signature schemes offered are unchanged.

**Limits, stated plainly.** Still pre-alpha. The three items of the ROADMAP's definition of "alpha" (a real release
key, NOW-2; the entropy decision, NOW-4; the MTU, NOW-19) are on `main` and in this release, but NOW-2's last check is
this release itself (verified with the new key on the builder page and the mirror after publishing) and the status
word changes only when the owner changes it. The release key's secret is passwordless because CI signs with it; its
protection is GitHub's secret store and the owner's own copies (docs/release-key-rotation.md). The MTU change ran under QEMU only (smoke group
`net_mtu`; QEMU's user network cannot announce an MTU, so DHCP option 26 was tested with urmqtt-attack's raw transport);
**nothing has run on Google Cloud**, the network it was made for. The virtio-console, -balloon, -input and -vsock
drivers (v0.4.0) have still run only under QEMU, never on a real machine, and vsock only against the fake device of the
tests. The real machines remain one netcup ARM64 VPS and, for x86_64, a Contabo KVM VPS at the H7 commit; nothing of
this release ran on either, and nothing on physical hardware. The x86_64 unit tests and the x86_64 and universal-ISO
smoke suites are not in CI. The new builder texts (entropy choice, test-key note, MTU range) are AI translations,
unreviewed. The rest of v0.4.1's limits is unchanged (the AArch64 X25519 assembly unreviewed, PSTATE.DIT never set,
Secure Boot partial, no IOMMU, encryption at rest not on the page, the audit a self-review).

### Fixed

- **The MTU was assumed to be 1500 bytes** (every release to v0.4.1): on a network with a smaller MTU full-sized TCP
  segments were lost without an error. Now the MTU comes from DHCP option 26 or `network.mtu` (Added, ADR-264).
- **Miri cfg skips the PBKDF2 tests it was meant to skip**: seven skip patterns read `passwd::<name>` while the tests are
  `passwd::tests::<name>`, so they never matched and those seven tests were most of the job; 34 of 47 tests now run under
  Miri (41 before), the seven run natively in `cargo test`.

### Changed

- **Releases ship the release environment only** (NOW-2). `make dist ENV=release`, which the Release workflow now
  runs, publishes `urmqtt-<tag>.elf` (the aarch64 release kernel), `urmqtt-<tag>.iso` (the universal ISO with the empty
  configuration, byte for byte the template), `urmqtt-<tag>.img` (its raw disk image, configurable with
  `urmqtt-config pack --image`), `urmqtt-template-<tag>-universal.iso` (as before), `urmqtt-<tag>.cdx.json`,
  `SHA256SUMS` and its signature. The dev build with throwaway certificates (`urmqtt-dev-<tag>.*`) is no longer a
  release asset; v0.4.1 and older keep theirs. The trusted comment is `urMQTT <tag> release <commit>`. The workflow
  refuses to start without the release key and the signing secret, checks the asset set and that no asset holds a PEM
  private key, and verifies the signature with `minisign.pub`. `make repro ENV=release` builds the release assets twice
  (no `deploy/` needed). `make dist` with any other ENV is unchanged (an operator's own image).
- **Release key rotation** (NOW-2). `minisign.pub` is the project's release key `721316B961DCB94B` (generated
  2026-11-06; its secret is in the repository secret `MINISIGN_SECRET_KEY` and kept outside every repository); v0.4.2 is the
  first release it signs. The former test key `9229E05252D01F8E` is `keys/minisign-test-9229E05252D01F8E.pub`, trusted
  for v0.1.0 to v0.4.1 only (`keys/release-keys.json`). The builder page verifies each release with the key its
  signature names, refuses unknown keys and keys outside their range, and marks the old releases "signed with the
  project's former test key" (the new texts in 14 languages are AI translations). The release mirror takes
  `--keyring` (`releases.json` gains `keys` and a per-release `signed_by`); `urmqtt-config check-release` takes several
  `--pubkey`, or `--keyring keys/release-keys.json --tag TAG`. `scripts/check-release-key.sh` guards the Release
  workflow, `make sign`, the mirror installer and the page deploy (SECURITY.md, "Release signing keys";
  docs/release-key-rotation.md).

- README: a "Start here" line (first hour, known issues, editions, security policy); the title, badges, WARNING
  banner, "Why urMQTT" table, Features Build row and M11 row brought in line with ROADMAP section 6; rows for O1 to
  O4, T1, C1, P1 and D1 (built, not deployed); the order list names 11b to 11e and the first-release scope. The status
  word stays "pre-alpha".
- **Miri in CI runs one process per test, four at a time** (cargo-nextest, `scripts/miri.sh`, ADR-262), instead of
  each crate's tests one after another on one core. The same tests run; two tls tests run a smaller size under Miri only
  (`MAX_CAPTURED` 64 instead of 4096 for the capture-table eviction test, 40 instead of 400 corruptions per certificate
  for the serial reader test; `cargo test` keeps the full size). `MIRI_RUNNER=libtest` keeps the old runner.
- **A Miri job whose inputs match an earlier green run reports "cached"** (`scripts/miri-cache-key.sh`: the crates and
  their path dependencies, `Cargo.lock`, the toolchain, Miri and nextest versions, the flags and the scripts). Only a green
  run is recorded; `workflow_dispatch` with `miri-cache` off runs Miri in full.

### Added

- **`scripts/pki.sh` and docs/PKI.md: a production PKI** (NOW-3): an offline operational CA (ECDSA P-256,
  passphrase-protected), the server certificate (DNS and IP names), device and service certificates with the identity
  as CN and SAN URI, certificates from a device's own CSR, server and CA rotation, the revocation list and the control
  key pair; `pki.sh check DIR` runs `urmqtt-config pack`'s checks on a deploy directory. Tested by
  `scripts/test-pki.sh` (`make pki-test`).

- **The weak entropy path is an explicit option, loud wherever a user decides** (NOW-4, D-3, ADR-263). The default stays
  `entropy.fallback = "jitter"` (a host with no virtio-rng and no `RNDR`/`RDRAND`, such as the netcup ARM VPS, still boots).
  The builder's basic view has a "Random numbers" choice (allow the CPU-jitter fallback, or require a hardware random number
  generator) with a warning, the result card names the one built and the notes list "Random numbers may come from CPU jitter"
  (14 translations, AI, unreviewed); `urmqtt-config pack`, `verify` and `show` print a `WARNING` line while the fallback is
  allowed; `$SYS/broker/entropy/source` (also in the info reply and `status`) says what seeded the generator (`virtio-rng`,
  `rndr`, `virtio-rng+rndr`, `jitter+firmware`); with `"none"` the refusal at boot names the key. Smoke scenario
  `entropy_option`; docs/DEPLOY.md "Entropy".
- **docs/FIRST-HOUR.md**: from nothing to a first message over mutual TLS in about an hour (test PKI, the builder
  page or `urmqtt-config pack`, QEMU for aarch64 and x86_64 with the ISO and an empty disk, a KVM VPS as on netcup,
  `mosquitto_pub`/`mosquitto_sub` and the `$SYS` topics, the five most likely failures with their log lines), with
  what was run for it: the v0.4.1 template under HVF (aarch64) and TCG (x86_64) on a Mac.
- **docs/KNOWN-ISSUES.md**: the limits and open weaknesses that affect a user (AUDIT.md sections 5 and 6, the
  v0.4.0 and v0.4.1 "Limits", protocol, network, platform and entropy limits), each with a workaround and its
  tracking reference. `scripts/check-known-issues.py`, run in the Lint job, fails when a cited AUDIT id, ROADMAP item
  or ADR does not exist or a cited AUDIT weakness is marked fixed.
- **Issue forms** `bug`, `boot-failure` and `question` (replacing `bug_report`), blank issues off, the contact links
  to the private advisory and SECURITY.md; `scripts/check-issue-forms.py` checks the forms against GitHub's rules.
  The pull request template names the DCO sign-off, `make check` and the edition rule for drivers that are not virtio.
- ROADMAP "Community readiness" and the definition of "alpha" (a real release key, NOW-2; the entropy decision,
  NOW-4; the MTU, NOW-19).
- **docs/EDITIONS.md**: the open edition (this repository, everything that runs on virtio devices) and the commercial
  edition (drivers for devices that are not virtio, bare metal, support), the promise that the line never moves backwards,
  contribution and licensing rules; README "Editions", ROADMAP NOW-18 (kernel as a library) and Google Cloud as the next
  real-machine target.
- **Developer Certificate of Origin**: every commit of a pull request must carry a `Signed-off-by:` trailer (`git commit -s`,
  CONTRIBUTING.md); the Lint job checks the pull request's commits.
- **The network's MTU is honoured** (ROADMAP NOW-19, ADR-264). Every packet was sized for 1500 bytes, so on a smaller
  network (Google Cloud's VPC: 1460) the full-sized TCP segments were lost without an error. The DHCP client now asks
  for and reads option 26 (Interface MTU; 576 to 9000 is used, another value is ignored with a warning), and the new
  optional key **`network.mtu`** (0 or 576 to 9000; default 0: from DHCP, else 1500; with a static address the only
  source) sets it; it is configuration format 7, and a configuration without it keeps its format. The MSS we announce
  and use is MTU minus 40 (at most 1460, the smaller of ours and the peer's), open connections follow a lower MTU at a
  DHCP renewal, UDP datagrams (statsd) stay within it, an ICMP echo reply that would not fit is not sent, and frames
  above 1500 bytes are never sent. Boot line `net: mtu 1460 (static|dhcp|default)`, `$SYS/broker/net/mtu`, the
  info query's `net.mtu`; the builder page's advanced view has the key (its range text in 15 languages, AI
  translations, unreviewed). Smoke group `net_mtu`: a static 1460 configuration (4 KiB QoS 1 round trip over mutual
  TLS, no guest frame above 1474 bytes, SYN-ACK MSS 1420) and DHCP announcing 1460, 9000 and 300 (urmqtt-attack's
  raw transport, new mode `mtu-probe`; QEMU's user network cannot announce an MTU).
- **A Miri negative control**: `scripts/miri.sh --negative-control` runs a deliberate use-after-free (compiled only under
  Miri, `#[ignore]`d, in urmqtt-config) and fails unless Miri reports it; every CI Miri job runs it.

### Security

- **The release key rotation** (NOW-2, above). What a user does: fetch `minisign.pub` **at the tag**
  (`https://raw.githubusercontent.com/zeljan-alduk/urMQTT/v0.4.2/minisign.pub`) and check that it names
  `721316B961DCB94B`; verify v0.4.1 and older with `keys/minisign-test-9229E05252D01F8E.pub`. The test key is
  **retired and considered compromised** (its secret was a passwordless CI secret): any signature by it on a tag after
  v0.4.1 is a forgery. The builder page, the mirror and `urmqtt-config check-release --keyring` accept it only for
  v0.1.0 to v0.4.1, and for each of those six tags only the `SHA256SUMS` whose SHA-256 is pinned in
  `keys/release-keys.json`, so the test key cannot sign a different `SHA256SUMS` for an old tag either. Pinning covers
  `SHA256SUMS` and the files it lists, nothing else.
- **No published asset holds a private key any more**: the dev images with throwaway certificates are gone from the
  release, and the workflow refuses an asset with a PEM private key (`scripts/check-no-pem-keys.py`).
- **Entropy** (ADR-263): the default stays `entropy.fallback = "jitter"` (D-3, the owner's decision), but the choice
  is explicit in the builder's basic view, `urmqtt-config` prints a `WARNING` while the fallback is allowed, and
  `$SYS/broker/entropy/source` says what seeded the generator; `"none"` makes an image refuse to boot without a
  hardware source.
- **The MTU** (ADR-264): an announced MTU outside 576 to 9000 is ignored with a warning, frames above 1500 bytes are
  never sent, and an ICMP echo reply that would not fit is dropped rather than sent.
- New `unsafe`: one more `#[unsafe(no_mangle)]` export of the builder's WebAssembly module (`ub_minisig_key_id`, to
  read a signature's key id), and the Miri negative control's deliberate use-after-free in urmqtt-config, compiled only
  under Miri and `#[ignore]`d (docs/audit/unsafe.md).

## [0.4.1] - 2026-11-05

A release of a **TCP fix that applies to every earlier release** (after the broker closes a connection whose device keeps
its side open and acknowledges every segment, the broker sent a new FIN on every ACK at line rate and never released the
connection: ADR-261, AUDIT.md A261-W1, present since M14), and of the TLS handshake work after v0.4.0 (ADR-259): the
trust anchors' verification tables, which were never built, X25519 on AArch64 in `mul`/`umulh` inline assembly, and a
faster P-256 verification on both architectures. On
the netcup Neoverse N1 VPS the server's CPU per mutual-TLS handshake was 461 us against 553 us with the P-256
assembly of ADR-255 alone, one run each (PERFORMANCE.md section 12.1).

**Compatibility.** No configuration format change: the kernel reads formats 1 to 6 and the template declares format 6,
as in v0.4.0, so everything v0.4.0's template takes, v0.4.1's takes, and the builder page of v0.4.0 offers this release
without a redeploy (`tools/builder`, `crates/cfg`, `crates/config`, `crates/config-schema` and `tools/config` are
unchanged since v0.4.0). The data-disk layout is unchanged (v2.1). The boot line `crypto:` gains `x25519=<ladder>`;
the cipher suites, key-exchange groups and signature schemes offered are unchanged.

**Limits, stated plainly.** The signing key is still a test key, and the release assets are **dev** builds with
throwaway certificates, for evaluation (as for v0.4.0); production images are built by the operator (docs/DEPLOY.md).
The AArch64 X25519 assembly is new code written for this project (not vendored from an upstream like the nistz256
assembly); it is tested against RFC 7748 and against dalek, and the timing records in the repository are from Docker on an
Apple M4 Pro only; it has had no independent review and needs a human review. PSTATE.DIT is still never set (AUDIT.md
A255-W2), which now covers the X25519 field arithmetic on the secret scalar too. The P-256 verification change is shared
code, so it runs on x86_64 as well: x86_64 is built and its kernel checked by clippy, but its unit tests run nowhere
(CI's host tests run on arm64 Linux and macOS) and nothing of this release ran on an x86_64 KVM guest; the x86_64 and
universal-ISO smoke suites are not in CI (PROGRESS, "Release candidate v0.4.1", says what was run locally). The
Neoverse N1 figures are from one netcup VPS, one run each, with a shared load host and a CPU clock that differed between
the runs (2.58 and 2.89 GHz); the per-stage profile is from Docker on an Apple M4 Pro, not the target CPU. The rest of
v0.4.0's limits is unchanged.

### Fixed
- **TCP: a FIN sent again on every acknowledgement in FIN-WAIT-2** (since M14; v0.1.0 to v0.4.0 have it; ADR-261,
  AUDIT.md A261-W1). After the broker closed a connection whose device kept its side open and acknowledged each
  segment (QEMU's user-mode network does), every ACK of the FIN brought a new FIN one sequence number further, at
  line rate, and the FIN-WAIT-2 timer that should end the connection after 60 s was replaced each time. It held core 0
  at 100 % in the `storm` smoke and made it hang. Now the FIN goes out once (and again only as a retransmission).
- **The trust-anchor tables take 148 KiB each instead of a 256 KiB heap block**, are built once at boot before the heap
  reserve is measured, and are logged (`tls: N trust-anchor verification table(s), K KiB of heap`); DEPLOY.md counts
  about 150 KiB per P-256 anchor in the heap sizing (ADR-261, A259-W2).
- `urmqtt-loadgen storm` cannot hang any more: `--io-timeout-s` (default 10) for every step of an attempt, the
  `--retry-s` deadline per attempt, and a round that is still busy past it fails with an error; `smoke.sh` bounds it
  at 15 minutes.
- **The trust anchors' verification tables were never built** (ADR-111, ADR-259, AUDIT.md A259-W1): webpki stores an
  anchor's SubjectPublicKeyInfo without its outer SEQUENCE, which `register_issuer` did not parse, so a device's
  first handshake verified its certificate on the slower unknown-key path. Both forms are accepted now. No effect on
  verdicts; about 20 us less for a first contact (Docker linux/arm64 on an Apple M4 Pro).
- docs/release-day-v0.4.0.md: the template check needs a configuration a release template accepts (not
  `deploy/dev/config.toml`), and a dev ELF cannot be reproduced on another machine (its certificates are generated
  per machine); reproducibility is `make repro ENV=prod`.

### Changed
- **X25519 on AArch64**: the shared secret uses `urmqtt-x25519` with new `mul`/`umulh` inline assembly
  (`Backend::Armv8`, ADR-259) instead of dalek's 51-bit ladder; 14.6 us against 20.3 us in the profile (Docker on an
  M4 Pro, not measured on a server core). The boot line reads `crypto: ecc=... x25519=armv8|adx|portable (...)`.
- **P-256 verification** (both architectures): a width-5 NAF for the key's multiple and a variable-time scalar
  inversion (public inputs only; signing and ECDH stay constant time): unknown key 29.0 -> 24.5 us, by a CA table
  9.8 -> 7.2 us (Docker on an M4 Pro).
- Server CPU per full mutual-TLS handshake, measured stage by stage (Docker on an M4 Pro, PERFORMANCE.md section
  12): returning device 88.8 -> 80.3 us, first contact 118.6 -> 87.8 us. Nothing was measured on the Neoverse N1.
- **Measured on the netcup Neoverse N1 VPS** (PERFORMANCE.md section 12.1, one run each, shared hosts): the server's
  CPU per handshake 461 us (553 us with the assembly alone, about 1.0 to 1.08 ms with the portable code; the CPU clock
  differed between the runs); X25519 128 us, ECDSA verify 124 us; full mTLS handshakes per second 1,451 / 1,624 / 1,599
  at 32 / 64 / 128 threads against 1,317 / 1,398 / 1,316 with the assembly alone and 848 / 827 / 778 with the portable
  code (0 errors).

### Added
- Smoke scenario `fin_wait2`: devices that keep their side open after a keep-alive timeout are released by
  FIN-WAIT-2 while they still hold their sockets (ADR-261).
- `stage-profile` feature and `handshake_profile` example of `urmqtt-tls` (host only): the server's handshake time
  per stage. `make ct` case `x25519_ladder_is_constant_time`; the RFC 7748 million-iteration vector (ignored test).
- ADR-260: a proposal, not built, for a cache of verified client certificates (it would save about 1 us per
  returning device's full handshake on top of the existing memo; recommended against).

### Security
- A259-W1 (above) is closed; it never changed a verdict.
- New `unsafe`: the five AArch64 X25519 inline-assembly blocks (register-only, `options(pure, nomem, nostack)`, each
  with a `// SAFETY:` comment; AUDIT.md, docs/audit/unsafe.md). They handle the secret scalar: `make ct` gains
  `x25519_ladder_is_constant_time` (|t| 1.0 to 4.7 in six runs against the bound of 7, Docker on an M4 Pro only;
  CRYPTO.md). Not measured on a server core, and without PSTATE.DIT (A255-W2, open).
- P-256 verification is variable time by design (a width-5 NAF and a variable-time inversion of `s`): its inputs (the
  message digest, the signature, the public key) are public. Signing and ECDH keep the constant-time paths.

## [0.4.0] - 2026-11-04

A release of what was built after v0.3.0: optional virtio drivers for the consoles and devices that VPS providers
attach (a virtio-gpu console, virtio-console, -balloon, -input and -vsock) behind one driver framework, P-256 on
the ARMv8 assembly, the Diagnostic entry's measurements over the network, and the first records of a real aarch64
KVM guest. Its main purpose: the builder page only offers published templates, and v0.3.0's template reads
configuration format 4, so the new keys (`console.virtio_gpu`, `[devices]`) can be used from the page only with a
release whose template reads format 6.

**Compatibility.** Nothing here breaks an existing image or disk. The kernel reads configuration formats 1 to 6. The
packer still writes the lowest format that can hold the configuration, so an image whose new keys are all `"off"`
(the default) is written in format 2, 3 or 4 exactly as before and boots on the kernels that boot it today (2:
v0.2.0 or newer, 3: v0.2.1 or newer, 4: v0.3.0 or newer). A configuration with `console.virtio_gpu` not "off" is
format 5, one with any `[devices]` key not "off" is format 6; only a v0.4.0 kernel reads them, an older kernel
refuses them at boot by the version, and `urmqtt-config pack --iso` (and the builder page) refuses to write them into
an older template, naming the reason ("use a newer release"). Format 5 was never in a release; a v0.4.0 template
declares format 6. The data-disk layout is unchanged (v2.1). The golden blobs of formats 1 and 2 are unchanged and
still valid; the builder page must be redeployed before the mirror lists this release (docs/RELEASE.md section 4).

**Limits, stated plainly.** The signing key is still a test key, and the release assets are **dev** builds with
throwaway certificates, for evaluation (as for v0.3.0); production images are built by the operator
(docs/DEPLOY.md). The only real-machine results are one netcup VPS 500 ARM G12.5 (Neoverse N1, 2 vCPU, aarch64 KVM)
and, for x86_64, the Contabo run at the H7 commit (PERFORMANCE.md 3 and 7). On the netcup machine the Diagnostic
entry, the measurements and load runs below, and the virtio-gpu console were run; install, boot from the installed disk and a retained message that survived a power cut are recorded in PROGRESS and PERFORMANCE (one run each). That machine has no virtio-rng and no `RNDR`: its generator was seeded from the
CPU-jitter fallback and the bootloader's EFI RNG only, the weakest seeding the kernel accepts (ADR-038). The P-256 speed-up of ADR-255 was measured on the Neoverse N1 once (and on an Apple M4 Pro). The virtio-console, -balloon, -input and
-vsock drivers have not run on a real VPS; vsock has run only against the fake device of the tests (it needs
vhost-vsock on a Linux host). The x86_64 and universal-ISO smoke suites are not in CI; for this release only the
x86_64 `virtio_gpu` and `virtio_devices` groups were run, under QEMU TCG on the Mac (PROGRESS, "Release candidate
v0.4.0"), not the full x86_64 or universal suites and nothing on KVM; the code after H7 (disk encryption, boot integrity, everything in this release) has not run
on an x86_64 KVM guest or on physical hardware. Secure Boot, IOMMU and the rest of v0.3.0's limits are unchanged.

### Added

- **A virtio driver framework** (ADR-257): every driver of `crates/virtio` behind its own Cargo feature, the umbrellas
  `vps` (the MQTT image's set) and `all`; the kernel's default is `virtio-vps` (`make build VIRTIO=all` for every
  driver). One table (`registry::KINDS` and the kernel's `vdev::DRIVERS`, kept in step by a build-time check); every
  virtio device found is listed in the boot log (`virtio: <name> at <bdf>: <state>`) and in the Diagnostic report's
  new `virtio` list, also those without a driver (`no driver in this image`). A `[devices]` section with one
  `"off" | "auto" | "on"` key per optional driver, all off by default: configuration **format 6** only when a key is
  not "off". `urmqtt-config pack --iso`/`--image`/`--kernel` refuses a key for a driver the image's kernel lacks (the
  kernel carries a `URMQTT-VIRTIO-DRIVERS:` marker); the boot warns where that could not be checked.
  docs/DEVELOPING-DRIVERS.md is the checklist for the next driver.
- **virtio-console, virtio-balloon, virtio-input and virtio-vsock drivers** (ADR-258), each off unless configured:
  the log on a virtio-console's port 0 and the Diagnostic prompts' keys from it; memory statistics for the host from
  a balloon that never inflates (fixed heap; a host request is logged and refused); virtio keyboards for "press any
  key" and `WIPE` from a provider's VNC console; the Diagnostic report, read-only, on vsock port 2883. Fuzz targets
  `virtio_console_device`, `virtio_balloon_device`, `virtio_input_event`, `virtio_vsock_packet`; smoke
  `virtio_devices` (QEMU HVF: console, balloon with QMP statistics, `WIPE` typed as QMP key events and on the
  console). **vsock is untested against a real device** (needs vhost-vsock on a Linux host); none of the four has
  run on a real VPS yet. The release kernels grow by about 80 KiB (aarch64, 2.3 %) and 67 KiB (x86_64, 1.9 %).
- **A virtio-gpu (2D) console, optional and off by default** (ADR-256, NOW-6): `[console] virtio_gpu = "off" |
  "auto" | "on"`. For VMs whose firmware display goes dark after boot (netcup ARM: "Display output is not active").
  The kernel gives the device a framebuffer of its own on scanout 0, moves the log's console onto it (the lines
  logged before are redrawn) and presents changes at most every 50 ms, and at once before a fatal stop, a panic, a
  power-off and after every Diagnostic dashboard redraw. "auto" takes the device when the boot framebuffer is
  missing or is RAM nothing shows; "on" whenever one is found. **Verified on a real machine:** netcup VPS 500 ARM
  G12.5, 1280x800, the Diagnostic dashboard visible live in the provider's Screen tab and the final "press any key"
  screen staying. Configuration format 5 when the key is not "off" (an "off" image stays format 2 and boots on older
  kernels); format 5 was never released on its own, a v0.4.0 template declares format 6. New fuzz target
  `virtio_gpu_response`; smoke `virtio_gpu` (QMP screendump checked); `run-qemu.sh --gpu virtio|virtio-vga`.
- **Configuration format 6** and the builder page for it: the page's WebAssembly module is `urmqtt-cfg6.wasm`; its
  advanced view offers `console.virtio_gpu` and the four `[devices]` keys. With a template of v0.2.0 to v0.3.0 the
  page and `urmqtt-config pack --iso` write every configuration that template's kernel reads and refuse the rest with
  the reason (new test `templates_of_earlier_releases_take_what_their_kernel_reads`).
- P-256 on aarch64 through OpenSSL's ARMv8 `nistz256` assembly (ADR-255), vendored from ring 0.17.14 like the
  x86_64 code (ADR-130): ECDSA sign and verify, ECDH, key generation and the trust-anchor tables. Boot line
  `crypto: ecc=nistz256-armv8`; the diagnostic screen's crypto line names the backend too. Measured in Docker on an
  Apple M4 Pro (not the target CPU), production paths, minimum of 11 runs: sign 34.7 -> 11.6 us, verify 147 -> 29 us,
  ECDH 135 -> 25 us, handshake estimate 292 -> 104 us (PERFORMANCE.md section 10). On the netcup Neoverse N1 VPS (PERFORMANCE.md section 11): full mTLS handshakes per second 848 -> 1317 at 32 threads, 827 -> 1398 at 64 and 778 -> 1316 at 128 (1.55 to 1.7x, 0 errors), the server's CPU per handshake 553 us (one run) against about 1.0 to 1.08 ms before; two vCPUs, so single-core broker figures. The vendored assembly uses integer registers only (upstream's two NEON selection
  functions are replaced by constant-time Rust) and starts every entry point with `bti c`. macOS, Miri and Kani keep
  the portable code.
- `make ct`: P-256 key generation, ECDH and signing (key and nonce) through the production paths (sparse fixed
  against random scalars), with a P-256-scale positive control (a variable-time double-and-add).
- `diag-serve` boot word: the Diagnostic entry's measurements (detection, RAM, crypto incl. AES-XTS, disk reads),
  then a normal live boot that serves MQTT with the report as the retained `$SYS/diag/report` (operator certificate).
  For machines whose console cannot be seen (written for the netcup ARM VPS before the virtio-gpu console existed;
  its serial port is not exposed). Use it with `mkiso.sh --diag-default --diag-cmdline diag-serve`.
- Diagnostic entry: the **CPU clock** (the PMU cycle counter, or the TSC rate on x86_64, measured against the time
  base; "not measurable" where only a fixed-rate timer is readable) and a **random number generator** panel: which
  sources seeded it (virtio-rng, RNDR or RDRAND/RDSEED, the bootloader's EFI RNG, the CPU-jitter fallback with its
  samples, credited bits and health tests), a sanity test of fresh bytes from each hardware source (share of ones,
  longest run; not a certification), the generator's throughput and a test of its output. `scripts/diag-check.py`
  checks the new keys.
- `tools/diag-png` (`urmqtt-diag-png`): draws that JSON (or the `URMQTT-DIAG-JSON` serial line) as the PNG of the
  dashboard, with the kernel's own `dash::draw` and framebuffer font, disks included.
- First measurement on a real aarch64 KVM guest (netcup VPS 500 ARM G12.5, Neoverse N1, 2 vCPU, before ADR-255):
  hardware AES-XTS 241 MiB/s per core, AES-GCM 314 MiB/s, ECDSA verify 508 us, sign 141 us, one mutual-TLS handshake
  1.08 ms; TLS 1.3 + mTLS, QoS 1 publish/subscribe, 500 held connections and three 1000-client reconnect storms ran
  over the Internet without an error.
- docs/ROADMAP.md: a proposal for the work after v0.3.0 (what is missing, why, effort, how each item would be
  verified). Nothing in it is decided.

### Changed

- The template ISO's empty configuration declares format 6 (`FORMAT_VERSION`), so the release mirror reports
  `config_format` 6 and a builder page built before this release greys the release out.
- `make clippy-kernel` also checks the kernel with `virtio-all` and with `--no-default-features`.
- The aldo.tech site patch (`tools/builder/site/apply_products.py`): Products goes first in the header and the footer
  wherever the site's own links sit.

### Fixed

- `urmqtt-diag-png` left the disks of the report out (the picture said "no disks found").
- The mm poison-on-free test looked at the obfuscated free-list header and failed about one run in eight.
- Tests: the P-256 timing cases retry (fail only if every attempt is over the bound); the ECDSA signing case signs a
  fresh random message per measurement in both classes (A255-W1: the signal on the arm64 runner came from the DER
  encoding of a repeated signature, not from the key) and its bound is 7 again; the install smoke patterns no longer
  depend on the image size; `virtio_devices` boots the x86_64-only ISO with the diag words on its one entry.
- CI: Miri runs as three parallel jobs (protocol crates, tls, cfg) with the development certificates and a 120 minute
  timeout, and skips the heavy P-256 table, known-answer and benchmark tests of `urmqtt-tls` (they run natively);
  Kani is a real gate (the documented NOT PROVEN harnesses are listed by name, any other failure fails); typos;
  `qemu-utils` for the discard scenario; three attempts and a 25 ms handler budget for the two slow-log watchdog
  scenarios on a slow TCG runner; the scheduled fuzz workflow makes the development certificates first (every target
  failed to build without them).
- docs/PROGRESS.md: the entries M0 to S6, lost when commit 85605d2 replaced the file, are restored from the history.

### Security

- A256-W1, fixed before merge: a virtio-gpu display-info response 4 bytes short of the structure was accepted (found
  by the new `virtio_gpu_response` fuzz target in its first minute; low, nothing past the buffer was read).
- A255-W1 closed: the ECDSA signing timing signal was the harness (see Fixed). A255-W2 stays open: PSTATE.DIT is never
  set, so Arm's data-independent-timing guarantee for the instructions the nistz256 assembly uses is not requested
  (docs/AUDIT.md).
- New device inputs, each with a fuzz target and AUDIT.md rows: virtio-gpu responses, virtio-console data, balloon
  requests, input events, vsock packets. All of them are off unless configured. The balloon never gives memory back;
  vsock serves only the read-only Diagnostic report.

## [0.3.0] - 2026-11-02

The first release with a runtime configuration, an optional plaintext listener, an x86_64 port, a storage track
(layout v2, growth, discard, in-disk backups, scrubbing, encryption at rest) and an audit package. It also covers
everything that was tagged as v0.2.0 and v0.2.1 without release notes (the template ISO and the builder page; TLS
off, configuration format 3).

**Compatibility.** Nothing here breaks an existing image or disk. A configuration blob of format 1, 2 or 3 is still
read, and format 4 is written only when disk encryption is switched on, so every other image still boots on a kernel
of v0.2.1. A layout-v2.0 data disk opens and is upgraded to v2.1 by one superblock write at boot (an older kernel then
refuses it). A layout-v1 disk is refused by the kernel and converted offline with `urmqtt-disk migrate`, as before.
The builder page picks the newest release whose template can do what the form asks.

**Limits, stated plainly.** The first supported target is a VPS or VM under KVM. The smoke suites run on aarch64 under Apple HVF and TCG and on x86_64 under QEMU TCG; **x86_64 has also been run on a real KVM VPS** (Contabo, 4 vCPU AMD EPYC: boot, mutual TLS under load and a comparison with Mosquitto, X11, at the H7 commit), but not the later code (disk encryption, boot integrity) and not on physical hardware. Secure Boot is only partly done (H8: the loaders'
configuration is enrolled and the signing path works under OVMF on x86_64, but release images are not signed and
no physical machine was tried), and there is no IOMMU. Encryption at rest is not on the builder page yet (use `urmqtt-config pack` with
`storage.encryption`). 53 of the 67 kernel-linked crates are `cargo-vet` exemptions, not audits. The release assets are
**dev** builds with throwaway keys, for evaluation; production images are built by the operator (docs/DEPLOY.md).

### Added

- **Runtime configuration (C1).** The kernel is built once; limits, ACLs, network, TLS certificate and key, trust anchors and control key are a versioned, canonical `urmqtt-cfg` blob in a 256 KiB slot that the bootloader hands to the kernel and that is re-validated at every boot (fail closed; a release kernel refuses development options). `urmqtt-config pack | show | verify | schema` builds the blob from a TOML and PEM files and writes it into a copy of the new `urmqtt-template-<version>-universal.iso`, published with every release, without a toolchain. The kernel prints the configuration fingerprint at every boot. ADR-215 to ADR-219.
- **The urMQTT builder (C1e, C1g).** A web page that does what `urmqtt-config pack --iso` does, in the browser: the tool compiled to WebAssembly (tested byte for byte against the command line), a simple and an advanced view, presets, TOML import and export, certificate and key import with checks, minisign and SHA-256 verification of the release against a key built into the page, 15 languages. Certificates and keys never leave the browser. "Try in the emulator" boots the image in QEMU compiled to WebAssembly (GPL-2.0, source offer). `scripts/mirror-releases.py` mirrors the GitHub releases to the site after verifying them. ADR-225 to ADR-228, ADR-232.
- **Optional plaintext MQTT for trusted networks (P1).** A `[plaintext]` section, off by default, opens TCP 1883 without TLS. `allow_from` is mandatory and enforced at the SYN; login by `password` (PBKDF2-HMAC-SHA-256), `anonymous` or `ip`; lock-out after failed logins; a narrow ACL, small packets and a low publish rate by default; never an operator, service or control right. Blob format 2. `network.mqtt_tls_port = 0` turns TLS off when plaintext is on (format 3, v0.2.1 or newer). See docs/SECURITY.md for what plaintext gives up. ADR-229 to ADR-231, ADR-233.
- **x86_64 (X2 to X10).** The same kernel boots and serves on x86_64 under QEMU TCG (UEFI and legacy BIOS): paging with NX/WP/SMEP/SMAP/UMIP, ACPI, x2APIC, SMP, PCI, virtio with MSI-X, RDSEED/RDRAND, hardware AES, PCLMULQDQ, SHA-NI and SSE4.2 CRC (X9). One universal ISO (`make universal`) boots on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS, installs itself on the machine's disk, and its installed disk boots by all three paths; data disks are portable between the architectures. **Not run on KVM or real hardware.**
- **Live mode (O3).** The ISO's first menu entry runs the broker from RAM with no disk (`storage.mode = "disk" | "auto" | "ram"`), loudly marked ephemeral.
- **Storage track (S2 to S8).** Layout v2 with aligned regions and an A/B superblock; `urmqtt-disk migrate` converts a v1 disk offline (ADR-140, ADR-141). The disk grows into a larger volume at boot and, on virtio-blk, while running (`urmqtt-disk grow`; ADR-142, ADR-143). Space is given back with DISCARD or UNMAP, only while idle (`storage.discard`; ADR-150, ADR-151). Two in-disk database backup slots written by SQLite's online backup API, automatic restore of a corrupt database at boot, `urmqtt-disk backup | backup-extract | backup-restore` (layout v2.1; ADR-160 to ADR-163). An idle scrubber checks the database, the backups and every telemetry record, and boot no longer reads the whole telemetry ring (`urmqtt-disk scrub`; ADR-164, ADR-165). Fuzz targets for the backup headers and encrypted disks, golden images for every layout version, and the data-disk format spec (docs/DISK-FORMAT.md).
- **Encryption at rest (S7), optional and off by default.** `storage.encryption = "aes-256-xts"` and `storage.disk_key` encrypt the data partition (hardware AES required; configuration format 4). `urmqtt-disk encrypt | decrypt | rekey` convert a disk offline and resume after a power cut; `--key FILE` opens an encrypted disk for every other command. Protects a stolen volume or snapshot, not a stolen ISO; XTS has no integrity. ADR-240.
- **SQLite as an unprivileged component (H6).** The database engine runs as a separate program at EL0 / ring 3 with its own address space and 12 checked system calls; a fault or an overrun restarts the worker and the broker keeps serving. ADR-210 to ADR-212.
- **Kernel hardening (H4, H5).** Allocator hardening and zeroisation, stack protector, KASLR on both architectures, MTE heap tagging on aarch64, a panic and fault policy with test hooks compiled out of production (ADR-170 to ADR-176). Miri, Kani proofs, sanitizer runs and a stateful ACL fuzzer (`make miri | kani | sanitize | acl-fuzz`).
- **Supply chain (H9).** A CycloneDX SBOM with every release, listed in `SHA256SUMS` and attested; `cargo-vet` and `cargo-deny` in CI (ADR-190 to ADR-193). `docs/VULNERABILITY-HANDLING.md`: intake, triage, fix, disclosure and supported versions, aligned with the EU Cyber Resilience Act (not legal advice; no support period promised yet).
- **Audit package (H10).** `docs/AUDIT.md` (TCB and `unsafe` inventory with every site justified, mitigation matrix, bounds table, proposed external audit scope, red-team checklist), a STRIDE table per component in `docs/SECURITY.md`, and the encryption section of `docs/CRYPTO.md`.
- **Performance measurement (X11).** A load generator mode for publish/subscribe and a measured comparison with Mosquitto on a 4 vCPU KVM VPS (docs/PERFORMANCE.md).
- **Boot integrity (H8)** (ADR-250 to ADR-254). The loaders' configuration is enrolled (`limine enroll-config` on `BOOTAA64.EFI`, `BOOTX64.EFI` and the BIOS stage), so a modified `limine.conf` is refused as a modified kernel or configuration module already was; `SMOKE_ONLY=integrity` flips bytes in a built ISO and raw disk image on aarch64 UEFI, x86_64 UEFI and x86_64 BIOS and shows the refusal, with controls that boot. `urmqtt-config pack --iso` re-enrolls. **Secure Boot signing path**: `scripts/sign-loaders.sh` (development keys, signing, verifying, an OVMF variable store with the keys), `mkiso.sh --sb-key`, `run-qemu.sh --secure-vars`, an OVMF Secure Boot scenario (x86_64) and the enrollment procedures in DEPLOY.md; no project key exists and release images are not signed. The installer entry's rules are tested (`install-rules`). A production image built outside CI warns loudly; the key bytes are scanned for in serial logs and `make repro` output. A TPM sealing spike is an ADR. Limits: a signed ISO cannot be configured afterwards, an installed disk does not boot under Secure Boot, aarch64 enforcement, Proxmox and a physical PC are untested.
- **A public demo broker (D1), built and not deployed.** A public demo broker, built and not deployed** (needs the owner's go-ahead). `deploy/demo/config.toml` (live mode, `demo/{id}/#`, plaintext only for a bridge host), `scripts/demo-certs.sh` (a published throwaway client CA, a separate broker CA whose key is deleted), `demo-pack.sh`, `demo-smoke.sh`; a stdlib Python WebSocket-to-TCP bridge with caps, rate limits and an Origin allow-list (`deploy/demo-bridge/`); the page "Try urMQTT live" with an MQTT client in plain JS (`tools/builder/demo/`, English and Croatian); the runbook in `docs/DEPLOY.md` section 11 and the threat model in `docs/SECURITY.md`.

### Fixed

- A subscriber whose output buffer filled was never served again until a keep-alive woke it (lost wake-up in the output loop). One TCP flow was slow because the stack dropped every segment after a loss, had a 16 bit window and counted ACKs instead of bytes; TCP gains an out-of-order queue, SACK, window scaling and timestamps. The 20 ms handler watchdog dropped healthy connections when the host stalled a vCPU; its budget is now running time. QoS 0 loss is counted per cause in `$SYS` (ADR-221 to ADR-224).
- H0-W2: captured TLS traffic secrets are wiped in place when taken, dropped or evicted. The AES-XTS tweak step is branch-free.

### Changed

- The boot sequence is shared by both architectures (ADR-059). The aarch64 boot log is unchanged.
- `make dist` also builds the template ISO and the SBOM; the release workflow lists both in `SHA256SUMS`.

## [0.1.0] - 2026-10-30

The first release: urMQTT as an aarch64 VM image, pre-alpha. The release
assets are a **dev** build with throwaway certificates, for evaluation only;
production images embed the operator's own keys and are built with
`make dist ENV=prod` (docs/DEPLOY.md).

### Added

- S1b: the ISO installs itself. A boot menu entry *Install urMQTT on this machine's disk* writes the raw image (mkraw-identical) onto the one qualifying disk after a 30 s on-screen countdown, verifies it and powers off. An interrupted install never leaves a disk that boots half-written. `install` is the only command-line word production honours (ADR-052).
- S1: single-disk model (ADR-051). The data lives in a partition of the boot disk, which is found by its GPT disk GUID and created crash-safely on the first boot; no other disk is ever written, and a damaged data partition is refused, never reformatted. Also new: `tools/urmqtt-disk` (info, verify, export-db, export-telemetry, import-devices, create, update-boot); fault injection (`test=disk-fault:`); fuzz target `gpt_parse`.
- H1: identity lifecycle without new images (ADR-048–050). Ed25519-signed control messages on `$urmqtt/control` (offline key, persisted sequence numbers, validity windows) revoke and unrevoke certificates and maintain an allowlist at runtime; live connections of a revoked or disallowed identity close within milliseconds. Also new:
  - trust anchors by role: operational, with CA rotation; bootstrap, limited to `provision/{id}/#`;
  - `registry.mode = "allowlist"`;
  - expiry checks at build time and at runtime;
  - the image's build time as the clock's lower bound;
  - `tools/urmqtt-control`; fuzz target `control_message`.
- X0: architecture facade `urmqtt-arch` with an API contract, all assembly confined to `arch-aarch64` (checked by `scripts/check-arch-leaks.sh`), CPU feature dispatch with a `[cpu] disable` opt-out (ADR-040, ADR-041).
- S0: byte-level specification of the data disk format (docs/DISK-FORMAT.md) with a spec-vs-code test and frozen golden images.
- H0: security baseline: TCB and `unsafe` inventory (docs/AUDIT.md, `make audit`), parser and mitigation tables, weaknesses list.

- M0: Cargo workspace with all crates, pinned nightly toolchain and Makefile.
- M0: Validated build-time configuration (`deploy/<env>/config.toml`) compiled into typed constants.
- M0: Dev certificate generator, including negative-test certificates.
- GICv2 support (ADR-039), so urMQTT runs as a KVM guest on GIC-400 hosts such as the Raspberry Pi 4/5: discovery from DT and ACPI, `Gicv2` driver, version-neutral IRQ/SGI layer, `run-qemu.sh --gic 2`, `gicv2` smoke scenarios (boot and mTLS broker under TCG), `scripts/kvm-host/` (installer, launcher, systemd unit) and the Raspberry Pi section in docs/DEPLOY.md.
- Entropy fallback for clouds without a hardware RNG (`entropy.fallback = "jitter"`: health-tested CPU jitter, conservative estimate); SMP fixed on CPUs without pointer authentication (Neoverse N1 / Ampere Altra, Cortex-A72); unsupported NICs named at boot; `run-qemu.sh --cpu/--no-rng`; `no-hw-rng` smoke scenario.
- virtio-scsi data disks (clouds attach disks that way): polled driver, `DataDisk` abstraction, `run-qemu.sh --bus scsi`, `scsi-disks` smoke scenario; Hetzner and Oracle Always Free deployment steps.
- M17: Deployment: reproducible images (paths remapped, `make repro` builds HEAD twice in separate worktrees, CI job), raw GPT disk image (`make raw`, `scripts/mkraw.py`), deterministic FAT images independent of the mtools version (`scripts/fat-stamp.py`), minisign signing (`make sign`, optional in the release workflow), dev-only benchmark and TLS client behind the `selftest` feature (prod ELF 180 KiB smaller), partitioned disks never used as the data disk, prod heap 1024 MiB, `raw-disk` smoke scenario, docs/DEPLOY.md for KVM/Proxmox and Hetzner.
- M16: Hardening and operations: admission refusing new connections on a low heap (`memory.min_free_mb`), a DB core that is behind, too many handshakes in flight per core or per source address (new config keys), or the handshake rate; memory returned after peaks (lowest-id-first slabs, shrinking tables); handler watchdog with log/drop/reset and stuck-core reset; health check; rate-limited logs; RFC 5424 syslog and statsd over UDP; revocation re-checked on TLS resumption; loadgen `storm`; smoke scenarios `storm`, `watchdog`, `observability`; fuzz targets `net_frame`, `tls_record`, `x509_identity`, `broker_input`, `telemetry_recover`; threat model in docs/SECURITY.md.
- M15: Memory per connection: exact heap accounting (requested and block bytes) with a per-connection report; compact TCP, TLS, connection and session state with size assertions; index-only TCP table; TLS key and IV derived per record; record state inline; slab chunks sized to heap blocks; device-scoped subscriptions without per-device trie nodes; loadgen `--subscribe`. 494 B per idle mTLS connection at 10k.
- M14: Own server-only TCP/IP stack replacing smoltcp: SYN cookies (SipHash), open-addressing connection table, hierarchical timing wheel, RFC 6298 RTO, NewReno, persist timer, RFC 5961 checks, ACK coalescing with replies, no TIME_WAIT; own Ethernet/ARP/IPv4/ICMP/UDP and DHCPv4 client; event-driven MQTT service; loss-simulation tests and tcp_segment fuzz target.
- M13: Multicore data plane: per-core smoltcp stacks, TLS and broker shards; core 0 dispatcher with Toeplitz/RSS steering; sessions on home shards with relayed connections and credit flow control; cross-core fan-out with retained replicas; per-CPU heap caches; asynchronous virtio-net TX; adaptive polling with WFI and wake SGIs; in-guest dp-bench (linear to 4 cores) and a real load generator.
- M12: Telemetry log: per-core partitions of segment rings on the data disk, CRC per record salted by segment sequence, batched sector-aligned writes by the DB core fed through per-core SPSC rings, crash recovery with torn-tail truncation, size and age retention; million-record SIGKILL test and torn-write test in smoke.
- M11: SQLite 3.54.1 inside the kernel: freestanding build, raw-disk VFS with superblock and region table, WAL + exclusive locking, quick_check at boot, embedded migrations; DB core fed by SPSC rings with 5 ms / 512-op batching; persisted device registry, revocations, retained messages and persistent sessions; crash-consistency tests (host power-loss model, SIGKILL in smoke); disk_layout fuzz target.
- M10: TLS 1.3 with mutual TLS on port 8883: rustls handshake with an own RustCrypto provider, own record layer (AES-128-GCM, ChaCha20-Poly1305, KeyUpdate), identity from CN or SAN URI, revocation list, stateless resumption, handshake admission control; mosquitto mTLS scenarios with all four rejections.
- M9: Sans-IO broker core (QoS 0/1, wildcards, retained, LWT, persistent sessions, ACL with service identities, limits) on plain TCP in dev builds; mosquitto acceptance scenarios.
- M8: Zero-copy MQTT 3.1.1 codec (no_std, no unsafe, streaming, bounded), property tests, mosquitto interop tests, mqtt_decode fuzz target.
- M7: smoltcp network prototype: DHCPv4, ARP, ICMP echo to the gateway, dev TCP echo service; service-style smoke tests.
- M6: PCIe enumeration, virtio-pci (rng, blk, net), MSI-X via GICv2m, ChaCha20 CSPRNG with hardware-entropy requirement, blk/net self-tests.
- M5: Unified platform description from DTB or ACPI (CPUs, GIC, timer, UART, PSCI, PCIe ECAM); DTB/ACPI fuzz targets.
- M4: SMP bring-up (Limine MP), per-CPU data, per-core GIC + timer, SGI IPIs with all-pairs ping-pong test.
- M3: GICv3 driver, generic timer, 10 ms tick, IRQ dispatch, measured IRQ latency (busy-poll vs WFI).
- M2: Kernel page tables with enforced W^X, locked tables, guard pages, frame allocator, buddy heap, PAC/BTI.
- M1: Bootable UEFI ISO, console, decoded exception reports, PSCI, `make run`/`smoke`, CI smoke job.
- M0: CI and CD: lint, host tests, kernel build, cargo-deny, fuzzing, CodeQL, Scorecard, Dependabot and a release workflow with provenance.

[Unreleased]: https://github.com/zeljan-alduk/urMQTT/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/zeljan-alduk/urMQTT/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/zeljan-alduk/urMQTT/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zeljan-alduk/urMQTT/compare/v0.2.1...v0.3.0
[0.1.0]: https://github.com/zeljan-alduk/urMQTT/releases/tag/v0.1.0
