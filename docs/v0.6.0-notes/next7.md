# v0.6.0 notes: NEXT-7, an outbound TCP client (ADR-315 to ADR-319)

For the release step: the changelog is built from this file. Branch `v060/next7`.

## What changed for operators

- **The broker can open a connection of its own, and does so only when the image says where to.** The TCP stack
  gained an active open (SYN-SENT, SYN retransmission at 1, 3, 7, 15, 31 s and a give-up at 63 s, RFC 6528 initial
  sequence numbers, ephemeral ports 49152–65535 that never collide with a listener or a steered port). It is off
  unless an outbound user is configured; the worker cores' stacks never open one; no remote input can choose a
  destination.
- **Log shipping over TLS 1.3**, the first user, off by default: `observability.log_tls = "a.b.c.d:port"` sends every
  log record (the RFC 5424 message the UDP path sends) to that collector with RFC 5425 octet-counting framing. The
  collector's certificate must chain to `observability.log_tls_ca` (the only trust anchors of that connection) and
  carry `observability.log_tls_name` (or, without a name, the address as an IP SAN), valid by the wall clock. No
  client certificate is offered. Records wait in a bounded queue while the collector is down (the boot's records
  included); the broker reconnects with a jittered exponential backoff (1 s to 5 minutes; reset after a connection
  that lasted 10 s). Console lines `logtls: …`; statsd `urmqtt.logtls.{up,records_sent,records_dropped,
  connections,failures,attempts,bytes_out,rx_dropped_bytes}`.
- The boot line `ops: syslog …, statsd …` now also says `log over TLS <addr|off>`.
- `urmqtt-config pack`, `show` and `verify` print an `outbound:` line naming the connection.
- Builder page: the four keys appear in "Logging and metrics"; the collector's CAs are a file list like the
  operational CAs (`log-ca-N.pem`), kept in the session copy and the encrypted project file (15 languages,
  machine-translated labels).
- Documentation: OPERATE.md "Log shipping over TLS" (rsyslog, syslog-ng, Fluent Bit settings; the console lines),
  DEPLOY.md (egress firewall rule), SECURITY.md (trust boundary, attack surface, STRIDE row, "Outbound connections"
  section, residual risks), AUDIT.md (§1 TCB growth, §2 two inputs, §6 limit, §6b bounds), ARCHITECTURE.md, README.
- Internal API for later users (NEXT-8 bridge, NEXT-10 DNS): `kernel/src/outbound.rs` (`TlsLink`),
  `urmqtt_tcp::dial` (reconnect policy), `urmqtt_tcp::queue::RecordQueue` (bounded record queue),
  `TcpStack::{connect, ephemeral_port, set_max_active, set_syn_retries}`, `App::connected`,
  `CloseReason::Refused`, `urmqtt_tls::client::TlsClient::verifying`.

## Configuration

- New keys in `[observability]`, **configuration format 20** (tags 450 to 453):
  - `log_tls` (`""` default: off; `"a.b.c.d:port"`, a unicast IPv4 address, no DNS),
  - `log_tls_name` (`""` default: the address; else a DNS name, RFC 1123 labels, at most 253 bytes),
  - `log_tls_ca` (PEM files, 1 to 8, **required** with `log_tls`; checked like the operational CAs, valid for
    `trust.min_anchor_days`),
  - `log_tls_queue_kb` (16 to 4096, default 256).
- A collector key without `log_tls` is refused naming the key. Unset, the keys write nothing and the blob keeps its
  version; any of them set needs format 20.
- **Format 19 is another v0.6.0 item's.** This branch has `FORMAT_VERSION = 20` and refuses 19 like 10
  (`blob::UNUSED_VERSIONS = [10, 19]`); the release merge removes 19 from that list when its item lands. Tests
  that name the newest format say 20 (`cfg`, `config-schema` plain and tls-off tests, `urmqtt-config` cli, builder
  wasm and the `formatVersion` asserts of the builder's `*.test.mjs`).
- **Store schema: unchanged (5 at the branch point).**

## Upgrade and downgrade

- **Upgrading changes nothing** unless `log_tls` is set: the same blob bytes, no connection opened, no new port.
- **With `log_tls`** the image needs a v0.6.0 kernel (format 20) and the firewall must let the VM out to the
  collector's address and port (from 49152–65535).
- **Downgrading** a kernel under an image with `log_tls` is refused at boot by the blob's version; without the keys
  the image runs on an older kernel as before.

## Limits and defaults

One outbound connection (core 0; `outbound::MAX_ACTIVE` 4, at most 64 per stack); SYN retries 5 (63 s); 30 s from
the SYN to a finished TLS handshake; backoff 1 s doubling to 300 s, equal jitter, reset after 10 s up; ARP for the
next hop first (3 requests, 1 s apart); record queue `log_tls_queue_kb` (256 KiB), oldest dropped, drops reported at
most once a minute; 64 KiB of ciphertext waiting for TCP; 16 KiB of received plaintext (more dropped); an
unfinished TLS record 16 KiB + 261 bytes; TLS 1.3 only, no resumption, no early data; the wall clock is required
(the link waits for it).

## Deliberately NOT done (ADR-319; each is in `left_out`)

- No DNS names for the collector (NEXT-10): IPv4 literal only.
- No client certificate for the collector (a collector that requires mutual TLS refuses the broker).
- Statsd stays plain UDP; `$SYS` and the Prometheus endpoint do not report the log connection (statsd and the log do).
- At-most-once delivery: up to 64 KiB written into a connection that then breaks may be lost.
- No IPv6, no proxy, no simultaneous open, no TCP keepalive on the outbound connection.
- No export bridge, webhooks, NTS or clustering (NEXT-8, LATER-1): the API is their base.
- Only one outbound user exists; several users at once in one kernel are not exercised (the stack's limit is).
- The TLS client handshake's cost on core 0 is not measured.

## Validation (this branch)

`cargo fmt --check` (workspace and fuzz), clippy `-D warnings` (host workspace, all targets; kernel aarch64 in the
four CI feature sets; kernel x86_64), typos, shellcheck, `cargo test --workspace`, `make builder-test` (one failure,
`simple.test.mjs` "the build ends in a result card", is the same on `release-v0.6.0` without this branch: not
caused here), `make build` aarch64 and x86_64 (dev and prod), smoke `SMOKE_ONLY=logtls` on aarch64 (HVF, TCG) and
x86_64 (TCG): 2/2 each, fuzz `tcp_active` 2 min (1.05 M runs) and `tls_client` 2 min (1.5 M runs) without a finding,
`python3 scripts/audit-inventory.py` regenerated.

## Merge notes (release step)

- New smoke group `logtls` (`SMOKE_ONLY=logtls`, CI matrix entry added); it uses `SMOKE_LOGTLS_PORT` (default
  `SMOKE_PORT + 5`) on the host's loopback.
- Tags 450 to 453 (chosen apart from the other items' ranges); ADR-315 to ADR-319.
- `urmqtt-tls` is built with the `client` feature in every kernel (crates/kernel/Cargo.toml) and in the fuzz
  workspace.
