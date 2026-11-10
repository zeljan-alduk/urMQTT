# v0.6.0 notes: NEXT-9, Prometheus metrics (ADR-290 to ADR-294)

For the release step: the changelog is built from this file. Branch `v060/next9`.

## What changed for operators

- **A Prometheus scrape target served by the kernel**, off by default: `[metrics] enabled = true` opens TCP 9100
  (`metrics.port`) and serves `GET /metrics` as plain HTTP/1.1 to the networks in `metrics.allow_from` (required, no
  "anywhere") and nobody else; any other address gets no answer at all.
- **Every `$SYS/broker/...` number is a metric** (about 170 series with four cores, 13 KiB), made from the same `Info`
  as the retained topics and the info query, so they cannot disagree. Names carry base units (`_seconds`, `_bytes`,
  `_ratio`), counters end in `_total`, gauges do not; text values are `_info` gauges; unknown values (certificate
  days without a clock, SNTP offset not measured) are absent. **Labels are bounded and never chosen by a client**
  (`core`, `reason`, `code`, `listener`, `result`, `direction`, `side`, `version`, `arch`, `source`, `mode`, `auth`).
  The endpoint adds its own `urmqtt_metrics_*` metrics.
- **Text format 0.0.4 by default, OpenMetrics 1.0.0 when `Accept` prefers it** (by quality value; Prometheus 2 and 3
  headers tested).
- Documentation: OPERATE.md "Metrics for Prometheus" (scrape config, the name table, alert rules, no Grafana
  needed), SECURITY.md (threat model, STRIDE row, residual risk), DEPLOY.md (firewall), README (config table), ADR-290
  to ADR-294.

## Configuration

- New section `[metrics]`, **configuration format 16** (tags 300 to 305): `enabled` (false), `port` (9100),
  `allow_from` (`[]`, at most 16 CIDRs, no `0.0.0.0/0`, required when enabled), `max_connections` (8, per core),
  `max_connections_per_ip` (2, per core), `request_timeout_s` (5, 1 to 30).
- An image that does not touch the section is the blob it always was. `urmqtt-config pack`/`verify`/`show` print a
  warning line while the endpoint is on. The builder page has the section (`section.metrics` in 15 languages, machine
  translations). The kernel refuses a format-16 blob below 16 (by the version) and `urmqtt-config` refuses to put
  `[metrics]` into an older template, naming the format.
- **Store schema: unchanged (5).**

## Upgrade and downgrade

- **Upgrading changes nothing** unless `[metrics]` is configured: no new port, no new behaviour, the same blob
  bytes. With the section set the image needs a v0.6.0 kernel (format 16).
- **Downgrading** a kernel under an image configured with `[metrics]` is refused at boot by the blob's version; use
  the older kernel's own configuration.
- `$SYS` is unchanged. (One hardening in `crates/broker/src/sys.rs`: `by_code` sums with `saturating_add`; the fuzz
  target found that the sum of arbitrary counters could overflow. No counter reaches that in practice.)

## Limits and defaults

Request at most 2048 bytes and 24 header lines, GET and HEAD only, one answer per connection then close, deadline
`request_timeout_s` from the accept (not extended by activity), 8 connections and 2 per address on each core, 20
scrapes a second per core, the heap reserve; no TLS handshake slot is used.

## Deliberately NOT done (ADR-294; each is in `left_out`)

- **TLS for log shipping** (needs NEXT-7, the outbound TCP client): a documented non-goal here; SECURITY.md's
  residual risk "Syslog and statsd are plain UDP" stays.
- **Mutual TLS with an operator-class identity on the metrics port**: the allow-list is the control (ADR-290 point
  2, the decision D-7 left to the implementation). Possible later as a `metrics.tls` mode.
- No Pushgateway, remote write or OTLP (outbound TCP), no histograms, no per-client series, no basic auth or token,
  no IPv6 allow-list entries (no IPv6 in the kernel).

## Merge notes (release step)

- `FORMAT_VERSION` is 16 in this branch and `blob::RESERVED_VERSIONS = [14, 15]` refuses those two as unknown: remove
  an entry as the item that owns it lands (and set `FORMAT_VERSION` to the highest of all). Tests that name the
  newest format (`crates/cfg/src/tests.rs`, `config-schema` `plain_tests`/`tls_off_tests`, the builder tests
  `mqtt5`/`shared`, `tools/builder/wasm/src/tests.rs`, `tools/config/tests/cli.rs`) were updated to 16; expect
  trivial conflicts there. `tools/builder/web/src/core.js`: `'metrics'` is last in `SECTION_ORDER`.
- Tags 300 to 305 are used; 262 to 299 are left to the other items.
- `docs/AUDIT.md` row 38 of the adversary table, `docs/audit/inventory.md` (regenerate: `python3 scripts/audit-inventory.py`).
- New workspace crate `urmqtt-http` (no dependency; `Cargo.lock` gains one entry), fuzz targets `http_request`
  and `metrics_render`, smoke group `metrics` (a CI shard was added to `ci.yml`), `scripts/metrics-scenarios.py`.
- The smoke scenarios use host port `PORT + 3` (`SMOKE_METRICS_PORT`).
