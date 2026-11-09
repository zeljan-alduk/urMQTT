# NOW-14: a limit on established TLS connections per source address (ADR-280)

## What changed for operators

- A source address can now hold at most `limits.max_connections_per_ip` established TLS connections (the MQTT
  port and the WebSocket port together, all cores added up). Default **1024**; 0 turns it off. Over the limit the
  SYN gets no answer (no handshake work, no token, no state); a connection that slips past is refused with a
  RST at the final ACK.
- New configuration key `limits.max_connections_per_ip`, 0 to 1 000 000, **configuration format 14**. At its
  default the key writes nothing, so an untouched configuration keeps its lowest format and boots on older
  kernels too. Set to any other value (0 included) the configuration needs format 14 and a v0.5.0 or older
  kernel refuses it at boot; the builder page and `urmqtt-config` say so for older templates ("needs
  configuration format 14").
- The builder page shows the key (in `[limits]`) in all 15 languages.
- Counters: `$SYS/broker/connections/per_address/{limit,established,addresses,peak,syn_dropped,refused,
  untracked}`, the `per_address` object in the JSON info reply, a `per address limit ...` line in the console's
  `status`, `syn_dropped.per_ip_established` and `refused.per_ip_established` in statsd, and
  `established per address N` in the 5 s `handshakes: core N:` log line.
- Relation to `limits.max_handshakes_in_flight_per_ip`: that one bounds handshakes in flight per core and
  address (a burst), this one bounds what an address holds in total. Independent counters and reasons.

## Upgrade effect (write this in the release notes)

A source address that held more than 1024 TLS connections before the upgrade is now refused beyond 1024.
Devices behind one NAT share an address: a site with more than 1024 devices behind one address must set a
larger value (or 0) before upgrading. QEMU's user network and any NAT test rig count as one address; the dev
command-line word `limits=bench` and `deploy/bench/config.toml` turn the limit off.

## Downgrade

A configuration that does not set the key boots on any kernel. One that sets it carries format 14 and is refused
by an older kernel.

## Limits and what is deliberately NOT done

- IPv4 only today. The table key (`SourceKey`) is 128 bits and already defines the IPv6 key as the /64 prefix,
  tested; NEXT-1 only has to call `SourceKey::v6`.
- The table holds 32 768 addresses (768 KiB). Beyond that (or on a bucket collision) a new address is let
  through uncounted and `per_address/untracked` counts it (fail open, ADR-280 point 6).
- No per-identity limit, no /24 grouping, no eviction of old connections, no exemption list. The plaintext port
  keeps its own `plaintext.max_connections_per_ip`.
- The `storm` smoke scenario (3000 devices from one address) runs with the limit off.

## Tests and tools

Host tests (`crates/net`), config format tests (`cfg`, `config-schema`, `config`, CLI, builder), fuzz target
`source_limit` (seeds in `fuzz/seeds/source_limit`), `tools/attack established-flood`, smoke group `conn-limit`
(`SMOKE_ONLY=misc SMOKE_SCENARIOS=conn_limit`, aarch64 and x86_64). Configuration tag 270 was used for the key;
the `tag` list in `crates/cfg/src/fields.rs` shows what the other items took.

Known unrelated failure seen in this tree: `tools/builder/test/simple.test.mjs` "the build ends in a result
card" expects the emulator build of the page (`make builder-emulator`); with `make builder` it fails with or
without this change.
