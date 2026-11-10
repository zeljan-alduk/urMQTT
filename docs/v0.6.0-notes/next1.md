# NEXT-1: IPv6 with SLAAC and static addresses (ADR-330 to ADR-334)

## What changed for operators

- **IPv6 beside IPv4, off by default.** `[network] ipv6 = "slaac"` makes the link-local address (`fe80::` + the
  EUI-64 of the MAC) and one global address from the first /64 prefix of the router's advertisements (the same
  interface identifier, so the address is predictable: `<prefix>:5054:ff:fe12:3456` for `52:54:00:12:34:56`), with
  the default router and the MTU from the advertisements. `ipv6 = "static"` uses `ipv6_address` and `ipv6_gateway`
  (the usual VPS case: a /64 routed to the VM, the router `fe80::1`, no advertisements). Duplicate address detection
  on every address; a duplicate is logged as an error and never used.
- **Every listener is dual-stack** when IPv6 is on: TLS (8883), WebSocket, plaintext and the Prometheus endpoint.
- **Per-address limits count an IPv6 /64 as one address**: `limits.max_connections_per_ip`,
  `limits.max_handshakes_in_flight_per_ip`, and the plaintext and WebSocket per-address tables (connections,
  failed logins, lock-outs).
- **Allow-lists take IPv6 networks**: `plaintext.allow_from` and `metrics.allow_from` accept `2001:db8::/32` beside
  IPv4 networks (strict: no host bits, no zone, `::/0` refused like `0.0.0.0/0`).
- **Visible**: boot log lines for each address, router, MTU and DAD result; `$SYS/broker/net/ipv6/{mode,
  address/link_local, address/global, router, mtu, frames_in, dropped, fragments, ext_headers, dad_duplicate,
  prefixes_ignored}`; `net.ipv6` in the JSON info reply; three `ipv6 ...` lines in the console's `status`; metrics
  `urmqtt_ipv6_mode_info`, `urmqtt_ipv6_mtu_bytes`, `urmqtt_ipv6_frames_received_total`,
  `urmqtt_ipv6_frames_dropped_total`, `urmqtt_ipv6_fragments_dropped_total`,
  `urmqtt_ipv6_extension_headers_dropped_total`, `urmqtt_ipv6_duplicate_addresses_total`,
  `urmqtt_ipv6_prefixes_ignored_total`.
- **Multiqueue NICs** are asked for TCP/IPv6 RSS hashing where the device offers it, so IPv6 flows land on their
  core's queue pair; otherwise core 0 steers them by the same hash.
- `scripts/run-qemu.sh --net6 dual|only` (QEMU's user network with IPv6) and `scripts/ipv6-relay.py` (a host
  process as the guest's whole link: carries host TCP connections into the guest over IPv6, since QEMU forwards
  host ports over IPv4 only).

## Configuration keys and format

| Key | Values | Default | Format |
|---|---|---|---|
| `network.ipv6` | `"off"`, `"slaac"`, `"static"` | `"off"` (writes nothing) | 23 |
| `network.ipv6_address` | `2001:db8:1::10/64` (global unicast, prefix 1-128); `static` only, required there | absent | 23 |
| `network.ipv6_gateway` | `fe80::1` or an address inside the prefix; `static` only, required there | absent | 23 |
| an IPv6 network in `plaintext.allow_from` or `metrics.allow_from` | `2001:db8::/32` | - | 23 (by the value) |

Tags 410, 411, 412. Format 23 is new (21 stays unused). The builder page shows the three keys in `[network]` in
all 15 languages; `urmqtt-config` and the page refuse them for a v0.5.0 or format-22 template with the reason.

## Upgrade

Nothing changes for an image that does not set the keys: IPv6 frames are dropped and counted as before, and IPv4
behaves as before. Turning IPv6 on opens every listening port to IPv6 clients too: a firewall in front must allow
(or deny) the same ports over IPv6, and allow-lists without IPv6 networks keep refusing IPv6 clients.
Per-connection TCP state grows from 112 to 128 bytes (16-byte addresses) on every image.

## Downgrade

Remove the `network.ipv6*` keys and the IPv6 allow-list entries; the configuration then keeps its older format and
boots on v0.5.x. A format 23 image is refused by an older kernel by its version.

## Limits

At most 4 extension headers (256 bytes) per packet, 32 options per header; 8 prefixes per Router Advertisement,
one global address; 32 neighbours per core; 100 Neighbour Discovery answers per second; one solicitation per
unknown next hop per second; IPv6 MTU 1280 to the link's (at most 1500, MSS 1440).

## Deliberately NOT done

- No fragment reassembly (fragments are dropped and counted), no ICMPv6 errors sent or acted on (no Packet Too
  Big, no path MTU discovery beyond the RA's MTU option).
- One global address only: a second prefix, temporary (RFC 8981) or stable-opaque (RFC 7217) addresses are not
  made; DHCPv6 is not done (the RA's M/O flags are ignored); no NUD probing.
- Neighbour Discovery is unauthenticated (no SEND, no RA guard in the host); use `static` on a shared segment.
- UDP over IPv6 is dropped: SNTP, syslog, statsd and log shipping over TLS stay IPv4; the outbound client's
  collector is an IPv4 address.
- `plaintext.ip_identities` takes IPv4 networks only (an IPv6 client with `auth = "ip"` is refused).
- Checksum offload: none is negotiated with virtio-net, for either family (no offload fields).

## Verification

Host tests in `net`, `tcp` (the RFC 9293/5961 scripts rerun over IPv6), `cfg`, `config-schema`, `config`,
`plain`, `virtio`, `broker`, `tools/config`, the builder page (`ipv6.test.mjs`). Fuzz: new target `ipv6_nd`
(seeds in `fuzz/seeds/ipv6_nd`; it found that a multicast "prefix" in an RA made a multicast address, fixed;
3.35 million runs in two minutes after the fix), `net_frame` with SLAAC, `tcp_segment` over both families (2.1 and
1.4 million runs). QEMU: `SMOKE_ONLY=ipv6` on aarch64 (HVF and TCG) and x86_64 (TCG): SLAAC against QEMU's router
beside DHCP; IPv6 only with an mTLS publish and subscribe over IPv6; dual stack with a message from IPv4 to IPv6
and the metrics endpoint for an IPv6 network. IPv4 regressions: smoke `metrics`, `plaintext-*`, `storm`,
`attack-*`, `mtu-*`, `conn-limit` pass.

Throughput rig (`scripts/bench.sh --accel hvf --relaxed`, M4 Pro, three runs each, release-v0.6.0 vs this branch):

| | dp-bench 1/2/4 cores (handshakes/s, in guest) | network via QEMU user net 1/2/4 cores (conn/s) |
|---|---|---|
| release-v0.6.0 | 4343/8395/15458, 4341/8383/15393, 4338/8402/15577 | 4119/4177/3465, 4198/4009/3591, 4112/4241/3086 |
| NEXT-1 | 4348/8381/15486, 4338/8369/15308, 4337/8363/14360 | 4049/4423/3138, 4105/2963/2726, 4103/3712/3310 |

The in-guest handshake rate is unchanged; the QEMU user-network rate varies from run to run by more than the
difference (2963 to 4423 for the same kernel at 2 cores), but its 2- and 4-core means are about 10 % lower than
the baseline's on this machine. Worth a measurement with the tap/multiqueue rig on the KVM host before the release.
