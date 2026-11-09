# Threat model

> Status: H1 (control channel and identity lifecycle added before their
> implementation, as PROMPT-security requires). To report a vulnerability, see [../SECURITY.md](../SECURITY.md).
> Every mitigation below names the test, fuzz target or smoke scenario that
> checks it. A claim without one is listed under [residual risks](#residual-risks).

urMQTT is a single-purpose appliance: one ARM64 VM, one public port (TCP 8883,
TLS 1.3 with client certificates), no shell, no console input, no remote
administration. Configuration changes mean a new image. The one exception is the
identity lifecycle (revocation and the device allowlist, H1): it changes at
runtime through signed control messages on the same MQTT/TLS port. See
[Control channel](#control-channel-h1). A second, **optional and off by default**
exception is a plaintext MQTT port for trusted networks (P1): see
[Plaintext MQTT for trusted networks](#plaintext-mqtt-for-trusted-networks-p1-adr-229-to-adr-231),
which says what it gives up.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Server TLS private key | In the image's configuration slot (ADR-215) | Impersonating the broker; decrypting nothing (TLS 1.3 is forward secret), but accepting devices. |
| Session-ticket keys | Random per boot (CSPRNG), in RAM only; current for 12 h, previous for 12 h, then zeroised (H2, ADR-054) | Forging resumption tickets. Never stored, never derived from the image: a copy of the image or disk forges nothing. |
| Traffic secrets | Per connection, in RAM, zeroized on drop | Reading or injecting one device's traffic. |
| Device identities and the revocation list | CA embedded; revocations embedded and in SQLite | Who may connect. |
| Control signing key (Ed25519) | **Offline**, never in the image: a file on an operator machine (dev) or an HSM/KMS behind `urmqtt-control --sign-cmd` (prod). The image holds only the public key (`deploy/<env>/control.pub`). | Revoking, unrevoking and allowlisting devices at runtime. |
| Trust anchors by role | `[trust] operational` and `bootstrap` CA lists, embedded | Which CA grants which rights; rotation with overlap. |
| Plaintext accounts (P1, opt-in) | Salted PBKDF2 hashes in the image's configuration slot (ADR-231); the passwords are never stored | Logging in on the plaintext port as a device. The hashes are public to whoever holds the image: use long random passwords. |
| Disk key (S7, opt-in) | In the image's configuration slot (`storage.disk_key`), and in RAM while the disk is open (the cipher's round keys, wiped on drop) | Reading a stolen volume or snapshot. Whoever has the ISO has it (ADR-240). |
| Messages | In flight (RAM), retained and offline queues (SQLite), telemetry (log on the data disk) | Confidentiality and integrity of device data. |
| Availability | — | The broker's purpose; the main target of a remote attacker. |

## Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| Network (TCP 8883, and the L2 segment) | **Untrusted** | Every byte is hostile until TLS client authentication completes, and stays untrusted as MQTT input afterwards. |
| Plaintext listener (P1, opt-in, `plaintext.enabled`) | **Untrusted, and unencrypted** | Reachable only from `plaintext.allow_from`; a client holds the plaintext role (a narrower ACL, smaller packets, a lower rate, no `$SYS`, no control) and its traffic can be read and changed by anyone on the path. Chosen by the owner for a network the owner controls. |
| Authenticated device | Partially | Restricted by the ACL and every limit below. A device can only harm itself and its own topics. |
| Backend/service identity | More trusted | Wider ACL (`acl.service_*`). Still no query interface and no code execution. |
| Data disk | Integrity-checked | Treated as corruptible (torn writes, bit rot), not as malicious: the hypervisor owns it. |
| Boot image (kernel, command line, configuration) | Trusted | Built reproducibly (M17); dev-only switches are ignored by non-dev builds. |
| Hypervisor / cloud provider | Trusted | It can read memory and disks. urMQTT cannot defend against its host. |
| Build machine and CI | Trusted | Pinned toolchain and dependencies; provenance attestations let others check builds. |

## Attackers

1. **Remote, unauthenticated:** anyone who can reach port 8883. Goals: code
   execution, bypassing authentication, denial of service.
2. **Authenticated device:** holds a valid certificate (possibly a stolen one).
   Goals: other devices' data, denial of service, persistence after revocation.
3. **On-link attacker:** on the same L2 segment as the VM (a shared cloud
   network). Goals: redirecting traffic, spoofing DHCP.
4. **On the path of a plaintext connection (P1, only when the owner enabled it):**
   can read and change everything on port 1883, replay a login and impersonate
   the broker. Not defended against by design; the exposure is limited by who can
   reach the port and by what a plaintext client may do.
5. **Damaged storage:** not an attacker, but the disk content after a crash or
   corruption is untrusted input at boot.

## Attack surface: everything that parses untrusted input

| Input | Parser | Verification |
|---|---|---|
| Ethernet, ARP, IPv4, ICMP, UDP | `urmqtt-net` (own) | unit tests; fuzz `net_frame` |
| DHCP replies | `urmqtt-net::dhcp` (own) | unit tests; fuzz `net_frame` |
| TCP segments | `urmqtt-tcp` (own) | 17 host tests incl. loss/duplication; fuzz `tcp_segment` |
| TLS handshake | rustls (no_std, own RustCrypto provider) | upstream fuzzing; mTLS scenarios in smoke (wrong CA, expired, mismatch, revoked) |
| TLS records after the handshake | `urmqtt-tls::record` (own) | unit tests; fuzz `tls_record` (garbage rejected, sealed records round-trip, any changed byte fails) |
| Client certificate identity and serial | `urmqtt-tls::identity` (x509-cert) | fuzz `x509_identity` |
| MQTT packets | `urmqtt-mqtt` (own, `forbid(unsafe_code)`) | spec and property tests; mosquitto interop; fuzz `mqtt_decode`; the MQTT 5.0 codec (ADR-273, reachable since ADR-274): spec-table tests, captured Mosquitto and paho interop, fuzz `mqtt5_packet`, `mqtt5_props`, Kani; the Eclipse Paho interoperability suite |
| MQTT session behaviour, QoS 2 flows (ADR-271), MQTT 5.0 semantics (ADR-274), shared subscriptions and Subscription Identifiers (ADR-275) | `urmqtt-broker` (own, `forbid(unsafe_code)`) | host tests (18 for QoS 2, 35 for 5.0, 20 for shared subscriptions and identifiers), the `qos2_model` proptest (3.1.1 and 5.0 devices, a shared backend), `acl_model` (mixed versions, shared filters), the `shared_model` proptest (three shards; each group exactly once, never across roles); fuzz `broker_input` and `broker_acl` (QoS 2, 5.0 and shared-group seeds) |
| Disk superblock and size table | `urmqtt-store::layout` | fuzz `disk_layout` |
| Telemetry log on the disk | `urmqtt-store::telemetry` | crash and torn-write tests; fuzz `telemetry_recover` |
| SQLite database file | SQLite 3.54.1 (vendored), **in the unprivileged database worker** (H6, ADR-210 to ADR-212) | EL0 / ring 3 in its own address space; fault containment and restart (smoke `worker-contain`, `worker-fault`); `quick_check` at boot, `SQLITE_DBCONFIG_DEFENSIVE`; upstream fuzzing |
| Firmware tables (DTB, ACPI) | `urmqtt-platform` | fuzz `fdt_parse`, `acpi_parse` (trusted source, fuzzed anyway) |
| IOMMU descriptions (DMAR, IVRS, IORT, `arm,smmu-v3` and `iommu-map`) and the units' fault records (ADR-305, ADR-306; read only with `devices.iommu` not `"off"`, except the description, which is parsed at every boot) | `urmqtt-platform::iommu`, `urmqtt-iommu` (own, `deny(unsafe_code)`, no `unsafe`) | host tests with QEMU's table shapes and a QEMU 11.1 DTB; models of the three units; fuzz `iommu_tables`; smoke `SMOKE_ONLY=iommu` |
| Control messages (`$urmqtt/control`, H1) | `urmqtt-control` (own, `forbid(unsafe_code)`, fixed layout) + `ed25519-dalek` `verify_strict` | RFC 8032 vectors, round trip, every flipped byte fails; fuzz `control_message`; smoke `control-*` |
| First packet of a plaintext connection, its CONNECT credentials, the `[plaintext]` entries (CIDRs, accounts, password hashes) | `urmqtt-mqtt` (the same decoder as TLS), `urmqtt-plain` and `urmqtt-cfg::{net,passwd,plain}` (own, `forbid(unsafe_code)` in `urmqtt-plain`) | fuzz `mqtt_decode`, `broker_input` (plaintext connections included), `plain_input` (parsers, allow-list and the table of source addresses against a model); 25 host tests in `urmqtt-plain`; smoke `plaintext-*` |
| WebSocket opening handshake (one HTTP/1.1 request, at most 4 KiB and 32 header lines) and RFC 6455 frames, `[websocket]` origins and paths (ADR-272) | `urmqtt-ws` (own, `no_std`, `forbid(unsafe_code)`, no allocation), `urmqtt-cfg::ws`; the MQTT bytes inside go to `urmqtt-mqtt` as on the TLS port | RFC 6455 and RFC 3174 vectors, proptest, Kani, Miri; fuzz `ws_upgrade`, `ws_frames`; Autobahn\|Testsuite (0 failed, docs/audit/ws-autobahn.md); smoke `websocket-*` |
| Build-time configuration | `urmqtt-config-schema` | 38 tests; fuzz `config_parse`; invalid configuration fails the build |

CI runs every fuzz target on every push (60 s each), and longer in the
scheduled fuzz workflow.

## STRIDE per component (H10)

One row per component, one cell per threat class, each with what answers it.
"—" means the class does not apply or is out of scope there; "**open**" means
no adequate answer exists yet and the item is in [AUDIT.md](AUDIT.md) §5 or §6.
S spoofing, T tampering, R repudiation, I information disclosure, D denial of
service, E elevation of privilege.

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| **Network stack** (Ethernet, ARP, IPv4, TCP) | forged SYN/ACK/RST: SYN cookies keyed (SipHash, rotating), RFC 5961 checks; **ARP and DHCP are unauthenticated on a shared segment (accepted, static addressing)** | segment injection: sequence and window checks, TLS above | — | none held: no state before the handshake | SYN, ACK, RST floods, slowloris: cookies, rate limits, per-address caps, admission (`tools/attack`) | a parser bug runs in ring 0: Rust, fuzzed (`net_frame`, `tcp_segment`), Kani, Miri |
| **TLS 1.3** (rustls handshake, own record layer) | mutual TLS, identity from the certificate (CN or SAN URI), revocation list, trust anchors by role; no 0-RTT | AEAD records, per-record keys, fatal alerts | — | forward secret; tickets under random per-boot keys; traffic secrets wiped (H0-W2) | handshake admission, in-flight caps, heap reserve, watchdog budget | rustls and webpki are third party (§6); hand-over code fuzzed and conformance-tested |
| **MQTT broker** (codec, sessions, ACL, retained) | identity fixed by the certificate; client id must match | packet and topic limits, validated UTF-8 | per-identity counters, logs without payloads | device-scoped ACL (`{id}`), reserved namespaces, `$SYS` only for operators | per-device publish rate, subscription, in-flight, queue and retained bounds (AUDIT §6b) | no code path from a message to anything but routing; ACL fuzzer |
| **Control channel** (signed revoke/unrevoke, registry) | Ed25519 signature from an offline key; only listed service identities may publish to it | sequence number, validity window, replay rejected; persisted | the sequence number and the log of each accepted message | — | verification before any work; rate limited like any publish | revocation is the only effect; unrevocation is off by default (`allow_unrevoke`); **theft of the signing key and a service identity is a residual risk** |
| **Operator surface** (`$SYS`, console) | operator identities by exact id over mutual TLS | four fixed commands (`help`, `status`, `log level`, `reboot`), anything else refused; output replayed from a bounded ring | every command is logged with the identity and the text, refused or not | metrics carry no payloads or secrets | at most 5 commands in a burst then one per 2 s; a slow reader loses lines, never blocks the broker; **`reboot` is a denial of service in the wrong hands, which is why operator ids are exact** | no shell and no way to run code; the log level is never above the build-time maximum |
| **Plaintext listener** (P1, opt-in) | **not authenticated by design** beyond the chosen login mode; `auth = "ip"` trusts the source address (documented) | none: nothing protects the path | per-identity counters | none: plaintext; a login can be replayed | SYN-time allow-list, per-address and total caps, lock-out, small packets, own rate | the plaintext role has no service, operator or control rights |
| **WebSocket listener** (ADR-272, opt-in, `wss://` only) | `mtls`: the TLS port's certificate identity; `password`: no client certificate, a user name and password inside TLS, PBKDF2, lock-out; **an origin allowlist against cross-site WebSocket hijacking** (required with passwords) | TLS records; a strict upgrade (duplicate headers refused, no body, no extension) | per-identity counters, refusals by reason | inside TLS; nothing the client sent is echoed in an HTTP answer | upgrade deadline and 4 KiB bound (slowloris), the TLS admission, per-address and total caps, login rate, lock-out; no reassembly buffer, pongs only while output has room | password sessions have their own role (`Role::Web`): no service, operator or control rights, no `$SYS`, own ACL and namespace `$ws/` |
| **Configuration and image** (blob, ISO, builder page) | the blob is validated at every boot; signed form available; template ISO refuses to serve | tampered module refused by the loader's hash pin and the blob's fingerprint; **a rewritten ISO is not detected without Secure Boot (H8 open)** | — | the image holds the server key (and the disk key): treat it as a secret | an invalid blob stops boot (fail closed) | production ignores the kernel command line; the builder runs in the user's browser and sends nothing |
| **Data volume** (layout, telemetry, backups) | UUID and CRC on every structure; a damaged or foreign partition is refused, never formatted | torn writes survive by design (A/B superblock, fault-injection loops); **a malicious rewrite of sectors is only detected by the CRCs** | — | optional AES-256-XTS (ADR-240): protects a stolen volume, not a stolen ISO | a full or failing disk: bounded ring, scrubbing, backup and restore | parsers fuzzed (`disk_layout`, `disk_backup`, `disk_crypt`, `telemetry_recover`); XTS has no integrity (sector swap and rollback are possible with write access to the volume) |
| **SQLite worker** (EL0 / ring 3) | — | checked system calls, bounds on every offset and length | — | own address space; no kernel symbol, no allocator | 30 s overrun and fault restart the worker; a restart storm makes storage unavailable | a compromised worker cannot touch kernel memory (`worker-contain`); **the kernel trusts its answers (an empty revocation list un-revokes certificates), there is no KPTI** |
| **Kernel** (memory, interrupts, boot) | — | W^X, locked page tables (**no test writes one**), guard pages, canary, KASLR, allocator checks | fault and panic reports redacted | no secret in logs or reports (`fault-secrets`, `panic-secret`) | watchdog and stuck-core reset | PAC, BTI, MTE (TCG only), poison on free; **no forward-edge CFI; the HHDM base is fixed** |
| **Boot chain** (UEFI, Limine, kernel) | pinned by hash in `limine.conf`, which is enrolled into the loaders (ADR-250); **loaders not signed (H8)** | a flipped byte in the kernel, the configuration module or `limine.conf` is refused (`integrity-*`, `config-tampered-refused`) | — | — | a refused boot is the failure mode | the installer entry erases a disk for whoever can use the boot menu (physical or console access, which already allows that) |
| **Time** (RTC, SNTP) | unauthenticated NTP: median of several servers, bounded steps; **NTS out of scope** | lower bound is the build time | — | — | a wrong date refuses handshakes (fail closed) | — |
| **Observability** (syslog, statsd, console) | plain UDP to a collector on a private network (accepted) | — | rate-limited logs | no payloads, keys or certificates in any sink | per-CPU rings drop rather than block | — |
| **Supply chain** (dependencies, build, release) | signed releases (minisign), SLSA provenance | reproducible builds (`make repro`), pinned toolchain and `Cargo.lock` | — | SBOM per release | — | 53 of 67 linked crate versions are cargo-vet exemptions, not audits (SUPPLY-CHAIN.md) |

## Control channel (H1)

Written before the implementation. The control channel changes who may
connect, at runtime and without a new image. It is the only path that
changes state without a new image, so it gets its own model.

**What it is.**
- Reserved topic namespace `$urmqtt/`. A message to the exact topic
  `$urmqtt/control` is not routed to anyone. It is handed to the control
  handler on the DB core.
- Commands: `revoke` and `unrevoke` certificate serials (unrevoke only with
  `control.allow_unrevoke`), and `allow` and `disallow` device ids for
  `registry.mode = "allowlist"`.
- No other effect exists. A control message cannot change configuration, run
  code, read data or open a port.

**Authenticated twice.**
1. *mTLS identity:* the publisher must be an operational (not bootstrap)
   identity listed in `control.service_ids`. Every other identity's publish to
   `$urmqtt/…` is dropped and counted (`control.dropped_unauthorized`).
   Subscribing to any `$urmqtt/…` filter is refused for every identity. MQTT's
   wildcard rule keeps `#` and `+` from matching `$` topics.
2. *Offline signature:* an Ed25519 signature (RFC 8032, strict verification)
   over a domain-separated, fixed binary encoding of the whole message. The
   signing key is offline. A compromised service identity alone cannot issue
   a command, and neither can the signing key alone.

**Freshness and replay.**
- Each message carries a 64-bit `seq`, which must be strictly greater than the
  last accepted one. The value is persisted in the same SQLite transaction as
  the effect.
- The validity window `not_before`/`not_after` must contain the broker's
  wall clock. It may not be longer than `control.max_message_age_s`.
- Without a trustworthy wall clock (unknown, or before the image's build time,
  H7) every control message is refused.
- Without durable storage every control message is refused, because a
  revocation that disappears at the next boot is worse than none.

**Effect.**
- The handler commits first, then applies the change to the in-memory sets
  that all cores read, then wakes every data core.
- Each core closes its live connections whose certificate serial is newly
  revoked, or whose identity left the allowlist.
- A revoked device is refused at its next full handshake and at its next
  resumption.

**Attackers and what stops them.**

| Attacker | Attempt | Stopped by | Test |
|---|---|---|---|
| Any device | publish to `$urmqtt/control` | reserved namespace before the ACL | broker test; smoke `control-from-device` |
| Any device | subscribe to `$urmqtt/#`, `#` | reserved namespace; `$` rule | broker tests |
| Compromised service identity | forge a command | Ed25519 signature | host vectors; smoke `control-forged` |
| Network attacker who recorded a message | replay it | persisted `seq` | host test; smoke `control-replay` |
| Anyone with an old message | delay it | validity window | host test; smoke `control-expired` |
| Malformed message | crash or confuse the decoder | bounded, fixed layout; fuzz `control_message` | fuzz |
| Bootstrap identity | act as a device or service | bootstrap role: only `provision/{id}/#`, its own session namespace, never persistent | broker tests; smoke `bootstrap-role` |
| Unknown device (allowlist mode) | connect | refused after the handshake, counted | smoke `registry-allowlist` |

**Residual risks of the control channel** (also in the table below):
- **Signing-key theft.** Theft of the signing key together with a service
  identity allows arbitrary revocation (denial of service) and, with
  `allow_unrevoke`, un-revoking a stolen device. Keep the key in an HSM or
  KMS. `allow_unrevoke` is off by default.
- **Disk rollback.** Restoring an old snapshot of the data disk restores old
  revocations and an old `seq`. Revocations that must survive anything belong
  in the image's `tls.revoked` list as well. The validity window limits what
  an old message can do after a rollback.
- **Dead service.** Revocation is only as timely as the service that publishes
  it.

## Operator role: `$SYS/` and the console (O1, O2)

Written with the implementation (ADR-060). It adds the one path by which a
remote party can read the kernel log and reset the machine.

**What it is.**
- The namespace `$SYS/`. Only an identity listed in `acl.operator_ids`,
  authenticated by a TLS client certificate from an operational CA, subscribes
  to `$SYS/#` and publishes to `$SYS/console/in` and `$SYS/query/info`.
- The console runs four commands: `help`, `status`, `log level <level>` and
  `reboot`. No shell, no code from the operator, no data access, no change of
  configuration, no way to raise the log level above the build-time maximum.

**What stands in the way.**
1. *Role by certificate:* an operator id on a connection without an
   authenticated identity is an ordinary device; devices, services and
   bootstrap identities are refused `$SYS/` whatever their ACL patterns say,
   and the build rejects such patterns.
2. *Requests are not messages:* what an operator publishes is queued for the
   kernel (bounded), never routed, retained or stored; a will cannot name
   `$SYS/`; any other `$SYS/` topic is dropped, also for operators.
3. *Closed command set, bounded input:* one line of printable ASCII, 64
   bytes, no chaining; refusals are answered and logged.
4. *Rate limit:* 5 commands, then one per 2 s per shard, and the session's
   publish rate.
5. *Audit:* every command, accepted or refused, is logged with the identity
   and text whatever the log level.

**Residual risk.** A stolen operator certificate allows a reboot loop and a
read of the log (which never holds secrets or payloads). Revoke it through
the control channel; keep operator certificates short-lived and on the
operator's machine only. The console is on in every build; with an empty
`acl.operator_ids` nobody can use it.

## Plaintext MQTT for trusted networks (P1, ADR-229 to ADR-231)

A release image can open a second MQTT port, TCP 1883 by default, **without
TLS**, for devices that cannot do it (a small microcontroller, a legacy sensor, a
gateway on a wire the owner controls). It is **off by default**; nothing about the
TLS port changes when it is on or off. This section says what it gives up, when
that is acceptable, what it never gives, and where each claim is checked.

### What plaintext gives up

| Property | TLS port (8883) | Plaintext port (1883) |
|---|---|---|
| Confidentiality of messages | yes | **no**: anyone on the path reads every packet, including passwords |
| Integrity of messages | yes | **no**: anyone on the path can change, inject or drop packets |
| Authenticity of the broker | certificate | **none**: a client cannot tell the broker from an impostor on the path |
| Authenticity of the client | client certificate (mTLS) | password (sent in the clear), or nothing (`anonymous`), or its source address (`ip`) |
| Replay of a captured login | impossible | **possible**: the password is the credential |
| Revocation | registry, control channel, CRL | registry allowlist and `disallow` (the identity), no certificate |

None of that can be repaired by configuration: it is what "no TLS" means. The
design limits what a plaintext client can **do** and who can **reach** the port;
it cannot make the bytes private.

### When it is acceptable

- A private network the owner controls end to end: a wired segment, a dedicated
  VLAN, a VPN or a cloud private network between the broker and the devices,
  where nobody untrusted can attach a machine or sniff.
- Devices whose messages are not secret and whose commands cannot cause harm
  if forged (or whose ACL is narrow enough that a forged message cannot).
- As a migration step, with an `allow_from` as narrow as the devices' subnet.

It is **not** acceptable on a public address with a public `allow_from`, for
anything private, or where a forged command matters. The configuration check, the
builder and the boot report all say so (see below), and `allow_from_anywhere`
exists only so that opening the port to everyone is never an accident.

### What it never gets

- **No service, operator or control rights.** The broker gives every plaintext
  session the plaintext role, whatever its name is. The configuration check
  refuses a plaintext identity that is also an `acl.service_ids`,
  `acl.operator_ids` or `control.service_ids` entry. A plaintext client cannot
  publish control messages, read `$SYS` or `$urmqtt`, or reach the console
  (host tests `plaintext_role_rules` and `a_plaintext_client_never_holds_another_role_whatever_its_name`;
  smoke `no-sys-subscribe`, and the `$urmqtt` publish a plaintext client makes is
  dropped and counted, as the log line of `plaintext-password` shows).
- **No access to TLS sessions.** The session key is `$plain/<identity>/<client
  id>`; no TLS session or client id can collide with it (host test `a_plaintext_client_id_cannot_take_over_anything_else`; smoke
  `plaintext-client-id-cannot-take-over-a-tls-session`).
- **No stored sessions.** `clean_session = 0` is refused (CONNACK 5), so there is
  no session to read after the device and no offline queue to fill (smoke
  `stored-session-refused`).
- **No retained messages** unless `plaintext.retain = true` (smoke
  `retained-publish-not-retained`).
- **A narrower ACL than the devices'**: `plaintext.acl_publish` /
  `acl_subscribe`, by default `devices/{id}/#` and `devices/{id}/cmd/#`, where
  `{id}` is the identity (smoke `acl-publish-only-own-topics`,
  `acl-subscribe-only-own-commands`, `anonymous-acl`).
- **Smaller packets and a lower rate**: 1024 bytes and 5 publishes a second by
  default (smoke `packet-limit`, `publish-rate-limited`).
- **The registry applies.** With `registry.mode = "allowlist"` an identity must
  be on the list to log in (smoke `not-on-the-allowlist-refused`).

### Who can reach it, and what a refusal costs

1. **The allow-list is checked at the SYN.** `plaintext.allow_from` is a list of
   IPv4 networks and is **mandatory** (an empty list is a configuration error
   when the listener is on; `0.0.0.0/0` is refused and spelled
   `allow_from_anywhere = true`). An address outside it, an address that is
   locked out and an address at its connection limit get **no SYN-ACK**: the
   broker keeps no state for them, so a scan or a flood from outside the list
   costs one comparison per packet (smoke `plaintext-refused`,
   `refused-source-gets-no-answer`; host tests in `urmqtt-plain`).
2. **Failed logins lock the source address out** (`max_failed_auths_per_ip`
   failures in `lockout_s` seconds: 5 in 300 by default). A locked-out address
   gets no SYN-ACK either. The count is by address, not by user name, so nobody
   can lock a user out from elsewhere (smoke `plaintext-lockout`).
3. **Logins cost CPU and are admitted at a rate** (a password check is about
   25 ms of one core at the default 100 000 iterations under HVF on the test
   machine, an estimated 50 ms on a VPS vCPU; the rate is sized from a
   measurement at boot so admitted checks use at most half of each data core,
   ADR-267), through an admission of its own, so a flood of logins cannot take
   handshake capacity from TLS (smoke `tls-is-not-locked-out`, and the TLS
   scenarios run on the same VM in `plaintext-password`). A check runs in one
   go on a data core: that is why the count is capped at 200 000, below
   OWASP's 600 000 for PBKDF2-HMAC-SHA-256 (ADR-267).
4. **Whatever the reason, a refused login looks the same and takes the same
   time**: no credentials, unknown user and wrong password are all CONNACK 4 and
   exactly one password hash is computed on each path (host tests
   `every_refusal_is_a_bad_login_with_one_code` and
   `the_work_does_not_depend_on_whether_the_user_exists` in `urmqtt-plain::auth`).

### Authentication modes

| Mode | Who a client is | What it proves | Use |
|---|---|---|---|
| `password` (default) | the user name, if the password matches the account's salted PBKDF2 hash | that the client knows the password, **which any sniffer learns** | the default; needs per-device accounts |
| `anonymous` | `anonymous_identity` (`lan`) | nothing | a closed segment where the allow-list is the only gate |
| `ip` | the identity of the longest matching `ip_identities` network | that the packet came from that address, which holds only while nobody can forge it | a segment with one network per device class |

Passwords are never stored: the image holds `pbkdf2-sha256$iterations$salt$key`
(ADR-231). The builder page hashes in the browser and keeps only the hash; the
command line reads the password from standard input. **An image is a file anyone
may copy, and its hashes allow offline guessing** at roughly GPU speed for
SHA-256: use long random passwords (the builder generates them: 20 characters
of a-zA-Z0-9, about 119 bits), not words. The iteration count (100 000 by
default, at most 200 000; `urmqtt-config hash-password --iterations N`) makes a
guess cost more, but no count the broker can afford per login rescues a word:
remember too that plaintext MQTT sends the password itself in the clear on
every CONNECT (ADR-267).

### Threat model entries (plaintext)

| Threat | Mitigation | Check |
|---|---|---|
| Sniffing messages or passwords on the path | None possible; limit where the port is reachable | documented; boot warning, builder risk dialog |
| Replaying a sniffed login | None possible (the password is the credential); lock-out limits only guessing | documented |
| Forging the broker (man in the middle) | None possible; clients cannot verify the broker | documented |
| Guessing passwords online | PBKDF2; lock-out per source address; login rate; uniform answer and time | `plaintext-lockout`; host tests |
| Scanning for the port from outside `allow_from` | No SYN-ACK, no state | `plaintext-refused` |
| Exhausting connections from one address | `max_connections_per_ip`, refused at the SYN | `per-address-connection-limit` |
| Exhausting connections from many allowed addresses | `max_connections`; TLS port has its own limits | `plaintext-limits` |
| Learning which user names exist | Same CONNACK and same work on every path | host tests |
| A plaintext client becoming a service, an operator or the control channel | Role is the plaintext role whatever the name; config check; `$SYS`/`$urmqtt` refused | host tests; `no-sys-subscribe` |
| Taking over a TLS device's session or reading a stored session | Separate session namespace; clean sessions only | `plaintext-client-id-cannot-take-over-a-tls-session`, `stored-session-refused` |
| A forged source address in `ip` mode | **Not mitigated**: the mode is documented as only as strong as the network | warning at boot |
| The port reachable from the internet by mistake | Mandatory allow-list, `allow_from_anywhere` spelled out, warnings at build and boot | config tests; boot report |
| A stolen image gives password hashes | Long random passwords; hashes are salted and iterated | documented (residual risk) |
| Parser attacks on the first packet | Same MQTT decoder as TLS (`mqtt_decode`), packet size limited to 1024 from the first byte | fuzz `mqtt_decode`, `broker_input`, `plain_input` |

### Operating it

`$SYS/broker/plaintext/*` (operator only) reports `enabled`, `port`, `auth`,
`allow_from`, `accounts`, `connections`, `accepted`, `refused/source`,
`refused/locked_out`, `refused/limit`, `refused/registry`, `refused/session`,
`auth_ok`, `auth_failed` and `lockouts`, and the JSON object of the info query (`$SYS/query/info`) and the status line
carry the same. The boot log carries one line with the port,
the mode, the allowed networks and every limit, and a warning when
`allow_from_anywhere` is set, when the mode is `anonymous` or `ip`, or when the
machine's own address is public. Accounts are changed by building a new image;
an identity can be cut off at once through the registry (`disallow` on the
signed control channel). Adding and removing accounts at run time is **not**
implemented (it would need a signed message type and a place to keep the hashes
across reboots) and is listed as later work.

## MQTT over secure WebSocket (ADR-272)

The `[websocket]` listener is off by default. When on it serves `wss://` only, on its own port, with the TLS
listener's certificate and key. What it adds to the attack surface is one HTTP request per connection and the
RFC 6455 framing, both in `urmqtt-ws` (no allocation, no reassembly; the MQTT bytes inside go to the broker's own
parser with its own limits).

| Threat | Mitigation | Check |
|---|---|---|
| Cross-site WebSocket hijacking (a page on another site opens a connection from the user's browser) | `websocket.origins`, exact origins; 403 for any other `Origin`; required with `auth = "password"`; with `mtls` only a browser holding a client certificate gets past TLS | `wss-wrong-origin-403`, `wss-origin-header-optional-but-checked`; host tests |
| A hostile page locking out its visitors' addresses | An origin refusal is not a failed login; only failed MQTT logins count toward the lock-out | ADR-272 |
| Slowloris on the upgrade | 4 KiB bound, `upgrade_timeout_s` from the accept (TLS included), the handshake timeout and in-flight caps on top | `wss-slowloris-upgrade-cut-at-the-deadline` |
| Request smuggling and header confusion | One request only; CRLF only, no folding, duplicates of the headers that matter refused, no body, no `Transfer-Encoding` | fuzz `ws_upgrade`; host tests |
| Memory sized by the client (frame or message length) | Streaming decoder, no reassembly; lengths checked at the header; 14 + 125 bytes of state | fuzz `ws_frames`; Kani; Autobahn 9.x |
| Compression oracles, decompression bombs | No extension is negotiated (permessage-deflate refused by omission) | Autobahn 12.x/13.x "unimplemented" (clean refusal) |
| Ping floods | Pongs only while the connection's output buffer has room; the TLS admission and per-address caps bound connections | ADR-272 |
| Guessing passwords online | PBKDF2; lock-out per source address; login rate at half a core; uniform answer and time | `wss-password-lockout`; host tests |
| A password login becoming a service, an operator or the control channel; reaching a certificate session | `Role::Web`, own ACL, `$ws/` namespace, clean only; config check refuses ids with other roles | broker tests; `wss-password-refusals-acl-and-clean-session` |
| A password on an unencrypted channel | No `ws://`; the password is checked inside TLS; the server-only TLS server issues no tickets | ADR-272; TLS test `a_server_only_session_has_no_client_identity` |

## The public demo broker (D1)

D1 (docs/PLAN.md, docs/DEPLOY.md section 11) is a urMQTT that **anyone on the internet may use**, so that people can try it
without installing anything. It is built, tested locally and **not deployed**. It is a toy; this section says what it exposes and
why that is acceptable.

**What is public, on purpose.** The private key of the demo *client* CA is in the download (`ca.key`): anyone can mint a client
certificate, so mutual TLS authenticates nobody here. The broker's own certificate comes from a *different* CA whose key is
deleted after signing, so a client that trusts `server-ca.pem` still talks to the real demo broker. Anyone can read `demo/<any
id>/#` for an id they mint, and the browser page shares one identity (`web`) between all visitors. The CA, certificates and ids
are generated for this deployment and must never be reused.

**What keeps it harmless** is configuration, not secrecy: `acl.device_*` = `demo/{id}/#` and no `service_ids`, `operator_ids` or
`control.service_ids` (a certificate that claims the name `operator` or `backend` gets `demo/operator/#`, nothing more), no
retained messages (`max_retained_per_device = 0`, `plaintext.retain = false`), no stored sessions, small limits (1 KiB packets, 4
subscriptions, 5 publishes a second, 60 plaintext connections and 400 per data core), live mode (nothing is written anywhere) and a
reboot as the reset.

| Threat | Mitigation | Check |
|---|---|---|
| Anyone mints a certificate and claims an operator, service or control identity | No such ids are configured; the role comes from the configuration, not from the name | `minted-operator-certificate-has-no-operator-rights`, `minted-backend-certificate-has-no-service-rights` (`scripts/demo-scenarios.py`) |
| Reading or writing another id's topics, `#`, `$SYS`, `$urmqtt` | ACL `demo/{id}/#`; refusals are SUBACK 0x80 | `tls-subscribe-elsewhere-refused`, `tls-publish-to-another-id-dropped`, `plaintext-subscribe-only-demo-web`, `plaintext-publish-only-demo-web` |
| **The bridge as an open relay** to the plaintext listener, or to other hosts | The upstream is one configured `host:port`, never taken from the request; the firewall and `plaintext.allow_from` accept only the bridge host (any other source gets no SYN-ACK); the first message of a session must be an MQTT CONNECT, so it is not a general TCP relay; an Origin allow-list | bridge tests `test_only_an_mqtt_connect_may_start_a_session`, `test_requests_that_are_refused`; smoke `plaintext-refused` (P1) |
| A page on another site uses the bridge | `Origin` must be on the allow-list (browsers always send it); a non-browser can fake it, so the limits below carry the load | `test_requests_that_are_refused` |
| Connection or bandwidth exhaustion through the bridge | Per-address (4) and total (50) caps, 20 new connections a minute per address, 1 KiB messages, per-connection token buckets, idle (120 s) and lifetime (1 h) limits, head and frame deadlines, container memory, pid and CPU limits | `test_per_address_and_total_caps`, `test_rate_limit_closes_a_flooding_connection`, `test_idle_timeout_and_pings_keep_a_connection_alive`, `test_a_frame_that_stalls_is_closed` |
| One visitor using up the broker's plaintext connections | The bridge's total (50) is below the broker's (60); per-address caps use the real client address from Caddy's `X-Forwarded-For`, trusted only from loopback and the container network | `test_client_address_is_the_peer_or_a_trusted_proxies_last_xff_entry` |
| Spoofing the client address with `X-Forwarded-For` | Used only when the peer is a trusted proxy, and only its last entry | `test_xff_from_an_untrusted_peer_cannot_dodge_the_cap` |
| Reflection and amplification | The bridge sends the browser only what the broker delivers; the broker's publish rate (5/s per session), 1 KiB packets and 4 subscriptions bound it; there is no UDP and no request-triggered outbound connection except the fixed upstream | design; `plaintext-publish-rate-limited` |
| Filling storage | Impossible: live mode has no disk. RAM is bounded by `storage.ram_percent`, the connection and subscription caps and `memory.min_free_mb` (new connections are refused below it); retained messages are not kept at all | boot line `EPHEMERAL`; `tls-retained-not-kept`, `plaintext-retained-not-kept` |
| Stored XSS: a visitor publishes markup that other visitors' pages render | The page shows every message as text (`textContent`), no `innerHTML`, no eval, no third-party script; the test publishes markup and checks it stays inert | `what other clients publish is shown as text, never as HTML`, `the page has no third-party script...` |
| Tracking visitors | No analytics script on the page, no cookies, nothing in browser storage; the bridge logs no addresses by default; the broker sees only the bridge's address | page tests, `test_payloads_and_addresses_are_not_logged` |
| Two people use `web` or `demo-001` at once | One connection per client id: the newer takes over the older. A nuisance, not a breach | by design, said on the page |
| Abuse (spam, illegal content) on a public broker | Small limits and no storage reduce it; the owner can take the demo down at once (DEPLOY section 11); messages are not logged, so there is no moderation | accepted |
| A flaw in the broker is now reachable by anyone | The demo runs the release image on a **separate machine** and address, so a compromise is not the production broker | operational (DEPLOY section 11, "Decide first") |

**Not covered.** The deployment (firewall, DNS, Caddy, the container image build) has not been exercised: the tests ran against
local processes and a QEMU VM on loopback. The demo image was booted on aarch64 only; the VPS is x86_64.

## Installer entry (S1b)

Written with the implementation. The ISO's boot menu has a second entry,
"Install urMQTT on this machine's disk". It boots the same hash-pinned kernel
with the command-line word `install` and the ESP as a hash-pinned module, and
writes the raw boot image onto the machine's disk.

- **What it can do:**
  - erase exactly one disk (the only writable disk large enough that is not
    the installation medium) and write the release image onto it;
  - with several candidates it refuses and writes nothing.
- **Who can trigger it:** anyone at the console of a machine booting the ISO
  (keyboard at the Limine menu), or who can set the VM's boot medium. That
  attacker already has physical or hypervisor access and could erase the
  disk anyway.
- **Mitigations:**
  - the menu editor is off;
  - the kernel and the image are pinned by blake2b in the menu file
    (`hash_mismatch_panic`), and the menu file itself is enrolled into the
    loaders (H8, ADR-250), so a word cannot be added to an entry, nor an entry
    to the menu, without the loader refusing to start;
  - the target, its size and a warning are on screen, followed by a 30 s
    countdown during which a power-off cancels; dev tests may shorten it,
    production cannot;
  - the write leaves a non-booting disk if interrupted, never a half-new one
    that boots (host test `an_interrupted_install_never_boots_and_can_be_redone`,
    smoke `install-crash`);
  - the result is verified by reading it back.
- **Production command line:** ignored, except three exact words: `install`
  (ADR-052), `live` (ADR-054) and `diag` (ADR-063); tests
  `production_honours_install_and_nothing_else`, `..._live_...`, `..._diag_...`.
  (SECURITY-PLAN H8 said "exactly one word, `install`"; the later entries added
  the other two, and only `install` writes to a disk.) Without the installation
  module, `install` only prints a message and powers off, and writes nothing.
- **Entry rules, tested (H8, ADR-253, `SMOKE_ONLY=install-rules`, on aarch64
  UEFI, x86_64 UEFI and x86_64 BIOS, each with a blank disk whose bytes must
  be unchanged afterwards):** a word added to an entry's command line is
  refused by the loader; the same edit in an image without the enrolled hash
  gives the kernel `install` and, with no module, "no installation image" and no
  write; a changed installation image is refused by the loader before the kernel
  runs.
- **Entry rules, not enforced (accepted):**
  - the kernel does not check the module's hash itself; the loader does, so the
    rule depends on the loader that the firmware starts (without Secure Boot,
    whoever can replace the loader on the boot medium controls this too);
  - the installed disk's `limine.conf` has no `install` entry and its module has no
    hash (ADR-217), so a person with write access to the ESP can add an entry with their
    own image; the enrollment (ADR-250) is what stops the *configuration* edit there.
- **Residual risk:** the installer erases the previous data partition. There
  is no "keep data" mode yet; an offline kernel update keeps data
  (`urmqtt-disk update-boot`).

## Configured images: what is attested (C1, ADR-219)

A released image has a published hash and a minisign signature over
`SHA256SUMS`. An image you configure with `urmqtt-config pack` (or the builder
page) is different bytes by construction, so **it has no official hash**. What
is attested, and by what:

- **The template** (kernels, loader, installer, the empty configuration): its
  SHA-256 in `SHA256SUMS`, signed. Check it before you configure it. Limine
  still verifies each kernel against the blake2b pinned in the menu
  (`hash_mismatch_panic`) at every boot; the tool changes neither the kernels
  nor their hashes.
- **The configuration**: its **fingerprint**, the SHA-256 of the canonical blob
  (limits, ACLs, network, certificates, keys, trust anchors, control key; each
  field in one form only, so one configuration has one fingerprint). The tool
  prints it, `urmqtt-config show IMAGE` prints it again from the image, and the
  kernel prints it at every boot together with whether and by whom it is signed.
  Compare them: that is how you know the machine runs the configuration you made.
- **The slot** is also protected against corruption: the blob's fingerprint is
  checked by the kernel, the menus pin the slot by blake2b (the bootloader stops
  on a mismatch).
- **Optional signature.** `pack --sign KEY.pem` attaches an Ed25519 signature
  over the fingerprint, together with the signer's public key; the kernel
  verifies it and prints an 8-byte id of the signer's key
  (`signed by key 1b3c...`; the first 8 bytes of the domain-separated SHA-256
  that `urmqtt-config show` prints for the same key). Default **off**. The image names no expected signer
  (a customer-configurable image has nowhere to pin one), so a valid signature
  proves only that the blob was not changed after the holder of that key signed
  it; compare the printed key id with the one your key has (`urmqtt-config show`
  prints it). Anyone who can write the ISO can replace the blob *and* the
  signature. Making signing mandatory would need an expected-key pin in the
  image, which is an operator decision (planned with the builder page).
- **What a patched image does not protect against:** whoever can write the
  image can replace the configuration, including the trust anchors and the
  control key; the fingerprint on the console is the check. The installed disk's
  `limine.conf` lists the configuration module without a hash because its ESP is
  writable by anyone with disk access anyway.
- **Fail closed.** The kernel refuses a configuration it does not understand or
  that fails a check (unknown or duplicate field, value out of range, wrong
  format version, bad fingerprint or signature) with the key and reason on the
  console. A release kernel also refuses `env = "dev"`, a plaintext port and the
  other development options (the durability shortcuts): they are impossible
  outside the dev environment. Without a server certificate, its key and an
  operational CA the kernel does not serve, whatever else the slot says.
- **Where keys go:** the tool reads and writes local files only. The server
  private key is in the slot of every image made from it, in the clear (as it
  was when it was compiled in).

### TLS off: plain MQTT only (ADR-233)

`network.mqtt_tls_port = 0` with `plaintext.enabled = true` serves **only** plain MQTT. What that means, honestly: nothing is encrypted and nobody on the path is authenticated beyond the login mode you chose; there are **no operator, service or control rights at all** (they are certificate identities over mutual TLS, so there is no way to read the counters, send control messages or reach `$SYS`), and no console; a device is whoever the plaintext login says (an account, one shared identity, or its network address), and only addresses in `plaintext.allow_from` get an answer. The builder says this beside the checkbox and asks again before building. Use it on a segment you control or behind a VPN; with both listeners on, TLS keeps all of its rights.

### The builder page (C1e and C1g, ADR-225 to ADR-228)

The page at aldo.tech (Products, urMQTT builder) does what `urmqtt-config pack
--iso` does, in the browser, with the same Rust code compiled to WebAssembly.
What that gives you and what it does not:

- **Same bytes.** The page and the tool produce identical images and the same
  problem messages for the same input; `make check` builds one configuration
  both ways in a headless browser and compares the files.
- **The release is checked in the browser, against a key built into the page.**
  The page downloads `SHA256SUMS` and `SHA256SUMS.minisig` from the mirror on
  the same site and verifies the signature with the key the signature names,
  from the key ring built into the page (`keys/release-keys.json`: the release
  key `minisign.pub` for releases after v0.4.1, the former test key
  `9229E05252D01F8E` for v0.1.0 to v0.4.1 only; the key ids are shown on the
  page, compare them with SECURITY.md), then the template's SHA-256 against the
  signed sums. A signature by a key the page does not know, or by a key outside
  its range of tags, is a failed check. **The former test key is considered
  compromised** from the day the release key exists (its secret was a
  passwordless CI secret); it is accepted only for the six releases it signed,
  and for each only the `SHA256SUMS` whose SHA-256 the key ring pins, so a
  forged file signed with it is refused (docs/RELEASE.md section 9). The mirror is **not** a
  trust anchor: a modified template or sums file fails the check, and a failed
  check blocks the build unless you override it in a dialog that says what is
  wrong. A release the mirror cannot verify is not offered at all.
- **What leaves the browser.** Only plain GET requests to the page's own site,
  for the release list and the release files. Certificates, private keys, the
  optional signing key, the settings and the finished ISO are never sent
  anywhere (the page's `Content-Security-Policy` is `connect-src 'self'`, there
  is no third-party script and no tracking; a browser test fails if any request
  carries key material). The address bar holds the changed settings and
  `sessionStorage` the public certificates and the control public key, so that a
  reload does not lose the form; **a private key is held in memory only** and
  must be chosen again after a reload.
- **What you still trust.** The page is code that handles your private key and
  it is delivered by aldo.tech each time you open it: whoever can change what
  that site serves could serve a page that sends the key away. The page cannot
  protect you from that, and a browser cannot prove which build of the page it
  is running. If that is a risk for your keys, build the image offline with
  `urmqtt-config pack` from a checked-out and verified release (same bytes,
  nothing leaves your machine), or use the page only with a certificate whose
  key you can replace. The kernel's checks at boot (fingerprint, optional
  signature, release rules) and the fingerprint comparison detect a changed
  *configuration*, not a leaked *key*.
- **The emulator (C1g) is optional and separate.** Nothing of it is fetched
  until you click its button and then *Start*; it is QEMU compiled to
  WebAssembly (GPL-2.0, files of its own under `emulator/<version>/` on the same
  site, with the source offer and the change we made to it next to them), runs in
  a worker of your browser and **has no network**: it cannot reach anything and
  nothing can reach it. The image you built is handed to it in memory and is
  never sent anywhere; closing the dialog ends the worker. It is code from
  another project at a pinned commit and its sums are checked when the files are
  made, not in your browser. What it shows says nothing about the broker's
  performance (ADR-228).

## Mitigations

### Code execution

- Rust everywhere except vendored SQLite and Limine. `forbid(unsafe_code)` in
  `mqtt`, `broker`, `timer-wheel` and `config`; elsewhere `unsafe` is confined
  to `arch`, `mm`, `pci`, `virtio`, `store` (FFI) and minimal kernel glue, each
  block with a `// SAFETY:` comment (lint-enforced).
- No panics on input: clippy denies `unwrap`, `expect`, indexing and `panic!` in
  data-path crates; fuzzing checks it.
- W^X with locked page tables, guard pages, PAC and BTI when the CPU has them,
  no dynamic code (smoke: `wx-write-text`, `wx-exec-heap`, `stack-overflow`,
  `pac-forgery`, `bti-violation`, `null-deref`).
- Exploit mitigations (H4, ADR-170 to ADR-176): the heap poisons what it frees,
  refuses double and invalid frees, hides its free lists behind a per-boot key
  and puts a canary behind large allocations; secrets live in a key slab that
  wipes on free; every function with an array or a taken address has a stack
  canary (Rust and SQLite) from the CSPRNG; the kernel image (both
  architectures) and every region of the address space get a random place at
  every boot, and logs show bit counts, never addresses; a production fault or
  panic report has no register, memory or formatted message; on aarch64 with
  FEAT_MTE2 heap allocations are tagged. The test hooks are compiled out of
  production images (`scripts/check-prod-hooks.sh`). Smoke: `SMOKE_ONLY=hardening`.
- SQLite: statements are fixed at compile time; defensive mode on; extensions
  and ATTACH compiled out. There is no network-reachable SQL. SQLite does not
  run in the kernel (H6): see "The database worker" below.

### The database worker (H6, ADR-210 to ADR-212)

SQLite parses a database, WAL and journal read from the volume, which an
attacker with write access to the disk image controls. It is 254k lines of C.
It therefore runs as an unprivileged program: EL0 on aarch64, ring 3 on
x86_64, in an address space of its own, called synchronously by the kernel
and talking to it through twelve checked VFS system calls (and `exit`) and one shared window.

**What is isolated.** A memory-safety bug in SQLite, in its libc shims or in
the worker's dispatcher can: corrupt the worker's own memory; return wrong
data; read and write the database, WAL, journal and an attached backup slot
(and nothing else on the disk: files are numbers 0 to 3, offsets and lengths
are checked, the disk layer bounds every access to the file's region); make
the worker fault, loop or burn its 30 s budget. It cannot: read or write
kernel memory, TLS and ticket keys, the CSPRNG, or another core's data (not
mapped; `PAN` or `SMAP` and the page tables hold, and the kernel never
dereferences an address the worker supplies); execute kernel code or inject
code (W^X; user pages are never kernel-executable: `PXN` or `SMEP`); touch a
device or MMIO; make any system call but those and `exit`. Every way of
misbehaving that the smoke test `worker-contain` tries (kernel read, write
and jump, a privileged instruction, a write to its own code, a jump into its
data, a null read, an endless loop) ends in a failed call and a restart, the
kernel word it tried to overwrite is intact, and the test asserts that
`PAN` or `SMEP`+`SMAP` is on. `worker-fault` does the same on the real store
path: committed rows survive, the open transaction is lost like after a
power cut, and the broker goes on.

**What is not.**

1. *The kernel trusts what the worker returns, after validating its shape.*
   A compromised worker can make the broker see wrong data (retained
   messages, sessions, the revocation list and the allow-list it reads at
   boot) and can write garbage to its files. A worker that returns an empty
   revocation list un-revokes certificates. This is what a crafted volume
   could already do through SQLite's own parsing; the split stops it from
   becoming a kernel compromise, not from being a wrong answer.
2. *Same CPU, no page-table isolation of the kernel half.* The worker runs on
   the DB core between its other duties and the kernel's mappings are present
   while it runs (no KPTI). Meltdown-class and Spectre-class leaks from the
   worker to kernel memory are not prevented by this change; KVM guests on
   current hosts get the host's mitigations, and no claim is made.
3. *Denial of service of the storage path* is possible within the budget: a
   worker that faults at every start is restarted at most five times in a
   minute, then given up on (storage unavailable until the next boot, the
   broker serves from memory and says so).
4. *Pointer authentication keys* are shared by EL0 and EL1 on aarch64. The
   worker is built with BTI but without pointer authentication, and a
   compromised worker can use `PACIA` as a signing oracle with the kernel's
   key for any pointer and modifier it chooses; it can see neither the key
   nor any kernel stack value.
5. *NMI on x86_64* arriving in the two instructions between a ring-3 entry's
   privilege test and `swapgs` would run with the wrong `GS`. The kernel
   enables no NMI source and QEMU raises none.
6. *Not fuzzed.* The protocol decoders have host tests; the worker is not fuzzed
   (H5's SQLite fuzzing target is still open, gap H0-W8).

### Authentication and authorisation

- TLS 1.3 only, mutual TLS against the embedded trust anchors, the client id
  must equal the certificate's device id (smoke: `mqtt-tls`).
- **Trust anchors by role (H1, ADR-049):**
  - Operational CAs give device and service rights. Two side by side allow
    rotation with overlap (smoke `ca-rotation`).
  - Bootstrap CAs give only `provision/{id}/#`, in a separate session
    namespace and never persistently (broker tests; smoke `bootstrap-role`).
  - A resumed session re-verifies its chain against the current anchors (test
    `trust_roles_and_ca_rotation`).
- Revocation by serial, checked in memory at every full handshake **and at
  every resumption** (M16: a ticket issued before a revocation does not resume
  after it; test `revoked_device_cannot_resume`).
- **Since H1, revocations also change at runtime:** signed control messages
  close the live connections of a revoked certificate within milliseconds
  (smoke `control-revoke-live`) and survive reboots (smoke `control-persist`).
  An MQTT 5.0 client is told DISCONNECT 0x98 first by the core that holds its
  session; the connection is cut after 1 s whatever happens (ADR-275, test
  `a_revoked_or_disallowed_connection_is_told_0x98_before_the_close`).
- **Registry (H1):** `registry.mode = "allowlist"` refuses unknown device
  identities after the handshake (smoke `registry-allowlist`).
- **Time (H7 lower bound, ADR-050):** a clock before the image's build time is
  treated as unknown, and certificate checks then refuse (smoke
  `time-before-build`).
- **Expiry safety (H1):** the build fails for a server certificate or trust
  anchor that is about to expire (test `expiry_build_check`). At runtime there
  is a gauge and warnings at 60, 30, 7 and 1 days.
- ACL in the image's configuration, evaluated without the database: by default a device may
  publish to `devices/{id}/#` and subscribe to `devices/{id}/cmd/#`.
- **Shared subscriptions (ADR-275)** cannot carry a message across roles: a
  group is (role class, group name, filter), so a device, a service, an
  operator, a bootstrap identity, a plaintext and a WebSocket login that use
  the same `$share/{group}/{filter}` are in different groups. The ACL judges
  the filter after `$share/{group}/` with the subscriber's own subscribe rules
  (the group name is not a topic), and every member gets only what its own
  subscription would give it (tests
  `the_acl_judges_the_filter_inside_the_share_and_groups_never_cross_roles`,
  the `shared_model` proptest, the `broker_acl` oracle with shares).
- **Enhanced authentication (MQTT 5.0 AUTH) is refused** (ADR-275): a CONNECT
  with an Authentication Method gets CONNACK 0x8C, an AUTH packet after the
  CONNECT DISCONNECT 0x82, an AUTH as the first packet is closed unanswered.
  Identity comes from the certificate or a plaintext/WebSocket account only.
- `network.mqtt_plain_port` (the development plaintext port, which takes the
  identity from the client id) can only exist in the `dev` environment; the build
  rejects it elsewhere (smoke `release-kernel-refuses-plaintext-port`). A release
  image gets plaintext MQTT only through the `[plaintext]` section (P1), which is
  off by default and has its own allow-list, logins and limits: see
  [Plaintext MQTT for trusted networks](#plaintext-mqtt-for-trusted-networks-p1-adr-229-to-adr-231).

### Denial of service

Every resource is bounded. What happens at the limit is part of the design:

| Resource | Limit (configuration) | At the limit |
|---|---|---|
| Half-open connections | none kept: SYN cookies always | — |
| RSTs to unknown connections | 200/s | not sent |
| ICMP echo replies | 100/s | not sent |
| New TLS handshakes per core | `limits.handshakes_per_core_per_sec` | SYN dropped without an answer, or refused (RST) at the ACK, before any crypto (ADR-080) |
| Handshakes in flight per core | `limits.max_handshakes_in_flight_per_core` | SYN dropped, or refused at the ACK; a flow refused at the ACK is remembered for 1 s and not admitted again by its next segment |
| … of those from one source address | `limits.max_handshakes_in_flight_per_ip` | refused (an unauthenticated peer cannot take every slot) |
| Plaintext SYNs from outside `plaintext.allow_from` | `plaintext.allow_from` (mandatory) | no SYN-ACK, no state (P1) |
| Plaintext connections | `plaintext.max_connections`, `plaintext.max_connections_per_ip` | SYN dropped without an answer, or refused at the ACK |
| Failed plaintext logins from one address | `plaintext.max_failed_auths_per_ip` in `plaintext.lockout_s` | the address gets no SYN-ACK for `lockout_s` |
| Password checks (CPU) | their own admission rate, sized from a boot-time measurement | SYN dropped before any hashing; TLS admission untouched |
| Time to finish a handshake and CONNECT | 10 s (3 s while three quarters of the in-flight limit are taken) | connection aborted |
| Free heap | `memory.min_free_mb` | new connections refused (smoke: `storm`) |
| DB core backlog | 16 384 requests | new connections refused; registry updates skipped beyond 4 096 |
| Connections per core | `limits.max_connections_per_core` | refused |
| Packet size, topic length and levels, client id, topics per packet | `limits.*` | protocol error, connection closed |
| Subscriptions per session | `limits.max_subscriptions_per_session` | SUBACK failure |
| Shared-subscription groups per data core, members per group | `limits.max_shared_groups`, `limits.max_shared_group_members` (1024 each; ADR-275) | SUBACK 0x97 (3.1.1: 0x80), counted (`shared/joins/refused`) |
| MQTT 5.0 topic-alias table per connection | `mqtt5.topic_alias_maximum` × (16 + `limits.max_topic_len`) bytes, 2 720 B by default | alias refused (DISCONNECT 0x94); counted in the heap statistics (`memory/topic_aliases`) and seen by the free-heap admission |
| QoS 1 and 2 in flight, offline queue | `limits.max_inflight_qos1`, `limits.max_queued_per_offline_session` | queued; beyond the queue, new messages are dropped and counted |
| QoS 2 ids awaiting PUBREL | `max(limits.max_inflight_qos1, 64)` per session (ADR-271) | one more closes the connection, counted (`messages/qos2/inbound_full`) |
| Publish rate per device | `limits.publish_rate_per_device` | dropped and counted |
| Output buffered per connection | 32 KiB | QoS 0 dropped, QoS 1 queued |
| Receive window | broker backpressure | TCP window closes |
| Cross-core fan-out | 16 384 messages per core pair | QoS 0 dropped, QoS 1 kept |
| Telemetry backlog | 65 536 records per core | dropped and counted |
| Log lines | 100/s, burst 300 | suppressed and counted |
| A handler hogging its core | `watchdog.handler_budget_ms` (handshake steps: `watchdog.handshake_budget_ms`, ADR-071) | `watchdog.action` (log, drop the connection, reset); a core stuck for 100 budgets (≥ 1 s) resets the VM (smoke: `watchdog`) |
| A core that stops making progress | 2 health checks (20 s) | VM reset (a fresh boot is the recovery) |

Memory left by a peak is returned within 10 s (slab chunks, tables), so the
free-heap admission recovers after a storm instead of refusing forever. The
`storm` smoke scenario checks this with 3 rounds of 3 000 devices reconnecting
at once against an 8 MiB admission limit.

### Data integrity

- Telemetry: CRC-32C per record salted with the segment sequence, torn tails
  truncated on recovery, a new segment after recovery (smoke: `log-crash`,
  `log-tear`).
- SQLite: WAL with `synchronous=FULL`, `quick_check` at boot, refuse to serve on
  corruption in production (smoke: `db-crash`).
- Disk layout: CRC on the superblock and the double-buffered size table.

### Confidentiality

- Logs never contain secrets, keys, full certificates or payloads.
- Traffic secrets, record keys and handshake buffers are zeroized when dropped;
  record keys exist only on the stack while a record is sealed or opened.
- Observability goes to private collectors named in the build-time
  configuration. It is plain UDP and carries no payloads or secrets.
- **Image secrecy (H8, ADR-252).** The image holds the server's private key and
  the disk key, so the image is a secret. Building a production image outside CI
  (the `CI` variable unset) prints a boxed warning to stderr, every time
  (`scripts/mkiso.sh`; tested by `SMOKE_ONLY=secrecy`). The serial logs of an
  encrypted-at-rest boot, of the wrong-key and no-key refusals, on the dev kernel
  and on a release kernel with the production configuration, and the output and
  build logs of `make repro`, are scanned for the key bytes in every form a log
  could show them (`scripts/secret-scan.py`: raw, hex, base64, the EC scalar, PEM
  lines), with the image itself as the control that proves the scan can see them.
  What this does **not** cover: panics and fault reports on paths the scenarios do
  not reach (the redaction policy of ADR-172 and its `-open` controls cover the
  planted-secret case), and the image's own contents (it holds the keys by design).

### Encryption at rest (S7, ADR-240)

Optional (`storage.encryption = "aes-256-xts"`). The whole data partition but
the two superblock slots is AES-256-XTS, one 512-byte sector per data unit,
under a 64-byte key from the configuration; the superblock carries a keyed
check so a wrong key is refused before anything is read (`docs/DISK-FORMAT.md`
§14). What that does and does not do:
- It protects a **stolen volume, snapshot or disk image**: registry, retained
  and queued messages, telemetry and backups are unreadable without the key.
- It does **not** protect against a **stolen ISO** (the key is inside it: the
  configuration holds the TLS private key as well), against someone who can
  read the running machine's memory, or against the cloud provider's
  hypervisor.
- **XTS is not authenticated.** A changed ciphertext sector decrypts to noise
  in the affected 16-byte blocks (the CRCs, the scrubber and SQLite's checks
  find it, as they find a flipped bit); an attacker with write access to the
  volume can also **roll back or swap whole sectors** between two snapshots.
  Integrity of the data against an active attacker on the storage is not a
  claim.
- **What stays visible:** the GPT, the superblock (layout, sizes, the UUID,
  that the disk is encrypted), which sectors were ever written, and the
  pattern and timing of access.
- **The key** is read from the configuration blob into the kernel's memory
  (like the TLS private key), used to build the cipher, and the 64-byte copy
  made for the open is wiped. The expanded round keys are wiped when the
  cipher is dropped. The configuration blob itself stays in memory. Rekeying
  and conversion are offline.
- **A weak or reused key** is the user's risk: the packer refuses a wrong
  length, equal halves and one repeated byte, nothing more. Generate it from
  `/dev/urandom`.
- **No hardware AES: refused**, never a silent software fallback.

### DMA isolation (H4b, ADR-305 to ADR-307)

With `devices.iommu = "auto"` or `"require"` the kernel drives the machine's IOMMU (Intel VT-d, AMD-Vi, Arm
SMMUv3) before any driver runs: from then on every device's DMA is blocked, and each device the broker drives
gets a translation domain of its own holding exactly the pages the kernel allocated for it (its virtqueues and
buffers; on a GIC also the MSI doorbell page). A device that writes anywhere else (the page tables, the key
slab, another device's buffers) is stopped by the unit; the fault is read by core 0 every 100 ms (at most 16
per unit per poll), counted in `$SYS/broker/iommu/faults` and logged (ADR-306). A virtio device that does not
use the platform's translation (no VIRTIO_F_ACCESS_PLATFORM) is treated as a device without isolation.
`require` refuses to boot when there is no IOMMU, a unit fails, or a driven device is outside every unit's
scope or bypasses it; `auto` goes on with a warning; `off` (the default) leaves the IOMMU as the firmware set
it. What it does not cover: interrupt remapping, reserved regions the firmware lists, more than 4 units or 32
ID ranges per unit, and any hardware other than QEMU's models (ADR-307). The firmware tables it reads (DMAR,
IVRS, IORT, the device tree) are fuzzed (`iommu_tables`).

### Supply chain

Pinned nightly toolchain and `Cargo.lock`; `--locked` builds; cargo-deny
(advisories, licenses, sources); vendored and checksummed Limine and SQLite;
SHA-pinned CI actions; OpenSSF Scorecard; SLSA provenance on releases.

## Residual risks

| Risk | Why it remains | Mitigation available today |
|---|---|---|
| The image contains the server key. | No secure key storage in the VM. TPM sealing was studied and not built (ADR-254). | Treat the ISO as a secret; rotate the key with a new image; a build outside CI says so loudly (ADR-252). |
| Theft of the control signing key **and** a control service identity. | Both are needed; then arbitrary revocation (DoS) or, with `allow_unrevoke`, unrevocation. | Offline key in an HSM/KMS (`--sign-cmd`); `allow_unrevoke = false` (default); revocations that must survive anything also in the image. |
| A restored old data-disk snapshot brings back old revocations and `seq`. | The disk is trusted not to be maliciously rolled back. | Image-listed revocations are re-applied at every boot; validity windows bound old messages. |
| DHCP and ARP are unauthenticated. | IPv4 on a shared L2 segment has no defence against on-link spoofing. | Static addressing (`network.mode = "static"`) and a private network for the VM. |
| Many source addresses defeat the per-address handshake limit. | A botnet can use the per-core in-flight and rate limits up. | Upstream filtering; the limits keep the broker alive for connected devices. |
| Plaintext MQTT (P1, only if enabled) gives up confidentiality, integrity and the broker's authenticity, and a sniffed login can be replayed. | That is what "no TLS" means. | Enable it only on a network the owner controls end to end; narrow `plaintext.allow_from`; keep a firewall in front; prefer `auth = "password"` over `anonymous` and `ip`. |
| Plaintext `auth = "ip"` trusts the source address. | An address on a shared segment can be forged. | Use it only where nobody can forge one; the boot report says so. |
| The password hashes in an image allow offline guessing (PBKDF2 at GPU speed). | An image is a file; there is no hardware-backed store, and no memory-hard function in the kernel (D-16, not now: ADR-267). | Long random passwords (the builder generates them); treat the ISO as a secret; change passwords with a new image. |
| Plaintext lock-out is by source address. | Devices behind one NAT share it; an attacker who shares it can lock the others out. | The allow-list is the better tool behind a NAT; raise `max_failed_auths_per_ip`. |
| Plaintext accounts cannot be added or removed at run time. | It needs a signed control message type and a place to keep the hashes (listed as later work, ADR-230). | A new image; revoke an identity at once with `disallow` through the registry. |
| Syslog and statsd are plain UDP. | No TLS sink in the kernel. | Collectors on a private network only. |
| No hardware RNG on the cloud (Ampere Altra has no `RNDR`; virtio-rng may be absent). | Then the CSPRNG is seeded from CPU timing jitter, which is weaker evidence than a hardware source. | Health tests and a conservative estimate gate it (ADR-038), and it is logged at boot. The weak path is an explicit option (ADR-263): the builder, `urmqtt-config pack`, the boot log and `$SYS/broker/entropy/source` all say when it is allowed or was used. Prefer clouds with virtio-rng; `entropy.fallback = "none"` refuses to boot without a hardware source. |
| Side channels in the crypto. | RustCrypto implementations are designed to be constant-time. The tag checks and our one secret comparison are checked by dudect-style timing tests (`make ct`, H2), but the asymmetric code (P-256, X25519, Ed25519) is not measured here. | ChaCha20-Poly1305 is offered alongside AES-128-GCM; docs/CRYPTO.md lists what is checked. |
| The HHDM (direct map of all RAM) has a fixed base, so memory reachable through it (the heap's frames, packet buffers, the SQLite arena) is at a known address. | Randomising it means placing the kernel's windows around it (ADR-173). | The kernel image, the heap, the stacks and the page-table alias are randomised; the allocator checks of ADR-170 stay. |
| No forward-edge control-flow integrity on the Rust and C indirect calls. | kCFI crashes the pinned compiler on the dependency graph (ADR-175). | BTI on aarch64, W^X, PAC, KASLR. |
| No memory tagging on x86_64, on HVF or on most clouds; the SQLite arena and DMA buffers are never tagged. | FEAT_MTE2 is rare in VPS hardware (ADR-174). | The software checks of ADR-170. |
| DMA isolation is off by default, and only tested against QEMU's IOMMU models. | `devices.iommu` (ADR-305) gives every driven device a domain with only its own pages, through VT-d, AMD-Vi or SMMUv3; it is `off` by default because a VPS's devices are the hypervisor's and an emulated IOMMU slows every DMA. Not run on real hardware; interrupt remapping is not enabled; reserved regions (RMRR/IVMD/RMR) are not mapped (ADR-307). With a GICv2m frame a device can still raise any SPI of the frame. | `devices.iommu = "require"` on bare metal or under a hypervisor whose device models you do not trust: the broker then refuses to boot without a working IOMMU covering every driven device, and `$SYS/broker/iommu/faults` counts blocked DMA. |
| The hypervisor sees everything. | Out of scope. | Choose the host. |
| 100k and 1M connections are not measured on the development host. | QEMU user networking on macOS stops near 10 240 sockets. | The per-connection footprint is flat from 1k to 10k (ADR-034); the storm test scales the heap down instead of the clients up. |
