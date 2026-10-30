# Cryptography

> Status: H2. What runs, where its keys live, and which test checks each
> claim. The threat model is [SECURITY.md](SECURITY.md); decisions are ADR-029
> (record layer), ADR-034 (memory per connection), ADR-041/053 (CPU dispatch,
> hardware backends) and ADR-054 (session tickets).

## Primitives

| Use | Algorithm | Implementation | Backend on aarch64 (ADR-053) |
|---|---|---|---|
| TLS record protection | AES-128-GCM, ChaCha20-Poly1305 | RustCrypto `aes-gcm` 0.10, `chacha20poly1305` 0.10 | ARMv8 AES + PMULL; NEON |
| TLS key schedule, HKDF-Expand-Label | HMAC-SHA-256 | RustCrypto `hkdf`, `hmac`, `sha2` 0.11 | ARMv8 SHA2 |
| Key exchange | X25519, ECDHE P-256 | `x25519-dalek` 2, `p256` 0.14 | portable |
| Signatures (server, client certificates) | ECDSA P-256 / SHA-256 | `p256` 0.14, rustls-webpki | portable |
| Control messages (H1) | Ed25519 (`verify_strict`) | `ed25519-dalek` 2.2 | portable (SHA-512) |
| Session tickets | ChaCha20-Poly1305 | `chacha20poly1305` 0.10 | NEON |
| CSPRNG | ChaCha20 (`rand_chacha`), seeded from RNDR / virtio-rng / jitter | `tls/src/rng.rs` (ADR-038) | — |
| Storage checksums (not a MAC) | CRC-32C | `store/src/crc.rs` | ARMv8 CRC32 |

Only TLS 1.3 is compiled into the protocol list. The suites are
`TLS13_AES_128_GCM_SHA256` and `TLS13_CHACHA20_POLY1305_SHA256`; the groups are
X25519 and secp256r1.

**Known answers at boot** (`urmqtt_tls::kat`, ADR-053) run in every image
before any TLS or storage work, on the backends the CPU dispatch chose:
- AES-128-GCM: McGrew–Viega test case 4;
- ChaCha20-Poly1305: RFC 8439 §2.8.2;
- SHA-256: FIPS 180-2, one-shot and streamed;
- HMAC-SHA-256: RFC 4231 test case 2;
- CRC-32C.

A mismatch stops the boot.

## The handshake

The handshake is rustls 0.23.46 (unbuffered, `no_std`) with our provider over
the primitives above. Its configuration (`tls/src/server.rs`):

- **Mutual TLS, always.** The client verifier is webpki over the operational
  and bootstrap trust anchors (H1). Revocation is checked during verification,
  and again on every resumption (the chain from the ticket is verified again).
- **0-RTT is off, twice over.**
  - `max_early_data_size = 0`, and the configuration key `tls.early_data = true`
    fails the build (config-schema `early_data_fails_the_build`).
  - Independently, rustls never allows early data with stateless tickets
    (RFC 8446 §8.1). A client that asks for 0-RTT gets tickets without
    `early_data` (`zero_rtt_is_never_offered`), and early data that a client
    sends anyway is skipped (tlsfuzzer `early_data offered without a PSK`).
- **Resumption only with (EC)DHE** (`psk_dhe_ke`), so resumed sessions keep
  forward secrecy. A client that offers no `psk_key_exchange_modes` gets no
  ticket.
- **Alerts.** rustls queues its fatal alert when it rejects a handshake. The
  unbuffered API only emits it on the next call, so the server makes that call
  (`flush_alert`). The peer then sees `certificate_required`,
  `certificate_expired`, `bad_certificate` and so on, not a bare close
  (`fatal_alerts_reach_the_peer`).

## The record layer (after the handshake)

The record layer is our own, in `tls/src/record.rs` (ADR-029). After the
handshake, rustls's connection is turned into traffic secrets and dropped.

- **State per direction:** the 32-byte traffic secret and the 64-bit sequence
  number, 40 bytes in all. The secret is zeroised on drop. No expanded key
  schedule is kept: the AEAD key and IV are derived again for every record with
  HKDF-Expand-Label (`"tls13 key"`, `"tls13 iv"`, RFC 8446 §7.3). The cipher
  lives on the stack and the derived key is wiped when it goes out of scope
  (`record::Key`). That trades about a microsecond per record for memory
  (ADR-034).
- **Nonce:** the IV XOR the sequence number, big-endian in the low 8 bytes
  (RFC 8446 §5.3).
- **Associated data:** the 5-byte record header (`23 03 03` + length).
- **Sending:**
  - plaintext goes in records of at most 2^14 bytes, with the content type
    appended and no padding;
  - close_notify is an encrypted `alert(1, 0)`.
- **Receiving:**
  - the outer type must be `application_data` with version `03 03`;
  - the ciphertext is at most 2^14 + 256 bytes, the inner plaintext at most
    2^14 + 1 bytes (`record_overflow` otherwise, `inner_plaintext_over_the_limit_is_record_overflow`);
  - zero padding is stripped and the last non-zero byte is the content type;
  - application data of length 0 is allowed;
  - the only post-handshake handshake message accepted is a KeyUpdate in a
    record of its own; everything else is `unexpected_message`.
- **KeyUpdate** (RFC 8446 §4.6.3, §7.2):
  - the next secret is HKDF-Expand-Label(secret, `"traffic upd"`) and the
    sequence number restarts at 0;
  - a peer's `update_requested` is answered with our own KeyUpdate
    (`update_not_requested`) under the old keys, and then we rotate;
  - we rotate our sending keys ourselves before the AES-GCM confidentiality
    limit of 2^24 records (`AES_GCM_RECORD_LIMIT`, RFC 8446 §5.5). ChaCha20 has
    no practical limit;
  - the sequence number never wraps: at 2^64 − 1 the connection ends.
- **Errors end the connection with a fatal alert** (RFC 8446 §6.2), sent
  encrypted under the current keys:

  | Condition | Alert |
  |---|---|
  | authentication failure (any tampering, wrong keys, record too short for a tag) | `bad_record_mac` (20) |
  | ciphertext over 2^14 + 256, inner plaintext over 2^14 + 1 | `record_overflow` (22) |
  | wrong outer type or version, CCS after the handshake, no or unknown inner content type, handshake messages other than one KeyUpdate | `unexpected_message` (10) |
  | sequence number exhausted | `internal_error` (80) |

  After a fatal alert nothing more is sent, not even close_notify. A received
  fatal alert ends the connection silently.
- **close_notify** is answered with our own close_notify before the TCP close
  (RFC 8446 §6.1).

**Vectors and references.** The key and IV derivation follows RFC 8448 §3
(`rfc8448_application_keys`). `diff_tls_record` fuzzes byte-identical records
against rustls's own record layer, with rustls's key schedule and `ring`'s AEAD
(10 min clean on aarch64: 24.5 M runs). The fuzz target `tls_record` covers
hostile input.

## Session tickets (ADR-054)

The ticket keys used to be derived from the server key, which is inside every
image (H0-W4). They are now:

- **Random per boot**, from the CSPRNG. They are never derived from the image
  and never written anywhere: a copy of the image or of the disk cannot forge a
  ticket.
- **Rotated by uptime:** a key is current for 12 h, then previous for 12 h,
  then zeroised in place. The ticket lifetime is 12 h, so every ticket opens
  for its whole lifetime and never longer.
  - The two key slots are fixed and keys never move, so no copy is left behind
    (`retired_keys_are_zeroised_in_place`).
  - Monotonic time drives the rotation, so it needs no wall clock and a clock
    cannot move it.
- **Ticket format:** `key id (4) || nonce (12) || ChaCha20-Poly1305(state)`,
  with `"urmqtt ticket v2" || key id` as associated data and a fresh random
  nonce per ticket. Key ids are random, so a ticket from another boot or replica
  names no key here.
- **Refusals** are a quiet full handshake, counted as
  `urmqtt.tls.resume_refused.{expired,unknown_key,invalid,malformed}` and
  logged at powers of two. Key changes are logged.
- If the CSPRNG fails, no ticket is issued (`tls.tickets_not_issued`).
- **Cost:** after a restart every device does one full handshake. That is the
  load the M16 storm scenario already measures, since its clients never resume.

Tests:
- host tests: rotation boundaries, every second of four intervals, long sleep,
  a forged bit at every position, a foreign key, the pre-H2 format, RNG
  failure and zeroisation;
- `ticket_from_another_boot_means_full_handshake`;
- smoke `ticket-rotation` (`test=ticket-rotate:20`): a ticket from late in the
  first interval resumes after the rotation;
- smoke `ticket-restart`: a ticket from before a reboot does not resume, and is
  counted as `unknown_key`.

## Constant time

| What | How | Checked by |
|---|---|---|
| AEAD tag checks (records, tickets) | RustCrypto (`subtle`) | `make ct`: `forged_record_rejection_is_constant_time` (both suites), `forged_ticket_rejection_is_constant_time` |
| Comparing our derived record keys and IVs with rustls's | `server::ct_eq` (`subtle`) | `secret_comparison_is_constant_time` |
| Signature checks (ECDSA, Ed25519) | `p256`, `ed25519-dalek` | upstream; the inputs are public |
| SYN-cookie MAC check | one 32-bit integer compare, no early exit | review |
| Ticket key id lookup | not secret (sent in the clear) | review |

`make ct` runs dudect-style tests (Welch's t-test on interleaved, randomly
ordered classes, release build). A negative control, a byte-wise comparison
with early exit, must be detected by the same harness. Measured on an M4 Pro:

| Case | |t| |
|---|---:|
| byte-wise comparison with early exit (control) | 6728 |
| `ct_eq` | 0.7 |
| AES-128-GCM bad tag | 1.1 |
| ChaCha20-Poly1305 bad tag | 2.6 |
| ticket bad tag | 0.0 |

The bound is 7 (dudect: < 4.5 "probably constant time", > 10 "definitely
not"). CI runs `make ct` on the arm64 runner.

The review list is the grep `(key|tag|mac|secret|digest|hash|token|cookie)
… (==|!=)` over `crates/*/src`. Every hit is in the table above, or it compares
public data (known-answer outputs, counters, MAC addresses, ACPI signatures).

## Conformance and interop

**tlsfuzzer** (`make conformance`, `scripts/tlsfuzzer/urmqtt_tls13.py`, pinned
tlsfuzzer `5eebc446`, tlslite-ng `7e95ea1a`). The stock scripts expect an HTTP
server without client authentication, so they cannot run against urMQTT as
they are:
- they send `GET /` and expect an answer;
- they never send a client certificate;
- they expect a NewSessionTicket even when the ClientHello offers no PSK
  modes.

The 23 probes below reuse tlsfuzzer's machinery with mutual TLS and MQTT. All
pass under HVF, and CI runs them under TCG:

| Probe | Expected and observed |
|---|---|
| sanity, AES-128-GCM and ChaCha20-Poly1305 | CONNECT/CONNACK, close_notify answered |
| empty client certificate | `certificate_required` |
| CertificateVerify corrupted (3 positions) | fatal alert |
| KeyUpdate `update_requested` / `update_not_requested` / three in a row | our KeyUpdate when requested; PINGRESP under the new keys |
| padding 1, 100, up to the limit | accepted |
| zero-length application data; CONNECT in 1-byte records | accepted |
| 2^14 bytes of plaintext in one record | accepted |
| 2^14 + 1 bytes of plaintext | `record_overflow` |
| record modified (first byte, tag) | `bad_record_mac` |
| inner content type 0; heartbeat (24); ClientHello after the handshake; CCS after the handshake | `unexpected_message` |
| early_data offered without a PSK, garbage early data | skipped, handshake completes |

Two probes were not possible:
- **Padding past the limit:** tlsfuzzer refuses to build it. The host test
  covers it.
- **The stock HTTP-oriented scripts:** they do not apply, as explained above.

**Interop** (`make interop`, `tools/interop/client.c` built against each
library, against one dev VM, HVF on an M4 Pro):

| Library | mTLS + CONNECT | resumption | KeyUpdate | 1-byte records | 16 KiB record |
|---|---|---|---|---|---|
| OpenSSL 3.6.3 | ✅ | ✅ | ✅ | ✅ | ✅ |
| OpenSSL 4.1.0 | ✅ | ✅ | ✅ | ✅ | ✅ |
| wolfSSL 5.9.4 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Mbed TLS 4.2.0 | ✅ | ✅ (server log) | n/a: no KeyUpdate API | ✅ | ✅ |
| rustls 0.23.46 (host tests) | ✅ | ✅ | ✅ | — | — |
| mosquitto 2 (OpenSSL), smoke | ✅ | — | — | — | — |

Resumption is confirmed in the server log as well as by the client. Not
covered yet: an embedded MQTT client on real firmware (ESP-IDF, or Paho
Embedded over mbedTLS on a device). Mbed TLS above is the library ESP-IDF
uses, run on the host.
