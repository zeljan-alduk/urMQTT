# MQTT 5.0 conformance plan (NEXT-3, ADR-273)

How the broker's MQTT 5.0 support (parts 2 and 3 of NEXT-3) will be tested. Part 1 (the codec, `urmqtt_mqtt::v5`)
is tested on its own: tests from the specification's tables, captured client traffic, fuzzing and Kani (ADR-273).
This document covers the broker. The harness is `scripts/mqtt5-conformance.sh` (part 2, ADR-274); results are in
section 2.

## 1. The three layers

| Layer | What | Where | Gate |
|---|---|---|---|
| Codec | Packets as bytes: every packet type, property, reason code and malformed form | `crates/mqtt/src/v5/tests.rs`, `crates/mqtt/tests/mqtt5_interop.rs` (fixtures in `crates/mqtt/tests/fixtures/v5/`), fuzz `mqtt5_packet` and `mqtt5_props` | `cargo test`, CI fuzz |
| Broker semantics, host | Each ADR-273 rule as a sans-IO test over the in-memory transport (expiry with a fake clock, mixed-version fan-out, aliases, Receive Maximum, reason codes per path); the QoS 2 reference model with 5.0 devices; the ACL oracle with 5.0 sessions | `crates/broker/src/v5_tests.rs`, `tests/qos2_model.rs`, `tests/acl_model.rs`, `tests/acl_oracle/` (fuzz `broker_acl`), seeds of `broker_input` | `cargo test` |
| Interoperability | Third-party clients against a booted broker | Eclipse Paho interoperability suite; Mosquitto clients `-V mqttv5` | `scripts/mqtt5-conformance.sh` (part 2: manual and in the smoke group; part 3: CI) |

## 2. Eclipse Paho interoperability suite

- **Source.** <https://github.com/eclipse/paho.mqtt.testing>, directory `interoperability/`: `client_test5.py` (27
  MQTT 5.0 tests) and `client_test.py` (10 MQTT 3.1.1 tests). Python 3, stdlib only, plain TCP, IPv4. Pinned by
  commit: `fdab9d2b1ce125385135e5d9f282a0ad315268cc` (2026-10-31). The harness clones it into a scratch directory
  (never into the repository; it is third-party code and runs from its own directory because it imports its local
  `mqtt` package).
- **Running.** `cd interoperability && python3 client_test5.py -p PORT [Test.test_name ...]`; positional
  `Test.<name>` arguments select tests. `client_test.py` leaves `-p` in `sys.argv` and unittest then refuses it, so the
  harness runs both scripts through a small wrapper that hands the port to the script and the remaining arguments to
  `unittest.main` (which also makes `-k`, `-v`, `-f` usable). unittest has no "exclude": the harness runs **each test
  in its own process with a timeout** (default 60 s), because `test_flow_control2` waits forever when a broker does not
  disconnect with 0x93.
- **What the suite needs from a broker.** Anonymous clients with client ids `myclientid`, `myclientid2`,
  `myclientid3`, `clientid` and an empty id; topics `TopicA`, `TopicA/B`, `Topic/C`, `TopicA/C`, `/TopicA`, `$SYS/...`
  read; the topic `test/nosubscribe` refused (`test_subscribe_failure` expects SUBACK 0x80); persistent sessions for
  `test_offline_message_queueing`, `test_redelivery_on_reconnect`, `test_session_expiry`.
- **urMQTT setup.** `scripts/mqtt5-conformance.sh --boot` packs the dev configuration with its development port
  off and the plaintext listener on (P1, ADR-230) in its open login mode (`auth = "anonymous"`), `allow_from` the
  QEMU host, `acl_publish = acl_subscribe = ["#"]`, `retain = true`, the publish rate (1000/s), packet size (64 KiB)
  and per-address connection limits raised for the suite, and `mqtt5.max_keep_alive_s = 60`; it boots that image in
  QEMU with the plaintext port forwarded. The ACL allows `#` because the suite cleans retained messages through a
  `#` subscription between tests (and ACLs have no deny rules), so `test/nosubscribe` is granted. Plaintext
  sessions are never persistent (ADR-230): the tests that need a stored session are expected failures there and
  are covered over mTLS by the smoke group `mqtt5` (section 3), where sessions persist.

### Baseline: the suite against Mosquitto

Measured 2026-11-08 against Mosquitto 2.1.2 on macOS (`listener` on 127.0.0.1, `allow_anonymous true`, `persistence
false`, an `acl_file` with `topic readwrite #` and `topic deny test/nosubscribe`), each test in its own process:

| Suite | Passed | Failed | Hang | Time |
|---|---|---|---|---|
| `client_test5.py` (5.0) | 22 of 27 | 4 | 1 | 390 s (149 s for the 26 without the hang, in one process) |
| `client_test.py` (3.1.1) | 9 of 10 | 1 | 0 | 66 s |

Mosquitto's failures, all on the broker side, none a suite bug we must work around:

| Test | Why it fails on Mosquitto 2.1.2 |
|---|---|
| `test_flow_control2` | Hangs: the client exceeds the server's Receive Maximum with QoS 2 and waits for DISCONNECT 0x93; Mosquitto only logs it |
| `test_subscribe_failure` (both suites) | Mosquitto grants the subscription despite the ACL deny; the test expects 0x80 |
| `test_subscribe_identifiers` | Mosquitto sends one PUBLISH per overlapping subscription (one identifier each); the test expects one PUBLISH with both |
| `test_server_keep_alive` | No Server Keep Alive without `max_keepalive`; the test expects 60 for a keep alive of 120 |
| `test_will_delay` | The will arrived after 2.4-2.9 s instead of 4 +/- 1 s |

The urMQTT design passes several of these by construction: 0x93 (ADR-273 rule 7), Server Keep Alive (rule 10 with
`mqtt5.max_keep_alive_s = 60` in the conformance image), the Will Delay (rule 6).

### Results against urMQTT (part 2, ADR-274)

Measured 2026-11-08, aarch64 kernel of this branch under QEMU/HVF on macOS, one vCPU (`--smp 1`, see "Ordering"
below), `scripts/mqtt5-conformance.sh --boot`, each test in its own process; run again after the rebase onto
ADR-268..272 (publisher back-pressure, the receive interrupt) with the same result per test:

| Suite | Listener | Passed | Expected failures | Failed | Time |
|---|---|---|---|---|---|
| `client_test5.py` (5.0) | plaintext, open login (the reference run) | **17 of 27** | 10 | 0 | 368 s for both suites |
| `client_test.py` (3.1.1) | plaintext, open login | **6 of 10** | 3 | 0 | |
| `client_test5.py` (5.0) | development port (`--listener dev`: sessions persist) | **23 of 27** | 4 | 0 | 401 s for both suites |
| `client_test.py` (3.1.1) | development port | **8 of 10** | 2 | 0 | |

Per test, 5.0 on the plaintext listener (P passed, X expected failure, with its reason):

| Test | urMQTT | Mosquitto 2.1.2 | Why it fails on urMQTT |
|---|---|---|---|
| `test_basic`, `test_retained_message`, `test_will_message`, `test_zero_length_clientid`, `test_overlapping_subscriptions`, `test_keepalive`, `test_dollar_topics`, `test_unsubscribe`, `test_user_properties`, `test_payload_format`, `test_subscribe_options`, `test_assigned_clientid`, `test_request_response`, `test_maximum_packet_size`, `test_server_keep_alive`, `test_flow_control1`, `test_flow_control2` | P (17) | P except `test_server_keep_alive`, `test_flow_control2` | |
| `test_offline_message_queueing`, `test_redelivery_on_reconnect`, `test_session_expiry`, `test_publication_expiry`, `test_client_topic_alias` | X | P | each needs a stored session (Session Expiry > 0, Clean Start 0 to resume it); plaintext sessions are never persistent (ADR-230) and are granted Session Expiry 0. Over a listener whose sessions persist they pass (development port, below; the smoke group `mqtt5` covers them over mTLS with paho and Mosquitto clients) |
| `test_will_delay` | X | F (timing) | the same: Session Expiry 0 ends the session at the close, and the Will goes out then (§3.1.2.5). Over mTLS the delay is honoured (smoke `mqtt5-will-delay`: 3.0 s for a delay of 3) |
| `test_server_topic_alias` | X | P | the broker never sends topic aliases (ADR-273 rule 9: no per-subscriber alias state); the client's aliases to the broker pass (`test_client_topic_alias` up to its stored-session step, smoke `mqtt5-topic-alias-resolved`) |
| `test_subscribe_failure` | X | F | the conformance ACL allows `#` because the suite cleans retained messages through a `#` subscription and ACLs have no deny rules, so `test/nosubscribe` is granted. A refused filter gets 0x87 Not authorized (ADR-273 rule 13), not the 0x80 the test expects (smoke `mqtt5-suback-0x87-and-0x9e`) |
| `test_shared_subscriptions`, `test_subscribe_identifiers` | X (part 3) | P, F | part 3 (ADR-273 rules 16, 17): SUBACK 0x9E and 0xA1 today |

3.1.1 on the plaintext listener: `test_retained_messages`, `test_zero_length_clientid`, `test_overlapping_subscriptions`,
`test_keepalive`, `test_dollar_topics`, `test_unsubscribe` pass; `test_offline_message_queueing` and
`test_redelivery_on_reconnect` need a stored session, `test_subscribe_failure` the ACL as above.

On the development port (`--listener dev`: the client id is the identity, sessions persist as on the TLS port, the
device ACL opened to `#`) the stored-session tests pass too: `test_offline_message_queueing`,
`test_redelivery_on_reconnect`, `test_session_expiry` (Session Expiry 1 s honoured), `test_publication_expiry`,
`test_client_topic_alias` and `test_will_delay` (5.0), `test_offline_message_queueing` and
`test_redelivery_on_reconnect` (3.1.1). Left: `test_shared_subscriptions`, `test_subscribe_identifiers` (part 3),
`test_server_topic_alias`, `test_subscribe_failure` (both suites, as above) and 3.1.1 `test_zero_length_clientid`:
there the client id is the identity, so a 3.1.1 CONNECT without one names nobody and is refused with 0x02, as 3.1.1
§3.1.3.1 allows (unchanged from 3.1.1-only builds; a 5.0 client is assigned an id and passes).

Two fixes came out of the runs: a Will of a connection the broker closed (keep alive) went out only when TCP was done
with the connection, which the suite's client drags out to the FIN_WAIT2 timeout (`test_keepalive` in both suites,
`test_will_message`; fixed in the kernel, ADR-274 item 16); and the suite's `-h` option is read as `--help` (a
substring test), so the harness passes the port only.

**Ordering.** `test_subscribe_options` and `test_request_response` subscribe client B and publish from client A
without waiting for B's SUBACK. Across cores (more than one vCPU) B's SUBSCRIBE and A's PUBLISH reach their home
shards by different paths, and the broker keeps no order between two connections (ADR-032; MQTT does not require
one), so with 4 vCPUs `test_subscribe_options` failed in all three full runs and `test_request_response` in one
(B got nothing). Waiting for the SUBACK, as a client
must to know its subscription is in effect, both pass every time (reproduced with the suite's own client). The
reference run therefore has one vCPU.

### Expected-failure lists

`scripts/mqtt5-conformance.xfail` (plaintext listener, the reference run) and `scripts/mqtt5-conformance-dev.xfail`
(development port), one line per test that is allowed to fail, each with its reason; the files are the source of
truth, the table above repeats them.

Rules of the list:
- Columns are whitespace-separated; `suite` is the script name without `.py`, `test` the unittest method name,
  `phase` one of `part2`, `part3`, `always`; the rest of the line is the reason (with the ADR rule).
- A listed test that **passes** is reported (XPASS) and fails the run, so the list only shrinks.
- `part2` entries must be gone when part 2 is merged, `part3` entries when part 3 is; `always` entries need an ADR
  reference. A hang (the timeout) counts as a failure.
- The harness prints one line per test (`PASS`, `FAIL`, `XFAIL`, `XPASS`, `TIMEOUT`) and a summary, and exits non-zero
  on any `FAIL`, `TIMEOUT` or `XPASS`.

## 3. Mosquitto clients and paho-mqtt over mTLS (smoke group `mqtt5`)

The smoke group `mqtt5` (`scripts/smoke.sh`, both architectures; `scripts/mqtt5-scenarios.py` for paho-mqtt 2.x and a
raw client, `mqtt5_mosquitto` for the Mosquitto clients) runs over mTLS with the dev certificates, where sessions
persist, then restarts the VM on the same disk and checks what the store kept. Its client lines are the evidence for
what the plaintext listener cannot show (stored sessions, will delay). The table is the original plan; the group
checks more (CONNACK properties, request/response, No Local, Retain As Published and Handling, reason codes per path,
the server's DISCONNECT packets, `$SYS`, the restart):

| Scenario | Command (abridged) | Checks |
|---|---|---|
| Version negotiation | `mosquitto_pub -V mqttv5 ...` and `-V mqttv311` on the same port | both accepted; `mqtt5.enabled = false`: CONNACK 0x84 |
| Properties forwarded | `mosquitto_sub -V mqttv5 -F '%P %R %C'` + `mosquitto_pub -D publish user-property k v -D publish response-topic r/t -D publish correlation-data abc -D publish content-type text/plain` | user properties, response topic, correlation data, content type arrive; a 3.1.1 subscriber gets the payload only |
| Message expiry | `-D publish message-expiry-interval 2` to an offline session, reconnect after 3 s | not delivered; `$SYS/broker/messages/expired` +1 |
| Session expiry | `-D connect session-expiry-interval 5`, disconnect, reconnect after 7 s | session present 0; after 3 s: 1 |
| Will delay | `--will-* -D will will-delay-interval 3`, kill the client, reconnect within 3 s | no will; without the reconnect: will after 3 s |
| Receive Maximum | `-D connect receive-maximum 2` and a burst | never more than 2 unacknowledged |
| Maximum Packet Size | `-D connect maximum-packet-size 100` and a 200-byte publish | not delivered, counted |
| Topic alias | `-D publish topic-alias 1` twice, the second with an empty topic | delivered with the full topic |
| Subscription options | paho (no-local, retain-as-published, retain-handling) via `scripts/mqtt5-capture-paho.py`-style client | as ADR-273 rule 12 |
| Reason codes | publish outside the ACL; subscribe outside the ACL | PUBACK 0x87; SUBACK 0x87 |

## 4. Captured traffic

`scripts/mqtt5-capture.sh` records client and broker bytes through `scripts/mqtt-record.py` (a TCP proxy) for
Mosquitto 2.x clients and paho-mqtt 2.x (`scripts/mqtt5-capture-paho.py`) against a local Mosquitto; the files are the
codec's fixtures. The planned side-by-side capture against urMQTT was not made in part 2: the interoperability suite
and the smoke group check the packets urMQTT sends directly (properties, reason codes, announced limits). It moves to
part 3.

## 5. Running it

```
scripts/mqtt5-conformance.sh --boot                    # the reference run: build, boot (one vCPU), run, stop
scripts/mqtt5-conformance.sh --boot --listener dev     # the development port, where sessions persist
scripts/mqtt5-conformance.sh --boot --smp 4            # more cores (see "Ordering")
scripts/mqtt5-conformance.sh --port 1883               # against a broker already running
scripts/mqtt5-conformance.sh --mosquitto               # the baseline, against a local Mosquitto
```

The suite is cloned at its pinned commit into `$TMPDIR/urmqtt-mqtt5-conformance` (`--work` changes it); each test's
output is kept under `logs/` there. Exit status non-zero on any FAIL, TIMEOUT or XPASS.
