# MQTT 5.0 conformance plan (NEXT-3, ADR-273)

How the broker's MQTT 5.0 support (parts 2 and 3 of NEXT-3) will be tested. Part 1 (the codec, `urmqtt_mqtt::v5`)
is tested on its own: tests from the specification's tables, captured client traffic, fuzzing and Kani (ADR-273).
This document covers the broker. The harness is `scripts/mqtt5-conformance.sh`; until part 2 lands it is a stub that
prints what it would run.

## 1. The three layers

| Layer | What | Where | Gate |
|---|---|---|---|
| Codec | Packets as bytes: every packet type, property, reason code and malformed form | `crates/mqtt/src/v5/tests.rs`, `crates/mqtt/tests/mqtt5_interop.rs` (fixtures in `crates/mqtt/tests/fixtures/v5/`), fuzz `mqtt5_packet` and `mqtt5_props` | `cargo test`, CI fuzz |
| Broker semantics, host | Each ADR-273 rule as a sans-IO test over the in-memory transport (expiry with a fake clock, mixed-version fan-out, aliases, Receive Maximum, shared groups across shards) | `crates/broker/src/tests.rs` (part 2/3) | `cargo test` |
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
- **urMQTT setup.** A dev image (`deploy/conformance/`, part 2) with the plaintext listener on (P1, ADR-230) in its
  open login mode, `plaintext.allow_from` the host, `plaintext.acl_publish = ["#"]`,
  `plaintext.acl_subscribe` = everything except `test/nosubscribe` (a filter list that covers the suite's topics),
  `plaintext.retain = true`, and the ADR-273 defaults for `[mqtt5]`. Plaintext sessions are never persistent
  (ADR-230), so the three persistent-session tests are expected failures there; session expiry is covered by the
  host tests and by Mosquitto clients over mTLS (section 3), where sessions persist.

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

The urMQTT design passes several of these by construction: 0x93 (ADR-273 rule 7), one delivery per session with
every identifier (rule 17), Server Keep Alive (rule 10 with `mqtt5.max_keep_alive_s = 60` in the conformance image),
the ACL refusal (rule 13), the timer-wheel Will Delay (rule 6).

### Expected-failure list

`scripts/mqtt5-conformance.xfail`, one line per test that is allowed to fail, created by part 2:

```
# suite        test                            phase   reason
client_test5   test_shared_subscriptions       part3   shared subscriptions arrive in part 3 (ADR-273 rule 16)
client_test5   test_subscribe_identifiers      part3   subscription identifiers arrive in part 3 (rule 17)
client_test5   test_offline_message_queueing   always  plaintext sessions are never persistent (ADR-230)
client_test5   test_redelivery_on_reconnect    always  plaintext sessions are never persistent (ADR-230)
client_test5   test_session_expiry             always  plaintext sessions are never persistent (ADR-230); covered over mTLS
client_test    test_offline_message_queueing   always  as above, 3.1.1
client_test    test_redelivery_on_reconnect    always  as above, 3.1.1
```

Rules of the list:
- Columns are whitespace-separated; `suite` is the script name without `.py`, `test` the unittest method name,
  `phase` one of `part2`, `part3`, `always`; the rest of the line is the reason (with the ADR rule).
- A listed test that **passes** is reported (XPASS) and fails the run, so the list only shrinks.
- `part2` entries must be gone when part 2 is merged, `part3` entries when part 3 is; `always` entries need an ADR
  reference. A hang (the timeout) counts as a failure.
- The harness prints one line per test (`PASS`, `FAIL`, `XFAIL`, `XPASS`, `TIMEOUT`) and a summary, and exits non-zero
  on any `FAIL`, `TIMEOUT` or `XPASS`.

## 3. Mosquitto clients

Mosquitto 2.x clients with `-V mqttv5`, over mTLS with the dev certificates (sessions persist there) and over the
plaintext listener. Each line is a scenario of the smoke group `mqtt5` (part 2), with what it checks:

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
codec's fixtures. Part 2 points the same proxy at urMQTT and compares, scenario by scenario, the packet types and
properties urMQTT sends with Mosquitto's (not the bytes: reason codes and announced limits differ by design, ADR-273).

## 5. Running it

```
scripts/mqtt5-conformance.sh --mosquitto     # the baseline above, against a local Mosquitto (part 2)
scripts/mqtt5-conformance.sh --port 1883     # against a booted urMQTT (part 2)
```

Until part 2 the script prints the plan and exits 0.
