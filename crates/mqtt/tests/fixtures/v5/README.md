# MQTT 5.0 capture fixtures

Raw TCP byte streams recorded between real MQTT 5.0 clients and Mosquitto
2.1.2 (Homebrew, macOS arm64) by `scripts/mqtt-record.py`. Each scenario has
`NAME.c2s.bin` (client to server) and `NAME.s2c.bin` (server to client),
one connection per scenario. Every `.c2s.bin` starts with CONNECT (0x10) at
protocol level 5.

Regenerate all of them with:

    scripts/mqtt5-capture.sh            # broker on 28831, proxy on 28832

which starts its own Mosquitto (`listener 28831 127.0.0.1`,
`allow_anonymous true`, `persistence false`), puts the recording proxy in
front of it per scenario, runs the client and checks the CONNECT headers.
The client commands below are run against the proxy
(`-h 127.0.0.1 -p 28832`, left out here). Clients: mosquitto_pub /
mosquitto_sub 2.1.2, paho-mqtt 2.2.0 for Python (what
`uv run --with 'paho-mqtt>=2,<3'` resolved).

Two consecutive runs gave byte-identical files (all clients set their
client identifier). In `paho-session` the packet identifiers depend on
paho's counter and could change with another paho version.

| Fixture | Command | Packets (properties) |
|---|---|---|
| `pub-qos0` | `mosquitto_pub -V mqttv5 -i pub-qos0 -t fx/q0 -m hello` | c2s: CONNECT (Receive Maximum), PUBLISH QoS 0, DISCONNECT (2-byte short form). s2c: CONNACK (Topic Alias Maximum, Maximum Packet Size, Receive Maximum) |
| `pub-qos1-props` | `mosquitto_pub -V mqttv5 -i pub-qos1-props -t fx/q1 -m hello -q 1 -D publish user-property k v -D publish user-property k v2 -D publish content-type text/plain -D publish payload-format-indicator 1 -D publish message-expiry-interval 30 -D publish response-topic r/t -D publish correlation-data abc -D publish topic-alias 3` | c2s: CONNECT, PUBLISH QoS 1 (User Property x2, Content Type, Payload Format Indicator, Message Expiry, Response Topic, Correlation Data, Topic Alias). s2c: CONNACK, PUBACK reason 0x10 (No matching subscribers) |
| `pub-qos2` | `mosquitto_pub -V mqttv5 -i pub-qos2 -t fx/q2 -m hello -q 2` | c2s: CONNECT, PUBLISH QoS 2, PUBREL. s2c: CONNACK, PUBREC, PUBCOMP (2-byte short forms) |
| `pub-connect-props` | `mosquitto_pub -V mqttv5 -i pub-connect-props -t fx/c -m hello -D connect session-expiry-interval 60 -D connect receive-maximum 10 -D connect maximum-packet-size 2000 -D connect topic-alias-maximum 5 -D connect request-response-information 1 -D connect user-property a b` | c2s: CONNECT (Session Expiry, Receive Maximum, Maximum Packet Size, Topic Alias Maximum, Request Response Information, User Property), PUBLISH QoS 0, DISCONNECT. s2c: CONNACK |
| `pub-will` | `mosquitto_pub -V mqttv5 -i pub-will -t fx/w -m hello --will-topic w --will-payload bye --will-qos 1 --will-retain -D will will-delay-interval 5 -D will content-type x` | c2s: CONNECT flags 0x2e (will, QoS 1, retain) with will properties (Will Delay Interval, Content Type), PUBLISH, DISCONNECT. s2c: CONNACK |
| `pub-userpass` | `mosquitto_pub -V mqttv5 -i pub-userpass -t fx/u -m hello -u user -P pass` | c2s: CONNECT flags 0xc2 (username, password), PUBLISH, DISCONNECT. s2c: CONNACK |
| `pub-retain` | `mosquitto_pub -V mqttv5 -i pub-retain -t fx/r -m kept -q 1 -r` | c2s: CONNECT, PUBLISH QoS 1 retain. s2c: CONNACK, PUBACK 0x10 |
| `pub-disconnect-props` | `mosquitto_pub -V mqttv5 -i pub-disconnect-props -t fx/d -m hello -D connect session-expiry-interval 30 -D disconnect session-expiry-interval 0 -D disconnect user-property r s` | c2s: CONNECT (Session Expiry, Receive Maximum), PUBLISH, DISCONNECT reason 0x00 with properties (Session Expiry 0, User Property). s2c: CONNACK |
| `sub-props` | `mosquitto_sub -V mqttv5 -C 1 -W 10 -i sub-props -q 1 -t fx/s/+ -t fx/other -t 'fx/#' -D subscribe subscription-identifier 7 -D subscribe user-property x y`, fed by `mosquitto_pub -V mqttv5 -p 28831 -t fx/s/1 -m to-sub-props -q 1` | c2s: CONNECT, SUBSCRIBE with 3 filters (Subscription Identifier 7, User Property), PUBACK, DISCONNECT. s2c: CONNACK, SUBACK [1,1,1], two PUBLISH QoS 1 (one per overlapping subscription, each with Subscription Identifier 7) |
| `sub-unsub` | `mosquitto_sub -V mqttv5 -C 1 -W 10 -i sub-unsub -q 2 -t fx/n/1 -t fx/n/2 -U fx/n/2 -U fx/never -D unsubscribe user-property x y`, fed by `mosquitto_pub -V mqttv5 -p 28831 -t fx/n/1 -m to-sub-unsub -q 1` | c2s: CONNECT, SUBSCRIBE 2 filters QoS 2, two UNSUBSCRIBE (one filter each, User Property), PUBACK, DISCONNECT. s2c: CONNACK, SUBACK [2,2], UNSUBACK [0x00], UNSUBACK [0x11 No subscription existed], PUBLISH QoS 1 |
| `paho-session` | `uv run --with 'paho-mqtt>=2,<3' python scripts/mqtt5-capture-paho.py --port 28832 --direct-port 28831` (a second, unrecorded paho client on 28831 feeds the subscription) | c2s: CONNECT flags 0x0e (clean start, will QoS 1) with Session Expiry 60, Receive Maximum 20, User Property and will property Will Delay Interval; SUBSCRIBE (Subscription Identifier 42, User Property) `paho/in/#` options 0x1d (QoS 1, No Local, Retain As Published, Retain Handling 1) and `paho/out/#` QoS 2; PUBACKs; PUBLISH QoS 0/1/2 (Message Expiry, Content Type, Response Topic, Correlation Data, User Property x2); PUBACK/PUBREC/PUBREL/PUBCOMP; UNSUBSCRIBE 2 filters (User Property); DISCONNECT reason 0x04 (with will) and Session Expiry 0. s2c: CONNACK, SUBACK [1,2], retained PUBLISH (retain flag kept), PUBLISH with Subscription Identifier and forwarded properties, PUBACK, PUBREC, PUBCOMP, PUBREL, UNSUBACK [0,0] |

## Client quirks seen

- mosquitto_pub 2.1.2 at QoS 1 and 2 (`pub-qos1-props`, `pub-qos2`,
  `pub-retain`) closes the socket without the DISCONNECT its `-d` log says
  it sends; the broker logs "connection closed by client". Those streams
  end without DISCONNECT.
- `-D publish subscription-identifier` is refused by mosquitto_pub
  ("not supported for publish"), as the spec forbids it client to server.
- `-c` together with `-D connect session-expiry-interval` makes
  mosquitto_pub fail with "Duplicate property in property list"; the
  disconnect scenario sets the session expiry through `-D connect` only.
- mosquitto_sub has no options for No Local, Retain As Published or Retain
  Handling; those subscription options are only in `paho-session`.
- No AUTH packet: Mosquitto has no enhanced authentication by default.
