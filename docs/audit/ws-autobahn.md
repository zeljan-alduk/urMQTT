# Autobahn|Testsuite: the `urmqtt-ws` frame codec (ADR-272)

**Run:** 2026-11-08, `crossbario/autobahn-testsuite` (AutobahnTestSuite 25.10.1, Autobahn 0.10.9; image
`sha256:519915fb568b…`, linux/amd64 under Docker on an Apple M-series Mac), mode `fuzzingclient`, **all 517 cases**
(spec: [ws-autobahn/fuzzingclient.json](ws-autobahn/fuzzingclient.json), summary:
[ws-autobahn/index.json](ws-autobahn/index.json)), against `crates/ws/examples/echo.rs` at the commit that adds
this file.

## What was tested

The echo example is a std TCP server around exactly the code the kernel runs: `urmqtt_ws::upgrade::{scan, parse}`
with the broker's checks and `urmqtt_ws::frame::Decoder`, each violation answered by a close frame carrying the
decoder's code, server frames from `frame::header`, `frame::close_frame` and `CLOSE_EMPTY`. Two things are the
example's own, because Autobahn needs them and the broker does not:

- Autobahn connects to `/` and offers **no subprotocol**; the broker requires `mqtt`. The example tells the parser
  the request offered `mqtt` (it appends the header before parsing) and answers 101 without the header, so every
  other check of the request runs unchanged.
- Autobahn's echo cases send **text** messages; the broker refuses text frames with 1003. The example runs the
  decoder with `text: true` and checks UTF-8 itself as the bytes arrive (fail fast, cases 6.x). The UTF-8 checker is
  not in the kernel.

## Result

| Section | Cases | OK | Informational | Unimplemented | Non-strict | Failed |
|---|---|---|---|---|---|---|
| 1 Framing (text and binary, lengths) | 16 | 16 | | | | |
| 2 Pings and pongs | 11 | 11 | | | | |
| 3 Reserved bits | 7 | 7 | | | | |
| 4 Opcodes | 10 | 10 | | | | |
| 5 Fragmentation | 20 | 20 | | | | |
| 6 UTF-8 handling | 145 | 145 | | | | |
| 7 Close handling | 37 | 34 | 3 | | | |
| 9 Limits and performance (up to 16 MiB messages) | 54 | 54 | | | | |
| 10 Miscellaneous (auto-fragmentation) | 1 | 1 | | | | |
| 12 permessage-deflate | 90 | | | 90 | | |
| 13 permessage-deflate, parameters | 126 | | | 126 | | |
| **All** | **517** | **298** | **3** | **216** | **0** | **0** |

Every case closed cleanly ("behaviorClose" OK or informational in all 517).

## Deviations, each explained

- **7.1.6 (informational):** "send a 256 KiB message followed by close, then a ping". The outcome is defined by the
  implementation (Autobahn: "if the close frame is processed before the text message write is complete ... the
  message may not be received"). The example answers the message, then the close, and ignores the ping after the
  close, as RFC 6455 5.5.1 requires.
- **7.13.1, 7.13.2 (informational):** close codes 5000 and 65535, "undefined by the spec". The decoder refuses them
  (only 1000-1003, 1007-1014 and 3000-4999 are accepted from a peer) and closes with 1002.
- **12.x and 13.x (unimplemented, 216 cases):** permessage-deflate. The broker never agrees on an extension (ADR-272:
  no decompressor in the TCB, no compression oracle inside TLS), so the client's offer goes unanswered and Autobahn
  records the cases as unimplemented, each with a clean close. This is the intended behaviour, not a gap to close.

## The first run

The first run (same day) had 4 failed and 7 non-strict cases, all in how the **example** used the codec, none in
the codec's rules:

- 1.1.1, 6.1.1, 6.1.2, 9.7.1 failed: an empty text message was echoed as binary, because the example took the
  message type from its first data chunk and an empty message has none. The codec's `Event::End` now carries the
  message's type (`End { text }`).
- 3.2, 3.3, 4.1.3, 4.1.4, 4.2.3, 4.2.4, 5.15 were non-strict: the example dropped the echoes of messages that came
  before a violation in the same read. Everything the decoder hands out comes before the violation (it stops there),
  so the example now answers it first, then closes. The kernel likewise delivers the MQTT bytes that preceded a
  violation or a close.

## Reproduce

```bash
cargo build --release -p urmqtt-ws --example echo
target/release/examples/echo 0.0.0.0:19301 &
docker run --rm --name ws-autobahn -v "$PWD/docs/audit/ws-autobahn:/config" -v /tmp/ws-reports:/reports \
    crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json
```

The spec's URL is `ws://host.docker.internal:19301` (Docker Desktop's name for the host); change the port in the spec
or the example's argument to match. The HTML report is in `/tmp/ws-reports/index.html`.
