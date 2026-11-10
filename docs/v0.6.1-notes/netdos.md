# v0.6.1 release notes: network stack and denial of service

- **Security (high, NETDOS-1):** a TLS handshake refused while the peer kept its receive window at zero left a
  connection that was never freed (about 500 bytes of heap each, until reboot); enough of them brought the heap
  to its reserve and the broker refused every new connection. A close the broker starts now has a 5 s deadline,
  after which the connection is reset, and TCP gives up a closed connection whose peer keeps its window shut
  after the retransmission bound (ADR-355).
- **Security (medium, NETDOS-2):** the same applied to the plaintext and WebSocket listeners' refusals and to every
  close the broker starts (keepalive expiry, protocol errors); the same deadline covers them (ADR-355).
- New log line: `tcp: N close(s) not finished within 5000 ms reset on core C` (at powers of two).
- `urmqtt-attack` has a `zero-window-close` mode; the `attack_raw` smoke group runs it.
