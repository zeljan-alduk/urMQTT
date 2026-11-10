# v0.6.1: TLS 1.3 and cryptography fixes (internal security review of v0.6.0)

- **Fixed (high): abandoned TLS handshakes could leave the broker able to finish only one handshake at a time,
  until reboot** (R060-C1, ADR-340). The traffic secrets captured for KeyUpdate sat in a global table keyed by the
  ClientHello random, and a handshake dropped after the server's flight (no client certificate needed) never freed
  its entry. After 4096 such handshakes, any two overlapping handshakes evicted each other and one failed. Each
  session now has its own capture, wiped when the handshake ends in any way. Test:
  `crates/tls/tests/secret_capture.rs::abandoned_handshakes_do_not_break_later_overlapping_ones`.
- **Fixed (low): a ClientHello fragmented over several TLS records never completed** (R060-C2, ADR-340): the
  client random was read from the raw first record. It is no longer used; non-TLS input is still refused, now after
  6 bytes instead of 43. Tests: `a_fragmented_client_hello_completes`, `not_a_client_hello_is_refused_after_six_bytes`.
