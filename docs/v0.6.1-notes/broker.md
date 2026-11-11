# v0.6.1 notes: broker semantics (v0.6.0 security review)

- **Fixed (medium, BROKER-1, ADR-375):** an authenticated client that kept sending packets the broker answers itself
  (PINGREQ, a QoS 1 PUBLISH the ACL refuses, a PUBREC) without reading its socket grew its output buffer without
  bound until the heap ran out and the VM stopped. Its input is now held and its TCP window closed once its output
  passes `max_outbound_bytes` + `limits.max_packet_size` + 4 KiB, and resumed once it reads; a client that ignores
  the closed window is disconnected at 2 MiB held. Clients that read are unaffected.
- **Fixed (medium, BROKER-5, ADR-376):** a device's subscriptions in its own scope (`devices/<id>/...`) left their
  trie nodes behind on UNSUBSCRIBE and at the session's end, so SUBSCRIBE/UNSUBSCRIBE churn of fresh filters grew the
  heap without bound. They are now counted and pruned when the last subscription using them goes.
- **Fixed (low, BROKER-2, ADR-377):** `limits.max_inflight_qos1` above 65 535 made the broker spin once that many
  QoS 1 deliveries were unacknowledged. The schema now refuses values above 65 535 and the broker clamps to it.
