# Security review of v0.6.0, lens "parsers of untrusted bytes": release notes input

- **TLS KeyUpdate answers are bounded (PARSERS-1, medium, ADR-350).** A device with a valid client certificate
  could send TLS 1.3 KeyUpdate records asking for an update while never reading; each one queued a 27-byte answer
  outside the 32 KiB per-connection output bound, until the heap ran out and the broker stopped. The broker now
  sends one answer for all requests received while it has sent nothing else (RFC 8446 §4.6.3). Peers that use
  KeyUpdate normally see no difference.
