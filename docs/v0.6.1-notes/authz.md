# v0.6.1 notes: security review of v0.6.0, authentication, authorisation and identity (ADR-360 to ADR-364)

For the release step: the changelog is built from this file. Branch `sec/authz`. No configuration format or store
schema change.

## Security fixes

- **High: certificate identity spoofing through a CSR with two CNs (AUTHZ-1, ADR-360).** The broker took the first CN
  that was a UTF8String or PrintableString; `scripts/pki.sh sign-csr` took the first CN of any type and copied the
  CSR's subject. A CSR with a T61String CN `sensor_042` followed by a PrintableString CN `operator` was signed as
  device `sensor_042` and authenticated as `operator`. A subject with more than one CN or a CN of another string type,
  and a SAN with more than one `urn:urmqtt:` URI, now give no identity; `sign-csr` builds the subject itself and
  refuses such a CSR; `pki.sh check` refuses such certificates. Enrollment services: see PROVISIONING.md.
- **Medium: a revocation applied while a device's handshake was between its Certificate and its Finished was not
  enforced on that connection (AUTHZ-8, ADR-361).** Every handshake now checks the revocation list again at its end.
- **Medium: `disallow` did not close a connection that had not sent its CONNECT yet, and such a connection could wait
  for ever (AUTHZ-9, ADR-362).** Those connections are now closed with the sessions, and a connection that sends no
  CONNECT within 60 s of the end of its TLS handshake (WebSocket: of its upgrade) is closed.
- **Medium: a successful login cleared the address's failed-login count (AUTHZ-2, ADR-363).** One account holder could
  guess other accounts' passwords without being locked out. A login no longer clears the count (failures expire with
  `lockout_s`), and a CONNECT from an address that is locked out is refused without being judged, also on connections
  it opened before the lock-out. Behaviour change: a user who mistyped and then logged in keeps the failures in the
  window.
- **Low: a revoked, disallowed or narrowed identity's Will was still published (AUTHZ-4, ADR-364)**, a delayed one up
  to its Will Delay Interval after the revocation. It is dropped now.
- **Low: with accounts of different PBKDF2 iteration counts, the time of a refused login told whether the user name
  exists (AUTHZ-3, ADR-364).** Every login now costs the dearest count of all accounts.

## Operators

- Certificates from `pki.sh` and `make certs` are unchanged in use. A certificate from another CA whose subject has
  two CNs stops working: reissue it with one.
- A client that sends its CONNECT more than 60 s after the TLS handshake (WebSocket: the upgrade) is closed.
