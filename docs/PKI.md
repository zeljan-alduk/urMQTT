# A production PKI for urMQTT (ROADMAP NOW-3)

urMQTT authenticates every client with mutual TLS. In production you run the certificate authority (CA) that issues
the server's and the clients' certificates, and you hold the control key that signs runtime revocations. This page
says how, with `scripts/pki.sh` (OpenSSL 3) and the checks of `urmqtt-config pack`. The development material of
`make certs` is throwaway; never use it for this. The identity lifecycle (bootstrap role, enrollment service,
allowlist) is in [PROVISIONING.md](PROVISIONING.md); the threat model in [SECURITY.md](SECURITY.md).

## Threat model, in two paragraphs

Whoever holds the **operational CA key** can mint any device or service identity: publish as any device, subscribe to
what the ACL gives services, and, with an identity listed in `acl.operator_ids`, read `$SYS` and use the console. The
**control key** together with an identity in `control.service_ids` can revoke any certificate at runtime (and unrevoke,
if `allow_unrevoke` is on). Neither key is ever in the image: the image holds the CA *certificates*, the server's own
key and the control *public* key. So the CA and control keys are the crown jewels and live offline; a lost server key
is bad but bounded (an impostor broker for clients that reach it; rotate the server certificate and revoke the old one
at the clients' side by expiry).

The **server key is in every image** built from it (the image is then a secret, docs/SECURITY.md "image secrecy"). A
device key should be born on the device and never leave it (secure element, TPM); the CA signs its CSR. Revocation in
the image (`tls.revocation_list`) takes effect with the next image; revocation over the control channel takes effect
at once (live connections are closed) and survives reboots on the data disk. A certificate's expiry is the backstop:
keep device certificates reasonably short.

## Where the keys live

| Key | Where | Why |
|---|---|---|
| CA key (`offline/ca.key`) | an offline machine (air-gapped laptop, or a VM without network on an encrypted disk), passphrase-protected (the default of `pki.sh`); two encrypted backups; or an HSM / cloud KMS for larger fleets | it issues every identity |
| control key (`offline/control.key`) | the same, or an HSM / KMS behind `urmqtt-control --sign-cmd` (PROVISIONING.md) | it revokes at runtime |
| server key (`deploy/server.key`) | the build machine, then inside the image | the broker must read it unattended; it cannot be encrypted |
| device keys | the devices | a central copy is a single point of compromise |

`scripts/pki.sh` decrypts the CA key with `openssl pkey` into its private temporary directory (mode 0700, removed when
it exits) for the signatures of one run: run it on the offline machine only.

## Making the PKI

```bash
scripts/pki.sh init ~/urmqtt-pki --org "Example Fleet" --dns mqtt.example.org --ip 203.0.113.10
#   --ca-days 3650 (default), --server-days 397 (default), --no-passphrase (only for tests),
#   --no-control-key (when the control key lives in an HSM: put its control.pub into deploy/ yourself)
scripts/pki.sh service ~/urmqtt-pki backend           # a backend; list it in acl.service_ids
scripts/pki.sh service ~/urmqtt-pki operator          # an operator; list it in acl.operator_ids
scripts/pki.sh device  ~/urmqtt-pki device-001        # a test device (key made here)
scripts/pki.sh sign-csr ~/urmqtt-pki device-042.csr   # a device whose key was born on it
```

What `init` prints, and what goes where:

| File (in `~/urmqtt-pki/deploy/`) | `config.toml` | builder page |
|---|---|---|
| `ca.pem` | `[trust] operational = ["ca.pem"]` | "Operational CA" |
| `server.pem` | `[tls] cert = "server.pem"` | "Server certificate" |
| `server.key` | `[tls] key = "server.key"` | "Server private key" |
| `control.pub` | `[control] public_key = "control.pub"` | "Control public key" |
| `revoked.txt` | `[tls] revocation_list = "revoked.txt"` | not on the page |
| `config-snippet.toml` | these lines, to merge | |

Copy the deploy files into `deploy/prod/` (git-ignored) or choose them in the builder page; **never** `offline/`.
Then `scripts/pki.sh check deploy/prod` (below) and build (docs/DEPLOY.md), or use the page.

The rules the script follows are the kernel's: ECDSA P-256 keys only (the TLS stack has no other), the control key
Ed25519; a client certificate carries its identity as the subject CN **and** as the SAN URI `urn:urmqtt:device:<id>`
or `urn:urmqtt:service:<id>`, so `tls.identity_field` can be `"cn"` (default) or `"san_uri"`; an identity is
`[A-Za-z0-9][A-Za-z0-9._:-]*` (it becomes a topic level: no `/ + #`, no leading `$`); the subject has **exactly one
CN**, a UTF8String or PrintableString, and the SAN exactly one `urn:urmqtt:` URI (the broker gives a certificate with
two CNs, or two such URIs, no identity: ADR-360); serials are random and positive,
so `revoked.txt` holds exactly what `openssl x509 -serial` prints, in lower case. Nothing that exists is overwritten;
private keys are created 0600. Every certificate issued is logged in `issued.tsv` (serial, kind, id, expiry).

## Checking a directory

```bash
scripts/pki.sh check deploy/prod
```

It runs `urmqtt-config pack` on the directory's `config.toml` (or on a minimal one naming its files) as a production
build would: the server certificate must outlive `tls.min_server_cert_days` (60) and the CAs `trust.min_anchor_days`
(365), the PEM kinds, the control key and the revocation list must parse. The Rust checks are not repeated in bash.
On top, a few OpenSSL checks that pack does not make: the server key belongs to the server certificate, the key types,
the CA flag, that the server certificate has a DNS or IP name, that device and service certificates found next to it
chain to a CA here and carry consistent identities, and that no CA or control private key sits in a deploy directory.
Without `urmqtt-config` (not on PATH, no checkout with cargo) it says so and fails: it does not pretend to check.

## Rotating the server certificate

Well before `tls.min_server_cert_days` (the broker warns at 60, 30, 7 and 1 days left, and exports
`urmqtt.tls.server_cert_days`):

```bash
scripts/pki.sh server ~/urmqtt-pki --dns mqtt.example.org --ip 203.0.113.10
# -> deploy/server-YYYYMMDD.{pem,key}; set [tls] cert/key to them, rebuild, deploy, then drop the old files
```

Devices trust the CA, not the server certificate, so nothing changes on their side.

## Rotating the CA (overlap)

`scripts/pki.sh ca ~/urmqtt-pki ca-2` makes a second CA; add `"ca-2.pem"` to `trust.operational` next to `ca.pem`,
deploy, re-issue the devices under the new CA (with OpenSSL directly: the script's `device`, `service` and `sign-csr`
issue under `ca.pem`), and remove the old CA when no device uses it (PROVISIONING.md, "CA rotation with overlap"). A
bootstrap CA for the provisioning role is made the same way and goes into `trust.bootstrap`.

## Revocation

```bash
scripts/pki.sh revoke ~/urmqtt-pki ~/urmqtt-pki/devices/device-042.pem   # or --serial HEX
# -> deploy/revoked.txt; copy it into deploy/prod/ and rebuild: the next image refuses it
urmqtt-control revoke --serial <hex> ...                                  # and now, without a new image
```

## Device certificates at scale

Do not generate device keys centrally. The device makes its key (in a secure element where it has one) and a CSR with
`CN=<device id>`; the factory or the enrollment service has the CA sign it with a subject it builds itself, never the
CSR's copied (a CSR may carry two CNs that two readers take differently, ADR-360; `scripts/pki.sh sign-csr`, for a batch on the
offline machine: `for c in csrs/*.csr; do scripts/pki.sh sign-csr ~/urmqtt-pki "$c"; done`), or, for a fleet that
enrolls in the field, the bootstrap flow of [PROVISIONING.md](PROVISIONING.md): a factory certificate under the
bootstrap CA, a CSR published on `provision/<id>/csr`, the operational certificate returned on `provision/<id>/cert` by
an enrollment service that talks to an HSM or KMS. `pki.sh` is a tool for an offline CA of a modest fleet; past a few
thousand devices use a CA product with an HSM (the identity rules above are what it must follow).

## Testing

`scripts/test-pki.sh` (`make pki-test`, also run by `make check`) makes a PKI in a temporary directory under a test
passphrase, issues and revokes, checks the negative cases (an identity with `/`, a non-P-256 CSR, a CA key in the
deploy directory, a server key that does not match, a 30-day server certificate that pack refuses) and packs the
result into the template ISO and the raw image of `make dist ENV=release` when they are built. It boots nothing.

## See also

[EDITIONS.md](EDITIONS.md) (this tooling and the release key are part of the open edition and apply to both editions),
[SECURITY.md](SECURITY.md) (control channel, image secrecy), [PROVISIONING.md](PROVISIONING.md), [OPERATE.md](OPERATE.md).
