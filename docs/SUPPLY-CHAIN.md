# Supply chain

What urMQTT is built from, how that is recorded, and what is and is not checked
(H9; ADR-190 to ADR-192). Vulnerability handling is in
[VULNERABILITY-HANDLING.md](VULNERABILITY-HANDLING.md).

## 1. Inputs

| Input | Where | Pinned by | Recorded in the SBOM with |
|---|---|---|---|
| Rust crates from crates.io | `Cargo.lock` | lockfile (`--locked` everywhere) | version, `.crate` SHA-256 from the lockfile, license, purl |
| Vendored, patched crates (`cpufeatures` 0.2.17 and 0.3.1, `primeorder` 0.14.0) | `vendor/` | the files | hash of the patched tree, the crates.io ancestor and its `.crate` SHA-256 |
| SQLite amalgamation 3.54.1 (C) | `vendor/sqlite` | `CHECKSUMS` | SHA-256 of `sqlite3.c`, `sqlite3.h`; the upstream zip's SHA3-256 |
| Limine 12.9.4 binaries | `vendor/limine` | `CHECKSUMS` (GPG-verified upstream tarball) | SHA-256 of every file; the upstream tarball's SHA-256 |
| P-256 assembly and table derived from ring 0.17.14 | `vendor/nistz256` | hashes in `vendor/README.md` | SHA-256 of both files; the ring `.crate` SHA-256 |
| Rust toolchain | `rust-toolchain.toml` | the nightly date | name and version |

Not listed because they are not in an image: the fuzz workspace (`fuzz/`, own
lockfile; it is checked for advisories but is not in the SBOM), the host build
tools (clang, xorriso, mtools, QEMU), and the CI actions (pinned by commit SHA,
updated by Dependabot).

## 2. SBOM

`scripts/sbom.py` writes a CycloneDX 1.5 JSON document.

```
make sbom                           # build/urmqtt-VERSION.cdx.json
scripts/sbom.py --check             # validate only
make dist ENV=release               # also writes build/dist/urmqtt-VERSION.cdx.json, covered by SHA256SUMS
```

It needs `cargo` and Python 3 and nothing else (no `cargo-cyclonedx`, ADR-190).
After one `cargo fetch` it runs offline (`cargo metadata --locked --offline`).
The output is deterministic for a commit (UUIDv5 serial number, timestamp
`SOURCE_DATE_EPOCH`). Each Rust component has a property `urmqtt:role`:
`kernel` (linked into an image), `build-time` (proc-macro or build script of
the kernel), `workspace` (our crates), `host-tool` (tests and tools, not in an
image). The metadata component is the image; its properties carry the commit
and the SHA-256 of `Cargo.lock`.

The script **fails** if a vendored file does not match the hash recorded for it
(`CHECKSUMS`, `vendor/README.md`), so the SBOM cannot disagree with the tree.
CI runs `--check` on every change (job `supply-chain`).

In a release (`.github/workflows/release.yml`) the SBOM is built by `make
dist`, so it is in `SHA256SUMS` (and under the minisign signature when the key
is configured), it is a release asset, it is covered by the build provenance
(`subject-path: build/dist/*`), and `actions/attest-sbom` binds it to the ELF,
ISO and raw image as an SBOM attestation:

```
gh attestation verify urmqtt-vX.Y.Z.iso -R zeljan-alduk/urMQTT --predicate-type https://cyclonedx.org/bom
# up to v0.4.1: urmqtt-dev-vX.Y.Z.iso
```

Limits, stated: the SBOM lists what is in the lockfile and `vendor/`; it does
not prove that a crate's source matches its repository (the `.crate` hash is
the registry's). `urmqtt:role` for the vendored crates is assumed `kernel`.
The document was validated by the script's own checks (unique references,
every dependency resolves, hash formats), not against the CycloneDX JSON
schema, which needs a download.

## 3. cargo-vet

`supply-chain/` holds the cargo-vet state. `cargo vet --locked` passes in CI
(and in `make check` when `cargo-vet` is installed). Criteria: the default
`safe-to-deploy` for everything.

How a dependency satisfies it, in order of preference:

1. **An audit by someone we trust, imported.** `supply-chain/config.toml`
   imports the published audits of Google, Mozilla, the Bytecode Alliance,
   ISRG (Divvi Up), Zcash and Embark. `supply-chain/imports.lock` records
   exactly what was imported (so a change in an imported file is a reviewable
   diff, and CI fails on a stale lock). These are audits by other people; we
   rely on them, we did not redo them.
2. **An audit by this project** (`supply-chain/audits.toml`). **There are
   none yet.** Nothing has been invented to make the numbers look better.
3. **An exemption** (`[[exemptions.*]]` in `config.toml`): the crate version
   is not audited by anyone we import. It is trusted on the registry, the
   lockfile pin (a changed version is a diff in review) and `cargo deny`
   (advisories, licenses, sources). That is a weaker statement, and it is
   listed as such.

The vendored, patched crates (`cpufeatures`, `primeorder`) have
`audit-as-crates-io = false`: cargo-vet treats them as our own code, because
they are not the crates.io bytes. The review of such a crate is the diff
against the pinned upstream (`vendor/README.md` says how to produce it).

### Where it stands

[audit/vet-exemptions.md](audit/vet-exemptions.md) is generated
(`scripts/vet-exemptions.py`, checked in CI) and lists every exemption by
role. Summary at H9: of the 67 third-party crate versions linked into a kernel,
**14 are covered by imported audits and 53 are exempt**. Another 22 exemptions
are build-time crates (proc-macros, build scripts) and 65 are host-only (tools,
tests). The acceptance wording of H9, "vet audits are complete", is therefore
met in the sense that `cargo vet` passes and every TCB crate is accounted for
either by an import or by a named exemption; it is **not** met in the sense
that the TCB has been audited: 53 kernel-linked crates are exemptions, most of
them the RustCrypto and rustls families (`aes`, `ghash`, `chacha20poly1305`,
`p256`, `ecdsa`, `crypto-bigint`, `curve25519-dalek`, `ed25519-dalek`, `rustls`, `rustls-webpki`, ...), which are the
crates whose audit matters most (imported audits do cover, among others, `subtle`, `zeroize`, `cipher`, `rand_core`, one `sha2` and one `signature` version).

Why they are exemptions and not audits: auditing a crypto crate is the work of
an auditor with the time to do it (H10 proposes the external audit scope), and
a self-audit by the author of the integration, in the same milestone, would be
worth less than an exemption that says what it is. Reducing the list is
ongoing work, in this order:

1. Re-run `cargo vet regenerate imports` and `cargo vet prune` at each release; new imported audits remove exemptions without any work here.
2. Audit, as a delta where an imported audit exists for a neighbouring version, the small kernel-linked crates (a few hundred lines each) that nobody imports.
3. The RustCrypto and rustls families: external audit (H10), or imported audits when their owners publish them.

### Rules for changes

- A new or updated dependency: `cargo vet` fails until it is audited, covered by an import, or added as an exemption. Adding an exemption is a visible diff of `config.toml`, to be justified in the pull request. For a crate linked into a kernel, prefer not to add it.
- `cargo vet certify` records an audit of ours: only after reading the code (or the diff) against the criteria; the notes field says what was read.
- Never `cargo vet regenerate exemptions` to make a failure go away.
- The example edition (`examples/edition`, NOW-18) is a Cargo workspace of its own, so its `Cargo.lock` is outside
  what `cargo vet`, `cargo deny` and the SBOM read. It may hold no third-party package that the workspace's lockfile
  does not (same name, version and checksum): `scripts/check-lock-subset.py examples/edition/Cargo.lock Cargo.lock`,
  run by the supply-chain job. After a dependency update of the workspace, refresh it with
  `cp Cargo.lock examples/edition/ && (cd examples/edition && cargo metadata --offline >/dev/null)`.

## 4. cargo-deny and the advisory job

`deny.toml`: `advisories` (vulnerabilities, unmaintained and unsound crates
anywhere in the graph, yanked versions: all errors, no `ignore` entries),
`licenses` (an allow list), `bans` (wildcards denied, duplicate versions warn),
`sources` (crates.io only; no git dependencies). CI runs it on every change
(job `deny`), including the fuzz workspace's lockfile for advisories.

`.github/workflows/advisories.yml` runs the advisory check daily against the
current RustSec database, so a new advisory against an unchanged lockfile is
noticed within a day. When it fails it opens one issue (not one per day).
The path from that issue to a fix is in VULNERABILITY-HANDLING.md. An `ignore`
entry in `deny.toml` is allowed only with the advisory id, the reason it does
not apply, and an expiry date, in the same pull request that records the
triage.

## 5. What was run

See docs/PROGRESS.md (H9) for what ran locally and what only runs on GitHub.
