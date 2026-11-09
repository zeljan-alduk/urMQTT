# NOW-15: password accounts at run time (v0.6.0 notes)

ADR-285 to ADR-289 (docs/DECISIONS.md). Configuration format **15**, store schema **6**.

## What changed for operators

- The signed control channel has two new commands: `set-account` (add an account, or replace its hash and class) and
  `remove-account`. `urmqtt-control set-account --id ID (--password-stdin | --hash H) [--class
  full|read-only|write-only] [--iterations N]` hashes the password on the operator's machine (PBKDF2-HMAC-SHA-256,
  random salt, 100 000 iterations by default) and signs only the hash; `urmqtt-control remove-account --id ID`.
  Same mutual TLS identity (`control.service_ids`), offline Ed25519 key, sequence number and validity window as
  `revoke`.
- The accounts log in on the plaintext listener (`plaintext.auth = "password"`) and on the WebSocket listener
  (`websocket.auth = "password"`) beside the image's own accounts, at once, without a reboot. A removed account, a
  changed password or a changed class closes that account's live connections (5.0: DISCONNECT 0x98).
- A class narrows the listener's `acl_*` patterns: `read-only` (no publish, no Will), `write-only` (no subscription).
  Never wider than the listener.
- They are kept on the data disk (database schema 6, table `accounts`, hashes only) and survive reboots.
- Audit lines without secrets: `control: seq N from operator: password account <id> set (class <class>, K run-time
  account(s))` / `... removed (K ... left)`; refusals are `control: message from operator rejected: <reason>`.
  New reasons (counters `urmqtt.control.rejected.<reason>`): `accounts_disabled`, `account_limit`,
  `no_password_listener`, `account_shadows_image`. Bad input is `malformed`.
- Builder page: `limits.max_runtime_accounts` under Limits (shown where an account could log in), texts in the 15
  languages. `urmqtt-config pack` knows the key.

## Configuration

| Key | Format | Default | Range |
|---|---|---|---|
| `limits.max_runtime_accounts` (tag 275, renumbered at integration: 270 is NOW-14's) | **15** | **0** (the control channel refuses account commands) | 0 to 1024 |

An image that does not set it keeps its lowest format and behaves exactly as before. Merge note: format 14 belongs to
another item of the release; `FORMAT_VERSION` is 15 here, and the tests that list valid versions accept 15 (14 is
accepted by the reader like any version between the minimum and the newest, so the merge needs no change there).

## Upgrade and downgrade

- The first boot of a v0.6.0 kernel migrates the data disk to **schema 6**, in one transaction, one way (like 3 to 5),
  whether or not accounts are used. A v0.5.x kernel refuses a schema 6 disk (`schema version 6 is newer than this
  build`): keep a backup snapshot if you may need to go back. A format 15 image needs a v0.6.0 template.
- Nothing else changes until an image sets `limits.max_runtime_accounts`.

## Limits and rules

At most `limits.max_runtime_accounts` accounts; 8 items per message; ids `A-Z a-z 0-9 - _ . :`, 1 to 64; hashes of
1 000 to 100 000 iterations; the image's own accounts, and the service, operator and control identities, cannot be
shadowed (`account_shadows_image`); a change over the limit is rolled back whole. The login admission and the
watchdog's handshake budget are sized for at least the default hash cost, and the decoy for an unknown user costs as
much as the dearest account.

## Tests

`crates/control` (messages, bounds, policy), `crates/plain` (authenticator with run-time accounts), `crates/broker`
(classes on both listeners), `crates/store` (`golden_schema6.rs`: migration from the frozen schema 5, constraints, a
power cut at every write; `golden_schema6_bytes.rs`; `golden_v2.rs`), `crates/cfg`, `crates/config`,
`crates/config-schema`, `tools/config` (format 15, templates), `tools/builder/test/runtime-accounts.test.mjs`, fuzz
`control_account` (seeds in `fuzz/seeds/control_account`, 400 000 runs in 2 minutes) and `control_message`, smoke group
`accounts` (`SMOKE_ONLY=misc SMOKE_GROUPS=accounts`: `accounts-run-time`, `accounts-persist`; both listeners, class,
limit, shadowing, a power cut, replay, no password or hash in the serial log).

## Validation notes

aarch64 smoke group `accounts` passes under HVF and TCG; the plaintext, websocket and control scenarios still pass. The
x86_64 release kernel builds and its clippy is clean; the `accounts` smoke group is skipped under x86_64 TCG (software
emulation makes one 100 000-iteration check take 5 to 8 seconds, so the login rate is below one a second) and should be
run with KVM on the x86_64 VPS: `SMOKE_ONLY=misc SMOKE_GROUPS=accounts scripts/smoke.sh --arch x86_64 --accels kvm`.
`tools/builder` tests: one pre-existing failure outside this item in the headless-browser "result card" test (it needs a
release template ISO), the rest pass with the new module.

## Deliberately not done

Per-account ACL patterns (three classes instead); listing accounts over the network; a bulk import (8 per message, one
account per tool call); password expiry; per-account rate limits; Argon2id (D-16: stays PBKDF2); an Argon2 or other
scheme in the control message; accounts for the TLS listener (certificates are its identities); accounts shared between
disks. Run-time accounts on both listeners share one namespace.
