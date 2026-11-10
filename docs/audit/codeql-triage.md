# Code scanning triage

The GitHub code scanning alerts (CodeQL for Rust and Actions, OpenSSF Scorecard) are triaged one by
one: each alert's code is read at its location, classified, and either fixed or dismissed with a
specific reason. Nothing is dismissed unread. The log of a triage is a CSV next to this file, one row
per alert: number, rule, location, class, the dismissal reason given to GitHub, and the comment.

| Triage | Alerts | Log |
|---|---|---|
| 2026-11-07, main at v0.4.2 (55d33ca) | 137 open | [codeql-triage-2026-11-07.csv](codeql-triage-2026-11-07.csv) |
| 2026-11-09, main at v0.5.0 (58531b1) | 9 open | [codeql-triage-2026-11-09.csv](codeql-triage-2026-11-09.csv) |
| 2026-11-09, release-v0.6.0 PR (a939046) | 13 open, 4 test code and 9 zero-initialised buffers or test models (PR #11, 8ee635e) | [codeql-triage-v0.6.0.csv](codeql-triage-v0.6.0.csv) |

## Classes

| Class | What | GitHub reason | 2026-11-07 |
|---|---|---|---|
| a | Test vectors and test keys: published known-answer constants (RFC 7914 and the published PBKDF2-HMAC-SHA-256 vectors, RFC 4231 in the boot self-test), fixed salts, keys and nonces in `tests/`, `*_tests.rs`, `#[cfg(test)]` modules, golden-image keys, fuzz targets; assertion messages in tests; deliberate faults in self-tests | `used in tests` | 96 |
| b | Not a secret or not a defect: zero-initialised buffers overwritten before use, the public login decoy hash, the boot-time cost probes and benchmarks (fixed keys over dummy data, outputs discarded), RFC 2104's long-key hashing inside PBKDF2, public signature metadata printed, pointer alerts whose invariant is checked (the SPSC ring's compile-time capacity check, the SQLite shim's handle contract), the CI cache-poisoning pattern on a step that only runs on `pull_request` and checks nothing out | `false positive` | 34 |
| c | A real finding: fixed, not dismissed. It closes when the fix reaches main and the scanner runs again | none | 1 (Scorecard PinnedDependencies: the demo bridge's base image, now pinned by digest) |
| d | True as reported, kept deliberately, reason documented | `won't fix` | 2 (the vendored Limine loaders, checksummed in `vendor/limine/CHECKSUMS`) |
| open | Repository posture (Scorecard: branch protection, code review, age, best-practices badge): the owner's decision, not the code's | left open | 4 |

No hard-coded secret or key was found in a production code path.

## Where the noise is stopped

`.github/codeql/codeql-config.yml` (used by `.github/workflows/codeql.yml` through `config-file`) leaves
out of the analysis: `fuzz`, every `tests` directory, every `tests.rs` and `*_tests.rs` file, and
`tools/builder/test`. Production source is analysed in full with every query.

A `#[cfg(test)] mod tests { ... }` written inside a production file (for example
`crates/cfg/src/passwd.rs`, `crates/plain/src/auth.rs`, `crates/broker/src/sys.rs`,
`crates/mm/src/cached.rs`, `crates/tcp/src/model.rs` declared under `#[cfg(test)]`) is still analysed:
CodeQL has no attribute-based exclusion, and leaving out the file would hide its production code. Such
alerts are dismissed as `used in tests` with the vector or standard named in the comment. A dismissed
alert stays dismissed while its code is unchanged.

The path exclusion relies on every `tests.rs` and `*_tests.rs` being a `#[cfg(test)]` module. Check it
before a new triage (each line must print 1 or more):

```bash
for f in $(git ls-files | grep -E '(^|/)tests\.rs$|_tests\.rs$'); do
  d=$(dirname "$f"); m=$(basename "$f" .rs)
  printf '%s %s\n' "$(grep -h -B3 -E "^\s*(pub(\(crate\))? )?mod $m;" "$d"/*.rs "$d.rs" 2>/dev/null | grep -c 'cfg(test)\|cfg(all(test\|cfg(any(test')" "$f"
done
```

## Re-running a triage

```bash
# 1. The open alerts, one per line
gh api --paginate "repos/zeljan-alduk/urMQTT/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | [.number, .rule.id, .rule.security_severity_level, .most_recent_instance.location.path,
               .most_recent_instance.location.start_line, .most_recent_instance.message.text] | @tsv'
# 2. Read each one at path:line on main; classify it (a, b, c, d or open, above).
# 3. Dismiss a, b and d with a specific comment (at most 280 characters):
gh api -X PATCH repos/zeljan-alduk/urMQTT/code-scanning/alerts/N -f state=dismissed \
  -f dismissed_reason="used in tests" -f dismissed_comment="RFC ... vector, #[cfg(test)] mod tests"
# 4. Fix class c on a branch, with a test where one can be written; record everything in a new
#    codeql-triage-YYYY-MM-DD.csv and add a row to the table at the top of this file.
```

Dismissed alerts with their comments: `gh api --paginate
"repos/zeljan-alduk/urMQTT/code-scanning/alerts?state=dismissed&per_page=100" --jq '.[] | [.number,
.dismissed_reason, .dismissed_comment] | @tsv'`.
