## P1: optional plaintext MQTT for trusted networks (2026-11-01)

A `[plaintext]` section, off by default, opens TCP 1883 without TLS for devices that cannot do it (ADR-229 to ADR-231). What it gives up, and when it is acceptable, is in docs/SECURITY.md.

**Done**

- **Configuration** (ADR-229): all keys of the plan with their defaults in `config.toml`, the runtime blob (format 2; format 1 still reads; untouched keys are not written), the schema (`urmqtt-config schema/show/pack`) and the builder form. Cross-field checks in two implementations compared by tests (allow-list mandatory, `0.0.0.0/0` only as `allow_from_anywhere`, mode-specific keys, identities that hold another role refused).
- **Listener** (ADR-230): the allow-list is checked at the SYN (no SYN-ACK, no state); one table of source addresses for all cores (connections, failures, lock-out); three login modes; lock-out by address; its own admission sized from a boot-time measurement of the password check; sessions in their own namespace (`$plain/<identity>/<client id>`), clean only; the broker's plaintext role (no service, operator or control rights, no `$SYS`, own ACL, packet size, rate, retain); registry allowlist applies; `$SYS/broker/plaintext/*`, boot line, warnings, fingerprint report line.
- **Passwords** (ADR-231): PBKDF2-HMAC-SHA-256 with a salt and 10 000 iterations by default, constant-time comparison, one hash computed on every path; `urmqtt-config hash-password`; the builder hashes in the browser and keeps only the hash in memory.
- **Builder:** the section collapsed with its switch off, risk dialogs, accounts editor with a generated password, 15 languages.
- **Docs:** README, SECURITY.md (what plaintext gives up, when it is acceptable, threat-model entries, residual risks), OPERATE.md, DEPLOY.md, AUDIT.md, PERFORMANCE.md section 8.

**Verified**

- `make check` (nested-worktree wrapper): 902 Rust tests passed, 0 failed, 8 ignored; builder 62 pass, 0 fail, 2 skipped.
- Fuzz: new target `plain_input` (parsers, allow-list, table against a model; 2.3M runs without a finding), `broker_input` now opens plaintext connections (2.4M runs).
- Smoke group `plaintext` (password, lockout, refused, anonymous, ip, limits, registry): 7 of 7 on aarch64 HVF and 7 of 7 on x86_64 TCG; in password mode the TLS scenarios run on the same VM.
- Measurement (PERFORMANCE.md section 8): at 8 000 messages a second TLS and plaintext deliver the same with the same latency; plaintext connects faster; a password login is capped by its admission at about 200 a second per data core. Floods on this rig are not stable and are not a conclusion.

**Not done / open**

- Adding and removing accounts at run time over the signed control channel (needs a message type and a place to keep the hashes across reboots); today a new image, and `disallow` through the registry cuts an identity at once.
- Plaintext against Mosquitto on the VPS (the VPS was out of scope).
- `docs/audit/inventory.md` is stale since H3 and was not regenerated here (the script needs the main checkout's cargo configuration).
- A memory-hard password hash (Argon2) as a second scheme.

## C1e and C1g: the builder page, the release mirror, the pages on aldo.tech and "Try in the emulator" (2026-11-01)

The page that does what `urmqtt-config pack --iso` does, in the browser, with the same Rust code (ADR-225, ADR-226); the mirror of the GitHub releases it loads its template from and the pages on aldo.tech (ADR-227); the optional emulator (ADR-228). **It is live: https://aldo.tech/en/products/urmqtt-builder/** (and the other 14 languages, see below). No release with a template exists yet (v0.1.0 predates the runtime configuration), so the page says so and builds nothing until the maintainer publishes one.

**Done**

- **The module** (`tools/builder/wasm`, ADR-225): the tool's library compiled to WebAssembly, 1.06 MB, no imports and no `unsafe` block, a plain C ABI on buffer handles; `make builder`. The tool's code was moved into the library, not copied (`pack_text`, `sign_pem`, `image::configure_iso_in_place`, `minisign`, `release`, `certs`); the command line gained `check-release`.
- **The page** (`tools/builder/web`, ADR-226): one screen with native modal dialogs, light and dark, labelled controls and keyboard focus tested (Lighthouse accessibility 95 or better), a form generated from the exported schema with every default shown and untouched fields not written, presets, TOML import and export, certificate and key import that says what a certificate is and whether the key belongs to it, state in the address and `sessionStorage` (never a private key), release list with pre-releases marked and releases without a template greyed with the reason, **the signature of `SHA256SUMS` and the template's SHA-256 checked in the browser against the key built into the page**, the ISO built in WebAssembly memory with progress and Cancel, SHA-256 and configuration fingerprint of the result, download as `urmqtt-<ver>-<name>-universal.iso`. 15 languages (`tools/builder/web/i18n`; field names are the TOML keys and the schema's help stays English). **With no usable release** it says so in plain words, keeps the releases there greyed out with their reasons, links to the releases on GitHub and switches Build, Download and the emulator off with the reason beside them.
- **The mirror** (`scripts/mirror-releases.py`, `scripts/mirror/`, ADR-227): hourly systemd timer, nice 19, idle I/O, rate limited, sandboxed, verifies every release before publishing it, writes `releases.json`; a nginx container behind Caddy adds rate limits (`nginx.conf`, `install-web.sh`); `caddy-apply.py` makes the two marked Caddy regions and is idempotent.
- **The pages on the site** (`tools/builder/site`, `scripts/deploy-builder-site.sh`, ADR-227): the Products page and the builder page in 15 languages through the site's own generator, patched by `apply_products.py` (every edit must match exactly once). *Products* is in the header and footer of every page, the sitemap and the home page; the two urMQTT posts and their cards link to the builder in the page's language. The owner's decision of 2026-11-01 to publish and link at once replaced the first plan (unlisted until a template exists, with a listing hook; both removed).
- **The emulator** (`tools/builder/emulator`, `emulator.js`, ADR-228): spike first (numbers in ADR-228), then QEMU compiled to WebAssembly (GPL-2.0, pinned upstream files checked by SHA-256, four bytes patched for a POPCNT bug, source offer in `SOURCE.txt`), loaded only on a click, no network, boots the configured image in about 9 s with the countdown skipped and checks that the kernel prints the page's fingerprint. `make builder-emulator`; the runtime is a build output and is not committed.
- README ("Configure and download your ISO"), `docs/SECURITY.md` (the builder page), `docs/DEPLOY.md` section 10 (install, check, roll back), screenshots in `docs/screenshots/` (the live page as it is today, and the full flow against a throwaway-key test mirror).

**Live on aldo.tech (2026-11-01)**

- Mirror: `urmqtt-mirror.timer` (hourly), `urmqtt-mirror-web.service` (container on `127.0.0.1:18089`, image pinned by digest), `/var/www/aldotech.io/urmqtt/releases/`; first run 15:02 UTC listed v0.1.0 without a template. Installed files are identical to the repository's (checked by SHA-256).
- Caddy: two marked regions (headers for the builder pages, the mirror and emulator handles, `/products/` redirect); `caddy validate` before every reload; four reloads (the status of all URLs compared after the first and after the publish, spot checks after the others).
- Site: generator patched, `publish.sh` now excludes `/urmqtt/releases/` and `/_x/`; published 15:36 UTC after a dry run of the rsync (0 deletions, 69 new files, the rest rewritten as on every publish). **Backups:** `/root/aldotech-site-backup-20261101` (the generator as it was), `/root/aldotech-site-backup-20261101-extra/` (original Caddyfile, `build.py.before-products`), `/etc/caddy/Caddyfile.bak-20261101-urmqtt` (original) and `-step2` to `-step4` (before each later edit), `/opt/aldotech-site/publish.sh.bak-20261101`. Rollback: `docs/DEPLOY.md` section 10.
- Hiding the pages without removing them: publish with `URMQTT_PRODUCTS_LISTED=0`.

**Verified**

- `make check`, as an equivalent script (nested worktree, see C1 below): fmt, typos, arch-leaks, `cargo vet`, host and kernel clippy for both architectures, workspace tests (824 passed, 0 failed, 8 ignored), the mirror job's 62 tests against a fake GitHub with throwaway minisign keys, the Caddy edit's 10 tests, shellcheck of the new scripts, and the builder's 45 tests: the module against the command line byte for byte (also the real 63 MB template), the form logic, the page in headless Chrome (15, among them a build whose bytes equal `urmqtt-config pack --iso`, the privacy of requests and storage, a tampered template blocked unless overridden, dialogs, phone and dark layout, **the emulator booting the page's image and printing the page's fingerprint**), the page without a usable release (4), the 15 language files (same keys and placeholders, nothing left in English).
- The site: before and after the publish, the status of the 140 URLs (the sitemap and a few fixed ones: 139 x 200 and my 404 probe) is identical; 30 new URLs (15 Products, 15 builder) answer 200 and the sitemap lists 170; a build of the patched generator into a temporary directory equals the old output once the additions are taken out (250 of 250 files).
- The live pages in headless Chrome, all 15 languages: renders, `releases.json` loads, no console error, no request to another site, cross-origin isolated, the Products link in header and footer, the "no release" state in the page's language.
- Live, with the real template ISO chosen from this computer: the page stops at the unsigned file and asks, builds after the override, and the emulator boots it on the live site (ready after 8.9 s, fingerprints equal).
- Live, in a labelled random-token directory (removed): a mirror signed with a throwaway key, the page built with that key: the 63 MB template comes from the site through Caddy, the signature is verified in the browser, the build takes 5 to 18 s, the downloaded file has the SHA-256 the page shows, no request carries key material. In the real mirror directory a template-shaped test file (removed) was served by nginx through Caddy with `immutable` caching, the sums with `must-revalidate`, `meta.json` with 404 and a single `Server` header.

**Not done / open**

- **A signed release with a template is needed for the builder to build from the mirror** (`urmqtt-template-<ver>-universal.iso`, `SHA256SUMS`, `SHA256SUMS.minisig`, signed with the release key, which this work never touched). Until then the real path (mirror, key built into the page) was proven with throwaway keys and the real template from the computer, not with a release. `.github/workflows/release.yml`'s template step has never run.
- The 13 translations of the page and the Products texts were written by an AI agent and checked by tests and spot checks, not by native speakers.
- The emulator: BIOS only (UEFI crashes in it), no network, a desktop browser with isolation and about 1.5 GB (Chrome tested, Firefox and Safari not), the upstream POPCNT bug is patched here but not reported.
- Headless Chrome on the development Mac stalls on any aldo.tech page over HTTP/3 (the site advertises it); with QUIC off everything loads. Presumably this machine's UDP path; not investigated.
- The site's build now copies a 36 MB emulator directory into its output on every publish (rsync skips what is unchanged).
- `.github/workflows/ci.yml`'s `builder` job has never run (nothing was pushed).

## C1 — Runtime configuration (C1a to C1d and the docs of C1f, 2026-11-01)

The kernel is built once and the configuration is data (ADR-215 to ADR-219). The web builder page (C1e) and the emulator (C1g) came after, see the entry above.

**Done**

- **C1a, the blob.** `crates/cfg`: the `urmqtt-cfg` format (magic, version, length, tag/length/value records in ascending tag order, SHA-256 fingerprint, optional detached Ed25519 signature), the one field table (70 fields with defaults, ranges, help text and dev-only flags), a fail-closed decoder, the cross-field checks, BLAKE2b for the hashes Limine checks. `config-schema`: `pack` (TOML plus PEM files to a blob, defaults filled in, expiry rules, control key, revocation list) and `schema_json` (the web form's schema). Tests: round trip, canonical form, every single bit flip refused, structural attacks, signature, slot discovery; an empty configuration packs to the defaults; every field has a default and help text; `parse` and the kernel-side validator agree on every integer range, every enum and 22 cross-field cases. Fuzz targets `cfg_blob` (new) and `config_parse` (now also requires that anything packable passes the kernel's checks): 20 s each, nothing found.
- **C1b, the kernel.** The kernel reads the slot as a Limine module before anything else, on aarch64 and x86_64: no compiled-in configuration, and **one release kernel for every `ENV` but `dev`** (the aarch64 ELFs built with `ENV=release`, `prod` and `bench` in one tree have the same SHA-256; checked on aarch64 only). A release kernel refuses `env = "dev"`, a plaintext port and the other dev-only options. Boot prints `config: fingerprint ... (n bytes, unsigned | signed by key id), env=...`. An empty or absent slot boots on the defaults and refuses to serve (`refusing to serve: no server certificate and key`); a present but invalid slot is fatal with the key and the reason (never replaced by defaults). `CONFIG` is a handle over a write-once `.bss` arena (no allocator before the heap; sizes are the field table's maxima), `log::MAX_LEVEL` an atomic. `mkiso.sh` packs `deploy/$ENV/config.toml` (or `--config`, `--empty-config`) with `urmqtt-config`, so `make iso/dist ENV=...`, CI and the VPS flows work as before. The installer copies the slot it booted with into the installed disk.
- **C1c, the installed disk.** The installation image carries an unconfigured empty slot (marker `DISK`), so its hash in the ISO does not depend on the customer's keys. `urmqtt-disk update-boot` keeps the disk's configuration (`--config`, `--keep-config`, `--replace-config`), `info` prints its fingerprint, `create --config`.
- **C1d, the tool and the template.** `urmqtt-config pack | show | verify | slot | schema`, `--sign`. `pack --iso TEMPLATE --out OUT` replaces both slot copies and the 24 module hashes in place; the result is byte for byte the ISO `mkiso.sh --config` builds. `make template` / `make dist` / `make dist-universal` produce `urmqtt-template-<version>-universal.iso` (release kernels, empty configuration); `make dist ENV=dev` run in a clean checkout lists it in `SHA256SUMS`. `.github/workflows/release.yml` checks it is there (not pushed, not run). The CI jobs no longer stage certificates for the `prod` kernel build.
- **C1f, docs.** README (Configuration: making a configured image), `docs/DEPLOY.md` (1b: the template ISO), `docs/SECURITY.md` (Configured images: what is attested; a patched ISO has no official hash; fingerprint; optional signature, default off), ARCHITECTURE, DISK-FORMAT, AUDIT, OPERATE, VERIFICATION, ADR-215 to ADR-219.

**Verified**

- `make check`, run as an equivalent script because this worktree is nested in the repository (cargo merges two `.cargo/config.toml` files and the Makefile's rustflags then appear twice, which rustc rejects; the bare-metal steps passed the full flag list through `RUSTFLAGS`): fmt, typos, the arch-leak check, workspace clippy `-D warnings`, kernel and dbworker clippy for aarch64 and x86_64 with and without `selftest`, workspace tests (785 passed, 8 ignored, 0 failed). Also `cargo vet --locked`, shellcheck (no new findings), actionlint, Miri on `urmqtt-cfg` and `urmqtt-config`.
- QEMU smoke, aarch64 under HVF: hardening group 14/14, storage group 79/79, the install, time, crash and dp-bench scenarios 29/29 (`install-vm-boots` shows the installer's fingerprint on the installed disk), boot, fault, W^X, `smp8` and the new configuration scenarios (packed non-default configuration, signed, tampered slot refused, empty slot refuses to serve) and the three release-kernel scenarios (refuses a dev configuration, refuses a production configuration that asks for the plaintext port, serves a production configuration with TLS and no plaintext).
- QEMU smoke, x86_64 under TCG: boot (UEFI, BIOS), fault, panic and `x86-disk-q35` with the fingerprint line, the four configuration scenarios and the three release-kernel scenarios, hardening 14/14, storage 79/79.
- Universal ISO (HVF plus TCG): `pack --iso` on the template equals the direct build; the patched ISO boots on aarch64 UEFI, x86_64 UEFI and BIOS with the configuration; the installer on each machine installs a signed non-default configuration and the disk boots on all three paths with the same fingerprint and setting (17/17). The template ISO of `make dist` itself (release kernels): verifies; unconfigured it boots and refuses to serve; configured with the production configuration by `pack --iso` it serves TLS on aarch64 UEFI, x86_64 UEFI and BIOS (8/8).
- Reproducibility: `make repro` (prod, with throwaway certificates staged as CI does): kernel ELF, ISO and raw image identical in two worktrees at different depths; `scripts/repro.sh prod --universal`: both kernels, the universal ISO and the raw image identical.

**Not done / open**

- `make smoke` was not run end to end as one command (about 150 scenarios per architecture; the groups above ran separately, with `SMOKE_PORT` because other jobs on this machine hold the default port). The x86_64 TLS-heavy TCG suites (`service` scenarios with `mosquitto` clients) were not run. aarch64 under TCG was not run (HVF only, as asked).
- (Done in C1e, see above: the WebAssembly build of the tool's library; the file reads are closures.)
- `pack` does not check that the key matches the certificate or that the certificate chains to a CA (the TLS stack fails at boot if the key does not match); expiry is checked.
- The signature has no pinned expected key (ADR-219); "sign by default?" is answered no.
- The audit inventory (`docs/audit`) was already out of date before this work (x86 crates and others missing) and is not regenerated here; the new `unsafe` (the configuration arena, `crates/config/src/store.rs`) is covered by Miri and will appear when it is.
- The release workflow's template step has never run; it builds the x86_64 kernel on the arm64 runner, which CI did not do before.
- ADR numbers 215 to 219 may collide with the robustness work done in parallel (resolve at merge).

## PERF/ROBUST — single flow, QoS 0 overload and the watchdog (2026-11-01)

Goal set after X11: find and fix the causes behind its findings. Decisions ADR-221 to ADR-224; numbers, method and the honest list of what is
left in `docs/PERFORMANCE.md` section 7; raw files `docs/perf-results/urmqtt-x11v-{before,after,step-*}.txt`, `mosquitto-x11v-same-session.txt`,
`local-wan-rig.txt`.

**Causes found (with evidence in PERFORMANCE.md 7.1)**

- A **lost wake-up** in `MqttService::poll` (the drained ready list overwrote the connections just put back): a subscriber that fell behind once was never served again, QoS 0 to it was dropped until a PINGRESP - "delivered 0/s" in 4 of 6 single-flow runs on the VPS. Fixed.
- **TCP threw away every segment after a loss** (in-order receive only), had a 16 bit window, a 64 KiB send queue and counted ACKs instead of bytes. Now: bounded out-of-order queue per connection and per core, SACK blocks, window scaling / SACK / timestamps through the SYN cookie (options in the low bits of our timestamp value; stateless until the final ACK), send queue = 2 x cwnd up to 1 MiB, byte-counting congestion window. Host tests (16 new), fuzz target extended (2 M runs clean), H3 model test unchanged and passing.
- The **dispatcher slept until the 10 ms tick** (no RX interrupt on virtio-net): 0-10 ms per pause. Now polls every 200 us while connections exist (ADR-224): ping through the rig 13.1 -> 7.4 ms.
- Frames dropped for a full NIC queue: core 0 now holds up to 4 096; rings 2 048; spare frame buffers returned when quiet (this also repaired the `storm` smoke).
- QoS 0 loss now **counted per cause** (`$SYS/broker/messages/dropped/*`, `frames/dropped/*`, `status`, a warning line per core per 10 s).
- **Watchdog**: the budget is **running time** (late ticks, lock waits including a wait in progress, close-up 1 ms ticks for a long handler, confirmation at the next tick; KVM steal time read where the host offers it, Contabo's does not). Production `action = "drop"` unchanged.

**Results on the Contabo VPS** (same load host, same day, 24-30 runs each): connections lost per run 7-16 -> 0 (flood), watchdog aborts 148 in 30 runs -> 0 in 24; one 64 B flow 1.9k -> 23.7k published/s (Mosquitto 29.3k), 1 KiB 0 -> 3.9k (5.4k); 16 pairs flood 24.7k -> 43.2k (Mosquitto 31.4k). **One flow is still not faster than Mosquitto**; see the open items (lock wait of 4-7 % of a data core, up to 27 % in a window; SACK on our sending side; RX interrupt).

**The VPS** is back on the production ISO built from this tree (`v0.1.0-90-g120da49`, `deploy/prod` unmodified; the commit after it only adds this line): console `URMQTT READY`, `openssl s_client` from the build server completes TLS 1.3, `$SYS/broker/version` as above. Temporary images, the SSH secret, the served ISO directory and the generator's directory (with the CA key) were deleted; Mosquitto ran on Debian 13 for the same-session comparison before that.

**Not done / open**: heap lock contention (per-CPU caches above 2 KiB), SACK-driven recovery on our sending side, a receive interrupt, handshake/idle/fan-out not measured again, the shared load host (steal 58-77 %) limits every cell, bare metal.


## X11 — Performance on the real VPS, with Mosquitto on the same VPS (2026-11-01)

First release scope (VPS only). Method ADR-213; every number, caveat and the findings are in `docs/PERFORMANCE.md`; raw output in `docs/perf-results/` (`urmqtt-prod.txt`, `urmqtt-bench.txt` and `.pass1.txt`, `urmqtt-bench-log.txt`, `mosquitto.txt`, `mosquitto-idle*.txt`; tables with `scripts/x11-report.py`).

**Done**

- **Load generator.** `urmqtt-loadgen` has a `pubsub` mode (publishers, subscribers, topics, QoS 0/1, payload, fixed rate or flood, in-flight window, end-to-end latency stamped in the payload, `RESULT` line, its own CPU use, reasons for lost connections), `--keepalive`, and prints a `RESULT` line and its CPU for `handshake`; `hold` no longer waits for each close. Nothing else changed; no host tests touch it (a binary with `test = false`); `cargo clippy -p urmqtt-loadgen` is clean.
- **Images and configurations.** `scripts/mkbench.sh --x11` (prod configuration, ADR-082 handshake limits, publish rate lifted, `svc-*` identities with the backend's `fleet/#` rights) and `--x11-watchdog-log`; `scripts/mosquitto/urmqtt-x11.{conf,acl}` and `scripts/x11-mosquitto.sh` (Debian 13, Mosquitto 2.0.21, same CA/server certificate, TLS 1.3 with urMQTT's two suites, mTLS, ACL, no persistence).
- **Suite.** `scripts/x11-bench.sh` (guarded run of the whole matrix from a Linux host: nice 19, two pinned CPUs, waits for the host's load, stops if the web server on the shared host answers slowly, records the host's steal) and `scripts/x11-report.py`.
- **Run on the Contabo VPS (4 vCPU EPYC, KVM)**, from the build server 15 ms away: urMQTT `prod` as it stood, `bench-x11`, `bench-x11` with the watchdog in log mode, Debian 13 with Mosquitto, then **the production ISO restored** (console `URMQTT READY`, `openssl s_client` completes, `$SYS/broker/version` v0.1.0-74-g794f607). Temporary images, the served ISO and the temporary ssh key deleted.

**Results** (median of three; generator-limited figures are lower bounds; see PERFORMANCE.md for ranges, caveats and the rest)

- Full mTLS handshakes/s at 32/64/128 clients: urMQTT prod 185/262/333 (limits as shipped; 202-286 errors at 128), bench 169/278/413, Mosquitto 82/140/184 (its single thread 70-84 % busy). Server side: 260 us of TLS work per handshake (console).
- Idle connections: urMQTT 0.50-0.66 KB of kernel heap each, 19 975 held (generator 10 KB each); Mosquitto 26.8 KB of process growth each at 5 000, 10 000 and 20 000 (`mosquitto-idle3.txt`; the earlier attempts are invalid, see PERFORMANCE.md 3.2).
- Latency, 800 msg/s, 64 B, p50: urMQTT 14.0 ms (QoS 0), 14.8 (QoS 1); Mosquitto 21.4 and 39.5; RTT 15 ms; tails equal within noise.
- Offered load, 16 pairs, QoS 1: urMQTT delivers more at the top (5 204/s against 4 630/s at 16 000/s offered); QoS 0 64 B flood: urMQTT 18 280 delivered/s (24 299 published), Mosquitto 28 977 (its one core at 101 %).
- Fan-out 1 to 100 at 5 000 deliveries/s: both complete, p50 16.6 ms (urMQTT) against 99 ms (Mosquitto).

**Found**

- The 20 ms handler watchdog (`action = "drop"`, the production default) **dropped live connections** under load on this VPS: `watchdog: core N input handler over budget: 37-111 ms > 20 ms (action: Drop)` every couple of seconds, while the console's `longest stall` of the cores was 50-170 ms. The vCPU was not scheduled; the handler was not slow. With `action = "log"` the same sweeps lost no connection in any of 20 runs (the `drop` image: 1-8 per run at 300 msg/s per publisher and above). Not changed here (a design decision: measure in running time, or a stall-aware drop rule).
- One TCP flow through urMQTT carries 0.7 MB/s (1 KiB messages) or about 3 000 small messages/s with stalls of seconds, 2 to 8 times less than Mosquitto. Leads, not established: 16-bit window without scaling, `frames dropped for a full NIC queue` (39 per 5 s), retransmissions.
- The 1 000-subscriber fan-out and every flood row are limited by the generator (a shared VM with 60-70 % CPU steal); they are not capacity figures.

**Not done / honest limits**

- No calibration of the generator alone, no second source address, no more than 20 000 idle connections or 128 handshake clients, no dp-bench scaling on the VPS, no bare metal, no Intel. The Mac cannot reach the VPS, so every figure carries the build server's noise.
- The production-limits column covers handshakes only (the shipped image has no identity that may publish at speed).
- The Mosquitto 20 000-connection figure needed a longer keep-alive in the generator (the first attempt measured the keep-alive of connections opened more than 90 s before the pings started, not the broker).


## H6 — SQLite as an unprivileged component (2026-11-01)

SECURITY-PLAN H6, on both architectures. ADR-210 (design, what is and is not isolated), ADR-211 (interface and validation), ADR-212 (build). Two commits: the user-mode infrastructure with a hello worker, then SQLite moved in. **Closes the part of gap H0-W8 that was the privilege of SQLite; it does not close the fuzzing half (H5), and it is not a claim about wrong answers or speculative leaks** (SECURITY.md, "The database worker").

**Done**

- **The worker.** `crates/dbworker` is a separate static program (own linker script at 0x400000, no kernel symbol, no allocator) containing SQLite 3.54.1 unchanged, its libc shims, a dispatcher and a VFS shim whose callbacks are twelve system calls. Built by the kernel's `build.rs` (nested cargo, own flags: BTI but no PAC on aarch64, small code model on x86_64) and embedded; the kernel links no SQLite any more (`nm` of the kernel ELF: only the Rust proxies). aarch64 image 700 KiB.
- **User mode.** aarch64: EL0 with its own `TTBR0` tables (disabled by `EPD0` except during a call), `PAN`, `PXN` on every user page, BTI at EL0, SCTLR hardening of EL0, an entry that works whether the kernel runs on `SP_EL0` or `SP_EL1`, interrupts masked until the `eret`. x86_64: ring 3 with GDT user segments, TSS `rsp0`, a DPL 3 gate (`int 0xf0`), a second PML4 sharing the kernel's upper half, `CR3` switched per call, `SMEP`/`SMAP`, `swapgs` and `AC` clearing in the common exception path, 16-byte stack alignment as the ABI wants.
- **Protocol.** `urmqtt-store::remote` (the 32 SQLite functions `db.rs` uses, as calls; binds and resets ride with the step, a row comes back whole) and `vfs::syscall` (12 calls, checked); `usys` holds the formats with host tests. `db.rs`, `store.rs`, `backup.rs`, `scrub.rs` and every SQL string are unchanged.
- **Failure handling.** A fault or a 30 s overrun restarts the worker; the DB core reopens the store from the WAL (`open_or_restore`), tells the data cores the transaction failed and goes on; more than 5 restarts a minute and storage is out of service until the next boot while the broker serves from memory.

**Tests**

- `cargo test --workspace`: 729 passed. The whole store suite (131 tests) passes **directly linked and through the protocol** (`cargo test -p urmqtt-store --features loopback`: the worker's code in process, calling the kernel's real `vfs::syscall` on the same window). New: `usys` protocol (4), `vfs_syscall` (5: hostile file numbers, lengths, offsets, sizes, sleep, log), user page descriptors and the user mapper on both architectures, GDT/IDT user entries.
- Smoke `worker-contain` (kernel read/write/jump, privileged instruction, write to own code, jump into data, null, endless loop: all contained, kernel word intact, `PAN` or `SMEP+SMAP` asserted) and `worker-fault` (rows committed, more uncommitted, the worker made to fault on the DB core, the store back with exactly the committed rows): aarch64 HVF and TCG, x86_64 TCG.
- Storage group (`SMOKE_ONLY=storage`, 79 scenarios, every one of them runs SQLite in the worker): aarch64 HVF 79 passed, 0 failed, aarch64 TCG 76 passed, 0 failed (`grow-online` is skipped under TCG: no MSI-X), x86_64 TCG 79 passed, 0 failed. Hardening group: aarch64 HVF and TCG 32 passed, 0 failed; x86_64 TCG 14 passed, 0 failed. Default suite on aarch64 HVF (final kernel): **136 passed, 4 failed; the four are the `storm` scenario**, whose host-side load generator stalls at 0% CPU on this machine with the pre-H6 kernel too (same stall, same connection counts: 2128 against 2067 admitted; killed by hand after 20 minutes), so that scenario is unproven here either way. `mqtt-persist` (retained message, persistent session and queued message across a restart, over mTLS) passes on aarch64 HVF and, run standalone, on x86_64 TCG; the rest of the x86_64 default suite (TLS-heavy, about 15 minutes per scenario under TCG) was not run.
- Bugs found by the tests on the way (all fixed): a 1 MiB row buffer in the kernel heap starved the `storm` scenario (118 connections admitted; rows over 4 KiB are now fetched at their exact size); an interrupt between setting `ELR_EL1` and the `eret` sent the worker to a kernel address (TCG scsi-boot; HVF never hit it); a lazy reset of a statement stopped mid-row kept a table locked; x86 entered the worker with a stack pointer the ABI does not allow (SSE `movaps` faulted).

**Cost** (aarch64 HVF, `test=db-bench`, same VM, direct-linked kernel before, worker after; the disk work is identical: 1572 writes, 319 flushes)

- **Entering and leaving user mode:** 1.1 us per round trip (20 000 empty calls, `worker-contain`, HVF). `test=db-bench` makes 10 505 calls and 1 689 VFS system calls for its 5 100 inserts and spends 141 to 148 ms inside the worker, so the mode switches alone are about 12 ms of it (8%); the rest is SQLite and the disk flushes inside the system calls.
- **`db-bench`, six runs of each kernel, interleaved, HVF** (a quieter host than the first set, which spread from 23k to 47k ops/s with other VMs running and showed no difference beyond that noise): 5 000 inserts in 50 transactions, best / median: **54.7k / 53.3k ops/s with the worker against 61.9k / 58.4k direct** (-11.6% / -8.7%; 1.83 ms per commit against 1.62 ms); one insert per transaction: 2 307 / 2 126 against 2 319 / 2 148 ops/s (-0.5% / -1%: the flush dominates). Disk writes (1 572) and flushes (319) are identical, as they must be.
- **`backup-bench`** (23 MiB database, backup in 16-page steps while a writer commits; one run each, the first set): commits during the backup mean 533 us (was 532), max 2.3 ms (was 3.2); a 16-page step mean 930 us (was 1 081), longest 4.6 ms (was 4.7); commits alone 676/s (was 650/s). The whole copy as **one call** takes 635 ms (was 514 ms, +23%: 6 024 pages, a VFS system call each way per page).
- **Telemetry batches** do not touch SQLite (the log is Rust over the disk layer) and are unchanged; the DB core now also spends the mode switches above.
- **x86_64:** not quotable. Under TCG a round trip is 11.6 us and means nothing; the cost that is specific to x86 (a `CR3` write without PCID flushes the whole TLB at each entry and exit) is **not measured on KVM**.

**Not done / honest limits**

- No fuzzing of the worker or the protocol decoders beyond host tests (H5 / gap H0-W8). No KPTI, no PCID: x86_64 flushes the TLB at each entry and exit (cost not measurable under TCG; **not measured on KVM**); no measurement on real hardware.
- The kernel trusts the worker's *answers* (SECURITY.md): an empty revocation list from a compromised worker un-revokes certificates.
- PAC keys are shared on aarch64 (the worker has no PAC, but can sign with the kernel's key); NMI on x86_64 is not supported while a call is entering.
- Rows are limited to 1 MiB and 64 columns; binds to 1 MiB. `max_packet_size` is 4 KiB in every shipped configuration.
- VHE (entry at EL2) is untested, as before. The nested worktree still needs `RUSTFLAGS` set by hand to build the aarch64 kernel.


## H7 — time security (closed 2026-11-01)

Nothing new to build: the lower bound (ADR-050, H1) and SNTP with median consensus, per-step and total bounds and kiss-of-death handling (ADR-100, T1) cover the H7 scope. NTS (RFC 8915) stays out of scope and is a documented residual: with plain SNTP a man in the middle that controls every answer can move the clock by `max_step` in total after boot. `docs/AUDIT.md` question 3 is updated and `deploy/prod/config.toml` carries a commented `[time]` example (no servers by default: an operator picks IPv4 literals).
