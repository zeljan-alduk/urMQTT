# Test plan: urMQTT v0.6.0 on two real VPSes

Status: plan only, nothing here has been run. Written 2026-11-11 for the owner, who will work from a laptop in the field.
The exact commands, account identifiers and image ids are in a private appendix outside the repository
(`~/urmqtt-vps-test-appendix-v0.6.0.md`); this file has none of them.

## 1. Purpose and the release rule

v0.6.0 was only ever run on the host and in QEMU. The internal security review and the critic both put the same gap
first: **no real KVM hypervisor, no real VPS network, no soak.** This plan closes as much of it as two rented machines
allow, and produces the numbers for the next blog post.

**Release rule.** The tag stays **v0.6.0** as long as everything found can be fixed without changing a byte of the
shipped images: documentation, `KNOWN-ISSUES`, tests, tooling that is not in the images, advice about configuration.
A change to the kernel, the template or the shipped tools means **v0.6.1** (never reuse a tag for different bytes,
docs/RELEASE.md section 6; a v0.6.1 is a pre-release too). The decision table is in section 9.

## 2. The machines and what they limit

| | Contabo | netcup |
|---|---|---|
| Architecture | x86_64, 4 vCPU (AMD EPYC Zen 1), 8 GiB, KVM | aarch64, 2 vCPU (Neoverse N1), 3.9 GiB, KVM |
| Role now | production instance, runs the v0.5.0 image | Debian 13 with the bench tools |
| How an image gets onto it | custom image from a URL, then reinstall | user ISO attach plus power cycle through the SCP API, or the installer ISO |
| Console | no serial; a web VNC exists (to be checked for keyboard input) | none; use the diag-serve ISO and the virtio-gpu console report |
| Control API | no IP restriction known | **restricts calls to registered source IPs** (it answered 401 whenever the owner's IP changed) |
| Offline access to the disk | rescue system (to be checked) | attach a Debian live ISO as CDROM (to be checked), or the rescue system |

Consequences that shape everything below:

1. **Only one of the two machines can run urMQTT at a time**, because the other is the load generator and needs Debian.
   Each urMQTT block therefore ends in a reinstall of the machine. A reinstall costs 15 to 40 minutes and is the real
   schedule driver.
2. **Mosquitto needs the measured machine to be Debian too**, so the Mosquitto baselines happen first, while both are
   Debian, with no swaps.
3. **A/B updates, the one-way store migration and the console passphrase need an installed disk**, not the
   ISO-as-disk image Contabo boots from. They are tested on **netcup**, which can use the installer ISO.
4. **The disk passphrase cannot be typed on either VPS** (no serial console). It is tested as a negative case only:
   the sealed broker must refuse to serve (section 6, T9).
5. **Secure Boot, a vIOMMU and a TPM do not exist on these VPSes.** They are tested as "refuses or ignores cleanly",
   never as "works" (T9, T10). Claiming otherwise in the blog post would be wrong.
6. **The per-address limit (1024 established connections) will block the load generator**, which is one address
   holding up to 20 000 connections. The bench images must set `limits.max_connections_per_ip = 0`
   (`mkbench.sh` already does) and one separate test checks the default (T6).

## 3. Field logistics

The owner will be away with a laptop. The plan is built so that the laptop is a window, not a worker.

- **Everything long runs on the VPSes, in `tmux`, and writes to disk there.** The laptop only starts, polls and pulls.
  A closed lid, a lost hotspot or a sleeping Mac must never stop a measurement. Every script is resumable and every
  result file is complete or absent.
- **Build everything before leaving**, at the desk, on mains power, with the fans free: the bench ISOs, the attack
  tool, the load generator, the templates, the Debian live ISO. No kernel builds in the field (the laptop overheated
  at load 44 once; `nice -n 15` and three build jobs are the limit if one is unavoidable).
- **The netcup API checks the source IP.** In the field the IP changes. Two options, do one before leaving: (a) route
  the SCP calls through an SSH SOCKS proxy on the web host (`ssh -D`, `HTTPS_PROXY`), whose IP is registered once in
  the SCP panel; or (b) register the field network's IP when known. Contabo's API needs no registration.
- **Pre-stage the long file transfers**: upload the netcup ISOs to its media store and put the Contabo image sources at
  an unguessable temporary URL before leaving, then delete them after (the ISOs carry the test PKI; section 10).
- **Power and heat.** Keep the laptop on mains when it must stay awake (`caffeinate -dimsu`). On battery, prefer
  check-ins: start, close the lid, come back to read results. Do not run local fuzzers, QEMU or the test suites in the
  field.
- **Network.** A phone hotspot is enough for ssh and the APIs; nothing in the plan needs more than a few MB per hour
  except pulling result files at the end.
- **A status line every 30 minutes** while a block runs: block name, step, last result, disk and memory on the VPS.

## 4. Safety and rollback

| Risk | Protection | Way back |
|---|---|---|
| Contabo is the production instance and is replaced several times | tell users first, or accept downtime; the v0.5.0 image and the v0.4.2 rollback image stay in the Contabo image list | `reinstall` with the production image (the v0.6.0 production image is made at the end, see section 10) |
| netcup ends up with a broken installed disk and no console | the snapshot `before-urmqtt-install` of the original OS exists; every installer run is preceded by checking the snapshot list | revert the snapshot offline, or reinstall Debian through the image setup |
| A test locks the machine (sealed disk, `iommu = require` on a VPS) | those tests are last on a machine, followed by a reinstall anyway | reinstall |
| An attack scenario trips the provider's abuse detection | raw floods (`syn-flood`, `ack-flood`, `rst-flood`) at low rates and short durations, between our own two machines only; read both providers' acceptable-use terms first; if in doubt, skip the raw floods and keep the application ones | stop the run; contact support |
| Test keys left on a VPS | the PKI is the throwaway test PKI of `deploy/prod`-style bench images, never a production key; the bench ssh key opens only these installs | section 10 cleanup |
| A result is lost | each run writes `results/<label>.txt`, `.console`, `.ss`; a copy is pulled after every block | rerun that block only |

Hard rules carry over: nobody reads or uses the release signing key, `deploy.sh` of the site repository is never run,
and no cloud resource other than the two rented machines is created.

## 5. Images and tools to prepare at the desk

1. **Bench images from the published v0.6.0 template, not from a local rebuild**, so the bytes under test are the
   release's: `mkbench.sh --no-build --x11` for each machine's static address, then
   `urmqtt-config pack <bench config> --iso urmqtt-template-v0.6.0-universal.iso`. One ISO per machine.
2. **Production-style image for the end state**, packed the same way from the production config (done once, last).
3. **Installer variants for netcup**: the template packed with `--install-default` for the clean install, and a v0.5.0
   installer for the upgrade test (T12).
4. **The Debian live ISO** (arm64) with `urmqtt-disk` on it or reachable, for offline slot work on netcup.
5. **Tools on both generators**: `urmqtt-loadgen`, `tools/attack`, `x11-bench.sh`, `x11-console.py`, `x11-report.py`,
   `x11-capture.sh`, Mosquitto 2.0.21 from the same script as before, `mosquitto-clients`, `tmux`, `tcpdump`, `iperf3`,
   and the operator and device certificates of the bench PKI.
6. **An orchestrator script** (to be written when this plan is approved) that runs a named block end to end inside
   `tmux`, records every step with a timestamp, and can resume. It is the one new piece of code the plan needs.
7. A dry run of the whole flow on the local QEMU rig first, with a short suite, to catch script errors before they cost
   a 30-minute reinstall.

## 6. Test catalogue

Every test has a pass criterion that can be decided from a file, not from a feeling. "Compare with v0.5.0" means the
`e053399` results of 2026-11-08/09 in `docs/perf-results/x11-2026-11-07/`.

### Boot and platform (both machines)

- **T1 Boot and environment.** The kernel boots from the bench image and reaches `listening`. Record the full boot log
  (the console report on netcup). Pass: no panic, no watchdog report in the first 10 minutes; the lines for entropy
  source, time, queue pairs, receive interrupt (`armed sleep(s)` count above 0 after load), IOMMU state, boot slot
  state and the build line (`build: 0.6.0 ... formats up to 23`) are all present and as expected. **Open item from
  v0.5.0: the receive interrupt was not confirmed on netcup; this test settles it and records why if it is not
  active.**
- **T2 Network.** IPv4 reachability and MTU from the other VPS; `mtu-probe`; ARP behaviour on the provider network;
  record whether the NIC offers multiqueue with RSS (the `net: one queue pair: <reason>` line). Pass: the line is
  present and the broker serves.
- **T3 IPv6 on a real /64.** Both providers hand out an IPv6 block. Configure the address statically
  (`network.ipv6 = static`), then test dual stack between the two VPSes: mTLS publish/subscribe over IPv6, the
  metrics endpoint from an IPv6 allow-list entry, a Neighbour Discovery exchange with the provider's router. If the
  provider sends router advertisements, test SLAAC too. Pass: a round trip over IPv6 from the other machine and
  nothing unexpected counted as dropped. This has never run outside QEMU's router.

### Function (both machines)

- **T4 Protocol smoke on real network.** mTLS QoS 0, 1 and 2, MQTT 5 including shared subscriptions and subscription
  identifiers, retained, will, WebSocket (`wss`), the plain port with an account. Use `mosquitto_pub/sub`, the Paho
  suite where it runs, and `urmqtt-loadgen`. Pass: every case as in the QEMU smoke.
- **T5 Run-time accounts.** Add, change and remove an account through the signed control channel from the operator
  machine; connect on the plain and WebSocket listeners; remove it and confirm the live connection is cut; restart the
  VM and confirm the account is still there (store schema 6). Pass: all steps as documented.
- **T6 Per-address limit, the default.** A separate image with the shipped default (1024). From the other VPS open
  1100 connections from one address. Pass: 1024 stay, the rest get no answer, the refusal counters in `$SYS` and the
  metrics match, and closing connections frees places. Then a count of what a NAT-heavy site would see.
- **T7 Metrics.** Scrape the Prometheus endpoint from the allow-listed address and confirm a non-listed address gets
  nothing; run a real Prometheus (a container on the generator) for an hour against the broker and look for gaps and
  cardinality. Pass: no series explosion, scrape time stable under load.
- **T8 Outbound log shipping.** A TLS collector on the generator, the broker ships its log over TLS 1.3; kill the
  collector and bring it back. Pass: reconnects with backoff, no growth of memory.

### The platform features that cannot fully work here

- **T9 Sealed and refused cases (netcup last, then reinstall).** `storage.disk_key_source = "console"` must leave the
  broker unreachable and say so; `devices.iommu = "require"` on a VPS with no IOMMU must refuse to boot with a clear
  message; `devices.iommu = "auto"` must boot normally with the IOMMU reported as absent. Pass: each behaves as
  documented and a reinstall recovers the machine.
- **T10 Secure Boot and TPM.** Only record what the firmware reports (Secure Boot state, TPM presence) and confirm an
  unsealed image boots. No enforcement claim is made from this.

### A/B update, migration and recovery (netcup only, installed disk)

- **T11 Clean install, A/B layout.** Install v0.6.0 with the installer ISO; first boot reserves the second slot. Pass:
  `gpt: standby boot slot reserved`, slot status shows two slots.
- **T12 The real upgrade path.** Install **v0.5.0** with the installer, fill it with data (sessions, retained messages,
  an account), power off, boot the Debian live ISO, update with the v0.6.0 tool (`update-boot` for a single-slot disk),
  boot v0.6.0. Pass: schema 5 to 6 migration reported, every retained message and session still there; then try to
  boot the v0.5.0 kernel on the migrated disk and confirm it **refuses** it with the documented message.
- **T13 A/B stage, confirm, rollback.** From the live ISO stage a second slot (a rebuilt v0.6.0 with a changed
  configuration, or a deliberately bad kernel); boot it; (a) let it confirm and check `slots status`, (b) a bad slot
  that never confirms must roll back by itself within the trial limit, (c) operator-triggered rollback.
- **T14 Power cuts.** Power-cycle through the API at the points the QEMU test used (during staging write, after the
  write, in the trial boot). Pass: the machine always comes back on a bootable slot with the data intact.
- **T15 The known hole.** The A295-W1 case (a kernel that dies before its block driver is counted) cannot be provoked
  safely; document that it was not tested.

### Performance and soak (both machines)

- **T16 Mosquitto baseline, the same day** (block 1): the full suite for Mosquitto 2.0.21 on each machine from the
  other. This removes the "Mosquitto was measured days apart" caveat of the last post.
- **T17 urMQTT v0.6.0, the full suite** (`handshake throughput latency fanout idle sweep single`, `REPS=3`,
  `CONSOLE=1 SS=1`) on each machine from the other. Pass: no cell more than 10 percent below the v0.5.0 median
  without an explanation, zero lost connections, no watchdog reports. Specific questions: does the QoS 1 and QoS 0
  gain on one ARM core hold, does the interrupt change the single-flow number, what does multiqueue do where it is
  offered, and does the ARM handshake noise (366 to 1501 per second) and the 1.1 s tail reproduce (capture with
  `x11-capture.sh` and keep the pcap).
- **T18 Attack tool against the real network** (both machines, from the other): `slowloris` per listener,
  `zero-window-close`, `half-records`, `max-packets`, `topic-flood`, `sub-flood`, `keepalive-abuse`, `identities`,
  `established-flood`, and at low rate the raw floods. After each: connections and heap back to the pre-run level,
  the broker still serves a probe client. This is the check that the three high findings stay fixed on a real
  network. Pass: nothing remains allocated; counters match the attacker's numbers.
- **T19 Handshake abandon storm.** Many handshakes opened and abandoned (the CRYPTO-1 shape) for 30 minutes, then a
  normal load. Pass: handshake rate afterwards equals the rate before.
- **T20 Soak.** 12 hours minimum, 24 if the schedule allows, on each machine: a fixed offered load (16 pairs at a few
  hundred messages a second, QoS 1, 1000 idle connections), a trickle of new connections and a reconnect storm every
  hour, the metrics scraped each minute. Pass: heap and per-core memory flat within 1 percent after the first hour,
  no retransmission growth, no watchdog or late-tick growth, the retained and session counts as expected. A trend,
  not a threshold, is the result.
- **T21 Chaos.** Power cycle the VM under load, twice. Pass: persistent sessions and retained messages recover, the
  broker serves again within the boot time, no corruption report.

### Documentation walk

- **T22 First hour, as a new user.** On a fresh VPS follow `docs/FIRST-HOUR.md` literally with a stopwatch and fix the
  text where it lies. Pass: a clean run, or a list of corrections.

## 7. Schedule

The numbers are planning figures from the last comparison (about 90 minutes per broker for the suite, 15 to 40
minutes per reinstall).

| Block | State | What runs | About |
|---|---|---|---|
| B0 | desk | section 5, dry run on QEMU, API reachability from a different network | 4 to 6 h |
| B1 | both Debian | T16 Mosquitto on Contabo (generator netcup), then on netcup (generator Contabo) | 3.5 h |
| B2 | Contabo urMQTT, netcup Debian | T1 to T8, T17, T18, T19 against Contabo | 5 h |
| B3 | Contabo back to Debian, netcup urMQTT (ISO) | T1 to T3 on arm64, T17, T18, T19 against netcup | 5 h |
| B4 | netcup installed disk | T11 to T14, T9, T10 | 3 h |
| B5 | soak | T20 and T21 on netcup (installed) and, if time, Contabo | 12 to 24 h |
| B6 | end state | production image on Contabo, Debian or urMQTT on netcup as the owner decides, cleanup, T22 | 2 h |

About two and a half days of wall clock, of which the owner's own attention is a few minutes per block. B5 runs
unattended; B2 and B3 are the places the owner should be reachable, in case a reinstall hangs.

## 8. What gets recorded

Per block a directory `results/<block>/` on the generator holding the raw suite files, the broker console and `$SYS`
samples, `ss` samples, packet captures for the handshake tail, the orchestrator log with timestamps and the boot logs.
After every block it is copied to the laptop and committed (raw files, no keys) to
`docs/perf-results/vps-2026-11-xx/`. Tables and figures come from `x11-report.py` and `x11-charts.py`, extended with
v0.6.0 and with Mosquitto of the same day; the charts keep the style of the last post.

## 9. Decision table: v0.6.0 or v0.6.1

| Finding | Action |
|---|---|
| Data loss, a corrupted store, a disk that does not boot, a rollback that does not roll back | **v0.6.1**, tested again from T11 |
| A security finding in code that ships (remote DoS, authentication or ACL bypass, a leak that survives T18 and T19) | **v0.6.1**, with an advisory, handled as in docs/VULNERABILITY-HANDLING.md |
| A performance regression above 10 percent against v0.5.0 with a cause in the code | **v0.6.1** if the fix is small and safe; otherwise KNOWN-ISSUES and the next release |
| A wrong default that hurts a common deployment (for instance the 1024 per address limit) | configuration advice and release notes first; **v0.6.1** only if the default itself must change |
| A tool bug in a shipped tool (`urmqtt-disk`, `urmqtt-config`) | **v0.6.1** (the tools are release assets) |
| Documentation, test and bench-script problems | fix on `main`, no release |
| A feature that does not work on KVM but is off by default (IOMMU, Secure Boot, passphrase) | document as untested on VPS, no release |

If v0.6.1 is needed: one batch of fixes, the same release day checklist, the same signing path (the `release`
environment approval), and the blog post tells both stories.

## 10. Cleanup and the end state

1. Delete from both providers every image and ISO that carries the bench PKI, and from the temporary URL host any file
   served to Contabo. Remove the bench ssh key from both machines or reinstall them.
2. Contabo ends on a production image of the owner's choice: the v0.5.0 image that is there now, or a new v0.6.0
   production image packed from the published template with `deploy/prod` (the exact procedure of the last
   production update). **Replacing production is the owner's decision at that point.**
3. netcup ends on Debian 13 (the bench machine) unless the owner wants urMQTT left running.
4. Record what ran and what did not in `docs/PROGRESS.md` and `docs/KNOWN-ISSUES.md`, and fix the claims in the
   changelog and the review report that the tests contradict.

## 11. The blog post that follows

A new post after the runs, in 15 languages, as a draft first and published only on the owner's "odobri i objavi".
Working title: *urMQTT 0.6.0 on two real VPSes: what held up, what did not, and Mosquitto the same day.* Outline:

1. The one-paragraph result, including what failed, written last.
2. Setup in three lines (same machines and method as the earlier posts; Mosquitto measured the same day this time).
3. The comparison charts in the established style: handshakes, flood throughput, single flow, QoS 1 sweep, latency,
   idle memory, now with v0.4.2, v0.5.0, v0.6.0 and Mosquitto per machine.
4. What the real KVM showed that QEMU did not: the receive interrupt, multiqueue, IPv6 on a /64, the handshake tail.
5. A/B update, migration and power cuts: the actual runs, the actual timings.
6. The soak: the memory and counter curves, with the honest length of the run.
7. What was attacked and what the broker did.
8. Limits: two machines, no bare metal, no Secure Boot or IOMMU or TPM, one operator; still not an independent audit.
9. If a v0.6.1 happened: why, and what changed.

## 12. Decisions needed from the owner

1. **Downtime of the Contabo production instance** during B2 and B6: accepted, or schedule it.
2. **Registering an IP for the netcup API**, or approval for the SSH SOCKS route through the web host.
3. **Whether raw packet floods run at all**, given the providers' terms, or only the application scenarios.
4. **Soak length**: 12 or 24 hours.
5. **End state of Contabo** (section 10).
