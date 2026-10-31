# urMQTT roadmap after M17

This joins three specifications into one order of work:

| Track | Specification | Detailed plan | Milestones |
|---|---|---|---|
| Security assurance | [PROMPT-security.md](../PROMPT-security.md) | [SECURITY-PLAN.md](SECURITY-PLAN.md) | H0–H10 |
| Storage | [PROMPT-storage.md](../PROMPT-storage.md) | [STORAGE-PLAN.md](STORAGE-PLAN.md) | S0–S8 |
| Platforms: x86_64, one multi-arch ISO, bare metal | [PROMPT-x86_64.md](../PROMPT-x86_64.md) | [X86-PLAN.md](X86-PLAN.md) | X0–X16 |

Written 2026-10-29 against commit `8186a61`. Nothing here is implemented yet.

## The result

1. **One multi-platform ISO.** A single file, `urmqtt-<env>-<version>.iso` (and one raw GPT disk image), boots on:
   - aarch64 UEFI;
   - x86_64 UEFI;
   - x86_64 legacy BIOS.

   It runs in VMs (KVM, Proxmox, clouds, QEMU) **and on bare-metal hardware** (first target: an Intel PC with 16 GB). The image stays an appliance: kernel, configuration and certificates are inside, nothing is configured after boot, and there is no way to log in. Builds stay bit-for-bit reproducible and signed.
2. **No filesystem: raw disk access, on one disk.** Persistent data lives in a raw partition of the disk urMQTT boots from, after the boot partition, accessed directly by the kernel. It holds a superblock, a region table, fixed regions for SQLite (DB, WAL, journal) and a per-core telemetry log. There is no filesystem code to attack or corrupt.

   The storage track adds what a filesystem would otherwise give:
   - offline tooling (`urmqtt-disk`);
   - aligned layout v2;
   - online growth;
   - discard;
   - in-disk backup;
   - scrubbing;
   - optional encryption at rest.

   The track itself adds no filesystem.
3. **Demonstrably secure.** The aim is an audit package an external auditor can use without questions: runtime revocation and an allowlist without new images, differential and conformance testing of the custom TLS and TCP code, KASLR and allocator hardening, SQLite isolated at EL0, Secure Boot, SBOM and a vulnerability process.

## Principles across the tracks

- **Security first.** Where the plans conflict, PROMPT-security wins unless the user approves otherwise in an ADR.
- **aarch64 must not regress.** After every milestone: all smoke scenarios, `make bench`, bytes per idle connection and reproducibility.
- **One disk, and it is ours** (decision 6). urMQTT keeps its data on the disk it booted from, after the boot partition, and never touches any other disk. Previous content of that disk does not matter. urMQTT's own state is never lost silently. Every on-disk change is proven crash-safe by fault injection.
- **Verify, don't assume.** Every claim in README and docs points to a measurement or a test. Bare-metal claims are only made for machines in `docs/HARDWARE.md`.
- **One shared mechanism per concern:**
  - CPU feature detection and dispatch (X0) serves the crypto optimisations (X0b, X9) and disk encryption (S7);
  - fault injection (S1) serves every on-disk procedure;
  - fuzzing and differential testing serve H2, X9 and S8.

## Where the tracks overlap (owned by one milestone)

| Concern | Owner | Others reference it |
|---|---|---|
| Data-disk safety: signature scan, the self-test only on an identified disk, explicit disk selection | **S1** | X12 |
| Secure Boot and signed loaders | **H8** | X12 (bare metal needs it) |
| Cross-arch hardening policy (CET, KASLR, stack protector) | **H4** | X3 implements the x86 baseline |
| Wall-clock policy (lower bound, SNTP) | **H7** (lower bound already in H1) | X4 (TSC, kvmclock) |
| Disk format v2 | **S2** | X8 cross-arch test, X13 NVMe/AHCI topology |
| Discard on NVMe and AHCI | **S4** | X13 |
| DMA isolation on bare metal (IOMMU) | **H4b** | X12–X14 |
| Crypto dispatch | **X0** | X0b, X9, S7 |

## Order

The order is chosen so that analysis comes before change, safety gaps close
early, the disk format settles before it is shared across architectures, and
bare metal comes before optimisation.

| Phase | Milestones | Why here |
|---|---|---|
| 1. Baseline | **H0**, **S0** | inventory, gaps and the byte-level disk spec; no behaviour change |
| 2. Foundation | **X0** | arch facade and dispatch, so later work is architecture-neutral |
| 3. Close the biggest gaps | **H1** (+ H7 lower bound), **S1**, **S1b** | runtime revocation, allowlist, expiry checks; host disk tool, fault injection, single-disk model; the self-installing ISO (VM-tested here, bare metal in X12) |
| 4. Quick win | **X0b** | ARMv8 hardware crypto on aarch64 (today all software) |
| 5. Prove the custom code | **H2**, **H3**, **H5** | TLS and TCP assurance, Miri, Kani, sanitizers |
| 6. Disk format v2 and features | **S2**, **S3**, **S4**, **S5**, **S6** | settled before x86 shares the format |
| 7. x86_64 | **X1**–**X8** | port with full parity and cross-arch data disks |
| 8. Mitigations on both architectures | **H4** (+ H4b), **H6**, rest of **H7** | KASLR, stack protector, MTE, allocator hardening, SQLite at EL0 |
| 9. One ISO, trusted boot | **X10**, **H8** | the multi-platform ISO; Secure Boot and signed loaders |
| 10. Bare metal | **X12**, **X13**, **X14**, X15 (optional), **X16** (continuous) | the Intel PC: USB boot, `hwreport`, NVMe/AHCI, its NIC |
| 11. Speed, encryption, release readiness | **X9**, **S7**, **H9**, **X11**, **S8** | optimisations measured on real hardware; encryption with measured overhead; SBOM; numbers and docs |
| 11b. Remote operation (user request 2026-10-30) | **O1**, **O2** | `$SYS` introspection and a console over MQTT, so a VNC session is no longer needed; done before the rest of phase 11 |
| 11c. Live mode (user request 2026-10-30) | **O3** (done, ADR-061, ADR-062) | the ISO's first entry runs from RAM with no disk, as an opt-in ephemeral mode |
| 11d. Diagnostic (user request 2026-10-30) | **O4** (done, ADR-063) | the third boot entry: hardware detection and RAM/disk benchmarks |
| 11e. Time (user request 2026-10-31) | **T1** | SNTP: a wall clock that is corrected, not only read once from the RTC |
| 12. Audit | **H10** | the audit package covers everything above |

About 38 milestones in all. Each ends as before: tests green, commit, PROGRESS
entry, ADRs, and a report. The work stops after each milestone for the user's
go-ahead.

## Decisions taken (user, 2026-10-29)

The user accepted every proposal ("everything as proposed, following best practice"):

1. **Order:** the phases above, as written. Bare metal (phase 10) comes before the x86 optimisations, and storage v2 (phase 6) before the x86 port.
2. **X0b:** ARMv8 hardware crypto on aarch64 early, right after X0. It changes aarch64 numbers upwards.
3. **Limine:** vendor the x86 Limine binaries and build the `limine` host tool from its checksummed C source. ADR-055 records that this overrides PROMPT.md §2 (ADR-043 is the universal image layout).
4. **S2 migration: offline.** The kernel reads only the current layout and refuses an older one with a clear message naming the fix. `urmqtt-disk migrate` converts offline, with the safeguards listed in STORAGE-PLAN S2.
5. **H2 session tickets: random keys that rotate.** A new key comes from the CSPRNG every 12 h and the previous key is still accepted for 12 h more. Tickets live at most 12 h, so none outlives its key. The keys exist only in memory: never on disk or in the image, and zeroised when retired. Tickets do not survive a broker restart; the reconnect after a restart is a full handshake, which admission control absorbs (M16).

6. **One disk: the boot disk is the data disk** (user decision 2026-10-29, refined the same day). urMQTT uses only the disk it booted from, and that whole disk is its own: what was on it before does not matter. **No other disk is ever read for data or written.** This overrides PROMPT-storage §0 ("never format over a non-blank disk") and replaces today's separate data disk. Design, following common appliance practice (STORAGE-PLAN §2a):
   - **Layout:** GPT with the EFI system partition first, then one urMQTT data partition (its own partition type GUID) up to the end of the disk. The data layout of DISK-FORMAT.md lives inside that partition.
   - **First boot:** the image carries only the ESP. On the first boot the kernel:
     - moves the backup GPT to the real end of the disk (the image is smaller than the disk);
     - assigns a fresh random disk GUID (every copy of the image starts with the same one);
     - adds the data partition and formats it.

     Each step is crash-safe and idempotent.
   - **The boot disk is identified exactly** from Limine's boot-volume information (GPT disk UUID / MBR id), never guessed.
   - **One artifact:** the multi-platform ISO is hybrid, so the same file is booted as a CD for a quick look, or written (`dd`, cloud image import) to the machine's disk for real use. Booted from read-only optical media there is nowhere to persist, so a production image refuses to serve and says so; a dev image may run from RAM.
   - **Kernel updates** replace the contents of the ESP and keep the data partition (`urmqtt-disk update-boot`, offline; A/B boot entries with rollback as a later step).
   - **urMQTT's own state is never lost silently:** a damaged data partition is refused or restored (S5), never re-formatted as new.

7. **The ISO installs itself** (user decision 2026-10-29: it must be able to install itself and be properly bootable). Design in STORAGE-PLAN §2b, milestone **S1b**:
   - The boot menu (Limine) has two entries: *urMQTT* (the default after a short timeout) and *Install urMQTT on this machine's disk*. Choosing the install entry at the console is the explicit, destructive operator action. There is no other input, and the kernel adds none.
   - **Target:** the machine's single installable disk (not the boot medium, not optical, not removable). Several candidates mean refusal with a list, or a configured serial number. Before writing, the target (model, serial, size) is shown for 30 s; power off cancels.
   - **What is written:** the installer writes exactly what `dd` of the image would write: protective MBR, GPT and the ESP, byte-identical to the raw image, and checks that by reading it back. The data partition then comes from the normal first boot, so installing and `dd` share one code path.
   - **Afterwards:** a power-off with "remove the installation medium". The installed disk boots by UEFI (removable-media path `\EFI\BOOT\BOOT*.EFI`, so no firmware variables are needed) and, on x86, by BIOS.
   - **Production:** the kernel still ignores its command line, except the single word `install`, which only the hash-pinned install entry passes. An ADR records this narrow exception and SECURITY.md gets a threat-model entry: physical access to the boot menu can erase the target disk, which an attacker with physical access can do anyway.
   - **This is the one exception** to "never touch another disk" (decision 6): it applies only when booted from the installer entry.

Still open: the Intel test PC's hardware inventory (TODO.md), which decides the order of X13/X14.

## O1, O2 — Remote operation over MQTT (user request, 2026-10-30)

**O1, `$SYS` introspection.** Retained topics under `$SYS/broker/` refreshed every
10 s: `version`, `uptime`, `arch`, `cpu/cores`, `cpu/busy/<core>`,
`memory/{total,used}`, `disk/{total,used}`, `clients/{connected,total}`,
`subscriptions`, `retained`, `messages/{received,sent}`, `connections/refused`,
`tls/server_cert_days`. A request/response form (`$SYS/query/info` with an MQTT 5
Response Topic) returns the same as one JSON document. Readable only by
identities with the `operator` role (ACL); ordinary devices still cannot
subscribe to `$SYS`.

**O2, console over MQTT.** A virtual serial port: kernel log lines are published
to `$SYS/console/out` (a bounded ring, replayed to a new subscriber); lines
published to `$SYS/console/in` go to a small command set (`status`, `log level`,
`reboot`, `help`), operator role only. No shell and no arbitrary code. Rate
limited, every command audit-logged.

Both need an ACL role for operator identities and a ready MQTTX connection
profile (client certificate, subscribed to the topics above).

**Status (2026-10-30): implemented**, see ADR-060, PROGRESS.md "O1, O2" and docs/OPERATE.md.

## O3 — Live mode in RAM (user request, 2026-10-30)

The boot menu has two entries: *live* and *install*. Live must not need a disk:
the kernel reserves a configurable share of RAM (`storage.ram_percent`, default
10, with a floor and a ceiling) as an in-memory block device and builds the
data partition, SQLite and the telemetry log on it through the same block
interface as a disk. It is explicit and loud: a banner and `$SYS` flag say
*EPHEMERAL, data is lost on reboot*; the reserved share is subtracted from the
connection budget; prod refuses it unless the config says
`storage.mode = "ram"`. Installing to a disk stays the way to persist.

## O4 — Diagnostic boot entry (user request, 2026-10-30)

**Status (2026-10-31): implemented**, see ADR-063 and PROGRESS.md "O4". Deviation: the installer leaves no scratch region at the end of the disk (the data partition runs to the end and the backup GPT lives there), so an installed disk has no free space and its write test is skipped with the reason.

A third menu entry, *diagnostic*, that shows what the system detects (CPU model,
cores, features and crypto units, RAM, PCI devices, disks, NICs, time source) and
measures RAM (read/write MB/s, access latency) and disk (sequential read/write,
random 4 KiB IOPS, latency), drawn on the framebuffer as panels and bars, with
the same numbers as JSON on the serial port. Safe by default: read tests only.
The write test touches only unallocated space (a scratch region the installer
leaves at the end of the disk, found through the region table); with no free
space, or an uninstalled disk, it asks for an explicit `WIPE` confirmation.
Never writes from the end of a disk blindly: the data partition ends at the end
of the disk and its backup GPT lives there. No fragmentation work is needed: the
disk has fixed regions and no filesystem, an SSD's controller owns placement,
RAM is mapped virtually and large contiguous blocks are reserved at boot. TRIM
(UNMAP) is left for freed regions as a later option.

## T1 — SNTP wall clock (user request, 2026-10-31)

Today the wall clock is the firmware RTC read once at boot plus uptime, floored
at the image's build time (ADR-009, H7): never corrected, and unknown (so
certificate checks and control messages are refused) when the RTC is wrong.
T1 adds an SNTP client (RFC 4330, UDP 123, over the existing UDP path): one
query at boot and then periodically (`time.servers`, `time.interval`, default
1 h, none by default in dev), several servers with a majority/median so one bad
server cannot move the clock. Rules: the clock never goes below the build-time
floor or backwards by more than a bound (`time.max_step`), a large forward step
is applied once at boot only, small drift is slewed; NTP responses are
rate-limited and checked (origin timestamp, stratum, leap indicator). The time
source (RTC, SNTP, or unknown) and the last offset are logged and published as
`$SYS/broker/time/{source,offset_ms}`. A wrong RTC no longer means "refuse
everything" when a server answers. NTS is out of scope (plain SNTP is
unauthenticated, so the bounds above are the defence).
