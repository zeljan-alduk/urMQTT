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
2. **No filesystem: raw disk access.** Persistent data lives on a separate disk that the kernel accesses raw. It holds a superblock, a region table, fixed regions for SQLite (DB, WAL, journal) and a per-core telemetry log. There is no filesystem code to attack or corrupt.

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
- **The data disk belongs to urMQTT** (user decision 2026-10-29). Whatever was on it before does not matter and is overwritten. What must never happen is picking the *wrong* disk: never the boot medium, never a guess between several disks. urMQTT's own state is never lost silently: a damaged urMQTT disk is refused or restored (S5), not reformatted. Every on-disk change is proven crash-safe by fault injection.
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
| 3. Close the biggest gaps | **H1** (+ H7 lower bound), **S1** | runtime revocation, allowlist, expiry checks; host disk tool, fault injection, disk safety |
| 4. Quick win | **X0b** | ARMv8 hardware crypto on aarch64 (today all software) |
| 5. Prove the custom code | **H2**, **H3**, **H5** | TLS and TCP assurance, Miri, Kani, sanitizers |
| 6. Disk format v2 and features | **S2**, **S3**, **S4**, **S5**, **S6** | settled before x86 shares the format |
| 7. x86_64 | **X1**–**X8** | port with full parity and cross-arch data disks |
| 8. Mitigations on both architectures | **H4** (+ H4b), **H6**, rest of **H7** | KASLR, stack protector, MTE, allocator hardening, SQLite at EL0 |
| 9. One ISO, trusted boot | **X10**, **H8** | the multi-platform ISO; Secure Boot and signed loaders |
| 10. Bare metal | **X12**, **X13**, **X14**, X15 (optional), **X16** (continuous) | the Intel PC: USB boot, `hwreport`, NVMe/AHCI, its NIC |
| 11. Speed, encryption, release readiness | **X9**, **S7**, **H9**, **X11**, **S8** | optimisations measured on real hardware; encryption with measured overhead; SBOM; numbers and docs |
| 12. Audit | **H10** | the audit package covers everything above |

About 38 milestones in all. Each ends as before: tests green, commit, PROGRESS
entry, ADRs, and a report. The work stops after each milestone for the user's
go-ahead.

## Decisions taken (user, 2026-10-29)

The user accepted every proposal ("everything as proposed, following best practice"):

1. **Order:** the phases above, as written. Bare metal (phase 10) comes before the x86 optimisations, and storage v2 (phase 6) before the x86 port.
2. **X0b:** ARMv8 hardware crypto on aarch64 early, right after X0. It changes aarch64 numbers upwards.
3. **Limine:** vendor the x86 Limine binaries and build the `limine` host tool from its checksummed C source. ADR-043 records that this overrides PROMPT.md §2.
4. **S2 migration: offline.** The kernel reads only the current layout and refuses an older one with a clear message naming the fix. `urmqtt-disk migrate` converts offline, with the safeguards listed in STORAGE-PLAN S2.
5. **H2 session tickets: random keys that rotate.** A new key comes from the CSPRNG every 12 h and the previous key is still accepted for 12 h more. Tickets live at most 12 h, so none outlives its key. The keys exist only in memory: never on disk or in the image, and zeroised when retired. Tickets do not survive a broker restart; the reconnect after a restart is a full handshake, which admission control absorbs (M16).

6. **Whole-disk ownership.** The data disk is urMQTT's entirely; previous content does not matter. This overrides PROMPT-storage §0 ("never format over a non-blank disk"). The safeguards that remain are about choosing the disk, not its contents (STORAGE-PLAN S1):
   - the boot disk is identified exactly and is never used;
   - with `storage.data_disk = "auto"`, exactly one other disk must exist, otherwise urMQTT refuses and lists the candidates;
   - an explicit selector (`{ serial = "…" }` or `{ model, size }`) picks one disk among several;
   - claiming a disk with foreign content is logged with model, serial and size.

Still open: the Intel test PC's hardware inventory (TODO.md), which decides the order of X13/X14.
