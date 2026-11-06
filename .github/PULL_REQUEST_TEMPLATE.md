## What and why

<!-- What changes, why, and the milestone, ROADMAP item, ADR or issue it belongs to. -->

## How it was tested

<!-- The commands you ran and on what (macOS or Linux, QEMU HVF/KVM/TCG, a real VM). Say what you did not run. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`): the Developer Certificate of Origin, see
      [CONTRIBUTING.md](https://github.com/zeljan-alduk/urMQTT/blob/main/CONTRIBUTING.md#developer-certificate-of-origin). CI's Lint job fails without it.
- [ ] `make check` passes locally (fmt, typos, clippy on the host and the bare-metal targets, host tests).
- [ ] `make smoke` passes for the boot paths this change touches (or say why it was not run).
- [ ] No `unwrap`/`expect`/indexing/`panic!` on external input; every new `unsafe` block has a `// SAFETY:` comment.
- [ ] A new parser of network, disk or device input has a fuzz target and rows in docs/AUDIT.md sections 2 and 6b.
- [ ] Non-obvious decisions are recorded in `docs/DECISIONS.md`; user-visible changes have a CHANGELOG line.
- [ ] A new limit or a fixed weakness is reflected in `docs/KNOWN-ISSUES.md` (`python3 scripts/check-known-issues.py`).
- [ ] This is not a driver for a device that is not virtio. Such drivers (AWS ENA, NVMe, gVNIC, Azure, VMware,
      bare-metal NICs and disk controllers) are the commercial edition's scope and may be declined here; see
      [docs/EDITIONS.md](https://github.com/zeljan-alduk/urMQTT/blob/main/docs/EDITIONS.md) section 6. Work that makes out-of-tree drivers possible without changing
      the open kernel's behaviour (ROADMAP NOW-18) is welcome.
