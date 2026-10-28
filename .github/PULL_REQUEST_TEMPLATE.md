## What and why

<!-- Milestone / ADR this belongs to, and what changes. -->

## Checklist

- [ ] `make check` passes locally
- [ ] `make smoke` passes (once the milestone has a boot path)
- [ ] No `unwrap`/`expect`/indexing/panic on external input; every new `unsafe` block has a `// SAFETY:` comment
- [ ] Non-obvious decisions are recorded in `docs/DECISIONS.md`
- [ ] `docs/PROGRESS.md` is updated (milestone commits)
- [ ] New parsers have a fuzz target
