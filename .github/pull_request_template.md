## What this changes

<!-- One paragraph. What does this PR do, and why now? -->

## Chunk

<!-- This repo is built in chunked PRs; name the chunk (e.g. "PR 03 - OSCAL ingest"). -->

## Compliance-correctness checklist

Tick only what is genuinely true. An unticked box is fine; a wrongly ticked box
is how this repository starts producing confident, incorrect compliance output.

- [ ] No control is reported `satisfied` without a recorded observation backing it
- [ ] Every new control binding records a `confidence` (`direct` / `proxy` / `partial`)
- [ ] Every new crosswalk entry cites its source and records an equivalence rating
- [ ] Controls that cannot be automatically tested are marked `attested` or
      `api-required` — not silently omitted from coverage
- [ ] Assessment paths are read-only; nothing added here can mutate a target host
- [ ] Vendored upstream data (`oscal/upstream/`) is unmodified and checksum-pinned

## Verification

<!--
State what you actually ran and what it produced. Distinguish clearly:
  - verified locally
  - verified in CI
  - NOT verified (and why) - e.g. needs a real AAP controller, Windows host,
    Entra ID tenant, or vSphere endpoint
Do not describe unverified work as tested.
-->

```
# commands run + relevant output
```

## Scope not covered

<!-- Anything deliberately left out, and which chunk picks it up. -->
