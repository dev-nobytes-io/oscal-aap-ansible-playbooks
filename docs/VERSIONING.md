# Versioning and releases

Three things version independently here, and conflating them causes confusion.

## 1. This project

Semantic versioning, `MAJOR.MINOR.PATCH`, with compliance-specific meaning for
what counts as breaking:

| Change | Bump |
|---|---|
| A check's verdict changes for unchanged input (interpretation revised, bug fixed) | **MAJOR** |
| The check contract, fact bundle schema or extension vocabulary changes incompatibly | **MAJOR** |
| A check's confidence or coverage is **lowered** | **MAJOR** |
| New checks, new platforms, new crosswalk entries | MINOR |
| A check's confidence or coverage is **raised** with better evidence | MINOR |
| Fixes that do not change any verdict; documentation | PATCH |

The unusual one is **"a verdict changes for unchanged input is MAJOR"**, even
when the new verdict is more correct. Someone has a published assessment result
that this release would contradict, and they need to know before it happens
rather than discover it in a dashboard.

Every release notes which checks changed verdict behaviour and why.

## 2. The ISM catalog

Versioned by ASD, tracked separately, pinned by upstream git tag
(currently `v2026.09.4`). ASD publishes roughly quarterly.

A catalog bump is **not** a version bump of this project, but it can force one:

- Control prose changes → `test_prose_drift` fails → a human re-affirms or
  revises each affected check. A revision that changes verdicts is MAJOR.
- Baseline membership changes → controls enter or leave a baseline. ML1 is 46
  controls today, not permanently.
- New controls appear → coverage percentages move without any code change.

The release-watch workflow opens a PR with a control-level diff. Catalog changes
are reviewed, never absorbed silently.

Every assessment result records `catalog-version` and every observation records
`control-revision`, so historical results stay interpretable after a bump.

## 3. OSCAL itself

This project emits **OSCAL 1.1.2**, matching what ASD publishes — not the latest
upstream release. The emitter is version-parameterised, so moving to the 1.2.x
line (which brings the native mapping model our crosswalks currently substitute
for) is a configuration change rather than a rewrite.

The extension namespace carries its own version:
`https://nobytes.io/ns/oscal/cca/1.0`. Adding vocabulary values is a minor
change; removing or redefining one requires a new namespace version and an ADR.

## Execution environments

Tagged with the project version and pinned **by digest** for consumption.
`ee-legacy` stays on ansible-core 2.16.x deliberately — see
[`adr/0004-dual-execution-environments.md`](adr/0004-dual-execution-environments.md).
That pin is a capability, not a deferred upgrade, and will not be bumped for
tidiness.

## Support

The latest MAJOR line receives fixes. Because compliance evidence is retained for
years, a released version must remain able to re-derive the results it produced —
so releases are not deleted, and deterministic output means an old result can be
re-verified with the version that produced it.
