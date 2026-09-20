# ADR 0002: Separate collection from evaluation

## Context

The obvious design has an Ansible role test a condition and report pass or fail.
It is simple, and it is what most compliance automation does.

It also destroys the evidence. A boolean cannot be re-examined, and a verdict
whose underlying observation was never retained is an assertion rather than
assurance. Three further pressures push the same way:

- ASD revises the ISM quarterly. When control text changes, or an interpretation
  turns out to be wrong, the only remedy in a verdict-producing design is to
  re-run against production.
- Legacy targets need an old `ansible-core`, but nothing about judging a fact
  requires an old Python.
- Logic embedded in Ansible roles — much of it PowerShell — is close to
  untestable without the target platform.

## Decision

Three stages. Ansible **collects raw facts** and never judges. A pure Python
function **evaluates** `(bundle, params, history)` off-host. A separate stage
**emits** OSCAL.

Facts are the durable artefact. Verdicts are derived and reproducible.

## Status

Accepted.

## Consequences

Good: evidence is re-evaluatable without touching production; the fact bundle is
independently auditable; nearly all logic is unit-testable with no host, which is
what makes wide platform coverage feasible; only collection needs the legacy
execution environment.

Costly: an extra layer, and a durable fact store that must be secured, redacted,
classified and retained — a new crown-jewel dataset that would not otherwise
exist. See ADR 0008.

Does not solve: temporal controls (about rates) and population controls (about
sets) need a history accessor and an aggregate scope respectively. Active probes
need an explicit escape hatch. All three are addressed in the architecture, not
by this split alone.
