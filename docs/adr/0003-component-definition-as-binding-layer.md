# ADR 0003: Use OSCAL component-definition as the control-to-check binding

## Context

Something must record which check evidences which control, on which platform, at
what confidence. The easy options are a table in a README or a naming convention
tying role names to control ids.

Both rot. Documentation drifts from code silently, and a naming convention
cannot express confidence, coverage, applicability or the residual gap — which
are the parts that keep the output honest.

## Decision

Use OSCAL **component-definition**, one per platform family, as the binding
layer. Each declares `implemented-requirements` keyed by ISM control id, with
props naming the collect role, the evaluator, the method, the confidence ceiling
and the coverage rationale.

These documents are **generated** from the `checks/` registry. CI fails if
regenerating produces a diff.

## Status

Accepted.

## Consequences

Coverage becomes queryable data rather than a claim: "which ML1 controls can we
test on Windows Server 2019" is a query, and the coverage ledger is generated so
it cannot drift into flattery.

It is also the OSCAL-native answer, so the artefacts are consumable by other
compliance tooling rather than being our private format.

Cost: a generation step, and the generator becomes load-bearing. Authors never
hand-write OSCAL, which is the point — but it means a generator bug is a
correctness bug, not a cosmetic one.
