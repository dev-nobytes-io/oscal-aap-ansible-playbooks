# ADR 0006: Absence of a finding means no determination was made

## Context

Assessment fails to reach a conclusion constantly and for mundane reasons: a host
is off, a credential lacks privilege, an API times out, a user profile hive is
not loaded, no check exists yet.

OSCAL 1.1.2 offers nowhere to say so. Verified against the NIST schema,
`finding-target.status.state` permits exactly `satisfied` and `not-satisfied`.
There is no `unassessed`, no `error`.

The available options are all bad:

- `not-satisfied` turns an operations failure into a compliance failure. A
  decommissioned host stays permanently red, and people learn to ignore red.
- `satisfied` is catastrophic and is the precise failure this project exists to
  prevent.
- Emit nothing — correct, but only if absence is unambiguous.

## Decision

Emit no finding, and make absence unambiguous:

> `reviewed-controls` − `findings` = **unassessed**

`reviewed-controls` is generated from the assessment **plan** — every control we
intended to determine, including those we failed to — and never from results. An
observation is still emitted carrying `NS:assessment-status = unassessed` and an
`NS:unassessed-reason`.

CI asserts that every control in a baseline appears in `reviewed-controls`
regardless of outcome.

## Status

Accepted.

## Consequences

This is the load-bearing honesty mechanism in the project, and it is fragile in
one specific way: generate `reviewed-controls` from results and "we could not
tell" becomes indistinguishable from "not in scope". The invariant is therefore
tested, not trusted.

It also makes the assessment plan mandatory in practice as well as in schema —
`import-ap` is a required field on `assessment-results` regardless, so the plan
had to exist; this decision gives it a second job.

Consumers that only read findings will see fewer controls than they expect. That
is correct behaviour, and is documented in `docs/oscal-extensions.md`.
