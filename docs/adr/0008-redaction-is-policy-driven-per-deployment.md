# ADR 0008: Make evidence redaction a per-deployment policy

## Context

Raw facts contain usernames, SIDs, email addresses, group memberships and a
detailed map of where an estate is weak. Retaining them durably — which ADR 0002
requires — creates a crown-jewel dataset that would not otherwise exist, inside
organisations that are already high-value targets.

There is no universally correct handling. Full identifiers give precise
remediation targeting and forensic value. Redacted bundles are far safer to
retain, share and lose. Which trade-off is right depends on the organisation's
classification, its records-management obligations and its risk appetite.

## Decision

Redaction is a **configurable policy with a conservative default**, applied
**between collection and persistence**. Each fact key declares a mode:
`retain`, `hash` (salted), `truncate` or `drop`.

The default hashes user identifiers and drops free-text fields that commonly
carry incidental data. The active policy version is recorded in every bundle.

This project does not decide the trade-off. The risk owner in each deployment
does.

## Status

Accepted.

## Consequences

The decision sits with whoever carries the consequences, which is correct — but
it means the project ships without a single answer, and deployments that never
revisit the default get conservative behaviour rather than optimal behaviour.
That is the right way round.

Redaction must happen before persistence, because you cannot retroactively
un-collect. That constrains the collect pipeline and adds a stage that must not
be bypassable.

Accepted costs: hashing loses remediation targeting (findings say "137 endpoints
fail" but not which user); the salt is itself a secret whose rotation breaks
longitudinal correlation. Both are stated plainly in the security model so the
choice is made deliberately.
