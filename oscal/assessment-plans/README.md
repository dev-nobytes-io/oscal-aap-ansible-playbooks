# Assessment plans

**Mandatory, not optional.** OSCAL 1.1.2 requires `import-ap` on every
`assessment-results` document — verified against the NIST schema, where
`assessment-results.required` is `["uuid", "metadata", "import-ap", "results"]`.
A results document with no plan is not conformant.

The plan is also load-bearing for honesty, because of a second schema fact:
`finding-target.status.state` permits exactly two values, `satisfied` and
`not-satisfied`. OSCAL gives you **no way to record "we did not determine this"
in a finding**. So this project adopts the only non-lying encoding available:

> **Absence of a finding means no determination was made.
> Presence in `reviewed-controls` means a determination was intended.
> `reviewed-controls − findings = unassessed`.**

That only works if `reviewed-controls` is generated from **the plan** — what we
set out to assess — and never from the results. Generate it from results and
"unassessed" becomes indistinguishable from "out of scope", and the whole scheme
degrades into a silent lie. CI enforces the invariant: every control in a
baseline must appear in `reviewed-controls` regardless of outcome.

Plans are generated from `checks/` so that what we claim to assess and what we
actually run cannot diverge.
