# ADR 0013: Declare structurally unobservable controls as `attested`

## Context

Until now a control either had a check or sat in an undifferentiated "no check"
pile. That pile conflates two completely different situations:

- **Nobody has built it yet.** A backlog item. Effort closes it.
- **No tool can observe it.** ism-1679 requires multi-factor authentication on
  **third-party** online services. An organisation cannot query another
  organisation's identity system, and never will be able to. ism-1507 requires
  that a privileged access request *was validated when first made* — an
  approval record, not a system state. A directory can show that an account
  holds privilege; it cannot show that anyone approved it.

Reporting both as "no check" tells a reader to expect progress on controls
where none is coming, and hides the fact that the organisation owes evidence of
a different kind. Worse, the pressure to make coverage numbers move invites the
opposite error: answering ism-1679 from our own tenant's conditional access
policy. That would produce a **pass**, for a control about systems we cannot
see, from evidence about a different population of users. It is the most
dangerous shape of wrong this project can produce.

Of the 46 Essential Eight ML1 controls, nine are identity-related. Enumerating
them against the vendored catalog rather than assuming: only three or four are
observable from an organisation's own tenant. Four concern third-party or
customer services, and one is an approval record.

## Decision

Every registry entry declares an **`assessability`**: `automated` or
`attested`. This is a separate axis from `confidence`, and conflating the two is
how a coverage figure starts lying:

- **`confidence`** asks *how closely does our observation match the control?*
- **`assessability`** asks *is there anything observable here at all?*

An `attested` entry carries no `collect` block and no `evaluator` — the schema
forbids both — and must carry an `attestation` block naming:

| Field | Why it is required |
|---|---|
| `source` | Where the evidence actually lives. A report that says "ask someone" is an excuse. |
| `owner` | The **role** answerable for keeping it current. |
| `renewal_days` | Evidence has a shelf life. An attestation is not permanent. |
| `why_not_observable` | Must argue **structure**, not effort. "Hard to build" is not a reason to stop measuring. |

**Attested controls are excluded from the automated coverage percentage.** They
are reported as their own bucket, so the three numbers — automated, attested,
nothing-yet — partition the baseline exactly.

`evaluate_check` on an attested entry returns `unassessed` with reason
`requires-attestation`. It cannot return `satisfied` or `not-satisfied`, and
`Check.resolve()` raises rather than importing anything.

## Status

Accepted.

## Consequences

The headline number **cannot be raised by writing prose**. This is enforced by
test, not by review: `test_attested_controls_are_excluded_from_automated_coverage`
fails if a control is ever counted in both buckets, and fails if the three
buckets stop partitioning the baseline. The test also refuses to pass vacuously
when no attested entries exist.

An assessment plan now carries three control selections rather than two, and the
attested selection states that those controls are determined by **examination of
an attestation, never by automated test**. An assessor reading the plan learns
where the evidence is held and who owns it, instead of finding a silent gap.

A cross-field rule requires an attested entry's `freshness_hours` to equal
`renewal_days × 24`. An attestation cannot be fresher than the process that
produces it, and marking it stale earlier is equally misleading.

The cost is a new way to be dishonest: classifying something as `attested`
because building the collector is inconvenient. Three things push back — the
`why_not_observable` field must argue structure, a test rejects text that reads
like a backlog item ("not yet", "too hard", "future work"), and an attested
entry buys no coverage credit, so the incentive to misuse it is absent.

`platform_family: organisation` is added for controls that belong to no system
we operate. Such controls are only ever attested; there is nothing to collect
from an organisation.
