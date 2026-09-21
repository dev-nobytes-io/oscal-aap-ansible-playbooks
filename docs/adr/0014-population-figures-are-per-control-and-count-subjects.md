# ADR 0014: Population figures are per-control and count subjects

## Context

Every finding this project emits carries `population-total`,
`population-assessed`, `population-failing` and `population-na`. They are the
numbers a reader quotes — the finding's own description renders them as
*"N of M assessed subjects do not satisfy this control"* — so they are the part
of the output most likely to end up in a report to an authorising officer.

They were wrong from PR 04 until PR 14, in two independent ways.

**`assessed` was computed once per run.** `emit_assessment_results` derived
`assessed = len(subjects)` across every evaluation in the run and passed that
one number to every control's finding. Measured on the committed golden file,
all nine findings claimed `population-assessed: 4` while their own
`related-observations` and `status.remarks` said 1, 2 or 3:

| Control | population-assessed | its own remarks | related-observations |
|---|---:|---:|---:|
| `ism-1488` | 4 | 1 | 1 |
| `ism-1501` | 4 | 3 | 3 |
| `ism-1654` | 4 | 2 | 2 |

`ism-1488` was determined for exactly one subject and failed on it. The
document rendered that as *"1 of 4 assessed subjects do not satisfy this
control"* — a 25% failure rate, where the observed rate was 100% of what was
actually looked at. The three subjects the control was never determined for
were counted into its denominator **as though they had passed**.

That inverts Principle 3. An undetermined control is not a passing control, and
`docs/ASSURANCE-PRINCIPLES.md` says so in the same breath as it says the
denominator comes from inventory. Counting undetermined subjects as the
numerator's complement smuggles them back in as compliant.

**`failing` and `na` counted evaluations, not subjects.** Two checks bound to
one control, both failing on one host, reported two failing subjects out of
one. A population figure that counts evaluations is not a population figure.

Neither defect was caught, and the guard written to catch exactly this —
`test_population_denominator_comes_from_inventory_not_results` — asserted only
that `population-total == 50` and `population-assessed < 50`. Both stayed true
throughout. This is the fifth time this repository has found the same shape in
itself: **a guard structurally unable to see the thing it was guarding**. It is
the first time that shape reached the output rather than the tooling.

A third problem sat alongside them. `scope: aggregate` was decorative: `scope`
was read in three places and all three only stamped its string into a prop.
Nothing consumed it. So a check that judges a whole directory tenant borrowed
the host estate as its denominator and reported the tenant as one of fifty
workstations — a number describing a different population from the one judged.

## Decision

**`population-total` is estate-wide and comes from inventory.** How many
subjects were in scope is a property of the estate, not of a control, so it is
the same for every finding. It is passed in explicitly (`--population-total`),
never inferred from how many bundles happened to arrive.

**`population-assessed`, `population-failing` and `population-na` are
per-control and count distinct subjects.**

- `assessed` — subjects this control was *determined* for. Not evaluations, not
  the run.
- `failing` — subjects with at least one `not-satisfied` determination.
- `na` — subjects whose *every* determination for this control is
  not-applicable. One applicable check makes the subject part of the
  population.

**A subject a control was not determined for appears in neither the numerator
nor the complement.** It is absent, and `status.remarks` says so explicitly:
*"this control was not determined for N of M in-scope subject(s). Those
subjects are not represented in this determination and must not be read as
passing."*

**A new prop, `population-basis`, says what the numbers count** — `subject` for
hosts drawn from inventory, `aggregate-subject` where the check judges a
population from inside a single subject such as a directory tenant. An
aggregate finding's denominator is its own aggregate subjects, never the host
estate. Without this prop a reader cannot tell whether "1 of 1" describes a
whole tenant or one laptop.

`scope` is now read in `emit_assessment_results` to make that determination. It
is the first place in the codebase that reads `scope` for anything other than
serialising it.

## Consequences

- **Published failure rates change, upward.** Anyone holding an earlier
  assessment-results document has figures that understate failure. The
  documents are not wrong about *verdicts* — no verdict moved when the golden
  files were regenerated — but their population arithmetic was wrong and
  should not be compared against post-PR-14 output.
- **`test_every_finding_is_internally_consistent`** now asserts that
  `population-assessed` never exceeds the finding's own observation count, that
  `failing` and `na` never exceed `assessed`, and that the prose and the props
  agree. A document that contradicts itself fails the suite.
- **`test_aggregate_findings_do_not_borrow_the_host_denominator`** fails if the
  golden output contains no aggregate finding at all, so the branch cannot
  become untested code by nobody exercising it. A tenant fixture bundle exists
  for that reason.
- The evaluator contract is unchanged. This is entirely an emit-layer fix.

## Alternatives considered

**Leave `assessed` run-wide and document it.** Rejected: the finding's own
description interpolates it into a sentence about that control. A number that
needs a footnote to stop it being read the obvious way is not fixed by the
footnote.

**Derive `total` per control from applicability.** A Windows control arguably
has a denominator of "the Windows estate", not the whole estate. That is
defensible and it is a larger change: it needs applicability data the inventory
does not currently carry, and getting it wrong would understate coverage gaps
instead of failure rates. Left for a later chunk; `population-total` continues
to mean the in-scope estate, which is what `docs/ASSURANCE-PRINCIPLES.md`
already documents.
