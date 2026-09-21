# Reporting

The OSCAL documents are the substrate. They are also close to unreadable
without tooling, and "here is a 400 KB JSON file" is not an answer to *"are we
compliant?"*.

This layer turns them into something a person reads. Four outputs are in scope;
this page covers the two that exist.

| Output | Form | State |
|---|---|---|
| OSCAL documents | assessment-plan, assessment-results, POA&M | **Always produced** |
| Human-readable report | Markdown, self-contained HTML | **Delivered** |
| ASD SSP Annex + Essential Eight | populated `.xlsx` / `.docx` | Planned — templates vendored |
| Obligation reports | PSPF ICT view, APP 11 evidence pack, SOCI CIRMP | Planned |

```bash
make report                       # both formats into out/
cca report --format html          # or one at a time
cca report --format markdown --output docs/latest-assessment.md
```

## The rule this layer exists to not break

**A status never renders without its confidence.**

A control shown `satisfied` on `proxy` evidence has not been demonstrated to
the same standard as one shown `satisfied` on `direct` evidence. If a report
renders them identically it has destroyed the single most valuable distinction
the pipeline produces — silently, in the artefact an executive actually reads,
at precisely the moment somebody decides no further work is needed.

So `ControlRow.display_status` fuses the two into one string and both renderers
go through it. There is deliberately no way to render the status alone: a
template that *can* drop the qualifier eventually will.

`tests/test_report.py` asserts the two cases are distinguishable by direct
comparison rather than by property check, because the failure being guarded is
exactly that they become indistinguishable.

## It reads the documents, not the registry

The report is generated from `assessment-plan.json` and
`assessment-results.json`, not by re-evaluating. That means it cannot drift
from the assessment it describes — and if the documents and the code ever
disagree, that is worth discovering rather than papering over.

It also means the documents have to be **self-describing**, which drove a
change in the emitter: results now carry a repeated `undetermined` property,
one per control, naming *why*. OSCAL 1.1.2 cannot express "not determined" in a
finding (ADR 0006), so without this a consumer sees an absent finding and has
to guess between:

| Reason | What it actually means |
|---|---|
| `not-implemented` | Nobody has built a check. A backlog item. |
| `requires-attestation` | No tool can ever observe it. Needs a human statement. |
| `no-subject-in-scope` | A check exists and works; this run included no system it applies to. |
| `unreachable` | The host could not be reached. **Not** a compliance failure. |
| `insufficient-history` | A rate control with too little history yet. |
| `partial-population` | Only part of the evidence was readable. |
| `evaluation-error` | **Our code broke.** A defect to report. |

Those call for completely different responses — buy a tool, chase a supplier,
widen the scope, fix the network, wait, or raise a bug. Collapsing them into
"not compliant" is how a report becomes something people learn to ignore.

## What the report says out loud

- **The subject gap.** "3 of 50 subjects in scope were assessed" appears above
  the numbers, not in a footnote. Every percentage describes only what was
  reached, and a control can read as satisfied while failing on a system the
  run never touched.
- **The attestation register.** Every `attested` control gets its own entry
  carrying why no tool can observe it, where the evidence lives, who is
  answerable, and how often it must be renewed. It is not a failure and it is
  not a pass — it is an outstanding obligation with a named owner.
- **No single headline percentage.** Satisfied, not-satisfied and undetermined
  are reported separately. A lone "87% compliant" figure invites averaging away
  the part that matters.

## Self-contained by construction

Standard library only, like the rest of the package (ADR 0007). Markdown and
HTML need nothing else, so a report can be produced inside an execution
environment in an enclave with no extra wheels and no index.

The HTML embeds its own CSS, respects `prefers-color-scheme`, and works on a
phone. It escapes every value it renders — the statements are Commonwealth text
and the rest is our own, but a renderer that trusts its input is a renderer
that will one day be handed something else, and a test pins that.

Document formats that genuinely need third-party libraries — the SSP Annex
`.xlsx`, the Essential Eight `.docx` — will need `openpyxl` and `python-docx`.
Those live in a separate module, imported lazily, so the evaluator's
stdlib-only constraint survives.

## Related

- [`docs/05-assessment-contract.md`](05-assessment-contract.md) — confidence, assessability, the three guards
- [`ADR 0006`](adr/0006-absence-of-finding-means-no-determination.md) — why absence of a finding means no determination
- [`ADR 0013`](adr/0013-declare-unobservable-controls-as-attested.md) — the attestation model
