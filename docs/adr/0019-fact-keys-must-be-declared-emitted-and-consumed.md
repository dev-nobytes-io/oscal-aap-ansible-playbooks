# ADR 0019: Fact keys must be declared, emitted and consumed

## Context

The defects this project keeps finding in itself are guards unable to see what
they guard. Most have been fixed by comparing two artefacts — a collector
against a fixture, a document against its own remarks. But **a comparison
between two artefacts cannot see a key that exists in only one place**, and
there were two of those.

**`windows.gpo.applied_computer`** was declared an optional fact by
`checks/windows/win-office-macro-internet-blocked.yml`, emitted by no role, and
read by no evaluator. A repo-wide grep returned exactly one hit: its own
declaration. Nothing could catch it — a fixture diff cannot see a key neither
side has, and the check's own tests pass because the fact is optional.

**`entra.tenant`** ran the other way, and is the more serious of the two. It was
emitted by `collect_entra_id` from a dedicated `GET /organization` Graph call,
declared by no check, read by no evaluator, and absent from
`tests/fixtures/bundles/tenant-contoso-entra.json`. Its single field, named
`tenant_id`, held the **entire organization object** rather than an id:

```yaml
tenant_id: "{{ (collect_entra_id_org.json | default({})).get('value', [{}])
             | first | default({}) | ansible.builtin.combine({}) }}"
```

That is not a harmless spare field. [ADR 0008](0008-redaction-is-policy-driven-per-deployment.md)
establishes that evidence cannot be retroactively un-collected, which is why
redaction runs before persistence. A Graph call whose result nothing consumes is
therefore **gratuitous collection of tenant identity data**, carried into every
bundle, protecting nothing and answering no control. `subject.asset_id` already
identifies the tenant.

Thirteenth and fourteenth instances of the recurring shape.

## Decision

A fact key must appear in all three places. `tests/test_fact_key_reconciliation.py`
parses each set from source — YAML for the first two, `bundle.fact("…")` call
sites for the third — and fails in **four** directions:

| Direction | Why it is a defect |
|---|---|
| declared, not emitted | the check can never be determined |
| declared, not consumed | a false dependency the check does not need |
| emitted, not declared | collection with no consumer, and evidence cannot be un-collected |
| consumed, not emitted | the evaluator returns `unassessed` forever, silently |

All four are hard failures. The fourth is the shape that shipped in PR 17: an
evaluator reading a key nothing produced, returning `unassessed` on every host
while its tests passed.

**Both instances were removed rather than wired up.** `windows.gpo.applied_computer`
was never used by the evaluator that declared it, and the `GET /organization`
call went with `entra.tenant` — collecting less is the correct fix for evidence
nothing reads, not finding it a consumer. A future fact that genuinely needs to
travel as context gets declared `optional` on the check that wants it: one line,
and the dependency becomes visible.

**The test refuses to pass vacuously.** It asserts each of the three sets has at
least ten members, so a parsing change that silently found nothing cannot render
as "everything reconciles".

## A second defect, found by fixing the first

Removing the only optional fact left `optional:` with nothing under it. YAML
parses that as `None`, so `facts.get("optional", [])` returned `None` — the
default never applies when the key is *present* — and `tuple(None)` raised
`TypeError` from inside `Registry.load()`, taking down `make validate`,
`make coverage` and 34 tests.

An author writing an empty `optional:` would have hit the same crash with no
useful message. Changed to `facts.get("optional") or ()`, which is the same rule
this repository applies everywhere else: decide what happens when the input is
**absent**, not merely wrong.

## Consequences

Coverage is unchanged at **15 of 46 (32.6%)** and no verdict moves. Neither key
reached any generated artefact — `entra.tenant` was declared by no check, so it
never became an observation, which is why `test_generated_artefacts_are_up_to_date`
passes without regeneration.

Bundles collected before this change carry a `entra.tenant` record holding a
tenant's full organization object. Like every other evidence-scope correction,
that cannot be fixed retrospectively.

Three assertions were verified to fail against the code as it shipped:
`windows.gpo.applied_computer` on both declared-side directions, and
`entra.tenant` on emitted-not-declared.

Also corrected here: `docs/ASSURANCE-PRINCIPLES.md` attributed Principle 9's
enforcement to `tests/test_prose_drift.py`, **which does not exist** — the
behaviour lives in `tests/test_registry_integrity.py`. The binding document
named an enforcement that was not where it said it was, which is the same class
of claim this ADR exists to make impossible for fact keys.

## Status

Accepted.
