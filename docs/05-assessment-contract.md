# The assessment contract

Every check, on every platform, produces the same shape. That is what lets a
Windows registry read, an `sshd_config` parse, a vSphere API call, an Entra ID
Graph query and a Splunk search coexist without the OSCAL emitters knowing
anything about any of them.

## The pipeline

```
COLLECT                    EVALUATE                       EMIT
Ansible, read-only    ──▶  (bundle, params, history)  ──▶ OSCAL 1.1.2
Raw facts. No verdicts.    pure function → CheckResult    results → POA&M
```

## CheckResult

| Status | Meaning | Emits a finding? |
|---|---|---|
| `satisfied` | Control met, with evidence | yes |
| `not-satisfied` | Control not met, with evidence | yes |
| `not-applicable` | Control does not apply here, with justification | yes |
| `unassessed` | **No determination was made**, with a reason | **no** |
| `error` | Our code failed. Not evidence about the estate. | **no** |

`satisfied` and `not-satisfied` **cannot be constructed without facts** — the
constructor raises. Principle 1 is enforced in code, not in review.

### Why `unassessed` emits no finding

OSCAL 1.1.2's `finding-target.status.state` permits exactly `satisfied` and
`not-satisfied`. There is no way to say "undetermined" in a finding. Of the
three available options:

- `not-satisfied` turns an unreachable host into a compliance failure; a
  decommissioned machine stays permanently red and people learn to ignore red.
- `satisfied` is catastrophic.
- Emit nothing — correct, **provided absence is unambiguous**.

So absence is made unambiguous: `reviewed-controls` is generated from the
assessment **plan**, enumerating every control we intended to determine.
`reviewed-controls` minus `findings` is exactly the unassessed set. See
[ADR 0006](adr/0006-absence-of-finding-means-no-determination.md).

Reasons are a closed vocabulary: `not-implemented`, `unreachable`,
`insufficient-privilege`, `insufficient-history`, `partial-population`,
`collection-error`, `evaluation-error`, `evidence-expired`, and others in
[`oscal-extensions.md`](oscal-extensions.md).

## Confidence is a ceiling

| Confidence | Meaning |
|---|---|
| `direct` | The check observes what the control requires |
| `proxy` | It observes something that implies it, with stated gaps |
| `partial` | Part of the control is tested; the rest is named |
| `attested` | A human asserted it; nothing was automatically determined |

A registry entry declares a ceiling. An evaluator may **lower** it at runtime
and may **never raise** it — enforced in `evaluate_check`, so no evaluator can
opt out. Headline compliance figures count `direct` only.

## The three guards

Run before the evaluator is even called, so authors need not remember them:

1. **Required facts missing** → `unassessed / collection-error`
2. **History window unsatisfiable** → `unassessed / insufficient-history`
3. **Evaluator raises** → `error`, never `not-satisfied`

## Temporal controls

Roughly a quarter of Essential Eight ML1 is about *rates*, not state:
`ism-1690/1691/1694/1695/1876/1877` (patch windows) and
`ism-1698/1699/1701/1702/1807` (scan cadence). "Applied within 48 hours of
release" cannot be answered by any single point-in-time observation.

So the evaluator signature is `(bundle, params, history)`, checks declare
`history_window_days`, and a window that cannot be satisfied returns
`unassessed / insufficient-history`. **Absence of history is not evidence of
non-compliance.**

## Scope: subject vs aggregate

Controls like `ism-0445`, `ism-1175`, `ism-1380`, `ism-1689`, `ism-1812` and
`ism-1814` are statements about a *population*. Findings therefore carry
`population-total`, `population-assessed` and `population-failing`, and the
**denominator comes from the inventory, never from the results**.

Forty-two unreachable hosts vanishing from output while a 94%-of-fleet pass
renders green is the default failure mode of compliance automation. Passing the
denominator explicitly is what prevents it.

## Freshness

Every observation carries `collected` (when the **fact** was gathered, not when
it was evaluated) and `expires`. Expiry is enforced at **report** time, not
merely recorded at emit time — otherwise a host that stopped being collected in
June still renders green in December, and the dashboard gets *greener* as
collection degrades.

## Evidence tiers

| Tier | Meaning |
|---|---|
| `passive` | Observation only. The default. |
| `active` | A probe with side effects. Opt-in, separate role namespace, separate credential, results marked non-reproducible. |
| `mutating` | Never valid for a check. |

## Purity

Evaluators are pure functions: no network, no subprocess, no clock. Enforced by
tests that remove `socket.socket` and `subprocess.Popen` and run every evaluator
anyway, plus an import contract and a source scan for clock access.

Purity is what makes evidence re-evaluatable and output **byte-deterministic**:
the same facts always produce identical OSCAL, which is what makes golden-file
tests possible and lets an auditor independently re-derive a published document.
