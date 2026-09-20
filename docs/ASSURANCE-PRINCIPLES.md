# Assurance principles

**This is the binding document. Every other file in this repository answers to
it.** Where code, documentation or a report conflicts with these principles, the
code is wrong.

The reason it exists: a compliance tool that is *usually* right is more
dangerous than no tool at all. A missing result prompts someone to go and look.
A wrong result gets believed, written into an authorisation package, and acted
upon. Confident incorrectness is the failure mode this project is built to
avoid, and it is not avoided by being careful — only by structure.

---

## 1. Never claim what was not observed

> **No control is reported `satisfied` without a recorded observation that
> supports it.**

Not "no evidence of failure". Not "the check didn't error". An affirmative
observation, retained, referenced from the finding, and re-derivable from the
stored fact bundle.

Corollary: **the absence of a finding means no determination was made.** It
never means "compliant". OSCAL 1.1.2 forces this on us — `finding-target.status.state`
permits exactly `satisfied` and `not-satisfied`, with no way to express
"undetermined" — so the encoding is:

```
reviewed-controls  −  findings  =  unassessed
```

This only holds if `reviewed-controls` is generated from the **assessment plan**
— what we set out to determine — and never from the results. Generate it from
results and "we couldn't tell" becomes indistinguishable from "not in scope",
and the entire scheme becomes a silent lie. CI enforces it.

## 2. An operational failure is not a compliance failure

A host that was unreachable, a credential that lacked privilege, an API that
timed out — none of these mean the control is not met. Reporting them as
`not-satisfied` corrupts the dataset and trains people to ignore red.

These produce `unassessed` with a reason: `unreachable`,
`insufficient-privilege`, `collection-error`, `insufficient-history`,
`partial-population`. The distinction between "failing" and "unmeasured" must
survive all the way to the report.

## 3. State the population, always

> **Every aggregate finding carries `population-total`, `population-assessed`
> and `population-failing`.**

The denominator comes from the **inventory**, never from the results. This is
the single most common way compliance automation lies: 42 hosts are unreachable,
vanish from the output, and a 94%-of-fleet pass renders as green.

A run below the coverage threshold fails. Overriding that is permitted — estates
have genuine outages — but the override records who approved it and what the
real numbers were, on the result itself.

## 4. Declare confidence, and never inflate it

Most ISM controls cannot be directly tested. Reading a registry value that
*implements* a control is not the same as observing the control's effect.

| Confidence | Meaning |
|---|---|
| `direct` | The check observes the thing the control requires |
| `proxy` | The check observes something that implies it, with stated residual gaps |
| `partial` | Part of the control is tested; the rest is not, and is named |
| `attested` | A human asserted it; no automated determination was made |

A check declares a confidence **ceiling**. An evaluator may lower it at runtime;
it may never raise it. Headline compliance percentages count `direct` only —
`proxy` and `partial` are reported in a separate, labelled band. Aggregating
them into one number is how a policy read becomes "macros are blocked".

## 5. Say what the check does not prove

Every check with `coverage: partial` carries a `rationale` naming the residual
gap. These are aggregated into a generated, published coverage statement.

An honest account of what this system *cannot* tell you is more valuable than
the list of what it can, because that is the part nobody else will supply.

## 6. Assessment does not change anything

Collection is read-only. Not by convention — structurally:

1. Collect roles carry no mutating module surface, so it is visible in review.
2. **Collect job templates are bound to credentials that cannot write.** A
   read-only vSphere role, a Graph app with only `*.Read.All`, an unprivileged
   SSH account with a narrow sudoers allowlist. Role hygiene is the first line;
   credential scoping is the one that survives adversarial review.
3. Anything beyond passive observation declares `evidence_tier: active`,
   requires explicit opt-in, and lives in a separate role namespace with its own
   credential.

Remediation is a separate playbook, separately triggered, never invoked by an
assessment run.

## 7. Collectors gather facts; they do not judge

A collector that returns a verdict has destroyed the evidence. Facts are raw and
re-evaluatable; verdicts are derived, off-host, by a pure function.

This is what makes it possible to re-run evaluation against stored evidence when
ASD revises control text — which happens quarterly — without touching production
again, and it is what makes the evidence independently auditable.

## 8. Evidence expires

An observation carries `collected` and `expires`. **Expiry is enforced when the
report is generated, not merely recorded when the observation is emitted.**

Otherwise a host that stopped being collected in June still renders green in
December, and the dashboard gets *greener* as collection degrades. Evidence past
its expiry degrades the control to `unassessed / evidence-expired`.

## 9. Control text is pinned, and drift is loud

Every check records the SHA-256 of the control statement it was written against,
plus the control revision and catalog version.

ASD publishes the ISM quarterly — 26 releases so far. A reworded control whose
identifier is unchanged will otherwise keep passing a check that no longer tests
what it says. CI fails on any prose change, forcing a human to re-affirm or
revise the check. Baseline membership is diffed too: ML1 is 46 controls today,
not forever.

## 10. Evidence is sensitive, and is treated that way

Raw facts contain usernames, SIDs, email addresses and policy state. Making
evidence durable and auditable means building a genuine sensitive data store.

Redaction is **policy-driven per deployment** with a conservative default, so
the risk owner in each organisation decides — not this project. Every bundle
carries a classification marking. Redaction happens between collection and
persistence, because you cannot retroactively un-collect.

## 11. Statutory obligations are not discharged by host checks

The ISM is a control framework and can be assessed. The PSPF, the Privacy Act
and the SOCI Act impose **obligations**, most of which are organisational.

Crosswalks say *this ISM control contributes evidence toward this obligation*.
They never say *this obligation is met*. Obligation-level reports are emitted as
partial or informative, never as `satisfied`, and every mapping carries a
citation and a confidence.

"Privacy Act APP 11 satisfied" derived from a registry key is not merely an
accuracy problem — it is a legal exposure for whoever relies on it.

## 12. The ISM is authoritative; we are not

This project is not affiliated with, endorsed by, or approved by the ASD, the
ACSC, or the Commonwealth. Where our interpretation of a control differs from
the ISM, **the ISM is correct and we have a bug**.

Questions about what a control *means* belong with ASD. This repository only
automates evidence for it.

---

## What CI enforces mechanically

Principles are worth little if they rely on remembering them. These are tests:

| Principle | Enforcement |
|---|---|
| 1 | `reviewed-controls` generated from the plan; a test asserts every baseline control appears regardless of outcome |
| 3 | Coverage gate fails the workflow below threshold; findings without population props are rejected |
| 4 | `checks/schema.json` makes `confidence` and `coverage` mandatory; evaluators cannot raise the declared ceiling |
| 5 | `coverage: partial` without a `rationale` fails validation |
| 7 | Evaluators run with `socket.socket` and `subprocess.Popen` patched to raise, and with networking disabled in CI |
| 8 | Expiry applied at report generation; golden tests cover the stale case |
| 9 | `test_prose_drift.py` fails on any upstream statement hash change |
| 11 | Crosswalk entries without a citation and confidence are rejected |

The rest rely on review. That is why they are written down.
