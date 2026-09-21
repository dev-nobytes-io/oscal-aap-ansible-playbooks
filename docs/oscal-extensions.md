# OSCAL extensions

OSCAL 1.1.2 cannot express several things this project needs — most importantly
"no determination was made". Rather than distort standard fields, we extend via
props in a documented namespace.

> **Namespace:** `https://nobytes.io/ns/oscal/cca/1.0`
> Referred to below as `NS`.

The difference between "custom props" and "a documented extension" is this page.
Third-party tooling can ignore our props safely; anything that reads them has a
specification to read them against.

## Design rules

1. **Props for machine bindings, links only for dereferenceable things.** A
   `link/@href` is a URI reference and validators will try to resolve it.
   Pointing one at a role's `tasks/main.yml` produces broken-link noise. Code
   references go in `back-matter/resources` with `rlinks` and `hashes` — the
   hash pins the exact version that produced the verdict, which is what an
   auditor actually wants.
2. **Reuse core OSCAL where it exists.** Classification markings use the
   core-namespace `marking` prop, not ours, so other tooling respects them.
3. **Never overload a standard field to mean something non-standard.**

## Vocabulary

| Prop | Valid on | Values |
|---|---|---|
| `assessment-status` | observation, finding, finding-target, control-selection | `satisfied` · `not-satisfied` · `not-applicable` · `unassessed` · `error` |
| `unassessed-reason` | observation, control-selection | `not-implemented` · `out-of-scope` · `unreachable` · `insufficient-privilege` · `insufficient-history` · `partial-population` · `unsupported-platform` · `collection-error` · `evaluation-error` · `requires-interview` · `requires-external-system` · `evidence-expired` · `deferred-by-policy` |
| `confidence` | observation, finding, implemented-requirement | `direct` · `proxy` · `partial` · `attested` |
| `evidence-tier` | observation, implemented-requirement | `passive` · `active` · `mutating` · `examined` · `interview` |
| `coverage` | implemented-requirement | `full` · `partial` · `proxy-only` · `none` |
| `scope` | observation, implemented-requirement | `subject` · `aggregate` |
| `check-id`, `check-version`, `collect-role`, `evaluator` | implemented-requirement, observation | free text |
| `control-revision`, `statement-sha256`, `catalog-version` | implemented-requirement, observation, result | free text |
| `freshness-hours`, `history-window-days` | implemented-requirement | integer |
| `population-total` | finding | integer — in-scope subjects from INVENTORY, estate-wide |
| `population-assessed`, `population-failing`, `population-na` | finding | integer — per control, counting distinct SUBJECTS |
| `population-basis` | finding | `subject` · `aggregate-subject` |
| `fact-bundle-sha256`, `aggregation-key`, `run-id`, `system-id` | various | free text |
| `poam-status` | poam-item | `open` · `in-progress` · `risk-accepted` · `remediated` · `closed` · `deferred` |

`poam-status` is a prop because `poam-item` has no status field in 1.1.2 — the
same approach FedRAMP takes.

### The population props mean something specific

`population-total` is a property of the **estate**: how many subjects were in
scope, from inventory. It is the same on every finding.

The other three are per **control**, and count **distinct subjects**, not
evaluations and not the run. `assessed` is the subjects the control was
*determined* for; a subject it was not determined for appears in neither the
numerator nor its complement, and `status.remarks` says so rather than leaving
a reader to assume the difference passed.

`population-basis` says what is being counted. An **aggregate** check judges a
population from inside one subject — a directory tenant rather than a laptop —
so its denominator is its own aggregate subjects and never the host estate.
Reporting a whole tenant as "1 of 50 assessed subjects" would describe a
different population from the one judged.

All of this was wrong until PR 14, in output rather than in tooling. See
[ADR 0014](adr/0014-population-figures-are-per-control-and-count-subjects.md).

## How each status is actually encoded

| Our status | OSCAL encoding | Notes |
|---|---|---|
| `satisfied` | `status.state = satisfied`, `reason = pass` | Direct |
| `not-satisfied` | `status.state = not-satisfied`, `reason = fail` | Direct |
| `not-applicable` | `status.state = satisfied`, `reason = "not-applicable"`, **plus** `implementation-status.state = not-applicable` | `reason` allows other values. The control objective is not violated, so `satisfied` is defensible — and `implementation-status` states NA explicitly, so no reader is misled. The one place we accept a slightly lossy encoding. |
| `attested` | `result.attestations[]` with `responsible-parties` and an assessment part carrying `method = EXAMINE`/`INTERVIEW`, plus an observation with matching `methods` | Genuinely idiomatic. This is what `attestation` is for, and it is how the ~13 procedural ML1 controls are handled. |
| `unassessed` / `error` | **No finding emitted.** An observation carries `NS:assessment-status` and `NS:unassessed-reason`; the control appears in `reviewed-controls` under a selection marked `NS:assessment-status = unassessed`. | There is no non-lying encoding in 1.1.2. See below. |

## The unassessed decision

This is the most consequential choice in the project, so the reasoning is
recorded rather than assumed.

`finding-target.status.state` permits only `satisfied` and `not-satisfied`.
Given a host that timed out, the options are:

- Emit `not-satisfied` → converts an operations failure into a compliance
  failure. A decommissioned host stays permanently red, and people learn to
  ignore red.
- Emit `satisfied` → catastrophic, and the whole reason this project exists.
- Emit nothing → correct, **provided** absence is unambiguous.

So absence is made unambiguous: `reviewed-controls` is generated from the
assessment **plan**, enumerating every control we intended to determine,
including those we failed to. `reviewed-controls − findings` is exactly the
unassessed set.

Generate `reviewed-controls` from results instead and absence becomes
unrecoverable — "we couldn't tell" and "not in scope" collapse into the same
thing. CI asserts that every control in a baseline appears in `reviewed-controls`
regardless of outcome.

## Classification markings

Use the **core** namespace:

```json
{ "name": "marking", "value": "OFFICIAL: Sensitive", "class": "pspf" }
```

`marking` is the one OSCAL-defined prop name for this, and reusing it means
third-party tooling honours it. Markings appear on results metadata,
observations and evidence resources.

## Stability

This vocabulary is versioned in the namespace URI. Adding values is a minor
change; removing or redefining one requires a new namespace version and an ADR.
