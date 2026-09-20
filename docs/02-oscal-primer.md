# OSCAL, enough to read this repository

[OSCAL](https://pages.nist.gov/OSCAL/) is a NIST standard for expressing control
catalogs, baselines and assessment output as structured data. This project
targets **OSCAL 1.1.2**, matching what ASD publishes.

## The models we use

| Model | Question it answers | Who authors it |
|---|---|---|
| **catalog** | What controls exist? | ASD (ISM); this project (PSPF, APPs, SOCI) |
| **profile** | Which subset applies to this system? | ASD (classification + E8 baselines) |
| **component-definition** | What can evidence a control, and how? | This project |
| **assessment-plan** | What do we intend to assess, and by what method? | Generated from `checks/` |
| **assessment-results** | What did we observe, and what do we conclude? | Emitted per run |
| **plan-of-action-and-milestones** | What is not met, and what is being done? | Derived from findings |

We do not use `system-security-plan`. This project assesses; it does not
document a system's design.

## Observations and findings — the distinction that matters

- An **observation** is a thing that was seen: a method (`TEST`/`EXAMINE`/`INTERVIEW`),
  a subject, a timestamp, and a pointer to evidence. Required fields are `uuid`,
  `description`, `methods` and `collected`; `expires` is optional but this
  project always sets it.
- A **finding** is a conclusion drawn about a control from one or more
  observations.

Many observations roll into one finding. A control can be evidenced directly on
a host *and* corroborated from a SIEM, and both are recorded rather than one
silently winning.

## Three schema facts that shape everything here

Verified directly against the NIST 1.1.2 schemas — each one constrains the
design, so they are worth knowing before reading the code.

**1. `import-ap` is required.** `assessment-results.required` is
`["uuid", "metadata", "import-ap", "results"]`. A results document with no
assessment plan is not conformant. The plan is a mandatory artefact, not a
nicety — see [`../oscal/assessment-plans/README.md`](../oscal/assessment-plans/README.md).

**2. A finding cannot say "we didn't check".** `finding-target.status.state`
permits exactly `satisfied` and `not-satisfied`. There is no `unassessed`, no
`error`, no `not-applicable`. So this project adopts the only non-lying
encoding available:

> Absence of a finding means **no determination was made**.
> Presence in `reviewed-controls` means a determination was **intended**.
> `reviewed-controls − findings = unassessed`.

which works only because `reviewed-controls` is generated from the **plan**.
`implementation-status` is a separate assembly that *does* have
`not-applicable`, and is used for genuine non-applicability.

**3. There is no mapping model at 1.1.2.** OSCAL's mapping model arrives in the
1.2.x line. Our PSPF/Privacy/SOCI crosswalks therefore use this project's own
schema, documented in [`../oscal/mappings/README.md`](../oscal/mappings/README.md).
The emitter is version-parameterised so adopting the native model later is a
configuration change rather than a rewrite.

## What the ISM catalog actually looks like

Reading real ACSC data saves several surprises:

- Control ids are `ism-1488`. **`title` is a useless stub** (`"Control: ism-1488"`)
  — the content is in `parts[0].prose`.
- Each control has **exactly one part**, named `statement`, with id
  `<control-id>_smt`. That id is a valid `finding-target` of type `statement-id`.
- **Groups have no `id`** — it is `null` at every level, in the catalog and in
  the resolved profile catalogs. Section structure must be derived from the
  `sort-id` prop. Code that assumes group ids silently produces ungrouped reports.
- **Controls carry no `links`.** There is no ISM→800-53, →ISO 27001, →CCI or
  →STIG crosswalk in the data. Every such mapping is authored here.
- **There are no assessment objectives** — one prose sentence per control.
  Turning that into a testable assertion is authoring work, not extraction, and
  it is the real cost centre of this project.

ASD-specific props live in namespace `https://cyber.gov.au/ns/ism/oscal/3.0`:
`applicability` (repeated, one per classification: `NC`/`OS`/`P`/`S`/`TS`),
`essential-eight-applicability` (`ML1`/`ML2`/`ML3`), `revision`, `updated`.

## Validating OSCAL

NIST publishes the schemas as GitHub **release assets**:
`https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_<model>_schema.json`.
The `raw.githubusercontent.com/.../json/schema/` and `pages.nist.gov/OSCAL/artifacts/`
paths return 404 — do not wire those into CI.

**The trap:** these schemas use `\p{...}` Unicode-property regexes. Python's
stdlib `re` cannot compile them, and stock `jsonschema` does not fail cleanly —
it raises `re.error: bad escape \p` and crashes. The fix is a six-line validator
extension overriding the `pattern` keyword to use the `regex` module.

With that in place, validation runs offline in pure Python with no Java
toolchain, which is what makes it usable in an air-gapped pipeline. `oscal-cli`
is a useful second opinion, not a dependency.

## Further reading

- [OSCAL concepts](https://pages.nist.gov/OSCAL/concepts/)
- [ASD's ISM OSCAL page](https://www.cyber.gov.au/ism/oscal)
- Our extensions: [`oscal-extensions.md`](oscal-extensions.md)
