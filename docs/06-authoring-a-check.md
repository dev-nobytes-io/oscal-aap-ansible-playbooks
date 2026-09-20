# Authoring a check

Two files. You never write OSCAL — component-definitions, assessment-plan
activities, the coverage ledger and the docs are generated from the registry
entry.

## 1. The registry entry — `checks/<platform>/<check-id>.yml`

Validated against [`../checks/schema.json`](../checks/schema.json). Every
required field is required because omitting it has produced a specific class of
wrong output.

```yaml
id: win-office-macro-internet-blocked
version: 1.0.0
title: Office policy blocks macros in files originating from the internet
platform_family: windows
component: microsoft-office-windows

controls:
  - id: ism-1488
    statement_id: ism-1488_smt          # always <control-id>_smt
    control_revision: "1"
    statement_sha256: c3572b76…          # hash of the control prose
    coverage: partial
    rationale: >-
      Verifies the ADMX policy state that implements the block… It does NOT
      observe runtime blocking, does not detect Mark-of-the-Web being stripped
      upstream, and cannot assess profile hives unloaded at collection time.

method: TEST
confidence: proxy                        # a CEILING, not a claim
scope: subject
evidence_tier: passive
freshness_hours: 168
history_window_days: 0

collect:
  role: nobytes.compliance.collect_windows_office
  facts:
    required: [windows.office.install, windows.office.macro_policy]

evaluator: nobytes_cca.checks.windows.office:macro_internet_blocked
parameters:
  in_scope_apps: [word, excel, powerpoint, access, publisher, visio, project]
  require_gpo_delivery: true
```

### The fields people are tempted to skip

**`statement_sha256`** — the hash of the control prose the check was written
against. ASD reworded **111 control statements in a single quarter** while
keeping ids unchanged; `ism-0009` went from "supplementary controls" to
"supplementary **security** controls". Without this hash a check keeps passing
while no longer testing what the control says, and nothing surfaces it. CI fails
on drift so a human re-affirms or revises.

Get it with:

```bash
python -c "import sys;sys.path.insert(0,'tools');\
from nobytes_cca.catalog import Catalog; from ism_release import catalog_path;\
print(Catalog.load(catalog_path()).require('ism-1488').statement_sha256)"
```

**`coverage` + `rationale`** — what the check does **not** prove. This is the
most valuable text in the file, because it is the part nobody else supplies, and
it is aggregated into the published coverage statement. A `partial` coverage
with a thin rationale is rejected.

**`history_window_days`** — non-zero for *rate* controls. See
[`05-assessment-contract.md`](05-assessment-contract.md).

## 2. The evaluator — a pure function

```python
def macro_internet_blocked(bundle, params, history) -> CheckResult:
    install = bundle.fact("windows.office.install")
    if install is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.office.install` absent from the bundle")
    if not install.value:
        return CheckResult.not_applicable(
            detail="No Microsoft Office installation detected.",
            facts={"office_installed": False})
    ...
```

Rules:

- **No network, no subprocess, no clock.** Time arrives in the bundle. Enforced
  by tests, not convention.
- **Standard library plus PyYAML** only (ADR 0011), Python 3.9 syntax — so the
  evaluator runs in `ee-legacy` too.
- **Return `unassessed`, not `satisfied`, when the picture is incomplete.** A
  host with one unreadable profile hive and no observed failures is not a pass:
  the hive you could not read might be the failing one. Most tools get this
  wrong; it is the main reason this one exists.
- **A failure still reports as a failure** even when coverage is partial —
  positive evidence of non-compliance outranks incomplete coverage.

## 3. Check your work

```bash
make validate     # schema, catalog, prose drift, evaluator imports
make test         # invariants, purity, golden OSCAL
make coverage     # what the baseline now looks like
make assess-local # end-to-end against the fixture bundles
```

Add a fixture bundle under `tests/fixtures/bundles/` exercising the interesting
case — ideally the *partial* one, not just the happy path.

## Where the objective comes from

The ISM gives **one prose sentence per control and no assessment objective**.
Turning that into a testable assertion is authoring work, and it is this
project's real cost centre.

For the Microsoft 365 / Entra surface, ASD's
[Blueprint for Secure Cloud](https://blueprint.asd.gov.au/) supplies concrete,
citable configuration decisions (e.g. *"disable accounts after >45 days of
inactivity"* against ISM 1404/1648). Cite the Blueprint page and version in
`references`. It is prose guidance, not machine-readable config — a human reads
it and authors the objective; nothing parses it into a verdict.
