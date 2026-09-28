# Lab validation runbook

**Read this first: what a lab run can and cannot establish is in
[`experiment-sheet.md`](experiment-sheet.md), and it is written before any run
rather than after one.**

Fourteen of the fifteen automated controls have never had their collector
executed against the platform it reads. [ADR 0017](../adr/0017-the-collector-output-contract.md)
established what that costs: the entire Windows collection path had never
populated a fact on a real host, and it surfaced as one confident false
`not-satisfied` and one false `satisfied` at **`direct`** confidence.

This runbook closes that gap for whatever the lab can actually reach.

## What crosses the boundary — and what does not

**The bundle never leaves the lab. The digest does.**

A fact bundle is evidence about a real estate: hostnames, SIDs, installed
software, registry contents. None of it is needed for the comparison this
harness makes, which is about key *paths* and value *types*.

`cca lab-digest` reduces a bundle to a **shape digest**: every key path, each
value's type, list cardinalities — and **no values at all**. Where a mapping's
*keys* are themselves collected content (`java_surface.javasoft` is keyed by
verbatim registry path; `policy.rows[].values` by Group Policy setting name,
including custom organisational ADMX) the digest emits a count plus a salted
hash per key, so a comparison still sees *that* a key differs without learning
what it was. `subject.asset_id` is dropped; `platform_family` and `estate_tier`
travel, because the comparison must be keyed on platform.

Credentials never reach the repository or anyone reviewing the digest.

## The read-only credential

This is the real control. The code is not.

Run the collectors under an account scoped per
[`docs/13-security-model.md`](../13-security-model.md). Two things are worth
stating plainly:

- **Running as Domain Admin proves the collectors *work*. It does not prove they
  work with the read-only credential the documentation specifies.** Those are
  different claims, and conflating them is how an assessment tool ends up
  needing privilege it told you it did not need.
- **Some reads genuinely require elevation.** `Get-WindowsOptionalFeature -Online`
  does, `Win32_DeviceGuard` needs an explicit WMI namespace ACE, and another
  user's profile hive is unreadable to a non-admin by design. Record which
  credential each run used — a floor met under Domain Admin and a floor met
  under a scoped account are not the same result.

## Running it

```bash
cp inventory/lab.yml.example inventory/lab.yml   # gitignored; edit for your lab
make lab-validate LAB_SALT="$(vault-read cca/lab/salt)"
```

That runs the **real** `playbooks/collect.yml` — not a parallel lab playbook.
A separate code path could diverge from the one production uses, which is this
repository's recurring defect in a new costume. Then:

```bash
make lab-digest LAB_SALT=…    # bundle -> out/lab/digest.json, no values
make lab-diff   LAB_SALT=…    # reconcile, and exit non-zero on a hard failure
```

## What comes back

Send **`out/lab/digest.json`**. Nothing else is needed, and nothing else should
travel.

The digest carries a `self_sha256` over its own content, so a hand-edited digest
is detectable — `lab-diff` refuses one outright. It also carries the bundle's
classification `marking`, the run id and the collection timestamp. **Review it
before it leaves**, and treat that review as the control: the guarantee here is
the declared keyspace split plus a human reading the file, not a proof.

## How to read the result

`lab-diff` reconciles three things, and two would not be enough — collector
reality against the fixtures is two artefacts an author wrote from one
assumption, which is exactly how the `display_name`/`name` defect passed 260
tests. The third leg is what the evaluators actually read, extracted from their
AST.

| Result | Means |
|---|---|
| **FAIL** — keys read but never emitted | An evaluator reads a key nothing produces, on a fact this run carried. It will read as absent on every host, forever, silently. This is the `display_name` signature. |
| **FAIL** — floors unmet | The run establishes **nothing** about those facts. Not that the estate lacks the thing — that nothing was learned. They must not be promoted. |
| **REVIEW** — read but never exercised | A key no bundle in scope populates. Often a platform this run did not touch; always a branch no real observation has hit. |
| **REVIEW** — lab found, fixtures do not model | Reality is ahead of the corpus. Usually means a fixture should gain a path. |
| **REVIEW** — fixtures model, lab did not produce | Either the host genuinely lacks it, or the fixture is a fiction. Worth deciding which. |

Only the two FAIL rows are failures. Everything else needs a person, and saying
so is deliberate: a guard that cried wolf on every difference would be switched
off within a week, and a guard that is switched off is worse than none.
