# Contributing

Thanks for considering it. Please read
[`docs/ASSURANCE-PRINCIPLES.md`](docs/ASSURANCE-PRINCIPLES.md) first — it is the
binding document, and most review feedback here traces back to it.

## The one rule

> **A wrong verdict is worse than a missing one.**

A control with no check prompts someone to go and look. A control wrongly
reported as satisfied gets believed, written into an authorisation package, and
acted upon. Coverage gaps are acceptable, tracked and published. Confident
incorrectness is not acceptable at any coverage level.

In practice this means a PR that says *"this check only verifies policy state,
not runtime behaviour, so confidence is `proxy` and here is the residual gap"*
is better than one claiming `direct` and being subtly wrong — even though the
first looks weaker on a dashboard.

## Getting set up

```bash
make bootstrap    # virtualenv + pinned Python tooling
make deps         # Ansible collection dependencies
make lint         # exactly what CI runs
make test         # unit tests
make ps-lint      # PowerShell collectors, if you have pwsh (CI always does)
```

Requires **Python 3.11**. ansible-core 2.20+ needs Python ≥3.12, so the control
node stays on 3.11 with core 2.19.x — see the rationale in `requirements.txt`.

`pre-commit install` is recommended; it mirrors CI.

## Chunked pull requests

This repository is built in numbered chunks: structure, then governing
documents, then content. Keep PRs within one chunk. A PR that adds a collector
*and* changes the evaluator contract *and* adds a crosswalk is three PRs.

## Adding a check

Two files. You do not write OSCAL — component-definitions, assessment-plan
activities, the coverage ledger and the docs are all generated from the registry
entry, and CI fails if regenerating produces a diff.

1. **`checks/<platform>/<check-id>.yml`** — the registry entry. Every field in
   [`checks/README.md`](checks/README.md) is mandatory for a reason; see below.
2. **An evaluator function** — a pure function of
   `(bundle, params, history) -> CheckResult`.

If the check needs facts nobody collects yet, a third file: the collect role.
Collect roles gather raw values and **never judge**.

### Fields people are tempted to skip

**`statement_sha256`** — the hash of the ISM control prose the check was written
against. ASD publishes quarterly; 26 releases exist so far. Without this, a
reworded control keeps passing a check that no longer tests what it says, and
nothing surfaces it. CI fails on drift so a human has to re-affirm.

**`confidence`** and **`coverage` + `rationale`** — say what the check does not
prove. This is the most valuable text in the file, because it is the part nobody
else supplies. A `coverage: partial` entry without a rationale is rejected.

**`history_window_days`** — non-zero for *rate* controls. Roughly a quarter of
Essential Eight ML1 is temporal rather than stateful: `ism-1690/1691/1694/1695/1876/1877`
(patch windows) and `ism-1698/1699/1701/1702/1807` (scan cadence). No
point-in-time fact can answer "applied within 48 hours of release". A check that
cannot satisfy its window returns `unassessed / insufficient-history` — **never**
`not-satisfied`.

### Evaluators must stay pure

No network. No subprocess. Standard library only at runtime, Python 3.9 syntax —
so the evaluator runs under a RHEL 9 / CentOS Stream 9 system interpreter, which
in an air-gapped enclave may be the only one available (ADR 0007).

This is enforced: the suite runs with `socket.socket` and `subprocess.Popen`
patched to raise, with networking disabled, and with an import contract over
`checks.*`. Adding an import there needs explicit architecture sign-off.

Purity is what makes evidence re-evaluatable and output byte-identical for the
same input — which is what makes golden-file testing possible. It is worth more
than any individual check.

### Prefer honest `unassessed` over optimistic `satisfied`

If two of three user profile hives were readable and neither failed, the answer
is **`unassessed / partial-population`**, not `satisfied`. Most tools get this
wrong. It is the main reason this one exists.

## Adding a crosswalk entry

Every entry needs a **citation** and an **equivalence rating**
(`equivalent` / `partial` / `related`). A STIG rule is not an ISM control, and
treating them as identical is the most likely route to being quietly wrong.

Obligation mappings (PSPF, APPs, SOCI) say *contributes evidence toward*. They
never say *satisfies*. See principle 11.

## Review expectations

Expect questions about what a check does **not** prove, whether the population
denominator is right, and whether a failure mode produces `unassessed` rather
than `not-satisfied`. These are not nitpicks — they are the product.

Changes to `oscal/mappings/`, `oscal/catalogs/`, `oscal/component-definitions/`
and the assurance principles carry extra scrutiny; see `.github/CODEOWNERS`.

## Describing your testing honestly

The PR template asks you to separate verified-locally, verified-in-CI and
not-verified. Please actually separate them. Much of this project cannot be
tested without real kit — a Windows host, an Entra tenant, a vSphere endpoint,
an AAP controller — and saying so plainly is expected and fine.

Describing unverified work as tested is the one thing that will get a PR closed
rather than reviewed.

## Commit messages

Explain *why*. A one-line summary, then prose. If a change encodes a decision
about control interpretation, say what the interpretation is and what it
excludes — that reasoning is audit evidence, not commentary.

Significant architectural decisions get an ADR in `docs/adr/` instead.

## Licensing

Contributions are licensed under Apache-2.0. Do not add content derived from
sources whose licensing you have not checked — and never paste ISM control text
into an authored file. Vendored Commonwealth material lives in
`oscal/upstream/`, unmodified, under CC BY 4.0. See [`NOTICE`](NOTICE).
