# Architecture Decision Records

One file per decision: `NNNN-short-title.md`, numbered sequentially, never
renumbered. Use the standard shape — Context, Decision, Status, Consequences.

ADRs are immutable once merged. A decision that is later reversed gets a NEW
ADR that supersedes the old one; the original stays in place so the reasoning
history survives. In a compliance tool, "why was it built this way" is itself
audit evidence.

## Decisions

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-separate-collection-from-evaluation.md) | Separate collection from evaluation | Accepted |
| [0003](0003-component-definition-as-binding-layer.md) | Use OSCAL component-definition as the control-to-check binding | Accepted |
| [0004](0004-dual-execution-environments.md) | Ship two execution environments to reach legacy estates | Accepted |
| [0005](0005-ingest-from-acsc-github-mirror.md) | Ingest ISM OSCAL from the ACSC GitHub mirror, pinned to a release tag | Accepted |
| [0006](0006-absence-of-finding-means-no-determination.md) | Absence of a finding means no determination was made | Accepted |
| [0007](0007-evaluator-is-a-plain-python-package.md) | Ship the evaluator as a plain Python package, not an Ansible plugin | Accepted |
| [0008](0008-redaction-is-policy-driven-per-deployment.md) | Make evidence redaction a per-deployment policy | Accepted |
| [0009](0009-licensing-apache-code-ccby-data.md) | License code under Apache-2.0 and attribute vendored ISM data under CC BY 4.0 | Accepted |
| [0010](0010-do-not-depend-on-compliance-trestle.md) | Do not take compliance-trestle as a dependency | Accepted |
| [0011](0011-permit-pyyaml-in-the-evaluator-runtime.md) | Permit PyYAML in the evaluator runtime | Accepted |
