# Documentation

The documentation is a deliverable, not an afterthought: this repository makes
claims about regulatory compliance, and a claim nobody can audit is worthless.

| Document | Purpose |
|---|---|
| [`ASSURANCE-PRINCIPLES.md`](ASSURANCE-PRINCIPLES.md) | **The binding rules.** What may and may not be claimed. Everything else answers to this. |
| `01-architecture.md` | The collect / evaluate / emit pipeline and why it is split that way |
| `02-oscal-primer.md` | Enough OSCAL to read this repo: catalog, profile, component-definition, assessment-results, POA&M |
| `03-ism-oscal-ingest.md` | Where ACSC ISM OSCAL comes from, how releases are pinned and refreshed |
| `04-regulatory-scope.md` | PSPF, Privacy Act / APPs, SOCI / CIRMP — and what is **not** technically assessable |
| `05-assessment-contract.md` | The check contract every collector on every platform must satisfy |
| `06-authoring-a-check.md` | How to add evidence collection for a new control |
| `07-*` / `platforms/` | One page per target platform family |
| `08-aap-deployment.md` | Ansible Automation Platform 2.6 deployment |
| `09-awx-deployment.md` | AWX deployment |
| `10-evidence-and-assurance.md` | Evidence lifecycle, freshness, provenance, chain of custody |
| `11-poam-and-reporting.md` | Findings to POA&M; obligation-level reporting |
| `12-operations-runbook.md` | Running this at estate scale |
| `13-security-model.md` | Least privilege, credential handling, evidence integrity |
| [`adr/`](adr/) | Architecture Decision Records |
| [`oscal-extensions.md`](oscal-extensions.md) | Our OSCAL prop namespace and vocabulary |
| [`GLOSSARY.md`](GLOSSARY.md) | Terms |
| [`VERSIONING.md`](VERSIONING.md) | How this project, the ISM catalog and OSCAL version independently |

### Present in this repository today

[`ASSURANCE-PRINCIPLES.md`](ASSURANCE-PRINCIPLES.md) ·
[`01-architecture.md`](01-architecture.md) ·
[`02-oscal-primer.md`](02-oscal-primer.md) ·
[`03-ism-oscal-ingest.md`](03-ism-oscal-ingest.md) ·
[`05-assessment-contract.md`](05-assessment-contract.md) ·
[`06-authoring-a-check.md`](06-authoring-a-check.md) ·
[`platforms/windows.md`](platforms/windows.md) ·
[`04-regulatory-scope.md`](04-regulatory-scope.md) ·
[`13-security-model.md`](13-security-model.md) ·
[`oscal-extensions.md`](oscal-extensions.md) ·
[`GLOSSARY.md`](GLOSSARY.md) ·
[`VERSIONING.md`](VERSIONING.md) ·
[`adr/`](adr/)

Remaining documents land with the pull request that makes them true, not in
advance. A document describing a collector that does not exist is a liability,
not a head start.
