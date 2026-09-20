# Glossary

| Term | Meaning |
|---|---|
| **ACSC** | Australian Cyber Security Centre, part of ASD |
| **ASD** | Australian Signals Directorate — publishes the ISM |
| **APP** | Australian Privacy Principle (13 of them, under the Privacy Act 1988) |
| **Attestation** | A human assertion that a control is met, where no automated determination is possible. An OSCAL `result.attestations[]` entry. |
| **Baseline** | A selected subset of controls — a classification level or an Essential Eight maturity level |
| **CIRMP** | Critical Infrastructure Risk Management Program, under the SOCI Act |
| **Check** | A registry entry binding an ISM control to a collector and an evaluator |
| **Collector** | An Ansible role that gathers raw facts. Read-only; never judges. |
| **Component-definition** | OSCAL model binding controls to what can evidence them |
| **Confidence** | `direct`, `proxy`, `partial` or `attested` — how closely a check observes what the control actually requires |
| **Coverage ledger** | Generated statement of which controls are assessed, at what confidence, on which platforms |
| **E8 / Essential Eight** | ASD's eight mitigation strategies, with maturity levels ML0–ML3 |
| **EE** | Execution Environment — the container image Ansible runs in |
| **Evaluator** | Pure function `(bundle, params, history) → CheckResult`. Runs off-host. |
| **Evidence tier** | `passive`, `active` or `mutating` — whether obtaining a fact has side effects |
| **Fact bundle** | Raw collected facts for one subject at one time. The durable evidence artefact. |
| **Finding** | An OSCAL conclusion about a control, drawn from observations |
| **ISM** | Information Security Manual, published quarterly by ASD |
| **Observation** | An OSCAL record of something seen: method, subject, timestamp, evidence pointer |
| **OSCAL** | Open Security Controls Assessment Language, a NIST standard |
| **POA&M** | Plan of Action and Milestones — what is not met and what is being done |
| **Profile** | OSCAL model expressing a baseline as a selection over a catalog |
| **PSPF** | Protective Security Policy Framework |
| **Scope** (`subject` / `aggregate`) | Whether a check judges one host or a population |
| **SOCI** | Security of Critical Infrastructure Act 2018 |
| **Subject** | The thing assessed — a host, a tenant, a cluster |
| **Unassessed** | No determination was made. Distinct from "failing", and recorded with a reason. |

## Classification codes in ISM props

| Code | Meaning |
|---|---|
| `NC` | Non-classified |
| `OS` | OFFICIAL: Sensitive |
| `P` | PROTECTED |
| `S` | SECRET |
| `TS` | TOP SECRET |
