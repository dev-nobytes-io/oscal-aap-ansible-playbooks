# oscal-aap-ansible-playbooks

Continuous compliance **assessment and assurance** for Australian government and
large-enterprise estates — driven by the ACSC **Information Security Manual** in
OSCAL, executed by Ansible on **Red Hat Ansible Automation Platform**, **AWX**,
or plain `ansible-playbook`.

> **Status: early. Built in reviewable chunks.**
> PR 01 (this one) establishes repository structure, licensing and tooling.
> Nothing assesses anything yet. See [Roadmap](#roadmap).

---

## What this is

The ISM ships as a machine-readable OSCAL catalog: **1143 controls**, each
carrying its applicability to every security classification and to the Essential
Eight maturity levels. That is a genuinely good dataset, and almost nobody wires
it to anything that runs.

This project closes that gap. It takes the published catalog, binds controls to
real evidence collection across the platforms an enterprise actually runs, and
emits **OSCAL assessment results** that GRC tooling can consume — repeatedly,
on a schedule, at estate scale.

## What this is *not*

This matters more than the feature list, so it comes first.

- **It is not a compliance certificate.** It gathers evidence. People and
  processes achieve compliance; a tool reports on what it could observe.
- **It does not claim to automate the whole ISM.** Most ISM controls are
  organisational and cannot be tested by any tool. Of the 46 Essential Eight
  ML1 controls, roughly 20 are host-testable, about 10 need a system API rather
  than a host, and around 13 are procedural. The repository states which is
  which, per control, and never quietly counts an untested control as passing.
- **It says out loud which controls no tool can ever answer.** Multi-factor
  authentication on a *third party's* service, or whether a privileged access
  request was validated when first made, are not backlog items — they are
  outside what any collector can see. Those are declared `attested`, with the
  evidence source and owner named, and are **excluded from the coverage
  percentage** so the number cannot be raised by writing prose. See
  [ADR 0013](docs/adr/0013-declare-unobservable-controls-as-attested.md).
- **It does not interpret the law.** The PSPF, Privacy Act and SOCI Act
  catalogues here are this project's reading of published obligations, with
  citations so you can check them. They are not legal advice and carry no
  government endorsement.
- **Where this project and the ISM disagree, the ISM is authoritative.**

The binding version of these rules lives in
[`docs/ASSURANCE-PRINCIPLES.md`](docs/ASSURANCE-PRINCIPLES.md). CI enforces the
parts that can be enforced mechanically.

---

## How it works

```
  COLLECT                     EVALUATE                    EMIT
  ─────────────────────       ─────────────────────       ─────────────────────
  Ansible, read-only.    ──▶  Pure function.         ──▶  OSCAL assessment
  Gathers RAW FACTS           facts + control             results → POA&M
  from the target.            assertion → verdict.        → reports
  Never judges.               Runs off-host.
```

Splitting collection from evaluation is the decision everything else rests on:

- **Facts can be re-evaluated.** ASD revises the ISM quarterly. When control
  text changes, re-run evaluation against stored evidence instead of touching
  production hosts again.
- **Evidence stands alone.** The fact bundle is the auditor-facing artefact. A
  verdict without its underlying observation is an assertion, not assurance.
- **Read-only is structural.** Collector roles have no mutating module surface,
  so "assessment never changes a host" is enforceable rather than promised.
- **Evaluation needs no host**, which is what makes broad platform coverage and
  real unit testing tractable.
- **Legacy targets stay in reach.** Only collection needs an old execution
  environment; evaluation always runs on current Python.

## Legacy is in scope

Government estates run Windows Server 2012 and Windows 10 today. Modern Ansible
does not reach them: ansible-core dropped Server 2012/2012 R2 after **2.16**,
dropped managed-node Python 2.7/3.6 in **2.17**, and does not support RHEL 8 as
a managed node in **2.20**.

So this project ships **two execution environments**, selected per inventory
group:

| Image | ansible-core | Reaches |
|---|---|---|
| `ee-current` | 2.19.x | Server 2016+/Win 11, RHEL 9/10, Ubuntu 22.04/24.04 |
| `ee-legacy` | 2.16.x | Server 2012/2012 R2, RHEL 7/8, Python 2.7/3.6 targets |

Both images run `ansible-core` on Python 3.11 — an execution environment's own
interpreter is the *controller's*, and what reaches a 2012 host is core 2.16's
**managed-node** support. See [`docs/08`](docs/08-aap-deployment.md).

Refusing to assess a legacy host does not make it secure — it makes it
unmeasured. Note also that an estate running unsupported operating systems
**fails `ism-1501`, `ism-1704` and `ism-1905` by definition**, and all three are
Essential Eight ML1 controls. Detecting and quantifying that is a feature here,
not an embarrassment to be hidden.

---

## Frameworks

| Framework | OSCAL | Role here |
|---|---|---|
| **ISM** (ACSC/ASD) | Published by ASD | The technical spine. 1143 controls; the only framework with host-testable content. |
| **Essential Eight** | Published by ASD (ML1/ML2/ML3) | Primary baseline. ML1 = 46 controls; also the framework SOCI CIRMP recognises. |
| **PSPF** | Authored here | Obligation layer; points at the ISM for ICT systems |
| **Privacy Act 1988 / APPs** | Authored here | APP 11 "reasonable steps" evidenced via ISM controls |
| **SOCI Act / CIRMP Rules** | Authored here | Cyber framework obligation evidenced via Essential Eight ML1 |

Only the ISM has authoritative OSCAL. The other three are modelled as
*obligations* that crosswalk to the ISM controls able to supply supporting
evidence — never as host checks, and never reported as "compliant" because a
host check passed.

## Data provenance

ISM OSCAL data is vendored under `oscal/upstream/`, pinned to an upstream git
tag and checksummed, so a build is reproducible and works fully air-gapped.

- Authoritative source: <https://www.cyber.gov.au/ism/oscal>
- Ingest mirror: <https://github.com/AustralianCyberSecurityCentre/ism-oscal>
- Pinned release: **v2026.09.4** · OSCAL **1.1.2**
- Licence: **CC BY 4.0**, © Commonwealth of Australia — see [`NOTICE`](NOTICE)

Upstream files are never edited. The release-watch workflow opens a pull request
with a control-level diff when ASD publishes, so changes to Commonwealth control
text get reviewed rather than absorbed silently.

---

## Quickstart

```bash
make bootstrap    # virtualenv + pinned Python tooling
make deps         # Ansible collection dependencies
make lint         # yamllint + ansible-lint (production profile) + ruff
make help         # everything else
```

```bash
make fetch        # vendor the pinned ISM OSCAL release + NIST schemas (needs network)
make validate     # checksums, OSCAL schemas, check registry (fully offline)
make test         # canary, invariant, purity and golden-OSCAL tests
make ps-lint      # parse every Windows collector with PowerShell (needs pwsh)
make coverage     # honest control coverage for a baseline
make assess-local # end-to-end evaluate -> OSCAL against fixture bundles
make report       # human-readable assessment report (markdown + html)
make annex        # populate ASD's SSP Annex (.xlsx) from the results
```

Targets for work that has not landed yet print an explicit `SKIP` naming the
pull request that delivers them. They do not report success for work not done —
that failure mode is the whole reason this project exists.

**Requires Python 3.11.** ansible-core 2.20+ needs Python ≥3.12, so the control
node stays on 3.11 with core 2.19.x. See the rationale in
[`requirements.txt`](requirements.txt).

---

## Roadmap

Built as chunked pull requests: structure, then governing documents, then
content, gradually.

| PR | Chunk | State |
|---|---|---|
| 01 | Repository skeleton, licensing, lint + CI | merged |
| 02 | Governance, assurance principles, regulatory scope, ADRs | merged |
| 03 | OSCAL ingest — fetch, pin, checksum, validate, release watch | merged |
| 04 | Check contract, evaluator, assessment-results + POA&M emitters | merged |
| 05 | Component-definition model + Windows collectors | merged |
| 06 | Linux collectors + end-of-life dataset | merged |
| 07 | Dual execution environments + AAP/AWX configuration-as-code | merged |
| 08 | Attestation model — declare what no tool can observe | merged |
| 09 | Entra ID collectors + Blueprint vendoring | merged |
| 10 | Reporting — human-readable report + ASD SSP Annex | merged |
| 11 | Windows application control — AppLocker / WDAC | merged |
| 12 | User application hardening — unsupported applications | merged |
| 13 | Application control reaches user profiles and temp folders | merged |
| 14 | Population arithmetic, aggregate scope, and the guards that could not see | **this PR** |
| 15 | Active Directory privileged access — one attestation, five documented refusals | **this PR** |
| 16 | Redaction is applied, not merely declared | **this PR** |
| 17 | Fact store — unblocks the 12 temporal ML1 controls | planned |
| 18 | Web browser hardening | planned |
| 19+ | CyberArk, ADCS, ADFS, Keycloak, Exchange, NetApp, Splunk, Change Auditor, VMware, Proxmox, XCP-ng, containers, network, cloud | planned |
| then | Obligation layer — PSPF, APPs, SOCI/CIRMP | planned |
| last | Remediation scaffolding — opt-in, separated | planned |

Assessment comes first throughout. Remediation is deliberately last, opt-in and
never invoked by an assessment run.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The one rule worth stating up front:
**a wrong verdict is worse than a missing one**, because someone acts on it.
Coverage gaps are acceptable and tracked; confident incorrectness is not.

Start with [`docs/ASSURANCE-PRINCIPLES.md`](docs/ASSURANCE-PRINCIPLES.md) — it is
the binding document, and most review feedback traces back to it. Decisions are
recorded as [ADRs](docs/adr/).

## Licence

- **Code**: Apache License 2.0 — see [`LICENSE`](LICENSE)
- **Vendored ISM data**: CC BY 4.0, © Commonwealth of Australia — see [`NOTICE`](NOTICE)

Not affiliated with, endorsed by, or approved by the Australian Signals
Directorate, the Australian Cyber Security Centre, or the Commonwealth of
Australia.
