# oscal-aap-ansible-playbooks

Continuous compliance **assessment and assurance** for Australian government and
large-enterprise estates — driven by the ACSC **Information Security Manual** in
OSCAL, executed by Ansible on **Red Hat Ansible Automation Platform**, **AWX**,
or plain `ansible-playbook`.

> **Status: working, partial, and honest about which.**
> The pipeline runs end to end — collect, evaluate, emit schema-valid OSCAL,
> report — and **15 of the 46 Essential Eight ML1 controls (32.6%) have an
> automated check**, with 6 more declared `attested` because no tool can observe
> them. `make coverage` prints the real figure and is built so it cannot
> flatter. Start at [Installing from scratch](#installing-from-scratch); see
> [Roadmap](#roadmap) for what is next and
> [what an install can prove](#what-an-install-can-prove-and-what-it-cannot)
> for what is still unverified.

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

## Installing from scratch

Every command in this section was run against a clean `git clone` on a machine
with nothing pre-installed, and the output shown is what it printed. Where a
step has *not* been verified that way, it says so.

### What the control node needs

| | |
|---|---|
| OS | Linux or macOS. Windows is a **target**, never the control node |
| **Python 3.11** | exactly 3.11 — see below |
| `git`, `make`, `pip` | no compiler or dev headers — nothing in the dependency set is built from source |
| Optional — `pwsh` 7.x | only for `make ps-lint` |
| Optional — `docker` or `podman` | only for `make ee-build` |

**Python 3.11 is a hard requirement, not a preference.** ansible-core 2.20+
needs Python ≥3.12 and drops managed-node support this project still needs, so
the control node stays on 3.11 with core 2.19.x. The *evaluator* separately
targets 3.9, because RHEL 9 system Python is 3.9 and it is invoked with whatever
`python3` an enclave hands it — see [ADR 0007](docs/adr/0007-evaluator-is-a-plain-python-package.md).

### Install — connected

```bash
git clone https://github.com/dev-nobytes-io/oscal-aap-ansible-playbooks.git
cd oscal-aap-ansible-playbooks

make bootstrap   # virtualenv + pinned Python tooling          (needs PyPI)
make deps        # third-party Ansible collections             (needs galaxy)
```

```
bootstrap OK -> Python 3.11.15, ansible [core 2.19.13]
ansible.posix:2.2.2 was installed successfully
ansible.windows:3.8.0 was installed successfully
community.general:12.6.5 was installed successfully
```

**Those two commands are the only steps that touch the network.** Everything
below runs fully offline:

```bash
make lint         # yamllint --strict + ansible-lint (production) + ruff + doc links
make validate     # checksums, pinned NIST schemas, check registry
make test         # canary, invariant, purity, wire-form and golden-OSCAL tests
make coverage     # honest control coverage for a baseline
make assess-local # evaluate -> OSCAL against the bundled fixtures
make report       # human-readable report (markdown + html)
make annex        # populate ASD's SSP Annex (.xlsx) from the results
make ps-lint      # parse every Windows collector with PowerShell (needs pwsh)
make assess-self  # run the REAL collect playbook against this host, then evaluate
make help         # everything else
```

Expected on a correct install:

```
Passed: 0 failure(s), 0 warning(s) in 103 files processed. Profile 'production' was required, and it passed.
18 OSCAL documents valid against NIST schemas; invariants hold
21 check(s) valid against schema, catalog and evaluators
329 passed, 13 skipped
automated coverage     : 32.6%
3 live OSCAL documents valid
```

Two notes on reading that output. The **13 skipped** are the PowerShell tests,
which skip when `pwsh` is not installed — with it on `PATH` the same suite
reports `342 passed`, and both are correct. And if `make coverage` prints a
different percentage, the install is fine and the repository has moved: that
figure is measured, not asserted.

### Install — air-gapped

This is the deployment this project is built for, so it is verified rather than
described. On a connected machine, stage both dependency sets:

```bash
pip download -r requirements.txt -d wheelhouse
ansible-galaxy collection download -r requirements.yml -p collection-tarballs
```

Carry `wheelhouse/`, `collection-tarballs/` and the repository across. Then,
with **no** package index and **no** galaxy reachable:

```bash
python3 -m venv .venv
.venv/bin/pip install --no-index --find-links ../wheelhouse -r requirements.txt
.venv/bin/pip install --no-index --no-build-isolation -e .

# NOTE: run this from INSIDE the download directory. The requirements.yml that
# `collection download` generates references the tarballs by RELATIVE path, so
# installing from anywhere else fails with "Could not find ansible-posix-…tar.gz".
cd ../collection-tarballs
ansible-galaxy collection install -r requirements.yml \
  -p /path/to/repo/collections --offline
```

`make lint`, `validate`, `test`, `coverage`, `assess-local`, `report`, `annex`
and `assess-self` then all pass with the network removed. `ansible-lint` is
configured `offline: true` precisely so linting never reaches for galaxy.

Two things worth knowing about that run:

- The third-party collections are needed only for the platforms that use them —
  `ansible.windows` for Windows, `community.general` for the Entra and LDAP
  surface. The Linux path, the whole test suite and `make assess-self` pass
  **with no third-party collections installed at all**, because they use
  `ansible.builtin` plus the in-repo `nobytes.compliance`.
- `make fetch` is **not** part of installation. See below.

### What ships in the clone — and what does not

The clone is ~20 MB and carries every piece of compliance data, checksum-pinned:

| Vendored, in-repo | Version |
|---|---|
| ACSC/ASD **ISM OSCAL** catalogue, profiles and resolved catalogues | `v2026.09.4` |
| **NIST OSCAL schemas** for validation | 1.1.2 |
| **endoflife.date** support dataset | pinned snapshot |
| **ASD Blueprint** cited pages + SSP Annex / Essential Eight templates | `v1.4.0` |

So **no compliance data is downloaded at install time**, and an assessment run
never reaches the internet for a control definition. `make fetch` exists only to
*re-vendor* — bumping to a new ISM release, driven by the release-watch
workflow, never by hand. Do not run it as an install step.

### First run against a real estate

`make assess-self` proves the pipeline end to end against the control node
itself. For an actual estate:

1. **Write an inventory.** Start from [`inventory/example.yml`](inventory/example.yml).
   Two group variables drive behaviour: `ism_baseline` (which OSCAL profile
   applies) and `estate_tier` (`current` or `legacy`, selecting the execution
   environment). Real inventories do not belong in this repository —
   see [`inventory/README.md`](inventory/README.md).
2. **Set the redaction salt from a vault.** `fact_bundle_redaction_salt` has no
   usable default; the role refuses to run until it is set, because a hash under
   a known salt is reversible and correlatable across organisations.
3. **Scope the credential read-only.** This is the real control, not the code —
   [`docs/13-security-model.md`](docs/13-security-model.md). Per-platform
   requirements are in [`docs/platforms/`](docs/platforms/).
4. **Run it.**

```bash
ansible-playbook -i inventory/mine.yml playbooks/assess.yml \
  -e fact_bundle_redaction_salt="$(vault-read …)"
```

Assessment playbooks have **no mutating module surface at all** — that is
enforced by an allowlist test, not promised in a comment. `remediate.yml` is
separate, opt-in, and never invoked by an assessment run.

### AAP 2.6 and AWX

```bash
make ee-build EE=ee-current    # ansible-core 2.19.x
make ee-build EE=ee-legacy     # ansible-core 2.16.x, for Server 2012 / RHEL 7-8 targets
```

Needs a container runtime, so it is CI-and-lab only — Docker is unavailable in
this project's development sandbox, which is exactly how three EE defects went
undetected until the first real build. Controller configuration-as-code and job
template definitions are in [`aap/`](aap/), with walkthroughs in
[`docs/08-aap-deployment.md`](docs/08-aap-deployment.md) and
[`docs/09-awx-deployment.md`](docs/09-awx-deployment.md).

### What an install can prove, and what it cannot

| Verified by the steps above | Needs a lab |
|---|---|
| Evaluators, emitters, OSCAL validity, coverage arithmetic | A Windows host — **no Windows collector has ever run on Windows** |
| The Linux collect path, live, end to end | An Entra ID tenant — Graph collectors have never touched one |
| Air-gapped install and offline operation | A real AAP controller; the `ee-legacy` tier |
| PowerShell **parsing**, and two parsers **executed** on Linux | PowerShell against a real registry |

That right-hand column is the honest state of the project, not a disclaimer.
[`docs/platforms/windows.md`](docs/platforms/windows.md) keeps the same
distinction per technique.

Targets for work that has not landed yet print an explicit `SKIP` naming the
pull request that delivers them. They do not report success for work not done —
that failure mode is the whole reason this project exists.

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
| 14 | Population arithmetic, aggregate scope, and the guards that could not see | merged |
| 15 | Active Directory privileged access — one attestation, five documented refusals | merged |
| 16 | Redaction is applied, not merely declared | merged |
| 17 | Web browser hardening — and three traps in it | merged |
| 18 | The Windows collection path has never worked — output contract + guards that fail closed | **this PR** |
| 19 | Redaction reaches identifiers inside lists | planned |
| 20 | Three-way fact-key reconciliation — declared, emitted, consumed | planned |
| 21 | Lab validation harness + a derived verification axis | planned |
| 22 | Fact store — unblocks the 12 temporal ML1 controls | planned |
| 23+ | CyberArk, ADCS, ADFS, Keycloak, Exchange, NetApp, Splunk, Change Auditor, VMware, Proxmox, XCP-ng, containers, network, cloud | planned |
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
