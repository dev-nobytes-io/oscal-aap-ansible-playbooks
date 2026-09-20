# Regulatory scope — and its limits

This project is aware of four Australian instruments. Only one of them is a
control framework that can be assessed by a tool.

| Instrument | OSCAL | What it is here |
|---|---|---|
| **ISM** (ASD/ACSC) | Published by ASD | The technical spine. 1143 controls; the only instrument with host-testable content. |
| **PSPF** | Authored here | Protective security obligations for Commonwealth entities |
| **Privacy Act 1988 / APPs** | Authored here | Privacy obligations, principally APP 11 |
| **SOCI Act / CIRMP Rules** | Authored here | Critical infrastructure risk management obligations |

**This page is scope and boundary, not legal analysis.** Precise requirement
identifiers, quoted obligations and citations land with the obligation layer in
PR 10, where each is sourced against the authoritative text. Nothing here should
be relied upon as advice.

## Why the other three are in scope at all

Not as a bolt-on. The ISM catalog's own `back-matter` — roughly 250 resources —
explicitly cites the **Protective Security Policy Framework**, the
**Privacy Act 1988**, the **Australian Privacy Principles** and the
**Security of Critical Infrastructure Act 2018**, alongside the Archives Act
1983 and the Telecommunications (Interception and Access) Act 1979.

The relationship runs in a consistent direction: these instruments impose
obligations, and they point at the ISM and the Essential Eight as the means of
meeting the technical portion. Most usefully for automation:

- The **PSPF** requires Commonwealth entities to apply the ISM to their ICT
  systems. ISM assessment is therefore direct evidence toward a PSPF obligation.
- The **CIRMP Rules** require a responsible entity to adopt one of a listed set
  of cyber security frameworks, and the **Essential Eight Maturity Level One** is
  among them. An E8 ML1 assessment maps unusually cleanly onto that obligation.
- **APP 11** requires "reasonable steps" to protect personal information. What is
  reasonable is not enumerated in the Act, and OAIC guidance points toward
  recognised technical baselines — which is where ISM and E8 evidence contributes.

## The boundary — what a tool can and cannot assess

This is the part that matters, and the part most compliance products blur.

| Layer | Example obligation | Can Ansible assess it? |
|---|---|---|
| ISM technical control | "Microsoft Office macros in files originating from the internet are blocked" | **Yes** — with stated confidence and residual gaps |
| ISM procedural control | "Requests for privileged access are validated when first requested" | **No** — a process, evidenced by attestation |
| PSPF requirement | Apply the ISM to ICT systems; governance, personnel and physical security | **Partly** — only the ICT-technical portion, and only as contributing evidence |
| APP 11 | Take reasonable steps to protect personal information | **No.** "Reasonable" is a legal standard weighing the entity's circumstances, the sensitivity of the information and the harm. A registry key is not that judgement. |
| SOCI CIRMP | Adopt and comply with a risk management program across four hazard vectors; board-approved annual report | **Partly** — the cyber framework element; not the personnel, supply chain or physical vectors, and certainly not the board's approval |
| SOCI incident reporting | Report within statutory timeframes | **No** — an organisational obligation about a response process |

### The rule this produces

> A crosswalk says *this ISM control contributes evidence toward this obligation*.
> It never says *this obligation is met*.

Obligation-level results are emitted as **partial** or **informative**, never as
`satisfied`. Every mapping carries a citation and a confidence rating.

"Privacy Act APP 11 satisfied" derived from a passing host check is not merely an
accuracy problem — it is a legal exposure for whoever relies on it, and it is the
kind of claim this project will not make. See
[`ASSURANCE-PRINCIPLES.md`](ASSURANCE-PRINCIPLES.md), principle 11.

## What this project will and will not do

**Will:** model the obligations as OSCAL catalogs; crosswalk them to the ISM
controls able to supply supporting evidence, with citations; generate
obligation-level reports showing which supporting evidence exists, which is
missing, and which parts no tool can address — for example, a CIRMP cyber
framework view driven by Essential Eight ML1 results, or an APP 11 evidence pack.

**Will not:** assert statutory compliance; interpret what an obligation requires
in a given organisation's circumstances; substitute for legal advice or for a
registered assessor; or present a framework-level percentage that silently mixes
technical evidence with untested organisational obligations.

## Classification and the Essential Eight

Two facts, verified against the catalog, that affect how baselines are selected:

- `applicability` is a repeated prop with values `NC`, `OS`, `P`, `S`, `TS`.
  Baseline sizes: NC 1017 · OS 1028 · P 1028 · S 1092 · TS 1101.
- **All 46 Essential Eight ML1 controls apply at every classification.**
  Intersecting E8 with a classification is a no-op; "ML1 for OFFICIAL" is simply
  ML1. Classification only begins to subset the catalog at the full baselines.

The Essential Eight Maturity Model defines **ML0–ML3**. There is no ML4. The
profile layer is driven from the catalog's own `essential-eight-applicability`
prop rather than a hard-coded ladder, so a future level would appear without a
code change.

## Caveat

Australian regulatory instruments change. The PSPF has been restructured in
recent years, the Privacy Act has been amended, and the SOCI Act has been
extended more than once. Anything in the obligation layer carries the date and
version of the source it was authored against, and stale citations are treated as
defects.
