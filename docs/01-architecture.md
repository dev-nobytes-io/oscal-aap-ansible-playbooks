# Architecture

## The pipeline

```
   COLLECT                  EVALUATE                     EMIT
   ─────────────────        ──────────────────────       ────────────────────
   Ansible, read-only  ──▶  Pure function           ──▶  OSCAL 1.1.2
   Raw facts from the       (bundle, params,             assessment-results
   target. No verdicts.      history) → verdict          → POA&M → reports
                             Runs off-host.
```

Three stages, deliberately separate. Facts in the middle, not verdicts.

## Why collection and evaluation are split

This is the decision everything else rests on, and it costs an extra layer. It
earns that cost five times over:

**Facts are re-evaluatable.** ASD revises the ISM quarterly — 26 releases so
far. When control text changes, or when an interpretation is found to be wrong,
re-run evaluation against stored evidence. The alternative is re-touching
production hosts to answer a question you already have the data for.

**Evidence has standalone value.** The fact bundle is the auditor-facing
artefact. A verdict without the observation behind it is an assertion, not
assurance. An auditor can re-derive the OSCAL document from the bundle and get
byte-identical output.

**Read-only becomes structural.** Collect roles carry no mutating module surface,
so "assessment never changes a host" is visible in review rather than promised in
a comment. (The guarantee that survives adversarial review is credential
scoping — see [`13-security-model.md`](13-security-model.md).)

**Evaluation needs no host.** Nearly all the logic, and therefore nearly all the
risk, lives in a pure function testable on any machine. This is what makes broad
platform coverage tractable at all. A useful consequence: because the PowerShell
collectors emit raw values and all interpretation is in Python, most Windows
check logic is testable on Linux with no Windows host and no container.

**Legacy stays in reach.** Only *collection* needs an old execution environment.
Evaluation always runs on current Python, so a Server 2012 box and a RHEL 10 box
produce the same bundle shape and are judged by identical code.

## What the split does not solve

Two classes of control do not fit "collect a fact, evaluate it later", and
pretending otherwise would quietly fake roughly a third of Essential Eight ML1.

### Temporal controls — about rates, not state

`ism-1690/1691/1694/1695/1876/1877` (patch windows) and
`ism-1698/1699/1701/1702/1807` (scan cadence) are **11 of the 46 ML1 controls**.
"Applied within 48 hours of release" cannot be answered by any single
point-in-time observation.

The evaluator signature is therefore `(bundle, params, history)`, where
`history` is a read-only accessor over prior bundles for the same subject.
Checks declare `history_window_days`. If the window cannot be satisfied the
result is `unassessed / insufficient-history` — never `not-satisfied`.

This makes the **fact store a first-class architectural component**, not a side
effect of running collections.

### Population controls — about a set, not a host

`ism-0445`, `ism-1175`, `ism-1380`, `ism-1689`, `ism-1812`, `ism-1814` are
statements about a *population* of accounts or hosts. Per-host facts cannot
answer them alone.

Checks declare `scope: subject` or `scope: aggregate` plus an aggregation key.
Aggregate findings carry `population-total` / `population-assessed` /
`population-failing`. Evaluating "no privileged account can log on to an
unprivileged environment" across 94% of hosts and emitting `satisfied` is the
most likely way this project becomes quietly wrong.

### The active-probe escape hatch

Some controls can only be *directly* tested by doing something with side
effects — fetching a page to prove a browser blocks Java, attempting egress from
a privileged account. Reading the policy instead is a `proxy`.

So facts declare an **evidence tier**:

| Tier | Meaning |
|---|---|
| `passive` | Observation only. The default; no side effects. |
| `active` | A probe with network side effects. Opt-in, separate role namespace, separate credential. |
| `mutating` | Never used for assessment. |

Active probes cost more than they look: they need write-or-network credentials
(so the read-only guarantee shifts onto credential scoping), they are not
reproducible from stored facts, they are non-deterministic, and in a government
environment each one needs change approval. They are marked `reproducible: false`
and the evaluator never re-derives a fresh verdict from a recorded probe outcome.

## Binding controls to checks

An OSCAL **component-definition** per platform family declares, per ISM control,
which collector gathers the evidence, which evaluator judges it, and at what
confidence.

The point is that **coverage becomes queryable data rather than a claim**.
"Which ML1 controls can we actually test on Windows Server 2019?" is answered by
querying these documents, and the coverage ledger is generated from them — so it
cannot drift into flattery.

A component is not always a machine. Some are `service` components for systems
that *hold* evidence about a control rather than being constrained by it:
CyberArk for privileged access, Splunk for log retention. Many observations, from
different providers with different methods and confidences, roll up into one
finding per (control, scope).

## Why the evaluator is not an Ansible plugin

The obvious design ships the evaluator as collection action/lookup plugins so
AAP calls it "natively". That is the wrong mechanism: plugins version-couple the
evaluator to `ansible-core`, are awkward to unit test, and evaluating 1000+
controls across thousands of hosts inside a `module_utils` import graph is the
wrong place to do that work.

The evaluator is an ordinary Python package, vendored into both execution
environments and invoked from a thin role. One implementation, two entrypoints.

## Determinism

Every OSCAL object gets a deterministic UUIDv5 derived from its identity, not a
random one. Consequences worth having:

- Re-running the evaluator on the same facts produces **byte-identical** output,
  which makes golden-file tests possible and `git diff` on results meaningful.
- POA&M items are **not run-scoped**, so `first-observed`, failure streaks and
  external ticket links survive across runs. Findings and observations are
  ephemeral per run; POA&M items are longitudinal.

The hard part is not the UUID scheme — it is **asset identity**. A rebuilt
machine with the same name is a different asset; a renamed machine is the same
asset. Use a durable key from AD/vCenter/Intune/CMDB and treat hostname as a
label. Getting this wrong silently corrupts all trend data.

## Storage tiers

| Tier | Holds | Purpose |
|---|---|---|
| Fact bundles | Raw collected facts, content-addressed, gzipped | System of record for evidence |
| Check results | One row per (check, subject, run), columnar | Trend, history, drift analytics |
| OSCAL documents | Assessment plans, results, POA&M | Attestable artefacts |

OSCAL is emitted **on publish**, not on every nightly collect. A full
assessment-results document for a large estate with per-host observations is
hundreds of megabytes that no tool will open — so aggregate findings carry true
population counts while embedding a bounded sample of observations, with full
detail referenced in the evidence store. A delta document, covering only controls
whose status changed, is what dashboards and auditors actually read.

## Execution environments

| Image | ansible-core | Reaches |
|---|---|---|
| `ee-current` | 2.19.x | Server 2016+/Win 11, RHEL 9/10, Ubuntu 22.04/24.04 |
| `ee-legacy` | 2.16.x | Server 2012/2012 R2, RHEL 7/8, Python 2.7/3.6 targets |

A job template binds exactly one execution environment, so the **inventory** is
split by tier, not the job. Tier is derived from CMDB/AD/vCenter OS data rather
than from gathered facts — you need the right image before you can gather
anything.
