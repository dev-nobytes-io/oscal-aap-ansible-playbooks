# ADR 0020: Lab validation is a shape digest and a three-way reconciliation

## Context

Fourteen of the fifteen automated controls have never had their collector
executed against the platform it reads. [ADR 0017](0017-the-collector-output-contract.md)
established what that costs: the entire Windows collection path had never
populated a fact on a real host, producing one confident false `not-satisfied`
for `ism-0843`/`ism-1657` and a false `satisfied` at **`direct`** confidence for
`ism-1654` — the highest-confidence claim this project makes anywhere.

A lab host now exists: a Windows domain controller. It cannot be reached from the
development environment, so the harness is built here and run there, and the
question becomes what may cross back.

**The first design of this chunk was itself five instances of this project's
recurring defect**, found by adversarial review before anything was built. This
ADR records the constraints that came out of that, because each is a decision
rather than an implementation detail.

## Decision

### 1. A shape digest crosses the boundary; the bundle does not

`cca lab-digest` reduces a bundle to key paths, value types and list
cardinalities, with **no values**. `subject.asset_id` is dropped — it is the
estate's own name for the host. `platform_family` and `estate_tier` travel,
because the comparison must be keyed on platform.

Asserted rather than claimed: `test_the_digest_emits_no_values` builds a digest
from a bundle carrying a known SID, UPN, registry path and version string, and
fails if any appears.

### 2. The digest records FULL key paths, including keys of list elements

The `display_name`/`name` defect lived nested inside a list element of
`windows.applications.installed`. A digest of top-level fact keys would have been
**structurally incapable of seeing the bug class it exists to catch** — the same
shape as every other defect in this repository's record, in the tool built to
prevent it.

### 3. A digest cannot be both recursive and value-free by default

In this repository some fact-object **keys** are themselves collected data:
`windows.browsers.java_surface.value.javasoft` is keyed by verbatim registry path
(`Get-BrowserPolicy.ps1` emits JavaSoft content verbatim), and
`windows.browsers.policy.value.rows[].values` by Group Policy setting name —
which on a real DC includes whatever custom ADMX the organisation authored.

So `DATA_KEYSPACES` declares those positions, and their keys are emitted as a
count plus a salted hash each. A diff still sees *that* a key differs without
learning what it was.

**The declared list is the mechanism; a heuristic is only a tripwire.**
`test_content_shaped_keys_are_declared_data_keyspaces` flags mapping keys
containing a separator or space, which catches registry paths and URLs. It cannot
catch a plausible-looking policy name. Saying so is the point: the guarantee is
the declared list plus a human reading the digest before it leaves, not a proof.

### 4. The reconciliation is three-way, and only one condition is a hard failure

Collector reality against the fixture corpus is **two artefacts an author wrote
from one assumption** — exactly how the `display_name` defect passed 260 tests.
The third leg is what the evaluators actually read, extracted by AST-walking
`tools/nobytes_cca/checks/` for keys read off values derived from
`bundle.fact(...)`, with one level of helper-function propagation because the
real code does `_applocker(fact.value)`.

Exactly one condition fails a run:

> an evaluator reads a key that appears in neither the lab digest nor anywhere in
> the fixture corpus, **on a fact the run actually carried**.

That is the `display_name` signature, and nothing legitimate produces it. The
scoping matters: an Entra key read off an Entra fact is not a finding against a
Windows domain controller, and a key absent from the fixtures may be one no
bundle has exercised yet rather than one no collector emits.

Everything else is a **review item** for a person: paths the lab found that the
fixtures do not model, paths the fixtures model that the lab did not produce, and
keys no bundle in scope populates. A guard that cried wolf on every difference
would be switched off within a week, and a guard that is switched off is worse
than no guard.

### 5. An empty collector fails a declared floor rather than reading as agreement

A shape diff over an empty fact yields zero differences, and zero differences
reads as agreement. On a domain controller Office is not installed and no Edge
policy exists, so **two of the five Windows collectors return nothing**.

`docs/lab/floors.yml` declares, **before any run and committed**, the key paths
each fact must carry for the run to establish anything — keyed by
`platform_family`, because `os.release` legitimately carries a Windows shape
(`product_name`, `current_build`) and a Linux one (`id`, `version_id`), and a
floor keyed on fact alone would be wrong on one platform or accept anything on
both. A `partial` fact fails its floor unconditionally.

The floors for Office and browser policy are written **knowing they will fail on
a DC**, and declared rather than omitted so the run reports them as unmet rather
than as silence.

### 6. The harness runs the real collect playbook

`make lab-validate` runs `playbooks/collect.yml`. A dedicated `lab_validate.yml`
was in the design and was removed: a second code path could diverge from the one
production uses, which is this repository's recurring defect in a new costume.
Validating the real playbook is the point of validating anything.

## Consequences

Coverage is unchanged at **15 of 46 (32.6%)**. This chunk makes a lab run
*possible and honest*; it promotes nothing on its own, and
a later chunk will carry the derived verification axis that records an
outcome — deliberately a separate chunk, because the axis must be derived from an
attestation artefact that does not exist until a run has happened.

**Two defects were found by building it**, both in merged code:

- The digest initially walked only a fact's `value`, not the record's `meta`, so
  `app_support.py:124`'s read of `unloaded_hives` showed as "read but never
  emitted". Real finding, mine, fixed.
- Then the finding **persisted**, because no fixture populated
  `windows.applications.installed.meta` at all — the collector always emits
  `scanned_keys`, `loaded_hives` and `unloaded_hives`
  (`Get-InstalledApplications.ps1:66-70`), and the corpus modelled the fact
  without them. So that branch of `ism-1704` had never seen a bundle. The
  fixture now models it, with `unloaded_hives` empty so no verdict moves.

Worth recording as a collector inconsistency the digest surfaces rather than
hides: `collect_windows_browsers` nests `meta` **inside** the fact value, while
`collect_windows_applications` puts it on the fact **record**. Both are walked;
neither is normalised, because normalising would conceal the divergence.

Three evaluator reads are reported as never exercised by any bundle:
`NotifyDisableIEOptions` and `InternetExplorerIntegrationLevel`
(`windows.browser.ie_policy` is modelled by one fixture, without those keys) and
`policyType` (the Entra strength-policies fixture value is `null`). None is a
defect in the evaluators; each is a branch no real observation has hit.

**Not verified:** nothing here has run against a Windows host. The modules,
digest, floors and reconciliation are exercised against the fixture corpus and
by executing the AST extractor over the real evaluators. That is a different
claim from "the harness works on dc01", and
[`docs/lab/experiment-sheet.md`](../lab/experiment-sheet.md) states in advance
what a run can and cannot establish — including that three of five collectors are
promotable on a DC and two are not, that the `ee-legacy` tier stays unverified,
and that ADR 0015's five refusals cannot be overturned by one lab domain.

## Status

Accepted.
