# ADR 0016: Apply the redaction policy

## Context

[ADR 0008](0008-redaction-is-policy-driven-per-deployment.md) decided that
evidence redaction is a per-deployment policy applied between collection and
persistence. The policy was then specified in full and **ran nowhere**.

From PR 04 to PR 15, verified at `ee0c718`:

- `fact_bundle_redaction_keys` (`sid`, `username`, `upn`, `email`, each `hash`)
  was referenced **nowhere outside `defaults/main.yml`**.
- No hashing existed anywhere in the collection. The only occurrences of the
  word were the configuration values themselves.
- `finalise.yml` wrote `facts: "{{ fact_bundle_facts | default({}) }}"` —
  verbatim — from a task named *"Redact identifiers and write the fact bundle"*.
- Every bundle stamped `redaction_policy: "1.0"`.
- The role **refused to run** until `fact_bundle_redaction_salt` was changed
  from its placeholder, and the salt was then never used for anything.

So a bundle produced by the Windows Office collector carried raw
`S-1-5-21-…` SIDs while asserting they had been hashed. The evidence store is
the dataset this project's own documentation calls a crown jewel, and it
shipped with a protection it did not have.

This is the **sixth** time this repository has found the same shape in itself —
a guard or protection structurally unable to perform the thing it claims. It is
the second to reach output rather than tooling, and the first that is a
security claim rather than an arithmetic one.

## Decision

**Redaction is applied by a filter plugin, `nobytes.compliance.redact_facts`,
called from `finalise.yml`.** It walks the fact tree and applies the
per-key action, recursing through lists and mappings so that identifiers nested
inside a fact's value — which is where they actually live — are reached.

**The test that matters asserts the wiring, not the filter.** A correct filter
nobody calls is exactly what was already shipping, so
`test_finalise_actually_applies_the_policy` parses `finalise.yml` and fails
unless the bundle's `facts` pass through `redact_facts` with all three policy
variables. It was verified to fail against the code as it shipped.

Three decisions follow from making the policy real.

**The default action becomes `retain`, not `hash`.** The shipped default was
`hash`, which — once actually applied — would have hashed every leaf in the
tree, turning `vbawarnings: 2` into an opaque digest and destroying the
evidence the bundle exists to carry. `retain` is also what the code did before
this change, so the declared default now describes the shipped behaviour
instead of contradicting it. Identifier keys are named explicitly and hashed;
everything else is kept.

**The salt guard fires on any hashing, not on the default action.** It was
gated on `fact_bundle_redaction_default == 'hash'`. With the default corrected
to `retain`, that guard would have silently stopped firing for the shipped
policy — which hashes four keys. It now tests the per-key actions too.

**Hashing without a real salt raises.** Not a warning: the filter refuses an
empty salt and refuses the shipped placeholder. A hash under a known salt is a
reversible hash with extra steps, and correlatable across organisations.

**Scope is `facts` only.** `subject.asset_id` is deliberately not redacted. It
is the correlation key that gives a POA&M item continuity across runs, and
hashing it would break that while protecting nothing — the inventory it came
from holds the same value in clear. A deployment needing it pseudonymous sets
`cca_asset_id` to an already-pseudonymous value.

**Truncation keeps well-known RIDs.** `docs/13-security-model.md` defines SID
truncation as removing the RID, and within a domain the RID is the account. But
RIDs below 1000 are identical on every Windows domain — `500` is the built-in
Administrator, `512` Domain Admins — so they name a role rather than a person.
Masking them would leave a truncated bundle unable to answer the
privileged-access controls it was collected for while protecting nobody.

## Consequences

- **Bundles change shape.** A `sid` becomes `sha256:<32 hex>`. Anything holding
  bundles collected before this change has unredacted identifiers in them,
  regardless of the `redaction_policy` stamp they carry, and should be treated
  accordingly.
- Hashing is truncated to 128 bits. Far beyond collision risk for an
  estate-sized population, and a full 64-character digest makes a bundle
  unreadable to a human auditor.
- The accepted costs in ADR 0008 now actually apply: hashing loses remediation
  targeting, and rotating the salt breaks longitudinal correlation. They were
  documented as costs while nothing was being paid.
- A deployment that wants no redaction sets every key to `retain` — a
  deliberate, reviewable choice, which is the point of ADR 0008.

## Alternatives considered

**Redact in the evaluator.** Too late: the bundle is already on disk, and you
cannot retroactively un-collect.

**Pure Jinja in `finalise.yml`.** Recursive walking of an arbitrary nested
structure in Jinja is unreadable and untestable. The defect being fixed here is
partly a consequence of redaction having no code to test.

**Drop the `redaction_policy` stamp instead, and document that bundles are
unredacted.** Honest, and far cheaper. Rejected because ADR 0008's reasoning
still stands: the evidence is sensitive, the trade-off belongs to the risk
owner, and the project had already told deployments to set a salt.
