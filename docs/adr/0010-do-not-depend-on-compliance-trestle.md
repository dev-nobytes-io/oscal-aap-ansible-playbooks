# ADR 0010: Do not take compliance-trestle as a dependency

## Context

[compliance-trestle](https://github.com/oscal-compass/compliance-trestle) is the
OSCAL toolkit from the oscal-compass project (a CNCF-adjacent effort, Apache-2.0,
actively maintained — 5.1.0 released September 2026). It provides typed pydantic
models for every OSCAL layer, validation, profile resolution and a task plugin
framework. It is the obvious thing to build on, and not evaluating it would be
negligent.

It was evaluated empirically against the real ACSC data rather than from its
documentation.

### What it does well

| Test | Result |
|---|---|
| Parse the ACSC `ISM_catalog.json` (OSCAL 1.1.2) | **Succeeds** — all 1192 controls |
| Preserve `oscal-version: 1.1.2` on round-trip | **Yes** — it does not force 1.2.1 |
| Preserve ASD custom props and the `cyber.gov.au` namespace | **Yes** |
| Round-trip fidelity | Semantically lossless **except timestamps** |

Its models are more permissive than its declared version, so 1.1.2 documents
parse cleanly. Credit where due: this is better behaviour than the version
constant suggests.

### Where it does not fit

**1. It cannot be used by the evaluator.** trestle requires Python ≥3.11 and
pulls roughly 60 dependencies including pydantic, paramiko, cryptography and
openpyxl. ADR 0007 constrains the evaluator to the standard library and Python
3.9 syntax so it runs under a RHEL 9 system interpreter — see ADR 0007; the
constraint is what lets the evaluator run in an enclave where only `ee-legacy`
reached Server 2012 and
RHEL 7/8, and in an enclave often the only one available. These are irreconcilable.

**2. It mutates timestamps on round-trip.** ASD publishes nanosecond precision;
trestle emits milliseconds with a normalised offset:

```
'2026-09-03T23:10:47.63884244Z'  ->  '2026-09-03T23:10:47.638+00:00'
```

Harmless in isolation, disqualifying here: vendored upstream data is checksum-
pinned and redistributed **byte-for-byte unmodified** under CC BY 4.0 (ADR 0009).
Anything that re-serialises it through trestle silently breaks both the checksum
chain and the "unmodified" claim.

**3. Its version validator rejects our target.** `OSCAL_VERSION_REGEX` is
`^1\.2\.[0-1]$`. OSCAL 1.1.2 — what ASD publishes and what we therefore emit —
does not match, so trestle's validation paths are unusable for our documents even
though its models are not.

**4. Sixty transitive dependencies is a real cost here.** This tool runs inside
government estates, often air-gapped, and holds estate-wide credentials. Each
dependency is supply-chain surface that someone has to justify. Pinned JSON
schemas plus a six-line validator extension achieve what we need from two
dependencies (`jsonschema`, `regex`), fully offline, with no Java toolchain.

## Decision

Do not depend on compliance-trestle.

Validate against the **pinned NIST 1.1.2 JSON schemas** using `jsonschema` with
the `pattern` keyword overridden to use `regex` (the schemas use `\p{...}`
Unicode-property escapes that stdlib `re` cannot compile). Emit OSCAL by
constructing plain dictionaries, which keeps output byte-deterministic.

## Status

Accepted — and explicitly **reversible**.

## Consequences

We write and maintain our own emitters instead of getting typed models for free.
Accepted, because byte-determinism is a requirement rather than a preference: the
same facts must produce identical OSCAL so golden-file tests work and an auditor
can independently re-derive a published document.

We forgo trestle's profile resolution. Little is lost — ASD publishes
**pre-resolved** profile catalogs for every classification and maturity level, so
there is nothing to resolve for the ACSC baselines.

**Revisit this when we move to OSCAL 1.2.x.** At that point the version mismatch
disappears, trestle's mapping model support becomes directly relevant (1.1.2 has
no mapping model, which is why our crosswalks use a local schema), and the
calculus changes. This ADR should be superseded rather than quietly ignored.

Nothing here prevents using trestle as an **external** cross-check — running it
over our output in CI as a second opinion, the same way `oscal-cli` is treated —
without it becoming a runtime dependency.
