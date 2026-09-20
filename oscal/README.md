# OSCAL artefacts

Everything expressed in NIST's Open Security Controls Assessment Language.
This directory is the machine-readable spine of the project.

| Directory | Holds | Authored by |
|---|---|---|
| `upstream/` | Vendored ACSC ISM OSCAL, byte-for-byte, tag-pinned + checksummed | ASD — **never edited here** |
| `schemas/` | Pinned NIST OSCAL 1.1.2 JSON schemas for offline validation | NIST |
| `catalogs/` | Authored catalogs for PSPF, the APPs and SOCI/CIRMP | this project |
| `profiles/` | Derived profiles (baseline selections) | this project |
| `assessment-plans/` | Assessment plans — **required** by `import-ap` on every results document | this project |
| `component-definitions/` | Control to check bindings, one per platform family | this project |
| `mappings/` | Crosswalks: obligation to ISM, ISM to STIG/CIS | this project |

The separation matters legally as well as technically. `upstream/` is
Commonwealth material under CC BY 4.0; everything else is this project's own
work and carries no ASD endorsement. See `NOTICE`.

OSCAL target version: **1.1.2** — matching what ASD publishes.

Two consequences of that version, both verified against the NIST schemas:

* `assessment-results` **requires** `import-ap`, so an assessment plan is a
  mandatory artefact rather than a nicety.
* OSCAL has **no mapping model at 1.1.2** (it arrives in the 1.2.x line), so the
  crosswalks in `mappings/` use this project's own schema. The emitter is
  version-parameterised so adopting the native model later is a configuration
  change, not a rewrite.
