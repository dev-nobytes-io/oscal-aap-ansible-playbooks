# ADR 0009: License code under Apache-2.0 and attribute vendored ISM data under CC BY 4.0

## Context

The repository mixes two things with different owners: our own code and
documentation, and Commonwealth control data vendored from the ACSC ISM OSCAL
release.

The ISM OSCAL material is © Commonwealth of Australia under **CC BY 4.0**
(excluding the Coat of Arms and the ASD logo). CC BY permits redistribution with
attribution, and requires that modifications be indicated.

There is also a reputational risk worth handling explicitly: a repository that
consumes government control data can easily read as government-endorsed.

## Decision

- Code and documentation: **Apache-2.0**.
- Vendored ISM data: redistributed **byte-for-byte unmodified** under
  `oscal/upstream/`, attributed in `NOTICE` with title, author, source, licence
  and an explicit statement of modifications.
- Derived artefacts (profiles, component-definitions, crosswalks, results)
  *reference* ISM control identifiers but are this project's own work and are not
  part of the licensed material.
- `NOTICE` carries an explicit non-endorsement disclaimer and states that where
  our interpretation differs from the ISM, **the ISM is authoritative**.
- The Coat of Arms and ASD logo are not reproduced.

## Status

Accepted.

## Consequences

Vendoring is permitted, which is what makes reproducible, air-gapped builds
possible — a fetch-at-build-time design would fail in exactly the environments
this project targets.

The unmodified/derived separation must be maintained mechanically: ISM control
text is never pasted into an authored file, and `oscal/upstream/` is written only
by automated ingest. CODEOWNERS covers that path accordingly.

Apache-2.0 suits infrastructure tooling and is compatible with the Ansible
ecosystem. Content reused from other open-source hardening projects will need its
own licence review at the point of use — noted, not resolved here.
