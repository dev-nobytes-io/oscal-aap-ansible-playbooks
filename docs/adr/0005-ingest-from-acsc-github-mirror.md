# ADR 0005: Ingest ISM OSCAL from the ACSC GitHub mirror, pinned to a release tag

## Context

`https://www.cyber.gov.au/ism/oscal` is authoritative for ISM OSCAL. It is also
unreachable from many build networks — it times out from ours entirely — and
offers no natural version-pinning mechanism for automation.

ASD maintains `github.com/AustralianCyberSecurityCentre/ism-oscal`, described in
its own README as a mirror of the ISM OSCAL documents.

## Decision

Ingest from the ACSC GitHub mirror, pinned to a **release git tag**, and vendor
the result into `oscal/upstream/ism/<tag>/` with a manifest recording the tag,
commit SHA and a SHA-256 per file.

Use `raw.githubusercontent.com` and `git ls-remote`, not the GitHub REST API —
the API is commonly blocked or rate-limited in restricted networks.

## Status

Accepted.

## Consequences

The mirror carries a tag per release (26 so far, currently `v2026.09.4`), which
is a better pin than a checksum against a moving branch and gives the
release-watch workflow a trivial trigger: a new tag.

Builds become reproducible and fully air-gapped after ingest. Ingest is the only
online step and runs in CI, never on the estate.

Risks accepted: the mirror could lag the primary site, so provenance records the
mirror explicitly and the authoritative URL is retained in the manifest. ASD's
published profiles reference `cyber.gov.au` URLs in their back-matter and are
therefore unresolvable offline — so the **pre-resolved** profile catalogs ASD
also publishes are used instead, and any profile we author points its back-matter
at vendored local paths.
