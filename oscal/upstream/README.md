# Vendored upstream data

Byte-for-byte copies of the ACSC ISM OSCAL release, laid out as
`ism/<release-tag>/`.

**Never edit anything in this directory by hand.** Files here are written only
by `make fetch` and updated only by the release-watch workflow, which opens a
pull request containing a control-level diff so that changes to Commonwealth
control text are reviewed rather than absorbed silently.

Each release directory carries a `MANIFEST.json` recording the upstream git
tag, the commit SHA and a SHA-256 for every file, so a vendored copy can be
proven identical to what ASD published.

Source of truth: <https://www.cyber.gov.au/ism/oscal>
Ingest mirror: <https://github.com/AustralianCyberSecurityCentre/ism-oscal>
(the mirror is tagged per release and is reachable from CI; the primary site is
not always reachable from build networks)

Licence: CC BY 4.0, (C) Commonwealth of Australia. See `NOTICE`.
