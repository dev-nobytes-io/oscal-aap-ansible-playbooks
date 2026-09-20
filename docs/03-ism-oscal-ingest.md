# ISM OSCAL ingest

How the ACSC Information Security Manual gets into this repository, how it is
pinned, and what happens when ASD publishes a new release.

## Where the data comes from

| | |
|---|---|
| Authoritative source | <https://www.cyber.gov.au/ism/oscal> |
| Ingest mirror | <https://github.com/AustralianCyberSecurityCentre/ism-oscal> |
| Pinned release | **`v2026.09.4`** |
| OSCAL version | **1.1.2** |
| Licence | **CC BY 4.0**, © Commonwealth of Australia — see [`../NOTICE`](../NOTICE) |

The mirror is maintained by ASD and described in its own README as a mirror of
the ISM OSCAL documents. Ingest uses it rather than the authoritative site for
two practical reasons:

1. **Reachability.** `www.cyber.gov.au` is frequently unreachable from build
   networks — it times out entirely from ours. The mirror is on GitHub and is
   reachable wherever `raw.githubusercontent.com` is.
2. **Pinning.** The mirror is **git-tagged per release** — 26 tags so far. A tag
   is a better pin than a checksum against a moving page, and it gives the
   release-watch workflow a trivial trigger.

Ingest deliberately avoids the **GitHub REST API**: it is commonly blocked or
rate-limited in restricted networks, and in some environments returns 403 for
repositories outside a session's scope while raw fetches succeed. Only
`raw.githubusercontent.com` and `git ls-remote` are used.

## What is vendored

17 JSON artefacts, ~14 MB, in `oscal/upstream/ism/<tag>/`:

- `ISM_catalog.json` — the full catalog (1143 controls + 49 principles)
- `ISM_<baseline>-baseline_profile.json` × 8
- `ISM_<baseline>-baseline-resolved-profile_catalog.json` × 8

for baselines `NON_CLASSIFIED`, `OFFICIAL_SENSITIVE`, `PROTECTED`, `SECRET`,
`TOP_SECRET`, `E8_ML1`, `E8_ML2`, `E8_ML3`.

ASD also publishes XML and YAML of identical content; carrying all three would
triple the size for no benefit. The **pre-resolved** catalogs are vendored
because ASD's profiles reference `cyber.gov.au` URLs in their back-matter and
are therefore unresolvable offline — and because there is no reason to
re-implement a resolver for baselines ASD already resolves.

Exactly **one** release directory is kept at a time. Git history retains prior
releases; keeping them all in the tree would add ~14 MB per quarter.

The NIST OSCAL 1.1.2 JSON schemas are vendored alongside, in `oscal/schemas/`.

## Integrity and provenance

Every release directory carries a `MANIFEST.json` recording the upstream tag,
the resolved commit SHA and a SHA-256 for every file:

```json
{
  "release": "v2026.09.4",
  "commit": "9f77120a7f8671c73da02431cdc299fac264edab",
  "oscal_version": "1.1.2",
  "authoritative_source": "https://www.cyber.gov.au/ism/oscal",
  "licence": "CC BY 4.0",
  "files": { "ISM_catalog.json": { "sha256": "237ea093…", "bytes": 2677748 } }
}
```

Upstream files are written **byte-for-byte unmodified**. Nothing re-serialises
them — not even reformatting JSON — because they are Commonwealth material
redistributed under CC BY 4.0 and any rewrite breaks both the checksum chain and
the "unmodified" claim. (This is one of the reasons
[ADR 0010](adr/0010-do-not-depend-on-compliance-trestle.md) declines
compliance-trestle: it mutates timestamps on round-trip.)

```bash
make fetch      # download + checksum (the only step needing network)
make validate   # verify checksums, then validate against pinned NIST schemas
```

`make validate` is fully offline. After `make fetch`, nothing in the
assess → evaluate → report path needs egress — which is what makes this usable
in an air-gapped environment.

## Validating OSCAL offline

NIST publishes the schemas **only as GitHub release assets**:

```
https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_<model>_schema.json
```

The paths people reach for first — `raw.githubusercontent.com/usnistgov/OSCAL/<tag>/json/schema/`
and `pages.nist.gov/OSCAL/artifacts/` — both return **404**. Do not wire those
into CI.

**The trap worth knowing before debugging it:** the schemas use `\p{...}`
Unicode-property regexes. Python's stdlib `re` cannot compile them, so stock
`jsonschema` does not fail cleanly — it raises `re.error: bad escape \p` and
crashes. `tools/oscal_validate.py` overrides the `pattern` keyword to use the
`regex` module instead.

With that in place all 17 vendored artefacts validate against the NIST schemas,
in pure Python, with no Java toolchain.

## Release bumps are reviewed, never absorbed

This is the part that matters most, and the numbers make the case better than
any argument.

Between `v2026.06.18` and `v2026.09.4` — **one quarter**:

| Change | Count |
|---|---|
| Controls added | 44 |
| Controls removed | 2 |
| **Statement text reworded** | **111** |
| Total controls | 1150 → 1192 |

Around **10% of the catalog was reworded in a single release**, with control ids
unchanged. The changes are often subtle:

> `ism-0009`
> **was:** …identify any supplementary **controls** required…
> **now:** …identify any supplementary **security controls** required…

A check bound to a reworded control keeps passing while no longer testing what
the control says. Nothing surfaces that on its own. So:

- Every check records the **SHA-256 of the statement prose** it was written
  against, plus the control revision and catalog version.
- `.github/workflows/ism-release-watch.yml` runs weekly, compares the newest
  upstream tag against the pinned one, and on a change vendors the new release
  and opens a **draft pull request** whose body is a control-level diff from
  `tools/ism_diff.py` — added, removed, reworded, and any Essential Eight or
  classification membership changes.
- **Canary tests are expected to fail on that PR.** `tests/test_catalog_canary.py`
  pins the counts (1143 / 49 / 1192, ML1 = 46, applicability totals). Failure is
  the mechanism working: a human decides what moved rather than absorbing it.

Baseline membership is diffed too. **ML1 is 46 controls today, not permanently.**

## Structural facts the code relies on

Verified against the pinned release and pinned by the canary tests:

- Control ids are `ism-1488`. **`title` is a stub** (`"Control: ism-1488"`) — the
  content is `parts[0].prose`.
- Exactly **one part** per control, named `statement`, id `<control-id>_smt`.
  That id is used directly as an OSCAL `finding-target` of type `statement-id`.
- **Groups carry `id: null`** at every level. Section structure must be derived
  from the `sort-id` prop; code assuming group ids produces silently ungrouped
  reports.
- **Controls carry no `links`.** There is no ISM→800-53, →ISO 27001, →CCI or
  →STIG crosswalk in the data — every such mapping is authored here.
- **There are no assessment objectives.** One prose sentence per control.
  Turning that into a testable assertion is authoring work, and it is this
  project's real cost centre.
- ASD props use namespace `https://cyber.gov.au/ns/ism/oscal/3.0`:
  `applicability` (repeated: NC 1017 · OS 1028 · P 1028 · S 1092 · TS 1101),
  `essential-eight-applicability` (ML1 46 · ML2 87 · ML3 123), `revision`,
  `updated`.
- **All 46 ML1 controls apply at every classification.** Intersecting the
  Essential Eight with a classification is a no-op; "ML1 for OFFICIAL" is ML1.

## Bumping by hand

```bash
python tools/fetch_ism_oscal.py --release v2026.12.x
python tools/ism_diff.py --old v2026.09.4 --new v2026.12.x
# then update PINNED_RELEASE in tools/ism_release.py, ISM_RELEASE in the
# Makefile, and the canary expectations — after reviewing the diff.
```

The release tag is validated against `^v\d{4}\.\d{2}\.\d{1,2}$` before it
reaches a URL or a subprocess argument, because in CI it can come from a
workflow input.
