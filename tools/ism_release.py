#!/usr/bin/env python3
"""Shared constants and helpers for the vendored ACSC ISM OSCAL release.

Ingest deliberately uses raw.githubusercontent.com and `git ls-remote` rather
than the GitHub REST API: the API is commonly blocked or rate-limited in the
restricted networks this project targets, and in this environment it returns 403
for repositories outside the session's scope while raw fetches succeed.

See docs/adr/0005-ingest-from-acsc-github-mirror.md.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

# The authoritative source. Recorded for provenance; frequently unreachable from
# build networks, which is why ingest uses the ASD-maintained mirror below.
AUTHORITATIVE_URL = "https://www.cyber.gov.au/ism/oscal"

MIRROR_REPO = "https://github.com/AustralianCyberSecurityCentre/ism-oscal"
MIRROR_RAW = "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal"

#: The ISM release this repository is pinned to. Bumped only by the
#: release-watch workflow, which opens a pull request carrying a control-level
#: diff so changes to Commonwealth control text are reviewed, never absorbed.
PINNED_RELEASE = "v2026.09.4"

#: OSCAL version ASD publishes, and therefore the version this project emits.
OSCAL_VERSION = "1.1.2"

#: Baseline keys ASD ships a profile and a pre-resolved catalog for.
BASELINES = (
    "NON_CLASSIFIED",
    "OFFICIAL_SENSITIVE",
    "PROTECTED",
    "SECRET",
    "TOP_SECRET",
    "E8_ML1",
    "E8_ML2",
    "E8_ML3",
)

#: Only JSON is vendored. ASD also publishes XML and YAML of identical content;
#: carrying all three would triple the vendored size for no benefit.
def artifact_names() -> list[str]:
    names = ["ISM_catalog.json"]
    for key in BASELINES:
        names.append(f"ISM_{key}-baseline_profile.json")
        names.append(f"ISM_{key}-baseline-resolved-profile_catalog.json")
    return names


def upstream_dir(release: str = PINNED_RELEASE) -> Path:
    return Path(__file__).resolve().parent.parent / "oscal" / "upstream" / "ism" / release


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest(release: str = PINNED_RELEASE) -> dict:
    path = upstream_dir(release) / "MANIFEST.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No vendored ISM release at {path.parent}. Run `make fetch` first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def catalog_path(release: str = PINNED_RELEASE) -> Path:
    return upstream_dir(release) / "ISM_catalog.json"


def resolved_baseline_path(key: str, release: str = PINNED_RELEASE) -> Path:
    return upstream_dir(release) / f"ISM_{key}-baseline-resolved-profile_catalog.json"
