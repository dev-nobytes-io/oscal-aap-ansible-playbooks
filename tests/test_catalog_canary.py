"""Canary tests over the vendored ACSC ISM catalog.

These are not testing ASD's work. They pin the shape and size this repository's
code assumes, so that a botched vendoring, a truncated download or a structural
change in a future ISM release fails loudly here rather than silently producing
an assessment over a partial catalog.

Every number below was measured against the pinned release. When ASD publishes
a new release these will change, and that is the point: the release-watch
workflow opens a pull request, these tests fail, and a human looks at what moved
instead of absorbing it.
"""

from __future__ import annotations

import json

import pytest

from conftest import prop_values
from ism_release import PINNED_RELEASE, load_manifest, resolved_baseline_path

# --- measured against ISM OSCAL v2026.09.4 ---
EXPECTED_CONTROLS = 1143
EXPECTED_PRINCIPLES = 49
EXPECTED_TOTAL = 1192
EXPECTED_APPLICABILITY = {"NC": 1017, "OS": 1028, "P": 1028, "S": 1092, "TS": 1101}
EXPECTED_E8 = {"ML1": 46, "ML2": 87, "ML3": 123}
ISM_NS = "https://cyber.gov.au/ns/ism/oscal/3.0"


def test_catalog_declares_expected_release(catalog: dict) -> None:
    assert catalog["metadata"]["version"] == PINNED_RELEASE.lstrip("v")
    assert catalog["metadata"]["oscal-version"] == "1.1.2"


def test_control_and_principle_counts(controls: list[dict]) -> None:
    by_class: dict[str, int] = {}
    for control in controls:
        by_class[control["class"]] = by_class.get(control["class"], 0) + 1
    assert by_class.get("ISM-control") == EXPECTED_CONTROLS
    assert by_class.get("ISM-principle") == EXPECTED_PRINCIPLES
    assert len(controls) == EXPECTED_TOTAL


def test_control_ids_are_unique(controls: list[dict]) -> None:
    ids = [c["id"] for c in controls]
    assert len(set(ids)) == len(ids) == EXPECTED_TOTAL


def test_every_control_has_exactly_one_statement_part(controls: list[dict]) -> None:
    """The statement id is what findings target.

    ISM controls carry exactly one part, named `statement`, with id
    `<control-id>_smt`. That id is used directly as an OSCAL
    finding-target of type `statement-id`, so if the convention ever changes,
    every finding this project emits would point at nothing.
    """
    for control in controls:
        parts = control.get("parts", [])
        assert len(parts) == 1, f"{control['id']} has {len(parts)} parts, expected 1"
        part = parts[0]
        assert part["name"] == "statement"
        assert part["id"] == f"{control['id']}_smt"
        assert part.get("prose", "").strip(), f"{control['id']} has an empty statement"


def test_control_title_is_a_stub_not_content(controls: list[dict]) -> None:
    """Guards a trap: `title` looks like content and is not.

    ISM control titles are stubs of the form "Control: ism-1488". Any code that
    renders a title expecting a description is wrong; the content lives in
    parts[0].prose.
    """
    numbered = [c for c in controls if c["class"] == "ISM-control"]
    stubs = [c for c in numbered if c["title"] == f"Control: {c['id']}"]
    assert len(stubs) == len(numbered)


def test_groups_carry_no_id(catalog: dict) -> None:
    """Documents a structural surprise so nobody rediscovers it at runtime.

    Every group in the ISM catalog has `id: null`. Section grouping must be
    derived from the `sort-id` prop. Code that assumes group ids produces
    silently ungrouped reports.
    """
    seen = 0

    def walk(node: object) -> None:
        nonlocal seen
        if isinstance(node, dict):
            if "groups" in node:
                for group in node["groups"]:
                    seen += 1
                    assert group.get("id") is None, "a group gained an id; revisit sort-id parsing"
                    walk(group)
            for key, value in node.items():
                if key != "groups":
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(catalog)
    assert seen > 0


@pytest.mark.parametrize(("code", "expected"), sorted(EXPECTED_APPLICABILITY.items()))
def test_applicability_counts(controls: list[dict], code: str, expected: int) -> None:
    numbered = [c for c in controls if c["class"] == "ISM-control"]
    count = sum(1 for c in numbered if code in prop_values(c, "applicability"))
    assert count == expected


@pytest.mark.parametrize(("level", "expected"), sorted(EXPECTED_E8.items()))
def test_essential_eight_counts(controls: list[dict], level: str, expected: int) -> None:
    numbered = [c for c in controls if c["class"] == "ISM-control"]
    count = sum(
        1 for c in numbered if level in prop_values(c, "essential-eight-applicability")
    )
    assert count == expected


def test_ml1_applies_at_every_classification(controls: list[dict]) -> None:
    """The Essential Eight is not subset by classification.

    All 46 ML1 controls apply at every level from NON_CLASSIFIED to TOP SECRET,
    so "ML1 for OFFICIAL" is simply ML1. Anything that intersects the two is
    doing no work, and anything that reports a smaller ML1 for a lower
    classification has a bug.
    """
    ml1 = [
        c
        for c in controls
        if c["class"] == "ISM-control"
        and "ML1" in prop_values(c, "essential-eight-applicability")
    ]
    assert len(ml1) == EXPECTED_E8["ML1"]
    for control in ml1:
        applicability = set(prop_values(control, "applicability"))
        assert applicability == {"NC", "OS", "P", "S", "TS"}, control["id"]


def test_asd_props_use_the_expected_namespace(controls: list[dict]) -> None:
    for control in controls:
        for prop in control.get("props", []):
            if prop["name"] in ("applicability", "essential-eight-applicability",
                                "revision", "updated"):
                assert prop.get("ns") == ISM_NS, f"{control['id']}: {prop['name']}"


def test_resolved_ml1_catalog_matches_the_catalog_props() -> None:
    """ASD's pre-resolved ML1 catalog and the ML1 props must agree.

    They are produced independently upstream. If they ever disagree, our
    baseline selection is ambiguous and we should stop rather than pick one.
    """
    path = resolved_baseline_path("E8_ML1")
    if not path.exists():
        pytest.skip("resolved ML1 catalog not vendored")
    doc = json.loads(path.read_text(encoding="utf-8"))["catalog"]

    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("class") == "ISM-control":
                found.append(node["id"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    assert len(found) == EXPECTED_E8["ML1"]


def test_manifest_records_provenance() -> None:
    manifest = load_manifest()
    assert manifest["release"] == PINNED_RELEASE
    assert len(manifest["commit"]) == 40
    assert manifest["licence"] == "CC BY 4.0"
    assert "cyber.gov.au" in manifest["authoritative_source"]
    assert len(manifest["files"]) == 17
    for name, meta in manifest["files"].items():
        assert len(meta["sha256"]) == 64, name
        assert meta["bytes"] > 0, name
