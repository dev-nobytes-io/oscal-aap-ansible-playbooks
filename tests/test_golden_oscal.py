"""Golden-file tests over emitted OSCAL.

Only possible because every identifier is derived deterministically (UUIDv5)
rather than generated. These catch emitter regressions that schema validation
never will -- a document can be perfectly schema-valid and say the wrong thing.

When one of these fails, read the diff before regenerating. A changed verdict
for unchanged input is a MAJOR version bump even when the new verdict is more
correct, because someone holds a published result it contradicts.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from conftest import ROOT
from ism_release import catalog_path
from nobytes_cca.bundle import load_bundle
from nobytes_cca.catalog import Catalog
from nobytes_cca.evaluate import evaluate_bundle
from nobytes_cca.oscal import emit, ids
from nobytes_cca.registry import Registry

GOLDEN = ROOT / "tests" / "fixtures" / "golden"
BUNDLES = ROOT / "tests" / "fixtures" / "bundles"
NOW = dt.datetime(2026, 9, 20, 3, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=10)))


def _emit_all() -> dict:
    registry = Registry.load()
    catalog = Catalog.load(catalog_path())
    baseline = catalog.baseline(e8="ML1")

    evaluations = []
    for name in ("wks-0042-partial.json", "wks-0043-failing.json"):
        bundle = load_bundle(BUNDLES / name)
        bundle.subject["inventory_item_uuid"] = ids.inventory_item_uuid(
            "SYSTEM-GOVDESK", bundle.subject["asset_id"]
        )
        evaluations.extend(evaluate_bundle(registry, bundle, baseline))

    plan = emit.emit_assessment_plan(
        system_id="SYSTEM-GOVDESK", baseline="E8_ML1", baseline_controls=baseline,
        registry=registry, catalog=catalog, now=NOW,
    )
    results = emit.emit_assessment_results(
        system_id="SYSTEM-GOVDESK", run_id="golden:001", baseline="E8_ML1",
        baseline_controls=baseline, evaluations=evaluations, catalog=catalog,
        plan_href="./assessment-plan.json", now=NOW, population_total=50,
    )
    poam = emit.emit_poam(
        system_id="SYSTEM-GOVDESK", baseline="E8_ML1", results=results, now=NOW
    )
    return {
        "assessment-plan.json": plan,
        "assessment-results.json": results,
        "poam.json": poam,
    }


@pytest.mark.parametrize(
    "name", ["assessment-plan.json", "assessment-results.json", "poam.json"]
)
def test_output_matches_golden(name: str) -> None:
    produced = json.dumps(_emit_all()[name], indent=2) + "\n"
    expected = (GOLDEN / name).read_text(encoding="utf-8")
    assert produced == expected, (
        f"{name} differs from the golden file. Read the diff before regenerating: "
        f"a changed verdict for unchanged input is a MAJOR version bump."
    )


def test_golden_documents_validate_against_nist_schemas() -> None:
    """Schema-valid AND semantically pinned. Both, or neither is worth much."""
    from oscal_validate import validate_document

    for name in ("assessment-plan.json", "assessment-results.json", "poam.json"):
        errors = validate_document(GOLDEN / name)
        assert not errors, f"{name}: " + "; ".join(errors[:3])


def test_population_denominator_comes_from_inventory_not_results() -> None:
    """Two subjects were assessed out of fifty in scope.

    Reporting 2/2 would render a 4%-of-fleet sample as full coverage. This is
    the default failure mode of compliance automation and the reason the
    denominator is passed in explicitly.
    """
    results = json.loads((GOLDEN / "assessment-results.json").read_text(encoding="utf-8"))
    finding = results["assessment-results"]["results"][0]["findings"][0]
    props = {p["name"]: p["value"] for p in finding["props"]}
    assert props["population-total"] == "50"
    assert props["population-assessed"] == "2"
    assert "not assessed" in finding["target"]["status"]["remarks"]


def test_poam_contains_only_determined_failures() -> None:
    """Undetermined controls must never leak into a POA&M as if they failed."""
    poam = json.loads((GOLDEN / "poam.json").read_text(encoding="utf-8"))
    results = json.loads((GOLDEN / "assessment-results.json").read_text(encoding="utf-8"))
    failing = {
        f["title"].split()[0]
        for f in results["assessment-results"]["results"][0]["findings"]
        if f["target"]["status"]["state"] == "not-satisfied"
    }
    items = poam["plan-of-action-and-milestones"]["poam-items"]
    in_poam = {
        p["value"]
        for item in items
        for p in item.get("props", [])
        if p["name"] == "control-id"
    }
    assert in_poam == failing
