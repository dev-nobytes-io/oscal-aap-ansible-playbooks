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
    # Enumerated from disk, not hardcoded: adding a fixture must change the
    # golden output rather than being silently ignored by the test that is
    # supposed to notice changes.
    for path in sorted(BUNDLES.glob("*.json")):
        bundle = load_bundle(path)
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
        baseline_controls=baseline, evaluations=evaluations, registry=registry,
        catalog=catalog, plan_href="./assessment-plan.json", now=NOW,
        population_total=50,
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
    finding = next(
        f
        for f in results["assessment-results"]["results"][0]["findings"]
        if {p["name"]: p["value"] for p in f["props"]}["population-basis"] == "subject"
    )
    props = {p["name"]: p["value"] for p in finding["props"]}
    assert props["population-total"] == "50"
    # Assessed count comes from the bundles actually present; the denominator
    # does not. Three subjects out of fifty in scope must not render as 100%.
    assessed = int(props["population-assessed"])
    assert assessed < 50
    assert props["population-total"] != props["population-assessed"]
    assert "not determined" in finding["target"]["status"]["remarks"]


def test_every_finding_is_internally_consistent() -> None:
    """A document that contradicts itself must fail, not ship.

    This is the assertion that was missing, and its absence let a real defect
    reach the output: `population-assessed` was computed ONCE PER RUN and
    stamped onto every finding. A control determined for one host out of four
    reported "1 of 4 assessed subjects do not satisfy this control" while its
    own remarks said it was determined from one observation. Every failure rate
    in the document was understated, and the three subjects the control was
    never determined for were counted into its denominator as though they had
    passed -- the inverse of Principle 3.

    The previous version of the guard above asserted only that the total was 50
    and that assessed was under 50. Both stayed true throughout. A check that
    cannot see the thing it is checking is not a check, which is the fifth time
    this repository has found that shape in itself.
    """
    results = json.loads((GOLDEN / "assessment-results.json").read_text(encoding="utf-8"))
    findings = results["assessment-results"]["results"][0]["findings"]
    assert findings, "no findings to check; a green run over nothing is not a pass"

    for finding in findings:
        props = {p["name"]: p["value"] for p in finding["props"]}
        control = finding["title"].split()[0]
        observations = len(finding.get("related-observations") or [])
        assessed = int(props["population-assessed"])
        failing = int(props["population-failing"])
        total = int(props["population-total"])

        # One subject can carry several observations for one control (two checks
        # bound to it), so assessed <= observations. It can never exceed them:
        # that would be a subject the document cannot point at any evidence for.
        assert 1 <= assessed <= observations, (
            f"{control}: claims {assessed} assessed subject(s) but carries "
            f"{observations} observation(s)"
        )
        assert failing <= assessed, (
            f"{control}: {failing} failing of {assessed} assessed is not a population"
        )
        assert int(props["population-na"]) <= assessed
        assert assessed <= total, f"{control}: assessed {assessed} exceeds in-scope {total}"

        # The prose and the props are two renderings of one fact and must agree.
        remarks = finding["target"]["status"]["remarks"]
        assert f"across {assessed} subject(s)" in remarks, (
            f"{control}: remarks disagree with population-assessed={assessed}"
        )
        if failing:
            assert f"{failing} of {assessed}" in finding["description"]
        else:
            assert f"All {assessed}" in finding["description"]


def test_aggregate_findings_do_not_borrow_the_host_denominator() -> None:
    """A tenant is not one of fifty workstations.

    An aggregate check judges a population from INSIDE a single subject. Giving
    it the host estate as a denominator would describe a completely different
    population from the one actually judged -- "1 of 50 assessed subjects" for
    a finding about an entire directory tenant.

    This also exists because `scope` was decorative for nine chunks: it was read
    in three places and all three only stamped its string into a prop. Nothing
    consumed it, so nothing noticed.
    """
    results = json.loads((GOLDEN / "assessment-results.json").read_text(encoding="utf-8"))
    findings = results["assessment-results"]["results"][0]["findings"]
    by_basis: dict = {}
    for finding in findings:
        props = {p["name"]: p["value"] for p in finding["props"]}
        by_basis.setdefault(props["population-basis"], []).append((finding, props))

    assert "aggregate-subject" in by_basis, (
        "no aggregate finding in the golden output, so the aggregate branch is "
        "untested code -- add a fixture bundle for an aggregate subject"
    )
    assert "subject" in by_basis, "no host finding; the fixtures no longer cover both bases"

    for finding, props in by_basis["aggregate-subject"]:
        assert props["population-total"] == props["population-assessed"], (
            f"{finding['title']}: an aggregate finding must not borrow the host estate "
            f"as its denominator"
        )
        assert props["population-total"] != "50"


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
