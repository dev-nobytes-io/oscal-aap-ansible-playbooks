"""The human-readable report.

One property matters more than every other here: **a status never renders
without its confidence.** "satisfied" on proxy evidence has not been
demonstrated to the same standard as "satisfied" on direct evidence, and a
report that renders them identically has thrown away the single most valuable
distinction the pipeline produces -- silently, and in the artefact an executive
actually reads.

The second is that an attested control must never read as an automated pass.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from conftest import ROOT
from ism_release import catalog_path
from nobytes_cca.bundle import load_bundle
from nobytes_cca.catalog import Catalog
from nobytes_cca.evaluate import evaluate_bundle
from nobytes_cca.oscal import emit, ids
from nobytes_cca.registry import Registry
from nobytes_cca.report import render
from nobytes_cca.report.model import ControlRow, build

BUNDLES = ROOT / "tests" / "fixtures" / "bundles"
NOW = dt.datetime(2026, 9, 21, 3, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def documents() -> tuple:
    path = catalog_path()
    if not path.exists():
        pytest.skip("no vendored catalog; run `make fetch`")
    catalog = Catalog.load(path)
    registry = Registry.load()
    baseline = catalog.baseline(e8="ML1")

    evaluations = []
    for bundle_path in sorted(BUNDLES.glob("*.json")):
        bundle = load_bundle(bundle_path)
        bundle.subject["inventory_item_uuid"] = ids.inventory_item_uuid(
            "REPORT-TEST", bundle.subject["asset_id"]
        )
        evaluations.extend(evaluate_bundle(registry, bundle, baseline))

    plan = emit.emit_assessment_plan(
        system_id="REPORT-TEST", baseline="E8_ML1", baseline_controls=baseline,
        registry=registry, catalog=catalog, now=NOW,
    )
    results = emit.emit_assessment_results(
        system_id="REPORT-TEST", run_id="report:001", baseline="E8_ML1",
        baseline_controls=baseline, evaluations=evaluations, registry=registry,
        catalog=catalog, plan_href="./assessment-plan.json", now=NOW,
        population_total=50,
    )
    return plan, results, catalog


@pytest.fixture(scope="module")
def report(documents: tuple):
    plan, results, catalog = documents
    return build(plan, results, catalog)


def test_every_baseline_control_appears(report) -> None:
    """A control missing from the report is a control nobody asks about."""
    assert len(report.rows) == 46
    assert len({r.control_id for r in report.rows}) == 46


def test_a_determined_control_always_carries_its_confidence(report) -> None:
    determined = [r for r in report.rows if r.is_determined]
    assert determined, "nothing determined; this test would pass vacuously"
    for row in determined:
        assert row.confidence, f"{row.control_id} is {row.status} with no confidence"
        assert row.confidence in row.display_status


def test_satisfied_at_proxy_never_renders_like_satisfied_at_direct() -> None:
    """The load-bearing test of this module.

    Written as a direct comparison rather than a property check because the
    failure it guards is precisely that the two become indistinguishable.
    """
    direct = ControlRow("ism-0001", "x", "satisfied", confidence="direct")
    proxy = ControlRow("ism-0001", "x", "satisfied", confidence="proxy")

    assert direct.display_status != proxy.display_status
    assert "direct" in direct.display_status
    assert "proxy" in proxy.display_status

    from nobytes_cca.report.render import _status_html

    assert _status_html(direct) != _status_html(proxy)
    assert "direct" in _status_html(direct)
    assert "proxy" in _status_html(proxy)


def test_undetermined_always_carries_a_reason(report) -> None:
    for row in report.rows:
        if row.is_determined:
            continue
        assert row.reason, f"{row.control_id} is undetermined with no reason"
        assert row.reason != "no-determination-recorded", (
            f"{row.control_id} fell through to the placeholder reason -- the "
            f"emitted documents should carry why, and if they do not the "
            f"report is guessing"
        )


def test_attested_controls_are_never_rendered_as_a_pass(report) -> None:
    attested = report.attested
    assert attested, "no attested controls; this test would pass vacuously"
    body = render.markdown(report)
    for row in attested:
        assert not row.is_determined
        assert "requires-attestation" in row.display_status
        assert row.attestation.get("owner"), f"{row.control_id} names no owner"
        assert row.attestation.get("source"), f"{row.control_id} names no source"
        # It must appear in the register with its evidence chain, not merely
        # in the big table as another undetermined row.
        assert row.control_id in body
    assert "Attestation register" in body


def test_report_states_the_unassessed_subject_gap(report) -> None:
    """3 of 50 assessed must not read as an estate-wide result."""
    assert report.subjects_assessed < report.subjects_in_scope
    for body in (render.markdown(report), render.to_html(report)):
        assert "subjects in scope were not assessed" in body


def test_html_escapes_control_statements(report) -> None:
    """Statements are Commonwealth text, but the renderer must not trust input."""
    hostile = ControlRow(
        "ism-9999", "<script>alert(1)</script>", "satisfied", confidence="direct"
    )
    from nobytes_cca.report.model import Report

    poisoned = Report(
        system_id="x", baseline="E8_ML1", catalog_version="1", run_id="r",
        generated="now", marking="OFFICIAL", subjects_assessed=1,
        subjects_in_scope=1, rows=(hostile,),
    )
    body = render.to_html(poisoned)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_markdown_and_html_agree_on_the_numbers(report) -> None:
    md, page = render.markdown(report), render.to_html(report)
    determined = len([r for r in report.rows if r.is_determined])
    undetermined = len(report.rows) - determined
    for body in (md, page):
        assert str(len(report.rows)) in body
        assert str(undetermined) in body


def test_report_round_trips_from_files(tmp_path: Path, documents: tuple) -> None:
    """The CLI path: render from documents on disk, not from memory."""
    plan, results, catalog = documents
    (tmp_path / "assessment-plan.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / "assessment-results.json").write_text(json.dumps(results), encoding="utf-8")

    from nobytes_cca.report.model import load

    loaded = load(
        tmp_path / "assessment-plan.json",
        tmp_path / "assessment-results.json",
        catalog,
    )
    assert len(loaded.rows) == 46
    assert loaded.confidence_counts
