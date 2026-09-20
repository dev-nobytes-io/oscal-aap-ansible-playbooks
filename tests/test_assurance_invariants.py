"""The tests that matter more than any positive one.

Each of these encodes a rule from docs/ASSURANCE-PRINCIPLES.md. If one of them
starts failing, the project has begun producing confident, well-formatted,
incorrect compliance output -- which is the specific failure it exists to avoid.
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
from nobytes_cca.contract import (
    CheckResult,
    Confidence,
    FactHistory,
    Status,
    UnassessedReason,
)
from nobytes_cca.evaluate import evaluate_bundle, evaluate_check, unassessed_controls
from nobytes_cca.oscal import emit
from nobytes_cca.registry import Registry

FIXTURES = ROOT / "tests" / "fixtures" / "bundles"
NOW = dt.datetime(2026, 9, 20, 3, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=10)))


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry.load()


@pytest.fixture(scope="module")
def ism() -> Catalog:
    return Catalog.load(catalog_path())


# --- Principle 1: never claim what was not observed ----------------------


def test_satisfied_requires_supporting_facts() -> None:
    """`satisfied` with no evidence is an assertion, not assurance."""
    with pytest.raises(ValueError, match="requires supporting facts"):
        CheckResult.satisfied("looks fine", {})


def test_not_satisfied_also_requires_facts() -> None:
    with pytest.raises(ValueError):
        CheckResult.not_satisfied("looks bad", {})


def test_control_with_no_check_never_becomes_a_finding(registry, ism) -> None:
    """The single most important test in the repository.

    45 of the 46 ML1 controls have no check. Not one of them may appear in
    findings -- in either direction. An unimplemented control is undetermined,
    never compliant and never failing.
    """
    baseline = ism.baseline(e8="ML1")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    bundle.subject["inventory_item_uuid"] = "00000000-0000-5000-8000-000000000001"
    evaluations = evaluate_bundle(registry, bundle, baseline)

    results = emit.emit_assessment_results(
        system_id="TEST", run_id="t1", baseline="E8_ML1",
        baseline_controls=baseline, evaluations=evaluations, catalog=ism,
        plan_href="./assessment-plan.json", now=NOW,
    )
    findings = results["assessment-results"]["results"][0]["findings"]
    covered = registry.covered_controls()
    for finding in findings:
        control_id = finding["title"].split()[0]
        assert control_id in covered, (
            f"{control_id} has no check yet produced a finding -- a verdict was "
            f"invented for a control nobody implemented"
        )


def test_unassessed_distinguishes_no_check_from_could_not_tell(registry, ism) -> None:
    """Two different kinds of "no determination", and they must not be conflated.

    With the partial-population bundle, all 46 ML1 controls end up undetermined:
    45 have no check at all, and ism-1488 HAS a check which ran and could not
    conclude. A report that lumps those together tells an operator nothing
    actionable -- one is a coverage gap, the other is a collection problem.
    """
    baseline = ism.baseline(e8="ML1")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    evaluations = evaluate_bundle(registry, bundle, baseline)
    undetermined = unassessed_controls(baseline, registry, evaluations)

    assert len(undetermined) == 46
    assert all(isinstance(r, UnassessedReason) for r in undetermined.values())

    by_reason: dict = {}
    for reason in undetermined.values():
        by_reason[reason] = by_reason.get(reason, 0) + 1
    assert by_reason[UnassessedReason.NOT_IMPLEMENTED] == 45
    assert undetermined["ism-1488"] is UnassessedReason.PARTIAL_POPULATION


# --- Principle 2: an operational failure is not a compliance failure -----


def test_missing_facts_yield_unassessed_not_failure(registry) -> None:
    """An unreachable host or a missing privilege must never read as failing."""
    from nobytes_cca.contract import FactBundle

    check = registry.get("win-office-macro-internet-blocked")
    empty = FactBundle(subject={"asset_id": "host"}, facts={}, collected=NOW)
    outcome = evaluate_check(check, empty)
    assert outcome.status is Status.UNASSESSED
    assert outcome.result.reason is UnassessedReason.COLLECTION_ERROR
    assert outcome.status is not Status.NOT_SATISFIED


def test_partial_population_yields_unassessed_not_satisfied(registry) -> None:
    """A host with one unreadable profile and no observed failures is NOT a pass.

    The profile that could not be read might be the failing one. Most compliance
    tools get this wrong, and it is the main reason this one exists.
    """
    check = registry.get("win-office-macro-internet-blocked")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    outcome = evaluate_check(check, bundle)
    assert outcome.status is Status.UNASSESSED
    assert outcome.result.reason is UnassessedReason.PARTIAL_POPULATION
    assert outcome.result.facts["profiles_unloaded"]


def test_observed_failure_is_reported_even_when_coverage_is_partial(registry) -> None:
    """Positive evidence of failure outranks incomplete coverage."""
    check = registry.get("win-office-macro-internet-blocked")
    bundle = load_bundle(FIXTURES / "wks-0043-failing.json")
    outcome = evaluate_check(check, bundle)
    assert outcome.status is Status.NOT_SATISFIED
    assert outcome.result.facts["failing"]


def test_evaluator_exception_becomes_error_not_failure(registry, monkeypatch) -> None:
    """A bug in our code is not evidence about the estate."""
    check = registry.get("win-office-macro-internet-blocked")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")

    def boom(*_args, **_kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(type(check), "resolve", lambda self: boom)
    outcome = evaluate_check(check, bundle)
    assert outcome.status is Status.ERROR
    assert outcome.status is not Status.NOT_SATISFIED


# --- Principle 4: declare confidence, never inflate it -------------------


def test_confidence_ceiling_can_lower_but_never_raise() -> None:
    strong = CheckResult.satisfied("x", {"a": 1}, Confidence.DIRECT)
    assert strong.with_confidence_ceiling(Confidence.PROXY).confidence is Confidence.PROXY

    weak = CheckResult.satisfied("x", {"a": 1}, Confidence.PARTIAL)
    assert weak.with_confidence_ceiling(Confidence.DIRECT).confidence is Confidence.PARTIAL


def test_registry_ceiling_is_applied_by_the_evaluator(registry) -> None:
    """An evaluator cannot opt out of its declared ceiling."""
    check = registry.get("win-office-macro-internet-blocked")
    assert check.confidence is Confidence.PROXY
    bundle = load_bundle(FIXTURES / "wks-0043-failing.json")
    outcome = evaluate_check(check, bundle)
    assert outcome.result.confidence is Confidence.PROXY


# --- Temporal controls: absence of history is not non-compliance ---------


def test_unsatisfiable_history_window_is_unassessed(registry) -> None:
    """Roughly a quarter of ML1 is temporal. None of it may be faked."""
    check = registry.get("win-office-macro-internet-blocked")
    hungry = type(check)(**{**check.__dict__, "history_window_days": 30})
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    outcome = evaluate_check(hungry, bundle, FactHistory.empty())
    assert outcome.status is Status.UNASSESSED
    assert outcome.result.reason is UnassessedReason.INSUFFICIENT_HISTORY


def test_empty_history_never_spans_a_window() -> None:
    assert FactHistory.empty().spans(1) is False
    assert FactHistory.empty().spans(0) is True


# --- Principle 8: evidence expires --------------------------------------


def test_expiry_is_derived_from_collection_not_evaluation(registry) -> None:
    """`collected` is when the FACT was gathered, which is what makes expiry mean
    anything. Deriving it from evaluation time would make stale evidence look
    permanently fresh."""
    check = registry.get("win-office-macro-internet-blocked")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    outcome = evaluate_check(check, bundle)
    assert outcome.collected == bundle.collected
    assert outcome.expires == bundle.collected + dt.timedelta(hours=check.freshness_hours)
    assert outcome.is_fresh(bundle.collected)
    assert not outcome.is_fresh(outcome.expires + dt.timedelta(seconds=1))


# --- ADR 0006: reviewed-controls comes from the plan ---------------------


def test_reviewed_controls_covers_the_entire_baseline(registry, ism) -> None:
    """reviewed-controls minus findings = unassessed only holds if
    reviewed-controls enumerates everything we intended to determine."""
    baseline = ism.baseline(e8="ML1")
    bundle = load_bundle(FIXTURES / "wks-0042-partial.json")
    bundle.subject["inventory_item_uuid"] = "00000000-0000-5000-8000-000000000001"
    evaluations = evaluate_bundle(registry, bundle, baseline)
    results = emit.emit_assessment_results(
        system_id="TEST", run_id="t1", baseline="E8_ML1",
        baseline_controls=baseline, evaluations=evaluations, catalog=ism,
        plan_href="./assessment-plan.json", now=NOW,
    )
    reviewed = {
        inc["control-id"]
        for sel in results["assessment-results"]["results"][0]["reviewed-controls"][
            "control-selections"
        ]
        for inc in sel["include-controls"]
    }
    assert reviewed == set(baseline), "reviewed-controls must cover the whole baseline"


def test_plan_marks_uncovered_controls_as_unassessed(registry, ism) -> None:
    baseline = ism.baseline(e8="ML1")
    plan = emit.emit_assessment_plan(
        system_id="TEST", baseline="E8_ML1", baseline_controls=baseline,
        registry=registry, catalog=ism, now=NOW,
    )
    selections = plan["assessment-plan"]["reviewed-controls"]["control-selections"]
    unassessed_sel = [
        s for s in selections
        if any(p["value"] == "unassessed" for p in s.get("props", []))
    ]
    assert unassessed_sel, "controls without a check must be explicitly marked unassessed"
    assert len(unassessed_sel[0]["include-controls"]) == 45


# --- Determinism ---------------------------------------------------------


def test_emission_is_byte_deterministic(registry, ism) -> None:
    """Same facts in, identical OSCAL out.

    This is what makes golden-file tests possible and lets an auditor
    independently re-derive a published document from its evidence.
    """
    baseline = ism.baseline(e8="ML1")

    def run() -> str:
        bundle = load_bundle(FIXTURES / "wks-0043-failing.json")
        bundle.subject["inventory_item_uuid"] = "00000000-0000-5000-8000-000000000002"
        evaluations = evaluate_bundle(registry, bundle, baseline)
        return json.dumps(
            emit.emit_assessment_results(
                system_id="TEST", run_id="t1", baseline="E8_ML1",
                baseline_controls=baseline, evaluations=evaluations, catalog=ism,
                plan_href="./assessment-plan.json", now=NOW,
            ),
            indent=2,
        )

    assert run() == run()


def test_poam_identity_survives_across_runs(registry, ism) -> None:
    """POA&M items are not run-scoped, so failure streaks and ticket links last."""
    from nobytes_cca.oscal import ids

    a = ids.poam_item_uuid("SYS", "ism-1488", "aggregate", "SYS/E8_ML1")
    b = ids.poam_item_uuid("SYS", "ism-1488", "aggregate", "SYS/E8_ML1")
    assert a == b
    assert a != ids.result_uuid("SYS", "run-1")


# --- Naive timestamps are refused ---------------------------------------


def test_naive_timestamps_are_rejected(registry, ism) -> None:
    """A naive timestamp silently read as local time makes freshness wrong in
    the direction that makes stale evidence look current."""
    with pytest.raises(ValueError, match=r"timezone|naive"):
        emit.emit_assessment_plan(
            system_id="TEST", baseline="E8_ML1",
            baseline_controls=ism.baseline(e8="ML1"), registry=registry,
            catalog=ism, now=dt.datetime(2026, 9, 20, 3, 0, 0),  # noqa: DTZ001 - naive on purpose
        )


def test_bundle_rejects_naive_timestamps(tmp_path: Path) -> None:
    from nobytes_cca.bundle import from_dict

    with pytest.raises(ValueError, match="timezone"):
        from_dict({"collected": "2026-09-20T02:14:07", "subject": {"asset_id": "h"}, "facts": {}})
