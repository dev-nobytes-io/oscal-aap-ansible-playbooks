"""The attestation model: declaring a control unobservable must never look like
assessing it.

`Assessability` exists because "nobody has built this yet" and "no tool can
observe this" call for completely different responses, and the undifferentiated
"no check" pile conflates them. The risk introduced by fixing that is obvious:
a coverage figure that can be raised by writing prose. These tests exist to make
that impossible rather than merely discouraged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ism_release import catalog_path
from nobytes_cca.catalog import Catalog
from nobytes_cca.contract import Assessability, Confidence, Method, Status, UnassessedReason
from nobytes_cca.evaluate import coverage_summary, evaluate_check
from nobytes_cca.registry import Registry

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry.load()


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    path = catalog_path()
    if not path.exists():
        pytest.skip(f"no vendored catalog at {path}; run `make fetch`")
    return Catalog.load(path)


def test_attested_controls_are_excluded_from_automated_coverage(
    registry: Registry, catalog: Catalog
) -> None:
    """The load-bearing test of this whole model.

    If an attested entry ever counts toward `controls_with_a_check`, the
    headline coverage number becomes something you can raise by writing a YAML
    file, and every figure this project publishes stops meaning anything.
    """
    baseline = catalog.baseline(e8="ML1")
    summary = coverage_summary(catalog, registry, baseline)

    automated = set(summary["covered"])
    attested = set(summary["attested"])

    assert attested, "no attested entries present; this test would pass vacuously"
    assert not (automated & attested), (
        "a control is counted as BOTH automated and attested: "
        f"{sorted(automated & attested)}"
    )
    for control_id in attested:
        assert control_id not in automated

    # The three buckets must exactly partition the baseline. A control that
    # falls through the accounting is the failure this arithmetic guards.
    assert (
        summary["controls_with_a_check"]
        + summary["controls_attested"]
        + summary["controls_unaccounted"]
        == summary["baseline_size"]
    )


def test_percentage_reflects_automation_only(registry: Registry, catalog: Catalog) -> None:
    baseline = catalog.baseline(e8="ML1")
    summary = coverage_summary(catalog, registry, baseline)
    assert summary["controls_with_a_check"] == len(registry.automated_controls() & set(baseline))


def test_attested_entries_carry_no_evaluator(registry: Registry) -> None:
    """An attested entry with an evaluator would be a contradiction that runs."""
    attested = [c for c in registry if c.assessability is Assessability.ATTESTED]
    assert attested, "no attested entries to check"
    for check in attested:
        assert not check.evaluator, f"{check.id} is attested but names an evaluator"
        assert not check.collect_role, f"{check.id} is attested but names a collect role"
        assert check.confidence is Confidence.ATTESTED
        assert check.method in (Method.EXAMINE, Method.INTERVIEW)
        with pytest.raises(ValueError, match="attested"):
            check.resolve()


def test_every_attested_entry_says_where_the_evidence_lives(registry: Registry) -> None:
    """A declaration with no owner and no source is an excuse, not a control."""
    for check in registry:
        if check.assessability is not Assessability.ATTESTED:
            continue
        att = check.attestation
        assert att is not None, check.id
        assert att.owner.strip(), f"{check.id}: attestation has no owner"
        assert att.source.strip(), f"{check.id}: attestation names no source"
        assert att.renewal_days > 0
        # The schema enforces a minimum length; this enforces that the text
        # argues structure rather than effort.
        lowered = att.why_not_observable.lower()
        assert not any(
            excuse in lowered for excuse in ("not yet", "too hard", "todo", "future work")
        ), (
            f"{check.id}: why_not_observable reads like a backlog item. "
            f"Attested means no tool can EVER observe it; if effort would fix "
            f"it, the entry belongs in the automated pile."
        )


def test_attested_check_never_produces_a_verdict(registry: Registry) -> None:
    """Even called directly, an attested entry may not pass or fail a control."""
    from nobytes_cca.bundle import load_bundle

    bundles = sorted(FIXTURES.glob("*.json"))
    assert bundles, "no fixture bundles; this test would pass vacuously"
    bundle = load_bundle(bundles[0])

    attested = [c for c in registry if c.assessability is Assessability.ATTESTED]
    assert attested
    for check in attested:
        evaluation = evaluate_check(check, bundle)
        assert evaluation.status is Status.UNASSESSED
        assert evaluation.result.reason is UnassessedReason.REQUIRES_ATTESTATION
        assert not evaluation.status.emits_finding
