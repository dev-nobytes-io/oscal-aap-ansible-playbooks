"""Windows application control.

Two traps drive these cases.

**AuditOnly blocks nothing.** An AppLocker collection in audit mode writes an
event and permits execution. Counting it as "implemented" is the most likely
way a workstation looks protected and is not, and it is the application-control
equivalent of a report-only conditional access policy.

**AppLocker cannot satisfy ism-1657, ever.** The control names seven file
types; AppLocker has five rule collections and Microsoft documents what each
covers. Compiled HTML (.chm), HTML applications (.hta) and control panel
applets (.cpl) are in none of them. A fully enforced AppLocker policy is
therefore still short of this control, and an organisation treating AppLocker
as equivalent to ML1 application control has a gap it does not know about.
Reporting `satisfied` because five collections are enforced would hide exactly
the thing worth finding.
"""

from __future__ import annotations

import datetime as dt

import pytest

from nobytes_cca.checks.windows.appcontrol import (
    BEYOND_APPLOCKER,
    REQUIRED_TYPES,
    application_control_covers_required_file_types,
    application_control_implemented,
)
from nobytes_cca.contract import Confidence, Fact, FactBundle, FactHistory, Status, UnassessedReason

COLLECTED = dt.datetime(2026, 9, 21, 4, 0, tzinfo=dt.timezone.utc)
SUBJECT = {"asset_id": "WKS-0001", "platform_family": "windows"}


def _bundle(state: dict, *, partial: bool = False) -> FactBundle:
    return FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state",
                value=state,
                collected=COLLECTED,
                partial=partial,
            )
        },
    )


def _applocker(*, enabled=(), audit=(), rules=12) -> dict:
    collections = [
        {"type": t, "enforcement_mode": "Enabled", "rule_count": rules} for t in enabled
    ] + [{"type": t, "enforcement_mode": "AuditOnly", "rule_count": rules} for t in audit]
    return {
        "applocker": {"available": True, "collections": collections, "rule_count": rules},
        "wdac": {"available": True, "running": []},
    }


def _wdac(enforced: bool) -> dict:
    return {
        "applocker": {"available": True, "collections": [], "rule_count": 0},
        "wdac": {
            "available": True,
            "running": [2] if enforced else [],
            "code_integrity_policy_enforcement_status": 2 if enforced else 0,
            "usermode_code_integrity_policy_enforcement_status": 2 if enforced else 0,
        },
    }


# --------------------------------------------------------------------------
# ism-0843 -- application control is implemented
# --------------------------------------------------------------------------

def test_audit_only_is_not_implemented() -> None:
    """The load-bearing case: audit mode logs and blocks nothing."""
    result = application_control_implemented(
        _bundle(_applocker(audit=["Exe", "Dll", "Script", "Msi"])), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert "blocks nothing" in result.detail
    assert result.facts["applocker_enforced_collections"] == []


def test_enforcing_applocker_is_implemented_at_proxy_only() -> None:
    result = application_control_implemented(
        _bundle(_applocker(enabled=["Exe", "Script"])), {}, FactHistory.empty()
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PROXY


def test_a_collection_with_no_rules_does_not_count() -> None:
    """Enabled with zero rules enforces nothing."""
    result = application_control_implemented(
        _bundle(_applocker(enabled=["Exe"], rules=0)), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED


def test_wdac_alone_satisfies_without_any_applocker_policy() -> None:
    """Reading AppLocker alone would report a false failure on a WDAC host."""
    result = application_control_implemented(_bundle(_wdac(True)), {}, FactHistory.empty())
    assert result.status is Status.SATISFIED
    assert result.facts["wdac_enforcing"] is True
    assert result.facts["applocker_enforced_collections"] == []


def test_nothing_enforcing_fails() -> None:
    result = application_control_implemented(_bundle(_wdac(False)), {}, FactHistory.empty())
    assert result.status is Status.NOT_SATISFIED


def test_unreadable_state_is_unassessed_not_failed() -> None:
    """A host that could not be inspected is not a host without app control."""
    result = application_control_implemented(
        _bundle({"applocker": {"available": False}, "wdac": {"available": False}}, partial=True),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


def test_missing_fact_is_unassessed() -> None:
    empty = FactBundle(subject=SUBJECT, collected=COLLECTED, facts={})
    result = application_control_implemented(empty, {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


# --------------------------------------------------------------------------
# ism-1657 -- the restricted set covers every listed file type
# --------------------------------------------------------------------------

def test_even_fully_enforced_applocker_cannot_satisfy_the_control() -> None:
    """The finding this check exists to produce.

    All four mappable collections enforced, and it is still not satisfied,
    because three of the seven file types the control names are outside
    AppLocker entirely.
    """
    result = application_control_covers_required_file_types(
        _bundle(_applocker(enabled=["Exe", "Dll", "Script", "Msi"])), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.confidence is Confidence.PARTIAL
    assert result.facts["not_covered_configurable"] == []
    for file_type, extension in BEYOND_APPLOCKER.items():
        assert file_type in result.detail
        assert extension in result.detail
    assert "however it is configured" in result.detail


def test_partial_applocker_names_what_configuration_could_still_fix() -> None:
    """Two kinds of gap, kept apart: fixable by config, and not fixable at all."""
    result = application_control_covers_required_file_types(
        _bundle(_applocker(enabled=["Exe"])), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert set(result.facts["covered_by_enforced_applocker"]) == {"executables"}
    assert set(result.facts["not_covered_configurable"]) == {
        "libraries",
        "scripts",
        "installers",
    }
    assert result.facts["not_coverable_by_applocker"] == BEYOND_APPLOCKER


def test_wdac_enforcing_is_unassessed_not_guessed() -> None:
    """WDAC covers more, and its rules are not readable from collected state."""
    result = application_control_covers_required_file_types(
        _bundle(_wdac(True)), {}, FactHistory.empty()
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.INSUFFICIENT_PRIVILEGE
    assert "guessing" in result.detail


def test_audit_only_covers_nothing_for_file_types_either() -> None:
    result = application_control_covers_required_file_types(
        _bundle(_applocker(audit=["Exe", "Dll", "Script", "Msi"])), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.facts["covered_by_enforced_applocker"] == []


def test_the_required_type_list_matches_the_control_wording() -> None:
    """Guards against the list drifting away from the ISM statement."""
    assert set(BEYOND_APPLOCKER) <= set(REQUIRED_TYPES)
    assert len(REQUIRED_TYPES) == 7
    for expected in ("compiled HTML", "HTML applications", "control panel applets"):
        assert expected in REQUIRED_TYPES


@pytest.mark.parametrize("evaluator", [
    application_control_implemented,
    application_control_covers_required_file_types,
])
def test_neither_evaluator_ever_returns_a_verdict_without_evidence(evaluator) -> None:
    result = evaluator(_bundle(_applocker(enabled=["Exe"])), {}, FactHistory.empty())
    if result.status in (Status.SATISFIED, Status.NOT_SATISFIED):
        assert result.facts, "a verdict with no supporting facts is an assertion"
