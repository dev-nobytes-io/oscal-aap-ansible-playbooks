"""ism-1704 — unsupported applications are removed.

The risk here is a vacuous pass. The vendored end-of-life dataset covers three
and a half of the six application families the control names, and most of what
is installed on a real workstation maps to nothing at all. A check that
reported `satisfied` because it happened to recognise nothing would be worse
than no check: it would put a green tick against a control it never evaluated.
"""

from __future__ import annotations

import datetime as dt

from nobytes_cca.checks.windows.app_support import (
    UNCOVERED_FAMILIES,
    unsupported_applications_removed,
)
from nobytes_cca.contract import Confidence, Fact, FactBundle, FactHistory, Status, UnassessedReason

COLLECTED = dt.datetime(2026, 9, 21, 4, 0, tzinfo=dt.timezone.utc)
SUBJECT = {"asset_id": "WKS-0001", "platform_family": "windows"}


def _bundle(apps, *, partial: bool = False, meta: dict | None = None) -> FactBundle:
    return FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "windows.applications.installed": Fact(
                key="windows.applications.installed",
                value=apps,
                collected=COLLECTED,
                partial=partial,
                meta=meta or {},
            )
        },
    )


def _app(name, version="", publisher="", scope="machine") -> dict:
    return {"name": name, "version": version, "publisher": publisher, "scope": scope}


def test_flash_is_unsupported_without_consulting_any_feed() -> None:
    """The control names Flash explicitly; its death is public record."""
    result = unsupported_applications_removed(
        _bundle([_app("Adobe Flash Player 32 NPAPI", "32.0.0.465")]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    entry = result.facts["unsupported"][0]
    assert entry["product"] == "Adobe Flash Player"
    assert entry["eol"] == "2020-12-31"
    assert "blocking Flash content" in entry["basis"]


def test_an_out_of_support_office_fails() -> None:
    result = unsupported_applications_removed(
        _bundle([_app("Microsoft Office Professional Plus 2016", "16.0.4266.1001")]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.confidence is Confidence.PARTIAL


def test_a_supported_browser_passes_but_only_at_partial() -> None:
    """Never `direct`: three of the six families cannot be seen at all."""
    result = unsupported_applications_removed(
        _bundle([_app("Mozilla Firefox", "115.0.2")]), {}, FactHistory.empty()
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PARTIAL


def test_nothing_mappable_is_unassessed_not_a_pass() -> None:
    """The load-bearing test.

    A workstation full of line-of-business software that maps to no support
    timeline has not been shown to satisfy this control. Reporting `satisfied`
    because nothing was recognised would put a green tick against a control
    that was never evaluated.
    """
    result = unsupported_applications_removed(
        _bundle(
            [
                _app("Acme Timesheets", "4.1"),
                _app("Contoso VPN Client", "9.2"),
                _app("Some Internal Tool", "1.0"),
            ]
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION
    assert result.facts["unmapped_count"] == 3
    assert "nothing was actually judged" in result.detail


def test_unmapped_applications_are_never_counted_as_supported() -> None:
    result = unsupported_applications_removed(
        _bundle([_app("Mozilla Firefox", "115.0.2"), _app("Acme Timesheets", "4.1")]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert len(result.facts["supported"]) == 1
    assert result.facts["unmapped_count"] == 1
    assert "neither passed nor failed" in result.detail


def test_every_result_names_the_families_it_cannot_see(  ) -> None:
    """Satisfied or not, the gap is stated. Silence would imply coverage."""
    for apps in (
        [_app("Mozilla Firefox", "115.0.2")],
        [_app("Adobe Flash Player", "32.0")],
    ):
        result = unsupported_applications_removed(_bundle(apps), {}, FactHistory.empty())
        assert result.facts["families_not_covered"] == list(UNCOVERED_FAMILIES)
        for family in ("Microsoft Edge", "PDF applications", "security products"):
            assert family in result.detail


def test_an_unreadable_profile_hive_is_partial_not_clean() -> None:
    """The hive we could not read may hold the unsupported application."""
    result = unsupported_applications_removed(
        _bundle([], partial=True, meta={"unloaded_hives": ["S-1-5-21-99"]}),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION
    assert result.facts["unloaded_hives"] == ["S-1-5-21-99"]


def test_support_is_judged_as_of_the_collection_date_not_now() -> None:
    """Re-running over archived evidence must reproduce the original verdict."""
    old = FactBundle(
        subject=SUBJECT,
        collected=dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc),
        facts={
            "windows.applications.installed": Fact(
                key="windows.applications.installed",
                value=[_app("Microsoft Office Professional Plus 2016", "16.0.1")],
                collected=dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc),
            )
        },
    )
    result = unsupported_applications_removed(old, {}, FactHistory.empty())
    assert result.facts["as_of"] == "2023-01-01"
    # Office 2016 was still in support in January 2023 (EOL 2025-10-14).
    assert result.status is Status.SATISFIED


def test_missing_fact_is_unassessed() -> None:
    empty = FactBundle(subject=SUBJECT, collected=COLLECTED, facts={})
    result = unsupported_applications_removed(empty, {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR
