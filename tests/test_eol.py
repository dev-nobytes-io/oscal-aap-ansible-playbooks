"""End-of-life lookup and the vendor-support check.

The distinctions tested here are the ones that decide whether a legacy estate
gets a useful answer or a misleading one.
"""

from __future__ import annotations

import datetime as dt

import pytest

from conftest import ROOT
from nobytes_cca.bundle import load_bundle
from nobytes_cca.checks.common.os_support import _windows_cycle
from nobytes_cca.contract import Status, UnassessedReason
from nobytes_cca.eol import lookup
from nobytes_cca.evaluate import evaluate_check
from nobytes_cca.registry import Registry

AS_OF = dt.date(2026, 9, 20)
FIXTURES = ROOT / "tests" / "fixtures" / "bundles"


@pytest.fixture(scope="module")
def check():
    return Registry.load().get("os-vendor-supported")


# --- the dataset itself --------------------------------------------------


@pytest.mark.parametrize(
    ("product", "cycle", "supported", "extended"),
    [
        ("rhel", "9.4", True, False),       # major-version fallback: 9.4 -> 9
        ("rhel", "7", False, True),         # ELS
        ("ubuntu", "24.04", True, False),
        ("ubuntu", "18.04", False, True),   # Ubuntu Pro ESM
        ("windows-server", "2022", True, False),
        ("windows-server", "2012-r2", False, True),
        ("windows", "10-22h2", False, True),  # ESU
    ],
)
def test_known_releases(product, cycle, supported, extended) -> None:
    status = lookup(product, cycle, AS_OF)
    assert not status.unknown
    assert status.supported is supported
    assert status.in_extended_support is extended


def test_unknown_release_is_unknown_not_unsupported() -> None:
    """Not knowing whether a release is supported is not evidence that it is not."""
    status = lookup("rhel", "99", AS_OF)
    assert status.unknown
    assert status.supported is False  # but the check must report unassessed, not fail


def test_unknown_product_is_unknown() -> None:
    assert lookup("plan9", "4", AS_OF).unknown


def test_support_is_judged_as_of_a_given_date() -> None:
    """The same release is supported before its EOL and not after.

    This is why the evaluator takes the date from the fact bundle rather than
    reading a clock: re-running an assessment over archived evidence must
    reproduce the verdict that was true when the evidence was gathered.
    """
    before = lookup("windows", "10-22h2", dt.date(2025, 1, 1))
    after = lookup("windows", "10-22h2", dt.date(2026, 1, 1))
    assert before.supported is True
    assert after.supported is False


# --- Windows cycle derivation -------------------------------------------


@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        ({"product_name": "Windows Server 2022 Datacenter", "install_type": "Server"}, "2022"),
        ({"product_name": "Windows Server 2012 R2 Standard", "install_type": "Server"}, "2012-r2"),
        (
            {"product_name": "Windows 10 Enterprise", "display_version": "22H2",
             "edition_id": "Enterprise", "install_type": "Client"},
            "10-22h2",
        ),
        (
            {"product_name": "Windows 11 Enterprise", "display_version": "24H2",
             "edition_id": "Enterprise", "install_type": "Client"},
            "11-24h2-e",
        ),
        (
            {"product_name": "Windows 11 Pro", "display_version": "24H2",
             "edition_id": "Professional", "install_type": "Client"},
            "11-24h2-w",
        ),
    ],
)
def test_windows_cycle_derivation(identity, expected) -> None:
    assert _windows_cycle(identity) == expected


def test_windows_11_without_an_edition_stays_ambiguous() -> None:
    """Enterprise and Pro support dates differ by a full year.

    Guessing would silently attach a date that may be a year out, so an
    unresolvable edition produces an ambiguous key that the lookup reports as
    unknown -- which becomes `unassessed`, not a verdict.
    """
    cycle = _windows_cycle(
        {"product_name": "Windows 11 Enterprise", "display_version": "24H2",
         "edition_id": "", "install_type": "Client"}
    )
    assert cycle == "11-24h2"
    status = lookup("windows", cycle, AS_OF)
    assert status.unknown
    assert "ambiguous" in status.source


# --- the check -----------------------------------------------------------


def test_legacy_rhel7_is_reported_as_extended_support(check) -> None:
    outcome = evaluate_check(check, load_bundle(FIXTURES / "srv-rhel7-legacy.json"))
    assert outcome.status is Status.SATISFIED
    assert outcome.result.facts["in_extended_support"] is True
    # A pass must not read as a healthy system.
    assert "PAST mainstream support" in outcome.result.detail


def test_extended_support_can_be_treated_as_unsupported(check) -> None:
    """The ESU interpretation is a parameter, not a silent decision."""
    strict = type(check)(
        **{**check.__dict__, "parameters": {"extended_support_counts_as_supported": False}}
    )
    outcome = evaluate_check(strict, load_bundle(FIXTURES / "srv-rhel7-legacy.json"))
    assert outcome.status is Status.NOT_SATISFIED


def test_missing_os_release_is_unassessed(check) -> None:
    from nobytes_cca.contract import FactBundle

    empty = FactBundle(subject={"asset_id": "h"}, facts={}, collected=dt.datetime.now(dt.timezone.utc))
    outcome = evaluate_check(check, empty)
    assert outcome.status is Status.UNASSESSED
    assert outcome.result.reason is UnassessedReason.COLLECTION_ERROR


def test_eol_dataset_is_vendored_and_checksummed() -> None:
    import json

    manifest = json.loads((ROOT / "data" / "eol" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["authoritative"] is False, (
        "the dataset is community-maintained; recording it as authoritative would "
        "let a check claim `direct` confidence it has not earned"
    )
    assert manifest["licence"] == "MIT"
    assert len(manifest["files"]) >= 6
