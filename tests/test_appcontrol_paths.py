"""ism-1870 -- application control applied to user profiles and temp folders.

The case this file exists for is the first one: a host enforcing every
AppLocker rule collection, with thousands of rules, that still lets a standard
user run an executable they dropped in `C:\\Windows\\Temp`. That is what
AppLocker's default rules do, it is what an auditor's rule-count checklist
misses, and it is the whole reason the collector was extended from counting
rules to reading their paths.

The second thing under test is the asymmetry. An incomplete look must be able
to produce a failure and never a pass: a writable directory that was found is
writable whether or not the walk finished, but "nothing found" by a walk that
ran out of budget is not evidence that there is nothing.
"""

from __future__ import annotations

import datetime as dt

import pytest

from nobytes_cca.checks.windows.appcontrol_paths import (
    _contains,
    _covers,
    _is_admin_sid,
    application_control_covers_user_writable_paths,
)
from nobytes_cca.contract import Confidence, Fact, FactBundle, FactHistory, Status, UnassessedReason

COLLECTED = dt.datetime(2026, 9, 21, 4, 0, tzinfo=dt.timezone.utc)
SUBJECT = {"asset_id": "WKS-0001", "platform_family": "windows"}
WINDOWS_ROOT = "C:\\Windows"
EVERYONE = "S-1-1-0"
ADMINISTRATORS = "S-1-5-32-544"


def _rule(paths, *, action="Allow", sid=EVERYONE, name="rule", exceptions=(), non_path=0):
    return {
        "name": name,
        "action": action,
        "sid": sid,
        "paths": list(paths),
        "exceptions": list(exceptions),
        "non_path_conditions": non_path,
        "non_path_exceptions": 0,
    }


def _collection(ctype, rules, *, mode="Enabled"):
    return {
        "type": ctype,
        "enforcement_mode": mode,
        "rule_count": len(rules),
        "rule_types": {"FilePathRule": len(rules)},
        "path_rules": list(rules),
    }


def _default_rules(ctype="Exe", extra=()):
    """AppLocker's default rule set, which is what most estates actually run."""
    return _collection(
        ctype,
        [
            _rule(["%PROGRAMFILES%\\*"], name="(Default Rule) All files in Program Files"),
            _rule(["%WINDIR%\\*"], name="(Default Rule) All files in Windows"),
            _rule(["*"], sid=ADMINISTRATORS, name="(Default Rule) All files for admins"),
            *extra,
        ],
    )


def _probe(path, role, *, writable=True, access="ok"):
    return {
        "path": path,
        "role": role,
        "exists": access != "missing",
        "access": access,
        "allow_write_sids": ["S-1-5-32-545"] if writable else [],
        "deny_write_sids": [],
        "non_admin_writable": writable if access == "ok" else None,
        "error": "",
    }


def _paths(probes=(), *, windows_writable=(), truncated=False, profiles=1):
    return {
        "windows_root": WINDOWS_ROOT,
        "profiles_root": "C:\\Users",
        "profiles_total": profiles,
        "profiles_probed": profiles,
        "profile_error": "",
        "probes": list(probes),
        "windows_writable": list(windows_writable),
        "windows_walk": {
            "depth": 3,
            "budget": 4000,
            "remaining": 0 if truncated else 3900,
            "truncated": truncated,
            "error": "",
        },
    }


def _bundle(state, paths, *, state_partial=False, paths_partial=False) -> FactBundle:
    return FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state",
                value=state,
                collected=COLLECTED,
                partial=state_partial,
            ),
            "windows.appcontrol.writable_paths": Fact(
                key="windows.appcontrol.writable_paths",
                value=paths,
                collected=COLLECTED,
                partial=paths_partial,
            ),
        },
    )


def _state(collections, *, wdac_enforced=False):
    return {
        "applocker": {
            "available": True,
            "collections": list(collections),
            "rule_count": sum(c["rule_count"] for c in collections),
        },
        "wdac": {
            "available": True,
            "running": [2] if wdac_enforced else [],
            "code_integrity_policy_enforcement_status": 2 if wdac_enforced else 0,
            "usermode_code_integrity_policy_enforcement_status": 2 if wdac_enforced else 0,
        },
    }


def _run(state, paths, params=None):
    return application_control_covers_user_writable_paths(
        _bundle(state, paths), params or {}, FactHistory.empty()
    )


# --------------------------------------------------------------------------
# The load-bearing case
# --------------------------------------------------------------------------

def test_default_rules_permit_execution_from_the_os_temp_folder() -> None:
    """Every collection enforced, many rules, and still a bypass.

    `%WINDIR%\\*` is an AppLocker default rule. `C:\\Windows\\Temp` is inside
    it and is writable by standard users on a default install. This is the
    finding the whole check exists to produce.
    """
    result = _run(
        _state([_default_rules()]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.confidence is Confidence.PARTIAL
    assert "temporary folder used by the operating system" in result.detail
    hits = result.facts["permitted_from_writable_locations"]
    assert [h["location"] for h in hits] == ["C:\\Windows\\Temp"]
    assert hits[0]["rule"] == "(Default Rule) All files in Windows"


def test_a_hardened_temp_folder_is_not_reported_as_a_bypass() -> None:
    """The reason the writability probe exists rather than a hardcoded list."""
    result = _run(
        _state([_default_rules()]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp", writable=False)]),
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PARTIAL


def test_user_profile_allow_is_a_finding() -> None:
    result = _run(
        _state(
            [
                _collection(
                    "Script",
                    [_rule(["%OSDRIVE%\\Users\\*\\AppData\\Local\\Temp\\*"], name="user temp")],
                )
            ]
        ),
        _paths([_probe("C:\\Users\\alice\\AppData\\Local\\Temp", "user-temp")]),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "temporary folder used by a web browser" not in result.detail
    assert "user's temporary folder" in result.detail


def test_windows_subdirectory_walk_findings_are_judged_too() -> None:
    """The generalisation of the Temp case: `C:\\Windows\\Tasks` and friends."""
    result = _run(
        _state([_default_rules()]),
        _paths(
            [_probe("C:\\Windows\\Temp", "os-temp", writable=False)],
            windows_writable=[_probe("C:\\Windows\\Tasks", "windows-subdirectory")],
        ),
    )
    assert result.status is Status.NOT_SATISFIED
    hits = result.facts["permitted_from_writable_locations"]
    assert [h["location"] for h in hits] == ["C:\\Windows\\Tasks"]


# --------------------------------------------------------------------------
# Hardening that actually works must be seen to work
# --------------------------------------------------------------------------

def test_a_deny_rule_over_the_temp_folder_cancels_the_broad_allow() -> None:
    """An administrator who fixed this must not still be reported as broken."""
    collection = _default_rules(
        extra=[_rule(["%WINDIR%\\Temp\\*"], action="Deny", name="deny windows temp")]
    )
    result = _run(
        _state([collection]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.SATISFIED


def test_an_exception_on_the_allow_rule_also_cancels_it() -> None:
    collection = _collection(
        "Exe",
        [_rule(["%WINDIR%\\*"], exceptions=["%WINDIR%\\Temp\\*"], name="windows minus temp")],
    )
    result = _run(_state([collection]), _paths([_probe("C:\\Windows\\Temp", "os-temp")]))
    assert result.status is Status.SATISFIED


def test_a_deny_in_one_collection_does_not_cover_another() -> None:
    """Exe and Script are evaluated independently, because AppLocker does."""
    exe = _collection(
        "Exe",
        [
            _rule(["%WINDIR%\\*"], name="exe windows"),
            _rule(["%WINDIR%\\Temp\\*"], action="Deny", name="exe deny temp"),
        ],
    )
    script = _collection("Script", [_rule(["%WINDIR%\\*"], name="script windows")])
    result = _run(_state([exe, script]), _paths([_probe("C:\\Windows\\Temp", "os-temp")]))
    assert result.status is Status.NOT_SATISFIED
    assert {h["collection"] for h in result.facts["permitted_from_writable_locations"]} == {
        "Script"
    }


# --------------------------------------------------------------------------
# Administrator scoping is a judgement, so it is a parameter
# --------------------------------------------------------------------------

def test_administrator_scoped_allow_is_recorded_not_failed_by_default() -> None:
    result = _run(
        _state([_collection("Exe", [_rule(["*"], sid=ADMINISTRATORS, name="admins")])]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.SATISFIED
    assert len(result.facts["administrator_scoped_allows"]) == 1


def test_administrator_scoped_allow_fails_when_the_deployment_says_so() -> None:
    result = _run(
        _state([_collection("Exe", [_rule(["*"], sid=ADMINISTRATORS, name="admins")])]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
        {"fail_on_administrator_allow": True},
    )
    assert result.status is Status.NOT_SATISFIED


def test_an_unrecognised_sid_counts_as_a_standard_user() -> None:
    """The allow-list is inverted on purpose: unknown fails closed."""
    assert _is_admin_sid("S-1-5-32-544") is True
    assert _is_admin_sid("S-1-5-21-1-2-3-500") is True
    assert _is_admin_sid("S-1-5-21-1-2-3-1104") is False
    assert _is_admin_sid("S-1-1-0") is False
    assert _is_admin_sid("") is False


# --------------------------------------------------------------------------
# An incomplete look can fail, but must never pass
# --------------------------------------------------------------------------

def test_a_truncated_walk_finding_nothing_is_not_a_pass() -> None:
    result = _run(_state([_default_rules()]), _paths([], truncated=True))
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


def test_an_unreadable_probe_blocks_a_pass() -> None:
    result = _run(
        _state([_default_rules()]),
        _paths([_probe("C:\\Users\\bob\\AppData\\Local\\Temp", "user-temp", access="denied")]),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


def test_a_truncated_walk_still_reports_what_it_did_find() -> None:
    """Asymmetry: incompleteness weakens a pass, never a finding."""
    result = _run(
        _state([_default_rules()]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")], truncated=True),
    )
    assert result.status is Status.NOT_SATISFIED


def test_a_partial_fact_produces_no_verdict() -> None:
    result = application_control_covers_user_writable_paths(
        _bundle(_state([_default_rules()]), _paths([]), paths_partial=True),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


def test_a_missing_fact_produces_no_verdict() -> None:
    bundle = FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state",
                value=_state([_default_rules()]),
                collected=COLLECTED,
            )
        },
    )
    result = application_control_covers_user_writable_paths(bundle, {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_an_allow_rule_with_no_readable_path_produces_no_verdict() -> None:
    """A parser that cannot see its target must not report the target as safe."""
    result = _run(
        _state([_collection("Exe", [_rule([], name="unparsed")])]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR
    assert "unparsed" in result.detail


def test_a_publisher_rule_with_no_paths_is_not_treated_as_unparsed() -> None:
    """A rule that genuinely has no path condition is readable, just not a path."""
    result = _run(
        _state([_collection("Exe", [_rule([], name="signed by vendor", non_path=1)])]),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.SATISFIED


# --------------------------------------------------------------------------
# Boundaries of what this check claims
# --------------------------------------------------------------------------

def test_audit_only_collections_are_not_enforcing() -> None:
    collection = _default_rules()
    collection["enforcement_mode"] = "AuditOnly"
    result = _run(_state([collection]), _paths([_probe("C:\\Windows\\Temp", "os-temp")]))
    assert result.status is Status.NOT_SATISFIED
    assert "not at all" in result.detail
    assert result.facts["unenforced_collections"] == ["Exe"]


def test_wdac_enforcing_yields_no_verdict() -> None:
    result = _run(
        _state([_default_rules()], wdac_enforced=True),
        _paths([_probe("C:\\Windows\\Temp", "os-temp")]),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.INSUFFICIENT_PRIVILEGE


def test_a_pass_states_what_it_does_not_prove() -> None:
    collection = _collection("Exe", [_rule(["%PROGRAMFILES%\\*"], name="program files")])
    result = _run(_state([collection]), _paths([_probe("C:\\Windows\\Temp", "os-temp")]))
    assert result.status is Status.SATISFIED
    assert "does not prove" in result.detail


# --------------------------------------------------------------------------
# Path matching, which is where a quiet wrong answer would come from
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("pattern", "location"),
    [
        ("*", "C:\\Users\\alice"),
        ("%WINDIR%\\*", "C:\\Windows\\Temp"),
        ("%OSDRIVE%\\*", "C:\\Users"),
        ("C:\\*", "C:\\Users\\alice\\Downloads"),
        # Case folds: NTFS is case-insensitive, so a lower-case rule is the
        # same rule.
        ("%windir%\\temp\\*", "C:\\Windows\\Temp"),
        # Narrower than the location, and still a finding: the rule permits
        # execution from part of it.
        ("%OSDRIVE%\\Users\\*\\AppData\\Local\\Temp\\*", "C:\\Users"),
        # %SYSTEM32% expands to SysWOW64 as well.
        ("%SYSTEM32%\\*", "C:\\Windows\\SysWOW64\\Tasks"),
        # %PROGRAMFILES% expands to both Program Files directories.
        ("%PROGRAMFILES%\\*", "C:\\Program Files (x86)\\Vendor\\writable"),
    ],
)
def test_covers(pattern: str, location: str) -> None:
    assert _covers(pattern, location, WINDOWS_ROOT) is True


@pytest.mark.parametrize(
    ("pattern", "location"),
    [
        ("%PROGRAMFILES%\\*", "C:\\Windows\\Temp"),
        ("%WINDIR%\\System32\\*", "C:\\Users\\alice"),
        # Removable and hot-plug media expand to no fixed-disk path, so a rule
        # using them can never cover a profile or a temporary folder.
        ("%REMOVABLE%\\*", "C:\\Users\\alice"),
        ("%HOT%\\*", "C:\\Windows\\Temp"),
    ],
)
def test_does_not_cover(pattern: str, location: str) -> None:
    assert _covers(pattern, location, WINDOWS_ROOT) is False


def test_contains_is_narrower_than_covers() -> None:
    """Only a FULL carve-out cancels a finding.

    A deny or exception over one user's temporary folder leaves every other
    profile allowed, and reporting that as fixed would be worse than not
    checking at all.
    """
    pattern = "%OSDRIVE%\\Users\\alice\\AppData\\Local\\Temp\\*"
    assert _covers(pattern, "C:\\Users", WINDOWS_ROOT) is True
    assert _contains(pattern, "C:\\Users", WINDOWS_ROOT) is False
    assert _contains(pattern, "C:\\Users\\alice\\AppData\\Local\\Temp", WINDOWS_ROOT) is True


def test_administrator_allows_are_counted_as_rules_not_as_combinations() -> None:
    """Two admin rules over six locations is two rules, not twelve.

    Multiplying rules by locations reads as an estate twelve times worse than
    it is, in the sentence a reader is most likely to quote.
    """
    admin_rule = _rule(["*"], sid=ADMINISTRATORS, name="(Default Rule) All files")
    state = _state(
        [
            _collection("Exe", [_rule(["%WINDIR%\\*"], name="windows"), admin_rule]),
            _collection("Script", [_rule(["%WINDIR%\\*"], name="windows scripts"), admin_rule]),
        ]
    )
    result = _run(
        state,
        _paths(
            [
                _probe("C:\\Windows\\Temp", "os-temp"),
                _probe("C:\\Windows\\Tasks", "windows-subdirectory"),
            ]
        ),
    )
    assert result.status is Status.NOT_SATISFIED
    assert len(result.facts["administrator_scoped_allows"]) == 4
    assert "2 allow rule(s) scoped to administrative principals" in result.detail
