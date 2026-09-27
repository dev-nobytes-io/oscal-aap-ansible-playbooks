"""The contract between a collector script and the role that consumes it.

Every Windows collector here ends `| ConvertTo-Json -Compress`, so its only
pipeline output is one [string]. `ansible.windows.win_powershell` passes strings
through unchanged:

    elseif ($InputObject -is [string]) { $InputObject.PSObject.BaseObject }
        -- ansible/windows/plugins/modules/win_powershell.ps1:528-531

Until ADR 0017 every role read `register.output[0]` as though it were a mapping
and indexed `.rows` / `.meta` / `.applications` into it. On a real Windows host
those all resolved to undefined and were swallowed by `| default({})`, while
`partial` -- derived from `output | length`, which is 1 because there IS one
element -- reported the emptiness as a successful collection of nothing.

The 261 tests in this repository all passed against that, because every fixture
bundle is a hand-written mapping that never travelled through win_powershell.
Two artefacts agreeing with each other while both being wrong is the defect
class this file exists to break, so these tests operate on the WIRE form: what
win_powershell actually hands back.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from nobytes_cca.checks.windows.appcontrol import application_control_implemented
from nobytes_cca.contract import Fact, FactBundle, FactHistory, Status, UnassessedReason

ROOT = Path(__file__).resolve().parent.parent
ROLES = ROOT / "collections/ansible_collections/nobytes/compliance/roles"
FILTER = (
    ROOT
    / "collections/ansible_collections/nobytes/compliance/plugins/filter/ps_object.py"
)

WINDOWS_COLLECT_ROLES = sorted(p.name for p in ROLES.glob("collect_windows_*"))

COLLECTED = dt.datetime(2026, 9, 23, 4, 0, tzinfo=dt.timezone.utc)


def _ps_object():
    """Import the filter without needing ansible on the path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_ps_object_under_test", FILTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ps_object


# --------------------------------------------------------------------------
# The wiring. A correct filter nobody calls is what was already shipping.
# --------------------------------------------------------------------------


def test_there_are_windows_collect_roles_to_check() -> None:
    """A green suite must not be able to mean "nothing was scanned"."""
    assert WINDOWS_COLLECT_ROLES, "no collect_windows_* roles found to check"


@pytest.mark.parametrize("role", WINDOWS_COLLECT_ROLES)
def test_no_role_indexes_win_powershell_output_directly(role: str) -> None:
    """`output[0]` is the JSON text, so indexing it as a mapping is the bug.

    Fails against the code as it shipped: every one of the five roles contained
    a line of the form `(X.output | default([{}]))[0] | default({})`.
    """
    for task_file in (ROLES / role / "tasks").glob("*.yml"):
        text = task_file.read_text()
        offenders = re.findall(r"\.output[^\n]*\)\s*\[0\]", text)
        assert not offenders, (
            f"{role}/{task_file.name} indexes win_powershell's `output` as a "
            f"mapping: {offenders}. `output[0]` is the script's ConvertTo-Json "
            f"TEXT -- parse it with `nobytes.compliance.ps_object`. See ADR 0017."
        )


@pytest.mark.parametrize("role", WINDOWS_COLLECT_ROLES)
def test_every_role_parses_its_output_through_ps_object(role: str) -> None:
    """Every role that registers win_powershell output must parse it."""
    texts = [p.read_text() for p in (ROLES / role / "tasks").glob("*.yml")]
    body = "\n".join(texts)
    if "win_powershell" not in body:
        pytest.skip(f"{role} runs no win_powershell task")
    assert "nobytes.compliance.ps_object" in body, (
        f"{role} registers win_powershell output but never passes it through "
        f"`nobytes.compliance.ps_object`, so nothing establishes that a usable "
        f"object came back rather than an unparsed string."
    )


@pytest.mark.parametrize("role", WINDOWS_COLLECT_ROLES)
def test_every_fact_record_can_report_a_collection_error(role: str) -> None:
    """A parse failure has to be able to reach the evaluator as `partial`."""
    body = "\n".join(p.read_text() for p in (ROLES / role / "tasks").glob("*.yml"))
    if "win_powershell" not in body:
        pytest.skip(f"{role} runs no win_powershell task")
    assert ".ok" in body, (
        f"{role} never consults ps_object's `ok` flag, so an unparseable "
        f"collector result cannot be distinguished from an empty one."
    )


# --------------------------------------------------------------------------
# The filter itself, against the wire form.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("wire", "ok", "expected"),
    [
        # What win_powershell really returns for `$obj | ConvertTo-Json`.
        (['{"rows":[{"app":"word"}],"meta":{}}'], True, {"rows": [{"app": "word"}]}),
        # ...and for the `,@($result)` form three collectors still use.
        (['[{"applocker":{"available":true}}]'], True, {"applocker": {"available": True}}),
        # Failure modes that must NOT read as an empty result.
        ([], False, {}),
        ([""], False, {}),
        (["not json at all"], False, {}),
        (None, False, {}),
        (['[{"a":1},{"b":2}]'], False, {}),  # never silently drop a tail
        (["[]"], False, {}),  # an array is not the mapping contract
    ],
)
def test_ps_object_on_the_wire_form(wire, ok: bool, expected: dict) -> None:
    result = _ps_object()(wire)
    assert result["ok"] is ok, f"{wire!r} -> {result!r}"
    if ok:
        for key, value in expected.items():
            assert result["value"][key] == value
    else:
        assert result["value"] == {}
        assert result["error"], "a failure must say why"


def test_ps_object_expect_any_keeps_a_list() -> None:
    """The Office inventory's contract is a JSON array; zero of them is valid."""
    result = _ps_object()(["[]"], expect="any")
    assert result["ok"] is True
    assert result["value"] == []


def test_ps_object_rejects_being_handed_the_register() -> None:
    result = _ps_object()({"output": ['{"a":1}']})
    assert result["ok"] is False
    assert "output" in result["error"]


# --------------------------------------------------------------------------
# The consequence. This is the test that matters.
# --------------------------------------------------------------------------


def _appcontrol_bundle(value, *, partial: bool) -> FactBundle:
    return FactBundle(
        subject={"asset_id": "DC01", "platform_family": "windows"},
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state",
                value=value,
                collected=COLLECTED,
                source="test",
                partial=partial,
            )
        },
    )


def test_an_unreadable_host_is_never_reported_as_lacking_app_control() -> None:
    """The false red, pinned.

    Before ADR 0017 this exact state reached `appcontrol.py:196` and returned
    `not_satisfied` -- "No enforcing application control was found" -- about a
    host from which nothing had been read. `partial` was False because it was
    derived from the output list's length, which is 1.

    Reverting `_guard`'s structural check makes this test fail with
    Status.NOT_SATISFIED, which is what shipped.
    """
    result = application_control_implemented(
        _appcontrol_bundle({}, partial=False), {}, FactHistory.empty()
    )
    assert result.status is not Status.NOT_SATISFIED, (
        "an empty appcontrol fact produced a confident failure verdict; an "
        "unreadable host is not a host without application control"
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_the_raw_json_string_the_collector_emits_also_fails_closed() -> None:
    """Belt and braces: even if a role regresses, the evaluator holds."""
    wire = '{"applocker":{"available":true,"collections":[]},"wdac":{}}'
    result = application_control_implemented(
        _appcontrol_bundle(wire, partial=False), {}, FactHistory.empty()
    )
    assert result.status is Status.UNASSESSED, (
        "a fact value that is still a JSON string must not be evaluated as "
        "though it were a parsed observation"
    )


def test_the_wire_form_round_trips_into_a_real_verdict() -> None:
    """And the fixed path must still reach a determination, not just refuse."""
    emitted = json.dumps(
        {
            "applocker": {
                "available": True,
                "rule_count": 12,
                "collections": [
                    {"type": "Exe", "enforcement_mode": "Enabled"},
                    {"type": "Script", "enforcement_mode": "Enabled"},
                ],
            },
            "wdac": {"available": True, "running": []},
        }
    )
    parsed = _ps_object()([emitted])
    assert parsed["ok"] is True
    result = application_control_implemented(
        _appcontrol_bundle(parsed["value"], partial=False), {}, FactHistory.empty()
    )
    assert result.status is not Status.UNASSESSED, (
        "a well-formed collector result must produce a determination"
    )


# --------------------------------------------------------------------------
# The false GREEN. Worse than the red: it tells an agency a control is met.
# --------------------------------------------------------------------------


def _ie_bundle(features, *, partial: bool, ie_policy=None) -> FactBundle:
    facts = {
        "windows.os.optional_features": Fact(
            key="windows.os.optional_features",
            value=features,
            collected=COLLECTED,
            source="test",
            partial=partial,
        )
    }
    if ie_policy is not None:
        facts["windows.browser.ie_policy"] = Fact(
            key="windows.browser.ie_policy",
            value=ie_policy,
            collected=COLLECTED,
            source="test",
        )
    return FactBundle(
        subject={"asset_id": "DC01", "platform_family": "windows"},
        collected=COLLECTED,
        facts=facts,
    )


@pytest.mark.parametrize("partial", [False, True])
def test_a_failed_feature_enumeration_is_never_proof_ie11_is_absent(partial) -> None:
    """ism-1654 returned `satisfied` at DIRECT confidence on an empty list.

    `Get-WindowsOptionalFeature -Online` needs elevation and is missing on
    Server SKUs without DISM. Both produced an empty list, which
    `ie11_disabled_or_removed` read as "no Internet Explorer feature is present"
    -- the highest-confidence claim in the registry, about a host it had not
    successfully queried. A false green is worse than a false red in a
    compliance tool. Reverting the guard makes this fail with SATISFIED.
    """
    from nobytes_cca.checks.windows.os_state import ie11_disabled_or_removed

    result = ie11_disabled_or_removed(
        _ie_bundle([], partial=partial), {}, FactHistory.empty()
    )
    assert result.status is not Status.SATISFIED, (
        "an empty optional-feature list was reported as Internet Explorer being "
        "absent; nothing was read from this host"
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_a_real_feature_list_still_reaches_a_determination() -> None:
    """The guard must not refuse everything."""
    from nobytes_cca.checks.windows.os_state import ie11_disabled_or_removed

    result = ie11_disabled_or_removed(
        _ie_bundle(
            [{"name": "Internet-Explorer-Optional-amd64", "state": "Disabled"}],
            partial=False,
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
