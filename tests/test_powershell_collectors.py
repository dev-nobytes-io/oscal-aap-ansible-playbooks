"""Run the Windows collectors, rather than reading them.

The standing gap in this repository is that no Windows collector has ever run
against a real system, so its PowerShell is reviewed and never executed. That
is the exact shape of defect the project keeps finding in itself: a thing that
validates is not evidence that a thing runs.

`Get-AppLockerPolicy`, `Get-Acl` and `Win32_DeviceGuard` need Windows. Most of
the code around them does not. So the AppLocker parsing was pulled into
`ConvertFrom-AppLockerPolicyXml`, and this module runs it under PowerShell
against a real policy document and feeds the result straight into the
evaluators. It also runs the writability collector on a host where every
Windows facility is absent, because a collector that throws there produces no
bundle at all.

What this proves, precisely:

    * the collector's XML handling and the evaluator's expectations agree,
      end to end, from a policy document to a verdict
    * the collectors emit well-formed output, with explicit errors, on a host
      that can answer none of their questions -- and that output yields no
      verdict rather than a pass
    * the administrative-SID allow-list held in PowerShell and the one held in
      Python classify the same SIDs the same way
    * the subdirectory walk's depth and budget actually bound it, which is what
      makes `truncated` mean something

What it does not prove, equally precisely: that `Get-AppLockerPolicy`,
`Get-Acl` or `Win32_DeviceGuard` behave as expected on a Windows host. Those
still need a lab. See docs/platforms/windows.md.

It found one defect on its first run that review had not: `@($list)` around a
generic List fails inside an `[ordered]` literal with "Argument types do not
match". `make ps-lint` parsed the script cleanly. Executing it did not.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess

import pytest

from conftest import ROOT
from nobytes_cca.checks.windows.appcontrol import (
    application_control_covers_required_file_types,
    application_control_implemented,
)
from nobytes_cca.checks.windows.appcontrol_paths import (
    application_control_covers_user_writable_paths,
)
from nobytes_cca.contract import Fact, FactBundle, FactHistory, Status

SCRIPT = (
    ROOT
    / "collections"
    / "ansible_collections"
    / "nobytes"
    / "compliance"
    / "roles"
    / "collect_windows_appcontrol"
    / "files"
    / "Get-ApplicationControlState.ps1"
)
POLICY = ROOT / "tests" / "fixtures" / "applocker" / "default-rules.xml"
COLLECTED = dt.datetime(2026, 9, 21, 4, 0, tzinfo=dt.timezone.utc)

pwsh = shutil.which("pwsh") or shutil.which("powershell")
requires_pwsh = pytest.mark.skipif(
    pwsh is None,
    reason="no PowerShell interpreter; the CI job named powershell runs these",
)


@pytest.fixture(scope="module")
def collections_from_policy() -> list:
    """Dot-source the collector and run its parser over the policy fixture.

    The whole script cannot run here -- `Get-AppLockerPolicy` does not exist --
    but dot-sourcing loads its functions, and the parser is the part that can
    be wrong in a way nobody would notice.
    """
    # `$null = . script` loads the functions AND runs the body. Both are
    # wanted: the body's own output is discarded, but running it proves the
    # script completes without a terminating error even where every cmdlet it
    # calls is missing -- which is what its try/catch blocks claim.
    command = (
        f"$null = . '{SCRIPT}'; "
        f"$xml = Get-Content -Raw -LiteralPath '{POLICY}'; "
        "ConvertFrom-AppLockerPolicyXml -Xml $xml | ConvertTo-Json -Depth 8 -Compress"
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-only
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, f"pwsh failed: {proc.stderr}"
    parsed = json.loads(proc.stdout)
    return parsed if isinstance(parsed, list) else [parsed]


@requires_pwsh
def test_the_script_parses(collections_from_policy: list) -> None:
    assert [c["type"] for c in collections_from_policy] == [
        "Appx",
        "Exe",
        "Script",
        "Msi",
        "Dll",
    ]


@requires_pwsh
def test_rule_collection_extensions_are_not_counted_as_rules(
    collections_from_policy: list,
) -> None:
    """The bug this chunk fixed, asserted against a document that carries one.

    `RuleCollectionExtensions` is a sibling of the rules. Counting it let a
    collection holding NO rules report `rule_count: 1`, and `rule_count > 0` is
    what ism-0843 uses to decide a collection is enforcing -- so an empty
    enforcing collection read as implemented.
    """
    by_type = {c["type"]: c for c in collections_from_policy}
    assert by_type["Dll"]["rule_count"] == 0
    assert by_type["Exe"]["rule_count"] == 4


@requires_pwsh
def test_path_rules_carry_paths_sids_actions_and_exceptions(
    collections_from_policy: list,
) -> None:
    exe = next(c for c in collections_from_policy if c["type"] == "Exe")
    windows_rule = next(
        r for r in exe["path_rules"] if r["paths"] == ["%WINDIR%\\*"]
    )
    assert windows_rule["action"] == "Allow"
    assert windows_rule["sid"] == "S-1-1-0"
    # A publisher condition sitting alongside a path condition in an Exceptions
    # block is counted, not silently folded into the path list.
    assert windows_rule["exceptions"] == ["%WINDIR%\\Tasks\\*"]
    assert windows_rule["non_path_exceptions"] == 1


@requires_pwsh
def test_a_publisher_rule_is_a_rule_but_not_a_path_rule(
    collections_from_policy: list,
) -> None:
    exe = next(c for c in collections_from_policy if c["type"] == "Exe")
    assert exe["rule_types"]["FilePublisherRule"] == 1
    assert exe["rule_types"]["FilePathRule"] == 3
    assert len(exe["path_rules"]) == 3


@requires_pwsh
def test_deny_rules_survive_parsing(collections_from_policy: list) -> None:
    msi = next(c for c in collections_from_policy if c["type"] == "Msi")
    actions = {r["name"]: r["action"] for r in msi["path_rules"]}
    assert "Deny" in actions.values()


@requires_pwsh
def test_the_evaluators_accept_what_the_collector_produces(
    collections_from_policy: list,
) -> None:
    """The join this test exists for.

    A fixture bundle hand-written to match the evaluator proves the evaluator
    self-consistent. Feeding it the collector's OWN output proves the two ends
    agree.
    """
    state = {
        "applocker": {
            "available": True,
            "collections": collections_from_policy,
            "rule_count": sum(c["rule_count"] for c in collections_from_policy),
            "error": "",
        },
        "wdac": {
            "available": True,
            "running": [],
            "code_integrity_policy_enforcement_status": 0,
            "usermode_code_integrity_policy_enforcement_status": 0,
            "error": "",
        },
    }
    paths = {
        "windows_root": "C:\\Windows",
        "profiles_root": "C:\\Users",
        "profiles_total": 1,
        "profiles_probed": 1,
        "profile_error": "",
        "probes": [
            {
                "path": "C:\\Windows\\Temp",
                "role": "os-temp",
                "exists": True,
                "access": "ok",
                "allow_write_sids": ["S-1-5-32-545"],
                "deny_write_sids": [],
                "non_admin_writable": True,
                "error": "",
            }
        ],
        "windows_writable": [],
        "windows_walk": {
            "depth": 3,
            "budget": 4000,
            "remaining": 2900,
            "truncated": False,
            "error": "",
        },
    }
    bundle = FactBundle(
        subject={"asset_id": "WKS-PWSH", "platform_family": "windows"},
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state", value=state, collected=COLLECTED
            ),
            "windows.appcontrol.writable_paths": Fact(
                key="windows.appcontrol.writable_paths", value=paths, collected=COLLECTED
            ),
        },
    )

    implemented = application_control_implemented(bundle, {}, FactHistory.empty())
    assert implemented.status is Status.SATISFIED
    assert implemented.facts["applocker_enforced_collections"] == ["Exe", "Msi"]
    assert implemented.facts["applocker_audit_only_collections"] == ["Script"]

    file_types = application_control_covers_required_file_types(
        bundle, {}, FactHistory.empty()
    )
    assert file_types.status is Status.NOT_SATISFIED

    # The Exe collection allows %WINDIR%\* with only %WINDIR%\Tasks\* excepted,
    # so C:\Windows\Temp is still permitted. The Msi collection denies it, and
    # the deny is scoped to its own collection -- which is why the finding is
    # Exe alone.
    writable = application_control_covers_user_writable_paths(
        bundle, {}, FactHistory.empty()
    )
    assert writable.status is Status.NOT_SATISFIED
    hits = writable.facts["permitted_from_writable_locations"]
    assert {h["collection"] for h in hits} == {"Exe"}
    assert {h["location"] for h in hits} == {"C:\\Windows\\Temp"}


WRITABLE_SCRIPT = SCRIPT.parent / "Get-UserWritableExecutionPaths.ps1"


def _pwsh(command: str) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-only
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, f"pwsh failed: {proc.stderr}"
    return proc.stdout


@requires_pwsh
def test_the_writability_collector_runs_where_nothing_windows_exists() -> None:
    """The fail-safe path, executed rather than reasoned about.

    On a host with no `SystemRoot`, no `HKLM:` drive and no `Get-Acl`, the
    script must still emit well-formed JSON that says what it could not do.
    A collector that throws here produces no bundle at all, and a run that
    silently collected nothing is the failure mode this project exists to
    refuse.

    This also pinned a real defect: `@($list)` around a generic List fails
    inside an `[ordered]` literal with "Argument types do not match". Parsing
    the script was clean. Running it was not.
    """
    payload = json.loads(_pwsh(f"& '{WRITABLE_SCRIPT}'"))
    assert isinstance(payload, list) and len(payload) == 1
    result = payload[0]
    assert result["environment_error"]
    assert result["probes"] == []
    # Nothing could be looked at, so the walk is truncated in the sense the
    # evaluator cares about: absence of findings here proves nothing.
    assert result["windows_walk"]["truncated"] is True


@requires_pwsh
def test_nothing_collected_yields_no_verdict() -> None:
    """Collector output from a host that answered nothing must not pass."""
    state = json.loads(_pwsh(f"& '{SCRIPT}'"))[0]
    paths = json.loads(_pwsh(f"& '{WRITABLE_SCRIPT}'"))[0]

    # The role marks the state fact partial exactly when neither source could
    # be read; asserted here so the playbook's condition and the evaluator's
    # expectation are checked against each other rather than separately.
    assert not state["applocker"]["available"]
    assert not state["wdac"]["available"]

    bundle = FactBundle(
        subject={"asset_id": "WKS-NOTHING", "platform_family": "windows"},
        collected=COLLECTED,
        facts={
            "windows.appcontrol.state": Fact(
                key="windows.appcontrol.state",
                value=state,
                collected=COLLECTED,
                partial=True,
            ),
            "windows.appcontrol.writable_paths": Fact(
                key="windows.appcontrol.writable_paths",
                value=paths,
                collected=COLLECTED,
                partial=not paths["probes"],
            ),
        },
    )
    result = application_control_covers_user_writable_paths(
        bundle, {}, FactHistory.empty()
    )
    assert result.status is Status.UNASSESSED


@requires_pwsh
def test_admin_sid_classification_matches_the_evaluator() -> None:
    """The collector and the evaluator hold the same list. Prove they agree.

    Two copies of a security-relevant allow-list, in two languages, is a
    standing invitation to drift. The list is duplicated because the collector
    must filter before emitting and the evaluator must classify what it
    receives; the duplication is fine, silent disagreement is not.
    """
    from nobytes_cca.checks.windows.appcontrol_paths import _is_admin_sid

    sids = [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "S-1-5-32-544",
        "S-1-5-32-545",
        "S-1-5-32-549",
        "S-1-1-0",
        "S-1-5-11",
        "S-1-3-0",
        "S-1-5-21-1-2-3-500",
        "S-1-5-21-1-2-3-512",
        "S-1-5-21-1-2-3-1104",
    ]
    listed = ",".join(f"'{s}'" for s in sids)
    out = _pwsh(
        f"$null = . '{WRITABLE_SCRIPT}'; "
        f"@({listed}) | ForEach-Object {{ Test-AdminSid -Sid $_ }} "
        "| ConvertTo-Json -Compress"
    )
    from_powershell = json.loads(out)
    from_python = [_is_admin_sid(s) for s in sids]
    assert from_powershell == from_python


@requires_pwsh
def test_the_subdirectory_walk_honours_depth_and_budget(tmp_path) -> None:
    """`truncated` is what stops an incomplete look reading as a clean one.

    So the budget has to actually stop the walk, and the depth has to actually
    bound it. Both are platform-independent and therefore testable here.
    """
    for level1 in range(3):
        for level2 in range(3):
            (tmp_path / f"a{level1}" / f"b{level2}" / "c").mkdir(parents=True)

    def walk(depth: int, budget: int) -> dict:
        out = _pwsh(
            f"$null = . '{WRITABLE_SCRIPT}'; "
            f"$b = {budget}; "
            f"$found = Get-SubdirectoryWalk -Root '{tmp_path}' -Depth {depth} "
            "-Budget ([ref]$b); "
            "@{ count = $found.Count; remaining = $b } | ConvertTo-Json -Compress"
        )
        return json.loads(out)

    assert walk(1, 100)["count"] == 3  # a0..a2
    assert walk(2, 100)["count"] == 12  # + 9 b directories
    assert walk(3, 100)["count"] == 21  # + 9 c directories

    capped = walk(3, 5)
    assert capped["count"] == 5
    assert capped["remaining"] == 0


@requires_pwsh
def test_an_unreadable_or_missing_path_reports_unknown_not_unwritable() -> None:
    """The distinction the whole check rests on, executed.

    `non_admin_writable` must come back `null` — not `false` — when the DACL
    could not be read or the directory does not exist. The evaluator tests
    `is True`, so a `false` here would quietly convert "we could not look" into
    "there is nothing to find", and an estate nobody could inspect would render
    as a clean one.
    """
    from nobytes_cca.checks.windows.appcontrol_paths import _writable_locations

    out = _pwsh(
        f"$null = . '{WRITABLE_SCRIPT}'; "
        "@((Get-PathWritability -Path '/tmp' -Role 'os-temp'), "
        "(Get-PathWritability -Path '/no/such/place' -Role 'user-temp')) "
        "| ConvertTo-Json -Depth 4 -Compress"
    )
    unreadable, missing = json.loads(out)

    assert unreadable["access"] == "denied"
    assert unreadable["non_admin_writable"] is None
    assert unreadable["error"]

    assert missing["access"] == "missing"
    assert missing["exists"] is False
    assert missing["non_admin_writable"] is None

    # And the evaluator reads them the way the collector means them: one
    # counted as unreadable, neither counted as a writable location.
    found, unreadable_count = _writable_locations(
        {"probes": [unreadable, missing], "windows_writable": []}
    )
    assert found == []
    assert unreadable_count == 1


BROWSER_SCRIPT = (
    ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance"
    / "roles" / "collect_windows_browsers" / "files" / "Get-BrowserPolicy.ps1"
)


@requires_pwsh
def test_the_browser_collector_classifies_recommended_as_not_locked() -> None:
    """The highest-risk line in the browser chunk, executed rather than reviewed.

    Chromium publishes every policy at both `…\\Policies\\Microsoft\\Edge`
    (mandatory) and `…\\Policies\\Microsoft\\Edge\\Recommended` (a default the
    user may override). The Office collector derives `gpo_delivered` from
    `$Path -like '*\\Policies\\*'`, which matches BOTH — so copying that line
    would report every user-overridable setting as locked, the exact inverse of
    what ism-1585 asks.

    `Get-PolicyLevel` is a pure string function precisely so this can run here.
    """
    cases = {
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge": "mandatory",
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended": "recommended",
        "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome": "mandatory",
        "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\Recommended": "recommended",
        # Trailing separator, because a key path assembled by concatenation
        # sometimes carries one and a classifier that missed it would silently
        # downgrade a recommended key to mandatory.
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended\\": "recommended",
        "HKU:\\S-1-5-21-1-1-1-1174\\SOFTWARE\\Policies\\Mozilla\\Firefox": "mandatory",
        # The browser's own settings store: neither mandatory nor recommended.
        "HKCU:\\SOFTWARE\\Microsoft\\Edge": "preference",
    }
    listed = ",".join(f"'{p}'" for p in cases)
    out = _pwsh(
        f"$null = . '{BROWSER_SCRIPT}'; "
        f"@({listed}) | ForEach-Object {{ Get-PolicyLevel -Path $_ }} "
        "| ConvertTo-Json -Compress"
    )
    assert json.loads(out) == list(cases.values())

    # And prove the Office derivation would have got it wrong, so the reason
    # this function exists cannot quietly stop being true.
    glob_says_locked = [p for p in cases if "\\Policies\\" in p]
    assert "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended" in glob_says_locked


@requires_pwsh
def test_the_browser_collector_runs_where_there_is_no_registry() -> None:
    """Well-formed output with an explicit error, never a thrown collector.

    A collector that throws produces no bundle at all, and a run that silently
    collected nothing is the failure mode this project exists to refuse.
    """
    payload = json.loads(_pwsh(f"& '{BROWSER_SCRIPT}'"))
    result = payload[0] if isinstance(payload, list) else payload
    assert result["rows"] == [] or result["rows"] is None
    assert result["meta"]["collection_error"], (
        "a host with no registry must say so, not report an estate with no browser policy"
    )
