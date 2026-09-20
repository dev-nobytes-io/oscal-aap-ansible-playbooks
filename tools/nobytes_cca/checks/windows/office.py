"""Microsoft Office policy checks.

Evaluators are PURE: no network, no subprocess, no clock. Everything they need
arrives in the fact bundle. That is enforced by tests, and it is what makes a
verdict reproducible from stored evidence years later.

Note how much logic lives here rather than in PowerShell. The collector emits
raw registry values and nothing else, so roughly all of the decision logic is
testable on Linux with no Windows host and no container. That is the strongest
practical argument for the collect/evaluate split, over and above the audit one.
"""

from __future__ import annotations

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)

#: Built-in service accounts. Their policy hives are not human-user policy and
#: counting them would produce noise, not findings.
SERVICE_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})


def macro_internet_blocked(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1488 — Office macros in files originating from the internet are blocked.

    Returns `unassessed` rather than `satisfied` when any in-scope application
    or user hive could not be inspected. A machine with one unloaded profile and
    no observed failures is NOT evidence that the control is met -- the profile
    that could not be read might be the failing one. Most tools get this wrong.
    """
    del history  # point-in-time control; history_window_days is 0

    install = bundle.fact("windows.office.install")
    if install is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.office.install` absent from the bundle",
        )
    if not install.value:
        return CheckResult.not_applicable(
            detail="No Microsoft Office or Microsoft 365 Apps installation detected.",
            facts={"office_installed": False},
        )

    policy = bundle.fact("windows.office.macro_policy")
    if policy is None or policy.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="Office is installed but macro policy enumeration returned nothing.",
        )

    apps = set(params.get("in_scope_apps", []))
    require_gpo = bool(params.get("require_gpo_delivery", True))
    rows = [r for r in policy.value if r.get("app") in apps]

    blocked_machine_wide = {
        r["app"]
        for r in rows
        if r.get("scope") == "machine"
        and r.get("blockcontentexecutionfrominternet") == 1
        and (r.get("gpo_delivered") or not require_gpo)
    }

    user_rows = [
        r for r in rows if r.get("scope") == "user" and r.get("sid") not in SERVICE_SIDS
    ]

    failing = []
    no_evidence = []
    for app in sorted(apps - blocked_machine_wide):
        app_rows = [r for r in user_rows if r.get("app") == app]
        if not app_rows:
            no_evidence.append(app)
            continue
        for row in app_rows:
            value = row.get("blockcontentexecutionfrominternet")
            if value != 1:
                failing.append(
                    {
                        "app": app,
                        "sid": row.get("sid"),
                        "observed": value,
                        "reason": "not-blocked",
                    }
                )
            elif require_gpo and not row.get("gpo_delivered"):
                failing.append(
                    {
                        "app": app,
                        "sid": row.get("sid"),
                        "observed": 1,
                        "reason": "user-writable-not-gpo",
                    }
                )

    unloaded = list(policy.meta.get("profiles_unloaded", []))
    facts = {
        "blocked_machine_wide": sorted(blocked_machine_wide),
        "failing": failing,
        "apps_without_evidence": no_evidence,
        "profiles_total": policy.meta.get("profiles_total"),
        "profiles_loaded": policy.meta.get("profiles_loaded"),
        "profiles_unloaded": unloaded,
    }

    # A failure is a failure even if the picture is incomplete: we have positive
    # evidence the control is not met somewhere.
    if failing:
        return CheckResult.not_satisfied(
            detail=(
                f"{len(failing)} application/profile combination(s) do not block "
                f"macros in files originating from the internet."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    # No failures found -- but only meaningful if we could see everything.
    if no_evidence or unloaded:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                f"No failures observed, but {len(unloaded)} user profile hive(s) were "
                f"not loaded and {len(no_evidence)} in-scope application(s) had no "
                f"policy evidence in any assessable scope. Not enough to conclude the "
                f"control is met."
            ),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            "All in-scope Office applications block macros in files originating "
            "from the internet, via GPO-delivered policy."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )
