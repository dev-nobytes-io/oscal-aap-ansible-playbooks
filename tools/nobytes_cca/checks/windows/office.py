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


def _office_guard(bundle: FactBundle):
    """Shared preamble: is Office here, and did policy collection work?

    Returns (policy_fact, None) to continue, or (None, CheckResult) to stop.
    """
    install = bundle.fact("windows.office.install")
    if install is None:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.office.install` absent from the bundle",
        )
    if not install.value:
        return None, CheckResult.not_applicable(
            detail="No Microsoft Office or Microsoft 365 Apps installation detected.",
            facts={"office_installed": False},
        )
    policy = bundle.fact("windows.office.macro_policy")
    if policy is None or policy.partial:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="Office is installed but macro policy enumeration returned nothing.",
        )
    return policy, None


def _coverage_gap(policy, apps_without_evidence: list) -> list:
    """Reasons the picture may be incomplete, in reporting order."""
    gaps = []
    unloaded = list(policy.meta.get("profiles_unloaded", []))
    if unloaded:
        gaps.append(f"{len(unloaded)} user profile hive(s) not loaded")
    if apps_without_evidence:
        gaps.append(f"{len(apps_without_evidence)} application(s) with no policy evidence")
    return gaps


def macro_settings_locked(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1489 — Office macro security settings cannot be changed by human users.

    Approximated by "the value lives under Policies and is GPO-delivered", which
    makes it read-only to a standard user. That is a proxy, not the control: a
    local administrator can still change it, and nothing in the value says
    whether the user holds administrator rights.
    """
    del history
    policy, stop = _office_guard(bundle)
    if stop is not None:
        return stop

    apps = set(params.get("in_scope_apps", []))
    rows = [r for r in policy.value if r.get("app") in apps]

    unlocked = [
        {"app": r.get("app"), "scope": r.get("scope"), "sid": r.get("sid")}
        for r in rows
        if not r.get("gpo_delivered")
    ]
    apps_seen = {r.get("app") for r in rows}
    no_evidence = sorted(apps - apps_seen)

    facts = {
        "apps_with_policy": sorted(apps_seen),
        "not_gpo_delivered": unlocked,
        "apps_without_evidence": no_evidence,
        "profiles_unloaded": list(policy.meta.get("profiles_unloaded", [])),
    }

    if unlocked:
        return CheckResult.not_satisfied(
            detail=(
                f"{len(unlocked)} macro security value(s) are not GPO-delivered and "
                f"are therefore writable by the user they apply to."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    gaps = _coverage_gap(policy, no_evidence)
    if gaps:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail="No unlocked settings observed, but " + "; ".join(gaps) + ".",
            facts=facts,
        )

    return CheckResult.satisfied(
        detail="All in-scope Office macro security settings are GPO-delivered policy values.",
        facts=facts,
        confidence=Confidence.PROXY,
    )


def macros_disabled_without_business_need(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1671 — macros disabled for users without a demonstrated business requirement.

    Only the first half of this control is observable on a host. Whether a user
    with macros enabled has a demonstrated business requirement is an
    organisational fact held in an approval register, not in the registry.

    So confidence is `partial` and the detail says so explicitly: a failure here
    may be a legitimately approved exemption, and a pass says nothing about
    whether the exemption process exists.
    """
    del history
    policy, stop = _office_guard(bundle)
    if stop is not None:
        return stop

    apps = set(params.get("in_scope_apps", []))
    required = params.get("required_vbawarnings", 4)
    rows = [r for r in policy.value if r.get("app") in apps]

    enabled = [
        {
            "app": r.get("app"),
            "scope": r.get("scope"),
            "sid": r.get("sid"),
            "vbawarnings": r.get("vbawarnings"),
        }
        for r in rows
        if r.get("vbawarnings") is not None and r.get("vbawarnings") != required
    ]
    with_value = {r.get("app") for r in rows if r.get("vbawarnings") is not None}
    no_evidence = sorted(apps - with_value)

    facts = {
        "required_vbawarnings": required,
        "not_disabled": enabled,
        "apps_without_evidence": no_evidence,
        "note": (
            "Whether any user with macros enabled has a demonstrated business "
            "requirement is not observable on the host and is not assessed."
        ),
    }

    if enabled:
        return CheckResult.not_satisfied(
            detail=(
                f"{len(enabled)} application/profile combination(s) do not disable "
                f"macros (VBAWarnings != {required}). Each may or may not be an "
                f"approved exemption; that is not observable here."
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    gaps = _coverage_gap(policy, no_evidence)
    if gaps:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail="No enabled macros observed, but " + "; ".join(gaps) + ".",
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"All in-scope Office applications disable macros (VBAWarnings={required}). "
            f"The business-requirement exemption process is not assessed."
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )


def macro_antivirus_scanning(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1672 — Office macro antivirus scanning is enabled.

    Observes that Office is configured to hand macro content to AMSI. It does
    not observe that an AMSI provider is registered, healthy, or backed by an
    antivirus with current signatures -- so a pass means "configured to offer",
    not "effectively scanned".
    """
    del history
    policy, stop = _office_guard(bundle)
    if stop is not None:
        return stop

    required = params.get("required_scan_scope", 2)
    scopes = [r for r in policy.value if r.get("macroruntimescanscope") is not None]

    if not scopes:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "No MacroRuntimeScanScope value was observed in any scope. Absence "
                "of the value is not evidence that scanning is disabled -- the "
                "default varies by Office build."
            ),
            facts={"observed": []},
        )

    wrong = [
        {"scope": r.get("scope"), "sid": r.get("sid"), "value": r.get("macroruntimescanscope")}
        for r in scopes
        if r.get("macroruntimescanscope") != required
    ]
    facts = {
        "required_scan_scope": required,
        "observed": [r.get("macroruntimescanscope") for r in scopes],
        "misconfigured": wrong,
    }

    if wrong:
        return CheckResult.not_satisfied(
            detail=f"{len(wrong)} scope(s) do not set MacroRuntimeScanScope={required}.",
            facts=facts,
            confidence=Confidence.PROXY,
        )

    return CheckResult.satisfied(
        detail=(
            f"MacroRuntimeScanScope={required} in every observed scope. AMSI provider "
            f"health and antivirus currency are not assessed."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )
