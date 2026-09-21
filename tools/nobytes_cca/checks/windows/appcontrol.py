"""Windows application control checks.

Essential Eight mitigation one, and the place where a widely-held belief turns
out to be wrong.

`ism-1657` requires application control to restrict "executables, libraries,
scripts, installers, compiled HTML, HTML applications and control panel
applets". AppLocker has exactly five rule collections, and Microsoft's own
documentation lists what each covers:

    Executable         .exe .com
    Windows Installer  .msi .mst .msp
    Scripts            .ps1 .bat .cmd .vbs .js
    DLLs               .dll .ocx
    Packaged apps      .appx

Compiled HTML (`.chm`), HTML applications (`.hta`) and control panel applets
(`.cpl`) appear in NO AppLocker rule collection. **A fully enforced AppLocker
policy therefore cannot satisfy ism-1657**, and an organisation that believes
AppLocker equals ML1 application control has a gap it does not know about.
Saying so is the entire value of this check; reporting `satisfied` because
five collections are enforced would hide exactly the thing worth finding.

App Control for Business (WDAC) enforces through code integrity policies
instead, and covers more. Where WDAC is enforcing, the rules are not readable
from the state this collector gathers, so the answer is `unassessed` rather
than a guess in either direction.
"""

from __future__ import annotations

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)

#: AppLocker rule collection -> the ISM file-type wording it satisfies.
#: Verified against Microsoft's "Understanding AppLocker rule collections",
#: not from recollection.
COLLECTION_COVERS = {
    "Exe": "executables",
    "Dll": "libraries",
    "Script": "scripts",
    "Msi": "installers",
}

#: What ism-1657 asks for, in the control's own words.
REQUIRED_TYPES = (
    "executables",
    "libraries",
    "scripts",
    "installers",
    "compiled HTML",
    "HTML applications",
    "control panel applets",
)

#: Listed by the control, enforceable by no AppLocker rule collection.
BEYOND_APPLOCKER = {
    "compiled HTML": ".chm",
    "HTML applications": ".hta",
    "control panel applets": ".cpl",
}

#: Win32_DeviceGuard enforcement status codes.
_WDAC_ENFORCED = 2
_WDAC_AUDIT = 1


def _applocker(value: dict) -> dict:
    return (value or {}).get("applocker") or {}


def _wdac(value: dict) -> dict:
    return (value or {}).get("wdac") or {}


def _enforced_collections(applocker: dict) -> dict:
    """Collection type -> enforcement mode, for collections that actually block.

    `AuditOnly` is deliberately NOT counted. A collection in audit mode writes
    an event and blocks nothing, which is the most likely way a host looks
    protected and is not.
    """
    out = {}
    for collection in applocker.get("collections") or []:
        mode = str(collection.get("enforcement_mode", ""))
        if mode == "Enabled" and int(collection.get("rule_count", 0)) > 0:
            out[str(collection.get("type", ""))] = mode
    return out


def _wdac_enforcing(wdac: dict) -> bool:
    return (
        int(wdac.get("code_integrity_policy_enforcement_status", 0) or 0) == _WDAC_ENFORCED
        or int(wdac.get("usermode_code_integrity_policy_enforcement_status", 0) or 0)
        == _WDAC_ENFORCED
    )


def _guard(bundle: FactBundle):
    fact = bundle.fact("windows.appcontrol.state")
    if fact is None:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.appcontrol.state` absent from the bundle",
        )
    if fact.partial:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "neither AppLocker policy nor Win32_DeviceGuard could be read; "
                "a host that could not be inspected is not a host without "
                "application control"
            ),
        )
    return fact, None


def application_control_implemented(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-0843 — application control is implemented on workstations.

    `proxy`, not `direct`: an enforcing policy is strong evidence that
    application control is implemented, but "implemented" is a judgement about
    an operational control and a policy can be enforcing while allowing
    everything. What is directly observable is enforcement mode, not efficacy.
    """
    del params, history

    fact, failure = _guard(bundle)
    if failure is not None:
        return failure

    applocker = _applocker(fact.value)
    wdac = _wdac(fact.value)
    enforced = _enforced_collections(applocker)
    audit_only = [
        c.get("type")
        for c in (applocker.get("collections") or [])
        if str(c.get("enforcement_mode", "")) == "AuditOnly"
    ]
    wdac_on = _wdac_enforcing(wdac)

    facts = {
        "applocker_available": bool(applocker.get("available")),
        "applocker_enforced_collections": sorted(enforced),
        "applocker_audit_only_collections": sorted(x for x in audit_only if x),
        "applocker_rule_count": applocker.get("rule_count", 0),
        "wdac_enforcing": wdac_on,
        "wdac_running": wdac.get("running", []),
    }

    if wdac_on:
        return CheckResult.satisfied(
            detail=(
                "App Control for Business (WDAC) is enforcing a code integrity "
                "policy. Application control is implemented."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    if enforced:
        note = ""
        if audit_only:
            note = (
                f" Note that {', '.join(sorted(x for x in audit_only if x))} "
                f"is in AuditOnly mode and blocks nothing."
            )
        return CheckResult.satisfied(
            detail=(
                f"AppLocker is enforcing {len(enforced)} rule collection(s): "
                f"{', '.join(sorted(enforced))}.{note}"
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    if audit_only:
        return CheckResult.not_satisfied(
            detail=(
                f"AppLocker policy exists but every configured collection is in "
                f"AuditOnly mode ({', '.join(sorted(x for x in audit_only if x))}). "
                f"Audit mode logs and blocks nothing, so nothing is being "
                f"restricted."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    return CheckResult.not_satisfied(
        detail=(
            "No enforcing application control was found: AppLocker has no "
            "enforced rule collection and WDAC is not enforcing a code "
            "integrity policy."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )


def application_control_covers_required_file_types(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1657 — the restricted set covers every file type the control lists.

    `partial` confidence, and the reason is structural rather than an
    engineering shortfall: three of the seven file types the control names are
    outside AppLocker's rule collections entirely, so an AppLocker-only estate
    cannot satisfy this control however well configured.
    """
    del params, history

    fact, failure = _guard(bundle)
    if failure is not None:
        return failure

    applocker = _applocker(fact.value)
    wdac = _wdac(fact.value)

    if _wdac_enforcing(wdac):
        return CheckResult.unassessed(
            reason=UnassessedReason.INSUFFICIENT_PRIVILEGE,
            detail=(
                "App Control for Business (WDAC) is enforcing. Which file types "
                "its code integrity policy covers is not readable from the "
                "state collected here, and guessing in either direction would "
                "be worse than saying so."
            ),
            facts={"wdac_enforcing": True, "wdac_running": wdac.get("running", [])},
        )

    enforced = _enforced_collections(applocker)
    covered = sorted({COLLECTION_COVERS[c] for c in enforced if c in COLLECTION_COVERS})
    missing_by_config = [
        t for t in REQUIRED_TYPES if t not in covered and t not in BEYOND_APPLOCKER
    ]

    facts = {
        "required_types": list(REQUIRED_TYPES),
        "covered_by_enforced_applocker": covered,
        "not_covered_configurable": missing_by_config,
        # The finding that matters: these cannot be fixed by configuring
        # AppLocker, because AppLocker has no rule collection for them.
        "not_coverable_by_applocker": BEYOND_APPLOCKER,
        "applocker_enforced_collections": sorted(enforced),
    }

    gap = (
        f"AppLocker has no rule collection for "
        f"{', '.join(f'{k} ({v})' for k, v in BEYOND_APPLOCKER.items())}, so these "
        f"cannot be restricted by AppLocker however it is configured. App Control "
        f"for Business (WDAC) covers more and is the route to this control."
    )

    if missing_by_config:
        return CheckResult.not_satisfied(
            detail=(
                f"AppLocker enforces {', '.join(covered) or 'nothing'}, leaving "
                f"{', '.join(missing_by_config)} unrestricted. Separately: {gap}"
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    return CheckResult.not_satisfied(
        detail=(
            f"AppLocker enforces every file type it is capable of restricting "
            f"({', '.join(covered)}), which is not all the control requires. {gap}"
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )
