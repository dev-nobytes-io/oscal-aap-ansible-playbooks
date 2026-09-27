"""Windows operating-system state checks."""

from __future__ import annotations

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)


def ie11_disabled_or_removed(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1654 — Internet Explorer 11 is disabled or removed.

    One of the few ML1 controls that is genuinely a binary, directly observable
    state, hence `direct` confidence. Either branch of the control's "disabled
    OR removed" satisfies it.

    Edge's IE mode is reported in the facts but not judged: it is a deliberately
    supported configuration, and the control speaks to Internet Explorer 11 as a
    browser rather than to the MSHTML engine. Treating IE mode as a failure would
    generate findings nobody can act on.
    """
    del params, history

    features = bundle.fact("windows.os.optional_features")
    if features is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.os.optional_features` absent from the bundle",
        )
    # Fail closed BEFORE the absence-of-evidence branches below, which read an
    # empty feature list as proof that Internet Explorer is not installed and
    # return `satisfied` at DIRECT confidence -- the strongest claim this
    # project makes anywhere.
    #
    # `Get-WindowsOptionalFeature -Online` requires elevation and is absent on
    # Server SKUs without the DISM cmdlets; before ADR 0017 the collector
    # swallowed both cases as an empty list, so a host that could not be asked
    # was reported as a host with no Internet Explorer. A real Windows install
    # always enumerates many optional features, so an empty list is a failed
    # read, never an estate fact.
    if features.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                "the Windows optional feature list could not be enumerated, so "
                "whether Internet Explorer 11 is installed is unknown: "
                + str(features.meta.get("collection_error", "no reason recorded"))
            ),
        )
    if not features.value:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                "the Windows optional feature list came back empty. Every "
                "supported Windows build enumerates optional features, so this "
                "is a failed read rather than a system without them, and it is "
                "not evidence that Internet Explorer 11 is absent."
            ),
        )

    ie_features = [
        f
        for f in (features.value or [])
        if "internet-explorer" in str(f.get("name", "")).lower()
        or "internetexplorer" in str(f.get("name", "")).lower()
    ]
    installed = [f for f in ie_features if str(f.get("state", "")).lower() == "enabled"]

    policy = bundle.fact("windows.browser.ie_policy")
    disabled_by_policy = bool(policy and policy.value and policy.value.get("NotifyDisableIEOptions"))

    facts = {
        "ie_features": ie_features,
        "installed_and_enabled": installed,
        "disabled_by_policy": disabled_by_policy,
        "edge_ie_mode": (policy.value or {}).get("InternetExplorerIntegrationLevel")
        if policy
        else None,
    }

    if not ie_features:
        return CheckResult.satisfied(
            detail="No Internet Explorer 11 optional feature is present on this system.",
            facts=facts,
            confidence=Confidence.DIRECT,
        )

    if not installed:
        return CheckResult.satisfied(
            detail="The Internet Explorer 11 optional feature is present but not enabled.",
            facts=facts,
            confidence=Confidence.DIRECT,
        )

    if disabled_by_policy:
        return CheckResult.satisfied(
            detail=(
                "Internet Explorer 11 is installed but disabled by policy "
                "(NotifyDisableIEOptions)."
            ),
            facts=facts,
            confidence=Confidence.DIRECT,
        )

    return CheckResult.not_satisfied(
        detail=(
            "Internet Explorer 11 is installed, enabled, and not disabled by policy."
        ),
        facts=facts,
        confidence=Confidence.DIRECT,
    )
