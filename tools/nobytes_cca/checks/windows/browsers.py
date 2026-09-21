r"""Web browser hardening — ism-1485, ism-1486 and ism-1585.

Three controls, and each one's obvious implementation is wrong in a specific,
documented way.

**ism-1485 — advertisements.** The obvious evidence is
`AdsSettingForIntrusiveAdsSites`. ASD's own Blueprint says in writing that it
is not a mitigation: *"Microsoft Edge's native web advertisement capability is
limited and does not provide an effective mitigation against the risk of
malicious web advertisement."* And `2` (block) is Edge's DEFAULT, so reading it
would turn every unmanaged Edge in an estate green. Chrome's unset default is
the opposite (`1`, allow everywhere), and Chromium documents that `2` does
nothing when Safe Browsing is off. So the verdict rests on a force-installed
ad-blocking extension, with the native setting recorded as a supporting fact
and never as the basis for a pass.

**ism-1486 — Java.** NPAPI left Chrome in 45 and Firefox in **53** — not 52,
where it survived in ESR. But Internet Explorer never used NPAPI: its Java
plug-in was an **ActiveX control**, and Edge IE mode runs Trident and supports
ActiveX. `win-ie11-disabled` deliberately records `edge_ie_mode` without
judging it, because that control is about IE11 as a browser rather than the
MSHTML engine. So the one live path by which a modern browser processes Java
is Edge + IE mode + a Java runtime, and nothing else in this repository
catches it.

**ism-1585 — settings cannot be changed.** The analogue of
`macro_settings_locked`, except that copying its `gpo_delivered` derivation
would be actively wrong: Chromium publishes every policy at both
`…\Policies\Microsoft\Edge` (mandatory) and `…\Policies\Microsoft\Edge\Recommended`
(a default the user may override), and both match `*\Policies\*`. The collector
classifies into `policy_level` instead; this module trusts that, never the path.

What none of them can prove: a registry value is an administrator's INTENT, not
the running browser's BEHAVIOUR. The only thing that would show the latter is
`edge://policy` reporting "Status: OK", which is per-user, per-profile and not
readable from a read-only remote query. That is why none of these three can be
`direct`.
"""

from __future__ import annotations

import json

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)

#: Display-name prefixes -> browser key, matching app_support.py's convention.
BROWSER_PATTERNS = {
    "edge": "Microsoft Edge",
    "chrome": "Google Chrome",
    "firefox": "Mozilla Firefox",
}

#: The version at which NPAPI -- and with it the Java plug-in -- was removed.
#: Firefox is 53, NOT 52: plugins kept working in ESR 52, which is exactly the
#: build a conservative government SOE is most likely to have pinned.
NPAPI_REMOVED_AT = {"chrome": 45, "firefox": 53}

#: Edge InternetExplorerIntegrationLevel. 0 None, 1 IEMode, 2 NeedIE.
_IE_MODE = 1
_IE_NEEDIE = 2

#: Extension ids widely deployed as ad blockers. Matching is on the id because
#: a forcelist entry is `<id>;<update url>` and the id is the stable part.
#: Deliberately NOT exhaustive -- ASD names uBlock Origin and Adblock Plus as
#: examples while explicitly declining to recommend either, so an estate using
#: something else is reported as "an extension is forced, we do not recognise
#: it" rather than as a failure.
KNOWN_AD_BLOCKERS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin (Chrome)",
    "odfafepnkmbhccpbejgmiehpchacaeak": "uBlock Origin (Edge)",
    "cfhdojbkjhnklbpkdaibdccddilifddb": "Adblock Plus (Chrome)",
    "gmgoamodcdcjnbaobigkjelfplakmdhh": "Adblock Plus (Edge)",
    "uBlock0@raymondhill.net": "uBlock Origin (Firefox)",
    "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}": "Adblock Plus (Firefox)",
}


def _policy_fact(bundle: FactBundle):
    fact = bundle.fact("windows.browsers.policy")
    if fact is None:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.browsers.policy` absent from the bundle",
        )
    if fact.partial:
        return None, CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                "browser policy enumeration failed; a registry that could not be "
                "walked is not an estate without browser policy"
            ),
        )
    return fact, None


def _rows(fact) -> list:
    return list((fact.value or {}).get("rows") or [])


def _meta(fact) -> dict:
    return dict((fact.value or {}).get("meta") or {})


def _installed_browsers(bundle: FactBundle) -> dict:
    """browser key -> list of (display name, version) from the app inventory.

    Returns an empty mapping when the inventory fact is absent, and callers
    treat that as "we do not know what is installed" rather than "nothing is".
    """
    fact = bundle.fact("windows.applications.installed")
    if fact is None:
        return {}
    found: dict = {}
    for app in fact.value or []:
        # `name`, not `display_name`. Get-InstalledApplications.ps1 emits
        # `name = [string]$item.DisplayName`, and app_support.py already reads
        # it that way. Guessing `display_name` here would have found zero
        # browsers on every real host while the fixtures -- written to match
        # the guess -- passed.
        name = str(app.get("name", ""))
        for key, prefix in BROWSER_PATTERNS.items():
            if name.startswith(prefix):
                found.setdefault(key, []).append((name, str(app.get("version", ""))))
    return found


def _coverage_gap(fact, bundle: FactBundle) -> list:
    gaps = []
    unloaded = list(_meta(fact).get("profiles_unloaded") or [])
    if unloaded:
        gaps.append(f"{len(unloaded)} user profile hive(s) not loaded")
    if bundle.fact("windows.applications.installed") is None:
        gaps.append("no application inventory, so which browsers are installed is unknown")
    return gaps


def _major(version: str) -> int | None:
    head = str(version).split(".")[0].strip()
    return int(head) if head.isdigit() else None


# --------------------------------------------------------------------------
# ism-1485 -- web advertisements
# --------------------------------------------------------------------------

def _forced_blockers(rows: list) -> dict:
    """browser -> the recognised ad blockers forced onto it."""
    out: dict = {}
    for row in rows:
        browser = str(row.get("browser", ""))
        for entry in row.get("forced_extensions") or []:
            ident = str(entry).split(";")[0].strip()
            if ident in KNOWN_AD_BLOCKERS:
                out.setdefault(browser, []).append(KNOWN_AD_BLOCKERS[ident])
        # Firefox forces extensions through ExtensionSettings, a JSON blob.
        settings = (row.get("values") or {}).get("ExtensionSettings")
        if settings:
            try:
                parsed = json.loads(settings)
            except (TypeError, ValueError):
                continue
            for ident, config in (parsed or {}).items():
                if not isinstance(config, dict):
                    continue
                if config.get("installation_mode") != "force_installed":
                    continue
                if ident in KNOWN_AD_BLOCKERS:
                    out.setdefault(browser, []).append(KNOWN_AD_BLOCKERS[ident])
    return out


def advertisements_not_processed(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1485 — web browsers do not process web advertisements."""
    del params, history

    fact, failure = _policy_fact(bundle)
    if failure is not None:
        return failure

    rows = _rows(fact)
    installed = _installed_browsers(bundle)
    blockers = _forced_blockers(rows)

    # Recorded, never decisive. ASD states this is not an effective mitigation
    # and `2` is Edge's default, so a pass built on it would go green on every
    # unmanaged Edge in the estate.
    native = {}
    for row in rows:
        value = (row.get("values") or {}).get("AdsSettingForIntrusiveAdsSites")
        if value is not None:
            native[str(row.get("browser"))] = value

    facts = {
        "installed_browsers": {k: [n for n, _ in v] for k, v in installed.items()},
        "forced_ad_blockers": blockers,
        "native_intrusive_ads_setting": native,
        "native_setting_is_not_a_mitigation": (
            "ASD's Blueprint: Microsoft Edge's native web advertisement capability "
            "is limited and does not provide an effective mitigation"
        ),
        "not_observable": (
            "gateway and proxy level advertisement filtering, which ASD also names "
            "as part of this control, is not visible from a host"
        ),
    }

    gaps = _coverage_gap(fact, bundle)
    if not installed:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "No application inventory, so which browsers are installed is "
                "unknown. A browser with no forced ad blocker cannot be "
                "distinguished from a browser that is not installed."
            ),
            facts=facts,
        )

    unprotected = sorted(set(installed) - set(blockers))
    if unprotected:
        return CheckResult.not_satisfied(
            detail=(
                f"No recognised ad-blocking extension is force-installed for "
                f"{', '.join(unprotected)}. Note this check cannot see gateway or "
                f"proxy level filtering, which ASD names as part of this control, "
                f"so an estate blocking advertisements upstream will appear here as "
                f"a failure it has in fact mitigated."
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    if gaps:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail="Every installed browser forces an ad blocker, but " + "; ".join(gaps),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"Every installed browser ({', '.join(sorted(installed))}) force-installs "
            f"a recognised ad-blocking extension. What this does not prove: that the "
            f"extension is enabled and running in each profile, only that policy "
            f"requires it."
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )


# --------------------------------------------------------------------------
# ism-1486 -- Java from the internet
# --------------------------------------------------------------------------

def java_not_processed(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1486 — web browsers do not process Java from the internet."""
    del params, history

    fact, failure = _policy_fact(bundle)
    if failure is not None:
        return failure

    java_fact = bundle.fact("windows.browsers.java_surface")
    if java_fact is None or java_fact.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                "the Edge IE-mode and Java runtime surface could not be read, and "
                "it is the only path by which a modern browser still processes Java"
            ),
        )

    installed = _installed_browsers(bundle)
    java = java_fact.value or {}
    ie_level = java.get("ie_integration_level")
    javasoft = dict(java.get("javasoft") or {})

    below_threshold = []
    for browser, entries in installed.items():
        floor = NPAPI_REMOVED_AT.get(browser)
        if floor is None:
            continue
        for name, version in entries:
            major = _major(version)
            if major is None or major < floor:
                below_threshold.append(f"{name} {version or '(version unknown)'}")

    facts = {
        "installed_browsers": {k: [n for n, _ in v] for k, v in installed.items()},
        "npapi_removed_at": NPAPI_REMOVED_AT,
        "browsers_below_npapi_threshold": below_threshold,
        "edge_ie_integration_level": ie_level,
        "edge_ie_site_list": java.get("ie_site_list"),
        "java_runtime_registry": javasoft,
    }

    if not installed:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "No application inventory. This control is answered from which "
                "browsers are installed and at what version, so without it there "
                "is nothing to judge."
            ),
            facts=facts,
        )

    # The live path. Edge IE mode runs Trident, which supports ActiveX, and the
    # Internet Explorer Java plug-in was an ActiveX control. A Java runtime
    # present alongside it is a real, current exposure.
    if ie_level in (_IE_MODE, _IE_NEEDIE) and javasoft:
        return CheckResult.not_satisfied(
            detail=(
                f"Edge Internet Explorer mode is enabled "
                f"(InternetExplorerIntegrationLevel={ie_level}) and a Java runtime is "
                f"registered. IE mode runs the Trident engine, which supports ActiveX "
                f"controls, and the Internet Explorer Java plug-in is an ActiveX "
                f"control rather than NPAPI — so a site on the IE-mode site list can "
                f"still process Java. ism-1654 does not cover this: it speaks to "
                f"Internet Explorer 11 as a browser, not to the MSHTML engine."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    if below_threshold:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                f"Browser(s) at or below the version where NPAPI was removed: "
                f"{', '.join(below_threshold)}. Whether a Java plug-in is actually "
                f"registered for them is not readable from the collected state."
            ),
            facts=facts,
        )

    gaps = _coverage_gap(fact, bundle)
    if gaps:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail="; ".join(gaps),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"Every installed browser is past the version at which NPAPI — and with "
            f"it the Java plug-in — was removed (Chrome {NPAPI_REMOVED_AT['chrome']}, "
            f"Firefox {NPAPI_REMOVED_AT['firefox']}), and Edge Internet Explorer mode "
            f"is not enabled. The control is met by construction rather than by "
            f"configuration, and this is the evidence of that construction."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )


# --------------------------------------------------------------------------
# ism-1585 -- security settings cannot be changed
# --------------------------------------------------------------------------

def _firefox_locked(row: dict) -> tuple:
    """(locked, total) preference entries in a Firefox Preferences policy.

    Firefox's only locking mechanism is the Status field inside this blob.
    Parsing lives here rather than in PowerShell because that is the split
    this project keeps: raw text out of the collector, judgement in Python.
    """
    blob = (row.get("values") or {}).get("Preferences")
    if not blob:
        return 0, 0
    try:
        parsed = json.loads(blob)
    except (TypeError, ValueError):
        return 0, -1  # unparseable: signalled to the caller, never counted as locked
    locked = 0
    for config in (parsed or {}).values():
        if isinstance(config, dict) and config.get("Status") == "locked":
            locked += 1
    return locked, len(parsed or {})


def security_settings_locked(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1585 — browser security settings cannot be changed by users."""
    del params, history

    fact, failure = _policy_fact(bundle)
    if failure is not None:
        return failure

    rows = _rows(fact)
    installed = _installed_browsers(bundle)

    # `policy_level`, never the key path. `…\Policies\Microsoft\Edge\Recommended`
    # matches the Office collector's `*\Policies\*` glob while being exactly the
    # thing this control prohibits: a default the user may override.
    mandatory = {str(r.get("browser")) for r in rows if r.get("policy_level") == "mandatory"}
    recommended_only: dict = {}
    for row in rows:
        browser = str(row.get("browser"))
        if row.get("policy_level") == "recommended" and browser not in mandatory:
            recommended_only.setdefault(browser, []).append(row.get("key"))

    firefox_unparseable = []
    firefox_locked = {}
    for row in rows:
        if str(row.get("browser")) != "firefox":
            continue
        locked, total = _firefox_locked(row)
        if total == -1:
            firefox_unparseable.append(row.get("key"))
        elif total:
            firefox_locked[str(row.get("key"))] = f"{locked} of {total} preferences locked"

    facts = {
        "installed_browsers": {k: [n for n, _ in v] for k, v in installed.items()},
        "browsers_with_mandatory_policy": sorted(mandatory),
        "browsers_with_recommended_policy_only": recommended_only,
        "firefox_preference_locking": firefox_locked,
        "not_observable": (
            "a registry value is an administrator's intent, not the running "
            "browser's behaviour; only edge://policy or chrome://policy reporting "
            "Status OK would show the latter, and neither is readable remotely"
        ),
    }

    if firefox_unparseable:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                f"Firefox Preferences policy could not be parsed at "
                f"{', '.join(str(k) for k in firefox_unparseable)}. An unreadable "
                f"policy is not an absent one."
            ),
            facts=facts,
        )

    if not installed:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "No application inventory, so 'every installed browser' cannot be "
                "evaluated. The control is a statement about browsers, plural."
            ),
            facts=facts,
        )

    # Every installed browser, not "at least one". A hardened Edge alongside a
    # developer's per-user Chrome with no policy does not meet this control.
    unlocked = sorted(set(installed) - mandatory)
    if unlocked:
        note = ""
        if any(b in recommended_only for b in unlocked):
            note = (
                " Note that policy exists for "
                f"{', '.join(b for b in unlocked if b in recommended_only)} under the "
                f"\\Recommended key, which sets a default the user may override rather "
                f"than locking anything."
            )
        return CheckResult.not_satisfied(
            detail=(
                f"No mandatory policy found for {', '.join(unlocked)}. Settings a user "
                f"can change are settings a user can change back.{note}"
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    gaps = _coverage_gap(fact, bundle)
    if gaps:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail="Every installed browser has mandatory policy, but " + "; ".join(gaps),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"Every installed browser ({', '.join(sorted(installed))}) is governed by "
            f"mandatory policy rather than a user-overridable default. What this does "
            f"not prove: that the running browser honours each policy name, that a "
            f"local administrator could not change it, or that a Firefox estate "
            f"managed through policies.json rather than the registry is covered."
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )
