"""ism-1870 -- application control applied to user profiles and temp folders.

    "Application control is applied to user profiles and temporary folders
     used by operating systems, web browsers and email clients."

This is the control that AppLocker's *default rules* fail, and it fails them
quietly. Those rules allow Everyone to execute anything under `%WINDIR%` and
`%PROGRAMFILES%`. `%WINDIR%\\Temp` is inside `%WINDIR%`, is the operating
system's temporary folder, and is writable by standard users on a default
install. So a host can enforce all five AppLocker rule collections, report
thousands of rules, satisfy an auditor's checklist -- and still permit a
standard user to drop an executable into a temporary folder and run it.

Microsoft states the problem in the control's own terms, on the page this
check cites:

    "Because path rules specify locations within the file system, you should
     ensure that there are no subdirectories that are writable by
     nonadministrators. For example, if you create a path rule using the allow
     action for C:\\, any file under that location can run, including file
     within users' profiles."

Two observations are therefore required and neither substitutes for the other:
the rule paths the policy allows, and which of the control's locations are
actually writable by a non-administrator **on this host**. An estate that has
hardened `C:\\Windows\\Temp` is in a different position from one that has not,
and a hardcoded list of "directories everyone knows are writable" would report
both identically.

Three deliberate asymmetries, each one a place where being wrong is cheap in
one direction and expensive in the other:

1. **A truncated filesystem walk can produce a failure but never a pass.** A
   writable directory that was found is writable whether or not the walk
   completed. "Nothing was found" from a walk that ran out of budget is not
   evidence that there is nothing.

2. **Only ENFORCED rule collections are judged here.** A collection left
   `NotConfigured` restricts nothing anywhere, which is `ism-0843` and
   `ism-1657`'s finding, not this one. Reporting it again under every control
   it touches turns one problem into five and buries the specific thing this
   check exists to surface.

3. **An allow rule scoped to administrators is recorded, not failed.** The
   control is about locations; whether privileged accounts are themselves
   subject to application control is `ism-1657` and the ML2 privileged-access
   controls. A deployment that disagrees can set the
   `fail_on_administrator_allow` parameter, and at ML2/ML3 it probably should.
"""

from __future__ import annotations

import fnmatch

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)
from .appcontrol import _applocker, _wdac, _wdac_enforcing

#: AppLocker path variables, from Microsoft's path-rule documentation. These
#: are NOT environment variables -- the AppLocker engine interprets this exact
#: set and nothing else, so `%TEMP%` in a rule is literal text that matches no
#: real directory.
#:
#: `%REMOVABLE%` (CD/DVD) and `%HOT%` (USB) expand to no fixed-disk path, so a
#: rule using them can never cover a user profile or a temporary folder. They
#: map to an empty expansion rather than to a literal that would silently
#: never match: the difference matters when reading the evidence.
_REMOVABLE_VARIABLES = ("%REMOVABLE%", "%HOT%")

#: Administrative principals, mirroring the collector. An allow-list, inverted
#: on purpose: an unrecognised SID counts as a standard user, so a rule we
#: cannot classify is flagged rather than waved through.
_ADMIN_SIDS = frozenset(
    {
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "S-1-5-32-544",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
    }
)
_ADMIN_RIDS = frozenset({"500", "512", "518", "519", "520"})

#: Probe role -> the control wording it is evidence for. Used in the finding
#: text so a reader sees WHICH half of the control failed, not just that it did.
ROLE_WORDING = {
    "os-temp": "a temporary folder used by the operating system",
    "windows-subdirectory": "a writable directory inside the Windows directory",
    "profile-root": "the user profile root",
    "user-profile": "a user profile",
    "user-temp": "a user's temporary folder",
    "user-downloads": "a user's downloads folder",
    "browser-temp": "a temporary folder used by a web browser",
    "email-temp": "a temporary folder used by an email client",
}


def _is_admin_sid(sid: str) -> bool:
    sid = (sid or "").strip().upper()
    if sid in _ADMIN_SIDS:
        return True
    if sid.startswith("S-1-5-21-"):
        return sid.rsplit("-", 1)[-1] in _ADMIN_RIDS
    return False


def _normalise(path: str) -> str:
    """Upper-case, forward-slash-free, no trailing separator.

    Case folding is correct rather than merely convenient: NTFS paths are
    case-insensitive, so `%windir%\\temp` and `%WINDIR%\\TEMP` are the same
    directory and a case-sensitive comparison would miss a real allow rule.
    """
    text = (path or "").strip().replace("/", "\\").upper()
    while text.endswith("\\") and len(text) > 3:
        text = text[:-1]
    return text


def _expand(pattern: str, windows_root: str) -> list[str]:
    """Resolve AppLocker path variables against this host's real directories.

    `%PROGRAMFILES%` and `%SYSTEM32%` each expand to TWO directories on a
    64-bit host, so this returns a list. Collapsing them to one would silently
    drop half the paths a rule actually covers.
    """
    root = _normalise(windows_root) or "C:\\WINDOWS"
    drive = root[:2] if len(root) > 1 and root[1] == ":" else "C:"
    text = _normalise(pattern)

    if any(variable in text for variable in _REMOVABLE_VARIABLES):
        return []

    substitutions = {
        "%WINDIR%": [root],
        "%SYSTEM32%": [root + "\\SYSTEM32", root + "\\SYSWOW64"],
        "%OSDRIVE%": [drive],
        "%PROGRAMFILES%": [drive + "\\PROGRAM FILES", drive + "\\PROGRAM FILES (X86)"],
    }

    candidates = [text]
    for variable, values in substitutions.items():
        if not any(variable in candidate for candidate in candidates):
            continue
        candidates = [c.replace(variable, value) for c in candidates for value in values]
    return candidates


def _has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def _contains(pattern: str, location: str, windows_root: str) -> bool:
    """True when `location` lies wholly inside what `pattern` matches.

    Used for deny rules and for exceptions, where only a full carve-out
    changes the answer: an exception covering part of a temporary folder
    leaves the rest of it allowed, and reporting that as fixed would be worse
    than not checking.
    """
    loc = _normalise(location)
    for expanded in _expand(pattern, windows_root):
        if not expanded:
            continue
        if fnmatch.fnmatchcase(loc, expanded) or fnmatch.fnmatchcase(loc, expanded + "\\*"):
            return True
        if not _has_wildcard(expanded) and (loc == expanded or loc.startswith(expanded + "\\")):
            return True
        # A rule written `X\*` governs everything that could execute in X, so
        # for the purposes of this control it covers the directory X itself.
        # Without this, a deny rule over `%WINDIR%\Temp\*` would fail to
        # cancel an allow over `%WINDIR%\*` -- the exact hardening an
        # administrator would apply, read as having no effect.
        trimmed = expanded[:-2] if expanded.endswith("\\*") else ""
        if not trimmed:
            continue
        if fnmatch.fnmatchcase(loc, trimmed):
            return True
        if not _has_wildcard(trimmed) and (loc == trimmed or loc.startswith(trimmed + "\\")):
            return True
    return False


def _covers(pattern: str, location: str, windows_root: str) -> bool:
    """True when `pattern` permits execution from anywhere within `location`.

    Broader than `_contains` on purpose, and in the direction that produces
    findings: a rule NARROWER than the location still permits execution from
    part of it. `%OSDRIVE%\\USERS\\*\\APPDATA\\LOCAL\\TEMP\\*` does not contain
    `C:\\USERS` -- it sits inside it -- and an allow rule for a user's
    temporary folder is exactly what this control prohibits.
    """
    if _contains(pattern, location, windows_root):
        return True
    loc = _normalise(location)
    for expanded in _expand(pattern, windows_root):
        stem = expanded.split("*")[0].split("?")[0].rstrip("\\")
        if stem and (stem == loc or stem.startswith(loc + "\\")):
            return True
    return False


def _writable_locations(paths: dict) -> tuple[list[dict], int]:
    """The control's locations that this host reports as non-admin-writable.

    Returns them alongside the number of probes that could not be read --
    which is what stops an unreadable estate from rendering as a clean one.
    """
    found = []
    unreadable = 0
    for probe in list(paths.get("probes") or []) + list(paths.get("windows_writable") or []):
        if probe.get("access") == "denied":
            unreadable += 1
            continue
        if probe.get("non_admin_writable") is True:
            found.append(probe)
    return found, unreadable


def _permitting_rules(collections: list, locations: list, windows_root: str, fail_on_admin: bool):
    """Every (collection, rule, location) the policy permits execution from.

    Also returns the rules it could not read. An allow rule whose path
    conditions did not parse is NOT assumed harmless: it is returned so the
    caller can decline to conclude. A guard that passes on input it cannot
    read is not a guard.
    """
    permitted = []
    admin_scoped = []
    unreadable_rules = []

    for collection in collections:
        ctype = str(collection.get("type", ""))
        for rule in collection.get("path_rules") or []:
            if str(rule.get("action", "")).lower() != "allow":
                continue
            patterns = [p for p in (rule.get("paths") or []) if str(p).strip()]
            if not patterns:
                # No path conditions AND no conditions of any other kind means
                # the rule was not parsed, not that it allows nothing.
                if not int(rule.get("non_path_conditions", 0) or 0):
                    unreadable_rules.append({"collection": ctype, "name": rule.get("name", "")})
                continue

            sid = str(rule.get("sid", ""))
            is_admin = _is_admin_sid(sid)
            exceptions = [p for p in (rule.get("exceptions") or []) if str(p).strip()]
            # Deny beats allow within a collection, and only within it: an Exe
            # deny says nothing about what the Script collection permits.
            denies = [
                p
                for other in collection.get("path_rules") or []
                if str(other.get("action", "")).lower() == "deny"
                for p in (other.get("paths") or [])
                if str(p).strip()
            ]

            for location in locations:
                path = str(location.get("path", ""))
                if not any(_covers(p, path, windows_root) for p in patterns):
                    continue
                if any(_contains(e, path, windows_root) for e in exceptions):
                    continue
                if any(_contains(d, path, windows_root) for d in denies):
                    continue
                hit = {
                    "collection": ctype,
                    "rule": str(rule.get("name", "")),
                    "sid": sid,
                    "paths": patterns,
                    "location": path,
                    "location_role": str(location.get("role", "")),
                }
                if is_admin and not fail_on_admin:
                    admin_scoped.append(hit)
                else:
                    permitted.append(hit)

    return permitted, admin_scoped, unreadable_rules


def _guard(bundle: FactBundle):
    for key in ("windows.appcontrol.state", "windows.appcontrol.writable_paths"):
        fact = bundle.fact(key)
        if fact is None:
            return None, None, CheckResult.unassessed(
                reason=UnassessedReason.COLLECTION_ERROR,
                detail=f"fact `{key}` absent from the bundle",
            )
        if fact.partial:
            return None, None, CheckResult.unassessed(
                reason=UnassessedReason.PARTIAL_POPULATION,
                detail=(
                    f"`{key}` was collected but is incomplete; a host that "
                    f"could not be fully inspected is not a host without "
                    f"application control"
                ),
            )
    return (
        bundle.fact("windows.appcontrol.state"),
        bundle.fact("windows.appcontrol.writable_paths"),
        None,
    )


def application_control_covers_user_writable_paths(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1870 — is application control actually applied where users can write?"""
    del history

    state_fact, paths_fact, failure = _guard(bundle)
    if failure is not None:
        return failure

    fail_on_admin = bool((params or {}).get("fail_on_administrator_allow", False))
    applocker = _applocker(state_fact.value)
    wdac = _wdac(state_fact.value)
    paths = paths_fact.value or {}
    windows_root = str(paths.get("windows_root") or "C:\\Windows")

    if _wdac_enforcing(wdac):
        return CheckResult.unassessed(
            reason=UnassessedReason.INSUFFICIENT_PRIVILEGE,
            detail=(
                "App Control for Business (WDAC) is enforcing a code integrity "
                "policy. WDAC decides by signature, hash and file attributes "
                "rather than by directory, so an AppLocker path rule does not "
                "settle what may execute here -- and the code integrity policy "
                "itself is not readable from the state collected. Saying so "
                "beats guessing in either direction."
            ),
            facts={"wdac_enforcing": True, "wdac_running": wdac.get("running", [])},
        )

    collections = list(applocker.get("collections") or [])
    enforced = [
        c
        for c in collections
        if str(c.get("enforcement_mode", "")) == "Enabled"
        and int(c.get("rule_count", 0) or 0) > 0
    ]

    locations, unreadable_probes = _writable_locations(paths)
    walk = paths.get("windows_walk") or {}
    truncated = bool(walk.get("truncated"))

    base_facts = {
        "windows_root": windows_root,
        "enforced_collections": sorted(str(c.get("type", "")) for c in enforced),
        "unenforced_collections": sorted(
            str(c.get("type", ""))
            for c in collections
            if str(c.get("enforcement_mode", "")) != "Enabled"
        ),
        "non_admin_writable_locations": [
            {"path": loc.get("path"), "role": loc.get("role")} for loc in locations
        ],
        "profiles_total": paths.get("profiles_total", 0),
        "profiles_probed": paths.get("profiles_probed", 0),
        "unreadable_probes": unreadable_probes,
        "windows_walk_truncated": truncated,
    }

    if not enforced:
        return CheckResult.not_satisfied(
            detail=(
                "No AppLocker rule collection is enforcing, so application "
                "control is applied to user profiles and temporary folders in "
                "the same sense it is applied everywhere else: not at all. "
                "Which collections exist and why they are not enforcing is "
                "ism-0843's finding; this one only records that the locations "
                "this control names are unrestricted as a result."
            ),
            facts=base_facts,
            confidence=Confidence.PARTIAL,
        )

    if not locations:
        # Nothing writable was OBSERVED. That is only a pass if the looking was
        # complete, and here it was not.
        if truncated or unreadable_probes:
            return CheckResult.unassessed(
                reason=UnassessedReason.PARTIAL_POPULATION,
                detail=(
                    f"No non-administrator-writable location was found, but the "
                    f"search was incomplete: {unreadable_probes} path(s) could "
                    f"not be read"
                    f"{' and the Windows directory walk hit its budget' if truncated else ''}. "
                    f"An incomplete search finding nothing is not the same as "
                    f"there being nothing."
                ),
                facts=base_facts,
            )
        return CheckResult.satisfied(
            detail=(
                "None of the locations this control names is writable by a "
                "non-administrator on this host, so no application control rule "
                "can be bypassed by writing to one. Note this is a statement "
                "about filesystem permissions, not about the rule set."
            ),
            facts=base_facts,
            confidence=Confidence.PARTIAL,
        )

    permitted, admin_scoped, unreadable_rules = _permitting_rules(
        enforced, locations, windows_root, fail_on_admin
    )

    facts = dict(base_facts)
    facts["permitted_from_writable_locations"] = permitted
    facts["administrator_scoped_allows"] = admin_scoped
    facts["unparsed_allow_rules"] = unreadable_rules

    if unreadable_rules and not permitted:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                f"{len(unreadable_rules)} allow rule(s) carried no readable path "
                f"condition. A rule whose scope could not be determined is not a "
                f"rule that allows nothing, so no verdict is reported: "
                f"{', '.join(sorted(r['collection'] + '/' + r['name'] for r in unreadable_rules))}."
            ),
            facts=facts,
        )

    if permitted:
        by_role: dict = {}
        for hit in permitted:
            by_role.setdefault(hit["location_role"], []).append(hit["location"])
        described = "; ".join(
            f"{ROLE_WORDING.get(role, role)} ({len(sorted(set(paths_hit)))} path(s), "
            f"e.g. {sorted(set(paths_hit))[0]})"
            for role, paths_hit in sorted(by_role.items())
        )
        collections_hit = sorted({hit["collection"] for hit in permitted})
        note = ""
        if admin_scoped:
            distinct = {(hit["collection"], hit["rule"]) for hit in admin_scoped}
            note = (
                f" Separately, {len(distinct)} allow rule(s) scoped to "
                f"administrative principals also cover these locations; those are "
                f"recorded but not counted as a failure of this control."
            )
        return CheckResult.not_satisfied(
            detail=(
                f"Application control permits execution from "
                f"{len(permitted)} location/rule combination(s) that a "
                f"non-administrator can write to, in the "
                f"{', '.join(collections_hit)} collection(s): {described}. "
                f"Writing a file to one of these and running it is not blocked."
                f"{note}"
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    if truncated or unreadable_probes:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                f"Every writable location that was found is covered by the "
                f"enforced rules, but the search was incomplete: "
                f"{unreadable_probes} path(s) unreadable"
                f"{', Windows directory walk truncated' if truncated else ''}. "
                f"The location that was not inspected could be the permitted one."
            ),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"{len(locations)} non-administrator-writable location(s) were found "
            f"and the enforced AppLocker collections "
            f"({', '.join(base_facts['enforced_collections'])}) permit execution "
            f"from none of them. What this does not prove: that every temporary "
            f"folder used by every installed browser and email client was among "
            f"the locations probed."
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )
