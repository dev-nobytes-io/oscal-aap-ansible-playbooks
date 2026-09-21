"""Entra ID authentication policy checks.

Everything here judges TENANT CONFIGURATION. That is the honest ceiling: a
conditional access policy states what the tenant will require, not what any
individual actually did at sign-in. Sign-in logs would move some of these
towards `direct`, and that is PR 10's evidence-provider work, not a claim to
make here.
"""

from __future__ import annotations

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)

#: Entra records a method's state under different keys across API versions;
#: treat any of these as "on".
_ENABLED_VALUES = frozenset({"enabled", "true", "on"})

#: A conditional access policy only ENFORCES in this state. `enabledForReporting
#: ButNotEnforced` is the trap: it appears in the policy list, reads as a
#: configured control, and blocks nobody. Counting it would report a tenant as
#: requiring MFA when it requires nothing.
_ENFORCING_STATE = "enabled"


def _method_enabled(configuration: dict) -> bool:
    state = str(configuration.get("state", "")).strip().lower()
    return state in _ENABLED_VALUES


def multi_factor_authentication_factors(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1401 — multi-factor authentication uses acceptable factor types.

    The control asks for either "something people have and something people
    know", or "something people have that is unlocked by something people know
    or are". That is a statement about the SHAPE of the factors, not their
    strength -- phishing resistance is an ML2/ML3 concern and belongs to a
    different bar. A check that failed a tenant here for allowing SMS would be
    measuring the wrong control, so the disallowed set is a parameter and
    defaults to the one method that genuinely cannot form either shape.

    Email OTP is that method: a one-time code delivered to another mailbox is
    not "something people have" in any meaningful sense -- it is a second
    account, usually reachable with the same password the first factor already
    used.

    Temporary Access Pass is reported but not failed. It is a time-limited
    bootstrap credential for registering a real factor, ASD's Blueprint enables
    it deliberately, and treating it as a standing factor would generate
    findings nobody can act on.
    """
    del history

    fact = bundle.fact("entra.authentication_methods_policy")
    if fact is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `entra.authentication_methods_policy` absent from the bundle",
        )
    if fact.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "the authentication methods policy was only partly read; the part "
                "that could not be read may be the part that fails"
            ),
        )

    disallowed = {str(m).lower() for m in params.get("disallowed_methods", ["email"])}
    reported_only = {str(m).lower() for m in params.get("reported_not_judged", ["temporaryaccesspass"])}

    configurations = (fact.value or {}).get("authenticationMethodConfigurations") or []
    enabled = [
        str(c.get("id", "")).lower() for c in configurations if _method_enabled(c)
    ]
    offending = sorted(m for m in enabled if m in disallowed)
    noted = sorted(m for m in enabled if m in reported_only)

    facts = {
        "enabled_methods": sorted(enabled),
        "disallowed_methods": sorted(disallowed),
        "enabled_but_disallowed": offending,
        "reported_not_judged": noted,
    }

    if not configurations:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail=(
                "the authentication methods policy carries no method "
                "configurations; nothing was observed to judge"
            ),
        )

    if offending:
        return CheckResult.not_satisfied(
            detail=(
                f"Authentication methods enabled that cannot form an acceptable "
                f"factor pair: {', '.join(offending)}. A one-time code sent to "
                f"another mailbox is not 'something people have'."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    note = f" Reported but not judged: {', '.join(noted)}." if noted else ""
    return CheckResult.satisfied(
        detail=(
            f"Every enabled authentication method can form one of the factor "
            f"pairs the control accepts ({', '.join(sorted(enabled)) or 'none enabled'})."
            f"{note} This observes tenant POLICY, not what any user registered "
            f"or used at sign-in."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )


def _grants_mfa(policy: dict, strength_ids: set) -> bool:
    """True when a policy's grant controls actually require a second factor."""
    grant = (policy.get("grantControls") or {}) or {}
    built_in = {str(c).lower() for c in (grant.get("builtInControls") or [])}
    if "mfa" in built_in:
        return True
    strength = grant.get("authenticationStrength") or {}
    return str(strength.get("id", "")) in strength_ids


def _targets_everyone(policy: dict, max_excluded: int) -> tuple:
    """Whether a policy covers all users and all resources, and why not."""
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    apps = conditions.get("applications") or {}

    includes_all_users = "All" in (users.get("includeUsers") or [])
    includes_all_apps = "All" in (apps.get("includeApplications") or [])

    excluded = (
        list(users.get("excludeUsers") or [])
        + list(users.get("excludeGroups") or [])
        + list(users.get("excludeRoles") or [])
    )

    reasons = []
    if not includes_all_users:
        reasons.append("does not include all users")
    if not includes_all_apps:
        reasons.append("does not include all resources")
    if len(excluded) > max_excluded:
        reasons.append(f"excludes {len(excluded)} principals (limit {max_excluded})")
    return (not reasons, reasons, len(excluded))


def mfa_required_for_organisation_services(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1504 — MFA authenticates users to the organisation's own online services.

    Observed from conditional access: an ENFORCING policy covering all users and
    all resources whose grant requires a second factor.

    Three things this deliberately gets right:

    `enabledForReportingButNotEnforced` does not count. A report-only policy sits
    in the policy list looking exactly like a control and enforces nothing;
    counting it would report a tenant as requiring MFA when it requires nothing,
    which is the most expensive possible false pass.

    Phishing resistance is NOT required by default. ASD's own Essential Eight
    mapping puts "Any" MFA at ML1 and phishing-resistant only at ML2/ML3, so the
    strictness is a parameter keyed to the baseline being assessed. Failing an
    ML1 assessment for not meeting an ML2 bar would be measuring the wrong
    control.

    Exclusions are counted, not ignored. Every real tenant excludes break-glass
    accounts, so a hard zero would fail everyone; an unbounded count would let a
    policy exclude the whole organisation and still pass.
    """
    del history

    ca_fact = bundle.fact("entra.conditional_access_policies")
    if ca_fact is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `entra.conditional_access_policies` absent from the bundle",
        )
    if ca_fact.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "conditional access policies were only partly read; an unread page "
                "may hold the policy that changes this answer"
            ),
        )

    require_phishing_resistant = bool(params.get("require_phishing_resistant", False))
    max_excluded = int(params.get("max_excluded_principals", 5))

    strengths_fact = bundle.fact("entra.authentication_strength_policies")
    strengths = (strengths_fact.value or []) if strengths_fact else []
    if require_phishing_resistant:
        acceptable = {
            str(s.get("id"))
            for s in strengths
            if "phishingresistant" in str(s.get("policyType", "")).lower()
            or "phishing-resistant" in str(s.get("displayName", "")).lower()
            or "phishing resistant" in str(s.get("displayName", "")).lower()
        }
    else:
        acceptable = {str(s.get("id")) for s in strengths}

    policies = ca_fact.value or []
    enforcing = [
        p for p in policies if str(p.get("state", "")).strip() == _ENFORCING_STATE
    ]
    report_only = [
        p
        for p in policies
        if "reporting" in str(p.get("state", "")).lower()
    ]

    qualifying = []
    near_misses = []
    for policy in enforcing:
        covers, reasons, excluded_count = _targets_everyone(policy, max_excluded)
        grants = _grants_mfa(policy, acceptable)
        if covers and grants:
            qualifying.append(policy.get("displayName", policy.get("id")))
        elif grants or covers:
            near_misses.append(
                {
                    "policy": policy.get("displayName", policy.get("id")),
                    "requires_mfa": grants,
                    "shortfall": reasons or ([] if grants else ["grant does not require MFA"]),
                    "excluded_principals": excluded_count,
                }
            )

    facts = {
        "policies_total": len(policies),
        "policies_enforcing": len(enforcing),
        # Surfaced because a report-only policy is the single most likely reason
        # a tenant believes it is protected when it is not.
        "policies_report_only": [p.get("displayName", p.get("id")) for p in report_only],
        "qualifying_policies": qualifying,
        "near_misses": near_misses,
        "require_phishing_resistant": require_phishing_resistant,
        "max_excluded_principals": max_excluded,
    }

    if not policies:
        return CheckResult.not_satisfied(
            detail=(
                "The tenant has no conditional access policies at all, so nothing "
                "requires multi-factor authentication for the organisation's own "
                "online services."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    if qualifying:
        bar = "phishing-resistant MFA" if require_phishing_resistant else "multi-factor authentication"
        return CheckResult.satisfied(
            detail=(
                f"{len(qualifying)} enforcing conditional access policy/policies "
                f"require {bar} across all users and all resources: "
                f"{', '.join(str(q) for q in qualifying)}. This observes tenant "
                f"POLICY; it is not evidence that any particular sign-in used a "
                f"second factor."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    hint = ""
    if report_only:
        hint = (
            f" {len(report_only)} policy/policies are report-only "
            f"(`enabledForReportingButNotEnforced`) and enforce nothing."
        )
    return CheckResult.not_satisfied(
        detail=(
            f"No enforcing conditional access policy requires multi-factor "
            f"authentication across all users and all resources."
            f"{hint}"
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )
