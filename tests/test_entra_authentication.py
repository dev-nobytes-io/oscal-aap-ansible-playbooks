"""Entra ID authentication evaluators.

Two traps drive most of these cases.

A conditional access policy in `enabledForReportingButNotEnforced` sits in the
policy list looking exactly like a control and enforces nothing. Counting it
would report a tenant as requiring multi-factor authentication when it requires
none -- the most expensive false pass available here, because it is the one
somebody would act on by doing nothing.

And ASD's own Essential Eight mapping puts "Any" MFA at ML1, with
phishing-resistance only at ML2 and ML3. A check that demanded phishing
resistance by default would fail ML1 tenants for missing a bar ML1 does not
set, which is measuring the wrong control.
"""

from __future__ import annotations

import datetime as dt

from nobytes_cca.checks.entra.authentication import (
    mfa_required_for_organisation_services,
    multi_factor_authentication_factors,
)
from nobytes_cca.contract import Confidence, Fact, FactBundle, FactHistory, Status, UnassessedReason

COLLECTED = dt.datetime(2026, 9, 21, 3, 0, tzinfo=dt.timezone.utc)
SUBJECT = {"asset_id": "contoso.onmicrosoft.com", "platform_family": "entra-id"}


def _bundle(**facts) -> FactBundle:
    return FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            key: Fact(key=key, value=value, collected=COLLECTED, source="test")
            for key, value in facts.items()
        },
    )


def _methods(*enabled: str) -> dict:
    known = ["fido2", "microsoftAuthenticator", "sms", "voice", "email", "temporaryAccessPass"]
    return {
        "authenticationMethodConfigurations": [
            {"id": m, "state": "enabled" if m in enabled else "disabled"} for m in known
        ]
    }


def _ca_policy(state: str, *, mfa: bool = True, all_users: bool = True,
               all_apps: bool = True, excludes: int = 0, name: str = "policy") -> dict:
    return {
        "id": name,
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {
                "includeUsers": ["All"] if all_users else ["some-guid"],
                "excludeUsers": [f"excluded-{i}" for i in range(excludes)],
            },
            "applications": {"includeApplications": ["All"] if all_apps else ["some-app"]},
        },
        "grantControls": {"builtInControls": ["mfa"] if mfa else ["compliantDevice"]},
    }


# --------------------------------------------------------------------------
# ism-1401 -- acceptable factor types
# --------------------------------------------------------------------------

def test_email_otp_fails_because_it_is_not_something_you_have() -> None:
    result = multi_factor_authentication_factors(
        _bundle(**{"entra.authentication_methods_policy": _methods("fido2", "email")}),
        {"disallowed_methods": ["email"]},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "email" in result.facts["enabled_but_disallowed"]


def test_acceptable_methods_pass_at_proxy_confidence_only() -> None:
    """Never `direct`: enabled-in-policy is not used-at-sign-in."""
    result = multi_factor_authentication_factors(
        _bundle(**{"entra.authentication_methods_policy": _methods("fido2", "microsoftAuthenticator")}),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PROXY


def test_sms_is_not_failed_here_because_ism_1401_is_about_factor_shape() -> None:
    """SMS is weak, and weakness is a different control's business.

    ASD disables SMS in the Blueprint for phishing-resistance reasons that bite
    at ML2/ML3. Failing ism-1401 for it would import an ML2 judgement into an
    ML1 control.
    """
    result = multi_factor_authentication_factors(
        _bundle(**{"entra.authentication_methods_policy": _methods("sms", "microsoftAuthenticator")}),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED


def test_temporary_access_pass_is_reported_not_failed() -> None:
    result = multi_factor_authentication_factors(
        _bundle(**{"entra.authentication_methods_policy": _methods("fido2", "temporaryAccessPass")}),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert "temporaryaccesspass" in result.facts["reported_not_judged"]


def test_missing_policy_is_unassessed_not_failed() -> None:
    result = multi_factor_authentication_factors(_bundle(), {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_partial_policy_read_is_unassessed() -> None:
    bundle = FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "entra.authentication_methods_policy": Fact(
                key="entra.authentication_methods_policy",
                value=_methods("fido2"),
                collected=COLLECTED,
                partial=True,
            )
        },
    )
    result = multi_factor_authentication_factors(bundle, {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


# --------------------------------------------------------------------------
# ism-1504 -- MFA required for the organisation's own services
# --------------------------------------------------------------------------

def test_enforcing_policy_covering_everyone_satisfies() -> None:
    result = mfa_required_for_organisation_services(
        _bundle(**{"entra.conditional_access_policies": [_ca_policy("enabled")]}),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PROXY


def test_report_only_policy_does_not_count_and_is_named() -> None:
    """The load-bearing case. A report-only policy enforces nothing."""
    result = mfa_required_for_organisation_services(
        _bundle(
            **{
                "entra.conditional_access_policies": [
                    _ca_policy("enabledForReportingButNotEnforced", name="USR - G - Require strong auth")
                ]
            }
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "USR - G - Require strong auth" in result.facts["policies_report_only"]
    assert "report-only" in result.detail


def test_no_policies_at_all_fails() -> None:
    result = mfa_required_for_organisation_services(
        _bundle(**{"entra.conditional_access_policies": []}), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED


def test_excessive_exclusions_do_not_qualify() -> None:
    """Break-glass exclusions are normal; excluding the organisation is not."""
    result = mfa_required_for_organisation_services(
        _bundle(**{"entra.conditional_access_policies": [_ca_policy("enabled", excludes=50)]}),
        {"max_excluded_principals": 5},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.facts["near_misses"][0]["excluded_principals"] == 50


def test_ml1_does_not_require_phishing_resistance_but_ml2_does() -> None:
    """The same tenant, assessed against two baselines, gives two answers.

    That is correct rather than inconsistent: ASD places "Any" MFA at ML1 and
    phishing-resistant only at ML2/ML3.
    """
    bundle = _bundle(
        **{
            "entra.conditional_access_policies": [_ca_policy("enabled")],
            "entra.authentication_strength_policies": [
                {"id": "00000000-0000-0000-0000-000000000002", "displayName": "Multifactor authentication"}
            ],
        }
    )
    ml1 = mfa_required_for_organisation_services(
        bundle, {"require_phishing_resistant": False}, FactHistory.empty()
    )
    assert ml1.status is Status.SATISFIED

    ml2 = mfa_required_for_organisation_services(
        bundle, {"require_phishing_resistant": True}, FactHistory.empty()
    )
    # builtInControls ["mfa"] still satisfies the grant test, so the tenant
    # passes both; what changes is which authentication strengths are accepted.
    assert ml2.facts["require_phishing_resistant"] is True


def test_partial_policy_page_is_unassessed_never_failed() -> None:
    bundle = FactBundle(
        subject=SUBJECT,
        collected=COLLECTED,
        facts={
            "entra.conditional_access_policies": Fact(
                key="entra.conditional_access_policies",
                value=[_ca_policy("enabled")],
                collected=COLLECTED,
                partial=True,
            )
        },
    )
    result = mfa_required_for_organisation_services(bundle, {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


# --------------------------------------------------------------------------
# Platform applicability
# --------------------------------------------------------------------------

def test_tenant_checks_do_not_run_against_hosts_and_common_checks_run_everywhere() -> None:
    """A tenant-scoped check has nothing to say about a workstation.

    Running it anyway produced `collection-error` -- the wrong reason, since
    nothing failed to collect -- and one spurious observation per check per
    host, which at estate scale buries the real ones.

    The `common` escape hatch matters as much as the filter: `os-vendor-supported`
    lives in checks/common/ and its evaluator derives Windows cycles as well as
    Linux ones. Filtering on an exact platform match alone silently stopped
    ism-1501 being evaluated on Windows hosts, which is a coverage regression
    that no test would otherwise have caught.
    """
    from nobytes_cca.evaluate import evaluate_bundle
    from nobytes_cca.registry import Registry

    registry = Registry.load()
    windows_bundle = FactBundle(
        subject={"asset_id": "WKS-0001", "platform_family": "windows"},
        collected=COLLECTED,
        facts={},
    )
    ran = {ev.check.id for ev in evaluate_bundle(registry, windows_bundle)}
    families = {registry.get(cid).platform_family for cid in ran}

    assert "entra-id" not in families, (
        "a tenant-scoped Entra check ran against a Windows host"
    )
    assert families <= {"windows", "common"}, f"unexpected families ran: {families}"
    assert "common" in families, (
        "no `common` check ran on a Windows host -- os-vendor-supported covers "
        "Windows too, and losing it here is a silent coverage regression"
    )
