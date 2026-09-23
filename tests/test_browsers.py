"""Web browser hardening — ism-1485, ism-1486, ism-1585.

Three traps drive these cases, and each has a test that fails without its fix.

**ASD says the obvious ism-1485 evidence is not a mitigation.** Its Blueprint
states that Edge's native advertisement capability "does not provide an
effective mitigation", and BlockAds is Edge's DEFAULT — so a check resting on
it would report every unmanaged Edge in an estate as compliant.

**`…\\Policies\\Microsoft\\Edge\\Recommended` matches `*\\Policies\\*`.** The
Office collector derives `gpo_delivered` from exactly that glob. Copying it
would report a user-overridable default as locked, which is the inverse of what
ism-1585 asks.

**NPAPI left Firefox at 53, not 52.** Plug-ins kept working in ESR 52 — the
build a conservative government SOE is most likely to have pinned. An
off-by-one here passes the one version that still runs Java.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from nobytes_cca.checks.windows.browsers import (
    NPAPI_REMOVED_AT,
    advertisements_not_processed,
    java_not_processed,
    security_settings_locked,
)
from nobytes_cca.contract import Confidence, Fact, FactBundle, FactHistory, Status, UnassessedReason

COLLECTED = dt.datetime(2026, 9, 21, 11, 0, tzinfo=dt.timezone.utc)
SUBJECT = {"asset_id": "WKS-0100", "platform_family": "windows"}
UBLOCK_EDGE = "odfafepnkmbhccpbejgmiehpchacaeak"
UBLOCK_CHROME = "cjpalhdlnbpafiamejdnhcphjbkeiagm"


def _row(browser, *, level="mandatory", values=None, forced=(), scope="machine", sid=None):
    key = {
        ("edge", "mandatory"): "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge",
        ("edge", "recommended"): "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended",
        ("chrome", "mandatory"): "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome",
        ("chrome", "recommended"): "HKLM:\\SOFTWARE\\Policies\\Google\\Chrome\\Recommended",
        ("firefox", "mandatory"): "HKLM:\\SOFTWARE\\Policies\\Mozilla\\Firefox",
    }[(browser, level)]
    return {
        "browser": browser,
        "scope": scope,
        "sid": sid,
        "key": key,
        "policy_level": level,
        "gpo_delivered": level == "mandatory",
        "values": dict(values or {}),
        "forced_extensions": list(forced),
    }


def _bundle(rows, *, java=None, apps=None, unloaded=(), partial=False, java_partial=False):
    facts = {
        "windows.browsers.policy": Fact(
            key="windows.browsers.policy",
            value={
                "rows": list(rows),
                "meta": {
                    "profiles_total": 2,
                    "profiles_loaded": 2 - len(unloaded),
                    "profiles_unloaded": list(unloaded),
                    "collection_error": "",
                },
            },
            collected=COLLECTED,
            partial=partial,
        ),
        "windows.browsers.java_surface": Fact(
            key="windows.browsers.java_surface",
            value=java if java is not None else
            {"ie_integration_level": 0, "ie_site_list": None, "javasoft": {}, "error": ""},
            collected=COLLECTED,
            partial=java_partial,
        ),
    }
    if apps is not None:
        facts["windows.applications.installed"] = Fact(
            key="windows.applications.installed", value=list(apps), collected=COLLECTED
        )
    return FactBundle(subject=SUBJECT, collected=COLLECTED, facts=facts)


def _app(name, version):
    return {"name": name, "version": version}


EDGE_CURRENT = _app("Microsoft Edge", "128.0.2739.42")
CHROME_CURRENT = _app("Google Chrome", "128.0.6613.120")
FIREFOX_CURRENT = _app("Mozilla Firefox (x64 en-US)", "129.0.2")


# --------------------------------------------------------------------------
# Trap 1 — ASD says the native setting is not a mitigation
# --------------------------------------------------------------------------

def test_edge_default_ads_setting_is_not_a_pass() -> None:
    """The load-bearing case for ism-1485.

    BlockAds (2) is Edge's shipped default. A check resting on it would turn
    every unmanaged Edge in the country green against a control ASD states in
    writing this setting does not meet.
    """
    result = advertisements_not_processed(
        _bundle(
            [_row("edge", values={"AdsSettingForIntrusiveAdsSites": 2})],
            apps=[EDGE_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert result.facts["native_intrusive_ads_setting"] == {"edge": 2}
    assert "not provide an effective mitigation" in result.facts[
        "native_setting_is_not_a_mitigation"
    ]


def test_a_forced_ad_blocker_is_what_satisfies_it() -> None:
    result = advertisements_not_processed(
        _bundle(
            [_row("edge", forced=[f"{UBLOCK_EDGE};https://edge.microsoft.com/x"])],
            apps=[EDGE_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PARTIAL
    assert "uBlock Origin (Edge)" in result.facts["forced_ad_blockers"]["edge"]


def test_the_gateway_blind_spot_is_stated_in_the_finding() -> None:
    """An estate filtering at the proxy is compliant and will read as failing.

    ASD names proxy-level filtering as part of this control. The check cannot
    see it, so it must say so where a reader will meet it.
    """
    result = advertisements_not_processed(
        _bundle([_row("edge")], apps=[EDGE_CURRENT]), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert "proxy" in result.detail
    assert "gateway" in result.facts["not_observable"]


def test_one_protected_browser_does_not_cover_an_unprotected_one() -> None:
    result = advertisements_not_processed(
        _bundle(
            [_row("edge", forced=[UBLOCK_EDGE]), _row("chrome")],
            apps=[EDGE_CURRENT, CHROME_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "chrome" in result.detail


def test_firefox_force_installed_extension_is_read_from_json() -> None:
    settings = json.dumps({"uBlock0@raymondhill.net": {"installation_mode": "force_installed"}})
    result = advertisements_not_processed(
        _bundle(
            [_row("firefox", values={"ExtensionSettings": settings})],
            apps=[FIREFOX_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED


def test_a_merely_normal_extension_setting_is_not_a_forced_install() -> None:
    settings = json.dumps({"uBlock0@raymondhill.net": {"installation_mode": "normal_installed"}})
    result = advertisements_not_processed(
        _bundle(
            [_row("firefox", values={"ExtensionSettings": settings})],
            apps=[FIREFOX_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED


def test_no_application_inventory_yields_no_verdict() -> None:
    """A browser with no blocker is indistinguishable from one not installed."""
    result = advertisements_not_processed(_bundle([_row("edge")]), {}, FactHistory.empty())
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.PARTIAL_POPULATION


# --------------------------------------------------------------------------
# Trap 2 — \Recommended is not locked
# --------------------------------------------------------------------------

def test_recommended_policy_is_not_locked_policy() -> None:
    """The highest-risk copy-paste in this chunk, asserted.

    `HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\Recommended` matches the Office
    collector's `*\\Policies\\*` glob while being exactly what ism-1585
    prohibits: a default the user may override.
    """
    rows = [_row("edge", level="recommended", values={"SmartScreenEnabled": 1})]
    assert "\\Policies\\" in rows[0]["key"], "fixture no longer exercises the glob"
    result = security_settings_locked(
        _bundle(rows, apps=[EDGE_CURRENT]), {}, FactHistory.empty()
    )
    assert result.status is Status.NOT_SATISFIED
    assert "\\Recommended" in result.detail or "Recommended" in result.detail
    assert result.facts["browsers_with_mandatory_policy"] == []


def test_mandatory_policy_alongside_recommended_still_counts() -> None:
    result = security_settings_locked(
        _bundle(
            [_row("edge"), _row("edge", level="recommended")],
            apps=[EDGE_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert result.facts["browsers_with_mandatory_policy"] == ["edge"]


def test_every_installed_browser_must_be_locked_not_just_one() -> None:
    """A hardened Edge beside an unmanaged per-user Chrome does not pass."""
    result = security_settings_locked(
        _bundle([_row("edge")], apps=[EDGE_CURRENT, CHROME_CURRENT]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "chrome" in result.detail


def test_firefox_locking_is_read_from_the_preferences_blob() -> None:
    prefs = json.dumps({
        "security.default_personal_cert": {"Value": "Ask Every Time", "Status": "locked"},
        "browser.urlbar.suggest.searches": {"Value": False, "Status": "default"},
    })
    result = security_settings_locked(
        _bundle([_row("firefox", values={"Preferences": prefs})], apps=[FIREFOX_CURRENT]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert "1 of 2 preferences locked" in str(result.facts["firefox_preference_locking"])


def test_an_unparseable_preferences_blob_yields_no_verdict() -> None:
    """An unreadable policy is not an absent one."""
    result = security_settings_locked(
        _bundle([_row("firefox", values={"Preferences": "{not json"})], apps=[FIREFOX_CURRENT]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_unloaded_hives_weaken_a_pass_but_not_a_failure() -> None:
    passing = security_settings_locked(
        _bundle([_row("edge")], apps=[EDGE_CURRENT], unloaded=["S-1-5-21-1-1-1-1174"]),
        {},
        FactHistory.empty(),
    )
    assert passing.status is Status.UNASSESSED

    failing = security_settings_locked(
        _bundle([], apps=[EDGE_CURRENT], unloaded=["S-1-5-21-1-1-1-1174"]),
        {},
        FactHistory.empty(),
    )
    assert failing.status is Status.NOT_SATISFIED


# --------------------------------------------------------------------------
# Trap 3 — NPAPI left Firefox at 53, and IE mode is the live hole
# --------------------------------------------------------------------------

def test_firefox_52_is_not_past_the_npapi_threshold() -> None:
    """ESR 52 still ran plug-ins. An off-by-one passes the one version that does."""
    assert NPAPI_REMOVED_AT["firefox"] == 53
    result = java_not_processed(
        _bundle([_row("firefox")], apps=[_app("Mozilla Firefox ESR (x64 en-US)", "52.9.0")]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.UNASSESSED
    assert "52.9.0" in str(result.facts["browsers_below_npapi_threshold"])


def test_modern_browsers_satisfy_by_construction() -> None:
    result = java_not_processed(
        _bundle([_row("edge")], apps=[EDGE_CURRENT, CHROME_CURRENT, FIREFOX_CURRENT]),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED
    assert result.confidence is Confidence.PROXY
    assert "by construction" in result.detail


@pytest.mark.parametrize("level", [1, 2])
def test_edge_ie_mode_with_a_java_runtime_is_a_failure(level: int) -> None:
    """The live hole, and the reason this check exists.

    IE never used NPAPI — its Java plug-in was an ActiveX control, and IE mode
    runs Trident, which supports ActiveX. win-ie11-disabled deliberately does
    not judge this, so nothing else in the repository catches it.
    """
    result = java_not_processed(
        _bundle(
            [_row("edge")],
            java={
                "ie_integration_level": level,
                "ie_site_list": "https://intranet.example.gov.au/sites.xml",
                "javasoft": {"HKLM:\\SOFTWARE\\JavaSoft\\Java Runtime Environment": ["1.8.0_411"]},
                "error": "",
            },
            apps=[EDGE_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.NOT_SATISFIED
    assert "ActiveX" in result.detail
    assert "ism-1654" in result.detail


def test_ie_mode_without_a_java_runtime_is_not_failed_here() -> None:
    """IE mode alone is a different control's business."""
    result = java_not_processed(
        _bundle(
            [_row("edge")],
            java={"ie_integration_level": 1, "ie_site_list": None, "javasoft": {}, "error": ""},
            apps=[EDGE_CURRENT],
        ),
        {},
        FactHistory.empty(),
    )
    assert result.status is Status.SATISFIED


def test_an_unreadable_java_surface_yields_no_verdict() -> None:
    result = java_not_processed(
        _bundle([_row("edge")], apps=[EDGE_CURRENT], java_partial=True), {}, FactHistory.empty()
    )
    assert result.status is Status.UNASSESSED
    assert result.reason is UnassessedReason.COLLECTION_ERROR


def test_a_failed_registry_walk_is_not_an_estate_without_policy() -> None:
    for evaluator in (advertisements_not_processed, java_not_processed, security_settings_locked):
        result = evaluator(_bundle([], apps=[EDGE_CURRENT], partial=True), {}, FactHistory.empty())
        assert result.status is Status.UNASSESSED, evaluator.__name__
        assert result.reason is UnassessedReason.COLLECTION_ERROR, evaluator.__name__


def test_the_evaluator_reads_the_field_the_collector_actually_emits() -> None:
    """Pins a bug this chunk shipped in draft and caught by looking.

    `browsers.py` originally read `display_name`. `Get-InstalledApplications.ps1`
    emits `name = [string]$item.DisplayName`. Every real host would have yielded
    zero browsers and a permanent `unassessed`, while these tests passed —
    because the fixtures were written to match the guess rather than the
    collector.

    A test whose fixture and whose subject were both written from the same
    wrong assumption proves nothing, so this one reads the PowerShell.
    """
    from conftest import ROOT

    script = (
        ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance"
        / "roles" / "collect_windows_applications" / "files"
        / "Get-InstalledApplications.ps1"
    ).read_text(encoding="utf-8")
    assert "name      = [string]$item.DisplayName" in script, (
        "the application collector's field names changed; browsers.py and "
        "app_support.py both read `name` and would silently find nothing"
    )
    assert "display_name" not in script

    # And the evaluator must agree with it.
    evaluator = (
        ROOT / "tools" / "nobytes_cca" / "checks" / "windows" / "browsers.py"
    ).read_text(encoding="utf-8")
    assert 'app.get("name"' in evaluator
    assert 'app.get("display_name"' not in evaluator
