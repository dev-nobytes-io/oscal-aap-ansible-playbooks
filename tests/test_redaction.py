"""Redaction is applied, not merely declared.

Until PR 16 this repository shipped a complete redaction policy that ran
nowhere. `fact_bundle_redaction_keys` named four identifier keys and an action
for each, `fact_bundle_redaction_salt` had a guard refusing to run until it was
changed, every bundle stamped `redaction_policy: "1.0"`, and the task that
wrote it was called "Redact identifiers and write the fact bundle".

No hashing existed anywhere in the collection. `finalise.yml` wrote
`facts: "{{ fact_bundle_facts }}"` verbatim. A bundle from the Windows Office
collector carried raw `S-1-5-21-...` SIDs while asserting they had been hashed.

That is the sixth time this project has found the same shape in itself: a
protection that cannot perform the thing it claims. So the load-bearing test
here is not that the filter works -- it is `test_finalise_actually_applies_the
_policy`, which asserts the WIRING. A correct filter nobody calls is exactly
what was already shipping.
"""

from __future__ import annotations

import sys

import pytest
import yaml

from conftest import ROOT

FILTER_DIR = (
    ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance"
    / "plugins" / "filter"
)
ROLE = (
    ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance"
    / "roles" / "fact_bundle"
)

sys.path.insert(0, str(FILTER_DIR))

from redact import AnsibleFilterError, redact_facts  # noqa: E402

SALT = "a-real-per-deployment-salt"
SHIPPED_POLICY = {"sid": "hash", "username": "hash", "upn": "hash", "email": "hash"}


def _defaults() -> dict:
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The wiring. This is the test that would have caught the original defect.
# --------------------------------------------------------------------------

def test_finalise_actually_applies_the_policy() -> None:
    """The bundle's `facts` must pass through the filter, with the real policy.

    A filter that works and is never called is indistinguishable, in the
    written bundle, from no filter at all -- which is precisely what shipped.
    """
    text = (ROLE / "tasks" / "finalise.yml").read_text(encoding="utf-8")
    tasks = yaml.safe_load(text)
    write = next(
        t for t in tasks if "copy" in str(t.get("ansible.builtin.copy", "")) or
        "ansible.builtin.copy" in t
    )
    facts_expr = str(write["vars"]["_cca_bundle"]["facts"])

    assert "redact_facts" in facts_expr, (
        "finalise.yml writes facts without passing them through redact_facts. "
        "The bundle stamps redaction_policy, so this would assert a protection "
        "the file does not perform."
    )
    for variable in (
        "fact_bundle_redaction_keys",
        "fact_bundle_redaction_default",
        "fact_bundle_redaction_salt",
    ):
        assert variable in facts_expr, (
            f"redact_facts is called without {variable}; the declared policy "
            f"would be partly ignored"
        )


def test_the_salt_guard_fires_for_the_shipped_policy() -> None:
    """The guard was gated on the DEFAULT action being `hash`.

    The shipped policy hashes four keys under a `retain` default, so a guard
    keyed on the default alone would never fire for the configuration this
    project actually ships.
    """
    defaults = _defaults()
    assert defaults["fact_bundle_redaction_default"] != "hash", (
        "if the default were hash, every leaf would be hashed and the evidence "
        "destroyed -- including values like vbawarnings"
    )
    assert "hash" in defaults["fact_bundle_redaction_keys"].values()

    guard = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))[0]
    condition = str(guard["when"])
    assert "fact_bundle_redaction_keys" in condition, (
        "the salt guard ignores per-key actions, so the shipped policy -- which "
        "hashes four keys under a non-hash default -- would skip it entirely"
    )


# --------------------------------------------------------------------------
# Fails closed
# --------------------------------------------------------------------------

def test_hashing_without_a_salt_is_refused() -> None:
    with pytest.raises(AnsibleFilterError, match="salt"):
        redact_facts({"a": {"sid": "S-1-5-21-1-2-3-1104"}}, keys=SHIPPED_POLICY, salt="")


def test_hashing_with_the_shipped_placeholder_salt_is_refused() -> None:
    """A known salt is a reversible hash with extra steps."""
    with pytest.raises(AnsibleFilterError, match="salt"):
        redact_facts({"a": {"sid": "S-1-5-21-1"}}, keys=SHIPPED_POLICY,
                     salt="CHANGE-ME-PER-DEPLOYMENT")


def test_an_unknown_action_is_refused_rather_than_ignored() -> None:
    with pytest.raises(AnsibleFilterError, match="unknown redaction action"):
        redact_facts({"a": {"sid": "x"}}, keys={"sid": "obfuscate"}, salt=SALT)


def test_a_non_mapping_is_refused() -> None:
    with pytest.raises(AnsibleFilterError):
        redact_facts(["not", "a", "mapping"], keys=SHIPPED_POLICY, salt=SALT)


# --------------------------------------------------------------------------
# Behaviour
# --------------------------------------------------------------------------

def test_identifiers_nested_in_lists_are_redacted() -> None:
    """The real shape: `windows.office.macro_policy` is a list of dicts."""
    facts = {
        "windows.office.macro_policy": {
            "value": [
                {"scope": "user", "sid": "S-1-5-21-1-1-1-1174", "vbawarnings": 2},
                {"scope": "machine", "sid": "S-1-5-18", "vbawarnings": 3},
            ]
        }
    }
    out = redact_facts(facts, keys=SHIPPED_POLICY, salt=SALT)
    rows = out["windows.office.macro_policy"]["value"]
    assert all(r["sid"].startswith("sha256:") for r in rows)
    # Evidence that is not an identifier must survive untouched, or the bundle
    # stops being able to answer the control it was collected for.
    assert [r["vbawarnings"] for r in rows] == [2, 3]
    assert [r["scope"] for r in rows] == ["user", "machine"]


def test_hashing_is_deterministic_and_salted() -> None:
    """Correlation survives; the identifier does not. Both halves matter."""
    a = redact_facts({"x": {"sid": "S-1-5-21-7"}}, keys=SHIPPED_POLICY, salt=SALT)
    b = redact_facts({"x": {"sid": "S-1-5-21-7"}}, keys=SHIPPED_POLICY, salt=SALT)
    c = redact_facts({"x": {"sid": "S-1-5-21-7"}}, keys=SHIPPED_POLICY, salt="other")
    assert a == b, "the same identifier must hash the same way, or longitudinal correlation breaks"
    assert a != c, "a different deployment's salt must produce a different hash"


def test_drop_removes_the_key_entirely() -> None:
    out = redact_facts({"x": {"email": "a@b.gov.au", "keep": 1}},
                       keys={"email": "drop"}, salt=SALT)
    assert "email" not in out["x"]
    assert out["x"]["keep"] == 1


def test_truncate_keeps_the_organisational_part() -> None:
    out = redact_facts(
        {"x": {"upn": "alice@agency.gov.au", "sid": "S-1-5-21-99-88-77-1174"}},
        keys={"upn": "truncate", "sid": "truncate"},
        salt=SALT,
    )
    assert out["x"]["upn"] == "***@agency.gov.au"
    # docs/13-security-model.md defines SID truncation as removing the RID,
    # because within a domain the RID is the account.
    assert out["x"]["sid"] == "S-1-5-21-99-88-77-***"


def test_truncate_keeps_well_known_rids() -> None:
    """A well-known RID names a role, not a person.

    500 is the built-in Administrator and 512 Domain Admins on every Windows
    domain in existence. Masking them would leave a truncated bundle unable to
    answer the privileged-access controls it was collected for, while
    protecting nobody.
    """
    out = redact_facts(
        {"x": {"admin": "S-1-5-21-99-88-77-500", "user": "S-1-5-21-99-88-77-1174"}},
        keys={"admin": "truncate", "user": "truncate"},
        salt=SALT,
    )
    assert out["x"]["admin"] == "S-1-5-21-99-88-77-500"
    assert out["x"]["user"] == "S-1-5-21-99-88-77-***"


def test_retain_is_the_default_and_leaves_everything_alone() -> None:
    facts = {"os.release": {"value": {"id": "ubuntu", "version_id": "24.04"}}}
    assert redact_facts(facts, keys={}, salt=SALT) == facts


def test_a_container_is_recursed_not_hashed_whole() -> None:
    """Hashing a subtree into one string would destroy the evidence."""
    out = redact_facts(
        {"x": {"sid": {"nested": "S-1-5-21-1", "count": 3}}},
        keys=SHIPPED_POLICY,
        salt=SALT,
    )
    assert isinstance(out["x"]["sid"], dict)
    assert out["x"]["sid"]["count"] == 3


def test_no_raw_identifier_survives_the_shipped_policy() -> None:
    """The end-to-end property, asserted over a realistic bundle shape."""
    import json
    import re

    defaults = _defaults()
    facts = json.loads(
        (ROOT / "tests" / "fixtures" / "bundles" / "wks-0043-failing.json")
        .read_text(encoding="utf-8")
    )["facts"]
    assert re.search(r"S-1-5-21-[\d-]+", json.dumps(facts)), (
        "the fixture carries no raw SID, so this test would pass vacuously"
    )

    out = redact_facts(
        facts,
        keys=defaults["fact_bundle_redaction_keys"],
        default=defaults["fact_bundle_redaction_default"],
        salt=SALT,
    )
    assert not re.search(r'"S-1-5-21-[\d-]+"', json.dumps(out)), (
        "a raw domain SID survived the shipped redaction policy"
    )


# --------------------------------------------------------------------------
# PR 19: the policy has to REACH the identifiers, not merely be applied.
#
# PR 16 made redaction run. It did not make it arrive. `walk()` selected the
# action from a mapping KEY, so:
#
#   - a bare SID inside a list had no key to match on and was returned
#     unchanged by the scalar branch;
#   - the enclosing key's action was discarded at every container boundary
#     (`out[key] = walk(value)`), so even `sid: hash` left a list of SIDs
#     untouched;
#   - and the shipped policy names `sid` / `username` / `upn` / `email`, while
#     the collectors emit SIDs under `allow_write_sids`, `deny_write_sids` and
#     `meta.profiles_unloaded`. None of those names matched anything.
#
# So real domain SIDs travelled verbatim into bundles stamped
# `redaction_policy: "1.0"`. See ADR 0018.
# --------------------------------------------------------------------------

#: A domain SID with a RID well above the well-known range: a person, not a role.
PERSON_SID = "S-1-5-21-1111111111-2222222222-3333333333-1174"
#: Domain Admins. RID 512 is identical on every Windows domain, so it names a
#: role and is deliberately KEPT -- see the carve-out in `_truncate`.
ROLE_SID = "S-1-5-32-544"

TRUNCATE_POLICY = {"sid": "truncate", "upn": "hash", "email": "hash"}


def test_a_sid_inside_a_list_is_redacted() -> None:
    """The live leak. `allow_write_sids` is a list of bare strings.

    Fails against the code as it shipped: the scalar branch returned any value
    reached without a key unchanged, so this came back verbatim.
    """
    out = redact_facts(
        {
            "windows.appcontrol.writable_paths": {
                "value": {"probes": [{"path": "C:\\Temp", "allow_write_sids": [PERSON_SID]}]}
            }
        },
        keys=TRUNCATE_POLICY,
        salt=SALT,
    )
    got = out["windows.appcontrol.writable_paths"]["value"]["probes"][0]["allow_write_sids"]
    assert PERSON_SID not in got, f"a raw domain SID survived redaction: {got}"
    assert got == ["S-1-5-21-1111111111-2222222222-3333333333-***"]


def test_a_well_known_rid_inside_a_list_is_still_kept() -> None:
    """Truncating role SIDs would break the controls they were collected for."""
    out = redact_facts(
        {"a": {"deny_write_sids": [ROLE_SID, PERSON_SID]}},
        keys=TRUNCATE_POLICY,
        salt=SALT,
    )
    assert out["a"]["deny_write_sids"][0] == ROLE_SID
    assert out["a"]["deny_write_sids"][1].endswith("***")


def test_the_enclosing_keys_action_reaches_into_a_list() -> None:
    """`sid: hash` must hash a list of SIDs, not skip it."""
    out = redact_facts({"a": {"sid": [PERSON_SID]}}, keys=SHIPPED_POLICY, salt=SALT)
    assert out["a"]["sid"][0].startswith("sha256:")


def test_a_sid_is_redacted_whatever_key_holds_it() -> None:
    """Shape detection is the backstop for the key names nobody thought of."""
    for key in ("allow_write_sids", "profiles_unloaded", "some_future_field"):
        out = redact_facts({"x": {key: [PERSON_SID]}}, keys=TRUNCATE_POLICY, salt=SALT)
        assert PERSON_SID not in out["x"][key], f"{key} leaked a raw SID"


def test_an_email_shaped_value_is_NOT_detected_by_shape() -> None:
    """Deliberately narrower than SIDs.

    Plenty of legitimate configuration values contain an "@" -- a proxy
    exception list, an ADMX policy string. Hashing those would destroy evidence
    to protect nothing, so email and UPN rely on their key name. `S-1-<n>-<n>-…`
    is unambiguous; an "@" is not.
    """
    out = redact_facts(
        {"a": {"note": "report issues to help@example.gov.au"}},
        keys=SHIPPED_POLICY,
        salt=SALT,
    )
    assert out["a"]["note"] == "report issues to help@example.gov.au"


def test_a_sub_mapping_under_a_named_key_does_not_inherit_the_action() -> None:
    """The counterpart to the propagation fix, and the reason it is narrow.

    A LIST under `sid` holds SIDs. A MAPPING under `sid` holds different fields,
    and hashing `count` would destroy the evidence the bundle exists to carry.
    Inheritance therefore resets at every dict boundary.
    """
    out = redact_facts(
        {"x": {"sid": {"nested": PERSON_SID, "count": 3}}},
        keys=TRUNCATE_POLICY,
        salt=SALT,
    )
    assert out["x"]["sid"]["count"] == 3
    # ...but the nested value is still a SID by shape, so it is still redacted.
    assert out["x"]["sid"]["nested"].endswith("***")


def _every_string(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _every_string(value)
    elif isinstance(node, list):
        for item in node:
            yield from _every_string(item)
    elif isinstance(node, str):
        yield node


@pytest.mark.parametrize(
    "policy", [TRUNCATE_POLICY, SHIPPED_POLICY], ids=["truncate", "hash"]
)
def test_no_committed_fixture_leaks_a_personal_sid_through_the_policy(policy) -> None:
    """End to end over the real fixture corpus, not a hand-made example.

    The fixtures deliberately CONTAIN realistic SIDs -- that is how the SID
    logic gets tested. What must not happen is one surviving the policy. Any
    RID >= 1000 identifies an account rather than a role.
    """
    import json
    import re

    bundles = sorted((ROOT / "tests" / "fixtures" / "bundles").glob("*.json"))
    assert bundles, "no fixture bundles found to scan"

    personal = re.compile(r"^S-1-5-21-[\d-]+-(\d{4,})$")
    checked = 0
    for path in bundles:
        facts = json.loads(path.read_text(encoding="utf-8")).get("facts", {})
        if not facts:
            continue
        for text in _every_string(redact_facts(facts, keys=policy, salt=SALT)):
            match = personal.match(text)
            assert match is None, (
                f"{path.name} leaked {text!r} through the redaction policy: "
                f"RID {match.group(1)} identifies an account, not a role"
            )
            checked += 1
    assert checked, "scanned no strings; the corpus or the walk is broken"
