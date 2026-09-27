"""Every fact key must be declared, emitted and consumed.

This closes the variant of the project's recurring defect that comparisons
between two artefacts cannot see: a key that exists in only ONE place.

`lab-diff`-style tooling compares collector reality against fixtures. The
`display_name`/`name` bug of PR 17 showed that two artefacts written from the
same wrong assumption agree with each other while both being wrong. A key
declared by a check and produced by nothing is worse still -- no comparison can
see it, because only one side has it at all.

Two live instances existed when this file was written:

  windows.gpo.applied_computer  declared optional by
                                checks/windows/win-office-macro-internet-blocked.yml,
                                emitted by no role, read by no evaluator.
                                One grep hit in the whole repository: its own
                                declaration.

  entra.tenant                  emitted by collect_entra_id from a dedicated
                                GET /organization call, declared by no check,
                                read by no evaluator, absent from the tenant
                                fixture -- and its single field, named
                                `tenant_id`, held the entire organization
                                object rather than an id.

The second is the more serious of the two. Evidence is a crown-jewel dataset
you cannot retroactively un-collect (ADR 0008), so a Graph call whose result
nothing consumes is gratuitous collection of identity data, not harmless
thoroughness. Both were removed rather than wired up. See ADR 0019.

All three directions are HARD failures:

  declared but not emitted  -- the check can never be determined
  declared but not read     -- a false dependency; the check does not need it
  emitted but not declared  -- collection with no consumer

A future fact that genuinely needs to travel as context gets declared
`optional` on the check that wants it. That is one line, and it makes the
dependency visible.
"""

from __future__ import annotations

import re

import pytest
import yaml

from conftest import ROOT

CHECKS = ROOT / "checks"
ROLES = ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance" / "roles"
EVALUATORS = ROOT / "tools" / "nobytes_cca" / "checks"


def _declared() -> dict:
    """fact key -> [(check file, required|optional), ...]"""
    out: dict = {}
    for path in sorted(CHECKS.glob("*/*.yml")):
        entry = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        facts = ((entry.get("collect") or {}).get("facts")) or {}
        for kind in ("required", "optional"):
            for key in facts.get(kind) or []:
                out.setdefault(key, []).append((path.name, kind))
    return out


def _emitted() -> dict:
    """fact key -> [role name, ...], parsed from YAML rather than grepped."""
    out: dict = {}

    def scan(node, role: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "fact_records" and isinstance(value, dict):
                    for fact_key in value:
                        out.setdefault(fact_key, []).append(role)
                else:
                    scan(value, role)
        elif isinstance(node, list):
            for item in node:
                scan(item, role)

    for path in sorted(ROLES.glob("collect_*/tasks/*.yml")):
        scan(yaml.safe_load(path.read_text(encoding="utf-8")) or [], path.parents[1].name)
    return out


def _consumed() -> dict:
    """fact key -> [evaluator file, ...], from bundle.fact("...") call sites."""
    out: dict = {}
    pattern = re.compile(r"\.fact\(\s*[\"']([a-z][a-z0-9_.]*)[\"']")
    for path in sorted(EVALUATORS.rglob("*.py")):
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            out.setdefault(match.group(1), []).append(path.name)
    return out


DECLARED = _declared()
EMITTED = _emitted()
CONSUMED = _consumed()


def test_the_three_sets_are_all_populated() -> None:
    """A green suite must not be able to mean "nothing was scanned"."""
    assert len(DECLARED) >= 10, f"only {len(DECLARED)} declared fact keys found"
    assert len(EMITTED) >= 10, f"only {len(EMITTED)} emitted fact keys found"
    assert len(CONSUMED) >= 10, f"only {len(CONSUMED)} consumed fact keys found"


@pytest.mark.parametrize("key", sorted(DECLARED))
def test_every_declared_fact_key_is_emitted_by_some_role(key: str) -> None:
    """Fails on `windows.gpo.applied_computer` as the code shipped."""
    assert key in EMITTED, (
        f"{key} is declared by {DECLARED[key]} but no collect_* role emits it. "
        f"A check that depends on a fact nothing produces can never be "
        f"determined. Either emit it or drop the declaration. See ADR 0019."
    )


@pytest.mark.parametrize("key", sorted(DECLARED))
def test_every_declared_fact_key_is_read_by_some_evaluator(key: str) -> None:
    """A declared dependency no evaluator reads is a false dependency."""
    assert key in CONSUMED, (
        f"{key} is declared by {DECLARED[key]} but no evaluator calls "
        f"bundle.fact({key!r}). The declaration overstates what the check needs."
    )


@pytest.mark.parametrize("key", sorted(EMITTED))
def test_every_emitted_fact_key_is_declared_by_some_check(key: str) -> None:
    """Fails on `entra.tenant` as the code shipped.

    Collection with no consumer is not harmless. Evidence cannot be
    retroactively un-collected, so a fact nothing reads is pure exposure.
    """
    assert key in DECLARED, (
        f"{key} is emitted by {EMITTED[key]} but no check declares it, so "
        f"nothing consumes it. Evidence cannot be un-collected -- declare it "
        f"`optional` on the check that wants it, or stop collecting it."
    )


def test_no_evaluator_reads_a_fact_no_role_emits() -> None:
    """The fourth direction, for completeness.

    An evaluator reading a key nothing produces returns `unassessed` forever --
    quietly, which is exactly how the browser check shipped in PR 17.
    """
    orphans = {k: v for k, v in CONSUMED.items() if k not in EMITTED}
    assert not orphans, (
        f"evaluators read fact keys no role emits: {orphans}. Each would return "
        f"unassessed on every host, permanently and silently."
    )
