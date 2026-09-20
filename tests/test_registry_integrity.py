"""Registry integrity: everything a JSON Schema cannot express.

A registry entry that looks valid but binds to a control that does not exist, or
pins a statement hash that no longer matches, is worse than a missing entry --
it sits in the repository looking authoritative while assessing nothing.
"""

from __future__ import annotations

import pytest

from ism_release import catalog_path
from nobytes_cca.catalog import Catalog
from nobytes_cca.registry import Registry, validate, validate_schema


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry.load()


def test_registry_files_match_the_schema() -> None:
    problems = validate_schema()
    assert not problems, "schema violations:\n  " + "\n  ".join(problems)


def test_registry_is_consistent_with_the_catalog(registry: Registry) -> None:
    """Covers control existence, statement ids, PROSE DRIFT and evaluator imports.

    The prose-drift arm is the one that matters most over time: ASD reworded 111
    control statements in a single quarter while keeping ids unchanged. Without
    this, a check keeps passing against text that changed under it.
    """
    catalog = Catalog.load(catalog_path())
    problems = validate(registry, catalog)
    assert not problems, "registry problems:\n  " + "\n  ".join(problems)


def test_every_check_declares_what_it_does_not_prove(registry: Registry) -> None:
    """The rationale is the most valuable text in a registry entry."""
    for check in registry:
        for binding in check.controls:
            assert len(binding.rationale.strip()) >= 40, (
                f"{check.id}/{binding.control_id}: rationale too thin to state a "
                f"residual gap"
            )


def test_partial_coverage_is_never_claimed_as_direct(registry: Registry) -> None:
    """A check covering part of a control cannot claim direct confidence."""
    from nobytes_cca.contract import Confidence

    for check in registry:
        for binding in check.controls:
            if binding.coverage in ("partial", "proxy-only"):
                assert check.confidence is not Confidence.DIRECT, (
                    f"{check.id}: coverage={binding.coverage} but confidence=direct"
                )


def test_check_ids_are_unique_and_evaluators_resolve(registry: Registry) -> None:
    seen = set()
    for check in registry:
        assert check.id not in seen
        seen.add(check.id)
        assert callable(check.resolve())
