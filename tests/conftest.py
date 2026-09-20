"""Shared fixtures. Keeps the vendored catalog parsed once per session -- it is
2.6 MB and every canary test walks it."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


@pytest.fixture(scope="session")
def catalog() -> dict:
    from ism_release import catalog_path

    path = catalog_path()
    if not path.exists():
        pytest.skip(f"no vendored catalog at {path}; run `make fetch`")
    return json.loads(path.read_text(encoding="utf-8"))["catalog"]


@pytest.fixture(scope="session")
def controls(catalog: dict) -> list[dict]:
    """Every control and principle in the catalog, flattened.

    Worth knowing: ISM catalog groups carry `id: null` at every level, so the
    tree cannot be walked by group id -- it has to be walked structurally.
    """
    found: list[dict] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("class") in ("ISM-control", "ISM-principle"):
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(catalog)
    return found


def prop_values(control: dict, name: str) -> list[str]:
    return [p["value"] for p in control.get("props", []) if p["name"] == name]
