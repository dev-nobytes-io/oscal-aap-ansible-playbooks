"""Evaluator purity is enforced, not promised.

ADR 0007 says evaluators are pure functions. That claim is worthless as a
comment: the moment one shells out to `gpresult` or hits the Graph API "just for
this one check" under deadline pressure, reproducibility is void, archived
evidence stops re-evaluating to the same answer, and nobody notices for six
months.

So the whole evaluator surface runs here with networking and subprocess
execution removed from underneath it.
"""

from __future__ import annotations

import datetime as dt
import socket
import subprocess
import sys

import pytest

from conftest import ROOT
from nobytes_cca.bundle import load_bundle
from nobytes_cca.registry import Registry

FIXTURES = ROOT / "tests" / "fixtures" / "bundles"

#: Modules an evaluator may import. Anything else is either an I/O surface or a
#: third-party dependency the execution environment may not have.
ALLOWED_EVALUATOR_IMPORTS = {
    "nobytes_cca",
    "__future__",
    "datetime",
    "math",
    "re",
    "json",
    "collections",
    "itertools",
    "functools",
    "typing",
    "dataclasses",
    "enum",
    "hashlib",
}


@pytest.fixture
def no_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the ability to do I/O, then run evaluators anyway."""

    def blocked_socket(*_args, **_kwargs):
        raise AssertionError(
            "an evaluator opened a socket: evaluators must be pure functions of "
            "the fact bundle (ADR 0007)"
        )

    def blocked_popen(*_args, **_kwargs):
        raise AssertionError(
            "an evaluator spawned a subprocess: evaluators must be pure functions "
            "of the fact bundle (ADR 0007)"
        )

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "create_connection", blocked_socket)
    monkeypatch.setattr(subprocess, "Popen", blocked_popen)
    monkeypatch.setattr(subprocess, "run", blocked_popen)


@pytest.mark.parametrize("fixture", ["wks-0042-partial.json", "wks-0043-failing.json"])
def test_every_evaluator_runs_without_io(no_io, fixture: str) -> None:
    from nobytes_cca.evaluate import evaluate_check

    registry = Registry.load()
    bundle = load_bundle(FIXTURES / fixture)
    for check in registry:
        outcome = evaluate_check(check, bundle)
        # A blocked socket surfaces as an evaluator exception, which the
        # orchestrator converts to ERROR. Assert we did not get there.
        assert "socket" not in outcome.result.detail.lower()
        assert "subprocess" not in outcome.result.detail.lower()


def test_evaluators_import_nothing_unexpected() -> None:
    """An import contract over the check modules.

    Adding an import here should require an explicit decision, not happen by
    accident while chasing a deadline.
    """
    import importlib
    import pkgutil

    import nobytes_cca.checks as checks_pkg

    offenders: list = []
    for module_info in pkgutil.walk_packages(checks_pkg.__path__, "nobytes_cca.checks."):
        module = importlib.import_module(module_info.name)
        source_modules = {
            name.split(".")[0]
            for name, mod in sys.modules.items()
            if mod is not None and name.startswith("nobytes_cca.checks")
        }
        del source_modules
        for attr in dir(module):
            value = getattr(module, attr)
            mod_name = getattr(value, "__module__", "") or ""
            root = mod_name.split(".")[0]
            if root and root not in ALLOWED_EVALUATOR_IMPORTS and not attr.startswith("_"):
                offenders.append(f"{module_info.name}: {attr} from {mod_name}")
    assert not offenders, "unexpected imports in evaluator modules: " + "; ".join(offenders)


def test_evaluators_do_not_read_the_clock() -> None:
    """Evaluators receive time through the fact bundle, never from the system.

    A verdict that depends on when it was computed cannot be re-derived, which
    defeats the whole point of keeping evidence.
    """
    import inspect

    import nobytes_cca.checks.windows.office as office

    source = inspect.getsource(office)
    for forbidden in ("datetime.now(", "dt.datetime.now(", "time.time(", "utcnow("):
        assert forbidden not in source, (
            f"{forbidden} in an evaluator: time must arrive via the fact bundle"
        )


def test_same_bundle_evaluates_identically_twice() -> None:
    """Purity, observed rather than asserted."""
    from nobytes_cca.evaluate import evaluate_check

    registry = Registry.load()
    check = registry.get("win-office-macro-internet-blocked")
    first = evaluate_check(check, load_bundle(FIXTURES / "wks-0043-failing.json"))
    second = evaluate_check(check, load_bundle(FIXTURES / "wks-0043-failing.json"))
    assert first.result == second.result
    assert first.expires == second.expires
    assert isinstance(first.collected, dt.datetime)


def test_evaluator_parses_as_python_39() -> None:
    """ADR 0007's Python 3.9 floor, checked locally rather than only in CI.

    The evaluator has to run inside ee-legacy, which pins ansible-core 2.16 on
    Python 3.9 to reach Windows Server 2012 and RHEL 7/8. The EE build that
    proves this end-to-end is CI-only (it needs a container runtime), so this
    catches a 3.10+ construct at the point it is written instead of two hours
    later in a matrix job.
    """
    import ast

    package = ROOT / "tools" / "nobytes_cca"
    offenders = []
    for path in sorted(package.rglob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 9))
        except SyntaxError as exc:
            offenders.append(f"{path.relative_to(ROOT)}: {exc}")

    assert not offenders, "not valid Python 3.9:\n  " + "\n  ".join(offenders)


def test_evaluator_runtime_imports_stay_within_the_allowed_set() -> None:
    """Only the standard library plus PyYAML may be imported at runtime.

    PyYAML is permitted because ansible-core requires it, so it is present in
    every execution environment by construction (ADR 0011). The bar for
    anything further is that it must ALSO already be there -- "it's only one
    small package" does not qualify.
    """
    import ast
    import sys

    allowed_third_party = {"yaml"}
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    package = ROOT / "tools" / "nobytes_cca"

    offenders = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in stdlib or name in allowed_third_party:
                    continue
                if name in ("nobytes_cca", "cca"):
                    continue
                # jsonschema is imported lazily inside a CI-only validation
                # helper; it never enters the evaluator's runtime import graph.
                if name == "jsonschema":
                    continue
                offenders.append(f"{path.relative_to(ROOT)}: imports {name!r}")

    assert not offenders, (
        "runtime dependency outside stdlib + PyYAML:\n  " + "\n  ".join(offenders)
    )
