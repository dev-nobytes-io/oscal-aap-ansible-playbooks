"""The check registry: what checks exist, and what each one claims.

Loading is stdlib + PyYAML only (ADR 0011), so the evaluator can import this
inside either execution environment. Schema validation imports `jsonschema`
lazily, because that is a CI-time concern and must not become an evaluator
runtime dependency.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from .catalog import Catalog
from .contract import Assessability, Confidence, EvidenceTier, Method, Scope
from .paths import checks_dir, project_root

# Deliberately NOT module-level constants derived from __file__. The package is
# vendored into an execution environment at a path that has nothing to do with
# the checkout -- resolving at import time gave `<install-prefix>/checks`, which
# does not exist, so every check silently vanished and coverage reported 0 of 46
# with a zero exit. A wrong answer delivered confidently is the one outcome this
# project exists to prevent, so the location is resolved when it is used, via
# CCA_PROJECT_ROOT. See ADR 0007 and paths.py.


def _display(path: Path) -> str:
    """A path as a reader recognises it, relative to the project when possible."""
    try:
        return str(path.relative_to(project_root()))
    except ValueError:
        return str(path)


@dataclass(frozen=True)
class ControlBinding:
    control_id: str
    statement_id: str
    control_revision: str
    statement_sha256: str
    coverage: str
    rationale: str


@dataclass(frozen=True)
class Attestation:
    """Where a human-supplied answer lives, and who is answerable for it."""

    source: str
    owner: str
    renewal_days: int
    why_not_observable: str


@dataclass(frozen=True)
class Check:
    id: str
    version: str
    title: str
    platform_family: str
    component: str
    controls: tuple
    method: Method
    confidence: Confidence
    scope: Scope
    evidence_tier: EvidenceTier
    freshness_hours: int
    history_window_days: int
    assessability: Assessability
    collect_role: str
    required_facts: tuple
    optional_facts: tuple
    evaluator: str
    parameters: dict
    not_applicable_when: str
    references: tuple
    remediation: dict | None
    attestation: Attestation | None
    source_file: Path

    @property
    def is_automated(self) -> bool:
        return self.assessability is Assessability.AUTOMATED

    def resolve(self) -> Callable:
        """Import the evaluator function named by `evaluator`."""
        if not self.is_automated:
            raise ValueError(
                f"{self.id} is declared `attested`: there is no evaluator to resolve. "
                f"Calling one would invent a verdict for something no tool observes."
            )
        module_name, _, func_name = self.evaluator.partition(":")
        module = importlib.import_module(module_name)
        func = getattr(module, func_name, None)
        if func is None or not callable(func):
            raise AttributeError(f"{self.evaluator}: no callable {func_name!r} in {module_name}")
        return func


def _to_check(data: dict, path: Path) -> Check:
    # An attested entry has no `collect` block by schema, so these degrade to
    # empty rather than raising -- the schema is what enforces the shape.
    collect = data.get("collect") or {}
    facts = collect.get("facts") or {}
    attestation_data = data.get("attestation")
    return Check(
        id=data["id"],
        version=data["version"],
        title=data["title"],
        platform_family=data["platform_family"],
        component=data["component"],
        controls=tuple(
            ControlBinding(
                control_id=c["id"],
                statement_id=c["statement_id"],
                control_revision=c["control_revision"],
                statement_sha256=c["statement_sha256"],
                coverage=c["coverage"],
                rationale=c["rationale"],
            )
            for c in data["controls"]
        ),
        method=Method(data["method"]),
        confidence=Confidence(data["confidence"]),
        scope=Scope(data["scope"]),
        evidence_tier=EvidenceTier(data["evidence_tier"]),
        freshness_hours=int(data["freshness_hours"]),
        history_window_days=int(data["history_window_days"]),
        assessability=Assessability(data["assessability"]),
        collect_role=collect.get("role", ""),
        required_facts=tuple(facts.get("required", [])),
        optional_facts=tuple(facts.get("optional", [])),
        evaluator=data.get("evaluator", ""),
        parameters=data.get("parameters", {}),
        not_applicable_when=data.get("not_applicable_when", ""),
        references=tuple(data.get("references", [])),
        remediation=data.get("remediation"),
        attestation=Attestation(**attestation_data) if attestation_data else None,
        source_file=path,
    )


class Registry:
    def __init__(self, checks: dict) -> None:
        self._checks = checks

    @classmethod
    def load(cls, directory: Path | None = None) -> Registry:
        directory = directory or checks_dir()
        checks: dict = {}
        for path in sorted(directory.rglob("*.yml")):
            if path.name == "schema.json":
                continue
            with path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            if not data:
                continue
            check = _to_check(data, path)
            if check.id in checks:
                raise ValueError(
                    f"duplicate check id {check.id!r}: {checks[check.id].source_file} and {path}"
                )
            checks[check.id] = check
        if not checks:
            # "no checks are defined" and "the checks could not be found" are
            # indistinguishable downstream, and both render as 0% coverage with
            # a successful exit. Refuse rather than report a green nothing.
            raise FileNotFoundError(
                f"No checks found under {directory}. Either the check registry is "
                f"empty or the project root resolved wrongly -- set CCA_PROJECT_ROOT "
                f"to the checkout containing oscal/ and checks/."
            )
        return cls(checks)

    def __len__(self) -> int:
        return len(self._checks)

    def __iter__(self):
        for key in sorted(self._checks):
            yield self._checks[key]

    def get(self, check_id: str) -> Check | None:
        return self._checks.get(check_id)

    def for_control(self, control_id: str) -> list:
        return [c for c in self if any(b.control_id == control_id for b in c.controls)]

    def covered_controls(self) -> set:
        """Every control this registry has ANY entry for, automated or attested.

        Use this to answer "has anyone considered this control?". For "can a
        tool answer this control?", use `automated_controls()` -- the two are
        deliberately different, and reporting the union as coverage would count
        a human promise as automation.
        """
        return {b.control_id for check in self for b in check.controls}

    def automated_controls(self) -> set:
        """Controls a tool can actually reach a verdict on."""
        return {
            b.control_id for check in self if check.is_automated for b in check.controls
        }

    def attested_controls(self) -> set:
        """Controls declared structurally unobservable, and why, per entry."""
        return {
            b.control_id
            for check in self
            if not check.is_automated
            for b in check.controls
        }


def validate(registry: Registry, catalog: Catalog) -> list:
    """Return a list of problems; empty means the registry is sound.

    Checks four things a JSON Schema cannot:

    1. Every bound control id exists in the vendored catalog.
    2. Every statement_id matches the catalog's actual statement id.
    3. Every statement_sha256 matches the CURRENT control prose -- this is the
       prose-drift guard. ASD reworded 111 statements in one quarter; without
       it, a check silently keeps passing against text that changed.
    4. Every evaluator dotted path actually imports.
    5. An attested entry's freshness matches its attestation renewal period --
       otherwise a report can call an attestation current for a week while the
       process that produces it runs yearly, or the reverse.
    """
    problems: list = []
    for check in registry:
        for binding in check.controls:
            control = catalog.get(binding.control_id)
            if control is None:
                problems.append(
                    f"{check.id}: control {binding.control_id!r} is not in ISM "
                    f"catalog {catalog.version}"
                )
                continue
            if binding.statement_id != control.statement_id:
                problems.append(
                    f"{check.id}: statement_id {binding.statement_id!r} != "
                    f"catalog {control.statement_id!r}"
                )
            if binding.statement_sha256 != control.statement_sha256:
                problems.append(
                    f"{check.id}: PROSE DRIFT on {binding.control_id}.\n"
                    f"    pinned  {binding.statement_sha256}\n"
                    f"    current {control.statement_sha256}\n"
                    f"    now reads: {control.statement}\n"
                    f"    Re-affirm or revise this check, then update the hash."
                )
        if check.is_automated:
            try:
                check.resolve()
            except (ImportError, AttributeError) as exc:
                problems.append(
                    f"{check.id}: evaluator {check.evaluator!r} does not resolve: {exc}"
                )
        else:
            problems.extend(_attestation_problems(check))
    return problems


def _attestation_problems(check: Check) -> list:
    """Cross-field rules for an attested entry that the schema cannot express."""
    problems: list = []
    attestation = check.attestation
    if attestation is None:
        # Unreachable via the schema, which requires the block; kept so a
        # hand-built Check cannot slip through with nothing behind it.
        return [f"{check.id}: declared attested but carries no attestation block"]

    expected_hours = attestation.renewal_days * 24
    if check.freshness_hours != expected_hours:
        problems.append(
            f"{check.id}: freshness_hours is {check.freshness_hours} but the "
            f"attestation renews every {attestation.renewal_days} days "
            f"({expected_hours}h). An attestation cannot be fresher than the "
            f"process that produces it, and calling it stale sooner is just as "
            f"misleading."
        )
    return problems


def validate_schema(directory: Path | None = None) -> list:
    """Validate every registry file against checks/schema.json.

    `jsonschema` is imported here rather than at module scope so it stays a
    CI-time dependency and never enters the evaluator's runtime import graph.
    """
    import json

    import jsonschema

    directory = directory or checks_dir()
    schema = json.loads((directory / "schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    problems: list = []
    for path in sorted(directory.rglob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not data:
            continue
        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            location = "/".join(str(p) for p in error.path) or "<root>"
            problems.append(f"{_display(path)}: {location}: {error.message}")
    return problems
