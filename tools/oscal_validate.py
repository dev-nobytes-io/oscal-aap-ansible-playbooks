#!/usr/bin/env python3
"""Validate OSCAL documents against the pinned NIST JSON schemas, offline.

Two things make this less trivial than it sounds.

1. NIST publishes the schemas ONLY as GitHub release assets. The paths people
   reach for first -- raw.githubusercontent.com/usnistgov/OSCAL/<tag>/json/schema/
   and pages.nist.gov/OSCAL/artifacts/ -- both return 404. They are vendored
   under oscal/schemas/ so validation needs no network at all.

2. The schemas use \\p{...} Unicode-property regexes. Python's stdlib `re`
   cannot compile them, so stock jsonschema does not merely fail -- it raises
   `re.error: bad escape \\p` and CRASHES. The fix is to override the `pattern`
   keyword to use the `regex` module, which does support them.

Beyond schema conformance this also enforces project invariants that a schema
cannot express -- see check_project_invariants().
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import regex
from jsonschema import Draft7Validator, validators

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Imported after the path shim above so this file runs standalone as a script.
from ism_release import catalog_path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "oscal" / "schemas"

#: Root JSON key -> schema file. A document is identified by its single root key.
MODEL_SCHEMAS = {
    "catalog": "oscal_catalog_schema.json",
    "profile": "oscal_profile_schema.json",
    "component-definition": "oscal_component_schema.json",
    "assessment-plan": "oscal_assessment-plan_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
    "plan-of-action-and-milestones": "oscal_poam_schema.json",
    "system-security-plan": "oscal_ssp_schema.json",
}


def _pattern_with_regex(validator, patrn, instance, schema):
    """Replacement for jsonschema's `pattern` keyword.

    Uses `regex` rather than `re` so that \\p{...} Unicode property escapes in
    the OSCAL schemas compile instead of raising.
    """
    del validator, schema
    if isinstance(instance, str) and not regex.search(patrn, instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {patrn!r}")


OscalValidator = validators.extend(Draft7Validator, {"pattern": _pattern_with_regex})


def load_schema(name: str) -> dict:
    path = SCHEMA_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Pinned schema missing: {path}. "
            "Run `make fetch` to vendor the NIST OSCAL schemas."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def validate_document(path: Path) -> list[str]:
    """Return a list of human-readable errors; empty means valid."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"not valid JSON: {exc}"]

    roots = [key for key in doc if key in MODEL_SCHEMAS]
    if len(roots) != 1:
        return [
            (
                "cannot identify OSCAL model: expected exactly one recognised "
                f"root key, found {sorted(doc)}"
            )
        ]

    root = roots[0]
    validator = OscalValidator(load_schema(MODEL_SCHEMAS[root]))
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [
        f"{'/'.join(str(p) for p in error.path) or '<root>'}: {error.message}"
        for error in errors
    ]


def discover() -> list[Path]:
    """Every OSCAL document in the repository, vendored upstream data included.

    Upstream data is validated too. It should always pass -- but a botched
    vendoring is exactly the failure this catches, and it is silent otherwise.
    """
    return sorted(
        path
        for path in (ROOT / "oscal").rglob("*.json")
        if path.name != "MANIFEST.json" and path.parent != SCHEMA_DIR
    )


def check_project_invariants(documents: list[Path]) -> list[str]:
    """Invariants a JSON schema cannot express.

    Currently: every control referenced by a component-definition must exist in
    the vendored catalog. A binding that names a control id which does not exist
    -- a typo, or a control ASD withdrew in a later release -- would otherwise
    sit in the repository looking authoritative and assessing nothing.
    """
    problems: list[str] = []
    comp_defs = [
        p for p in documents
        if "component-definition" in json.loads(p.read_text(encoding="utf-8"))
    ]
    if not comp_defs:
        return problems

    catalog_file = catalog_path()
    if not catalog_file.exists():
        return [f"component-definitions present but no vendored catalog at {catalog_file}"]

    known: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("class") in ("ISM-control", "ISM-principle") and "id" in node:
                known.add(node["id"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(json.loads(catalog_file.read_text(encoding="utf-8")))

    for path in comp_defs:
        doc = json.loads(path.read_text(encoding="utf-8"))
        for component in doc["component-definition"].get("components", []):
            for impl in component.get("control-implementations", []):
                for req in impl.get("implemented-requirements", []):
                    cid = req.get("control-id")
                    if cid and cid not in known:
                        problems.append(
                            f"{path.relative_to(ROOT)}: control-id {cid!r} does not "
                            f"exist in the vendored ISM catalog"
                        )
    return problems


def main() -> int:
    documents = discover()
    if not documents:
        print("No OSCAL documents found under oscal/. Run `make fetch` first.")
        return 1

    failed = 0
    for path in documents:
        errors = validate_document(path)
        rel = path.relative_to(ROOT)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for error in errors[:5]:
                print(f"       {error}")
            if len(errors) > 5:
                print(f"       ... and {len(errors) - 5} more")
        else:
            print(f"ok   {rel}")

    problems = check_project_invariants(documents)
    for problem in problems:
        print(f"FAIL {problem}")

    total = len(documents)
    if failed or problems:
        print(f"\n{failed}/{total} documents invalid; {len(problems)} invariant violation(s)")
        return 1
    print(f"\n{total} OSCAL documents valid against NIST schemas; invariants hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
