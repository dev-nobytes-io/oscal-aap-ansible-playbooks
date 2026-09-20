#!/usr/bin/env python3
"""cca -- continuous compliance assessment CLI.

Two front doors over one implementation (ADR 0007): this CLI for CI and local
use, and the same package invoked from a thin Ansible role inside an execution
environment. There is no second implementation to drift.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ism_release import catalog_path
from nobytes_cca.bundle import load_bundle
from nobytes_cca.catalog import Catalog
from nobytes_cca.evaluate import (
    coverage_summary,
    evaluate_bundle,
    unassessed_controls,
)
from nobytes_cca.oscal import emit, ids
from nobytes_cca.registry import Registry, validate, validate_schema

BASELINES = {
    "E8_ML1": {"e8": "ML1"},
    "E8_ML2": {"e8": "ML2"},
    "E8_ML3": {"e8": "ML3"},
    "NON_CLASSIFIED": {"classification": "NC"},
    "OFFICIAL_SENSITIVE": {"classification": "OS"},
    "PROTECTED": {"classification": "P"},
    "SECRET": {"classification": "S"},
    "TOP_SECRET": {"classification": "TS"},
}


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys=False preserves our deliberate key order; the determinism comes
    # from UUIDv5 derivation, not from sorting.
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def cmd_validate_registry(args: argparse.Namespace) -> int:
    del args
    registry = Registry.load()
    catalog = Catalog.load(catalog_path())
    problems = validate_schema() + validate(registry, catalog)
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        print(f"\n{len(problems)} registry problem(s)")
        return 1
    print(f"{len(registry)} check(s) valid against schema, catalog and evaluators")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    registry = Registry.load()
    catalog = Catalog.load(catalog_path())
    baseline = catalog.baseline(**BASELINES[args.baseline])
    summary = coverage_summary(catalog, registry, baseline)
    summary["baseline"] = args.baseline
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Baseline {args.baseline} @ ISM {summary['catalog_version']}")
        print(f"  controls in baseline   : {summary['baseline_size']}")
        print(f"  with an automated check: {summary['controls_with_a_check']}")
        print(f"  without                : {summary['controls_without_a_check']}")
        print(f"  by confidence          : {summary['by_confidence'] or '{}'}")
        pct = 100 * summary["controls_with_a_check"] / max(summary["baseline_size"], 1)
        print(f"  coverage               : {pct:.1f}%")
        print(
            "\n  Coverage counts intent, not outcome. A control with a check is "
            "\n  covered even if the last run could not reach the host."
        )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    registry = Registry.load()
    catalog = Catalog.load(catalog_path())
    baseline = catalog.baseline(**BASELINES[args.baseline])

    now = dt.datetime.fromisoformat(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        print("--now must carry a timezone", file=sys.stderr)
        return 2

    evaluations = []
    for bundle_path in args.bundles:
        bundle = load_bundle(Path(bundle_path))
        subject = bundle.subject
        subject.setdefault(
            "inventory_item_uuid",
            ids.inventory_item_uuid(args.system_id, subject["asset_id"]),
        )
        evaluations.extend(evaluate_bundle(registry, bundle, baseline))

    out = Path(args.out)
    plan = emit.emit_assessment_plan(
        system_id=args.system_id,
        baseline=args.baseline,
        baseline_controls=baseline,
        registry=registry,
        catalog=catalog,
        now=now,
    )
    plan_path = out / "assessment-plan.json"
    _write(plan_path, plan)

    results = emit.emit_assessment_results(
        system_id=args.system_id,
        run_id=args.run_id,
        baseline=args.baseline,
        baseline_controls=baseline,
        evaluations=evaluations,
        catalog=catalog,
        plan_href="./assessment-plan.json",
        now=now,
        population_total=args.population_total,
    )
    _write(out / "assessment-results.json", results)
    _write(
        out / "poam.json",
        emit.emit_poam(
            system_id=args.system_id, baseline=args.baseline, results=results, now=now
        ),
    )

    undetermined = unassessed_controls(baseline, registry, evaluations)
    result = results["assessment-results"]["results"][0]
    print(f"\n{args.baseline}: {len(baseline)} controls in baseline")
    print(f"  determined  : {len(result['findings'])}")
    print(f"  unassessed  : {len(undetermined)}")
    print(f"  observations: {len(result['observations'])}")
    reasons: dict = {}
    for reason in undetermined.values():
        reasons[reason.value] = reasons.get(reason.value, 0) + 1
    for reason, count in sorted(reasons.items()):
        print(f"      {reason:<24} {count}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cca", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate-registry", help="validate checks/ against schema and catalog")

    cov = sub.add_parser("coverage", help="report control coverage for a baseline")
    cov.add_argument("--baseline", default="E8_ML1", choices=sorted(BASELINES))
    cov.add_argument("--json", action="store_true")

    ev = sub.add_parser("evaluate", help="evaluate fact bundles and emit OSCAL")
    ev.add_argument("bundles", nargs="+")
    ev.add_argument("--baseline", default="E8_ML1", choices=sorted(BASELINES))
    ev.add_argument("--system-id", required=True)
    ev.add_argument("--run-id", required=True)
    ev.add_argument("--out", default="out")
    ev.add_argument("--now", help="ISO-8601 with timezone; defaults to now")
    ev.add_argument(
        "--population-total",
        type=int,
        help="in-scope subject count from INVENTORY. Defaults to the number of "
        "bundles, which is only correct when every subject was reachable.",
    )

    args = parser.parse_args()
    return {
        "validate-registry": cmd_validate_registry,
        "coverage": cmd_coverage,
        "evaluate": cmd_evaluate,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
