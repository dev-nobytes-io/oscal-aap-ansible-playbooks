#!/usr/bin/env python3
"""The `cca` command line.

Two front doors over one implementation (ADR 0007): `tools/cca.py` for local
and CI use without installing anything, and this same module exposed as the
`cca` console script inside an execution environment. The logic lives here so
a wheel installed into an EE is self-contained -- reaching back into `tools/`
would work only for an editable install and fail in the image that matters.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from .bundle import load_bundle
from .catalog import Catalog
from .evaluate import coverage_summary, evaluate_bundle, unassessed_controls
from .generate import component_definitions
from .oscal import emit, ids
from .paths import ism_catalog, project_root
from .registry import Registry, validate, validate_schema

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
    catalog = Catalog.load(ism_catalog())
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
    catalog = Catalog.load(ism_catalog())
    baseline = catalog.baseline(**BASELINES[args.baseline])
    summary = coverage_summary(catalog, registry, baseline)
    summary["baseline"] = args.baseline
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Baseline {args.baseline} @ ISM {summary['catalog_version']}")
        print(f"  controls in baseline   : {summary['baseline_size']}")
        print(f"  with an automated check: {summary['controls_with_a_check']}")
        print(f"  declared attested      : {summary['controls_attested']}")
        print(f"  nothing yet            : {summary['controls_unaccounted']}")
        print(f"  by confidence          : {summary['by_confidence'] or '{}'}")
        pct = 100 * summary["controls_with_a_check"] / max(summary["baseline_size"], 1)
        print(f"  automated coverage     : {pct:.1f}%")
        print(
            "\n  Coverage counts intent, not outcome. A control with a check is "
            "\n  covered even if the last run could not reach the host."
            "\n  Attested controls are NOT in the percentage: no tool can observe"
            "\n  them, so counting them would let the number grow by writing prose."
        )
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Regenerate every derived OSCAL artefact.

    CI runs this and fails on a diff, so the component-definitions cannot drift
    away from the checks that produce them.
    """
    registry = Registry.load()
    catalog = Catalog.load(ism_catalog())
    # A fixed timestamp keeps generation deterministic; the meaningful version
    # is the catalog version, which is already carried in metadata.
    now = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
    out = Path(args.out) if args.out else project_root() / "oscal"
    _write(
        out / "component-definitions" / "nobytes-cca.json",
        component_definitions.generate(registry, catalog, now),
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    registry = Registry.load()
    catalog = Catalog.load(ism_catalog())
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

    out = Path(args.out) if args.out else project_root() / "out"
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
        registry=registry,
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


def cmd_report(args: argparse.Namespace) -> int:
    """Render the human-readable report from emitted OSCAL documents.

    Reads the documents rather than re-evaluating, so the report cannot drift
    from the assessment it describes: if they disagree, one of them is stale
    and that is worth finding out.
    """
    from .report import render
    from .report.model import load

    out = Path(args.out) if args.out else project_root() / "out"
    plan_path = Path(args.plan) if args.plan else out / "assessment-plan.json"
    results_path = Path(args.results) if args.results else out / "assessment-results.json"
    for path in (plan_path, results_path):
        if not path.exists():
            print(f"missing {path}; run `cca evaluate` first", file=sys.stderr)
            return 1

    report = load(plan_path, results_path, Catalog.load(ism_catalog()))
    suffix = "md" if args.format == "markdown" else "html"
    body = render.markdown(report) if suffix == "md" else render.to_html(report)

    target = Path(args.output) if args.output else out / f"assessment-report.{suffix}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    print(f"wrote {target}")
    determined = [r for r in report.rows if r.is_determined]
    print(
        f"  {len(determined)} determined, "
        f"{len(report.rows) - len(determined)} undetermined, "
        f"{len(report.attested)} attested"
    )
    return 0


def cmd_annex(args: argparse.Namespace) -> int:
    """Populate ASD's SSP Annex from the emitted assessment results.

    The vendored template is opened read-only and a copy is written. It is
    Commonwealth material redistributed unmodified under CC BY 4.0 and
    checksummed; modifying it in place would break both the attribution and
    `make validate`.
    """
    from .report.annex import populate
    from .report.model import load

    out = Path(args.out) if args.out else project_root() / "out"
    plan_path = Path(args.plan) if args.plan else out / "assessment-plan.json"
    results_path = Path(args.results) if args.results else out / "assessment-results.json"
    for path in (plan_path, results_path):
        if not path.exists():
            print(f"missing {path}; run `cca evaluate` first", file=sys.stderr)
            return 1

    template = (
        Path(args.template)
        if args.template
        else project_root()
        / "blueprint"
        / "static"
        / "content"
        / "files"
        / "Blueprint System Security Plan Annex Template (June 2026).xlsx"
    )
    destination = Path(args.output) if args.output else out / "ssp-annex-populated.xlsx"

    report = load(plan_path, results_path, Catalog.load(ism_catalog()))
    try:
        summary = populate(report, template, destination)
    except (FileNotFoundError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    print(f"wrote {summary['destination']}")
    print(
        f"  {summary['written']} of {summary['baseline_controls']} baseline "
        f"controls written; rows outside the baseline left untouched"
    )
    for status, count in summary["by_status"].items():
        print(f"      {status:<18} {count}")
    print(
        "\n  Generated, not authored. Every Implementation Comment states the "
        "\n  confidence behind its status. Review before submission."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cca", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate-registry", help="validate checks/ against schema and catalog")

    cov = sub.add_parser("coverage", help="report control coverage for a baseline")
    cov.add_argument("--baseline", default="E8_ML1", choices=sorted(BASELINES))
    cov.add_argument("--json", action="store_true")

    rep = sub.add_parser("report", help="render a human-readable assessment report")
    rep.add_argument("--format", default="markdown", choices=["markdown", "html"])
    rep.add_argument("--plan", default=None, help="default: <out>/assessment-plan.json")
    rep.add_argument("--results", default=None, help="default: <out>/assessment-results.json")
    rep.add_argument("--out", default=None, help="default: <project root>/out")
    rep.add_argument("--output", default=None, help="explicit output file path")

    ann = sub.add_parser("annex", help="populate ASD's SSP Annex from assessment results")
    ann.add_argument("--plan", default=None)
    ann.add_argument("--results", default=None)
    ann.add_argument("--out", default=None, help="default: <project root>/out")
    ann.add_argument("--template", default=None, help="default: the vendored Blueprint template")
    ann.add_argument("--output", default=None, help="default: <out>/ssp-annex-populated.xlsx")

    gen = sub.add_parser("generate", help="regenerate derived OSCAL artefacts")
    gen.add_argument("--out", default=None, help="default: <project root>/oscal")

    ev = sub.add_parser("evaluate", help="evaluate fact bundles and emit OSCAL")
    ev.add_argument("bundles", nargs="+")
    ev.add_argument("--baseline", default="E8_ML1", choices=sorted(BASELINES))
    ev.add_argument("--system-id", required=True)
    ev.add_argument("--run-id", required=True)
    ev.add_argument("--out", default=None, help="default: <project root>/out")
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
        "generate": cmd_generate,
        "report": cmd_report,
        "annex": cmd_annex,
        "evaluate": cmd_evaluate,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
