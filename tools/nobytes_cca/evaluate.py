"""Evaluation: facts in, verdicts out.

Pure. No network, no subprocess -- enforced by tests rather than by convention,
because the moment one evaluator shells out under deadline pressure,
reproducibility is void and nobody notices for six months.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .catalog import Catalog
from .contract import (
    CheckResult,
    FactBundle,
    FactHistory,
    Status,
    UnassessedReason,
)
from .registry import Check, Registry


@dataclass(frozen=True)
class Evaluation:
    """One check against one subject, with everything needed to emit OSCAL."""

    check: Check
    subject: dict
    result: CheckResult
    collected: dt.datetime
    expires: dt.datetime

    @property
    def status(self) -> Status:
        return self.result.status

    def is_fresh(self, at: dt.datetime) -> bool:
        return self.collected <= at < self.expires


def evaluate_check(
    check: Check,
    bundle: FactBundle,
    history: FactHistory | None = None,
) -> Evaluation:
    """Run one check against one fact bundle.

    Three guards run before the evaluator is even called, because each protects
    an invariant the evaluator author should not have to remember:

    * required facts missing        -> unassessed / collection-error
    * history window unsatisfiable  -> unassessed / insufficient-history
    * evaluator raises              -> error, never a silent pass

    An evaluator that raises produces `error`, not `not-satisfied`. A bug in our
    code is not evidence about the estate.
    """
    history = history or FactHistory.empty()

    guard = bundle.require(*check.required_facts)
    if guard is not None:
        result = guard
    elif check.history_window_days and not history.spans(check.history_window_days):
        result = CheckResult.unassessed(
            reason=UnassessedReason.INSUFFICIENT_HISTORY,
            detail=(
                f"{check.id} needs {check.history_window_days} days of history to "
                f"judge a rate; {len(history)} bundle(s) available. Absence of "
                f"history is not evidence of non-compliance."
            ),
        )
    else:
        try:
            result = check.resolve()(bundle, check.parameters, history)
        except Exception as exc:
            result = CheckResult.error(
                detail=f"{check.evaluator} raised {type(exc).__name__}: {exc}"
            )

    # The registry declares a ceiling; an evaluator may lower confidence but
    # never raise it. Enforced here so no evaluator can opt out.
    result = result.with_confidence_ceiling(check.confidence)

    collected = bundle.collected
    expires = collected + dt.timedelta(hours=check.freshness_hours)
    return Evaluation(
        check=check,
        subject=bundle.subject,
        result=result,
        collected=collected,
        expires=expires,
    )


def evaluate_bundle(
    registry: Registry,
    bundle: FactBundle,
    baseline_controls: list | None = None,
    history: FactHistory | None = None,
) -> list:
    """Run every applicable check against one subject's facts."""
    evaluations = []
    for check in registry:
        if baseline_controls is not None and not any(
            b.control_id in baseline_controls for b in check.controls
        ):
            continue
        evaluations.append(evaluate_check(check, bundle, history))
    return evaluations


def unassessed_controls(
    baseline_controls: list,
    registry: Registry,
    evaluations: list,
) -> dict:
    """Controls in the baseline for which no determination was made, and why.

    This is the other half of ADR 0006. A finding is absent both when no check
    exists and when a check ran but could not determine an answer; the report
    must distinguish those, and neither may be mistaken for compliance.
    """
    determined = {
        binding.control_id
        for ev in evaluations
        if ev.status.emits_finding
        for binding in ev.check.controls
    }
    attempted = registry.covered_controls()

    out = {}
    for control_id in baseline_controls:
        if control_id in determined:
            continue
        if control_id not in attempted:
            out[control_id] = UnassessedReason.NOT_IMPLEMENTED
        else:
            reasons = [
                ev.result.reason
                for ev in evaluations
                if any(b.control_id == control_id for b in ev.check.controls)
                and ev.result.reason is not None
            ]
            out[control_id] = reasons[0] if reasons else UnassessedReason.EVALUATION_ERROR
    return out


def coverage_summary(catalog: Catalog, registry: Registry, baseline: list) -> dict:
    """Honest arithmetic about what this repository can actually assess.

    Counts intent, not outcome: a control with a check is "covered" even if the
    last run could not reach the host. Outcome belongs in assessment results.
    """
    covered = registry.covered_controls()
    by_confidence: dict = {}
    for check in registry:
        for binding in check.controls:
            if binding.control_id in baseline:
                key = check.confidence.value
                by_confidence[key] = by_confidence.get(key, 0) + 1

    in_baseline_covered = sorted(c for c in baseline if c in covered)
    return {
        "catalog_version": catalog.version,
        "baseline_size": len(baseline),
        "controls_with_a_check": len(in_baseline_covered),
        "controls_without_a_check": len(baseline) - len(in_baseline_covered),
        "by_confidence": dict(sorted(by_confidence.items())),
        "covered": in_baseline_covered,
        "uncovered": sorted(c for c in baseline if c not in covered),
    }
