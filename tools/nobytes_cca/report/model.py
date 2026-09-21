"""Turn assessment-plan + assessment-results into something renderable.

One rule governs this whole module: **a status never travels without its
confidence.** A control that is `satisfied` on `proxy` evidence has not been
demonstrated to the same standard as one that is `satisfied` on `direct`
evidence, and a report that renders them identically has destroyed the single
most important distinction the pipeline produces.

The same applies to `attested`: it must never read as an automated pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..catalog import Catalog

NS = "https://nobytes.io/ns/oscal/cca/1.0"


def _props(node: dict) -> dict:
    return {p["name"]: p["value"] for p in node.get("props", []) if p.get("ns") == NS}


@dataclass(frozen=True)
class ControlRow:
    """One control's line in the report."""

    control_id: str
    statement: str
    #: "satisfied" | "not-satisfied" | "undetermined"
    status: str
    #: Always carried. None only where nothing was determined AND nothing was
    #: claimed -- never dropped to make a table tidier.
    confidence: str | None = None
    reason: str | None = None
    population: dict = field(default_factory=dict)
    attestation: dict = field(default_factory=dict)

    @property
    def is_determined(self) -> bool:
        return self.status in ("satisfied", "not-satisfied")

    @property
    def display_status(self) -> str:
        """Status and confidence as one inseparable string.

        Deliberately not two fields a template could render one of. If a caller
        wants the status it gets the qualifier with it.
        """
        if self.status == "undetermined":
            return f"undetermined ({self.reason or 'unknown reason'})"
        return f"{self.status} ({self.confidence or 'unqualified'})"


@dataclass(frozen=True)
class Report:
    system_id: str
    baseline: str
    catalog_version: str
    run_id: str
    generated: str
    marking: str
    subjects_assessed: int
    subjects_in_scope: int
    rows: tuple

    def by_status(self, status: str) -> list:
        return [r for r in self.rows if r.status == status]

    @property
    def attested(self) -> list:
        return [r for r in self.rows if r.reason == "requires-attestation"]

    @property
    def confidence_counts(self) -> dict:
        out: dict = {}
        for row in self.rows:
            if row.is_determined and row.confidence:
                out[row.confidence] = out.get(row.confidence, 0) + 1
        return dict(sorted(out.items()))

    @property
    def reason_counts(self) -> dict:
        out: dict = {}
        for row in self.rows:
            if not row.is_determined:
                key = row.reason or "unknown"
                out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))


def build(plan: dict, results: dict, catalog: Catalog) -> Report:
    """Assemble a report from the two OSCAL documents and the vendored catalog."""
    plan_body = plan["assessment-plan"]
    result = results["assessment-results"]["results"][0]
    result_props = _props(result)

    # Attestation detail lives on the plan's activities, keyed by control.
    attestations: dict = {}
    for activity in plan_body.get("local-definitions", {}).get("activities", []):
        props = _props(activity)
        if props.get("assessability") != "attested":
            continue
        detail = {
            "source": props.get("attestation-source", ""),
            "owner": props.get("attestation-owner", ""),
            "renewal_days": props.get("attestation-renewal-days", ""),
            "why_not_observable": props.get("why-not-observable", ""),
            "title": activity.get("title", ""),
        }
        for selection in activity.get("related-controls", {}).get("control-selections", []):
            for include in selection.get("include-controls", []):
                attestations[include["control-id"]] = detail

    # Every control the plan set out to review -- including those with no check.
    # Generating this from the plan rather than from findings is what makes
    # "absent finding means undetermined" safe (ADR 0006).
    reviewed: list = []
    reason_by_control: dict = {}
    for selection in plan_body["reviewed-controls"]["control-selections"]:
        sel_props = {p["name"]: p["value"] for p in selection.get("props", [])}
        for include in selection.get("include-controls", []):
            cid = include["control-id"]
            reviewed.append(cid)
            if "unassessed-reason" in sel_props:
                reason_by_control[cid] = sel_props["unassessed-reason"]
            elif sel_props.get("assessment-status") == "requires-attestation":
                reason_by_control[cid] = "requires-attestation"

    # Per-control reasons the emitter now carries in the results document, so
    # a consumer never has to guess why a finding is absent.
    emitted_reasons: dict = {}
    for prop in result.get("props", []):
        if prop.get("name") != "undetermined" or prop.get("ns") != NS:
            continue
        control_id, _, reason = str(prop.get("value", "")).partition("=")
        if control_id and reason:
            emitted_reasons[control_id] = reason

    findings: dict = {}
    for finding in result.get("findings", []):
        props = _props(finding)
        cid = finding["target"]["target-id"].replace("_smt", "")
        findings[cid] = props

    # An observation records why a check that RAN could not conclude -- a more
    # specific answer than the plan's blanket selection reason, so it wins.
    # Where several subjects disagree the first is taken and the count is kept,
    # because "unreachable on two of fifty hosts" and "unreachable on all
    # fifty" are different situations and flattening them would hide the
    # difference.
    observed_reasons: dict = {}
    for observation in result.get("observations", []):
        props = _props(observation)
        reason = props.get("unassessed-reason")
        if not reason:
            continue
        for link in observation.get("relevant-evidence", []) or []:
            cid = str(link.get("href", "")).lstrip("#").replace("_smt", "")
            if cid:
                seen = observed_reasons.setdefault(cid, {"reason": reason, "subjects": 0})
                seen["subjects"] += 1

    rows = []
    for cid in reviewed:
        control = catalog.get(cid)
        statement = control.statement if control else ""
        if cid in findings:
            props = findings[cid]
            rows.append(
                ControlRow(
                    control_id=cid,
                    statement=statement,
                    status=props.get("assessment-status", "undetermined"),
                    confidence=props.get("confidence"),
                    population={
                        k: v for k, v in props.items() if k.startswith("population-")
                    },
                )
            )
        else:
            rows.append(
                ControlRow(
                    control_id=cid,
                    statement=statement,
                    status="undetermined",
                    reason=(
                        observed_reasons.get(cid, {}).get("reason")
                        or emitted_reasons.get(cid)
                        or reason_by_control.get(cid)
                        or "no-determination-recorded"
                    ),
                    attestation=attestations.get(cid, {}),
                )
            )

    metadata = results["assessment-results"]["metadata"]
    marking = next(
        (p["value"] for p in metadata.get("props", []) if p["name"] == "marking"),
        "UNMARKED",
    )
    return Report(
        system_id=result_props.get("system-id", ""),
        baseline=result_props.get("baseline", ""),
        catalog_version=result_props.get("catalog-version", ""),
        run_id=result_props.get("run-id", ""),
        generated=metadata.get("last-modified", ""),
        marking=marking,
        subjects_assessed=int(result_props.get("subjects-assessed", 0)),
        subjects_in_scope=int(result_props.get("subjects-in-scope", 0)),
        rows=tuple(sorted(rows, key=lambda r: r.control_id)),
    )


def load(plan_path: Path, results_path: Path, catalog: Catalog) -> Report:
    import json

    return build(
        json.loads(plan_path.read_text(encoding="utf-8")),
        json.loads(results_path.read_text(encoding="utf-8")),
        catalog,
    )
