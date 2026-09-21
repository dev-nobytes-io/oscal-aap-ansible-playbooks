"""Emit OSCAL 1.1.2 assessment plans, results and POA&M documents.

Built as plain dictionaries with sorted, stable key order so output is
byte-deterministic for a given input (ADR 0010).

Two OSCAL 1.1.2 facts drive the shape of everything here, both verified against
the NIST schemas rather than assumed:

* `assessment-results` REQUIRES `import-ap`, so the plan is a mandatory
  artefact, not a nicety.
* `finding-target.status.state` permits only `satisfied` and `not-satisfied`.
  There is no way to say "we did not determine this" in a finding. So absence of
  a finding carries that meaning, and `reviewed-controls` -- generated from the
  PLAN, never from results -- is what makes absence unambiguous. See ADR 0006.
"""

from __future__ import annotations

import datetime as dt

from ..catalog import Catalog
from ..contract import Scope, Status
from ..registry import Registry
from . import NS, OSCAL_VERSION, ids


def _ts(moment: dt.datetime) -> str:
    """OSCAL dateTime-with-timezone. A naive datetime is rejected rather than
    silently stamped as UTC -- evidence timestamps decide expiry."""
    if moment.tzinfo is None:
        raise ValueError(f"refusing naive datetime {moment!r}: evidence timestamps need a timezone")
    return moment.isoformat()


def _prop(name: str, value: str, ns: str | None = NS, cls: str | None = None) -> dict:
    prop = {"name": name, "value": str(value)}
    if ns:
        prop["ns"] = ns
    if cls:
        prop["class"] = cls
    return prop


def marking(value: str) -> dict:
    """Classification marking, in the CORE namespace, not ours.

    `marking` is the one OSCAL-defined prop name for this, so reusing it means
    third-party tooling honours it instead of ignoring a custom prop.
    """
    return {"name": "marking", "value": value, "class": "pspf"}


def _metadata(title: str, last_modified: dt.datetime, version: str, classification: str) -> dict:
    return {
        "title": title,
        "last-modified": _ts(last_modified),
        "version": version,
        "oscal-version": OSCAL_VERSION,
        "props": [marking(classification)],
    }


# --------------------------------------------------------------------------
# Assessment plan
# --------------------------------------------------------------------------


def emit_assessment_plan(
    *,
    system_id: str,
    baseline: str,
    baseline_controls: list,
    registry: Registry,
    catalog: Catalog,
    now: dt.datetime,
    classification: str = "OFFICIAL: Sensitive",
) -> dict:
    """The declaration of intent: every control we set out to determine.

    `reviewed-controls` here is the reference `reviewed-controls minus findings =
    unassessed` is measured against, which is why it enumerates the WHOLE
    baseline including controls with no check. Generating it from results
    instead would make "we could not tell" indistinguishable from "out of
    scope", and the honesty mechanism would collapse silently.
    """
    automated = registry.automated_controls()
    attested = registry.attested_controls()
    with_check = [c for c in baseline_controls if c in automated]
    attested_only = [c for c in baseline_controls if c in attested and c not in automated]
    without_check = [
        c for c in baseline_controls if c not in automated and c not in attested
    ]

    selections = [
        {
            "description": (
                f"Controls in the {baseline} baseline with an implemented automated "
                f"check in this release."
            ),
            "include-controls": [
                {"control-id": cid, "statement-ids": [catalog.require(cid).statement_id]}
                for cid in with_check
            ],
        }
    ]
    if attested_only:
        # Kept as its own selection rather than folded into either neighbour.
        # An assessor reading the plan needs to know these are in scope and
        # will be answered -- by examining an attestation, not by a tool -- and
        # that no amount of automation is coming for them.
        selections.append(
            {
                "description": (
                    f"Controls in the {baseline} baseline that NO tool can observe: "
                    f"they concern third-party systems, customer identity estates, "
                    f"or approval records. They are in scope and are determined by "
                    f"EXAMINATION of an attestation, never by automated test. "
                    f"Each names where its evidence is held and who owns it."
                ),
                "props": [
                    _prop("assessment-status", "requires-attestation"),
                    _prop("assessability", "attested"),
                ],
                "include-controls": [
                    {"control-id": cid, "statement-ids": [catalog.require(cid).statement_id]}
                    for cid in attested_only
                ],
            }
        )
    if without_check:
        selections.append(
            {
                "description": (
                    f"Controls in the {baseline} baseline with NO automated check in "
                    f"this release. They are in scope and no determination is made "
                    f"for them. Their absence from findings means undetermined, not "
                    f"compliant."
                ),
                "props": [
                    _prop("assessment-status", "unassessed"),
                    _prop("unassessed-reason", "not-implemented"),
                ],
                "include-controls": [
                    {"control-id": cid, "statement-ids": [catalog.require(cid).statement_id]}
                    for cid in without_check
                ],
            }
        )

    activities = []
    for check in registry:
        if not any(b.control_id in baseline_controls for b in check.controls):
            continue
        activities.append(
            {
                "uuid": ids.resource_uuid("activity", f"{system_id}:{check.id}"),
                "title": check.title,
                "description": check.controls[0].rationale,
                "props": [
                    _prop("check-id", check.id),
                    _prop("check-version", check.version),
                    _prop("method", check.method.value),
                    _prop("confidence", check.confidence.value),
                    _prop("scope", check.scope.value),
                    _prop("evidence-tier", check.evidence_tier.value),
                    _prop("freshness-hours", str(check.freshness_hours)),
                    _prop("history-window-days", str(check.history_window_days)),
                    _prop("assessability", check.assessability.value),
                ]
                + (
                    [
                        _prop("collect-role", check.collect_role),
                        _prop("evaluator", check.evaluator),
                    ]
                    if check.is_automated
                    else [
                        _prop("attestation-source", check.attestation.source),
                        _prop("attestation-owner", check.attestation.owner),
                        _prop("attestation-renewal-days", str(check.attestation.renewal_days)),
                        _prop("why-not-observable", check.attestation.why_not_observable),
                    ]
                ),
                "related-controls": {
                    "control-selections": [
                        {
                            "include-controls": [
                                {"control-id": b.control_id, "statement-ids": [b.statement_id]}
                                for b in check.controls
                            ]
                        }
                    ]
                },
            }
        )

    return {
        "assessment-plan": {
            "uuid": ids.plan_uuid(system_id, baseline),
            "metadata": _metadata(
                f"Continuous assessment plan — {baseline} — {system_id}",
                now,
                catalog.version,
                classification,
            ),
            "import-ssp": {"href": f"#{ids.resource_uuid('ssp', system_id)}"},
            "local-definitions": {"activities": activities},
            "reviewed-controls": {
                "description": (
                    f"Every control in the {baseline} baseline at ISM catalog "
                    f"{catalog.version} is in scope, including those for which no "
                    f"determination can be made."
                ),
                "control-selections": selections,
            },
            "back-matter": {
                "resources": [
                    {
                        "uuid": ids.resource_uuid("ssp", system_id),
                        "title": f"System security plan placeholder for {system_id}",
                        "description": (
                            "This project assesses; it does not author SSPs. The "
                            "reference exists because import-ssp is part of the "
                            "assessment-plan model."
                        ),
                    }
                ]
            },
        }
    }


# --------------------------------------------------------------------------
# Assessment results
# --------------------------------------------------------------------------


def _observation(
    result_id: str,
    evaluation,
    catalog: Catalog,
    classification: str,
) -> dict:
    check = evaluation.check
    subject_id = evaluation.subject["asset_id"]
    subject_uuid = evaluation.subject["inventory_item_uuid"]
    res = evaluation.result

    props = [
        _prop("check-id", check.id),
        _prop("check-version", check.version),
        _prop("assessment-status", res.status.value),
        _prop("evidence-tier", check.evidence_tier.value),
        _prop("scope", check.scope.value),
        _prop("catalog-version", catalog.version),
        marking(classification),
    ]
    if res.confidence is not None:
        props.append(_prop("confidence", res.confidence.value))
    if res.reason is not None:
        props.append(_prop("unassessed-reason", res.reason.value))

    observation = {
        "uuid": ids.observation_uuid(result_id, check.id, subject_id),
        "title": f"{check.controls[0].control_id} / {check.id} — {subject_id}",
        "description": res.detail,
        "props": props,
        "methods": [check.method.value],
        "types": ["control-objective"],
        "subjects": [
            {"subject-uuid": subject_uuid, "type": "inventory-item", "title": subject_id}
        ],
        "collected": _ts(evaluation.collected),
        "expires": _ts(evaluation.expires),
    }
    if res.facts:
        observation["relevant-evidence"] = [
            {
                "description": "Raw collected facts supporting this observation.",
                "props": [_prop("fact-keys", ",".join(sorted(res.facts)))],
            }
        ]
    return observation


def _population(determined: list, estate_total: int) -> dict:
    """The population figures for ONE control, counted in distinct SUBJECTS.

    Every number here was previously wrong in a way that flattered the estate,
    and the two mistakes were different:

    `assessed` was computed once per RUN and stamped onto every control. A
    control determined for one host out of four reported "1 of 4 assessed
    subjects do not satisfy this control" -- quoting a 25% failure rate for
    something that failed on 100% of what was actually looked at. The three
    hosts the control was never determined for were counted into its
    denominator as though they had passed, which is the inverse of Principle 3:
    a subject a control was not determined for is neither passing nor failing,
    it is absent.

    `failing` and `na` counted EVALUATIONS, not subjects. Two checks bound to
    the same control failing on one host reported two failing subjects out of
    one. Population figures must count subjects or they are not population
    figures.

    `total` stays estate-wide and comes from inventory: the denominator is how
    many subjects were in scope, which is a property of the estate and not of
    the control. For an aggregate-scope finding it is overridden by the caller,
    because a tenant is not one of fifty workstations.
    """
    subjects_of = lambda evs: {e.subject["asset_id"] for e in evs}  # noqa: E731

    assessed = subjects_of(determined)
    failing = subjects_of([e for e in determined if e.status is Status.NOT_SATISFIED])
    # A subject is not-applicable only when EVERY determination for it says so.
    # One applicable check on a host makes that host part of the population.
    by_subject: dict = {}
    for evaluation in determined:
        by_subject.setdefault(evaluation.subject["asset_id"], []).append(evaluation)
    na = {
        asset_id
        for asset_id, evs in by_subject.items()
        if all(e.status is Status.NOT_APPLICABLE for e in evs)
    }

    return {
        "total": max(estate_total, len(assessed)),
        "assessed": len(assessed),
        "failing": len(failing),
        "na": len(na),
        "observations": len(determined),
    }


def _finding(
    result_id: str,
    control_id: str,
    statement_id: str,
    statement: str,
    evaluations: list,
    aggregation_key: str,
    population: dict,
    basis: str = "subject",
) -> dict | None:
    """One finding per (control, aggregation scope), from many observations.

    Returns None when no determination was made. That is not an omission -- it
    is the only honest encoding OSCAL 1.1.2 offers, because
    finding-target.status.state has no value meaning "undetermined".

    `population` is this CONTROL's figures, from `_population`. `basis` says
    what the numbers count: `subject` for hosts drawn from inventory, or
    `aggregate-subject` where the check judges a population from inside a
    single subject such as a directory tenant. Without it a reader cannot tell
    whether "1 of 1" describes a whole tenant or one laptop.
    """
    determined = [e for e in evaluations if e.status.emits_finding]
    if not determined:
        return None

    failing = [e for e in determined if e.status is Status.NOT_SATISFIED]
    na = [e for e in determined if e.status is Status.NOT_APPLICABLE]
    satisfied = not failing

    # The weakest confidence among contributing observations wins. An aggregate
    # verdict cannot be more certain than its least certain input.
    confidences = [e.result.confidence for e in determined if e.result.confidence]
    confidence = max(confidences, key=lambda c: c.rank).value if confidences else "direct"

    state = "satisfied" if satisfied else "not-satisfied"
    noun = "assessed subjects" if basis == "subject" else "assessed aggregate subjects"
    if failing:
        detail = (
            f"{population['failing']} of {population['assessed']} {noun} do not "
            f"satisfy this control."
        )
    else:
        detail = f"All {population['assessed']} {noun} satisfy this control."

    props = [
        _prop("assessment-status", "not-applicable" if na and satisfied and len(na) == len(determined) else state),
        _prop("confidence", confidence),
        _prop("aggregation-key", aggregation_key),
        # These four count SUBJECTS this control was determined for, not
        # evaluations and not the whole run. See `_population`.
        _prop("population-total", str(population["total"])),
        _prop("population-assessed", str(population["assessed"])),
        _prop("population-failing", str(population["failing"])),
        _prop("population-na", str(population["na"])),
        # What the numbers above count. A reader cannot otherwise tell whether
        # "1 of 1" is a whole directory tenant or a single laptop.
        _prop("population-basis", basis),
    ]

    target = {
        "type": "statement-id",
        "target-id": statement_id,
        "title": statement,
        "description": detail,
        "status": {
            "state": state,
            "reason": "pass" if satisfied else "fail",
            "remarks": (
                f"Determined from {population['observations']} observation(s) across "
                f"{population['assessed']} subject(s) at `{confidence}` confidence."
                + (
                    " Coverage is incomplete: this control was not determined for "
                    f"{population['total'] - population['assessed']} of "
                    f"{population['total']} in-scope subject(s). Those subjects are "
                    "not represented in this determination and must not be read as "
                    "passing."
                    if population["assessed"] < population["total"]
                    else ""
                )
            ),
        },
    }
    if na and len(na) == len(determined):
        # OSCAL has no not-applicable finding state. `satisfied` is defensible --
        # the objective is not violated -- and implementation-status says NA
        # explicitly so no reader is misled.
        target["implementation-status"] = {
            "state": "not-applicable",
            "remarks": na[0].result.detail,
        }

    return {
        "uuid": ids.finding_uuid(result_id, control_id, aggregation_key),
        "title": f"{control_id} {state}",
        "description": detail,
        "props": props,
        "target": target,
        "related-observations": [
            {"observation-uuid": ids.observation_uuid(result_id, e.check.id, e.subject["asset_id"])}
            for e in determined
        ],
    }


def emit_assessment_results(
    *,
    system_id: str,
    run_id: str,
    baseline: str,
    baseline_controls: list,
    evaluations: list,
    registry: Registry,
    catalog: Catalog,
    plan_href: str,
    now: dt.datetime,
    population_total: int | None = None,
    classification: str = "OFFICIAL: Sensitive",
) -> dict:
    result_id = ids.result_uuid(system_id, run_id)

    subjects = {e.subject["asset_id"]: e.subject for e in evaluations}
    # The estate denominator: how many subjects were in scope, from INVENTORY.
    # It is a property of the estate, so it is the same for every control. How
    # many of them a given control was actually determined for is a different
    # number entirely, computed per control by `_population` -- conflating the
    # two is what made every finding understate its own failure rate.
    estate_total = population_total if population_total is not None else len(subjects)

    observations = [
        _observation(result_id, ev, catalog, classification) for ev in evaluations
    ]

    by_control: dict = {}
    for ev in evaluations:
        for binding in ev.check.controls:
            by_control.setdefault(binding.control_id, []).append(ev)

    findings = []
    for control_id in sorted(by_control):
        control = catalog.require(control_id)
        contributing = by_control[control_id]
        determined = [e for e in contributing if e.status.emits_finding]
        if not determined:
            continue

        # `scope` is read here, and this is the first place in the codebase
        # that reads it for anything other than stamping a string into a prop.
        # An aggregate check judges a population from INSIDE one subject -- a
        # directory tenant, not a laptop -- so the host estate is not its
        # denominator. Reporting a tenant as "1 of 50 assessed subjects" would
        # describe a completely different population from the one judged.
        scopes = {e.check.scope for e in determined}
        aggregate_only = scopes == {Scope.AGGREGATE}

        population = _population(
            determined,
            estate_total=len(determined) if aggregate_only else estate_total,
        )
        finding = _finding(
            result_id,
            control_id,
            control.statement_id,
            control.statement,
            contributing,
            aggregation_key=f"{system_id}/{baseline}",
            population=population,
            basis="aggregate-subject" if aggregate_only else "subject",
        )
        if finding is not None:
            findings.append(finding)

    determined = {f["title"].split()[0] for f in findings}
    undetermined = [c for c in baseline_controls if c not in determined]

    # Imported here rather than at module scope: emit is the OSCAL layer and
    # should not pull the evaluation orchestrator into every importer of it.
    from ..evaluate import unassessed_controls

    undetermined_reasons = unassessed_controls(baseline_controls, registry, evaluations)

    inventory = [
        {
            "uuid": subject["inventory_item_uuid"],
            "description": subject.get("description", subject["asset_id"]),
            "props": [
                {"name": "asset-id", "value": subject["asset_id"]},
                _prop("ee-tier", subject.get("estate_tier", "current")),
            ],
        }
        for _, subject in sorted(subjects.items())
    ]

    return {
        "assessment-results": {
            "uuid": ids.resource_uuid("results", f"{system_id}:{run_id}"),
            "metadata": _metadata(
                f"Continuous assessment — {baseline} — {system_id}",
                now,
                catalog.version,
                classification,
            ),
            # Required by the schema. A results document without a plan is not
            # conformant, and the plan is also what makes absence-of-finding
            # mean "undetermined".
            "import-ap": {"href": plan_href},
            "results": [
                {
                    "uuid": result_id,
                    "title": f"{baseline} assessment run {run_id}",
                    "description": (
                        f"Automated assessment of the {baseline} baseline against "
                        f"{system_id}. {len(findings)} of {len(baseline_controls)} "
                        f"baseline controls were determined; {len(undetermined)} were "
                        f"not and are reported as unassessed rather than compliant."
                    ),
                    "start": _ts(min((e.collected for e in evaluations), default=now)),
                    "end": _ts(now),
                    "props": [
                        _prop("catalog-version", catalog.version),
                        _prop("baseline", baseline),
                        _prop("system-id", system_id),
                        _prop("run-id", run_id),
                        _prop("controls-in-baseline", str(len(baseline_controls))),
                        _prop("controls-determined", str(len(findings))),
                        _prop("controls-unassessed", str(len(undetermined))),
                        # Run-level, and genuinely run-wide: how big the estate
                        # is and how much of it this run reached. Per-control
                        # figures live on each finding and are a different
                        # number -- see `_population`.
                        _prop("subjects-in-scope", str(estate_total)),
                        _prop("subjects-assessed", str(len(subjects))),
                    ]
                    # WHY each control went undetermined, carried in the
                    # document rather than only printed to a terminal. OSCAL
                    # cannot express "not determined" in a finding, so without
                    # this a consumer sees an absent finding and has to guess
                    # between "nobody built a check", "no tool can ever answer
                    # it", "the host was unreachable" and "our code broke".
                    # Those call for completely different responses.
                    + [
                        _prop("undetermined", f"{control_id}={reason.value}")
                        for control_id, reason in sorted(undetermined_reasons.items())
                    ],
                    "local-definitions": {"inventory-items": inventory},
                    "reviewed-controls": {
                        "description": (
                            "Generated from the assessment plan, so it enumerates the "
                            "whole baseline including controls no check determined. "
                            "reviewed-controls minus findings is exactly the "
                            "unassessed set."
                        ),
                        "control-selections": [
                            {
                                "description": f"The complete {baseline} baseline.",
                                "include-controls": [
                                    {
                                        "control-id": cid,
                                        "statement-ids": [catalog.require(cid).statement_id],
                                    }
                                    for cid in baseline_controls
                                ],
                            }
                        ],
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }


# --------------------------------------------------------------------------
# POA&M
# --------------------------------------------------------------------------


def emit_poam(
    *,
    system_id: str,
    baseline: str,
    results: dict,
    now: dt.datetime,
    classification: str = "OFFICIAL: Sensitive",
) -> dict:
    """Turn not-satisfied findings into POA&M items.

    Item UUIDs are NOT run-scoped, so re-running against an unchanged estate
    produces the same item identity -- which is what lets first-observed dates,
    failure streaks and external ticket links survive across runs.
    """
    result = results["assessment-results"]["results"][0]
    items = []
    for finding in result["findings"]:
        if finding["target"]["status"]["state"] != "not-satisfied":
            continue
        control_id = finding["title"].split()[0]
        props = {p["name"]: p["value"] for p in finding.get("props", [])}
        items.append(
            {
                "uuid": ids.poam_item_uuid(
                    system_id, control_id, "aggregate", props.get("aggregation-key", baseline)
                ),
                "title": f"{control_id} not satisfied",
                "description": finding["description"],
                "props": [
                    _prop("control-id", control_id),
                    _prop("baseline", baseline),
                    _prop("poam-status", "open"),
                    _prop("confidence", props.get("confidence", "direct")),
                    _prop("population-failing", props.get("population-failing", "0")),
                    _prop("population-assessed", props.get("population-assessed", "0")),
                    marking(classification),
                ],
                "related-findings": [{"finding-uuid": finding["uuid"]}],
            }
        )

    return {
        "plan-of-action-and-milestones": {
            "uuid": ids.resource_uuid("poam", f"{system_id}:{baseline}"),
            "metadata": _metadata(
                f"Plan of action and milestones — {system_id}", now, baseline, classification
            ),
            "system-id": {
                "identifier-type": f"{NS}/system-id",
                "id": system_id,
            },
            "poam-items": items
            or [
                {
                    "uuid": ids.resource_uuid("poam-empty", system_id),
                    "title": "No open items",
                    "description": (
                        "No control was determined not-satisfied in this run. Note "
                        "that undetermined controls are not represented here; see the "
                        "assessment results for the unassessed set."
                    ),
                }
            ],
        }
    }
