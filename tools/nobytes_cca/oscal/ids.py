"""Deterministic OSCAL identifiers.

Every UUID is derived with UUIDv5 from the identity of the thing it names, not
generated randomly. Two consequences worth the constraint:

1. Re-running the evaluator over the same facts produces BYTE-IDENTICAL OSCAL.
   That makes golden-file tests possible, makes `git diff` on results
   meaningful, and lets an auditor independently re-derive a published document
   from its evidence bundle and compare.

2. POA&M items are NOT run-scoped. Findings and observations are ephemeral per
   run, but a POA&M item keeps the same identity across runs, so first-observed
   dates, consecutive-failure counts and external ticket links survive.

The genuinely hard part is not this scheme -- it is `asset_id`. A rebuilt
machine with the same hostname is a different asset; a renamed machine is the
same asset. Use a durable key from AD/vCenter/Intune/CMDB and treat hostname as
a label. Getting that wrong silently corrupts every trend.
"""

from __future__ import annotations

import uuid

#: Fixed forever. Changing it re-identifies every object ever emitted.
CCA_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "oscal-cca.nobytes.io")


def _v5(kind: str, *parts: str) -> str:
    return str(uuid.uuid5(CCA_NAMESPACE, kind + ":" + ":".join(parts)))


def component_uuid(system_id: str, component_key: str) -> str:
    return _v5("component", system_id, component_key)


def inventory_item_uuid(system_id: str, asset_id: str) -> str:
    return _v5("inventory-item", system_id, asset_id)


def platform_uuid(platform_id: str) -> str:
    return _v5("platform", platform_id)


def plan_uuid(system_id: str, baseline: str) -> str:
    return _v5("plan", system_id, baseline)


def result_uuid(system_id: str, run_id: str) -> str:
    return _v5("result", system_id, run_id)


def observation_uuid(result: str, check_id: str, subject: str) -> str:
    return _v5("observation", result, check_id, subject)


def finding_uuid(result: str, control_id: str, aggregation_key: str) -> str:
    return _v5("finding", result, control_id, aggregation_key)


def poam_item_uuid(system_id: str, control_id: str, check_id: str, aggregation_key: str) -> str:
    """NOT run-scoped -- that is the whole point. See the module docstring."""
    return _v5("poam", system_id, control_id, check_id, aggregation_key)


def resource_uuid(kind: str, identifier: str) -> str:
    return _v5("resource", kind, identifier)
