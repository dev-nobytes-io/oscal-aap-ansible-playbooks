"""Generate OSCAL component-definitions from the check registry.

This is the binding layer (ADR 0003): it records which platform can evidence
which control, via which collector and evaluator, and at what confidence.

Generated, never hand-written. The point is that coverage becomes queryable
data rather than a claim -- "which ML1 controls can we test on Windows?" is a
query over these documents, and the coverage ledger is derived from them so it
cannot drift into flattery.
"""

from __future__ import annotations

import datetime as dt

from ..catalog import Catalog
from ..oscal import NS, OSCAL_VERSION, ids
from ..registry import Registry

#: OSCAL defined-component types. Picked per platform family, because a
#: component is not always a machine: CyberArk and Splunk are `service`
#: components that hold evidence ABOUT a control rather than being constrained
#: by it.
COMPONENT_TYPES = {
    "windows": "software",
    "linux": "software",
    "entra-id": "service",
    "active-directory": "service",
    "adcs": "service",
    "adfs": "service",
    "keycloak": "service",
    "exchange": "service",
    "cyberark": "service",
    "netapp": "hardware",
    "splunk": "service",
    "change-auditor": "service",
    "vmware": "service",
    "proxmox": "service",
    "xcp-ng": "service",
    "containers": "software",
    "kubernetes": "service",
    "network": "hardware",
    "cloud": "service",
    # Not a system we run. Controls about a third party's tenant, a customer
    # identity estate or an approval record have no technical component to
    # bind to, so they bind to the organisation itself and are only ever
    # attested.
    "organisation": "policy",
}


def _prop(name: str, value: str) -> dict:
    return {"name": name, "ns": NS, "value": str(value)}


def generate(registry: Registry, catalog: Catalog, now: dt.datetime) -> dict:
    """One component-definition covering every component the registry names."""
    by_component: dict = {}
    for check in registry:
        by_component.setdefault((check.component, check.platform_family), []).append(check)

    components = []
    for (component_key, platform), checks in sorted(by_component.items()):
        implemented = []
        for check in sorted(checks, key=lambda c: c.id):
            for binding in check.controls:
                control = catalog.require(binding.control_id)
                implemented.append(
                    {
                        "uuid": ids.resource_uuid(
                            "implemented-requirement",
                            f"{component_key}:{check.id}:{binding.control_id}",
                        ),
                        "control-id": binding.control_id,
                        "description": binding.rationale.strip(),
                        "props": [
                            _prop("check-id", check.id),
                            _prop("check-version", check.version),
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
                                _prop(
                                    "attestation-renewal-days",
                                    str(check.attestation.renewal_days),
                                ),
                                _prop(
                                    "why-not-observable",
                                    check.attestation.why_not_observable,
                                ),
                            ]
                        )
                        + [
                            _prop("method", check.method.value),
                            _prop("confidence", check.confidence.value),
                            _prop("coverage", binding.coverage),
                            _prop("scope", check.scope.value),
                            _prop("evidence-tier", check.evidence_tier.value),
                            _prop("freshness-hours", check.freshness_hours),
                            _prop("history-window-days", check.history_window_days),
                            _prop("control-revision", binding.control_revision),
                            _prop("statement-sha256", binding.statement_sha256),
                        ],
                        "statements": [
                            {
                                "statement-id": binding.statement_id,
                                "uuid": ids.resource_uuid(
                                    "statement", f"{component_key}:{binding.statement_id}"
                                ),
                                "description": control.statement,
                            }
                        ],
                        "remarks": (
                            f"Residual assessment gap: {binding.rationale.strip()}"
                        ),
                    }
                )

        components.append(
            {
                "uuid": ids.component_uuid("catalog", component_key),
                "type": COMPONENT_TYPES.get(platform, "software"),
                "title": component_key.replace("-", " ").title(),
                "description": (
                    f"Assessment coverage provided by nobytes.compliance collectors "
                    f"and nobytes_cca evaluators for {component_key}. This document "
                    f"asserts what is ASSESSED, not what is implemented."
                ),
                "props": [
                    _prop("platform-family", platform),
                    _prop("component-key", component_key),
                ],
                "control-implementations": [
                    {
                        "uuid": ids.resource_uuid("control-implementation", component_key),
                        "source": f"../upstream/ism/v{catalog.version}/ISM_catalog.json",
                        "description": (
                            "Controls this component can produce evidence for. A control "
                            "absent from this list is not assessed on this platform."
                        ),
                        "props": [_prop("implementation-kind", "assessment")],
                        "implemented-requirements": implemented,
                    }
                ],
            }
        )

    return {
        "component-definition": {
            "uuid": ids.resource_uuid("component-definition", "nobytes-cca"),
            "metadata": {
                "title": "Continuous compliance assessment coverage",
                "last-modified": now.isoformat(),
                "version": catalog.version,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _prop("catalog-version", catalog.version),
                    _prop(
                        "generated-by",
                        "nobytes_cca.generate.component_definitions",
                    ),
                ],
            },
            "components": components,
        }
    }
