"""Vendor-support checks, shared across platform families."""

from __future__ import annotations

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)
from ...eol import lookup


def _windows_cycle(value: dict) -> str:
    """Derive an endoflife.date cycle key from raw Windows registry identity.

    Interpretation, deliberately here rather than in the collector, so it is
    unit-testable without a Windows host.

    Server SKUs are unambiguous: the product year in ProductName. Windows 10 is
    unambiguous: a single `10-<release>` cycle. Windows 11 is NOT -- Enterprise
    (`-e`) and Pro (`-w`) support dates differ by a full year -- so unless the
    edition is known, an ambiguous key is returned deliberately and the lookup
    reports unknown rather than guessing.
    """
    import re

    product = str(value.get("product_name", ""))
    release = str(value.get("display_version", "")).lower()
    edition = str(value.get("edition_id", "")).lower()

    if str(value.get("install_type", "")) == "Server":
        match = re.search(r"\b(20\d{2})\b", product)
        if match:
            year = match.group(1)
            # 2012 R2 is a distinct cycle from 2012.
            return f"{year}-r2" if "r2" in product.lower() else year
        return ""

    major = "11" if "windows 11" in product.lower() else "10" if "windows 10" in product.lower() else ""
    if not major or not release:
        return ""
    if major == "10":
        return f"10-{release}"
    # Windows 11: only resolvable when the edition is known.
    if "enterprise" in edition or "education" in edition:
        return f"11-{release}-e"
    if "professional" in edition or "core" in edition or "home" in edition:
        return f"11-{release}-w"
    return f"11-{release}"  # ambiguous on purpose; lookup() will say so


def vendor_supported(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1501 — operating systems no longer supported by vendors are replaced.

    Judged **as of the fact's collection date**, not "now". Evaluators cannot
    read a clock, and here that constraint is correct rather than merely
    tolerated: re-running an assessment over archived evidence must reproduce
    the verdict that was true when the evidence was gathered.

    An unrecognised release yields `unassessed`, never `not-satisfied`. Not
    knowing whether something is supported is not the same as knowing it is not.
    """
    del history

    release = bundle.fact("os.release")
    if release is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `os.release` absent from the bundle",
        )

    value = release.value or {}
    product = value.get("eol_product")
    cycle = value.get("eol_cycle")
    if product in ("windows", "windows-server") and not cycle:
        cycle = _windows_cycle(value)
    if not product or not cycle:
        return CheckResult.unassessed(
            reason=UnassessedReason.UNSUPPORTED_PLATFORM,
            detail=(
                "The collector did not report an end-of-life product/cycle for this "
                "system, so its support status cannot be determined."
            ),
            facts={"observed": value},
        )

    status = lookup(product, cycle, bundle.collected.date())
    facts = {
        "product": status.product,
        "cycle": status.cycle,
        "eol": status.eol,
        "extended_support": status.extended_support,
        "supported": status.supported,
        "in_extended_support": status.in_extended_support,
        "assessed_as_of": bundle.collected.date().isoformat(),
        "dataset": "endoflife.date (community-maintained, not vendor-authoritative)",
        "observed": value,
    }

    if status.unknown:
        return CheckResult.unassessed(
            reason=UnassessedReason.UNSUPPORTED_PLATFORM,
            detail=(
                f"No usable end-of-life record for {product} {cycle}: {status.reason}. "
                f"Not knowing whether a release is supported is not evidence that it "
                f"is unsupported."
            ),
            facts=facts,
        )

    if status.supported:
        return CheckResult.satisfied(
            detail=(
                f"{status.product} {status.cycle} is within vendor support as of "
                f"{facts['assessed_as_of']} ({status.reason})."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    if status.in_extended_support:
        if params.get("extended_support_counts_as_supported", True):
            return CheckResult.satisfied(
                detail=(
                    f"{status.product} {status.cycle} is PAST mainstream support and "
                    f"relies on paid extended support: {status.reason}. The vendor is "
                    f"still issuing patches, so the control's wording is met, but this "
                    f"is a degraded state with a hard end date."
                ),
                facts=facts,
                confidence=Confidence.PROXY,
            )
        return CheckResult.not_satisfied(
            detail=(
                f"{status.product} {status.cycle} relies on paid extended support "
                f"({status.reason}), which this deployment treats as unsupported."
            ),
            facts=facts,
            confidence=Confidence.PROXY,
        )

    return CheckResult.not_satisfied(
        detail=(
            f"{status.product} {status.cycle} is no longer supported by its vendor: "
            f"{status.reason}. Assessed as of {facts['assessed_as_of']}."
        ),
        facts=facts,
        confidence=Confidence.PROXY,
    )
