"""ism-1704 — unsupported applications are removed.

The control names six families: *Office productivity suites, web browsers and
their extensions, email clients, PDF applications, Adobe Flash Player, and
security products*.

The end-of-life dataset this project vendors covers three and a half of them.
Confirmed by searching endoflife.date's 477-product index rather than assumed:
there is no entry for Microsoft Edge, for any PDF reader, for email clients, or
for security products. So this check reports `partial` confidence and NAMES the
families it cannot see, because "checked and supported" and "not checked at
all" must never render the same way.

Adobe Flash Player is handled separately and deliberately. The control names it
explicitly, it is not in endoflife.date, and its end of life is a matter of
public record rather than a judgement: Adobe ended support on 2020-12-31 and
began blocking Flash content from running on 2021-01-12. Any installation found
is unsupported, with no feed required and no room for argument.
"""

from __future__ import annotations

import datetime as dt
import re

from ...contract import (
    CheckResult,
    Confidence,
    FactBundle,
    FactHistory,
    UnassessedReason,
)
from ...eol import lookup

#: Display-name patterns -> the endoflife.date product whose cycles apply.
#: Deliberately conservative: an application we cannot map confidently is
#: reported as unmapped rather than guessed at, because a wrong cycle produces
#: a confident wrong verdict about whether a product is supported.
PRODUCT_PATTERNS = (
    (re.compile(r"^Microsoft Office (Professional|Standard|Home)", re.I), "office"),
    (re.compile(r"^Microsoft Office (\d{4})", re.I), "office"),
    (re.compile(r"^Google Chrome\b", re.I), "chrome"),
    (re.compile(r"^Mozilla Firefox\b", re.I), "firefox"),
    (re.compile(r"^LibreOffice\b", re.I), "libreoffice"),
    (re.compile(r"^Java\b.*\b(SE|Development Kit|Runtime)", re.I), "oracle-jdk"),
)

#: Products the control names that no feed covers, whose end of life is public
#: record. Kept tiny and cited; this is the project's own data, not upstream.
KNOWN_DEAD = {
    re.compile(r"Adobe Flash Player", re.I): {
        "product": "Adobe Flash Player",
        "eol": dt.date(2020, 12, 31),
        "source": (
            "Adobe ended support for Flash Player on 2020-12-31 and began "
            "blocking Flash content from running on 2021-01-12."
        ),
    },
}

#: Application families ism-1704 names that the vendored dataset does not
#: cover. Reported in the evidence of every result, satisfied or not.
UNCOVERED_FAMILIES = (
    "Microsoft Edge",
    "PDF applications",
    "email clients",
    "security products",
    "web browser extensions",
)


#: Office's end-of-life cycles are RELEASE YEARS -- 2016, 2019, 2021, 2024 --
#: while every modern Office reports a version of 16.0.x. Deriving the cycle
#: from the version therefore yields "16", which matches nothing, and the
#: check silently learned nothing about the one product family the control
#: names first. The year lives in the display name instead.
_OFFICE_YEAR = re.compile(r"\b(20\d{2})\b")


def _cycle_for(product: str, name: str, version: str) -> str:
    """The dataset's cycle key for an installed application."""
    if product == "office":
        found = _OFFICE_YEAR.search(name or "")
        # No year in the name means a subscription build (Microsoft 365 Apps),
        # which is evergreen and has no cycle in the dataset. Returning empty
        # makes the lookup report unknown, which is the honest answer.
        return found.group(1) if found else ""
    # chrome / firefox / libreoffice / oracle-jdk cycles are the major version.
    return (version or "").strip().split(".")[0]


def _map_product(name: str) -> str:
    for pattern, product in PRODUCT_PATTERNS:
        if pattern.search(name or ""):
            return product
    return ""


def unsupported_applications_removed(
    bundle: FactBundle, params: dict, history: FactHistory
) -> CheckResult:
    """ism-1704 — unsupported applications are removed.

    Support is judged as of the fact's COLLECTION date, not "now", for the
    same reason ism-1501 does: re-running over archived evidence must
    reproduce the verdict that was true when the evidence was gathered.
    """
    del history

    fact = bundle.fact("windows.applications.installed")
    if fact is None:
        return CheckResult.unassessed(
            reason=UnassessedReason.COLLECTION_ERROR,
            detail="fact `windows.applications.installed` absent from the bundle",
        )
    if fact.partial:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                "at least one user profile hive could not be read, so the "
                "application inventory is incomplete; the hive not read may "
                "hold the unsupported application"
            ),
            facts={"unloaded_hives": (fact.meta or {}).get("unloaded_hives", [])},
        )

    as_of = bundle.collected.date()
    treat_extended_as_supported = bool(params.get("extended_support_counts", True))

    unsupported: list = []
    supported: list = []
    unmapped: list = []

    for app in fact.value or []:
        name = str(app.get("name", ""))
        version = str(app.get("version", ""))

        dead = next(
            (meta for pattern, meta in KNOWN_DEAD.items() if pattern.search(name)), None
        )
        if dead is not None:
            unsupported.append(
                {
                    "name": name,
                    "version": version,
                    "product": dead["product"],
                    "eol": dead["eol"].isoformat(),
                    "basis": dead["source"],
                }
            )
            continue

        product = _map_product(name)
        if not product:
            unmapped.append({"name": name, "version": version})
            continue

        cycle = _cycle_for(product, name, version)
        status = lookup(product, cycle, as_of)
        entry = {
            "name": name,
            "version": version,
            "product": product,
            "cycle": cycle,
            "eol": status.eol,
        }
        if status.unknown:
            unmapped.append({**entry, "reason": "no matching cycle in the dataset"})
        elif status.supported or (
            treat_extended_as_supported and status.in_extended_support
        ):
            supported.append(entry)
        else:
            unsupported.append({**entry, "basis": "endoflife.date"})

    facts = {
        "as_of": as_of.isoformat(),
        "applications_seen": len(fact.value or []),
        "unsupported": unsupported,
        "supported": supported,
        # Neither supported nor unsupported: no cycle matched, or the product
        # is outside the vendored dataset. Never counted as a pass.
        "unmapped_count": len(unmapped),
        "unmapped_sample": unmapped[:10],
        "families_not_covered": list(UNCOVERED_FAMILIES),
    }

    caveat = (
        f"Families this check cannot see: {', '.join(UNCOVERED_FAMILIES)}. "
        f"{len(unmapped)} installed application(s) could not be mapped to a "
        f"support timeline and are neither passed nor failed."
    )

    if unsupported:
        listed = ", ".join(f"{u['name']} {u['version']}".strip() for u in unsupported[:5])
        return CheckResult.not_satisfied(
            detail=(
                f"{len(unsupported)} unsupported application(s) present as of "
                f"{as_of.isoformat()}: {listed}. {caveat}"
            ),
            facts=facts,
            confidence=Confidence.PARTIAL,
        )

    if not supported:
        return CheckResult.unassessed(
            reason=UnassessedReason.PARTIAL_POPULATION,
            detail=(
                f"No installed application could be mapped to a support "
                f"timeline, so nothing was actually judged. {caveat}"
            ),
            facts=facts,
        )

    return CheckResult.satisfied(
        detail=(
            f"All {len(supported)} mapped application(s) were within vendor "
            f"support as of {as_of.isoformat()}. {caveat}"
        ),
        facts=facts,
        confidence=Confidence.PARTIAL,
    )
