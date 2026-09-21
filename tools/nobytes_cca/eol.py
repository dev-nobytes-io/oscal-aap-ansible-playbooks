"""Operating-system vendor-support lookup.

Backs ism-1501 ("Operating systems that are no longer supported by vendors are
replaced"), ism-1704 and ism-1905.

Two design points worth stating, because both affect what the verdict means:

1. **Support is judged as of the fact's collection date, not "now".** Evaluators
   are pure and cannot read a clock, and that constraint turns out to be
   correct here rather than merely tolerated: an assessment re-run over archived
   evidence must reproduce the verdict that was true when the evidence was
   gathered, not a different one because time passed.

2. **The dataset is community-maintained, not vendor-authoritative.** Checks
   consuming it report `proxy` confidence. A deployment can override entries
   with vendor-confirmed dates; the override is recorded in the evidence.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass

#: Maps what a collector reports to an endoflife.date product file.
PRODUCT_FILES = {
    "redhat": "rhel.json",
    "rhel": "rhel.json",
    "rocky": "rocky-linux.json",
    "ubuntu": "ubuntu.json",
    "debian": "debian.json",
    "windows": "windows.json",
    "windows-server": "windows-server.json",
    # Applications -- ism-1704. Slugs confirmed against the endoflife.date
    # index rather than guessed: `microsoft-office` and `google-chrome` 404.
    "office": "office.json",
    "chrome": "chrome.json",
    "firefox": "firefox.json",
    "libreoffice": "libreoffice.json",
    "oracle-jdk": "oracle-jdk.json",
}


@dataclass(frozen=True)
class SupportStatus:
    product: str
    cycle: str
    eol: str | None
    extended_support: str | None
    supported: bool
    in_extended_support: bool
    #: True when no matching cycle was found. NOT the same as unsupported --
    #: an unknown OS must produce `unassessed`, never a failure.
    unknown: bool = False
    source: str = "endoflife.date"

    @property
    def reason(self) -> str:
        if self.unknown:
            if self.source.startswith("ambiguous:"):
                return f"release matches multiple support cycles ({self.source})"
            return "no end-of-life record for this release"
        if self.supported:
            return f"vendor support runs to {self.eol}"
        if self.in_extended_support:
            return (
                f"mainstream support ended {self.eol}; extended support runs to "
                f"{self.extended_support}"
            )
        return f"vendor support ended {self.eol}"


def _load(product_file: str) -> list:
    from .paths import eol_dir

    path = eol_dir() / product_file
    if not path.exists():
        raise FileNotFoundError(f"EOL data missing: {path}. Run `make fetch`.")
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _as_date(value: object) -> dt.date | None:
    """endoflife.date uses a date string, or `true`/`false` for 'still supported'."""
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def lookup(product: str, cycle: str, as_of: dt.date) -> SupportStatus:
    """Support status for a release, judged as of a given date."""
    key = product.strip().lower()
    product_file = PRODUCT_FILES.get(key)
    if product_file is None:
        return SupportStatus(product, cycle, None, None, False, False, unknown=True)

    cycles = _load(product_file)
    wanted = cycle.strip().lower()

    match = next(
        (e for e in cycles if str(e.get("cycle", "")).strip().lower() == wanted), None
    )

    if match is None:
        # Linux collectors report 9.4 where the dataset tracks 9.
        major = wanted.split(".")[0]
        match = next(
            (e for e in cycles if str(e.get("cycle", "")).strip().lower() == major), None
        )

    if match is None:
        # Windows cycles are edition-qualified: `10-22h2`, `11-24h2-e` (Enterprise)
        # vs `11-24h2-w` (Pro/Home). A collector that reported only `11-24h2`
        # matches several.
        candidates = [
            e
            for e in cycles
            if str(e.get("cycle", "")).strip().lower().startswith(wanted + "-")
        ]
        if len(candidates) == 1:
            match = candidates[0]
        elif len(candidates) > 1:
            # Refuse to guess. Picking an edition would silently attach a
            # support date that may be years out -- Windows 11 24H2 Enterprise
            # and Pro differ by a full year. An ambiguous answer is `unknown`,
            # which becomes `unassessed`, not a verdict.
            return SupportStatus(
                product,
                cycle,
                None,
                None,
                False,
                False,
                unknown=True,
                source=(
                    "ambiguous: "
                    + ", ".join(sorted(str(c.get("cycle")) for c in candidates))
                    + " - collector must report the edition"
                ),
            )

    if match is None:
        return SupportStatus(product, cycle, None, None, False, False, unknown=True)

    raw_eol = match.get("eol")
    raw_ext = match.get("extendedSupport")

    # `eol: false` means "still supported, no announced date".
    if raw_eol is False:
        return SupportStatus(product, str(match.get("cycle")), None, None, True, False)

    eol_date = _as_date(raw_eol)
    ext_date = _as_date(raw_ext)

    if eol_date is None:
        return SupportStatus(
            product, str(match.get("cycle")), None, None, False, False, unknown=True
        )

    mainstream_ok = as_of <= eol_date
    extended_ok = ext_date is not None and as_of <= ext_date

    return SupportStatus(
        product=product,
        cycle=str(match.get("cycle")),
        eol=eol_date.isoformat(),
        extended_support=ext_date.isoformat() if ext_date else None,
        supported=mainstream_ok,
        in_extended_support=(not mainstream_ok) and extended_ok,
    )
