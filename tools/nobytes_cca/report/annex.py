"""Populate ASD's System Security Plan Annex from assessment results.

This is the artefact an agency hands an IRAP assessor, and it is where every
qualifier this project has been careful about either survives into a government
submission or gets flattened into a tick.

Three rules follow.

**A confidence qualifier must reach the spreadsheet.** ASD's Implementation
Status vocabulary has no room for the difference between a control satisfied on
`direct` evidence and one satisfied on `proxy` evidence -- both write
`Effective`. So the Implementation Comments cell carries it. A cell reading only
"Effective" would be the most expensive omission this codebase could make,
because somebody uses it to decide whether a system may hold PROTECTED data.

**The template is edited, not rebuilt.** The obvious implementation loads the
workbook with a spreadsheet library and saves it. Tried that first: openpyxl
warns `Conditional Formatting extension is not supported and will be removed`
and the same for Data Validation, which means handing an agency a submission
template whose Implementation Status dropdowns no longer exist. Silently
degrading a Commonwealth artefact to save effort is exactly what this project
refuses elsewhere. So this edits the sheet XML inside the zip and copies every
other part through byte-for-byte: conditional formatting, validation, styles
and print setup all survive because they are never touched.

That also keeps the standard-library-only constraint (ADR 0007), so the Annex
can be produced inside `ee-legacy` in an enclave with no index -- which is
precisely where an agency air-gapped enough to need this is working.

**The vendored template is never modified.** It is Commonwealth material
redistributed unmodified under CC BY 4.0 (see NOTICE) and checksummed in
`blueprint/MANIFEST.json`. This module reads it and writes a copy.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from .model import Report

#: Column letters on the "Controls" sheet, established by reading the template
#: rather than assumed: B holds `ISM-1997` style identifiers, K the
#: Implementation Status, L the Implementation Comments.
#:
#: Column J is Responsible Entity and is deliberately LEFT ALONE -- who owns a
#: control is an organisational decision, not something this tool observes.
COL_CONTROL = "B"
COL_STATUS = "K"
COL_COMMENTS = "L"

CONTROL_PATTERN = re.compile(r"^ISM-(\d{3,4})$", re.IGNORECASE)

#: ASD's own vocabulary, taken from the template's Data sheet. Writing anything
#: outside this list would break the sheet's validation and invent a category
#: ASD does not recognise.
ASD_STATUSES = (
    "Not Assessed",
    "Effective",
    "Alternate Control",
    "Not Implemented",
    "Ineffective",
    "No Visibility",
    "Not Applicable",
)

#: Every mapping below is a judgement, so it is written down rather than
#: trusted.
#:
#: `not-satisfied` -> **Ineffective**, NOT "Not Implemented". Our checks observe
#: that a required state was not met; they generally cannot tell whether the
#: control is absent or present-but-misconfigured. "Not Implemented" asserts the
#: former. "Ineffective" says what we actually know.
#:
#: `requires-attestation` -> **No Visibility**, which is literally true: no tool
#: can see a third party's tenant or an approval record. The comment then names
#: where the evidence lives and who owns it, so whoever completes the Annex
#: knows what to go and get.
#:
#: Reasons where we TRIED and could not see map to **No Visibility**; reasons
#: where we did not try map to **Not Assessed**. Collapsing the two would tell
#: an assessor we looked when we did not.
REASON_STATUS = {
    "requires-attestation": "No Visibility",
    "unreachable": "No Visibility",
    "partial-population": "No Visibility",
    "collection-error": "No Visibility",
    "insufficient-privilege": "No Visibility",
    "not-implemented": "Not Assessed",
    "no-subject-in-scope": "Not Assessed",
    "insufficient-history": "Not Assessed",
    "evaluation-error": "Not Assessed",
    "out-of-scope": "Not Applicable",
    "unsupported-platform": "Not Applicable",
}

CONFIDENCE_NOTE = {
    "direct": "DIRECT evidence: the check observes what the control requires.",
    "proxy": (
        "PROXY evidence only: the check observes something that implies the "
        "control, with stated gaps. This is NOT a direct observation."
    ),
    "partial": (
        "PARTIAL evidence: part of the control is tested; the remainder is "
        "named and untested."
    ),
    "attested": "ATTESTED: a human asserted this; nothing was automatically determined.",
}


def status_for(row) -> str:
    if row.status == "satisfied":
        return "Effective"
    if row.status == "not-satisfied":
        return "Ineffective"
    return REASON_STATUS.get(row.reason or "", "Not Assessed")


def comment_for(row, report: Report) -> str:
    """The cell that carries everything the status column cannot."""
    parts = [
        (
            f"Automated assessment {report.run_id} against ISM "
            f"{report.catalog_version} ({report.baseline}), "
            f"{report.subjects_assessed} of {report.subjects_in_scope} "
            f"subjects in scope assessed."
        )
    ]

    if row.is_determined:
        parts.append(
            CONFIDENCE_NOTE.get(row.confidence or "")
            or f"Confidence: {row.confidence or 'unqualified'}."
        )
        if row.status == "not-satisfied":
            parts.append(
                "Assessed as not meeting the control. Whether it is absent or "
                "present-but-misconfigured was NOT determined."
            )
        failing = row.population.get("population-failing")
        if failing:
            parts.append(
                f"{failing} of {row.population.get('population-assessed', '?')} "
                f"assessed subjects failed."
            )
    else:
        parts.append(f"Not determined by automation: {row.reason}.")
        att = row.attestation
        if att:
            parts.append(
                f"NO TOOL CAN OBSERVE THIS. {att.get('why_not_observable', '')} "
                f"Evidence is held at: {att.get('source', 'not recorded')} "
                f"Answerable: {att.get('owner', 'not recorded')}. "
                f"Renews every {att.get('renewal_days', '?')} days."
            )

    parts.append(
        "Generated, not authored. Review before submission; this project is not "
        "endorsed by ASD or the Commonwealth."
    )
    return " ".join(p.strip() for p in parts if p and p.strip())


# ---------------------------------------------------------------------------
# Minimal OOXML editing. Deliberately narrow: locate one sheet, rewrite two
# cells per matched row, copy everything else through untouched.
# ---------------------------------------------------------------------------

_CELL = re.compile(r"<c\b([^>]*?)(?:/>|>(.*?)</c>)", re.S)
_ROW = re.compile(r"<row\b([^>]*)>(.*?)</row>", re.S)


def _col_of(ref: str) -> str:
    return "".join(ch for ch in ref if ch.isalpha())


def _col_index(letters: str) -> int:
    value = 0
    for ch in letters.upper():
        value = value * 26 + (ord(ch) - 64)
    return value


def _shared_strings(archive: zipfile.ZipFile) -> list:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    blob = archive.read("xl/sharedStrings.xml").decode("utf-8", "replace")
    return [
        "".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.S))
        for si in re.findall(r"<si>(.*?)</si>", blob, re.S)
    ]


def _controls_sheet_path(archive: zipfile.ZipFile) -> str:
    workbook = archive.read("xl/workbook.xml").decode("utf-8", "replace")
    rels = archive.read("xl/_rels/workbook.xml.rels").decode("utf-8", "replace")
    targets = dict(re.findall(r'Id="([^"]+)"[^>]*Target="([^"]+)"', rels))
    for name, rid in re.findall(r'<sheet name="([^"]+)"[^>]*r:id="([^"]+)"', workbook):
        if name.startswith("Controls"):
            return "xl/" + targets[rid].lstrip("/")
    raise ValueError(
        "No 'Controls' sheet in the Annex template; its layout has changed and "
        "this mapping must be re-checked before it is trusted."
    )


def _cell_value(attrs: str, body: str, strings: list) -> str:
    raw = re.search(r"<v>(.*?)</v>", body or "", re.S)
    if 't="inlineStr"' in attrs:
        inline = re.search(r"<t[^>]*>(.*?)</t>", body or "", re.S)
        return inline.group(1) if inline else ""
    if not raw:
        return ""
    if 't="s"' in attrs and raw.group(1).isdigit():
        index = int(raw.group(1))
        return strings[index] if index < len(strings) else ""
    return raw.group(1)


def _inline_cell(ref: str, style_attrs: str, text: str) -> str:
    style = re.search(r'\ss="(\d+)"', style_attrs or "")
    style_part = f' s="{style.group(1)}"' if style else ""
    return (
        f'<c r="{ref}"{style_part} t="inlineStr">'
        f'<is><t xml:space="preserve">{escape(text)}</t></is></c>'
    )


def _rewrite_row(row_attrs: str, row_body: str, updates: dict, strings: list) -> str:
    """Replace or insert the target cells, keeping column order."""
    kept = []
    for match in _CELL.finditer(row_body):
        attrs = match.group(1)
        ref = re.search(r'r="([A-Z]+\d+)"', attrs)
        if ref is None:
            kept.append((None, match.group(0), attrs))
            continue
        column = _col_of(ref.group(1))
        if column in updates:
            kept.append((column, _inline_cell(ref.group(1), attrs, updates[column]), attrs))
            del updates[column]
        else:
            kept.append((column, match.group(0), attrs))

    row_number = re.search(r'r="(\d+)"', row_attrs)
    number = row_number.group(1) if row_number else ""
    for column, text in updates.items():
        kept.append((column, _inline_cell(f"{column}{number}", "", text), ""))

    kept.sort(key=lambda item: _col_index(item[0]) if item[0] else 0)
    return f"<row{row_attrs}>" + "".join(cell for _, cell, _ in kept) + "</row>"


def populate(report: Report, template: Path, destination: Path) -> dict:
    """Write a populated copy of the SSP Annex. The template is never touched."""
    if not template.exists():
        raise FileNotFoundError(
            f"No SSP Annex template at {template}. Run `make fetch` to vendor it."
        )

    rows_by_control = {r.control_id: r for r in report.rows}
    written = 0
    by_status: dict = {}

    with zipfile.ZipFile(template) as archive:
        strings = _shared_strings(archive)
        sheet_path = _controls_sheet_path(archive)
        sheet_xml = archive.read(sheet_path).decode("utf-8")

        def replace_row(match: re.Match) -> str:
            nonlocal written
            attrs, body = match.group(1), match.group(2)
            identifier = ""
            for cell in _CELL.finditer(body):
                ref = re.search(r'r="([A-Z]+\d+)"', cell.group(1))
                if ref and _col_of(ref.group(1)) == COL_CONTROL:
                    identifier = _cell_value(cell.group(1), cell.group(2), strings)
                    break
            found = CONTROL_PATTERN.match(identifier.strip())
            if not found:
                return match.group(0)
            row = rows_by_control.get(f"ism-{found.group(1)}")
            if row is None:
                # Outside the assessed baseline. Left exactly as ASD shipped it:
                # writing "Not Assessed" over a cell an agency may already have
                # completed would destroy their work.
                return match.group(0)
            status = status_for(row)
            if status not in ASD_STATUSES:  # pragma: no cover - guarded by tests
                return match.group(0)
            written += 1
            by_status[status] = by_status.get(status, 0) + 1
            return _rewrite_row(
                attrs,
                body,
                {COL_STATUS: status, COL_COMMENTS: comment_for(row, report)},
                strings,
            )

        updated = _ROW.sub(replace_row, sheet_xml)

        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as handle:
            staging = Path(handle.name)
        try:
            with zipfile.ZipFile(staging, "w", zipfile.ZIP_DEFLATED) as out:
                for item in archive.infolist():
                    payload = (
                        updated.encode("utf-8")
                        if item.filename == sheet_path
                        else archive.read(item.filename)
                    )
                    out.writestr(item, payload)
            shutil.move(str(staging), str(destination))
        finally:
            if staging.exists():  # pragma: no cover - only on a failed move
                staging.unlink()

    return {
        "written": written,
        "by_status": dict(sorted(by_status.items())),
        "baseline_controls": len(report.rows),
        "destination": str(destination),
    }
