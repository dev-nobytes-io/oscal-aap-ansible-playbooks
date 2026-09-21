"""Populating ASD's SSP Annex.

This is the artefact an agency hands an IRAP assessor. Two ways to ruin it:

1. **Flatten the qualifiers.** ASD's status vocabulary cannot express the
   difference between `satisfied` on direct evidence and `satisfied` on proxy
   evidence -- both write "Effective". If that difference does not reach the
   Implementation Comments cell it is gone, and somebody decides whether a
   system may hold PROTECTED data without it.

2. **Degrade the template.** The obvious implementation loads the workbook with
   a spreadsheet library and saves it; openpyxl then warns that conditional
   formatting and data validation "will be removed". That hands an agency a
   submission template whose status dropdowns no longer work. These tests pin
   the fidelity so nobody swaps the implementation back for a simpler one
   without noticing what it costs.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

import pytest

from conftest import ROOT
from nobytes_cca.report.annex import (
    ASD_STATUSES,
    COL_COMMENTS,
    COL_CONTROL,
    COL_STATUS,
    comment_for,
    populate,
    status_for,
)
from nobytes_cca.report.model import ControlRow, Report

TEMPLATE = (
    ROOT
    / "blueprint"
    / "static"
    / "content"
    / "files"
    / "Blueprint System Security Plan Annex Template (June 2026).xlsx"
)


def _report(rows) -> Report:
    return Report(
        system_id="TEST", baseline="E8_ML1", catalog_version="2026.09.4",
        run_id="test:001", generated="2026-09-21T00:00:00+00:00",
        marking="OFFICIAL: Sensitive", subjects_assessed=3, subjects_in_scope=50,
        rows=tuple(rows),
    )


@pytest.fixture(scope="module")
def populated(tmp_path_factory) -> tuple:
    if not TEMPLATE.exists():
        pytest.skip("SSP Annex template not vendored; run `make fetch`")
    rows = [
        ControlRow("ism-1488", "macros", "satisfied", confidence="proxy"),
        ControlRow("ism-1654", "IE11", "not-satisfied", confidence="direct"),
        ControlRow(
            "ism-1679", "third-party MFA", "undetermined",
            reason="requires-attestation",
            attestation={
                "source": "The third-party service register.",
                "owner": "CISO function",
                "renewal_days": "365",
                "why_not_observable": "Another organisation's tenant.",
                "title": "Third-party MFA",
            },
        ),
        ControlRow("ism-1501", "supported OS", "undetermined", reason="unreachable"),
        ControlRow("ism-1401", "MFA factors", "undetermined", reason="no-subject-in-scope"),
    ]
    report = _report(rows)
    destination = tmp_path_factory.mktemp("annex") / "out.xlsx"
    summary = populate(report, TEMPLATE, destination)
    return report, destination, summary


def _cells(path: Path) -> dict:
    """Read back {control-id: (status, comment)} from a populated Annex."""
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    from nobytes_cca.report.annex import (
        _CELL,
        _ROW,
        _cell_value,
        _col_of,
        _controls_sheet_path,
        _shared_strings,
    )

    with zipfile.ZipFile(path) as archive:
        strings = _shared_strings(archive)
        xml = archive.read(_controls_sheet_path(archive)).decode()
    out = {}
    for row in _ROW.finditer(xml):
        found = {}
        for cell in _CELL.finditer(row.group(2)):
            ref = re.search(r'r="([A-Z]+\d+)"', cell.group(1))
            if ref:
                found[_col_of(ref.group(1))] = _cell_value(
                    cell.group(1), cell.group(2), strings
                )
        identifier = found.get(COL_CONTROL, "")
        if identifier.upper().startswith("ISM-"):
            out[f"ism-{identifier.split('-')[1]}"] = (
                found.get(COL_STATUS, ""),
                found.get(COL_COMMENTS, ""),
            )
    return out


def test_the_vendored_template_is_never_modified(populated) -> None:
    """It is checksummed Commonwealth material. Editing it in place would break
    both the CC BY 4.0 attribution and `make validate`."""
    _, _, _ = populated
    manifest = ROOT / "blueprint" / "MANIFEST.json"
    import json

    expected = json.loads(manifest.read_text())["files"][
        "static/content/files/Blueprint System Security Plan Annex Template (June 2026).xlsx"
    ]["sha256"]
    assert hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() == expected


def test_only_the_controls_sheet_changes(populated) -> None:
    """Everything else copies through byte-for-byte."""
    _, destination, _ = populated
    with zipfile.ZipFile(TEMPLATE) as a, zipfile.ZipFile(destination) as b:
        assert set(a.namelist()) == set(b.namelist())
        changed = [n for n in a.namelist() if a.read(n) != b.read(n)]
    assert len(changed) == 1, f"expected only the Controls sheet to change, got {changed}"
    assert changed[0].endswith(".xml")


def test_conditional_formatting_and_validation_survive(populated) -> None:
    """The regression that made this module edit XML instead of using openpyxl.

    openpyxl warns `Conditional Formatting extension is not supported and will
    be removed`, and the same for Data Validation -- which means shipping an
    agency a submission template whose Implementation Status dropdowns are
    gone.
    """
    _, destination, _ = populated
    with zipfile.ZipFile(TEMPLATE) as a, zipfile.ZipFile(destination) as b:
        sheet = next(n for n in b.namelist() if n.endswith("sheet3.xml"))
        before, after = a.read(sheet).decode(), b.read(sheet).decode()
    for feature in ("<conditionalFormatting", "<extLst"):
        assert before.count(feature) > 0, f"template has no {feature}; test is vacuous"
        assert after.count(feature) == before.count(feature), (
            f"{feature} was lost when populating the Annex"
        )


def test_every_written_status_is_in_asds_vocabulary(populated) -> None:
    _, destination, summary = populated
    for status in summary["by_status"]:
        assert status in ASD_STATUSES
    for control_id, (status, _) in _cells(destination).items():
        if control_id in {"ism-1488", "ism-1654", "ism-1679", "ism-1501", "ism-1401"}:
            assert status in ASD_STATUSES, f"{control_id} got {status!r}"


def test_confidence_reaches_the_spreadsheet(populated) -> None:
    """The load-bearing test.

    Both write "Effective". If the comment does not distinguish them, the
    difference between a direct observation and an inference is gone from the
    submission.
    """
    report, _, _ = populated
    direct = ControlRow("ism-0001", "x", "satisfied", confidence="direct")
    proxy = ControlRow("ism-0001", "x", "satisfied", confidence="proxy")

    assert status_for(direct) == status_for(proxy) == "Effective"
    assert comment_for(direct, report) != comment_for(proxy, report)
    assert "DIRECT" in comment_for(direct, report)
    assert "PROXY" in comment_for(proxy, report)
    assert "NOT a direct observation" in comment_for(proxy, report)


def test_not_satisfied_is_ineffective_not_not_implemented() -> None:
    """We observed the control is not met. We did NOT observe that it is absent."""
    row = ControlRow("ism-0001", "x", "not-satisfied", confidence="direct")
    assert status_for(row) == "Ineffective"
    report = _report([row])
    assert "NOT determined" in comment_for(row, report)


def test_attested_becomes_no_visibility_with_its_evidence_chain(populated) -> None:
    _, destination, _ = populated
    status, comment = _cells(destination)["ism-1679"]
    assert status == "No Visibility"
    assert "NO TOOL CAN OBSERVE THIS" in comment
    assert "third-party service register" in comment
    assert "CISO function" in comment


def test_tried_and_could_not_see_differs_from_did_not_try(populated) -> None:
    """`unreachable` means we looked. `no-subject-in-scope` means we did not.

    Collapsing them would tell an assessor we looked when we did not.
    """
    _, destination, _ = populated
    cells = _cells(destination)
    assert cells["ism-1501"][0] == "No Visibility"
    assert cells["ism-1401"][0] == "Not Assessed"


def test_rows_outside_the_baseline_are_left_alone(populated) -> None:
    """An agency may already have completed them; overwriting destroys work."""
    _, destination, summary = populated
    cells = _cells(destination)
    assert len(cells) > 100, "expected the full ISM control list in the sheet"
    assert summary["written"] == 5
    untouched = [c for c in cells if c not in
                 {"ism-1488", "ism-1654", "ism-1679", "ism-1501", "ism-1401"}]
    assert untouched
    for control_id in untouched[:20]:
        assert cells[control_id][0] in ("Not Assessed", ""), (
            f"{control_id} is outside the baseline but was written to"
        )
