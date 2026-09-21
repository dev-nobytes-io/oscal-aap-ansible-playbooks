"""Render a Report as Markdown or self-contained HTML.

Both renderers go through `ControlRow.display_status`, which fuses status and
confidence into one string. That is not a style choice: a template that can
render the status without the qualifier eventually will, and "satisfied" on
proxy evidence reading identically to "satisfied" on direct evidence destroys
the distinction the whole pipeline exists to produce.
"""

from __future__ import annotations

import html

from .model import Report

#: What each undetermined reason actually means to the person reading. Written
#: out because a bare enum value tells an executive nothing, and the difference
#: between these is the difference between "buy a tool", "chase a supplier" and
#: "our tooling is broken".
REASON_MEANING = {
    "not-implemented": "No check has been built for this control yet.",
    "requires-attestation": (
        "No tool can observe this. It requires a human attestation -- see the "
        "attestation register below."
    ),
    "no-subject-in-scope": (
        "A check exists and works, but this run included no system it applies "
        "to. Widen the scope to assess it."
    ),
    "unreachable": "The system could not be reached. Not a compliance failure.",
    "insufficient-privilege": "The collector lacked the rights to read the evidence.",
    "insufficient-history": (
        "The control is a rate ('within 48 hours'). Not enough history has been "
        "gathered yet to judge it."
    ),
    "partial-population": (
        "Only part of the evidence could be read. The unread part may be the "
        "part that fails, so no verdict is claimed."
    ),
    "unsupported-platform": "This platform is out of the check's declared support.",
    "collection-error": "Evidence collection failed.",
    "evaluation-error": "OUR CODE failed while evaluating. This is a defect to report.",
    "out-of-scope": "Deliberately excluded from this assessment.",
}

_PREAMBLE = (
    "This report states what could be **observed**, at what **confidence**, and "
    "what could not be observed and **why**. It is not a compliance "
    "certificate. A control shown as satisfied has been observed to the stated "
    "confidence and no further; where this project and the ISM disagree, the "
    "ISM is authoritative."
)


def _pct(part: int, whole: int) -> str:
    return f"{(100 * part / whole):.1f}%" if whole else "n/a"


def markdown(report: Report) -> str:
    satisfied = report.by_status("satisfied")
    failed = report.by_status("not-satisfied")
    undetermined = [r for r in report.rows if not r.is_determined]

    out = [
        f"# Assessment report — {report.baseline} — {report.system_id}",
        "",
        f"**{report.marking}**",
        "",
        _PREAMBLE,
        "",
        "| | |",
        "|---|---|",
        f"| System | `{report.system_id}` |",
        f"| Baseline | {report.baseline} |",
        f"| ISM catalogue | {report.catalog_version} |",
        f"| Run | `{report.run_id}` |",
        f"| Generated | {report.generated} |",
        (
            f"| Subjects assessed | {report.subjects_assessed} of "
            f"{report.subjects_in_scope} in scope |"
        ),
        "",
        "## Where this assessment stands",
        "",
        f"Of **{len(report.rows)}** controls in the baseline:",
        "",
        f"- **{len(satisfied)} satisfied** ({_pct(len(satisfied), len(report.rows))})",
        f"- **{len(failed)} not satisfied** ({_pct(len(failed), len(report.rows))})",
        (
            f"- **{len(undetermined)} undetermined** "
            f"({_pct(len(undetermined), len(report.rows))}) — see why, below"
        ),
        "",
    ]

    if report.subjects_assessed < report.subjects_in_scope:
        out += [
            (
                f"> **{report.subjects_in_scope - report.subjects_assessed} of "
                f"{report.subjects_in_scope} subjects in scope were not "
                f"assessed.** Every figure above describes only the "
                f"{report.subjects_assessed} that were. A control can read as "
                f"satisfied here while failing on a system this run never "
                f"reached."
            ),
            "",
        ]

    out += [
        "### Determined controls, by confidence",
        "",
        (
            "Confidence is how closely the check observes what the control "
            "actually requires. It is a ceiling, not a score, and it is never "
            "dropped."
        ),
        "",
        "| Confidence | Controls | Means |",
        "|---|---:|---|",
    ]
    meanings = {
        "direct": "The check observes what the control requires.",
        "proxy": "It observes something that implies it, with stated gaps.",
        "partial": "Part of the control is tested; the rest is named.",
        "attested": "A human asserted it; nothing was automatically determined.",
    }
    for confidence, count in report.confidence_counts.items():
        out.append(f"| `{confidence}` | {count} | {meanings.get(confidence, '')} |")
    out += ["", "### Undetermined controls, by reason", ""]
    out += ["| Reason | Controls | Means |", "|---|---:|---|"]
    for reason, count in report.reason_counts.items():
        out.append(f"| `{reason}` | {count} | {REASON_MEANING.get(reason, '')} |")

    out += ["", "## Every control", "", "| Control | Status | Statement |", "|---|---|---|"]
    for row in report.rows:
        statement = row.statement.replace("|", "\\|")
        if len(statement) > 150:
            statement = statement[:147] + "..."
        out.append(f"| `{row.control_id}` | {row.display_status} | {statement} |")

    attested = report.attested
    if attested:
        out += [
            "",
            "## Attestation register",
            "",
            (
                "These controls cannot be observed by any tool. They are "
                "**not** counted as automated coverage, and they are **not** "
                "failures — they require a human statement, and this is where "
                "that statement must come from."
            ),
            "",
        ]
        for row in attested:
            att = row.attestation
            out += [
                f"### `{row.control_id}` — {att.get('title', '')}",
                "",
                f"> {row.statement}",
                "",
                f"- **Why no tool can observe it**: {att.get('why_not_observable', 'not recorded')}",
                f"- **Where the evidence lives**: {att.get('source', 'not recorded')}",
                f"- **Who is answerable**: {att.get('owner', 'not recorded')}",
                f"- **Renews every**: {att.get('renewal_days', '?')} days",
                "",
            ]

    out += [
        "",
        "---",
        "",
        (
            "Generated by [oscal-aap-ansible-playbooks]"
            "(https://github.com/dev-nobytes-io/oscal-aap-ansible-playbooks). "
            "Not affiliated with, endorsed by, or approved by the Australian "
            "Signals Directorate, the Australian Cyber Security Centre, or the "
            "Commonwealth of Australia."
        ),
        "",
    ]
    return "\n".join(out)


_CSS = """
:root { --fg:#1a1a1a; --muted:#666; --line:#ddd; --bg:#fff;
        --ok:#0a6a3a; --bad:#a61b1b; --unk:#7a5c00; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e8e8e8; --muted:#a0a0a0; --line:#3a3a3a; --bg:#161616;
          --ok:#5fd18f; --bad:#ff8a8a; --unk:#e8c65c; }
}
* { box-sizing:border-box; }
body { margin:0 auto; padding:2rem 1rem; max-width:64rem; background:var(--bg);
       color:var(--fg); font:16px/1.55 -apple-system,BlinkMacSystemFont,
       "Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
h1,h2,h3 { line-height:1.25; }
h1 { font-size:1.8rem; margin-bottom:.25rem; }
h2 { margin-top:2.5rem; border-bottom:1px solid var(--line); padding-bottom:.3rem; }
table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.94rem; }
th,td { border:1px solid var(--line); padding:.45rem .6rem; text-align:left;
        vertical-align:top; }
th { background:rgba(127,127,127,.12); }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.9em; }
.marking { display:inline-block; font-weight:700; letter-spacing:.06em;
           border:2px solid var(--fg); padding:.2rem .6rem; margin:.5rem 0 1rem; }
.s-satisfied { color:var(--ok); font-weight:600; }
.s-not-satisfied { color:var(--bad); font-weight:600; }
.s-undetermined { color:var(--unk); font-weight:600; }
.qualifier { color:var(--muted); font-weight:400; }
.note { border-left:4px solid var(--unk); padding:.6rem .9rem; margin:1rem 0;
        background:rgba(127,127,127,.08); }
footer { margin-top:3rem; color:var(--muted); font-size:.85rem;
         border-top:1px solid var(--line); padding-top:1rem; }
@media (max-width:640px){ body{padding:1rem;} table{font-size:.85rem;} }
"""


def _status_html(row) -> str:
    """Status and qualifier, always together, never one without the other."""
    cls = f"s-{row.status}"
    if row.status == "undetermined":
        qualifier = row.reason or "unknown reason"
    else:
        qualifier = row.confidence or "unqualified"
    return (
        f'<span class="{cls}">{html.escape(row.status)}</span> '
        f'<span class="qualifier">({html.escape(qualifier)})</span>'
    )


def to_html(report: Report) -> str:
    satisfied = report.by_status("satisfied")
    failed = report.by_status("not-satisfied")
    undetermined = [r for r in report.rows if not r.is_determined]
    e = html.escape

    rows_html = "\n".join(
        f"<tr><td><code>{e(r.control_id)}</code></td><td>{_status_html(r)}</td>"
        f"<td>{e(r.statement)}</td></tr>"
        for r in report.rows
    )
    conf_html = "\n".join(
        f"<tr><td><code>{e(c)}</code></td><td>{n}</td></tr>"
        for c, n in report.confidence_counts.items()
    )
    reason_html = "\n".join(
        f"<tr><td><code>{e(r)}</code></td><td>{n}</td>"
        f"<td>{e(REASON_MEANING.get(r, ''))}</td></tr>"
        for r, n in report.reason_counts.items()
    )

    partial_note = ""
    if report.subjects_assessed < report.subjects_in_scope:
        missing = report.subjects_in_scope - report.subjects_assessed
        partial_note = (
            f'<p class="note"><strong>{missing} of {report.subjects_in_scope} '
            f"subjects in scope were not assessed.</strong> Every figure here "
            f"describes only the {report.subjects_assessed} that were. A control "
            f"can read as satisfied while failing on a system this run never "
            f"reached.</p>"
        )

    attested_html = ""
    if report.attested:
        blocks = []
        for row in report.attested:
            att = row.attestation
            blocks.append(
                f"<h3><code>{e(row.control_id)}</code> — {e(att.get('title', ''))}</h3>"
                f"<blockquote>{e(row.statement)}</blockquote><ul>"
                f"<li><strong>Why no tool can observe it</strong>: "
                f"{e(att.get('why_not_observable', 'not recorded'))}</li>"
                f"<li><strong>Where the evidence lives</strong>: "
                f"{e(att.get('source', 'not recorded'))}</li>"
                f"<li><strong>Who is answerable</strong>: "
                f"{e(att.get('owner', 'not recorded'))}</li>"
                f"<li><strong>Renews every</strong>: "
                f"{e(str(att.get('renewal_days', '?')))} days</li></ul>"
            )
        attested_html = (
            "<h2>Attestation register</h2><p>These controls cannot be observed "
            "by any tool. They are <strong>not</strong> counted as automated "
            "coverage, and they are <strong>not</strong> failures — they require "
            "a human statement, and this is where that statement must come "
            "from.</p>" + "".join(blocks)
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment report — {e(report.baseline)} — {e(report.system_id)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>Assessment report — {e(report.baseline)} — {e(report.system_id)}</h1>
<div class="marking">{e(report.marking)}</div>
<p>{_PREAMBLE.replace('**', '')}</p>
<table>
<tr><th>System</th><td><code>{e(report.system_id)}</code></td></tr>
<tr><th>Baseline</th><td>{e(report.baseline)}</td></tr>
<tr><th>ISM catalogue</th><td>{e(report.catalog_version)}</td></tr>
<tr><th>Run</th><td><code>{e(report.run_id)}</code></td></tr>
<tr><th>Generated</th><td>{e(report.generated)}</td></tr>
<tr><th>Subjects assessed</th><td>{report.subjects_assessed} of
    {report.subjects_in_scope} in scope</td></tr>
</table>

<h2>Where this assessment stands</h2>
<p>Of <strong>{len(report.rows)}</strong> controls in the baseline:</p>
<ul>
<li><span class="s-satisfied">{len(satisfied)} satisfied</span>
    ({_pct(len(satisfied), len(report.rows))})</li>
<li><span class="s-not-satisfied">{len(failed)} not satisfied</span>
    ({_pct(len(failed), len(report.rows))})</li>
<li><span class="s-undetermined">{len(undetermined)} undetermined</span>
    ({_pct(len(undetermined), len(report.rows))})</li>
</ul>
{partial_note}

<h3>Determined controls, by confidence</h3>
<p>Confidence is how closely the check observes what the control actually
requires. It is a ceiling, not a score, and it is never dropped.</p>
<table><tr><th>Confidence</th><th>Controls</th></tr>{conf_html}</table>

<h3>Undetermined controls, by reason</h3>
<table><tr><th>Reason</th><th>Controls</th><th>Means</th></tr>{reason_html}</table>

<h2>Every control</h2>
<table><tr><th>Control</th><th>Status</th><th>Statement</th></tr>{rows_html}</table>

{attested_html}

<footer>Generated by
<a href="https://github.com/dev-nobytes-io/oscal-aap-ansible-playbooks">oscal-aap-ansible-playbooks</a>.
Not affiliated with, endorsed by, or approved by the Australian Signals
Directorate, the Australian Cyber Security Centre, or the Commonwealth of
Australia.</footer>
</body>
</html>
"""
