# Check registry

One YAML file per check. This is the authoring surface: a contributor adding
evidence collection for a control writes a registry entry here and an evaluator
function — and nothing else.

Everything OSCAL is **generated** from these files: component-definitions,
assessment-plan activities, the coverage ledger and the docs. CI fails if
regenerating produces a diff, so the OSCAL cannot drift from the code that
produces it.

Each entry must declare, at minimum:

| Field | Why it is mandatory |
|---|---|
| `controls[].id` + `statement_id` | What is being assessed. ISM statement ids are `<control-id>_smt`. |
| `controls[].statement_sha256` | Hash of the upstream control prose. ASD revises the ISM quarterly; without this, a reworded control silently keeps passing an outdated check. |
| `method` | `TEST` / `EXAMINE` / `INTERVIEW` — OSCAL assessment method |
| `confidence` | `direct` / `proxy` / `partial` / `attested`. A ceiling: an evaluator may lower it, never raise it. |
| `coverage` + `rationale` | What this check does **not** prove. Aggregated into the published coverage statement. |
| `scope` | `subject` (per host) or `aggregate` (a statement about a population) |
| `evidence_tier` | `passive` / `active` / `mutating`. Anything beyond `passive` is opt-in. |
| `freshness_hours` | How long an observation stays valid before it degrades to unassessed |
| `history_window_days` | Non-zero for *rate* controls (patch timeliness, scan cadence) that no single point-in-time fact can answer |

`history_window_days` exists because roughly **a quarter of Essential Eight ML1
is temporal** — `ism-1690/1691/1694/1695/1876/1877` (patch windows) and
`ism-1698/1699/1701/1702/1807` (scan cadence) are statements about *rates*, not
about current state. A check that cannot satisfy its window returns
`unassessed / insufficient-history`, never `not-satisfied`.
