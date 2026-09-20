#!/usr/bin/env python3
"""Control-level diff between two ISM OSCAL releases.

ASD publishes the ISM roughly quarterly -- 26 releases so far. A bump is not a
routine dependency update: control text can be reworded while the control id
stays the same, and a check written against the old wording will keep passing
while no longer testing what the control says. That is the quietest way this
project could become wrong.

So a release bump produces a reviewable summary rather than a 14 MB diff nobody
reads. The release-watch workflow puts this in the pull request body.

Usage:
    ism_diff.py --old v2026.06.18 --new v2026.09.4
    ism_diff.py --old-file a/ISM_catalog.json --new-file b/ISM_catalog.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ism_release import upstream_dir

NS = "https://cyber.gov.au/ns/ism/oscal/3.0"


def extract(catalog: dict) -> dict[str, dict]:
    """Flatten a catalog to {control_id: {...}} with the fields we care about."""
    out: dict[str, dict] = {}

    def props(node: dict, name: str) -> list[str]:
        return sorted(p["value"] for p in node.get("props", []) if p["name"] == name)

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("class") in ("ISM-control", "ISM-principle") and "id" in node:
                parts = node.get("parts") or [{}]
                prose = (parts[0].get("prose") or "").strip()
                out[node["id"]] = {
                    "class": node["class"],
                    "prose": prose,
                    "sha256": hashlib.sha256(prose.encode("utf-8")).hexdigest(),
                    "applicability": props(node, "applicability"),
                    "e8": props(node, "essential-eight-applicability"),
                    "revision": (props(node, "revision") or [""])[0],
                    "updated": (props(node, "updated") or [""])[0],
                }
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(catalog)
    return out


def load(path: Path) -> dict[str, dict]:
    return extract(json.loads(path.read_text(encoding="utf-8"))["catalog"])


def render(old: dict[str, dict], new: dict[str, dict], old_tag: str, new_tag: str) -> str:
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    common = old.keys() & new.keys()

    reworded = sorted(c for c in common if old[c]["sha256"] != new[c]["sha256"])
    applicability_changed = sorted(
        c for c in common if old[c]["applicability"] != new[c]["applicability"]
    )
    e8_changed = sorted(c for c in common if old[c]["e8"] != new[c]["e8"])

    lines: list[str] = []
    add = lines.append

    add(f"# ISM control diff: `{old_tag}` → `{new_tag}`")
    add("")
    add("| Change | Count |")
    add("|---|---|")
    add(f"| Controls added | {len(added)} |")
    add(f"| Controls removed | {len(removed)} |")
    add(f"| **Statement text reworded** | **{len(reworded)}** |")
    add(f"| Classification applicability changed | {len(applicability_changed)} |")
    add(f"| Essential Eight membership changed | {len(e8_changed)} |")
    add(f"| Total controls | {len(old)} → {len(new)} |")
    add("")

    if reworded:
        add("## Reworded statements — review every one")
        add("")
        add(
            "A reworded control keeps its id. Any check bound to one of these was "
            "written against the previous text and must be re-affirmed or revised "
            "before this bump merges."
        )
        add("")
        for cid in reworded:
            add(f"<details><summary><code>{cid}</code></summary>")
            add("")
            add(f"- **was:** {old[cid]['prose']}")
            add(f"- **now:** {new[cid]['prose']}")
            add("")
            add("</details>")
        add("")

    for title, ids, note in (
        ("Controls added", added, "New controls are unassessed until a check exists."),
        ("Controls removed", removed, "Any check bound to these is now orphaned."),
    ):
        if ids:
            add(f"## {title}")
            add("")
            add(note)
            add("")
            for cid in ids:
                source = new if cid in new else old
                add(f"- `{cid}` — {source[cid]['prose']}")
            add("")

    if e8_changed:
        add("## Essential Eight membership changed")
        add("")
        add("Baseline sizes move. ML1 is not permanently 46 controls.")
        add("")
        for cid in e8_changed:
            add(f"- `{cid}`: {old[cid]['e8'] or '—'} → {new[cid]['e8'] or '—'}")
        add("")

    if applicability_changed:
        add("## Classification applicability changed")
        add("")
        for cid in applicability_changed:
            add(f"- `{cid}`: {old[cid]['applicability']} → {new[cid]['applicability']}")
        add("")

    if not any((added, removed, reworded, applicability_changed, e8_changed)):
        add("No control-level changes detected.")
        add("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", help="vendored release tag, e.g. v2026.06.18")
    parser.add_argument("--new", help="vendored release tag, e.g. v2026.09.4")
    parser.add_argument("--old-file", type=Path, help="path to an ISM_catalog.json")
    parser.add_argument("--new-file", type=Path, help="path to an ISM_catalog.json")
    parser.add_argument("--output", type=Path, help="write the report here instead of stdout")
    args = parser.parse_args()

    old_path = args.old_file or (upstream_dir(args.old) / "ISM_catalog.json" if args.old else None)
    new_path = args.new_file or (upstream_dir(args.new) / "ISM_catalog.json" if args.new else None)
    if not old_path or not new_path:
        parser.error("need --old/--new (vendored tags) or --old-file/--new-file")
    for path in (old_path, new_path):
        if not path.exists():
            parser.error(f"not found: {path}")

    report = render(
        load(old_path), load(new_path), args.old or old_path.name, args.new or new_path.name
    )
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
