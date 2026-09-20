"""Reading and writing fact bundles.

A bundle is the durable evidence artefact: raw facts from one subject at one
time, with provenance and a classification marking. It is deliberately a plain
JSON document so it can be read by an auditor, a script, or a future version of
this tool that no longer exists in the same form.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .contract import Fact, FactBundle

SCHEMA_ID = "https://nobytes.io/schema/oscal-cca/fact-bundle/1.0"


def _parse_ts(value: str) -> dt.datetime:
    """Parse an ISO-8601 timestamp, rejecting naive ones.

    Evidence timestamps decide expiry. A naive timestamp silently interpreted as
    local time would make freshness wrong by up to a day, in the direction that
    makes stale evidence look current.
    """
    moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError(f"fact bundle timestamp {value!r} has no timezone")
    return moment


def load_bundle(path: Path) -> FactBundle:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return from_dict(data)


def from_dict(data: dict) -> FactBundle:
    collected = _parse_ts(data["collected"])
    facts = {}
    for key, raw in (data.get("facts") or {}).items():
        facts[key] = Fact(
            key=key,
            value=raw.get("value"),
            collected=_parse_ts(raw.get("collected", data["collected"])),
            source=raw.get("source", ""),
            partial=bool(raw.get("partial", False)),
            meta=raw.get("meta") or {},
        )
    subject = dict(data["subject"])
    subject.setdefault("asset_id", data.get("asset_id", "unknown"))
    return FactBundle(
        subject=subject,
        facts=facts,
        collected=collected,
        run_id=data.get("run_id", ""),
        provenance=data.get("collector") or {},
    )
