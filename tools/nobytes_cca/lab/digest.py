"""Reduce a fact bundle to its SHAPE, so it can leave the lab.

A lab run produces evidence about a real estate: hostnames, SIDs, installed
software, registry contents. None of that needs to cross a boundary for the
comparison this package exists to make, which is about key PATHS and value
TYPES rather than values.

Three things this module gets right because the first design of it got them
wrong -- an adversarial review found each one:

1. **Full key paths, including keys of list elements.** The `display_name`/`name`
   defect of PR 17 lived nested inside a list element of
   `windows.applications.installed`. A digest of top-level fact keys is
   structurally incapable of seeing the bug class it exists to catch.

2. **A digest cannot be both recursive and value-free by default**, because in
   this repository some fact-object KEYS are themselves collected data.
   `windows.browsers.java_surface.value.javasoft` is keyed by a verbatim
   registry path, and `windows.browsers.policy.value.rows[].values` by Group
   Policy setting names -- which on a real domain controller include whatever
   custom ADMX the organisation authored. Those key-spaces are declared in
   `DATA_KEYSPACES` and emitted as a count plus a salted hash per key, never
   literally, so a diff can still see THAT a key differs without learning what
   it was.

3. **`subject.asset_id` never travels.** It is the estate's own name for the
   host. `platform_family` and `estate_tier` do travel, because the diff has to
   be keyed on platform -- `os.release` legitimately carries a Windows shape and
   a Linux shape, and a diff that unions them accepts anything.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = "https://nobytes.io/schema/oscal-cca/lab-digest/1.0"

#: Paths whose CHILD KEYS are collected content rather than field names.
#:
#: Declared, not inferred, because getting this wrong in either direction is
#: harmful: treat a content key as schema and the digest exports estate data;
#: treat a schema key as content and the diff goes blind to the field names it
#: exists to compare. `tests/test_lab_digest.py` carries a heuristic tripwire
#: for content-shaped keys that are NOT declared here, which catches the obvious
#: cases (registry paths, URLs) but cannot catch a plausible-looking policy
#: name -- those need this list and human judgement.
DATA_KEYSPACES = (
    # Keyed by verbatim registry path: HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment
    "windows.browsers.java_surface.javasoft",
    # Keyed by Group Policy setting name, including custom organisational ADMX.
    "windows.browsers.policy.rows[].values",
)

#: Keys whose VALUES are identifiers even after redaction truncates them. The
#: digest carries no values at all, so this is only used to assert that fact in
#: tests -- it is documentation of intent, not a filter.
_IDENTIFIER_BEARING = ("sid", "allow_write_sids", "deny_write_sids", "profiles_unloaded")


def _hash(text: str, salt: str) -> str:
    return "sha256:" + hashlib.sha256((salt + text).encode("utf-8")).hexdigest()[:16]


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "map"
    return type(value).__name__


def _is_data_keyspace(path: str) -> bool:
    return path in DATA_KEYSPACES


def walk(node: Any, path: str, out: dict, salt: str) -> None:
    """Record every key path under `node`, with types and cardinalities.

    A list contributes ONE entry per distinct child path, with `n` counting the
    elements -- so a 400-row policy table does not produce 400 entries, and the
    count still changes visibly when the estate does.
    """
    if isinstance(node, dict):
        data_keyspace = _is_data_keyspace(path)
        if data_keyspace:
            # The keys here are estate content. Emit how many there were and a
            # salted hash of each, so a diff sees a difference without learning
            # the registry path or policy name that caused it.
            out[path] = {
                "type": "map",
                "keyspace": "data",
                "n": len(node),
                "key_hashes": sorted(_hash(str(k), salt) for k in node),
            }
            for value in node.values():
                # Recurse into the VALUES, filed under a collapsed path, so the
                # shape beneath a content key is still compared.
                walk(value, path + ".*", out, salt)
            return
        out.setdefault(path, {"type": "map", "keyspace": "schema"})
        for key, value in node.items():
            walk(value, f"{path}.{key}", out, salt)
        return

    if isinstance(node, list):
        entry = out.setdefault(path, {"type": "list", "n": 0})
        entry["n"] = max(int(entry.get("n", 0)), len(node))
        for item in node:
            walk(item, path + "[]", out, salt)
        return

    existing = out.get(path)
    observed = _type_name(node)
    if existing is None:
        out[path] = {"type": observed}
    elif existing.get("type") != observed:
        # A path that carries two types across subjects is worth seeing rather
        # than silently collapsing to whichever came last.
        types = set(str(existing.get("type", "")).split("|")) | {observed}
        existing["type"] = "|".join(sorted(t for t in types if t))


def digest_bundle(bundle: dict, salt: str) -> dict:
    """Reduce one fact bundle to a shape digest carrying no values."""
    if not isinstance(bundle, dict):
        raise TypeError("digest_bundle expects a parsed fact bundle mapping")
    if not salt:
        raise ValueError(
            "a salt is required: unsalted key hashes are correlatable across "
            "organisations, which is the same objection ADR 0016 raises against "
            "hashing identifiers under a known salt"
        )

    subject = bundle.get("subject") or {}
    facts = bundle.get("facts") or {}

    out_facts = {}
    for key in sorted(facts):
        record = facts[key] or {}
        paths: dict = {}
        walk(record.get("value"), key, paths, salt)
        # The fact RECORD's meta is read by evaluators too -- `office.py` reads
        # `policy.meta.get("profiles_unloaded")` and `app_support.py` reads
        # `unloaded_hives`. Walking only `value` made the digest blind to them,
        # which showed up immediately as spurious "read but never emitted"
        # findings the first time this was run. Note the collectors are not
        # consistent about it: `collect_windows_browsers` nests `meta` INSIDE
        # the value, while `collect_windows_applications` puts it on the record.
        # Both are walked; neither is normalised here, because normalising would
        # hide the inconsistency rather than surface it.
        walk(record.get("meta"), key + ".@meta", paths, salt)
        out_facts[key] = {
            # `source` names the collection technique, not the host.
            "source": str(record.get("source", "")),
            "partial": bool(record.get("partial", False)),
            "collection_error": bool((record.get("meta") or {}).get("collection_error")),
            "paths": {p: paths[p] for p in sorted(paths)},
        }

    digest = {
        "schema": SCHEMA,
        "run_id": str(bundle.get("run_id", "")),
        "collected": str(bundle.get("collected", "")),
        "redaction_policy": str(bundle.get("redaction_policy", "")),
        "marking": bundle.get("marking") or {},
        # NOT asset_id. See the module docstring.
        "subject": {
            "platform_family": str(subject.get("platform_family", "")),
            "estate_tier": str(subject.get("estate_tier", "")),
        },
        "facts": out_facts,
    }
    digest["self_sha256"] = self_hash(digest)
    return digest


def self_hash(digest: dict) -> str:
    """Hash the digest's own content, so CI can tell generated from hand-edited."""
    body = {k: v for k, v in digest.items() if k != "self_sha256"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_self_hash(digest: dict) -> bool:
    return bool(digest.get("self_sha256")) and digest["self_sha256"] == self_hash(digest)
