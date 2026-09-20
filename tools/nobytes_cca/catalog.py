"""Access to the vendored ACSC ISM catalog.

Stdlib only. Everything here is read from the vendored JSON -- the catalog is
never fetched at evaluation time, so this works air-gapped and always reflects
the pinned release rather than whatever ASD published this morning.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ISM_NS = "https://cyber.gov.au/ns/ism/oscal/3.0"


@dataclass(frozen=True)
class Control:
    """One ISM control or principle, flattened out of the catalog tree."""

    id: str
    control_class: str
    statement: str
    statement_id: str
    revision: str
    updated: str
    applicability: tuple  # NC / OS / P / S / TS
    essential_eight: tuple  # ML1 / ML2 / ML3
    #: Reconstructed from the sort-id prop. ISM catalog groups carry `id: null`
    #: at every level, so there is no group id to walk; section structure has to
    #: come from here.
    sort_id: str

    @property
    def statement_sha256(self) -> str:
        return hashlib.sha256(self.statement.encode("utf-8")).hexdigest()

    def applies_at(self, classification: str) -> bool:
        return classification in self.applicability

    def in_e8(self, level: str) -> bool:
        return level in self.essential_eight


def _props(node: dict, name: str) -> list:
    return [p["value"] for p in node.get("props", []) if p.get("name") == name]


def _first(values: list, default: str = "") -> str:
    return values[0] if values else default


class Catalog:
    """The ISM catalog, indexed by control id."""

    def __init__(self, document: dict) -> None:
        self._doc = document
        self._controls: dict = {}
        self._index()

    @classmethod
    def load(cls, path: Path) -> Catalog:
        with path.open(encoding="utf-8") as handle:
            return cls(json.load(handle)["catalog"])

    def _index(self) -> None:
        def walk(node: Any) -> None:
            if isinstance(node, dict):
                if node.get("class") in ("ISM-control", "ISM-principle") and "id" in node:
                    parts = node.get("parts") or []
                    part = parts[0] if parts else {}
                    control = Control(
                        id=node["id"],
                        control_class=node["class"],
                        statement=(part.get("prose") or "").strip(),
                        statement_id=part.get("id", f"{node['id']}_smt"),
                        revision=_first(_props(node, "revision")),
                        updated=_first(_props(node, "updated")),
                        applicability=tuple(sorted(_props(node, "applicability"))),
                        essential_eight=tuple(
                            sorted(_props(node, "essential-eight-applicability"))
                        ),
                        sort_id=_first(_props(node, "sort-id")),
                    )
                    self._controls[control.id] = control
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(self._doc)

    # -- metadata ---------------------------------------------------------

    @property
    def version(self) -> str:
        return self._doc["metadata"]["version"]

    @property
    def oscal_version(self) -> str:
        return self._doc["metadata"]["oscal-version"]

    # -- lookup -----------------------------------------------------------

    def __contains__(self, control_id: str) -> bool:
        return control_id in self._controls

    def __len__(self) -> int:
        return len(self._controls)

    def __iter__(self) -> Iterator[Control]:
        for key in sorted(self._controls):
            yield self._controls[key]

    def get(self, control_id: str) -> Control | None:
        return self._controls.get(control_id)

    def require(self, control_id: str) -> Control:
        control = self._controls.get(control_id)
        if control is None:
            raise KeyError(
                f"{control_id!r} is not in ISM catalog {self.version}. Either it is "
                f"a typo, or ASD withdrew it in a later release."
            )
        return control

    # -- baselines --------------------------------------------------------

    def baseline(self, *, e8: str | None = None, classification: str | None = None) -> list:
        """Controls in a baseline, as a sorted list of control ids.

        Worth knowing before combining these: all 46 ML1 controls apply at every
        classification from NON_CLASSIFIED to TOP SECRET, so intersecting the
        Essential Eight with a classification does no work at all.
        """
        out = []
        for control in self:
            if control.control_class != "ISM-control":
                continue
            if e8 and not control.in_e8(e8):
                continue
            if classification and not control.applies_at(classification):
                continue
            out.append(control.id)
        return sorted(out)
