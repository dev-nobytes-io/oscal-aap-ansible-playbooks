"""Locating the project's data from inside an execution environment.

The evaluator needs three things that live in the repository rather than in the
package: the vendored ISM catalog, the check registry, and the end-of-life
dataset. Inside AAP or AWX the repository is mounted as the project, so paths
must resolve relative to *that*, not to wherever the package happens to be
installed.

Resolution order, most explicit first:

1. ``CCA_PROJECT_ROOT`` environment variable.
2. A directory at or above the current working directory containing ``oscal/``
   and ``checks/`` -- the normal case when a playbook runs from the project.
3. The repository the package was installed from, for an editable install.

A wrong answer here is not subtle: it surfaces as "no vendored catalog", not as
a silently empty assessment.
"""

from __future__ import annotations

import os
from pathlib import Path

MARKERS = ("oscal", "checks")


def _looks_like_project(path: Path) -> bool:
    return all((path / marker).is_dir() for marker in MARKERS)


def project_root() -> Path:
    explicit = os.environ.get("CCA_PROJECT_ROOT")
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not _looks_like_project(candidate):
            raise FileNotFoundError(
                f"CCA_PROJECT_ROOT={candidate} does not contain {MARKERS}. "
                f"Point it at the checkout, not at the package."
            )
        return candidate

    for candidate in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if _looks_like_project(candidate):
            return candidate

    # Editable install: the package still sits inside the checkout.
    fallback = Path(__file__).resolve().parent.parent.parent
    if _looks_like_project(fallback):
        return fallback

    raise FileNotFoundError(
        "Cannot locate the project root. Set CCA_PROJECT_ROOT to the checkout "
        "containing oscal/ and checks/, or run from inside it."
    )


def checks_dir() -> Path:
    return project_root() / "checks"


def eol_dir() -> Path:
    return project_root() / "data" / "eol"


def schemas_dir() -> Path:
    return project_root() / "oscal" / "schemas"


def ism_release_dir() -> Path:
    """The single vendored ISM release directory.

    Exactly one is kept at a time by design -- a release bump replaces it, and
    git history retains the rest. That means the pinned release can be
    DISCOVERED rather than duplicated as a constant in two places that could
    drift apart. Zero or several is a broken checkout, and says so.
    """
    base = project_root() / "oscal" / "upstream" / "ism"
    if not base.is_dir():
        raise FileNotFoundError(f"No vendored ISM data at {base}. Run `make fetch`.")
    releases = sorted(p for p in base.iterdir() if p.is_dir() and (p / "MANIFEST.json").exists())
    if not releases:
        raise FileNotFoundError(f"No vendored ISM release under {base}. Run `make fetch`.")
    if len(releases) > 1:
        raise RuntimeError(
            f"Expected exactly one vendored ISM release under {base}, found "
            f"{[p.name for p in releases]}. A bump replaces the directory; git "
            f"history keeps the old one."
        )
    return releases[0]


def ism_catalog() -> Path:
    return ism_release_dir() / "ISM_catalog.json"
