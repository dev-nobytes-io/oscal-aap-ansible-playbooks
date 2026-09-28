"""Three-way reconciliation: the lab, the fixtures, and what the evaluators read.

Two of those legs were the whole of the first design, and two is not enough.
Collector-reality against the fixture corpus compares two artefacts an author
wrote from one assumption, which is precisely how the `display_name`/`name`
defect passed 260 tests in PR 17. The evaluators' own read set
(`nobytes_cca.lab.reads`) is the independent third.

What is a HARD failure and what is a review item is a deliberate,
load-bearing choice. Extracting evaluator reads yields a candidate set, and a
guard that cried wolf on every difference would be switched off within a week --
and a guard that is switched off is worse than no guard. So exactly one
condition fails the run:

    an evaluator reads a key that appears NOWHERE -- not in the lab digest, not
    anywhere in the fixture corpus.

That is the `display_name` signature exactly, and it cannot be produced by
anything legitimate: a key no collector has ever emitted and no fixture models
is a key that will read as absent on every host, forever, silently.

Everything else is reported for a human: paths the lab found that the fixtures
do not model (the fixtures are behind reality), and paths the fixtures model
that the lab did not produce (either the host genuinely lacks it, or the fixture
is a fiction). Both are worth knowing; neither is unambiguously a defect.

Separately, a per-fact FLOOR declared before the run must be met. A shape diff
over an empty fact yields zero differences, which reads as agreement -- so on a
domain controller, where Office is not installed and browser policy does not
exist, "no differences" must not be mistaken for "verified". See ADR 0020.
"""

from __future__ import annotations


def leaf(path: str) -> str:
    """The final key name in a digest path, ignoring list and wildcard markers."""
    cleaned = path.replace("[]", "")
    if cleaned.endswith(".*"):
        cleaned = cleaned[:-2]
    return cleaned.rsplit(".", 1)[-1] if "." in cleaned else cleaned


def leaf_keys(paths) -> set:
    return {leaf(p) for p in paths}


def _fact_paths(digest: dict) -> dict:
    """fact key -> {path: entry} across a digest."""
    out = {}
    for fact_key, record in (digest.get("facts") or {}).items():
        out[fact_key] = dict(record.get("paths") or {})
    return out


def _all_paths(digest: dict) -> dict:
    merged: dict = {}
    for paths in _fact_paths(digest).values():
        merged.update(paths)
    return merged


def check_floors(digest: dict, floors: dict) -> list:
    """Every declared floor must be met, or the run establishes nothing.

    `floors` maps a fact key to a list of {path, min_n} requirements. A path
    that is absent fails. A path present with `n` below `min_n` fails. A scalar
    path present with no `min_n` passes -- presence is the claim.
    """
    failures = []
    facts = _fact_paths(digest)
    for fact_key in sorted(floors or {}):
        requirements = (floors.get(fact_key) or {}).get("require") or []
        paths = facts.get(fact_key)
        if paths is None:
            failures.append(
                {
                    "fact": fact_key,
                    "path": fact_key,
                    "reason": "the fact is absent from the digest entirely",
                }
            )
            continue
        record = (digest.get("facts") or {}).get(fact_key) or {}
        if record.get("partial") or record.get("collection_error"):
            failures.append(
                {
                    "fact": fact_key,
                    "path": fact_key,
                    "reason": "the collector reported partial or a collection error",
                }
            )
        for requirement in requirements:
            path = str(requirement.get("path", ""))
            min_n = requirement.get("min_n")
            entry = paths.get(path)
            if entry is None:
                failures.append(
                    {"fact": fact_key, "path": path, "reason": "required path absent"}
                )
                continue
            if min_n is not None and int(entry.get("n", 0)) < int(min_n):
                failures.append(
                    {
                        "fact": fact_key,
                        "path": path,
                        "reason": "present but holds {} element(s), floor is {}".format(
                            entry.get("n", 0), min_n
                        ),
                    }
                )
    return failures


def reconcile(lab: dict, fixtures: dict, reads: dict, floors: dict) -> dict:
    """Compare the three legs. Returns a report; `ok` is False on hard failures.

    `lab` and `fixtures` are digests (the fixture side is a digest of the whole
    corpus). `reads` is `reads_in_package()` output. `floors` is the declared
    per-fact minimum.
    """
    lab_paths = _all_paths(lab)
    fixture_paths = _all_paths(fixtures)

    lab_platform = (lab.get("subject") or {}).get("platform_family", "")

    known_leaves = leaf_keys(lab_paths) | leaf_keys(fixture_paths)
    lab_fact_keys = set(_fact_paths(lab))

    # THE hard failure -- and it is SCOPED, for a reason worth stating.
    #
    # "Nothing emits this key" can only be asserted about facts a real run
    # actually produced. An Entra key read off an Entra fact is not a finding
    # against a Windows domain controller, and a key missing from the fixture
    # corpus may simply be one no bundle has exercised yet. So a key becomes a
    # hard failure only when the lab run carried at least one of the facts its
    # reader reaches for; otherwise it is reported for review.
    unreadable = {}
    unexercised = {}
    for key, meta in (reads or {}).items():
        if key in known_leaves:
            continue
        files = meta.get("files", []) if isinstance(meta, dict) else list(meta or [])
        facts = set(meta.get("facts", [])) if isinstance(meta, dict) else set()
        if facts & lab_fact_keys:
            unreadable[key] = files
        else:
            unexercised[key] = files

    floor_failures = check_floors(lab, floors)

    # Review items, keyed on paths rather than leaves so nesting is visible.
    # Restricted to facts the lab actually carries: a Linux digest saying
    # nothing about `windows.*` is not a finding.
    lab_facts = set(_fact_paths(lab))
    in_lab_not_fixtures = sorted(
        p for p in lab_paths if p not in fixture_paths
    )
    in_fixtures_not_lab = sorted(
        p
        for p in fixture_paths
        if p not in lab_paths and p.split(".")[0] in {f.split(".")[0] for f in lab_facts}
    )

    return {
        "ok": not unreadable and not floor_failures,
        "lab_platform_family": lab_platform,
        "lab_run_id": lab.get("run_id", ""),
        "counts": {
            "lab_paths": len(lab_paths),
            "fixture_paths": len(fixture_paths),
            "evaluator_reads": len(reads or {}),
        },
        "hard_failures": {
            "keys_read_but_never_emitted": unreadable,
            "floors_unmet": floor_failures,
        },
        "review": {
            "in_lab_not_in_fixtures": in_lab_not_fixtures,
            "in_fixtures_not_in_lab": in_fixtures_not_lab,
            # Keys the evaluators read that no bundle in scope has ever
            # populated. Not a failure on its own -- the fact may belong to a
            # platform this run did not touch -- but each one is a code path
            # that has never seen a real observation.
            "keys_never_exercised_by_a_bundle": unexercised,
        },
    }


def render(report: dict) -> str:
    """Human-readable reconciliation summary."""
    lines = []
    counts = report.get("counts", {})
    lines.append(
        "lab paths {} · fixture paths {} · evaluator reads {} · platform {}".format(
            counts.get("lab_paths", 0),
            counts.get("fixture_paths", 0),
            counts.get("evaluator_reads", 0),
            report.get("lab_platform_family", "?") or "?",
        )
    )

    unreadable = report["hard_failures"]["keys_read_but_never_emitted"]
    if unreadable:
        lines.append("")
        lines.append("FAIL  evaluators read keys that NOTHING emits:")
        for key in sorted(unreadable):
            lines.append(
                "        {:38} read by {}".format(key, ", ".join(unreadable[key]))
            )
        lines.append(
            "      Each will read as absent on every host, forever, silently."
        )

    floors = report["hard_failures"]["floors_unmet"]
    if floors:
        lines.append("")
        lines.append("FAIL  declared floors not met -- this run establishes nothing")
        lines.append("      about the facts below, and they must NOT be promoted:")
        for failure in floors:
            lines.append(
                "        {:44} {}".format(failure["path"], failure["reason"])
            )

    unexercised = report.get("review", {}).get("keys_never_exercised_by_a_bundle") or {}
    if unexercised:
        lines.append("")
        lines.append(
            f"REVIEW  keys the evaluators read that NO bundle in scope populates ({len(unexercised)}):"
        )
        for key in sorted(unexercised):
            lines.append(
                "        {:38} read by {}".format(key, ", ".join(unexercised[key]))
            )
        lines.append(
            "      Not failures here -- the fact may belong to a platform this run"
        )
        lines.append(
            "      did not touch -- but each is a branch no real observation has hit."
        )

    review = report.get("review", {})
    for label, key in (
        ("lab found, fixtures do not model", "in_lab_not_in_fixtures"),
        ("fixtures model, lab did not produce", "in_fixtures_not_in_lab"),
    ):
        items = review.get(key) or []
        if items:
            lines.append("")
            lines.append(f"REVIEW  {label} ({len(items)}):")
            for path in items[:25]:
                lines.append("        " + path)
            if len(items) > 25:
                lines.append(f"        ... {len(items) - 25} more")

    lines.append("")
    lines.append("RESULT  " + ("ok" if report.get("ok") else "FAILED"))
    return "\n".join(lines)
