#!/usr/bin/env python3
"""Vendor the ASD Blueprint for Secure Cloud pages this repository actually cites.

Deliberately NOT a full mirror. The Blueprint is 7.7 MB, 3.2 MB of which is
website styling and imagery that nothing here will ever read, and a vendored
dataset nothing reads is just weight that still has to be reviewed on every
release bump.

What is vendored:

* the **submission templates** -- the SSP Annex (xlsx), the SSP template and the
  Essential Eight template (docx). These are the artefacts an agency actually
  hands an IRAP assessor, and PR 11 populates them from assessment results.
* exactly the **pages cited by a check**, discovered by reading
  `blueprint_page` out of the check registry rather than from a hand-kept list
  that would drift away from the checks it describes.

Every file is checksummed into MANIFEST.json. A citation whose page has been
reworded upstream then fails validation instead of silently invalidating the
objective a check was written against -- the same guard `statement_sha256`
gives for ISM control prose.

Licence: CC BY 4.0, © Commonwealth of Australia. Files are redistributed
unmodified; see NOTICE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nobytes_cca.paths import project_root

REPO = "https://github.com/ASD-Blueprint/ASD-Blueprint-for-Secure-Cloud"
RAW = "https://raw.githubusercontent.com/ASD-Blueprint/ASD-Blueprint-for-Secure-Cloud"
SITE = "https://blueprint.asd.gov.au"
TIMEOUT = 60

#: ASD tags the Blueprint as vMAJOR.MINOR.PATCH.
TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+$")

#: Submission artefacts. Vendored regardless of citation: they are outputs this
#: project fills in, not evidence it reads.
TEMPLATES = (
    "static/content/files/Blueprint System Security Plan Annex Template (June 2026).xlsx",
    "static/content/files/Blueprint System Security Plan Template.docx",
    "static/content/files/Blueprint Essential Eight Template.docx",
)


def blueprint_dir() -> Path:
    return project_root() / "blueprint"


def check_tag(tag: str) -> str:
    if not TAG_PATTERN.match(tag):
        raise ValueError(
            f"refusing to use Blueprint tag {tag!r}: expected the form vMAJOR.MINOR.PATCH"
        )
    return tag


def fetch(url: str) -> bytes:
    """HTTPS-only fetch, scheme asserted rather than assumed.

    A `file:` or custom scheme reaching urlopen would turn a supply-chain input
    into local file disclosure.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing non-HTTPS URL: {url!r}")
    request = urllib.request.Request(  # noqa: S310  (scheme asserted https above)
        url, headers={"User-Agent": "oscal-aap-ansible-playbooks"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return response.read()


def resolve_tag_commit(tag: str) -> str:
    """Resolve a tag to its commit SHA with git ls-remote; no REST API needed."""
    check_tag(tag)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git not found on PATH")
    result = subprocess.run(  # noqa: S603  (absolute path, fixed argv, validated tag)
        [git, "ls-remote", REPO, f"refs/tags/{tag}^{{}}", f"refs/tags/{tag}"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git ls-remote failed for {tag}: {result.stderr.strip()}")
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"tag {tag} not found in {REPO}")
    for line in lines:
        if line.endswith("^{}"):
            return line.split()[0]
    return lines[0].split()[0]


def cited_pages() -> list:
    """Blueprint pages named by the check registry, in sorted order.

    Reading this out of the checks themselves is the point: vendoring follows
    citation automatically, so a page cannot be cited without being pinned, and
    a page cannot linger after the check that needed it is gone.
    """
    import yaml

    pages = set()
    for path in sorted((project_root() / "checks").rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            continue
        for reference in data.get("references") or []:
            page = reference.get("blueprint_page")
            if page:
                pages.add(page)
    return sorted(pages)


def _write(target: Path, payload: bytes) -> str:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def download(tag: str) -> int:
    check_tag(tag)
    commit = resolve_tag_commit(tag)
    base = blueprint_dir()
    pages = cited_pages()

    files: dict = {}
    for relative in list(TEMPLATES) + pages:
        url = f"{RAW}/{commit}/{urllib.parse.quote(relative)}"
        payload = fetch(url)
        files[relative] = {
            "sha256": _write(base / relative, payload),
            "bytes": len(payload),
        }
        print(f"  {relative}  ({len(payload)} bytes)")

    manifest = {
        "_comment": (
            "Generated by tools/fetch_blueprint.py. Do not edit by hand. Files are "
            "redistributed unmodified under CC BY 4.0; see NOTICE."
        ),
        "release": tag,
        "commit": commit,
        "site": SITE,
        "repository": REPO,
        "licence": "CC BY 4.0",
        "copyright": "© Commonwealth of Australia",
        "cited_pages": pages,
        "files": dict(sorted(files.items())),
    }
    (base / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nvendored {len(files)} file(s) from Blueprint {tag} ({commit[:12]})")
    return 0


def verify() -> int:
    """Offline: every vendored file matches its manifest, and every cited page is vendored."""
    base = blueprint_dir()
    manifest_path = base / "MANIFEST.json"
    if not manifest_path.exists():
        print(f"FAIL no Blueprint manifest at {manifest_path}; run `make fetch`", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    problems = []
    for relative, expected in manifest["files"].items():
        path = base / relative
        if not path.exists():
            problems.append(f"missing: {relative}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected["sha256"]:
            problems.append(
                f"CHECKSUM MISMATCH: {relative}\n    manifest {expected['sha256']}\n"
                f"    on disk  {actual}"
            )

    # A check may not cite a page that was never pinned: the citation would be
    # unverifiable, and an objective resting on unverifiable guidance is an
    # assertion.
    for page in cited_pages():
        if page not in manifest["files"]:
            problems.append(
                f"cited but not vendored: {page} -- re-run `make fetch` so the "
                f"citation is pinned and checkable"
            )

    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"Blueprint {manifest['release']} ({manifest['commit'][:12]}): "
        f"{len(manifest['files'])} file(s) verified, "
        f"{len(manifest['cited_pages'])} cited page(s) pinned"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", default="v1.4.0", help="Blueprint tag, e.g. v1.4.0")
    parser.add_argument("--verify", action="store_true", help="offline checksum verification")
    args = parser.parse_args()
    try:
        return verify() if args.verify else download(args.release)
    except (ValueError, RuntimeError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
