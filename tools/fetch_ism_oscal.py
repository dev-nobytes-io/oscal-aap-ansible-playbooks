#!/usr/bin/env python3
"""Vendor the pinned ACSC ISM OSCAL release and the NIST OSCAL JSON schemas.

Writes into oscal/upstream/ism/<tag>/ and oscal/schemas/, alongside a
MANIFEST.json recording the upstream tag, the resolved commit SHA and a SHA-256
for every file -- so a vendored copy can be proven identical to what ASD
published, and a build is reproducible offline afterwards.

Why this fetches the way it does:

  * `www.cyber.gov.au` is authoritative but frequently unreachable from build
    networks (it times out entirely from ours). ASD maintains a GitHub mirror
    that is tagged per release, which is both reachable and a better pin.
  * The GitHub REST API is commonly blocked or rate-limited in restricted
    networks -- here it returns 403 for out-of-scope repositories -- so this
    uses raw.githubusercontent.com and `git ls-remote` only.
  * Upstream files are written BYTE-FOR-BYTE UNMODIFIED. They are Commonwealth
    material redistributed under CC BY 4.0; rewriting them (even reformatting
    JSON) would break both the checksum chain and the "unmodified" claim.

Run with --verify to check vendored files against the manifest without
re-downloading. That is what CI does; it needs no network.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ism_release import (
    AUTHORITATIVE_URL,
    MIRROR_RAW,
    MIRROR_REPO,
    OSCAL_VERSION,
    PINNED_RELEASE,
    artifact_names,
    sha256_file,
    upstream_dir,
)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "oscal" / "schemas"

#: NIST publishes these ONLY as GitHub release assets. The paths people reach
#: for first -- raw.githubusercontent.com/usnistgov/OSCAL/<tag>/json/schema/ and
#: pages.nist.gov/OSCAL/artifacts/ -- both 404. Do not "fix" these URLs.
NIST_RELEASE = f"https://github.com/usnistgov/OSCAL/releases/download/v{OSCAL_VERSION}"
NIST_SCHEMAS = (
    "oscal_catalog_schema.json",
    "oscal_profile_schema.json",
    "oscal_component_schema.json",
    "oscal_assessment-plan_schema.json",
    "oscal_assessment-results_schema.json",
    "oscal_poam_schema.json",
    "oscal_ssp_schema.json",
)

TIMEOUT = 60

#: ASD release tags look like v2026.09.4. The tag reaches both a URL and a
#: subprocess argument, so it is validated rather than trusted -- this tool runs
#: in CI where the tag can come from a workflow input.
TAG_PATTERN = re.compile(r"^v\d{4}\.\d{2}\.\d{1,2}$")


def check_tag(tag: str) -> str:
    if not TAG_PATTERN.match(tag):
        raise ValueError(
            f"refusing to use release tag {tag!r}: expected the ASD form vYYYY.MM.N"
        )
    return tag


def fetch(url: str) -> bytes:
    """HTTPS-only fetch. The scheme is asserted rather than assumed: a `file:`
    or custom scheme reaching urlopen would turn a supply-chain input into local
    file disclosure."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing non-HTTPS URL: {url!r}")
    request = urllib.request.Request(  # noqa: S310  (scheme asserted https above)
        url, headers={"User-Agent": "oscal-aap-ansible-playbooks"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return response.read()


def resolve_tag_commit(tag: str) -> str:
    """Resolve a tag to its commit SHA via git ls-remote (no REST API)."""
    check_tag(tag)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git not found on PATH")
    result = subprocess.run(  # noqa: S603  (absolute path, fixed argv, validated tag)
        [git, "ls-remote", MIRROR_REPO, f"refs/tags/{tag}^{{}}", f"refs/tags/{tag}"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git ls-remote failed for {tag}: {result.stderr.strip()}")
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"tag {tag} not found in {MIRROR_REPO}")
    # A dereferenced annotated tag (^{}) points at the commit; prefer it.
    for line in lines:
        if line.endswith("^{}"):
            return line.split()[0]
    return lines[0].split()[0]


def download_release(tag: str) -> dict:
    check_tag(tag)
    target = upstream_dir(tag)
    target.mkdir(parents=True, exist_ok=True)

    commit = resolve_tag_commit(tag)
    print(f"{MIRROR_REPO} @ {tag} -> {commit}")

    files: dict[str, dict] = {}
    for name in artifact_names():
        url = f"{MIRROR_RAW}/{tag}/{name}"
        try:
            payload = fetch(url)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{name}: HTTP {exc.code} from {url}") from exc
        # Written verbatim. Never json.dump() upstream data.
        (target / name).write_bytes(payload)
        digest = sha256_file(target / name)
        files[name] = {"sha256": digest, "bytes": len(payload)}
        print(f"  {name:<58} {len(payload):>9,} B  {digest[:16]}…")

    manifest = {
        "_comment": (
            "Generated by tools/fetch_ism_oscal.py. Do not edit by hand. "
            "Upstream files are redistributed byte-for-byte unmodified under "
            "CC BY 4.0; see NOTICE."
        ),
        "release": tag,
        "commit": commit,
        "oscal_version": OSCAL_VERSION,
        "authoritative_source": AUTHORITATIVE_URL,
        "ingest_mirror": MIRROR_REPO,
        "licence": "CC BY 4.0",
        "copyright": "© Commonwealth of Australia",
        "files": dict(sorted(files.items())),
    }
    (target / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return manifest


def download_schemas() -> dict:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict] = {}
    for name in NIST_SCHEMAS:
        url = f"{NIST_RELEASE}/{name}"
        payload = fetch(url)
        (SCHEMA_DIR / name).write_bytes(payload)
        files[name] = {"sha256": sha256_file(SCHEMA_DIR / name), "bytes": len(payload)}
        print(f"  {name:<58} {len(payload):>9,} B")
    manifest = {
        "_comment": "Generated by tools/fetch_ism_oscal.py. Do not edit by hand.",
        "oscal_version": OSCAL_VERSION,
        "source": NIST_RELEASE,
        "note": (
            "NIST publishes these as GitHub release assets only; the repository "
            "json/schema/ path and pages.nist.gov/OSCAL/artifacts/ both return 404."
        ),
        "files": dict(sorted(files.items())),
    }
    (SCHEMA_DIR / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify(tag: str) -> int:
    problems: list[str] = []
    for directory in (upstream_dir(tag), SCHEMA_DIR):
        manifest_path = directory / "MANIFEST.json"
        if not manifest_path.exists():
            problems.append(f"{manifest_path} missing — run `make fetch`")
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name, meta in manifest["files"].items():
            path = directory / name
            if not path.exists():
                problems.append(f"{path.relative_to(ROOT)}: missing")
                continue
            actual = sha256_file(path)
            if actual != meta["sha256"]:
                problems.append(
                    f"{path.relative_to(ROOT)}: SHA-256 mismatch\n"
                    f"    manifest {meta['sha256']}\n"
                    f"    actual   {actual}"
                )
        print(f"verified {len(manifest['files'])} files in {directory.relative_to(ROOT)}")

    if problems:
        print("\nVERIFICATION FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("all vendored files match their manifests")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", default=PINNED_RELEASE, help="upstream ISM release tag")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="check vendored files against their manifests (offline; no download)",
    )
    args = parser.parse_args()

    check_tag(args.release)

    if args.verify:
        return verify(args.release)

    print(f"Vendoring ISM OSCAL {args.release}")
    download_release(args.release)
    print(f"\nVendoring NIST OSCAL {OSCAL_VERSION} schemas")
    download_schemas()
    print("\nDone. Re-run with --verify to confirm integrity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
