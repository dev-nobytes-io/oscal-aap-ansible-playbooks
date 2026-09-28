"""The lab harness, and the two claims it must actually make good on.

This harness exists because fourteen of fifteen automated controls have never
had their collector run against the platform it reads. Its first design was
itself five instances of this project's recurring defect, found by adversarial
review before anything was built. Two of those five are the tests below:

1. **A top-level shape digest cannot see the bug class it exists to catch.**
   The `display_name`/`name` defect of PR 17 lived nested inside a list element.
   `test_the_diff_catches_the_display_name_defect` reintroduces that exact bug
   and asserts the harness fails.

2. **"No values leave the lab" is a claim, so it gets an assertion.**
   `test_the_digest_emits_no_values` builds a digest from a bundle containing a
   known SID, UPN and registry path and asserts none appears anywhere in it.

Plus the third, which is what makes an empty run safe: a floor declared before
the run must refuse a fact that came back empty, because a shape diff over an
empty fact yields zero differences and zero differences reads as agreement.
"""

from __future__ import annotations

import json

import pytest
import yaml

from conftest import ROOT
from nobytes_cca.lab import diff
from nobytes_cca.lab.digest import DATA_KEYSPACES, digest_bundle, self_hash, verify_self_hash
from nobytes_cca.lab.reads import reads_in_package, reads_in_source

SALT = "a-real-per-deployment-lab-salt"
CHECKS = ROOT / "tools" / "nobytes_cca" / "checks"
BUNDLES = ROOT / "tests" / "fixtures" / "bundles"
FLOORS = ROOT / "docs" / "lab" / "floors.yml"

PERSON_SID = "S-1-5-21-1111111111-2222222222-3333333333-1174"
UPN = "alice.smith@agency.gov.au"
REGISTRY_KEY = r"HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment"


def _corpus() -> dict:
    merged: dict = {"schema": "x", "subject": {"platform_family": "corpus"}, "facts": {}}
    for path in sorted(BUNDLES.glob("*.json")):
        digest = digest_bundle(json.loads(path.read_text(encoding="utf-8")), SALT)
        for key, record in digest["facts"].items():
            target = merged["facts"].setdefault(
                key,
                {"source": "", "partial": False, "collection_error": False, "paths": {}},
            )
            target["paths"].update(record["paths"])
    return merged


def test_there_are_bundles_and_evaluators_to_scan() -> None:
    """A green suite must not be able to mean "nothing was scanned"."""
    assert sorted(BUNDLES.glob("*.json")), "no fixture bundles found"
    assert reads_in_package(CHECKS), "no evaluator reads extracted"


# --------------------------------------------------------------------------
# 1. The digest carries no values. This is a privacy claim, so it is asserted.
# --------------------------------------------------------------------------


def test_the_digest_emits_no_values() -> None:
    bundle = {
        "run_id": "probe",
        "subject": {"asset_id": "corp.example/DC01", "platform_family": "windows"},
        "facts": {
            "windows.browsers.java_surface": {
                "source": "registry",
                "value": {"javasoft": {REGISTRY_KEY: ["1.8.0_411"]}, "ie_site_list": UPN},
            },
            "windows.appcontrol.writable_paths": {
                "source": "Get-Acl",
                "value": {"probes": [{"path": "C:\\Temp", "allow_write_sids": [PERSON_SID]}]},
            },
        },
    }
    text = json.dumps(digest_bundle(bundle, SALT))
    for secret in (PERSON_SID, UPN, REGISTRY_KEY, "1.8.0_411", "C:\\\\Temp", "DC01"):
        assert secret not in text, f"{secret!r} leaked into the digest"


def test_a_content_keyspace_is_hashed_not_named() -> None:
    """`javasoft` is keyed by verbatim registry path. The key itself is data."""
    bundle = {
        "subject": {"platform_family": "windows"},
        "facts": {
            "windows.browsers.java_surface": {
                "source": "r",
                "value": {"javasoft": {REGISTRY_KEY: []}},
            }
        },
    }
    entry = digest_bundle(bundle, SALT)["facts"]["windows.browsers.java_surface"]["paths"][
        "windows.browsers.java_surface.javasoft"
    ]
    assert entry["keyspace"] == "data"
    assert entry["n"] == 1
    assert entry["key_hashes"] and all(h.startswith("sha256:") for h in entry["key_hashes"])


def test_the_asset_id_never_travels() -> None:
    bundle = {
        "subject": {"asset_id": "corp.example/DC01", "platform_family": "windows"},
        "facts": {},
    }
    subject = digest_bundle(bundle, SALT)["subject"]
    assert "asset_id" not in subject
    assert subject["platform_family"] == "windows"


def test_hashing_without_a_salt_is_refused() -> None:
    with pytest.raises(ValueError, match="salt"):
        digest_bundle({"facts": {}}, "")


def test_a_hand_edited_digest_is_detectable() -> None:
    digest = digest_bundle(
        {"subject": {"platform_family": "windows"}, "facts": {}}, SALT
    )
    assert verify_self_hash(digest)
    digest["run_id"] = "tampered"
    assert not verify_self_hash(digest)
    assert self_hash(digest) != digest["self_sha256"]


def test_every_declared_data_keyspace_is_reachable_in_the_corpus() -> None:
    """A declared keyspace that matches nothing is a stale declaration."""
    corpus_paths = set()
    for paths in (_corpus()["facts"][k]["paths"] for k in _corpus()["facts"]):
        corpus_paths |= set(paths)
    for keyspace in DATA_KEYSPACES:
        assert keyspace in corpus_paths, (
            f"{keyspace} is declared a data keyspace but appears nowhere in the "
            f"fixture corpus -- either the fixtures do not model it or the "
            f"declaration is stale"
        )


def test_content_shaped_keys_are_declared_data_keyspaces() -> None:
    """Tripwire, and its limits are stated in DATA_KEYSPACES.

    Catches a mapping whose keys are obviously content -- registry paths, URLs,
    anything with a separator or a space. It CANNOT catch a plausible-looking
    policy name, which is why the declared list exists and why this is a
    tripwire rather than a proof.
    """
    suspicious = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                looks_like_content = any(c in str(key) for c in "\\/: ") or len(str(key)) > 60
                if looks_like_content and path not in DATA_KEYSPACES:
                    suspicious.append((path, str(key)))
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for item in node:
                walk(item, path + "[]")

    for bundle_path in sorted(BUNDLES.glob("*.json")):
        facts = json.loads(bundle_path.read_text(encoding="utf-8")).get("facts", {})
        for key, record in facts.items():
            walk(record.get("value"), key)

    assert not suspicious, (
        "content-shaped mapping keys found outside a declared data keyspace; "
        f"the digest would export them literally: {suspicious}"
    )


# --------------------------------------------------------------------------
# 2. The diff catches the defect it was built for. THE load-bearing test.
# --------------------------------------------------------------------------


def test_the_diff_catches_the_display_name_defect() -> None:
    """Reintroduce PR 17's bug in source and assert the harness fails.

    `browsers.py` read `display_name` where `Get-InstalledApplications.ps1`
    emits `name`: every real host would have found zero browsers forever, while
    260 tests passed because the fixtures were written from the same wrong
    assumption as the code. A diff of two artefacts written from one assumption
    cannot see that, which is why the evaluators' own read set is a third leg.
    """
    source = (CHECKS / "windows" / "browsers.py").read_text(encoding="utf-8")
    assert 'app.get("name"' in source, "the fixed code no longer reads `name`"

    lab = digest_bundle(
        json.loads((BUNDLES / "wks-0045-browsers.json").read_text(encoding="utf-8")), SALT
    )
    corpus = _corpus()

    clean_reads, _ = reads_in_source(source)
    broken_reads, fact_keys = reads_in_source(source.replace('app.get("name"', 'app.get("display_name"'))

    assert "display_name" in broken_reads and "display_name" not in clean_reads

    def as_package(reads):
        return {k: {"files": ["browsers.py"], "facts": sorted(fact_keys)} for k in reads}

    clean = diff.reconcile(lab, corpus, as_package(clean_reads), {})
    broken = diff.reconcile(lab, corpus, as_package(broken_reads), {})

    assert "display_name" not in clean["hard_failures"]["keys_read_but_never_emitted"]
    assert "display_name" in broken["hard_failures"]["keys_read_but_never_emitted"], (
        "the harness did not notice an evaluator reading a key nothing emits -- "
        "which is the entire defect it exists to catch"
    )
    assert broken["ok"] is False


def test_a_hard_failure_is_scoped_to_facts_the_run_carried() -> None:
    """An Entra key is not a finding against a Windows domain controller."""
    lab = digest_bundle(
        {
            "subject": {"platform_family": "windows"},
            "facts": {"windows.applications.installed": {"source": "r", "value": [{"name": "x"}]}},
        },
        SALT,
    )
    reads = {
        "policyType": {"files": ["authentication.py"], "facts": ["entra.conditional_access_policies"]}
    }
    report = diff.reconcile(lab, _corpus(), reads, {})
    assert "policyType" not in report["hard_failures"]["keys_read_but_never_emitted"]
    assert "policyType" in report["review"]["keys_never_exercised_by_a_bundle"]


# --------------------------------------------------------------------------
# 3. An empty collector must FAIL, not read as agreement.
# --------------------------------------------------------------------------


def test_the_declared_floors_parse_and_cover_both_platforms() -> None:
    floors = yaml.safe_load(FLOORS.read_text(encoding="utf-8"))
    assert set(floors) >= {"windows", "linux"}
    for platform, facts in floors.items():
        for fact_key, spec in facts.items():
            assert spec.get("require"), f"{platform}/{fact_key} declares no requirement"
            for requirement in spec["require"]:
                assert requirement["path"].startswith(fact_key.split("[")[0]), (
                    f"{platform}/{fact_key}: floor path {requirement['path']!r} is "
                    f"not under the fact it belongs to"
                )


def test_an_empty_fact_fails_its_floor_rather_than_reading_as_agreement() -> None:
    """The constraint that makes a domain-controller run safe.

    On a DC, Office is not installed and no Edge policy exists. A shape diff
    over those empty facts yields zero differences, which reads as agreement.
    """
    floors = {
        "windows.browsers.policy": {
            "require": [{"path": "windows.browsers.policy.rows", "min_n": 1}]
        }
    }
    empty = digest_bundle(
        {
            "subject": {"platform_family": "windows"},
            "facts": {
                "windows.browsers.policy": {"source": "r", "value": {"rows": [], "meta": {}}}
            },
        },
        SALT,
    )
    report = diff.reconcile(empty, _corpus(), {}, floors)
    assert report["ok"] is False
    unmet = report["hard_failures"]["floors_unmet"]
    assert any(f["path"] == "windows.browsers.policy.rows" for f in unmet), unmet

    populated = digest_bundle(
        {
            "subject": {"platform_family": "windows"},
            "facts": {
                "windows.browsers.policy": {
                    "source": "r",
                    "value": {"rows": [{"browser": "edge"}], "meta": {}},
                }
            },
        },
        SALT,
    )
    assert diff.reconcile(populated, _corpus(), {}, floors)["ok"] is True


def test_a_partial_collection_fails_its_floor() -> None:
    """`partial` means the host could not be read. That is never a pass."""
    floors = {"os.release": {"require": [{"path": "os.release.product_name"}]}}
    digest = digest_bundle(
        {
            "subject": {"platform_family": "windows"},
            "facts": {
                "os.release": {
                    "source": "r",
                    "partial": True,
                    "value": {"product_name": "Windows Server 2022"},
                }
            },
        },
        SALT,
    )
    report = diff.reconcile(digest, _corpus(), {}, floors)
    assert report["ok"] is False
    assert any("partial" in f["reason"] for f in report["hard_failures"]["floors_unmet"])


def test_leaf_strips_list_and_wildcard_markers() -> None:
    assert diff.leaf("windows.applications.installed[].name") == "name"
    assert diff.leaf("windows.browsers.java_surface.javasoft.*") == "javasoft"
    assert diff.leaf("os.release") == "release"
