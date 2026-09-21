#!/usr/bin/env python3
"""Verify that every relative Markdown link in the repository resolves.

This repository's documentation is heavily cross-linked and is a deliverable in
its own right -- a compliance tool whose stated limits point at a 404 is not
documenting its limits. Without a check, those links rot silently.

External (http/https) links are not fetched: CI must work air-gapped, and a
network-dependent docs check would be flaky for no benefit.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# `blueprint/` holds Commonwealth content vendored byte-for-byte unmodified.
# Its links are site-absolute for blueprint.asd.gov.au and cannot resolve in a
# checkout -- and we must not "fix" them, because rewriting the licensed
# material is exactly what the CC BY 4.0 attribution says we do not do.
SKIP_PREFIXES = (".venv", ".ansible", ".git", "blueprint/")
SKIP_PARTS = ("collections/ansible_collections/community",)


def is_ours(path: Path) -> bool:
    text = str(path)
    if text.startswith(SKIP_PREFIXES):
        return False
    return all(part not in text for part in SKIP_PARTS)


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)

    files = sorted(p for p in Path().rglob("*.md") if is_ours(p))
    broken: list[str] = []

    for path in files:
        for text, link in LINK.findall(path.read_text(encoding="utf-8")):
            if link.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = (path.parent / link.split("#", 1)[0]).resolve()
            if not target.exists():
                broken.append(f"{path}: [{text}]({link})")

    print(f"checked {len(files)} markdown files")
    if broken:
        print(f"BROKEN LINKS ({len(broken)}):", file=sys.stderr)
        for item in broken:
            print(f"  {item}", file=sys.stderr)
        return 1
    print("all relative links resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
