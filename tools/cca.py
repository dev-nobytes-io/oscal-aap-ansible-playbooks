#!/usr/bin/env python3
"""Repository-local entry point for the `cca` command line.

The implementation lives in `nobytes_cca.cli` so that a wheel installed into an
execution environment is self-contained. This shim exists so contributors and
CI can run the CLI straight from a checkout without installing anything.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nobytes_cca.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
