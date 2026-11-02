#!/usr/bin/env python3
"""Compatibility launcher for generating a safe review from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from captive_portal_diagnostics.safe_review import main


if __name__ == "__main__":
    raise SystemExit(main())
