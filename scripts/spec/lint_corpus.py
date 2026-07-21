#!/usr/bin/env python3
"""Lint spec/corpus and validate expect.json oracles."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def main() -> None:
    script = _REPO_ROOT / "scripts" / "spec" / "validate_corpus.py"
    raise SystemExit(subprocess.call([sys.executable, str(script)], cwd=_REPO_ROOT))


if __name__ == "__main__":
    main()
