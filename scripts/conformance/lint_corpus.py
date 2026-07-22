#!/usr/bin/env python3
"""Implementation-agnostic linter corpus conformance CLI.

Delegates to scripts/spec/validate_corpus.py for the Python implementation.
Future alternate binaries can be selected via --impl.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_VALIDATE_CORPUS = _REPO_ROOT / "scripts" / "spec" / "validate_corpus.py"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Blinter linter corpus conformance checks"
    )
    parser.add_argument(
        "--impl",
        choices=("python",),
        default="python",
        help="Linter implementation to exercise (default: python)",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=_REPO_ROOT / "spec" / "corpus",
        help="Corpus root directory (only spec/corpus is supported today)",
    )
    parser.add_argument(
        "--lint-only",
        action="store_true",
        help="Only run live lint assertions, skip schema validation",
    )
    args = parser.parse_args()

    if args.impl != "python":
        raise SystemExit(f"Unsupported implementation: {args.impl}")

    corpus = args.corpus.resolve()
    expected_corpus = (_REPO_ROOT / "spec" / "corpus").resolve()
    if corpus != expected_corpus:
        raise SystemExit(
            f"Custom corpus paths are not yet supported; use {expected_corpus}"
        )

    cmd = [sys.executable, str(_VALIDATE_CORPUS)]
    if args.lint_only:
        cmd.append("--lint-only")
    raise SystemExit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
