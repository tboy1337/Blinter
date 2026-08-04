"""Performance regression gate for synthetic lint benchmark."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

_REPO = Path(__file__).resolve().parent.parent


def test_synthetic_lint_within_baseline() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(_REPO / "scripts" / "benchmark_lint.py"),
            "--runs",
            "3",
            "--check-baseline",
        ],
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"benchmark baseline check failed:\n{result.stdout}\n{result.stderr}"
