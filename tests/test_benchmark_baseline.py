"""Performance regression gate for synthetic lint benchmark."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

_REPO = Path(__file__).resolve().parent.parent


_BENCHMARK_RUNNER = (
    "import runpy, sys; "
    "sys.argv = ['benchmark_lint.py', '--runs', '3', '--check-baseline']; "
    "runpy.run_path('scripts/benchmark_lint.py', run_name='__main__')"
)


def test_synthetic_lint_within_baseline() -> None:
    # Use runpy.run_path instead of executing scripts/benchmark_lint.py directly:
    # on Windows, `python scripts/foo.py` puts scripts/ on sys.path[0] and can
    # make the benchmark subprocess much slower than an equivalent runpy launch.
    result = subprocess.run(
        [sys.executable, "-c", _BENCHMARK_RUNNER],
        cwd=_REPO,
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"benchmark baseline check failed:\n{result.stdout}\n{result.stderr}"
