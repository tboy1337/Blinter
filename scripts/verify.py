#!/usr/bin/env python3
"""Run local quality checks for Blinter."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
from typing import Sequence, cast

# Portable directory names (no platform-specific separators).
_CHECK_DIRS: tuple[str, ...] = ("src", "tests", "scripts")
_VERIFY_SCRIPT = Path("scripts") / "verify.py"
_PACKAGE_DIR = Path("src") / "blinter"
_PYPROJECT = "pyproject.toml"
_PYLINT_OUTPUT = "pylint-output.txt"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _python_m(module: str, *module_args: str) -> list[str]:
    """Build a ``sys.executable -m module`` command (works on Windows and Unix)."""
    return [sys.executable, "-m", module, *module_args]


def _run_step(name: str, args: Sequence[str], *, cwd: Path | None = None) -> None:
    """Run a subprocess step; raise SystemExit on non-zero exit code."""
    print(f"==> {name}")
    result = subprocess.run(
        list(args),
        cwd=cwd if cwd is not None else _repo_root(),
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"Step failed: {name} (exit code {result.returncode})")


def _run_pylint_package(*, cwd: Path, package_dir: str, report_path: Path) -> None:
    """Run pylint on the package and write UTF-8 output (avoids Windows UTF-16)."""
    print("==> pylint (package)")
    result = subprocess.run(
        _python_m("pylint", package_dir),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    report_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(
            f"Step failed: pylint (package) (exit code {result.returncode})"
        )


def _autopep8_args(*, fix: bool) -> list[str]:
    args = _python_m("autopep8", "--select=W291,W293", "-r", *_CHECK_DIRS)
    mode_flag = "--in-place" if fix else "--diff"
    args.insert(3, mode_flag)
    return args


def _isort_args(*, fix: bool) -> list[str]:
    args = _python_m("isort", *_CHECK_DIRS)
    if not fix:
        args.insert(3, "--check-only")
    return args


def main() -> None:
    """Execute formatting, linting, security, and test checks."""
    parser = argparse.ArgumentParser(description="Run Blinter quality checks.")
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply autopep8 and isort fixes before running checks",
    )
    args = parser.parse_args()
    fix = cast(bool, args.fix)

    root = _repo_root()
    pylint_report = root / _PYLINT_OUTPUT
    verify_script = str(_VERIFY_SCRIPT)
    package_dir = str(_PACKAGE_DIR)

    subprocess_steps_before_pylint: list[tuple[str, list[str]]] = [
        ("autopep8 (trailing whitespace)", _autopep8_args(fix=fix)),
        ("isort", _isort_args(fix=fix)),
        ("black", _python_m("black", "--check", *_CHECK_DIRS)),
        (
            "mypy",
            _python_m("mypy", package_dir, "tests", verify_script),
        ),
    ]

    subprocess_steps_after_pylint: list[tuple[str, list[str]]] = [
        ("pylint (verify)", _python_m("pylint", verify_script)),
        (
            "bandit",
            _python_m("bandit", "-r", package_dir, "-c", _PYPROJECT, "-q"),
        ),
        (
            "pip-audit",
            _python_m(
                "pip_audit", "-r", "requirements.txt", "-r", "requirements-dev.txt"
            ),
        ),
        ("pytest", _python_m("pytest")),
    ]

    for name, step_args in subprocess_steps_before_pylint:
        _run_step(name, step_args, cwd=root)

    _run_pylint_package(cwd=root, package_dir=package_dir, report_path=pylint_report)

    for name, step_args in subprocess_steps_after_pylint:
        _run_step(name, step_args, cwd=root)

    print("All verification steps passed.")


if __name__ == "__main__":
    main()
