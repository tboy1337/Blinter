#!/usr/bin/env python3
"""Run local quality checks for Blinter."""

from __future__ import annotations

import argparse
from pathlib import Path
import platform
import subprocess
import sys
from typing import Sequence, cast

# Portable directory names (no platform-specific separators).
_CHECK_DIRS: tuple[str, ...] = ("src", "tests", "scripts")
_VERIFY_SCRIPT = Path("scripts") / "verify.py"
_SPEC_VALIDATE = Path("scripts") / "spec" / "validate_spec.py"
_SPEC_VALIDATE_CORPUS = Path("scripts") / "spec" / "validate_corpus.py"
_SPEC_GENERATE_RULES = Path("scripts") / "spec" / "generate_rules.py"
_SPEC_GENERATE_PARSER = Path("scripts") / "spec" / "generate_parser.py"
_SPEC_GENERATE_DOCS = Path("scripts") / "spec" / "generate_docs.py"
_SPEC_GENERATE_GRAMMAR_RULES = Path("scripts") / "spec" / "generate_grammar_rules.py"
_SPEC_GENERATE_EXPANSION = Path("scripts") / "spec" / "generate_expansion.py"
_SPEC_GENERATE_COMMANDS = Path("scripts") / "spec" / "generate_commands.py"
_SPEC_AUDIT = Path("scripts") / "spec" / "audit_ssot.py"
_SPEC_CMD_ORACLE = Path("scripts") / "spec" / "cmd_oracle.py"
_PACKAGE_DIR = Path("src") / "blinter"
_PYPROJECT = "pyproject.toml"
_PYLINT_OUTPUT = "pylint-output.txt"
_POWERSHELL_SCRIPT = Path("scripts") / "test_exe_smoke.ps1"
_POWERSHELL_HELPERS = Path("scripts") / "TestExeSmoke.Helpers.ps1"
_POWERSHELL_ANALYZER_SETTINGS = Path("scripts") / "PSScriptAnalyzerSettings.psd1"
_PESTER_TEST = Path("scripts") / "TestExeSmoke.Tests.ps1"


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


def _run_autopep8_step(*, cwd: Path, fix: bool) -> None:
    """Run autopep8; in check mode fail when trailing whitespace would change."""
    name = "autopep8 (trailing whitespace)"
    print(f"==> {name}")
    if fix:
        fix_result = subprocess.run(
            _autopep8_args(fix=True),
            cwd=cwd,
            check=False,
        )
        if fix_result.returncode != 0:
            raise SystemExit(f"Step failed: {name} (exit code {fix_result.returncode})")
        return

    check_result = subprocess.run(
        _autopep8_args(fix=False),
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check_result.returncode != 0:
        raise SystemExit(f"Step failed: {name} (exit code {check_result.returncode})")
    diff_output = check_result.stdout + check_result.stderr
    if diff_output.strip():
        print(diff_output, end="" if diff_output.endswith("\n") else "\n")
        raise SystemExit(
            f"Step failed: {name} (trailing whitespace found; run py scripts/verify.py --fix)"
        )


def _isort_args(*, fix: bool) -> list[str]:
    args = _python_m("isort", *_CHECK_DIRS)
    if not fix:
        args.insert(3, "--check-only")
    return args


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _powershell_executable() -> str:
    return "powershell"


def _run_powershell_step(name: str, command: str, *, cwd: Path | None = None) -> None:
    """Run a PowerShell command on Windows."""
    print(f"==> {name}")
    result = subprocess.run(
        [
            _powershell_executable(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        cwd=cwd if cwd is not None else _repo_root(),
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"Step failed: {name} (exit code {result.returncode})")


def _run_windows_powershell_checks(root: Path) -> None:
    """Run PSScriptAnalyzer and Pester checks for the exe smoke script."""
    helpers = root / _POWERSHELL_HELPERS
    runner = root / _POWERSHELL_SCRIPT
    analyzer_settings = root / _POWERSHELL_ANALYZER_SETTINGS
    pester_test = root / _PESTER_TEST

    ensure_modules = (
        "$ErrorActionPreference = 'Stop'; "
        "foreach ($moduleName in @('PSScriptAnalyzer', 'Pester')) { "
        "if (-not (Get-Module -ListAvailable -Name $moduleName)) { "
        "Install-Module -Name $moduleName -Force -Scope CurrentUser -AllowClobber "
        "-Repository PSGallery } }"
    )
    _run_powershell_step("PowerShell module prerequisites", ensure_modules, cwd=root)

    analyzer_command = (
        "$issues = @(); "
        f"foreach ($path in @('{helpers}', '{runner}')) {{ "
        f"$issues += Invoke-ScriptAnalyzer -Path $path -Settings '{analyzer_settings}' "
        "-Severity Warning }; "
        "if ($issues) { $issues | Format-Table -AutoSize; exit 1 }"
    )
    _run_powershell_step(
        "PSScriptAnalyzer (exe smoke scripts)", analyzer_command, cwd=root
    )

    pester_command = (
        "Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop; "
        f"$config = New-PesterConfiguration; "
        f"$config.Run.Path = '{pester_test}'; "
        "$config.Run.PassThru = $true; "
        "$config.Run.Exit = $true; "
        "Invoke-Pester -Configuration $config | Out-Null"
    )
    _run_powershell_step("Pester (exe smoke helpers)", pester_command, cwd=root)


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
        ("validate spec schemas", [sys.executable, str(_SPEC_VALIDATE)]),
        ("validate SSOT corpus", [sys.executable, str(_SPEC_VALIDATE_CORPUS)]),
    ]

    if _is_windows():
        subprocess_steps_before_pylint.append(
            (
                "cmd.exe corpus oracle",
                [sys.executable, str(_SPEC_CMD_ORACLE)],
            )
        )

    subprocess_steps_before_pylint.extend(
        [
            (
                "check generated registry.py",
                [sys.executable, str(_SPEC_GENERATE_RULES), "--check"],
            ),
            (
                "check generated parser",
                [sys.executable, str(_SPEC_GENERATE_PARSER), "--check"],
            ),
            (
                "check generated expansion_data.py",
                [sys.executable, str(_SPEC_GENERATE_EXPANSION), "--check"],
            ),
            (
                "check generated patterns.py",
                [sys.executable, str(_SPEC_GENERATE_COMMANDS), "--check"],
            ),
            (
                "check generated docs catalog",
                [sys.executable, str(_SPEC_GENERATE_DOCS), "--check"],
            ),
            (
                "check generated grammar_rules.py",
                [sys.executable, str(_SPEC_GENERATE_GRAMMAR_RULES), "--check"],
            ),
            (
                "SSOT audit (strict)",
                [sys.executable, str(_SPEC_AUDIT), "--strict"],
            ),
        ]
    )

    formatting_steps: list[tuple[str, list[str]]] = [
        ("isort", _isort_args(fix=fix)),
        ("black", _python_m("black", "--check", *_CHECK_DIRS)),
        (
            "mypy",
            _python_m(
                "mypy",
                package_dir,
                "tests",
                verify_script,
            ),
        ),
    ]

    subprocess_steps_after_pylint: list[tuple[str, list[str]]] = [
        ("pylint (verify)", _python_m("pylint", verify_script)),
        (
            "bandit",
            _python_m("bandit", "-r", package_dir, "-c", _PYPROJECT, "-ll", "-q"),
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

    _run_autopep8_step(cwd=root, fix=fix)

    for name, step_args in formatting_steps:
        _run_step(name, step_args, cwd=root)

    _run_pylint_package(cwd=root, package_dir=package_dir, report_path=pylint_report)

    for name, step_args in subprocess_steps_after_pylint:
        _run_step(name, step_args, cwd=root)

    if _is_windows():
        _run_windows_powershell_checks(root)
    else:
        print("Skipping PowerShell checks (Windows only).")

    print("All verification steps passed.")


if __name__ == "__main__":
    main()
