#!/usr/bin/env python3
"""Run local quality checks for Blinter."""

from __future__ import annotations

import argparse
import importlib.metadata
from pathlib import Path
import platform
import re
import subprocess
import sys
import tomllib
from typing import Sequence, cast

_SCRIPTS_SPEC_DIR = Path(__file__).resolve().parent / "spec"
_EXPECTED_ANTLR_RUNTIME_VERSION = "4.13.2"

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


def _check_antlr_runtime_version() -> None:
    """Fail when installed antlr4-python3-runtime drifts from the generator pin."""
    name = "antlr4-python3-runtime"
    expected = _read_antlr_runtime_pin()
    print(f"==> {name} version (expected {expected})")
    try:
        installed = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise SystemExit(f"Step failed: {name} is not installed") from exc

    expected_prefix = ".".join(expected.split(".")[:2])
    installed_prefix = ".".join(installed.split(".")[:2])
    if installed_prefix != expected_prefix:
        raise SystemExit(
            "Step failed: "
            f"{name} {installed} does not match generator pin "
            f"{expected}"
        )


def _read_antlr_runtime_pin() -> str:
    """Read the generator pin from scripts/spec/generate_parser.py."""
    parser_path = _SCRIPTS_SPEC_DIR / "generate_parser.py"
    for line in parser_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("EXPECTED_ANTLR_RUNTIME_VERSION"):
            _, _, value = stripped.partition("=")
            return value.strip().strip('"').strip("'")
    return _EXPECTED_ANTLR_RUNTIME_VERSION


def _normalize_requirement_name(name: str) -> str:
    """Normalize a distribution name for set comparison."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _read_requirements_packages(path: Path) -> set[str]:
    """Return normalized package names from a requirements file."""
    packages: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-r"):
            continue
        package = stripped.split()[0].split("[")[0]
        packages.add(_normalize_requirement_name(package))
    return packages


def _dependency_names_from_list(raw: object) -> set[str]:
    """Extract normalized package names from a TOML list value."""
    if not isinstance(raw, list):
        return set()
    names: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            names.add(_normalize_requirement_name(item))
    return names


def _read_pyproject_dependency_sets(pyproject_path: Path) -> tuple[set[str], set[str]]:
    """Return runtime and dev dependency name sets from pyproject.toml."""
    with pyproject_path.open("rb") as pyproject_file:
        data_object: object = tomllib.load(pyproject_file)
    if not isinstance(data_object, dict):
        raise SystemExit("Step failed: pyproject.toml missing root table")
    project_object: object = data_object.get("project")
    if not isinstance(project_object, dict):
        raise SystemExit("Step failed: pyproject.toml missing [project] table")

    runtime = _dependency_names_from_list(project_object.get("dependencies"))
    optional_object: object = project_object.get("optional-dependencies")
    dev: set[str] = set()
    if isinstance(optional_object, dict):
        dev = _dependency_names_from_list(optional_object.get("dev"))
    return runtime, dev


def _check_requirements_drift(root: Path) -> None:
    """Fail when requirements files drift from pyproject.toml dependency lists."""
    name = "requirements drift (pyproject.toml vs requirements*.txt)"
    print(f"==> {name}")
    pyproject_path = root / _PYPROJECT
    requirements_path = root / "requirements.txt"
    requirements_dev_path = root / "requirements-dev.txt"

    runtime_expected, dev_expected = _read_pyproject_dependency_sets(pyproject_path)
    runtime_actual = _read_requirements_packages(requirements_path)
    dev_actual = _read_requirements_packages(requirements_dev_path) - runtime_actual

    runtime_missing = runtime_expected - runtime_actual
    runtime_extra = runtime_actual - runtime_expected
    dev_missing = dev_expected - dev_actual
    dev_extra = dev_actual - dev_expected

    problems: list[str] = []
    if runtime_missing:
        problems.append(
            f"requirements.txt missing: {', '.join(sorted(runtime_missing))}"
        )
    if runtime_extra:
        problems.append(f"requirements.txt extra: {', '.join(sorted(runtime_extra))}")
    if dev_missing:
        problems.append(
            f"requirements-dev.txt missing: {', '.join(sorted(dev_missing))}"
        )
    if dev_extra:
        problems.append(f"requirements-dev.txt extra: {', '.join(sorted(dev_extra))}")

    if problems:
        raise SystemExit(f"Step failed: {name}\n" + "\n".join(problems))


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
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip pytest (for CI jobs that run tests separately)",
    )
    args = parser.parse_args()
    fix = cast(bool, args.fix)
    skip_tests = cast(bool, args.skip_tests)

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

    _check_requirements_drift(root)
    _check_antlr_runtime_version()

    _run_autopep8_step(cwd=root, fix=fix)

    for name, step_args in formatting_steps:
        _run_step(name, step_args, cwd=root)

    _run_pylint_package(cwd=root, package_dir=package_dir, report_path=pylint_report)

    steps_after_pylint = list(subprocess_steps_after_pylint)
    if skip_tests:
        steps_after_pylint = [
            step for step in steps_after_pylint if step[0] != "pytest"
        ]

    for name, step_args in steps_after_pylint:
        _run_step(name, step_args, cwd=root)

    if _is_windows():
        _run_windows_powershell_checks(root)
    else:
        print("Skipping PowerShell checks (Windows only).")

    print("All verification steps passed.")


if __name__ == "__main__":
    main()
