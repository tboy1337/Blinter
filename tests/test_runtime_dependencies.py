"""Tests that production runtime dependencies are declared and importable."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Final

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_REQUIREMENTS = _REPO_ROOT / "requirements.txt"

# Import-time runtime dependencies required for lint_batch_file to work.
_REQUIRED_RUNTIME_PACKAGES: Final[tuple[str, ...]] = (
    "charset_normalizer",
    "antlr4-python3-runtime",
)


def _read_pyproject_dependencies() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    assert isinstance(deps, list)
    return [str(dep) for dep in deps]


def _read_requirements_packages() -> set[str]:
    packages: set[str] = set()
    for line in _REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        packages.add(stripped.split()[0])
    return packages


class TestRuntimeDependencies:
    """Ensure production installs include every import-time dependency."""

    def test_pyproject_declares_required_runtime_packages(self) -> None:
        """pyproject.toml must list all packages needed at import/lint time."""
        declared = {dep.split("[")[0] for dep in _read_pyproject_dependencies()}
        for package in _REQUIRED_RUNTIME_PACKAGES:
            assert (
                package in declared
            ), f"{package} missing from pyproject.toml [project].dependencies"

    def test_requirements_txt_matches_pyproject_runtime_deps(self) -> None:
        """requirements.txt must mirror pyproject.toml runtime dependencies."""
        pyproject_deps = {dep.split("[")[0] for dep in _read_pyproject_dependencies()}
        requirements_deps = _read_requirements_packages()
        assert pyproject_deps == requirements_deps

    @pytest.mark.slow
    def test_minimal_editable_install_imports_lint_api(self, tmp_path: Path) -> None:
        """pip install -e . without [dev] must expose lint_batch_file."""
        venv_dir = tmp_path / "minimal-venv"
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            timeout=120,
        )
        if sys.platform == "win32":
            python = venv_dir / "Scripts" / "python.exe"
            pip = venv_dir / "Scripts" / "pip.exe"
        else:
            python = venv_dir / "bin" / "python"
            pip = venv_dir / "bin" / "pip"

        subprocess.run(
            [str(pip), "install", "-q", "-e", str(_REPO_ROOT)],
            check=True,
            timeout=300,
        )
        result = subprocess.run(
            [
                str(python),
                "-c",
                "from blinter import lint_batch_file; print('ok')",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr or result.stdout
