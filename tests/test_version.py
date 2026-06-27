"""Tests for package version resolution."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import subprocess
import sys

import pytest
from pytest_mock import MockerFixture

from blinter._version import _fallback_version, _pyproject_path, get_version
from blinter.rules.registry import RULE_COUNT
from scripts.generate_file_version_info import (
    _build_version_info,
    _read_project_version,
    _version_tuple,
)


class TestVersion:
    """Tests for get_version and fallback parsing."""

    def test_get_version_uses_installed_metadata_without_pyproject(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test installed metadata is used when pyproject.toml is not present."""
        missing = tmp_path / "missing.toml"
        mocker.patch("blinter._version._pyproject_path", return_value=missing)
        try:
            installed = version("Blinter")
        except PackageNotFoundError:
            pytest.skip("Blinter is not installed")
        assert get_version() == installed

    def test_pyproject_path_points_at_repo_root(self) -> None:
        """Test pyproject path resolves beside the repository root."""
        assert _pyproject_path().name == "pyproject.toml"
        assert _pyproject_path().is_file()

    def test_fallback_reads_pyproject(self, mocker: MockerFixture) -> None:
        """Test fallback parses pyproject.toml when metadata is missing."""
        mocker.patch(
            "blinter._version.version",
            side_effect=PackageNotFoundError("Blinter"),
        )
        mocker.patch("blinter._version._pyproject_path", return_value=Path("missing"))
        version_value = get_version()
        assert version_value == "unknown"

    def test_get_version_reads_pyproject_in_source_tree(self) -> None:
        """Test source checkouts resolve version from pyproject.toml."""
        from tests.conftest import get_project_version

        assert get_version() == get_project_version()

    def test_fallback_unknown_when_pyproject_missing(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test fallback returns unknown when pyproject.toml is absent."""
        missing = tmp_path / "missing.toml"
        mocker.patch("blinter._version._pyproject_path", return_value=missing)
        assert _fallback_version() == "unknown"

    def test_fallback_unknown_without_version_key(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test fallback returns unknown when pyproject has no version field."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'x'\n", encoding="utf-8")
        mocker.patch("blinter._version._pyproject_path", return_value=pyproject)
        assert _fallback_version() == "unknown"

    def test_pyproject_path_uses_meipass_when_frozen(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test frozen executables resolve version from bundled pyproject.toml."""
        bundled = tmp_path / "pyproject.toml"
        bundled.write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
        mocker.patch("blinter._version.sys.frozen", True, create=True)
        mocker.patch("blinter._version.sys._MEIPASS", str(tmp_path), create=True)
        assert _pyproject_path() == bundled
        assert get_version() == "9.9.9"

    def test_readme_rule_count_matches_registry(self) -> None:
        """README should reference the live RULE_COUNT from the registry."""
        readme = (_pyproject_path().parent / "README.md").read_text(encoding="utf-8")
        assert "RULE_COUNT" in readme
        assert re.search(
            rf"\*\*{RULE_COUNT}\*\* rules",
            readme,
        ), f"README must state **{RULE_COUNT}** rules explicitly"


class TestGenerateFileVersionInfo:
    """Tests for Windows executable version resource generation."""

    def test_version_tuple_pads_short_versions(self) -> None:
        """Short version strings should pad missing segments with zero."""
        assert _version_tuple("1") == (1, 0, 0)
        assert _version_tuple("1.2") == (1, 2, 0)
        assert _version_tuple("1.2.3") == (1, 2, 3)

    def test_build_version_info_includes_pyproject_version(self) -> None:
        """Generated VSVersionInfo should embed the project version."""
        from tests.conftest import get_project_version

        project_version = get_project_version()
        content = _build_version_info(project_version)
        assert f"u'{project_version}'" in content
        major, minor, patch = _version_tuple(project_version)
        assert f"filevers=({major}, {minor}, {patch}, 0)" in content
        assert "Blinter.exe" in content
        assert "AGPL-3.0-or-later" in content

    def test_read_project_version_matches_pyproject(self) -> None:
        """Script should read the same version as test helpers."""
        from tests.conftest import get_project_version

        repo_root = Path(__file__).resolve().parent.parent
        assert _read_project_version(repo_root / "pyproject.toml") == get_project_version()

    def test_generate_script_writes_version_file(self) -> None:
        """CLI entry point should write file_version_info.txt in the repo root."""
        repo_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, str(repo_root / "scripts" / "generate_file_version_info.py")],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        output = repo_root / "file_version_info.txt"
        assert output.is_file()
        assert "VSVersionInfo(" in output.read_text(encoding="utf-8")
