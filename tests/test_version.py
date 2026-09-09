"""Tests for package version resolution."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

import pytest
from pytest_mock import MockerFixture

from blinter._version import _fallback_version, _pyproject_path, get_version
from blinter.rules.registry import RULE_COUNT
from scripts.extract_release_notes import extract_latest_section
from scripts.generate_file_version_info import (
    _build_version_info,
    _read_project_version,
    _version_tuple,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_UV_EXECUTABLE = shutil.which("uv")


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
        assert "blinter.exe" in content
        assert "AGPL-3.0-or-later" in content

    def test_read_project_version_matches_pyproject(self) -> None:
        """Script should read the same version as test helpers."""
        from tests.conftest import get_project_version

        repo_root = Path(__file__).resolve().parent.parent
        assert (
            _read_project_version(repo_root / "pyproject.toml") == get_project_version()
        )

    def test_generate_script_writes_version_file(self) -> None:
        """CLI entry point should write file_version_info.txt in the repo root."""
        repo_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [
                sys.executable,
                str(repo_root / "scripts" / "generate_file_version_info.py"),
            ],
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


class TestBlinterSpecIcon:
    """Tests for PyInstaller spec icon configuration."""

    def test_blinter_spec_references_application_icon(self) -> None:
        """Blinter.spec must embed resources/blinter_icon.ico in the Windows exe."""
        repo_root = Path(__file__).resolve().parent.parent
        icon_path = repo_root / "resources" / "blinter_icon.ico"
        spec_path = repo_root / "Blinter.spec"

        assert icon_path.is_file(), "Application icon asset is missing"
        spec_text = spec_path.read_text(encoding="utf-8")
        assert re.search(
            r"""icon\s*=\s*["']resources/blinter_icon\.ico["']""",
            spec_text,
        ), "Blinter.spec must set icon=resources/blinter_icon.ico"


class TestUvSupport:
    """Tests that uv remains a documented, resolvable install path."""

    def test_readme_documents_uv_tool_and_uvx(self) -> None:
        """README must document persistent and one-shot uv install commands."""
        readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "uv tool install Blinter" in readme
        assert "uvx blinter" in readme

    def test_contributing_documents_uv_sync(self) -> None:
        """CONTRIBUTING must document uv sync with the dev extra."""
        contributing = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert "uv sync --extra dev" in contributing

    def test_pyproject_declares_uv_package_and_dev_extra(self) -> None:
        """pyproject.toml must keep the uv package flag and pip dev extra."""
        with (_REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
            pyproject_data: object = tomllib.load(pyproject_file)
        assert isinstance(pyproject_data, dict)
        tool_object: object = pyproject_data.get("tool")
        assert isinstance(tool_object, dict)
        uv_object: object = tool_object.get("uv")
        assert isinstance(uv_object, dict)
        assert uv_object.get("package") is True
        project_object: object = pyproject_data.get("project")
        assert isinstance(project_object, dict)
        extras_object: object = project_object.get("optional-dependencies")
        assert isinstance(extras_object, dict)
        dev_extra: object = extras_object.get("dev")
        assert isinstance(dev_extra, list)
        assert len(dev_extra) > 0

    @pytest.mark.skipif(_UV_EXECUTABLE is None, reason="uv is not installed")
    def test_uv_resolves_dev_extra(self) -> None:
        """uv must be able to compile pyproject.toml with the dev extra."""
        assert _UV_EXECUTABLE is not None
        result = subprocess.run(
            [
                _UV_EXECUTABLE,
                "pip",
                "compile",
                "pyproject.toml",
                "--extra",
                "dev",
                "--quiet",
            ],
            cwd=_REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        compiled = result.stdout.casefold()
        assert "charset-normalizer" in compiled or "charset_normalizer" in compiled
        assert "pytest" in compiled


class TestExtractReleaseNotes:
    """Tests for changelog section extraction used by GitHub Releases."""

    def test_skips_unreleased_and_returns_latest_version(self, tmp_path: Path) -> None:
        """Unreleased notes must not replace the latest versioned section."""
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "### Added\n\n"
            "- In-progress work\n\n"
            "## [1.2.3] - 2026-01-01\n\n"
            "### Fixed\n\n"
            "- Released fix\n\n"
            "## [1.2.2] - 2025-12-01\n\n"
            "### Added\n\n"
            "- Older change\n",
            encoding="utf-8",
        )
        section = extract_latest_section(changelog)
        assert "[1.2.3]" in section
        assert "Released fix" in section
        assert "Unreleased" not in section
        assert "In-progress work" not in section

    def test_extracts_first_section_when_no_unreleased(self, tmp_path: Path) -> None:
        """The newest versioned heading is used when Unreleased is absent."""
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "## [9.9.9] - 2026-09-01\n\nOnly this.\n",
            encoding="utf-8",
        )
        assert "9.9.9" in extract_latest_section(changelog)

    def test_repo_changelog_latest_versioned_section_is_non_empty(self) -> None:
        """The repository changelog must yield a versioned release section."""
        section = extract_latest_section(_REPO_ROOT / "CHANGELOG.md")
        assert section.startswith("## [")
        assert not section.lower().startswith("## [unreleased]")
        assert len(section) > 20
