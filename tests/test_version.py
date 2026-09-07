"""Tests for package version resolution."""

from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import re
import sys

import pytest
from pytest_mock import MockerFixture

from blinter._version import _fallback_version, _pyproject_path, get_version
from blinter.rules.registry import RULE_COUNT
from scripts.build_exe import (
    COMPANY_NAME,
    FILE_DESCRIPTION,
    ICON_PATH,
    MAIN_FILE,
    OUTPUT_DIR,
    OUTPUT_FILENAME,
    PACKAGE_DIR,
    PRODUCT_NAME,
    TYPED_MARKER,
    _is_windows,
    _read_project_version,
    _validate_inputs,
    build_nuitka_command,
    main,
    nuitka_environment,
    run_nuitka,
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

    def test_pyproject_path_uses_compiled_layout_when_frozen(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test frozen executables resolve version from bundled pyproject.toml."""
        bundled = tmp_path / "pyproject.toml"
        bundled.write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
        package_dir = tmp_path / "blinter"
        package_dir.mkdir()
        version_module = package_dir / "_version.py"
        version_module.write_text("# test fixture\n", encoding="utf-8")
        mocker.patch("blinter._version.sys.frozen", True, create=True)
        mocker.patch("blinter._version.__file__", str(version_module))
        assert _pyproject_path() == bundled
        assert get_version() == "9.9.9"

    def test_pyproject_path_frozen_missing_bundle_stays_in_extract_dir(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Test frozen lookup does not walk out of the Nuitka extract directory."""
        package_dir = tmp_path / "blinter"
        package_dir.mkdir()
        version_module = package_dir / "_version.py"
        version_module.write_text("# test fixture\n", encoding="utf-8")
        mocker.patch("blinter._version.sys.frozen", True, create=True)
        mocker.patch("blinter._version.__file__", str(version_module))
        bundled = tmp_path / "pyproject.toml"
        assert _pyproject_path() == bundled
        assert not bundled.is_file()
        assert _fallback_version() == "unknown"

    def test_readme_rule_count_matches_registry(self) -> None:
        """README should reference the live RULE_COUNT from the registry."""
        readme = (_pyproject_path().parent / "README.md").read_text(encoding="utf-8")
        assert "RULE_COUNT" in readme
        assert re.search(
            rf"\*\*{RULE_COUNT}\*\* rules",
            readme,
        ), f"README must state **{RULE_COUNT}** rules explicitly"


class TestBuildExe:
    """Tests for the Nuitka Windows executable build script."""

    def test_read_project_version_matches_pyproject(self) -> None:
        """Script should read the same version as test helpers."""
        from tests.conftest import get_project_version

        repo_root = Path(__file__).resolve().parent.parent
        assert (
            _read_project_version(repo_root / "pyproject.toml") == get_project_version()
        )

    def test_validate_inputs_requires_pyproject(self, tmp_path: Path) -> None:
        """Build validation should fail loudly when pyproject.toml is missing."""
        with pytest.raises(FileNotFoundError, match="pyproject.toml"):
            _validate_inputs(tmp_path)

    def test_nuitka_environment_prepends_src(self, tmp_path: Path) -> None:
        """Nuitka must import the src/ layout package during compilation."""
        env = nuitka_environment(tmp_path)
        src_dir = str(tmp_path / "src")
        pythonpath = env["PYTHONPATH"]
        assert pythonpath == src_dir or pythonpath.startswith(src_dir + os.pathsep)

    def test_build_command_includes_windows_metadata(self) -> None:
        """Nuitka command must embed icon, version, package, and data files."""
        from tests.conftest import get_project_version

        project_version = get_project_version()
        command = build_nuitka_command(
            version=project_version,
            python_executable=sys.executable,
            windows=True,
            mingw=False,
        )
        joined = " ".join(command)
        assert command[:3] == [sys.executable, "-m", "nuitka"]
        assert "--mode=onefile" in command
        assert "--assume-yes-for-downloads" in command
        assert "--msvc=latest" in command
        assert "--mingw64" not in command
        assert f"--output-filename={OUTPUT_FILENAME}" in command
        assert f"--output-dir={OUTPUT_DIR.as_posix()}" in command
        assert "--include-package=blinter" in command
        assert "--include-package-data=blinter" in command
        assert "--include-module=charset_normalizer" in command
        assert "--include-data-files=pyproject.toml=pyproject.toml" in command
        assert "--python-flag=-m" in command
        assert f"--windows-icon-from-ico={ICON_PATH.as_posix()}" in command
        assert f"--company-name={COMPANY_NAME}" in command
        assert f"--product-name={PRODUCT_NAME}" in command
        assert f"--file-version={project_version}" in command
        assert f"--product-version={project_version}" in command
        assert f"--file-description={FILE_DESCRIPTION}" in command
        assert command[-1] == PACKAGE_DIR.as_posix()
        assert "blinter.exe" in joined

    def test_build_command_uses_mingw_when_requested(self) -> None:
        """Local MinGW builds must opt into the experimental 3.13+ flag."""
        command = build_nuitka_command(
            version="1.2.3",
            python_executable=sys.executable,
            windows=True,
            mingw=True,
        )
        assert "--mingw64" in command
        assert "--experimental=force-mingw64" in command
        assert "--msvc=latest" not in command

    def test_build_command_omits_windows_flags_off_windows(self) -> None:
        """Non-Windows invocations should not pass MSVC or PE resource flags."""
        command = build_nuitka_command(
            version="1.2.3",
            python_executable=sys.executable,
            windows=False,
        )
        assert "--msvc=latest" not in command
        assert "--mingw64" not in command
        assert not any(part.startswith("--windows-icon-from-ico=") for part in command)
        assert not any(part.startswith("--company-name=") for part in command)
        assert command[-1] == PACKAGE_DIR.as_posix()

    def test_application_icon_asset_exists(self) -> None:
        """The ICO referenced by the Nuitka build must be present."""
        repo_root = Path(__file__).resolve().parent.parent
        assert (repo_root / ICON_PATH).is_file(), "Application icon asset is missing"
        assert (repo_root / MAIN_FILE).is_file(), "package __main__ module is missing"
        assert (repo_root / TYPED_MARKER).is_file(), "py.typed marker is missing"
        _validate_inputs(repo_root)

    def test_read_project_version_rejects_missing_version(self, tmp_path: Path) -> None:
        """Invalid pyproject.toml must fail before Nuitka is launched."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'Blinter'\n", encoding="utf-8")
        with pytest.raises(ValueError, match="project.version"):
            _read_project_version(pyproject)

    def test_run_nuitka_returns_subprocess_exit_code(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """A Nuitka compiler failure should surface its exit code."""
        mocker.patch(
            "scripts.build_exe.subprocess.run",
            return_value=mocker.Mock(returncode=7),
        )
        assert run_nuitka([sys.executable, "-m", "nuitka"], tmp_path) == 7

    def test_run_nuitka_fails_when_output_missing(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Success from Nuitka without dist/blinter.exe is still a build failure."""
        mocker.patch(
            "scripts.build_exe.subprocess.run",
            return_value=mocker.Mock(returncode=0),
        )
        assert run_nuitka([sys.executable, "-m", "nuitka"], tmp_path) == 1

    def test_run_nuitka_succeeds_when_exe_exists(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """A completed onefile build must leave dist/blinter.exe in place."""
        dist_dir = tmp_path / OUTPUT_DIR
        dist_dir.mkdir()
        (dist_dir / OUTPUT_FILENAME).write_bytes(b"exe")
        mocker.patch(
            "scripts.build_exe.subprocess.run",
            return_value=mocker.Mock(returncode=0),
        )
        assert run_nuitka([sys.executable, "-m", "nuitka"], tmp_path) == 0

    def test_main_returns_2_when_inputs_missing(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """CLI should exit 2 when required build inputs are absent."""
        mocker.patch("scripts.build_exe.ROOT", tmp_path)
        assert main([]) == 2

    def test_is_windows_matches_os_name(self) -> None:
        """Platform detection must follow os.name without mutating the process."""
        assert _is_windows() is (os.name == "nt")

    def test_main_invokes_nuitka_with_mingw_flag(self, mocker: MockerFixture) -> None:
        """--mingw must reach the Nuitka command line."""
        repo_root = Path(__file__).resolve().parent.parent
        mocker.patch("scripts.build_exe.ROOT", repo_root)
        mocker.patch("scripts.build_exe._is_windows", return_value=True)
        run = mocker.patch("scripts.build_exe.run_nuitka", return_value=0)
        assert main(["--mingw"]) == 0
        command = run.call_args[0][0]
        assert "--mingw64" in command
        assert "--experimental=force-mingw64" in command
        assert run.call_args[0][1] == repo_root

    def test_main_omits_windows_flags_when_not_windows(
        self, mocker: MockerFixture
    ) -> None:
        """POSIX hosts must not receive MSVC or MinGW flags even with --mingw."""
        repo_root = Path(__file__).resolve().parent.parent
        mocker.patch("scripts.build_exe.ROOT", repo_root)
        mocker.patch("scripts.build_exe._is_windows", return_value=False)
        run = mocker.patch("scripts.build_exe.run_nuitka", return_value=0)
        assert main(["--mingw"]) == 0
        command = run.call_args[0][0]
        assert "--mingw64" not in command
        assert "--msvc=latest" not in command
        assert not any(part.startswith("--windows-icon-from-ico=") for part in command)

    def test_main_reports_launch_failures(self, mocker: MockerFixture) -> None:
        """OS errors starting Nuitka should return exit code 1."""
        repo_root = Path(__file__).resolve().parent.parent
        mocker.patch("scripts.build_exe.ROOT", repo_root)
        mocker.patch(
            "scripts.build_exe.run_nuitka",
            side_effect=OSError("nuitka missing"),
        )
        assert main([]) == 1
