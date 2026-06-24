"""pytest configuration and shared fixtures for blinter tests."""

from pathlib import Path
import tomllib
from typing import Any, Callable, Generator
from unittest.mock import MagicMock, patch
import warnings

import pytest

try:
    import coverage.misc

    COVERAGE_AVAILABLE = True
except ImportError:
    COVERAGE_AVAILABLE = False


def make_mock_encoding_path(read_data: bytes = b"test content\n") -> MagicMock:
    """Return a Path-like mock whose read_bytes() returns the given payload."""
    mock_path = MagicMock(spec=Path)
    mock_path.read_bytes.return_value = read_data
    return mock_path


def patch_valid_encoding_path(read_data: bytes = b"test content\n") -> Any:
    """Bypass filesystem checks for mocked encoding read tests."""
    return patch(
        "blinter.io.encoding._validate_file_for_read",
        return_value=make_mock_encoding_path(read_data),
    )


def get_project_version() -> str:
    """Return the package version from pyproject.toml."""
    project_root = Path(__file__).resolve().parent.parent
    with (project_root / "pyproject.toml").open("rb") as pyproject_file:
        pyproject_data_object: object = tomllib.load(pyproject_file)
    if not isinstance(pyproject_data_object, dict):
        raise ValueError("pyproject.toml must contain a top-level table")
    project_object: object = pyproject_data_object.get("project")
    if not isinstance(project_object, dict):
        raise ValueError("pyproject.toml must contain a [project] table")
    version_object: object = project_object.get("version")
    if not isinstance(version_object, str) or not version_object:
        raise ValueError("pyproject.toml [project].version must be a non-empty string")
    return version_object


@pytest.fixture
def write_batch_file(tmp_path: Path) -> Callable[[str, str], Path]:
    """Write batch script content to a file under the pytest tmp directory."""

    def _write(content: str, name: str = "test.bat") -> Path:
        script_path = tmp_path / name
        script_path.write_text(content, encoding="utf-8")
        return script_path

    return _write


@pytest.fixture(autouse=True)
def suppress_test_warnings() -> Generator[None, None, None]:
    """Suppress expected warnings during tests.

    These warnings are expected when testing various scenarios and
    should not clutter the test output.
    """
    # Suppress encoding warnings
    warnings.filterwarnings(
        "ignore",
        message="File .* was read using .* encoding instead of UTF-8.*",
        category=UserWarning,
    )

    # Suppress coverage warnings about configuration
    if COVERAGE_AVAILABLE:
        warnings.filterwarnings("ignore", category=coverage.misc.CoverageWarning)

    yield
    # Reset warnings after test
    warnings.resetwarnings()
