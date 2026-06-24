"""Sync __version__ in src/blinter/_version.py from pyproject.toml [project].version."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
VERSION_PATH = ROOT / "src" / "blinter" / "_version.py"
PYPROJECT_PATH = ROOT / "pyproject.toml"


def read_pyproject_version() -> str:
    """Return the package version from pyproject.toml."""
    with PYPROJECT_PATH.open("rb") as pyproject_file:
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


def sync_version_to_package(version: str) -> None:
    """Rewrite __version__ in src/blinter/_version.py."""
    text = VERSION_PATH.read_text(encoding="utf-8")
    text, version_assignments = re.subn(
        r'^__version__ = "[^"]+"',
        f'__version__ = "{version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if version_assignments != 1:
        raise ValueError("Failed to update __version__ assignment in _version.py")
    VERSION_PATH.write_text(text, encoding="utf-8")


def main() -> None:
    """Sync package version fields from pyproject.toml."""
    version = read_pyproject_version()
    sync_version_to_package(version)
    print(f"Synced src/blinter/_version.py to version {version}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
