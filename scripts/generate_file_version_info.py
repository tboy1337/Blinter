#!/usr/bin/env python3
"""Generate Windows version resource file for PyInstaller builds."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "file_version_info.txt"
FILE_DESCRIPTION = "Blinter - Professional Batch File Linter for Windows"
LEGAL_COPYRIGHT = (
    "\\xa9 2026 tboy1337. Licensed under AGPL-3.0-or-later."
)


def _read_project_version(pyproject_path: Path) -> str:
    """Return [project].version from pyproject.toml."""
    with pyproject_path.open("rb") as pyproject_file:
        data = tomllib.load(pyproject_file)
    project = data.get("project")
    if not isinstance(project, dict):
        raise ValueError("Missing [project] table in pyproject.toml")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("Missing project.version in pyproject.toml")
    return version


def _version_tuple(version: str) -> tuple[int, int, int]:
    """Convert a semantic version string to major/minor/patch integers."""
    parts = version.split(".")
    while len(parts) < 3:
        parts.append("0")
    return int(parts[0]), int(parts[1]), int(parts[2])


def _build_version_info(version: str) -> str:
    """Build the PyInstaller VSVersionInfo source text."""
    major, minor, patch = _version_tuple(version)
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'tboy1337'),
        StringStruct(u'FileDescription', u'{FILE_DESCRIPTION}'),
        StringStruct(u'FileVersion', u'{version}'),
        StringStruct(u'InternalName', u'Blinter'),
        StringStruct(u'LegalCopyright', u'{LEGAL_COPYRIGHT}'),
        StringStruct(u'OriginalFilename', u'Blinter.exe'),
        StringStruct(u'ProductName', u'Blinter'),
        StringStruct(u'ProductVersion', u'{version}')])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""


def main() -> int:
    """Write file_version_info.txt for the current pyproject.toml version."""
    pyproject_path = ROOT / "pyproject.toml"
    if not pyproject_path.is_file():
        print(f"ERROR: Expected pyproject.toml in {ROOT}", file=sys.stderr)
        return 2

    try:
        version = _read_project_version(pyproject_path)
        OUTPUT.write_text(
            _build_version_info(version),
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
