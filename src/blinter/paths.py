"""Cross-platform path helpers for batch file tooling."""

from __future__ import annotations

import os
from pathlib import Path


def path_basename(path: str) -> str:
    """Return the final path segment, handling Windows separators on any OS."""
    normalized = path.replace("\\", "/")
    if normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    return normalized.rsplit("/", 1)[-1]


def display_path(
    file_path: str,
    target_path: str,
    *,
    is_directory: bool,
) -> str:
    """Format a path for CLI output on Windows and non-Windows runners."""
    if not is_directory:
        return path_basename(file_path)

    file_norm = file_path.replace("\\", "/")
    target_norm = target_path.replace("\\", "/").rstrip("/")
    if file_norm.startswith(f"{target_norm}/"):
        return file_norm[len(target_norm) + 1 :]

    try:
        return str(Path(file_path).relative_to(Path(target_path)))
    except ValueError:
        return path_basename(file_path)


def paths_equal(left: str, right: str) -> bool:
    """Compare paths using OS-appropriate case sensitivity."""
    left_resolved = str(Path(left))
    right_resolved = str(Path(right))
    if os.path.normcase(left_resolved) == os.path.normcase(right_resolved):
        return True
    return left_resolved == right_resolved
