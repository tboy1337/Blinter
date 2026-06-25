"""Batch file discovery in directories and paths."""

from pathlib import Path
from typing import List, Optional, Union

from blinter.constants import MAX_SCAN_FILES
from blinter.logging_config import logger


def _resolved_is_under_root(resolved: Path, root_resolved: Path) -> bool:
    """Return True when resolved is inside root_resolved."""
    try:
        resolved.relative_to(root_resolved)
        return True
    except ValueError:
        return False


def is_path_under_root(path: Path, root: Path) -> bool:
    """Return True when path resolves inside root without symlink escape."""
    try:
        root_resolved = root.resolve()
        candidate = path if path.is_absolute() else Path.cwd() / path

        for part in [candidate, *candidate.parents]:
            if part.is_symlink():
                link_target = part.readlink()
                resolved_link = (
                    link_target
                    if link_target.is_absolute()
                    else (part.parent / link_target)
                )
                try:
                    resolved_link = resolved_link.resolve()
                except OSError:
                    return False
                if not _resolved_is_under_root(resolved_link, root_resolved):
                    return False

        return _resolved_is_under_root(candidate.resolve(), root_resolved)
    except (OSError, ValueError) as path_error:
        logger.debug("Path %s is not under root %s: %s", path, root, path_error)
        return False


def find_batch_files(
    path: Union[str, Path],
    recursive: bool = True,
    root: Optional[Path] = None,
    max_scan_files: int = MAX_SCAN_FILES,
) -> List[Path]:
    """
    Find all batch files (.bat and .cmd) in a directory or return single file.

    Args:
        path: Path to file or directory to search
        recursive: Whether to search subdirectories recursively (default: True)
        root: When set, only return files that resolve inside this directory
        max_scan_files: Maximum batch files returned from a directory scan (default: 1000)

    Returns:
        List of Path objects representing batch files found

    Raises:
        FileNotFoundError: If the path doesn't exist
        ValueError: If path is not a file or directory
    """
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if path_obj.is_file():
        # Return single file if it's a batch file
        if path_obj.suffix.lower() in [".bat", ".cmd"]:
            if root is not None and not is_path_under_root(path_obj, root):
                return []
            return [path_obj]
        raise ValueError(f"File '{path}' is not a batch file (.bat or .cmd)")

    if path_obj.is_dir():
        # Find all batch files in directory
        batch_files: List[Path] = []

        if recursive:
            # Recursive search
            for pattern in ["**/*.bat", "**/*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))
        else:
            # Non-recursive search
            for pattern in ["*.bat", "*.cmd"]:
                batch_files.extend(path_obj.glob(pattern))

        if root is not None:
            batch_files = [
                batch_file
                for batch_file in batch_files
                if is_path_under_root(batch_file, root)
            ]

        if len(batch_files) > max_scan_files:
            raise ValueError(
                f"Directory scan found {len(batch_files)} batch files, "
                f"exceeding the limit of {max_scan_files}. "
                "Use a narrower path, disable recursive scanning, "
                "or increase max_scan_files in blinter.ini."
            )

        # Sort for consistent output
        batch_files.sort()
        return batch_files

    raise ValueError(f"Path '{path}' is neither a file nor a directory")
