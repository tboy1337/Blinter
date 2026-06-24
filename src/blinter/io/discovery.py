"""Batch file discovery in directories and paths."""
from pathlib import Path
from typing import List, Union


def is_path_under_root(path: Path, root: Path) -> bool:
    """Return True when path resolves inside root."""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def find_batch_files(path: Union[str, Path], recursive: bool = True) -> List[Path]:
    """
    Find all batch files (.bat and .cmd) in a directory or return single file.

    Args:
        path: Path to file or directory to search
        recursive: Whether to search subdirectories recursively (default: True)

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

        # Sort for consistent output
        batch_files.sort()
        return batch_files

    raise ValueError(f"Path '{path}' is neither a file nor a directory")
