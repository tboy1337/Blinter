"""Blinter package module."""

from pathlib import Path
import re
from typing import (
    Dict,
    List,
    Optional,
    Set,
)
from blinter.logging_config import logger
from blinter.parsing.structure import _collect_set_variables

def _extract_called_scripts(batch_file: Path) -> List[Path]:
    """
    Extract paths to scripts called by CALL statements in a batch file.

    Args:
        batch_file: Path to the batch file to analyze

    Returns:
        List of Path objects for called scripts that exist
    """
    called_scripts: List[Path] = []
    batch_dir = batch_file.parent

    try:
        with open(batch_file, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                # Skip comments
                stripped = line.strip().lower()
                if stripped.startswith("rem ") or stripped.startswith("::"):
                    continue

                # Look for CALL statements with .bat or .cmd files
                # Pattern: CALL "path\script.bat" or CALL %~dp0script.bat, etc.
                call_match = re.search(
                    r'\bcall\s+(?:"([^"]+\.(?:bat|cmd))"|([^\s]+\.(?:bat|cmd)))',
                    line,
                    re.IGNORECASE,
                )

                if call_match:
                    # Get the script path (from either quoted or unquoted group)
                    script_path_str = call_match.group(1) or call_match.group(2)

                    # Resolve batch parameter expansions
                    # %~dp0 = directory of current script
                    if "%~dp0" in script_path_str:
                        script_path_str = script_path_str.replace("%~dp0", "")
                        # Path is relative to batch file directory
                        script_path = batch_dir / script_path_str
                    elif "%~d0" in script_path_str:
                        script_path_str = script_path_str.replace(
                            "%~d0", str(batch_dir.drive)
                        )
                        script_path = Path(script_path_str)
                    else:
                        # Try to resolve the path
                        script_path = Path(script_path_str)
                        if not script_path.is_absolute():
                            # Try relative to batch file directory
                            script_path = batch_dir / script_path_str

                    # Try to resolve the path
                    try:
                        # Check if file exists
                        if script_path.exists() and script_path.is_file():
                            # Avoid circular references
                            if script_path.resolve() != batch_file.resolve():
                                called_scripts.append(script_path)
                    except (ValueError, OSError):
                        # Invalid path, skip
                        continue

    except (OSError, UnicodeDecodeError):
        # If we can't read the file, return empty list
        pass

    return called_scripts

def _resolve_call_script_path(script_path_str: str, batch_dir: Path) -> Optional[Path]:
    """
    Resolve a CALL script path with batch parameter expansions.

    Args:
        script_path_str: The script path string from the CALL statement
        batch_dir: The directory containing the batch file

    Returns:
        Resolved Path object, or None if resolution fails
    """
    # Resolve batch parameter expansions
    if "%~dp0" in script_path_str:
        script_path_str = script_path_str.replace("%~dp0", "")
        return batch_dir / script_path_str
    if "%~d0" in script_path_str:
        script_path_str = script_path_str.replace("%~d0", str(batch_dir.drive))
        return Path(script_path_str)

    script_path = Path(script_path_str)
    if not script_path.is_absolute():
        return batch_dir / script_path_str
    return script_path

def _try_add_dependency(
    script_path: Path, batch_file_resolved: Path, deps: Set[Path]
) -> None:
    """
    Try to add a dependency if the script path is valid.

    Args:
        script_path: Path to the script file
        batch_file_resolved: Resolved path of the current batch file
        deps: Set to add the dependency to
    """
    try:
        if not (script_path.exists() and script_path.is_file()):
            return
        resolved_script = script_path.resolve()
        if resolved_script != batch_file_resolved:
            deps.add(resolved_script)
    except (ValueError, OSError) as dependency_error:
        logger.debug("Skipping dependency %s: %s", script_path, dependency_error)

def _extract_direct_dependencies(
    batch_file: Path, batch_file_resolved: Path
) -> Set[Path]:
    """
    Extract direct dependencies from a batch file by parsing CALL statements.

    Args:
        batch_file: Path to the batch file
        batch_file_resolved: Resolved path of the batch file

    Returns:
        Set of resolved Path objects that this file directly depends on
    """
    deps: Set[Path] = set()
    try:
        with open(batch_file, "r", encoding="utf-8", errors="ignore") as file:
            batch_dir = batch_file.parent

            for line in file:
                # Skip comments
                stripped = line.strip().lower()
                if stripped.startswith("rem ") or stripped.startswith("::"):
                    continue

                # Look for CALL statements with .bat or .cmd files
                call_match = re.search(
                    r'\bcall\s+(?:"([^"]+\.(?:bat|cmd))"|([^\s]+\.(?:bat|cmd)))',
                    line,
                    re.IGNORECASE,
                )

                if not call_match:
                    continue

                script_path_str = call_match.group(1) or call_match.group(2)
                script_path = _resolve_call_script_path(script_path_str, batch_dir)

                if script_path:
                    _try_add_dependency(script_path, batch_file_resolved, deps)

    except (OSError, UnicodeDecodeError):
        pass

    return deps

def _build_call_dependency_graph(batch_files: List[Path]) -> Dict[Path, Set[Path]]:
    """
    Build a dependency graph showing which batch files call which other files.

    This function scans all provided batch files and builds a directed graph of
    CALL relationships. The graph includes transitive dependencies, so if fileA
    calls fileB and fileB calls fileC, then fileA's dependencies include both
    fileB and fileC.

    Args:
        batch_files: List of Path objects representing batch files to analyze

    Returns:
        Dictionary mapping each file Path to a Set of Path objects it depends on
        (directly or transitively via CALL statements).
    """
    # First pass: build direct dependencies only
    direct_deps: Dict[Path, Set[Path]] = {}

    for batch_file in batch_files:
        batch_file_resolved = batch_file.resolve()
        direct_deps[batch_file_resolved] = _extract_direct_dependencies(
            batch_file, batch_file_resolved
        )

    # Second pass: compute transitive closure
    transitive_deps: Dict[Path, Set[Path]] = {}

    def get_all_deps(file_path: Path, visited: Set[Path]) -> Set[Path]:
        """Recursively get all dependencies (direct and transitive)."""
        if file_path in visited:
            return set()

        visited.add(file_path)
        all_deps = set(direct_deps.get(file_path, set()))

        # Add transitive dependencies
        for dep in list(all_deps):
            all_deps.update(get_all_deps(dep, visited))

        return all_deps

    for batch_file in batch_files:
        batch_file_resolved = batch_file.resolve()
        transitive_deps[batch_file_resolved] = get_all_deps(batch_file_resolved, set())

    return transitive_deps

def _collect_vars_from_dependencies(
    batch_file_resolved: Path,
    dependency_graph: Dict[Path, Set[Path]],
) -> Dict[int, Set[str]]:
    """
    Collect variables from all dependencies in the dependency graph.

    Args:
        batch_file_resolved: Resolved path to the batch file
        dependency_graph: Pre-built graph of file dependencies from folder scan

    Returns:
        Dictionary with {0: all_vars} where all_vars includes variables from all
        dependencies in the graph.
    """
    all_vars: Set[str] = set()
    dependencies = dependency_graph.get(batch_file_resolved, set())

    for dep_file in dependencies:
        try:
            with open(dep_file, "r", encoding="utf-8", errors="ignore") as called_file:
                called_lines = called_file.readlines()
                # Collect variables from the dependency
                dep_vars = _collect_set_variables(called_lines)
                # Remove special markers like __DYNAMIC_VARS__
                dep_vars.discard("__DYNAMIC_VARS__")
                all_vars.update(dep_vars)
        except (ValueError, OSError, UnicodeDecodeError):
            # If we can't read a dependency, skip it
            continue

    # Store all variables as available from line 0 (start of file)
    return {0: all_vars} if all_vars else {}

def _resolve_script_path(script_path_str: str, batch_dir: Path) -> Path:
    """
    Resolve a script path from a CALL statement.

    Args:
        script_path_str: The script path string from the CALL statement
        batch_dir: The directory of the batch file containing the CALL

    Returns:
        Resolved Path object for the script
    """
    # Resolve batch parameter expansions
    if "%~dp0" in script_path_str:
        script_path_str = script_path_str.replace("%~dp0", "")
        return batch_dir / script_path_str
    if "%~d0" in script_path_str:
        script_path_str = script_path_str.replace("%~d0", str(batch_dir.drive))
        return Path(script_path_str)

    script_path = Path(script_path_str)
    if not script_path.is_absolute():
        return batch_dir / script_path_str
    return script_path

def _collect_vars_from_script(
    script_path: Path,
    batch_file_resolved: Path,
) -> Set[str]:
    """
    Collect variables from a called script.

    Args:
        script_path: Path to the called script
        batch_file_resolved: Resolved path to the calling batch file

    Returns:
        Set of variable names defined in the called script
    """
    if not (script_path.exists() and script_path.is_file()):
        return set()

    # Avoid circular references
    if script_path.resolve() == batch_file_resolved:
        return set()

    try:
        with open(script_path, "r", encoding="utf-8", errors="ignore") as called_file:
            called_lines = called_file.readlines()
            # Collect variables from the called script
            called_vars = _collect_set_variables(called_lines)
            # Remove special markers like __DYNAMIC_VARS__
            called_vars.discard("__DYNAMIC_VARS__")
            return called_vars
    except (ValueError, OSError, UnicodeDecodeError):
        return set()

def _collect_called_vars(
    batch_file: Path,
    dependency_graph: Optional[Dict[Path, Set[Path]]] = None,
) -> Dict[int, Set[str]]:
    """
    For each CALL statement in the batch file, collect variables from the called script.

    This function implements position-aware variable tracking: variables from called scripts
    are only considered "defined" for lines AFTER the CALL statement that invokes them.

    When a dependency_graph is provided (from folder scanning with --follow-calls), this
    function collects variables from all dependencies in the graph, making them available
    from line 0 (start of file) since we're treating the entire folder as interconnected.

    Args:
        batch_file: Path to the batch file to analyze
        dependency_graph: Optional pre-built graph of file dependencies from folder scan

    Returns:
        Dictionary mapping line numbers to sets of variables available after that line.
        For example, if line 10 has a CALL to a script that defines VAR1 and VAR2,
        the returned dict will have {10: {'VAR1', 'VAR2'}}.

        When dependency_graph is provided, returns {0: all_vars} where all_vars includes
        variables from all dependencies in the graph.
    """
    batch_file_resolved = batch_file.resolve()

    # If we have a dependency graph, use it to collect all variables from dependencies
    if dependency_graph is not None:
        return _collect_vars_from_dependencies(batch_file_resolved, dependency_graph)

    # Original behavior: scan for CALL statements line by line
    called_vars_by_line: Dict[int, Set[str]] = {}
    batch_dir = batch_file.parent

    try:
        with open(batch_file, "r", encoding="utf-8", errors="ignore") as file:
            for line_num, line in enumerate(file, start=1):
                # Skip comments
                stripped = line.strip().lower()
                if stripped.startswith("rem ") or stripped.startswith("::"):
                    continue

                # Look for CALL statements with .bat or .cmd files
                call_match = re.search(
                    r'\bcall\s+(?:"([^"]+\.(?:bat|cmd))"|([^\s]+\.(?:bat|cmd)))',
                    line,
                    re.IGNORECASE,
                )

                if call_match:
                    # Get the script path (from either quoted or unquoted group)
                    script_path_str = call_match.group(1) or call_match.group(2)
                    script_path = _resolve_script_path(script_path_str, batch_dir)

                    # Try to read the called script and collect its variables
                    called_vars = _collect_vars_from_script(
                        script_path, batch_file_resolved
                    )
                    if called_vars:
                        called_vars_by_line[line_num] = called_vars

    except (OSError, UnicodeDecodeError):
        # If we can't read the main file, return empty dict
        pass

    return called_vars_by_line
