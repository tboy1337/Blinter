"""CALL dependency graph and cross-script variable collection."""
from pathlib import Path
import re
from typing import (
    Dict,
    List,
    Optional,
    Set,
)
from blinter.io.discovery import is_path_under_root
from blinter.io.encoding import read_file_with_encoding
from blinter.logging_config import logger
from blinter.parsing.structure import _collect_set_variables


def _is_within_scan_root(path: Path, scan_root: Optional[str]) -> bool:
    """Return True when scan_root is unset or path is inside it."""
    if scan_root is None:
        return True
    return is_path_under_root(path, Path(scan_root))


def _read_batch_lines(path: Path) -> Optional[List[str]]:
    """Read batch file lines using encoding detection."""
    try:
        lines, _encoding = read_file_with_encoding(str(path))
        return lines
    except (OSError, ValueError, UnicodeDecodeError) as read_error:
        logger.debug("Could not read batch file %s: %s", path, read_error)
        return None


def _extract_called_scripts(
    batch_file: Path,
    scan_root: Optional[str] = None,
) -> List[Path]:
    """
    Extract paths to scripts called by CALL statements in a batch file.

    Args:
        batch_file: Path to the batch file to analyze
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        List of Path objects for called scripts that exist
    """
    called_scripts: List[Path] = []
    batch_dir = batch_file.parent

    lines = _read_batch_lines(batch_file)
    if lines is None:
        return called_scripts

    for line in lines:
        stripped = line.strip().lower()
        if stripped.startswith("rem ") or stripped.startswith("::"):
            continue

        call_match = re.search(
            r'\bcall\s+(?:"([^"]+\.(?:bat|cmd))"|([^\s]+\.(?:bat|cmd)))',
            line,
            re.IGNORECASE,
        )

        if not call_match:
            continue

        script_path_str = call_match.group(1) or call_match.group(2)
        script_path = _resolve_call_script_path(script_path_str, batch_dir)
        if script_path is None:
            continue

        try:
            if not (script_path.exists() and script_path.is_file()):
                continue
            if script_path.resolve() == batch_file.resolve():
                continue
            if not _is_within_scan_root(script_path, scan_root):
                logger.debug(
                    "Skipping called script outside scan root: %s", script_path
                )
                continue
            called_scripts.append(script_path)
        except (ValueError, OSError) as path_error:
            logger.debug("Skipping invalid called script path: %s", path_error)
            continue

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
    script_path: Path,
    batch_file_resolved: Path,
    deps: Set[Path],
    scan_root: Optional[str] = None,
) -> None:
    """
    Try to add a dependency if the script path is valid.

    Args:
        script_path: Path to the script file
        batch_file_resolved: Resolved path of the current batch file
        deps: Set to add the dependency to
        scan_root: Optional root directory; paths outside it are skipped
    """
    try:
        if not (script_path.exists() and script_path.is_file()):
            return
        resolved_script = script_path.resolve()
        if resolved_script == batch_file_resolved:
            return
        if not _is_within_scan_root(resolved_script, scan_root):
            logger.debug(
                "Skipping dependency outside scan root: %s", resolved_script
            )
            return
        deps.add(resolved_script)
    except (ValueError, OSError) as dependency_error:
        logger.debug("Skipping dependency %s: %s", script_path, dependency_error)


def _extract_direct_dependencies(
    batch_file: Path,
    batch_file_resolved: Path,
    scan_root: Optional[str] = None,
) -> Set[Path]:
    """
    Extract direct dependencies from a batch file by parsing CALL statements.

    Args:
        batch_file: Path to the batch file
        batch_file_resolved: Resolved path of the batch file
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        Set of resolved Path objects that this file directly depends on
    """
    deps: Set[Path] = set()
    lines = _read_batch_lines(batch_file)
    if lines is None:
        return deps

    batch_dir = batch_file.parent
    for line in lines:
        stripped = line.strip().lower()
        if stripped.startswith("rem ") or stripped.startswith("::"):
            continue

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
            _try_add_dependency(
                script_path, batch_file_resolved, deps, scan_root=scan_root
            )

    return deps


def _build_call_dependency_graph(
    batch_files: List[Path],
    scan_root: Optional[str] = None,
) -> Dict[Path, Set[Path]]:
    """
    Build a dependency graph showing which batch files call which other files.

    This function scans all provided batch files and builds a directed graph of
    CALL relationships. The graph includes transitive dependencies, so if fileA
    calls fileB and fileB calls fileC, then fileA's dependencies include both
    fileB and fileC.

    Args:
        batch_files: List of Path objects representing batch files to analyze
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        Dictionary mapping each file Path to a Set of Path objects it depends on
        (directly or transitively via CALL statements).
    """
    direct_deps: Dict[Path, Set[Path]] = {}

    for batch_file in batch_files:
        batch_file_resolved = batch_file.resolve()
        direct_deps[batch_file_resolved] = _extract_direct_dependencies(
            batch_file, batch_file_resolved, scan_root=scan_root
        )

    transitive_deps: Dict[Path, Set[Path]] = {}

    def get_all_deps(file_path: Path, visited: Set[Path]) -> Set[Path]:
        """Recursively get all dependencies (direct and transitive)."""
        if file_path in visited:
            return set()

        visited.add(file_path)
        all_deps = set(direct_deps.get(file_path, set()))

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
    scan_root: Optional[str] = None,
) -> Dict[int, Set[str]]:
    """
    Collect variables from all dependencies in the dependency graph.

    Args:
        batch_file_resolved: Resolved path to the batch file
        dependency_graph: Pre-built graph of file dependencies from folder scan
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        Dictionary with {0: all_vars} where all_vars includes variables from all
        dependencies in the graph.
    """
    all_vars: Set[str] = set()
    dependencies = dependency_graph.get(batch_file_resolved, set())

    for dep_file in dependencies:
        if not _is_within_scan_root(dep_file, scan_root):
            logger.debug("Skipping dependency outside scan root: %s", dep_file)
            continue

        called_lines = _read_batch_lines(dep_file)
        if called_lines is None:
            continue

        dep_vars = _collect_set_variables(called_lines)
        dep_vars.discard("__DYNAMIC_VARS__")
        all_vars.update(dep_vars)

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
    scan_root: Optional[str] = None,
) -> Set[str]:
    """
    Collect variables from a called script.

    Args:
        script_path: Path to the called script
        batch_file_resolved: Resolved path to the calling batch file
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        Set of variable names defined in the called script
    """
    if not (script_path.exists() and script_path.is_file()):
        return set()

    if script_path.resolve() == batch_file_resolved:
        return set()

    if not _is_within_scan_root(script_path, scan_root):
        logger.debug("Skipping called script outside scan root: %s", script_path)
        return set()

    called_lines = _read_batch_lines(script_path)
    if called_lines is None:
        return set()

    called_vars = _collect_set_variables(called_lines)
    called_vars.discard("__DYNAMIC_VARS__")
    return called_vars


def _collect_called_vars(
    batch_file: Path,
    dependency_graph: Optional[Dict[Path, Set[Path]]] = None,
    scan_root: Optional[str] = None,
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
        scan_root: Optional root directory; paths outside it are skipped

    Returns:
        Dictionary mapping line numbers to sets of variables available after that line.
        For example, if line 10 has a CALL to a script that defines VAR1 and VAR2,
        the returned dict will have {10: {'VAR1', 'VAR2'}}.

        When dependency_graph is provided, returns {0: all_vars} where all_vars includes
        variables from all dependencies in the graph.
    """
    batch_file_resolved = batch_file.resolve()

    if dependency_graph is not None:
        return _collect_vars_from_dependencies(
            batch_file_resolved, dependency_graph, scan_root=scan_root
        )

    called_vars_by_line: Dict[int, Set[str]] = {}
    batch_dir = batch_file.parent

    lines = _read_batch_lines(batch_file)
    if lines is None:
        return called_vars_by_line

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        if stripped.startswith("rem ") or stripped.startswith("::"):
            continue

        call_match = re.search(
            r'\bcall\s+(?:"([^"]+\.(?:bat|cmd))"|([^\s]+\.(?:bat|cmd)))',
            line,
            re.IGNORECASE,
        )

        if not call_match:
            continue

        script_path_str = call_match.group(1) or call_match.group(2)
        script_path = _resolve_script_path(script_path_str, batch_dir)

        called_vars = _collect_vars_from_script(
            script_path, batch_file_resolved, scan_root=scan_root
        )
        if called_vars:
            called_vars_by_line[line_num] = called_vars

    return called_vars_by_line
